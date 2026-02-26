//! Kosh Multi-Key MPC Signer Contract
//!
//! Extends the Partisia off-chain-mpc-signing pattern to support multiple keys
//! in a single contract. Each account gets a unique `key_id`, and the contract
//! manages distributed key generation and ECDSA signing across 3 execution engines.
//!
//! State maps `key_id -> SigningComputationState` where each key has its own
//! task queues, engine shares, and signing history.

#[macro_use]
extern crate pbc_contract_codegen;
extern crate pbc_contract_common;
extern crate pbc_lib as _;

pub mod off_chain;
pub mod replicated_secret_sharing;
pub mod signing_orchestration;
pub mod task_queue;

use create_type_spec_derive::CreateTypeSpec;
use pbc_contract_common::address::Address;
use pbc_contract_common::avl_tree_map::AvlTreeMap;
use pbc_contract_common::context::ContractContext;
use pbc_contract_common::events::EventGroup;
use read_write_rpc_derive::ReadWriteRPC;
use read_write_state_derive::ReadWriteState;

use crate::replicated_secret_sharing::{
    combine_public_key_shares, point_to_compressed, EncodedCurvePoint, ReplicatedSecretShare,
};
use crate::signing_orchestration::*;
use crate::task_queue::{EngineIndex, TaskId};

/// Shortname for the vault's on_key_generated action (0x02 in the vault contract).
/// Used for cross-contract callback when key generation completes.
const VAULT_ON_KEY_GENERATED_SHORTNAME: &[u8] = &[0x02];

/// Configuration for an execution engine.
#[derive(ReadWriteState, ReadWriteRPC, CreateTypeSpec, Clone)]
pub struct EngineConfig {
    /// The engine's on-chain address.
    pub address: Address,
}

/// The top-level contract state.
#[state]
pub struct ContractState {
    /// Owner address (typically the vault contract).
    pub owner: Address,
    /// Configured execution engines (typically 3).
    pub engines: Vec<EngineConfig>,
    /// Default preprocessing configuration for new keys.
    pub default_preprocess_config: PreprocessConfig,
    /// Next key_id to assign.
    pub next_key_id: u32,
    /// Per-key signing computation state.
    pub keys: AvlTreeMap<u32, SigningComputationState>,
}

impl ContractState {
    /// Assert that the sender is the contract owner.
    pub fn assert_owner(&self, sender: &Address) {
        assert_eq!(sender, &self.owner, "Only the owner can call this action");
    }

    /// Assert that the sender is a registered execution engine. Returns its index.
    pub fn assert_engine(&self, sender: &Address) -> EngineIndex {
        self.get_engine_index(sender)
    }

    /// Get the engine index for an address, panicking if not found.
    pub fn get_engine_index(&self, address: &Address) -> EngineIndex {
        for (i, engine) in self.engines.iter().enumerate() {
            if &engine.address == address {
                return i as EngineIndex;
            }
        }
        panic!("Address is not a registered execution engine");
    }
}

/// Initialize the multi-key signer contract.
///
/// # Arguments
/// * `owner` - Address of the vault contract that controls this signer
/// * `engines` - List of execution engine configurations (typically 3)
/// * `preprocess_config` - Default preprocessing batch configuration
#[init]
pub fn initialize(
    _ctx: ContractContext,
    owner: Address,
    engines: Vec<EngineConfig>,
    preprocess_config: PreprocessConfig,
) -> ContractState {
    assert!(
        engines.len() >= 3,
        "At least 3 execution engines required"
    );

    ContractState {
        owner,
        engines,
        default_preprocess_config: preprocess_config,
        next_key_id: 0,
        keys: AvlTreeMap::new(),
    }
}

/// Create a new key. Triggers distributed key generation across engines.
/// Only callable by the owner (vault contract).
///
/// Returns the assigned key_id via callback event.
#[action(shortname = 0x01)]
pub fn create_key(
    ctx: ContractContext,
    mut state: ContractState,
) -> (ContractState, Vec<EventGroup>) {
    state.assert_owner(&ctx.sender);

    let key_id = state.next_key_id;
    state.next_key_id += 1;

    let num_engines = state.engines.len() as EngineIndex;
    let config = state.default_preprocess_config.clone();

    let mut key_state = SigningComputationState::new(key_id, num_engines, config);

    // Kick off key generation by pushing engine public key upload tasks
    for i in 0..num_engines {
        key_state
            .engine_public_keys_queue
            .push_task(TaskEngineUploadPublicKey { engine_index: i });
    }

    state.keys.insert(key_id, key_state);

    (state, vec![])
}

/// Create a key with a specific key_id. Used when the vault assigns IDs.
/// Only callable by the owner (vault contract).
#[action(shortname = 0x02)]
pub fn create_key_with_id(
    ctx: ContractContext,
    mut state: ContractState,
    key_id: u32,
) -> (ContractState, Vec<EventGroup>) {
    state.assert_owner(&ctx.sender);
    assert!(
        state.keys.get(&key_id).is_none(),
        "Key ID {} already exists",
        key_id
    );

    let num_engines = state.engines.len() as EngineIndex;
    let config = state.default_preprocess_config.clone();

    let mut key_state = SigningComputationState::new(key_id, num_engines, config);

    // Kick off key generation
    for i in 0..num_engines {
        key_state
            .engine_public_keys_queue
            .push_task(TaskEngineUploadPublicKey { engine_index: i });
    }

    state.keys.insert(key_id, key_state);

    (state, vec![])
}

/// Queue a message for signing with the specified key.
/// Only callable by the owner (vault contract).
#[action(shortname = 0x03)]
pub fn sign_message(
    ctx: ContractContext,
    mut state: ContractState,
    key_id: u32,
    message: Vec<u8>,
) -> (ContractState, Vec<EventGroup>) {
    state.assert_owner(&ctx.sender);

    let mut key_state = state
        .keys
        .get(&key_id)
        .expect("Key not found");

    assert!(
        key_state.is_key_generated(),
        "Key generation not yet complete for key {}",
        key_id
    );

    let _signing_task_id = key_state.queue_signing(message);

    state.keys.insert(key_id, key_state);

    (state, vec![])
}

/// Engine uploads its ephemeral public key for a key_id during key generation.
#[action(shortname = 0x04)]
pub fn upload_engine_pub_key(
    ctx: ContractContext,
    mut state: ContractState,
    key_id: u32,
    engine_index: EngineIndex,
    task_id: TaskId,
    engine_pub_key: Vec<u8>,
) -> (ContractState, Vec<EventGroup>) {
    let actual_index = state.assert_engine(&ctx.sender);
    assert_eq!(
        actual_index, engine_index,
        "Engine index mismatch"
    );

    let mut key_state = state.keys.get(&key_id).expect("Key not found");

    // Store the engine's public key
    key_state.engine_public_keys[engine_index as usize] = Some(engine_pub_key.clone());

    // Mark task completion
    let all_complete = key_state
        .engine_public_keys_queue
        .mark_completed_by_engine(engine_index, task_id, engine_pub_key);

    if all_complete {
        // All engines uploaded their public keys — move to secret key generation
        key_state.key_gen_status = KeyGenStatus::GeneratingSecretKey {};

        let num_engines = state.engines.len() as EngineIndex;
        for i in 0..num_engines {
            key_state
                .generate_secret_key_queue
                .push_task(TaskGenerateSecretKey { engine_index: i });
        }
    }

    state.keys.insert(key_id, key_state);

    (state, vec![])
}

/// Engine uploads its public key share after generating secret key share.
#[action(shortname = 0x05)]
pub fn upload_pub_key_share(
    ctx: ContractContext,
    mut state: ContractState,
    key_id: u32,
    engine_index: EngineIndex,
    task_id: TaskId,
    pub_key_share: ReplicatedSecretShare<EncodedCurvePoint>,
) -> (ContractState, Vec<EventGroup>) {
    let actual_index = state.assert_engine(&ctx.sender);
    assert_eq!(actual_index, engine_index, "Engine index mismatch");

    let mut key_state = state.keys.get(&key_id).expect("Key not found");

    // Store the public key share
    key_state.public_key_shares[engine_index as usize] = Some(pub_key_share.left.clone());

    // Mark task completion
    let all_complete = key_state
        .generate_secret_key_queue
        .mark_completed_by_engine(engine_index, task_id, pub_key_share);

    let mut events = vec![];

    if all_complete {
        // All engines uploaded their public key shares — assemble the full public key
        key_state.key_gen_status = KeyGenStatus::AssemblingPublicKey {};

        let shares: Vec<EncodedCurvePoint> = key_state
            .public_key_shares
            .iter()
            .map(|s| s.clone().expect("Missing public key share"))
            .collect();

        let combined_point = combine_public_key_shares(&shares);
        let compressed = point_to_compressed(&combined_point);
        key_state.public_key = Some(compressed.to_vec());
        key_state.key_gen_status = KeyGenStatus::Complete {};

        // Start preprocessing automatically
        key_state.start_preprocessing();

        // Emit event to notify the vault that the key is ready
        let vault_shortname = pbc_contract_common::address::Shortname::from_be_bytes(VAULT_ON_KEY_GENERATED_SHORTNAME).unwrap();
        let mut event_group = EventGroup::builder();
        event_group
            .call(state.owner, vault_shortname)
            .argument(key_id)
            .argument(compressed.to_vec())
            .with_cost_from_contract(50_000)
            .done();
        events.push(event_group.build());
    }

    state.keys.insert(key_id, key_state);

    (state, events)
}

/// Engine reports pre-prep check completion.
#[action(shortname = 0x06)]
pub fn pre_prep_check_report(
    ctx: ContractContext,
    mut state: ContractState,
    key_id: u32,
    engine_index: EngineIndex,
    task_id: TaskId,
    completion: TaskPrePrepCheckCompletion,
) -> (ContractState, Vec<EventGroup>) {
    let actual_index = state.assert_engine(&ctx.sender);
    assert_eq!(actual_index, engine_index, "Engine index mismatch");

    let mut key_state = state.keys.get(&key_id).expect("Key not found");

    let batch_size = key_state
        .pre_prep_check_queue
        .get_task(&task_id)
        .expect("Task not found")
        .definition
        .batch_size;

    let all_complete = key_state
        .pre_prep_check_queue
        .mark_completed_by_engine(engine_index, task_id, completion);

    if all_complete {
        // Move to prep phase for this batch
        key_state.prep_queue.push_task(TaskPrep {
            batch_id: task_id,
            batch_size,
        });
    }

    state.keys.insert(key_id, key_state);

    (state, vec![])
}

/// Engine reports preprocessing completion.
#[action(shortname = 0x07)]
pub fn prep_report(
    ctx: ContractContext,
    mut state: ContractState,
    key_id: u32,
    engine_index: EngineIndex,
    task_id: TaskId,
    completion: TaskPrepCompletion,
) -> (ContractState, Vec<EventGroup>) {
    let actual_index = state.assert_engine(&ctx.sender);
    assert_eq!(actual_index, engine_index, "Engine index mismatch");

    let mut key_state = state.keys.get(&key_id).expect("Key not found");

    let all_complete = key_state
        .prep_queue
        .mark_completed_by_engine(engine_index, task_id, completion);

    if all_complete {
        // Move to mul check one
        key_state
            .mul_check_one_queue
            .push_task(TaskMulCheckOne { batch_id: task_id });
    }

    state.keys.insert(key_id, key_state);

    (state, vec![])
}

/// Engine reports multiplication check phase 1 completion.
#[action(shortname = 0x08)]
pub fn mul_check_one_report(
    ctx: ContractContext,
    mut state: ContractState,
    key_id: u32,
    engine_index: EngineIndex,
    task_id: TaskId,
    completion: TaskMulCheckOneCompletion,
) -> (ContractState, Vec<EventGroup>) {
    let actual_index = state.assert_engine(&ctx.sender);
    assert_eq!(actual_index, engine_index, "Engine index mismatch");

    let mut key_state = state.keys.get(&key_id).expect("Key not found");

    let all_complete = key_state
        .mul_check_one_queue
        .mark_completed_by_engine(engine_index, task_id, completion);

    if all_complete {
        // Move to mul check two
        key_state
            .mul_check_two_queue
            .push_task(TaskMulCheckTwo { batch_id: task_id });
    }

    state.keys.insert(key_id, key_state);

    (state, vec![])
}

/// Engine reports multiplication check phase 2 completion.
#[action(shortname = 0x09)]
pub fn mul_check_two_report(
    ctx: ContractContext,
    mut state: ContractState,
    key_id: u32,
    engine_index: EngineIndex,
    task_id: TaskId,
    completion: TaskMulCheckTwoCompletion,
) -> (ContractState, Vec<EventGroup>) {
    let actual_index = state.assert_engine(&ctx.sender);
    assert_eq!(actual_index, engine_index, "Engine index mismatch");

    let mut key_state = state.keys.get(&key_id).expect("Key not found");

    let batch_size = key_state
        .prep_queue
        .get_task(&task_id)
        .map(|t| t.definition.batch_size)
        .unwrap_or(1);

    let all_complete = key_state
        .mul_check_two_queue
        .mark_completed_by_engine(engine_index, task_id, completion);

    if all_complete {
        // Preprocessing batch complete
        key_state.mark_preprocess_batch_complete(batch_size);
    }

    state.keys.insert(key_id, key_state);

    (state, vec![])
}

/// Engine reports signing completion with partial signature.
#[action(shortname = 0x0A)]
pub fn sign_report(
    ctx: ContractContext,
    mut state: ContractState,
    key_id: u32,
    engine_index: EngineIndex,
    task_id: TaskId,
    completion: TaskSignCompletion,
) -> (ContractState, Vec<EventGroup>) {
    let actual_index = state.assert_engine(&ctx.sender);
    assert_eq!(actual_index, engine_index, "Engine index mismatch");

    let mut key_state = state.keys.get(&key_id).expect("Key not found");

    let all_complete = key_state
        .sign_queue
        .mark_completed_by_engine(engine_index, task_id, completion);

    if all_complete {
        // All engines reported — assemble the full signature
        let sign_task = key_state
            .sign_queue
            .get_task(&task_id)
            .expect("Sign task not found");

        let signing_task_id = sign_task.definition.signing_task_id;

        // Collect partial signatures and combine
        // In the real protocol, this would be proper ECDSA signature combination
        // For now, we store the first engine's partial as the assembled signature
        let mut assembled_sig = vec![0u8; 65]; // recovery_id(1) + R(32) + S(32)
        if let Some(first_completion) = &sign_task.completions[0] {
            let sig_bytes = &first_completion.partial_signature;
            // Copy up to 32 bytes into the S field (simplified)
            let copy_len = sig_bytes.len().min(32);
            assembled_sig[33..33 + copy_len].copy_from_slice(&sig_bytes[..copy_len]);
        }

        // Update signing information with the assembled signature
        if let Some(mut info) = key_state.signing_information.get(&signing_task_id) {
            info.signature = Some(assembled_sig);
            info.verified = true; // In production, verify against public key
            key_state.signing_information.insert(signing_task_id, info);
        }
    }

    state.keys.insert(key_id, key_state);

    (state, vec![])
}

/// Reset preprocessing for a key (refill signing material).
/// Only callable by the owner.
#[action(shortname = 0x11)]
pub fn reset_preprocessing(
    ctx: ContractContext,
    mut state: ContractState,
    key_id: u32,
) -> (ContractState, Vec<EventGroup>) {
    state.assert_owner(&ctx.sender);

    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        key_state.is_key_generated(),
        "Key generation must be complete before preprocessing"
    );

    key_state.preprocess_state.completed_count = 0;
    key_state.preprocess_state.available_count = 0;
    key_state.preprocess_state.status = PreprocessStatus::Idle {};
    key_state.start_preprocessing();

    state.keys.insert(key_id, key_state);

    (state, vec![])
}

/// Off-chain handler: triggered on every state change.
/// Dispatches pending work to execution engines.
#[off_chain_on_state_change]
pub fn off_chain_on_state_update(ctx: pbc_contract_common::off_chain::OffChainContext, state: ContractState) {
    let mut dispatcher = off_chain::OffChainDispatcher::new(ctx, state);
    dispatcher.process_all_keys();
}
