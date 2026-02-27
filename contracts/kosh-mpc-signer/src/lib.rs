//! Kosh Multi-Key MPC Signer Contract (k256 ECDSA)
//!
//! Coordinates key generation and ECDSA signing across execution engines.
//!
//! Testnet approach (centralized, WASM-compatible):
//! - Engine 0 generates a random secp256k1 key pair using k256 (pure Rust)
//! - Engine 0 directly signs messages — no threshold protocol
//! - All engines store the full secret key (no real secret sharing)
//!
//! The on-chain state and round-message infrastructure remains in place for a
//! future upgrade to real threshold ECDSA with WASM-compatible dependencies.
//!
//! NOTE: Previously used cggmp21 which depends on gmp-mpfr-sys (C library)
//! that cannot compile to wasm32-unknown-unknown. Replaced with k256 (pure Rust).

#[macro_use]
extern crate pbc_contract_codegen;
extern crate pbc_contract_common;
extern crate pbc_lib as _;

pub mod off_chain;
pub mod signing_orchestration;
pub mod task_queue;

use create_type_spec_derive::CreateTypeSpec;
use pbc_contract_common::address::Address;
use pbc_contract_common::avl_tree_map::AvlTreeMap;
use pbc_contract_common::context::ContractContext;
use pbc_contract_common::events::EventGroup;
use read_write_rpc_derive::ReadWriteRPC;
use read_write_state_derive::ReadWriteState;

use crate::signing_orchestration::*;
use crate::task_queue::EngineIndex;

/// Shortname for the vault's on_key_generated action (0x02 in the vault contract).
const VAULT_ON_KEY_GENERATED_SHORTNAME: &[u8] = &[0x02];

/// Configuration for an execution engine.
#[derive(ReadWriteState, ReadWriteRPC, CreateTypeSpec, Clone)]
pub struct EngineConfig {
    pub address: Address,
}

/// The top-level contract state.
#[state]
pub struct ContractState {
    /// Owner address (typically the vault contract).
    pub owner: Address,
    /// Configured execution engines (typically 3).
    pub engines: Vec<EngineConfig>,
    /// Threshold for signing (e.g., 2 for 2-of-3).
    pub threshold: u16,
    /// Next key_id to assign.
    pub next_key_id: u32,
    /// Per-key signing computation state.
    pub keys: AvlTreeMap<u32, SigningComputationState>,
}

impl ContractState {
    pub fn assert_owner(&self, sender: &Address) {
        assert_eq!(sender, &self.owner, "Only the owner can call this action");
    }

    pub fn assert_engine(&self, sender: &Address) -> EngineIndex {
        self.get_engine_index(sender)
    }

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
#[init]
pub fn initialize(
    _ctx: ContractContext,
    owner: Address,
    engines: Vec<EngineConfig>,
    threshold: u16,
) -> ContractState {
    assert!(
        engines.len() >= 3,
        "At least 3 execution engines required"
    );
    assert!(
        threshold >= 2 && (threshold as usize) <= engines.len(),
        "Threshold must be >= 2 and <= number of engines"
    );

    ContractState {
        owner,
        engines,
        threshold,
        next_key_id: 0,
        keys: AvlTreeMap::new(),
    }
}

/// Create a new key. Triggers key generation via trusted dealer.
/// Only callable by the owner (vault contract).
#[action(shortname = 0x01)]
pub fn create_key(
    ctx: ContractContext,
    mut state: ContractState,
) -> (ContractState, Vec<EventGroup>) {
    state.assert_owner(&ctx.sender);

    let key_id = state.next_key_id;
    state.next_key_id += 1;

    let num_engines = state.engines.len() as EngineIndex;
    let key_state = SigningComputationState::new(num_engines, state.threshold);
    state.keys.insert(key_id, key_state);

    (state, vec![])
}

/// Create a key with a specific key_id.
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
    let key_state = SigningComputationState::new(num_engines, state.threshold);
    state.keys.insert(key_id, key_state);

    (state, vec![])
}

/// Queue a 32-byte message hash for signing with the specified key.
/// Only callable by the owner (vault contract).
#[action(shortname = 0x03)]
pub fn sign_message(
    ctx: ContractContext,
    mut state: ContractState,
    key_id: u32,
    message: Vec<u8>,
) -> (ContractState, Vec<EventGroup>) {
    state.assert_owner(&ctx.sender);

    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        key_state.is_key_generated(),
        "Key generation not yet complete for key {}",
        key_id
    );

    let _signing_task_id = key_state.queue_signing(message);
    state.keys.insert(key_id, key_state);

    (state, vec![])
}

/// Engine 0 (trusted dealer) distributes key shares and public key.
/// Posts serialized key shares for all engines on-chain.
///
/// WARNING: Key shares are posted in the clear — testnet only!
#[action(shortname = 0x04)]
pub fn distribute_key_shares(
    ctx: ContractContext,
    mut state: ContractState,
    key_id: u32,
    shares: Vec<Vec<u8>>,
    public_key: Vec<u8>,
) -> (ContractState, Vec<EventGroup>) {
    let engine_index = state.assert_engine(&ctx.sender);
    assert_eq!(engine_index, 0, "Only engine 0 (trusted dealer) can distribute shares");

    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        matches!(key_state.keygen_phase, KeyGenPhase::WaitingForDealer {}),
        "Key shares already distributed"
    );
    assert_eq!(
        shares.len(),
        key_state.num_engines as usize,
        "Must provide one share per engine"
    );
    assert_eq!(public_key.len(), 33, "Public key must be 33 bytes (compressed secp256k1)");

    // Store all shares and public key
    for (i, share) in shares.into_iter().enumerate() {
        key_state.key_shares[i] = Some(share);
    }
    key_state.public_key = Some(public_key.clone());
    key_state.keygen_phase = KeyGenPhase::SharesDistributed {};

    // Engine 0 auto-confirms (it already has its share)
    key_state.share_confirmations[0] = true;

    // Check if all engines confirmed (engine 0 just did)
    let all_confirmed = key_state.share_confirmations.iter().all(|c| *c);
    let mut events = vec![];

    if all_confirmed {
        key_state.keygen_phase = KeyGenPhase::Complete {};
        events.extend(emit_key_generated_event(&state, key_id, &public_key));
    }

    state.keys.insert(key_id, key_state);
    (state, events)
}

/// Engine confirms it has loaded its key share from on-chain state.
#[action(shortname = 0x05)]
pub fn confirm_key_share(
    ctx: ContractContext,
    mut state: ContractState,
    key_id: u32,
    engine_index: EngineIndex,
) -> (ContractState, Vec<EventGroup>) {
    let actual_index = state.assert_engine(&ctx.sender);
    assert_eq!(actual_index, engine_index, "Engine index mismatch");

    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        matches!(key_state.keygen_phase, KeyGenPhase::SharesDistributed {}),
        "Key shares not yet distributed"
    );

    key_state.share_confirmations[engine_index as usize] = true;

    let all_confirmed = key_state.share_confirmations.iter().all(|c| *c);
    let mut events = vec![];

    if all_confirmed {
        key_state.keygen_phase = KeyGenPhase::Complete {};
        if let Some(pk) = &key_state.public_key {
            events.extend(emit_key_generated_event(&state, key_id, pk));
        }
    }

    state.keys.insert(key_id, key_state);
    (state, events)
}

/// Engine posts signing round messages.
#[action(shortname = 0x06)]
pub fn signing_round_message(
    ctx: ContractContext,
    mut state: ContractState,
    key_id: u32,
    engine_index: EngineIndex,
    round: u16,
    task_id: u32,
    messages: Vec<RoundMessage>,
) -> (ContractState, Vec<EventGroup>) {
    let actual_index = state.assert_engine(&ctx.sender);
    assert_eq!(actual_index, engine_index, "Engine index mismatch");

    let mut key_state = state.keys.get(&key_id).expect("Key not found");

    match &key_state.signing_phase {
        SigningPhase::InProgress {
            task_id: current_task,
            round: current_round,
        } => {
            assert_eq!(*current_task, task_id, "Task ID mismatch");
            assert_eq!(*current_round, round, "Round mismatch");
        }
        _ => panic!("Signing not in progress"),
    }

    key_state.signing_round_tracker.mark_posted(engine_index);

    for msg in messages {
        key_state.signing_messages.push(msg);
    }

    // Advance round when threshold engines have posted
    if key_state.signing_round_tracker.threshold_posted(key_state.threshold) {
        key_state.advance_signing_round();
    }

    state.keys.insert(key_id, key_state);
    (state, vec![])
}

/// Engine reports signing completion with the final ECDSA signature.
#[action(shortname = 0x07)]
pub fn signing_complete(
    ctx: ContractContext,
    mut state: ContractState,
    key_id: u32,
    engine_index: EngineIndex,
    task_id: u32,
    signature: Vec<u8>,
) -> (ContractState, Vec<EventGroup>) {
    let actual_index = state.assert_engine(&ctx.sender);
    assert_eq!(actual_index, engine_index, "Engine index mismatch");

    let mut key_state = state.keys.get(&key_id).expect("Key not found");

    assert!(
        signature.len() == 64 || signature.len() == 65,
        "Signature must be 64 bytes (r||s) or 65 bytes (r||s||v)"
    );

    // Store the first valid signature we receive
    if let Some(mut info) = key_state.signing_information.get(&task_id) {
        if info.signature.is_none() {
            info.signature = Some(signature);
            info.verified = true;
            key_state.signing_information.insert(task_id, info);
        }
    }

    // Move to next signing request
    key_state.signing_phase = SigningPhase::Complete { task_id };
    key_state
        .pending_sign_requests
        .retain(|r| r.task_id != task_id);
    key_state.signing_messages.clear();

    if !key_state.pending_sign_requests.is_empty() {
        key_state.start_next_signing();
    } else {
        key_state.signing_phase = SigningPhase::Idle {};
    }

    state.keys.insert(key_id, key_state);
    (state, vec![])
}

/// Emit the vault callback event when key generation completes.
fn emit_key_generated_event(
    state: &ContractState,
    key_id: u32,
    public_key: &[u8],
) -> Vec<EventGroup> {
    let vault_shortname =
        pbc_contract_common::address::Shortname::from_be_bytes(VAULT_ON_KEY_GENERATED_SHORTNAME)
            .unwrap();
    let mut event_group = EventGroup::builder();
    event_group
        .call(state.owner, vault_shortname)
        .argument(key_id)
        .argument(public_key.to_vec())
        .with_cost_from_contract(50_000)
        .done();
    vec![event_group.build()]
}

/// Off-chain handler: triggered on every state change.
#[off_chain_on_state_change]
pub fn off_chain_on_state_update(
    ctx: pbc_contract_common::off_chain::OffChainContext,
    state: ContractState,
) {
    let mut dispatcher = off_chain::OffChainDispatcher::new(ctx, state);
    dispatcher.process_all_keys();
}
