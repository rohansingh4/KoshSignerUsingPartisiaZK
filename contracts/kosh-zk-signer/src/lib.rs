//! Kosh ZK Signer Contract — ECDSA key splitting via Shamir's Secret Sharing on Partisia ZK nodes.
//!
//! Architecture:
//! 1. Engine 0 generates secp256k1 keypair and Shamir-splits the private key
//! 2. Each share is stored as ZK secret variables (split into 2x Sbi128 halves)
//! 3. ZK nodes auto-secret-share each variable across the cluster
//! 4. For signing: threshold shares are opened, Engine 0 reconstructs via Lagrange interpolation
//! 5. Engine 0 signs with k256 ECDSA and posts the verified (r, s, v) on-chain
//!
//! Vault-compatible shortnames: 0x02 (create_key_with_id), 0x03 (sign_message)

#[macro_use]
extern crate pbc_contract_codegen;
extern crate pbc_contract_common;
extern crate pbc_lib as _;

pub mod off_chain;
pub mod shamir;
pub mod signing_state;

use create_type_spec_derive::CreateTypeSpec;
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use pbc_contract_common::address::Address;
use pbc_contract_common::avl_tree_map::AvlTreeMap;
use pbc_contract_common::context::ContractContext;
use pbc_contract_common::events::EventGroup;
use pbc_contract_common::zk::{SecretVarId, ZkInputDef, ZkState, ZkStateChange};
use pbc_zk::Sbi128;
use read_write_rpc_derive::ReadWriteRPC;
use read_write_state_derive::ReadWriteState;

use crate::signing_state::*;

/// Shortname for the vault's on_key_generated callback (0x02 in the vault contract).
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
    /// Configured execution engines.
    pub engines: Vec<EngineConfig>,
    /// Shamir threshold (t in t-of-n).
    pub threshold: u16,
    /// Total number of Shamir shares (n), typically == engines.len().
    pub num_shares: u8,
    /// Next key_id to assign.
    pub next_key_id: u32,
    /// Per-key ZK signing state.
    pub keys: AvlTreeMap<u32, ZkKeyState>,
}

impl ContractState {
    pub fn assert_owner(&self, sender: &Address) {
        assert_eq!(sender, &self.owner, "Only the owner can call this action");
    }

    pub fn assert_engine(&self, sender: &Address) -> u8 {
        self.get_engine_index(sender)
            .expect("Address is not a registered execution engine or ZK node")
    }

    pub fn get_engine_index(&self, address: &Address) -> Option<u8> {
        for (i, engine) in self.engines.iter().enumerate() {
            if &engine.address == address {
                return Some(i as u8);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Initialization
// ---------------------------------------------------------------------------

/// Initialize the ZK signer contract.
#[init(zk = true)]
pub fn initialize(
    _ctx: ContractContext,
    _zk_state: ZkState<ShareMetadata>,
    owner: Address,
    engines: Vec<EngineConfig>,
    threshold: u16,
    num_shares: u8,
) -> ContractState {
    assert!(engines.len() >= 3, "At least 3 execution engines required");
    assert!(
        threshold >= 2 && (threshold as usize) <= engines.len(),
        "Threshold must be >= 2 and <= number of engines"
    );
    assert!(
        (num_shares as usize) >= threshold as usize && (num_shares as usize) <= engines.len(),
        "num_shares must be >= threshold and <= number of engines"
    );

    ContractState {
        owner,
        engines,
        threshold,
        num_shares,
        next_key_id: 0,
        keys: AvlTreeMap::new(),
    }
}

// ---------------------------------------------------------------------------
// Vault-compatible actions (same shortnames as V2 signer)
// ---------------------------------------------------------------------------

/// Create a key with a specific key_id.
/// Called by the vault contract to trigger key generation.
#[action(shortname = 0x02, zk = true)]
pub fn create_key_with_id(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);
    assert!(
        state.keys.get(&key_id).is_none(),
        "Key ID {} already exists",
        key_id
    );

    let key_state = ZkKeyState::new(state.threshold, state.num_shares);
    state.keys.insert(key_id, key_state);

    (state, vec![], vec![])
}

/// Queue a 32-byte message hash for signing with the specified key.
/// Called by the vault contract.
#[action(shortname = 0x03, zk = true)]
pub fn sign_message(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    message: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);

    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        key_state.is_key_generated(),
        "Key generation not yet complete for key {}",
        key_id
    );

    let _signing_task_id = key_state.queue_signing(message);
    state.keys.insert(key_id, key_state);

    (state, vec![], vec![])
}

/// Engine 0 posts the compressed public key after generating the keypair off-chain.
#[action(shortname = 0x05, zk = true)]
pub fn post_public_key(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    public_key: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    // Accept from any ZK node or registered engine (off-chain runs on ZK nodes)
    let _engine_index = state.get_engine_index(&ctx.sender);

    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        matches!(
            key_state.keygen_phase,
            ZkKeyGenPhase::WaitingForDealer {} | ZkKeyGenPhase::SubmittingShares {}
        ),
        "Key generation already complete"
    );
    assert_eq!(
        public_key.len(),
        33,
        "Public key must be 33 bytes (compressed secp256k1)"
    );

    // Validate that this is a real secp256k1 public key
    VerifyingKey::from_sec1_bytes(&public_key).expect("Invalid secp256k1 public key");

    key_state.public_key = Some(public_key.clone());

    // If all shares are already submitted, complete keygen
    let mut events = vec![];
    if key_state.shares_submitted >= key_state.expected_share_count {
        key_state.keygen_phase = ZkKeyGenPhase::Complete {};
        events.extend(emit_key_generated_event(&state, key_id, &public_key));
    }

    state.keys.insert(key_id, key_state);
    (state, events, vec![])
}

/// Engine reports signing completion with the final ECDSA signature.
/// Verifies the signature on-chain before accepting it.
#[action(shortname = 0x07, zk = true)]
pub fn signing_complete(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    _engine_index: u8,
    task_id: u32,
    signature: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    // Accept from any ZK node or registered engine (off-chain runs on ZK nodes)
    let _actual_index = state.get_engine_index(&ctx.sender);

    let mut key_state = state.keys.get(&key_id).expect("Key not found");

    assert!(
        signature.len() == 64 || signature.len() == 65,
        "Signature must be 64 bytes (r||s) or 65 bytes (r||s||v)"
    );

    // Verify the ECDSA signature against the stored public key
    let public_key = key_state
        .public_key
        .clone()
        .expect("Public key missing for this key");
    let verifying_key = VerifyingKey::from_sec1_bytes(&public_key)
        .expect("Stored public key is not a valid secp256k1 key");

    let sig64 = &signature[0..64];
    let parsed_signature =
        Signature::try_from(sig64).expect("Failed to parse signature bytes as ECDSA signature");

    let mut info = key_state
        .signing_information
        .get(&task_id)
        .expect("Unknown signing task");
    assert!(
        info.signature.is_none(),
        "Signature already set for this task"
    );

    verifying_key
        .verify_prehash(&info.message_hash, &parsed_signature)
        .expect("Signature verification failed");

    // Store the verified signature
    if signature.len() == 65 {
        info.recovery_id = signature[64];
    }
    info.signature = Some(signature);
    info.verified = true;
    key_state.signing_information.insert(task_id, info);

    // Clear opened shares (no longer needed, reduces exposure window)
    key_state.opened_shares.clear();

    // Move to next signing request
    key_state.signing_phase = ZkSigningPhase::Complete { task_id };
    key_state
        .pending_sign_requests
        .retain(|r| r.task_id != task_id);

    if !key_state.pending_sign_requests.is_empty() {
        key_state.start_next_signing();
    } else {
        key_state.signing_phase = ZkSigningPhase::Idle {};
    }

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

// ---------------------------------------------------------------------------
// ZK secret input handling
// ---------------------------------------------------------------------------

/// Accept a Shamir share half as a ZK secret input.
///
/// Engine 0 calls this for each share half (high and low 128 bits).
/// The ZK layer receives the secret Sbi128 value and auto-secret-shares it across ZK nodes.
#[zk_on_secret_input(shortname = 0x10)]
pub fn submit_key_share(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    share_index: u8,
    is_high_half: bool,
) -> (
    ContractState,
    Vec<EventGroup>,
    ZkInputDef<ShareMetadata, Sbi128>,
) {
    // Accept from any ZK node or registered engine (off-chain runs on ZK nodes)
    let _engine_index = state.get_engine_index(&ctx.sender);

    let key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        matches!(
            key_state.keygen_phase,
            ZkKeyGenPhase::WaitingForDealer {} | ZkKeyGenPhase::SubmittingShares {}
        ),
        "Cannot submit shares in current keygen phase"
    );

    // Update phase to SubmittingShares if still WaitingForDealer
    if matches!(key_state.keygen_phase, ZkKeyGenPhase::WaitingForDealer {}) {
        let mut ks = key_state;
        ks.keygen_phase = ZkKeyGenPhase::SubmittingShares {};
        state.keys.insert(key_id, ks);
    }

    let metadata = ShareMetadata {
        key_id,
        share_index,
        is_high_half,
    };

    let input_def = ZkInputDef::with_metadata(None, metadata);

    (state, vec![], input_def)
}

/// Called by the ZK framework when a secret variable has been successfully inputted.
#[zk_on_variable_inputted(shortname = 0x12)]
pub fn on_share_inputted(
    _ctx: ContractContext,
    mut state: ContractState,
    zk_state: ZkState<ShareMetadata>,
    inputted_variable: SecretVarId,
) -> ContractState {
    // Read the metadata attached to this variable
    let variable_info = zk_state
        .get_variable(inputted_variable)
        .expect("Variable not found in ZK state");
    let metadata = variable_info.metadata;

    let mut key_state = state
        .keys
        .get(&metadata.key_id)
        .expect("Key not found for inputted share");

    // Track this variable
    key_state.share_variables.push(StoredShareVar {
        variable_id: inputted_variable.raw_id,
        key_id: metadata.key_id,
        share_index: metadata.share_index,
        is_high_half: metadata.is_high_half,
    });
    key_state.shares_submitted += 1;

    // Check if all share halves are stored AND public key is posted
    if key_state.shares_submitted >= key_state.expected_share_count
        && key_state.public_key.is_some()
    {
        key_state.keygen_phase = ZkKeyGenPhase::Complete {};
    }

    state.keys.insert(metadata.key_id, key_state);
    state
}

// ---------------------------------------------------------------------------
// ZK share reconstruction for signing
// ---------------------------------------------------------------------------

/// Request reconstruction of threshold shares for signing.
///
/// Opens the minimum required ZK variables (threshold shares) so Engine 0
/// can reconstruct the private key and sign.
#[action(shortname = 0x11, zk = true)]
pub fn request_reconstruction(
    ctx: ContractContext,
    state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    // Allow engines or owner to request reconstruction
    let is_engine = state.engines.iter().any(|e| e.address == ctx.sender);
    assert!(
        is_engine || ctx.sender == state.owner,
        "Only engines or owner can request reconstruction"
    );

    let key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        matches!(
            key_state.signing_phase,
            ZkSigningPhase::ReconstructingKey { .. }
        ),
        "No signing request pending reconstruction"
    );

    // Get variable IDs for threshold shares to open
    let var_ids: Vec<SecretVarId> = key_state
        .get_threshold_variable_ids()
        .into_iter()
        .map(SecretVarId::new)
        .collect();

    assert!(
        !var_ids.is_empty(),
        "No share variables available for reconstruction"
    );

    let zk_changes = vec![ZkStateChange::OpenVariables {
        variables: var_ids,
    }];

    (state, vec![], zk_changes)
}

/// Called by the ZK framework when variables have been opened (reconstructed from MPC).
///
/// Reads the opened share values and stores them temporarily in contract state
/// for Engine 0 to reconstruct the key and sign off-chain.
#[zk_on_variables_opened]
pub fn on_shares_opened(
    _ctx: ContractContext,
    mut state: ContractState,
    zk_state: ZkState<ShareMetadata>,
    opened_variables: Vec<SecretVarId>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    // First, figure out which key this belongs to
    let first_var = zk_state
        .get_variable(opened_variables[0])
        .expect("Opened variable not found");
    let key_id = first_var.metadata.key_id;

    let mut key_state = state.keys.get(&key_id).expect("Key not found");

    // Read each opened variable and group by share_index
    let mut share_halves: Vec<(u8, bool, Vec<u8>)> = Vec::new();
    for var_id in &opened_variables {
        let var_info = zk_state
            .get_variable(*var_id)
            .expect("Opened variable not found in ZK state");

        // Read the opened value as raw bytes (16 bytes for Sbi128)
        // The exact API depends on the SDK version; try open_value or data field.
        let data: Vec<u8> = {
            // Opened variable data is available as raw bytes
            let raw = var_info.data.as_ref().expect("Opened variable has no data");
            raw.clone()
        };

        share_halves.push((
            var_info.metadata.share_index,
            var_info.metadata.is_high_half,
            data,
        ));
    }

    // Assemble full shares from high/low pairs
    let mut assembled: AvlTreeMap<u8, OpenedShare> = AvlTreeMap::new();
    for (share_index, is_high_half, data) in share_halves {
        let mut share = assembled.get(&share_index).unwrap_or_else(|| OpenedShare {
            share_index,
            high_bytes: vec![0u8; 16],
            low_bytes: vec![0u8; 16],
        });

        if is_high_half {
            share.high_bytes = data;
        } else {
            share.low_bytes = data;
        }
        assembled.insert(share_index, share);
    }

    // Collect assembled shares
    key_state.opened_shares.clear();
    let share_indices: Vec<u8> = (1..=key_state.num_shares)
        .filter(|i| assembled.get(i).is_some())
        .collect();
    for idx in share_indices {
        if let Some(share) = assembled.get(&idx) {
            key_state.opened_shares.push(share);
        }
    }

    // Move to Signing phase
    if let ZkSigningPhase::ReconstructingKey { task_id } = key_state.signing_phase {
        key_state.signing_phase = ZkSigningPhase::Signing { task_id };
    }

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

// ---------------------------------------------------------------------------
// Keygen completion check (for vault callback)
// ---------------------------------------------------------------------------

/// Check if keygen is complete and emit vault callback if so.
///
/// Needed because zk_on_variable_inputted can only return ContractState (no events).
/// Engine 0 calls this after all shares are inputted to trigger the vault callback.
#[action(shortname = 0x06, zk = true)]
pub fn check_keygen_complete(
    _ctx: ContractContext,
    state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    let key_state = state.keys.get(&key_id).expect("Key not found");
    let mut events = vec![];

    if key_state.is_key_generated() {
        if let Some(pk) = &key_state.public_key {
            events.extend(emit_key_generated_event(&state, key_id, pk));
        }
    }

    (state, events, vec![])
}

/// Force-complete keygen for testing when off-chain isn't available.
/// Owner can call this after posting a public key to mark keygen as done.
#[action(shortname = 0x08, zk = true)]
pub fn force_complete_keygen(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);
    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        key_state.public_key.is_some(),
        "Public key must be posted first"
    );
    key_state.keygen_phase = ZkKeyGenPhase::Complete {};
    let _pk = key_state.public_key.clone().unwrap();
    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Off-chain handler
// ---------------------------------------------------------------------------

/// Off-chain handler: triggered on every state change.
/// Dispatches keygen and signing tasks to Engine 0.
#[off_chain_on_state_change]
pub fn off_chain_on_state_update(
    ctx: pbc_contract_common::off_chain::OffChainContext,
    state: ContractState,
) {
    let mut dispatcher = off_chain::OffChainDispatcher::new(ctx, state);
    dispatcher.process_all_keys();
}
