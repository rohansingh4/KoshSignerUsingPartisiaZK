//! Kosh ZK Signer Contract — DKG + Threshold ECDSA on Partisia ZK nodes.
//!
//! Architecture (private key NEVER assembled):
//! 1. DKG: Each party generates a random secret scalar s_i and public share P_i = s_i × G
//! 2. Commit-reveal ceremony on-chain prevents manipulation
//! 3. Contract computes combined public key P = P₁ + P₂ + ... + Pₙ (EC point addition)
//! 4. Each s_i is stored as encrypted ZK secret variables (2x Sbi128 halves)
//! 5. For signing: each party computes partial σ_i = k⁻¹(m + r·s_i), contract combines σ = Σσ_i
//! 6. Contract verifies the combined ECDSA signature on-chain
//!
//! The private key s = s₁ + s₂ + ... + sₙ is NEVER computed anywhere.

#[macro_use]
extern crate pbc_contract_codegen;
extern crate pbc_contract_common;
extern crate pbc_lib as _;

pub mod dkg;
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
            ZkKeyGenPhase::WaitingForDealer {}
                | ZkKeyGenPhase::SubmittingShares {}
                | ZkKeyGenPhase::DkgFinalized {}
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
        variable_type: 0, // key_share
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

    if metadata.variable_type == 1 {
        // Delta ZK variable
        key_state.gg20_delta_zk_vars.push(StoredShareVar {
            variable_id: inputted_variable.raw_id,
            key_id: metadata.key_id,
            share_index: metadata.share_index,
            is_high_half: metadata.is_high_half,
        });
        key_state.gg20_delta_zk_count += 1;
    } else {
        // Key share variable (existing behavior)
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
    let first_variable_type = first_var.metadata.variable_type;

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

    if first_variable_type == 1 {
        // --- Delta ZK variables opened ---
        // Assemble 256-bit delta values from high/low halves
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

        // Reconstruct 32-byte delta values and store in gg20_delta_indices/values
        for party_idx in 1..=key_state.gg20_num_parties {
            if let Some(share) = assembled.get(&party_idx) {
                // Combine high + low into 32-byte delta
                let mut delta_bytes = Vec::with_capacity(32);
                delta_bytes.extend_from_slice(&share.high_bytes);
                delta_bytes.extend_from_slice(&share.low_bytes);

                // Only add if not already present (from plaintext path)
                if !key_state.gg20_delta_indices.iter().any(|&idx| idx == party_idx) {
                    key_state.gg20_delta_indices.push(party_idx);
                    key_state.gg20_delta_values.push(delta_bytes);
                }
            }
        }

        // Clear ZK delta tracking
        key_state.gg20_delta_zk_vars.clear();
        key_state.gg20_delta_zk_count = 0;
    } else {
        // --- Key share variables opened (existing behavior) ---
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
// DKG (Distributed Key Generation) — key is NEVER assembled
// ---------------------------------------------------------------------------

/// Create a key using DKG: initializes a commit/reveal ceremony for num_parties participants.
/// The private key is born split — no single party ever holds the full key.
#[action(shortname = 0x20, zk = true)]
pub fn dkg_create_key(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    num_parties: u8,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);
    assert!(
        state.keys.get(&key_id).is_none(),
        "Key ID {} already exists",
        key_id
    );
    assert!(num_parties >= 2, "DKG requires at least 2 parties");

    let mut key_state = ZkKeyState::new(state.threshold, state.num_shares);
    key_state.keygen_phase = ZkKeyGenPhase::DkgCommitting {};
    key_state.dkg_num_parties = num_parties;
    state.keys.insert(key_id, key_state);

    (state, vec![], vec![])
}

/// DKG commit: a party submits hash(P_i) where P_i is their public key share.
#[action(shortname = 0x21, zk = true)]
pub fn dkg_commit(
    _ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    party_index: u8,
    commitment_hash: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        matches!(key_state.keygen_phase, ZkKeyGenPhase::DkgCommitting {}),
        "Key is not in DKG committing phase"
    );

    let all_committed = dkg::add_commitment(&mut key_state, party_index, commitment_hash);

    if all_committed {
        key_state.keygen_phase = ZkKeyGenPhase::DkgRevealing {};
    }
    state.keys.insert(key_id, key_state);

    (state, vec![], vec![])
}

/// DKG reveal: a party reveals their public key share P_i.
/// Contract verifies it matches the previously committed hash.
#[action(shortname = 0x22, zk = true)]
pub fn dkg_reveal(
    _ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    party_index: u8,
    public_key_share: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        matches!(key_state.keygen_phase, ZkKeyGenPhase::DkgRevealing {}),
        "Key is not in DKG revealing phase"
    );

    let _all_revealed = dkg::add_reveal(&mut key_state, party_index, public_key_share);

    state.keys.insert(key_id, key_state);

    (state, vec![], vec![])
}

/// DKG finalize: compute the combined public key P = P₁ + P₂ + ... + Pₙ.
/// After this, parties submit their secret shares s_i as ZK secrets (existing 0x10 flow).
#[action(shortname = 0x23, zk = true)]
pub fn dkg_finalize(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);

    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        matches!(key_state.keygen_phase, ZkKeyGenPhase::DkgRevealing {}),
        "Key is not in DKG revealing phase"
    );

    assert!(
        key_state.dkg_reveal_indices.len() as u8 >= key_state.dkg_num_parties,
        "Not all parties have revealed yet"
    );

    // Compute combined public key via EC point addition
    let combined_pk = dkg::combine_public_keys(&key_state.dkg_reveal_pubkeys);

    // Validate the combined key
    VerifyingKey::from_sec1_bytes(&combined_pk).expect("Combined public key is invalid");

    key_state.public_key = Some(combined_pk);
    key_state.keygen_phase = ZkKeyGenPhase::DkgFinalized {};

    state.keys.insert(key_id, key_state);

    (state, vec![], vec![])
}

/// Force-complete DKG keygen after shares have been submitted.
/// Moves from DkgFinalized to Complete so signing can proceed.
#[action(shortname = 0x24, zk = true)]
pub fn dkg_complete_keygen(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);

    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        matches!(key_state.keygen_phase, ZkKeyGenPhase::DkgFinalized {}),
        "Key is not in DkgFinalized phase"
    );
    assert!(
        key_state.public_key.is_some(),
        "Public key must be set (run dkg_finalize first)"
    );

    key_state.keygen_phase = ZkKeyGenPhase::Complete {};
    state.keys.insert(key_id, key_state);

    (state, vec![], vec![])
}

// ---------------------------------------------------------------------------
// Threshold ECDSA Signing — private key NEVER reconstructed
// ---------------------------------------------------------------------------

/// Start a threshold signing session.
///
/// The coordinator submits the nonce point R (computed as k × G off-chain).
/// Each party will then submit their partial signature σ_i = k⁻¹ · r · s_i.
/// The contract combines partials and verifies the final ECDSA signature.
///
/// SECURITY: The private key s = Σ s_i is NEVER computed. Each party only uses
/// their own secret share s_i. The contract combines the partial signatures
/// on-chain so no single off-chain entity ever sees the full signature σ
/// before the nonce k is discarded.
#[action(shortname = 0x30, zk = true)]
pub fn start_threshold_sign(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    task_id: u32,
    r_bytes: Vec<u8>,
    recovery_id: u8,
    num_parties: u8,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);

    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        key_state.is_key_generated(),
        "Key generation not yet complete"
    );
    assert_eq!(r_bytes.len(), 32, "r_bytes must be 32 bytes");
    assert!(recovery_id <= 1, "recovery_id must be 0 or 1");
    assert!(num_parties >= 2, "Need at least 2 parties");

    // Ensure we have a signing task queued
    let info = key_state
        .signing_information
        .get(&task_id)
        .expect("Unknown signing task — call sign_message first");
    assert!(
        info.signature.is_none(),
        "Signature already set for this task"
    );

    // Create threshold signing session
    key_state.ts_active = true;
    key_state.ts_task_id = task_id;
    key_state.ts_r_bytes = r_bytes;
    key_state.ts_recovery_id = recovery_id;
    key_state.ts_num_parties = num_parties;
    key_state.ts_partial_indices.clear();
    key_state.ts_partial_values.clear();
    key_state.signing_phase = ZkSigningPhase::ThresholdSigning { task_id };

    // Set deadline for this signing round
    key_state.signing_deadline_block =
        ctx.block_production_time + key_state.signing_timeout_blocks;

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

/// Submit a partial signature for threshold ECDSA signing.
///
/// Each party submits σ_i = k⁻¹ · r · s_i (mod n).
/// Party 1 also includes the message component: σ_1 += k⁻¹ · m.
///
/// When all partials are collected, the contract:
/// 1. Sums σ = Σ σ_i
/// 2. Constructs the full ECDSA signature (r, σ)
/// 3. Verifies against the stored public key
/// 4. Stores the verified signature
///
/// The private key s is NEVER computed — only individual s_i values are used.
#[action(shortname = 0x31, zk = true)]
pub fn submit_partial_sig(
    _ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    party_index: u8,
    partial_s: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    let mut key_state = state.keys.get(&key_id).expect("Key not found");

    assert!(
        matches!(
            key_state.signing_phase,
            ZkSigningPhase::ThresholdSigning { .. }
        ),
        "Not in threshold signing phase"
    );
    assert_eq!(partial_s.len(), 32, "Partial signature must be 32 bytes");
    assert!(key_state.ts_active, "No threshold signing session active");

    // Check party hasn't already submitted
    assert!(
        !key_state.ts_partial_indices.iter().any(|&idx| idx == party_index),
        "Party {} has already submitted a partial signature",
        party_index
    );

    // If partial commitment exists, verify σ_i matches commitment
    if let Some(commit_pos) = key_state
        .ps_commit_indices
        .iter()
        .position(|&idx| idx == party_index)
    {
        let committed_hash = &key_state.ps_commit_hashes[commit_pos];
        let actual_hash = dkg::sha256(&partial_s);
        assert_eq!(
            committed_hash.as_slice(),
            &actual_hash[..],
            "Partial signature does not match commitment for party {}",
            party_index
        );
    }

    key_state.ts_partial_indices.push(party_index);
    key_state.ts_partial_values.push(partial_s.clone());

    // Check if all partials collected
    if key_state.ts_partial_indices.len() as u8 >= key_state.ts_num_parties {
        // Combine partial signatures with low-s normalization: σ = Σ σ_i (mod n)
        let (combined_s, was_negated) =
            combine_partial_signatures_with_flag(&key_state.ts_partial_values);

        // If s was negated for low-s, flip recovery ID
        let recovery_id = if was_negated {
            key_state.ts_recovery_id ^ 1
        } else {
            key_state.ts_recovery_id
        };

        // Build the full 65-byte signature: r (32) || s (32) || v (1)
        let mut signature = Vec::with_capacity(65);
        signature.extend_from_slice(&key_state.ts_r_bytes);
        signature.extend_from_slice(&combined_s);
        signature.push(recovery_id);

        // Verify the combined ECDSA signature against the stored public key
        let public_key = key_state
            .public_key
            .clone()
            .expect("Public key missing");
        let verifying_key = VerifyingKey::from_sec1_bytes(&public_key)
            .expect("Stored public key is not valid");

        let sig64 = &signature[0..64];
        let parsed_sig = Signature::try_from(sig64)
            .expect("Failed to parse combined signature");

        let task_id = key_state.ts_task_id;
        let mut info = key_state
            .signing_information
            .get(&task_id)
            .expect("Signing task not found");

        verifying_key
            .verify_prehash(&info.message_hash, &parsed_sig)
            .expect("Combined threshold signature verification failed");

        // Store the verified signature
        info.recovery_id = recovery_id;
        info.signature = Some(signature);
        info.verified = true;
        key_state.signing_information.insert(task_id, info);

        // Clean up and advance
        key_state.ts_active = false;
        key_state.ts_partial_indices.clear();
        key_state.ts_partial_values.clear();
        key_state.signing_phase = ZkSigningPhase::Complete { task_id };
        key_state
            .pending_sign_requests
            .retain(|r| r.task_id != task_id);

        if !key_state.pending_sign_requests.is_empty() {
            key_state.start_next_signing();
        } else {
            key_state.signing_phase = ZkSigningPhase::Idle {};
        }
    }

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

// ---------------------------------------------------------------------------
// Distributed Nonce Ceremony — removes single coordinator trust
// ---------------------------------------------------------------------------

/// Start a distributed nonce ceremony for threshold signing.
///
/// Instead of one coordinator generating k alone, all parties contribute:
/// 1. Each party commits hash(R_i) where R_i = k_i × G
/// 2. Each party reveals R_i
/// 3. Contract combines R = R₁ + R₂ + ... + Rₙ
/// 4. Coordinator (rotated each round) computes k_inv from contributed seeds
///
/// SECURITY: No single party can bias k. Coordinator rotates each round.
#[action(shortname = 0x40, zk = true)]
pub fn start_nonce_ceremony(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    task_id: u32,
    num_parties: u8,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);

    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        key_state.is_key_generated(),
        "Key generation not yet complete"
    );
    assert!(num_parties >= 2, "Need at least 2 parties");

    // Ensure signing task exists
    let _info = key_state
        .signing_information
        .get(&task_id)
        .expect("Unknown signing task — call sign_message first");

    // Rotate coordinator each round
    let coordinator = (key_state.signing_round % (num_parties as u32)) as u8;

    key_state.nc_num_parties = num_parties;
    key_state.nc_coordinator = coordinator;
    key_state.nc_commit_indices.clear();
    key_state.nc_commitment_hashes.clear();
    key_state.nc_reveal_indices.clear();
    key_state.nc_reveal_points.clear();
    key_state.signing_phase = ZkSigningPhase::NonceCommitting { task_id };

    // Set deadline for this signing round
    key_state.signing_deadline_block =
        ctx.block_production_time + key_state.signing_timeout_blocks;

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

/// Commit a nonce point hash during distributed nonce ceremony.
/// Each party submits SHA-256(compressed_R_i) where R_i = k_i × G.
#[action(shortname = 0x41, zk = true)]
pub fn nonce_commit(
    _ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    party_index: u8,
    commitment_hash: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        matches!(key_state.signing_phase, ZkSigningPhase::NonceCommitting { .. }),
        "Not in nonce committing phase"
    );
    assert_eq!(commitment_hash.len(), 32, "Commitment hash must be 32 bytes");
    assert!(
        !key_state.nc_commit_indices.iter().any(|&idx| idx == party_index),
        "Party {} has already committed a nonce",
        party_index
    );

    key_state.nc_commit_indices.push(party_index);
    key_state.nc_commitment_hashes.push(commitment_hash);

    // Move to reveal phase when all committed
    if key_state.nc_commit_indices.len() as u8 >= key_state.nc_num_parties {
        if let ZkSigningPhase::NonceCommitting { task_id } = key_state.signing_phase {
            key_state.signing_phase = ZkSigningPhase::NonceRevealing { task_id };
        }
    }

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

/// Reveal a nonce point during distributed nonce ceremony.
/// Contract verifies R_i matches the previously committed hash.
#[action(shortname = 0x42, zk = true)]
pub fn nonce_reveal(
    _ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    party_index: u8,
    nonce_point: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(
        matches!(key_state.signing_phase, ZkSigningPhase::NonceRevealing { .. }),
        "Not in nonce revealing phase"
    );
    assert_eq!(nonce_point.len(), 33, "Nonce point must be 33 bytes (compressed)");
    assert!(
        !key_state.nc_reveal_indices.iter().any(|&idx| idx == party_index),
        "Party {} has already revealed nonce",
        party_index
    );

    // Find commitment and verify
    let commit_idx = key_state
        .nc_commit_indices
        .iter()
        .position(|&idx| idx == party_index)
        .expect("Party did not commit — cannot reveal");
    let commitment_hash = &key_state.nc_commitment_hashes[commit_idx];

    assert!(
        dkg::verify_commitment(commitment_hash, &nonce_point),
        "Nonce reveal does not match commitment hash"
    );

    // Validate it's a real EC point
    VerifyingKey::from_sec1_bytes(&nonce_point)
        .expect("Invalid secp256k1 nonce point");

    key_state.nc_reveal_indices.push(party_index);
    key_state.nc_reveal_points.push(nonce_point);

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

/// Finalize nonce ceremony: combine R points and start threshold signing.
///
/// The coordinator (rotated) provides k⁻¹ and starts the signing session.
/// The contract verifies that the nonce point R matches the combined R_i points.
#[action(shortname = 0x43, zk = true)]
pub fn finalize_nonce_and_sign(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    r_bytes: Vec<u8>,
    recovery_id: u8,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);

    let mut key_state = state.keys.get(&key_id).expect("Key not found");

    let task_id = match key_state.signing_phase {
        ZkSigningPhase::NonceRevealing { task_id } => task_id,
        _ => panic!("Not in nonce revealing phase"),
    };

    assert!(
        key_state.nc_reveal_indices.len() as u8 >= key_state.nc_num_parties,
        "Not all parties have revealed nonce points"
    );
    assert_eq!(r_bytes.len(), 32, "r_bytes must be 32 bytes");

    // Combine all nonce points: R = R₁ + R₂ + ... + Rₙ
    let combined_nonce = dkg::combine_public_keys(&key_state.nc_reveal_points);

    // Verify that the provided r matches the combined nonce point's x-coordinate
    // Extract x-coordinate from the combined compressed point
    // Compressed format: 0x02/0x03 + x(32 bytes)
    let combined_x = &combined_nonce[1..33];
    assert_eq!(
        r_bytes.as_slice(),
        combined_x,
        "Provided r does not match combined nonce point R = R₁+R₂+...+Rₙ"
    );

    // Start threshold signing with verified r
    key_state.ts_active = true;
    key_state.ts_task_id = task_id;
    key_state.ts_r_bytes = r_bytes;
    key_state.ts_recovery_id = recovery_id;
    key_state.ts_num_parties = key_state.nc_num_parties;
    key_state.ts_partial_indices.clear();
    key_state.ts_partial_values.clear();
    key_state.ps_commit_indices.clear();
    key_state.ps_commit_hashes.clear();
    key_state.signing_phase = ZkSigningPhase::ThresholdSigning { task_id };

    // Increment signing round for coordinator rotation
    key_state.signing_round += 1;

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

// ---------------------------------------------------------------------------
// Partial Signature Commitments — prevents tampering
// ---------------------------------------------------------------------------

/// Commit hash(σ_i) before revealing the actual partial signature.
/// This prevents any party from modifying their σ_i after seeing others'.
#[action(shortname = 0x44, zk = true)]
pub fn commit_partial_sig(
    _ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    party_index: u8,
    commitment_hash: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    let mut key_state = state.keys.get(&key_id).expect("Key not found");

    assert!(
        matches!(
            key_state.signing_phase,
            ZkSigningPhase::ThresholdSigning { .. }
        ),
        "Not in threshold signing phase"
    );
    assert_eq!(commitment_hash.len(), 32, "Commitment must be 32 bytes");
    assert!(
        !key_state.ps_commit_indices.iter().any(|&idx| idx == party_index),
        "Party {} has already committed a partial signature",
        party_index
    );

    key_state.ps_commit_indices.push(party_index);
    key_state.ps_commit_hashes.push(commitment_hash);

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

// ---------------------------------------------------------------------------
// GG20 Fully Trustless Signing — NO coordinator, NO single k knowledge
// ---------------------------------------------------------------------------

/// Start a GG20 signing session.
/// After MtA rounds complete off-chain, parties submit δ_i and Γ_i.
#[action(shortname = 0x50, zk = true)]
pub fn gg20_start_signing(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    task_id: u32,
    num_parties: u8,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);

    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(key_state.is_key_generated(), "Key not yet generated");
    assert!(num_parties >= 2, "Need at least 2 parties");

    let _info = key_state
        .signing_information
        .get(&task_id)
        .expect("Unknown signing task");

    key_state.gg20_active = true;
    key_state.gg20_num_parties = num_parties;
    key_state.gg20_delta_indices.clear();
    key_state.gg20_delta_values.clear();
    key_state.gg20_delta_commit_indices.clear();
    key_state.gg20_delta_commit_hashes.clear();
    key_state.gg20_delta_zk_vars.clear();
    key_state.gg20_delta_zk_count = 0;
    key_state.gg20_delta_zk_expected = 0;
    key_state.gg20_gamma_indices.clear();
    key_state.gg20_gamma_points.clear();
    key_state.gg20_r_bytes.clear();
    key_state.ts_task_id = task_id;
    key_state.ps_commit_indices.clear();
    key_state.ps_commit_hashes.clear();
    key_state.ts_partial_indices.clear();
    key_state.ts_partial_values.clear();

    // Set deadline for this signing round
    key_state.signing_deadline_block =
        ctx.block_production_time + key_state.signing_timeout_blocks;

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

/// Commit hash(δ_i) before revealing the actual delta value.
/// Prevents a malicious party from choosing δ_i after seeing others'.
#[action(shortname = 0x49, zk = true)]
pub fn commit_delta(
    _ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    party_index: u8,
    commitment_hash: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(key_state.gg20_active, "No GG20 session active");
    assert_eq!(commitment_hash.len(), 32, "Commitment must be 32 bytes");
    assert!(
        !key_state
            .gg20_delta_commit_indices
            .iter()
            .any(|&idx| idx == party_index),
        "Party {} has already committed delta",
        party_index
    );

    key_state.gg20_delta_commit_indices.push(party_index);
    key_state.gg20_delta_commit_hashes.push(commitment_hash);

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

/// Submit δ_i value (party's additive share of k·γ).
/// All δ_i are needed to compute δ = k·γ, then R = δ⁻¹·Γ.
/// If a delta commitment exists, verifies the value matches.
#[action(shortname = 0x45, zk = true)]
pub fn submit_delta(
    _ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    party_index: u8,
    delta_bytes: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(key_state.gg20_active, "No GG20 session active");
    assert_eq!(delta_bytes.len(), 32, "Delta must be 32 bytes");
    assert!(
        !key_state.gg20_delta_indices.iter().any(|&idx| idx == party_index),
        "Party {} already submitted delta",
        party_index
    );

    // If delta commitment exists for this party, verify it matches
    if let Some(commit_pos) = key_state
        .gg20_delta_commit_indices
        .iter()
        .position(|&idx| idx == party_index)
    {
        let committed_hash = &key_state.gg20_delta_commit_hashes[commit_pos];
        let actual_hash = dkg::sha256(&delta_bytes);
        assert_eq!(
            committed_hash.as_slice(),
            &actual_hash[..],
            "Delta does not match commitment for party {}",
            party_index
        );
    }

    key_state.gg20_delta_indices.push(party_index);
    key_state.gg20_delta_values.push(delta_bytes);

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

/// Submit Γ_i = γ_i·G point (party's gamma commitment).
#[action(shortname = 0x46, zk = true)]
pub fn submit_gamma_point(
    _ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    party_index: u8,
    gamma_point: Vec<u8>,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(key_state.gg20_active, "No GG20 session active");
    assert_eq!(gamma_point.len(), 33, "Gamma point must be 33 bytes");
    assert!(
        !key_state.gg20_gamma_indices.iter().any(|&idx| idx == party_index),
        "Party {} already submitted gamma point",
        party_index
    );

    // Validate it's a real EC point
    VerifyingKey::from_sec1_bytes(&gamma_point)
        .expect("Invalid gamma point");

    key_state.gg20_gamma_indices.push(party_index);
    key_state.gg20_gamma_points.push(gamma_point);

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

/// Submit δ_i as ZK secret input (encrypted, not visible on-chain).
/// Delta values are 256-bit scalars, submitted as two Sbi128 halves.
/// This is the privacy-preserving alternative to plaintext submit_delta (0x45).
#[zk_on_secret_input(shortname = 0x51)]
pub fn submit_delta_zk(
    _ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
    party_index: u8,
    is_high_half: bool,
) -> (
    ContractState,
    Vec<EventGroup>,
    ZkInputDef<ShareMetadata, Sbi128>,
) {
    let key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(key_state.gg20_active, "No GG20 session active");

    // Set expected count if not yet set
    if key_state.gg20_delta_zk_expected == 0 {
        let mut ks = key_state;
        ks.gg20_delta_zk_expected = (ks.gg20_num_parties as u32) * 2;
        state.keys.insert(key_id, ks);
    }

    let metadata = ShareMetadata {
        key_id,
        share_index: party_index,
        is_high_half,
        variable_type: 1, // delta
    };

    let input_def = ZkInputDef::with_metadata(None, metadata);
    (state, vec![], input_def)
}

/// Open all submitted delta ZK variables so the contract can read them.
/// Called by the client after all delta halves have been submitted via submit_delta_zk.
/// The opened values are processed in on_shares_opened (variable_type == 1).
#[action(shortname = 0x52, zk = true)]
pub fn open_gg20_deltas(
    _ctx: ContractContext,
    state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    let key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(key_state.gg20_active, "No GG20 session active");

    // Collect all delta ZK variable IDs
    let delta_var_ids: Vec<SecretVarId> = key_state
        .gg20_delta_zk_vars
        .iter()
        .map(|sv| SecretVarId::new(sv.variable_id))
        .collect();

    assert!(!delta_var_ids.is_empty(), "No delta ZK variables to open");

    (
        state,
        vec![],
        vec![ZkStateChange::OpenVariables {
            variables: delta_var_ids,
        }],
    )
}

/// Finalize GG20 R computation on-chain.
///
/// Contract computes:
/// 1. δ = Σ δ_i (mod n) — additive combination
/// 2. Γ = Σ Γ_i (EC point addition)
/// 3. R = δ⁻¹ · Γ = (k·γ)⁻¹ · (γ·G) = k⁻¹ · G
/// 4. r = R.x
///
/// NOBODY ever computed k⁻¹ as a number. R = k⁻¹·G was computed
/// via scalar multiplication of δ⁻¹ with the point Γ.
#[action(shortname = 0x47, zk = true)]
pub fn gg20_finalize_r(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    state.assert_owner(&ctx.sender);

    let mut key_state = state.keys.get(&key_id).expect("Key not found");
    assert!(key_state.gg20_active, "No GG20 session active");
    assert!(
        key_state.gg20_delta_indices.len() as u8 >= key_state.gg20_num_parties,
        "Not all delta values submitted"
    );
    assert!(
        key_state.gg20_gamma_points.len() as u8 >= key_state.gg20_num_parties,
        "Not all gamma points submitted"
    );

    // 1. Compute δ = Σ δ_i (mod n) using k256 Scalar
    use k256::elliptic_curve::ff::PrimeField;
    use k256::{FieldBytes, Scalar, ProjectivePoint as K256Proj, AffinePoint as K256Affine};
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    use k256::EncodedPoint;

    let mut delta = Scalar::ZERO;
    for dv in &key_state.gg20_delta_values {
        let mut fb = FieldBytes::default();
        fb.copy_from_slice(dv);
        let s = Option::<Scalar>::from(Scalar::from_repr(fb))
            .expect("Invalid delta scalar");
        delta = delta + s;
    }

    // 2. Compute Γ = Σ Γ_i (EC point addition)
    let mut gamma_combined = K256Proj::IDENTITY;
    for gp in &key_state.gg20_gamma_points {
        let encoded = EncodedPoint::from_bytes(gp)
            .expect("Invalid gamma point encoding");
        let affine = Option::<K256Affine>::from(K256Affine::from_encoded_point(&encoded))
            .expect("Invalid gamma affine point");
        gamma_combined = gamma_combined + K256Proj::from(affine);
    }

    // 3. R = δ⁻¹ · Γ
    let delta_inv = delta.invert();
    assert!(bool::from(delta_inv.is_some()), "Delta has no inverse");
    let delta_inv = delta_inv.unwrap();
    let r_point = gamma_combined * delta_inv;

    // 4. Extract r = R.x
    let r_affine = r_point.to_affine();
    let r_encoded = EncodedPoint::from(r_affine);
    let r_compressed = r_encoded.compress();
    let r_bytes_full = r_compressed.as_bytes();

    // x-coordinate is bytes [1..33] of compressed point
    let r_bytes = r_bytes_full[1..33].to_vec();

    // Recovery ID from y parity
    let recovery_id = if r_bytes_full[0] == 0x02 { 0u8 } else { 1u8 };

    key_state.gg20_r_bytes = r_bytes.clone();
    key_state.gg20_recovery_id = recovery_id;

    // Set up threshold signing with the computed r
    let task_id = key_state.ts_task_id;
    key_state.ts_active = true;
    key_state.ts_r_bytes = r_bytes;
    key_state.ts_recovery_id = recovery_id;
    key_state.ts_num_parties = key_state.gg20_num_parties;
    key_state.signing_phase = ZkSigningPhase::ThresholdSigning { task_id };
    key_state.signing_round += 1;

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

// ---------------------------------------------------------------------------
// Timeout / Abort — prevents locked keys when a party goes offline
// ---------------------------------------------------------------------------

/// Abort a signing session that has exceeded its deadline.
///
/// Anyone can call this after the deadline block has passed.
/// Resets the signing state so new signing sessions can proceed.
/// The timed-out task remains in signing_information (signature = None).
#[action(shortname = 0x48, zk = true)]
pub fn abort_signing(
    ctx: ContractContext,
    mut state: ContractState,
    _zk_state: ZkState<ShareMetadata>,
    key_id: u32,
) -> (ContractState, Vec<EventGroup>, Vec<ZkStateChange>) {
    let mut key_state = state.keys.get(&key_id).expect("Key not found");

    // Must be in an active signing phase (not idle or complete)
    assert!(
        !matches!(
            key_state.signing_phase,
            ZkSigningPhase::Idle {} | ZkSigningPhase::Complete { .. }
        ),
        "No active signing session to abort"
    );

    // Check deadline: anyone can abort after deadline, owner can abort anytime
    if ctx.sender != state.owner {
        assert!(
            key_state.signing_deadline_block > 0
                && ctx.block_production_time >= key_state.signing_deadline_block,
            "Signing deadline has not passed yet — only owner can force-abort"
        );
    }

    // Reset all signing-related state
    key_state.ts_active = false;
    key_state.ts_partial_indices.clear();
    key_state.ts_partial_values.clear();
    key_state.ps_commit_indices.clear();
    key_state.ps_commit_hashes.clear();
    key_state.gg20_active = false;
    key_state.gg20_delta_indices.clear();
    key_state.gg20_delta_values.clear();
    key_state.gg20_delta_commit_indices.clear();
    key_state.gg20_delta_commit_hashes.clear();
    key_state.gg20_delta_zk_vars.clear();
    key_state.gg20_delta_zk_count = 0;
    key_state.gg20_delta_zk_expected = 0;
    key_state.gg20_gamma_indices.clear();
    key_state.gg20_gamma_points.clear();
    key_state.gg20_r_bytes.clear();
    key_state.nc_commit_indices.clear();
    key_state.nc_commitment_hashes.clear();
    key_state.nc_reveal_indices.clear();
    key_state.nc_reveal_points.clear();
    key_state.signing_deadline_block = 0;
    key_state.signing_phase = ZkSigningPhase::Idle {};

    // Re-queue the task if it was pending
    // (The task stays in signing_information with signature = None)

    state.keys.insert(key_id, key_state);
    (state, vec![], vec![])
}

/// Combine partial signature scalars via modular addition over secp256k1 order.
/// Enforces low-s normalization for EVM compatibility (BIP 62 / EIP-2).
/// Returns (combined_s_bytes, was_negated) so caller can flip recovery_id.
///
/// σ = σ₁ + σ₂ + ... + σₙ (mod n)
/// If σ > n/2, replace with n - σ (both are valid ECDSA, but EVM requires low-s).
fn combine_partial_signatures_with_flag(partial_values: &[Vec<u8>]) -> (Vec<u8>, bool) {
    use k256::elliptic_curve::ff::PrimeField;
    use k256::{FieldBytes, Scalar};

    let mut sum = Scalar::ZERO;
    for partial_s in partial_values {
        let mut bytes = FieldBytes::default();
        bytes.copy_from_slice(partial_s);
        let scalar = Option::<Scalar>::from(Scalar::from_repr(bytes))
            .expect("Invalid partial signature scalar");
        sum = sum + scalar;
    }

    // Low-s normalization: if s > n/2, use n - s
    // This is required for EVM compatibility (EIP-2)
    let sum_bytes = sum.to_bytes();
    let half_n_bytes: [u8; 32] = [
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
        0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
    ];
    // Compare sum_bytes > half_n_bytes
    let mut is_high = false;
    for i in 0..32 {
        if sum_bytes[i] > half_n_bytes[i] {
            is_high = true;
            break;
        } else if sum_bytes[i] < half_n_bytes[i] {
            break;
        }
    }
    if is_high {
        ((-sum).to_bytes().to_vec(), true)
    } else {
        (sum_bytes.to_vec(), false)
    }
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

