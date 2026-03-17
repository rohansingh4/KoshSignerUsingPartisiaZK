//! ZK-aware signing state machine types.
//!
//! Adapted from kosh-mpc-signer-v2's signing_orchestration, but designed for
//! Shamir-split key storage on ZK nodes instead of plain engine commitments.

use create_type_spec_derive::CreateTypeSpec;
use pbc_contract_common::avl_tree_map::AvlTreeMap;
use read_write_rpc_derive::ReadWriteRPC;
use read_write_state_derive::ReadWriteState;

/// Key generation phase for ZK-based Shamir key splitting.
#[derive(ReadWriteState, ReadWriteRPC, CreateTypeSpec, Clone, Debug)]
pub enum ZkKeyGenPhase {
    /// Waiting for Engine 0 to generate keypair and submit shares.
    #[discriminant(0)]
    WaitingForDealer {},
    /// Shares are being submitted as ZK secret inputs.
    #[discriminant(1)]
    SubmittingShares {},
    /// All shares stored on ZK nodes, public key available.
    #[discriminant(2)]
    Complete {},
    /// DKG commit phase: parties are submitting commitment hashes.
    #[discriminant(3)]
    DkgCommitting {},
    /// DKG reveal phase: parties are revealing their public key shares.
    #[discriminant(4)]
    DkgRevealing {},
    /// DKG finalized: combined public key computed, awaiting ZK secret share inputs.
    #[discriminant(5)]
    DkgFinalized {},
}

/// Signing phase for ZK-based reconstruction and signing.
#[derive(ReadWriteState, ReadWriteRPC, CreateTypeSpec, Clone, Debug)]
pub enum ZkSigningPhase {
    /// No signing in progress.
    #[discriminant(0)]
    Idle {},
    /// Threshold ZK shares being opened for reconstruction.
    #[discriminant(1)]
    ReconstructingKey { task_id: u32 },
    /// Shares opened, waiting for Engine 0 to sign.
    #[discriminant(2)]
    Signing { task_id: u32 },
    /// Signing complete for a task.
    #[discriminant(3)]
    Complete { task_id: u32 },
    /// Threshold ECDSA: collecting partial signatures (key NEVER reconstructed).
    #[discriminant(4)]
    ThresholdSigning { task_id: u32 },
    /// Distributed nonce: parties committing hash(R_i).
    #[discriminant(5)]
    NonceCommitting { task_id: u32 },
    /// Distributed nonce: parties revealing R_i points.
    #[discriminant(6)]
    NonceRevealing { task_id: u32 },
}

/// Metadata attached to each ZK secret variable (share half).
///
/// Each Shamir share (256-bit scalar) is stored as two Sbi128 variables:
/// one for the high 128 bits and one for the low 128 bits.
#[derive(ReadWriteState, ReadWriteRPC, CreateTypeSpec, Clone)]
pub struct ShareMetadata {
    /// Which key this share belongs to.
    pub key_id: u32,
    /// 1-based share index (x-coordinate in Shamir polynomial).
    pub share_index: u8,
    /// Whether this is the high half (true) or low half (false) of the 256-bit share.
    pub is_high_half: bool,
    /// 0 = key_share, 1 = delta_value
    pub variable_type: u8,
}

/// A pending signing request.
#[derive(ReadWriteState, ReadWriteRPC, CreateTypeSpec, Clone)]
pub struct SignRequest {
    /// Unique task ID for this signing operation.
    pub task_id: u32,
    /// The 32-byte message hash to sign (e.g., keccak256 of EVM tx).
    pub message_hash: Vec<u8>,
}

/// Information about a completed (or in-progress) signing operation.
#[derive(ReadWriteState, ReadWriteRPC, CreateTypeSpec, Clone)]
pub struct SigningInformation {
    /// The message hash that was signed.
    pub message_hash: Vec<u8>,
    /// The ECDSA signature bytes (65 bytes: r || s || v), if complete.
    pub signature: Option<Vec<u8>>,
    /// Recovery ID (0 or 1) for EVM v-value derivation.
    pub recovery_id: u8,
    /// Whether the signature has been verified against the public key.
    pub verified: bool,
}

/// A share that has been opened from ZK storage for reconstruction.
///
/// The high and low bytes together form the 256-bit Shamir share value.
#[derive(ReadWriteState, ReadWriteRPC, CreateTypeSpec, Clone)]
pub struct OpenedShare {
    /// 1-based share index (x-coordinate in Shamir polynomial).
    pub share_index: u8,
    /// High 128 bits of the share value (16 bytes, big-endian).
    pub high_bytes: Vec<u8>,
    /// Low 128 bits of the share value (16 bytes, big-endian).
    pub low_bytes: Vec<u8>,
}

/// Tracks a ZK variable ID along with its share metadata.
#[derive(ReadWriteState, ReadWriteRPC, CreateTypeSpec, Clone)]
pub struct StoredShareVar {
    /// The ZK secret variable ID (SecretVarId.raw_id value).
    pub variable_id: u32,
    /// Which key this variable belongs to.
    pub key_id: u32,
    /// 1-based share index.
    pub share_index: u8,
    /// Whether this is the high half.
    pub is_high_half: bool,
}

/// The full ZK signing state for a single key.
///
/// DKG and threshold signing fields are flattened into this struct
/// (no nested custom structs in Vecs) to work with the Partisia ABI parser.
#[derive(ReadWriteState, CreateTypeSpec)]
pub struct ZkKeyState {
    /// The compressed public key (33 bytes secp256k1), set after keygen.
    pub public_key: Option<Vec<u8>>,

    /// Current key generation phase.
    pub keygen_phase: ZkKeyGenPhase,

    /// Current signing phase.
    pub signing_phase: ZkSigningPhase,

    /// ZK variable IDs for stored share halves.
    pub share_variables: Vec<StoredShareVar>,

    /// Total expected share variables (2 * num_shares: high + low for each).
    pub expected_share_count: u32,

    /// Number of share variables successfully stored in ZK.
    pub shares_submitted: u32,

    /// Shamir threshold (t in t-of-n).
    pub threshold: u16,

    /// Total number of Shamir shares (n).
    pub num_shares: u8,

    /// Next signing task ID to assign.
    pub next_signing_task_id: u32,

    /// Pending signing requests (FIFO queue).
    pub pending_sign_requests: Vec<SignRequest>,

    /// Completed signatures keyed by task_id.
    pub signing_information: AvlTreeMap<u32, SigningInformation>,

    /// Temporarily stores opened share values for Engine 0 reconstruction.
    /// Cleared after signing is complete.
    pub opened_shares: Vec<OpenedShare>,

    // --- DKG fields (flattened) ---

    /// Number of parties expected in the DKG ceremony.
    pub dkg_num_parties: u8,
    /// DKG commitment party indices (parallel with dkg_commitment_hashes).
    pub dkg_commit_indices: Vec<u8>,
    /// DKG commitment hashes — SHA-256 of each party's compressed public key share.
    /// Each entry is 32 bytes. Parallel with dkg_commit_indices.
    pub dkg_commitment_hashes: Vec<Vec<u8>>,
    /// DKG reveal party indices (parallel with dkg_reveal_pubkeys).
    pub dkg_reveal_indices: Vec<u8>,
    /// DKG revealed public key shares (33 bytes compressed secp256k1 each).
    /// Parallel with dkg_reveal_indices.
    pub dkg_reveal_pubkeys: Vec<Vec<u8>>,

    // --- Threshold signing fields (flattened) ---

    /// Whether a threshold signing session is active.
    pub ts_active: bool,
    /// Threshold signing: the signing task ID.
    pub ts_task_id: u32,
    /// Threshold signing: nonce point R's x-coordinate (32 bytes).
    pub ts_r_bytes: Vec<u8>,
    /// Threshold signing: ECDSA recovery ID (0 or 1).
    pub ts_recovery_id: u8,
    /// Threshold signing: number of parties expected.
    pub ts_num_parties: u8,
    /// Threshold signing: party indices for submitted partials.
    /// Parallel with ts_partial_values.
    pub ts_partial_indices: Vec<u8>,
    /// Threshold signing: partial signature scalars (32 bytes each).
    /// Parallel with ts_partial_indices.
    pub ts_partial_values: Vec<Vec<u8>>,

    // --- Distributed nonce ceremony fields (flattened) ---

    /// Nonce ceremony: number of parties expected to contribute.
    pub nc_num_parties: u8,
    /// Nonce ceremony: which party index is coordinator this round (rotated).
    pub nc_coordinator: u8,
    /// Nonce ceremony: party indices that have committed hash(R_i).
    pub nc_commit_indices: Vec<u8>,
    /// Nonce ceremony: commitment hashes (SHA-256 of compressed R_i point).
    pub nc_commitment_hashes: Vec<Vec<u8>>,
    /// Nonce ceremony: party indices that have revealed R_i.
    pub nc_reveal_indices: Vec<u8>,
    /// Nonce ceremony: revealed R_i points (33 bytes compressed each).
    pub nc_reveal_points: Vec<Vec<u8>>,

    // --- Partial signature commitment fields (flattened) ---

    /// Partial commitment: party indices that have committed hash(σ_i).
    pub ps_commit_indices: Vec<u8>,
    /// Partial commitment: SHA-256 hashes of partial signatures.
    pub ps_commit_hashes: Vec<Vec<u8>>,

    /// Signing round counter (used for coordinator rotation).
    pub signing_round: u32,

    // --- GG20 fields (fully trustless signing) ---

    /// GG20: delta values δ_i submitted by each party (32 bytes each).
    pub gg20_delta_indices: Vec<u8>,
    /// GG20: delta values (parallel with gg20_delta_indices).
    pub gg20_delta_values: Vec<Vec<u8>>,
    /// GG20: gamma point party indices (parallel with gg20_gamma_points).
    pub gg20_gamma_indices: Vec<u8>,
    /// GG20: gamma points (compressed, 33 bytes each).
    pub gg20_gamma_points: Vec<Vec<u8>>,
    /// GG20: computed combined r bytes (set after finalize).
    pub gg20_r_bytes: Vec<u8>,
    /// GG20: computed recovery ID.
    pub gg20_recovery_id: u8,
    /// GG20: number of parties expected for this round.
    pub gg20_num_parties: u8,
    /// GG20: whether GG20 signing is active.
    pub gg20_active: bool,
    /// GG20: delta commitment indices (parties that committed hash(δ_i)).
    pub gg20_delta_commit_indices: Vec<u8>,
    /// GG20: delta commitment hashes (SHA-256 of δ_i bytes, parallel with indices).
    pub gg20_delta_commit_hashes: Vec<Vec<u8>>,

    /// GG20: ZK variable IDs for delta values (similar to share_variables for key shares).
    pub gg20_delta_zk_vars: Vec<StoredShareVar>,
    /// GG20: count of delta ZK variables submitted.
    pub gg20_delta_zk_count: u32,
    /// GG20: expected delta ZK variables (num_parties * 2 for high/low halves).
    pub gg20_delta_zk_expected: u32,

    // --- Timeout / Abort fields ---

    /// Block number by which the current signing round must complete.
    /// After this block, anyone can call abort to reset the signing state.
    pub signing_deadline_block: i64,
    /// Number of blocks allowed for a signing round (configurable, default 100 ~= 5 minutes).
    pub signing_timeout_blocks: i64,
}

impl ZkKeyState {
    /// Create a new ZkKeyState for a key with the given threshold parameters.
    pub fn new(threshold: u16, num_shares: u8) -> Self {
        Self {
            public_key: None,
            keygen_phase: ZkKeyGenPhase::WaitingForDealer {},
            signing_phase: ZkSigningPhase::Idle {},
            share_variables: Vec::new(),
            expected_share_count: (num_shares as u32) * 2,
            shares_submitted: 0,
            threshold,
            num_shares,
            next_signing_task_id: 0,
            pending_sign_requests: Vec::new(),
            signing_information: AvlTreeMap::new(),
            opened_shares: Vec::new(),
            dkg_num_parties: 0,
            dkg_commit_indices: Vec::new(),
            dkg_commitment_hashes: Vec::new(),
            dkg_reveal_indices: Vec::new(),
            dkg_reveal_pubkeys: Vec::new(),
            ts_active: false,
            ts_task_id: 0,
            ts_r_bytes: Vec::new(),
            ts_recovery_id: 0,
            ts_num_parties: 0,
            ts_partial_indices: Vec::new(),
            ts_partial_values: Vec::new(),
            nc_num_parties: 0,
            nc_coordinator: 0,
            nc_commit_indices: Vec::new(),
            nc_commitment_hashes: Vec::new(),
            nc_reveal_indices: Vec::new(),
            nc_reveal_points: Vec::new(),
            ps_commit_indices: Vec::new(),
            ps_commit_hashes: Vec::new(),
            signing_round: 0,
            gg20_delta_indices: Vec::new(),
            gg20_delta_values: Vec::new(),
            gg20_gamma_indices: Vec::new(),
            gg20_gamma_points: Vec::new(),
            gg20_r_bytes: Vec::new(),
            gg20_recovery_id: 0,
            gg20_num_parties: 0,
            gg20_active: false,
            gg20_delta_commit_indices: Vec::new(),
            gg20_delta_commit_hashes: Vec::new(),
            gg20_delta_zk_vars: Vec::new(),
            gg20_delta_zk_count: 0,
            gg20_delta_zk_expected: 0,
            signing_deadline_block: 0,
            signing_timeout_blocks: 100, // ~5 minutes on Partisia
        }
    }

    /// Check if key generation is complete.
    pub fn is_key_generated(&self) -> bool {
        matches!(self.keygen_phase, ZkKeyGenPhase::Complete {})
    }

    /// Queue a message hash for signing. Returns the signing task ID.
    pub fn queue_signing(&mut self, message_hash: Vec<u8>) -> u32 {
        assert_eq!(
            message_hash.len(),
            32,
            "Message hash must be exactly 32 bytes"
        );

        let task_id = self.next_signing_task_id;
        self.next_signing_task_id += 1;

        self.signing_information.insert(
            task_id,
            SigningInformation {
                message_hash: message_hash.clone(),
                signature: None,
                recovery_id: 0,
                verified: false,
            },
        );

        self.pending_sign_requests.push(SignRequest {
            task_id,
            message_hash,
        });

        if matches!(self.signing_phase, ZkSigningPhase::Idle {}) {
            self.start_next_signing();
        }

        task_id
    }

    /// Start the next pending signing request.
    pub fn start_next_signing(&mut self) {
        if let Some(request) = self.pending_sign_requests.first() {
            let task_id = request.task_id;
            self.signing_phase = ZkSigningPhase::ReconstructingKey { task_id };
        }
    }

    /// Get ZK variable IDs for threshold shares to open.
    pub fn get_threshold_variable_ids(&self) -> Vec<u32> {
        let mut var_ids = Vec::new();
        let mut seen_indices: Vec<u8> = Vec::new();

        for sv in &self.share_variables {
            if !seen_indices.contains(&sv.share_index)
                && seen_indices.len() < self.threshold as usize
            {
                seen_indices.push(sv.share_index);
            }
        }

        for sv in &self.share_variables {
            if seen_indices.contains(&sv.share_index) {
                var_ids.push(sv.variable_id);
            }
        }

        var_ids
    }
}
