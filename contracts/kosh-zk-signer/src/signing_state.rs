//! ZK-aware signing state machine types.
//!
//! Adapted from kosh-mpc-signer-v2's signing_orchestration, but designed for
//! Shamir-split key storage on ZK nodes instead of plain engine commitments.

use create_type_spec_derive::CreateTypeSpec;
use pbc_contract_common::address::Address;
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
    /// 0 = key_share, 1 = delta_value, 2 = kinv (k⁻¹ for ZK partial sig)
    pub variable_type: u8,
}

/// A pending signing request.
#[derive(ReadWriteState, ReadWriteRPC, CreateTypeSpec, Clone)]
pub struct SignRequest {
    /// Unique task ID for this signing operation.
    pub task_id: u32,
    /// The 32-byte message hash to sign (e.g., keccak256 of EVM tx).
    pub message_hash: Vec<u8>,
    /// Transaction type tag (UTF-8). Empty = no policy applies.
    pub tx_tag: Vec<u8>,
    /// Policy ID resolved from tx_tag at queue time. 0 = no policy constraint.
    pub policy_id: u32,
    /// Effective minimum signer count resolved at queue time.
    pub min_signers: u8,
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

    // --- Session isolation (Protection 5) ---

    /// Auto-incrementing signing session ID. Prevents nonce reuse across sessions.
    pub signing_session_id: u64,

    // --- Schnorr proof fields (Protection 3) ---

    /// DKG: slope commitments C_i1 = a_i·G (parallel with dkg_commit_indices).
    pub dkg_slope_commitments: Vec<Vec<u8>>,
    /// DKG: Schnorr proof R points (parallel with dkg_commit_indices).
    pub dkg_schnorr_r_points: Vec<Vec<u8>>,
    /// DKG: Schnorr proof z values (parallel with dkg_commit_indices).
    pub dkg_schnorr_z_values: Vec<Vec<u8>>,

    // --- Paillier key registration (Protection 2) ---

    /// Party indices that have registered Paillier keys.
    pub paillier_key_indices: Vec<u8>,
    /// Paillier public key modulus N for each registered party (256+ bytes each).
    pub paillier_keys: Vec<Vec<u8>>,
    /// SHA-256 commitment to Paillier key proof (verified off-chain).
    pub paillier_proof_commitments: Vec<Vec<u8>>,

    // --- Identifiable abort / blame protocol (Protection 4) ---

    /// Whether blame mode is active (entered when combined sig fails verification).
    pub blame_active: bool,
    /// Blame: opened k_i values from each party (32 bytes each, parallel with blame_indices).
    pub blame_k_indices: Vec<u8>,
    pub blame_k_openings: Vec<Vec<u8>>,
    /// Blame: opened γ_i values from each party (32 bytes each, parallel with blame_indices).
    pub blame_gamma_indices: Vec<u8>,
    pub blame_gamma_openings: Vec<Vec<u8>>,
    /// Block deadline for blame submissions.
    pub blame_deadline_block: i64,

    // --- Key refresh (Protection 7) ---

    /// Whether a key refresh is in progress.
    pub refresh_active: bool,
    /// Refresh: slope commitment D_i1 = b_i·G from each party (parallel with refresh_indices).
    pub refresh_indices: Vec<u8>,
    pub refresh_slope_commitments: Vec<Vec<u8>>,

    // --- Key recovery (Protection 8) ---

    /// Whether a key recovery is in progress.
    pub recovery_active: bool,
    /// Recovery: which party was lost.
    pub recovery_lost_party: u8,
    /// Recovery: commitments from surviving parties (parallel with recovery_indices).
    pub recovery_indices: Vec<u8>,
    pub recovery_c0_commitments: Vec<Vec<u8>>,
    pub recovery_c1_commitments: Vec<Vec<u8>>,

    // --- Policy / RBAC (flattened — no nested Vec<CustomStruct>) ---

    /// Policy IDs (parallel with all other policy_* fields below).
    pub policy_ids: Vec<u32>,
    /// Policy human-readable names (UTF-8 bytes, parallel with policy_ids).
    pub policy_names: Vec<Vec<u8>>,
    /// Transaction tags each policy applies to (UTF-8 bytes, parallel with policy_ids).
    pub policy_tags: Vec<Vec<u8>>,
    /// Mandatory party indices (1-based) for each policy (parallel with policy_ids).
    pub policy_mandatory_parties: Vec<Vec<u8>>,
    /// Minimum number of parties required per policy (0 = use global threshold).
    pub policy_min_thresholds: Vec<u8>,
    /// Auto-incrementing policy ID counter (starts at 1).
    pub next_policy_id: u32,

    // --- Party address binding (flattened) ---

    /// Party indices that have registered wallet addresses (parallel with party_addr_values).
    pub party_addr_indices: Vec<u8>,
    /// Wallet addresses for each registered party (parallel with party_addr_indices).
    pub party_addr_values: Vec<Address>,

    // --- GG20 active signing parties ---

    /// Party indices participating in the current GG20 signing session.
    /// Set by gg20_start_signing. Used to validate submissions.
    pub gg20_signing_parties: Vec<u8>,
    /// Active GG20 signing task ID. Zero when no GG20 session is active.
    pub gg20_task_id: u32,
    /// Policy ID bound to the active GG20 session. Zero means no policy.
    pub gg20_policy_id: u32,
    /// Required parties for the active GG20 session.
    pub gg20_required_parties: Vec<u8>,
    /// Effective minimum signer count for the active GG20 session.
    pub gg20_min_signers: u8,

    // --- PQC approval session (contract-authoritative approval gate) ---

    /// Whether a PQC approval session is active.
    pub pqc_approval_active: bool,
    /// Whether the active PQC approval session has been finalized.
    pub pqc_approval_approved: bool,
    /// Task ID bound to the active PQC approval session.
    pub pqc_approval_task_id: u32,
    /// Message hash bound to the active PQC approval session.
    pub pqc_approval_message_hash: Vec<u8>,
    /// tx_tag bound to the active PQC approval session.
    pub pqc_approval_tx_tag: Vec<u8>,
    /// Signing subset proposed for the active PQC approval session.
    pub pqc_approval_signing_parties: Vec<u8>,
    /// Required parties derived from policy for the active PQC approval session.
    pub pqc_approval_required_parties: Vec<u8>,
    /// Effective minimum signer count for the active PQC approval session.
    pub pqc_approval_min_signers: u8,
    /// Deterministic challenge bound to the approval session.
    pub pqc_approval_challenge: Vec<u8>,
    /// Block deadline for collecting PQC approvals.
    pub pqc_approval_deadline_block: i64,
    /// Parties that have submitted contract-bound approval digests.
    pub pqc_approval_received_parties: Vec<u8>,
    /// Approval digests parallel with pqc_approval_received_parties.
    pub pqc_approval_received_hashes: Vec<Vec<u8>>,

    // --- ZK partial signature computation (on ZK nodes) ---

    /// Whether a ZK partial sig session is active.
    pub zk_psig_active: bool,
    /// ZK variable IDs for k⁻¹ halves submitted via submit_kinv_zk (0x53).
    pub zk_psig_kinv_vars: Vec<StoredShareVar>,
    /// Number of k⁻¹ ZK variables received so far.
    pub zk_psig_kinv_count: u32,
    /// Expected k⁻¹ ZK variables (num_parties * 2 for hi/lo halves).
    pub zk_psig_kinv_expected: u32,
    /// Party indices for which ZK partial σ_i results have been returned
    /// (parallel with zk_psig_result_hi_bytes and zk_psig_result_lo_bytes).
    pub zk_psig_result_indices: Vec<u8>,
    /// High 128-bit halves of the ZK-computed partial signatures (16 bytes each).
    pub zk_psig_result_hi_bytes: Vec<Vec<u8>>,
    /// Low 128-bit halves of the ZK-computed partial signatures (16 bytes each).
    pub zk_psig_result_lo_bytes: Vec<Vec<u8>>,

    // --- PQC public key registry (quantum-safe identity) ---

    /// Party indices that have registered Dilithium (ML-DSA-65) public keys.
    pub dilithium_pubkey_indices: Vec<u8>,
    /// Dilithium public keys (1952 bytes each for ML-DSA-65, parallel with indices).
    pub dilithium_pubkeys: Vec<Vec<u8>>,
    /// Party indices that have registered Kyber (ML-KEM-768) public keys.
    pub kyber_pubkey_indices: Vec<u8>,
    /// Kyber public keys (1184 bytes each for ML-KEM-768, parallel with indices).
    pub kyber_pubkeys: Vec<Vec<u8>>,
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
            signing_session_id: 0,
            dkg_slope_commitments: Vec::new(),
            dkg_schnorr_r_points: Vec::new(),
            dkg_schnorr_z_values: Vec::new(),
            paillier_key_indices: Vec::new(),
            paillier_keys: Vec::new(),
            paillier_proof_commitments: Vec::new(),
            blame_active: false,
            blame_k_indices: Vec::new(),
            blame_k_openings: Vec::new(),
            blame_gamma_indices: Vec::new(),
            blame_gamma_openings: Vec::new(),
            blame_deadline_block: 0,
            refresh_active: false,
            refresh_indices: Vec::new(),
            refresh_slope_commitments: Vec::new(),
            recovery_active: false,
            recovery_lost_party: 0,
            recovery_indices: Vec::new(),
            recovery_c0_commitments: Vec::new(),
            recovery_c1_commitments: Vec::new(),
            policy_ids: Vec::new(),
            policy_names: Vec::new(),
            policy_tags: Vec::new(),
            policy_mandatory_parties: Vec::new(),
            policy_min_thresholds: Vec::new(),
            next_policy_id: 1,
            party_addr_indices: Vec::new(),
            party_addr_values: Vec::new(),
            gg20_signing_parties: Vec::new(),
            gg20_task_id: 0,
            gg20_policy_id: 0,
            gg20_required_parties: Vec::new(),
            gg20_min_signers: 0,
            pqc_approval_active: false,
            pqc_approval_approved: false,
            pqc_approval_task_id: 0,
            pqc_approval_message_hash: Vec::new(),
            pqc_approval_tx_tag: Vec::new(),
            pqc_approval_signing_parties: Vec::new(),
            pqc_approval_required_parties: Vec::new(),
            pqc_approval_min_signers: 0,
            pqc_approval_challenge: Vec::new(),
            pqc_approval_deadline_block: 0,
            pqc_approval_received_parties: Vec::new(),
            pqc_approval_received_hashes: Vec::new(),
            zk_psig_active: false,
            zk_psig_kinv_vars: Vec::new(),
            zk_psig_kinv_count: 0,
            zk_psig_kinv_expected: 0,
            zk_psig_result_indices: Vec::new(),
            zk_psig_result_hi_bytes: Vec::new(),
            zk_psig_result_lo_bytes: Vec::new(),
            dilithium_pubkey_indices: Vec::new(),
            dilithium_pubkeys: Vec::new(),
            kyber_pubkey_indices: Vec::new(),
            kyber_pubkeys: Vec::new(),
        }
    }

    /// Check if key generation is complete.
    pub fn is_key_generated(&self) -> bool {
        matches!(self.keygen_phase, ZkKeyGenPhase::Complete {})
    }

    /// Queue a message hash for signing. Returns the signing task ID.
    pub fn queue_signing(
        &mut self,
        message_hash: Vec<u8>,
        tx_tag: Vec<u8>,
        policy_id: u32,
        min_signers: u8,
    ) -> u32 {
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
            tx_tag,
            policy_id,
            min_signers,
        });

        if matches!(self.signing_phase, ZkSigningPhase::Idle {}) {
            self.start_next_signing();
        }

        task_id
    }

    /// Find the index into the policy_* vecs for the given tx_tag. Returns None if not found.
    pub fn find_policy_index_for_tag(&self, tag: &[u8]) -> Option<usize> {
        if tag.is_empty() {
            return None;
        }
        self.policy_tags.iter().position(|t| t.as_slice() == tag)
    }

    /// Look up the policy_id for a tx_tag. Returns 0 if no policy matches.
    pub fn resolve_policy_id_for_tag(&self, tag: &[u8]) -> u32 {
        self.find_policy_index_for_tag(tag)
            .map(|i| self.policy_ids[i])
            .unwrap_or(0)
    }

    /// Get the wallet address bound to a party index, if any.
    pub fn get_party_address(&self, party_index: u8) -> Option<&Address> {
        self.party_addr_indices
            .iter()
            .position(|&idx| idx == party_index)
            .map(|i| &self.party_addr_values[i])
    }

    pub fn has_registered_address(&self, party_index: u8) -> bool {
        self.party_addr_indices.contains(&party_index)
    }

    pub fn has_registered_dilithium_pubkey(&self, party_index: u8) -> bool {
        self.dilithium_pubkey_indices.contains(&party_index)
    }

    pub fn has_registered_kyber_pubkey(&self, party_index: u8) -> bool {
        self.kyber_pubkey_indices.contains(&party_index)
    }

    pub fn is_party_ready_for_signing(&self, party_index: u8) -> bool {
        self.has_registered_address(party_index)
            && self.has_registered_dilithium_pubkey(party_index)
            && self.has_registered_kyber_pubkey(party_index)
    }

    pub fn assert_all_parties_ready_for_signing(&self) {
        for party_index in 1..=self.num_shares {
            assert!(
                self.is_party_ready_for_signing(party_index),
                "Party {} is not operationally ready: address, Dilithium key, and Kyber key must all be registered",
                party_index
            );
        }
    }

    pub fn is_active_signing_party(&self, party_index: u8) -> bool {
        self.gg20_signing_parties.contains(&party_index)
    }

    pub fn is_pqc_approval_party(&self, party_index: u8) -> bool {
        self.pqc_approval_signing_parties.contains(&party_index)
    }

    pub fn reset_pqc_approval_session(&mut self) {
        self.pqc_approval_active = false;
        self.pqc_approval_approved = false;
        self.pqc_approval_task_id = 0;
        self.pqc_approval_message_hash.clear();
        self.pqc_approval_tx_tag.clear();
        self.pqc_approval_signing_parties.clear();
        self.pqc_approval_required_parties.clear();
        self.pqc_approval_min_signers = 0;
        self.pqc_approval_challenge.clear();
        self.pqc_approval_deadline_block = 0;
        self.pqc_approval_received_parties.clear();
        self.pqc_approval_received_hashes.clear();
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
