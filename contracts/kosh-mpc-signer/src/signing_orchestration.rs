//! Per-key signing computation state for cggmp21-based threshold ECDSA.
//!
//! Keygen uses trusted dealer (engine 0 generates all shares, posts on-chain).
//! Signing uses real cggmp21 threshold ECDSA via on-chain round message board.
//!
//! NOTE: Trusted dealer keygen posts key shares on-chain in the clear.
//! This is acceptable for testnet prototyping only. Production should use
//! the full CGGMP21 DKG protocol or encrypted share distribution.

use create_type_spec_derive::CreateTypeSpec;
use pbc_contract_common::avl_tree_map::AvlTreeMap;
use read_write_rpc_derive::ReadWriteRPC;
use read_write_state_derive::ReadWriteState;

use crate::task_queue::EngineIndex;

/// Key generation phase tracking.
#[derive(ReadWriteState, ReadWriteRPC, CreateTypeSpec, Clone, Debug)]
pub enum KeyGenPhase {
    /// Waiting for engine 0 (trusted dealer) to generate and distribute shares.
    #[discriminant(0)]
    WaitingForDealer {},
    /// Shares distributed on-chain, engines loading their shares.
    #[discriminant(1)]
    SharesDistributed {},
    /// Key generation complete, public key available.
    #[discriminant(2)]
    Complete {},
}

/// Signing phase tracking.
#[derive(ReadWriteState, ReadWriteRPC, CreateTypeSpec, Clone, Debug)]
pub enum SigningPhase {
    /// No signing in progress.
    #[discriminant(0)]
    Idle {},
    /// Signing protocol running for a specific task.
    #[discriminant(1)]
    InProgress { task_id: u32, round: u16 },
    /// Signing complete for a task.
    #[discriminant(2)]
    Complete { task_id: u32 },
}

/// A serialized cggmp21 protocol message posted by an engine.
#[derive(ReadWriteState, ReadWriteRPC, CreateTypeSpec, Clone)]
pub struct RoundMessage {
    /// Which engine posted this message.
    pub sender: u8,
    /// Protocol round number.
    pub round: u16,
    /// Serialized cggmp21 protocol message (serde_json bytes).
    pub data: Vec<u8>,
    /// Whether this is a broadcast (true) or P2P to a specific engine (false).
    pub is_broadcast: bool,
    /// Target engine index for P2P messages (ignored for broadcast).
    pub recipient: u8,
}

/// A pending signing request.
#[derive(ReadWriteState, ReadWriteRPC, CreateTypeSpec, Clone)]
pub struct SignRequest {
    /// Unique task ID for this signing operation.
    pub task_id: u32,
    /// The 32-byte message hash to sign (e.g., keccak256 of EVM tx).
    pub message_hash: Vec<u8>,
}

/// Information about a completed signing operation.
#[derive(ReadWriteState, ReadWriteRPC, CreateTypeSpec, Clone)]
pub struct SigningInformation {
    /// The message hash that was signed.
    pub message_hash: Vec<u8>,
    /// The ECDSA signature bytes (64 bytes: r || s), if complete.
    pub signature: Option<Vec<u8>>,
    /// Recovery ID (0 or 1) for EVM v-value derivation.
    pub recovery_id: u8,
    /// Whether the signature has been verified against the public key.
    pub verified: bool,
}

/// Tracks which engines have posted for the current round.
#[derive(ReadWriteState, CreateTypeSpec, Clone)]
pub struct RoundTracker {
    pub posted: Vec<bool>,
    pub num_engines: u8,
}

impl RoundTracker {
    pub fn new(num_engines: u8) -> Self {
        let mut posted = Vec::new();
        for _ in 0..num_engines {
            posted.push(false);
        }
        Self {
            posted,
            num_engines,
        }
    }

    pub fn mark_posted(&mut self, engine_index: u8) {
        assert!(
            (engine_index as usize) < self.posted.len(),
            "Invalid engine index"
        );
        assert!(
            !self.posted[engine_index as usize],
            "Engine {} already posted for this round",
            engine_index
        );
        self.posted[engine_index as usize] = true;
    }

    pub fn all_posted(&self) -> bool {
        self.posted.iter().all(|p| *p)
    }

    /// Check if the first `count` engines have posted.
    pub fn threshold_posted(&self, count: u16) -> bool {
        self.posted.iter().take(count as usize).all(|p| *p)
    }

    pub fn reset(&mut self) {
        for p in self.posted.iter_mut() {
            *p = false;
        }
    }
}

/// The full MPC signing state for a single key.
#[derive(ReadWriteState, CreateTypeSpec)]
pub struct SigningComputationState {
    /// The assembled public key (33 bytes compressed secp256k1), set after keygen.
    pub public_key: Option<Vec<u8>>,

    /// Current key generation phase.
    pub keygen_phase: KeyGenPhase,

    /// Current signing phase.
    pub signing_phase: SigningPhase,

    /// Signing round tracker.
    pub signing_round_tracker: RoundTracker,

    /// Serialized key shares distributed by trusted dealer.
    /// Index = engine_index, value = serde_json bytes of KeyShare<Secp256k1, SecurityLevel128>.
    /// WARNING: These are in the clear on-chain — testnet only!
    pub key_shares: Vec<Option<Vec<u8>>>,

    /// Tracker: which engines have confirmed loading their key share.
    pub share_confirmations: Vec<bool>,

    /// Signing round messages for the current signing task.
    pub signing_messages: Vec<RoundMessage>,

    /// Completed signatures keyed by task_id.
    pub signing_information: AvlTreeMap<u32, SigningInformation>,

    /// Next signing task ID.
    pub next_signing_task_id: u32,

    /// Pending signing requests (FIFO queue).
    pub pending_sign_requests: Vec<SignRequest>,

    /// Number of engines in this signing group.
    pub num_engines: u8,

    /// Threshold for signing (e.g., 2 for 2-of-3).
    pub threshold: u16,
}

impl SigningComputationState {
    /// Create a new SigningComputationState for a key.
    pub fn new(num_engines: EngineIndex, threshold: u16) -> Self {
        let mut key_shares = Vec::new();
        let mut share_confirmations = Vec::new();
        for _ in 0..num_engines {
            key_shares.push(None);
            share_confirmations.push(false);
        }

        Self {
            public_key: None,
            keygen_phase: KeyGenPhase::WaitingForDealer {},
            signing_phase: SigningPhase::Idle {},
            signing_round_tracker: RoundTracker::new(num_engines),
            key_shares,
            share_confirmations,
            signing_messages: Vec::new(),
            signing_information: AvlTreeMap::new(),
            next_signing_task_id: 0,
            pending_sign_requests: Vec::new(),
            num_engines,
            threshold,
        }
    }

    /// Check if key generation is complete.
    pub fn is_key_generated(&self) -> bool {
        matches!(self.keygen_phase, KeyGenPhase::Complete {})
    }

    /// Queue a message hash for signing. Returns the signing task ID.
    pub fn queue_signing(&mut self, message_hash: Vec<u8>) -> u32 {
        assert!(
            message_hash.len() == 32,
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

        // If no signing is in progress, start this one
        if matches!(self.signing_phase, SigningPhase::Idle {}) {
            self.start_next_signing();
        }

        task_id
    }

    /// Start the next pending signing request.
    pub fn start_next_signing(&mut self) {
        if let Some(request) = self.pending_sign_requests.first() {
            let task_id = request.task_id;
            self.signing_phase = SigningPhase::InProgress { task_id, round: 0 };
            self.signing_round_tracker.reset();
            self.signing_messages.clear();
        }
    }

    /// Advance the signing round after participating engines have posted.
    pub fn advance_signing_round(&mut self) {
        if let SigningPhase::InProgress { task_id, round } = &self.signing_phase {
            self.signing_phase = SigningPhase::InProgress {
                task_id: *task_id,
                round: round + 1,
            };
            self.signing_round_tracker.reset();
        }
    }
}
