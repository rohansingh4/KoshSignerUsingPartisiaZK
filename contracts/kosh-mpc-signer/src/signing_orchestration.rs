//! Per-key signing computation state and on-chain orchestration.
//!
//! Manages the MPC protocol state machine for a single key:
//! - Key generation (engine pub key exchange, secret key share generation, public key assembly)
//! - Preprocessing (nonce/commitment generation in batches)
//! - Signing (partial signature assembly)

use create_type_spec_derive::CreateTypeSpec;
use pbc_contract_common::avl_tree_map::AvlTreeMap;
use read_write_rpc_derive::ReadWriteRPC;
use read_write_state_derive::ReadWriteState;

use crate::replicated_secret_sharing::{EncodedCurvePoint, ReplicatedSecretShare};
use crate::task_queue::{EngineIndex, TaskId, TaskQueue};

/// Configuration for preprocessing batch sizes.
#[derive(ReadWriteState, ReadWriteRPC, CreateTypeSpec, Clone)]
pub struct PreprocessConfig {
    /// Number of signing operations to preprocess.
    pub num_to_preprocess: u32,
    /// Batch size for preprocessing tasks.
    pub batch_size: u32,
}

/// Status of the key generation process.
#[derive(ReadWriteState, ReadWriteRPC, CreateTypeSpec, Clone, Debug)]
pub enum KeyGenStatus {
    /// Waiting for engine public keys to be uploaded.
    #[discriminant(0)]
    WaitingForEngineKeys {},
    /// Engine keys received, generating secret key shares.
    #[discriminant(1)]
    GeneratingSecretKey {},
    /// Secret key shares generated, assembling public key.
    #[discriminant(2)]
    AssemblingPublicKey {},
    /// Key generation complete, public key available.
    #[discriminant(3)]
    Complete {},
}

/// Status of preprocessing.
#[derive(ReadWriteState, ReadWriteRPC, CreateTypeSpec, Clone, Debug)]
pub enum PreprocessStatus {
    #[discriminant(0)]
    Idle {},
    #[discriminant(1)]
    CalculatingPreprocess {},
    #[discriminant(2)]
    SuccessPreprocess {},
}

/// Information about a completed signing operation.
#[derive(ReadWriteState, ReadWriteRPC, CreateTypeSpec, Clone)]
pub struct SigningInformation {
    /// The message that was signed.
    pub message: Vec<u8>,
    /// The 65-byte ECDSA signature (recovery_id || R || S), if complete.
    pub signature: Option<Vec<u8>>,
    /// Whether the signature has been verified against the public key.
    pub verified: bool,
}

/// Preprocessing material for a single signing operation.
#[derive(ReadWriteState, ReadWriteRPC, CreateTypeSpec, Clone)]
pub struct PreProcessInformation {
    /// Preprocess ID.
    pub id: u32,
    /// Whether this material has been consumed for a signing operation.
    pub used: bool,
}

/// Preprocess state tracking.
#[derive(ReadWriteState, CreateTypeSpec, Clone)]
pub struct PreprocessState {
    /// Configuration for batch sizes.
    pub config: PreprocessConfig,
    /// Current preprocessing status.
    pub status: PreprocessStatus,
    /// Counter for next preprocess batch.
    pub next_preprocess_id: u32,
    /// Number of preprocessing rounds completed.
    pub completed_count: u32,
    /// Number of available (unused) preprocessing materials.
    pub available_count: u32,
}

// -- Task definition types for each queue --

/// Task: Engine uploads its ephemeral public key.
#[derive(ReadWriteState, CreateTypeSpec, Clone)]
pub struct TaskEngineUploadPublicKey {
    pub engine_index: EngineIndex,
}

/// Task: Engine generates its secret key share.
#[derive(ReadWriteState, CreateTypeSpec, Clone)]
pub struct TaskGenerateSecretKey {
    pub engine_index: EngineIndex,
}

/// Task: Preprocessing check phase.
#[derive(ReadWriteState, CreateTypeSpec, Clone)]
pub struct TaskPrePrepCheck {
    pub batch_id: u32,
    pub batch_size: u32,
}

/// Completion data for pre-prep check.
#[derive(ReadWriteState, ReadWriteRPC, CreateTypeSpec, Clone)]
pub struct TaskPrePrepCheckCompletion {
    pub values: Vec<Vec<u8>>,
}

/// Task: Preprocessing phase.
#[derive(ReadWriteState, CreateTypeSpec, Clone)]
pub struct TaskPrep {
    pub batch_id: u32,
    pub batch_size: u32,
}

/// Completion data for preprocessing.
#[derive(ReadWriteState, ReadWriteRPC, CreateTypeSpec, Clone)]
pub struct TaskPrepCompletion {
    pub values: Vec<Vec<u8>>,
}

/// Task: Multiplication check phase 1.
#[derive(ReadWriteState, CreateTypeSpec, Clone)]
pub struct TaskMulCheckOne {
    pub batch_id: u32,
}

/// Completion data for mul check 1.
#[derive(ReadWriteState, ReadWriteRPC, CreateTypeSpec, Clone)]
pub struct TaskMulCheckOneCompletion {
    pub value: Vec<u8>,
}

/// Task: Multiplication check phase 2.
#[derive(ReadWriteState, CreateTypeSpec, Clone)]
pub struct TaskMulCheckTwo {
    pub batch_id: u32,
}

/// Completion data for mul check 2.
#[derive(ReadWriteState, ReadWriteRPC, CreateTypeSpec, Clone)]
pub struct TaskMulCheckTwoCompletion {
    pub value: Vec<u8>,
}

/// Task: Sign a message using preprocessed material.
#[derive(ReadWriteState, CreateTypeSpec, Clone)]
pub struct TaskSign {
    pub signing_task_id: TaskId,
    pub message: Vec<u8>,
    pub preprocess_id: u32,
}

/// Completion data for a signing operation.
#[derive(ReadWriteState, ReadWriteRPC, CreateTypeSpec, Clone)]
pub struct TaskSignCompletion {
    pub partial_signature: Vec<u8>,
}

/// The full MPC signing state for a single key.
///
/// Each key_id maps to one of these in the contract's AvlTreeMap.
#[derive(ReadWriteState, CreateTypeSpec)]
pub struct SigningComputationState {
    /// The assembled public key (set after key generation completes).
    pub public_key: Option<Vec<u8>>,

    /// Key generation status.
    pub key_gen_status: KeyGenStatus,

    /// Engine ephemeral public keys (collected during key gen).
    pub engine_public_keys: Vec<Option<Vec<u8>>>,

    /// Public key shares from each engine (collected during key gen).
    pub public_key_shares: Vec<Option<EncodedCurvePoint>>,

    /// Completed signing operations.
    pub signing_information: AvlTreeMap<TaskId, SigningInformation>,

    /// Next signing task ID.
    pub next_signing_task_id: TaskId,

    /// Preprocessing state.
    pub preprocess_state: PreprocessState,

    /// Preprocessing information.
    pub preprocess_information: AvlTreeMap<u32, PreProcessInformation>,

    // -- Task queues for the MPC protocol pipeline --
    /// Queue: Engine uploads ephemeral public keys.
    pub engine_public_keys_queue: TaskQueue<TaskEngineUploadPublicKey, Vec<u8>>,

    /// Queue: Engines generate and upload secret key shares.
    pub generate_secret_key_queue:
        TaskQueue<TaskGenerateSecretKey, ReplicatedSecretShare<EncodedCurvePoint>>,

    /// Queue: Pre-prep check phase.
    pub pre_prep_check_queue: TaskQueue<TaskPrePrepCheck, TaskPrePrepCheckCompletion>,

    /// Queue: Preprocessing phase.
    pub prep_queue: TaskQueue<TaskPrep, TaskPrepCompletion>,

    /// Queue: Multiplication check phase 1.
    pub mul_check_one_queue: TaskQueue<TaskMulCheckOne, TaskMulCheckOneCompletion>,

    /// Queue: Multiplication check phase 2.
    pub mul_check_two_queue: TaskQueue<TaskMulCheckTwo, TaskMulCheckTwoCompletion>,

    /// Queue: Signing phase.
    pub sign_queue: TaskQueue<TaskSign, TaskSignCompletion>,
}

impl SigningComputationState {
    /// Create a new SigningComputationState for a key with the given number of engines.
    pub fn new(key_id: u32, num_engines: EngineIndex, preprocess_config: PreprocessConfig) -> Self {
        let prefix = format!("key_{}", key_id);

        let mut engine_public_keys = Vec::new();
        let mut public_key_shares = Vec::new();
        for _ in 0..num_engines {
            engine_public_keys.push(None);
            public_key_shares.push(None);
        }

        Self {
            public_key: None,
            key_gen_status: KeyGenStatus::WaitingForEngineKeys {},
            engine_public_keys,
            public_key_shares,
            signing_information: AvlTreeMap::new(),
            next_signing_task_id: 0,
            preprocess_state: PreprocessState {
                config: preprocess_config,
                status: PreprocessStatus::Idle {},
                next_preprocess_id: 0,
                completed_count: 0,
                available_count: 0,
            },
            preprocess_information: AvlTreeMap::new(),
            engine_public_keys_queue: TaskQueue::new(
                format!("{}_engine_pub_keys", prefix).into_bytes(),
                num_engines,
            ),
            generate_secret_key_queue: TaskQueue::new(
                format!("{}_gen_secret_key", prefix).into_bytes(),
                num_engines,
            ),
            pre_prep_check_queue: TaskQueue::new(
                format!("{}_pre_prep_check", prefix).into_bytes(),
                num_engines,
            ),
            prep_queue: TaskQueue::new(
                format!("{}_prep", prefix).into_bytes(),
                num_engines,
            ),
            mul_check_one_queue: TaskQueue::new(
                format!("{}_mul_check_one", prefix).into_bytes(),
                num_engines,
            ),
            mul_check_two_queue: TaskQueue::new(
                format!("{}_mul_check_two", prefix).into_bytes(),
                num_engines,
            ),
            sign_queue: TaskQueue::new(
                format!("{}_sign", prefix).into_bytes(),
                num_engines,
            ),
        }
    }

    /// Check if key generation is complete.
    pub fn is_key_generated(&self) -> bool {
        matches!(self.key_gen_status, KeyGenStatus::Complete {})
    }

    /// Queue a message for signing. Returns the signing task ID.
    pub fn queue_signing(&mut self, message: Vec<u8>) -> TaskId {
        let signing_task_id = self.next_signing_task_id;
        self.next_signing_task_id += 1;

        // Store signing info (signature will be filled in later)
        self.signing_information.insert(
            signing_task_id,
            SigningInformation {
                message: message.clone(),
                signature: None,
                verified: false,
            },
        );

        // Allocate preprocessing material
        let preprocess_id = self.allocate_preprocess();

        // Push to sign queue
        self.sign_queue.push_task(TaskSign {
            signing_task_id,
            message,
            preprocess_id,
        });

        signing_task_id
    }

    /// Allocate a preprocess slot, returning its ID.
    fn allocate_preprocess(&mut self) -> u32 {
        assert!(
            self.preprocess_state.available_count > 0,
            "No preprocessing material available. Wait for preprocessing to complete."
        );
        self.preprocess_state.available_count -= 1;
        let id = self.preprocess_state.next_preprocess_id;
        self.preprocess_state.next_preprocess_id += 1;
        id
    }

    /// Start the preprocessing pipeline for this key.
    pub fn start_preprocessing(&mut self) {
        let config = self.preprocess_state.config.clone();
        self.preprocess_state.status = PreprocessStatus::CalculatingPreprocess {};

        let num_batches = (config.num_to_preprocess + config.batch_size - 1) / config.batch_size;
        for batch_id in 0..num_batches {
            let actual_size = if batch_id == num_batches - 1 {
                let remainder = config.num_to_preprocess % config.batch_size;
                if remainder == 0 {
                    config.batch_size
                } else {
                    remainder
                }
            } else {
                config.batch_size
            };

            self.pre_prep_check_queue.push_task(TaskPrePrepCheck {
                batch_id,
                batch_size: actual_size,
            });
        }
    }

    /// Record that a preprocessing batch completed, updating available count.
    pub fn mark_preprocess_batch_complete(&mut self, batch_size: u32) {
        self.preprocess_state.completed_count += 1;
        self.preprocess_state.available_count += batch_size;

        let config = self.preprocess_state.config.clone();
        let num_batches = (config.num_to_preprocess + config.batch_size - 1) / config.batch_size;
        if self.preprocess_state.completed_count >= num_batches {
            self.preprocess_state.status = PreprocessStatus::SuccessPreprocess {};
        }
    }
}
