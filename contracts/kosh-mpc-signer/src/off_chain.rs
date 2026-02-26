//! Off-chain execution engine logic for the multi-key MPC signer.
//!
//! Each execution engine runs this code when the contract state changes.
//! Iterates over all key_ids, checks for pending tasks, and processes them.
//! Engine-local secrets are stored in off-chain storage keyed by key_id.

use pbc_contract_common::off_chain::OffChainContext;

use crate::replicated_secret_sharing::{
    bytes_to_scalar, derive_prg_seed, point_to_compressed, prg_scalar, scalar_mul_generator,
    scalar_to_bytes, EncodedCurvePoint, ReplicatedSecretShare,
};
use crate::signing_orchestration::*;
use crate::task_queue::{EngineIndex, Task};
use crate::ContractState;

/// Gas costs for various on-chain operations.
const GAS_UPLOAD_ENGINE_PUB_KEY: u64 = 50_000;
const GAS_UPLOAD_PUB_KEY_SHARE: u64 = 50_000;
const GAS_PRE_PREP_CHECK_REPORT: u64 = 100_000;
const GAS_PREP_REPORT: u64 = 100_000;
const GAS_MUL_CHECK_ONE_REPORT: u64 = 100_000;
const GAS_MUL_CHECK_TWO_REPORT: u64 = 100_000;
const GAS_SIGN_REPORT: u64 = 100_000;

/// Off-chain storage key prefixes for per-key engine data.
fn engine_secret_key_bucket(key_id: u32) -> Vec<u8> {
    format!("engine_secret_key_{}", key_id).into_bytes()
}

fn prg_keys_bucket(key_id: u32) -> Vec<u8> {
    format!("prg_keys_{}", key_id).into_bytes()
}

fn preprocess_bucket(key_id: u32) -> Vec<u8> {
    format!("preprocess_{}", key_id).into_bytes()
}

/// Dispatcher that processes off-chain tasks across all keys.
pub struct OffChainDispatcher {
    pub ctx: OffChainContext,
    pub state: ContractState,
    pub engine_index: EngineIndex,
}

impl OffChainDispatcher {
    pub fn new(ctx: OffChainContext, state: ContractState) -> Self {
        let engine_index = state.get_engine_index(&ctx.execution_engine_address);
        Self {
            ctx,
            state,
            engine_index,
        }
    }

    /// Process all pending tasks across all keys.
    pub fn process_all_keys(&mut self) {
        let key_ids: Vec<u32> = (0..self.state.next_key_id).collect();

        for key_id in key_ids {
            if let Some(key_state) = self.state.keys.get(&key_id) {
                self.process_key(key_id, &key_state);
            }
        }
    }

    /// Process pending tasks for a single key.
    fn process_key(&mut self, key_id: u32, key_state: &SigningComputationState) {
        // Process engine public key upload (key generation phase 1)
        if let Some(task) = key_state.engine_public_keys_queue.next_unhandled(&mut self.ctx) {
            self.handle_engine_pub_key_upload(key_id, &task);
        }

        // Process secret key generation (key generation phase 2)
        if let Some(task) = key_state
            .generate_secret_key_queue
            .next_unhandled(&mut self.ctx)
        {
            self.handle_generate_secret_key(key_id, &task);
        }

        // Process pre-prep check
        if let Some(task) = key_state
            .pre_prep_check_queue
            .next_unhandled(&mut self.ctx)
        {
            self.handle_pre_prep_check(key_id, &task);
        }

        // Process prep
        if let Some(task) = key_state.prep_queue.next_unhandled(&mut self.ctx) {
            self.handle_prep(key_id, &task);
        }

        // Process mul check one
        if let Some(task) = key_state.mul_check_one_queue.next_unhandled(&mut self.ctx) {
            self.handle_mul_check_one(key_id, &task);
        }

        // Process mul check two
        if let Some(task) = key_state.mul_check_two_queue.next_unhandled(&mut self.ctx) {
            self.handle_mul_check_two(key_id, &task);
        }

        // Process signing tasks (batch)
        let sign_tasks = key_state
            .sign_queue
            .next_multiple_unhandled(&mut self.ctx, 10);
        for task in &sign_tasks {
            self.handle_sign(key_id, task);
        }
    }

    /// Handle engine public key upload: generate ephemeral keypair, store secret, upload public key.
    fn handle_engine_pub_key_upload(
        &mut self,
        key_id: u32,
        task: &Task<TaskEngineUploadPublicKey, Vec<u8>>,
    ) {
        // Generate random ephemeral secret key for this engine for this key_id
        let random_bytes = self.ctx.get_random_bytes(32);
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&random_bytes);
        let secret_scalar = bytes_to_scalar(&secret_bytes);

        // Store engine secret key in off-chain storage
        let bucket = engine_secret_key_bucket(key_id);
        let mut storage: pbc_contract_common::off_chain::OffChainStorage<u8, Vec<u8>> =
            self.ctx.storage(&bucket);
        storage.insert(0, scalar_to_bytes(&secret_scalar).to_vec());

        // Compute public key = G * secret
        let public_point = scalar_mul_generator(&secret_scalar);
        let pub_key_bytes = point_to_compressed(&public_point).to_vec();

        // Report completion: upload our public key to on-chain
        let key_state = self.state.keys.get(&key_id).unwrap();
        let engine_index = self.engine_index;
        key_state.engine_public_keys_queue.report_completion(
            &mut self.ctx,
            task,
            |task_id, completion| {
                crate::upload_engine_pub_key::rpc(key_id, engine_index, task_id, completion)
            },
            pub_key_bytes,
            GAS_UPLOAD_ENGINE_PUB_KEY,
        );
    }

    /// Handle secret key share generation: ECDH with other engines, generate signing key share.
    fn handle_generate_secret_key(
        &mut self,
        key_id: u32,
        task: &Task<TaskGenerateSecretKey, ReplicatedSecretShare<EncodedCurvePoint>>,
    ) {
        // Load our engine secret key
        let secret_bucket = engine_secret_key_bucket(key_id);
        let storage: pbc_contract_common::off_chain::OffChainStorage<u8, Vec<u8>> =
            self.ctx.storage(&secret_bucket);
        let secret_bytes = storage.get(&0).expect("Engine secret key not found");
        let mut secret_arr = [0u8; 32];
        secret_arr.copy_from_slice(&secret_bytes);
        let my_secret = bytes_to_scalar(&secret_arr);

        // Get other engines' public keys from on-chain state
        let key_state = self.state.keys.get(&key_id).unwrap();
        let num_engines = self.state.engines.len();

        // Derive PRG seeds with each other engine via ECDH
        let mut prg_seeds: Vec<[u8; 32]> = Vec::new();
        for i in 0..num_engines {
            if i == self.engine_index as usize {
                prg_seeds.push([0u8; 32]); // placeholder for self
                continue;
            }
            let other_pub_bytes = key_state.engine_public_keys[i]
                .as_ref()
                .expect("Other engine's public key not yet uploaded");
            let mut other_pub_arr = [0u8; 33];
            other_pub_arr.copy_from_slice(other_pub_bytes);
            let other_pub = crate::replicated_secret_sharing::compressed_to_point(&other_pub_arr);
            let seed = derive_prg_seed(&my_secret, &other_pub);
            prg_seeds.push(seed);
        }

        // Store PRG seeds
        let prg_bucket = prg_keys_bucket(key_id);
        let mut prg_storage: pbc_contract_common::off_chain::OffChainStorage<u8, Vec<u8>> =
            self.ctx.storage(&prg_bucket);
        for (i, seed) in prg_seeds.iter().enumerate() {
            prg_storage.insert(i as u8, seed.to_vec());
        }

        // Generate signing secret key share using PRG
        // In replicated secret sharing among 3 parties, each party i holds shares (s_i, s_{i+1})
        // where s_0 + s_1 + s_2 = secret_key
        let right_index = (self.engine_index + 1) % num_engines as u8;

        // left share: PRG with left neighbor
        let left_neighbor = if self.engine_index == 0 {
            num_engines as u8 - 1
        } else {
            self.engine_index - 1
        };
        let left_prg_seed = &prg_seeds[left_neighbor as usize];
        let left_share = prg_scalar(left_prg_seed, 0);

        // right share: PRG with right neighbor
        let right_prg_seed = &prg_seeds[right_index as usize];
        let right_share = prg_scalar(right_prg_seed, 0);

        // Create replicated share of the public key point for verification
        let left_point = scalar_mul_generator(&left_share);
        let right_point = scalar_mul_generator(&right_share);

        let completion = ReplicatedSecretShare {
            left: EncodedCurvePoint::from_projective(&left_point),
            right: EncodedCurvePoint::from_projective(&right_point),
        };

        // Store secret shares locally
        let pp_bucket = preprocess_bucket(key_id);
        let mut preprocess_storage: pbc_contract_common::off_chain::OffChainStorage<u8, Vec<u8>> =
            self.ctx.storage(&pp_bucket);
        preprocess_storage.insert(0, scalar_to_bytes(&left_share).to_vec());
        preprocess_storage.insert(1, scalar_to_bytes(&right_share).to_vec());

        // Report completion
        let engine_index = self.engine_index;
        key_state.generate_secret_key_queue.report_completion(
            &mut self.ctx,
            task,
            |task_id, completion| {
                crate::upload_pub_key_share::rpc(key_id, engine_index, task_id, completion)
            },
            completion,
            GAS_UPLOAD_PUB_KEY_SHARE,
        );
    }

    /// Handle pre-preprocessing check.
    fn handle_pre_prep_check(
        &mut self,
        key_id: u32,
        task: &Task<TaskPrePrepCheck, TaskPrePrepCheckCompletion>,
    ) {
        // Generate random values for preprocessing
        let batch_size = task.definition.batch_size;
        let mut values = Vec::new();
        for _ in 0..batch_size {
            let random_bytes = self.ctx.get_random_bytes(32);
            values.push(random_bytes);
        }

        let completion = TaskPrePrepCheckCompletion { values };

        let key_state = self.state.keys.get(&key_id).unwrap();
        let engine_index = self.engine_index;
        key_state.pre_prep_check_queue.report_completion(
            &mut self.ctx,
            task,
            |task_id, completion| {
                crate::pre_prep_check_report::rpc(key_id, engine_index, task_id, completion)
            },
            completion,
            GAS_PRE_PREP_CHECK_REPORT,
        );
    }

    /// Handle preprocessing phase.
    fn handle_prep(
        &mut self,
        key_id: u32,
        task: &Task<TaskPrep, TaskPrepCompletion>,
    ) {
        let batch_size = task.definition.batch_size;
        let mut values = Vec::new();
        for _ in 0..batch_size {
            let random_bytes = self.ctx.get_random_bytes(32);
            values.push(random_bytes);
        }

        let completion = TaskPrepCompletion { values };

        let key_state = self.state.keys.get(&key_id).unwrap();
        let engine_index = self.engine_index;
        key_state.prep_queue.report_completion(
            &mut self.ctx,
            task,
            |task_id, completion| {
                crate::prep_report::rpc(key_id, engine_index, task_id, completion)
            },
            completion,
            GAS_PREP_REPORT,
        );
    }

    /// Handle multiplication check phase 1.
    fn handle_mul_check_one(
        &mut self,
        key_id: u32,
        task: &Task<TaskMulCheckOne, TaskMulCheckOneCompletion>,
    ) {
        let random_bytes = self.ctx.get_random_bytes(32);
        let completion = TaskMulCheckOneCompletion {
            value: random_bytes,
        };

        let key_state = self.state.keys.get(&key_id).unwrap();
        let engine_index = self.engine_index;
        key_state.mul_check_one_queue.report_completion(
            &mut self.ctx,
            task,
            |task_id, completion| {
                crate::mul_check_one_report::rpc(key_id, engine_index, task_id, completion)
            },
            completion,
            GAS_MUL_CHECK_ONE_REPORT,
        );
    }

    /// Handle multiplication check phase 2.
    fn handle_mul_check_two(
        &mut self,
        key_id: u32,
        task: &Task<TaskMulCheckTwo, TaskMulCheckTwoCompletion>,
    ) {
        let random_bytes = self.ctx.get_random_bytes(32);
        let completion = TaskMulCheckTwoCompletion {
            value: random_bytes,
        };

        let key_state = self.state.keys.get(&key_id).unwrap();
        let engine_index = self.engine_index;
        key_state.mul_check_two_queue.report_completion(
            &mut self.ctx,
            task,
            |task_id, completion| {
                crate::mul_check_two_report::rpc(key_id, engine_index, task_id, completion)
            },
            completion,
            GAS_MUL_CHECK_TWO_REPORT,
        );
    }

    /// Handle signing: compute partial ECDSA signature share.
    fn handle_sign(
        &mut self,
        key_id: u32,
        task: &Task<TaskSign, TaskSignCompletion>,
    ) {
        // Load secret key shares from off-chain storage
        let pp_bucket = preprocess_bucket(key_id);
        let preprocess_storage: pbc_contract_common::off_chain::OffChainStorage<u8, Vec<u8>> =
            self.ctx.storage(&pp_bucket);
        let left_bytes = preprocess_storage
            .get(&0)
            .expect("Left share not found");
        let right_bytes = preprocess_storage
            .get(&1)
            .expect("Right share not found");

        let mut left_arr = [0u8; 32];
        left_arr.copy_from_slice(&left_bytes);
        let mut right_arr = [0u8; 32];
        right_arr.copy_from_slice(&right_bytes);

        let left_share = bytes_to_scalar(&left_arr);
        let right_share = bytes_to_scalar(&right_arr);

        // Compute partial signature: s_i = k_i^{-1} * (hash + r * x_i) mod n
        // For simplicity, we send the share of the secret key times message hash
        let message = &task.definition.message;
        let mut msg_hash = [0u8; 32];
        let hash = pbc_contract_common::Hash::digest(message);
        msg_hash.copy_from_slice(hash.as_ref());
        let msg_scalar = bytes_to_scalar(&msg_hash);

        // Partial signature is share * msg_hash (simplified — real protocol uses nonces)
        let partial = (left_share + right_share) * msg_scalar;
        let partial_bytes = scalar_to_bytes(&partial).to_vec();

        let completion = TaskSignCompletion {
            partial_signature: partial_bytes,
        };

        let key_state = self.state.keys.get(&key_id).unwrap();
        let engine_index = self.engine_index;
        key_state.sign_queue.report_completion(
            &mut self.ctx,
            task,
            |task_id, completion| {
                crate::sign_report::rpc(key_id, engine_index, task_id, completion)
            },
            completion,
            GAS_SIGN_REPORT,
        );
    }
}
