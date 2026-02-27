//! Off-chain execution engine logic for k256 ECDSA signing.
//!
//! Simplified single-signer approach for testnet:
//! - Engine 0 generates a random secp256k1 key pair
//! - Engine 0 directly signs messages (no threshold protocol)
//! - All engines store the full secret key (no secret sharing)
//!
//! This avoids the WASM32 compilation blocker from cggmp21 -> gmp-mpfr-sys (C library).
//! Production should use real threshold ECDSA with WASM-compatible dependencies.

use k256::ecdsa::SigningKey;
use pbc_contract_common::off_chain::OffChainContext;

use crate::signing_orchestration::*;
use crate::task_queue::EngineIndex;
use crate::ContractState;

/// Gas costs for on-chain operations.
const GAS_DISTRIBUTE_SHARES: u64 = 500_000;
const GAS_CONFIRM_SHARE: u64 = 50_000;
const GAS_SIGNING_COMPLETE: u64 = 100_000;

/// Off-chain storage key for the engine's secret key.
fn secret_key_bucket(key_id: u32) -> Vec<u8> {
    format!("k256_secret_key_{}", key_id).into_bytes()
}

/// Off-chain storage key for tracking if we've handled keygen for this key.
fn keygen_handled_bucket(key_id: u32) -> Vec<u8> {
    format!("k256_keygen_done_{}", key_id).into_bytes()
}

/// Off-chain storage for signing task tracking.
fn signing_handled_bucket(key_id: u32) -> Vec<u8> {
    format!("k256_signing_handled_{}", key_id).into_bytes()
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
        match &key_state.keygen_phase {
            KeyGenPhase::WaitingForDealer {} => {
                if self.engine_index == 0 {
                    self.handle_keygen(key_id, key_state);
                }
            }
            KeyGenPhase::SharesDistributed {} => {
                self.handle_load_key_share(key_id, key_state);
            }
            KeyGenPhase::Complete {} => {
                if let SigningPhase::InProgress { task_id, .. } = &key_state.signing_phase {
                    if self.engine_index == 0 {
                        self.handle_signing(key_id, key_state, *task_id);
                    }
                }
            }
        }
    }

    /// Engine 0: Generate a random secp256k1 key pair and distribute.
    fn handle_keygen(&mut self, key_id: u32, key_state: &SigningComputationState) {
        // Check if we already handled this
        let handled_bucket = keygen_handled_bucket(key_id);
        let handled_storage: pbc_contract_common::off_chain::OffChainStorage<u8, u8> =
            self.ctx.storage(&handled_bucket);
        if handled_storage.get(&0).is_some() {
            return;
        }

        // Generate random 32 bytes for the secret key
        let random_bytes = self.ctx.get_random_bytes(32);
        let signing_key = SigningKey::from_slice(&random_bytes)
            .expect("Failed to create signing key from random bytes");

        let secret_key_bytes = signing_key.to_bytes().to_vec();

        // Compute compressed public key (33 bytes)
        let verifying_key = signing_key.verifying_key();
        let public_key_point = verifying_key.to_encoded_point(true);
        let public_key_bytes = public_key_point.as_bytes().to_vec();

        // Store secret key in off-chain storage
        let sk_bucket = secret_key_bucket(key_id);
        let mut sk_storage: pbc_contract_common::off_chain::OffChainStorage<u8, Vec<u8>> =
            self.ctx.storage(&sk_bucket);
        sk_storage.insert(0, secret_key_bytes.clone());

        // For testnet: all engines get the full secret key as their "share"
        let num_engines = key_state.num_engines as usize;
        let shares: Vec<Vec<u8>> = (0..num_engines)
            .map(|_| secret_key_bytes.clone())
            .collect();

        // Post shares + public key on-chain
        let rpc = crate::distribute_key_shares::rpc(key_id, shares, public_key_bytes);
        self.ctx
            .send_transaction_to_contract(rpc, GAS_DISTRIBUTE_SHARES);

        // Mark as handled
        let mut handled_storage: pbc_contract_common::off_chain::OffChainStorage<u8, u8> =
            self.ctx.storage(&handled_bucket);
        handled_storage.insert(0, 1);
    }

    /// Non-dealer engines: Load secret key from on-chain state into off-chain storage.
    fn handle_load_key_share(&mut self, key_id: u32, key_state: &SigningComputationState) {
        // Check if we already loaded
        let handled_bucket = keygen_handled_bucket(key_id);
        let handled_storage: pbc_contract_common::off_chain::OffChainStorage<u8, u8> =
            self.ctx.storage(&handled_bucket);
        if handled_storage.get(&0).is_some() {
            return;
        }

        let idx = self.engine_index as usize;

        // Read our "share" (full secret key) from on-chain state
        let share_bytes = match &key_state.key_shares[idx] {
            Some(bytes) => bytes.clone(),
            None => return, // Share not yet available
        };

        // Store in off-chain storage
        let sk_bucket = secret_key_bucket(key_id);
        let mut sk_storage: pbc_contract_common::off_chain::OffChainStorage<u8, Vec<u8>> =
            self.ctx.storage(&sk_bucket);
        sk_storage.insert(0, share_bytes);

        // Confirm share loaded
        let engine_index = self.engine_index;
        let rpc = crate::confirm_key_share::rpc(key_id, engine_index);
        self.ctx
            .send_transaction_to_contract(rpc, GAS_CONFIRM_SHARE);

        // Mark as handled
        let mut handled_storage: pbc_contract_common::off_chain::OffChainStorage<u8, u8> =
            self.ctx.storage(&handled_bucket);
        handled_storage.insert(0, 1);
    }

    /// Engine 0: Sign message hash directly with k256.
    fn handle_signing(
        &mut self,
        key_id: u32,
        key_state: &SigningComputationState,
        task_id: u32,
    ) {
        // Check if we already handled this task
        let handled_bucket = signing_handled_bucket(key_id);
        let handled_storage: pbc_contract_common::off_chain::OffChainStorage<u32, u8> =
            self.ctx.storage(&handled_bucket);
        if handled_storage.get(&task_id).is_some() {
            return;
        }

        // Load secret key from off-chain storage
        let sk_bucket = secret_key_bucket(key_id);
        let sk_storage: pbc_contract_common::off_chain::OffChainStorage<u8, Vec<u8>> =
            self.ctx.storage(&sk_bucket);
        let secret_key_bytes = match sk_storage.get(&0) {
            Some(bytes) => bytes,
            None => return,
        };

        let signing_key = match SigningKey::from_slice(&secret_key_bytes) {
            Ok(sk) => sk,
            Err(_) => return,
        };

        // Get the signing request
        let sign_request = match key_state.pending_sign_requests.first() {
            Some(req) if req.task_id == task_id => req,
            _ => return,
        };

        // Sign the 32-byte prehash directly
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(&sign_request.message_hash)
            .expect("ECDSA signing failed");

        // Build 65-byte signature: r (32) || s (32) || v (1)
        let sig_bytes = signature.to_bytes();
        let mut result = sig_bytes.to_vec();
        result.push(recovery_id.to_byte());

        // Post signature on-chain
        let engine_index = self.engine_index;
        let rpc = crate::signing_complete::rpc(key_id, engine_index, task_id, result);
        self.ctx
            .send_transaction_to_contract(rpc, GAS_SIGNING_COMPLETE);

        // Mark as handled
        let mut handled_storage: pbc_contract_common::off_chain::OffChainStorage<u32, u8> =
            self.ctx.storage(&handled_bucket);
        handled_storage.insert(task_id, 1);
    }
}
