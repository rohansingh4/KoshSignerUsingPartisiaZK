//! Off-chain execution engine logic for ZK Shamir ECDSA signing.
//!
//! Engine 0 (dealer) responsibilities:
//! 1. Keygen: Generate secp256k1 keypair, Shamir-split the private key,
//!    store shares in off-chain storage, post the public key on-chain.
//! 2. Signing: Reconstruct the private key from locally-stored Shamir shares
//!    via Lagrange interpolation, sign the message hash, and post the signature.
//!
//! ZK integration: Shares are also submitted as ZK secret inputs for secure
//! cluster-wide storage. When the ZK reconstruction path is used (via opened shares
//! in contract state), the off-chain engine reads those instead.

use k256::ecdsa::SigningKey;
use k256::elliptic_curve::ff::PrimeField;
use k256::{FieldBytes, Scalar};
use pbc_contract_common::off_chain::OffChainContext;

use crate::shamir;
use crate::signing_state::*;
use crate::ContractState;

/// Gas costs for on-chain operations.
const GAS_POST_PUBLIC_KEY: u64 = 200_000;
const GAS_REQUEST_RECONSTRUCTION: u64 = 200_000;
const GAS_SIGNING_COMPLETE: u64 = 100_000;
const GAS_CHECK_KEYGEN: u64 = 50_000;

/// Off-chain storage key for tracking keygen handled state.
fn keygen_handled_bucket(key_id: u32) -> Vec<u8> {
    format!("zk_keygen_done_{}", key_id).into_bytes()
}

/// Off-chain storage key for tracking reconstruction requests.
fn reconstruction_handled_bucket(key_id: u32) -> Vec<u8> {
    format!("zk_reconstruction_{}", key_id).into_bytes()
}

/// Off-chain storage key for tracking signing handled state.
fn signing_handled_bucket(key_id: u32) -> Vec<u8> {
    format!("zk_signing_done_{}", key_id).into_bytes()
}

/// Off-chain storage key for the keygen-complete callback check.
fn keygen_callback_bucket(key_id: u32) -> Vec<u8> {
    format!("zk_keygen_callback_{}", key_id).into_bytes()
}

/// Off-chain storage key for the secret key (Engine 0 only, backup).
fn secret_key_bucket(key_id: u32) -> Vec<u8> {
    format!("zk_secret_key_{}", key_id).into_bytes()
}

/// Dispatcher that processes off-chain tasks across all keys.
pub struct OffChainDispatcher {
    pub ctx: OffChainContext,
    pub state: ContractState,
    pub engine_index: u8,
}

impl OffChainDispatcher {
    pub fn new(ctx: OffChainContext, state: ContractState) -> Self {
        // ZK nodes run off-chain code; they may not be in our engine list.
        // Use engine_index 0 for any node (idempotent via storage flags).
        let engine_index = state
            .get_engine_index(&ctx.execution_engine_address)
            .unwrap_or(0);
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
    fn process_key(&mut self, key_id: u32, key_state: &ZkKeyState) {
        match &key_state.keygen_phase {
            ZkKeyGenPhase::WaitingForDealer {} => {
                if self.engine_index == 0 {
                    self.handle_keygen(key_id, key_state);
                }
            }
            ZkKeyGenPhase::SubmittingShares {} => {
                // Shares are being submitted via ZK; nothing to do off-chain.
            }
            ZkKeyGenPhase::Complete {} => {
                // Emit the vault callback if not yet done
                if self.engine_index == 0 {
                    self.maybe_emit_keygen_callback(key_id, key_state);
                }

                // Handle signing phases
                match &key_state.signing_phase {
                    ZkSigningPhase::ReconstructingKey { task_id } => {
                        if self.engine_index == 0 {
                            self.handle_request_reconstruction(key_id, *task_id);
                        }
                    }
                    ZkSigningPhase::Signing { task_id } => {
                        if self.engine_index == 0 {
                            self.handle_signing(key_id, key_state, *task_id);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Keygen: Generate key, Shamir split, store shares, post public key
    // -----------------------------------------------------------------------

    /// Engine 0: Generate keypair, Shamir-split, store in off-chain storage, post public key.
    fn handle_keygen(&mut self, key_id: u32, key_state: &ZkKeyState) {
        // Check if we already handled this
        let handled_bucket = keygen_handled_bucket(key_id);
        let handled_storage: pbc_contract_common::off_chain::OffChainStorage<u8, u8> =
            self.ctx.storage(&handled_bucket);
        if handled_storage.get(&0).is_some() {
            return;
        }

        // Step 1: Generate random 32 bytes for the secret key
        let random_bytes = self.ctx.get_random_bytes(32);
        let signing_key = SigningKey::from_slice(&random_bytes)
            .expect("Failed to create signing key from random bytes");

        let secret_key_bytes = signing_key.to_bytes().to_vec();
        let mut secret_field = FieldBytes::default();
        secret_field.copy_from_slice(&secret_key_bytes);
        let secret_scalar = Option::<Scalar>::from(Scalar::from_repr(secret_field))
            .expect("Failed to parse secret scalar");

        // Step 2: Compute compressed public key (33 bytes)
        let verifying_key = signing_key.verifying_key();
        let public_key_point = verifying_key.to_encoded_point(true);
        let public_key_bytes = public_key_point.as_bytes().to_vec();

        // Step 3: Generate t-1 random coefficients for the Shamir polynomial
        let degree = (key_state.threshold.saturating_sub(1)) as usize;
        let mut random_coeffs = Vec::with_capacity(degree);
        for _ in 0..degree {
            let coeff_bytes = self.ctx.get_random_bytes(32);
            let coeff_key = SigningKey::from_slice(&coeff_bytes)
                .expect("Failed to create polynomial coefficient");
            let mut coeff_field = FieldBytes::default();
            coeff_field.copy_from_slice(&coeff_key.to_bytes());
            let coeff = Option::<Scalar>::from(Scalar::from_repr(coeff_field))
                .expect("Failed to parse coefficient scalar");
            random_coeffs.push(coeff);
        }

        // Step 4: Shamir split into n shares
        let num_shares = key_state.num_shares as usize;
        let threshold = key_state.threshold as usize;
        let shares = shamir::split(secret_scalar, threshold, num_shares, random_coeffs);

        // Step 5: Store secret key in off-chain storage (Engine 0 backup for signing)
        let sk_bucket = secret_key_bucket(key_id);
        let mut sk_storage: pbc_contract_common::off_chain::OffChainStorage<u8, Vec<u8>> =
            self.ctx.storage(&sk_bucket);
        sk_storage.insert(0, secret_key_bytes);

        // Step 6: Store Shamir shares in off-chain storage
        // Each share is stored as: [index(1)] [high(16)] [low(16)] = 33 bytes
        for share in &shares {
            let (high, low) = shamir::scalar_to_halves(&share.value);
            let mut share_bytes = Vec::with_capacity(33);
            share_bytes.push(share.index);
            share_bytes.extend_from_slice(&high);
            share_bytes.extend_from_slice(&low);
            sk_storage.insert(share.index, share_bytes);
        }

        // Step 7: Post public key on-chain
        let post_pk_rpc = crate::post_public_key::rpc(key_id, public_key_bytes);
        self.ctx
            .send_transaction_to_contract(post_pk_rpc, GAS_POST_PUBLIC_KEY);

        // Mark as handled
        let mut handled_storage: pbc_contract_common::off_chain::OffChainStorage<u8, u8> =
            self.ctx.storage(&handled_bucket);
        handled_storage.insert(0, 1);
    }

    /// Emit the vault callback if keygen is complete but callback hasn't been sent yet.
    fn maybe_emit_keygen_callback(&mut self, key_id: u32, key_state: &ZkKeyState) {
        let callback_bucket = keygen_callback_bucket(key_id);
        let callback_storage: pbc_contract_common::off_chain::OffChainStorage<u8, u8> =
            self.ctx.storage(&callback_bucket);
        if callback_storage.get(&0).is_some() {
            return;
        }

        if key_state.is_key_generated() && key_state.public_key.is_some() {
            // Call check_keygen_complete to emit the vault callback event
            let rpc = crate::check_keygen_complete::rpc(key_id);
            self.ctx
                .send_transaction_to_contract(rpc, GAS_CHECK_KEYGEN);

            let mut callback_storage: pbc_contract_common::off_chain::OffChainStorage<u8, u8> =
                self.ctx.storage(&callback_bucket);
            callback_storage.insert(0, 1);
        }
    }

    // -----------------------------------------------------------------------
    // Signing: Reconstruct key from shares, sign, post signature
    // -----------------------------------------------------------------------

    /// Engine 0: Request opening of threshold ZK shares for reconstruction.
    fn handle_request_reconstruction(&mut self, key_id: u32, task_id: u32) {
        let handled_bucket = reconstruction_handled_bucket(key_id);
        let handled_storage: pbc_contract_common::off_chain::OffChainStorage<u32, u8> =
            self.ctx.storage(&handled_bucket);
        if handled_storage.get(&task_id).is_some() {
            return;
        }

        // Send request_reconstruction transaction to open ZK variables
        let rpc = crate::request_reconstruction::rpc(key_id);
        self.ctx
            .send_transaction_to_contract(rpc, GAS_REQUEST_RECONSTRUCTION);

        let mut handled_storage: pbc_contract_common::off_chain::OffChainStorage<u32, u8> =
            self.ctx.storage(&handled_bucket);
        handled_storage.insert(task_id, 1);
    }

    /// Engine 0: Reconstruct key from shares, sign, post signature.
    ///
    /// Attempts to reconstruct from ZK-opened shares first (in contract state).
    /// Falls back to locally-stored shares in off-chain storage if ZK shares
    /// are not yet available.
    fn handle_signing(
        &mut self,
        key_id: u32,
        key_state: &ZkKeyState,
        task_id: u32,
    ) {
        // Check if we already handled this task
        let handled_bucket = signing_handled_bucket(key_id);
        let handled_storage: pbc_contract_common::off_chain::OffChainStorage<u32, u8> =
            self.ctx.storage(&handled_bucket);
        if handled_storage.get(&task_id).is_some() {
            return;
        }

        // Get the signing request
        let sign_request = match key_state.pending_sign_requests.first() {
            Some(req) if req.task_id == task_id => req,
            _ => return,
        };

        // Try to reconstruct from ZK-opened shares (preferred path)
        let signing_key = if !key_state.opened_shares.is_empty() {
            // Reconstruct from ZK-opened shares via Lagrange interpolation
            let shamir_shares: Vec<shamir::ShamirShare> = key_state
                .opened_shares
                .iter()
                .map(|opened| {
                    let value = shamir::halves_to_scalar(&opened.high_bytes, &opened.low_bytes);
                    shamir::ShamirShare {
                        index: opened.share_index,
                        value,
                    }
                })
                .collect();

            let secret_scalar = shamir::reconstruct(&shamir_shares);
            let secret_bytes = secret_scalar.to_bytes();
            match SigningKey::from_slice(&secret_bytes) {
                Ok(sk) => sk,
                Err(_) => return,
            }
        } else {
            // Fall back to locally-stored secret key
            let sk_bucket = secret_key_bucket(key_id);
            let sk_storage: pbc_contract_common::off_chain::OffChainStorage<u8, Vec<u8>> =
                self.ctx.storage(&sk_bucket);
            let secret_key_bytes = match sk_storage.get(&0) {
                Some(bytes) => bytes,
                None => return,
            };
            match SigningKey::from_slice(&secret_key_bytes) {
                Ok(sk) => sk,
                Err(_) => return,
            }
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
