//! Off-chain execution engine logic for cggmp21 threshold ECDSA.
//!
//! Keygen: Engine 0 acts as trusted dealer, generates all key shares and posts
//! them on-chain. All engines then load their share into off-chain storage.
//!
//! Signing: Uses cggmp21 threshold ECDSA via round-based state machine.
//! On each state change, engines replay the protocol with all accumulated
//! messages and post new outgoing messages on-chain.
//!
//! NOTE: Key shares are posted on-chain in the clear for testnet prototyping.

use pbc_contract_common::off_chain::OffChainContext;
use round_based::state_machine::{ProceedResult, StateMachine};
use round_based::{Incoming, MessageType};

use cggmp21::security_level::SecurityLevel128;
use cggmp21::supported_curves::Secp256k1;
use cggmp21::KeyShare;

use crate::signing_orchestration::*;
use crate::task_queue::EngineIndex;
use crate::ContractState;

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// Gas costs for on-chain operations.
const GAS_DISTRIBUTE_SHARES: u64 = 500_000;
const GAS_CONFIRM_SHARE: u64 = 50_000;
const GAS_SIGNING_ROUND_MSG: u64 = 100_000;
const GAS_SIGNING_COMPLETE: u64 = 100_000;

/// Off-chain storage key for the engine's cggmp21 key share.
fn key_share_bucket(key_id: u32) -> Vec<u8> {
    format!("cggmp21_key_share_{}", key_id).into_bytes()
}

/// Off-chain storage key for tracking if we've handled keygen for this key.
fn keygen_handled_bucket(key_id: u32) -> Vec<u8> {
    format!("cggmp21_keygen_done_{}", key_id).into_bytes()
}

/// Off-chain storage key for the engine's master secret (used for deterministic RNG).
fn master_secret_bucket() -> Vec<u8> {
    b"cggmp21_master_secret".to_vec()
}

/// Off-chain storage for signing round tracking.
fn signing_handled_bucket(key_id: u32) -> Vec<u8> {
    format!("cggmp21_signing_handled_{}", key_id).into_bytes()
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
        // Ensure we have a master secret for deterministic RNG
        self.ensure_master_secret();

        let key_ids: Vec<u32> = (0..self.state.next_key_id).collect();
        for key_id in key_ids {
            if let Some(key_state) = self.state.keys.get(&key_id) {
                self.process_key(key_id, &key_state);
            }
        }
    }

    /// Ensure the engine has a master secret in off-chain storage.
    fn ensure_master_secret(&mut self) {
        let bucket = master_secret_bucket();
        let storage: pbc_contract_common::off_chain::OffChainStorage<u8, Vec<u8>> =
            self.ctx.storage(&bucket);
        if storage.get(&0).is_none() {
            let secret = self.ctx.get_random_bytes(32);
            let mut storage: pbc_contract_common::off_chain::OffChainStorage<u8, Vec<u8>> =
                self.ctx.storage(&bucket);
            storage.insert(0, secret);
        }
    }

    /// Create a deterministic RNG from master secret + key_id + purpose.
    /// This ensures replayed state machines produce identical output.
    fn make_deterministic_rng(&mut self, key_id: u32, purpose: &[u8]) -> ChaCha20Rng {
        let bucket = master_secret_bucket();
        let storage: pbc_contract_common::off_chain::OffChainStorage<u8, Vec<u8>> =
            self.ctx.storage(&bucket);
        let master_secret = storage.get(&0).expect("Master secret not initialized");

        let mut seed_material = Vec::new();
        seed_material.extend_from_slice(&master_secret);
        seed_material.extend_from_slice(&key_id.to_be_bytes());
        seed_material.extend_from_slice(&(self.engine_index as u32).to_be_bytes());
        seed_material.extend_from_slice(purpose);
        let hash = pbc_contract_common::Hash::digest(&seed_material);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(hash.as_ref());
        ChaCha20Rng::from_seed(seed)
    }

    /// Process pending tasks for a single key.
    fn process_key(&mut self, key_id: u32, key_state: &SigningComputationState) {
        match &key_state.keygen_phase {
            KeyGenPhase::WaitingForDealer {} => {
                if self.engine_index == 0 {
                    self.handle_trusted_dealer_keygen(key_id, key_state);
                }
            }
            KeyGenPhase::SharesDistributed {} => {
                self.handle_load_key_share(key_id, key_state);
            }
            KeyGenPhase::Complete {} => {
                if let SigningPhase::InProgress { task_id, .. } = &key_state.signing_phase {
                    self.handle_signing(key_id, key_state, *task_id);
                }
            }
        }
    }

    /// Engine 0: Generate all key shares using trusted dealer and post on-chain.
    fn handle_trusted_dealer_keygen(
        &mut self,
        key_id: u32,
        key_state: &SigningComputationState,
    ) {
        // Check if we already handled this
        let handled_bucket = keygen_handled_bucket(key_id);
        let handled_storage: pbc_contract_common::off_chain::OffChainStorage<u8, u8> =
            self.ctx.storage(&handled_bucket);
        if handled_storage.get(&0).is_some() {
            return;
        }

        let num_engines = key_state.num_engines as u16;
        let threshold = key_state.threshold;

        let mut rng = self.make_deterministic_rng(key_id, b"trusted_dealer");

        // Generate all key shares using trusted dealer
        let key_shares: Vec<KeyShare<Secp256k1, SecurityLevel128>> =
            cggmp21::trusted_dealer::builder::<Secp256k1, SecurityLevel128>(num_engines)
                .set_threshold(Some(threshold))
                .generate_shares(&mut rng)
                .expect("Trusted dealer key generation failed");

        // Extract public key from first share
        let public_key = key_shares[0]
            .shared_public_key
            .to_bytes(true);
        let public_key_bytes = public_key.as_bytes().to_vec();

        // Serialize all shares
        let serialized_shares: Vec<Vec<u8>> = key_shares
            .iter()
            .map(|ks| serde_json::to_vec(ks).expect("Failed to serialize key share"))
            .collect();

        // Store our own share (engine 0) in off-chain storage
        let ks_bucket = key_share_bucket(key_id);
        let mut ks_storage: pbc_contract_common::off_chain::OffChainStorage<u8, Vec<u8>> =
            self.ctx.storage(&ks_bucket);
        ks_storage.insert(0, serialized_shares[0].clone());

        // Post all shares + public key on-chain
        let rpc = crate::distribute_key_shares::rpc(
            key_id,
            serialized_shares,
            public_key_bytes,
        );
        self.ctx.send_transaction_to_contract(rpc, GAS_DISTRIBUTE_SHARES);

        // Mark as handled
        let mut handled_storage: pbc_contract_common::off_chain::OffChainStorage<u8, u8> =
            self.ctx.storage(&handled_bucket);
        handled_storage.insert(0, 1);
    }

    /// Non-dealer engines: Load key share from on-chain state into off-chain storage.
    fn handle_load_key_share(
        &mut self,
        key_id: u32,
        key_state: &SigningComputationState,
    ) {
        // Check if we already loaded our share
        let handled_bucket = keygen_handled_bucket(key_id);
        let handled_storage: pbc_contract_common::off_chain::OffChainStorage<u8, u8> =
            self.ctx.storage(&handled_bucket);
        if handled_storage.get(&0).is_some() {
            return;
        }

        let idx = self.engine_index as usize;

        // Read our share from on-chain state
        let share_bytes = match &key_state.key_shares[idx] {
            Some(bytes) => bytes.clone(),
            None => return, // Share not yet available
        };

        // Store in off-chain storage
        let ks_bucket = key_share_bucket(key_id);
        let mut ks_storage: pbc_contract_common::off_chain::OffChainStorage<u8, Vec<u8>> =
            self.ctx.storage(&ks_bucket);
        ks_storage.insert(0, share_bytes);

        // Confirm share loaded
        let engine_index = self.engine_index;
        let rpc = crate::confirm_key_share::rpc(key_id, engine_index);
        self.ctx.send_transaction_to_contract(rpc, GAS_CONFIRM_SHARE);

        // Mark as handled
        let mut handled_storage: pbc_contract_common::off_chain::OffChainStorage<u8, u8> =
            self.ctx.storage(&handled_bucket);
        handled_storage.insert(0, 1);
    }

    /// Handle signing: run cggmp21 signing state machine via replay.
    ///
    /// On each state change, we:
    /// 1. Create a fresh state machine with a deterministic RNG
    /// 2. Replay all accumulated messages (both ours and others')
    /// 3. Extract new outgoing messages for the current round
    /// 4. Post them on-chain
    fn handle_signing(
        &mut self,
        key_id: u32,
        key_state: &SigningComputationState,
        task_id: u32,
    ) {
        let current_round = match &key_state.signing_phase {
            SigningPhase::InProgress { round, .. } => *round,
            _ => return,
        };

        // Check if we already handled this round for this task
        let handled_bucket = signing_handled_bucket(key_id);
        let handled_storage: pbc_contract_common::off_chain::OffChainStorage<u32, u8> =
            self.ctx.storage(&handled_bucket);
        let handled_key = task_id * 1000 + current_round as u32;
        if handled_storage.get(&handled_key).is_some() {
            return;
        }

        // Only first `threshold` engines participate in signing
        let party_index = self.engine_index as u16;
        if party_index >= key_state.threshold {
            return;
        }

        // Load key share from off-chain storage
        let ks_bucket = key_share_bucket(key_id);
        let ks_storage: pbc_contract_common::off_chain::OffChainStorage<u8, Vec<u8>> =
            self.ctx.storage(&ks_bucket);
        let key_share_bytes = match ks_storage.get(&0) {
            Some(bytes) => bytes,
            None => return,
        };

        let key_share: KeyShare<Secp256k1, SecurityLevel128> =
            match serde_json::from_slice(&key_share_bytes) {
                Ok(ks) => ks,
                Err(_) => return,
            };

        // Get the signing request
        let sign_request = match key_state.pending_sign_requests.first() {
            Some(req) if req.task_id == task_id => req,
            _ => return,
        };

        // Build parties list (first `threshold` engines)
        let parties_indexes: Vec<u16> = (0..key_state.threshold).collect();

        let eid_bytes = format!("kosh_sign_{}_{}", key_id, task_id);
        let eid = cggmp21::ExecutionId::new(eid_bytes.as_bytes());

        // IMPORTANT: Use deterministic RNG so replays produce identical messages
        let mut rng = self.make_deterministic_rng(
            key_id,
            format!("sign_{}", task_id).as_bytes(),
        );

        // Build DataToSign from the 32-byte message hash
        let data_to_sign = cggmp21::DataToSign::<Secp256k1>::digest::<k256::sha2::Sha256>(
            &sign_request.message_hash,
        );

        // Build the signing state machine
        let mut sm = cggmp21::signing(eid, party_index, &parties_indexes, &key_share)
            .sign_sync(&mut rng, data_to_sign);

        // Drive the state machine with accumulated messages
        let mut msg_id: u64 = 0;
        let mut feed_index: usize = 0;
        let mut outgoing_messages: Vec<RoundMessage> = Vec::new();
        let mut our_msg_count: u64 = 0;
        let mut already_sent_count: u64 = 0;

        // Count how many messages we've already posted to know which to skip
        for msg in &key_state.signing_messages {
            if msg.sender == self.engine_index {
                already_sent_count += 1;
            }
        }

        loop {
            match sm.proceed() {
                ProceedResult::SendMsg(out) => {
                    our_msg_count += 1;
                    // Skip messages we've already posted on-chain
                    if our_msg_count > already_sent_count {
                        let data = serde_json::to_vec(&out.msg)
                            .expect("Failed to serialize signing message");

                        let (is_broadcast, recipient) = match out.recipient {
                            round_based::MessageDestination::AllParties => (true, 0u8),
                            round_based::MessageDestination::OneParty(idx) => (false, idx as u8),
                        };

                        outgoing_messages.push(RoundMessage {
                            sender: party_index as u8,
                            round: current_round,
                            data,
                            is_broadcast,
                            recipient,
                        });
                    }
                }
                ProceedResult::NeedsOneMoreMessage => {
                    // Try to feed the next message from on-chain state
                    if let Some(incoming) = find_next_message(
                        &key_state.signing_messages,
                        &mut feed_index,
                        party_index,
                        self.engine_index,
                        &mut msg_id,
                    ) {
                        let _ = sm.received_msg(incoming);
                    } else {
                        // No more messages available
                        break;
                    }
                }
                ProceedResult::Output(result) => {
                    if let Ok(signature) = result {
                        // Extract r, s from the signature (each 32 bytes BE)
                        let r_bytes = signature.r.to_be_bytes();
                        let s_bytes = signature.s.to_be_bytes();
                        let mut sig_bytes = Vec::with_capacity(64);
                        sig_bytes.extend_from_slice(r_bytes.as_ref());
                        sig_bytes.extend_from_slice(s_bytes.as_ref());

                        let engine_index = self.engine_index;
                        let rpc = crate::signing_complete::rpc(
                            key_id,
                            engine_index,
                            task_id,
                            sig_bytes,
                        );
                        self.ctx
                            .send_transaction_to_contract(rpc, GAS_SIGNING_COMPLETE);
                    }
                    break;
                }
                ProceedResult::Yielded => continue,
                ProceedResult::Error(_) => break,
            }
        }

        // Post new outgoing messages on-chain
        if !outgoing_messages.is_empty() {
            let engine_index = self.engine_index;
            let rpc = crate::signing_round_message::rpc(
                key_id,
                engine_index,
                current_round,
                task_id,
                outgoing_messages,
            );
            self.ctx
                .send_transaction_to_contract(rpc, GAS_SIGNING_ROUND_MSG);

            let mut handled_storage: pbc_contract_common::off_chain::OffChainStorage<u32, u8> =
                self.ctx.storage(&handled_bucket);
            handled_storage.insert(handled_key, 1);
        }
    }
}

/// Find the next relevant incoming message for this party.
fn find_next_message(
    messages: &[RoundMessage],
    feed_index: &mut usize,
    party_index: u16,
    engine_index: EngineIndex,
    msg_id: &mut u64,
) -> Option<Incoming<cggmp21::signing::msg::Msg<Secp256k1, k256::sha2::Sha256>>> {
    while *feed_index < messages.len() {
        let msg = &messages[*feed_index];
        *feed_index += 1;

        // Skip our own messages
        if msg.sender as u16 == party_index {
            continue;
        }

        // Check if this message is for us (broadcast or P2P to us)
        let is_for_us = msg.is_broadcast || msg.recipient == engine_index;
        if !is_for_us {
            continue;
        }

        // Deserialize the protocol message
        if let Ok(protocol_msg) = serde_json::from_slice(&msg.data) {
            *msg_id += 1;
            let msg_type = if msg.is_broadcast {
                MessageType::Broadcast
            } else {
                MessageType::P2P
            };

            return Some(Incoming {
                id: *msg_id,
                sender: msg.sender as u16,
                msg_type,
                msg: protocol_msg,
            });
        }
    }
    None
}
