use crate::{
    action_builders,
    app::{ActiveRuntimeState, AppState},
    evm_broadcaster::BroadcastSignedTxResult,
    jobs::{Job, JobKind, JobPhase},
    keystore::{KeyMaterialMetadata, PersistedPartyRuntime},
    party_runtime::{dkg, gg20},
    pqc::{self, PqcIdentity},
    threshold_read,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Digest;

const DEFAULT_ACTION_GAS: u64 = 10_000_000;

#[derive(Debug, Clone, Deserialize)]
pub struct CreateKeyWorkflowRequest {
    pub contract_address: String,
    pub key_id: u32,
    pub num_parties: u8,
    pub seed_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateKeyWorkflowResult {
    pub contract_address: String,
    pub key_id: u32,
    pub num_parties: u8,
    pub public_key_hex: String,
    pub runtimes_persisted: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReuseSignWorkflowRequest {
    pub contract_address: String,
    pub key_id: u32,
    pub tx_tag: String,
    pub signing_parties: Vec<u8>,
    pub threshold: u8,
    pub msg_hash_hex: String,
    pub session_id: Option<u32>,
    pub signed_tx_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReuseSignWorkflowResult {
    pub contract_address: String,
    pub key_id: u32,
    pub public_key_hex: String,
    pub task_id_used: u32,
    pub next_task_id: u32,
    pub signature: gg20::GG20SignatureData,
    pub onchain_signature_hex: Option<String>,
    pub onchain_signature_verified: bool,
    pub sepolia_broadcast: Option<BroadcastSignedTxResult>,
}

pub async fn start_create_key_workflow(state: AppState, request: CreateKeyWorkflowRequest) -> Job {
    let job = state.jobs.create_job(JobKind::CreateKey).await;
    let job_id = job.id;
    let jobs = state.jobs.clone();
    tokio::spawn(async move {
        if let Err(err) = run_create_key_workflow(state, job_id, request).await {
            let _ = jobs
                .set_failed(job_id, JobPhase::Failed, err.to_string())
                .await;
        }
    });
    job
}

pub async fn start_reuse_sign_workflow(state: AppState, request: ReuseSignWorkflowRequest) -> Job {
    let job = state.jobs.create_job(JobKind::ReuseSign).await;
    let job_id = job.id;
    let jobs = state.jobs.clone();
    tokio::spawn(async move {
        if let Err(err) = run_reuse_sign_workflow(state, job_id, request).await {
            let _ = jobs
                .set_failed(job_id, JobPhase::Failed, err.to_string())
                .await;
        }
    });
    job
}

async fn run_create_key_workflow(
    state: AppState,
    job_id: uuid::Uuid,
    request: CreateKeyWorkflowRequest,
) -> Result<()> {
    state
        .jobs
        .set_running(
            job_id,
            JobPhase::CreatingKey,
            "starting create-key workflow",
        )
        .await;

    let mut resumed_from_existing = false;
    let mut existing_public_key_hex: Option<String> = None;
    if state.chain_relay.is_action_submission_configured().await {
        if let Ok(contract_state) = state.chain_relay.get_contract_data(&request.contract_address).await {
            if let Ok(status) = threshold_read::threshold_key_status(&contract_state, request.key_id).await {
                if status.exists && status.keygen_phase_discriminant.unwrap_or(0) >= 5 {
                    resumed_from_existing = true;
                    existing_public_key_hex = status.public_key_hex.clone();
                    state.jobs.log(job_id, format!("resuming existing key {} from keygen phase {}", request.key_id, status.keygen_phase_discriminant.unwrap_or(0))).await;
                }
            }
        }
    }

    let seed = request
        .seed_hex
        .as_deref()
        .and_then(|s| hex::decode(s.trim_start_matches("0x")).ok());

    let mut shares = Vec::new();
    if !resumed_from_existing {
        if state.chain_relay.is_action_submission_configured().await {
            let rpc = action_builders::build_dkg_create_key_rpc(request.key_id, request.num_parties);
            let submitted = state
                .chain_relay
                .submit_action(&request.contract_address, "dkg_create_key", &rpc, DEFAULT_ACTION_GAS)
                .await?;
            state
                .jobs
                .log(
                    job_id,
                    format!(
                        "submitted dkg_create_key on {} tx {}",
                        submitted.node_url, submitted.tx_hash
                    ),
                )
                .await;
        } else {
            state
                .jobs
                .log(
                    job_id,
                    "chain relay submission not configured; skipping live dkg_create_key",
                )
                .await;
        }

        for party_index in 1..=request.num_parties {
            let share =
                dkg::generate_threshold_dkg_share(party_index, request.num_parties, seed.as_deref())?;
            state
                .jobs
                .log(
                    job_id,
                    format!("generated DKG share for party {party_index}"),
                )
                .await;
            shares.push(share);
        }
    }

    if !resumed_from_existing && state.chain_relay.is_action_submission_configured().await {
        for share in &shares {
            let proof = dkg::generate_schnorr_proof(
                &share.secret_scalar_hex,
                &share.public_key_share_hex,
                share.party_index,
            )?;
            let commit_rpc = action_builders::build_dkg_commit_rpc(
                request.key_id,
                share.party_index,
                &hex::decode(&share.commitment_hash_hex)?,
                &hex::decode(&share.c_i1_hex)?,
                &hex::decode(&proof.r_hex)?,
                &hex::decode(&proof.z_hex)?,
            );
            let committed = state
                .chain_relay
                .submit_action(
                    &request.contract_address,
                    "dkg_commit",
                    &commit_rpc,
                    DEFAULT_ACTION_GAS,
                )
                .await?;
            state
                .jobs
                .log(
                    job_id,
                    format!(
                        "submitted dkg_commit for party {} on {} tx {}",
                        share.party_index, committed.node_url, committed.tx_hash
                    ),
                )
                .await;
        }

        for share in &shares {
            let reveal_rpc = action_builders::build_dkg_reveal_rpc(
                request.key_id,
                share.party_index,
                &hex::decode(&share.public_key_share_hex)?,
            );
            let revealed = state
                .chain_relay
                .submit_action(
                    &request.contract_address,
                    "dkg_reveal",
                    &reveal_rpc,
                    DEFAULT_ACTION_GAS,
                )
                .await?;
            state
                .jobs
                .log(
                    job_id,
                    format!(
                        "submitted dkg_reveal for party {} on {} tx {}",
                        share.party_index, revealed.node_url, revealed.tx_hash
                    ),
                )
                .await;
        }

        let finalize_rpc = action_builders::build_dkg_finalize_rpc(request.key_id);
        let finalized = state
            .chain_relay
            .submit_action(
                &request.contract_address,
                "dkg_finalize",
                &finalize_rpc,
                DEFAULT_ACTION_GAS,
            )
            .await?;
        state
            .jobs
            .log(
                job_id,
                format!(
                    "submitted dkg_finalize on {} tx {}",
                    finalized.node_url, finalized.tx_hash
                ),
            )
            .await;
    }
    let public_key_hex = if resumed_from_existing {
        existing_public_key_hex
            .clone()
            .ok_or_else(|| anyhow::anyhow!("existing key missing public key"))?
    } else {
        dkg::compute_combined_public_key(&shares)?
    };

    let mut persisted = 0usize;
    if let Some(keystore) = &state.keystore {
        if !resumed_from_existing {
            let combined_shares = (1..=request.num_parties)
                .map(|party_index| dkg::combine_shamir_shares(party_index, &shares))
                .collect::<Result<Vec<_>, _>>()?;
            for (share, combined_share) in shares.iter().zip(combined_shares.iter()) {
                let runtime = PersistedPartyRuntime {
                    contract_address: request.contract_address.clone(),
                    key_id: request.key_id,
                    party_index: share.party_index,
                    public_key_hex: public_key_hex.clone(),
                    next_task_id: 0,
                    shamir_share_hex: combined_share.share_hex.clone(),
                    runtime_version: "phase7-foundation".to_string(),
                };
                keystore.store_party_runtime(&runtime).await?;
                let meta = KeyMaterialMetadata {
                    contract_address: request.contract_address.clone(),
                    key_id: request.key_id,
                    party_index: share.party_index,
                    public_key_hex: public_key_hex.clone(),
                    runtime_version: "phase7-foundation".to_string(),
                };
                let secret_name = format!(
                    "share-{}-{}-p{}",
                    request.contract_address, request.key_id, share.party_index
                );
                keystore
                    .store_secret(&secret_name, share.secret_scalar_hex.as_bytes(), meta)
                    .await?;
                persisted += 1;
            }
        } else {
            for party_index in 1..=request.num_parties {
                if keystore.load_party_runtime(&request.contract_address, request.key_id, party_index).await.is_ok() {
                    persisted += 1;
                }
            }
        }
    }

    ensure_party_operational_readiness(
        &state,
        job_id,
        &request.contract_address,
        request.key_id,
        request.num_parties,
        &public_key_hex,
    )
    .await?;

    *state.active_runtime.write().await = Some(ActiveRuntimeState {
        mode: "create_key".to_string(),
        contract_address: request.contract_address.clone(),
        key_id: request.key_id,
        sender_address: state.chain_relay.health().await.sender_address,
        evm_address: None,
        updated_at: chrono::Utc::now().to_rfc3339(),
    });

    if state.chain_relay.is_action_submission_configured().await {
        let complete_rpc = action_builders::build_dkg_complete_keygen_rpc(request.key_id);
        let completed = state
            .chain_relay
            .submit_action(
                &request.contract_address,
                "dkg_complete_keygen",
                &complete_rpc,
                DEFAULT_ACTION_GAS,
            )
            .await?;
        state
            .jobs
            .log(
                job_id,
                format!(
                    "submitted dkg_complete_keygen on {} tx {}",
                    completed.node_url, completed.tx_hash
                ),
            )
            .await;
    }

    let result = CreateKeyWorkflowResult {
        contract_address: request.contract_address,
        key_id: request.key_id,
        num_parties: request.num_parties,
        public_key_hex,
        runtimes_persisted: persisted,
    };
    state
        .jobs
        .set_completed(
            job_id,
            JobPhase::Completed,
            Some(json!(result)),
            "create-key workflow completed",
        )
        .await;
    Ok(())
}

async fn run_reuse_sign_workflow(
    state: AppState,
    job_id: uuid::Uuid,
    request: ReuseSignWorkflowRequest,
) -> Result<()> {
    recover_signing_session_if_needed(&state, job_id, &request.contract_address, request.key_id)
        .await?;
    state
        .jobs
        .set_running(job_id, JobPhase::EvaluatingPolicy, "evaluating policy")
        .await;
    let decision = state
        .policy
        .validate(&request.tx_tag, &request.signing_parties, request.threshold)
        .await;
    if !decision.allowed {
        anyhow::bail!(decision
            .violation
            .unwrap_or_else(|| "policy denied signing request".to_string()));
    }

    state
        .jobs
        .set_running(job_id, JobPhase::LoadingShares, "loading persisted shares")
        .await;
    let keystore = state
        .keystore
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("keystore disabled"))?;
    ensure_party_operational_readiness(
        &state,
        job_id,
        &request.contract_address,
        request.key_id,
        3,
        "pqc-reuse",
    )
    .await?;
    let mut party_inputs = Vec::new();
    let mut public_key_hex = None;
    let mut runtimes = Vec::new();
    for party_index in &request.signing_parties {
        let runtime = keystore
            .load_party_runtime(&request.contract_address, request.key_id, *party_index)
            .await?;
        public_key_hex = Some(runtime.public_key_hex.clone());
        let adjusted_share_hex = dkg::compute_adjusted_share(
            &runtime.shamir_share_hex,
            runtime.party_index,
            &request.signing_parties,
        )?;
        party_inputs.push((runtime.party_index, adjusted_share_hex));
        runtimes.push(runtime);
        state
            .jobs
            .log(job_id, format!("loaded runtime for party {}", party_index))
            .await;
    }
    let task_id_used = runtimes
        .iter()
        .map(|runtime| runtime.next_task_id)
        .max()
        .unwrap_or(0);

    let msg_hash_bytes = hex::decode(request.msg_hash_hex.trim_start_matches("0x"))?;
    if state.chain_relay.is_action_submission_configured().await {
        state
            .jobs
            .set_running(
                job_id,
                JobPhase::StartingSignMessage,
                "queueing sign_message on Partisia",
            )
            .await;
        let rpc = action_builders::build_sign_message_rpc(
            request.key_id,
            &msg_hash_bytes,
            &request.tx_tag,
        );
        let submitted = state
            .chain_relay
            .submit_action(&request.contract_address, "sign_message", &rpc, DEFAULT_ACTION_GAS)
            .await?;
        state
            .jobs
            .log(
                job_id,
                format!(
                    "submitted sign_message on {} tx {}",
                    submitted.node_url, submitted.tx_hash
                ),
            )
            .await;

        state
            .jobs
            .set_running(
                job_id,
                JobPhase::StartingPqcApproval,
                "starting and finalizing PQC approval session on Partisia",
            )
            .await;
        let challenge = pqc::compute_pqc_session_challenge(
            request.key_id,
            task_id_used,
            &msg_hash_bytes,
            &request.tx_tag,
            &request.signing_parties,
        );
        let start_pqc_rpc = action_builders::build_start_pqc_approval_session_rpc(
            request.key_id,
            task_id_used,
            &request.signing_parties,
        );
        let pqc_started = state
            .chain_relay
            .submit_action(
                &request.contract_address,
                "start_pqc_approval_session",
                &start_pqc_rpc,
                DEFAULT_ACTION_GAS,
            )
            .await?;
        state
            .jobs
            .log(
                job_id,
                format!(
                    "submitted start_pqc_approval_session on {} tx {}",
                    pqc_started.node_url, pqc_started.tx_hash
                ),
            )
            .await;

        for &party_index in &request.signing_parties {
            let approval_hash = pqc::compute_pqc_approval_hash(
                request.key_id,
                task_id_used,
                party_index,
                &msg_hash_bytes,
                &request.tx_tag,
                &request.signing_parties,
                &challenge,
            );
            let submit_pqc_rpc = action_builders::build_submit_pqc_approval_rpc(
                request.key_id,
                task_id_used,
                party_index,
                &approval_hash,
            );
            let approval_submitted = state
                .chain_relay
                .submit_action(
                    &request.contract_address,
                    "submit_pqc_approval",
                    &submit_pqc_rpc,
                    DEFAULT_ACTION_GAS,
                )
                .await?;
            state
                .jobs
                .log(
                    job_id,
                    format!(
                        "submitted submit_pqc_approval for party {} on {} tx {}",
                        party_index, approval_submitted.node_url, approval_submitted.tx_hash
                    ),
                )
                .await;
        }

        let finalize_pqc_rpc =
            action_builders::build_finalize_pqc_approval_rpc(request.key_id, task_id_used);
        let pqc_finalized = state
            .chain_relay
            .submit_action(
                &request.contract_address,
                "finalize_pqc_approval",
                &finalize_pqc_rpc,
                DEFAULT_ACTION_GAS,
            )
            .await?;
        state
            .jobs
            .log(
                job_id,
                format!(
                    "submitted finalize_pqc_approval on {} tx {}",
                    pqc_finalized.node_url, pqc_finalized.tx_hash
                ),
            )
            .await;

        state
            .jobs
            .set_running(
                job_id,
                JobPhase::StartingGg20,
                "queueing gg20_start_signing on Partisia",
            )
            .await;
        let start_rpc = action_builders::build_gg20_start_signing_rpc(
            request.key_id,
            task_id_used,
            &request.signing_parties,
        );
        let gg20_started = state
            .chain_relay
            .submit_action(
                &request.contract_address,
                "gg20_start_signing",
                &start_rpc,
                DEFAULT_ACTION_GAS,
            )
            .await?;
        state
            .jobs
            .log(
                job_id,
                format!(
                    "submitted gg20_start_signing on {} tx {}",
                    gg20_started.node_url, gg20_started.tx_hash
                ),
            )
            .await;
    } else {
        state
            .jobs
            .log(
                job_id,
                "chain relay submission not configured; skipping live sign_message and gg20_start_signing",
            )
            .await;
    }

    state
        .jobs
        .set_running(
            job_id,
            JobPhase::RunningMta,
            "running GG20 signing foundation",
        )
        .await;
    let signature =
        gg20::gg20_sign_foundation(&party_inputs, &request.msg_hash_hex, request.session_id)?;

    let combined_s_hex = gg20::gg20_combine_partials(&signature.partials)?;
    if let Some(stored_public_key_hex) = public_key_hex.clone() {
        let derived_public_key_hex = gg20::derive_public_key_from_shares(&party_inputs)?;
        state.jobs.log(job_id, format!("derived pubkey from adjusted shares matches stored={} derived={} stored={}", derived_public_key_hex.eq_ignore_ascii_case(&stored_public_key_hex), derived_public_key_hex, stored_public_key_hex)).await;
        let local_verify = gg20::gg20_verify_locally(&stored_public_key_hex, &request.msg_hash_hex, &signature.r_hex, &combined_s_hex)?;
        state.jobs.log(job_id, format!("local GG20 verification before on-chain submit verified={} r={} s={}", local_verify, signature.r_hex, combined_s_hex)).await;
    }

    if state.chain_relay.is_action_submission_configured().await {
        for delta in &signature.deltas {
            let delta_bytes = hex::decode(&delta.delta_i_hex)?;
            let commit_hash = sha2::Sha256::digest(&delta_bytes);
            let commit_rpc = action_builders::build_commit_delta_rpc(
                request.key_id,
                delta.party_index,
                commit_hash.as_slice(),
            );
            let committed = state
                .chain_relay
                .submit_action(
                    &request.contract_address,
                    "commit_delta",
                    &commit_rpc,
                    DEFAULT_ACTION_GAS,
                )
                .await?;
            state
                .jobs
                .log(
                    job_id,
                    format!(
                        "submitted commit_delta for party {} on {} tx {}",
                        delta.party_index, committed.node_url, committed.tx_hash
                    ),
                )
                .await;

            let delta_rpc = action_builders::build_submit_delta_rpc(
                request.key_id,
                delta.party_index,
                &delta_bytes,
            );
            let submitted = state
                .chain_relay
                .submit_action(
                    &request.contract_address,
                    "submit_delta",
                    &delta_rpc,
                    DEFAULT_ACTION_GAS,
                )
                .await?;
            state
                .jobs
                .log(
                    job_id,
                    format!(
                        "submitted submit_delta for party {} on {} tx {}",
                        delta.party_index, submitted.node_url, submitted.tx_hash
                    ),
                )
                .await;
        }

        for (idx, gamma_point_hex) in signature.gamma_points_hex.iter().enumerate() {
            let party_index = request.signing_parties[idx];
            let gamma_rpc = action_builders::build_submit_gamma_point_rpc(
                request.key_id,
                party_index,
                &hex::decode(gamma_point_hex)?,
            );
            let gamma_submitted = state
                .chain_relay
                .submit_action(
                    &request.contract_address,
                    "submit_gamma_point",
                    &gamma_rpc,
                    DEFAULT_ACTION_GAS,
                )
                .await?;
            state
                .jobs
                .log(
                    job_id,
                    format!(
                        "submitted submit_gamma_point for party {} on {} tx {}",
                        party_index, gamma_submitted.node_url, gamma_submitted.tx_hash
                    ),
                )
                .await;
        }

        let finalize_r_rpc = action_builders::build_gg20_finalize_r_rpc(request.key_id);
        let finalized_r = state
            .chain_relay
            .submit_action(
                &request.contract_address,
                "gg20_finalize_r",
                &finalize_r_rpc,
                DEFAULT_ACTION_GAS,
            )
            .await?;
        state
            .jobs
            .log(
                job_id,
                format!(
                    "submitted gg20_finalize_r on {} tx {}",
                    finalized_r.node_url, finalized_r.tx_hash
                ),
            )
            .await;

        for partial in &signature.partials {
            let partial_bytes = hex::decode(&partial.s_i_hex)?;
            let commit_hash = sha2::Sha256::digest(&partial_bytes);
            let commit_rpc = action_builders::build_commit_partial_sig_rpc(
                request.key_id,
                partial.party_index,
                commit_hash.as_slice(),
            );
            let committed = state
                .chain_relay
                .submit_action(
                    &request.contract_address,
                    "commit_partial_sig",
                    &commit_rpc,
                    DEFAULT_ACTION_GAS,
                )
                .await?;
            state
                .jobs
                .log(
                    job_id,
                    format!(
                        "submitted commit_partial_sig for party {} on {} tx {}",
                        partial.party_index, committed.node_url, committed.tx_hash
                    ),
                )
                .await;

            let partial_rpc = action_builders::build_submit_partial_sig_rpc(
                request.key_id,
                partial.party_index,
                &partial_bytes,
            );
            let revealed = state
                .chain_relay
                .submit_action(
                    &request.contract_address,
                    "submit_partial_sig",
                    &partial_rpc,
                    DEFAULT_ACTION_GAS,
                )
                .await?;
            state
                .jobs
                .log(
                    job_id,
                    format!(
                        "submitted submit_partial_sig for party {} on {} tx {}",
                        partial.party_index, revealed.node_url, revealed.tx_hash
                    ),
                )
                .await;
        }
    }

    let mut onchain_signature_hex = None;
    let mut onchain_signature_verified = false;
    if state.chain_relay.is_action_submission_configured().await {
        if let Ok(contract_state) = state
            .chain_relay
            .get_contract_data(&request.contract_address)
            .await
        {
            if let Ok(task_signature) = threshold_read::threshold_task_signature(
                &contract_state,
                request.key_id,
                task_id_used,
            )
            .await
            {
                onchain_signature_verified = task_signature.verified;
                onchain_signature_hex = task_signature.signature_hex;
                state
                    .jobs
                    .log(
                        job_id,
                        format!(
                            "fetched on-chain signature status for task {} verified={}",
                            task_id_used, onchain_signature_verified
                        ),
                    )
                    .await;
            }
        }
    }

    let sepolia_broadcast = if let Some(signed_tx_hex) = request.signed_tx_hex.as_deref() {
        state
            .jobs
            .set_running(
                job_id,
                JobPhase::BroadcastingSepolia,
                "broadcasting signed transaction to Ethereum Sepolia",
            )
            .await;
        Some(
            state
                .evm_broadcaster
                .broadcast_signed_transaction(signed_tx_hex)
                .await?,
        )
    } else {
        None
    };

    let next_task_id = task_id_used.saturating_add(1);
    for mut runtime in runtimes {
        runtime.next_task_id = next_task_id;
        keystore.store_party_runtime(&runtime).await?;
    }

    *state.active_runtime.write().await = Some(ActiveRuntimeState {
        mode: "reuse_sign".to_string(),
        contract_address: request.contract_address.clone(),
        key_id: request.key_id,
        sender_address: state.chain_relay.health().await.sender_address,
        evm_address: None,
        updated_at: chrono::Utc::now().to_rfc3339(),
    });

    let result = ReuseSignWorkflowResult {
        contract_address: request.contract_address,
        key_id: request.key_id,
        public_key_hex: public_key_hex.unwrap_or_default(),
        task_id_used,
        next_task_id,
        signature,
        onchain_signature_hex,
        onchain_signature_verified,
        sepolia_broadcast,
    };

    state
        .jobs
        .set_completed(
            job_id,
            JobPhase::Completed,
            Some(json!(result)),
            "reuse-sign workflow completed",
        )
        .await;
    Ok(())
}

async fn ensure_party_operational_readiness(
    state: &AppState,
    job_id: uuid::Uuid,
    contract_address: &str,
    key_id: u32,
    num_parties: u8,
    public_key_hex: &str,
) -> Result<()> {
    if !state.chain_relay.is_action_submission_configured().await {
        state
            .jobs
            .log(
                job_id,
                "chain relay submission not configured; skipping party readiness registration",
            )
            .await;
        return Ok(());
    }
    let Some(keystore) = &state.keystore else {
        state
            .jobs
            .log(job_id, "keystore unavailable; skipping party readiness registration")
            .await;
        return Ok(());
    };
    let sender_address = state
        .config
        .partisia_sender_address
        .as_deref()
        .context("PARTISIA_SENDER_ADDRESS is required for party readiness registration")?;
    let encoded_address = parse_partisia_address(sender_address)?;

    for party_index in 1..=num_parties {
        let identity = PqcIdentity::load_or_generate(keystore, party_index, public_key_hex).await?;

        let party_rpc =
            action_builders::build_register_party_address_rpc(key_id, party_index, &encoded_address);
        let party_registered = submit_action_idempotent(
            state,
            contract_address,
            "register_party_address",
            &party_rpc,
            DEFAULT_ACTION_GAS,
        )
        .await?;
        state
            .jobs
            .log(
                job_id,
                format!(
                    "submitted register_party_address for party {} on {} tx {}",
                    party_index, party_registered.node_url, party_registered.tx_hash
                ),
            )
            .await;

        let dsa_rpc = action_builders::build_register_dilithium_pubkey_rpc(
            key_id,
            party_index,
            &identity.dilithium_public_key()?,
        );
        let dsa_registered = submit_action_idempotent(
            state,
            contract_address,
            "register_dilithium_pubkey",
            &dsa_rpc,
            DEFAULT_ACTION_GAS,
        )
        .await?;
        state
            .jobs
            .log(
                job_id,
                format!(
                    "submitted register_dilithium_pubkey for party {} on {} tx {}",
                    party_index, dsa_registered.node_url, dsa_registered.tx_hash
                ),
            )
            .await;

        let kyber_rpc = action_builders::build_register_kyber_pubkey_rpc(
            key_id,
            party_index,
            &identity.kyber_public_key()?,
        );
        let kyber_registered = submit_action_idempotent(
            state,
            contract_address,
            "register_kyber_pubkey",
            &kyber_rpc,
            DEFAULT_ACTION_GAS,
        )
        .await?;
        state
            .jobs
            .log(
                job_id,
                format!(
                    "submitted register_kyber_pubkey for party {} on {} tx {}",
                    party_index, kyber_registered.node_url, kyber_registered.tx_hash
                ),
            )
            .await;
    }

    Ok(())
}

async fn recover_signing_session_if_needed(
    state: &AppState,
    job_id: uuid::Uuid,
    contract_address: &str,
    key_id: u32,
) -> Result<()> {
    if !state.chain_relay.is_action_submission_configured().await {
        return Ok(());
    }

    state
        .jobs
        .set_running(
            job_id,
            JobPhase::RecoveringSigningSession,
            "clearing any stale signing session",
        )
        .await;

    let abort_rpc = action_builders::build_abort_signing_rpc(key_id);
    match state
        .chain_relay
        .submit_action(contract_address, "abort_signing", &abort_rpc, DEFAULT_ACTION_GAS)
        .await
    {
        Ok(submitted) => {
            state
                .jobs
                .log(
                    job_id,
                    format!(
                        "submitted abort_signing on {} tx {}",
                        submitted.node_url, submitted.tx_hash
                    ),
                )
                .await;
        }
        Err(err) => {
            let message = err.to_string();
            if is_no_active_signing_error(&message) {
                state
                    .jobs
                    .log(job_id, "no stale signing session found")
                    .await;
            } else {
                return Err(err);
            }
        }
    }
    Ok(())
}

async fn submit_action_idempotent(
    state: &AppState,
    contract_address: &str,
    action: &str,
    payload: &[u8],
    gas_cost: u64,
) -> Result<crate::chain_relay::SubmitActionResult> {
    match state
        .chain_relay
        .submit_action(contract_address, action, payload, gas_cost)
        .await
    {
        Ok(result) => Ok(result),
        Err(err) if is_idempotent_success_error(action, &err.to_string()) => Ok(
            crate::chain_relay::SubmitActionResult {
                tx_hash: "already_satisfied".to_string(),
                node_url: state.chain_relay.active_node().await.unwrap_or_default(),
                destination_shard_id: "Shard0".to_string(),
            },
        ),
        Err(err) => Err(err),
    }
}

fn is_no_active_signing_error(message: &str) -> bool {
    message.contains("No active signing session to abort")
}

fn is_idempotent_success_error(action: &str, message: &str) -> bool {
    match action {
        "register_party_address" => message.contains("already registered"),
        "register_dilithium_pubkey" | "register_kyber_pubkey" => false,
        _ => false,
    }
}

fn parse_partisia_address(input: &str) -> Result<Vec<u8>> {
    let trimmed = input.trim().trim_start_matches("0x");
    let bytes = hex::decode(trimmed).context("decode PARTISIA_SENDER_ADDRESS")?;
    if bytes.len() != 21 {
        bail!(
            "PARTISIA_SENDER_ADDRESS must decode to 21 bytes, got {}",
            bytes.len()
        );
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::{
        start_create_key_workflow, start_reuse_sign_workflow, CreateKeyWorkflowRequest,
        ReuseSignWorkflowRequest,
    };
    use crate::{
        app::AppState,
        chain_relay::{ChainRelay, ChainRelayConfig},
        config::Config,
        coordinator::BulletinBoard,
        evm_broadcaster::{EvmBroadcaster, EvmBroadcasterConfig},
        jobs::{JobManager, JobStatus},
        keystore::KeyStore,
        policy::PolicyStore,
    };
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        path::PathBuf,
        sync::Arc,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    use tokio::sync::RwLock;

    fn temp_root(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("kosh-backend-orch-{name}-{nanos}"))
    }

    fn test_state() -> AppState {
        let config = Config {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            database_url: None,
            log_filter: "info".to_string(),
            service_name: "test".to_string(),
            keystore_root_dir: Some(temp_root("keystore")),
            keystore_master_key: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ),
            partisia_node_urls: vec![],
            partisia_sender_key: None,
            partisia_sender_address: None,
            partisia_confirm_timeout: Duration::from_secs(1),
            partisia_max_retries: 1,
            sepolia_rpc_url: None,
            sepolia_chain_id: 11155111,
        };

        AppState {
            config: Arc::new(config),
            jobs: JobManager::new(),
            coordinator: BulletinBoard::new(),
            policy: PolicyStore::new(),
            keystore: Some(
                KeyStore::new(
                    temp_root("secrets"),
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                )
                .unwrap(),
            ),
            chain_relay: ChainRelay::new(ChainRelayConfig {
                node_urls: vec![],
                sender_address: None,
                sender_key: None,
                confirm_timeout: Duration::from_secs(1),
                max_retries: 1,
            }),
            evm_broadcaster: EvmBroadcaster::new(EvmBroadcasterConfig {
                rpc_url: None,
                chain_id: 11155111,
            }),
            database: None,
            active_runtime: Arc::new(RwLock::new(None)),
        }
    }

    #[tokio::test]
    async fn create_key_then_reuse_sign_persists_and_advances_task_id() {
        let state = test_state();
        let create_job = start_create_key_workflow(
            state.clone(),
            CreateKeyWorkflowRequest {
                contract_address: "contract-x".to_string(),
                key_id: 7,
                num_parties: 3,
                seed_hex: Some("01".repeat(32)),
            },
        )
        .await;

        let created = wait_for_job(&state, create_job.id).await;
        assert!(matches!(created.status, JobStatus::Completed));

        let sign_job = start_reuse_sign_workflow(
            state.clone(),
            ReuseSignWorkflowRequest {
                contract_address: "contract-x".to_string(),
                key_id: 7,
                tx_tag: "eth_transfer".to_string(),
                signing_parties: vec![1, 2],
                threshold: 2,
                msg_hash_hex: "0xc9b03991a1a3fa025eebe1fe2c9186e0a4d1b275f5eb8369e4f4429416655735"
                    .to_string(),
                session_id: Some(1),
                signed_tx_hex: None,
            },
        )
        .await;

        let signed = wait_for_job(&state, sign_job.id).await;
        assert!(matches!(signed.status, JobStatus::Completed));
        let result = signed.result.unwrap();
        assert_eq!(result["task_id_used"], 0);
        assert_eq!(result["next_task_id"], 1);

        let runtime = state
            .keystore
            .as_ref()
            .unwrap()
            .load_party_runtime("contract-x", 7, 1)
            .await
            .unwrap();
        assert_eq!(runtime.next_task_id, 1);
    }

    async fn wait_for_job(state: &AppState, job_id: uuid::Uuid) -> crate::jobs::Job {
        for _ in 0..100 {
            let job = state.jobs.get_job(job_id).await.unwrap();
            if !matches!(job.status, JobStatus::Queued | JobStatus::Running) {
                return job;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        state.jobs.get_job(job_id).await.unwrap()
    }
}
