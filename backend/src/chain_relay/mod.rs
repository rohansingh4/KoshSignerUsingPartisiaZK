use anyhow::{anyhow, Context, Result};
use base64::Engine;
use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use reqwest::Client;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tokio::sync::{Mutex, RwLock};

#[derive(Clone, Debug)]
pub struct ChainRelayConfig {
    pub node_urls: Vec<String>,
    pub sender_address: Option<String>,
    pub sender_key: Option<String>,
    pub confirm_timeout: Duration,
    pub poll_interval: Duration,
    pub max_retries: u32,
}

#[derive(Clone)]
pub struct ChainRelay {
    config: Arc<ChainRelayConfig>,
    client: Client,
    active_index: Arc<Mutex<usize>>,
    sender_state: Arc<Mutex<Option<SenderState>>>,
    last_error: Arc<RwLock<Option<String>>>,
}

#[derive(Clone, Debug)]
struct SenderState {
    chain_id: String,
    next_nonce: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelayHealth {
    pub configured: bool,
    pub sender_address: Option<String>,
    pub active_node: Option<String>,
    pub node_count: usize,
    pub max_retries: u32,
    pub last_error: Option<String>,
    pub sender_gas_balance: Option<u64>,
    pub gas_ok: Option<bool>,
    pub recommended_mint_command: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelayPreflight {
    pub ok: bool,
    pub backend_reachable: bool,
    pub relay_configured: bool,
    pub sender_address: Option<String>,
    pub sender_gas_balance: Option<u64>,
    pub sender_gas_ok: bool,
    pub local_runtime_present: bool,
    pub key_exists_onchain: bool,
    pub can_create: bool,
    pub can_sign: bool,
    pub recommended_mint_command: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitActionResult {
    pub tx_hash: String,
    pub node_url: String,
    pub destination_shard_id: String,
}

#[derive(Debug, Clone)]
pub struct PipelineAction {
    pub action: String,
    pub payload: Vec<u8>,
    pub gas_cost: u64,
}

impl ChainRelay {
    pub fn new(config: ChainRelayConfig) -> Self {
        Self {
            config: Arc::new(config),
            client: Client::new(),
            active_index: Arc::new(Mutex::new(0)),
            sender_state: Arc::new(Mutex::new(None)),
            last_error: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn is_action_submission_configured(&self) -> bool {
        !self.config.node_urls.is_empty()
            && self.config.sender_address.is_some()
            && self.config.sender_key.is_some()
    }

    pub async fn health(&self) -> RelayHealth {
        let sender_gas_balance = self.sender_gas_balance().await.ok().flatten();
        let gas_ok = sender_gas_balance.map(|balance| balance > 0);
        RelayHealth {
            configured: !self.config.node_urls.is_empty(),
            sender_address: self.config.sender_address.clone(),
            active_node: self.active_node().await,
            node_count: self.config.node_urls.len(),
            max_retries: self.config.max_retries,
            last_error: self.last_error.read().await.clone(),
            sender_gas_balance,
            gas_ok,
            recommended_mint_command: self
                .config
                .sender_address
                .as_ref()
                .map(|sender| format!("cargo pbc account --net=testnet mintgas {sender}")),
        }
    }

    pub async fn sender_gas_balance(&self) -> Result<Option<u64>> {
        let Some(sender_address) = self.config.sender_address.as_deref() else {
            return Ok(None);
        };
        let account = self
            .try_across_nodes("sender_gas_balance", |node| {
                let node = node.to_string();
                let sender_address = sender_address.to_string();
                async move { fetch_account(&self.client, &node, &sender_address).await }
            })
            .await?;
        Ok(max_gas_balance(&account))
    }

    pub async fn active_node(&self) -> Option<String> {
        let index = *self.active_index.lock().await;
        self.config.node_urls.get(index).cloned()
    }

    pub async fn rotate_node(&self) -> Option<String> {
        if self.config.node_urls.is_empty() {
            return None;
        }
        let mut index = self.active_index.lock().await;
        *index = (*index + 1) % self.config.node_urls.len();
        self.config.node_urls.get(*index).cloned()
    }

    pub async fn record_error(&self, message: impl Into<String>) {
        *self.last_error.write().await = Some(message.into());
    }

    pub async fn clear_error(&self) {
        *self.last_error.write().await = None;
    }

    pub async fn get_contract_data(&self, contract_address: &str) -> Result<Value> {
        self.try_across_nodes("get_contract_data", |node| {
            let node = node.to_string();
            let contract_address = contract_address.to_string();
            async move {
                let url = format!(
                    "{node}/shards/Shard0/blockchain/contracts/{contract_address}?requireContractState=true"
                );
                let response = self
                    .client
                    .get(&url)
                    .send()
                    .await
                    .with_context(|| format!("GET {url}"))?;
                let status = response.status();
                if !status.is_success() {
                    return Err(anyhow!("contract read failed with HTTP {status}"));
                }
                let body: Value = response.json().await.context("decode contract state json")?;
                Ok(body.get("serializedContract").cloned().unwrap_or(body))
            }
        })
        .await
    }

    pub async fn poll_contract_data_until<F, T>(
        &self,
        contract_address: &str,
        interval: Duration,
        timeout: Duration,
        selector: F,
    ) -> Result<T>
    where
        F: Fn(&Value) -> Option<T>,
    {
        let started = tokio::time::Instant::now();
        loop {
            let state = self.get_contract_data(contract_address).await?;
            if let Some(value) = selector(&state) {
                return Ok(value);
            }
            if started.elapsed() >= timeout {
                let message = format!(
                    "timed out polling contract {contract_address} after {}ms",
                    timeout.as_millis()
                );
                self.record_error(message.clone()).await;
                return Err(anyhow!(message));
            }
            tokio::time::sleep(interval).await;
        }
    }

    pub async fn submit_action(
        &self,
        contract_address: &str,
        action: &str,
        payload: &[u8],
        gas_cost: u64,
    ) -> Result<SubmitActionResult> {
        let sender_address = self
            .config
            .sender_address
            .clone()
            .ok_or_else(|| anyhow!("PARTISIA_SENDER_ADDRESS is required for submit_action"))?;
        let sender_key = self
            .config
            .sender_key
            .clone()
            .ok_or_else(|| anyhow!("PARTISIA_SENDER_KEY is required for submit_action"))?;
        let sender_key = sender_key;
        let sender_address = sender_address;
        self.try_across_nodes(action, |node| {
            let node = node.to_string();
            let contract_address = contract_address.to_string();
            let payload = payload.to_vec();
            let sender_key = sender_key.clone();
            let sender_address = sender_address.clone();
            async move {
                let mut attempted_nonce_retry = false;
                let submitted = loop {
                    let reserved = self.reserve_sender_state(&node, &sender_address).await?;
                    let signed = sign_transaction(
                        &sender_key,
                        reserved.next_nonce,
                        current_time_millis() + self.config.confirm_timeout.as_millis() as i64,
                        gas_cost as i64,
                        &reserved.chain_id,
                        &contract_address,
                        &payload,
                    )?;
                    match submit_serialized_transaction(&self.client, &node, &signed).await {
                        Ok(submitted) => break submitted,
                        Err(err) if !attempted_nonce_retry && is_unexpected_nonce_error(&err) => {
                            attempted_nonce_retry = true;
                            self.invalidate_sender_state().await;
                            continue;
                        }
                        Err(err) => {
                            self.invalidate_sender_state().await;
                            return Err(err);
                        }
                    }
                };
                let tree = wait_for_spawned_events(
                    &self.client,
                    &node,
                    &submitted.destination_shard_id,
                    &submitted.tx_hash,
                    self.config.confirm_timeout,
                    self.config.poll_interval,
                )
                .await?;
                ensure_execution_success(&tree)?;
                Ok(submitted)
            }
        })
        .await
    }

    pub async fn submit_action_pipeline(
        &self,
        contract_address: &str,
        actions: &[PipelineAction],
    ) -> Result<Vec<SubmitActionResult>> {
        if actions.is_empty() {
            return Ok(vec![]);
        }
        let sender_address = self.config.sender_address.clone().ok_or_else(|| {
            anyhow!("PARTISIA_SENDER_ADDRESS is required for submit_action_pipeline")
        })?;
        let sender_key =
            self.config.sender_key.clone().ok_or_else(|| {
                anyhow!("PARTISIA_SENDER_KEY is required for submit_action_pipeline")
            })?;
        let node = self
            .active_node()
            .await
            .or_else(|| self.config.node_urls.first().cloned())
            .ok_or_else(|| anyhow!("submit_action_pipeline: no Partisia nodes configured"))?;

        let reserved = self
            .reserve_sender_nonces(&node, &sender_address, actions.len())
            .await?;
        let mut submitted = Vec::with_capacity(actions.len());
        for (offset, action) in actions.iter().enumerate() {
            let mut nonce = reserved.next_nonce + offset as i64;
            let chain_id = reserved.chain_id.clone();
            let mut attempted_nonce_retry = false;
            loop {
                let signed = sign_transaction(
                    &sender_key,
                    nonce,
                    current_time_millis() + self.config.confirm_timeout.as_millis() as i64,
                    action.gas_cost as i64,
                    &chain_id,
                    contract_address,
                    &action.payload,
                )?;
                match submit_serialized_transaction(&self.client, &node, &signed).await {
                    Ok(tx) => {
                        submitted.push(tx);
                        break;
                    }
                    Err(err) if !attempted_nonce_retry && is_unexpected_nonce_error(&err) => {
                        attempted_nonce_retry = true;
                        self.invalidate_sender_state().await;
                        let refreshed = self.reserve_sender_state(&node, &sender_address).await?;
                        nonce = refreshed.next_nonce;
                        continue;
                    }
                    Err(err) => {
                        self.invalidate_sender_state().await;
                        self.record_error(format!("{} via {}: {}", action.action, node, err))
                            .await;
                        return Err(err);
                    }
                }
            }
        }

        let mut results = Vec::with_capacity(submitted.len());
        for (action, tx) in actions.iter().zip(submitted.into_iter()) {
            let tree = wait_for_spawned_events(
                &self.client,
                &node,
                &tx.destination_shard_id,
                &tx.tx_hash,
                self.config.confirm_timeout,
                self.config.poll_interval,
            )
            .await
            .map_err(|err| anyhow!("{} via {}: {}", action.action, node, err))?;
            ensure_execution_success(&tree)
                .map_err(|err| anyhow!("{} via {}: {}", action.action, node, err))?;
            results.push(tx);
        }
        self.clear_error().await;
        Ok(results)
    }

    async fn reserve_sender_state(&self, node: &str, sender_address: &str) -> Result<SenderState> {
        let mut guard = self.sender_state.lock().await;
        if let Some(state) = guard.as_mut() {
            let reserved = SenderState {
                chain_id: state.chain_id.clone(),
                next_nonce: state.next_nonce,
            };
            state.next_nonce += 1;
            return Ok(reserved);
        }

        let chain_id = fetch_chain_id(&self.client, node).await?;
        let nonce = fetch_nonce(&self.client, node, sender_address).await?;
        *guard = Some(SenderState {
            chain_id: chain_id.clone(),
            next_nonce: nonce + 1,
        });
        Ok(SenderState {
            chain_id,
            next_nonce: nonce,
        })
    }

    async fn reserve_sender_nonces(
        &self,
        node: &str,
        sender_address: &str,
        count: usize,
    ) -> Result<SenderState> {
        let mut guard = self.sender_state.lock().await;
        if let Some(state) = guard.as_mut() {
            let reserved = SenderState {
                chain_id: state.chain_id.clone(),
                next_nonce: state.next_nonce,
            };
            state.next_nonce += count as i64;
            return Ok(reserved);
        }

        let chain_id = fetch_chain_id(&self.client, node).await?;
        let nonce = fetch_nonce(&self.client, node, sender_address).await?;
        *guard = Some(SenderState {
            chain_id: chain_id.clone(),
            next_nonce: nonce + count as i64,
        });
        Ok(SenderState {
            chain_id,
            next_nonce: nonce,
        })
    }

    async fn invalidate_sender_state(&self) {
        *self.sender_state.lock().await = None;
    }

    async fn try_across_nodes<F, Fut, T>(&self, label: &str, mut op: F) -> Result<T>
    where
        F: FnMut(&str) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        if self.config.node_urls.is_empty() {
            let message = format!("{label}: no Partisia nodes configured");
            self.record_error(message.clone()).await;
            return Err(anyhow!(message));
        }

        let start_index = *self.active_index.lock().await;
        let attempts = self
            .config
            .node_urls
            .len()
            .min(self.config.max_retries.max(1) as usize);
        let mut last_error = None;

        for offset in 0..attempts {
            let index = (start_index + offset) % self.config.node_urls.len();
            let node = self.config.node_urls[index].clone();
            match op(&node).await {
                Ok(value) => {
                    *self.active_index.lock().await = index;
                    self.clear_error().await;
                    return Ok(value);
                }
                Err(err) => {
                    last_error = Some(format!("{label} via {node}: {err}"));
                    self.record_error(last_error.clone().unwrap()).await;
                    if offset + 1 < attempts {
                        *self.active_index.lock().await = (index + 1) % self.config.node_urls.len();
                    }
                }
            }
        }

        Err(anyhow!(
            last_error.unwrap_or_else(|| format!("{label} failed"))
        ))
    }
}

fn is_unexpected_nonce_error(err: &anyhow::Error) -> bool {
    let message = err.to_string();
    message.contains("UNEXPECTED_NONCE")
        || message.contains("transaction nonce did not match the expected nonce")
}

async fn fetch_chain_id(client: &Client, node: &str) -> Result<String> {
    let url = format!("{node}/chain");
    let response = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!("get chain failed with HTTP {status}: {body}"));
    }
    let body: Value = response.json().await.context("decode chain json")?;
    body.get("chainId")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("chainId missing from chain response"))
}

async fn fetch_account(client: &Client, node: &str, sender_address: &str) -> Result<Value> {
    let url = format!("{node}/chain/accounts/{sender_address}");
    let response = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!("get account failed with HTTP {status}: {body}"));
    }
    response.json().await.context("decode account json")
}

fn max_gas_balance(account: &Value) -> Option<u64> {
    account
        .get("account")
        .and_then(|v| v.get("accountCoins"))
        .and_then(Value::as_array)
        .and_then(|coins| {
            coins
                .iter()
                .filter_map(|coin| coin.get("balance").and_then(Value::as_str))
                .filter_map(|balance| balance.parse::<u64>().ok())
                .max()
        })
}

async fn fetch_nonce(client: &Client, node: &str, sender_address: &str) -> Result<i64> {
    let url = format!("{node}/chain/accounts/{sender_address}");
    let response = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!("get nonce failed with HTTP {status}: {body}"));
    }
    let body = fetch_account(client, node, sender_address).await?;
    body.get("nonce")
        .and_then(Value::as_i64)
        .ok_or_else(|| anyhow!("nonce missing from account response"))
}

fn sign_transaction(
    sender_key_hex: &str,
    nonce: i64,
    valid_to_time: i64,
    gas_cost: i64,
    chain_id: &str,
    contract_address: &str,
    rpc: &[u8],
) -> Result<Vec<u8>> {
    let inner = serialize_inner_transaction(nonce, valid_to_time, gas_cost, contract_address, rpc)?;
    let mut chain_encoded = Vec::new();
    write_i32_be(&mut chain_encoded, chain_id.len() as i32);
    chain_encoded.extend_from_slice(chain_id.as_bytes());

    let hash = sha256_many(&[&inner, &chain_encoded]);
    let signing_key_bytes = hex::decode(sender_key_hex.trim_start_matches("0x"))
        .context("decode PARTISIA_SENDER_KEY")?;
    let signing_key = SigningKey::from_slice(&signing_key_bytes)
        .map_err(|err| anyhow!("invalid PARTISIA_SENDER_KEY: {err}"))?;
    let (signature, recovery_id) = signing_key
        .sign_prehash_recoverable(&hash)
        .map_err(|err| anyhow!("sign Partisia transaction: {err}"))?;
    Ok(serialize_signed_transaction(
        recovery_id,
        &signature,
        &inner,
    ))
}

fn serialize_inner_transaction(
    nonce: i64,
    valid_to_time: i64,
    gas_cost: i64,
    contract_address: &str,
    rpc: &[u8],
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    write_i64_be(&mut out, nonce);
    write_i64_be(&mut out, valid_to_time);
    write_i64_be(&mut out, gas_cost);
    let address = hex::decode(contract_address.trim_start_matches("0x"))
        .context("decode contract address")?;
    out.extend_from_slice(&address);
    write_i32_be(&mut out, rpc.len() as i32);
    out.extend_from_slice(rpc);
    Ok(out)
}

fn serialize_signed_transaction(
    recovery_id: RecoveryId,
    signature: &Signature,
    inner: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(65 + inner.len());
    out.push(recovery_id.to_byte());
    out.extend_from_slice(&signature.r().to_bytes());
    out.extend_from_slice(&signature.s().to_bytes());
    out.extend_from_slice(inner);
    out
}

async fn submit_serialized_transaction(
    client: &Client,
    node: &str,
    signed: &[u8],
) -> Result<SubmitActionResult> {
    let url = format!("{node}/chain/transactions");
    let payload = serde_json::json!({
        "payload": base64::engine::general_purpose::STANDARD.encode(signed)
    });
    let response = client
        .put(&url)
        .json(&payload)
        .send()
        .await
        .with_context(|| format!("PUT {url}"))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!("put transaction failed with HTTP {status}: {body}"));
    }
    let body: Value = response
        .json()
        .await
        .context("decode putTransaction json")?;
    let tx_hash = body
        .get("identifier")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("transaction identifier missing"))?;
    let destination_shard_id = body
        .get("destinationShardId")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| "Shard0".to_string());
    Ok(SubmitActionResult {
        tx_hash,
        node_url: node.to_string(),
        destination_shard_id,
    })
}

async fn wait_for_spawned_events(
    client: &Client,
    node: &str,
    shard_id: &str,
    tx_id: &str,
    timeout: Duration,
    poll_interval: Duration,
) -> Result<Value> {
    let started = tokio::time::Instant::now();
    let root = loop {
        let maybe = get_transaction(client, node, shard_id, tx_id).await?;
        if let Some(maybe) = maybe {
            if maybe.get("executionStatus").is_some() {
                break maybe;
            }
        }
        if started.elapsed() >= timeout {
            return Err(anyhow!("timed out waiting for transaction inclusion"));
        }
        tokio::time::sleep(poll_interval).await;
    };

    let mut events = Vec::new();
    let mut pending = root
        .get("executionStatus")
        .and_then(|s| s.get("events"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    while let Some(event) = pending.first().cloned() {
        pending.remove(0);
        let shard = event
            .get("destinationShardId")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("spawned event missing shard"))?;
        let id = event
            .get("identifier")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("spawned event missing identifier"))?;
        let executed = loop {
            let maybe = get_transaction(client, node, shard, id).await?;
            if let Some(maybe) = maybe {
                if maybe.get("executionStatus").is_some() {
                    break maybe;
                }
            }
            if started.elapsed() >= timeout {
                return Err(anyhow!("timed out waiting for spawned event inclusion"));
            }
            tokio::time::sleep(poll_interval).await;
        };
        if let Some(spawned) = executed
            .get("executionStatus")
            .and_then(|s| s.get("events"))
            .and_then(Value::as_array)
        {
            pending.extend(spawned.iter().cloned());
        }
        events.push(executed);
    }

    Ok(serde_json::json!({ "root": root, "events": events }))
}

async fn get_transaction(
    client: &Client,
    node: &str,
    shard_id: &str,
    tx_id: &str,
) -> Result<Option<Value>> {
    let url = format!("{node}/chain/shards/{shard_id}/transactions/{tx_id}");
    let response = client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!("get transaction failed with HTTP {status}: {body}"));
    }
    Ok(Some(
        response
            .json()
            .await
            .context("decode executed transaction json")?,
    ))
}

fn ensure_execution_success(tree: &Value) -> Result<()> {
    let root_status = tree
        .get("root")
        .and_then(|root| root.get("executionStatus"))
        .ok_or_else(|| anyhow!("missing root executionStatus"))?;
    ensure_status_success(root_status, "contract failure")?;
    if let Some(events) = tree.get("events").and_then(Value::as_array) {
        for event in events {
            let status = event
                .get("executionStatus")
                .ok_or_else(|| anyhow!("missing spawned event executionStatus"))?;
            ensure_status_success(status, "spawned failure")?;
        }
    }
    Ok(())
}

fn ensure_status_success(status: &Value, prefix: &str) -> Result<()> {
    if status.get("success").and_then(Value::as_bool) == Some(false) {
        let message = status
            .get("failure")
            .and_then(|f| f.get("errorMessage"))
            .and_then(Value::as_str)
            .or_else(|| status.get("errorMessage").and_then(Value::as_str))
            .unwrap_or("unknown error");
        return Err(anyhow!(
            "{prefix}: {}",
            message.lines().next().unwrap_or(message)
        ));
    }
    Ok(())
}

fn write_i32_be(out: &mut Vec<u8>, value: i32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_i64_be(out: &mut Vec<u8>, value: i64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn sha256_many(buffers: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for buffer in buffers {
        hasher.update(buffer);
    }
    hasher.finalize().into()
}

fn current_time_millis() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::{ChainRelay, ChainRelayConfig};
    use anyhow::anyhow;
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::Duration,
    };

    fn relay_for(nodes: Vec<String>) -> ChainRelay {
        ChainRelay::new(ChainRelayConfig {
            node_urls: nodes,
            sender_address: Some("sender".to_string()),
            sender_key: Some("key".to_string()),
            confirm_timeout: Duration::from_secs(1),
            poll_interval: Duration::from_millis(10),
            max_retries: 7,
        })
    }

    #[tokio::test]
    async fn rotates_to_next_node_when_first_attempt_fails() {
        let relay = relay_for(vec![
            "https://node1.example".to_string(),
            "https://node2.example".to_string(),
        ]);
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();

        let value: String = relay
            .try_across_nodes("test-op", move |node| {
                let calls_clone = calls_clone.clone();
                let node = node.to_string();
                async move {
                    let attempt = calls_clone.fetch_add(1, Ordering::SeqCst);
                    if attempt == 0 {
                        Err(anyhow!("boom on {node}"))
                    } else {
                        Ok(node)
                    }
                }
            })
            .await
            .unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(value, "https://node2.example");
        assert_eq!(
            relay.active_node().await,
            Some("https://node2.example".to_string())
        );
    }

    #[tokio::test]
    async fn preserves_last_error_when_all_attempts_fail() {
        let relay = relay_for(vec![
            "https://node1.example".to_string(),
            "https://node2.example".to_string(),
        ]);

        let err = relay
            .try_across_nodes("test-op", |_node| async {
                Err::<String, _>(anyhow!("still failing"))
            })
            .await
            .unwrap_err();

        assert!(err.to_string().contains("still failing"));
        let health = relay.health().await;
        assert!(health
            .last_error
            .unwrap()
            .contains("test-op via https://node2.example"));
    }

    #[tokio::test]
    async fn submit_action_requires_sender_configuration() {
        let relay = ChainRelay::new(ChainRelayConfig {
            node_urls: vec!["https://node1.example".to_string()],
            sender_address: None,
            sender_key: None,
            confirm_timeout: Duration::from_secs(1),
            poll_interval: Duration::from_millis(10),
            max_retries: 1,
        });

        let err = relay
            .submit_action(
                "03134ea5680d7681863d25f99e28ca30dfb44adb9b",
                "sign_message",
                b"payload",
                500_000,
            )
            .await
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("PARTISIA_SENDER_ADDRESS is required"));
    }
}
