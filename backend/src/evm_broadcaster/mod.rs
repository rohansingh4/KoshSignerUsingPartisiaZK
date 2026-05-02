use anyhow::{anyhow, Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct EvmBroadcasterConfig {
    pub rpc_url: Option<String>,
    pub chain_id: u64,
}

#[derive(Clone)]
pub struct EvmBroadcaster {
    config: EvmBroadcasterConfig,
    client: Client,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedEthTransfer {
    pub from: String,
    pub to: String,
    pub value_wei: String,
    pub chain_id: u64,
    pub nonce: u64,
    pub max_fee_per_gas: String,
    pub max_priority_fee_per_gas: String,
    pub gas_limit: u64,
    pub tx_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastSignedTxRequest {
    pub signed_tx_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastSignedTxResult {
    pub chain: String,
    pub chain_id: u64,
    pub tx_hash: String,
    pub rpc_url: Option<String>,
    pub submitted: bool,
}

impl EvmBroadcaster {
    pub fn new(config: EvmBroadcasterConfig) -> Self {
        Self {
            config,
            client: Client::new(),
        }
    }

    pub fn chain_id(&self) -> u64 {
        self.config.chain_id
    }

    pub async fn broadcast_signed_transaction(
        &self,
        signed_tx_hex: &str,
    ) -> Result<BroadcastSignedTxResult> {
        let tx_hash = pseudo_tx_hash(signed_tx_hex)?;
        let Some(rpc_url) = self.config.rpc_url.clone() else {
            return Ok(BroadcastSignedTxResult {
                chain: "ethereum-sepolia".to_string(),
                chain_id: self.config.chain_id,
                tx_hash,
                rpc_url: None,
                submitted: false,
            });
        };

        let payload = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_sendRawTransaction",
            "params": [normalize_hex(signed_tx_hex)?],
        });
        let response: serde_json::Value = self
            .client
            .post(&rpc_url)
            .json(&payload)
            .send()
            .await
            .with_context(|| format!("post Sepolia RPC to {rpc_url}"))?
            .json()
            .await
            .context("decode Sepolia RPC response")?;

        if let Some(err) = response.get("error") {
            return Err(anyhow!("Sepolia RPC error: {err}"));
        }
        let tx_hash = response
            .get("result")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned)
            .unwrap_or(tx_hash);

        Ok(BroadcastSignedTxResult {
            chain: "ethereum-sepolia".to_string(),
            chain_id: self.config.chain_id,
            tx_hash,
            rpc_url: Some(rpc_url),
            submitted: true,
        })
    }
}

fn normalize_hex(value: &str) -> Result<String> {
    let normalized = if value.starts_with("0x") {
        value.to_string()
    } else {
        format!("0x{value}")
    };
    if normalized.len() <= 2 {
        return Err(anyhow!("empty signed transaction"));
    }
    Ok(normalized)
}

fn pseudo_tx_hash(signed_tx_hex: &str) -> Result<String> {
    let bytes = hex::decode(signed_tx_hex.trim_start_matches("0x"))?;
    let digest = Sha256::digest(bytes);
    Ok(format!("0x{}", hex::encode(digest)))
}
