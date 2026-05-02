use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedPartyRuntime {
    pub contract_address: String,
    pub key_id: u32,
    pub party_index: u8,
    pub public_key_hex: String,
    pub next_task_id: u32,
    pub shamir_share_hex: String,
    pub runtime_version: String,
}
