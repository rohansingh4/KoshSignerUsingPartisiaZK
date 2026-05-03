use anyhow::{anyhow, Result};
use base64::Engine;
use k256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey};
use kosh_zk_signer::signing_state::{
    SigningInformation, ZkKeyGenPhase, ZkKeyState, ZkSigningPhase,
};
use pbc_traits::ReadWriteState;
use serde::Serialize;
use serde_json::Value;
use sha3::{Digest, Keccak256};
use std::panic::{catch_unwind, AssertUnwindSafe};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdKeyStatus {
    pub key_id: u32,
    pub exists: bool,
    pub public_key_hex: Option<String>,
    pub evm_address: Option<String>,
    pub keygen_phase_discriminant: Option<u64>,
    pub signing_phase_discriminant: Option<u64>,
    pub verified_task_ids: Vec<u32>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ThresholdTaskSignature {
    pub key_id: u32,
    pub task_id: u32,
    pub verified: bool,
    pub signature_hex: Option<String>,
}

pub async fn threshold_key_status(state: &Value, key_id: u32) -> Result<ThresholdKeyStatus> {
    if let Some(key) = read_keys(state).and_then(|keys| keys.get(&key_id.to_string())) {
        return threshold_key_status_from_decoded(key_id, key);
    }

    if let Some(key) = maybe_decode_from_avl_tree(state, key_id).await? {
        return threshold_key_status_from_typed(state, key_id, &key);
    }

    if looks_like_decoded_key_state(state) {
        return threshold_key_status_from_decoded(key_id, state);
    }

    Ok(missing_key_status(key_id))
}

pub async fn decode_key_state(state: &Value, key_id: u32) -> Result<Option<ZkKeyState>> {
    maybe_decode_from_avl_tree(state, key_id).await
}

pub async fn threshold_task_signature(
    state: &Value,
    key_id: u32,
    task_id: u32,
) -> Result<ThresholdTaskSignature> {
    if let Some(key) = read_keys(state).and_then(|keys| keys.get(&key_id.to_string())) {
        return Ok(threshold_task_signature_from_decoded(key_id, task_id, key));
    }

    if let Some(key) = maybe_decode_from_avl_tree(state, key_id).await? {
        return Ok(threshold_task_signature_from_typed(
            state, key_id, task_id, &key,
        ));
    }

    if looks_like_decoded_key_state(state) {
        return Ok(threshold_task_signature_from_decoded(
            key_id, task_id, state,
        ));
    }

    Ok(ThresholdTaskSignature {
        key_id,
        task_id,
        verified: false,
        signature_hex: None,
    })
}

fn threshold_key_status_from_decoded(key_id: u32, key: &Value) -> Result<ThresholdKeyStatus> {
    let public_key_hex = key
        .get("public_key")
        .and_then(parse_optional_hex_field)
        .map(normalize_hex);
    let evm_address = public_key_hex
        .as_deref()
        .map(pub_key_to_evm_address)
        .transpose()?;
    let verified_task_ids = read_signing_information_entries(key)
        .into_iter()
        .filter(|(_, value)| {
            value
                .get("verified")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        })
        .filter_map(|(task_id, _)| parse_task_id(&task_id))
        .collect::<Vec<_>>();

    Ok(ThresholdKeyStatus {
        key_id,
        exists: true,
        public_key_hex,
        evm_address,
        keygen_phase_discriminant: parse_phase_discriminant(key.get("keygen_phase")),
        signing_phase_discriminant: parse_phase_discriminant(key.get("signing_phase")),
        verified_task_ids,
    })
}

fn threshold_task_signature_from_decoded(
    key_id: u32,
    task_id: u32,
    key: &Value,
) -> ThresholdTaskSignature {
    let task = read_signing_information_entries(key)
        .into_iter()
        .find(|(entry_task_id, _)| parse_task_id(entry_task_id) == Some(task_id))
        .map(|(_, value)| value)
        .unwrap_or(Value::Null);

    ThresholdTaskSignature {
        key_id,
        task_id,
        verified: task
            .get("verified")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        signature_hex: task
            .get("signature")
            .and_then(parse_optional_hex_field)
            .map(normalize_hex),
    }
}

fn threshold_key_status_from_typed(
    state: &Value,
    key_id: u32,
    key: &ZkKeyState,
) -> Result<ThresholdKeyStatus> {
    let public_key_hex = key
        .public_key
        .as_ref()
        .map(|bytes| format!("0x{}", hex::encode(bytes)));
    let evm_address = public_key_hex
        .as_deref()
        .map(pub_key_to_evm_address)
        .transpose()?;
    let verified_task_ids = read_signing_information_from_avl(state, &key.signing_information)
        .into_iter()
        .filter_map(|(task_id, info)| info.verified.then_some(task_id))
        .collect::<Vec<_>>();

    Ok(ThresholdKeyStatus {
        key_id,
        exists: true,
        public_key_hex,
        evm_address,
        keygen_phase_discriminant: Some(keygen_phase_discriminant(&key.keygen_phase)),
        signing_phase_discriminant: Some(signing_phase_discriminant(&key.signing_phase)),
        verified_task_ids,
    })
}

fn threshold_task_signature_from_typed(
    state: &Value,
    key_id: u32,
    task_id: u32,
    key: &ZkKeyState,
) -> ThresholdTaskSignature {
    let maybe_info = read_signing_information_from_avl(state, &key.signing_information)
        .into_iter()
        .find(|(candidate_task_id, _)| *candidate_task_id == task_id)
        .map(|(_, info)| info);
    if let Some(info) = maybe_info {
        threshold_task_signature_from_info(key_id, task_id, &info)
    } else {
        ThresholdTaskSignature {
            key_id,
            task_id,
            verified: false,
            signature_hex: None,
        }
    }
}

fn threshold_task_signature_from_info(
    key_id: u32,
    task_id: u32,
    info: &SigningInformation,
) -> ThresholdTaskSignature {
    ThresholdTaskSignature {
        key_id,
        task_id,
        verified: info.verified,
        signature_hex: info
            .signature
            .as_ref()
            .map(|bytes| format!("0x{}", hex::encode(bytes))),
    }
}

fn missing_key_status(key_id: u32) -> ThresholdKeyStatus {
    ThresholdKeyStatus {
        key_id,
        exists: false,
        public_key_hex: None,
        evm_address: None,
        keygen_phase_discriminant: None,
        signing_phase_discriminant: None,
        verified_task_ids: vec![],
    }
}

fn read_keys(state: &Value) -> Option<&serde_json::Map<String, Value>> {
    state
        .get("keys")
        .and_then(Value::as_object)
        .or_else(|| {
            state
                .get("openState")
                .and_then(|value| value.get("keys"))
                .and_then(Value::as_object)
        })
        .or_else(|| {
            state
                .get("state")
                .and_then(|value| value.get("keys"))
                .and_then(Value::as_object)
        })
        .or_else(|| {
            state
                .get("state")
                .and_then(|value| value.get("openState"))
                .and_then(|value| value.get("keys"))
                .and_then(Value::as_object)
        })
}

fn looks_like_decoded_key_state(state: &Value) -> bool {
    state.get("public_key").is_some()
        && state.get("keygen_phase").is_some()
        && state.get("signing_information").is_some()
}

fn parse_optional_hex_field(value: &Value) -> Option<&str> {
    if let Some(value) = value.as_str() {
        return Some(value);
    }
    value
        .get("isSome")
        .and_then(Value::as_bool)
        .filter(|is_some| *is_some)
        .and_then(|_| value.get("innerValue"))
        .and_then(Value::as_str)
}

fn parse_phase_discriminant(phase: Option<&Value>) -> Option<u64> {
    let phase = phase?;
    if let Some(discriminant) = phase.get("discriminant").and_then(Value::as_u64) {
        return Some(discriminant);
    }
    match phase.get("@type").and_then(Value::as_str) {
        Some("Idle") => Some(0),
        Some("Started") => Some(1),
        Some("Complete") => Some(2),
        Some("Completed") => Some(2),
        _ => None,
    }
}

fn read_signing_information_from_avl(
    state: &Value,
    map: &impl ReadWriteState,
) -> Vec<(u32, SigningInformation)> {
    let tree_id = avl_tree_id(map);
    let Some(entries) = find_avl_tree_entries(state, tree_id) else {
        return vec![];
    };

    let mut decoded = entries
        .iter()
        .filter_map(|entry| {
            let key_b64 = entry
                .get("key")
                .and_then(|key| key.get("data"))
                .and_then(|data| data.get("data"))
                .and_then(Value::as_str)?;
            let key_bytes = base64::engine::general_purpose::STANDARD
                .decode(key_b64)
                .ok()?;
            if key_bytes.len() != 4 {
                return None;
            }
            let task_id =
                u32::from_le_bytes([key_bytes[0], key_bytes[1], key_bytes[2], key_bytes[3]]);
            let value_b64 = entry
                .get("value")
                .and_then(|value| value.get("data"))
                .and_then(Value::as_str)?;
            let value_bytes = base64::engine::general_purpose::STANDARD
                .decode(value_b64)
                .ok()?;
            let info = SigningInformation::state_read_from(&mut value_bytes.as_slice());
            Some((task_id, info))
        })
        .collect::<Vec<_>>();
    decoded.sort_by_key(|(task_id, _)| *task_id);
    decoded
}

fn avl_tree_id(map: &impl ReadWriteState) -> u64 {
    let mut bytes = Vec::new();
    map.state_write_to(&mut bytes)
        .expect("serialize avl tree id");
    i32::from_le_bytes(bytes[..4].try_into().expect("tree id bytes")) as u64
}

fn find_avl_tree_entries<'a>(state: &'a Value, tree_id: u64) -> Option<&'a Vec<Value>> {
    avl_trees_root(state)?
        .iter()
        .find(|tree| tree.get("key").and_then(Value::as_u64) == Some(tree_id))
        .and_then(|tree| tree.get("value"))
        .and_then(|value| value.get("avlTree"))
        .and_then(Value::as_array)
}

fn avl_trees_root(state: &Value) -> Option<&Vec<Value>> {
    state
        .get("openState")
        .and_then(|value| value.get("avlTrees"))
        .and_then(Value::as_array)
        .or_else(|| {
            state
                .get("serializedContract")
                .and_then(|value| value.get("openState"))
                .and_then(|value| value.get("avlTrees"))
                .and_then(Value::as_array)
        })
}

fn read_signing_information_entries(key: &Value) -> Vec<(String, Value)> {
    if let Some(entries) = key
        .get("signing_information")
        .and_then(|value| value.get("map"))
        .and_then(Value::as_array)
    {
        let mut collected = entries
            .iter()
            .filter_map(|entry| {
                let key = entry.get("key")?;
                let value = entry.get("value")?.clone();
                Some((key.to_string(), value))
            })
            .collect::<Vec<_>>();
        collected.sort_by_key(|(k, _)| parse_task_id(k).unwrap_or(u32::MAX));
        return collected;
    }

    if let Some(entries) = key.get("signing_information").and_then(Value::as_object) {
        let mut collected = entries
            .iter()
            .filter(|(k, _)| *k != "treeId" && *k != "map")
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<Vec<_>>();
        collected.sort_by_key(|(k, _)| parse_task_id(k).unwrap_or(u32::MAX));
        return collected;
    }

    key.get("signing_information")
        .and_then(|value| value.get("map"))
        .and_then(Value::as_array)
        .map(|entries| {
            let mut collected = entries
                .iter()
                .filter_map(|entry| {
                    let key = entry.get("key")?;
                    let value = entry.get("value")?.clone();
                    Some((key.to_string(), value))
                })
                .collect::<Vec<_>>();
            collected.sort_by_key(|(k, _)| parse_task_id(k).unwrap_or(u32::MAX));
            collected
        })
        .unwrap_or_default()
}

fn parse_task_id(raw: &str) -> Option<u32> {
    raw.trim_matches('"').parse::<u32>().ok()
}

async fn maybe_decode_from_avl_tree(state: &Value, key_id: u32) -> Result<Option<ZkKeyState>> {
    let tree_entry_count = avl_trees_root(state)
        .and_then(|trees| {
            trees
                .iter()
                .find(|tree| tree.get("key").and_then(Value::as_u64) == Some(0))
        })
        .and_then(|tree| tree.get("value"))
        .and_then(|value| value.get("avlTree"))
        .and_then(Value::as_array)
        .map(|entries| entries.len())
        .unwrap_or(0);

    if tree_entry_count == 0 {
        return Ok(None);
    }
    let lookup_key_b64 = encode_key_id_base64(key_id);
    let avl_entries = avl_trees_root(state)
        .and_then(|trees| {
            trees
                .iter()
                .find(|tree| tree.get("key").and_then(Value::as_u64) == Some(0))
        })
        .and_then(|tree| tree.get("value"))
        .and_then(|value| value.get("avlTree"))
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("missing avl tree entries"))?;

    let entry = avl_entries.iter().find(|entry| {
        entry
            .get("key")
            .and_then(|key| key.get("data"))
            .and_then(|data| data.get("data"))
            .and_then(Value::as_str)
            == Some(lookup_key_b64.as_str())
    });

    let Some(entry) = entry else {
        return Ok(None);
    };
    let value_b64 = entry
        .get("value")
        .and_then(|value| value.get("data"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing avl tree value bytes"))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value_b64)
        .map_err(|err| anyhow!("decode avl tree value: {err}"))?;
    let decoded = catch_unwind(AssertUnwindSafe(|| {
        ZkKeyState::state_read_from(&mut bytes.as_slice())
    }))
    .map_err(|_| anyhow!("panic while decoding avl tree value"))?;
    Ok(Some(decoded))
}

fn encode_key_id_base64(key_id: u32) -> String {
    base64::engine::general_purpose::STANDARD.encode([
        (key_id & 0xff) as u8,
        ((key_id >> 8) & 0xff) as u8,
        ((key_id >> 16) & 0xff) as u8,
        ((key_id >> 24) & 0xff) as u8,
    ])
}

fn keygen_phase_discriminant(phase: &ZkKeyGenPhase) -> u64 {
    match phase {
        ZkKeyGenPhase::WaitingForDealer {} => 0,
        ZkKeyGenPhase::SubmittingShares {} => 1,
        ZkKeyGenPhase::Complete {} => 2,
        ZkKeyGenPhase::DkgCommitting {} => 3,
        ZkKeyGenPhase::DkgRevealing {} => 4,
        ZkKeyGenPhase::DkgFinalized {} => 5,
    }
}

fn signing_phase_discriminant(phase: &ZkSigningPhase) -> u64 {
    match phase {
        ZkSigningPhase::Idle {} => 0,
        ZkSigningPhase::ReconstructingKey { .. } => 1,
        ZkSigningPhase::Signing { .. } => 2,
        ZkSigningPhase::Complete { .. } => 3,
        ZkSigningPhase::ThresholdSigning { .. } => 4,
        ZkSigningPhase::NonceCommitting { .. } => 5,
        ZkSigningPhase::NonceRevealing { .. } => 6,
    }
}

fn normalize_hex(value: &str) -> String {
    if value.starts_with("0x") {
        value.to_string()
    } else {
        format!("0x{value}")
    }
}

fn pub_key_to_evm_address(public_key_hex: &str) -> Result<String> {
    let normalized = public_key_hex.trim_start_matches("0x");
    let bytes = hex::decode(normalized).map_err(|err| anyhow!("invalid public key hex: {err}"))?;
    let public_key =
        PublicKey::from_sec1_bytes(&bytes).map_err(|_| anyhow!("invalid secp256k1 public key"))?;
    let uncompressed = public_key.to_encoded_point(false);
    let key_bytes = uncompressed.as_bytes();
    let digest = Keccak256::digest(&key_bytes[1..]);
    Ok(format!("0x{}", hex::encode(&digest[12..])))
}

#[cfg(test)]
mod tests {
    use super::{threshold_key_status, threshold_task_signature};
    use serde_json::json;

    #[tokio::test]
    async fn reads_key_status_and_signature_from_keys_map() {
        let state = json!({
            "keys": {
                "62003": {
                    "public_key": "026773160817a77fc23eca37599b22832c9453dd89833f3c8655ea93587e40e5e3",
                    "keygen_phase": { "discriminant": 2 },
                    "signing_phase": { "discriminant": 0 },
                    "signing_information": {
                        "6": {
                            "verified": true,
                            "signature": "0xdeadbeef"
                        },
                        "7": {
                            "verified": false,
                            "signature": null
                        }
                    }
                }
            }
        });

        let status = threshold_key_status(&state, 62003).await.unwrap();
        assert!(status.exists);
        assert_eq!(status.verified_task_ids, vec![6]);
        assert_eq!(
            status.evm_address.as_deref(),
            Some("0xa048c839b129149354a1403113ed66e4b2b678ac")
        );

        let task = threshold_task_signature(&state, 62003, 6).await.unwrap();
        assert!(task.verified);
        assert_eq!(task.signature_hex.as_deref(), Some("0xdeadbeef"));
    }

    #[tokio::test]
    async fn reads_key_status_and_signature_from_decoded_state() {
        let state = json!({
            "public_key": { "isSome": true, "innerValue": "026773160817a77fc23eca37599b22832c9453dd89833f3c8655ea93587e40e5e3" },
            "keygen_phase": { "@type": "Complete" },
            "signing_phase": { "@type": "Idle" },
            "signing_information": {
                "treeId": 2,
                "map": [
                    { "key": 6, "value": { "verified": true, "signature": { "isSome": true, "innerValue": "deadbeef" } } },
                    { "key": 7, "value": { "verified": false, "signature": { "isSome": false } } }
                ]
            }
        });

        let status = threshold_key_status(&state, 60004).await.unwrap();
        assert!(status.exists);
        assert_eq!(status.verified_task_ids, vec![6]);
        assert_eq!(status.keygen_phase_discriminant, Some(2));
        assert_eq!(status.signing_phase_discriminant, Some(0));
        assert_eq!(
            status.public_key_hex.as_deref(),
            Some("0x026773160817a77fc23eca37599b22832c9453dd89833f3c8655ea93587e40e5e3")
        );

        let task = threshold_task_signature(&state, 60004, 6).await.unwrap();
        assert!(task.verified);
        assert_eq!(task.signature_hex.as_deref(), Some("0xdeadbeef"));
    }
}
