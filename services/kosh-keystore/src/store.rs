// AES-256-GCM encrypted keystore — ported from backend/src/keystore/mod.rs.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, path::{Path, PathBuf}, sync::Arc};
use tokio::task;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ShareRecord {
    pub contract_address: String,
    pub key_id:           u32,
    pub party_index:      u8,
    pub public_key_hex:   String,
    pub shamir_share_hex: String,
    pub next_task_id:     u32,
    pub runtime_version:  String,
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    nonce_b64:      String,
    ciphertext_b64: String,
    key_id:         u32,
    party_index:    u8,
}

#[derive(Clone)]
pub struct KeyStore {
    root:   Arc<PathBuf>,
    cipher: Arc<Aes256Gcm>,
}

impl KeyStore {
    pub fn new(root: impl Into<PathBuf>, master_key_hex: &str) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)
            .with_context(|| format!("create keystore dir {}", root.display()))?;
        let key_bytes = decode_key(master_key_hex)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
        Ok(Self { root: Arc::new(root), cipher: Arc::new(cipher) })
    }

    pub async fn store(&self, record: &ShareRecord) -> Result<PathBuf> {
        let name = share_filename(record.key_id, record.party_index);
        let path = self.root.join(&name);
        let cipher = Arc::clone(&self.cipher);
        let root = Arc::clone(&self.root);
        let plaintext = serde_json::to_vec(record)?;
        let key_id = record.key_id;
        let party_index = record.party_index;

        Ok(task::spawn_blocking(move || {
            fs::create_dir_all(root.as_path())?;
            let nonce_bytes = derive_nonce(key_id, party_index, &plaintext);
            let nonce = Nonce::from_slice(&nonce_bytes);
            let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
                .map_err(|_| anyhow!("encrypt share"))?;
            let envelope = Envelope {
                nonce_b64:      B64.encode(nonce_bytes),
                ciphertext_b64: B64.encode(&ciphertext),
                key_id, party_index,
            };
            fs::write(&path, serde_json::to_vec_pretty(&envelope)?)?;
            Ok::<PathBuf, anyhow::Error>(path)
        }).await??)
    }

    pub async fn load(&self, key_id: u32, party_index: u8) -> Result<ShareRecord> {
        let name = share_filename(key_id, party_index);
        let path = self.root.join(&name);
        let cipher = Arc::clone(&self.cipher);

        Ok(task::spawn_blocking(move || {
            let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let env: Envelope = serde_json::from_slice(&bytes)?;
            let nonce = B64.decode(&env.nonce_b64)?;
            let ct    = B64.decode(&env.ciphertext_b64)?;
            let mut pt = cipher.decrypt(Nonce::from_slice(&nonce), ct.as_ref())
                .map_err(|_| anyhow!("decrypt share"))?;
            let record = serde_json::from_slice::<ShareRecord>(&pt)?;
            pt.zeroize();
            Ok::<ShareRecord, anyhow::Error>(record)
        }).await??)
    }

    pub async fn exists(&self, key_id: u32, party_index: u8) -> bool {
        self.root.join(share_filename(key_id, party_index)).exists()
    }
}

fn share_filename(key_id: u32, party_index: u8) -> String {
    format!("share-key{key_id}-party{party_index}.enc")
}

fn decode_key(input: &str) -> Result<[u8; 32]> {
    let t = input.trim();
    let bytes = if let Some(h) = t.strip_prefix("0x") { hex::decode(h)? }
        else if t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit()) { hex::decode(t)? }
        else { B64.decode(t)? };
    bytes.try_into().map_err(|_| anyhow!("master key must be 32 bytes"))
}

fn derive_nonce(key_id: u32, party_index: u8, plaintext: &[u8]) -> [u8; 12] {
    let mut h = Sha256::new();
    h.update(key_id.to_be_bytes());
    h.update([party_index]);
    h.update(plaintext);
    let d = h.finalize();
    let mut n = [0u8; 12];
    n.copy_from_slice(&d[..12]);
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmp() -> PathBuf {
        let ns = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir().join(format!("kosh-ks-test-{ns}"))
    }

    const KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn record() -> ShareRecord {
        ShareRecord {
            contract_address: "03abc".to_string(),
            key_id: 1, party_index: 1,
            public_key_hex: "deadbeef".to_string(),
            shamir_share_hex: "cafebabe".to_string(),
            next_task_id: 0,
            runtime_version: "test".to_string(),
        }
    }

    #[tokio::test]
    async fn roundtrip() {
        let ks = KeyStore::new(tmp(), KEY).unwrap();
        ks.store(&record()).await.unwrap();
        let loaded = ks.load(1, 1).await.unwrap();
        assert_eq!(loaded.shamir_share_hex, "cafebabe");
        assert_eq!(loaded.next_task_id, 0);
    }

    #[tokio::test]
    async fn wrong_key_fails() {
        let ks = KeyStore::new(tmp(), KEY).unwrap();
        ks.store(&record()).await.unwrap();
        let ks2 = KeyStore::new(ks.root.as_path(), "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
        assert!(ks2.load(1, 1).await.is_err());
    }
}
