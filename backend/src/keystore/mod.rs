pub mod runtime_state;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use runtime_state::PersistedPartyRuntime;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::task;

#[derive(Clone)]
pub struct KeyStore {
    root: Arc<PathBuf>,
    cipher: Arc<Aes256Gcm>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMaterialMetadata {
    pub contract_address: String,
    pub key_id: u32,
    pub party_index: u8,
    pub public_key_hex: String,
    pub runtime_version: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Envelope {
    nonce_b64: String,
    ciphertext_b64: String,
    metadata: KeyMaterialMetadata,
}

impl KeyStore {
    pub fn new(root: impl Into<PathBuf>, master_key: &str) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)
            .with_context(|| format!("create keystore dir {}", root.display()))?;
        let key_bytes = decode_master_key(master_key)?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
        Ok(Self {
            root: Arc::new(root),
            cipher: Arc::new(cipher),
        })
    }

    pub async fn store_secret(
        &self,
        name: &str,
        plaintext: &[u8],
        metadata: KeyMaterialMetadata,
    ) -> Result<PathBuf> {
        let path = self.root.join(name);
        let cipher = Arc::clone(&self.cipher);
        let root = Arc::clone(&self.root);
        let name = name.to_string();
        let plaintext = plaintext.to_vec();
        Ok(task::spawn_blocking(move || {
            fs::create_dir_all(root.as_path())?;
            let nonce_bytes = derive_nonce(&name, &plaintext, &metadata);
            let nonce = Nonce::from_slice(&nonce_bytes);
            let ciphertext = cipher
                .encrypt(nonce, plaintext.as_ref())
                .map_err(|_| anyhow!("encrypt secret"))?;
            let envelope = Envelope {
                nonce_b64: B64.encode(nonce_bytes),
                ciphertext_b64: B64.encode(ciphertext),
                metadata,
            };
            let json = serde_json::to_vec_pretty(&envelope)?;
            fs::write(&path, json)?;
            Ok::<PathBuf, anyhow::Error>(path)
        })
        .await??)
    }

    pub async fn store_party_runtime(&self, runtime: &PersistedPartyRuntime) -> Result<PathBuf> {
        let name = format!(
            "runtime-contract-{}-key-{}-party-{}.json",
            runtime.contract_address, runtime.key_id, runtime.party_index
        );
        let plaintext = serde_json::to_vec_pretty(runtime)?;
        let metadata = KeyMaterialMetadata {
            contract_address: runtime.contract_address.clone(),
            key_id: runtime.key_id,
            party_index: runtime.party_index,
            public_key_hex: runtime.public_key_hex.clone(),
            runtime_version: runtime.runtime_version.clone(),
        };
        self.store_secret(&name, &plaintext, metadata).await
    }

    pub async fn load_party_runtime(
        &self,
        contract_address: &str,
        key_id: u32,
        party_index: u8,
    ) -> Result<PersistedPartyRuntime> {
        let name = format!(
            "runtime-contract-{}-key-{}-party-{}.json",
            contract_address, key_id, party_index
        );
        let (plaintext, _) = self.load_secret(&name).await?;
        Ok(serde_json::from_slice(&plaintext)?)
    }

    pub async fn load_secret(&self, name: &str) -> Result<(Vec<u8>, KeyMaterialMetadata)> {
        let path = self.root.join(name);
        let cipher = Arc::clone(&self.cipher);
        let path_for_err = path.clone();
        Ok(task::spawn_blocking(move || {
            let bytes = fs::read(&path_for_err)
                .with_context(|| format!("read {}", path_for_err.display()))?;
            let envelope: Envelope = serde_json::from_slice(&bytes)?;
            let nonce_bytes = B64.decode(envelope.nonce_b64)?;
            let ciphertext = B64.decode(envelope.ciphertext_b64)?;
            let nonce = Nonce::from_slice(&nonce_bytes);
            let plaintext = cipher
                .decrypt(nonce, ciphertext.as_ref())
                .map_err(|_| anyhow!("decrypt secret"))?;
            Ok::<(Vec<u8>, KeyMaterialMetadata), anyhow::Error>((plaintext, envelope.metadata))
        })
        .await??)
    }

    pub fn root(&self) -> &Path {
        self.root.as_path()
    }
}

fn decode_master_key(input: &str) -> Result<[u8; 32]> {
    let trimmed = input.trim();
    let bytes = if let Some(hex) = trimmed.strip_prefix("0x") {
        hex::decode(hex)?
    } else if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(trimmed)?
    } else {
        B64.decode(trimmed)?
    };
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("master key must be 32 bytes"))?;
    Ok(arr)
}

fn derive_nonce(name: &str, plaintext: &[u8], metadata: &KeyMaterialMetadata) -> [u8; 12] {
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    hasher.update(plaintext);
    hasher.update(metadata.contract_address.as_bytes());
    hasher.update(metadata.key_id.to_be_bytes());
    hasher.update([metadata.party_index]);
    hasher.update(metadata.public_key_hex.as_bytes());
    hasher.update(metadata.runtime_version.as_bytes());
    let digest = hasher.finalize();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&digest[..12]);
    nonce
}

#[cfg(test)]
mod tests {
    use super::{KeyMaterialMetadata, KeyStore, PersistedPartyRuntime};
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temp_root(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("kosh-backend-tests-{name}-{nanos}"))
    }

    fn metadata() -> KeyMaterialMetadata {
        KeyMaterialMetadata {
            contract_address: "contract-1".to_string(),
            key_id: 42,
            party_index: 1,
            public_key_hex: "abcd".to_string(),
            runtime_version: "test".to_string(),
        }
    }

    #[tokio::test]
    async fn secret_roundtrip_works() {
        let store = KeyStore::new(
            temp_root("secret"),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();

        store
            .store_secret("secret-a", b"hello", metadata())
            .await
            .unwrap();

        let (plaintext, meta) = store.load_secret("secret-a").await.unwrap();
        assert_eq!(plaintext, b"hello");
        assert_eq!(meta.key_id, 42);
    }

    #[tokio::test]
    async fn runtime_roundtrip_works() {
        let store = KeyStore::new(
            temp_root("runtime"),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();

        let runtime = PersistedPartyRuntime {
            contract_address: "contract-1".to_string(),
            key_id: 42,
            party_index: 2,
            public_key_hex: "beef".to_string(),
            next_task_id: 7,
            shamir_share_hex: "cafe".to_string(),
            runtime_version: "test".to_string(),
        };

        store.store_party_runtime(&runtime).await.unwrap();
        let loaded = store.load_party_runtime("contract-1", 42, 2).await.unwrap();

        assert_eq!(loaded.party_index, 2);
        assert_eq!(loaded.next_task_id, 7);
        assert_eq!(loaded.shamir_share_hex, "cafe");
    }
}
