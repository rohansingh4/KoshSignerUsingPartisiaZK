use crate::keystore::{KeyMaterialMetadata, KeyStore};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ml_dsa::signature::rand_core::{Infallible, TryCryptoRng, TryRng};
use ml_dsa::{KeyGen, MlDsa65};
use ml_kem::{KeyExport, MlKem768};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqcIdentityFile {
    pub kyber_private_key_b64: String,
    pub kyber_public_key_b64: String,
    pub dilithium_private_key_b64: String,
    pub dilithium_public_key_b64: String,
}

#[derive(Debug, Clone)]
pub struct PqcIdentity {
    file: PqcIdentityFile,
}

impl PqcIdentity {
    pub async fn load_or_generate(
        keystore: &KeyStore,
        party_index: u8,
        public_key_hex: &str,
    ) -> Result<Self> {
        let name = format!("pqc-identity-party-{party_index}.json");
        match keystore.load_secret(&name).await {
            Ok((plaintext, _)) => {
                let file: PqcIdentityFile =
                    serde_json::from_slice(&plaintext).context("decode stored PQC identity")?;
                Ok(Self { file })
            }
            Err(_) => {
                let identity = Self::generate()?;
                let metadata = KeyMaterialMetadata {
                    contract_address: "pqc-global".to_string(),
                    key_id: 0,
                    party_index,
                    public_key_hex: public_key_hex.to_string(),
                    runtime_version: "pqc-v1".to_string(),
                };
                let plaintext = serde_json::to_vec_pretty(&identity.file)?;
                keystore.store_secret(&name, &plaintext, metadata).await?;
                Ok(identity)
            }
        }
    }

    pub fn kyber_public_key(&self) -> Result<Vec<u8>> {
        Ok(B64.decode(&self.file.kyber_public_key_b64)?)
    }

    pub fn dilithium_public_key(&self) -> Result<Vec<u8>> {
        Ok(B64.decode(&self.file.dilithium_public_key_b64)?)
    }

    fn generate() -> Result<Self> {
        use ml_dsa::signature::rand_core::UnwrapErr;
        use ml_kem::kem::Kem;
        let (kem_dk, kem_ek) = MlKem768::generate_keypair();
        let mut rng = UnwrapErr(SystemRng);
        let dsa_sk = MlDsa65::key_gen(&mut rng);
        let kem_dk_bytes = kem_dk.to_bytes();
        let kem_ek_bytes = kem_ek.to_bytes();
        let dsa_sk_bytes = dsa_sk.signing_key().to_expanded();
        let dsa_vk_bytes = dsa_sk.signing_key().verifying_key().encode();
        let file = PqcIdentityFile {
            kyber_private_key_b64: B64.encode(&kem_dk_bytes[..]),
            kyber_public_key_b64: B64.encode(&kem_ek_bytes[..]),
            dilithium_private_key_b64: B64.encode(&dsa_sk_bytes[..]),
            dilithium_public_key_b64: B64.encode(&dsa_vk_bytes[..]),
        };
        Ok(Self { file })
    }
}

pub fn compute_pqc_session_challenge(
    key_id: u32,
    task_id: u32,
    msg_hash: &[u8],
    tx_tag: &str,
    signing_subset: &[u8],
) -> Vec<u8> {
    let payload = concat_bytes(&[
        b"KOSH_PQC_SESSION_V1",
        &encode_u32_be(key_id),
        &encode_u32_be(task_id),
        &encode_len_prefixed(msg_hash),
        &encode_len_prefixed(tx_tag.as_bytes()),
        &encode_party_vector(signing_subset),
    ]);
    Sha256::digest(payload).to_vec()
}

pub fn build_pqc_approval_payload(
    key_id: u32,
    task_id: u32,
    party_index: u8,
    msg_hash: &[u8],
    tx_tag: &str,
    signing_subset: &[u8],
    challenge: &[u8],
    expires_at_block: i64,
) -> Vec<u8> {
    concat_bytes(&[
        b"KOSH_PQC_APPROVAL_V1",
        &encode_u32_be(key_id),
        &encode_u32_be(task_id),
        &[party_index],
        &encode_len_prefixed(msg_hash),
        &encode_len_prefixed(tx_tag.as_bytes()),
        &encode_party_vector(signing_subset),
        &encode_len_prefixed(challenge),
        // Bind to session deadline — prevents replay on a renewed session
        &expires_at_block.to_be_bytes(),
    ])
}

pub fn compute_pqc_approval_hash(
    key_id: u32,
    task_id: u32,
    party_index: u8,
    msg_hash: &[u8],
    tx_tag: &str,
    signing_subset: &[u8],
    challenge: &[u8],
    expires_at_block: i64,
) -> Vec<u8> {
    Sha256::digest(build_pqc_approval_payload(
        key_id,
        task_id,
        party_index,
        msg_hash,
        tx_tag,
        signing_subset,
        challenge,
        expires_at_block,
    ))
    .to_vec()
}

pub struct SystemRng;

impl TryRng for SystemRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut buf = [0u8; 4];
        fill(&mut buf);
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut buf = [0u8; 8];
        fill(&mut buf);
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        fill(dest);
        Ok(())
    }
}

impl TryCryptoRng for SystemRng {}

fn fill(buf: &mut [u8]) {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .expect("cannot open /dev/urandom")
        .read_exact(buf)
        .expect("urandom read failed");
}

fn encode_u32_be(value: u32) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

fn encode_len_prefixed(bytes: &[u8]) -> Vec<u8> {
    let mut encoded = encode_u32_be(bytes.len() as u32);
    encoded.extend_from_slice(bytes);
    encoded
}

fn encode_party_vector(parties: &[u8]) -> Vec<u8> {
    encode_len_prefixed(parties)
}

fn concat_bytes(parts: &[&[u8]]) -> Vec<u8> {
    let total_len = parts.iter().map(|part| part.len()).sum();
    let mut out = Vec::with_capacity(total_len);
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}
