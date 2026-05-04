use crate::rng::SystemRng;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ml_dsa::signature::rand_core::UnwrapErr;
use ml_dsa::{ExpandedSigningKeyBytes, KeyGen, MlDsa65, SigningKey};
use ml_kem::{DecapsulationKey768, Encapsulate, EncapsulationKey768, MlKem768};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct IdentityFile {
    pub kem_dk_b64: String,
    pub kem_ek_b64: String,
    pub dsa_sk_b64: String, // ExpandedSigningKeyBytes
    pub dsa_vk_b64: String,
}

pub struct Identity {
    pub kem_dk: DecapsulationKey768,
    pub kem_ek: EncapsulationKey768,
    pub dsa_sk: SigningKey<ml_dsa::MlDsa65>,
}

impl Identity {
    pub fn load_or_generate(path: &str) -> Result<Self> {
        if Path::new(path).exists() {
            Self::load(path).context("failed to load PQC identity")
        } else {
            let id = Self::generate();
            id.save(path)?;
            tracing::info!("generated new PQC identity → {}", path);
            Ok(id)
        }
    }

    fn generate() -> Self {
        use ml_kem::kem::Kem;
        let (kem_dk, kem_ek) = MlKem768::generate_keypair();
        let mut rng = UnwrapErr(SystemRng);
        let dsa_sk = MlDsa65::key_gen(&mut rng);
        Self {
            kem_dk,
            kem_ek,
            dsa_sk,
        }
    }

    fn save(&self, path: &str) -> Result<()> {
        use ml_kem::EncodedSizeUser;
        let file = IdentityFile {
            kem_dk_b64: B64.encode(self.kem_dk.as_bytes()),
            kem_ek_b64: B64.encode(self.kem_ek.as_bytes()),
            dsa_sk_b64: B64.encode(self.dsa_sk.signing_key().to_expanded().as_ref()),
            dsa_vk_b64: B64.encode(self.dsa_sk.signing_key().verifying_key().encode().as_ref()),
        };
        fs::write(path, serde_json::to_string_pretty(&file)?)?;
        Ok(())
    }

    fn load(path: &str) -> Result<Self> {
        use ml_kem::EncodedSizeUser;
        let raw = fs::read_to_string(path)?;
        let file: IdentityFile = serde_json::from_str(&raw)?;

        let dk_bytes = B64.decode(&file.kem_dk_b64)?;
        let ek_bytes = B64.decode(&file.kem_ek_b64)?;
        let kem_dk = DecapsulationKey768::from_bytes(dk_bytes.as_slice().into());
        let kem_ek = EncapsulationKey768::from_bytes(ek_bytes.as_slice().into());

        let sk_bytes = B64.decode(&file.dsa_sk_b64)?;
        let arr = ExpandedSigningKeyBytes::<ml_dsa::MlDsa65>::try_from(sk_bytes.as_slice())
            .map_err(|_| anyhow::anyhow!("invalid DSA signing key bytes"))?;
        let dsa_sk = SigningKey::<ml_dsa::MlDsa65>::from_expanded(&arr);

        Ok(Self {
            kem_dk,
            kem_ek,
            dsa_sk,
        })
    }

    pub fn public_keys(&self) -> (String, String) {
        use ml_kem::EncodedSizeUser;
        let kem_pk = B64.encode(self.kem_ek.as_bytes());
        let dsa_pk = B64.encode(self.dsa_sk.signing_key().verifying_key().encode().as_ref());
        (kem_pk, dsa_pk)
    }
}
