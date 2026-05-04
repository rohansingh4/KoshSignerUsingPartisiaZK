use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ml_dsa::signature::{Signer, Verifier};
use ml_kem::{Decapsulate, Encapsulate};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tonic::{Request, Response, Status};

use crate::identity::Identity;
use crate::pb::pqc_service_server::PqcService;
use crate::pb::*;

pub struct PqcServiceImpl {
    pub identity: Arc<Identity>,
}

#[tonic::async_trait]
impl PqcService for PqcServiceImpl {
    async fn get_identity(
        &self,
        _req: Request<GetIdentityRequest>,
    ) -> Result<Response<GetIdentityResponse>, Status> {
        let (kem_pk, dsa_pk) = self.identity.public_keys();
        Ok(Response::new(GetIdentityResponse {
            kyber_pk_b64: kem_pk,
            dilithium_pk_b64: dsa_pk,
        }))
    }

    async fn encapsulate(
        &self,
        req: Request<EncapsulateRequest>,
    ) -> Result<Response<EncapsulateResponse>, Status> {
        use ml_kem::kem::EncapsulationKey;
        use ml_kem::EncodedSizeUser;

        let pk_bytes = B64
            .decode(&req.into_inner().recipient_kyber_pk_b64)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        let ek = EncapsulationKey::<ml_kem::MlKem768Params>::from_bytes(pk_bytes.as_slice().into());
        let (ct, ss) = ek.encapsulate();

        Ok(Response::new(EncapsulateResponse {
            ciphertext_b64: B64.encode(ct.as_ref()),
            shared_secret_b64: B64.encode(ss.as_ref()),
        }))
    }

    async fn decapsulate(
        &self,
        req: Request<DecapsulateRequest>,
    ) -> Result<Response<DecapsulateResponse>, Status> {
        use ml_kem::kem::Ciphertext;

        let ct_bytes = B64
            .decode(&req.into_inner().ciphertext_b64)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        let ct = Ciphertext::<ml_kem::MlKem768Params>::from(
            <[u8; 1088]>::try_from(ct_bytes.as_slice())
                .map_err(|_| Status::invalid_argument("invalid ciphertext length"))?,
        );
        let ss = self.identity.kem_dk.decapsulate(&ct);

        Ok(Response::new(DecapsulateResponse {
            shared_secret_b64: B64.encode(ss.as_ref()),
        }))
    }

    async fn encrypt_payload(
        &self,
        req: Request<EncryptPayloadRequest>,
    ) -> Result<Response<EncryptPayloadResponse>, Status> {
        let r = req.into_inner();
        let ss = B64
            .decode(&r.shared_secret_b64)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        let key_bytes = Sha256::digest(&ss);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));

        let mut nonce_bytes = [0u8; 12];
        std::io::Read::read_exact(
            &mut std::fs::File::open("/dev/urandom").unwrap(),
            &mut nonce_bytes,
        )
        .unwrap();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, r.plaintext.as_ref())
            .map_err(|e| Status::internal(e.to_string()))?;

        let (ct, tag) = ciphertext.split_at(ciphertext.len() - 16);

        Ok(Response::new(EncryptPayloadResponse {
            ciphertext: ct.to_vec(),
            nonce: nonce_bytes.to_vec(),
            tag: tag.to_vec(),
        }))
    }

    async fn decrypt_payload(
        &self,
        req: Request<DecryptPayloadRequest>,
    ) -> Result<Response<DecryptPayloadResponse>, Status> {
        let r = req.into_inner();
        let ss = B64
            .decode(&r.shared_secret_b64)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        let key_bytes = Sha256::digest(&ss);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
        let nonce = Nonce::from_slice(&r.nonce);

        let mut ct_with_tag = r.ciphertext.clone();
        ct_with_tag.extend_from_slice(&r.tag);

        let plaintext = cipher
            .decrypt(nonce, ct_with_tag.as_ref())
            .map_err(|_| Status::unauthenticated("AES-GCM decryption failed"))?;

        Ok(Response::new(DecryptPayloadResponse { plaintext }))
    }

    async fn sign(&self, req: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        let sig = self.identity.dsa_sk.sign(&req.into_inner().message);
        Ok(Response::new(SignResponse {
            signature: sig.encode().to_vec(),
        }))
    }

    async fn verify(
        &self,
        req: Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        let r = req.into_inner();
        let pk_bytes = B64
            .decode(&r.dilithium_pk_b64)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;

        use ml_dsa::VerifyingKey;
        let arr: &ml_dsa::EncodedVerifyingKey<ml_dsa::MlDsa65Params> = pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid dilithium pk length"))?;
        let vk = VerifyingKey::<ml_dsa::MlDsa65Params>::decode(arr);

        use ml_dsa::EncodedSignature;
        let sig_bytes = r.signature;
        let sig_arr: &EncodedSignature<ml_dsa::MlDsa65Params> = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid signature length"))?;
        let sig = ml_dsa::Signature::<ml_dsa::MlDsa65Params>::decode(sig_arr);

        let valid = vk.verify(&r.message, &sig).is_ok();
        Ok(Response::new(VerifyResponse { valid }))
    }
}
