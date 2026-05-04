use crate::store::{KeyStore, ShareRecord};
use tonic::{Request, Response, Status};

pub mod pb {
    tonic::include_proto!("kosh.ks");
}

use pb::{
    key_store_server::KeyStore as KeyStoreTrait,
    GenerateShareRequest, GenerateShareResponse,
    LoadShareRequest, LoadShareResponse,
    ReceiveSubshareRequest, ReceiveSubshareResponse,
    FinalizeShareRequest, FinalizeShareResponse,
    GetShareHalvesRequest, GetShareHalvesResponse,
    GetPublicKeyRequest, GetPublicKeyResponse,
    AdvanceTaskIdRequest, AdvanceTaskIdResponse,
    GetNextTaskIdRequest, GetNextTaskIdResponse,
};

pub struct KeyStoreService {
    store: KeyStore,
}

impl KeyStoreService {
    pub fn new(store: KeyStore) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl KeyStoreTrait for KeyStoreService {
    // GenerateShare: create a new polynomial and save it
    async fn generate_share(
        &self,
        request: Request<GenerateShareRequest>,
    ) -> Result<Response<GenerateShareResponse>, Status> {
        let req = request.into_inner();
        // For now: generate a random share and persist it
        // Full Feldman VSS implementation in kosh-party
        let share_hex = hex::encode(rand_scalar_bytes());
        let pub_key_hex = hex::encode([0u8; 33]); // placeholder — party computes real pubkey

        let record = ShareRecord {
            contract_address: String::new(),
            key_id: req.key_id,
            party_index: req.party_index as u8,
            public_key_hex: pub_key_hex.clone(),
            shamir_share_hex: share_hex,
            next_task_id: 0,
            runtime_version: "v1".to_string(),
        };
        self.store.store(&record).await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(GenerateShareResponse {
            c_i0_hex: pub_key_hex.clone(),
            c_i1_hex: pub_key_hex,
            commitment_hash_hex: String::new(),
            schnorr_r_hex: String::new(),
            schnorr_z_hex: String::new(),
            encrypted_subshares: std::collections::HashMap::new(),
        }))
    }

    async fn load_share(
        &self,
        request: Request<LoadShareRequest>,
    ) -> Result<Response<LoadShareResponse>, Status> {
        let req = request.into_inner();
        // party_index not in LoadShareRequest — load party 1 as default; real impl passes it
        match self.store.load(req.key_id, 1).await {
            Ok(r) => Ok(Response::new(LoadShareResponse {
                found: true,
                combined_pk_hex: r.public_key_hex.clone(),
            })),
            Err(_) => Ok(Response::new(LoadShareResponse { found: false, combined_pk_hex: String::new() })),
        }
    }

    async fn receive_subshare(
        &self,
        _request: Request<ReceiveSubshareRequest>,
    ) -> Result<Response<ReceiveSubshareResponse>, Status> {
        Ok(Response::new(ReceiveSubshareResponse { valid: true, error: String::new() }))
    }

    async fn finalize_share(
        &self,
        request: Request<FinalizeShareRequest>,
    ) -> Result<Response<FinalizeShareResponse>, Status> {
        let req = request.into_inner();
        match self.store.load(req.key_id, 1).await {
            Ok(r) => Ok(Response::new(FinalizeShareResponse { combined_pk_hex: r.public_key_hex.clone() })),
            Err(e) => Err(Status::not_found(e.to_string())),
        }
    }

    async fn get_share_halves(
        &self,
        request: Request<GetShareHalvesRequest>,
    ) -> Result<Response<GetShareHalvesResponse>, Status> {
        let req = request.into_inner();
        let r = self.store.load(req.key_id, 1).await
            .map_err(|e| Status::not_found(e.to_string()))?;
        let bytes = hex::decode(&r.shamir_share_hex)
            .map_err(|e| Status::internal(e.to_string()))?;
        let mid = bytes.len() / 2;
        Ok(Response::new(GetShareHalvesResponse {
            share_hi: hex::encode(&bytes[..mid]),
            share_lo: hex::encode(&bytes[mid..]),
        }))
    }

    async fn get_public_key(
        &self,
        request: Request<GetPublicKeyRequest>,
    ) -> Result<Response<GetPublicKeyResponse>, Status> {
        let req = request.into_inner();
        let r = self.store.load(req.key_id, 1).await
            .map_err(|e| Status::not_found(e.to_string()))?;
        Ok(Response::new(GetPublicKeyResponse { combined_pk_hex: r.public_key_hex.clone() }))
    }

    async fn advance_task_id(
        &self,
        request: Request<AdvanceTaskIdRequest>,
    ) -> Result<Response<AdvanceTaskIdResponse>, Status> {
        let req = request.into_inner();
        let r = self.store.load(req.key_id, 1).await
            .map_err(|e| Status::not_found(e.to_string()))?;
        let next = r.next_task_id + 1;
        let updated = ShareRecord {
            contract_address: r.contract_address.clone(),
            key_id: r.key_id,
            party_index: r.party_index,
            public_key_hex: r.public_key_hex.clone(),
            shamir_share_hex: r.shamir_share_hex.clone(),
            next_task_id: next,
            runtime_version: r.runtime_version.clone(),
        };
        self.store.store(&updated).await.map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(AdvanceTaskIdResponse { next_task_id: next }))
    }

    async fn get_next_task_id(
        &self,
        request: Request<GetNextTaskIdRequest>,
    ) -> Result<Response<GetNextTaskIdResponse>, Status> {
        let req = request.into_inner();
        let r = self.store.load(req.key_id, 1).await
            .map_err(|e| Status::not_found(e.to_string()))?;
        Ok(Response::new(GetNextTaskIdResponse { next_task_id: r.next_task_id }))
    }
}

fn rand_scalar_bytes() -> [u8; 32] {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}
