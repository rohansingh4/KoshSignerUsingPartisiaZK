fn encode_u32_be(n: u32) -> Vec<u8> {
    vec![
        ((n >> 24) & 0xff) as u8,
        ((n >> 16) & 0xff) as u8,
        ((n >> 8) & 0xff) as u8,
        (n & 0xff) as u8,
    ]
}

fn encode_vec(bytes: &[u8]) -> Vec<u8> {
    let mut out = encode_u32_be(bytes.len() as u32);
    out.extend_from_slice(bytes);
    out
}

use kosh_zk_signer::SigningPartyBundleV2;
use pbc_traits::WriteRPC;

fn encode_action(shortname: u16, args: &[u8]) -> Vec<u8> {
    let mut wasm_rpc = if shortname <= 0xff {
        vec![shortname as u8]
    } else {
        vec![(shortname >> 8) as u8, (shortname & 0xff) as u8]
    };
    wasm_rpc.extend_from_slice(args);
    let mut rpc = vec![0x09u8];
    rpc.extend_from_slice(&wasm_rpc);
    rpc
}

pub fn build_dkg_create_key_rpc(key_id: u32, num_parties: u8) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.push(num_parties);
    encode_action(0x20, &args)
}

pub fn build_dkg_commit_rpc(
    key_id: u32,
    party_index: u8,
    commitment_hash: &[u8],
    slope_commitment: &[u8],
    schnorr_r: &[u8],
    schnorr_z: &[u8],
) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.push(party_index);
    args.extend_from_slice(&encode_vec(commitment_hash));
    args.extend_from_slice(&encode_vec(slope_commitment));
    args.extend_from_slice(&encode_vec(schnorr_r));
    args.extend_from_slice(&encode_vec(schnorr_z));
    encode_action(0x21, &args)
}

pub fn build_dkg_reveal_rpc(key_id: u32, party_index: u8, public_key_share: &[u8]) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.push(party_index);
    args.extend_from_slice(&encode_vec(public_key_share));
    encode_action(0x22, &args)
}

pub fn build_dkg_finalize_rpc(key_id: u32) -> Vec<u8> {
    encode_action(0x23, &encode_u32_be(key_id))
}

pub fn build_dkg_complete_keygen_rpc(key_id: u32) -> Vec<u8> {
    encode_action(0x24, &encode_u32_be(key_id))
}

pub fn build_register_party_address_rpc(key_id: u32, party_index: u8, address: &[u8]) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.push(party_index);
    args.extend_from_slice(address);
    encode_action(0x72, &args)
}

pub fn build_register_dilithium_pubkey_rpc(
    key_id: u32,
    party_index: u8,
    dilithium_pubkey: &[u8],
) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.push(party_index);
    args.extend_from_slice(&encode_vec(dilithium_pubkey));
    encode_action(0x73, &args)
}

pub fn build_register_kyber_pubkey_rpc(
    key_id: u32,
    party_index: u8,
    kyber_pubkey: &[u8],
) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.push(party_index);
    args.extend_from_slice(&encode_vec(kyber_pubkey));
    encode_action(0x74, &args)
}

pub fn build_start_pqc_approval_session_rpc(
    key_id: u32,
    task_id: u32,
    signing_parties: &[u8],
) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.extend_from_slice(&encode_u32_be(task_id));
    args.extend_from_slice(&encode_vec(signing_parties));
    encode_action(0x75, &args)
}

pub fn build_submit_pqc_approval_rpc(
    key_id: u32,
    task_id: u32,
    party_index: u8,
    approval_hash: &[u8],
) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.extend_from_slice(&encode_u32_be(task_id));
    args.push(party_index);
    args.extend_from_slice(&encode_vec(approval_hash));
    encode_action(0x76, &args)
}

pub fn build_finalize_pqc_approval_rpc(key_id: u32, task_id: u32) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.extend_from_slice(&encode_u32_be(task_id));
    encode_action(0x77, &args)
}

pub fn build_sign_message_rpc(key_id: u32, message_hash: &[u8], tx_tag: &str) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.extend_from_slice(&encode_vec(message_hash));
    args.extend_from_slice(&encode_vec(tx_tag.as_bytes()));
    encode_action(0x03, &args)
}

pub fn build_gg20_start_signing_rpc(key_id: u32, task_id: u32, signing_parties: &[u8]) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.extend_from_slice(&encode_u32_be(task_id));
    args.extend_from_slice(&encode_vec(signing_parties));
    encode_action(0x50, &args)
}

pub fn build_gg20_finalize_r_rpc(key_id: u32) -> Vec<u8> {
    encode_action(0x47, &encode_u32_be(key_id))
}

pub fn build_abort_signing_rpc(key_id: u32) -> Vec<u8> {
    encode_action(0x48, &encode_u32_be(key_id))
}

pub fn build_commit_delta_rpc(key_id: u32, party_index: u8, commitment_hash: &[u8]) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.push(party_index);
    args.extend_from_slice(&encode_vec(commitment_hash));
    encode_action(0x49, &args)
}

pub fn build_submit_delta_rpc(key_id: u32, party_index: u8, delta_bytes: &[u8]) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.push(party_index);
    args.extend_from_slice(&encode_vec(delta_bytes));
    encode_action(0x45, &args)
}

pub fn build_submit_gamma_point_rpc(key_id: u32, party_index: u8, gamma_point: &[u8]) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.push(party_index);
    args.extend_from_slice(&encode_vec(gamma_point));
    encode_action(0x46, &args)
}

pub fn build_commit_partial_sig_rpc(
    key_id: u32,
    party_index: u8,
    commitment_hash: &[u8],
) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.push(party_index);
    args.extend_from_slice(&encode_vec(commitment_hash));
    encode_action(0x44, &args)
}

pub fn build_submit_partial_sig_rpc(key_id: u32, party_index: u8, partial_s: &[u8]) -> Vec<u8> {
    let mut args = encode_u32_be(key_id);
    args.push(party_index);
    args.extend_from_slice(&encode_vec(partial_s));
    encode_action(0x31, &args)
}

pub fn build_submit_signing_bundle_v2_rpc(
    key_id: u32,
    task_id: u32,
    party_indices: &[u8],
    delta_values: &[Vec<u8>],
    gamma_points: &[Vec<u8>],
    partial_sigs: &[Vec<u8>],
) -> Vec<u8> {
    assert_eq!(
        party_indices.len(),
        delta_values.len(),
        "party_indices/delta_values length mismatch"
    );
    assert_eq!(
        party_indices.len(),
        gamma_points.len(),
        "party_indices/gamma_points length mismatch"
    );
    assert_eq!(
        party_indices.len(),
        partial_sigs.len(),
        "party_indices/partial_sigs length mismatch"
    );

    let bundles: Vec<SigningPartyBundleV2> = party_indices
        .iter()
        .enumerate()
        .map(|(idx, party_index)| SigningPartyBundleV2 {
            party_index: *party_index,
            delta_bytes: delta_values[idx].clone(),
            gamma_point: gamma_points[idx].clone(),
            partial_s: partial_sigs[idx].clone(),
        })
        .collect();

    let mut args = encode_u32_be(key_id);
    args.extend_from_slice(&encode_u32_be(task_id));
    bundles
        .rpc_write_to(&mut args)
        .expect("serializing signing bundle v2 rpc should not fail");
    encode_action(0x58, &args)
}

#[cfg(test)]
mod tests {
    use super::{
        build_commit_delta_rpc, build_commit_partial_sig_rpc, build_dkg_commit_rpc,
        build_dkg_complete_keygen_rpc, build_dkg_create_key_rpc, build_dkg_finalize_rpc,
        build_dkg_reveal_rpc, build_finalize_pqc_approval_rpc, build_gg20_finalize_r_rpc,
        build_gg20_start_signing_rpc, build_register_dilithium_pubkey_rpc,
        build_register_kyber_pubkey_rpc, build_register_party_address_rpc, build_sign_message_rpc,
        build_start_pqc_approval_session_rpc, build_submit_delta_rpc, build_submit_gamma_point_rpc,
        build_submit_partial_sig_rpc, build_submit_pqc_approval_rpc,
        build_submit_signing_bundle_v2_rpc,
    };

    #[test]
    fn builds_dkg_create_key_rpc() {
        let rpc = build_dkg_create_key_rpc(62003, 3);
        assert_eq!(rpc[0], 0x09);
        assert_eq!(rpc[1], 0x20);
        assert_eq!(&rpc[2..6], &[0x00, 0x00, 0xf2, 0x33]);
        assert_eq!(rpc[6], 3);
    }

    #[test]
    fn builds_sign_message_rpc() {
        let msg = [0x11u8; 32];
        let rpc = build_sign_message_rpc(60004, &msg, "eth_transfer");
        assert_eq!(rpc[0], 0x09);
        assert_eq!(rpc[1], 0x03);
        assert_eq!(&rpc[2..6], &[0x00, 0x00, 0xea, 0x64]);
        assert_eq!(&rpc[6..10], &[0, 0, 0, 32]);
        assert_eq!(&rpc[10..42], &msg);
        assert_eq!(rpc.len(), 58);
    }

    #[test]
    fn builds_abort_signing_rpc() {
        let rpc = super::build_abort_signing_rpc(62003);
        assert_eq!(rpc[0], 0x09);
        assert_eq!(rpc[1], 0x48);
        assert_eq!(&rpc[2..6], &[0x00, 0x00, 0xf2, 0x33]);
    }

    #[test]
    fn builds_commit_and_reveal_rpcs() {
        let commit =
            build_dkg_commit_rpc(62003, 1, &[0x11; 32], &[0x22; 33], &[0x33; 33], &[0x44; 32]);
        assert_eq!(commit[0], 0x09);
        assert_eq!(commit[1], 0x21);
        assert_eq!(&commit[2..6], &[0x00, 0x00, 0xf2, 0x33]);
        assert_eq!(commit[6], 1);

        let reveal = build_dkg_reveal_rpc(62003, 1, &[0x55; 33]);
        assert_eq!(reveal[0], 0x09);
        assert_eq!(reveal[1], 0x22);
        assert_eq!(&reveal[2..6], &[0x00, 0x00, 0xf2, 0x33]);
        assert_eq!(reveal[6], 1);
    }

    #[test]
    fn builds_finalize_and_complete_keygen_rpcs() {
        let finalize = build_dkg_finalize_rpc(62003);
        assert_eq!(finalize[0], 0x09);
        assert_eq!(finalize[1], 0x23);
        assert_eq!(&finalize[2..6], &[0x00, 0x00, 0xf2, 0x33]);

        let complete = build_dkg_complete_keygen_rpc(62003);
        assert_eq!(complete[0], 0x09);
        assert_eq!(complete[1], 0x24);
        assert_eq!(&complete[2..6], &[0x00, 0x00, 0xf2, 0x33]);
    }

    #[test]
    fn builds_party_readiness_registration_rpcs() {
        let addr = [0x11u8; 21];
        let party = build_register_party_address_rpc(62003, 1, &addr);
        assert_eq!(party[0], 0x09);
        assert_eq!(party[1], 0x72);
        assert_eq!(&party[2..6], &[0x00, 0x00, 0xf2, 0x33]);
        assert_eq!(party[6], 1);
        assert_eq!(&party[7..28], &addr);

        let dsa = build_register_dilithium_pubkey_rpc(62003, 1, &[0x22; 1952]);
        assert_eq!(dsa[0], 0x09);
        assert_eq!(dsa[1], 0x73);

        let kem = build_register_kyber_pubkey_rpc(62003, 1, &[0x33; 1184]);
        assert_eq!(kem[0], 0x09);
        assert_eq!(kem[1], 0x74);
    }

    #[test]
    fn builds_pqc_approval_rpcs() {
        let start = build_start_pqc_approval_session_rpc(62003, 7, &[1, 2]);
        assert_eq!(start[0], 0x09);
        assert_eq!(start[1], 0x75);

        let submit = build_submit_pqc_approval_rpc(62003, 7, 1, &[0x44; 32]);
        assert_eq!(submit[0], 0x09);
        assert_eq!(submit[1], 0x76);

        let finalize = build_finalize_pqc_approval_rpc(62003, 7);
        assert_eq!(finalize[0], 0x09);
        assert_eq!(finalize[1], 0x77);
    }

    #[test]
    fn builds_gg20_start_and_partial_submission_rpcs() {
        let start = build_gg20_start_signing_rpc(62003, 7, &[1, 2]);
        assert_eq!(start[0], 0x09);
        assert_eq!(start[1], 0x50);
        assert_eq!(&start[2..6], &[0x00, 0x00, 0xf2, 0x33]);
        assert_eq!(&start[6..10], &[0, 0, 0, 7]);
        assert_eq!(&start[10..14], &[0, 0, 0, 2]);
        assert_eq!(&start[14..16], &[1, 2]);

        let commit = build_commit_partial_sig_rpc(62003, 1, &[0xaa; 32]);
        assert_eq!(commit[0], 0x09);
        assert_eq!(commit[1], 0x44);

        let submit = build_submit_partial_sig_rpc(62003, 1, &[0xbb; 32]);
        assert_eq!(submit[0], 0x09);
        assert_eq!(submit[1], 0x31);
    }

    #[test]
    fn builds_finalize_r_rpc() {
        let finalize_r = build_gg20_finalize_r_rpc(62003);
        assert_eq!(finalize_r[0], 0x09);
        assert_eq!(finalize_r[1], 0x47);
        assert_eq!(&finalize_r[2..6], &[0x00, 0x00, 0xf2, 0x33]);
    }

    #[test]
    fn builds_delta_and_gamma_rpcs() {
        let commit_delta = build_commit_delta_rpc(62003, 1, &[0xcc; 32]);
        assert_eq!(commit_delta[0], 0x09);
        assert_eq!(commit_delta[1], 0x49);

        let submit_delta = build_submit_delta_rpc(62003, 1, &[0xdd; 32]);
        assert_eq!(submit_delta[0], 0x09);
        assert_eq!(submit_delta[1], 0x45);

        let submit_gamma = build_submit_gamma_point_rpc(62003, 1, &[0xee; 33]);
        assert_eq!(submit_gamma[0], 0x09);
        assert_eq!(submit_gamma[1], 0x46);
    }

    #[test]
    fn builds_submit_signing_bundle_v2_rpc() {
        let rpc = build_submit_signing_bundle_v2_rpc(
            62003,
            7,
            &[1, 2],
            &[vec![0xaa; 32], vec![0xbb; 32]],
            &[vec![0xcc; 33], vec![0xdd; 33]],
            &[vec![0xee; 32], vec![0xff; 32]],
        );
        assert_eq!(rpc[0], 0x09);
        assert_eq!(rpc[1], 0x58);
        assert_eq!(&rpc[2..6], &[0x00, 0x00, 0xf2, 0x33]);
        assert_eq!(&rpc[6..10], &[0x00, 0x00, 0x00, 0x07]);
    }
}
