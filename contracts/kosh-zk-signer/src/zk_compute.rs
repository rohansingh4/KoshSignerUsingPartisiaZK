/// ZK Computation: Partial ECDSA Signature on ZK Nodes
///
/// Compiled by the Partisia ZK compiler (not rustc).
/// Cannot import from the rest of the crate.
///
/// Computes partial sig for party p:
///   sigma_p = kinv * (hmsg + r * s_p)   (128-bit prototype)
///
/// Public inputs (i128):
///   args[0] = party_index  (cast to u8 for share_index comparison)
///   args[1] = r_hi
///   args[2] = r_lo
///   args[3] = hmsg_hi
///   args[4] = hmsg_lo
///
/// Secret variables scanned:
///   variable_type=0u8, share_index==party_index -> s_hi/s_lo (key share)
///   variable_type=2u8, share_index==party_index -> kinv_hi/kinv_lo
///
/// Returns (sigma_hi, sigma_lo): partial signature split into two Sbi128 halves.

use pbc_zk::*;

/// Local copy of ShareMetadata -- layout must match signing_state.rs exactly.
/// variable_type: 0=key_share, 1=delta, 2=kinv, 3=psig_result
struct ShareMetadata {
    key_id: u32,
    share_index: u8,
    is_high_half: bool,
    variable_type: u8,
}

#[zk_compute(shortname = 0x61)]
pub fn compute_partial_sig(
    party_index: i128,
    r_hi: i128,
    r_lo: i128,
    hmsg_hi: i128,
    hmsg_lo: i128,
) -> (Sbi128, Sbi128) {
    let target: u8 = party_index as u8;

    let mut s_hi = Sbi128::from(0);
    let mut s_lo = Sbi128::from(0);
    let mut kinv_hi = Sbi128::from(0);
    let mut kinv_lo = Sbi128::from(0);

    for var_id in secret_variable_ids() {
        let meta: ShareMetadata = load_metadata::<ShareMetadata>(var_id);
        if meta.share_index == target {
            if meta.variable_type == 0u8 {
                if meta.is_high_half {
                    s_hi = load_sbi::<Sbi128>(var_id);
                } else {
                    s_lo = load_sbi::<Sbi128>(var_id);
                }
            } else if meta.variable_type == 2u8 {
                if meta.is_high_half {
                    kinv_hi = load_sbi::<Sbi128>(var_id);
                } else {
                    kinv_lo = load_sbi::<Sbi128>(var_id);
                }
            }
        }
    }

    // Prototype 128-bit GG20 formula (TODO: full 256-bit mod n for production)
    // r * s_p (cross-multiply limbs)
    let rs_lo = Sbi128::from(r_lo) * s_lo;
    let rs_hi = Sbi128::from(r_hi) * s_lo + Sbi128::from(r_lo) * s_hi;

    // inner = hmsg + r*s_p
    let inner_lo = Sbi128::from(hmsg_lo) + rs_lo;
    let inner_hi = Sbi128::from(hmsg_hi) + rs_hi;

    // sigma_p = kinv * inner
    let sigma_lo = kinv_lo * inner_lo;
    let sigma_hi = kinv_hi * inner_lo + kinv_lo * inner_hi;

    (sigma_hi, sigma_lo)
}
