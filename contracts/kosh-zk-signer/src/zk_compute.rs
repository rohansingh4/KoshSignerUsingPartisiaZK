/// ZK computation functions for the Kosh ZK Signer contract.
///
/// The biometric_match circuit compares enrollment vs recovery templates
/// using chunk-level equality. Templates are quantized and sorted on the
/// client side, so identical finger scans produce identical chunks.
/// Noise tolerance happens pre-quantization at the capture layer.

use pbc_zk::*;

/// No-op ZK compute stub — kept for backward compatibility.
#[zk_compute(shortname = 0x61)]
pub fn zk_compute() -> Sbi128 {
    Sbi128::from(0)
}

/// Biometric matching circuit — chunk equality comparison.
///
/// Variables 1..8: enrollment chunks (Sbi128).
/// Variables 9..16: recovery chunks (Sbi128).
///
/// Compares each chunk pair for exact equality using XOR.
/// XOR == 0 means chunks match. Uses or-reduce to detect non-zero.
///
/// If >= 4 of 8 chunks match (32+ cells): output XOR-fold seed.
/// Else: output 0.
#[zk_compute(shortname = 0x63)]
pub fn biometric_match() -> Sbi128 {
    let e0 = load_sbi::<Sbi128>(SecretVarId::new(1));
    let e1 = load_sbi::<Sbi128>(SecretVarId::new(2));
    let e2 = load_sbi::<Sbi128>(SecretVarId::new(3));
    let e3 = load_sbi::<Sbi128>(SecretVarId::new(4));
    let e4 = load_sbi::<Sbi128>(SecretVarId::new(5));
    let e5 = load_sbi::<Sbi128>(SecretVarId::new(6));
    let e6 = load_sbi::<Sbi128>(SecretVarId::new(7));
    let e7 = load_sbi::<Sbi128>(SecretVarId::new(8));

    let r0 = load_sbi::<Sbi128>(SecretVarId::new(9));
    let r1 = load_sbi::<Sbi128>(SecretVarId::new(10));
    let r2 = load_sbi::<Sbi128>(SecretVarId::new(11));
    let r3 = load_sbi::<Sbi128>(SecretVarId::new(12));
    let r4 = load_sbi::<Sbi128>(SecretVarId::new(13));
    let r5 = load_sbi::<Sbi128>(SecretVarId::new(14));
    let r6 = load_sbi::<Sbi128>(SecretVarId::new(15));
    let r7 = load_sbi::<Sbi128>(SecretVarId::new(16));

    let seed = e0 ^ e1 ^ e2 ^ e3 ^ e4 ^ e5 ^ e6 ^ e7;
    let one = Sbi128::from(1i128);

    // XOR each chunk pair — zero means equal
    let x0 = e0 ^ r0;
    let x1 = e1 ^ r1;
    let x2 = e2 ^ r2;
    let x3 = e3 ^ r3;
    let x4 = e4 ^ r4;
    let x5 = e5 ^ r5;
    let x6 = e6 ^ r6;
    let x7 = e7 ^ r7;

    // Or-reduce each XOR result to a single bit (0 if equal, 1 if different)
    let v0 = x0 | (x0 >> 64); let v0 = v0 | (v0 >> 32); let v0 = v0 | (v0 >> 16);
    let v0 = v0 | (v0 >> 8); let v0 = v0 | (v0 >> 4); let v0 = v0 | (v0 >> 2);
    let v0 = v0 | (v0 >> 1); let m0 = one - (v0 & one);

    let v1 = x1 | (x1 >> 64); let v1 = v1 | (v1 >> 32); let v1 = v1 | (v1 >> 16);
    let v1 = v1 | (v1 >> 8); let v1 = v1 | (v1 >> 4); let v1 = v1 | (v1 >> 2);
    let v1 = v1 | (v1 >> 1); let m1 = one - (v1 & one);

    let v2 = x2 | (x2 >> 64); let v2 = v2 | (v2 >> 32); let v2 = v2 | (v2 >> 16);
    let v2 = v2 | (v2 >> 8); let v2 = v2 | (v2 >> 4); let v2 = v2 | (v2 >> 2);
    let v2 = v2 | (v2 >> 1); let m2 = one - (v2 & one);

    let v3 = x3 | (x3 >> 64); let v3 = v3 | (v3 >> 32); let v3 = v3 | (v3 >> 16);
    let v3 = v3 | (v3 >> 8); let v3 = v3 | (v3 >> 4); let v3 = v3 | (v3 >> 2);
    let v3 = v3 | (v3 >> 1); let m3 = one - (v3 & one);

    let v4 = x4 | (x4 >> 64); let v4 = v4 | (v4 >> 32); let v4 = v4 | (v4 >> 16);
    let v4 = v4 | (v4 >> 8); let v4 = v4 | (v4 >> 4); let v4 = v4 | (v4 >> 2);
    let v4 = v4 | (v4 >> 1); let m4 = one - (v4 & one);

    let v5 = x5 | (x5 >> 64); let v5 = v5 | (v5 >> 32); let v5 = v5 | (v5 >> 16);
    let v5 = v5 | (v5 >> 8); let v5 = v5 | (v5 >> 4); let v5 = v5 | (v5 >> 2);
    let v5 = v5 | (v5 >> 1); let m5 = one - (v5 & one);

    let v6 = x6 | (x6 >> 64); let v6 = v6 | (v6 >> 32); let v6 = v6 | (v6 >> 16);
    let v6 = v6 | (v6 >> 8); let v6 = v6 | (v6 >> 4); let v6 = v6 | (v6 >> 2);
    let v6 = v6 | (v6 >> 1); let m6 = one - (v6 & one);

    let v7 = x7 | (x7 >> 64); let v7 = v7 | (v7 >> 32); let v7 = v7 | (v7 >> 16);
    let v7 = v7 | (v7 >> 8); let v7 = v7 | (v7 >> 4); let v7 = v7 | (v7 >> 2);
    let v7 = v7 | (v7 >> 1); let m7 = one - (v7 & one);

    // Count matching chunks (0..8, each worth 8 cells)
    let matched = m0 + m1 + m2 + m3 + m4 + m5 + m6 + m7;

    // Threshold: >= 4 chunks (32 cells) must match
    // (matched + 4) >> 3: matched=3: 7>>3=0, matched=4: 8>>3=1
    let passed = (matched + Sbi128::from(4i128)) >> 3;
    let passed = passed & one;

    seed * passed
}
