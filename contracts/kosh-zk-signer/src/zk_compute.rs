/// Minimal ZK computation stub.
///
/// This contract uses ZK only for secret variable storage (input/open),
/// not for MPC computation. The actual ECDSA signing happens off-chain
/// after shares are opened via `ZkStateChange::OpenVariables`.
///
/// A zk_compute entry point is still required by the build toolchain.

use pbc_zk::*;

#[zk_compute(shortname = 0x61)]
pub fn zk_compute() -> Sbi128 {
    // No-op: we don't do computation in ZK.
    // Return zero — this function is never actually invoked.
    Sbi128::from(0)
}
