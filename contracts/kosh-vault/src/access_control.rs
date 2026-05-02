//! Access control for the Kosh vault.
//!
//! Simple owner-based authorization for now.
//! Future versions will support guardian/social recovery.

use pbc_contract_common::address::Address;

use crate::VaultState;

/// Assert that the sender is the vault admin (deployer).
pub fn assert_is_admin(state: &VaultState, sender: &Address) {
    assert_eq!(
        sender, &state.owner,
        "Only the vault admin can call this action"
    );
}

/// Assert that the sender is the owner of the specified account.
pub fn assert_is_account_owner(state: &VaultState, sender: &Address, account_id: u32) {
    let owner = state
        .account_owners
        .get(&account_id)
        .expect("Account not found");
    assert_eq!(
        sender, &owner,
        "Not authorized: sender is not the account owner"
    );
}

/// Assert that the sender is either the vault admin or the account owner.
pub fn assert_is_admin_or_account_owner(state: &VaultState, sender: &Address, account_id: u32) {
    if sender == &state.owner {
        return;
    }
    assert_is_account_owner(state, sender, account_id);
}
