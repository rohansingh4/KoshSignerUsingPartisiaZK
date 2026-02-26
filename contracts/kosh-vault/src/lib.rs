//! Kosh Vault Coordinator Contract
//!
//! Entry point for the Kosh keyless account system. Coordinates between:
//! - **kosh-mpc-signer**: Multi-key MPC signer for distributed key gen + signing
//! - **kosh-account-registry**: On-chain mapping of user IDs to public keys
//!
//! The vault handles account creation, signature requests, and lifecycle management.
//! Simple owner-based auth for now; guardian/social recovery designed for later.

#[macro_use]
extern crate pbc_contract_codegen;
extern crate pbc_contract_common;
extern crate pbc_lib as _;

pub mod access_control;

use pbc_contract_common::address::Address;
use pbc_contract_common::avl_tree_map::AvlTreeMap;
use pbc_contract_common::context::ContractContext;
use pbc_contract_common::events::EventGroup;
use pbc_contract_common::Hash;

use crate::access_control::{assert_is_account_owner, assert_is_admin, assert_is_admin_or_account_owner};

// -- Cross-contract action shortnames --
// These match the shortnames defined in the signer and registry contracts.
// Constructed as byte slices for Shortname::from_be_bytes().

/// Signer: create_key_with_id(key_id: u32)
const SIGNER_CREATE_KEY_WITH_ID: &[u8] = &[0x02];
/// Signer: sign_message(key_id: u32, message: Vec<u8>)
const SIGNER_SIGN_MESSAGE: &[u8] = &[0x03];
/// Registry: register_account(user_id_hash: Hash, signer_contract: Address, signer_key_id: u32)
const REGISTRY_REGISTER_ACCOUNT: &[u8] = &[0x01];
/// Registry: activate_account(account_id: u32, public_key: Vec<u8>)
const REGISTRY_ACTIVATE_ACCOUNT: &[u8] = &[0x02];
/// Registry: begin_key_rotation(account_id: u32)
#[allow(dead_code)]
const REGISTRY_BEGIN_KEY_ROTATION: &[u8] = &[0x03];
/// Registry: deactivate_account(account_id: u32)
const REGISTRY_DEACTIVATE_ACCOUNT: &[u8] = &[0x05];

/// Gas costs for cross-contract calls.
const GAS_CREATE_KEY: u64 = 200_000;
const GAS_REGISTER_ACCOUNT: u64 = 100_000;
const GAS_SIGN_MESSAGE: u64 = 200_000;
const GAS_ACTIVATE_ACCOUNT: u64 = 100_000;

/// The vault contract state.
#[state]
pub struct VaultState {
    /// Deployer/admin address.
    pub owner: Address,
    /// Address of the kosh-account-registry contract.
    pub registry_address: Address,
    /// Address of the primary kosh-mpc-signer contract.
    pub signer_address: Address,
    /// Mapping: account_id -> signer contract (supports multiple signers in the future).
    pub signer_contracts: AvlTreeMap<u32, Address>,
    /// Mapping: account_id -> owner address (who controls this account).
    pub account_owners: AvlTreeMap<u32, Address>,
    /// Mapping: signer key_id -> account_id (reverse lookup for callbacks).
    pub key_to_account: AvlTreeMap<u32, u32>,
    /// Next account ID to assign.
    pub next_account_id: u32,
}

/// Initialize the vault contract.
///
/// # Arguments
/// * `registry_address` - Address of the deployed kosh-account-registry contract
/// * `signer_address` - Address of the deployed kosh-mpc-signer contract
#[init]
pub fn initialize(
    ctx: ContractContext,
    registry_address: Address,
    signer_address: Address,
) -> VaultState {
    VaultState {
        owner: ctx.sender,
        registry_address,
        signer_address,
        signer_contracts: AvlTreeMap::new(),
        account_owners: AvlTreeMap::new(),
        key_to_account: AvlTreeMap::new(),
        next_account_id: 0,
    }
}

/// Create a new keyless account.
///
/// This action:
/// 1. Assigns an account_id and key_id
/// 2. Calls the signer to generate a new MPC key
/// 3. Registers the account in the registry as Pending
///
/// The caller becomes the account owner.
///
/// # Arguments
/// * `user_id_hash` - SHA256 hash of the user's external identity
#[action(shortname = 0x01)]
pub fn create_account(
    ctx: ContractContext,
    mut state: VaultState,
    user_id_hash: Hash,
) -> (VaultState, Vec<EventGroup>) {
    let account_id = state.next_account_id;
    state.next_account_id += 1;

    // The key_id in the signer is the same as the account_id for simplicity
    let key_id = account_id;

    // Store account owner
    state.account_owners.insert(account_id, ctx.sender);
    state.signer_contracts.insert(account_id, state.signer_address);
    state.key_to_account.insert(key_id, account_id);

    let mut events = Vec::new();

    // 1. Call signer to create a new MPC key
    let mut eg1 = EventGroup::builder();
    eg1.call(
        state.signer_address,
        pbc_contract_common::address::Shortname::from_be_bytes(SIGNER_CREATE_KEY_WITH_ID).unwrap(),
    )
    .argument(key_id)
    .with_cost_from_contract(GAS_CREATE_KEY)
    .done();
    events.push(eg1.build());

    // 2. Call registry to register the account as Pending
    let mut eg2 = EventGroup::builder();
    eg2.call(
        state.registry_address,
        pbc_contract_common::address::Shortname::from_be_bytes(REGISTRY_REGISTER_ACCOUNT).unwrap(),
    )
    .argument(user_id_hash)
    .argument(state.signer_address)
    .argument(key_id)
    .with_cost_from_contract(GAS_REGISTER_ACCOUNT)
    .done();
    events.push(eg2.build());

    (state, events)
}

/// Callback from the signer contract when key generation completes.
/// Activates the corresponding account in the registry.
///
/// # Arguments
/// * `key_id` - The key_id that was generated
/// * `public_key` - The MPC-generated compressed public key (33 bytes)
#[action(shortname = 0x02)]
pub fn on_key_generated(
    ctx: ContractContext,
    state: VaultState,
    key_id: u32,
    public_key: Vec<u8>,
) -> (VaultState, Vec<EventGroup>) {
    // Only the signer contract can call this
    assert_eq!(
        ctx.sender, state.signer_address,
        "Only the signer contract can notify key generation"
    );

    let account_id = state
        .key_to_account
        .get(&key_id)
        .expect("No account found for this key_id");

    // Call registry to activate the account with the public key
    let mut eg = EventGroup::builder();
    eg.call(
        state.registry_address,
        pbc_contract_common::address::Shortname::from_be_bytes(REGISTRY_ACTIVATE_ACCOUNT).unwrap(),
    )
    .argument(account_id)
    .argument(public_key)
    .with_cost_from_contract(GAS_ACTIVATE_ACCOUNT)
    .done();

    (state, vec![eg.build()])
}

/// Request a signature for a message using the account's MPC key.
///
/// The sender must be the account owner. The message is forwarded to the signer
/// contract, which queues it for distributed signing.
///
/// # Arguments
/// * `account_id` - The account to sign with
/// * `message` - The message bytes to sign (typically tx_bytes + chain_id)
#[action(shortname = 0x03)]
pub fn request_signature(
    ctx: ContractContext,
    state: VaultState,
    account_id: u32,
    message: Vec<u8>,
) -> (VaultState, Vec<EventGroup>) {
    // Check authorization
    assert_is_account_owner(&state, &ctx.sender, account_id);

    let signer_address = state
        .signer_contracts
        .get(&account_id)
        .expect("No signer contract for this account");

    // key_id == account_id (by our convention)
    let key_id = account_id;

    // Forward signing request to the signer contract
    let mut eg = EventGroup::builder();
    eg.call(
        signer_address,
        pbc_contract_common::address::Shortname::from_be_bytes(SIGNER_SIGN_MESSAGE).unwrap(),
    )
    .argument(key_id)
    .argument(message)
    .with_cost_from_contract(GAS_SIGN_MESSAGE)
    .done();

    (state, vec![eg.build()])
}

/// Transfer ownership of an account to a new address.
///
/// Only the current account owner or vault admin can do this.
///
/// # Arguments
/// * `account_id` - The account to transfer
/// * `new_owner` - The new owner's address
#[action(shortname = 0x04)]
pub fn transfer_account_ownership(
    ctx: ContractContext,
    mut state: VaultState,
    account_id: u32,
    new_owner: Address,
) -> VaultState {
    assert_is_admin_or_account_owner(&state, &ctx.sender, account_id);

    state.account_owners.insert(account_id, new_owner);

    state
}

/// Deactivate an account. Marks it as unusable in the registry.
/// Only the vault admin can deactivate accounts.
///
/// # Arguments
/// * `account_id` - The account to deactivate
#[action(shortname = 0x05)]
pub fn deactivate_account(
    ctx: ContractContext,
    state: VaultState,
    account_id: u32,
) -> (VaultState, Vec<EventGroup>) {
    assert_is_admin(&state, &ctx.sender);

    // Call registry to deactivate
    let mut eg = EventGroup::builder();
    eg.call(
        state.registry_address,
        pbc_contract_common::address::Shortname::from_be_bytes(REGISTRY_DEACTIVATE_ACCOUNT).unwrap(),
    )
    .argument(account_id)
    .with_cost_from_contract(GAS_ACTIVATE_ACCOUNT)
    .done();

    (state, vec![eg.build()])
}

/// Transfer vault admin ownership.
/// Only the current admin can do this.
#[action(shortname = 0x06)]
pub fn transfer_vault_ownership(
    ctx: ContractContext,
    mut state: VaultState,
    new_owner: Address,
) -> VaultState {
    assert_is_admin(&state, &ctx.sender);
    state.owner = new_owner;
    state
}
