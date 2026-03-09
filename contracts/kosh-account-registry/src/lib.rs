//! Kosh Account Registry Contract
//!
//! On-chain mapping of user identities to MPC-generated public keys.
//! Tracks account lifecycle: Pending -> Active -> (RotatingKey -> Active) -> Deactivated.
//!
//! All mutations are restricted to the owner (vault contract).

#[macro_use]
extern crate pbc_contract_codegen;
extern crate pbc_contract_common;
extern crate pbc_lib as _;

use create_type_spec_derive::CreateTypeSpec;
use k256::PublicKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use pbc_contract_common::address::{Address, AddressType};
use pbc_contract_common::avl_tree_map::AvlTreeMap;
use pbc_contract_common::context::ContractContext;
use pbc_contract_common::Hash;
use read_write_rpc_derive::ReadWriteRPC;
use read_write_state_derive::ReadWriteState;
use tiny_keccak::{Hasher, Keccak};

/// Account lifecycle status.
#[derive(ReadWriteState, ReadWriteRPC, CreateTypeSpec, Clone, Debug, PartialEq)]
pub enum AccountStatus {
    /// Account registered, waiting for MPC key generation to complete.
    #[discriminant(0)]
    Pending {},
    /// Account active with a valid public key.
    #[discriminant(1)]
    Active {},
    /// Key rotation in progress — old key still valid, new key being generated.
    #[discriminant(2)]
    RotatingKey {},
    /// Account deactivated — no longer usable.
    #[discriminant(3)]
    Deactivated {},
}

/// Information about a registered account.
#[derive(ReadWriteState, ReadWriteRPC, CreateTypeSpec, Clone)]
pub struct AccountInfo {
    /// Hash of the user's external identity (e.g., SHA256 of email or OAuth ID).
    pub user_id_hash: Hash,
    /// The MPC-generated compressed public key (33 bytes), set when key gen completes.
    pub public_key: Option<Vec<u8>>,
    /// The derived blockchain address (21 bytes), computed from public key.
    pub derived_address: Option<Address>,
    /// Canonical EVM address (20 bytes) derived from secp256k1 public key.
    pub evm_address: Option<Vec<u8>>,
    /// Address of the signer contract managing this account's key.
    pub signer_contract: Address,
    /// The key_id within the signer contract.
    pub signer_key_id: u32,
    /// Current account status.
    pub status: AccountStatus,
    /// Block production time when account was created (Unix millis).
    pub created_at: i64,
}

/// The registry contract state.
#[state]
pub struct RegistryState {
    /// Owner address (the vault contract).
    pub owner: Address,
    /// Next account ID to assign.
    pub next_account_id: u32,
    /// Account data keyed by account_id.
    pub accounts: AvlTreeMap<u32, AccountInfo>,
    /// Index: user_id_hash -> account_id for lookup by identity.
    pub user_id_index: AvlTreeMap<Hash, u32>,
}

impl RegistryState {
    /// Assert that the sender is the contract owner (vault).
    fn assert_owner(&self, sender: &Address) {
        assert_eq!(
            sender, &self.owner,
            "Only the owner (vault) can call this action"
        );
    }
}

/// Derive Partisia and EVM addresses from a compressed secp256k1 public key.
fn derive_addresses(public_key: &[u8]) -> (Address, Vec<u8>) {
    // Existing Partisia derivation:
    // Address = type_prefix(1) + SHA256(compressed_pubkey)[last 20 bytes]
    let hash = Hash::digest(public_key);
    let hash_bytes: &[u8] = hash.as_ref();
    let mut partisia_id = [0u8; 20];
    partisia_id.copy_from_slice(&hash_bytes[12..32]);
    let partisia_address = Address::from_components(AddressType::Account, partisia_id);

    // Canonical EVM derivation:
    // EVM = last 20 bytes of keccak256(uncompressed_pubkey_without_prefix)
    let public_key = PublicKey::from_sec1_bytes(public_key)
        .expect("Public key must be a valid compressed secp256k1 point");
    let uncompressed = public_key.to_encoded_point(false);
    let uncompressed_bytes = uncompressed.as_bytes();
    assert_eq!(
        uncompressed_bytes.len(),
        65,
        "Uncompressed public key must be 65 bytes"
    );

    let mut keccak = Keccak::v256();
    keccak.update(&uncompressed_bytes[1..]);
    let mut out = [0u8; 32];
    keccak.finalize(&mut out);

    let mut evm_address = vec![0u8; 20];
    evm_address.copy_from_slice(&out[12..32]);

    (partisia_address, evm_address)
}

/// Initialize the registry contract.
///
/// # Arguments
/// * `owner` - Address of the vault contract that controls this registry
#[init]
pub fn initialize(
    _ctx: ContractContext,
    owner: Address,
) -> RegistryState {
    RegistryState {
        owner,
        next_account_id: 0,
        accounts: AvlTreeMap::new(),
        user_id_index: AvlTreeMap::new(),
    }
}

/// Register a new account. Creates a Pending entry.
/// Only callable by the owner (vault contract).
///
/// # Arguments
/// * `user_id_hash` - SHA256 hash of the user's external identity
/// * `signer_contract` - Address of the MPC signer contract
/// * `signer_key_id` - The key_id assigned in the signer contract
///
/// # Returns
/// The assigned account_id
#[action(shortname = 0x01)]
pub fn register_account(
    ctx: ContractContext,
    mut state: RegistryState,
    user_id_hash: Hash,
    signer_contract: Address,
    signer_key_id: u32,
) -> RegistryState {
    state.assert_owner(&ctx.sender);

    // Ensure this user_id_hash isn't already registered
    assert!(
        state.user_id_index.get(&user_id_hash).is_none(),
        "User ID hash already registered"
    );

    let account_id = state.next_account_id;
    state.next_account_id += 1;

    let user_id_hash_clone = user_id_hash.clone();
    let account = AccountInfo {
        user_id_hash,
        public_key: None,
        derived_address: None,
        evm_address: None,
        signer_contract,
        signer_key_id,
        status: AccountStatus::Pending {},
        created_at: ctx.block_production_time,
    };

    state.accounts.insert(account_id, account);
    state.user_id_index.insert(user_id_hash_clone, account_id);

    state
}

/// Activate an account after key generation completes.
/// Sets the public key and derives the blockchain address.
/// Only callable by the owner (vault contract).
///
/// # Arguments
/// * `account_id` - The account to activate
/// * `public_key` - The MPC-generated compressed public key (33 bytes)
#[action(shortname = 0x02)]
pub fn activate_account(
    ctx: ContractContext,
    mut state: RegistryState,
    account_id: u32,
    public_key: Vec<u8>,
) -> RegistryState {
    state.assert_owner(&ctx.sender);

    let mut account = state
        .accounts
        .get(&account_id)
        .expect("Account not found");

    assert!(
        matches!(account.status, AccountStatus::Pending {} | AccountStatus::RotatingKey {}),
        "Account must be in Pending or RotatingKey status to activate"
    );

    assert_eq!(
        public_key.len(),
        33,
        "Public key must be 33 bytes (compressed)"
    );

    let (derived_address, evm_address) = derive_addresses(&public_key);

    account.public_key = Some(public_key);
    account.derived_address = Some(derived_address);
    account.evm_address = Some(evm_address);
    account.status = AccountStatus::Active {};

    state.accounts.insert(account_id, account);

    state
}

/// Begin key rotation for an account.
/// Marks the account as RotatingKey — the old key remains valid during rotation.
/// Only callable by the owner (vault contract).
#[action(shortname = 0x03)]
pub fn begin_key_rotation(
    ctx: ContractContext,
    mut state: RegistryState,
    account_id: u32,
) -> RegistryState {
    state.assert_owner(&ctx.sender);

    let mut account = state
        .accounts
        .get(&account_id)
        .expect("Account not found");

    assert!(
        matches!(account.status, AccountStatus::Active {}),
        "Account must be Active to begin key rotation"
    );

    account.status = AccountStatus::RotatingKey {};
    state.accounts.insert(account_id, account);

    state
}

/// Complete key rotation with a new public key.
/// Only callable by the owner (vault contract).
#[action(shortname = 0x04)]
pub fn complete_key_rotation(
    ctx: ContractContext,
    mut state: RegistryState,
    account_id: u32,
    new_public_key: Vec<u8>,
    new_signer_key_id: u32,
) -> RegistryState {
    state.assert_owner(&ctx.sender);

    let mut account = state
        .accounts
        .get(&account_id)
        .expect("Account not found");

    assert!(
        matches!(account.status, AccountStatus::RotatingKey {}),
        "Account must be in RotatingKey status to complete rotation"
    );

    assert_eq!(
        new_public_key.len(),
        33,
        "Public key must be 33 bytes (compressed)"
    );

    let (derived_address, evm_address) = derive_addresses(&new_public_key);

    account.public_key = Some(new_public_key);
    account.derived_address = Some(derived_address);
    account.evm_address = Some(evm_address);
    account.signer_key_id = new_signer_key_id;
    account.status = AccountStatus::Active {};

    state.accounts.insert(account_id, account);

    state
}

/// Deactivate an account. Irreversible.
/// Only callable by the owner (vault contract).
#[action(shortname = 0x05)]
pub fn deactivate_account(
    ctx: ContractContext,
    mut state: RegistryState,
    account_id: u32,
) -> RegistryState {
    state.assert_owner(&ctx.sender);

    let mut account = state
        .accounts
        .get(&account_id)
        .expect("Account not found");

    assert!(
        !matches!(account.status, AccountStatus::Deactivated {}),
        "Account is already deactivated"
    );

    account.status = AccountStatus::Deactivated {};
    state.accounts.insert(account_id, account);

    state
}

/// Transfer ownership of this registry to a new owner.
/// Only callable by the current owner.
#[action(shortname = 0x06)]
pub fn transfer_ownership(
    ctx: ContractContext,
    mut state: RegistryState,
    new_owner: Address,
) -> RegistryState {
    state.assert_owner(&ctx.sender);
    state.owner = new_owner;
    state
}
