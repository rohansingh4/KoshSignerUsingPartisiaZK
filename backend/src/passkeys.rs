use anyhow::{anyhow, Context, Result};
use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashMap, fs, path::PathBuf, sync::Arc};
use tokio::sync::RwLock;
use url::Url;
use uuid::Uuid;
use webauthn_rs::prelude::*;

#[derive(Clone)]
pub struct PasskeyManager {
    root: Arc<PathBuf>,
    webauthn: Arc<Webauthn>,
    registration_states: Arc<RwLock<HashMap<Uuid, PendingRegistration>>>,
    auth_states: Arc<RwLock<HashMap<Uuid, DiscoverableAuthentication>>>,
    sessions: Arc<RwLock<HashMap<String, PasskeySession>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkedKey {
    pub contract_address: String,
    pub key_id: u32,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyAccount {
    pub account_id: Uuid,
    pub label: String,
    pub created_at: String,
    pub updated_at: String,
    pub credentials: Vec<StoredCredential>,
    pub linked_keys: Vec<LinkedKey>,
    pub selected_key: Option<LinkedKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    pub credential_id: String,
    pub passkey: Passkey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeySession {
    pub token: String,
    pub account_id: Uuid,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterStartResponse {
    pub registration_id: Uuid,
    pub options: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthStartResponse {
    pub authentication_id: Uuid,
    pub options: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyMe {
    pub authenticated: bool,
    pub account: Option<PasskeyAccount>,
    pub session_token: Option<String>,
}

#[derive(Debug, Clone)]
struct PendingRegistration {
    account_id: Uuid,
    label: String,
    link_key: Option<LinkedKey>,
    state: PasskeyRegistration,
}

impl PasskeyManager {
    pub fn new(
        root: PathBuf,
        rp_id: &str,
        rp_origin: &str,
        extra_origins: &[String],
    ) -> Result<Self> {
        fs::create_dir_all(&root)
            .with_context(|| format!("create passkey dir {}", root.display()))?;
        let origin = Url::parse(rp_origin).context("parse KOSH_WEBAUTHN_ORIGIN")?;
        let mut builder = WebauthnBuilder::new(rp_id, &origin).context("build webauthn config")?;
        builder = builder.rp_name("Kosh").allow_any_port(true);
        for extra in extra_origins {
            if extra != rp_origin {
                if let Ok(url) = Url::parse(extra) {
                    builder = builder.append_allowed_origin(&url);
                }
            }
        }
        let webauthn = builder.build().context("finalize webauthn config")?;
        Ok(Self {
            root: Arc::new(root),
            webauthn: Arc::new(webauthn),
            registration_states: Arc::new(RwLock::new(HashMap::new())),
            auth_states: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn start_registration(
        &self,
        label: String,
        link_key: Option<LinkedKey>,
    ) -> Result<RegisterStartResponse> {
        let account_id = Uuid::new_v4();
        let exclude_credentials = None;
        let (options, state) = self
            .webauthn
            .start_passkey_registration(account_id, &label, &label, exclude_credentials)
            .context("start passkey registration")?;
        let registration_id = Uuid::new_v4();
        self.registration_states.write().await.insert(
            registration_id,
            PendingRegistration {
                account_id,
                label,
                link_key,
                state,
            },
        );
        Ok(RegisterStartResponse {
            registration_id,
            options: serde_json::to_value(options)
                .context("serialize passkey registration options")?,
        })
    }

    pub async fn finish_registration(
        &self,
        registration_id: Uuid,
        credential: Value,
    ) -> Result<(PasskeySession, PasskeyAccount)> {
        let pending = self
            .registration_states
            .write()
            .await
            .remove(&registration_id)
            .ok_or_else(|| anyhow!("registration session not found or expired"))?;
        let reg: RegisterPublicKeyCredential =
            serde_json::from_value(credential).context("decode passkey registration credential")?;
        let passkey = self
            .webauthn
            .finish_passkey_registration(&reg, &pending.state)
            .context("finish passkey registration")?;
        let mut account = PasskeyAccount {
            account_id: pending.account_id,
            label: pending.label,
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
            credentials: vec![StoredCredential {
                credential_id: base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(passkey.cred_id()),
                passkey,
            }],
            linked_keys: pending.link_key.clone().into_iter().collect(),
            selected_key: pending.link_key,
        };
        self.save_account(&account)?;
        let session = self.create_session(account.account_id).await;
        account.updated_at = Utc::now().to_rfc3339();
        Ok((session, account))
    }

    pub async fn start_authentication(&self) -> Result<AuthStartResponse> {
        let (options, state) = self
            .webauthn
            .start_discoverable_authentication()
            .context("start discoverable authentication")?;
        let authentication_id = Uuid::new_v4();
        self.auth_states
            .write()
            .await
            .insert(authentication_id, state);
        Ok(AuthStartResponse {
            authentication_id,
            options: serde_json::to_value(options)
                .context("serialize passkey authentication options")?,
        })
    }

    pub async fn finish_authentication(
        &self,
        authentication_id: Uuid,
        credential: Value,
    ) -> Result<(PasskeySession, PasskeyAccount)> {
        let state = self
            .auth_states
            .write()
            .await
            .remove(&authentication_id)
            .ok_or_else(|| anyhow!("authentication session not found or expired"))?;
        let auth: PublicKeyCredential = serde_json::from_value(credential)
            .context("decode passkey authentication credential")?;
        let (account_id, credential_id) = self
            .webauthn
            .identify_discoverable_authentication(&auth)
            .context("identify discoverable authentication")?;
        let mut account = self.load_account(account_id)?;
        let discoverable = account
            .credentials
            .iter()
            .filter(|cred| cred.passkey.cred_id() == credential_id)
            .map(|cred| DiscoverableKey::from(cred.passkey.clone()))
            .collect::<Vec<_>>();
        if discoverable.is_empty() {
            return Err(anyhow!("credential is not linked to this passkey account"));
        }
        let result = self
            .webauthn
            .finish_discoverable_authentication(&auth, state, &discoverable)
            .context("finish passkey authentication")?;
        if let Some(stored) = account
            .credentials
            .iter_mut()
            .find(|cred| cred.passkey.cred_id() == credential_id)
        {
            stored.passkey.update_credential(&result);
        }
        account.updated_at = Utc::now().to_rfc3339();
        self.save_account(&account)?;
        let session = self.create_session(account.account_id).await;
        Ok((session, account))
    }

    pub async fn selected_key(&self, token: &str) -> Result<LinkedKey> {
        let session = self.session(token).await?;
        let account = self.load_account(session.account_id)?;
        account
            .selected_key
            .or_else(|| account.linked_keys.first().cloned())
            .ok_or_else(|| anyhow!("no linked key selected for this passkey account"))
    }

    pub async fn me(&self, token: &str) -> Result<PasskeyMe> {
        let Some(session) = self.sessions.read().await.get(token).cloned() else {
            return Ok(PasskeyMe {
                authenticated: false,
                account: None,
                session_token: None,
            });
        };
        let account = self.load_account(session.account_id)?;
        Ok(PasskeyMe {
            authenticated: true,
            account: Some(account),
            session_token: Some(session.token),
        })
    }

    pub async fn link_key(&self, token: &str, key: LinkedKey) -> Result<PasskeyAccount> {
        let session = self.session(token).await?;
        let mut account = self.load_account(session.account_id)?;
        if !account.linked_keys.iter().any(|existing| {
            existing.contract_address == key.contract_address && existing.key_id == key.key_id
        }) {
            account.linked_keys.push(key.clone());
        }
        account.selected_key = Some(key);
        account.updated_at = Utc::now().to_rfc3339();
        self.save_account(&account)?;
        Ok(account)
    }

    pub async fn select_key(
        &self,
        token: &str,
        contract_address: &str,
        key_id: u32,
    ) -> Result<PasskeyAccount> {
        let session = self.session(token).await?;
        let mut account = self.load_account(session.account_id)?;
        let selected = account
            .linked_keys
            .iter()
            .find(|key| key.contract_address == contract_address && key.key_id == key_id)
            .cloned()
            .ok_or_else(|| anyhow!("linked key not found for this passkey account"))?;
        account.selected_key = Some(selected);
        account.updated_at = Utc::now().to_rfc3339();
        self.save_account(&account)?;
        Ok(account)
    }

    async fn create_session(&self, account_id: Uuid) -> PasskeySession {
        let token = Uuid::new_v4().to_string();
        let session = PasskeySession {
            token: token.clone(),
            account_id,
            created_at: Utc::now().to_rfc3339(),
        };
        self.sessions
            .write()
            .await
            .insert(token.clone(), session.clone());
        session
    }

    async fn session(&self, token: &str) -> Result<PasskeySession> {
        self.sessions
            .read()
            .await
            .get(token)
            .cloned()
            .ok_or_else(|| anyhow!("passkey session not found; sign in again"))
    }

    fn account_path(&self, account_id: Uuid) -> PathBuf {
        self.root.join(format!("account-{account_id}.json"))
    }

    fn load_account(&self, account_id: Uuid) -> Result<PasskeyAccount> {
        let path = self.account_path(account_id);
        let bytes = fs::read(&path).with_context(|| format!("read {}", path.display()))?;
        serde_json::from_slice(&bytes).context("decode passkey account")
    }

    fn save_account(&self, account: &PasskeyAccount) -> Result<()> {
        let path = self.account_path(account.account_id);
        let bytes = serde_json::to_vec_pretty(account).context("encode passkey account")?;
        fs::write(&path, bytes).with_context(|| format!("write {}", path.display()))
    }
}
