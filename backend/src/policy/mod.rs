use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: Uuid,
    pub tx_tag: String,
    pub min_threshold: u8,
    pub mandatory_parties: Vec<u8>,
    pub require_pqc: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyInput {
    pub tx_tag: String,
    pub min_threshold: u8,
    pub mandatory_parties: Vec<u8>,
    pub require_pqc: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub require_pqc: bool,
    pub violation: Option<String>,
}

#[derive(Clone, Default)]
pub struct PolicyStore {
    policies: Arc<RwLock<HashMap<Uuid, Policy>>>,
}

impl PolicyStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn add(&self, input: PolicyInput) -> Policy {
        let policy = Policy {
            id: Uuid::new_v4(),
            tx_tag: input.tx_tag,
            min_threshold: input.min_threshold,
            mandatory_parties: input.mandatory_parties,
            require_pqc: input.require_pqc,
        };
        self.policies
            .write()
            .await
            .insert(policy.id, policy.clone());
        policy
    }

    pub async fn remove(&self, id: Uuid) -> Option<Policy> {
        self.policies.write().await.remove(&id)
    }

    pub async fn list(&self) -> Vec<Policy> {
        let mut values = self
            .policies
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        values.sort_by(|a, b| a.tx_tag.cmp(&b.tx_tag));
        values
    }

    pub async fn validate(
        &self,
        tx_tag: &str,
        signing_parties: &[u8],
        threshold: u8,
    ) -> PolicyDecision {
        let policies = self.policies.read().await;
        let relevant = policies
            .values()
            .filter(|p| p.tx_tag == tx_tag)
            .collect::<Vec<_>>();
        if relevant.is_empty() {
            return PolicyDecision {
                allowed: true,
                require_pqc: false,
                violation: None,
            };
        }
        for policy in relevant {
            if threshold < policy.min_threshold {
                return PolicyDecision {
                    allowed: false,
                    require_pqc: policy.require_pqc,
                    violation: Some(format!(
                        "threshold {} below required {}",
                        threshold, policy.min_threshold
                    )),
                };
            }
            if policy
                .mandatory_parties
                .iter()
                .any(|p| !signing_parties.contains(p))
            {
                return PolicyDecision {
                    allowed: false,
                    require_pqc: policy.require_pqc,
                    violation: Some("mandatory parties missing from signing subset".to_string()),
                };
            }
            return PolicyDecision {
                allowed: true,
                require_pqc: policy.require_pqc,
                violation: None,
            };
        }
        PolicyDecision {
            allowed: true,
            require_pqc: false,
            violation: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PolicyInput, PolicyStore};

    #[tokio::test]
    async fn validate_allows_when_no_policy_exists() {
        let store = PolicyStore::new();
        let decision = store.validate("eth_transfer", &[1, 2], 2).await;
        assert!(decision.allowed);
        assert!(!decision.require_pqc);
    }

    #[tokio::test]
    async fn validate_enforces_threshold_and_parties() {
        let store = PolicyStore::new();
        store
            .add(PolicyInput {
                tx_tag: "eth_transfer".to_string(),
                min_threshold: 2,
                mandatory_parties: vec![1, 2],
                require_pqc: true,
            })
            .await;

        let denied = store.validate("eth_transfer", &[1], 1).await;
        assert!(!denied.allowed);
        assert!(denied.require_pqc);

        let allowed = store.validate("eth_transfer", &[1, 2], 2).await;
        assert!(allowed.allowed);
        assert!(allowed.require_pqc);
    }
}
