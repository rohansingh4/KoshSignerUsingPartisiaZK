use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    DeployContract,
    CreateKey,
    ReuseSign,
    FreshSign,
    BroadcastSepolia,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobPhase {
    Queued,
    EvaluatingPolicy,
    DeployingContract,
    CreatingKey,
    LoadingShares,
    RecoveringSigningSession,
    StartingPqcApproval,
    StartingSignMessage,
    StartingGg20,
    RunningMta,
    BroadcastingSepolia,
    Completed,
    Failed,
}

#[derive(Clone, Debug, Serialize)]
pub struct Job {
    pub id: Uuid,
    pub kind: JobKind,
    pub status: JobStatus,
    pub phase: JobPhase,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub result: Option<Value>,
    pub error: Option<String>,
    pub logs: Vec<String>,
}

impl Job {
    pub fn queued(kind: JobKind) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            kind,
            status: JobStatus::Queued,
            phase: JobPhase::Queued,
            created_at: now,
            updated_at: now,
            result: None,
            error: None,
            logs: Vec::new(),
        }
    }
}
