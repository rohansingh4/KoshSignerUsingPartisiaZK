use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobEventKind {
    Created,
    StatusChanged,
    Log,
}

#[derive(Clone, Debug, Serialize)]
pub struct JobEvent {
    pub job_id: Uuid,
    pub kind: JobEventKind,
    pub message: String,
    pub timestamp: DateTime<Utc>,
}

impl JobEvent {
    pub fn new(job_id: Uuid, kind: JobEventKind, message: impl Into<String>) -> Self {
        Self {
            job_id,
            kind,
            message: message.into(),
            timestamp: Utc::now(),
        }
    }
}
