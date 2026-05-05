use super::{Job, JobEvent, JobEventKind, JobKind, JobPhase, JobStatus};
use chrono::Utc;
use serde_json::Value;
use std::{collections::HashMap, sync::Arc};
use tokio::sync::{broadcast, RwLock};
use tracing::info;
use uuid::Uuid;

#[derive(Clone)]
pub struct JobManager {
    jobs: Arc<RwLock<HashMap<Uuid, Job>>>,
    events: broadcast::Sender<JobEvent>,
}

impl JobManager {
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(512);
        Self {
            jobs: Arc::new(RwLock::new(HashMap::new())),
            events,
        }
    }

    pub async fn create_job(&self, kind: JobKind) -> Job {
        let mut job = Job::queued(kind);
        job.logs.push("job created".to_string());
        self.jobs.write().await.insert(job.id, job.clone());
        let _ = self
            .events
            .send(JobEvent::new(job.id, JobEventKind::Created, "job created"));
        info!(job_id=%job.id, ?job.kind, "job created");
        job
    }

    pub async fn get_job(&self, job_id: Uuid) -> Option<Job> {
        self.jobs.read().await.get(&job_id).cloned()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<JobEvent> {
        self.events.subscribe()
    }

    pub async fn set_running(
        &self,
        job_id: Uuid,
        phase: JobPhase,
        message: impl Into<String>,
    ) -> Option<Job> {
        self.update_job(
            job_id,
            Some(JobStatus::Running),
            Some(phase),
            None,
            None,
            message,
        )
        .await
    }

    pub async fn set_completed(
        &self,
        job_id: Uuid,
        phase: JobPhase,
        result: Option<Value>,
        message: impl Into<String>,
    ) -> Option<Job> {
        self.update_job(
            job_id,
            Some(JobStatus::Completed),
            Some(phase),
            result,
            None,
            message,
        )
        .await
    }

    pub async fn set_failed(
        &self,
        job_id: Uuid,
        phase: JobPhase,
        error: impl Into<String>,
    ) -> Option<Job> {
        let error = error.into();
        self.update_job(
            job_id,
            Some(JobStatus::Failed),
            Some(phase),
            None,
            Some(error.clone()),
            error,
        )
        .await
    }

    pub async fn log(&self, job_id: Uuid, message: impl Into<String>) {
        let message = message.into();
        if let Some(job) = self.jobs.write().await.get_mut(&job_id) {
            job.logs.push(message.clone());
            if job.logs.len() > 300 {
                let excess = job.logs.len() - 300;
                job.logs.drain(0..excess);
            }
            job.updated_at = Utc::now();
        }
        let _ = self
            .events
            .send(JobEvent::new(job_id, JobEventKind::Log, message));
    }

    async fn update_job(
        &self,
        job_id: Uuid,
        status: Option<JobStatus>,
        phase: Option<JobPhase>,
        result: Option<Value>,
        error: Option<String>,
        message: impl Into<String>,
    ) -> Option<Job> {
        let mut jobs = self.jobs.write().await;
        let job = jobs.get_mut(&job_id)?;
        if let Some(status) = status {
            job.status = status;
        }
        if let Some(phase) = phase {
            job.phase = phase;
        }
        if result.is_some() {
            job.result = result;
        }
        if error.is_some() {
            job.error = error;
        }
        job.updated_at = Utc::now();
        let message = message.into();
        job.logs.push(message.clone());
        if job.logs.len() > 300 {
            let excess = job.logs.len() - 300;
            job.logs.drain(0..excess);
        }
        let cloned = job.clone();
        drop(jobs);
        let _ = self
            .events
            .send(JobEvent::new(job_id, JobEventKind::StatusChanged, message));
        Some(cloned)
    }
}
