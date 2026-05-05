use crate::{app::AppState, jobs::JobEvent};
use axum::{
    extract::{Path, State},
    response::sse::{Event, KeepAlive, Sse},
};
use futures_core::Stream;
use std::{convert::Infallible, time::Duration};
use tokio_stream::{wrappers::BroadcastStream, StreamExt};
use uuid::Uuid;

pub async fn stream_job_events(
    State(state): State<AppState>,
    Path(job_id): Path<Uuid>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream = BroadcastStream::new(state.jobs.subscribe()).filter_map(move |result| {
        let target = job_id;
        match result.ok() {
            Some(JobEvent {
                job_id, message, ..
            }) if job_id == target => Some(Ok(Event::default().data(message))),
            _ => None,
        }
    });

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(10))
            .text("keep-alive"),
    )
}

pub async fn stream_topic_events(
    State(state): State<AppState>,
    Path(topic): Path<String>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let stream =
        BroadcastStream::new(state.coordinator.subscribe(&topic).await).filter_map(|result| {
            match result.ok() {
                Some(message) => Some(Ok(Event::default().data(message))),
                None => None,
            }
        });

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(10))
            .text("keep-alive"),
    )
}
