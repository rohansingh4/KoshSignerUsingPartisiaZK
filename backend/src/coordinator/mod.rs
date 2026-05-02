use anyhow::Result;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::{broadcast, Mutex, RwLock};

#[derive(Clone)]
pub struct BulletinBoard {
    values: Arc<RwLock<HashMap<String, String>>>,
    buses: Arc<Mutex<HashMap<String, broadcast::Sender<String>>>>,
}

impl BulletinBoard {
    pub fn new() -> Self {
        Self {
            values: Arc::new(RwLock::new(HashMap::new())),
            buses: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn post(&self, topic: impl Into<String>, value: impl Into<String>) {
        let topic = topic.into();
        let value = value.into();
        self.values
            .write()
            .await
            .insert(topic.clone(), value.clone());
        let bus = self.bus_for(&topic).await;
        let _ = bus.send(value);
    }

    pub async fn read(
        &self,
        topic: &str,
        wait: bool,
        timeout: Option<Duration>,
    ) -> Result<Option<String>> {
        if let Some(value) = self.values.read().await.get(topic).cloned() {
            return Ok(Some(value));
        }
        if !wait {
            return Ok(None);
        }

        let mut rx = self.bus_for(topic).await.subscribe();
        let recv = async move { rx.recv().await.ok() };
        let result = match timeout {
            Some(duration) => tokio::time::timeout(duration, recv).await.ok().flatten(),
            None => recv.await,
        };
        Ok(result)
    }

    pub async fn clear(&self) {
        self.values.write().await.clear();
    }

    pub async fn list(&self) -> Vec<String> {
        let mut keys = self.values.read().await.keys().cloned().collect::<Vec<_>>();
        keys.sort();
        keys
    }

    pub async fn subscribe(&self, topic: &str) -> broadcast::Receiver<String> {
        self.bus_for(topic).await.subscribe()
    }

    async fn bus_for(&self, topic: &str) -> broadcast::Sender<String> {
        let mut buses = self.buses.lock().await;
        buses
            .entry(topic.to_string())
            .or_insert_with(|| broadcast::channel(256).0)
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::BulletinBoard;
    use std::time::Duration;

    #[tokio::test]
    async fn post_read_list_and_clear_work() {
        let board = BulletinBoard::new();
        board.post("alpha", "one").await;
        board.post("beta", "two").await;

        assert_eq!(
            board.read("alpha", false, None).await.unwrap(),
            Some("one".to_string())
        );
        assert_eq!(
            board.list().await,
            vec!["alpha".to_string(), "beta".to_string()]
        );

        board.clear().await;
        assert_eq!(board.read("alpha", false, None).await.unwrap(), None);
        assert!(board.list().await.is_empty());
    }

    #[tokio::test]
    async fn waiting_reader_receives_posted_value() {
        let board = BulletinBoard::new();
        let board_clone = board.clone();
        let waiter = tokio::spawn(async move {
            board_clone
                .read("delayed", true, Some(Duration::from_millis(500)))
                .await
                .unwrap()
        });

        tokio::time::sleep(Duration::from_millis(25)).await;
        board.post("delayed", "value").await;

        let result = waiter.await.unwrap();
        assert_eq!(result, Some("value".to_string()));
    }
}
