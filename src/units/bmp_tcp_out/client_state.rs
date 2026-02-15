use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use chrono::{DateTime, Utc};
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

use crate::ingress::IngressId;
use crate::payload::Update;

use super::metrics::BmpTcpOutMetrics;

/// Phase of a connected BMP client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientPhase {
    /// Initial table dump is in progress.
    Dumping,
    /// Client is receiving live updates.
    Live,
}

/// State for a single connected BMP consumer client.
pub struct ClientState {
    /// Unique identifier for this client connection.
    pub id: Uuid,

    /// Remote address of the connected client.
    pub remote_addr: SocketAddr,

    /// Current phase (Dumping or Live).
    pub phase: RwLock<ClientPhase>,

    /// Channel sender to the client's writer task.
    pub tx: mpsc::Sender<Vec<u8>>,

    /// Buffer for updates received during the initial dump phase.
    pub dump_buffer: tokio::sync::Mutex<Vec<Update>>,

    /// Set of peer IngressIds that this client knows about (has received Peer Up for).
    pub known_peers: RwLock<HashSet<IngressId>>,

    /// When this client connected.
    pub connected_at: DateTime<Utc>,

    /// Number of BMP messages sent to this client.
    pub messages_sent: AtomicUsize,

    /// Number of bytes sent to this client.
    pub bytes_sent: AtomicUsize,

    /// Maximum buffer size during dump phase.
    pub max_buffer: usize,

    /// Global metrics shared across all clients.
    pub global_metrics: Arc<BmpTcpOutMetrics>,
}

impl ClientState {
    pub fn new(
        remote_addr: SocketAddr,
        tx: mpsc::Sender<Vec<u8>>,
        max_buffer: usize,
        global_metrics: Arc<BmpTcpOutMetrics>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            remote_addr,
            phase: RwLock::new(ClientPhase::Dumping),
            tx,
            dump_buffer: tokio::sync::Mutex::new(Vec::new()),
            known_peers: RwLock::new(HashSet::new()),
            connected_at: Utc::now(),
            messages_sent: AtomicUsize::new(0),
            bytes_sent: AtomicUsize::new(0),
            max_buffer,
            global_metrics,
        }
    }

    /// Check if client is in dumping phase.
    pub async fn is_dumping(&self) -> bool {
        *self.phase.read().await == ClientPhase::Dumping
    }

    /// Transition client to live phase.
    pub async fn set_live(&self) {
        *self.phase.write().await = ClientPhase::Live;
    }

    /// Buffer an update during dump phase.
    ///
    /// Returns `Some(true)` if buffered successfully, `Some(false)` if the
    /// buffer is full (client should be disconnected), or `None` if the
    /// client transitioned to live while we were waiting for the lock
    /// (caller should send the update directly).
    pub async fn buffer_update(&self, update: Update) -> Option<bool> {
        let mut buf = self.dump_buffer.lock().await;
        // Recheck phase while holding the buffer lock to prevent a race
        // with drain_or_go_live(), which sets phase to Live while holding
        // the same lock.
        if *self.phase.read().await != ClientPhase::Dumping {
            return None;
        }
        if buf.len() >= self.max_buffer {
            return Some(false);
        }
        buf.push(update);
        Some(true)
    }

    /// Drain buffered updates, or atomically transition to live if the
    /// buffer is empty.
    ///
    /// Holds the `dump_buffer` lock across the phase transition so that
    /// concurrent `buffer_update()` calls cannot sneak an update into the
    /// buffer after we observed it empty but before we go live.
    pub async fn drain_or_go_live(&self) -> Vec<Update> {
        let mut buf = self.dump_buffer.lock().await;
        let updates = std::mem::take(&mut *buf);
        if updates.is_empty() {
            *self.phase.write().await = ClientPhase::Live;
        }
        updates
    }

    /// Send a BMP message to this client.
    pub async fn send_message(&self, msg: Vec<u8>) -> bool {
        let len = msg.len();
        if self.tx.send(msg).await.is_ok() {
            self.messages_sent.fetch_add(1, Ordering::Relaxed);
            self.bytes_sent.fetch_add(len, Ordering::Relaxed);
            self.global_metrics
                .messages_sent
                .fetch_add(1, Ordering::Relaxed);
            self.global_metrics
                .bytes_sent
                .fetch_add(len, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Add a peer to the known peers set.
    pub async fn add_known_peer(&self, ingress_id: IngressId) {
        self.known_peers.write().await.insert(ingress_id);
    }

    /// Remove a peer from the known peers set.
    pub async fn remove_known_peer(&self, ingress_id: IngressId) -> bool {
        self.known_peers.write().await.remove(&ingress_id)
    }

    /// Check if a peer is known to this client.
    pub async fn has_known_peer(&self, ingress_id: IngressId) -> bool {
        self.known_peers.read().await.contains(&ingress_id)
    }
}

impl std::fmt::Debug for ClientState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientState")
            .field("id", &self.id)
            .field("remote_addr", &self.remote_addr)
            .field("connected_at", &self.connected_at)
            .field("messages_sent", &self.messages_sent.load(Ordering::Relaxed))
            .finish()
    }
}
