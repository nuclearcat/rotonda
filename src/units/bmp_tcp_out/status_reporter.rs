use std::{
    fmt::Display,
    net::SocketAddr,
    sync::{atomic::Ordering::SeqCst, Arc},
};

use log::{debug, error, info, warn};

use crate::common::status_reporter::{
    sr_log, AnyStatusReporter, Chainable, Named, UnitStatusReporter,
};

use super::metrics::BmpTcpOutMetrics;

#[derive(Debug, Default)]
pub struct BmpTcpOutStatusReporter {
    name: String,
    metrics: Arc<BmpTcpOutMetrics>,
}

impl BmpTcpOutStatusReporter {
    pub fn new<T: Display>(name: T, metrics: Arc<BmpTcpOutMetrics>) -> Self {
        Self {
            name: format!("{}", name),
            metrics,
        }
    }

    pub fn bind_error<T: Display>(&self, listen_addr: &str, err: T) {
        sr_log!(warn: self, "Error while listening for connections on {}: {}", listen_addr, err);
    }

    pub fn listener_listening(&self, server_uri: &str) {
        sr_log!(info: self, "Listening for BMP client connections on {}", server_uri);
        self.metrics.listener_bound_count.fetch_add(1, SeqCst);
    }

    pub fn client_connected(&self, client_addr: SocketAddr) {
        sr_log!(debug: self, "BMP client connected from {}", client_addr);
        self.metrics.clients_connected.fetch_add(1, SeqCst);
    }

    pub fn client_disconnected(&self, client_addr: SocketAddr) {
        sr_log!(debug: self, "BMP client disconnected: {}", client_addr);
        self.metrics.clients_disconnected.fetch_add(1, SeqCst);
    }

    pub fn dump_started(&self, client_addr: SocketAddr) {
        sr_log!(debug: self, "Initial table dump started for client {}", client_addr);
        self.metrics.active_dumps.fetch_add(1, SeqCst);
    }

    pub fn dump_completed(&self, client_addr: SocketAddr) {
        sr_log!(debug: self, "Initial table dump completed for client {}", client_addr);
        self.metrics.active_dumps.fetch_sub(1, SeqCst);
    }

    pub fn dump_failed(&self, client_addr: SocketAddr) {
        sr_log!(warn: self, "Initial table dump failed for client {}", client_addr);
        self.metrics.active_dumps.fetch_sub(1, SeqCst);
    }

    pub fn buffer_overflow(&self, client_addr: SocketAddr) {
        sr_log!(warn: self, "Buffer overflow for client {}, disconnecting", client_addr);
        self.metrics.buffer_overflows.fetch_add(1, SeqCst);
    }

    pub fn listener_io_error<T: Display>(&self, err: T) {
        sr_log!(warn: self, "Error while listening for connections: {}", err);
    }

    pub fn internal_error<T: Display>(&self, err: T) {
        sr_log!(error: self, "Internal error: {}", err);
    }
}

impl UnitStatusReporter for BmpTcpOutStatusReporter {}

impl AnyStatusReporter for BmpTcpOutStatusReporter {
    fn metrics(&self) -> Option<Arc<dyn crate::metrics::Source>> {
        Some(self.metrics.clone())
    }
}

impl Chainable for BmpTcpOutStatusReporter {
    fn add_child<T: Display>(&self, child_name: T) -> Self {
        Self::new(self.link_names(child_name), self.metrics.clone())
    }
}

impl Named for BmpTcpOutStatusReporter {
    fn name(&self) -> &str {
        &self.name
    }
}
