use std::sync::{
    atomic::{AtomicUsize, Ordering::SeqCst},
    Arc,
};

use crate::{
    comms::{Gate, GateMetrics, GraphStatus},
    metrics::{self, Metric, MetricType, MetricUnit},
};

#[derive(Debug, Default)]
pub struct BmpTcpOutMetrics {
    gate: Option<Arc<GateMetrics>>,
    pub listener_bound_count: Arc<AtomicUsize>,
    pub clients_connected: Arc<AtomicUsize>,
    pub clients_disconnected: Arc<AtomicUsize>,
    pub messages_sent: Arc<AtomicUsize>,
    pub bytes_sent: Arc<AtomicUsize>,
    pub active_dumps: Arc<AtomicUsize>,
    pub buffer_overflows: Arc<AtomicUsize>,
}

impl GraphStatus for BmpTcpOutMetrics {
    fn status_text(&self) -> String {
        let num_clients = self.clients_connected.load(SeqCst)
            .saturating_sub(self.clients_disconnected.load(SeqCst));
        let num_msgs = self.messages_sent.load(SeqCst);
        format!("clients: {}\nmsgs sent: {}", num_clients, num_msgs)
    }

    fn okay(&self) -> Option<bool> {
        let connected = self.clients_connected.load(SeqCst);
        if connected > 0 {
            let disconnected = self.clients_disconnected.load(SeqCst);
            Some(connected > disconnected)
        } else {
            None
        }
    }
}

impl BmpTcpOutMetrics {
    const LISTENER_BOUND_COUNT_METRIC: Metric = Metric::new(
        "bmp_tcp_out_listener_bound_count",
        "the number of times the TCP listen port was bound to",
        MetricType::Counter,
        MetricUnit::Total,
    );
    const CLIENTS_CONNECTED_METRIC: Metric = Metric::new(
        "bmp_tcp_out_clients_connected",
        "the number of BMP client connections accepted",
        MetricType::Counter,
        MetricUnit::Total,
    );
    const CLIENTS_DISCONNECTED_METRIC: Metric = Metric::new(
        "bmp_tcp_out_clients_disconnected",
        "the number of BMP client connections lost",
        MetricType::Counter,
        MetricUnit::Total,
    );
    const MESSAGES_SENT_METRIC: Metric = Metric::new(
        "bmp_tcp_out_messages_sent",
        "the total number of BMP messages sent to all clients",
        MetricType::Counter,
        MetricUnit::Total,
    );
    const BYTES_SENT_METRIC: Metric = Metric::new(
        "bmp_tcp_out_bytes_sent",
        "the total number of bytes sent to all clients",
        MetricType::Counter,
        MetricUnit::Total,
    );
    const ACTIVE_DUMPS_METRIC: Metric = Metric::new(
        "bmp_tcp_out_active_dumps",
        "the number of clients currently receiving initial table dump",
        MetricType::Gauge,
        MetricUnit::Total,
    );
    const BUFFER_OVERFLOWS_METRIC: Metric = Metric::new(
        "bmp_tcp_out_buffer_overflows",
        "the number of clients disconnected due to buffer overflow",
        MetricType::Counter,
        MetricUnit::Total,
    );

    pub fn new(gate: &Gate) -> Self {
        Self {
            gate: Some(gate.metrics()),
            ..Default::default()
        }
    }
}

impl metrics::Source for BmpTcpOutMetrics {
    fn append(&self, unit_name: &str, target: &mut metrics::Target) {
        if let Some(gate) = &self.gate {
            gate.append(unit_name, target);
        }

        target.append_simple(
            &Self::LISTENER_BOUND_COUNT_METRIC,
            Some(unit_name),
            self.listener_bound_count.load(SeqCst),
        );
        target.append_simple(
            &Self::CLIENTS_CONNECTED_METRIC,
            Some(unit_name),
            self.clients_connected.load(SeqCst),
        );
        target.append_simple(
            &Self::CLIENTS_DISCONNECTED_METRIC,
            Some(unit_name),
            self.clients_disconnected.load(SeqCst),
        );
        target.append_simple(
            &Self::MESSAGES_SENT_METRIC,
            Some(unit_name),
            self.messages_sent.load(SeqCst),
        );
        target.append_simple(
            &Self::BYTES_SENT_METRIC,
            Some(unit_name),
            self.bytes_sent.load(SeqCst),
        );
        target.append_simple(
            &Self::ACTIVE_DUMPS_METRIC,
            Some(unit_name),
            self.active_dumps.load(SeqCst),
        );
        target.append_simple(
            &Self::BUFFER_OVERFLOWS_METRIC,
            Some(unit_name),
            self.buffer_overflows.load(SeqCst),
        );
    }
}
