use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use futures::{future::select, pin_mut};
use log::{debug, warn};
use non_empty_vec::NonEmpty;
use serde::Deserialize;
use serde_with::{serde_as, DisplayFromStr};
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    sync::{mpsc, RwLock},
    time::sleep,
};
use uuid::Uuid;

use crate::{
    comms::{
        AnyDirectUpdate, DirectLink, DirectUpdate, Gate, GateStatus,
        Terminated,
    },
    http_ng,
    ingress::register::Register,
    manager::{Component, WaitPoint},
    payload::Update,
    units::Unit,
};

use super::{
    bmp_builder,
    client_handler,
    client_state::ClientState,
    metrics::BmpTcpOutMetrics,
    status_reporter::BmpTcpOutStatusReporter,
};

//-------- BmpTcpOut config --------------------------------------------------

#[serde_as]
#[derive(Clone, Debug, Deserialize)]
pub struct BmpTcpOut {
    /// Listen address for BMP client connections.
    #[serde_as(as = "Arc<DisplayFromStr>")]
    pub listen: Arc<SocketAddr>,

    /// Sources to receive updates from (upstream gates).
    pub sources: NonEmpty<DirectLink>,

    /// Name of the RIB unit to read initial state from.
    #[serde(default = "BmpTcpOut::default_rib_unit")]
    pub rib_unit: String,

    /// HTTP API path for client listing.
    #[serde(default = "BmpTcpOut::default_http_api_path")]
    http_api_path: Arc<String>,

    /// BMP Initiation sysName TLV.
    #[serde(default = "BmpTcpOut::default_sys_name")]
    pub sys_name: String,

    /// BMP Initiation sysDescr TLV.
    #[serde(default = "BmpTcpOut::default_sys_descr")]
    pub sys_descr: String,

    /// Maximum buffered updates per client during dump phase.
    #[serde(default = "BmpTcpOut::default_max_client_buffer")]
    pub max_client_buffer: usize,
}

impl BmpTcpOut {
    pub async fn run(
        self,
        mut component: Component,
        gate: Gate,
        mut waitpoint: WaitPoint,
    ) -> Result<(), Terminated> {
        let unit_name = component.name().clone();

        // Setup metrics
        let metrics = Arc::new(BmpTcpOutMetrics::new(&gate));
        component.register_metrics(metrics.clone());

        // Setup status reporter
        let status_reporter = Arc::new(BmpTcpOutStatusReporter::new(
            &unit_name,
            metrics.clone(),
        ));

        let ingress_register = component.ingresses();

        // Keep a shared reference to the HTTP API which holds the RIB.
        // The RibUnit calls Api::set_rib() at startup, which may happen
        // before or after this unit starts. By keeping the shared Api
        // reference, we can resolve the RIB lazily when a client connects,
        // avoiding a race where a cloned OnceLock stays empty forever.
        let http_ng_api = component.http_ng_api_arc();

        // Wait for other components to be ready
        gate.process_until(waitpoint.ready()).await?;
        waitpoint.running().await;

        BmpTcpOutRunner::new(
            gate,
            self.listen,
            self.sys_name,
            self.sys_descr,
            self.max_client_buffer,
            http_ng_api,
            ingress_register,
            metrics,
            status_reporter,
        )
        .run(self.sources)
        .await
    }

    fn default_http_api_path() -> Arc<String> {
        Arc::new("/bmp-out/".to_string())
    }

    fn default_rib_unit() -> String {
        "rib".to_string()
    }

    fn default_sys_name() -> String {
        "rotonda-bmp-out".to_string()
    }

    fn default_sys_descr() -> String {
        "Rotonda BMP restreamer".to_string()
    }

    fn default_max_client_buffer() -> usize {
        100_000
    }
}

//-------- BmpTcpOutRunner ---------------------------------------------------

struct BmpTcpOutRunner {
    gate: Arc<Gate>,
    listen: Arc<SocketAddr>,
    sys_name: String,
    sys_descr: String,
    max_client_buffer: usize,
    http_ng_api: Arc<Mutex<http_ng::Api>>,
    ingress_register: Arc<Register>,
    metrics: Arc<BmpTcpOutMetrics>,
    status_reporter: Arc<BmpTcpOutStatusReporter>,
    clients: Arc<RwLock<HashMap<Uuid, Arc<ClientState>>>>,
}

#[async_trait]
impl DirectUpdate for BmpTcpOutRunner {
    async fn direct_update(&self, update: Update) {
        let clients = self.clients.read().await;
        for (_id, client) in clients.iter() {
            if client.is_dumping().await {
                // Buffer updates during initial dump
                match client.buffer_update(update.clone()).await {
                    Some(true) => {} // buffered ok
                    Some(false) => {
                        // Buffer overflow — mark for disconnect
                        self.status_reporter.buffer_overflow(client.remote_addr);
                        // Signal disconnect by closing the channel
                        let _ = client.tx.send(Vec::new()).await;
                    }
                    None => {
                        // Client went live between is_dumping() and
                        // buffer_update() — send directly instead.
                        if !client_handler::send_update_to_client(
                            client,
                            &update,
                            &self.ingress_register,
                        )
                        .await
                        {
                            debug!(
                                "Failed to send update to client {}, will be cleaned up",
                                client.remote_addr
                            );
                        }
                    }
                }
            } else {
                // Live phase — send directly
                if !client_handler::send_update_to_client(
                    client,
                    &update,
                    &self.ingress_register,
                )
                .await
                {
                    debug!(
                        "Failed to send update to client {}, will be cleaned up",
                        client.remote_addr
                    );
                }
            }
        }
    }
}

impl std::fmt::Debug for BmpTcpOutRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BmpTcpOutRunner").finish()
    }
}

impl AnyDirectUpdate for BmpTcpOutRunner {}

impl BmpTcpOutRunner {
    #[allow(clippy::too_many_arguments)]
    fn new(
        gate: Gate,
        listen: Arc<SocketAddr>,
        sys_name: String,
        sys_descr: String,
        max_client_buffer: usize,
        http_ng_api: Arc<Mutex<http_ng::Api>>,
        ingress_register: Arc<Register>,
        metrics: Arc<BmpTcpOutMetrics>,
        status_reporter: Arc<BmpTcpOutStatusReporter>,
    ) -> Self {
        Self {
            gate: Arc::new(gate),
            listen,
            sys_name,
            sys_descr,
            max_client_buffer,
            http_ng_api,
            ingress_register,
            metrics,
            status_reporter,
            clients: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn run(
        self,
        mut sources: NonEmpty<DirectLink>,
    ) -> Result<(), Terminated> {
        let arc_self = Arc::new(self);

        // Register as a direct update receiver with the linked gates.
        for link in sources.iter_mut() {
            link.connect(arc_self.clone(), false).await.unwrap();
        }

        let listen_addr = arc_self.listen.clone();
        let status_reporter = arc_self.status_reporter.clone();

        // Bind TCP listener with backoff
        let listener = loop {
            match TcpListener::bind(listen_addr.as_ref()).await {
                Ok(listener) => break listener,
                Err(err) => {
                    let msg = format!("{err}: Will retry in 5 seconds.");
                    status_reporter.bind_error(&listen_addr.to_string(), &msg);
                    sleep(Duration::from_secs(5)).await;
                }
            }
        };

        status_reporter.listener_listening(&listen_addr.to_string());

        // Main accept loop
        loop {
            let process_fut = arc_self.gate.process();
            let accept_fut = listener.accept();
            pin_mut!(process_fut);
            pin_mut!(accept_fut);

            match select(process_fut, accept_fut).await {
                futures::future::Either::Left((gate_result, _)) => {
                    match gate_result {
                        Ok(status) => match status {
                            GateStatus::Reconfiguring {
                                new_config:
                                    Unit::BmpTcpOut(BmpTcpOut {
                                        sources: new_sources,
                                        ..
                                    }),
                            } => {
                                debug!("BmpTcpOut reconfiguring");
                                sources = new_sources;
                                for link in sources.iter_mut() {
                                    link.connect(arc_self.clone(), false)
                                        .await
                                        .unwrap();
                                }
                            }
                            GateStatus::ReportLinks { report } => {
                                report.set_sources(&sources);
                                report.set_graph_status(
                                    arc_self.metrics.clone(),
                                );
                            }
                            _ => { /* Nothing to do */ }
                        },
                        Err(Terminated) => {
                            // Send termination to all clients
                            let term_msg =
                                bmp_builder::build_termination_message();
                            let clients = arc_self.clients.read().await;
                            for (_, client) in clients.iter() {
                                let _ =
                                    client.send_message(term_msg.clone()).await;
                            }
                            return Err(Terminated);
                        }
                    }
                }
                futures::future::Either::Right((accept_result, _)) => {
                    match accept_result {
                        Ok((tcp_stream, client_addr)) => {
                            arc_self
                                .handle_new_client(tcp_stream, client_addr)
                                .await;
                        }
                        Err(err) => {
                            status_reporter.listener_io_error(err);
                        }
                    }
                }
            }
        }
    }

    /// Handle a newly connected BMP client.
    async fn handle_new_client(
        self: &Arc<Self>,
        tcp_stream: tokio::net::TcpStream,
        client_addr: SocketAddr,
    ) {
        self.status_reporter.client_connected(client_addr);

        // Create channel for sending messages to this client
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024);

        let client = Arc::new(ClientState::new(
            client_addr,
            tx,
            self.max_client_buffer,
        ));

        let client_id = client.id;

        // Insert client into map before spawning tasks so that
        // direct_update() can see it immediately and writer cleanup
        // cannot race ahead of the insert.
        self.clients
            .write()
            .await
            .insert(client_id, client.clone());

        // Spawn writer task
        let status_reporter = self.status_reporter.clone();
        let clients_for_writer = self.clients.clone();

        let (_reader, mut writer) = tcp_stream.into_split();

        crate::tokio::spawn(
            &format!("bmp-out-writer[{}]", client_addr),
            async move {
                while let Some(msg) = rx.recv().await {
                    if msg.is_empty() {
                        // Empty message signals disconnect
                        break;
                    }
                    if writer.write_all(&msg).await.is_err() {
                        break;
                    }
                }

                // Clean up client on disconnect
                clients_for_writer.write().await.remove(&client_id);
                status_reporter.client_disconnected(client_addr);
            },
        );

        // Spawn dump task — resolve the RIB lazily so that late
        // RibUnit initialization is visible.
        let http_ng_api = self.http_ng_api.clone();
        let ingress_register = self.ingress_register.clone();
        let sys_name = self.sys_name.clone();
        let sys_descr = self.sys_descr.clone();
        let metrics_for_dump = self.metrics.clone();
        let status_reporter_for_dump = self.status_reporter.clone();

        crate::tokio::spawn(
            &format!("bmp-out-dump[{}]", client_addr),
            async move {
                // Resolve the RIB from the shared API at dump time,
                // not at unit startup.
                let rib = http_ng_api
                    .lock()
                    .ok()
                    .and_then(|api| {
                        api.cloned_api_state().store.get().cloned()
                    });

                if let Some(rib) = rib {
                    let success = client_handler::perform_initial_dump(
                        &client,
                        &rib,
                        &ingress_register,
                        &sys_name,
                        &sys_descr,
                        &metrics_for_dump,
                        &status_reporter_for_dump,
                    )
                    .await;

                    if !success {
                        warn!(
                            "Initial dump failed for client {}",
                            client_addr
                        );
                    }
                } else {
                    // No RIB available yet - just send initiation and go live
                    warn!("No RIB available for initial dump, sending initiation only");
                    let init_msg = bmp_builder::build_initiation_message(
                        &sys_name, &sys_descr,
                    );
                    client.send_message(init_msg).await;
                    client.set_live().await;
                }
            },
        );
    }
}
