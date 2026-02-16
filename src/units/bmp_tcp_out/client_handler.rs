use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use log::{debug, info, warn};

use rotonda_store::prefix_record::RouteStatus;

use crate::{
    ingress::{
        self,
        http_ng::QueryFilter,
        IngressId, IngressInfo, IngressType,
    },
    payload::{Payload, RotondaRoute, Update},
    units::rib_unit::rib::Rib,
};
use routecore::bgp::types::AfiSafiType;

use super::{
    bmp_builder::{self, PeerInfo},
    client_state::ClientState,
    metrics::BmpTcpOutMetrics,
    status_reporter::BmpTcpOutStatusReporter,
};

/// Perform the initial table dump for a newly connected BMP client.
///
/// This sends:
/// 1. BMP Initiation Message
/// 2. For each active peer: Peer Up + all routes from the RIB
/// 3. Transitions client to Live phase
/// 4. Drains any buffered updates that arrived during dump
pub async fn perform_initial_dump(
    client: &Arc<ClientState>,
    rib: &Arc<Rib>,
    ingress_register: &Arc<register::Register>,
    sys_name: &str,
    sys_descr: &str,
    metrics: &Arc<BmpTcpOutMetrics>,
    status_reporter: &Arc<BmpTcpOutStatusReporter>,
) -> bool {
    status_reporter.dump_started(client.remote_addr);

    // 1. Send Initiation Message
    let init_msg = bmp_builder::build_initiation_message(sys_name, sys_descr);
    if !client.send_message(init_msg).await {
        return false;
    }

    // 2. Find active BGP peers (both BgpViaBmp and Bgp types)
    let peers = {
        let mut all_peers = Vec::new();
        for ingress_type in [IngressType::BgpViaBmp, IngressType::Bgp] {
            let type_name = format!("{:?}", ingress_type);
            let filter = QueryFilter {
                ingress_type: Some(ingress_type),
                ..Default::default()
            };
            let found = ingress_register.search(filter);
            info!(
                "bmp-out dump for {}: found {} peers of type {}",
                client.remote_addr,
                found.len(),
                type_name,
            );
            all_peers.extend(found);
        }
        all_peers
    };

    info!(
        "bmp-out dump for {}: total {} peers to dump",
        client.remote_addr,
        peers.len()
    );

    // 3. For each peer, send Peer Up + routes
    let dump_start = Instant::now();
    let bytes_before_dump = client.bytes_sent.load(Ordering::Relaxed);
    let mut total_routes: usize = 0;
    for peer_entry in &peers {
        let ingress_id = peer_entry.ingress_id;
        let info = &peer_entry.ingress_info;
        let peer_info = PeerInfo::from_ingress_info(info);

        let peer_start = Instant::now();
        let bytes_before_peer = client.bytes_sent.load(Ordering::Relaxed);

        // Send Peer Up
        let peer_up_msg = bmp_builder::build_peer_up(&peer_info);
        if !client.send_message(peer_up_msg).await {
            return false;
        }

        client.add_known_peer(ingress_id).await;

        // Query RIB for all routes from this peer
        let mut peer_route_count: usize = 0;
        let mut has_ipv4 = false;
        let mut has_ipv6 = false;
        match rib.match_ingress_id(ingress_id) {
            Ok(prefix_records) => {
                for record in prefix_records {
                    let prefix = record.prefix;
                    if prefix.is_v4() {
                        has_ipv4 = true;
                    } else {
                        has_ipv6 = true;
                    }

                    for route_record in record.meta {
                        let pamap = &route_record.meta;
                        let msg = bmp_builder::build_route_monitoring(
                            &peer_info,
                            prefix,
                            pamap,
                            false,
                        );
                        peer_route_count += 1;
                        if !client.send_message(msg).await {
                            return false;
                        }
                    }
                }
            }
            Err(e) => {
                warn!(
                    "Failed to query RIB for ingress_id {}: {}",
                    ingress_id, e
                );
            }
        }

        if has_ipv4 {
            if let Some(msg) =
                bmp_builder::build_end_of_rib_marker(
                    &peer_info,
                    AfiSafiType::Ipv4Unicast,
                )
            {
                if !client.send_message(msg).await {
                    return false;
                }
            }
        }

        if has_ipv6 {
            if let Some(msg) =
                bmp_builder::build_end_of_rib_marker(
                    &peer_info,
                    AfiSafiType::Ipv6Unicast,
                )
            {
                if !client.send_message(msg).await {
                    return false;
                }
            }
        }
        let peer_bytes = client.bytes_sent.load(Ordering::Relaxed) - bytes_before_peer;
        let peer_elapsed = peer_start.elapsed();
        info!(
            "bmp-out dump for {}: peer ingress_id={} sent {} routes, {:.2} MB in {:.2}s",
            client.remote_addr,
            ingress_id,
            peer_route_count,
            peer_bytes as f64 / (1024.0 * 1024.0),
            peer_elapsed.as_secs_f64(),
        );
        total_routes += peer_route_count;
    }

    let dump_bytes = client.bytes_sent.load(Ordering::Relaxed) - bytes_before_dump;
    let dump_elapsed = dump_start.elapsed();
    info!(
        "bmp-out dump for {}: dump complete, {} peers, {} total routes, {:.2} MB in {:.2}s",
        client.remote_addr,
        peers.len(),
        total_routes,
        dump_bytes as f64 / (1024.0 * 1024.0),
        dump_elapsed.as_secs_f64(),
    );

    // 4. Drain buffered updates
    let buffered = client.take_buffered_updates().await;
    debug!(
        "Draining {} buffered updates for client {}",
        buffered.len(),
        client.remote_addr
    );

    for update in buffered {
        if !send_update_to_client(client, &update, ingress_register).await {
            return false;
        }
    }

    // 5. Transition to Live phase after buffered updates are sent
    client.set_live().await;
    status_reporter.dump_completed(client.remote_addr);

    true
}

/// Convert an Update to BMP messages and send to a single client.
///
/// Returns false if the send failed (client disconnected).
pub async fn send_update_to_client(
    client: &Arc<ClientState>,
    update: &Update,
    ingress_register: &Arc<register::Register>,
) -> bool {
    match update {
        Update::Single(payload) => {
            send_payload_to_client(client, payload, ingress_register).await
        }
        Update::Bulk(payloads) => {
            for payload in payloads {
                if !send_payload_to_client(client, payload, ingress_register).await {
                    return false;
                }
            }
            true
        }
        Update::Withdraw(ingress_id, _afisafi) => {
            send_peer_down(client, *ingress_id, ingress_register).await
        }
        Update::WithdrawBulk(ingress_ids) => {
            for &ingress_id in ingress_ids {
                if !send_peer_down(client, ingress_id, ingress_register).await {
                    return false;
                }
            }
            true
        }
        Update::IngressReappeared(ingress_id) => {
            send_peer_reappeared(client, *ingress_id, ingress_register).await
        }
        _ => {
            // Other update types are ignored for BMP out
            true
        }
    }
}

/// Send a single Payload as a Route Monitoring BMP message.
async fn send_payload_to_client(
    client: &Arc<ClientState>,
    payload: &Payload,
    ingress_register: &Arc<register::Register>,
) -> bool {
    let ingress_id = payload.ingress_id;

    // Ensure we have sent Peer Up for this peer
    if client.register_known_peer_if_absent(ingress_id).await {
        if let Some(info) = ingress_register.get(ingress_id) {
            let peer_info = PeerInfo::from_ingress_info(&info);
            let peer_up = bmp_builder::build_peer_up(&peer_info);
            if !client.send_message(peer_up).await {
                client.remove_known_peer(ingress_id).await;
                return false;
            }
        }
    }

    // Build and send Route Monitoring message
    let info = ingress_register.get(ingress_id);
    let peer_info = match info {
        Some(ref info) => PeerInfo::from_ingress_info(info),
        None => {
            // Fall back to a default peer info
            PeerInfo::from_ingress_info(&IngressInfo::default())
        }
    };

    let is_withdrawal = payload.route_status == RouteStatus::Withdrawn;
    if let Some(msg) = bmp_builder::build_route_monitoring_from_route(&peer_info, &payload.rx_value, is_withdrawal)
    {
        client.send_message(msg).await
    } else {
        true // Skip if we can't build the message
    }
}

/// Send a Peer Down notification for an ingress.
async fn send_peer_down(
    client: &Arc<ClientState>,
    ingress_id: IngressId,
    ingress_register: &Arc<register::Register>,
) -> bool {
    if !client.has_known_peer(ingress_id).await {
        return true; // Client doesn't know about this peer, nothing to do
    }

    let info = ingress_register.get(ingress_id);
    let peer_info = match info {
        Some(ref info) => PeerInfo::from_ingress_info(info),
        None => PeerInfo::from_ingress_info(&IngressInfo::default()),
    };

    let msg = bmp_builder::build_peer_down(&peer_info);
    let sent = client.send_message(msg).await;

    client.remove_known_peer(ingress_id).await;

    sent
}

/// Handle IngressReappeared: send Peer Up for the reappeared peer.
async fn send_peer_reappeared(
    client: &Arc<ClientState>,
    ingress_id: IngressId,
    ingress_register: &Arc<register::Register>,
) -> bool {
    if let Some(info) = ingress_register.get(ingress_id) {
        let peer_info = PeerInfo::from_ingress_info(&info);

        // Only send Peer Up if this peer was not already known.
        if client.register_known_peer_if_absent(ingress_id).await {
            // Send Peer Up
            let peer_up = bmp_builder::build_peer_up(&peer_info);
            if !client.send_message(peer_up).await {
                client.remove_known_peer(ingress_id).await;
                return false;
            }
        }
    }
    true
}

// Make register accessible from the ingress module
use crate::ingress::register;
