use std::collections::{HashMap, HashSet};
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

/// Look up the parent (router-level) IngressInfo for a peer and build a
/// JSON Admin Label string from its sysName/sysDescr.
fn resolve_admin_label(
    info: &IngressInfo,
    ingress_register: &register::Register,
    forward_router_info: bool,
) -> Option<String> {
    if !forward_router_info {
        return None;
    }
    let parent_id = info.parent_ingress?;
    let parent = ingress_register.get(parent_id)?;
    bmp_builder::build_admin_label_json(
        parent.name.as_deref(),
        parent.desc.as_deref(),
    )
}

/// Perform the initial table dump for a newly connected BMP client.
///
/// Uses a two-phase approach for fast dumps with many peers:
/// 1. BMP Initiation Message
/// 2. Peer Up for ALL active peers
/// 3. Single RIB walk sending all routes for all peers (interleaved)
/// 4. End-of-RIB markers for all peers
/// 5. Transitions client to Live phase
/// 6. Drains any buffered updates that arrived during dump
pub async fn perform_initial_dump(
    client: &Arc<ClientState>,
    rib: &Arc<Rib>,
    ingress_register: &Arc<register::Register>,
    sys_name: &str,
    sys_descr: &str,
    forward_router_info: bool,
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

    // 3. Phase 1: Send Peer Up for ALL peers first
    let dump_start = Instant::now();
    let bytes_before_dump = client.bytes_sent.load(Ordering::Relaxed);

    // Build a lookup map: IngressId -> PeerInfo for quick access during RIB walk
    let mut peer_info_map: HashMap<IngressId, PeerInfo> = HashMap::with_capacity(peers.len());
    let mut known_ingress_ids: HashSet<IngressId> = HashSet::with_capacity(peers.len());

    for peer_entry in &peers {
        let ingress_id = peer_entry.ingress_id;
        let info = &peer_entry.ingress_info;
        let mut peer_info = PeerInfo::from_ingress_info(info);
        peer_info.admin_label = resolve_admin_label(info, ingress_register, forward_router_info);

        // Send Peer Up
        let peer_up_msg = bmp_builder::build_peer_up(&peer_info);
        if !client.send_message(peer_up_msg).await {
            return false;
        }

        client.add_known_peer(ingress_id).await;
        peer_info_map.insert(ingress_id, peer_info);
        known_ingress_ids.insert(ingress_id);
    }

    info!(
        "bmp-out dump for {}: sent Peer Up for {} peers in {:.2}s",
        client.remote_addr,
        peers.len(),
        dump_start.elapsed().as_secs_f64(),
    );

    // 4. Phase 2: Single RIB walk — send all routes for all peers interleaved
    let rib_walk_start = Instant::now();
    let mut total_routes: usize = 0;
    // Track which address families each peer has routes for (for End-of-RIB)
    let mut peer_has_ipv4: HashSet<IngressId> = HashSet::new();
    let mut peer_has_ipv6: HashSet<IngressId> = HashSet::new();

    match rib.iter_all_prefix_records() {
        Ok(prefix_records) => {
            for prefix_record in prefix_records {
                let prefix = prefix_record.prefix;

                for route_record in prefix_record.meta {
                    // Skip withdrawn routes
                    if route_record.status == RouteStatus::Withdrawn {
                        continue;
                    }

                    let ingress_id = route_record.multi_uniq_id;

                    // Only send routes for peers we know about
                    let peer_info = match peer_info_map.get(&ingress_id) {
                        Some(pi) => pi,
                        None => continue,
                    };

                    // Track address families per peer
                    if prefix.is_v4() {
                        peer_has_ipv4.insert(ingress_id);
                    } else {
                        peer_has_ipv6.insert(ingress_id);
                    }

                    let pamap = &route_record.meta;
                    let msg = bmp_builder::build_route_monitoring(
                        peer_info,
                        prefix,
                        pamap,
                        false,
                    );
                    total_routes += 1;
                    if !client.send_message(msg).await {
                        return false;
                    }
                }
            }
        }
        Err(e) => {
            warn!(
                "bmp-out dump for {}: failed to iterate RIB: {}",
                client.remote_addr, e
            );
        }
    }

    let rib_walk_elapsed = rib_walk_start.elapsed();
    info!(
        "bmp-out dump for {}: RIB walk sent {} routes in {:.2}s",
        client.remote_addr,
        total_routes,
        rib_walk_elapsed.as_secs_f64(),
    );

    // 5. Phase 3: Send End-of-RIB markers for all peers
    for peer_entry in &peers {
        let ingress_id = peer_entry.ingress_id;
        let peer_info = match peer_info_map.get(&ingress_id) {
            Some(pi) => pi,
            None => continue,
        };

        if peer_has_ipv4.contains(&ingress_id) {
            if let Some(msg) =
                bmp_builder::build_end_of_rib_marker(
                    peer_info,
                    AfiSafiType::Ipv4Unicast,
                )
            {
                if !client.send_message(msg).await {
                    return false;
                }
            }
        }

        if peer_has_ipv6.contains(&ingress_id) {
            if let Some(msg) =
                bmp_builder::build_end_of_rib_marker(
                    peer_info,
                    AfiSafiType::Ipv6Unicast,
                )
            {
                if !client.send_message(msg).await {
                    return false;
                }
            }
        }
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
        if !send_update_to_client(client, &update, ingress_register, forward_router_info).await {
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
    forward_router_info: bool,
) -> bool {
    match update {
        Update::Single(payload) => {
            send_payload_to_client(client, payload, ingress_register, forward_router_info).await
        }
        Update::Bulk(payloads) => {
            for payload in payloads.iter() {
                if !send_payload_to_client(client, payload, ingress_register, forward_router_info).await {
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
            send_peer_reappeared(client, *ingress_id, ingress_register, forward_router_info).await
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
    forward_router_info: bool,
) -> bool {
    let ingress_id = payload.ingress_id;

    // Ensure we have sent Peer Up for this peer
    if client.register_known_peer_if_absent(ingress_id).await {
        if let Some(info) = ingress_register.get(ingress_id) {
            let mut peer_info = PeerInfo::from_ingress_info(&info);
            peer_info.admin_label = resolve_admin_label(&info, ingress_register, forward_router_info);
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
    forward_router_info: bool,
) -> bool {
    if let Some(info) = ingress_register.get(ingress_id) {
        let mut peer_info = PeerInfo::from_ingress_info(&info);
        peer_info.admin_label = resolve_admin_label(&info, ingress_register, forward_router_info);

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
