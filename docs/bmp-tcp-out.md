# BMP TCP Out Unit

The `bmp-tcp-out` unit restreams BMP (BGP Monitoring Protocol, RFC 7854) data to
downstream consumers. It accepts TCP connections from BMP collectors and sends
them a full initial table dump followed by real-time updates.

## Configuration

```toml
[units.bmp-out]
type = "bmp-tcp-out"
listen = "0.0.0.0:11020"
sources = ["rib"]
rib_unit = "rib"
sys_name = "rotonda-bmp-out"
sys_descr = "Rotonda BMP restreamer"
max_client_buffer = 100000
acl = ["0.0.0.0/0", "::/0"]

# Optional TLS
tls = false
tls_cert = "/path/to/cert.pem"
tls_key = "/path/to/key.pem"
```

### Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `listen` | yes | — | Address and port to listen on for BMP client connections. |
| `sources` | yes | — | Upstream gate(s) to receive live updates from (typically a RIB unit). |
| `rib_unit` | no | `"rib"` | Name of the RIB unit used for the initial table dump. |
| `sys_name` | no | `"rotonda-bmp-out"` | Value sent in the BMP Initiation Message sysName TLV. |
| `sys_descr` | no | `"Rotonda BMP restreamer"` | Value sent in the BMP Initiation Message sysDescr TLV. |
| `max_client_buffer` | no | `100000` | Maximum number of updates buffered per client during the initial dump phase. If exceeded, the client is disconnected. See [Buffer Overflow](#buffer-overflow) below. |
| `acl` | yes | — | List of allowed client IP addresses or CIDR prefixes. Use `["0.0.0.0/0", "::/0"]` to allow all. |
| `tls` | no | `false` | Enable TLS encryption for client connections. |
| `tls_cert` | no | — | Path to PEM certificate file. If omitted with `tls = true`, a self-signed certificate is generated. |
| `tls_key` | no | — | Path to PEM private key file. Required if `tls_cert` is set. |

## How It Works

### Connection Lifecycle

When a BMP consumer connects:

1. **ACL check** — the client IP is checked against the `acl` list. Rejected connections are closed immediately.
2. **Initiation Message** — a BMP Initiation Message (type 4) is sent with `sys_name` and `sys_descr`.
3. **Initial table dump** — for each active BGP peer known to Rotonda:
   - A BMP Peer Up Notification is sent (with synthetic BGP OPEN messages).
   - All routes for that peer are read from the RIB and sent as BMP Route Monitoring messages.
   - End-of-RIB markers are sent per address family (IPv4 Unicast, IPv6 Unicast).
4. **Buffered updates drained** — any live updates that arrived during the dump are replayed.
5. **Live phase** — the client receives real-time updates as they arrive from upstream.

### Update Types

| Upstream event | BMP message sent |
|---|---|
| Route announcement/withdrawal | Route Monitoring (type 0) wrapping a BGP UPDATE |
| BGP session down | Peer Down Notification (type 2) |
| BGP session reappears | Peer Up Notification (type 3) |

### Buffer Overflow

During the initial dump phase, live updates are buffered in memory so they can
be replayed after the dump completes. If the RIB is large and the update rate is
high, the buffer can fill up before the dump finishes.

When the buffer exceeds `max_client_buffer`, the client is **disconnected**. The
`rotonda_bmp_tcp_out_buffer_overflows_total` metric tracks how often this happens.

**Tuning considerations:**

- If `rotonda_bmp_tcp_out_buffer_overflows_total` is increasing and the system
  has sufficient RAM available, increasing `max_client_buffer` (e.g., to 200000
  or 500000) can resolve the issue by giving the initial dump more time to
  complete before the buffer fills up.
- Each buffered update consumes approximately 750-900 bytes of memory. Use this
  table to estimate peak memory usage per client:

  | `max_client_buffer` | Approx. RAM per client |
  |---------------------|------------------------|
  | 100,000 (default)   | ~75-90 MB              |
  | 200,000             | ~150-180 MB            |
  | 500,000             | ~375-450 MB            |

- If buffer overflows persist even with a larger buffer, the root cause is
  usually that the dump is too slow relative to the update rate. Consider
  whether the consuming application can keep up with the data rate.

## Prometheus Metrics

All metrics are exported under the configured unit name (e.g., `component="bmp-out"`).

| Metric | Type | Description |
|--------|------|-------------|
| `rotonda_bmp_tcp_out_listener_bound_count_total` | counter | Number of times the TCP listen port was bound. |
| `rotonda_bmp_tcp_out_clients_connected_total` | counter | Total BMP client connections accepted. |
| `rotonda_bmp_tcp_out_clients_disconnected_total` | counter | Total BMP client connections lost. |
| `rotonda_bmp_tcp_out_messages_sent_total` | counter | Total BMP messages sent to all clients. |
| `rotonda_bmp_tcp_out_bytes_sent_total` | counter | Total bytes sent to all clients. |
| `rotonda_bmp_tcp_out_active_dumps_total` | gauge | Number of clients currently receiving an initial table dump. |
| `rotonda_bmp_tcp_out_buffer_overflows_total` | counter | Number of clients disconnected due to buffer overflow during dump. |
| `rotonda_bmp_tcp_out_acl_rejected_total` | counter | Number of connections rejected by ACL. |
| `rotonda_bmp_tcp_out_tls_handshake_failures_total` | counter | Number of TLS handshake failures. |

## Example Configuration

Minimal setup receiving from a BMP input and restreaming:

```toml
[units.bmp-in]
type = "bmp-tcp-in"
listen = "0.0.0.0:11019"

[units.rib]
type = "rib"
sources = ["bmp-in"]

[units.bmp-out]
type = "bmp-tcp-out"
listen = "0.0.0.0:11020"
sources = ["rib"]
rib_unit = "rib"
acl = ["0.0.0.0/0", "::/0"]

[targets.null]
type = "null-out"
sources = ["rib"]
```

With TLS and restricted access:

```toml
[units.bmp-out]
type = "bmp-tcp-out"
listen = "0.0.0.0:11020"
sources = ["rib"]
rib_unit = "rib"
sys_name = "my-collector"
sys_descr = "Production BMP restreamer"
max_client_buffer = 200000
acl = ["10.0.0.0/8", "2001:db8::/32"]
tls = true
tls_cert = "/etc/rotonda/cert.pem"
tls_key = "/etc/rotonda/key.pem"
```
