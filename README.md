# dnstap

A zero-daemon, pure-Rust DNS wire protocol tap and chaos proxy (UDP & TCP).

Inspects DNS queries and responses in real time, injects latency and packet drop, forces TCP fallback via the Truncated (TC) bit, and injects synthetic faults (SERVFAIL, NXDOMAIN, and spoofed A records) — without requiring root or external packet capture daemons like Wireshark or tcpdump.

## Status

Built and verified live. Full pure-Rust RFC 1035 wire codec parsing questions, resource records, and headers. Tested against live upstream Do53 resolvers across UDP and TCP query paths.

## Installation

```sh
cargo install --path .
```

Or build from source:

```sh
cargo build --release
```

## Features

- **Transparent Duplex Tap**: Proxies both UDP and TCP DNS queries to an upstream resolver (default `1.1.1.1:53`).
- **Wire Inspection**: Formats DNS packets in human-readable colorized output, NDJSON, or raw hex.
- **Latency & Jitter Injection**: Adds artificial response delays (`--delay-ms`) and jitter (`--jitter-ms`).
- **Fault Injection**:
  - Drops packets at a configurable probability (`--drop-rate 0.25`).
  - Returns `SERVFAIL` for matching regex patterns (`--servfail ".*internal.*"`).
  - Returns `NXDOMAIN` for matching regex patterns (`--nxdomain ".*legacy.*"`).
  - Overrides A records dynamically (`--override "api.local=127.0.0.1"`).
  - Forces client TCP fallback by setting the Truncated bit (`--force-tc`).

## Usage

### 1. Transparent Tap & Inspection

Run the proxy listening locally on port 5353 and forwarding to Cloudflare:

```sh
dnstap --listen 127.0.0.1:5353 --upstream 1.1.1.1:53
```

Query it using standard `dig`:

```sh
dig @127.0.0.1 -p 5353 example.com
```

### 2. JSON / NDJSON Telemetry Streaming

Pipe live DNS events into `jq` or logging pipelines:

```sh
dnstap --listen 127.0.0.1:5353 --upstream 1.1.1.1:53 --format json | jq .
```

### 3. Testing Client Resiliency (Chaos Engineering)

Simulate 150ms latency with 50ms jitter and a 10% query drop rate:

```sh
dnstap --listen 127.0.0.1:5353 --delay-ms 150 --jitter-ms 50 --drop-rate 0.1
```

### 4. Spoofing and Mocking Records for Local Dev

Override specific domain endpoints to point to local test instances:

```sh
dnstap --listen 127.0.0.1:5353 --override api.production.com=127.0.0.1 --override auth.production.com=127.0.0.1
```

### 5. Forcing TCP Fallback Testing

Test whether your client or application correctly falls back to TCP when receiving truncated UDP responses:

```sh
dnstap --listen 127.0.0.1:5353 --force-tc
```

## License

MIT
