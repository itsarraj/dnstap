pub mod wire;

use anyhow::{anyhow, Result};
use chrono::Utc;
use colored::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use wire::{
    create_nxdomain_response, create_servfail_response, create_spoofed_a_response,
    parse_dns_message, set_truncated_flag,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Pretty,
    Json,
    Raw,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pretty" => Ok(OutputFormat::Pretty),
            "json" | "ndjson" => Ok(OutputFormat::Json),
            "raw" => Ok(OutputFormat::Raw),
            other => Err(format!("Unknown output format: {}", other)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChaosConfig {
    pub delay_ms: u64,
    pub jitter_ms: u64,
    pub drop_rate: f64,
    pub servfail_patterns: Vec<Regex>,
    pub nxdomain_patterns: Vec<Regex>,
    pub overrides: HashMap<String, Ipv4Addr>,
    pub force_tc: bool,
}

impl Default for ChaosConfig {
    fn default() -> Self {
        Self {
            delay_ms: 0,
            jitter_ms: 0,
            drop_rate: 0.0,
            servfail_patterns: Vec::new(),
            nxdomain_patterns: Vec::new(),
            overrides: HashMap::new(),
            force_tc: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsEvent {
    pub timestamp: String,
    pub transport: String,
    pub client: String,
    pub id: u16,
    pub qname: String,
    pub qtype: String,
    pub rcode: Option<String>,
    pub latency_ms: Option<f64>,
    pub answers: Vec<String>,
    pub chaos_action: Option<String>,
}

impl DnsEvent {
    pub fn format(&self, format: OutputFormat) -> String {
        match format {
            OutputFormat::Json => serde_json::to_string(self).unwrap_or_default(),
            OutputFormat::Raw => {
                let ans = self.answers.join(",");
                format!(
                    "proto={} client={} id={:#06x} qname={} qtype={} rcode={} rtt={:.2}ms chaos={:?} answers=[{}]",
                    self.transport,
                    self.client,
                    self.id,
                    self.qname,
                    self.qtype,
                    self.rcode.as_deref().unwrap_or("NONE"),
                    self.latency_ms.unwrap_or(0.0),
                    self.chaos_action.as_deref().unwrap_or("none"),
                    ans
                )
            }
            OutputFormat::Pretty => {
                let ts = self.timestamp.dimmed();
                let proto = if self.transport == "TCP" {
                    "TCP".bold().blue()
                } else {
                    "UDP".bold().cyan()
                };

                let rcode_str = match self.rcode.as_deref() {
                    Some("NOERROR") => "NOERROR".bold().green(),
                    Some("SERVFAIL") => "SERVFAIL".bold().red(),
                    Some("NXDOMAIN") => "NXDOMAIN".bold().yellow(),
                    Some(rc) => rc.bold().white(),
                    None => "DROP".bold().red(),
                };

                let latency = if let Some(lat) = self.latency_ms {
                    format!("{:.2}ms", lat).cyan()
                } else {
                    "-".dimmed()
                };

                let chaos_tag = if let Some(ref action) = self.chaos_action {
                    format!(" {}", format!("[CHAOS: {}]", action).bold().bright_red())
                } else {
                    "".to_string()
                };

                let answers_str = if self.answers.is_empty() {
                    "".to_string()
                } else {
                    format!(" -> [{}]", self.answers.join(", ").yellow())
                };

                format!(
                    "[{}] [{}] {} {} ({}) -> {} ({}){}{}",
                    ts,
                    proto,
                    self.client.dimmed(),
                    self.qname.bold().white(),
                    self.qtype.magenta(),
                    rcode_str,
                    latency,
                    answers_str,
                    chaos_tag
                )
            }
        }
    }
}

pub struct ProxyStats {
    pub total_queries: AtomicUsize,
    pub total_responses: AtomicUsize,
    pub total_servfail: AtomicUsize,
    pub total_nxdomain: AtomicUsize,
    pub total_spoofed: AtomicUsize,
    pub total_dropped: AtomicUsize,
}

impl ProxyStats {
    pub fn new() -> Self {
        Self {
            total_queries: AtomicUsize::new(0),
            total_responses: AtomicUsize::new(0),
            total_servfail: AtomicUsize::new(0),
            total_nxdomain: AtomicUsize::new(0),
            total_spoofed: AtomicUsize::new(0),
            total_dropped: AtomicUsize::new(0),
        }
    }
}

/// Helper function to check if domain matches any regex in list
pub fn matches_any(domain: &str, regexes: &[Regex]) -> bool {
    regexes.iter().any(|r| r.is_match(domain))
}

/// Evaluate chaos actions for a parsed query
pub fn evaluate_chaos(
    qname: &str,
    chaos: &ChaosConfig,
) -> (Option<String>, Option<ChaosEffect>) {
    // 1. Drop check
    if chaos.drop_rate > 0.0 {
        let rand_val = (Utc::now().timestamp_subsec_nanos() % 1000) as f64 / 1000.0;
        if rand_val < chaos.drop_rate {
            return (Some("DROP".into()), Some(ChaosEffect::Drop));
        }
    }

    // 2. Override check
    if let Some(&ip) = chaos.overrides.get(qname) {
        return (
            Some(format!("SPOOF {}", ip)),
            Some(ChaosEffect::SpoofA(ip)),
        );
    }

    // 3. SERVFAIL check
    if matches_any(qname, &chaos.servfail_patterns) {
        return (Some("SERVFAIL".into()), Some(ChaosEffect::ServFail));
    }

    // 4. NXDOMAIN check
    if matches_any(qname, &chaos.nxdomain_patterns) {
        return (Some("NXDOMAIN".into()), Some(ChaosEffect::NxDomain));
    }

    (None, None)
}

#[derive(Debug, Clone)]
pub enum ChaosEffect {
    Drop,
    ServFail,
    NxDomain,
    SpoofA(Ipv4Addr),
}

/// Process a single UDP DNS packet with chaos logic
pub async fn handle_udp_packet(
    socket: &UdpSocket,
    upstream_addr: SocketAddr,
    client_addr: SocketAddr,
    buf: &[u8],
    chaos: &ChaosConfig,
    filter: Option<&Regex>,
    format: OutputFormat,
    stats: &ProxyStats,
) -> Result<()> {
    let start = Instant::now();
    stats.total_queries.fetch_add(1, Ordering::Relaxed);

    let parsed = match parse_dns_message(buf) {
        Ok(m) => m,
        Err(e) => {
            return Err(anyhow!("Failed to parse DNS query from {}: {}", client_addr, e));
        }
    };

    let qname = parsed
        .questions
        .get(0)
        .map(|q| q.qname.as_str())
        .unwrap_or("");
    let qtype = parsed
        .questions
        .get(0)
        .map(|q| q.qtype.to_string())
        .unwrap_or_else(|| "UNKNOWN".into());

    if let Some(f) = filter {
        if !f.is_match(qname) {
            // Forward without logging or chaos if not matched
            let upstream_sock = UdpSocket::bind("0.0.0.0:0").await?;
            upstream_sock.connect(upstream_addr).await?;
            upstream_sock.send(buf).await?;
            let mut resp_buf = [0u8; 4096];
            let n = upstream_sock.recv(&mut resp_buf).await?;
            socket.send_to(&resp_buf[..n], client_addr).await?;
            return Ok(());
        }
    }

    // Evaluate chaos
    let (chaos_action, effect) = evaluate_chaos(qname, chaos);

    // Artificial delay
    if chaos.delay_ms > 0 {
        let jitter = if chaos.jitter_ms > 0 {
            Utc::now().timestamp_subsec_nanos() as u64 % (chaos.jitter_ms + 1)
        } else {
            0
        };
        tokio::time::sleep(Duration::from_millis(chaos.delay_ms + jitter)).await;
    }

    let response_bytes = match effect {
        Some(ChaosEffect::Drop) => {
            stats.total_dropped.fetch_add(1, Ordering::Relaxed);
            let event = DnsEvent {
                timestamp: Utc::now().to_rfc3339(),
                transport: "UDP".into(),
                client: client_addr.to_string(),
                id: parsed.id,
                qname: qname.to_string(),
                qtype,
                rcode: None,
                latency_ms: Some(start.elapsed().as_secs_f64() * 1000.0),
                answers: Vec::new(),
                chaos_action,
            };
            println!("{}", event.format(format));
            return Ok(());
        }
        Some(ChaosEffect::ServFail) => {
            stats.total_servfail.fetch_add(1, Ordering::Relaxed);
            create_servfail_response(buf)?
        }
        Some(ChaosEffect::NxDomain) => {
            stats.total_nxdomain.fetch_add(1, Ordering::Relaxed);
            create_nxdomain_response(buf)?
        }
        Some(ChaosEffect::SpoofA(ip)) => {
            stats.total_spoofed.fetch_add(1, Ordering::Relaxed);
            create_spoofed_a_response(buf, ip)?
        }
        None => {
            // Forward to upstream DNS server
            let upstream_sock = UdpSocket::bind("0.0.0.0:0").await?;
            upstream_sock.connect(upstream_addr).await?;
            upstream_sock.send(buf).await?;

            let mut resp = [0u8; 4096];
            let n = tokio::time::timeout(Duration::from_secs(4), upstream_sock.recv(&mut resp))
                .await
                .map_err(|_| anyhow!("Upstream DNS timeout for {}", qname))??;

            let mut resp_vec = resp[..n].to_vec();
            if chaos.force_tc {
                set_truncated_flag(&mut resp_vec);
            }
            resp_vec
        }
    };

    let mut final_resp = response_bytes;
    if chaos.force_tc {
        set_truncated_flag(&mut final_resp);
    }

    socket.send_to(&final_resp, client_addr).await?;
    stats.total_responses.fetch_add(1, Ordering::Relaxed);

    let parsed_resp = parse_dns_message(&final_resp).ok();
    let rcode = parsed_resp.as_ref().map(|r| r.rcode.to_string());
    let answers = parsed_resp
        .map(|r| r.answers.into_iter().map(|a| a.data).collect())
        .unwrap_or_default();

    let event = DnsEvent {
        timestamp: Utc::now().to_rfc3339(),
        transport: "UDP".into(),
        client: client_addr.to_string(),
        id: parsed.id,
        qname: qname.to_string(),
        qtype,
        rcode,
        latency_ms: Some(start.elapsed().as_secs_f64() * 1000.0),
        answers,
        chaos_action,
    };

    println!("{}", event.format(format));
    Ok(())
}

/// Process a single TCP DNS client connection
pub async fn handle_tcp_client(
    mut stream: TcpStream,
    client_addr: SocketAddr,
    upstream_addr: SocketAddr,
    chaos: Arc<ChaosConfig>,
    filter: Option<Arc<Regex>>,
    format: OutputFormat,
    stats: Arc<ProxyStats>,
) -> Result<()> {
    let mut len_buf = [0u8; 2];
    loop {
        match stream.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(_) => break, // Connection closed
        }

        let length = u16::from_be_bytes(len_buf) as usize;
        let mut query_buf = vec![0u8; length];
        stream.read_exact(&mut query_buf).await?;

        let start = Instant::now();
        stats.total_queries.fetch_add(1, Ordering::Relaxed);

        let parsed = match parse_dns_message(&query_buf) {
            Ok(m) => m,
            Err(_) => break,
        };

        let qname = parsed
            .questions
            .get(0)
            .map(|q| q.qname.as_str())
            .unwrap_or("");
        let qtype = parsed
            .questions
            .get(0)
            .map(|q| q.qtype.to_string())
            .unwrap_or_else(|| "UNKNOWN".into());

        if let Some(ref f) = filter {
            if !f.is_match(qname) {
                // Forward directly
                let mut up_stream = TcpStream::connect(upstream_addr).await?;
                up_stream.write_all(&len_buf).await?;
                up_stream.write_all(&query_buf).await?;
                let mut up_len = [0u8; 2];
                up_stream.read_exact(&mut up_len).await?;
                let resp_len = u16::from_be_bytes(up_len) as usize;
                let mut resp_data = vec![0u8; resp_len];
                up_stream.read_exact(&mut resp_data).await?;
                stream.write_all(&up_len).await?;
                stream.write_all(&resp_data).await?;
                continue;
            }
        }

        let (chaos_action, effect) = evaluate_chaos(qname, &chaos);

        if chaos.delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(chaos.delay_ms)).await;
        }

        let resp_data = match effect {
            Some(ChaosEffect::Drop) => {
                stats.total_dropped.fetch_add(1, Ordering::Relaxed);
                break;
            }
            Some(ChaosEffect::ServFail) => {
                stats.total_servfail.fetch_add(1, Ordering::Relaxed);
                create_servfail_response(&query_buf)?
            }
            Some(ChaosEffect::NxDomain) => {
                stats.total_nxdomain.fetch_add(1, Ordering::Relaxed);
                create_nxdomain_response(&query_buf)?
            }
            Some(ChaosEffect::SpoofA(ip)) => {
                stats.total_spoofed.fetch_add(1, Ordering::Relaxed);
                create_spoofed_a_response(&query_buf, ip)?
            }
            None => {
                let mut up_stream = TcpStream::connect(upstream_addr).await?;
                up_stream.write_all(&len_buf).await?;
                up_stream.write_all(&query_buf).await?;
                let mut up_len = [0u8; 2];
                up_stream.read_exact(&mut up_len).await?;
                let resp_len = u16::from_be_bytes(up_len) as usize;
                let mut d = vec![0u8; resp_len];
                up_stream.read_exact(&mut d).await?;
                d
            }
        };

        let out_len = (resp_data.len() as u16).to_be_bytes();
        stream.write_all(&out_len).await?;
        stream.write_all(&resp_data).await?;
        stats.total_responses.fetch_add(1, Ordering::Relaxed);

        let parsed_resp = parse_dns_message(&resp_data).ok();
        let rcode = parsed_resp.as_ref().map(|r| r.rcode.to_string());
        let answers = parsed_resp
            .map(|r| r.answers.into_iter().map(|a| a.data).collect())
            .unwrap_or_default();

        let event = DnsEvent {
            timestamp: Utc::now().to_rfc3339(),
            transport: "TCP".into(),
            client: client_addr.to_string(),
            id: parsed.id,
            qname: qname.to_string(),
            qtype,
            rcode,
            latency_ms: Some(start.elapsed().as_secs_f64() * 1000.0),
            answers,
            chaos_action,
        };

        println!("{}", event.format(format));
    }

    Ok(())
}
