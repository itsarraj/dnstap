use anyhow::{Context, Result};
use clap::Parser;
use colored::*;
use regex::Regex;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};

use dnstap::{
    handle_tcp_client, handle_udp_packet, ChaosConfig, OutputFormat, ProxyStats,
};

#[derive(Parser, Debug)]
#[command(
    name = "dnstap",
    about = "Zero-daemon DNS wire protocol tap and chaos proxy (UDP & TCP) with real-time inspection, fault injection, and NDJSON streaming",
    version
)]
pub struct Cli {
    /// Local address to bind and listen on (UDP & TCP)
    #[arg(short = 'l', long, default_value = "127.0.0.1:5353")]
    pub listen: String,

    /// Upstream DNS resolver address to proxy queries to
    #[arg(short = 'u', long, default_value = "1.1.1.1:53")]
    pub upstream: String,

    /// Output format: pretty, json, raw
    #[arg(short = 'f', long, default_value = "pretty")]
    pub format: OutputFormat,

    /// Only tap and inspect domains matching regex filter
    #[arg(long)]
    pub filter: Option<String>,

    /// Artificial latency added to responses in milliseconds
    #[arg(long, default_value_t = 0)]
    pub delay_ms: u64,

    /// Maximum random jitter added to delay in milliseconds
    #[arg(long, default_value_t = 0)]
    pub jitter_ms: u64,

    /// Probability of dropping query or response (0.0 to 1.0)
    #[arg(long, default_value_t = 0.0)]
    pub drop_rate: f64,

    /// Domains to return SERVFAIL for (comma-separated regex list, e.g. ".*internal.*,.*broken.*")
    #[arg(long)]
    pub servfail: Option<String>,

    /// Domains to return NXDOMAIN for (comma-separated regex list, e.g. ".*legacy.*")
    #[arg(long)]
    pub nxdomain: Option<String>,

    /// Spoof A records for specific domains (format: domain=ip, e.g. api.local=127.0.0.1)
    #[arg(long, value_name = "DOMAIN=IP")]
    pub r#override: Vec<String>,

    /// Set Truncated bit (TC=1) on UDP responses to test client TCP fallback
    #[arg(long)]
    pub force_tc: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let listen_addr: SocketAddr = cli
        .listen
        .parse()
        .context("Invalid local listen address format")?;
    let upstream_addr: SocketAddr = cli
        .upstream
        .parse()
        .context("Invalid upstream DNS address format")?;

    let filter_regex = if let Some(ref pat) = cli.filter {
        Some(Arc::new(Regex::new(pat).context("Invalid filter regex")?))
    } else {
        None
    };

    let mut servfail_patterns = Vec::new();
    if let Some(ref s) = cli.servfail {
        for pat in s.split(',') {
            let pat_trim = pat.trim();
            if !pat_trim.is_empty() {
                servfail_patterns.push(Regex::new(pat_trim).context("Invalid servfail pattern")?);
            }
        }
    }

    let mut nxdomain_patterns = Vec::new();
    if let Some(ref s) = cli.nxdomain {
        for pat in s.split(',') {
            let pat_trim = pat.trim();
            if !pat_trim.is_empty() {
                nxdomain_patterns.push(Regex::new(pat_trim).context("Invalid nxdomain pattern")?);
            }
        }
    }

    let mut overrides = HashMap::new();
    for entry in &cli.r#override {
        if let Some((dom, ip_str)) = entry.split_once('=') {
            let ip: Ipv4Addr = ip_str.trim().parse().with_context(|| {
                format!("Invalid IPv4 in override: {}", ip_str)
            })?;
            overrides.insert(dom.trim().to_string(), ip);
        }
    }

    let chaos = Arc::new(ChaosConfig {
        delay_ms: cli.delay_ms,
        jitter_ms: cli.jitter_ms,
        drop_rate: cli.drop_rate,
        servfail_patterns,
        nxdomain_patterns,
        overrides,
        force_tc: cli.force_tc,
    });

    let stats = Arc::new(ProxyStats::new());

    // Bind UDP
    let udp_socket = Arc::new(
        UdpSocket::bind(listen_addr)
            .await
            .with_context(|| format!("Failed to bind UDP socket on {}", listen_addr))?,
    );

    // Bind TCP
    let tcp_listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("Failed to bind TCP listener on {}", listen_addr))?;

    if cli.format == OutputFormat::Pretty {
        eprintln!(
            "{} dnstap DNS tap & chaos proxy listening on {} -> upstream {}",
            "✓".bold().green(),
            listen_addr.to_string().cyan(),
            upstream_addr.to_string().yellow()
        );
        if chaos.delay_ms > 0 {
            eprintln!(
                "  * Latency: +{}ms (jitter: {}ms)",
                chaos.delay_ms, chaos.jitter_ms
            );
        }
        if chaos.drop_rate > 0.0 {
            eprintln!("  * Drop rate: {:.1}%", chaos.drop_rate * 100.0);
        }
        if !chaos.servfail_patterns.is_empty() {
            eprintln!("  * SERVFAIL patterns: {}", chaos.servfail_patterns.len());
        }
        if !chaos.nxdomain_patterns.is_empty() {
            eprintln!("  * NXDOMAIN patterns: {}", chaos.nxdomain_patterns.len());
        }
        if !chaos.overrides.is_empty() {
            eprintln!("  * Overrides: {} domains", chaos.overrides.len());
        }
        if chaos.force_tc {
            eprintln!("  * Force TC=1 on UDP responses (testing TCP fallback)");
        }
    }

    // Spawn UDP proxy loop
    let udp_sock_clone = Arc::clone(&udp_socket);
    let chaos_udp = Arc::clone(&chaos);
    let filter_udp = filter_regex.clone();
    let stats_udp = Arc::clone(&stats);
    let format = cli.format;

    let udp_handle = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            match udp_sock_clone.recv_from(&mut buf).await {
                Ok((n, client_addr)) => {
                    let packet = buf[..n].to_vec();
                    let sock = Arc::clone(&udp_sock_clone);
                    let chaos_c = Arc::clone(&chaos_udp);
                    let filt_c = filter_udp.clone();
                    let stats_c = Arc::clone(&stats_udp);

                    tokio::spawn(async move {
                        if let Err(e) = handle_udp_packet(
                            &sock,
                            upstream_addr,
                            client_addr,
                            &packet,
                            &chaos_c,
                            filt_c.as_deref(),
                            format,
                            &stats_c,
                        )
                        .await
                        {
                            eprintln!("{} UDP processing error: {}", "warn:".bold().yellow(), e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("{} UDP recv error: {}", "error:".bold().red(), e);
                    break;
                }
            }
        }
    });

    // Spawn TCP proxy loop
    let chaos_tcp = Arc::clone(&chaos);
    let filter_tcp = filter_regex.clone();
    let stats_tcp = Arc::clone(&stats);

    let tcp_handle = tokio::spawn(async move {
        loop {
            match tcp_listener.accept().await {
                Ok((stream, client_addr)) => {
                    let chaos_c = Arc::clone(&chaos_tcp);
                    let filt_c = filter_tcp.clone();
                    let stats_c = Arc::clone(&stats_tcp);

                    tokio::spawn(async move {
                        let _ = handle_tcp_client(
                            stream,
                            client_addr,
                            upstream_addr,
                            chaos_c,
                            filt_c,
                            format,
                            stats_c,
                        )
                        .await;
                    });
                }
                Err(e) => {
                    eprintln!("{} TCP accept error: {}", "error:".bold().red(), e);
                    break;
                }
            }
        }
    });

    // Graceful shutdown on Ctrl-C
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
    }

    udp_handle.abort();
    tcp_handle.abort();

    if cli.format == OutputFormat::Pretty {
        eprintln!("\n{}", "--- dnstap Proxy Session Statistics ---".bold());
        eprintln!("Total Queries Received: {}", stats.total_queries.load(Ordering::Relaxed));
        eprintln!("Total Responses Sent:   {}", stats.total_responses.load(Ordering::Relaxed));
        eprintln!("SERVFAIL Injected:      {}", stats.total_servfail.load(Ordering::Relaxed));
        eprintln!("NXDOMAIN Injected:      {}", stats.total_nxdomain.load(Ordering::Relaxed));
        eprintln!("Spoofed A Records:      {}", stats.total_spoofed.load(Ordering::Relaxed));
        eprintln!("Queries Dropped:        {}", stats.total_dropped.load(Ordering::Relaxed));
    }

    Ok(())
}
