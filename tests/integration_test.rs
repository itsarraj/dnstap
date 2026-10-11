use dnstap::wire::{
    create_spoofed_a_response, encode_domain_name, parse_dns_message, Rcode, RecordType,
};
use dnstap::{handle_tcp_client, handle_udp_packet, ChaosConfig, OutputFormat, ProxyStats};
use regex::Regex;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

fn build_query(id: u16, domain: &str, qtype: u16) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    p.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend(encode_domain_name(domain));
    p.extend_from_slice(&qtype.to_be_bytes());
    p.extend_from_slice(&1u16.to_be_bytes()); // IN
    p
}

#[tokio::test]
async fn test_udp_proxy_passthrough() {
    // 1. Mock upstream DNS server
    let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream.local_addr().unwrap();

    let up_task = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        let (n, peer) = upstream.recv_from(&mut buf).await.unwrap();
        let resp = create_spoofed_a_response(&buf[..n], Ipv4Addr::new(93, 184, 216, 34)).unwrap();
        upstream.send_to(&resp, peer).await.unwrap();
    });

    // 2. Proxy socket
    let proxy_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let proxy_addr = proxy_sock.local_addr().unwrap();

    let chaos = ChaosConfig::default();
    let stats = Arc::new(ProxyStats::new());

    let sock_c = Arc::clone(&proxy_sock);
    let stats_c = Arc::clone(&stats);
    let proxy_task = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        let (n, client) = sock_c.recv_from(&mut buf).await.unwrap();
        handle_udp_packet(
            &sock_c,
            upstream_addr,
            client,
            &buf[..n],
            &chaos,
            None,
            OutputFormat::Json,
            &stats_c,
        )
        .await
        .unwrap();
    });

    // 3. Client query
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = build_query(0x1111, "example.com", 1);
    client.send_to(&query, proxy_addr).await.unwrap();

    let mut resp_buf = [0u8; 1024];
    let (n, _) = client.recv_from(&mut resp_buf).await.unwrap();
    let parsed = parse_dns_message(&resp_buf[..n]).unwrap();

    assert_eq!(parsed.id, 0x1111);
    assert_eq!(parsed.rcode, Rcode::NoError);
    assert_eq!(parsed.answers.len(), 1);
    assert_eq!(parsed.answers[0].data, "93.184.216.34");

    up_task.await.unwrap();
    proxy_task.await.unwrap();
}

#[tokio::test]
async fn test_chaos_spoof_override() {
    let proxy_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let proxy_addr = proxy_sock.local_addr().unwrap();

    let mut chaos = ChaosConfig::default();
    chaos
        .overrides
        .insert("api.local".to_string(), Ipv4Addr::new(127, 0, 0, 1));
    let stats = Arc::new(ProxyStats::new());

    let sock_c = Arc::clone(&proxy_sock);
    let stats_c = Arc::clone(&stats);
    let proxy_task = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        let (n, client) = sock_c.recv_from(&mut buf).await.unwrap();
        let dummy_upstream: SocketAddr = "127.0.0.1:9".parse().unwrap();
        handle_udp_packet(
            &sock_c,
            dummy_upstream,
            client,
            &buf[..n],
            &chaos,
            None,
            OutputFormat::Raw,
            &stats_c,
        )
        .await
        .unwrap();
    });

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = build_query(0x2222, "api.local", 1);
    client.send_to(&query, proxy_addr).await.unwrap();

    let mut resp_buf = [0u8; 1024];
    let (n, _) = client.recv_from(&mut resp_buf).await.unwrap();
    let parsed = parse_dns_message(&resp_buf[..n]).unwrap();

    assert_eq!(parsed.id, 0x2222);
    assert_eq!(parsed.rcode, Rcode::NoError);
    assert_eq!(parsed.answers[0].data, "127.0.0.1");

    proxy_task.await.unwrap();
}

#[tokio::test]
async fn test_chaos_servfail_injection() {
    let proxy_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let proxy_addr = proxy_sock.local_addr().unwrap();

    let mut chaos = ChaosConfig::default();
    chaos
        .servfail_patterns
        .push(Regex::new(r".*broken.*").unwrap());
    let stats = Arc::new(ProxyStats::new());

    let sock_c = Arc::clone(&proxy_sock);
    let stats_c = Arc::clone(&stats);
    let proxy_task = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        let (n, client) = sock_c.recv_from(&mut buf).await.unwrap();
        let dummy_upstream: SocketAddr = "127.0.0.1:9".parse().unwrap();
        handle_udp_packet(
            &sock_c,
            dummy_upstream,
            client,
            &buf[..n],
            &chaos,
            None,
            OutputFormat::Raw,
            &stats_c,
        )
        .await
        .unwrap();
    });

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = build_query(0x3333, "my-broken-service.internal", 1);
    client.send_to(&query, proxy_addr).await.unwrap();

    let mut resp_buf = [0u8; 1024];
    let (n, _) = client.recv_from(&mut resp_buf).await.unwrap();
    let parsed = parse_dns_message(&resp_buf[..n]).unwrap();

    assert_eq!(parsed.id, 0x3333);
    assert_eq!(parsed.rcode, Rcode::ServerFailure);

    proxy_task.await.unwrap();
}

#[tokio::test]
async fn test_chaos_nxdomain_injection() {
    let proxy_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let proxy_addr = proxy_sock.local_addr().unwrap();

    let mut chaos = ChaosConfig::default();
    chaos
        .nxdomain_patterns
        .push(Regex::new(r".*legacy.*").unwrap());
    let stats = Arc::new(ProxyStats::new());

    let sock_c = Arc::clone(&proxy_sock);
    let stats_c = Arc::clone(&stats);
    let proxy_task = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        let (n, client) = sock_c.recv_from(&mut buf).await.unwrap();
        let dummy_upstream: SocketAddr = "127.0.0.1:9".parse().unwrap();
        handle_udp_packet(
            &sock_c,
            dummy_upstream,
            client,
            &buf[..n],
            &chaos,
            None,
            OutputFormat::Raw,
            &stats_c,
        )
        .await
        .unwrap();
    });

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = build_query(0x4444, "legacy-api.company.com", 1);
    client.send_to(&query, proxy_addr).await.unwrap();

    let mut resp_buf = [0u8; 1024];
    let (n, _) = client.recv_from(&mut resp_buf).await.unwrap();
    let parsed = parse_dns_message(&resp_buf[..n]).unwrap();

    assert_eq!(parsed.id, 0x4444);
    assert_eq!(parsed.rcode, Rcode::NameError);

    proxy_task.await.unwrap();
}

#[tokio::test]
async fn test_chaos_force_tc_truncated() {
    let proxy_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let proxy_addr = proxy_sock.local_addr().unwrap();

    let mut chaos = ChaosConfig::default();
    chaos.force_tc = true;
    chaos
        .overrides
        .insert("large.domain.com".to_string(), Ipv4Addr::new(10, 0, 0, 1));
    let stats = Arc::new(ProxyStats::new());

    let sock_c = Arc::clone(&proxy_sock);
    let stats_c = Arc::clone(&stats);
    let proxy_task = tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        let (n, client) = sock_c.recv_from(&mut buf).await.unwrap();
        let dummy_upstream: SocketAddr = "127.0.0.1:9".parse().unwrap();
        handle_udp_packet(
            &sock_c,
            dummy_upstream,
            client,
            &buf[..n],
            &chaos,
            None,
            OutputFormat::Raw,
            &stats_c,
        )
        .await
        .unwrap();
    });

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = build_query(0x5555, "large.domain.com", 1);
    client.send_to(&query, proxy_addr).await.unwrap();

    let mut resp_buf = [0u8; 1024];
    let (n, _) = client.recv_from(&mut resp_buf).await.unwrap();
    let parsed = parse_dns_message(&resp_buf[..n]).unwrap();

    assert_eq!(parsed.id, 0x5555);
    assert!(parsed.truncated); // Truncated bit must be set!

    proxy_task.await.unwrap();
}

#[tokio::test]
async fn test_tcp_proxy_passthrough() {
    // 1. Mock upstream TCP server
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();

    let up_task = tokio::spawn(async move {
        let (mut stream, _) = upstream_listener.accept().await.unwrap();
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.unwrap();
        let len = u16::from_be_bytes(len_buf) as usize;
        let mut qbuf = vec![0u8; len];
        stream.read_exact(&mut qbuf).await.unwrap();

        let resp = create_spoofed_a_response(&qbuf, Ipv4Addr::new(1, 2, 3, 4)).unwrap();
        let out_len = (resp.len() as u16).to_be_bytes();
        stream.write_all(&out_len).await.unwrap();
        stream.write_all(&resp).await.unwrap();
    });

    // 2. Proxy listener
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let chaos = Arc::new(ChaosConfig::default());
    let stats = Arc::new(ProxyStats::new());

    let proxy_task = tokio::spawn(async move {
        let (stream, client_addr) = proxy_listener.accept().await.unwrap();
        handle_tcp_client(
            stream,
            client_addr,
            upstream_addr,
            chaos,
            None,
            OutputFormat::Json,
            stats,
        )
        .await
        .unwrap();
    });

    // 3. Client TCP query
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let query = build_query(0x6666, "tcp.example.com", 1);
    let qlen = (query.len() as u16).to_be_bytes();
    client.write_all(&qlen).await.unwrap();
    client.write_all(&query).await.unwrap();

    let mut rlen_buf = [0u8; 2];
    client.read_exact(&mut rlen_buf).await.unwrap();
    let rlen = u16::from_be_bytes(rlen_buf) as usize;
    let mut resp_data = vec![0u8; rlen];
    client.read_exact(&mut resp_data).await.unwrap();

    let parsed = parse_dns_message(&resp_data).unwrap();
    assert_eq!(parsed.id, 0x6666);
    assert_eq!(parsed.rcode, Rcode::NoError);
    assert_eq!(parsed.answers[0].data, "1.2.3.4");

    up_task.await.unwrap();
    proxy_task.await.unwrap();
}
