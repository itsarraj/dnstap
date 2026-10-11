use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RecordType {
    A,
    NS,
    CNAME,
    SOA,
    PTR,
    MX,
    TXT,
    AAAA,
    SRV,
    ANY,
    Other(u16),
}

impl RecordType {
    pub fn from_u16(val: u16) -> Self {
        match val {
            1 => RecordType::A,
            2 => RecordType::NS,
            5 => RecordType::CNAME,
            6 => RecordType::SOA,
            12 => RecordType::PTR,
            15 => RecordType::MX,
            16 => RecordType::TXT,
            28 => RecordType::AAAA,
            33 => RecordType::SRV,
            255 => RecordType::ANY,
            other => RecordType::Other(other),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::CNAME => 5,
            RecordType::SOA => 6,
            RecordType::PTR => 12,
            RecordType::MX => 15,
            RecordType::TXT => 16,
            RecordType::AAAA => 28,
            RecordType::SRV => 33,
            RecordType::ANY => 255,
            RecordType::Other(val) => val,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::NS => "NS",
            RecordType::CNAME => "CNAME",
            RecordType::SOA => "SOA",
            RecordType::PTR => "PTR",
            RecordType::MX => "MX",
            RecordType::TXT => "TXT",
            RecordType::AAAA => "AAAA",
            RecordType::SRV => "SRV",
            RecordType::ANY => "ANY",
            RecordType::Other(_) => "OTHER",
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Rcode {
    NoError,
    FormatError,
    ServerFailure,
    NameError, // NXDOMAIN
    NotImplemented,
    Refused,
    Other(u8),
}

impl Rcode {
    pub fn from_u8(val: u8) -> Self {
        match val & 0x0F {
            0 => Rcode::NoError,
            1 => Rcode::FormatError,
            2 => Rcode::ServerFailure,
            3 => Rcode::NameError,
            4 => Rcode::NotImplemented,
            5 => Rcode::Refused,
            other => Rcode::Other(other),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Rcode::NoError => "NOERROR",
            Rcode::FormatError => "FORMERR",
            Rcode::ServerFailure => "SERVFAIL",
            Rcode::NameError => "NXDOMAIN",
            Rcode::NotImplemented => "NOTIMP",
            Rcode::Refused => "REFUSED",
            Rcode::Other(_) => "OTHER",
        }
    }
}

impl fmt::Display for Rcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsQuestion {
    pub qname: String,
    pub qtype: RecordType,
    pub qclass: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: RecordType,
    pub ttl: u32,
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsMessage {
    pub id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub rcode: Rcode,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
}

pub fn encode_domain_name(domain: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let trimmed = domain.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        out.push(0);
        return out;
    }

    for label in trimmed.split('.') {
        let bytes = label.as_bytes();
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0);
    out
}

pub fn read_name(buf: &[u8], offset: &mut usize, depth: usize) -> Result<String> {
    if depth > 10 {
        bail!("Too many compression pointers in DNS packet");
    }

    let mut labels = Vec::new();
    let mut jumped = false;
    let mut jump_offset = 0;

    while *offset < buf.len() {
        let len = buf[*offset];
        if len == 0 {
            *offset += 1;
            break;
        }

        if (len & 0xC0) == 0xC0 {
            if *offset + 1 >= buf.len() {
                bail!("Truncated DNS compression pointer");
            }
            let pointer = (((len & 0x3F) as usize) << 8) | (buf[*offset + 1] as usize);
            if !jumped {
                jump_offset = *offset + 2;
                jumped = true;
            }

            let mut target_offset = pointer;
            let target_name = read_name(buf, &mut target_offset, depth + 1)?;
            labels.push(target_name);
            break;
        } else {
            *offset += 1;
            let usize_len = len as usize;
            if *offset + usize_len > buf.len() {
                bail!("Truncated DNS label");
            }
            let label_bytes = &buf[*offset..*offset + usize_len];
            let label = String::from_utf8_lossy(label_bytes).to_string();
            labels.push(label);
            *offset += usize_len;
        }
    }

    if jumped {
        *offset = jump_offset;
    }

    Ok(labels.join("."))
}

pub fn parse_dns_message(buf: &[u8]) -> Result<DnsMessage> {
    if buf.len() < 12 {
        bail!("DNS packet too short for 12-byte header");
    }

    let id = u16::from_be_bytes(buf[0..2].try_into().unwrap());
    let flags = u16::from_be_bytes(buf[2..4].try_into().unwrap());

    let is_response = (flags & 0x8000) != 0;
    let opcode = ((flags >> 11) & 0x0F) as u8;
    let authoritative = (flags & 0x0400) != 0;
    let truncated = (flags & 0x0200) != 0;
    let recursion_desired = (flags & 0x0100) != 0;
    let recursion_available = (flags & 0x0080) != 0;
    let rcode = Rcode::from_u8((flags & 0x000F) as u8);

    let qdcount = u16::from_be_bytes(buf[4..6].try_into().unwrap()) as usize;
    let ancount = u16::from_be_bytes(buf[6..8].try_into().unwrap()) as usize;

    let mut offset = 12;
    let mut questions = Vec::with_capacity(qdcount);

    for _ in 0..qdcount {
        if offset >= buf.len() {
            break;
        }
        let qname = read_name(buf, &mut offset, 0)?;
        if offset + 4 > buf.len() {
            bail!("Truncated question section");
        }
        let qtype = RecordType::from_u16(u16::from_be_bytes(buf[offset..offset + 2].try_into().unwrap()));
        let qclass = u16::from_be_bytes(buf[offset + 2..offset + 4].try_into().unwrap());
        offset += 4;
        questions.push(DnsQuestion {
            qname,
            qtype,
            qclass,
        });
    }

    let mut answers = Vec::with_capacity(ancount);
    for _ in 0..ancount {
        if offset >= buf.len() {
            break;
        }
        let name = read_name(buf, &mut offset, 0)?;
        if offset + 10 > buf.len() {
            break;
        }
        let rtype = RecordType::from_u16(u16::from_be_bytes(buf[offset..offset + 2].try_into().unwrap()));
        let ttl = u32::from_be_bytes(buf[offset + 4..offset + 8].try_into().unwrap());
        let rdlength = u16::from_be_bytes(buf[offset + 8..offset + 10].try_into().unwrap()) as usize;
        offset += 10;

        if offset + rdlength > buf.len() {
            break;
        }

        let rdata_bytes = &buf[offset..offset + rdlength];
        let data = match rtype {
            RecordType::A => {
                if rdlength == 4 {
                    Ipv4Addr::new(
                        rdata_bytes[0],
                        rdata_bytes[1],
                        rdata_bytes[2],
                        rdata_bytes[3],
                    )
                    .to_string()
                } else {
                    format!("{:?}", rdata_bytes)
                }
            }
            RecordType::AAAA => {
                if rdlength == 16 {
                    let mut b = [0u8; 16];
                    b.copy_from_slice(rdata_bytes);
                    Ipv6Addr::from(b).to_string()
                } else {
                    format!("{:?}", rdata_bytes)
                }
            }
            RecordType::CNAME | RecordType::PTR | RecordType::NS => {
                let mut roff = offset;
                read_name(buf, &mut roff, 0).unwrap_or_else(|_| "(invalid name)".to_string())
            }
            RecordType::TXT => {
                if !rdata_bytes.is_empty() {
                    let tlen = rdata_bytes[0] as usize;
                    if tlen + 1 <= rdlength {
                        String::from_utf8_lossy(&rdata_bytes[1..1 + tlen]).to_string()
                    } else {
                        String::from_utf8_lossy(rdata_bytes).to_string()
                    }
                } else {
                    "".to_string()
                }
            }
            _ => format!("({} bytes)", rdlength),
        };

        offset += rdlength;
        answers.push(DnsRecord {
            name,
            record_type: rtype,
            ttl,
            data,
        });
    }

    Ok(DnsMessage {
        id,
        is_response,
        opcode,
        authoritative,
        truncated,
        recursion_desired,
        recursion_available,
        rcode,
        questions,
        answers,
    })
}

/// Create a spoofed SERVFAIL (RCODE=2) response packet mirroring the incoming query
pub fn create_servfail_response(query_buf: &[u8]) -> Result<Vec<u8>> {
    create_error_response(query_buf, 2)
}

/// Create a spoofed NXDOMAIN (RCODE=3) response packet mirroring the incoming query
pub fn create_nxdomain_response(query_buf: &[u8]) -> Result<Vec<u8>> {
    create_error_response(query_buf, 3)
}

fn create_error_response(query_buf: &[u8], rcode: u8) -> Result<Vec<u8>> {
    if query_buf.len() < 12 {
        bail!("Query packet too short");
    }

    let mut resp = query_buf.to_vec();
    let query_flags = u16::from_be_bytes(query_buf[2..4].try_into().unwrap());
    let rd = (query_flags & 0x0100) != 0;

    // Response header: QR=1 (response), RA=1, RD copied, RCODE=rcode
    let mut flags = 0x8000 | (rcode as u16 & 0x000F);
    if rd {
        flags |= 0x0100;
    }
    flags |= 0x0080; // RA=1 (Recursion Available)

    resp[2..4].copy_from_slice(&flags.to_be_bytes());
    // ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0
    resp[6..8].copy_from_slice(&0u16.to_be_bytes());
    resp[8..10].copy_from_slice(&0u16.to_be_bytes());
    resp[10..12].copy_from_slice(&0u16.to_be_bytes());

    Ok(resp)
}

/// Create a spoofed A record response answering the query with a specific IPv4 address
pub fn create_spoofed_a_response(query_buf: &[u8], ip: Ipv4Addr) -> Result<Vec<u8>> {
    if query_buf.len() < 12 {
        bail!("Query packet too short");
    }

    let parsed = parse_dns_message(query_buf).context("Failed to parse query for spoofing")?;
    let qname = parsed
        .questions
        .get(0)
        .map(|q| q.qname.as_str())
        .unwrap_or("example.com");

    let mut packet = Vec::with_capacity(64);
    // Header
    packet.extend_from_slice(&parsed.id.to_be_bytes());
    let flags = 0x8180u16; // QR=1, RD=1, RA=1, NOERROR
    packet.extend_from_slice(&flags.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    packet.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1
    packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

    // Question
    let enc_qname = encode_domain_name(qname);
    packet.extend(&enc_qname);
    packet.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
    packet.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN

    // Answer (Pointer to Question name at offset 12)
    packet.extend_from_slice(&0xC00Cu16.to_be_bytes()); // Pointer to 12
    packet.extend_from_slice(&1u16.to_be_bytes()); // TYPE = A
    packet.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
    packet.extend_from_slice(&60u32.to_be_bytes()); // TTL = 60
    packet.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH = 4
    packet.extend_from_slice(&ip.octets());

    Ok(packet)
}

/// Set Truncated bit (TC=1) on a DNS response packet
pub fn set_truncated_flag(resp_buf: &mut [u8]) {
    if resp_buf.len() >= 4 {
        let mut flags = u16::from_be_bytes(resp_buf[2..4].try_into().unwrap());
        flags |= 0x0200; // TC bit
        resp_buf[2..4].copy_from_slice(&flags.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let domain = "api.internal.corp";
        let encoded = encode_domain_name(domain);
        let mut offset = 0;
        let decoded = read_name(&encoded, &mut offset, 0).unwrap();
        assert_eq!(decoded, domain);
    }

    #[test]
    fn test_spoofed_a_response() {
        let mut query = Vec::new();
        query.extend_from_slice(&0x1234u16.to_be_bytes()); // ID
        query.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
        query.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT=1
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend(encode_domain_name("test.local"));
        query.extend_from_slice(&1u16.to_be_bytes()); // QTYPE=A
        query.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN

        let spoofed = create_spoofed_a_response(&query, Ipv4Addr::new(127, 0, 0, 1)).unwrap();
        let parsed = parse_dns_message(&spoofed).unwrap();

        assert_eq!(parsed.id, 0x1234);
        assert!(parsed.is_response);
        assert_eq!(parsed.rcode, Rcode::NoError);
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].data, "127.0.0.1");
        assert_eq!(parsed.answers[0].record_type, RecordType::A);
    }

    #[test]
    fn test_servfail_response() {
        let mut query = Vec::new();
        query.extend_from_slice(&0x5678u16.to_be_bytes());
        query.extend_from_slice(&0x0100u16.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend(encode_domain_name("broken.local"));
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());

        let sf = create_servfail_response(&query).unwrap();
        let parsed = parse_dns_message(&sf).unwrap();
        assert_eq!(parsed.id, 0x5678);
        assert_eq!(parsed.rcode, Rcode::ServerFailure);
    }
}
