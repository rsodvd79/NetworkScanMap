//! Explicit, bounded inventory queries. No authentication, redirects or advertised targets.

use crate::model::now;
use hickory_resolver::{
    Resolver,
    config::ResolverConfig,
    proto::{
        op::{Message, MessageType, OpCode, Query, ResponseCode},
        rr::{DNSClass, Name, RData, RecordType},
    },
};
use native_tls::{HandshakeError, TlsConnector, TlsStream};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket},
    sync::atomic::{AtomicBool, AtomicU16, Ordering},
    time::{Duration, Instant},
};
use x509_parser::prelude::*;

static DNS_ID: AtomicU16 = AtomicU16::new(1);
const MAX_TEXT: usize = 512;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Report {
    pub observed_at: u64,
    pub dns_name: Option<String>,
    pub mdns_name: Option<String>,
    pub services: Vec<Service>,
    pub warnings: Vec<String>,
    pub cancelled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Service {
    pub port: u16,
    pub state: String,
    pub hint: String,
    pub banner: Option<String>,
    pub http_status: Option<String>,
    pub http_server: Option<String>,
    pub certificate: Option<Certificate>,
    pub note: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Certificate {
    pub subject: String,
    pub issuer: String,
    pub dns_names: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub not_before_unix: i64,
    pub not_after_unix: i64,
}

impl Certificate {
    pub fn summary(&self) -> String {
        let current = now() as i64;
        let validity = if current < self.not_before_unix {
            "non ancora valido"
        } else if current > self.not_after_unix {
            "SCADUTO"
        } else {
            "entro le date di validita"
        };
        format!(
            "TLS: {}\nEmittente: {}\nNomi SAN: {}\nValidita: {} -> {} ({validity})\nCertificato osservato, identita e catena NON verificate",
            self.subject,
            self.issuer,
            self.dns_names.join(", "),
            self.not_before,
            self.not_after,
        )
    }
}

impl Report {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.services.len() <= 16 && self.warnings.len() <= 16,
            "Inventario rete troppo grande"
        );
        let valid =
            |text: &str| text.chars().count() <= MAX_TEXT && !text.chars().any(char::is_control);
        anyhow::ensure!(
            self.dns_name
                .iter()
                .chain(&self.mdns_name)
                .all(|name| valid(name)),
            "Nome rete non valido"
        );
        anyhow::ensure!(
            self.warnings.iter().all(|warning| valid(warning)),
            "Avviso inventario non valido"
        );
        for service in &self.services {
            anyhow::ensure!(
                service.port > 0
                    && valid(&service.state)
                    && valid(&service.hint)
                    && valid(&service.note)
                    && service
                        .banner
                        .iter()
                        .chain(&service.http_status)
                        .chain(&service.http_server)
                        .all(|value| valid(value)),
                "Servizio rete non valido"
            );
            if let Some(cert) = &service.certificate {
                anyhow::ensure!(
                    cert.dns_names.len() <= 32
                        && cert.dns_names.iter().all(|name| valid(name))
                        && valid(&cert.subject)
                        && valid(&cert.issuer)
                        && valid(&cert.not_before)
                        && valid(&cert.not_after),
                    "Certificato salvato non valido"
                );
            }
        }
        Ok(())
    }

    pub fn summary(&self) -> String {
        if self.observed_at == 0 {
            return "Inventario rete: non ancora raccolto".into();
        }
        let mut lines = vec![
            format!(
                "Inventario rete: Unix {}{}",
                self.observed_at,
                if self.cancelled {
                    " (parziale / annullato)"
                } else {
                    ""
                }
            ),
            format!(
                "DNS inverso: {}",
                self.dns_name.as_deref().unwrap_or("non disponibile")
            ),
            format!(
                "mDNS: {}",
                self.mdns_name.as_deref().unwrap_or("non disponibile")
            ),
        ];
        for service in &self.services {
            lines.push(format!(
                "TCP {}: {} - {} (indizio da porta)",
                service.port, service.state, service.hint
            ));
            for value in [&service.banner, &service.http_status, &service.http_server]
                .into_iter()
                .flatten()
            {
                lines.push(value.clone());
            }
            if let Some(cert) = &service.certificate {
                lines.push(cert.summary());
            }
            if !service.note.is_empty() {
                lines.push(service.note.clone());
            }
        }
        lines.extend(self.warnings.iter().cloned());
        lines.join("\n")
    }
}

fn clean(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_TEXT)
        .collect()
}

fn reverse_name(ip: Ipv4Addr) -> Name {
    let [a, b, c, d] = ip.octets();
    // Every formatted label is a decimal octet; Name::from is infallible for this input.
    Name::from_labels([
        d.to_string(),
        c.to_string(),
        b.to_string(),
        a.to_string(),
        "in-addr".into(),
        "arpa".into(),
    ])
    .unwrap_or_default()
}

fn reverse_dns(ip: Ipv4Addr, timeout: Duration) -> Option<String> {
    let (config, mut options) = hickory_resolver::system_conf::read_system_conf().ok()?;
    let servers: Vec<_> = config.name_servers().iter().take(2).cloned().collect();
    let config = ResolverConfig::from_parts(None, vec![], servers);
    if config.name_servers().is_empty() {
        return None;
    }
    options.timeout = timeout;
    options.attempts = 1;
    options.num_concurrent_reqs = 2;
    options.try_tcp_on_error = false;
    let resolver = Resolver::new(config, options).ok()?;
    resolver
        .reverse_lookup(IpAddr::V4(ip))
        .ok()?
        .iter()
        .next()
        .map(|name| clean(name.to_utf8().trim_end_matches('.')))
}

fn mdns_answer(packet: &[u8], id: u16, query: &Name) -> Option<String> {
    let message = Message::from_vec(packet).ok()?;
    if message.id() != id
        || message.message_type() != MessageType::Response
        || message.op_code() != OpCode::Query
        || message.response_code() != ResponseCode::NoError
        || message.truncated()
    {
        return None;
    }
    message.answers().iter().find_map(|record| {
        if record.name() != query || record.dns_class() != DNSClass::IN {
            return None;
        }
        match record.data()? {
            RData::PTR(name) => Some(clean(name.to_utf8().trim_end_matches('.'))),
            _ => None,
        }
    })
}

fn mdns(ip: Ipv4Addr, timeout: Duration, cancel: &AtomicBool) -> Option<String> {
    // Legacy unicast mDNS asks only this authorized host, never enumerates the multicast LAN.
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect((ip, 5353)).ok()?;
    let id = DNS_ID.fetch_add(1, Ordering::Relaxed);
    let query = reverse_name(ip);
    let mut request = Message::new();
    request
        .set_id(id)
        .add_query(Query::query(query.clone(), RecordType::PTR));
    socket.send(&request.to_vec().ok()?).ok()?;
    let deadline = Instant::now() + timeout;
    let mut buffer = [0u8; 4096];
    while !cancel.load(Ordering::Relaxed) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        socket
            .set_read_timeout(Some(remaining.min(Duration::from_millis(100))))
            .ok()?;
        match socket.recv(&mut buffer) {
            Ok(length) => {
                if let Some(name) = mdns_answer(&buffer[..length], id, &query) {
                    return Some(name);
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => break,
        }
    }
    None
}

fn certificate(der: &[u8]) -> Option<Certificate> {
    if der.len() > 65536 {
        return None;
    }
    let (remaining, cert) = parse_x509_certificate(der).ok()?;
    if !remaining.is_empty() {
        return None;
    }
    let dns_names = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|name| {
                    if let GeneralName::DNSName(name) = name {
                        Some(clean(name))
                    } else {
                        None
                    }
                })
                .take(32)
                .collect()
        })
        .unwrap_or_default();
    Some(Certificate {
        subject: clean(&cert.subject().to_string()),
        issuer: clean(&cert.issuer().to_string()),
        dns_names,
        not_before: cert.validity().not_before.to_string(),
        not_after: cert.validity().not_after.to_string(),
        not_before_unix: cert.validity().not_before.timestamp(),
        not_after_unix: cert.validity().not_after.timestamp(),
    })
}

fn tls(
    stream: TcpStream,
    host: &str,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Option<TlsStream<TcpStream>> {
    stream.set_nonblocking(true).ok()?;
    // Inventory only: capture self-signed/expired certificates without sending credentials.
    // These flags never establish trust; the UI explicitly labels every observation unverified.
    let connector = TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .build()
        .ok()?;
    let mut result = connector.connect(host, stream);
    loop {
        match result {
            Ok(stream) => return Some(stream),
            Err(HandshakeError::Failure(_)) => return None,
            Err(HandshakeError::WouldBlock(handshake)) => {
                if Instant::now() >= deadline || cancel.load(Ordering::Relaxed) {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(5));
                result = handshake.handshake();
            }
        }
    }
}

fn http(
    stream: &mut (impl Read + Write),
    host: &str,
    deadline: Instant,
    cancel: &AtomicBool,
) -> (Option<String>, Option<String>) {
    let request = format!("HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    let mut written = 0;
    while written < request.len() && Instant::now() < deadline && !cancel.load(Ordering::Relaxed) {
        match stream.write(&request.as_bytes()[written..]) {
            Ok(0) => return (None, None),
            Ok(length) => written += length,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5))
            }
            Err(_) => return (None, None),
        }
    }
    if written != request.len() {
        return (None, None);
    }
    let mut buffer = [0u8; 4096];
    let mut length = 0;
    while length < buffer.len() && Instant::now() < deadline && !cancel.load(Ordering::Relaxed) {
        match stream.read(&mut buffer[length..]) {
            Ok(0) => break,
            Ok(count) => {
                length += count;
                if buffer[..length]
                    .windows(4)
                    .any(|bytes| bytes == b"\r\n\r\n")
                {
                    break;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5))
            }
            Err(_) => break,
        }
    }
    http_headers(&buffer[..length])
}

fn http_headers(bytes: &[u8]) -> (Option<String>, Option<String>) {
    let text = String::from_utf8_lossy(bytes);
    let mut lines = text.split("\r\n");
    let first = lines.next().unwrap_or_default();
    if !first.starts_with("HTTP/1.") && !first.starts_with("HTTP/2 ") {
        return (None, None);
    }
    let status = Some(clean(first));
    let server = lines.take_while(|line| !line.is_empty()).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case("server")
            .then(|| format!("Server HTTP: {}", clean(value.trim())))
    });
    (status, server)
}

fn service_hint(port: u16) -> &'static str {
    match port {
        22 => "SSH",
        80 | 8000 | 8080 | 8888 => "HTTP",
        443 | 8443 | 9443 => "HTTPS",
        25 | 587 => "SMTP",
        53 => "DNS",
        139 | 445 => "SMB",
        631 => "IPP",
        3389 => "RDP",
        9100 => "Stampa",
        465 | 636 | 853 | 990 | 993 | 995 => "TLS",
        _ => "Servizio non identificato",
    }
}

fn inspect_service(
    ip: Ipv4Addr,
    port: u16,
    host: &str,
    timeout: Duration,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Service {
    let mut result = Service {
        port,
        state: "non verificata".into(),
        hint: service_hint(port).into(),
        banner: None,
        http_status: None,
        http_server: None,
        certificate: None,
        note: String::new(),
    };
    let stream = match TcpStream::connect_timeout(&SocketAddr::from((ip, port)), timeout) {
        Ok(stream) => stream,
        Err(error) => {
            result.state = match error.kind() {
                std::io::ErrorKind::ConnectionRefused => "chiusa (rifiutata)",
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => "nessuna risposta",
                _ => "errore / non disponibile",
            }
            .into();
            return result;
        }
    };
    result.state = "aperta".into();
    let budget = timeout.min(deadline.saturating_duration_since(Instant::now()));
    if budget.is_zero() || cancel.load(Ordering::Relaxed) {
        return result;
    }
    let _ = stream.set_read_timeout(Some(budget));
    let _ = stream.set_write_timeout(Some(budget));
    if matches!(port, 443 | 8443 | 9443 | 465 | 636 | 853 | 990 | 993 | 995) {
        if let Some(mut secure) = tls(stream, host, deadline.min(Instant::now() + budget), cancel) {
            result.certificate = secure
                .peer_certificate()
                .ok()
                .flatten()
                .and_then(|cert| cert.to_der().ok())
                .and_then(|der| certificate(&der));
            if matches!(port, 443 | 8443 | 9443) && !cancel.load(Ordering::Relaxed) {
                (result.http_status, result.http_server) = http(
                    &mut secure,
                    host,
                    deadline.min(Instant::now() + budget),
                    cancel,
                );
            }
        } else {
            result.note =
                "Handshake TLS non riuscito / incompleto; nessuna verifica di fiducia".into();
        }
    } else if matches!(port, 80 | 8000 | 8080 | 8888) {
        let mut stream = stream;
        if stream.set_nonblocking(true).is_ok() {
            (result.http_status, result.http_server) = http(
                &mut stream,
                host,
                deadline.min(Instant::now() + budget),
                cancel,
            );
        }
    } else if port == 22 {
        let mut stream = stream;
        let mut buffer = [0u8; 512];
        if let Ok(length) = stream.read(&mut buffer) {
            let line = String::from_utf8_lossy(&buffer[..length]);
            if let Some(line) = line.lines().find(|line| line.starts_with("SSH-")) {
                result.banner = Some(clean(line));
            }
        }
    }
    result
}

pub fn collect(ip: Ipv4Addr, ports: &[u16], timeout: Duration, cancel: &AtomicBool) -> Report {
    let mut result = Report {
        observed_at: now(),
        ..Default::default()
    };
    if ip.octets()[0] == 0 || ip.octets()[0] >= 224 || timeout.is_zero() {
        result
            .warnings
            .push("Destinazione IPv4 o timeout non valido".into());
        return result;
    }
    let timeout = timeout.min(Duration::from_secs(1));
    let deadline = Instant::now() + Duration::from_secs(10);
    if !cancel.load(Ordering::Relaxed) {
        result.dns_name = reverse_dns(ip, timeout.min(Duration::from_millis(500)));
    }
    if !cancel.load(Ordering::Relaxed) {
        result.mdns_name = mdns(ip, timeout.min(Duration::from_millis(500)), cancel);
    }
    let host = result
        .dns_name
        .as_deref()
        .or(result.mdns_name.as_deref())
        .map(str::to_owned)
        .unwrap_or_else(|| ip.to_string());
    let mut ports = ports
        .iter()
        .copied()
        .filter(|port| *port != 0)
        .take(16)
        .collect::<Vec<_>>();
    ports.sort_unstable();
    ports.dedup();
    for port in ports {
        let budget = timeout.min(deadline.saturating_duration_since(Instant::now()));
        if budget.is_zero() || cancel.load(Ordering::Relaxed) {
            break;
        }
        result
            .services
            .push(inspect_service(ip, port, &host, budget, deadline, cancel));
    }
    result.cancelled = cancel.load(Ordering::Relaxed);
    if Instant::now() >= deadline {
        result
            .warnings
            .push("Budget inventario di 10 secondi esaurito; risultati parziali".into());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::rr::{Record, rdata::PTR};

    #[test]
    fn mdns_accepts_only_matching_reverse_ptr_and_rejects_malformed_packets() {
        let name = reverse_name(Ipv4Addr::LOCALHOST);
        let mut reply = Message::new();
        reply
            .set_id(17)
            .set_message_type(MessageType::Response)
            .add_answer(Record::from_rdata(
                name.clone(),
                120,
                RData::PTR(PTR(Name::from_ascii("printer.local.").unwrap())),
            ));
        let bytes = reply.to_vec().unwrap();
        assert_eq!(
            mdns_answer(&bytes, 17, &name).as_deref(),
            Some("printer.local")
        );
        assert!(mdns_answer(&bytes, 18, &name).is_none());
        assert!(mdns_answer(&bytes, 17, &reverse_name(Ipv4Addr::new(127, 0, 0, 2))).is_none());
        assert!(mdns_answer(&bytes[..bytes.len() - 1], 17, &name).is_none());
    }

    #[test]
    fn service_inspection_reports_real_open_and_unresponsive_ports_and_cancellation() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let result = inspect_service(
            Ipv4Addr::LOCALHOST,
            port,
            "localhost",
            Duration::from_millis(100),
            Instant::now() + Duration::from_secs(1),
            &AtomicBool::new(false),
        );
        assert_eq!(result.state, "aperta");
        drop(listener);
        let result = inspect_service(
            Ipv4Addr::LOCALHOST,
            port,
            "localhost",
            Duration::from_millis(100),
            Instant::now() + Duration::from_secs(1),
            &AtomicBool::new(false),
        );
        assert!(matches!(
            result.state.as_str(),
            "chiusa (rifiutata)" | "nessuna risposta"
        ));
        let report = collect(
            Ipv4Addr::LOCALHOST,
            &[port],
            Duration::from_secs(1),
            &AtomicBool::new(true),
        );
        assert!(report.cancelled && report.services.is_empty() && report.dns_name.is_none());
    }

    #[test]
    fn http_inventory_keeps_status_and_server_but_not_cookies_or_response_body() {
        let (status, server) = http_headers(
            b"HTTP/1.1 302 Found\r\nServer: example\r\nSet-Cookie: secret\r\n\r\nsecret body",
        );
        assert_eq!(status.as_deref(), Some("HTTP/1.1 302 Found"));
        assert_eq!(server.as_deref(), Some("Server HTTP: example"));
        assert_eq!(http_headers(b"not HTTP"), (None, None));
    }

    #[test]
    fn loopback_tls_collects_self_signed_certificate_without_claiming_trust() {
        // Public test-only identity, not a production credential.
        let identity = native_tls::Identity::from_pkcs12(
            include_bytes!("../tests/fixtures/inventory-test.p12"),
            "test-only",
        )
        .unwrap();
        let acceptor = native_tls::TlsAcceptor::new(identity).unwrap();
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut socket = acceptor.accept(socket).unwrap();
            let mut buffer = [0u8; 1024];
            let length = socket.read(&mut buffer).unwrap();
            assert!(buffer[..length].starts_with(b"HEAD / HTTP/1.0"));
            socket
                .write_all(b"HTTP/1.0 200 OK\r\nServer: loopback-test\r\n\r\n")
                .unwrap();
        });
        let socket = TcpStream::connect_timeout(&address, Duration::from_secs(1)).unwrap();
        let mut secure = tls(
            socket,
            "localhost",
            Instant::now() + Duration::from_secs(3),
            &AtomicBool::new(false),
        )
        .unwrap();
        let der = secure
            .peer_certificate()
            .unwrap()
            .unwrap()
            .to_der()
            .unwrap();
        let cert = certificate(&der).unwrap();
        assert!(cert.subject.contains("localhost") && cert.issuer.contains("localhost"));
        assert!(cert.dns_names.contains(&"test.local".into()));
        assert!(cert.summary().contains("NON verificate"));
        let report = Report {
            observed_at: 123,
            services: vec![Service {
                port: 443,
                state: "aperta".into(),
                hint: "HTTPS".into(),
                banner: None,
                http_status: None,
                http_server: None,
                certificate: Some(cert.clone()),
                note: String::new(),
            }],
            ..Default::default()
        };
        let restored: Report =
            serde_json::from_slice(&serde_json::to_vec(&report).unwrap()).unwrap();
        restored.validate().unwrap();
        assert_eq!(restored.summary(), report.summary());
        let mut expired = cert.clone();
        expired.not_after_unix = 0;
        assert!(expired.summary().contains("SCADUTO"));
        let mut malformed = der;
        malformed.push(0);
        assert!(certificate(&malformed).is_none());
        assert_eq!(
            http(
                &mut secure,
                "localhost",
                Instant::now() + Duration::from_secs(3),
                &AtomicBool::new(false)
            )
            .0
            .as_deref(),
            Some("HTTP/1.0 200 OK")
        );
        server.join().unwrap();
    }

    #[test]
    fn stalled_tls_peer_cannot_extend_handshake_deadline() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (_socket, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_millis(150));
        });
        let socket = TcpStream::connect_timeout(&address, Duration::from_secs(1)).unwrap();
        let started = Instant::now();
        assert!(
            tls(
                socket,
                "localhost",
                started + Duration::from_millis(50),
                &AtomicBool::new(false)
            )
            .is_none()
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        server.join().unwrap();
    }
}
