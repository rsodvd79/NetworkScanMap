//! Shared bounded helpers plus unicast NTP, SSDP/UPnP and WS-Discovery probes.
//! Targets are only the authorized IPv4; no multicast and no advertised address is contacted.

use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket},
    sync::atomic::AtomicBool,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const MAX_TEXT: usize = 512;
const MAX_FIELDS: usize = 32;
const NTP_EPOCH: f64 = 2_208_988_800.0;
static COUNTER: AtomicU64 = AtomicU64::new(1);

/// Labelled observations from one protocol, stored as plain text.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Info {
    pub protocol: String,
    pub fields: Vec<(String, String)>,
}

pub fn clean(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_TEXT)
        .collect::<String>()
        .trim()
        .to_owned()
}

impl Info {
    pub fn new(protocol: &str) -> Self {
        Self {
            protocol: protocol.into(),
            fields: Vec::new(),
        }
    }

    pub fn add(&mut self, label: &str, value: impl AsRef<str>) {
        let value = clean(value.as_ref());
        if !value.is_empty() && self.fields.len() < MAX_FIELDS {
            self.fields.push((label.into(), value));
        }
    }

    pub fn summary(&self) -> String {
        let mut lines = vec![format!("{}:", self.protocol)];
        lines.extend(
            self.fields
                .iter()
                .map(|(label, value)| format!("{label}: {value}")),
        );
        lines.join("\n")
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let valid =
            |text: &str| text.chars().count() <= MAX_TEXT && !text.chars().any(char::is_control);
        anyhow::ensure!(
            self.fields.len() <= MAX_FIELDS
                && valid(&self.protocol)
                && self
                    .fields
                    .iter()
                    .all(|(label, value)| valid(label) && valid(value)),
            "Dati protocollo non validi"
        );
        Ok(())
    }
}

pub fn udp_exchange<T>(
    target: SocketAddr,
    packet: &[u8],
    timeout: Duration,
    cancel: &AtomicBool,
    mut parse: impl FnMut(&[u8]) -> Option<T>,
) -> Option<T> {
    if timeout.is_zero() || cancel.load(Ordering::Relaxed) {
        return None;
    }
    let deadline = Instant::now() + timeout.min(Duration::from_secs(1));
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    // A connected socket only receives datagrams from the queried address.
    socket.connect(target).ok()?;
    socket.send(packet).ok()?;
    let mut buffer = [0u8; 16384];
    while !cancel.load(Ordering::Relaxed) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        socket
            .set_read_timeout(Some(remaining.min(Duration::from_millis(50))))
            .ok()?;
        match socket.recv(&mut buffer) {
            Ok(length) => {
                if let Some(value) = parse(&buffer[..length]) {
                    return Some(value);
                }
            }
            Err(error) if is_retry(&error) => {}
            Err(_) => return None,
        }
    }
    None
}

pub fn is_retry(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::Interrupted
    )
}

/// Fill `buffer` before the deadline, polling for cancellation.
pub fn read_full(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    deadline: Instant,
    cancel: &AtomicBool,
) -> Option<()> {
    let mut done = 0;
    while done < buffer.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || cancel.load(Ordering::Relaxed) {
            return None;
        }
        stream
            .set_read_timeout(Some(remaining.min(Duration::from_millis(50))))
            .ok()?;
        match stream.read(&mut buffer[done..]) {
            Ok(0) => return None,
            Ok(length) => done += length,
            Err(error) if is_retry(&error) => {}
            Err(_) => return None,
        }
    }
    Some(())
}

fn http_parts(data: &[u8]) -> Option<(u16, Option<usize>, &[u8])> {
    let end = data.windows(4).position(|window| window == b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&data[..end]);
    let mut lines = head.lines();
    let status = lines.next()?.split_whitespace().nth(1)?.parse().ok()?;
    let length = lines.find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse().ok())
            .flatten()
    });
    Some((status, length, &data[end + 4..]))
}

/// One HTTP/1.0 request to the authorized address; no redirects, bounded body.
pub fn http_exchange(
    target: SocketAddr,
    request: &[u8],
    timeout: Duration,
    cancel: &AtomicBool,
    max_body: usize,
) -> Option<(u16, Vec<u8>)> {
    if timeout.is_zero() || cancel.load(Ordering::Relaxed) {
        return None;
    }
    let timeout = timeout.min(Duration::from_secs(1));
    let deadline = Instant::now() + timeout;
    let mut stream = TcpStream::connect_timeout(&target, timeout).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    stream.write_all(request).ok()?;
    let mut data = Vec::new();
    let mut chunk = [0u8; 4096];
    while !cancel.load(Ordering::Relaxed) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || data.len() > max_body + 8192 {
            break;
        }
        stream
            .set_read_timeout(Some(remaining.min(Duration::from_millis(50))))
            .ok()?;
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(length) => {
                data.extend_from_slice(&chunk[..length]);
                if http_parts(&data)
                    .is_some_and(|(_, length, body)| length.is_some_and(|l| body.len() >= l))
                {
                    break;
                }
            }
            Err(error) if is_retry(&error) => {}
            Err(_) => break,
        }
    }
    let (status, _, body) = http_parts(&data)?;
    Some((status, body[..body.len().min(max_body)].to_vec()))
}

fn unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// First non-empty text of an element, ignoring namespace prefixes.
fn xml_text(xml: &str, name: &str) -> Option<String> {
    let mut rest = xml;
    while let Some(start) = rest.find('<') {
        rest = &rest[start + 1..];
        let end = rest.find('>')?;
        let tag = rest[..end].split_whitespace().next().unwrap_or("");
        rest = &rest[end + 1..];
        if tag.rsplit(':').next() == Some(name) {
            let text = rest[..rest.find('<')?].trim();
            if !text.is_empty() {
                return Some(clean(&unescape(text)));
            }
        }
    }
    None
}

fn unix_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |elapsed| elapsed.as_secs_f64())
}

fn stamp(bytes: &[u8]) -> f64 {
    let seconds = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let fraction = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    f64::from(seconds) + f64::from(fraction) / 4_294_967_296.0
}

fn put_stamp(time: f64) -> [u8; 8] {
    let seconds = time as u32;
    let fraction = ((time - f64::from(seconds)) * 4_294_967_296.0) as u32;
    let mut out = [0; 8];
    out[..4].copy_from_slice(&seconds.to_be_bytes());
    out[4..].copy_from_slice(&fraction.to_be_bytes());
    out
}

fn fixed_ms(bytes: &[u8]) -> f64 {
    f64::from(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])) / 65.536
}

pub fn ntp(ip: Ipv4Addr, timeout: Duration, cancel: &AtomicBool) -> Option<Info> {
    ntp_at((ip, 123).into(), timeout, cancel)
}

fn ntp_at(target: SocketAddr, timeout: Duration, cancel: &AtomicBool) -> Option<Info> {
    let mut request = [0u8; 48];
    request[0] = 0x23;
    request[40..].copy_from_slice(&put_stamp(unix_now() + NTP_EPOCH));
    let sent = stamp(&request[40..]);
    let reply = udp_exchange(target, &request, timeout, cancel, |packet| {
        // Mode 4 reply whose origin timestamp echoes our transmit timestamp.
        let valid = packet.len() >= 48
            && packet[0] & 7 == 4
            && (1..=4).contains(&(packet[0] >> 3 & 7))
            && packet[24..32] == request[40..48];
        valid.then(|| (packet[..48].to_vec(), unix_now() + NTP_EPOCH))
    })?;
    let (packet, received) = reply;
    let (t2, t3) = (stamp(&packet[32..40]), stamp(&packet[40..48]));
    let mut info = Info::new("NTP (UDP 123)");
    info.add("Versione", (packet[0] >> 3 & 7).to_string());
    let stratum = packet[1];
    info.add("Stratum", stratum.to_string());
    let reference = match stratum {
        0 | 1 => String::from_utf8_lossy(&packet[12..16])
            .trim_end_matches('\0')
            .to_owned(),
        _ => Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]).to_string(),
    };
    info.add(
        if stratum == 0 {
            "Codice kiss-o'-death"
        } else {
            "ID riferimento (IPv4 o hash)"
        },
        reference,
    );
    info.add(
        "Sincronizzazione",
        if packet[0] >> 6 == 3 || matches!(stratum, 0 | 16..) {
            "NON sincronizzato"
        } else {
            "sincronizzato"
        },
    );
    if t2 != 0.0 && t3 != 0.0 {
        let offset = ((t2 - sent) + (t3 - received)) / 2.0 * 1000.0;
        let delay = ((received - sent) - (t3 - t2)) * 1000.0;
        info.add(
            "Offset rispetto a questo PC",
            format!("{offset:+.2} ms (dipende dall'orologio locale)"),
        );
        info.add("Ritardo di rete", format!("{delay:.2} ms"));
    }
    info.add("Root delay", format!("{:.2} ms", fixed_ms(&packet[4..8])));
    info.add(
        "Root dispersion",
        format!("{:.2} ms", fixed_ms(&packet[8..12])),
    );
    Some(info)
}

pub fn ssdp(ip: Ipv4Addr, timeout: Duration, cancel: &AtomicBool) -> Option<Info> {
    ssdp_at((ip, 1900).into(), timeout, cancel)
}

fn ssdp_at(target: SocketAddr, timeout: Duration, cancel: &AtomicBool) -> Option<Info> {
    const REQUEST: &[u8] = b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n";
    let (mut info, location) = udp_exchange(target, REQUEST, timeout, cancel, |packet| {
        let text = String::from_utf8_lossy(packet);
        let mut lines = text.lines();
        if !lines.next()?.starts_with("HTTP/1.1 200") {
            return None;
        }
        let mut info = Info::new("SSDP/UPnP (UDP 1900)");
        let mut location = None;
        for line in lines {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let label = match name.trim().to_ascii_lowercase().as_str() {
                "server" => "Server",
                "st" => "Tipo annunciato",
                "usn" => "USN",
                "location" => {
                    location = Some(value.trim().to_owned());
                    "Descrizione"
                }
                _ => continue,
            };
            info.add(label, value);
        }
        (!info.fields.is_empty()).then_some((info, location))
    })?;
    // The advertised URL is fetched only when it points at the queried address itself.
    if let Some((address, path)) = location.as_deref().and_then(|l| local_url(l, target.ip())) {
        let request = format!("GET {path} HTTP/1.0\r\nHost: {address}\r\nAccept: text/xml\r\n\r\n");
        if let Some((200, body)) =
            http_exchange(address, request.as_bytes(), timeout, cancel, 65536)
        {
            let xml = String::from_utf8_lossy(&body);
            for (label, tag) in [
                ("Nome UPnP", "friendlyName"),
                ("Produttore", "manufacturer"),
                ("Modello", "modelName"),
                ("Numero modello", "modelNumber"),
                ("Seriale", "serialNumber"),
                ("Tipo dispositivo", "deviceType"),
            ] {
                if let Some(value) = xml_text(&xml, tag) {
                    info.add(label, value);
                }
            }
        }
    }
    Some(info)
}

fn local_url(url: &str, ip: IpAddr) -> Option<(SocketAddr, String)> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = rest.split_once('/').map_or((rest, ""), |(a, p)| (a, p));
    let (host, port) = authority.split_once(':').unwrap_or((authority, "80"));
    let address = SocketAddr::new(IpAddr::V4(host.parse().ok()?), port.parse().ok()?);
    (address.ip() == ip && address.port() != 0).then(|| (address, format!("/{path}")))
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let decoded = (bytes[at] == b'%')
            .then(|| text.get(at + 1..at + 3))
            .flatten()
            .and_then(|hex| u8::from_str_radix(hex, 16).ok());
        out.push(decoded.unwrap_or(bytes[at]));
        at += if decoded.is_some() { 3 } else { 1 };
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn wsd(ip: Ipv4Addr, timeout: Duration, cancel: &AtomicBool) -> Option<Info> {
    wsd_at((ip, 3702).into(), timeout, cancel)
}

fn wsd_at(target: SocketAddr, timeout: Duration, cancel: &AtomicBool) -> Option<Info> {
    let seed = (u128::from(unix_now().to_bits()) << 32)
        | u128::from(COUNTER.fetch_add(1, Ordering::Relaxed));
    let hex = format!("{seed:032x}");
    let id = format!(
        "urn:uuid:{}-{}-4{}-8{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[13..16],
        &hex[17..20],
        &hex[20..]
    );
    let request = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:wsa=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\" xmlns:wsd=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action><wsa:MessageID>{id}</wsa:MessageID></soap:Header><soap:Body><wsd:Probe/></soap:Body></soap:Envelope>"
    );
    udp_exchange(target, request.as_bytes(), timeout, cancel, |packet| {
        let xml = std::str::from_utf8(packet).ok()?;
        // Only matches answering this probe are accepted.
        if !xml.contains(&id) || !xml.contains("ProbeMatch") {
            return None;
        }
        let mut info = Info::new("WS-Discovery / ONVIF (UDP 3702)");
        info.add("Tipi", xml_text(xml, "Types").unwrap_or_default());
        for scope in xml_text(xml, "Scopes")
            .unwrap_or_default()
            .split_whitespace()
            .take(64)
        {
            let Some(item) = scope.strip_prefix("onvif://www.onvif.org/") else {
                continue;
            };
            let label = match item.split_once('/').map(|(kind, _)| kind) {
                Some("name") => "Nome ONVIF",
                Some("hardware") => "Hardware ONVIF",
                Some("location") => "Posizione ONVIF",
                Some("type") => "Tipo ONVIF",
                Some("Profile") => "Profilo ONVIF",
                _ => continue,
            };
            info.add(label, percent_decode(item.split_once('/')?.1));
        }
        info.add(
            "Indirizzi servizio annunciati (non contattati)",
            xml_text(xml, "XAddrs").unwrap_or_default(),
        );
        Some(info)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field<'a>(info: &'a Info, label: &str) -> Option<&'a str> {
        info.fields
            .iter()
            .find(|(name, _)| name == label)
            .map(|(_, value)| value.as_str())
    }

    #[test]
    fn ntp_reports_sync_state_and_ignores_unrelated_origin() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = server.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let mut buffer = [0; 64];
            let (_, peer) = server.recv_from(&mut buffer).unwrap();
            let mut reply = [0u8; 48];
            reply[0] = 0x24;
            reply[1] = 2;
            reply[12..16].copy_from_slice(&[10, 0, 0, 1]);
            reply[32..40].copy_from_slice(&put_stamp(unix_now() + NTP_EPOCH));
            reply[40..48].copy_from_slice(&put_stamp(unix_now() + NTP_EPOCH));
            // A reply with a foreign origin must be ignored; the valid one follows.
            server.send_to(&reply, peer).unwrap();
            reply[24..32].copy_from_slice(&buffer[40..48]);
            server.send_to(&reply, peer).unwrap();
        });
        let info = ntp_at(address, Duration::from_secs(1), &AtomicBool::new(false)).unwrap();
        worker.join().unwrap();
        assert_eq!(field(&info, "Stratum"), Some("2"));
        assert_eq!(field(&info, "Sincronizzazione"), Some("sincronizzato"));
        assert_eq!(
            field(&info, "ID riferimento (IPv4 o hash)"),
            Some("10.0.0.1")
        );
        assert!(field(&info, "Ritardo di rete").is_some());
        info.validate().unwrap();
    }

    #[test]
    fn ssdp_fetches_description_only_from_the_queried_address() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        assert!(local_url("http://192.0.2.10:49152/d.xml", ip).is_some());
        for url in [
            "http://192.0.2.11/d.xml",
            "https://192.0.2.10/d.xml",
            "http://router.local/d.xml",
        ] {
            assert!(local_url(url, ip).is_none(), "{url}");
        }
        let http = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = http.local_addr().unwrap().port();
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = udp.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let mut buffer = [0; 512];
            let (_, peer) = udp.recv_from(&mut buffer).unwrap();
            udp.send_to(
                format!("HTTP/1.1 200 OK\r\nSERVER: Linux UPnP/1.0\r\nST: upnp:rootdevice\r\nLOCATION: http://127.0.0.1:{port}/d.xml\r\n\r\n").as_bytes(),
                peer,
            )
            .unwrap();
            let (mut stream, _) = http.accept().unwrap();
            let mut request = [0; 512];
            let _ = stream.read(&mut request).unwrap();
            let body = "<root><device><deviceType>urn:x:MediaServer</deviceType><friendlyName>NAS &amp; Co</friendlyName><manufacturerURL>http://x</manufacturerURL><manufacturer>Acme</manufacturer><modelName>N1</modelName></device></root>";
            write!(
                stream,
                "HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        let info = ssdp_at(address, Duration::from_secs(1), &AtomicBool::new(false)).unwrap();
        worker.join().unwrap();
        assert_eq!(field(&info, "Nome UPnP"), Some("NAS & Co"));
        assert_eq!(field(&info, "Produttore"), Some("Acme"));
        assert_eq!(field(&info, "Server"), Some("Linux UPnP/1.0"));
    }

    #[test]
    fn wsd_extracts_onvif_scopes_and_rejects_other_message_ids() {
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = udp.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let mut buffer = [0; 4096];
            let (length, peer) = udp.recv_from(&mut buffer).unwrap();
            let request = String::from_utf8_lossy(&buffer[..length]).into_owned();
            let id = request.split("urn:uuid:").nth(1).unwrap()[..36].to_owned();
            let reply = |id: &str| {
                format!(
                    "<e><RelatesTo>urn:uuid:{id}</RelatesTo><d:ProbeMatches><d:ProbeMatch><d:Types>dn:NetworkVideoTransmitter</d:Types><d:Scopes>onvif://www.onvif.org/name/Front%20Door onvif://www.onvif.org/hardware/C1 onvif://www.onvif.org/Profile/S http://other</d:Scopes><d:XAddrs>http://10.9.9.9/onvif</d:XAddrs></d:ProbeMatch></d:ProbeMatches></e>"
                )
            };
            udp.send_to(
                reply("00000000-0000-4000-8000-000000000000").as_bytes(),
                peer,
            )
            .unwrap();
            udp.send_to(reply(&id).as_bytes(), peer).unwrap();
        });
        let info = wsd_at(address, Duration::from_secs(1), &AtomicBool::new(false)).unwrap();
        worker.join().unwrap();
        assert_eq!(field(&info, "Nome ONVIF"), Some("Front Door"));
        assert_eq!(field(&info, "Hardware ONVIF"), Some("C1"));
        assert_eq!(field(&info, "Profilo ONVIF"), Some("S"));
        assert!(field(&info, "Indirizzi servizio annunciati (non contattati)").is_some());
    }

    #[test]
    fn silent_or_cancelled_udp_probes_return_none_quickly() {
        let silent = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = silent.local_addr().unwrap();
        let started = Instant::now();
        assert!(ntp_at(address, Duration::from_millis(30), &AtomicBool::new(false)).is_none());
        assert!(wsd_at(address, Duration::from_millis(30), &AtomicBool::new(false)).is_none());
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(ssdp_at(address, Duration::from_secs(1), &AtomicBool::new(true)).is_none());
    }

    #[test]
    fn info_rejects_control_characters_and_oversized_lists() {
        let mut info = Info::new("Test");
        info.add("Nome", "a\nb");
        assert_eq!(info.fields[0].1, "ab");
        info.fields.push(("x".into(), "bad\n".into()));
        assert!(info.validate().is_err());
    }
}
