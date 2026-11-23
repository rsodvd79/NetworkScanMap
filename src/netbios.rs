//! Unicast NBNS node status (RFC 1002), without SMB sessions or broadcasts.

use serde::{Deserialize, Serialize};
use std::{
    net::{Ipv4Addr, SocketAddr, UdpSocket},
    sync::atomic::{AtomicBool, AtomicU16, Ordering},
    time::{Duration, Instant},
};

static TRANSACTION: AtomicU16 = AtomicU16::new(1);
const MAX_NAMES: usize = 255;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Node {
    pub names: Vec<Name>,
    pub reported_mac: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Name {
    pub name: String,
    pub suffix: u8,
    pub group: bool,
    pub flags: u16,
}

impl Node {
    pub fn hostname(&self) -> Option<&str> {
        [0x00, 0x20].into_iter().find_map(|suffix| {
            self.names
                .iter()
                .find(|entry| {
                    !entry.group
                        && entry.suffix == suffix
                        && entry.flags & 0x1c00 == 0x0400
                        && !entry.name.is_empty()
                })
                .map(|entry| entry.name.as_str())
        })
    }

    pub fn summary(&self) -> String {
        let mut lines = vec!["NetBIOS (NBSTAT UDP 137):".into()];
        for entry in &self.names {
            let role = match (entry.group, entry.suffix) {
                (true, 0x00) => "gruppo di lavoro / dominio",
                (false, 0x00) => "nome workstation",
                (false, 0x20) => "servizio file server",
                (true, 0x1c) => "gruppo controller di dominio",
                (false, 0x1b) => "domain master browser",
                (false, 0x1d) => "local master browser",
                _ => "nome registrato",
            };
            lines.push(format!(
                "{} <{:02X}>: {role}, {}, flag 0x{:04X}{}",
                entry.name,
                entry.suffix,
                if entry.group { "gruppo" } else { "univoco" },
                entry.flags,
                if entry.flags & 0x1c00 == 0x0400 {
                    ""
                } else {
                    " (non attivo / in conflitto)"
                },
            ));
        }
        if let Some(mac) = &self.reported_mac {
            lines.push(format!(
                "MAC dichiarato NetBIOS: {mac} (non conferma identita o adiacenza)"
            ));
        }
        lines.join("\n")
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.names.len() <= MAX_NAMES, "Troppi nomi NetBIOS");
        for name in &self.names {
            anyhow::ensure!(
                name.name.len() <= 60
                    && name.name.is_ascii()
                    && !name.name.chars().any(char::is_control)
                    && name.group == (name.flags & 0x8000 != 0),
                "Nome NetBIOS non valido"
            );
        }
        if let Some(mac) = &self.reported_mac {
            anyhow::ensure!(
                mac.len() == 17
                    && mac.split(':').count() == 6
                    && mac
                        .split(':')
                        .all(|part| part.len() == 2 && u8::from_str_radix(part, 16).is_ok()),
                "MAC NetBIOS non valido"
            );
        }
        Ok(())
    }
}

fn query(id: u16) -> Vec<u8> {
    let mut packet = vec![0u8; 12];
    packet[..2].copy_from_slice(&id.to_be_bytes());
    packet[5] = 1;
    packet.push(32);
    for byte in std::iter::once(b'*').chain(std::iter::repeat_n(0, 15)) {
        packet.push(b'A' + (byte >> 4));
        packet.push(b'A' + (byte & 15));
    }
    packet.extend_from_slice(&[0, 0, 0x21, 0, 1]);
    packet
}

fn word(packet: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        packet.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn owner(packet: &[u8], cursor: &mut usize) -> Option<Vec<u8>> {
    let mut at = *cursor;
    let mut end = None;
    let mut name = Vec::new();
    for _ in 0..128 {
        let length = *packet.get(at)?;
        if length & 0xc0 == 0xc0 {
            let target = usize::from(word(packet, at)? & 0x3fff);
            if target >= at {
                return None;
            }
            end.get_or_insert(at + 2);
            at = target;
        } else {
            if length > 63 {
                return None;
            }
            at += 1;
            name.push(length);
            if length == 0 {
                *cursor = end.unwrap_or(at);
                return Some(name);
            }
            name.extend_from_slice(packet.get(at..at + usize::from(length))?);
            if name.len() > 254 {
                return None;
            }
            at += usize::from(length);
        }
    }
    None
}

fn answer(packet: &[u8], id: u16) -> Option<Node> {
    let flags = word(packet, 2)?;
    if word(packet, 0)? != id
        || flags & 0x8000 == 0
        || flags & 0x7a0f != 0
        || word(packet, 4)? > 1
        || word(packet, 6)? != 1
        || word(packet, 8)? != 0
        || word(packet, 10)? != 0
    {
        return None;
    }
    let request = query(id);
    let expected = &request[12..46];
    let mut cursor = 12;
    if word(packet, 4)? == 1 {
        if owner(packet, &mut cursor)?.as_slice() != expected
            || word(packet, cursor)? != 0x21
            || word(packet, cursor + 2)? != 1
        {
            return None;
        }
        cursor += 4;
    }
    if owner(packet, &mut cursor)?.as_slice() != expected
        || word(packet, cursor)? != 0x21
        || word(packet, cursor + 2)? != 1
    {
        return None;
    }
    let length = usize::from(word(packet, cursor + 8)?);
    cursor += 10;
    let data = packet.get(cursor..cursor + length)?;
    if cursor + length != packet.len() {
        return None;
    }
    let count = usize::from(*data.first()?);
    let stats = 1 + count * 18;
    if data.len() < stats + 46 {
        return None;
    }
    let mut names = Vec::with_capacity(count);
    for entry in data[1..stats].as_chunks::<18>().0 {
        let bytes = &entry[..15];
        let end = bytes
            .iter()
            .rposition(|byte| !matches!(byte, b' ' | 0))
            .map_or(0, |i| i + 1);
        let mut name = String::new();
        for &byte in &bytes[..end] {
            if (0x20..=0x7e).contains(&byte) {
                name.push(char::from(byte));
            } else {
                use std::fmt::Write;
                let _ = write!(name, "\\x{byte:02X}");
            }
        }
        let flags = word(entry, 16)?;
        names.push(Name {
            name,
            suffix: entry[15],
            group: flags & 0x8000 != 0,
            flags,
        });
    }
    let mac = &data[stats..stats + 6];
    let reported_mac = (mac[0] & 1 == 0 && mac.iter().any(|&byte| byte != 0)).then(|| {
        mac.iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    });
    Some(Node {
        names,
        reported_mac,
    })
}

pub fn collect(ip: Ipv4Addr, timeout: Duration, cancel: &AtomicBool) -> Option<Node> {
    if ip.octets()[0] == 0 || ip.octets()[0] >= 224 {
        return None;
    }
    collect_at((ip, 137).into(), timeout, cancel)
}

fn collect_at(target: SocketAddr, timeout: Duration, cancel: &AtomicBool) -> Option<Node> {
    if timeout.is_zero() || cancel.load(Ordering::Relaxed) {
        return None;
    }
    let deadline = Instant::now() + timeout.min(Duration::from_secs(1));
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    socket.connect(target).ok()?;
    let id = TRANSACTION.fetch_add(1, Ordering::Relaxed);
    socket.send(&query(id)).ok()?;
    let mut buffer = [0u8; 8192];
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
                if let Some(node) = answer(&buffer[..length], id) {
                    return Some(node);
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(_) => return None,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(id: u16, compressed: bool) -> Vec<u8> {
        let mut packet = query(id);
        packet[2..4].copy_from_slice(&0x8400u16.to_be_bytes());
        packet[6..8].copy_from_slice(&1u16.to_be_bytes());
        if compressed {
            packet.extend_from_slice(&[0xc0, 12]);
        } else {
            packet.extend_from_slice(&query(id)[12..46]);
        }
        let mut data = vec![3];
        for (name, suffix, flags) in [
            ("NAS", 0x20, 0x0400u16),
            ("NAS", 0, 0x0400),
            ("OFFICE", 0, 0x8400),
        ] {
            let mut entry = [b' '; 18];
            entry[..name.len()].copy_from_slice(name.as_bytes());
            entry[15] = suffix;
            entry[16..].copy_from_slice(&flags.to_be_bytes());
            data.extend_from_slice(&entry);
        }
        data.extend_from_slice(&[0x02, 1, 2, 3, 4, 5]);
        data.extend_from_slice(&[0; 40]);
        packet.extend_from_slice(&[0, 0x21, 0, 1, 0, 0, 0, 0]);
        packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
        packet.extend(data);
        packet
    }

    #[test]
    fn node_status_parses_names_groups_suffixes_and_reported_mac() {
        for compressed in [true, false] {
            let node = answer(&response(42, compressed), 42).unwrap();
            node.validate().unwrap();
            assert_eq!(node.hostname(), Some("NAS"));
            assert_eq!(node.reported_mac.as_deref(), Some("02:01:02:03:04:05"));
            assert!(
                node.summary()
                    .contains("OFFICE <00>: gruppo di lavoro / dominio")
            );
            assert!(node.summary().contains("NAS <20>: servizio file server"));
            let restored: Node =
                serde_json::from_slice(&serde_json::to_vec(&node).unwrap()).unwrap();
            assert_eq!(node.summary(), restored.summary());
        }
        let mut no_question = response(42, false);
        no_question[4..6].copy_from_slice(&0u16.to_be_bytes());
        no_question.drain(12..50);
        assert_eq!(answer(&no_question, 42).unwrap().hostname(), Some("NAS"));
    }

    #[test]
    fn malformed_unrelated_negative_and_inactive_replies_are_not_used_as_hostnames() {
        let packet = response(42, true);
        assert!(answer(&packet, 43).is_none());
        for end in 0..packet.len() {
            assert!(answer(&packet[..end], 42).is_none());
        }
        for (offset, value) in [
            (2, 0x86),
            (3, 3),
            (6, 1),
            (12, 0xff),
            (52, 1),
            (51, 50),
            (62, 255),
        ] {
            let mut bad = packet.clone();
            bad[offset] = value;
            assert!(answer(&bad, 42).is_none(), "{offset}");
        }
        let mut node = answer(&packet, 42).unwrap();
        for name in &mut node.names {
            name.flags |= 0x0800;
        }
        assert_eq!(node.hostname(), None);
        node.names[0].name = "\nInjected".into();
        assert!(node.validate().is_err());
    }

    #[test]
    fn unicast_loopback_ignores_wrong_transaction_and_respects_cancellation_and_timeout() {
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let address = server.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let mut buffer = [0; 512];
            let (length, peer) = server.recv_from(&mut buffer).unwrap();
            let id = word(&buffer, 0).unwrap();
            assert_eq!(&buffer[..length], query(id));
            server
                .send_to(&response(id.wrapping_add(1), true), peer)
                .unwrap();
            server.send_to(&response(id, true), peer).unwrap();
        });
        assert_eq!(
            collect_at(address, Duration::from_secs(1), &AtomicBool::new(false))
                .unwrap()
                .hostname(),
            Some("NAS")
        );
        worker.join().unwrap();
        let silent = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let started = Instant::now();
        assert!(
            collect_at(
                silent.local_addr().unwrap(),
                Duration::from_millis(30),
                &AtomicBool::new(false)
            )
            .is_none()
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(
            collect_at(
                silent.local_addr().unwrap(),
                Duration::from_secs(1),
                &AtomicBool::new(true)
            )
            .is_none()
        );
        let mut buffer = [0; 512];
        silent.set_nonblocking(true).unwrap();
        silent.recv_from(&mut buffer).unwrap();
        assert!(silent.recv_from(&mut buffer).is_err());
    }
}
