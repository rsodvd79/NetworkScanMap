//! SMB2 negotiate plus an NTLM challenge. No credentials are sent and no session is
//! established: the second request only asks the server to describe itself.

use crate::probe::{Info, read_full};
use std::{
    io::Write,
    net::{Ipv4Addr, SocketAddr, TcpStream},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

const HEADER: usize = 64;
const MORE_PROCESSING: u32 = 0xC000_0016;
const NTLM_SIGNATURE: &[u8] = b"NTLMSSP\0";

fn header(command: u16, id: u64) -> Vec<u8> {
    let mut out = vec![0xFE, b'S', b'M', b'B'];
    out.extend(64u16.to_le_bytes());
    out.extend(1u16.to_le_bytes());
    out.extend(0u32.to_le_bytes());
    out.extend(command.to_le_bytes());
    out.extend(1u16.to_le_bytes());
    out.extend(0u32.to_le_bytes());
    out.extend(0u32.to_le_bytes());
    out.extend(id.to_le_bytes());
    out.resize(HEADER, 0);
    out
}

fn framed(mut message: Vec<u8>) -> Vec<u8> {
    let length = (message.len() as u32).to_be_bytes();
    message.splice(0..0, [0, length[1], length[2], length[3]]);
    message
}

fn negotiate() -> Vec<u8> {
    let mut packet = header(0, 0);
    packet.extend(36u16.to_le_bytes());
    packet.extend(4u16.to_le_bytes());
    packet.extend(1u16.to_le_bytes());
    packet.extend([0; 2]);
    packet.extend([0; 4]);
    packet.extend([0x5a; 16]);
    packet.extend([0; 8]);
    for dialect in [0x0202u16, 0x0210, 0x0300, 0x0302] {
        packet.extend(dialect.to_le_bytes());
    }
    framed(packet)
}

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let length = content.len();
    let mut out = vec![tag];
    match length {
        0..=127 => out.push(length as u8),
        128..=255 => out.extend([0x81, length as u8]),
        _ => out.extend([0x82, (length >> 8) as u8, length as u8]),
    }
    out.extend(content);
    out
}

fn ntlm_negotiate() -> Vec<u8> {
    let mut message = NTLM_SIGNATURE.to_vec();
    message.extend(1u32.to_le_bytes());
    // Unicode, target request, NTLM, always sign, extended security, target info, version, 128-bit.
    message.extend(0x6288_8205u32.to_le_bytes());
    message.extend([0; 16]);
    message.extend([10, 0, 0, 0, 0, 0, 0, 15]);
    message
}

fn session_setup() -> Vec<u8> {
    let mut ntlm = ntlm_negotiate();
    // Domain and workstation security buffers point past the fixed 40 byte message.
    ntlm[20..24].copy_from_slice(&40u32.to_le_bytes());
    ntlm[28..32].copy_from_slice(&40u32.to_le_bytes());
    let mechanisms = der(
        0xa0,
        &der(
            0x30,
            &[
                0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
            ],
        ),
    );
    let token = der(0xa2, &der(0x04, &ntlm));
    let init = der(0xa0, &der(0x30, &[mechanisms, token].concat()));
    let spnego = der(
        0x60,
        &[&[0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02][..], &init].concat(),
    );
    let mut packet = header(1, 1);
    packet.extend(25u16.to_le_bytes());
    packet.extend([0, 1]);
    packet.extend([0; 8]);
    packet.extend(((HEADER + 24) as u16).to_le_bytes());
    packet.extend((spnego.len() as u16).to_le_bytes());
    packet.extend([0; 8]);
    packet.extend(spnego);
    framed(packet)
}

fn frame(stream: &mut TcpStream, deadline: Instant, cancel: &AtomicBool) -> Option<Vec<u8>> {
    let mut head = [0u8; 4];
    read_full(stream, &mut head, deadline, cancel)?;
    let length = u32::from_be_bytes([0, head[1], head[2], head[3]]) as usize;
    if head[0] != 0 || !(HEADER + 2..=65536).contains(&length) {
        return None;
    }
    let mut body = vec![0u8; length];
    read_full(stream, &mut body, deadline, cancel)?;
    Some(body)
}

fn le16(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(data.get(at..at + 2)?.try_into().ok()?))
}

fn le32(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(at..at + 4)?.try_into().ok()?))
}

fn le64(data: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(data.get(at..at + 8)?.try_into().ok()?))
}

/// Reply header check: protocol ID, command and echoed message ID; returns the status.
fn reply_status(data: &[u8], command: u16, id: u64) -> Option<u32> {
    (data.get(..4)? == [0xFE, b'S', b'M', b'B']
        && le16(data, 12)? == command
        && le64(data, 24)? == id)
        .then(|| le32(data, 8))
        .flatten()
}

fn filetime_unix(time: u64) -> Option<u64> {
    (time / 10_000_000).checked_sub(11_644_473_600)
}

fn describe_negotiate(data: &[u8], info: &mut Info) -> Option<()> {
    let body = data.get(HEADER..)?;
    if body.len() < 64 || le16(body, 0)? != 65 {
        return None;
    }
    let signing = le16(body, 2)?;
    info.add(
        "Dialetto",
        match le16(body, 4)? {
            0x0202 => "SMB 2.0.2".to_string(),
            0x0210 => "SMB 2.1".to_string(),
            0x0300 => "SMB 3.0".to_string(),
            0x0302 => "SMB 3.0.2".to_string(),
            0x0311 => "SMB 3.1.1".to_string(),
            other => format!("0x{other:04X}"),
        },
    );
    info.add(
        "Firma messaggi",
        if signing & 2 != 0 {
            "richiesta"
        } else {
            "non richiesta"
        },
    );
    let guid = body.get(8..24)?;
    info.add(
        "GUID server",
        guid.iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    );
    let (now, start) = (le64(body, 40)?, le64(body, 48)?);
    if let Some(unix) = filetime_unix(now) {
        info.add("Ora server (Unix)", unix.to_string());
        if let Some(uptime) = filetime_unix(start)
            .filter(|_| start != 0)
            .and_then(|start| unix.checked_sub(start))
        {
            info.add(
                "Uptime stimato",
                format!("{} g {} h", uptime / 86400, uptime % 86400 / 3600),
            );
        }
    }
    Some(())
}

fn utf16(data: &[u8]) -> String {
    char::decode_utf16(
        data.as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair)),
    )
    .map(|c| c.unwrap_or('?'))
    .collect()
}

fn describe_challenge(data: &[u8], info: &mut Info) -> Option<()> {
    let body = data.get(HEADER..)?;
    let start = body
        .windows(NTLM_SIGNATURE.len())
        .position(|window| window == NTLM_SIGNATURE)?;
    let ntlm = &body[start..];
    if le32(ntlm, 8)? != 2 {
        return None;
    }
    let flags = le32(ntlm, 20)?;
    if flags & 0x0200_0000 != 0 && *ntlm.get(48)? != 0 {
        info.add(
            "Versione sistema (NTLM)",
            format!(
                "NT {}.{} build {}",
                ntlm[48],
                ntlm.get(49)?,
                le16(ntlm, 50)?
            ),
        );
    }
    let length = usize::from(le16(ntlm, 40)?);
    let offset = le32(ntlm, 44)? as usize;
    let mut pairs = ntlm.get(offset..offset.checked_add(length)?)?;
    while pairs.len() >= 4 {
        let (id, size) = (le16(pairs, 0)?, usize::from(le16(pairs, 2)?));
        let value = pairs.get(4..4 + size)?;
        let label = match id {
            0 => break,
            1 => "Nome computer NetBIOS",
            2 => "Dominio NetBIOS",
            3 => "Nome DNS computer",
            4 => "Dominio DNS",
            5 => "Foresta DNS",
            _ => "",
        };
        if !label.is_empty() {
            info.add(label, utf16(value));
        }
        pairs = &pairs[4 + size..];
    }
    Some(())
}

pub fn collect(ip: Ipv4Addr, timeout: Duration, cancel: &AtomicBool) -> Option<Info> {
    collect_at((ip, 445).into(), timeout, cancel)
}

fn collect_at(target: SocketAddr, timeout: Duration, cancel: &AtomicBool) -> Option<Info> {
    if timeout.is_zero() || cancel.load(Ordering::Relaxed) {
        return None;
    }
    let timeout = timeout.min(Duration::from_secs(1));
    let deadline = Instant::now() + timeout * 2;
    let mut stream = TcpStream::connect_timeout(&target, timeout).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    stream.write_all(&negotiate()).ok()?;
    let reply = frame(&mut stream, deadline, cancel)?;
    if reply_status(&reply, 0, 0)? != 0 {
        return None;
    }
    let mut info = Info::new("SMB2 (TCP 445), nessuna autenticazione");
    describe_negotiate(&reply, &mut info)?;
    if stream.write_all(&session_setup()).is_ok()
        && let Some(reply) = frame(&mut stream, deadline, cancel)
        && reply_status(&reply, 1, 1) == Some(MORE_PROCESSING)
    {
        let _ = describe_challenge(&reply, &mut info);
    }
    Some(info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn answer(command: u16, id: u64, status: u32, body: &[u8]) -> Vec<u8> {
        let mut packet = header(command, id);
        packet[8..12].copy_from_slice(&status.to_le_bytes());
        packet.extend(body);
        framed(packet)
    }

    fn negotiate_body() -> Vec<u8> {
        let mut body = vec![0u8; 64];
        body[..2].copy_from_slice(&65u16.to_le_bytes());
        body[2..4].copy_from_slice(&1u16.to_le_bytes());
        body[4..6].copy_from_slice(&0x0302u16.to_le_bytes());
        let now = (1_800_000_000u64 + 11_644_473_600) * 10_000_000;
        let start = (1_799_000_000u64 + 11_644_473_600) * 10_000_000;
        body[40..48].copy_from_slice(&now.to_le_bytes());
        body[48..56].copy_from_slice(&start.to_le_bytes());
        body
    }

    fn challenge_body() -> Vec<u8> {
        let mut pairs = Vec::new();
        for (id, text) in [(1u16, "FILESRV"), (2, "CORP"), (4, "corp.example")] {
            let value: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
            pairs.extend(id.to_le_bytes());
            pairs.extend((value.len() as u16).to_le_bytes());
            pairs.extend(value);
        }
        pairs.extend([0; 4]);
        let mut ntlm = NTLM_SIGNATURE.to_vec();
        ntlm.extend(2u32.to_le_bytes());
        ntlm.extend([0; 8]);
        ntlm.extend(0x0200_0000u32.to_le_bytes());
        ntlm.extend([0; 16]);
        ntlm.extend((pairs.len() as u16).to_le_bytes());
        ntlm.extend((pairs.len() as u16).to_le_bytes());
        ntlm.extend(56u32.to_le_bytes());
        ntlm.extend([10, 0]);
        ntlm.extend(19045u16.to_le_bytes());
        ntlm.extend([0, 0, 0, 15]);
        ntlm.extend(pairs);
        let mut body = vec![0u8; 8];
        body.extend([0xa1, 0x81]);
        body.extend(ntlm);
        body
    }

    #[test]
    fn negotiate_and_ntlm_challenge_describe_server_without_credentials() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0; 1024];
            let length = stream.read(&mut buffer).unwrap();
            assert_eq!(&buffer[..length], negotiate().as_slice());
            stream
                .write_all(&answer(0, 0, 0, &negotiate_body()))
                .unwrap();
            let length = stream.read(&mut buffer).unwrap();
            assert_eq!(&buffer[..length], session_setup().as_slice());
            stream
                .write_all(&answer(1, 1, MORE_PROCESSING, &challenge_body()))
                .unwrap();
        });
        let info = collect_at(address, Duration::from_secs(1), &AtomicBool::new(false)).unwrap();
        worker.join().unwrap();
        let text = info.summary();
        for expected in [
            "Dialetto: SMB 3.0.2",
            "Uptime stimato: 11 g 13 h",
            "Nome computer NetBIOS: FILESRV",
            "Dominio DNS: corp.example",
            "Versione sistema (NTLM): NT 10.0 build 19045",
        ] {
            assert!(text.contains(expected), "{expected}\n{text}");
        }
        assert!(text.contains("richiesta") || text.contains("non richiesta"));
    }

    #[test]
    fn malformed_negotiate_replies_are_rejected() {
        let good = answer(0, 0, 0, &negotiate_body());
        let mut info = Info::default();
        assert!(describe_negotiate(&good[4..], &mut info).is_some());
        for end in 0..good.len() - 4 {
            assert!(describe_negotiate(&good[4..4 + end], &mut Info::default()).is_none());
        }
        assert!(reply_status(&good[4..], 0, 1).is_none());
        assert!(reply_status(&good[4..], 1, 0).is_none());
        let challenge = answer(1, 1, MORE_PROCESSING, &challenge_body());
        for end in 0..challenge.len() - 4 {
            let _ = describe_challenge(&challenge[4..4 + end], &mut Info::default());
        }
    }
}
