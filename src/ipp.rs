//! IPP Get-Printer-Attributes over plain HTTP, read-only and unauthenticated.

use crate::probe::{Info, clean, http_exchange};
use std::{net::SocketAddr, sync::atomic::AtomicBool, time::Duration};

type Attributes = Vec<(String, Vec<String>)>;

fn attribute(out: &mut Vec<u8>, tag: u8, name: &str, value: &[u8]) {
    out.push(tag);
    out.extend((name.len() as u16).to_be_bytes());
    out.extend(name.as_bytes());
    out.extend((value.len() as u16).to_be_bytes());
    out.extend(value);
}

fn request(target: SocketAddr, path: &str) -> Vec<u8> {
    let mut body = vec![1, 1, 0, 0x0b, 0, 0, 0, 1, 1];
    attribute(&mut body, 0x47, "attributes-charset", b"utf-8");
    attribute(&mut body, 0x48, "attributes-natural-language", b"en");
    let uri = format!("ipp://{target}{path}");
    attribute(&mut body, 0x45, "printer-uri", uri.as_bytes());
    for (index, name) in [
        "printer-make-and-model",
        "printer-name",
        "printer-info",
        "printer-location",
        "printer-firmware-string-version",
        "printer-state",
        "printer-state-reasons",
        "marker-names",
        "marker-levels",
    ]
    .into_iter()
    .enumerate()
    {
        attribute(
            &mut body,
            0x44,
            if index == 0 {
                "requested-attributes"
            } else {
                ""
            },
            name.as_bytes(),
        );
    }
    body.push(3);
    let mut packet = format!(
        "POST {path} HTTP/1.0\r\nHost: {target}\r\nContent-Type: application/ipp\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    packet.extend(body);
    packet
}

fn parse(body: &[u8]) -> Option<Attributes> {
    let word = |at: usize| {
        Some(usize::from(u16::from_be_bytes(
            body.get(at..at + 2)?.try_into().ok()?,
        )))
    };
    // Status codes below 0x0100 are successful.
    if word(2)? >= 0x100 {
        return None;
    }
    let mut at = 8;
    let mut result: Attributes = Vec::new();
    loop {
        let tag = *body.get(at)?;
        at += 1;
        if tag == 3 {
            return Some(result);
        }
        if tag <= 5 {
            continue;
        }
        let name_length = word(at)?;
        let name = body.get(at + 2..at + 2 + name_length)?;
        at += 2 + name_length;
        let length = word(at)?;
        let value = body.get(at + 2..at + 2 + length)?;
        at += 2 + length;
        let text = match tag {
            0x21 | 0x23 if value.len() == 4 => {
                i32::from_be_bytes(value.try_into().ok()?).to_string()
            }
            0x22 if value.len() == 1 => (value[0] != 0).to_string(),
            0x41..=0x49 => clean(&String::from_utf8_lossy(value)),
            _ => String::new(),
        };
        if name_length == 0 {
            let values = &mut result.last_mut()?.1;
            if values.len() < 32 {
                values.push(text);
            }
        } else if result.len() < 256 {
            result.push((clean(&String::from_utf8_lossy(name)), vec![text]));
        } else {
            return None;
        }
    }
}

fn describe(attributes: &Attributes) -> Info {
    let get = |name: &str| {
        attributes
            .iter()
            .find(|(attribute, _)| attribute == name)
            .map(|(_, values)| values)
    };
    let mut info = Info::new("IPP (TCP 631)");
    for (label, name) in [
        ("Modello", "printer-make-and-model"),
        ("Nome stampante", "printer-name"),
        ("Descrizione", "printer-info"),
        ("Posizione", "printer-location"),
        ("Firmware", "printer-firmware-string-version"),
    ] {
        if let Some(values) = get(name) {
            info.add(label, values.join(", "));
        }
    }
    if let Some(state) = get("printer-state").and_then(|values| values.first()) {
        info.add(
            "Stato",
            match state.as_str() {
                "3" => "inattiva",
                "4" => "in stampa",
                "5" => "ferma",
                other => other,
            },
        );
    }
    if let Some(reasons) = get("printer-state-reasons") {
        let reasons: Vec<_> = reasons.iter().filter(|r| *r != "none").cloned().collect();
        info.add("Motivi di stato", reasons.join(", "));
    }
    if let (Some(names), Some(levels)) = (get("marker-names"), get("marker-levels")) {
        let supplies: Vec<_> = names
            .iter()
            .zip(levels)
            .map(|(name, level)| match level.parse::<i32>() {
                Ok(level @ 0..=100) => format!("{name} {level}%"),
                _ => format!("{name} livello sconosciuto"),
            })
            .collect();
        info.add("Materiali di consumo", supplies.join("; "));
    }
    info
}

pub fn collect(ip: std::net::Ipv4Addr, timeout: Duration, cancel: &AtomicBool) -> Option<Info> {
    collect_at((ip, 631).into(), timeout, cancel)
}

fn collect_at(target: SocketAddr, timeout: Duration, cancel: &AtomicBool) -> Option<Info> {
    ["/ipp/print", "/"].into_iter().find_map(|path| {
        let (status, body) = http_exchange(target, &request(target, path), timeout, cancel, 65536)?;
        let info = describe(&parse(&body).filter(|_| status == 200)?);
        (!info.fields.is_empty()).then_some(info)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn reply() -> Vec<u8> {
        let mut body = vec![1, 1, 0, 0, 0, 0, 0, 1, 4];
        attribute(&mut body, 0x41, "printer-make-and-model", b"Acme Laser 9");
        attribute(&mut body, 0x23, "printer-state", &3i32.to_be_bytes());
        attribute(
            &mut body,
            0x44,
            "printer-state-reasons",
            b"toner-low-warning",
        );
        attribute(&mut body, 0x42, "marker-names", b"Black");
        attribute(&mut body, 0x42, "", b"Cyan");
        attribute(&mut body, 0x21, "marker-levels", &40i32.to_be_bytes());
        attribute(&mut body, 0x21, "", &(-2i32).to_be_bytes());
        body.push(3);
        body
    }

    #[test]
    fn printer_attributes_include_state_and_supply_levels() {
        let info = describe(&parse(&reply()).unwrap());
        let text = info.summary();
        assert!(text.contains("Modello: Acme Laser 9"));
        assert!(text.contains("Stato: inattiva"));
        assert!(text.contains("Black 40%; Cyan livello sconosciuto"));
        assert!(text.contains("toner-low-warning"));
    }

    #[test]
    fn truncated_error_status_and_oversized_values_are_rejected() {
        let body = reply();
        for end in 0..body.len() - 1 {
            assert!(parse(&body[..end]).is_none(), "{end}");
        }
        let mut failed = body.clone();
        failed[2..4].copy_from_slice(&0x0400u16.to_be_bytes());
        assert!(parse(&failed).is_none());
    }

    #[test]
    fn loopback_printer_answers_over_http() {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0; 2048];
            let length = stream.read(&mut buffer).unwrap();
            assert!(buffer[..length].starts_with(b"POST /ipp/print HTTP/1.0"));
            let body = reply();
            write!(
                stream,
                "HTTP/1.0 200 OK\r\nContent-Type: application/ipp\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(&body).unwrap();
        });
        let info = collect_at(address, Duration::from_secs(1), &AtomicBool::new(false)).unwrap();
        worker.join().unwrap();
        assert!(info.summary().contains("Acme Laser 9"));
    }
}
