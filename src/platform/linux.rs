use super::{Interface, Neighbor, NetworkInfo, Route, mac, unix};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

fn u16_at(bytes: &[u8], offset: usize) -> io::Result<u16> {
    let b = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| io::Error::other("Truncated u16"))?;
    Ok(u16::from_ne_bytes([b[0], b[1]]))
}

fn u32_at(bytes: &[u8], offset: usize) -> io::Result<u32> {
    let b = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| io::Error::other("Truncated u32"))?;
    Ok(u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
}

fn attributes(mut bytes: &[u8]) -> io::Result<Vec<(u16, &[u8])>> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        let length = u16_at(bytes, 0)? as usize;
        let kind = u16_at(bytes, 2)? & 0x3fff;
        if length < 4 || length > bytes.len() {
            return Err(io::Error::other("Invalid Netlink attribute length"));
        }
        result.push((kind, &bytes[4..length]));
        let aligned = (length + 3) & !3;
        if aligned > bytes.len() {
            if length == bytes.len() {
                break;
            }
            return Err(io::Error::other("Truncated Netlink attribute padding"));
        }
        bytes = &bytes[aligned..];
    }
    Ok(result)
}

fn attr<'a>(attrs: &[(u16, &'a [u8])], kind: u16) -> Option<&'a [u8]> {
    attrs.iter().find(|(k, _)| *k == kind).map(|(_, b)| *b)
}

fn ipv4(bytes: &[u8]) -> Option<Ipv4Addr> {
    (bytes.len() == 4).then(|| Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
}

fn dump(kind: u16, body_length: usize) -> io::Result<Vec<Vec<u8>>> {
    let socket = Socket::new(
        Domain::from(libc::AF_NETLINK),
        Type::DGRAM,
        Some(Protocol::from(libc::NETLINK_ROUTE)),
    )?;
    socket.set_nonblocking(true)?;
    // SAFETY: zeroed sockaddr_nl with family is a valid kernel-assigned local Netlink address.
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as u16;
    // SAFETY: address and size refer to a fully initialized sockaddr_nl.
    if unsafe {
        libc::bind(
            socket.as_raw_fd(),
            (&address as *const libc::sockaddr_nl).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut request = vec![0u8; 16 + body_length];
    let length = request.len() as u32;
    request[0..4].copy_from_slice(&length.to_ne_bytes());
    request[4..6].copy_from_slice(&kind.to_ne_bytes());
    request[6..8].copy_from_slice(&0x301u16.to_ne_bytes()); // REQUEST | ROOT | MATCH
    request[8..12].copy_from_slice(&1u32.to_ne_bytes());
    request[16] = if kind == 18 {
        libc::AF_UNSPEC as u8
    } else {
        libc::AF_INET as u8
    };
    // SAFETY: nl_pid=0 and nl_groups=0 target the kernel, request is initialized.
    let sent = unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            request.as_ptr().cast(),
            request.len(),
            0,
            (&address as *const libc::sockaddr_nl).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    if sent as usize != request.len() {
        return Err(io::Error::other("Incomplete Netlink request"));
    }
    let started = Instant::now();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut records = Vec::new();
    let mut total = 0usize;
    loop {
        let remaining = Duration::from_secs(2).saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Netlink dump timed out",
            ));
        }
        let mut poll = libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one live socket descriptor and one initialized pollfd.
        let ready =
            unsafe { libc::poll(&mut poll, 1, remaining.as_millis().saturating_add(1) as i32) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if ready == 0 {
            continue;
        }
        // SAFETY: recvfrom receives into a capacity-checked buffer and initialized address.
        let (n, source, size) = unsafe {
            let mut source: libc::sockaddr_nl = std::mem::zeroed();
            let mut size = std::mem::size_of_val(&source) as libc::socklen_t;
            let n = libc::recvfrom(
                socket.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_TRUNC,
                (&mut source as *mut libc::sockaddr_nl).cast(),
                &mut size,
            );
            (n, source, size)
        };
        if n < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(error);
        }
        if n == 0 || n as usize > buffer.len() {
            return Err(io::Error::other("Truncated Netlink datagram"));
        }
        if (size as usize) < std::mem::size_of::<libc::sockaddr_nl>() || source.nl_pid != 0 {
            continue;
        }
        total += n as usize;
        if total > 16 * 1024 * 1024 {
            return Err(io::Error::other("Oversized Netlink dump"));
        }
        let mut bytes = &buffer[..n as usize];
        while !bytes.is_empty() {
            let length = u32_at(bytes, 0)? as usize;
            if length < 16 || length > bytes.len() {
                return Err(io::Error::other("Invalid Netlink message length"));
            }
            let message_kind = u16_at(bytes, 4)?;
            let flags = u16_at(bytes, 6)?;
            let sequence = u32_at(bytes, 8)?;
            let body = &bytes[16..length];
            if sequence == 1 {
                if flags & 0x10 != 0 {
                    return Err(io::Error::other("Netlink dump interrupted; retry snapshot"));
                }
                match message_kind {
                    2 => {
                        let code = u32_at(body, 0)? as i32;
                        if code != 0 {
                            return Err(io::Error::from_raw_os_error(code.saturating_neg()));
                        }
                    }
                    3 => {
                        if body.len() >= 4 {
                            let code = u32_at(body, 0)? as i32;
                            if code != 0 {
                                return Err(io::Error::from_raw_os_error(code.saturating_neg()));
                            }
                        }
                        return Ok(records);
                    }
                    4 => return Err(io::Error::other("Netlink receive overrun")),
                    k if k == kind - 2 => records.push(body.to_vec()),
                    _ => {}
                }
            }
            let aligned = (length + 3) & !3;
            if aligned > bytes.len() {
                if length == bytes.len() {
                    break;
                }
                return Err(io::Error::other("Truncated Netlink message padding"));
            }
            bytes = &bytes[aligned..];
        }
    }
}

pub(super) fn network_info() -> NetworkInfo {
    let mut info = NetworkInfo::default();
    let mut names = HashMap::new();
    match dump(18, 16).and_then(|records| {
        for b in records {
            if b.len() < 16 {
                return Err(io::Error::other("Truncated interface record"));
            }
            let index = u32_at(&b, 4)?;
            let flags = u32_at(&b, 8)?;
            let attrs = attributes(&b[16..])?;
            let name = attr(&attrs, 3)
                .and_then(|name| {
                    let end = name.iter().position(|b| *b == 0)?;
                    std::str::from_utf8(&name[..end]).ok().map(str::to_owned)
                })
                .unwrap_or_else(|| unix::interface_name(index));
            names.insert(index, (name, flags & libc::IFF_UP as u32 != 0));
        }
        Ok(())
    }) {
        Ok(()) => {}
        Err(e) => info.warnings.push(format!("Netlink interfaces: {e}")),
    }
    for (kind, size, label) in [
        (22, 8, "addresses"),
        (26, 12, "routes"),
        (30, 12, "neighbors"),
    ] {
        let result = dump(kind, size).and_then(|records| {
            for bytes in records {
                parse_record(kind, &bytes, &names, &mut info)?;
            }
            Ok(())
        });
        if let Err(e) = result {
            info.warnings.push(format!("Netlink {label}: {e}"));
        }
    }
    info
}

fn name(index: u32, names: &HashMap<u32, (String, bool)>) -> String {
    names
        .get(&index)
        .map(|(n, _)| n.clone())
        .unwrap_or_else(|| unix::interface_name(index))
}

fn parse_record(
    kind: u16,
    b: &[u8],
    names: &HashMap<u32, (String, bool)>,
    info: &mut NetworkInfo,
) -> io::Result<()> {
    let size = if kind == 22 { 8 } else { 12 };
    if b.len() < size {
        return Err(io::Error::other("Truncated Netlink record"));
    }
    if b[0] as i32 != libc::AF_INET {
        return Ok(());
    }
    let attrs = attributes(&b[size..])?;
    match kind {
        22 => {
            let index = u32_at(b, 4)?;
            let flags = attr(&attrs, 8)
                .map(|v| u32_at(v, 0))
                .transpose()?
                .unwrap_or(b[2] as u32);
            if b[1] > 32 || flags & 0x48 != 0 || names.get(&index).is_some_and(|(_, up)| !up) {
                return Ok(());
            }
            if let Some(address) = attr(&attrs, 2).or_else(|| attr(&attrs, 1)).and_then(ipv4) {
                info.interfaces.push(Interface {
                    name: name(index, names),
                    address,
                    prefix: b[1],
                });
            }
        }
        26 => {
            // Only forwarding unicast routes, not local/broadcast/blackhole cache entries.
            let table = attr(&attrs, 15)
                .map(|v| u32_at(v, 0))
                .transpose()?
                .unwrap_or(b[4] as u32);
            if b[7] != 1 || b[1] > 32 || table == 255 || u32_at(b, 8)? & 0x200 != 0 {
                return Ok(());
            }
            let destination = match attr(&attrs, 1) {
                Some(b) => ipv4(b).ok_or_else(|| io::Error::other("Invalid route address"))?,
                None if b[1] == 0 => Ipv4Addr::UNSPECIFIED,
                None => return Err(io::Error::other("Missing route destination")),
            };
            let network = ipnet::Ipv4Net::new(destination, b[1])
                .map_err(io::Error::other)?
                .trunc();
            if let Some(mut paths) = attr(&attrs, 9) {
                while !paths.is_empty() {
                    let length = u16_at(paths, 0)? as usize;
                    if length < 8 || length > paths.len() {
                        return Err(io::Error::other("Invalid multipath route"));
                    }
                    let index = u32_at(paths, 4)?;
                    let path_attrs = attributes(&paths[8..length])?;
                    if paths[2] & 1 == 0 && index != 0 {
                        info.routes.push(Route {
                            network,
                            gateway: gateway(&path_attrs)?,
                            interface: name(index, names),
                        });
                    }
                    let aligned = (length + 3) & !3;
                    if aligned > paths.len() {
                        return Err(io::Error::other("Truncated multipath padding"));
                    }
                    paths = &paths[aligned..];
                }
            } else if let Some(index) = attr(&attrs, 4).map(|v| u32_at(v, 0)).transpose()? {
                info.routes.push(Route {
                    network,
                    gateway: gateway(&attrs)?,
                    interface: name(index, names),
                });
            }
        }
        30 => {
            let state = u16_at(b, 8)?;
            if state == 0 || state & 0x21 != 0 {
                return Ok(());
            }
            if let (Some(ip), Some(mac)) = (
                attr(&attrs, 1).and_then(ipv4),
                attr(&attrs, 2).and_then(mac),
            ) && !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_broadcast()
            {
                info.neighbors.push(Neighbor {
                    ip,
                    mac,
                    interface: name(u32_at(b, 4)?, names),
                });
            }
        }
        _ => {}
    }
    Ok(())
}

fn gateway(attrs: &[(u16, &[u8])]) -> io::Result<Option<Ipv4Addr>> {
    if attr(attrs, 18).is_some() {
        return Err(io::Error::other("Cross-family route gateway unsupported"));
    }
    attr(attrs, 5)
        .map(|b| ipv4(b).ok_or_else(|| io::Error::other("Invalid IPv4 gateway")))
        .transpose()
        .map(|ip| ip.filter(|ip| !ip.is_unspecified()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attribute(kind: u16, value: &[u8]) -> Vec<u8> {
        let length = 4 + value.len();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(length as u16).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(value);
        bytes.resize((length + 3) & !3, 0);
        bytes
    }

    #[test]
    fn parses_default_and_multipath_routes_without_inventing_neighbors() {
        let mut record = vec![2, 0, 0, 0, 254, 0, 0, 1, 0, 0, 0, 0];
        record.extend(attribute(4, &1u32.to_ne_bytes()));
        record.extend(attribute(5, &[127, 0, 0, 2]));
        let mut info = NetworkInfo::default();
        parse_record(26, &record, &HashMap::new(), &mut info).unwrap();
        assert_eq!(info.routes[0].network.prefix_len(), 0);
        assert_eq!(info.routes[0].gateway, Some(Ipv4Addr::new(127, 0, 0, 2)));
        let mut path = vec![16, 0, 0, 0];
        path.extend_from_slice(&2u32.to_ne_bytes());
        path.extend(attribute(5, &[127, 0, 0, 3]));
        let mut record = record[..12].to_vec();
        record.extend(attribute(9, &path));
        parse_record(26, &record, &HashMap::new(), &mut info).unwrap();
        assert_eq!(info.routes[1].gateway, Some(Ipv4Addr::new(127, 0, 0, 3)));
        assert!(info.neighbors.is_empty());
        record[16] = 1;
        assert!(parse_record(26, &record, &HashMap::new(), &mut info).is_err());
    }

    #[test]
    fn attributes_reject_truncation_and_zero_lengths() {
        assert!(attributes(&[0, 0, 1, 0]).is_err());
        assert!(attributes(&[8, 0, 1, 0, 1]).is_err());
        assert_eq!(
            attributes(&[5, 0, 1, 0, 7, 0, 0, 0]).unwrap()[0],
            (1, &[7][..])
        );
    }

    #[test]
    fn only_resolved_destination_neighbors_have_macs() {
        let mut record = vec![2, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0];
        record.extend_from_slice(&[8, 0, 1, 0, 127, 0, 0, 1]);
        record.extend_from_slice(&[10, 0, 2, 0, 2, 3, 4, 5, 6, 7, 0, 0]);
        let mut info = NetworkInfo::default();
        parse_record(30, &record, &HashMap::new(), &mut info).unwrap();
        assert_eq!(info.neighbors[0].ip, Ipv4Addr::LOCALHOST);
        record[8] = 1;
        let mut info = NetworkInfo::default();
        parse_record(30, &record, &HashMap::new(), &mut info).unwrap();
        assert!(info.neighbors.is_empty());
    }

    #[test]
    fn reads_loopback_interface_without_probing_lan() {
        let info = network_info();
        assert!(
            info.interfaces.iter().any(|i| i.address.is_loopback()),
            "{:?}",
            info.warnings
        );
    }
}
