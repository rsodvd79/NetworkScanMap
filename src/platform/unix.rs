use super::EchoResult;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static TOKEN: AtomicU64 = AtomicU64::new(1);

fn classify(error: io::Error) -> EchoResult {
    if matches!(
        error.raw_os_error(),
        Some(libc::EPERM | libc::EACCES | libc::EPROTONOSUPPORT | libc::EAFNOSUPPORT)
    ) {
        EchoResult::Unavailable(error.to_string())
    } else {
        EchoResult::LocalError(error.to_string())
    }
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        sum += u16::from_be_bytes([pair[0], pair.get(1).copied().unwrap_or(0)]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn reply_matches(packet: &[u8], ip: Ipv4Addr, id: u16, seq: u16, payload: &[u8]) -> bool {
    let icmp = if packet.first().is_some_and(|b| b >> 4 == 4) {
        if packet.len() < 20 || packet[9] != libc::IPPROTO_ICMP as u8 {
            return false;
        }
        let offset = usize::from(packet[0] & 15) * 4;
        #[cfg(target_os = "macos")]
        // Darwin ICMP datagram sockets deliver ip_len as native-endian payload length.
        let length = u16::from_ne_bytes([packet[2], packet[3]]) as usize + offset;
        #[cfg(not(target_os = "macos"))]
        let length = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        #[cfg(target_os = "macos")]
        let fragment = u16::from_ne_bytes([packet[6], packet[7]]);
        #[cfg(not(target_os = "macos"))]
        let fragment = u16::from_be_bytes([packet[6], packet[7]]);
        if offset < 20
            || length < offset
            || length > packet.len()
            || packet[12..16] != ip.octets()
            || fragment & 0x3fff != 0
        {
            return false;
        }
        &packet[offset..length]
    } else {
        packet
    };
    icmp.len() == payload.len() + 8
        && icmp[0] == 0
        && icmp[1] == 0
        && u16::from_be_bytes([icmp[4], icmp[5]]) == id
        && u16::from_be_bytes([icmp[6], icmp[7]]) == seq
        && &icmp[8..] == payload
        && checksum(icmp) == 0
}

pub(super) fn echo(ip: Ipv4Addr, timeout: Duration) -> EchoResult {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4));
    #[cfg(target_os = "linux")]
    let (socket, ping_socket) = match socket {
        Ok(s) => (s, true),
        Err(first) => match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
            Ok(s) => (s, false),
            Err(second) => {
                return classify(if first.kind() == io::ErrorKind::PermissionDenied {
                    first
                } else {
                    second
                });
            }
        },
    };
    #[cfg(not(target_os = "linux"))]
    let socket = match socket {
        Ok(s) => s,
        Err(e) => return classify(e),
    };
    if let Err(e) = socket.set_nonblocking(true) {
        return classify(e);
    }
    let token = TOKEN.fetch_add(1, Ordering::Relaxed);
    let seq = token as u16;
    let id = std::process::id() as u16;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut packet = [0u8; 32];
    packet[0] = 8;
    packet[4..6].copy_from_slice(&id.to_be_bytes());
    packet[6..8].copy_from_slice(&seq.to_be_bytes());
    packet[8..16].copy_from_slice(&token.to_be_bytes());
    packet[16..32].copy_from_slice(&stamp.to_be_bytes());
    let sum = checksum(&packet);
    packet[2..4].copy_from_slice(&sum.to_be_bytes());
    let destination = SocketAddrV4::new(ip, 0).into();
    let started = Instant::now();
    match socket.send_to(&packet, &destination) {
        Ok(n) if n == packet.len() => {}
        Ok(_) => return EchoResult::LocalError("Incomplete ICMP send".into()),
        Err(e) => return classify(e),
    }
    #[cfg(target_os = "linux")]
    let id = if ping_socket {
        // Linux ping sockets replace the identifier with their allocated local port.
        match socket.local_addr().ok().and_then(|s| s.as_socket_ipv4()) {
            Some(local) => local.port(),
            None => return EchoResult::LocalError("Cannot read ping socket identifier".into()),
        }
    } else {
        id
    };
    wait_reply(&socket, ip, id, seq, &packet[8..], started, timeout)
}

fn wait_reply(
    socket: &Socket,
    ip: Ipv4Addr,
    id: u16,
    seq: u16,
    payload: &[u8],
    started: Instant,
    timeout: Duration,
) -> EchoResult {
    loop {
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return EchoResult::NoReply;
        }
        let mut poll = libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = remaining
            .as_millis()
            .saturating_add(1)
            .min(i32::MAX as u128) as i32;
        // SAFETY: poll points to one initialized descriptor for a live owned socket.
        let ready = unsafe { libc::poll(&mut poll, 1, millis) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return classify(error);
        }
        if ready == 0 {
            continue;
        }
        let mut buffer = [0u8; 65536];
        // SAFETY: sockaddr and byte buffer are writable and lengths describe their capacity.
        let (length, source) = unsafe {
            let mut source: libc::sockaddr_in = std::mem::zeroed();
            let mut size = std::mem::size_of_val(&source) as libc::socklen_t;
            let n = libc::recvfrom(
                socket.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
                (&mut source as *mut libc::sockaddr_in).cast(),
                &mut size,
            );
            (n, (source, size))
        };
        if length < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return classify(error);
        }
        if source.1 as usize >= std::mem::size_of::<libc::sockaddr_in>()
            && source.0.sin_family as i32 == libc::AF_INET
            && Ipv4Addr::from(source.0.sin_addr.s_addr.to_ne_bytes()) == ip
            && reply_matches(&buffer[..length as usize], ip, id, seq, payload)
        {
            return EchoResult::Reply(started.elapsed());
        }
    }
}

pub(super) fn interface_name(index: u32) -> String {
    let mut name = [0 as libc::c_char; libc::IF_NAMESIZE];
    // SAFETY: if_indextoname receives a buffer of the required IF_NAMESIZE.
    if unsafe { libc::if_indextoname(index, name.as_mut_ptr()) }.is_null() {
        return format!("if#{index}");
    }
    // SAFETY: a successful if_indextoname returns a NUL-terminated name in this buffer.
    unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrelated_loopback_packets_do_not_extend_deadline() {
        let receiver = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        receiver
            .bind(&SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into())
            .unwrap();
        receiver.set_nonblocking(true).unwrap();
        let target = receiver.local_addr().unwrap().as_socket().unwrap();
        let sender = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let done = stop.clone();
        let noise = std::thread::spawn(move || {
            let started = Instant::now();
            while !done.load(Ordering::Relaxed) && started.elapsed() < Duration::from_secs(1) {
                sender.send_to(&[99; 32], target).unwrap();
                std::thread::sleep(Duration::from_millis(1));
            }
        });
        let started = Instant::now();
        let result = wait_reply(
            &receiver,
            Ipv4Addr::LOCALHOST,
            1,
            1,
            &[1; 24],
            started,
            Duration::from_millis(30),
        );
        let elapsed = started.elapsed();
        stop.store(true, Ordering::Relaxed);
        noise.join().unwrap();
        assert_eq!(result, EchoResult::NoReply);
        assert!(elapsed < Duration::from_millis(500), "{elapsed:?}");
    }

    #[test]
    fn echo_parser_rejects_wrong_sequence_payload_and_truncation() {
        let mut packet = vec![0, 0, 0, 0, 0, 7, 0, 9, 1, 2, 3];
        let sum = checksum(&packet);
        packet[2..4].copy_from_slice(&sum.to_be_bytes());
        assert!(reply_matches(
            &packet,
            Ipv4Addr::LOCALHOST,
            7,
            9,
            &[1, 2, 3]
        ));
        assert!(!reply_matches(
            &packet,
            Ipv4Addr::LOCALHOST,
            7,
            10,
            &[1, 2, 3]
        ));
        assert!(!reply_matches(
            &packet,
            Ipv4Addr::LOCALHOST,
            7,
            9,
            &[1, 2, 4]
        ));
        assert!(!reply_matches(
            &packet[..7],
            Ipv4Addr::LOCALHOST,
            7,
            9,
            &[1, 2, 3]
        ));
        let mut raw = vec![0; 20];
        raw[0] = 0x45;
        raw[9] = 1;
        raw[12..16].copy_from_slice(&Ipv4Addr::LOCALHOST.octets());
        raw.extend_from_slice(&packet);
        #[cfg(target_os = "macos")]
        raw[2..4].copy_from_slice(&(packet.len() as u16).to_ne_bytes());
        #[cfg(not(target_os = "macos"))]
        {
            let length = raw.len() as u16;
            raw[2..4].copy_from_slice(&length.to_be_bytes());
        }
        assert!(reply_matches(&raw, Ipv4Addr::LOCALHOST, 7, 9, &[1, 2, 3]));
        raw[0] = 0x4f;
        assert!(!reply_matches(&raw, Ipv4Addr::LOCALHOST, 7, 9, &[1, 2, 3]));
    }
}
