use super::{HopOutcome, Probe, TraceHop, cancelled};
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static TOKEN: AtomicU64 = AtomicU64::new(1);

pub(super) struct Session {
    socket: Socket,
    token: u64,
}

impl Session {
    pub(super) fn new() -> Result<Self, String> {
        // Linux ping sockets do not deliver ICMP errors via normal recvfrom.
        // Do not turn a missing raw capability into thirty misleading timeouts.
        #[cfg(target_os = "linux")]
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)).map_err(|e| {
            format!(
                "Linux traceroute requires an already-permitted raw ICMP socket \
                 (CAP_NET_RAW); ping-socket MSG_ERRQUEUE is not implemented: {e}"
            )
        })?;
        // Darwin ICMP datagram sockets deliver both echo replies and ICMP errors,
        // including an IPv4 header whose length/fragment fields are host-endian.
        #[cfg(target_os = "macos")]
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))
            .map_err(|e| format!("Darwin ICMP datagram traceroute unavailable: {e}"))?;
        socket
            .set_nonblocking(true)
            .map_err(|e| format!("Cannot configure nonblocking ICMP receive: {e}"))?;
        Ok(Self {
            socket,
            token: TOKEN.fetch_add(1, Ordering::Relaxed),
        })
    }

    pub(super) fn probe(
        &mut self,
        ip: Ipv4Addr,
        ttl: u8,
        budget: Duration,
        cancel: &AtomicBool,
    ) -> Probe {
        let started = Instant::now();
        if cancelled(cancel) {
            return Probe::Cancelled;
        }
        if let Err(e) = self.socket.set_ttl_v4(u32::from(ttl)) {
            return error_hop(ttl, e);
        }
        let mut packet = [0u8; 32];
        packet[0] = 8;
        let id = (std::process::id() as u16) ^ (self.token >> 16) as u16;
        let seq = (self.token as u16).wrapping_add(u16::from(ttl));
        packet[4..6].copy_from_slice(&id.to_be_bytes());
        packet[6..8].copy_from_slice(&seq.to_be_bytes());
        packet[8..16].copy_from_slice(&self.token.to_be_bytes());
        packet[16..32].copy_from_slice(
            &SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                .to_be_bytes(),
        );
        let sum = checksum(&packet);
        packet[2..4].copy_from_slice(&sum.to_be_bytes());
        if cancelled(cancel) {
            return Probe::Cancelled;
        }
        if started.elapsed() >= budget {
            return Probe::Deadline;
        }
        match self
            .socket
            .send_to(&packet, &SocketAddrV4::new(ip, 0).into())
        {
            Ok(n) if n == packet.len() => {}
            Ok(_) => return error_hop(ttl, io::Error::other("Incomplete ICMP echo send")),
            Err(e) => return error_hop(ttl, e),
        }
        wait_reply(&self.socket, ip, ttl, &packet, started, budget, cancel)
    }
}

fn timeout_hop(ttl: u8) -> TraceHop {
    TraceHop {
        ttl,
        ..TraceHop::default()
    }
}

fn error_hop(ttl: u8, error: io::Error) -> Probe {
    Probe::Hop(TraceHop {
        ttl,
        outcome: HopOutcome::Error,
        detail: Some(error.to_string()),
        ..TraceHop::default()
    })
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([
            pair[0],
            pair.get(1).copied().unwrap_or(0),
        ]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn valid_source(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast() && ip.octets()[0] != 0
}

/// `quoted` headers are wire-format, possibly truncated after the echo header.
/// Only outer Darwin headers have their length/fragment fields rewritten.
fn ipv4_payload(packet: &[u8], quoted: bool) -> Option<&[u8]> {
    if packet.len() < 20 || packet[0] >> 4 != 4 || packet[9] != 1 {
        return None;
    }
    let offset = usize::from(packet[0] & 15) * 4;
    let length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    let fragment = u16::from_be_bytes([packet[6], packet[7]]);
    #[cfg(target_os = "macos")]
    let (length, fragment) = if quoted {
        (length, fragment)
    } else {
        (
            usize::from(u16::from_ne_bytes([packet[2], packet[3]])) + offset,
            u16::from_ne_bytes([packet[6], packet[7]]),
        )
    };
    if offset < 20
        || offset > packet.len()
        || length < offset + 8
        || (!quoted && length != packet.len())
        || fragment & 0x3fff != 0
    {
        return None;
    }
    Some(&packet[offset..length.min(packet.len())])
}

fn parse_reply(
    packet: &[u8],
    source: Ipv4Addr,
    destination: Ipv4Addr,
    request: &[u8],
) -> Option<(HopOutcome, String)> {
    if !valid_source(source) {
        return None;
    }
    let icmp = ipv4_payload(packet, false)?;
    if packet[12..16] != source.octets() || checksum(icmp) != 0 {
        return None;
    }
    match (icmp[0], icmp[1]) {
        (0, 0)
            if source == destination
                && icmp.len() == request.len()
                && icmp[4..] == request[4..] =>
        {
            Some((HopOutcome::Destination, "ICMP echo reply (0/0)".into()))
        }
        (3, code @ 0..=15) | (11, code @ 0) => {
            let inner = icmp.get(8..)?;
            let echo = ipv4_payload(inner, true)?;
            let offset = usize::from(inner[0] & 15) * 4;
            let original_length = usize::from(u16::from_be_bytes([inner[2], inner[3]]));
            if inner[16..20] != destination.octets()
                || !valid_source(Ipv4Addr::new(inner[12], inner[13], inner[14], inner[15]))
                || original_length != offset + request.len()
                || echo.len() < 8
                || echo.len() > request.len()
                || echo != &request[..echo.len()]
            {
                return None;
            }
            // RFC 792 guarantees only eight quoted bytes. Check the original
            // checksum/id/sequence and every payload byte the router included.
            Some((
                if icmp[0] == 11 {
                    HopOutcome::TimeExceeded
                } else {
                    HopOutcome::Unreachable
                },
                format!("ICMP type {} code {code}", icmp[0]),
            ))
        }
        _ => None,
    }
}

fn wait_reply(
    socket: &Socket,
    ip: Ipv4Addr,
    ttl: u8,
    request: &[u8],
    started: Instant,
    budget: Duration,
    cancel: &AtomicBool,
) -> Probe {
    let mut buffer = [0u8; 65536];
    loop {
        if cancelled(cancel) {
            return Probe::Cancelled;
        }
        let remaining = budget.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Probe::Hop(timeout_hop(ttl));
        }
        let mut poll = libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = remaining.as_millis().min(20) as i32;
        // SAFETY: poll references one initialized descriptor of a live socket.
        let ready = unsafe { libc::poll(&mut poll, 1, millis) };
        if cancelled(cancel) {
            return Probe::Cancelled;
        }
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return error_hop(ttl, error);
        }
        if ready == 0 {
            continue;
        }
        if poll.revents & libc::POLLNVAL != 0 {
            return error_hop(ttl, io::Error::other("Invalid ICMP descriptor"));
        }
        // SAFETY: initialized address and writable byte buffer with their exact capacities.
        let (length, source, address_length) = unsafe {
            let mut source: libc::sockaddr_in = std::mem::zeroed();
            let mut size = std::mem::size_of_val(&source) as libc::socklen_t;
            let length = libc::recvfrom(
                socket.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
                (&mut source as *mut libc::sockaddr_in).cast(),
                &mut size,
            );
            (length, source, size)
        };
        if length < 0 {
            let error = io::Error::last_os_error();
            if matches!(
                error.kind(),
                io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
            ) && poll.revents & (libc::POLLERR | libc::POLLHUP) == 0
            {
                continue;
            }
            return error_hop(ttl, error);
        }
        if cancelled(cancel) {
            return Probe::Cancelled;
        }
        if started.elapsed() >= budget {
            return Probe::Hop(timeout_hop(ttl));
        }
        if address_length as usize != std::mem::size_of::<libc::sockaddr_in>()
            || source.sin_family as i32 != libc::AF_INET
            || length as usize > buffer.len()
        {
            continue;
        }
        let source = Ipv4Addr::from(source.sin_addr.s_addr.to_ne_bytes());
        if let Some((outcome, detail)) =
            parse_reply(&buffer[..length as usize], source, ip, request)
        {
            let elapsed = started.elapsed();
            if elapsed >= budget {
                return Probe::Hop(timeout_hop(ttl));
            }
            return Probe::Hop(TraceHop {
                ttl,
                source: Some(source),
                latency_us: Some(elapsed.as_micros().min(u64::MAX as u128) as u64),
                outcome,
                detail: Some(detail),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wire_ip(source: Ipv4Addr, destination: Ipv4Addr, payload: &[u8], outer: bool) -> Vec<u8> {
        let mut bytes = vec![0u8; 20];
        bytes[0] = 0x45;
        bytes[9] = 1;
        bytes[12..16].copy_from_slice(&source.octets());
        bytes[16..20].copy_from_slice(&destination.octets());
        bytes[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        #[cfg(target_os = "macos")]
        if outer {
            bytes[2..4].copy_from_slice(&(payload.len() as u16).to_ne_bytes());
        }
        let _ = outer;
        bytes.extend_from_slice(payload);
        bytes
    }

    fn fix_checksum(bytes: &mut [u8]) {
        bytes[2..4].fill(0);
        let sum = checksum(bytes);
        bytes[2..4].copy_from_slice(&sum.to_be_bytes());
    }

    fn request() -> Vec<u8> {
        let mut request = vec![8, 0, 0, 0, 0x12, 0x34, 0, 7, 11, 12, 13, 14];
        fix_checksum(&mut request);
        request
    }

    #[test]
    fn trace_echo_requires_source_id_sequence_payload_and_checksum() {
        let ip = Ipv4Addr::LOCALHOST;
        let request = request();
        let mut echo = request.clone();
        echo[0] = 0;
        fix_checksum(&mut echo);
        let packet = wire_ip(ip, ip, &echo, true);
        assert_eq!(
            parse_reply(&packet, ip, ip, &request).unwrap().0,
            HopOutcome::Destination
        );
        for index in [4, 6, 8] {
            let mut changed = echo.clone();
            changed[index] ^= 1;
            fix_checksum(&mut changed);
            assert!(parse_reply(&wire_ip(ip, ip, &changed, true), ip, ip, &request).is_none());
        }
        assert!(parse_reply(&packet, Ipv4Addr::new(127, 0, 0, 2), ip, &request).is_none());
        for n in 0..packet.len() {
            assert!(parse_reply(&packet[..n], ip, ip, &request).is_none());
        }
    }

    #[test]
    fn trace_errors_require_matching_inner_destination_echo_and_available_payload() {
        let local = Ipv4Addr::LOCALHOST;
        let destination = Ipv4Addr::new(192, 0, 2, 1);
        let router = Ipv4Addr::new(192, 0, 2, 2);
        let request = request();
        let inner = wire_ip(local, destination, &request, false);
        for quoted in [28, inner.len()] {
            for kind in [3, 11] {
                let mut error = vec![kind, 0, 0, 0, 0, 0, 0, 0];
                error.extend_from_slice(&inner[..quoted]);
                fix_checksum(&mut error);
                let packet = wire_ip(router, local, &error, true);
                let expected = if kind == 3 {
                    HopOutcome::Unreachable
                } else {
                    HopOutcome::TimeExceeded
                };
                assert_eq!(
                    parse_reply(&packet, router, destination, &request)
                        .unwrap()
                        .0,
                    expected
                );
                // Inner destination, fragment flag, checksum, identifier, sequence, payload.
                for offset in [24, 14, 30, 32, 34, 36] {
                    if offset >= error.len() {
                        continue;
                    }
                    let mut changed = error.clone();
                    changed[offset] ^= 1;
                    fix_checksum(&mut changed);
                    assert!(
                        parse_reply(
                            &wire_ip(router, local, &changed, true),
                            router,
                            destination,
                            &request
                        )
                        .is_none(),
                        "accepted changed offset {offset}"
                    );
                }
            }
        }
    }

    #[test]
    fn trace_stray_traffic_does_not_extend_deadline_and_wait_is_cancellable() {
        let receiver = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        receiver
            .bind(&SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into())
            .unwrap();
        receiver.set_nonblocking(true).unwrap();
        let target = receiver.local_addr().unwrap().as_socket().unwrap();
        let sender = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let stop = AtomicBool::new(false);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let started = Instant::now();
                while !cancelled(&stop) && started.elapsed() < Duration::from_millis(200) {
                    sender.send_to(&[99; 32], target).unwrap();
                    std::thread::sleep(Duration::from_millis(1));
                }
            });
            let started = Instant::now();
            let result = wait_reply(
                &receiver,
                Ipv4Addr::LOCALHOST,
                1,
                &request(),
                started,
                Duration::from_millis(30),
                &stop,
            );
            assert!(matches!(
                result,
                Probe::Hop(TraceHop {
                    outcome: HopOutcome::Timeout,
                    ..
                })
            ));
            assert!(started.elapsed() < Duration::from_millis(200));
            stop.store(true, Ordering::Release);
        });
        stop.store(false, Ordering::Release);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(20));
                stop.store(true, Ordering::Release);
            });
            let started = Instant::now();
            assert!(matches!(
                wait_reply(
                    &receiver,
                    Ipv4Addr::LOCALHOST,
                    1,
                    &request(),
                    started,
                    Duration::from_secs(1),
                    &stop
                ),
                Probe::Cancelled
            ));
            assert!(started.elapsed() < Duration::from_millis(300));
        });
    }
}
