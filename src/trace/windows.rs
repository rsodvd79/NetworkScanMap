use super::{HopOutcome, Probe, TraceHop, cancelled};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::NetworkManagement::IpHelper::*;

static TOKEN: AtomicU64 = AtomicU64::new(1);

pub(super) struct Session(HANDLE);

impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: this successful IcmpCreateFile handle is owned and closed once.
        unsafe { IcmpCloseHandle(self.0) };
    }
}

impl Session {
    pub(super) fn new() -> Result<Self, String> {
        // SAFETY: no arguments; transfers ownership of a valid handle on success.
        let handle = unsafe { IcmpCreateFile() };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            // SAFETY: read the thread-local error immediately after failure.
            return Err(format!("Windows ICMP unavailable: {}", unsafe {
                GetLastError()
            }));
        }
        Ok(Self(handle))
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
        let mut payload = [0u8; 16];
        payload[..8].copy_from_slice(&TOKEN.fetch_add(1, Ordering::Relaxed).to_be_bytes());
        payload[8..12].copy_from_slice(&std::process::id().to_be_bytes());
        payload[12..].copy_from_slice(b"TRC1");
        let capacity = std::mem::size_of::<ICMP_ECHO_REPLY>() + payload.len() + 8;
        let mut buffer = vec![0usize; capacity.div_ceil(std::mem::size_of::<usize>())];
        if cancelled(cancel) {
            return Probe::Cancelled;
        }
        let (options, millis) = request_options(ttl, budget.saturating_sub(started.elapsed()));
        if millis == 0 {
            return Probe::Deadline;
        }
        // SAFETY: all buffers and the TTL options stay live for the complete
        // synchronous call. The native stack owns echo id/sequence allocation
        // and correlates quoted ICMP errors to this request/destination.
        let count = unsafe {
            IcmpSendEcho(
                self.0,
                u32::from_ne_bytes(ip.octets()),
                payload.as_ptr().cast(),
                payload.len() as u16,
                &options,
                buffer.as_mut_ptr().cast(),
                std::mem::size_of_val(buffer.as_slice()) as u32,
                millis,
            )
        };
        let error = if count == 0 {
            // SAFETY: read immediately following the failed call.
            Some(unsafe { GetLastError() })
        } else {
            None
        };
        if cancelled(cancel) {
            return Probe::Cancelled;
        }
        if matches!(error, Some(5 | 50 | 10013)) {
            return Probe::Unavailable(format!(
                "Windows ICMP traceroute denied or unsupported (error {})",
                error.unwrap_or_default()
            ));
        }
        let result = if let Some(error) = error {
            hop(
                ttl,
                if error == IP_SUCCESS {
                    HopOutcome::Error
                } else {
                    status_outcome(error)
                },
                Some(format!(
                    "Windows ICMP error {error} (no router address returned)"
                )),
            )
        } else {
            parse_reply(&buffer, count, ip, ttl, &payload)
        };
        Probe::Hop(result)
    }
}

fn request_options(ttl: u8, budget: Duration) -> (IP_OPTION_INFORMATION, u32) {
    (
        IP_OPTION_INFORMATION {
            Ttl: ttl,
            ..IP_OPTION_INFORMATION::default()
        },
        budget.as_millis().min(1000) as u32,
    )
}

fn hop(ttl: u8, outcome: HopOutcome, detail: Option<String>) -> TraceHop {
    TraceHop {
        ttl,
        outcome,
        detail,
        ..TraceHop::default()
    }
}

fn status_outcome(status: u32) -> HopOutcome {
    match status {
        IP_SUCCESS => HopOutcome::Destination,
        IP_REQ_TIMED_OUT => HopOutcome::Timeout,
        IP_TTL_EXPIRED_TRANSIT => HopOutcome::TimeExceeded,
        IP_DEST_NET_UNREACHABLE
        | IP_DEST_HOST_UNREACHABLE
        | IP_DEST_PROT_UNREACHABLE
        | IP_DEST_PORT_UNREACHABLE
        | IP_PACKET_TOO_BIG
        | IP_DEST_UNREACHABLE => HopOutcome::Unreachable,
        _ => HopOutcome::Error,
    }
}

fn in_buffer(buffer: &[usize], pointer: usize, length: usize) -> bool {
    let base = buffer.as_ptr() as usize;
    pointer >= base
        && pointer
            .checked_add(length)
            .zip(base.checked_add(std::mem::size_of_val(buffer)))
            .is_some_and(|(end, limit)| end <= limit)
}

fn parse_reply(
    buffer: &[usize],
    count: u32,
    destination: Ipv4Addr,
    ttl: u8,
    payload: &[u8],
) -> TraceHop {
    let invalid = || {
        hop(
            ttl,
            HopOutcome::Error,
            Some("Windows ICMP returned a malformed or mismatched reply".into()),
        )
    };
    if count != 1 || std::mem::size_of_val(buffer) < std::mem::size_of::<ICMP_ECHO_REPLY>() {
        return invalid();
    }
    // SAFETY: usize storage has the header's pointer alignment and checked extent.
    let reply = unsafe { &*buffer.as_ptr().cast::<ICMP_ECHO_REPLY>() };
    if reply.Status == IP_REQ_TIMED_OUT {
        return hop(ttl, HopOutcome::Timeout, None);
    }
    let source = Ipv4Addr::from(reply.Address.to_ne_bytes());
    if source.is_unspecified()
        || source.is_multicast()
        || source.is_broadcast()
        || source.octets()[0] == 0
        || reply.RoundTripTime > 1000
        || (reply.DataSize != 0
            && !in_buffer(buffer, reply.Data as usize, usize::from(reply.DataSize)))
        || (reply.Options.OptionsSize != 0
            && !in_buffer(
                buffer,
                reply.Options.OptionsData as usize,
                usize::from(reply.Options.OptionsSize),
            ))
    {
        return invalid();
    }
    if reply.Status == IP_SUCCESS {
        if source != destination
            || usize::from(reply.DataSize) != payload.len()
            || !in_buffer(buffer, reply.Data as usize, payload.len())
        {
            return invalid();
        }
        // SAFETY: the returned pointer and full length are inside live storage.
        if unsafe { std::slice::from_raw_parts(reply.Data.cast::<u8>(), payload.len()) } != payload
        {
            return invalid();
        }
    }
    let mut result = hop(
        ttl,
        status_outcome(reply.Status),
        Some(format!("Windows ICMP status {}", reply.Status)),
    );
    result.source = Some(source);
    result.latency_us = Some(u64::from(reply.RoundTripTime) * 1000);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_windows_ttl_and_requested_receive_timeout_are_preserved() {
        for (requested, expected) in [(50, 50), (400, 400), (1000, 1000), (5000, 1000)] {
            let (options, millis) = request_options(17, Duration::from_millis(requested));
            assert_eq!(options.Ttl, 17);
            assert_eq!(millis, expected);
        }
        assert_eq!(request_options(1, Duration::ZERO).1, 0);
    }

    #[test]
    fn trace_windows_validates_native_buffers_and_preserves_error_router() {
        let ip = Ipv4Addr::LOCALHOST;
        let payload = [1u8, 2, 3, 4];
        let size = std::mem::size_of::<ICMP_ECHO_REPLY>();
        let mut storage =
            vec![0usize; (size + payload.len()).div_ceil(std::mem::size_of::<usize>())];
        let data = unsafe { storage.as_mut_ptr().cast::<u8>().add(size) };
        // SAFETY: header and data have aligned, disjoint, capacity-checked extents.
        unsafe {
            std::ptr::copy_nonoverlapping(payload.as_ptr(), data, payload.len());
            storage
                .as_mut_ptr()
                .cast::<ICMP_ECHO_REPLY>()
                .write(ICMP_ECHO_REPLY {
                    Address: u32::from_ne_bytes(ip.octets()),
                    Status: IP_SUCCESS,
                    DataSize: payload.len() as u16,
                    Data: data.cast(),
                    ..ICMP_ECHO_REPLY::default()
                });
        }
        assert_eq!(
            parse_reply(&storage, 1, ip, 1, &payload).outcome,
            HopOutcome::Destination
        );
        assert_eq!(
            parse_reply(&storage, 2, ip, 1, &payload).outcome,
            HopOutcome::Error
        );
        // SAFETY: storage still owns the initialized reply header.
        unsafe {
            (*storage.as_mut_ptr().cast::<ICMP_ECHO_REPLY>()).Data = std::ptr::null_mut();
        }
        assert_eq!(
            parse_reply(&storage, 1, ip, 1, &payload).outcome,
            HopOutcome::Error
        );
        // ICMP errors may omit data but must preserve a valid router address.
        unsafe {
            let reply = &mut *storage.as_mut_ptr().cast::<ICMP_ECHO_REPLY>();
            reply.DataSize = 0;
            reply.Status = IP_TTL_EXPIRED_TRANSIT;
            reply.Address = u32::from_ne_bytes([127, 0, 0, 2]);
        }
        let result = parse_reply(&storage, 1, ip, 1, &payload);
        assert_eq!(result.outcome, HopOutcome::TimeExceeded);
        assert_eq!(result.source, Some(Ipv4Addr::new(127, 0, 0, 2)));
        assert_eq!(
            parse_reply(&[], 1, ip, 1, &payload).outcome,
            HopOutcome::Error
        );
    }
}
