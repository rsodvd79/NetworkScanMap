//! Native IPv4 probes and local network evidence. Interfaces are display context,
//! not a claim that probes are bound to an interface. Neighbor caches are historical
//! destination-IP observations, never evidence of current reachability.

use std::net::Ipv4Addr;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EchoResult {
    Reply(Duration),
    NoReply,
    Unavailable(String),
    LocalError(String),
}

#[derive(Clone, Debug, Default)]
pub struct NetworkInfo {
    pub interfaces: Vec<Interface>,
    pub neighbors: Vec<Neighbor>,
    pub routes: Vec<Route>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct Interface {
    pub name: String,
    pub address: Ipv4Addr,
    pub prefix: u8,
}

#[derive(Clone, Debug)]
pub struct Neighbor {
    pub ip: Ipv4Addr,
    pub mac: String,
    pub interface: String,
}

#[derive(Clone, Debug)]
pub struct Route {
    pub network: ipnet::Ipv4Net,
    pub gateway: Option<Ipv4Addr>,
    pub interface: String,
}

#[cfg(target_os = "macos")]
#[path = "platform/macos.rs"]
mod native;
#[cfg(target_os = "linux")]
#[path = "platform/linux.rs"]
mod native;
#[cfg(windows)]
#[path = "platform/windows.rs"]
mod native;
#[cfg(unix)]
#[path = "platform/unix.rs"]
mod unix;

/// A zero timeout performs no I/O. Permission/unsupported-method failures are
/// `Unavailable`, not negative observations. This call blocks for its probe budget.
pub fn echo(ip: Ipv4Addr, timeout: Duration) -> EchoResult {
    if timeout.is_zero() {
        return EchoResult::NoReply;
    }
    if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
        return EchoResult::LocalError("ICMP requires a unicast IPv4 destination".into());
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        unix::echo(ip, timeout)
    }
    #[cfg(windows)]
    {
        native::echo(ip, timeout)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        EchoResult::Unavailable("Native ICMP is unsupported on this system".into())
    }
}

/// Reads local IPv4 interfaces, forwarding entries and resolved neighbor caches.
/// Failures leave successfully obtained evidence intact and append warnings.
pub fn network_info() -> NetworkInfo {
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    {
        native::network_info()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        NetworkInfo {
            warnings: vec!["Native network tables are unsupported on this system".into()],
            ..NetworkInfo::default()
        }
    }
}

fn mac(bytes: &[u8]) -> Option<String> {
    if bytes.len() != 6 || bytes.iter().all(|b| *b == 0) || bytes[0] & 1 != 0 {
        return None;
    }
    Some(
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

#[cfg(any(target_os = "macos", windows, test))]
fn prefix(mask: Ipv4Addr) -> Option<u8> {
    let value = u32::from(mask);
    let bits = value.leading_ones() as u8;
    (value
        == if bits == 0 {
            0
        } else {
            u32::MAX << (32 - bits)
        })
    .then_some(bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_noncontiguous_masks_and_invalid_macs() {
        assert_eq!(prefix(Ipv4Addr::new(255, 0, 255, 0)), None);
        assert_eq!(prefix(Ipv4Addr::UNSPECIFIED), Some(0));
        assert_eq!(prefix(Ipv4Addr::BROADCAST), Some(32));
        assert_eq!(mac(&[0; 6]), None);
        assert_eq!(mac(&[1, 2, 3, 4, 5, 6]), None);
        assert_eq!(
            mac(&[2, 2, 3, 4, 5, 6]).as_deref(),
            Some("02:02:03:04:05:06")
        );
    }

    #[test]
    fn loopback_echo_or_explicit_unavailability() {
        let started = std::time::Instant::now();
        let result = echo(Ipv4Addr::LOCALHOST, Duration::from_millis(400));
        assert!(
            matches!(result, EchoResult::Reply(_) | EchoResult::Unavailable(_)),
            "{result:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn zero_budget_does_not_probe() {
        assert_eq!(
            echo(Ipv4Addr::LOCALHOST, Duration::ZERO),
            EchoResult::NoReply
        );
    }
}
