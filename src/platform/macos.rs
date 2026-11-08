use super::{Interface, Neighbor, NetworkInfo, Route, mac, prefix, unix};
use std::io;
use std::net::Ipv4Addr;

const MAX_TABLE: usize = 16 * 1024 * 1024;

pub(super) fn network_info() -> NetworkInfo {
    let mut info = NetworkInfo::default();
    if let Err(error) = interfaces(&mut info) {
        info.warnings.push(format!("IPv4 interfaces: {error}"));
    }
    match routing_table(libc::NET_RT_DUMP, 0).and_then(|bytes| parse_routes(&bytes, &mut info)) {
        Ok(()) => {}
        Err(error) => info.warnings.push(format!("IPv4 routes: {error}")),
    }
    // Darwin keeps ARP/LLINFO entries in a separate routing-table snapshot.
    match routing_table(libc::NET_RT_FLAGS, libc::RTF_LLINFO)
        .and_then(|bytes| parse_routes(&bytes, &mut info))
    {
        Ok(()) => {}
        Err(error) => info.warnings.push(format!("IPv4 neighbors: {error}")),
    }
    info.neighbors
        .sort_by(|a, b| (&a.interface, a.ip, &a.mac).cmp(&(&b.interface, b.ip, &b.mac)));
    info.neighbors
        .dedup_by(|a, b| a.interface == b.interface && a.ip == b.ip && a.mac == b.mac);
    if info.neighbors.is_empty() && requires_topology_permission() {
        info.warnings.push("MAC: macOS 27 richiede la capability Network Topology Observation (com.apple.developer.networking.topology-observation), firma e provisioning profile. La cache ARP puo essere nascosta; i MAC non disponibili non indicano apparati spenti.".into());
    }
    info
}

fn requires_topology_permission() -> bool {
    let mut bytes = [0u8; 64];
    let mut length = bytes.len();
    // SAFETY: the name is NUL-terminated; buffer and length are valid writable storage.
    let result = unsafe {
        libc::sysctlbyname(
            c"kern.osproductversion".as_ptr(),
            bytes.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    result == 0
        && length <= bytes.len()
        && std::str::from_utf8(&bytes[..length])
            .ok()
            .and_then(|version| version.split('.').next())
            .and_then(|major| major.trim_end_matches('\0').parse::<u32>().ok())
            .is_some_and(|major| major >= 27)
}

fn neighbor_mac(bytes: &[u8]) -> Option<String> {
    // Darwin's privacy placeholder is not an observed hardware address.
    if bytes == [2, 0, 0, 0, 0, 0] {
        None
    } else {
        mac(bytes)
    }
}

fn interfaces(info: &mut NetworkInfo) -> io::Result<()> {
    struct Addresses(*mut libc::ifaddrs);
    impl Drop for Addresses {
        fn drop(&mut self) {
            // SAFETY: this list was allocated by getifaddrs and is freed exactly once.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }
    let mut head = std::ptr::null_mut();
    // SAFETY: head is a writable out-pointer.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let list = Addresses(head);
    let mut current = list.0;
    let mut count = 0;
    while !current.is_null() {
        count += 1;
        if count > 65536 {
            return Err(io::Error::other("Oversized interface list"));
        }
        // SAFETY: pointers belong to the still-live OS-allocated getifaddrs list.
        let item = unsafe { &*current };
        if !item.ifa_addr.is_null() && !item.ifa_netmask.is_null() && !item.ifa_name.is_null() {
            // SAFETY: sa_family can be read from these valid sockaddr pointers.
            let ipv4 = unsafe {
                (*item.ifa_addr).sa_family as i32 == libc::AF_INET
                    && (*item.ifa_netmask).sa_family as i32 == libc::AF_INET
                    && (*item.ifa_addr).sa_len as usize >= std::mem::size_of::<libc::sockaddr_in>()
                    && (*item.ifa_netmask).sa_len >= 2
            };
            if ipv4 && item.ifa_flags & libc::IFF_UP as u32 != 0 {
                // SAFETY: address has full sockaddr_in size; Darwin's netmask can be
                // compressed, so only its advertised bytes are read.
                let (address, bits, name) = unsafe {
                    let address = &*item.ifa_addr.cast::<libc::sockaddr_in>();
                    let netmask = std::slice::from_raw_parts(
                        item.ifa_netmask.cast::<u8>(),
                        (*item.ifa_netmask).sa_len as usize,
                    );
                    (
                        Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()),
                        mask(netmask),
                        std::ffi::CStr::from_ptr(item.ifa_name)
                            .to_string_lossy()
                            .into_owned(),
                    )
                };
                if let Some(prefix) = bits {
                    info.interfaces.push(Interface {
                        name,
                        address,
                        prefix,
                    });
                } else {
                    info.warnings.push(format!("Noncontiguous mask on {name}"));
                }
            }
        }
        current = item.ifa_next;
    }
    Ok(())
}

fn routing_table(kind: i32, flags: i32) -> io::Result<Vec<u8>> {
    let mut mib = [libc::CTL_NET, libc::PF_ROUTE, 0, libc::AF_INET, kind, flags];
    // The table may grow between size and data queries; retry a bounded number of times.
    for _ in 0..4 {
        let mut size = 0;
        // SAFETY: MIB is initialized, size is writable, null oldp requests size only.
        if unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                std::ptr::null_mut(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if size > MAX_TABLE {
            return Err(io::Error::other("Oversized routing table"));
        }
        if size == 0 {
            return Ok(Vec::new());
        }
        let mut bytes = vec![0; size];
        // SAFETY: bytes has the advertised writable capacity and size is in/out.
        if unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                mib.len() as u32,
                bytes.as_mut_ptr().cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        } == 0
        {
            if size > bytes.len() {
                return Err(io::Error::other("Invalid sysctl table size"));
            }
            bytes.truncate(size);
            return Ok(bytes);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ENOMEM) {
            return Err(error);
        }
    }
    Err(io::Error::other("Routing table changed during snapshot"))
}

fn sockaddrs(bytes: &[u8], flags: i32) -> io::Result<[Option<&[u8]>; 8]> {
    let mut addresses = [None; 8];
    let mut offset = 0;
    for (index, slot) in addresses.iter_mut().enumerate() {
        if flags & (1 << index) == 0 {
            continue;
        }
        let length = *bytes
            .get(offset)
            .ok_or_else(|| io::Error::other("Missing sockaddr"))? as usize;
        let aligned = if length == 0 { 4 } else { (length + 3) & !3 };
        let record = bytes
            .get(offset..offset + aligned)
            .ok_or_else(|| io::Error::other("Truncated sockaddr"))?;
        if length == 1 {
            return Err(io::Error::other("Invalid sockaddr length"));
        }
        *slot = Some(&record[..length]);
        offset += aligned;
    }
    Ok(addresses)
}

fn address(bytes: &[u8]) -> Option<Ipv4Addr> {
    (bytes.len() >= 8 && bytes[1] as i32 == libc::AF_INET)
        .then(|| Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]))
}

fn mask(bytes: &[u8]) -> Option<u8> {
    // Darwin compresses masks; family/port bytes are mask bytes too (often 0xff),
    // not an address family. Only the four sin_addr bytes determine the IPv4 mask.
    let mut octets = [0; 4];
    for (i, b) in octets.iter_mut().enumerate() {
        *b = bytes.get(i + 4).copied().unwrap_or(0);
    }
    prefix(octets.into())
}

fn parse_routes(mut bytes: &[u8], info: &mut NetworkInfo) -> io::Result<()> {
    while !bytes.is_empty() {
        let header_size = std::mem::size_of::<libc::rt_msghdr>();
        if bytes.len() < header_size {
            return Err(io::Error::other("Truncated route header"));
        }
        // SAFETY: size was checked; read_unaligned avoids any buffer alignment requirement.
        let header = unsafe { bytes.as_ptr().cast::<libc::rt_msghdr>().read_unaligned() };
        let length = header.rtm_msglen as usize;
        if length < header_size || length > bytes.len() {
            return Err(io::Error::other("Invalid route message length"));
        }
        let record = &bytes[header_size..length];
        bytes = &bytes[length..];
        if header.rtm_version as i32 != libc::RTM_VERSION {
            continue;
        }
        let a = sockaddrs(record, header.rtm_addrs)?;
        let Some(destination) = a[0].and_then(address) else {
            continue;
        };
        let interface = unix::interface_name(header.rtm_index as u32);
        if header.rtm_flags & libc::RTF_LLINFO != 0 {
            if let Some(link) = a[1].filter(|b| b.len() >= 8 && b[1] as i32 == libc::AF_LINK) {
                let start = 8 + link[5] as usize;
                let end = start + link[6] as usize;
                if let Some(mac) = link.get(start..end).and_then(neighbor_mac)
                    && !destination.is_unspecified()
                    && !destination.is_multicast()
                    && !destination.is_broadcast()
                {
                    info.neighbors.push(Neighbor {
                        ip: destination,
                        mac,
                        interface,
                    });
                }
            }
            continue;
        }
        if header.rtm_flags & libc::RTF_UP == 0
            || header.rtm_flags & (libc::RTF_REJECT | libc::RTF_BLACKHOLE) != 0
        {
            continue;
        }
        let bits = if header.rtm_flags & libc::RTF_HOST != 0 {
            Some(32)
        } else {
            a[2].and_then(mask)
                .or_else(|| destination.is_unspecified().then_some(0))
        };
        let Some(bits) = bits else {
            info.warnings.push("Route has no valid IPv4 netmask".into());
            continue;
        };
        if let Ok(network) = ipnet::Ipv4Net::new(destination, bits) {
            let gateway = if header.rtm_flags & libc::RTF_GATEWAY != 0 {
                a[1].and_then(address).filter(|ip| !ip.is_unspecified())
            } else {
                None
            };
            info.routes.push(Route {
                network: network.trunc(),
                gateway,
                interface,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(flags: i32, addresses: &[u8], address_flags: i32) -> Vec<u8> {
        let header_size = std::mem::size_of::<libc::rt_msghdr>();
        let mut bytes = vec![0; header_size];
        let length = (header_size + addresses.len()) as u16;
        bytes[..2].copy_from_slice(&length.to_ne_bytes());
        bytes[std::mem::offset_of!(libc::rt_msghdr, rtm_version)] = libc::RTM_VERSION as u8;
        let offset = std::mem::offset_of!(libc::rt_msghdr, rtm_flags);
        bytes[offset..offset + 4].copy_from_slice(&flags.to_ne_bytes());
        let offset = std::mem::offset_of!(libc::rt_msghdr, rtm_addrs);
        bytes[offset..offset + 4].copy_from_slice(&address_flags.to_ne_bytes());
        bytes.extend_from_slice(addresses);
        bytes
    }

    #[test]
    fn cache_parser_rejects_privacy_placeholder_but_keeps_real_locally_administered_macs() {
        let destination = [16, 2, 0, 0, 192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        let link = [
            20, 18, 0, 0, 6, 3, 6, 0, b'e', b'n', b'0', 2, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let mut addresses = destination.to_vec();
        addresses.extend_from_slice(&link);
        let reply = message(
            libc::RTF_UP | libc::RTF_LLINFO | libc::RTF_HOST,
            &addresses,
            3,
        );
        let mut info = NetworkInfo::default();
        parse_routes(&reply, &mut info).unwrap();
        assert!(info.neighbors.is_empty());
        assert_eq!(
            neighbor_mac(&[2, 3, 4, 5, 6, 7]).as_deref(),
            Some("02:03:04:05:06:07")
        );
    }

    #[test]
    fn neighbor_mac_belongs_only_to_destination_not_routed_hosts() {
        let destination = [16, 2, 0, 0, 127, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0];
        let link = [14, 18, 0, 0, 6, 0, 6, 0, 2, 3, 4, 5, 6, 7, 0, 0];
        let mut addresses = destination.to_vec();
        addresses.extend_from_slice(&link);
        let mut info = NetworkInfo::default();
        parse_routes(
            &message(
                libc::RTF_UP | libc::RTF_LLINFO | libc::RTF_HOST,
                &addresses,
                3,
            ),
            &mut info,
        )
        .unwrap();
        assert_eq!(info.neighbors.len(), 1);
        assert_eq!(info.neighbors[0].ip, Ipv4Addr::new(127, 0, 0, 2));
        let mut addresses = vec![16, 2, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        addresses.extend_from_slice(&destination);
        addresses.extend_from_slice(&[5, 255, 255, 255, 255, 0, 0, 0]);
        parse_routes(
            &message(libc::RTF_UP | libc::RTF_GATEWAY, &addresses, 7),
            &mut info,
        )
        .unwrap();
        assert_eq!(info.routes[0].network.to_string(), "10.0.0.0/8");
        assert_eq!(info.routes[0].gateway, Some(Ipv4Addr::new(127, 0, 0, 2)));
        assert_eq!(info.neighbors.len(), 1);
        assert!(info.warnings.is_empty());
    }

    #[test]
    fn compressed_masks_and_sockaddr_bounds() {
        assert_eq!(mask(&[7, 0, 0, 0, 255, 255, 255]), Some(24));
        assert_eq!(mask(&[5, 255, 255, 255, 255]), Some(8));
        assert_eq!(mask(&[7, 255, 255, 255, 255, 255, 255]), Some(24));
        assert_eq!(mask(&[7, 255, 255, 255, 255, 0, 255]), None);
        assert_eq!(mask(&[]), Some(0));
        assert!(sockaddrs(&[16, 2, 0, 0], 1).is_err());
        assert!(sockaddrs(&[0, 0, 0, 0], 1).is_ok());
        assert!(parse_routes(&[0; 8], &mut NetworkInfo::default()).is_err());
    }

    #[test]
    fn reads_loopback_interface_without_probing_lan() {
        let info = network_info();
        assert!(
            info.interfaces.iter().any(|i| i.address.is_loopback()),
            "{:?}",
            info.warnings
        );
        assert!(
            info.routes
                .iter()
                .any(|r| r.network.contains(&Ipv4Addr::LOCALHOST)),
            "{:?}",
            info.warnings
        );
    }
}
