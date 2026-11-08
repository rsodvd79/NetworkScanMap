use super::{EchoResult, Interface, Neighbor, NetworkInfo, Route, mac, prefix};
use std::io;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use windows_sys::Win32::Foundation::{GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, NlnsIncomplete, NlnsUnreachable, SOCKADDR_INET,
};

static TOKEN: AtomicU64 = AtomicU64::new(1);

struct IcmpHandle(HANDLE);
impl Drop for IcmpHandle {
    fn drop(&mut self) {
        // SAFETY: this is a successful IcmpCreateFile handle, closed exactly once.
        unsafe { IcmpCloseHandle(self.0) };
    }
}

fn echo_error(code: u32) -> EchoResult {
    match code {
        IP_REQ_TIMED_OUT => EchoResult::NoReply,
        5 | 50 | 10013 => {
            EchoResult::Unavailable(io::Error::from_raw_os_error(code as i32).to_string())
        }
        _ => EchoResult::LocalError(format!("Windows ICMP error {code}")),
    }
}

pub(super) fn echo(ip: Ipv4Addr, timeout: Duration) -> EchoResult {
    // SAFETY: IcmpCreateFile takes no arguments and transfers ownership on success.
    let handle = unsafe { IcmpCreateFile() };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        // SAFETY: read thread-local error immediately after the failed API.
        return echo_error(unsafe { GetLastError() });
    }
    let handle = IcmpHandle(handle);
    let mut payload = [0u8; 16];
    payload[..8].copy_from_slice(&TOKEN.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    payload[8..12].copy_from_slice(&std::process::id().to_be_bytes());
    payload[12..].copy_from_slice(b"NSM1");
    let capacity = std::mem::size_of::<ICMP_ECHO_REPLY>() + payload.len() + 8;
    // usize storage ensures the ICMP_ECHO_REPLY alignment without unaligned dereferences.
    let mut buffer = vec![0usize; capacity.div_ceil(std::mem::size_of::<usize>())];
    let buffer_size = std::mem::size_of_val(buffer.as_slice());
    let millis = timeout.as_millis().max(1).min((u32::MAX - 1) as u128) as u32;
    // SAFETY: request/reply buffers are live and their specified lengths fit the allocations.
    // Windows manages echo identifiers/sequences internally; we also verify source and payload.
    let count = unsafe {
        IcmpSendEcho(
            handle.0,
            u32::from_ne_bytes(ip.octets()),
            payload.as_ptr().cast(),
            payload.len() as u16,
            std::ptr::null(),
            buffer.as_mut_ptr().cast(),
            buffer_size as u32,
            millis,
        )
    };
    if count == 0 {
        // SAFETY: read thread-local error before any other native call.
        return echo_error(unsafe { GetLastError() });
    }
    // SAFETY: the buffer is aligned and large enough for the reply header.
    let reply = unsafe { &*buffer.as_ptr().cast::<ICMP_ECHO_REPLY>() };
    if reply.Status != IP_SUCCESS {
        return echo_error(reply.Status);
    }
    if reply.Address != u32::from_ne_bytes(ip.octets()) || reply.DataSize as usize != payload.len()
    {
        return EchoResult::LocalError("Windows ICMP returned a mismatched reply".into());
    }
    let base = buffer.as_ptr() as usize;
    let data = reply.Data as usize;
    if data < base
        || data
            .checked_add(payload.len())
            .is_none_or(|end| end > base + buffer_size)
    {
        return EchoResult::LocalError("Windows ICMP returned an invalid payload pointer".into());
    }
    // SAFETY: the pointer and payload extent have been checked inside the live allocation.
    if unsafe { std::slice::from_raw_parts(reply.Data.cast::<u8>(), payload.len()) } != payload {
        return EchoResult::LocalError("Windows ICMP returned a mismatched payload".into());
    }
    EchoResult::Reply
}

fn interface_name(index: u32) -> String {
    let mut luid = NET_LUID_LH::default();
    let mut alias = [0u16; 257];
    // SAFETY: output objects are valid and alias length is its capacity.
    if unsafe { ConvertInterfaceIndexToLuid(index, &mut luid) } == 0
        && unsafe { ConvertInterfaceLuidToAlias(&luid, alias.as_mut_ptr(), alias.len()) } == 0
    {
        let end = alias.iter().position(|c| *c == 0).unwrap_or(alias.len());
        return String::from_utf16_lossy(&alias[..end]);
    }
    format!("if#{index}")
}

fn ipv4(address: &SOCKADDR_INET) -> Option<Ipv4Addr> {
    // SAFETY: the family field is common to the union members; AF_INET selects Ipv4.
    unsafe {
        (address.si_family == AF_INET)
            .then(|| Ipv4Addr::from(address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()))
    }
}

pub(super) fn network_info() -> NetworkInfo {
    let mut info = NetworkInfo::default();
    for (label, result) in [
        ("IPv4 interfaces", interfaces(&mut info)),
        ("IPv4 routes", routes(&mut info)),
        ("IPv4 neighbors", neighbors(&mut info)),
    ] {
        if let Err(e) = result {
            info.warnings.push(format!("{label}: {e}"));
        }
    }
    info
}

fn error(code: u32) -> io::Error {
    io::Error::from_raw_os_error(code as i32)
}

fn interfaces(info: &mut NetworkInfo) -> io::Result<()> {
    let mut size = 0u32;
    // SAFETY: null table requests its required size.
    let status = unsafe { GetIpAddrTable(std::ptr::null_mut(), &mut size, 0) };
    if status != 0 && status != 122 {
        return Err(error(status));
    }
    for _ in 0..4 {
        if !(4..=16 * 1024 * 1024).contains(&size) {
            return Err(io::Error::other("Invalid IPv4 address table size"));
        }
        let mut storage = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
        let capacity = std::mem::size_of_val(storage.as_slice());
        let table = storage.as_mut_ptr().cast::<MIB_IPADDRTABLE>();
        size = capacity as u32;
        // SAFETY: table is aligned writable storage with size describing its allocation.
        let status = unsafe { GetIpAddrTable(table, &mut size, 0) };
        if status == 122 {
            continue;
        }
        if status != 0 {
            return Err(error(status));
        }
        if size as usize > capacity {
            return Err(io::Error::other("Invalid returned table size"));
        }
        // SAFETY: the table has at least the count field and API returned success.
        let count = unsafe { (*table).dwNumEntries } as usize;
        let offset = std::mem::offset_of!(MIB_IPADDRTABLE, table);
        let row_size = std::mem::size_of::<MIB_IPADDRROW_XP>();
        if count > 65536
            || count
                .checked_mul(row_size)
                .and_then(|n| n.checked_add(offset))
                .is_none_or(|n| n > size as usize)
        {
            return Err(io::Error::other("Invalid IPv4 table row count"));
        }
        // SAFETY: row count, alignment and extent were verified in caller-owned storage.
        let rows = unsafe {
            std::slice::from_raw_parts(
                storage
                    .as_ptr()
                    .cast::<u8>()
                    .add(offset)
                    .cast::<MIB_IPADDRROW_XP>(),
                count,
            )
        };
        for row in rows {
            let address = Ipv4Addr::from(row.dwAddr.to_ne_bytes());
            if address.is_unspecified() || row.wType & (8 | 64) != 0 {
                continue;
            }
            let name = interface_name(row.dwIndex);
            if let Some(prefix) = prefix(Ipv4Addr::from(row.dwMask.to_ne_bytes())) {
                info.interfaces.push(Interface {
                    name,
                    address,
                    prefix,
                });
            } else {
                info.warnings.push(format!("Noncontiguous mask on {name}"));
            }
        }
        return Ok(());
    }
    Err(io::Error::other(
        "IPv4 address table changed during snapshot",
    ))
}

struct MibTable(*mut core::ffi::c_void);
impl Drop for MibTable {
    fn drop(&mut self) {
        // SAFETY: the table was allocated by a successful IP Helper call.
        unsafe { FreeMibTable(self.0) };
    }
}

fn routes(info: &mut NetworkInfo) -> io::Result<()> {
    let mut table = std::ptr::null_mut();
    // SAFETY: writable out-pointer; on success the returned allocation is owned by us.
    let status = unsafe { GetIpForwardTable2(AF_INET, &mut table) };
    if status != 0 {
        return Err(error(status));
    }
    if table.is_null() {
        return Err(io::Error::other("Null forwarding table"));
    }
    let _owner = MibTable(table.cast());
    // SAFETY: a successful API gives a valid header; rows are within its OS-owned allocation.
    let count = unsafe { (*table).NumEntries } as usize;
    if count > 65536 {
        return Err(io::Error::other("Oversized forwarding table"));
    }
    // SAFETY: IP Helper guarantees NumEntries rows. The API provides no allocation byte size.
    let rows = unsafe {
        std::slice::from_raw_parts(
            std::ptr::addr_of!((*table).Table).cast::<MIB_IPFORWARD_ROW2>(),
            count,
        )
    };
    for row in rows {
        let Some(destination) = ipv4(&row.DestinationPrefix.Prefix) else {
            continue;
        };
        let Ok(network) = ipnet::Ipv4Net::new(destination, row.DestinationPrefix.PrefixLength)
        else {
            info.warnings.push("Invalid Windows route prefix".into());
            continue;
        };
        info.routes.push(Route {
            network: network.trunc(),
            gateway: ipv4(&row.NextHop).filter(|ip| !ip.is_unspecified()),
            interface: interface_name(row.InterfaceIndex),
        });
    }
    Ok(())
}

fn neighbors(info: &mut NetworkInfo) -> io::Result<()> {
    let mut table = std::ptr::null_mut();
    // SAFETY: writable out-pointer receives an IP Helper owned table on success.
    let status = unsafe { GetIpNetTable2(AF_INET, &mut table) };
    if status != 0 {
        return Err(error(status));
    }
    if table.is_null() {
        return Err(io::Error::other("Null neighbor table"));
    }
    let _owner = MibTable(table.cast());
    // SAFETY: the successful API returns a valid table header.
    let count = unsafe { (*table).NumEntries } as usize;
    if count > 65536 {
        return Err(io::Error::other("Oversized neighbor table"));
    }
    // SAFETY: IP Helper guarantees NumEntries rows in the returned OS allocation.
    let rows = unsafe {
        std::slice::from_raw_parts(
            std::ptr::addr_of!((*table).Table).cast::<MIB_IPNET_ROW2>(),
            count,
        )
    };
    for row in rows {
        if row.State == NlnsIncomplete || row.State == NlnsUnreachable {
            continue;
        }
        let Some(ip) = ipv4(&row.Address)
            .filter(|ip| !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast())
        else {
            continue;
        };
        let Some(mac) = row
            .PhysicalAddress
            .get(..row.PhysicalAddressLength as usize)
            .and_then(mac)
        else {
            continue;
        };
        info.neighbors.push(Neighbor {
            ip,
            mac,
            interface: interface_name(row.InterfaceIndex),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denied_icmp_is_not_a_negative_observation() {
        assert!(matches!(echo_error(5), EchoResult::Unavailable(_)));
        assert_eq!(echo_error(IP_REQ_TIMED_OUT), EchoResult::NoReply);
        assert!(matches!(
            echo_error(IP_BAD_ROUTE),
            EchoResult::LocalError(_)
        ));
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
