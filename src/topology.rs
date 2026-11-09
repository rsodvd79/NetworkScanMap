//! Bounded, read-only SNMPv2c observations. FDB entries are hints, not physical links.

use anyhow::{Result, anyhow, bail};
use snmp2::{Oid, SyncSession, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

/// Credentials deliberately implement neither Debug nor Serialize.
#[derive(Clone)]
pub struct Profile {
    pub target: Ipv4Addr,
    pub port: u16,
    pub community: String,
}

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub target: Ipv4Addr,
    pub name: String,
    pub description: String,
    pub chassis: Option<String>,
    pub neighbors: Vec<Adjacency>,
    pub fdb: Vec<FdbEntry>,
    pub warnings: Vec<String>,
    /// Only a complete observation may invalidate older evidence from this source.
    pub complete: bool,
    pub telemetry: crate::telemetry::Telemetry,
}

impl Default for Snapshot {
    fn default() -> Self {
        Self {
            target: Ipv4Addr::UNSPECIFIED,
            name: String::new(),
            description: String::new(),
            chassis: None,
            neighbors: Vec::new(),
            fdb: Vec::new(),
            warnings: Vec::new(),
            complete: false,
            telemetry: crate::telemetry::Telemetry::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Adjacency {
    pub local_port: String,
    pub remote_chassis: String,
    pub remote_port: String,
    pub remote_name: String,
    pub remote_ip: Option<Ipv4Addr>,
}

/// Learned MAC on a bridge port; never sufficient evidence of direct adjacency.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct FdbEntry {
    pub mac: String,
    pub port: String,
    /// Resolved through dot1qVlanFdbId, not assumed equal to the FDB ID.
    pub vlan: Option<u32>,
}

const SYSTEM_NAME: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 5, 0];
const SYSTEM_DESCRIPTION: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];
const SYSTEM_UPTIME: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 3, 0];
const ENTITY: &[u32] = &[1, 3, 6, 1, 2, 1, 47, 1, 1, 1, 1];
const IF_ENTRY: &[u32] = &[1, 3, 6, 1, 2, 1, 2, 2, 1];
const IF_X_ENTRY: &[u32] = &[1, 3, 6, 1, 2, 1, 31, 1, 1, 1];
const VLAN_NAMES: &[u32] = &[1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 3, 1, 1];
const CHASSIS_SUBTYPE: &[u32] = &[1, 0, 8802, 1, 1, 2, 1, 3, 1, 0];
const CHASSIS_ID: &[u32] = &[1, 0, 8802, 1, 1, 2, 1, 3, 2, 0];
const LLDP_LOCAL: &[u32] = &[1, 0, 8802, 1, 1, 2, 1, 3, 7, 1];
const LLDP_REMOTE: &[u32] = &[1, 0, 8802, 1, 1, 2, 1, 4, 1, 1];
const LLDP_MANAGEMENT: &[u32] = &[1, 0, 8802, 1, 1, 2, 1, 4, 2, 1];
const IF_NAME: &[u32] = &[1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1];
const IF_DESCRIPTION: &[u32] = &[1, 3, 6, 1, 2, 1, 2, 2, 1, 2];
const BRIDGE_PORT: &[u32] = &[1, 3, 6, 1, 2, 1, 17, 1, 4, 1, 2];
const BRIDGE_FDB: &[u32] = &[1, 3, 6, 1, 2, 1, 17, 4, 3, 1];
const Q_FDB: &[u32] = &[1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1];
const VLAN_FDB: &[u32] = &[1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 2, 1, 3];
const MAX_ROWS: usize = 8192;
const MAX_TOTAL_ROWS: usize = 32768;

#[derive(Clone, Debug)]
enum Cell {
    Number(u32),
    Counter64(u64),
    Signed(i64),
    Bytes(Vec<u8>),
}

type Table = BTreeMap<Vec<u32>, Cell>;

fn oid(parts: &[u32]) -> Result<Oid<'static>> {
    Oid::from(
        &parts
            .iter()
            .map(|part| u64::from(*part))
            .collect::<Vec<_>>(),
    )
    .map_err(|_| anyhow!("OID SNMP non valido"))
}

fn oid_parts(value: &Oid<'_>) -> Result<Vec<u32>> {
    let parts = value
        .iter()
        .ok_or_else(|| anyhow!("OID SNMP non valido"))?
        .map(u32::try_from)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| anyhow!("OID SNMP fuori intervallo"))?;
    if parts.len() > 128 {
        bail!("OID SNMP troppo lungo");
    }
    Ok(parts)
}

fn cell(value: Value<'_>) -> Result<Cell> {
    match value {
        Value::Integer(n) if n < 0 => Ok(Cell::Signed(n)),
        Value::Integer(n) => u32::try_from(n)
            .map(Cell::Number)
            .map_err(|_| anyhow!("Intero SNMP fuori intervallo")),
        Value::Unsigned32(n) | Value::Counter32(n) | Value::Timeticks(n) => Ok(Cell::Number(n)),
        Value::Counter64(n) => Ok(Cell::Counter64(n)),
        Value::OctetString(bytes) if bytes.len() <= 4096 => Ok(Cell::Bytes(bytes.to_vec())),
        Value::IpAddress(ip) => Ok(Cell::Bytes(ip.to_vec())),
        // LLDP capability bits and other unneeded table columns still have valid types.
        Value::ObjectIdentifier(value) => {
            oid_parts(&value)?;
            Ok(Cell::Bytes(Vec::new()))
        }
        _ => bail!("Valore SNMP mancante, malformato o non supportato"),
    }
}

fn number(value: Option<&Cell>) -> Option<u32> {
    match value? {
        Cell::Number(n) => Some(*n),
        _ => None,
    }
}

fn bytes(value: Option<&Cell>) -> Option<&[u8]> {
    match value? {
        Cell::Bytes(bytes) => Some(bytes),
        _ => None,
    }
}

fn text(value: &[u8]) -> String {
    String::from_utf8_lossy(value)
        .chars()
        .filter(|c| !c.is_control())
        .take(512)
        .collect::<String>()
        .trim()
        .to_owned()
}

fn mac(value: &[u8]) -> Option<String> {
    if value.len() != 6 || value[0] & 1 != 0 || value.iter().all(|b| *b == 0) {
        return None;
    }
    Some(
        value
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

fn ipv4(value: &[u8]) -> Option<Ipv4Addr> {
    let ip = Ipv4Addr::from(<[u8; 4]>::try_from(value).ok()?);
    (!ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast()).then_some(ip)
}

/// Namespaced identities avoid conflating local strings, MACs and network addresses.
fn chassis(subtype: u32, value: &[u8]) -> Option<String> {
    if value.is_empty() || value.len() > 255 {
        return None;
    }
    match subtype {
        4 => mac(value).map(|m| format!("mac:{m}")),
        5 => match value.split_first()? {
            (1, address) => ipv4(address).map(|ip| format!("ipv4:{ip}")),
            (2, address) if address.len() == 16 => {
                let ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(address).ok()?);
                Some(format!("ipv6:{ip}"))
            }
            _ => None,
        },
        1..=3 | 6..=7 => Some(format!(
            "lldp:{subtype}:{}",
            value.iter().map(|b| format!("{b:02x}")).collect::<String>()
        )),
        _ => None,
    }
}

fn port_id(subtype: u32, value: &[u8]) -> Option<String> {
    match subtype {
        3 => mac(value),
        4 => {
            let (family, address) = value.split_first()?;
            (*family == 1)
                .then(|| ipv4(address))
                .flatten()
                .map(|ip| ip.to_string())
        }
        1..=2 | 5..=7 if !value.is_empty() => {
            let label = text(value);
            (!label.is_empty()).then_some(label)
        }
        _ => None,
    }
}

fn session(profile: &Profile, timeout: Duration) -> Result<SyncSession> {
    if timeout.is_zero() || profile.port == 0 || profile.community.is_empty() {
        bail!("Profilo SNMP o timeout non valido");
    }
    SyncSession::new_v2c(
        (profile.target, profile.port),
        profile.community.as_bytes(),
        Some(timeout.min(Duration::from_secs(2))),
        1,
    )
    .map_err(|_| anyhow!("Impossibile aprire la sessione UDP SNMP"))
}

fn get(session: &mut SyncSession, parts: &[u32]) -> Result<Cell> {
    let requested = oid(parts)?;
    let mut response = session
        .get(&requested)
        .map_err(|_| anyhow!("GET SNMP fallito o risposta non valida"))?;
    if response.version().ok() != Some(snmp2::Version::V2C)
        || response.error_status != 0
        || response.error_index != 0
    {
        bail!("Errore dell'agente SNMP");
    }
    let (name, value) = response
        .varbinds
        .next()
        .ok_or_else(|| anyhow!("Risposta SNMP vuota o malformata"))?;
    if oid_parts(&name)? != parts || response.varbinds.next().is_some() {
        bail!("Risposta GET SNMP non corrispondente");
    }
    let valid = if parts == SYSTEM_UPTIME {
        matches!(&value, Value::Timeticks(_))
    } else if parts == CHASSIS_SUBTYPE {
        matches!(&value, Value::Integer(_))
    } else {
        matches!(&value, Value::OctetString(_))
    };
    if !valid {
        bail!("Tipo del valore scalare SNMP non valido");
    }
    cell(value)
}

/// True requires a valid system GET, not merely receipt of a UDP datagram.
pub fn alive(profile: &Profile, timeout: Duration) -> Result<bool> {
    let mut session = session(profile, timeout)?;
    Ok(matches!(
        get(&mut session, SYSTEM_DESCRIPTION),
        Ok(Cell::Bytes(_))
    ))
}

struct Collector<'a> {
    session: SyncSession,
    cancel: &'a AtomicBool,
    deadline: Instant,
    timeout: Duration,
    rows: usize,
    row_limit: usize,
}

impl Collector<'_> {
    fn check(&self, deadline: Instant) -> Result<()> {
        if self.cancel.load(Ordering::Relaxed) {
            bail!("Raccolta SNMP annullata");
        }
        if deadline.saturating_duration_since(Instant::now()) < self.timeout {
            bail!("Budget temporale SNMP esaurito");
        }
        Ok(())
    }

    fn scalar(&mut self, parts: &[u32]) -> Result<Cell> {
        self.check(self.deadline)?;
        get(&mut self.session, parts)
    }

    fn walk(&mut self, root: &[u32]) -> (Table, Result<()>) {
        let mut table = Table::new();
        let result = self.walk_into(root, &mut table);
        (table, result)
    }

    fn walk_into(&mut self, root: &[u32], table: &mut Table) -> Result<()> {
        let deadline = self
            .deadline
            .min(Instant::now() + self.timeout.saturating_mul(8).max(Duration::from_secs(1)));
        let mut current = root.to_vec();
        // GETNEXT has exactly one expected binding, unlike bulk responses whose
        // truncated varbind list snmp2's iterator can silently accept.
        loop {
            self.check(deadline)?;
            if table.len() >= MAX_ROWS || self.rows >= self.row_limit {
                bail!("Limite righe SNMP raggiunto");
            }
            let requested = oid(&current)?;
            let mut response = self
                .session
                .getnext(&requested)
                .map_err(|_| anyhow!("Walk SNMP fallito o risposta non valida"))?;
            if response.version().ok() != Some(snmp2::Version::V2C)
                || response.error_status != 0
                || response.error_index != 0
            {
                bail!("Errore dell'agente durante il walk SNMP");
            }
            let (name, value) = response
                .varbinds
                .next()
                .ok_or_else(|| anyhow!("Walk SNMP vuoto o malformato"))?;
            if response.varbinds.next().is_some() {
                bail!("Walk SNMP con numero di valori non valido");
            }
            let next = oid_parts(&name)?;
            if matches!(value, Value::EndOfMibView) {
                if next < current {
                    bail!("OID finale SNMP non valido");
                }
                return Ok(());
            }
            if matches!(value, Value::NoSuchObject | Value::NoSuchInstance) {
                bail!("Tabella SNMP non supportata");
            }
            if next <= current {
                bail!("OID SNMP non crescente");
            }
            if !next.starts_with(root) {
                // No rows means unsupported/absent, not a trustworthy empty table.
                if table.is_empty() {
                    bail!("Tabella SNMP assente o non supportata");
                }
                return Ok(());
            }
            if next.len() <= root.len() {
                bail!("Indice tabella SNMP mancante");
            }
            let index = &next[root.len()..];
            let value = cell(value)?;
            if !valid_row(root, index, &value) {
                bail!("Indice o tipo della riga SNMP non valido");
            }
            table.insert(index.to_vec(), value);
            self.rows += 1;
            current = next;
        }
    }
}

fn valid_row(root: &[u32], index: &[u32], value: &Cell) -> bool {
    // entPhysicalParentRelPos permits -1 (unknown); it must not prevent
    // collecting the later manufacturer/model/revision columns.
    if let Cell::Signed(n) = value {
        return root == ENTITY && matches!(index, [6, 1..=u32::MAX]) && *n == -1;
    }
    if matches!(value, Cell::Counter64(_)) {
        return root == IF_X_ENTRY && matches!(index, [6..=13, 1..=u32::MAX]);
    }
    let numeric = matches!(value, Cell::Number(_));
    if root == IF_ENTRY {
        return matches!(index, [1..=22, 1..=u32::MAX])
            && if matches!(index[0], 2 | 6 | 22) {
                matches!(value, Cell::Bytes(_))
            } else {
                numeric
            };
    }
    if root == IF_X_ENTRY {
        return matches!(index, [1..=19, 1..=u32::MAX])
            && match index[0] {
                1 | 18 => matches!(value, Cell::Bytes(_)),
                6..=13 => matches!(value, Cell::Counter64(_)),
                _ => numeric,
            };
    }
    if root == ENTITY {
        return matches!(index, [1..=20, 1..=u32::MAX])
            && if matches!(index[0], 9 | 10 | 12 | 13) {
                matches!(value, Cell::Bytes(_))
            } else {
                !matches!(value, Cell::Counter64(_))
            };
    }
    if root == VLAN_NAMES {
        return matches!(index, [1..=4094]) && matches!(value, Cell::Bytes(_));
    }
    if root == IF_NAME || root == IF_DESCRIPTION {
        return matches!(index, [1..=u32::MAX]) && !numeric;
    }
    if root == BRIDGE_PORT {
        return matches!(index, [1..=u32::MAX]) && number(Some(value)).is_some_and(|n| n > 0);
    }
    if root == VLAN_FDB {
        return matches!(index, [_, 1..=4094]) && numeric;
    }
    if root == LLDP_LOCAL {
        return matches!(index, [1..=4, 1..=u32::MAX]) && numeric == (index[0] <= 2);
    }
    if root == LLDP_REMOTE {
        return matches!(index, [1..=12, _, 1..=u32::MAX, 1..=u32::MAX])
            && numeric == matches!(index[0], 1..=4 | 6);
    }
    if root == LLDP_MANAGEMENT {
        return index.len() >= 7
            && matches!(index[0], 1..=5)
            && index[2] > 0
            && index[3] > 0
            && index[4] > 0
            && (1..=31).contains(&index[5])
            && index.len() == 6 + index[5] as usize
            && index[6..].iter().all(|n| *n <= 255)
            && numeric == matches!(index[0], 1 | 3 | 4);
    }
    if root == BRIDGE_FDB || root == Q_FDB {
        let offset = usize::from(root == Q_FDB) + 1;
        return index.len() == offset + 6
            && matches!(index[0], 1..=3)
            && index[offset..].iter().all(|n| *n <= 255)
            && numeric == (index[0] != 1);
    }
    false
}

fn warning(snapshot: &mut Snapshot, label: &str, result: Result<()>) {
    if let Err(error) = result {
        snapshot.complete = false;
        // Both the label and error are our fixed strings; no agent data or credentials.
        snapshot.warnings.push(format!("{label}: {error}"));
    }
}

fn table(
    collector: &mut Collector<'_>,
    snapshot: &mut Snapshot,
    label: &str,
    root: &[u32],
) -> Table {
    let (values, result) = collector.walk(root);
    snapshot
        .telemetry
        .status(label, !values.is_empty() || result.is_ok(), result.is_ok());
    warning(snapshot, label, result);
    values
}

/// Optional telemetry never changes topology completeness.
fn telemetry_table(
    collector: &mut Collector<'_>,
    snapshot: &mut Snapshot,
    label: &str,
    root: &[u32],
) -> Table {
    let (values, result) = collector.walk(root);
    snapshot
        .telemetry
        .status(label, !values.is_empty() || result.is_ok(), result.is_ok());
    if let Err(error) = result {
        snapshot.warnings.push(format!("{label}: {error}"));
    }
    values
}

fn octets(value: Option<&Cell>) -> Option<crate::telemetry::Counter> {
    use crate::telemetry::Counter;
    match value? {
        Cell::Number(value) => Some(Counter {
            value: u64::from(*value),
            width: 32,
        }),
        Cell::Counter64(value) => Some(Counter {
            value: *value,
            width: 64,
        }),
        _ => None,
    }
}

fn telemetry_interfaces(
    base: &Table,
    extended: &Table,
    names: &BTreeMap<u32, String>,
) -> Vec<crate::telemetry::Interface> {
    let indices = base
        .keys()
        .chain(extended.keys())
        .filter_map(|key| match key.as_slice() {
            [_, index] => Some(*index),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    indices
        .into_iter()
        .take(crate::telemetry::MAX_RECORDS)
        .map(|index| {
            let key = [index];
            let base_number = |col| number(column(base, col, &key));
            let high_speed = number(column(extended, 15, &key)).filter(|n| *n > 0);
            crate::telemetry::Interface {
                index,
                name: bytes(column(extended, 1, &key))
                    .map(text)
                    .filter(|s| !s.is_empty())
                    .or_else(|| names.get(&index).cloned())
                    .or_else(|| bytes(column(base, 2, &key)).map(text))
                    .unwrap_or_default(),
                admin_status: base_number(7).filter(|s| (1..=3).contains(s)),
                oper_status: base_number(8).filter(|s| (1..=7).contains(s)),
                speed_bps: high_speed
                    .map(|n| u64::from(n) * 1_000_000)
                    .or_else(|| base_number(5).filter(|n| *n != u32::MAX).map(u64::from)),
                rx_octets: octets(column(extended, 6, &key))
                    .or_else(|| octets(column(base, 10, &key))),
                tx_octets: octets(column(extended, 10, &key))
                    .or_else(|| octets(column(base, 16, &key))),
                rx_errors: base_number(14),
                tx_errors: base_number(20),
                rx_discards: base_number(13),
                tx_discards: base_number(19),
                discontinuity_ticks: number(column(extended, 19, &key)),
                ..crate::telemetry::Interface::default()
            }
        })
        .collect()
}

fn telemetry_entities(values: &Table) -> Vec<crate::telemetry::Entity> {
    let indices = values
        .keys()
        .filter_map(|key| match key.as_slice() {
            [9 | 10 | 12 | 13, index] => Some(*index),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    indices
        .into_iter()
        .take(crate::telemetry::MAX_RECORDS)
        .map(|index| {
            let field = |col| {
                bytes(column(values, col, &[index]))
                    .map(text)
                    .unwrap_or_default()
            };
            crate::telemetry::Entity {
                index,
                manufacturer: field(12),
                model: field(13),
                software: field(10),
                firmware: field(9),
            }
        })
        .collect()
}

fn column<'a>(table: &'a Table, column: u32, index: &[u32]) -> Option<&'a Cell> {
    let mut key = Vec::with_capacity(index.len() + 1);
    key.push(column);
    key.extend_from_slice(index);
    table.get(&key)
}

fn interfaces(names: &Table, descriptions: &Table) -> BTreeMap<u32, String> {
    let mut result = BTreeMap::new();
    for source in [descriptions, names] {
        for (index, value) in source {
            if let ([index], Cell::Bytes(value)) = (index.as_slice(), value) {
                let label = text(value);
                if !label.is_empty() {
                    result.insert(*index, label);
                }
            }
        }
    }
    result
}

fn local_ports(local: &Table) -> BTreeMap<u32, String> {
    let indices = local
        .keys()
        .filter_map(|key| match key.as_slice() {
            [_, index] => Some(*index),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    indices
        .into_iter()
        .map(|index| {
            let key = [index];
            let label = number(column(local, 2, &key))
                .zip(bytes(column(local, 3, &key)))
                .and_then(|(subtype, value)| port_id(subtype, value))
                .or_else(|| {
                    bytes(column(local, 4, &key))
                        .map(text)
                        .filter(|s| !s.is_empty())
                })
                .unwrap_or_else(|| format!("lldp-port:{index}"));
            (index, label)
        })
        .collect()
}

fn management_addresses(table: &Table) -> BTreeMap<Vec<u32>, BTreeSet<Ipv4Addr>> {
    let mut result: BTreeMap<Vec<u32>, BTreeSet<Ipv4Addr>> = BTreeMap::new();
    for key in table.keys() {
        // column, timeMark, localPortNum, remIndex, addressSubtype,
        // OCTET STRING length, address bytes.
        if let [column @ 1..=5, time, local, remote, 1, 4, a, b, c, d] = key.as_slice() {
            let _ = column;
            let Ok(address) = [*a, *b, *c, *d]
                .map(u8::try_from)
                .into_iter()
                .collect::<std::result::Result<Vec<_>, _>>()
            else {
                continue;
            };
            if let Some(ip) = ipv4(&address) {
                result
                    .entry(vec![*time, *local, *remote])
                    .or_default()
                    .insert(ip);
            }
        }
    }
    result
}

fn adjacencies(
    remote: &Table,
    management: &Table,
    ports: &BTreeMap<u32, String>,
) -> (Vec<Adjacency>, bool) {
    let addresses = management_addresses(management);
    let indices = remote
        .keys()
        .filter_map(|key| match key.as_slice() {
            [_, time, local, index] => Some(vec![*time, *local, *index]),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let mut result = Vec::new();
    let mut valid = remote.keys().all(|key| key.len() == 4);
    for index in indices {
        let identity = number(column(remote, 4, &index))
            .zip(bytes(column(remote, 5, &index)))
            .and_then(|(subtype, value)| chassis(subtype, value));
        let remote_port = number(column(remote, 6, &index))
            .zip(bytes(column(remote, 7, &index)))
            .and_then(|(subtype, value)| port_id(subtype, value));
        let (Some(identity), Some(remote_port)) = (identity, remote_port) else {
            valid = false;
            continue;
        };
        let ips = addresses.get(&index);
        let remote_ip = ips
            .filter(|ips| ips.len() == 1)
            .and_then(|ips| ips.first().copied())
            .or_else(|| {
                identity
                    .strip_prefix("ipv4:")
                    .and_then(|value| value.parse().ok())
            });
        if ips.is_some_and(|ips| ips.len() > 1) {
            valid = false;
        }
        let entry = Adjacency {
            local_port: ports.get(&index[1]).cloned().unwrap_or_else(|| {
                valid = false;
                format!("lldp-port:{}", index[1])
            }),
            remote_chassis: identity,
            remote_port,
            remote_name: bytes(column(remote, 9, &index))
                .map(text)
                .unwrap_or_default(),
            remote_ip,
        };
        if !result.contains(&entry) {
            result.push(entry);
        }
    }
    (result, valid)
}

fn fdb_entries(
    fdb: &Table,
    q_bridge: bool,
    bridge: &Table,
    interfaces: &BTreeMap<u32, String>,
    vlan_fdb: &Table,
) -> (Vec<FdbEntry>, bool) {
    let mut vlans: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
    for (index, value) in vlan_fdb {
        if let ([_, vlan @ 1..=4094], Cell::Number(id)) = (index.as_slice(), value) {
            vlans.entry(*id).or_default().insert(*vlan);
        }
    }
    let indices = fdb
        .keys()
        .filter_map(|key| key.get(1..).map(<[u32]>::to_vec))
        .collect::<BTreeSet<_>>();
    let mut result = BTreeSet::new();
    let mut valid = fdb.keys().all(|key| !key.is_empty());
    for index in indices {
        let mac_index = if q_bridge {
            index.get(1..).unwrap_or_default()
        } else {
            &index
        };
        if mac_index.len() != 6 || mac_index.iter().any(|part| *part > 255) {
            valid = false;
            continue;
        }
        let address = mac_index.iter().map(|n| *n as u8).collect::<Vec<_>>();
        let Some(address) = mac(&address) else {
            continue;
        };
        if let Some(reported) = bytes(column(fdb, 1, &index))
            && mac(reported).as_deref() != Some(&address)
        {
            valid = false;
            continue;
        }
        let status = number(column(fdb, 3, &index));
        if !matches!(status, Some(3 | 5)) {
            if status.is_none() {
                valid = false;
            }
            continue;
        }
        let Some(port) = number(column(fdb, 2, &index)) else {
            valid = false;
            continue;
        };
        if port == 0 {
            continue;
        }
        let if_index = number(bridge.get(&vec![port]));
        let label = if_index
            .and_then(|index| interfaces.get(&index).cloned())
            .unwrap_or_else(|| match if_index {
                Some(index) => format!("ifIndex:{index}"),
                None => {
                    valid = false;
                    format!("bridge-port:{port}")
                }
            });
        let contexts = if q_bridge { vlans.get(&index[0]) } else { None };
        if let Some(contexts) = contexts {
            for vlan in contexts {
                if result.len() >= MAX_ROWS {
                    valid = false;
                    break;
                }
                result.insert(FdbEntry {
                    mac: address.clone(),
                    port: label.clone(),
                    vlan: Some(*vlan),
                });
            }
        } else {
            if result.len() >= MAX_ROWS {
                valid = false;
                break;
            }
            result.insert(FdbEntry {
                mac: address,
                port: label,
                vlan: None,
            });
        }
    }
    (result.into_iter().collect(), valid)
}

/// Collect independent tables even if another is unsupported. Network errors and
/// cancellation yield partial snapshots; invalid profiles/local socket setup fail.
/// No retries; each receive is capped at two seconds, each walk at eight receives,
/// and the entire collection at thirty seconds. The final ten seconds and 8192
/// rows are reserved for telemetry, so topology cannot starve interface samples.
/// No remote management IP is probed.
pub fn collect(profile: &Profile, timeout: Duration, cancel: &AtomicBool) -> Result<Snapshot> {
    let session = session(profile, timeout)?;
    let timeout = timeout.min(Duration::from_secs(2));
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut collector = Collector {
        session,
        cancel,
        deadline: deadline - Duration::from_secs(10),
        timeout,
        rows: 0,
        row_limit: MAX_TOTAL_ROWS - MAX_ROWS,
    };
    let mut snapshot = Snapshot {
        target: profile.target,
        complete: true,
        telemetry: crate::telemetry::Telemetry::start_sample(),
        ..Snapshot::default()
    };
    for (parts, name) in [(SYSTEM_NAME, true), (SYSTEM_DESCRIPTION, false)] {
        match collector.scalar(parts) {
            Ok(Cell::Bytes(value)) => {
                if name {
                    snapshot.name = text(&value);
                } else {
                    snapshot.description = text(&value);
                }
            }
            _ => warning(
                &mut snapshot,
                "SYSTEM",
                Err(anyhow!("Dati di sistema non disponibili")),
            ),
        }
    }
    let local_subtype = collector.scalar(CHASSIS_SUBTYPE).ok();
    let local_identity = collector.scalar(CHASSIS_ID).ok();
    snapshot.chassis = number(local_subtype.as_ref())
        .zip(bytes(local_identity.as_ref()))
        .and_then(|(subtype, value)| chassis(subtype, value));
    if snapshot.chassis.is_none() {
        warning(
            &mut snapshot,
            "LLDP",
            Err(anyhow!("Identita chassis locale non disponibile")),
        );
    }
    // LLDP is collected before optional interface/FDB enrichment, so those
    // unsupported walks cannot consume the budget before supported LLDP tables.
    let local = table(&mut collector, &mut snapshot, "LLDP locale", LLDP_LOCAL);
    let remote = table(&mut collector, &mut snapshot, "LLDP remoto", LLDP_REMOTE);
    let management = table(
        &mut collector,
        &mut snapshot,
        "LLDP gestione",
        LLDP_MANAGEMENT,
    );
    let names = table(&mut collector, &mut snapshot, "IF-MIB nomi", IF_NAME);
    let descriptions = table(
        &mut collector,
        &mut snapshot,
        "IF-MIB descrizioni",
        IF_DESCRIPTION,
    );
    let interfaces = interfaces(&names, &descriptions);
    // localPortNum is not ifIndex: use LLDP's explicit port ID/description.
    let ports = local_ports(&local);
    let (neighbors, valid) = adjacencies(&remote, &management, &ports);
    snapshot.neighbors = neighbors;
    if !valid {
        warning(
            &mut snapshot,
            "LLDP",
            Err(anyhow!("Righe incomplete o identita ambigue")),
        );
    }
    let bridge = table(&mut collector, &mut snapshot, "BRIDGE porte", BRIDGE_PORT);
    let fdb = table(&mut collector, &mut snapshot, "BRIDGE FDB", BRIDGE_FDB);
    let q_fdb = table(&mut collector, &mut snapshot, "Q-BRIDGE FDB", Q_FDB);
    let vlan_fdb = table(&mut collector, &mut snapshot, "Q-BRIDGE VLAN", VLAN_FDB);
    let (entries, valid) = fdb_entries(&fdb, false, &bridge, &interfaces, &vlan_fdb);
    let (q_entries, q_valid) = fdb_entries(&q_fdb, true, &bridge, &interfaces, &vlan_fdb);
    snapshot.fdb = entries
        .into_iter()
        .chain(q_entries)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if !valid || !q_valid {
        warning(
            &mut snapshot,
            "FDB",
            Err(anyhow!("Righe FDB incomplete o porte non risolte")),
        );
    }
    let fdb_complete = [
        "BRIDGE porte",
        "BRIDGE FDB",
        "Q-BRIDGE FDB",
        "Q-BRIDGE VLAN",
    ]
    .iter()
    .all(|label| {
        snapshot
            .telemetry
            .tables
            .get(*label)
            .is_some_and(|s| s.complete)
    });
    snapshot.telemetry.status(
        "FDB",
        !snapshot.fdb.is_empty() || fdb_complete,
        fdb_complete && valid && q_valid && snapshot.fdb.len() <= crate::telemetry::MAX_RECORDS,
    );
    snapshot.telemetry.fdb = snapshot
        .fdb
        .iter()
        .take(crate::telemetry::MAX_RECORDS)
        .cloned()
        .collect();
    if cancel.load(Ordering::Relaxed) {
        snapshot.complete = false;
    }
    collector.deadline = deadline;
    collector.row_limit = MAX_TOTAL_ROWS;
    collect_interface_telemetry(&mut collector, &mut snapshot, &interfaces);
    let entities = telemetry_table(&mut collector, &mut snapshot, "ENTITY-MIB", ENTITY);
    snapshot.telemetry.entities = telemetry_entities(&entities);
    let entity_complete = !snapshot.telemetry.entities.is_empty()
        && snapshot.telemetry.entities.iter().all(|e| {
            !e.manufacturer.is_empty()
                && !e.model.is_empty()
                && !e.software.is_empty()
                && !e.firmware.is_empty()
        });
    snapshot.telemetry.status(
        "ENTITY-MIB dati",
        !snapshot.telemetry.entities.is_empty(),
        entity_complete,
    );
    let vlans = telemetry_table(&mut collector, &mut snapshot, "VLAN nomi", VLAN_NAMES);
    let mut vlan_records = BTreeMap::new();
    for key in vlan_fdb.keys() {
        if let [_, id @ 1..=4094] = key.as_slice() {
            vlan_records.insert(
                *id,
                crate::telemetry::Vlan {
                    id: *id,
                    name: String::new(),
                },
            );
        }
    }
    for (key, value) in &vlans {
        if let [id] = key.as_slice()
            && let Some(value) = bytes(Some(value))
        {
            vlan_records.insert(
                *id,
                crate::telemetry::Vlan {
                    id: *id,
                    name: text(value),
                },
            );
        }
    }
    snapshot.telemetry.vlans = vlan_records
        .into_values()
        .take(crate::telemetry::MAX_RECORDS)
        .collect();
    Ok(snapshot)
}

/// Periodic, read-only interface sample with the same thirty-second/row limits.
/// Never collects LLDP, FDB, ENTITY-MIB or VLAN tables and returns no topology
/// snapshot; merging the result cannot invalidate links. Excluded tables are
/// unavailable for this sample, so `Telemetry::merge` retains their old values.
pub fn collect_telemetry(
    profile: &Profile,
    timeout: Duration,
    cancel: &AtomicBool,
) -> Result<crate::telemetry::Telemetry> {
    let session = session(profile, timeout)?;
    let mut collector = Collector {
        session,
        cancel,
        deadline: Instant::now() + Duration::from_secs(30),
        timeout: timeout.min(Duration::from_secs(2)),
        rows: 0,
        row_limit: MAX_TOTAL_ROWS,
    };
    let mut snapshot = Snapshot {
        telemetry: crate::telemetry::Telemetry::start_sample(),
        ..Snapshot::default()
    };
    collect_interface_telemetry(&mut collector, &mut snapshot, &BTreeMap::new());
    for label in [
        "ENTITY-MIB",
        "ENTITY-MIB dati",
        "VLAN nomi",
        "Q-BRIDGE VLAN",
        "FDB",
    ] {
        snapshot.telemetry.status(label, false, false);
    }
    Ok(snapshot.telemetry)
}

fn collect_interface_telemetry(
    collector: &mut Collector<'_>,
    snapshot: &mut Snapshot,
    interfaces: &BTreeMap<u32, String>,
) {
    match collector.scalar(SYSTEM_UPTIME) {
        Ok(Cell::Number(ticks)) => {
            snapshot.telemetry.uptime_ticks = Some(ticks);
            snapshot.telemetry.status("sysUpTime", true, true);
        }
        _ => {
            snapshot.telemetry.status("sysUpTime", false, false);
            snapshot
                .warnings
                .push("sysUpTime: Dati non disponibili".into());
        }
    }
    let base = telemetry_table(collector, snapshot, "IF-MIB contatori", IF_ENTRY);
    let extended = telemetry_table(collector, snapshot, "IF-MIB estesa", IF_X_ENTRY);
    snapshot.telemetry.interfaces = telemetry_interfaces(&base, &extended, interfaces);
    let interface_complete = !snapshot.telemetry.interfaces.is_empty()
        && snapshot.telemetry.interfaces.iter().all(|p| {
            p.admin_status.is_some()
                && p.oper_status.is_some()
                && p.speed_bps.is_some()
                && p.rx_octets.is_some()
                && p.tx_octets.is_some()
                && p.rx_errors.is_some()
                && p.tx_errors.is_some()
                && p.rx_discards.is_some()
                && p.tx_discards.is_some()
                && p.discontinuity_ticks.is_some()
        });
    snapshot.telemetry.status(
        "IF-MIB dati",
        !snapshot.telemetry.interfaces.is_empty(),
        interface_complete,
    );
    snapshot.telemetry.finish_sample();
}

#[cfg(test)]
mod tests {
    use super::*;
    use snmp2::{MessageType, Pdu};
    use std::{net::UdpSocket, thread};

    fn put(table: &mut Table, column: u32, index: &[u32], value: Cell) {
        let mut key = vec![column];
        key.extend_from_slice(index);
        table.insert(key, value);
    }

    #[test]
    fn telemetry_parser_prefers_high_capacity_and_preserves_counter_width() {
        let mut base = Table::new();
        for (col, value) in [
            (5, 1_000_000_000),
            (7, 1),
            (8, 2),
            (10, 123),
            (16, 456),
            (13, 3),
            (14, 4),
            (19, 5),
            (20, 6),
        ] {
            put(&mut base, col, &[7], Cell::Number(value));
        }
        let mut extended = Table::new();
        put(
            &mut extended,
            6,
            &[7],
            cell(Value::Counter64(1 << 40)).unwrap(),
        );
        put(&mut extended, 10, &[7], Cell::Counter64(1 << 41));
        put(&mut extended, 15, &[7], Cell::Number(10_000));
        put(&mut extended, 19, &[7], Cell::Number(100));
        let parsed = telemetry_interfaces(&base, &extended, &BTreeMap::new());
        assert_eq!(
            parsed[0].rx_octets,
            Some(crate::telemetry::Counter {
                value: 1 << 40,
                width: 64
            })
        );
        assert_eq!(parsed[0].speed_bps, Some(10_000_000_000));
        assert_eq!(
            (parsed[0].admin_status, parsed[0].oper_status),
            (Some(1), Some(2))
        );
        assert_eq!(
            (parsed[0].rx_errors, parsed[0].tx_discards),
            (Some(4), Some(5))
        );
        assert_eq!(parsed[0].discontinuity_ticks, Some(100));
        let fallback = telemetry_interfaces(&base, &Table::new(), &BTreeMap::new());
        assert_eq!(
            fallback[0].rx_octets,
            Some(crate::telemetry::Counter {
                value: 123,
                width: 32
            })
        );
    }

    #[test]
    fn telemetry_entity_and_vlan_validation_keeps_actual_values() {
        let mut values = Table::new();
        for (col, value) in [
            (9, "firmware-2"),
            (10, "software-3"),
            (12, "Vendor"),
            (13, "Model-X"),
        ] {
            put(
                &mut values,
                col,
                &[1],
                Cell::Bytes(value.as_bytes().to_vec()),
            );
        }
        let parsed = telemetry_entities(&values);
        assert_eq!(
            (
                parsed[0].manufacturer.as_str(),
                parsed[0].model.as_str(),
                parsed[0].software.as_str(),
                parsed[0].firmware.as_str()
            ),
            ("Vendor", "Model-X", "software-3", "firmware-2")
        );
        assert!(valid_row(
            ENTITY,
            &[6, 1],
            &cell(Value::Integer(-1)).unwrap()
        ));
        assert!(valid_row(
            VLAN_NAMES,
            &[4094],
            &Cell::Bytes(b"voice".to_vec())
        ));
        assert!(!valid_row(VLAN_NAMES, &[4095], &Cell::Bytes(Vec::new())));
        assert!(!valid_row(IF_X_ENTRY, &[6, 1], &Cell::Number(1)));
        assert!(!valid_row(IF_ENTRY, &[10, 1], &Cell::Counter64(1)));
    }

    #[test]
    fn optional_telemetry_failure_does_not_invalidate_topology() {
        let profile = Profile {
            target: Ipv4Addr::LOCALHOST,
            port: 161,
            community: "test".into(),
        };
        let cancel = AtomicBool::new(true);
        let mut collector = Collector {
            session: session(&profile, Duration::from_millis(10)).unwrap(),
            cancel: &cancel,
            deadline: Instant::now() + Duration::from_secs(1),
            timeout: Duration::from_millis(10),
            rows: 0,
            row_limit: MAX_TOTAL_ROWS,
        };
        let mut snapshot = Snapshot {
            complete: true,
            ..Snapshot::default()
        };
        let values = telemetry_table(&mut collector, &mut snapshot, "ENTITY-MIB", ENTITY);
        assert!(values.is_empty());
        assert!(snapshot.complete);
        assert!(!snapshot.telemetry.tables["ENTITY-MIB"].available);
    }

    #[test]
    fn chassis_subtypes_do_not_collide_and_binary_mac_is_normalized() {
        assert_eq!(
            chassis(4, &[0x02, 0xab, 0, 0, 0, 1]).as_deref(),
            Some("mac:02:ab:00:00:00:01")
        );
        assert_ne!(chassis(7, b"switch"), chassis(6, b"switch"));
        assert!(chassis(4, b"bad").is_none());
    }

    #[test]
    fn lldp_joins_full_remote_index_and_preserves_parallel_ports() {
        let mut remote = Table::new();
        for index in [[10, 42, 1], [10, 43, 1]] {
            put(&mut remote, 4, &index, Cell::Number(4));
            put(&mut remote, 5, &index, Cell::Bytes(vec![2, 0, 0, 0, 0, 1]));
            put(&mut remote, 6, &index, Cell::Number(5));
            put(&mut remote, 7, &index, Cell::Bytes(b"eth9".to_vec()));
        }
        let management = BTreeMap::from([
            (vec![1, 10, 42, 1, 1, 4, 192, 0, 2, 9], Cell::Number(2)),
            (vec![1, 10, 43, 2, 1, 4, 192, 0, 2, 8], Cell::Number(2)),
        ]);
        let ports = BTreeMap::from([(42, "Gi1/1".into()), (43, "Gi1/2".into())]);
        let (entries, valid) = adjacencies(&remote, &management, &ports);
        assert!(valid);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].local_port, "Gi1/1");
        assert_eq!(entries[0].remote_ip, Some(Ipv4Addr::new(192, 0, 2, 9)));
        assert_eq!(entries[1].remote_ip, None);
    }

    #[test]
    fn incomplete_lldp_does_not_claim_complete_or_invent_identity() {
        let remote = BTreeMap::from([(vec![5, 10, 42, 1], Cell::Bytes(b"unknown".to_vec()))]);
        let (entries, valid) = adjacencies(&remote, &Table::new(), &BTreeMap::new());
        assert!(!valid);
        assert!(entries.is_empty());
    }

    #[test]
    fn malformed_indices_are_rejected_and_lldp_ports_are_not_interface_indices() {
        assert!(!valid_row(
            LLDP_REMOTE,
            &[5, 10, 42],
            &Cell::Bytes(vec![2; 6])
        ));
        assert!(!valid_row(
            LLDP_MANAGEMENT,
            &[1, 10, 42, 1, 1, 4, 192, 0, 2, 999],
            &Cell::Number(1)
        ));
        let local = BTreeMap::from([
            (vec![2, 42], Cell::Number(5)),
            (vec![3, 42], Cell::Bytes(b"Gi1/9".to_vec())),
        ]);
        assert_eq!(
            local_ports(&local).get(&42).map(String::as_str),
            Some("Gi1/9")
        );
    }

    #[test]
    fn q_bridge_maps_bridge_port_and_shared_fdb_to_actual_vlans() {
        let mut fdb = Table::new();
        let index = [700, 2, 0, 0, 0, 0, 1];
        put(&mut fdb, 2, &index, Cell::Number(9));
        put(&mut fdb, 3, &index, Cell::Number(3));
        let bridge = BTreeMap::from([(vec![9], Cell::Number(101))]);
        let interfaces = BTreeMap::from([(101, "uplink".into())]);
        let vlans = BTreeMap::from([
            (vec![0, 20], Cell::Number(700)),
            (vec![0, 30], Cell::Number(700)),
        ]);
        let (entries, valid) = fdb_entries(&fdb, true, &bridge, &interfaces, &vlans);
        assert!(valid);
        assert_eq!(
            entries
                .iter()
                .map(|e| (e.port.as_str(), e.vlan))
                .collect::<Vec<_>>(),
            vec![("uplink", Some(20)), ("uplink", Some(30))]
        );
        let (unknown, _) = fdb_entries(&fdb, true, &bridge, &interfaces, &Table::new());
        assert_eq!(unknown[0].vlan, None);
    }

    fn mock(replies: usize, mode: u8) -> (Profile, thread::JoinHandle<()>) {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let port = socket.local_addr().unwrap().port();
        let worker = thread::spawn(move || {
            let mut buffer = [0; 2048];
            for _ in 0..replies {
                let (size, peer) = socket.recv_from(&mut buffer).unwrap();
                let mut request = Pdu::from_bytes(&buffer[..size]).unwrap();
                assert!(matches!(
                    request.message_type,
                    MessageType::GetRequest | MessageType::GetNextRequest
                ));
                request.message_type = MessageType::Response;
                if mode == 1 {
                    request.error_status = 5;
                }
                // Echoing NULL is invalid for GET and a repeated OID for GETNEXT.
                // For alive, replace the binding with a valid sysDescr OCTET STRING.
                let binding = [
                    0x30, 0x10, 0x06, 0x08, 0x2b, 6, 1, 2, 1, 1, 1, 0, 0x04, 0x04, b't', b'e',
                    b's', b't',
                ];
                if mode == 0 {
                    request.varbinds = snmp2::Varbinds::from_bytes(&binding);
                }
                socket.send_to(&request.to_bytes().unwrap(), peer).unwrap();
            }
        });
        (
            Profile {
                target: Ipv4Addr::LOCALHOST,
                port,
                community: "private-test-secret".into(),
            },
            worker,
        )
    }

    #[test]
    fn alive_accepts_valid_loopback_system_response_but_not_agent_error() {
        for (mode, expected) in [(0, true), (1, false)] {
            let (profile, worker) = mock(1, mode);
            assert_eq!(
                alive(&profile, Duration::from_millis(200)).unwrap(),
                expected
            );
            worker.join().unwrap();
        }
    }

    #[test]
    fn walk_rejects_repeated_oid_and_retains_no_false_complete_result() {
        let (profile, worker) = mock(1, 2);
        let cancel = AtomicBool::new(false);
        let mut collector = Collector {
            session: session(&profile, Duration::from_millis(200)).unwrap(),
            cancel: &cancel,
            deadline: Instant::now() + Duration::from_secs(2),
            timeout: Duration::from_millis(200),
            rows: 0,
            row_limit: MAX_TOTAL_ROWS,
        };
        let (rows, result) = collector.walk(LLDP_REMOTE);
        assert!(rows.is_empty());
        assert!(result.unwrap_err().to_string().contains("non crescente"));
        worker.join().unwrap();
    }

    fn binding(name: &[u32], value: Option<&Cell>, end: bool) -> Vec<u8> {
        let uptime = name == SYSTEM_UPTIME;
        let name = oid(name).unwrap();
        let mut pair = vec![6, name.as_bytes().len() as u8];
        pair.extend_from_slice(name.as_bytes());
        match value {
            Some(Cell::Bytes(value)) => {
                pair.extend_from_slice(&[4, value.len() as u8]);
                pair.extend_from_slice(value);
            }
            Some(Cell::Number(value)) => {
                assert!(*value < 128);
                pair.extend_from_slice(&[if uptime { 0x43 } else { 2 }, 1, *value as u8]);
            }
            Some(Cell::Counter64(value)) => {
                let bytes = value.to_be_bytes();
                let first = bytes
                    .iter()
                    .position(|b| *b != 0)
                    .unwrap_or(bytes.len() - 1);
                let bytes = &bytes[first..];
                let padding = usize::from(bytes[0] & 0x80 != 0);
                pair.extend_from_slice(&[0x46, (bytes.len() + padding) as u8]);
                if padding != 0 {
                    pair.push(0);
                }
                pair.extend_from_slice(bytes);
            }
            Some(Cell::Signed(_)) => panic!("Unsupported fixture value"),
            None => pair.extend_from_slice(&[if end { 0x82 } else { 0x80 }, 0]),
        }
        assert!(pair.len() < 128);
        let mut result = vec![0x30, pair.len() as u8];
        result.extend_from_slice(&pair);
        result
    }

    #[test]
    fn periodic_collection_requests_only_uptime_and_interface_tables() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let profile = Profile {
            target: Ipv4Addr::LOCALHOST,
            port: socket.local_addr().unwrap().port(),
            community: "periodic-test-secret".into(),
        };
        let mut values = Table::from([(SYSTEM_UPTIME.to_vec(), Cell::Number(100))]);
        for (root, suffix, value) in [
            (IF_ENTRY, [2, 7], Cell::Bytes(b"eth7".to_vec())),
            (IF_ENTRY, [5, 7], Cell::Number(100)),
            (IF_ENTRY, [7, 7], Cell::Number(1)),
            (IF_ENTRY, [8, 7], Cell::Number(1)),
            (IF_ENTRY, [10, 7], Cell::Number(10)),
            (IF_ENTRY, [13, 7], Cell::Number(0)),
            (IF_ENTRY, [14, 7], Cell::Number(0)),
            (IF_ENTRY, [16, 7], Cell::Number(20)),
            (IF_ENTRY, [19, 7], Cell::Number(0)),
            (IF_ENTRY, [20, 7], Cell::Number(0)),
            (IF_X_ENTRY, [1, 7], Cell::Bytes(b"uplink".to_vec())),
            (IF_X_ENTRY, [6, 7], Cell::Counter64(100)),
            (IF_X_ENTRY, [10, 7], Cell::Counter64(200)),
            (IF_X_ENTRY, [15, 7], Cell::Number(1)),
            (IF_X_ENTRY, [19, 7], Cell::Number(0)),
        ] {
            values.insert(root.iter().copied().chain(suffix).collect(), value);
        }
        let worker = thread::spawn(move || {
            let mut buffer = [0; 2048];
            for _ in 0..values.len() + 2 {
                let (size, peer) = socket.recv_from(&mut buffer).unwrap();
                let mut request = Pdu::from_bytes(&buffer[..size]).unwrap();
                let (name, _) = request.varbinds.clone().next().unwrap();
                let name = oid_parts(&name).unwrap();
                let encoded = match request.message_type {
                    MessageType::GetRequest => {
                        assert_eq!(name, SYSTEM_UPTIME);
                        binding(&name, values.get(&name), false)
                    }
                    MessageType::GetNextRequest => {
                        let root = [IF_ENTRY, IF_X_ENTRY]
                            .into_iter()
                            .find(|root| name.starts_with(root))
                            .expect("Forbidden periodic table");
                        if let Some((next, value)) = values.iter().find(|(next, _)| {
                            next.as_slice() > name.as_slice() && next.starts_with(root)
                        }) {
                            binding(next, Some(value), false)
                        } else {
                            binding(&name, None, true)
                        }
                    }
                    _ => panic!("Non-read-only periodic request"),
                };
                request.message_type = MessageType::Response;
                request.varbinds = snmp2::Varbinds::from_bytes(&encoded);
                socket.send_to(&request.to_bytes().unwrap(), peer).unwrap();
            }
        });
        let sample = collect_telemetry(
            &profile,
            Duration::from_millis(100),
            &AtomicBool::new(false),
        )
        .unwrap();
        worker.join().unwrap();
        assert_eq!(sample.uptime_ticks, Some(100));
        assert_eq!(sample.interfaces[0].name, "uplink");
        assert_eq!(
            sample.interfaces[0].rx_octets,
            Some(crate::telemetry::Counter {
                value: 100,
                width: 64
            })
        );
        assert_eq!(sample.interfaces[0].speed_bps, Some(1_000_000));
        assert!(sample.tables["IF-MIB dati"].complete);
        assert!(!sample.tables["ENTITY-MIB"].available);
        assert!(!sample.tables["FDB"].available);
        assert!(sample.validate().is_ok());
        assert!(!format!("{sample:?}").contains(&profile.community));
    }

    #[test]
    fn periodic_cancellation_and_row_bounds_send_no_requests() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();
        let profile = Profile {
            target: Ipv4Addr::LOCALHOST,
            port: socket.local_addr().unwrap().port(),
            community: "test".into(),
        };
        let sample =
            collect_telemetry(&profile, Duration::from_millis(10), &AtomicBool::new(true)).unwrap();
        assert!(sample.interfaces.is_empty());
        assert!(!sample.tables["sysUpTime"].available);
        let cancel = AtomicBool::new(false);
        let mut collector = Collector {
            session: session(&profile, Duration::from_millis(10)).unwrap(),
            cancel: &cancel,
            deadline: Instant::now() + Duration::from_secs(1),
            timeout: Duration::from_millis(10),
            rows: 0,
            row_limit: 0,
        };
        assert!(collector.walk(IF_ENTRY).1.is_err());
        assert!(socket.recv_from(&mut [0; 2048]).is_err());
    }

    fn collect_mock_topology(include_management: bool) -> (Profile, Snapshot) {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let profile = Profile {
            target: Ipv4Addr::LOCALHOST,
            port: socket.local_addr().unwrap().port(),
            community: "private-test-secret".into(),
        };
        let mut values = Table::new();
        values.insert(SYSTEM_NAME.to_vec(), Cell::Bytes(b"switch".to_vec()));
        values.insert(
            SYSTEM_DESCRIPTION.to_vec(),
            Cell::Bytes(b"test switch".to_vec()),
        );
        values.insert(CHASSIS_SUBTYPE.to_vec(), Cell::Number(4));
        values.insert(CHASSIS_ID.to_vec(), Cell::Bytes(vec![2, 0, 0, 0, 0, 1]));
        for (root, suffix, value) in [
            (LLDP_LOCAL, vec![2, 42], Cell::Number(5)),
            (LLDP_LOCAL, vec![3, 42], Cell::Bytes(b"Gi1/9".to_vec())),
            (LLDP_REMOTE, vec![4, 10, 42, 1], Cell::Number(4)),
            (
                LLDP_REMOTE,
                vec![5, 10, 42, 1],
                Cell::Bytes(vec![2, 0, 0, 0, 0, 2]),
            ),
            (LLDP_REMOTE, vec![6, 10, 42, 1], Cell::Number(5)),
            (
                LLDP_REMOTE,
                vec![7, 10, 42, 1],
                Cell::Bytes(b"eth1".to_vec()),
            ),
            (
                LLDP_MANAGEMENT,
                vec![1, 10, 42, 1, 1, 4, 192, 0, 2, 9],
                Cell::Number(1),
            ),
        ] {
            if root == LLDP_MANAGEMENT && !include_management {
                continue;
            }
            values.insert(root.iter().copied().chain(suffix).collect(), value);
        }
        let worker = thread::spawn(move || {
            let mut buffer = [0; 2048];
            // Four scalars, seven LLDP rows, three LLDP terminators, six
            // independently unsupported IF/BRIDGE/Q-BRIDGE walks.
            // Optional uptime and four independent telemetry walks.
            for _ in 0..(24 + usize::from(include_management)) {
                let (size, peer) = socket.recv_from(&mut buffer).unwrap();
                let mut request = Pdu::from_bytes(&buffer[..size]).unwrap();
                let (name, _) = request.varbinds.clone().next().unwrap();
                let name = oid_parts(&name).unwrap();
                let encoded = match request.message_type {
                    MessageType::GetRequest => binding(&name, values.get(&name), false),
                    MessageType::GetNextRequest => {
                        if let Some(root) = [LLDP_LOCAL, LLDP_REMOTE, LLDP_MANAGEMENT]
                            .into_iter()
                            .find(|root| name.starts_with(root))
                        {
                            if let Some((next, value)) = values.iter().find(|(next, _)| {
                                next.as_slice() > name.as_slice() && next.starts_with(root)
                            }) {
                                binding(next, Some(value), false)
                            } else {
                                binding(&name, None, true)
                            }
                        } else {
                            binding(&name, None, false)
                        }
                    }
                    _ => panic!("Unexpected non-read-only request"),
                };
                request.message_type = MessageType::Response;
                request.varbinds = snmp2::Varbinds::from_bytes(&encoded);
                socket.send_to(&request.to_bytes().unwrap(), peer).unwrap();
            }
        });
        let snapshot = collect(
            &profile,
            Duration::from_millis(200),
            &AtomicBool::new(false),
        )
        .unwrap();
        worker.join().unwrap();
        (profile, snapshot)
    }

    #[test]
    fn collection_keeps_supported_lldp_when_bridge_and_interface_mibs_are_absent() {
        let (profile, snapshot) = collect_mock_topology(true);
        assert!(!snapshot.complete);
        assert_eq!(snapshot.neighbors.len(), 1);
        assert_eq!(snapshot.neighbors[0].local_port, "Gi1/9");
        assert_eq!(
            snapshot.neighbors[0].remote_ip,
            Some(Ipv4Addr::new(192, 0, 2, 9))
        );
        assert_eq!(snapshot.chassis.as_deref(), Some("mac:02:00:00:00:00:01"));
        assert!(!snapshot.warnings.join(" ").contains(&profile.community));
    }

    #[test]
    fn loopback_lldp_survives_save_load_and_partial_refresh_with_manual_metadata() {
        use crate::{
            model::{LinkKind, Map, Status},
            storage,
        };

        let subnet = "127.0.0.0/8";
        let (profile, snapshot) = collect_mock_topology(false);
        let partial = Snapshot {
            target: snapshot.target,
            chassis: snapshot.chassis.clone(),
            name: "updated switch".into(),
            complete: false,
            ..Snapshot::default()
        };
        let mut map = Map::default();
        map.apply_topology(snapshot, "test", subnet);
        assert_eq!(map.links.len(), 1);
        let edge = map.links[0].clone();
        assert_eq!(edge.kind, LinkKind::Observed);
        assert_eq!(
            (edge.from_port.as_str(), edge.to_port.as_str()),
            ("Gi1/9", "eth1")
        );
        assert!(!edge.stale);
        let unresolved = map
            .devices
            .iter()
            .find(|device| device.id == edge.to)
            .unwrap();
        assert_eq!(unresolved.ip, None);
        assert_eq!(unresolved.status, Status::Unknown);
        assert_eq!(unresolved.chassis.as_deref(), Some("mac:02:00:00:00:00:02"));
        let source = map
            .devices
            .iter_mut()
            .find(|device| device.id == edge.from)
            .unwrap();
        source.custom_name = "Nome manuale".into();
        source.notes = "Nota da conservare".into();
        source.position = [123.0, 42.0];

        let directory = tempfile::Builder::new()
            .prefix("topology-test-")
            .tempdir_in(".")
            .unwrap();
        let path = directory.path().join("map.json");
        storage::save(&path, &map).unwrap();
        let mut restored = storage::load(&path).unwrap();
        restored.apply_topology(partial, "test", subnet);
        assert_eq!(restored.devices.len(), 2);
        assert_eq!(restored.links.len(), 1);
        let retained = &restored.links[0];
        assert_eq!(
            (
                retained.from,
                retained.to,
                retained.kind,
                retained.stale,
                retained.from_port.as_str(),
                retained.to_port.as_str()
            ),
            (
                edge.from,
                edge.to,
                LinkKind::Observed,
                false,
                "Gi1/9",
                "eth1"
            )
        );
        let source = restored
            .devices
            .iter()
            .find(|device| device.id == edge.from)
            .unwrap();
        assert_eq!(source.ip, Some(profile.target));
        assert_eq!(source.name, "updated switch");
        assert_eq!(
            (
                source.custom_name.as_str(),
                source.notes.as_str(),
                source.position
            ),
            ("Nome manuale", "Nota da conservare", [123.0, 42.0])
        );
        assert!(
            restored
                .devices
                .iter()
                .any(|device| device.id == edge.to && device.ip.is_none())
        );
    }

    #[test]
    fn cancellation_never_sends_requests_or_exposes_community() {
        let profile = Profile {
            target: Ipv4Addr::LOCALHOST,
            port: 161,
            community: "private-test-secret".into(),
        };
        let snapshot =
            collect(&profile, Duration::from_millis(20), &AtomicBool::new(true)).unwrap();
        assert!(!snapshot.complete);
        assert!(!format!("{snapshot:?}").contains(&profile.community));
    }
}
