use serde::{Deserialize, Serialize};
use std::{net::Ipv4Addr, time::SystemTime};

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn latency_label(microseconds: u64) -> String {
    if microseconds == 0 {
        "<1 ms".into()
    } else {
        format!("{:.2} ms", microseconds as f64 / 1000.0)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Settings {
    pub networks: String,
    pub context: String,
    pub interface: String,
    pub max_addresses: usize,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub interval_secs: u64,
    pub failure_threshold: u32,
    pub tcp_ports: Vec<u16>,
    pub icmp: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            networks: String::new(),
            context: "Rete principale".into(),
            interface: String::new(),
            max_addresses: 4096,
            concurrency: 32,
            timeout_ms: 1000,
            interval_secs: 30,
            failure_threshold: 3,
            tcp_ports: vec![22, 80, 443],
            icmp: true,
        }
    }
}

impl Settings {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.context.trim().is_empty(),
            "Contesto rete obbligatorio"
        );
        anyhow::ensure!(
            (1..=1_048_576).contains(&self.max_addresses),
            "Limite indirizzi: 1..1048576"
        );
        anyhow::ensure!((1..=128).contains(&self.concurrency), "Concorrenza: 1..128");
        anyhow::ensure!(
            (50..=10_000).contains(&self.timeout_ms),
            "Timeout: 50..10000 ms"
        );
        anyhow::ensure!(
            (1..=86400).contains(&self.interval_secs),
            "Intervallo: 1..86400 secondi"
        );
        anyhow::ensure!(
            (1..=100).contains(&self.failure_threshold),
            "Soglia: 1..100"
        );
        anyhow::ensure!(
            self.tcp_ports.len() <= 16 && !self.tcp_ports.contains(&0),
            "Massimo 16 porte TCP, tutte non nulle"
        );
        anyhow::ensure!(
            self.icmp || !self.tcp_ports.is_empty(),
            "Abilitare almeno una sonda"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    #[default]
    Unknown,
    Up,
    Checking,
    Down,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unknown => "? Sconosciuto",
            Self::Up => "+ Raggiungibile",
            Self::Checking => "~ In verifica",
            Self::Down => "- Non raggiungibile",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Device {
    pub id: u64,
    pub context: String,
    pub group: String,
    pub ip: Option<Ipv4Addr>,
    pub mac: Option<String>,
    pub chassis: Option<String>,
    pub name: String,
    pub custom_name: String,
    pub notes: String,
    pub description: String,
    pub position: [f32; 2],
    pub last_seen: Option<u64>,
    pub last_method: String,
    #[serde(default)]
    pub last_latency_us: Option<u64>,
    pub historical_status: Status,
    #[serde(default)]
    pub manual: bool,
    #[serde(skip)]
    pub status: Status,
    #[serde(skip)]
    pub failures: u32,
}

impl Device {
    pub fn label(&self) -> String {
        if !self.custom_name.is_empty() {
            self.custom_name.clone()
        } else if !self.name.is_empty() {
            self.name.clone()
        } else {
            self.ip
                .map_or_else(|| "Vicino LLDP".into(), |ip| ip.to_string())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinkKind {
    Observed,
    Inferred,
    Manual,
}

impl LinkKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Observed => "Rilevato LLDP",
            Self::Inferred => "Dedotto",
            Self::Manual => "Manuale",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Link {
    pub from: u64,
    pub to: u64,
    pub from_port: String,
    pub to_port: String,
    pub kind: LinkKind,
    pub evidence: String,
    pub source: u64,
    pub last_seen: u64,
    pub stale: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub time: u64,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Map {
    pub version: u32,
    pub settings: Settings,
    pub devices: Vec<Device>,
    pub links: Vec<Link>,
    pub events: Vec<Event>,
    pub next_id: u64,
}

impl Default for Map {
    fn default() -> Self {
        Self {
            version: 1,
            settings: Settings::default(),
            devices: vec![],
            links: vec![],
            events: vec![],
            next_id: 1,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Observation {
    pub ip: Option<Ipv4Addr>,
    pub context: String,
    pub group: String,
    pub mac: Option<String>,
    pub chassis: Option<String>,
    pub name: String,
    pub description: String,
    pub method: String,
    pub responding: bool,
}

impl Map {
    pub fn event(&mut self, message: impl Into<String>) {
        self.events.push(Event {
            time: now(),
            message: message.into(),
        });
        if self.events.len() > 10_000 {
            self.events.drain(..self.events.len() - 10_000);
        }
    }

    pub fn merge(&mut self, obs: Observation) -> u64 {
        let compatible = |d: &&Device| {
            d.context == obs.context
                && !(d.chassis.is_some() && obs.chassis.is_some() && d.chassis != obs.chassis)
                && !(d.mac.is_some() && obs.mac.is_some() && d.mac != obs.mac)
        };
        let strong: Vec<_> = self
            .devices
            .iter()
            .filter(compatible)
            .filter(|d| {
                obs.chassis.is_some() && d.chassis == obs.chassis
                    || obs.mac.is_some() && d.mac == obs.mac
            })
            .map(|d| d.id)
            .collect();
        let by_ip: Vec<_> = self
            .devices
            .iter()
            .filter(compatible)
            .filter(|d| obs.ip.is_some() && d.ip == obs.ip)
            .map(|d| d.id)
            .collect();
        let ambiguous_response =
            strong.is_empty() && by_ip.len() > 1 && obs.mac.is_none() && obs.chassis.is_none();
        let id = if strong.len() == 1 {
            Some(strong[0])
        } else if by_ip.len() == 1 {
            Some(by_ip[0])
        } else if ambiguous_response {
            // A reply proves an IP is reachable, not which conflicting device owns it.
            by_ip.iter().max().copied()
        } else {
            let unidentified: Vec<_> = self
                .devices
                .iter()
                .filter(compatible)
                .filter(|d| d.ip == obs.ip && d.mac.is_none() && d.chassis.is_none())
                .map(|d| d.id)
                .collect();
            if obs.mac.is_none() && obs.chassis.is_none() && unidentified.len() == 1 {
                Some(unidentified[0])
            } else {
                None
            }
        };
        let id = match id {
            Some(id) => id,
            None => {
                if obs.ip.is_some()
                    && self
                        .devices
                        .iter()
                        .any(|d| d.context == obs.context && d.ip == obs.ip)
                {
                    self.event(format!(
                        "Identita ambigua / possibile riuso IP: {}",
                        obs.ip.map(|x| x.to_string()).unwrap_or_default()
                    ));
                }
                let id = self.next_id;
                self.next_id += 1;
                let group_count = self
                    .devices
                    .iter()
                    .filter(|d| d.context == obs.context && d.group == obs.group)
                    .count();
                let group_y = self
                    .devices
                    .iter()
                    .filter(|d| d.context == obs.context && d.group == obs.group)
                    .map(|d| d.position[1])
                    .min_by(f32::total_cmp)
                    .unwrap_or_else(|| {
                        self.devices
                            .iter()
                            .map(|d| d.position[1] + 200.0)
                            .max_by(f32::total_cmp)
                            .unwrap_or(0.0)
                    });
                self.devices.push(Device {
                    id,
                    context: obs.context.clone(),
                    group: obs.group.clone(),
                    ip: None,
                    mac: None,
                    chassis: None,
                    name: String::new(),
                    custom_name: String::new(),
                    notes: String::new(),
                    description: String::new(),
                    position: [
                        (group_count % 8) as f32 * 180.0,
                        group_y + (group_count / 8) as f32 * 100.0,
                    ],
                    last_seen: None,
                    last_method: String::new(),
                    last_latency_us: None,
                    historical_status: Status::Unknown,
                    status: Status::Unknown,
                    failures: 0,
                    manual: false,
                });
                id
            }
        };
        if obs.responding && (obs.mac.is_some() || obs.chassis.is_some()) {
            for previous in self.devices.iter_mut().filter(|d| {
                d.id != id && d.context == obs.context && obs.ip.is_some() && d.ip == obs.ip
            }) {
                previous.status = Status::Unknown;
                previous.failures = 0;
                previous.last_method = "IP riutilizzato / identita non piu confermata".into();
            }
        }
        if let Some(d) = self.devices.iter_mut().find(|d| d.id == id) {
            if obs.ip.is_some() {
                d.ip = obs.ip;
            }
            if obs.mac.is_some() {
                d.mac = obs.mac;
            }
            if obs.chassis.is_some() {
                d.chassis = obs.chassis;
            }
            if !obs.name.is_empty() {
                d.name = obs.name;
            }
            if !obs.description.is_empty() {
                d.description = obs.description;
            }
            if !obs.group.is_empty() && (obs.ip.is_some() || d.ip.is_none()) {
                d.group = obs.group;
            }
            if obs.responding && !ambiguous_response {
                d.last_seen = Some(now());
                d.last_method = obs.method;
                d.status = Status::Up;
                d.historical_status = Status::Up;
                d.failures = 0;
            }
            if ambiguous_response {
                d.status = Status::Unknown;
                d.last_method = "Risposta da IP ambiguo; identita non confermata".into();
            }
        }
        id
    }

    pub fn add_link(&mut self, mut link: Link) {
        // Canonical endpoints preserve parallel ports while deduplicating reciprocal LLDP.
        if link.from > link.to {
            std::mem::swap(&mut link.from, &mut link.to);
            std::mem::swap(&mut link.from_port, &mut link.to_port);
        }
        if let Some(old) = self.links.iter_mut().find(|old| {
            old.from == link.from
                && old.to == link.to
                && old.from_port == link.from_port
                && old.to_port == link.to_port
                && old.kind == link.kind
                && old.source == link.source
        }) {
            *old = link;
        } else if link.from != link.to {
            self.links.push(link);
        }
    }

    pub fn apply_topology(
        &mut self,
        snapshot: crate::topology::Snapshot,
        context: &str,
        group: &str,
    ) {
        let source = self.merge(Observation {
            ip: Some(snapshot.target),
            context: context.into(),
            group: group.into(),
            mac: None,
            chassis: snapshot.chassis,
            name: snapshot.name,
            description: snapshot.description,
            method: "SNMPv2c".into(),
            responding: true,
        });
        if snapshot.complete {
            for link in &mut self.links {
                if link.source == source && link.kind != LinkKind::Manual {
                    link.stale = true;
                }
            }
        }
        for adjacency in snapshot.neighbors {
            // Never probe newly advertised management addresses outside the user's ranges.
            let remote_ip = adjacency
                .remote_ip
                .filter(|ip| ip.octets()[0] > 0 && ip.octets()[0] < 224);
            let remote_group = remote_ip
                .map(|ip| crate::discovery::group_for(ip, &self.settings.networks))
                .unwrap_or_else(|| "Vicini LLDP".into());
            let target = self.merge(Observation {
                ip: remote_ip,
                context: context.into(),
                group: remote_group,
                mac: adjacency
                    .remote_chassis
                    .strip_prefix("mac:")
                    .map(str::to_owned),
                chassis: Some(adjacency.remote_chassis),
                name: adjacency.remote_name,
                description: String::new(),
                method: "LLDP via SNMP".into(),
                responding: false,
            });
            self.add_link(Link {
                from: source,
                to: target,
                from_port: adjacency.local_port,
                to_port: adjacency.remote_port,
                kind: LinkKind::Observed,
                evidence: "Adiacenza pubblicata in LLDP-MIB".into(),
                source,
                last_seen: now(),
                stale: false,
            });
        }
        for entry in snapshot.fdb {
            let matches: Vec<_> = self
                .devices
                .iter()
                .filter(|d| {
                    d.context == context
                        && d.mac.as_deref() == Some(entry.mac.as_str())
                        && d.id != source
                })
                .map(|d| d.id)
                .collect();
            if matches.len() == 1 {
                self.add_link(Link {
                    from: source,
                    to: matches[0],
                    from_port: entry.port,
                    to_port: String::new(),
                    kind: LinkKind::Inferred,
                    evidence: format!(
                        "MAC appreso in FDB; non prova collegamento diretto. VLAN {:?}",
                        entry.vlan
                    ),
                    source,
                    last_seen: now(),
                    stale: false,
                });
            }
        }
        for warning in snapshot.warnings {
            self.event(format!("SNMP {}: {warning}", snapshot.target));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn observation(mac: &str) -> Observation {
        Observation {
            ip: Some(Ipv4Addr::LOCALHOST),
            context: "test".into(),
            group: "loopback".into(),
            mac: Some(mac.into()),
            chassis: None,
            name: "Host".into(),
            description: String::new(),
            method: "TCP".into(),
            responding: true,
        }
    }
    #[test]
    fn rescan_preserves_manual_metadata_and_coordinates() {
        let mut map = Map::default();
        let id = map.merge(observation("00:01:02:03:04:05"));
        map.devices[0].custom_name = "Personalizzato".into();
        map.devices[0].position = [42.0, 99.0];
        assert_eq!(map.merge(observation("00:01:02:03:04:05")), id);
        assert_eq!(
            (
                map.devices.len(),
                map.devices[0].label(),
                map.devices[0].position
            ),
            (1, "Personalizzato".into(), [42.0, 99.0])
        );
    }
    #[test]
    fn reused_ip_with_different_mac_is_not_destructively_merged() {
        let mut map = Map::default();
        let first = map.merge(observation("00:01:02:03:04:05"));
        assert_ne!(map.merge(observation("00:01:02:03:04:06")), first);
        assert_eq!(map.devices[0].status, Status::Unknown);
        let mut without_identity = observation("00:01:02:03:04:06");
        without_identity.mac = None;
        map.merge(without_identity.clone());
        map.merge(without_identity);
        assert_eq!(map.devices.len(), 2);
    }
    #[test]
    fn strong_identity_survives_address_change() {
        let mut map = Map::default();
        let id = map.merge(observation("00:01:02:03:04:05"));
        let mut obs = observation("00:01:02:03:04:05");
        obs.ip = Some(Ipv4Addr::new(127, 0, 0, 2));
        assert_eq!(map.merge(obs), id);
    }
    #[test]
    fn partial_topology_preserves_links_and_complete_walk_marks_only_its_source_stale() {
        let mut map = Map::default();
        map.settings.context = "test".into();
        let source = map.merge(observation("00:01:02:03:04:05"));
        let mut other = observation("00:01:02:03:04:06");
        other.ip = Some(Ipv4Addr::new(127, 0, 0, 2));
        let target = map.merge(other);
        for kind in [LinkKind::Observed, LinkKind::Manual] {
            map.add_link(Link {
                from: source,
                to: target,
                from_port: "1".into(),
                to_port: "2".into(),
                kind,
                evidence: "t".into(),
                source,
                last_seen: now(),
                stale: false,
            });
        }
        map.apply_topology(
            crate::topology::Snapshot {
                target: Ipv4Addr::LOCALHOST,
                complete: false,
                ..Default::default()
            },
            "test",
            "loopback",
        );
        assert!(map.links.iter().all(|l| !l.stale));
        map.apply_topology(
            crate::topology::Snapshot {
                target: Ipv4Addr::LOCALHOST,
                complete: true,
                ..Default::default()
            },
            "test",
            "loopback",
        );
        assert_eq!(
            map.links.iter().map(|l| l.stale).collect::<Vec<_>>(),
            vec![true, false]
        );
    }
}
