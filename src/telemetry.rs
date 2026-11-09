//! Persistable, bounded SNMP observations. Runtime counter baselines never survive a map load.

use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt::Write,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

pub const MAX_RECORDS: usize = 8192;
pub const MAX_TABLES: usize = 64;
pub const MAX_TEXT_CHARS: usize = 512;
const DISPLAY_RECORDS: usize = 64;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TableStatus {
    pub available: bool,
    pub complete: bool,
    pub sampled_at: Option<u64>,
    pub stale: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Entity {
    pub index: u32,
    pub manufacturer: String,
    pub model: String,
    pub software: String,
    pub firmware: String,
}

/// Counter width is retained explicitly; a width change invalidates a rate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counter {
    pub value: u64,
    pub width: u8,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Interface {
    pub index: u32,
    pub name: String,
    pub admin_status: Option<u32>,
    pub oper_status: Option<u32>,
    pub speed_bps: Option<u64>,
    pub rx_octets: Option<Counter>,
    pub tx_octets: Option<Counter>,
    pub rx_errors: Option<u32>,
    pub tx_errors: Option<u32>,
    pub rx_discards: Option<u32>,
    pub tx_discards: Option<u32>,
    pub discontinuity_ticks: Option<u32>,
    #[serde(skip)]
    pub rates: Rates,
}

#[derive(Clone, Debug, Default)]
pub struct Rates {
    pub rx_bps: Option<f64>,
    pub tx_bps: Option<f64>,
    pub rx_errors: Option<u32>,
    pub tx_errors: Option<u32>,
    pub rx_discards: Option<u32>,
    pub tx_discards: Option<u32>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Vlan {
    pub id: u32,
    pub name: String,
}

#[derive(Clone, Debug)]
struct Baseline {
    at: Instant,
    uptime: Option<u32>,
    interfaces: Vec<Interface>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Telemetry {
    /// Unix seconds, for display only (never used to calculate rates).
    pub sampled_at: Option<u64>,
    pub uptime_ticks: Option<u32>,
    #[serde(deserialize_with = "bounded_records")]
    pub entities: Vec<Entity>,
    #[serde(deserialize_with = "bounded_records")]
    pub interfaces: Vec<Interface>,
    #[serde(deserialize_with = "bounded_records")]
    pub vlans: Vec<Vlan>,
    #[serde(deserialize_with = "bounded_records")]
    pub fdb: Vec<crate::topology::FdbEntry>,
    /// Independent walk/scalar status; retained observations are explicitly stale.
    pub tables: BTreeMap<String, TableStatus>,
    #[serde(skip)]
    runtime: Option<Baseline>,
}

fn bounded_records<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Records<T>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Records<T> {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a bounded telemetry table")
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<T>, A::Error> {
            let mut rows = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(MAX_RECORDS));
            while let Some(row) = seq.next_element()? {
                if rows.len() == MAX_RECORDS {
                    return Err(serde::de::Error::custom(
                        "telemetry table exceeds row limit",
                    ));
                }
                rows.push(row);
            }
            Ok(rows)
        }
    }
    deserializer.deserialize_seq(Records(std::marker::PhantomData))
}

impl Telemetry {
    /// Validates persisted observations without trusting agent/map strings or counters.
    /// Empty/default telemetry is valid. Errors contain no supplied values.
    pub fn validate(&self) -> anyhow::Result<()> {
        use anyhow::ensure;
        for size in [
            self.entities.len(),
            self.interfaces.len(),
            self.vlans.len(),
            self.fdb.len(),
        ] {
            ensure!(size <= MAX_RECORDS, "Telemetry table exceeds row limit");
        }
        ensure!(
            self.tables.len() <= MAX_TABLES,
            "Too many telemetry table statuses"
        );
        let valid_text = |text: &str| {
            text.chars().count() <= MAX_TEXT_CHARS && !text.chars().any(char::is_control)
        };
        let mut indices = std::collections::BTreeSet::new();
        for entity in &self.entities {
            ensure!(
                entity.index > 0 && indices.insert(entity.index),
                "Invalid telemetry entity index"
            );
            ensure!(
                [
                    &entity.manufacturer,
                    &entity.model,
                    &entity.software,
                    &entity.firmware
                ]
                .into_iter()
                .all(|s| valid_text(s)),
                "Invalid telemetry entity text"
            );
        }
        indices.clear();
        for port in &self.interfaces {
            ensure!(
                port.index > 0 && indices.insert(port.index),
                "Invalid telemetry interface index"
            );
            ensure!(valid_text(&port.name), "Invalid telemetry interface name");
            ensure!(
                port.admin_status.is_none_or(|s| (1..=3).contains(&s))
                    && port.oper_status.is_none_or(|s| (1..=7).contains(&s)),
                "Invalid telemetry interface state"
            );
            ensure!(
                port.speed_bps
                    .is_none_or(|s| s <= u64::from(u32::MAX) * 1_000_000),
                "Invalid telemetry interface speed"
            );
            for counter in [port.rx_octets, port.tx_octets].into_iter().flatten() {
                ensure!(
                    counter.width == 64
                        || (counter.width == 32 && counter.value <= u64::from(u32::MAX)),
                    "Invalid telemetry counter width or value"
                );
            }
        }
        indices.clear();
        for vlan in &self.vlans {
            ensure!(
                (1..=4094).contains(&vlan.id) && indices.insert(vlan.id) && valid_text(&vlan.name),
                "Invalid telemetry VLAN"
            );
        }
        for entry in &self.fdb {
            ensure!(entry.mac.len() == 17, "Invalid telemetry FDB address");
            let address = entry
                .mac
                .split(':')
                .map(|part| {
                    (part.len() == 2)
                        .then(|| u8::from_str_radix(part, 16).ok())
                        .flatten()
                })
                .collect::<Option<Vec<_>>>();
            ensure!(
                address.is_some_and(|a| a.len() == 6 && a[0] & 1 == 0 && a.iter().any(|b| *b != 0))
                    && valid_text(&entry.port)
                    && !entry.port.is_empty()
                    && entry.vlan.is_none_or(|v| (1..=4094).contains(&v)),
                "Invalid telemetry FDB record"
            );
        }
        ensure!(
            self.tables.keys().all(|s| valid_text(s) && !s.is_empty()),
            "Invalid telemetry table label"
        );
        Ok(())
    }

    pub(crate) fn start_sample() -> Self {
        Self {
            sampled_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs()),
            ..Self::default()
        }
    }

    pub(crate) fn status(&mut self, label: &str, available: bool, complete: bool) {
        self.tables.insert(
            label.to_owned(),
            TableStatus {
                available,
                complete,
                sampled_at: available.then_some(self.sampled_at).flatten(),
                stale: !complete,
            },
        );
    }

    pub(crate) fn finish_sample(&mut self) {
        self.entities.truncate(MAX_RECORDS);
        self.interfaces.truncate(MAX_RECORDS);
        self.vlans.truncate(MAX_RECORDS);
        self.fdb.truncate(MAX_RECORDS);
        self.runtime = Some(Baseline {
            at: Instant::now(),
            uptime: self.uptime_ticks,
            interfaces: self.interfaces.clone(),
        });
    }

    /// Retains independent unsupported tables/columns, but never treats retained
    /// counters (or deserialized counters) as a fresh rate baseline.
    pub fn merge(&mut self, mut incoming: Telemetry) {
        for port in &mut self.interfaces {
            port.rates = Rates::default();
        }
        if let (Some(old), Some(new)) = (&self.runtime, &incoming.runtime) {
            let elapsed = new.at.saturating_duration_since(old.at).as_secs_f64();
            let uptime_ok = matches!((old.uptime, new.uptime), (Some(a), Some(b)) if b > a);
            if elapsed > 0.0 && uptime_ok {
                for port in &mut incoming.interfaces {
                    if let Some(previous) = old.interfaces.iter().find(|p| p.index == port.index)
                        && port.discontinuity_ticks == previous.discontinuity_ticks
                    {
                        port.rates = rates(previous, port, elapsed);
                    }
                }
            }
        }
        if incoming.sampled_at.is_some() {
            self.sampled_at = incoming.sampled_at;
        }
        if incoming.uptime_ticks.is_some() {
            self.uptime_ticks = incoming.uptime_ticks;
        }
        merge_records(
            &mut self.entities,
            incoming.entities,
            false,
            |e| e.index,
            |old, new| {
                if !new.manufacturer.is_empty() {
                    old.manufacturer = new.manufacturer;
                }
                if !new.model.is_empty() {
                    old.model = new.model;
                }
                if !new.software.is_empty() {
                    old.software = new.software;
                }
                if !new.firmware.is_empty() {
                    old.firmware = new.firmware;
                }
            },
        );
        if complete(&incoming.tables, "IF-MIB contatori")
            && complete(&incoming.tables, "IF-MIB estesa")
        {
            self.interfaces
                .retain(|old| incoming.interfaces.iter().any(|new| new.index == old.index));
        }
        // Interface columns have independent support, so missing values must not erase old ones.
        merge_records(
            &mut self.interfaces,
            incoming.interfaces,
            false,
            |p| p.index,
            |old, new| {
                if !new.name.is_empty() {
                    old.name = new.name;
                }
                macro_rules! copy_present {
                ($($field:ident),*) => { $(if new.$field.is_some() { old.$field = new.$field; })* };
            }
                copy_present!(
                    admin_status,
                    oper_status,
                    speed_bps,
                    rx_octets,
                    tx_octets,
                    rx_errors,
                    tx_errors,
                    rx_discards,
                    tx_discards,
                    discontinuity_ticks
                );
                old.rates = new.rates;
            },
        );
        merge_records(
            &mut self.vlans,
            incoming.vlans,
            complete(&incoming.tables, "VLAN nomi") && complete(&incoming.tables, "Q-BRIDGE VLAN"),
            |v| v.id,
            |old, new| {
                if !new.name.is_empty() {
                    old.name = new.name;
                }
            },
        );
        if complete(&incoming.tables, "FDB") {
            self.fdb = incoming.fdb;
        } else {
            self.fdb.extend(incoming.fdb);
            self.fdb.sort();
            self.fdb.dedup();
        }
        self.fdb.truncate(MAX_RECORDS);
        for status in self.tables.values_mut() {
            status.stale = true;
        }
        for (name, mut status) in incoming.tables {
            if !status.available
                && let Some(previous) = self.tables.get(&name)
            {
                status.available = previous.available;
                status.sampled_at = previous.sampled_at;
                status.stale = true;
            }
            self.tables.insert(name, status);
        }
        self.runtime = incoming.runtime;
    }

    /// Bounded text for the device details pane. Missing values are never zero-filled.
    pub fn summary(&self) -> String {
        if self.sampled_at.is_none() {
            return "SNMP telemetry: unavailable".into();
        }
        let persisted = self.runtime.is_none();
        let partial = persisted || self.tables.values().any(|s| !s.complete || s.stale);
        let mut out = format!(
            "SNMP telemetry: {} (sample Unix {})\n",
            if partial {
                "partial / stale retained data"
            } else {
                "available"
            },
            self.sampled_at.unwrap_or_default()
        );
        if let Some(ticks) = self.uptime_ticks {
            let _ = writeln!(out, "Agent uptime: {:.2} s", f64::from(ticks) / 100.0);
        } else {
            out.push_str("Agent uptime: unavailable\n");
        }
        for entity in self.entities.iter().take(DISPLAY_RECORDS) {
            let _ = writeln!(
                out,
                "Entity {}: manufacturer={} model={} software={} firmware={}",
                entity.index,
                label(&entity.manufacturer),
                label(&entity.model),
                label(&entity.software),
                label(&entity.firmware)
            );
        }
        for port in self.interfaces.iter().take(DISPLAY_RECORDS) {
            let _ = writeln!(
                out,
                "Port {} {}: admin={} oper={} speed={} bit/s; RX={} TX={} bit/s; errors RX/TX={}/{} Δ{}/{}; discards RX/TX={}/{} Δ{}/{}; octets RX/TX={}/{}",
                port.index,
                label(&port.name),
                state(port.admin_status),
                state(port.oper_status),
                display(port.speed_bps),
                display(port.rates.rx_bps.map(|v| format!("{v:.1}"))),
                display(port.rates.tx_bps.map(|v| format!("{v:.1}"))),
                display(port.rx_errors),
                display(port.tx_errors),
                display(port.rates.rx_errors),
                display(port.rates.tx_errors),
                display(port.rx_discards),
                display(port.tx_discards),
                display(port.rates.rx_discards),
                display(port.rates.tx_discards),
                counter_label(port.rx_octets),
                counter_label(port.tx_octets)
            );
        }
        for vlan in self.vlans.iter().take(DISPLAY_RECORDS) {
            let _ = writeln!(out, "VLAN {}: {}", vlan.id, label(&vlan.name));
        }
        for entry in self.fdb.iter().take(DISPLAY_RECORDS) {
            let _ = writeln!(
                out,
                "FDB {} → {} VLAN {}",
                label(&entry.mac),
                label(&entry.port),
                display(entry.vlan)
            );
        }
        for (name, status) in self.tables.iter().take(DISPLAY_RECORDS) {
            let _ = writeln!(
                out,
                "{}: {}",
                label(name),
                if !status.available {
                    "unavailable"
                } else if persisted || status.stale {
                    "partial / stale"
                } else {
                    "available"
                }
            );
        }
        if [
            self.entities.len(),
            self.interfaces.len(),
            self.vlans.len(),
            self.fdb.len(),
        ]
        .into_iter()
        .any(|n| n > DISPLAY_RECORDS)
        {
            out.push_str("Display truncated to 64 records per table.\n");
        }
        out
    }
}

fn complete(tables: &BTreeMap<String, TableStatus>, label: &str) -> bool {
    tables.get(label).is_some_and(|s| s.complete && s.available)
}

fn merge_records<T>(
    old: &mut Vec<T>,
    new: Vec<T>,
    replace: bool,
    key: impl Fn(&T) -> u32,
    merge: impl Fn(&mut T, T),
) {
    if replace {
        *old = new.into_iter().take(MAX_RECORDS).collect();
        return;
    }
    for item in new.into_iter().take(MAX_RECORDS) {
        if let Some(previous) = old.iter_mut().find(|p| key(p) == key(&item)) {
            merge(previous, item);
        } else if old.len() < MAX_RECORDS {
            old.push(item);
        }
    }
}

fn octet_delta(old: Option<Counter>, new: Option<Counter>) -> Option<u64> {
    let (old, new) = old.zip(new)?;
    if old.width != new.width || !matches!(new.width, 32 | 64) {
        return None;
    }
    // A decrease may be a reset OR wrap; never guess and create a spike.
    new.value.checked_sub(old.value)
}

fn rates(old: &Interface, new: &Interface, seconds: f64) -> Rates {
    // Any counter decrease resets this interface's whole observation interval.
    let pairs = [
        (old.rx_errors, new.rx_errors),
        (old.tx_errors, new.tx_errors),
        (old.rx_discards, new.rx_discards),
        (old.tx_discards, new.tx_discards),
    ];
    if pairs
        .iter()
        .any(|(a, b)| a.zip(*b).is_some_and(|(a, b)| b < a))
        || [
            (old.rx_octets, new.rx_octets),
            (old.tx_octets, new.tx_octets),
        ]
        .iter()
        .any(|(a, b)| {
            a.zip(*b)
                .is_some_and(|(a, b)| a.width != b.width || b.value < a.value)
        })
    {
        return Rates::default();
    }
    let traffic = |a, b| {
        octet_delta(a, b)
            .map(|d| d as f64 * 8.0 / seconds)
            .filter(|bps| {
                new.speed_bps
                    .is_none_or(|speed| speed == 0 || *bps <= speed as f64 * 1.1)
            })
    };
    let delta = |a: Option<u32>, b: Option<u32>| a.zip(b).and_then(|(a, b)| b.checked_sub(a));
    Rates {
        rx_bps: traffic(old.rx_octets, new.rx_octets),
        tx_bps: traffic(old.tx_octets, new.tx_octets),
        rx_errors: delta(old.rx_errors, new.rx_errors),
        tx_errors: delta(old.tx_errors, new.tx_errors),
        rx_discards: delta(old.rx_discards, new.rx_discards),
        tx_discards: delta(old.tx_discards, new.tx_discards),
    }
}

fn label(value: &str) -> String {
    if value.is_empty() {
        "unavailable".into()
    } else {
        value
            .chars()
            .filter(|c| !c.is_control())
            .take(512)
            .collect()
    }
}

fn display(value: Option<impl std::fmt::Display>) -> String {
    value.map(|v| v.to_string()).unwrap_or_else(|| "—".into())
}

fn counter_label(value: Option<Counter>) -> String {
    display(value.map(|c| format!("{} (Counter{})", c.value, c.width)))
}

fn state(value: Option<u32>) -> String {
    match value {
        Some(1) => "up".into(),
        Some(2) => "down".into(),
        Some(3) => "testing".into(),
        Some(4) => "unknown".into(),
        Some(5) => "dormant".into(),
        Some(6) => "notPresent".into(),
        Some(7) => "lowerLayerDown".into(),
        other => display(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn sample(ticks: u32, octets: u64) -> Telemetry {
        let mut value = Telemetry::start_sample();
        value.uptime_ticks = Some(ticks);
        value.interfaces.push(Interface {
            index: 1,
            rx_octets: Some(Counter {
                value: octets,
                width: 64,
            }),
            rx_errors: Some((octets / 100) as u32),
            discontinuity_ticks: Some(0),
            ..Interface::default()
        });
        value.finish_sample();
        value
    }

    #[test]
    fn consecutive_samples_compute_rates_and_reset_conditions_suppress_them() {
        let mut old = sample(100, 1000);
        let mut new = sample(200, 2000);
        new.runtime.as_mut().unwrap().at =
            old.runtime.as_ref().unwrap().at + Duration::from_secs(2);
        old.merge(new);
        assert_eq!(old.interfaces[0].rates.rx_bps, Some(4000.0));
        assert_eq!(old.interfaces[0].rates.rx_errors, Some(10));
        for mode in 0..5 {
            let mut previous = sample(200, 2000);
            let mut next = sample(300, 3000);
            match mode {
                0 => next.uptime_ticks = Some(1),
                1 => next.interfaces[0].rx_octets.as_mut().unwrap().value = 1,
                2 => next.interfaces[0].rx_octets.as_mut().unwrap().width = 32,
                3 => next.interfaces[0].discontinuity_ticks = Some(250),
                _ => next.interfaces[0].rx_errors = Some(1),
            }
            next.finish_sample();
            previous.merge(next);
            assert_eq!(previous.interfaces[0].rates.rx_bps, None, "mode {mode}");
        }
    }

    #[test]
    fn roundtrip_never_reuses_persisted_baselines_or_rates() {
        let value = sample(100, 1000);
        let json = serde_json::to_string(&value).unwrap();
        assert!(!json.contains("runtime"));
        assert!(!json.contains("rates"));
        let mut restored: Telemetry = serde_json::from_str(&json).unwrap();
        assert!(restored.summary().contains("stale"));
        restored.merge(sample(200, 2000));
        assert_eq!(restored.interfaces[0].rates.rx_bps, None);
        assert_eq!(restored.interfaces[0].rx_octets.unwrap().width, 64);
    }

    #[test]
    fn partial_refresh_retains_independent_tables_and_marks_stale() {
        let mut value = sample(100, 1000);
        value.entities.push(Entity {
            index: 1,
            model: "Actual model".into(),
            firmware: "1.2".into(),
            ..Entity::default()
        });
        value.status("ENTITY-MIB", true, true);
        let mut next = sample(200, 2000);
        next.status("ENTITY-MIB", false, false);
        next.interfaces[0].rx_octets = None;
        next.finish_sample();
        value.merge(next);
        assert_eq!(value.entities[0].model, "Actual model");
        assert_eq!(value.interfaces[0].rx_octets.unwrap().value, 1000);
        assert!(value.tables["ENTITY-MIB"].stale);
        assert!(value.summary().contains("firmware=1.2"));
    }

    #[test]
    fn counter_wrap_is_not_guessed() {
        assert_eq!(
            octet_delta(
                Some(Counter {
                    value: u32::MAX as u64,
                    width: 32
                }),
                Some(Counter {
                    value: 10,
                    width: 32
                })
            ),
            None
        );
    }

    #[test]
    fn deserialize_defaults_and_table_bounds_are_enforced() {
        let empty: Telemetry = serde_json::from_str("{}").unwrap();
        assert!(empty.interfaces.is_empty());
        let oversized = format!(r#"{{"vlans":[{}]}}"#, vec!["{}"; MAX_RECORDS + 1].join(","));
        assert!(serde_json::from_str::<Telemetry>(&oversized).is_err());
    }

    #[test]
    fn validate_rejects_untrusted_counter_widths_text_and_vlan_ids() {
        assert!(Telemetry::default().validate().is_ok());
        let mut value = sample(100, 1000);
        assert!(value.validate().is_ok());
        value.interfaces[0].rx_octets = Some(Counter {
            value: u64::from(u32::MAX) + 1,
            width: 32,
        });
        assert!(value.validate().is_err());
        value.interfaces[0].rx_octets = None;
        value.interfaces[0].name = "port\nforged".into();
        assert!(value.validate().is_err());
        value.interfaces[0].name.clear();
        value.vlans.push(Vlan {
            id: 4095,
            name: String::new(),
        });
        assert!(value.validate().is_err());
    }
}
