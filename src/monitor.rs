use crate::{
    discovery::ProbeResult,
    model::{Map, Status, now},
};

pub fn apply(map: &mut Map, id: u64, result: ProbeResult) {
    let threshold = map.settings.failure_threshold;
    let Some(device) = map.devices.iter_mut().find(|d| d.id == id) else {
        return;
    };
    let previous = device.status;
    match result {
        ProbeResult::Responding { method, latency } => {
            device.status = Status::Up;
            device.failures = 0;
            device.last_seen = Some(now());
            device.last_method = method;
            device.last_latency_us = Some(latency.as_micros().try_into().unwrap_or(u64::MAX));
        }
        ProbeResult::Negative => {
            device.failures = device.failures.saturating_add(1);
            device.last_latency_us = None;
            device.status = if device.failures >= threshold {
                Status::Down
            } else {
                Status::Checking
            };
        }
        ProbeResult::Unknown(reason) => {
            device.status = Status::Unknown;
            device.failures = 0;
            device.last_method = reason;
            device.last_latency_us = None;
        }
    }
    if device.status != Status::Unknown {
        device.historical_status = device.status;
    }
    let status = device.status;
    let label = device.label();
    if previous != status {
        map.event(format!(
            "{label}: {} -> {}",
            previous.label(),
            status.label()
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Observation;
    #[test]
    fn three_failed_cycles_then_one_reply_recovers_without_moving_node() {
        let mut map = Map::default();
        let id = map.merge(Observation {
            ip: Some(std::net::Ipv4Addr::LOCALHOST),
            context: "t".into(),
            group: "t".into(),
            mac: None,
            chassis: None,
            name: String::new(),
            description: String::new(),
            method: "TCP".into(),
            responding: true,
        });
        let position = map.devices[0].position;
        apply(&mut map, id, ProbeResult::Negative);
        apply(&mut map, id, ProbeResult::Negative);
        assert_eq!(map.devices[0].status, Status::Checking);
        apply(&mut map, id, ProbeResult::Negative);
        assert_eq!(map.devices[0].status, Status::Down);
        apply(
            &mut map,
            id,
            ProbeResult::Unknown("Rete locale non disponibile".into()),
        );
        assert_eq!(map.devices[0].failures, 0);
        apply(
            &mut map,
            id,
            ProbeResult::Responding {
                method: "TCP".into(),
                latency: std::time::Duration::from_micros(950),
            },
        );
        assert_eq!(map.devices[0].last_latency_us, Some(950));
        assert_eq!(
            (map.devices[0].status, map.devices[0].position),
            (Status::Up, position)
        );
    }
}
