use crate::{
    enrichment,
    model::Settings,
    platform::{self, EchoResult},
    topology::{self, Profile},
    trace,
};
use anyhow::{Context, Result, ensure};
use ipnet::Ipv4Net;
use std::{
    collections::BTreeSet,
    net::{Ipv4Addr, SocketAddr, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::Sender,
    },
    thread,
    time::{Duration, Instant, SystemTime},
};

pub fn networks(text: &str) -> Result<Vec<Ipv4Net>> {
    text.split(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<Ipv4Net>()
                .with_context(|| format!("Subnet IPv4 non valida: {s}"))
        })
        .collect()
}

pub fn targets(text: &str, limit: usize) -> Result<Vec<Ipv4Addr>> {
    ensure!(limit > 0, "Limite indirizzi nullo");
    let nets = networks(text)?;
    ensure!(!nets.is_empty(), "Inserire almeno una subnet CIDR");
    let mut intervals: Vec<(u64, u64)> = nets
        .iter()
        .map(|net| {
            let offset = u64::from(net.prefix_len() < 31);
            (
                u32::from(net.network()) as u64 + offset,
                u32::from(net.broadcast()) as u64 - offset,
            )
        })
        .collect();
    intervals.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (start, end) in intervals {
        if let Some(last) = merged.last_mut()
            && start <= last.1 + 1
        {
            last.1 = last.1.max(end);
            continue;
        }
        merged.push((start, end));
    }
    let count: u64 = merged.iter().map(|(s, e)| e - s + 1).sum();
    ensure!(
        count <= limit as u64,
        "{count} indirizzi richiesti, limite {limit}. Ridurre le subnet o aumentare esplicitamente il limite."
    );
    ensure!(
        merged
            .iter()
            .all(|(s, e)| *s >= (1u64 << 24) && *e < (224u64 << 24)),
        "Sono consentite solo destinazioni IPv4 unicast (non 0/8 o multicast)"
    );
    Ok(merged
        .into_iter()
        .flat_map(|(s, e)| (s..=e).map(|n| Ipv4Addr::from(n as u32)))
        .collect())
}

pub fn group_for(ip: Ipv4Addr, text: &str) -> String {
    networks(text)
        .unwrap_or_default()
        .into_iter()
        .filter(|net| net.contains(&ip))
        .max_by_key(Ipv4Net::prefix_len)
        .map_or_else(
            || "Fuori subnet / manuali".into(),
            |net| net.trunc().to_string(),
        )
}

#[derive(Clone, Debug)]
pub enum ProbeResult {
    Responding { method: String, latency: Duration },
    Negative,
    Unknown(String),
}

#[derive(Clone, Debug)]
pub struct ProbeReport {
    pub result: ProbeResult,
    pub icmp: Option<EchoResult>,
}

pub fn probe(
    ip: Ipv4Addr,
    settings: &Settings,
    profile: Option<&Profile>,
    cancel: &AtomicBool,
) -> ProbeReport {
    let icmp = if settings.icmp && !cancel.load(Ordering::Relaxed) {
        Some(platform::echo(
            ip,
            Duration::from_millis(settings.timeout_ms),
        ))
    } else {
        None
    };
    let result = probe_result(ip, settings, profile, cancel, icmp.as_ref());
    ProbeReport { result, icmp }
}

fn probe_result(
    ip: Ipv4Addr,
    settings: &Settings,
    profile: Option<&Profile>,
    cancel: &AtomicBool,
    icmp: Option<&EchoResult>,
) -> ProbeResult {
    let timeout = Duration::from_millis(settings.timeout_ms);
    let mut local_error = None;
    let mut invalid_negative = false;
    let mut usable = false;
    if cancel.load(Ordering::Relaxed) {
        return ProbeResult::Unknown("Annullato".into());
    }
    if let Some(icmp) = icmp {
        match icmp {
            EchoResult::Reply(latency) => {
                return ProbeResult::Responding {
                    method: "ICMP".into(),
                    latency: *latency,
                };
            }
            EchoResult::NoReply => usable = true,
            EchoResult::Unavailable(reason) => local_error = Some(reason.clone()),
            EchoResult::LocalError(reason) => {
                invalid_negative = true;
                local_error = Some(reason.clone());
            }
        }
    }
    let ports: BTreeSet<_> = settings.tcp_ports.iter().copied().collect();
    let tcp_started = Instant::now();
    for (index, port) in ports.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            return ProbeResult::Unknown("Annullato".into());
        }
        // One per-host budget for the TCP phase, not one full timeout per port.
        let budget = timeout.saturating_sub(tcp_started.elapsed());
        let slot = budget / (ports.len() - index) as u32;
        if slot.is_zero() {
            break;
        }
        let started = Instant::now();
        match TcpStream::connect_timeout(&SocketAddr::from((ip, *port)), slot) {
            Ok(_) => {
                return ProbeResult::Responding {
                    method: format!("TCP {port}"),
                    latency: started.elapsed(),
                };
            }
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                return ProbeResult::Responding {
                    method: format!("TCP {port} (rifiutato)"),
                    latency: started.elapsed(),
                };
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::PermissionDenied
                        | std::io::ErrorKind::NetworkUnreachable
                        | std::io::ErrorKind::AddrNotAvailable
                ) =>
            {
                local_error = Some(format!("Sonda locale: {error}"));
                invalid_negative = true;
            }
            Err(_) => usable = true,
        }
    }
    if let Some(profile) = profile
        && !cancel.load(Ordering::Relaxed)
    {
        let started = Instant::now();
        match topology::alive(profile, timeout) {
            Ok(true) => {
                return ProbeResult::Responding {
                    method: "SNMPv2c".into(),
                    latency: started.elapsed(),
                };
            }
            Ok(false) => usable = true,
            Err(_) => {}
        }
    }
    if cancel.load(Ordering::Relaxed) {
        ProbeResult::Unknown("Annullato".into())
    } else if invalid_negative {
        ProbeResult::Unknown(local_error.unwrap_or_else(|| "Problema di rete locale".into()))
    } else if usable {
        ProbeResult::Negative
    } else {
        ProbeResult::Unknown(local_error.unwrap_or_else(|| "Nessuna sonda disponibile".into()))
    }
}

#[derive(Clone)]
pub struct Target {
    pub id: u64,
    pub ip: Ipv4Addr,
}

pub enum JobMessage {
    Host {
        job: u64,
        target: Target,
        result: ProbeReport,
    },
    NetworkInfo {
        job: u64,
        info: Box<platform::NetworkInfo>,
    },
    Topology {
        job: u64,
        snapshot: Box<topology::Snapshot>,
    },
    Inventory {
        job: u64,
        target: Target,
        report: Box<enrichment::Report>,
    },
    Trace {
        job: u64,
        target: Target,
        report: Box<trace::TraceReport>,
    },
    Telemetry {
        job: u64,
        target: Target,
        report: Box<crate::telemetry::Telemetry>,
    },
    Warning {
        job: u64,
        text: String,
    },
    Finished {
        job: u64,
        cancelled: bool,
        local_problem: bool,
    },
}

pub struct Job {
    pub id: u64,
    pub cancel: Arc<AtomicBool>,
    pub handle: thread::JoinHandle<()>,
}

#[derive(Clone, Copy)]
pub enum Inspection {
    Inventory,
    Trace,
}

pub fn inspect(
    id: u64,
    target: Target,
    settings: Settings,
    kind: Inspection,
    sender: Sender<JobMessage>,
) -> Result<Job> {
    settings.validate()?;
    ensure!(
        target.ip.octets()[0] > 0 && target.ip.octets()[0] < 224,
        "Destinazione IPv4 non unicast"
    );
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = cancel.clone();
    let handle = thread::Builder::new()
        .name("network-inspection".into())
        .spawn(move || {
            let timeout = Duration::from_millis(settings.timeout_ms);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let message = match kind {
                    Inspection::Inventory => JobMessage::Inventory {
                        job: id,
                        report: Box::new(enrichment::collect(
                            target.ip,
                            &settings.tcp_ports,
                            timeout,
                            &worker_cancel,
                        )),
                        target,
                    },
                    Inspection::Trace => JobMessage::Trace {
                        job: id,
                        report: Box::new(trace::collect(target.ip, timeout, 30, &worker_cancel)),
                        target,
                    },
                };
                let _ = sender.send(message);
            }));
            if result.is_err() {
                let _ = sender.send(JobMessage::Warning {
                    job: id,
                    text: "Raccolta dati di rete interrotta da un errore interno".into(),
                });
            }
            let _ = sender.send(JobMessage::Finished {
                job: id,
                cancelled: worker_cancel.load(Ordering::Relaxed),
                local_problem: result.is_err(),
            });
        })?;
    Ok(Job { id, cancel, handle })
}

pub fn start(
    id: u64,
    targets: Vec<Target>,
    settings: Settings,
    profiles: Vec<Profile>,
    scan: bool,
    sender: Sender<JobMessage>,
) -> Result<Job> {
    settings.validate()?;
    ensure!(!targets.is_empty(), "Nessuna destinazione");
    ensure!(
        targets
            .iter()
            .all(|target| target.ip.octets()[0] > 0 && target.ip.octets()[0] < 224),
        "Destinazioni IPv4 non unicast"
    );
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = cancel.clone();
    let handle = thread::Builder::new().name("network-coordinator".into()).spawn(move || {
        let next = AtomicUsize::new(0);
        let problem = AtomicBool::new(false);
        let wall = SystemTime::now();
        let instant = Instant::now();
        let responded: Vec<_> = targets.iter().map(|_| AtomicBool::new(false)).collect();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            thread::scope(|scope| {
                for _ in 0..settings.concurrency.min(targets.len()) {
                    let next = &next;
                    let problem = &problem;
                    let targets = &targets;
                    let profiles = &profiles;
                    let settings = &settings;
                    let sender = &sender;
                    let cancel = &worker_cancel;
                    let responded = &responded;
                    scope.spawn(move || loop {
                        if cancel.load(Ordering::Relaxed) { break; }
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let Some(target) = targets.get(index) else { break };
                        let profile = profiles.iter().find(|p| p.target == target.ip);
                        let result = probe(target.ip, settings, profile, cancel);
                        if matches!(result.result, ProbeResult::Responding { .. }) { responded[index].store(true, Ordering::Relaxed); }
                        if matches!(result.result, ProbeResult::Unknown(_)) { problem.store(true, Ordering::Relaxed); }
                        let enrich = scan && settings.enrich_scan && matches!(result.result, ProbeResult::Responding { .. });
                        if sender.send(JobMessage::Host { job: id, target: target.clone(), result }).is_err() { break; }
                        if enrich && !cancel.load(Ordering::Relaxed) {
                            let report = enrichment::collect(target.ip, &settings.tcp_ports, Duration::from_millis(settings.timeout_ms), cancel);
                            if sender.send(JobMessage::Inventory { job: id, target: target.clone(), report: Box::new(report) }).is_err() { break; }
                        }
                    });
                }
            });
            if scan {
                let _ = sender.send(JobMessage::NetworkInfo { job: id, info: Box::new(platform::network_info()) });
            }
            for profile in &profiles {
                if worker_cancel.load(Ordering::Relaxed) { break; }
                let Some((_, target)) = targets.iter().enumerate().find(|(index, target)| target.ip == profile.target && responded[*index].load(Ordering::Relaxed)) else { continue };
                if scan {
                    match topology::collect(profile, Duration::from_millis(settings.timeout_ms), &worker_cancel) {
                        Ok(snapshot) => { let _ = sender.send(JobMessage::Topology { job: id, snapshot: Box::new(snapshot) }); }
                        Err(_) => { let _ = sender.send(JobMessage::Warning { job: id, text: format!("SNMP {}: nessuna risposta valida o interrogazione incompleta", profile.target) }); }
                    }
                } else {
                    match topology::collect_telemetry(profile, Duration::from_millis(settings.timeout_ms), &worker_cancel) {
                        Ok(report) => { let _ = sender.send(JobMessage::Telemetry { job: id, target: target.clone(), report: Box::new(report) }); }
                        Err(_) => { let _ = sender.send(JobMessage::Warning { job: id, text: format!("SNMP {}: telemetria non disponibile o incompleta", profile.target) }); }
                    }
                }
            }
        }));
        if result.is_err() {
            problem.store(true, Ordering::Relaxed);
            let _ = sender.send(JobMessage::Warning { job: id, text: "Worker di rete terminato in modo inatteso".into() });
        }
        let elapsed = wall.elapsed().unwrap_or_default();
        // Some platforms' monotonic clocks stop in suspend; wall-clock drift invalidates negatives.
        if elapsed.abs_diff(instant.elapsed()) > Duration::from_secs(5) {
            problem.store(true, Ordering::Relaxed);
        }
        let _ = sender.send(JobMessage::Finished {
            job: id, cancelled: worker_cancel.load(Ordering::Relaxed), local_problem: problem.load(Ordering::Relaxed),
        });
    })?;
    Ok(Job { id, cancel, handle })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn subnet_overlap_and_small_prefixes_are_deduplicated() {
        assert_eq!(
            targets("127.0.0.0/31,127.0.0.1/32", 2).unwrap(),
            vec![Ipv4Addr::new(127, 0, 0, 0), Ipv4Addr::LOCALHOST]
        );
    }
    #[test]
    fn huge_range_rejected_before_allocation() {
        assert!(targets("0.0.0.0/0", 4096).is_err());
    }
    #[test]
    fn conventional_subnet_excludes_network_and_broadcast() {
        assert_eq!(targets("192.0.2.0/30", 2).unwrap().len(), 2);
    }
    #[test]
    fn tcp_loopback_response_includes_its_latency() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let settings = Settings {
            icmp: false,
            tcp_ports: vec![port],
            ..Settings::default()
        };
        let response = probe(
            Ipv4Addr::LOCALHOST,
            &settings,
            None,
            &AtomicBool::new(false),
        );
        assert!(response.icmp.is_none());
        match response.result {
            ProbeResult::Responding { latency, .. } => assert!(!latency.is_zero()),
            other => panic!("Expected a loopback response, got {other:?}"),
        }
    }
    #[test]
    fn cancelled_probe_never_becomes_negative() {
        let report = probe(
            Ipv4Addr::LOCALHOST,
            &Settings::default(),
            None,
            &AtomicBool::new(true),
        );
        assert!(matches!(report.result, ProbeResult::Unknown(_)));
        assert!(report.icmp.is_none());
    }

    #[test]
    fn icmp_timeout_or_unavailability_does_not_prevent_tcp_fallback() {
        let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let settings = Settings {
            tcp_ports: vec![listener.local_addr().unwrap().port()],
            ..Settings::default()
        };
        for icmp in [
            EchoResult::NoReply,
            EchoResult::Unavailable("Permesso negato".into()),
        ] {
            let result = probe_result(
                Ipv4Addr::LOCALHOST,
                &settings,
                None,
                &AtomicBool::new(false),
                Some(&icmp),
            );
            assert!(
                matches!(result, ProbeResult::Responding { method, .. } if method.starts_with("TCP"))
            );
        }
    }

    #[test]
    fn loopback_probe_preserves_icmp_evidence_separately_from_reachability() {
        let report = probe(
            Ipv4Addr::LOCALHOST,
            &Settings::default(),
            None,
            &AtomicBool::new(false),
        );
        match report.icmp {
            Some(EchoResult::Reply(rtt)) => {
                assert!(matches!(report.result,
                    ProbeResult::Responding { method, latency } if method == "ICMP" && latency == rtt));
            }
            Some(EchoResult::Unavailable(_)) => {}
            other => panic!("Esito ICMP loopback inatteso: {other:?}"),
        }
    }
}
