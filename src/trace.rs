//! One native ICMP echo per TTL, with no external commands or privilege escalation.
//! Routers may filter ICMP; a timeout is not evidence that a hop does not exist.

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix;
#[cfg(windows)]
mod windows;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceOutcome {
    #[default]
    NotStarted,
    DestinationReached,
    HopLimit,
    Deadline,
    Cancelled,
    Unreachable,
    Unavailable,
    Error,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HopOutcome {
    TimeExceeded,
    Destination,
    #[default]
    Timeout,
    Unreachable,
    Error,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TraceHop {
    pub ttl: u8,
    pub source: Option<Ipv4Addr>,
    pub latency_us: Option<u64>,
    pub outcome: HopOutcome,
    /// ICMP type/code or a native/local error, not a guessed router identity.
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct TraceReport {
    /// Unix timestamp in seconds, captured before probing.
    pub timestamp: u64,
    pub destination: Ipv4Addr,
    pub hops: Vec<TraceHop>,
    /// True only when the destination actually replied.
    pub completed: bool,
    pub outcome: TraceOutcome,
    pub warnings: Vec<String>,
}

impl Default for TraceReport {
    fn default() -> Self {
        Self {
            timestamp: 0,
            destination: Ipv4Addr::UNSPECIFIED,
            hops: Vec::new(),
            completed: false,
            outcome: TraceOutcome::NotStarted,
            warnings: Vec::new(),
        }
    }
}

impl TraceReport {
    /// Validates saved reports: at most 30 sequential hops, 16 warnings, and
    /// 1024 UTF-8 bytes per text field without control characters. Timestamps
    /// must fit years 1970–9999 and measured latencies must fit one second.
    /// Empty/default reports are valid. Errors never echo supplied text.
    pub fn validate(&self) -> anyhow::Result<()> {
        use anyhow::ensure;
        ensure!(self.hops.len() <= 30, "Too many traceroute hops");
        ensure!(self.warnings.len() <= 16, "Too many traceroute warnings");
        ensure!(
            self.timestamp <= 253_402_300_799,
            "Invalid traceroute timestamp"
        );
        let valid_text = |text: &str| text.len() <= 1024 && !text.chars().any(char::is_control);
        ensure!(
            self.warnings.iter().all(|text| valid_text(text)),
            "Invalid traceroute warning"
        );
        ensure!(
            valid_destination(self.destination)
                || (self.hops.is_empty()
                    && matches!(
                        self.outcome,
                        TraceOutcome::NotStarted | TraceOutcome::Error | TraceOutcome::Cancelled
                    )),
            "Invalid traceroute destination"
        );
        ensure!(
            self.completed == (self.outcome == TraceOutcome::DestinationReached),
            "Inconsistent traceroute completion"
        );
        for (index, hop) in self.hops.iter().enumerate() {
            ensure!(
                usize::from(hop.ttl) == index + 1,
                "Invalid traceroute hop sequence"
            );
            ensure!(
                hop.source.is_none_or(valid_destination)
                    && hop.latency_us.is_none_or(|latency| latency <= 1_000_000)
                    && hop.source.is_some() == hop.latency_us.is_some(),
                "Invalid traceroute hop address or latency"
            );
            ensure!(
                hop.detail.as_deref().is_none_or(valid_text),
                "Invalid traceroute hop detail"
            );
            if hop.outcome == HopOutcome::Timeout {
                ensure!(
                    hop.source.is_none() && hop.latency_us.is_none(),
                    "Timeout cannot identify a traceroute router"
                );
            }
            if matches!(
                hop.outcome,
                HopOutcome::Destination | HopOutcome::Unreachable | HopOutcome::Error
            ) {
                ensure!(
                    index + 1 == self.hops.len(),
                    "Traceroute continues after a terminal hop"
                );
                let expected = match hop.outcome {
                    HopOutcome::Destination => TraceOutcome::DestinationReached,
                    HopOutcome::Unreachable => TraceOutcome::Unreachable,
                    _ => TraceOutcome::Error,
                };
                ensure!(self.outcome == expected, "Inconsistent traceroute outcome");
            }
            if hop.outcome == HopOutcome::Destination {
                ensure!(
                    hop.source == Some(self.destination),
                    "Traceroute destination reply has the wrong source"
                );
            }
        }
        if matches!(
            self.outcome,
            TraceOutcome::DestinationReached | TraceOutcome::Unreachable
        ) {
            let expected = if self.completed {
                HopOutcome::Destination
            } else {
                HopOutcome::Unreachable
            };
            ensure!(
                self.hops.last().is_some_and(|hop| hop.outcome == expected),
                "Traceroute terminal outcome has no matching hop"
            );
        }
        ensure!(
            self.outcome != TraceOutcome::NotStarted || self.hops.is_empty(),
            "Unstarted traceroute contains hops"
        );
        Ok(())
    }

    pub fn summary(&self) -> String {
        let outcome = match self.outcome {
            TraceOutcome::NotStarted => "not started",
            TraceOutcome::DestinationReached => "destination reached",
            TraceOutcome::HopLimit => "hop limit reached",
            TraceOutcome::Deadline => "deadline reached",
            TraceOutcome::Cancelled => "cancelled",
            TraceOutcome::Unreachable => "unreachable",
            TraceOutcome::Unavailable => "unavailable",
            TraceOutcome::Error => "error",
        };
        let mut summary = format!(
            "{}: {outcome} ({} probes)",
            self.destination,
            self.hops.len()
        );
        if let Some(warning) = self.warnings.first() {
            summary.push_str(": ");
            summary.push_str(warning);
        }
        summary
    }
}

pub(super) enum Probe {
    Hop(TraceHop),
    Cancelled,
    Deadline,
    #[cfg(windows)]
    Unavailable(String),
}

fn cancelled(cancel: &AtomicBool) -> bool {
    cancel.load(Ordering::Acquire)
}

fn valid_destination(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast() && ip.octets()[0] != 0
}

/// Collects a trace to exactly `ip`. `timeout` is the per-hop receive budget,
/// clamped to one second. There are at most 30 probes and a separate 30-second
/// wall-clock deadline, including setup. Zero budget/hops performs no I/O.
///
/// Cancellation is checked between probes and in short native receive waits.
/// Windows observes cancellation before/after each synchronous native probe,
/// so cancellation can wait for the current hop's timeout (at most one second).
/// Linux requires an already-permitted raw ICMP socket: ping datagram sockets
/// without error-queue handling cannot reliably observe intermediate routers.
pub fn collect(ip: Ipv4Addr, timeout: Duration, max_hops: u8, cancel: &AtomicBool) -> TraceReport {
    let started = Instant::now();
    let budget = timeout.min(Duration::from_secs(1));
    let mut report = TraceReport {
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        destination: ip,
        ..TraceReport::default()
    };
    if cancelled(cancel) {
        report.outcome = TraceOutcome::Cancelled;
        return report;
    }
    if !valid_destination(ip) {
        report.outcome = TraceOutcome::Error;
        report
            .warnings
            .push("Traceroute requires a unicast IPv4 destination".into());
        return report;
    }
    if budget.is_zero() {
        report.outcome = TraceOutcome::Deadline;
        return report;
    }
    if max_hops == 0 {
        report.outcome = TraceOutcome::HopLimit;
        return report;
    }
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        use unix::Session;
        #[cfg(windows)]
        use windows::Session;
        let mut session = match Session::new() {
            Ok(session) => session,
            Err(error) => {
                report.outcome = if cancelled(cancel) {
                    TraceOutcome::Cancelled
                } else {
                    TraceOutcome::Unavailable
                };
                report.warnings.push(error);
                return report;
            }
        };
        collect_hops(
            &mut report,
            started,
            budget,
            max_hops,
            cancel,
            |ttl, budget| session.probe(ip, ttl, budget, cancel),
        );
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = started;
        report.outcome = TraceOutcome::Unavailable;
        report
            .warnings
            .push("Native IPv4 traceroute is unsupported on this system".into());
    }
    report
}

fn collect_hops(
    report: &mut TraceReport,
    started: Instant,
    timeout: Duration,
    max_hops: u8,
    cancel: &AtomicBool,
    mut probe: impl FnMut(u8, Duration) -> Probe,
) {
    for ttl in 1..=max_hops.min(30) {
        if cancelled(cancel) {
            report.outcome = TraceOutcome::Cancelled;
            return;
        }
        let remaining = Duration::from_secs(30).saturating_sub(started.elapsed());
        if remaining.is_zero() {
            report.outcome = TraceOutcome::Deadline;
            return;
        }
        let probe = probe(ttl, timeout.min(Duration::from_secs(1)).min(remaining));
        if cancelled(cancel) || matches!(probe, Probe::Cancelled) {
            report.outcome = TraceOutcome::Cancelled;
            return;
        }
        if matches!(probe, Probe::Deadline) {
            report.outcome = TraceOutcome::Deadline;
            return;
        }
        #[cfg(windows)]
        if let Probe::Unavailable(error) = probe {
            report.outcome = TraceOutcome::Unavailable;
            report.warnings.insert(0, error);
            return;
        }
        if let Probe::Hop(hop) = probe {
            let terminal = match hop.outcome {
                HopOutcome::Destination => Some(TraceOutcome::DestinationReached),
                HopOutcome::Unreachable => Some(TraceOutcome::Unreachable),
                HopOutcome::Error => Some(TraceOutcome::Error),
                _ => None,
            };
            report.hops.push(hop);
            if let Some(outcome) = terminal {
                report.completed = outcome == TraceOutcome::DestinationReached;
                report.outcome = outcome;
                return;
            }
        }
    }
    report.outcome = if started.elapsed() >= Duration::from_secs(30) {
        TraceOutcome::Deadline
    } else {
        TraceOutcome::HopLimit
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_receive_budget_is_per_hop_not_divided_across_thirty_hops() {
        let stop = AtomicBool::new(false);
        for requested in [Duration::from_millis(100), Duration::MAX] {
            let mut report = TraceReport {
                destination: Ipv4Addr::LOCALHOST,
                ..TraceReport::default()
            };
            let mut calls = 0;
            collect_hops(
                &mut report,
                Instant::now(),
                requested,
                255,
                &stop,
                |ttl, budget| {
                    calls += 1;
                    assert_eq!(ttl, calls);
                    assert_eq!(budget, requested.min(Duration::from_secs(1)));
                    Probe::Hop(TraceHop {
                        ttl,
                        ..TraceHop::default()
                    })
                },
            );
            assert_eq!(calls, 30);
            assert_eq!(report.outcome, TraceOutcome::HopLimit);
            report.validate().unwrap();
        }
    }

    #[test]
    fn trace_global_deadline_stops_probes_independently_of_per_hop_timeout() {
        let mut report = TraceReport::default();
        collect_hops(
            &mut report,
            Instant::now() - Duration::from_secs(30),
            Duration::from_millis(100),
            30,
            &AtomicBool::new(false),
            |_, _| panic!("A probe started after the global deadline"),
        );
        assert_eq!(report.outcome, TraceOutcome::Deadline);
        assert!(report.hops.is_empty());
    }

    #[test]
    fn trace_saved_report_rejects_excessive_or_unsafe_fields() {
        TraceReport::default().validate().unwrap();
        let good = TraceReport {
            timestamp: 253_402_300_799,
            destination: Ipv4Addr::LOCALHOST,
            warnings: vec!["x".repeat(1024); 16],
            outcome: TraceOutcome::HopLimit,
            hops: vec![TraceHop {
                ttl: 1,
                ..TraceHop::default()
            }],
            ..TraceReport::default()
        };
        good.validate().unwrap();
        let invalid = [
            {
                let mut report = good.clone();
                report.hops = vec![TraceHop::default(); 31];
                report
            },
            {
                let mut report = good.clone();
                report.warnings.push("extra".into());
                report
            },
            {
                let mut report = good.clone();
                report.warnings[0].push('x');
                report
            },
            {
                let mut report = good.clone();
                report.warnings[0] = "untrusted\ntext".into();
                report
            },
            {
                let mut report = good.clone();
                report.hops[0].detail = Some("x".repeat(1025));
                report
            },
            {
                let mut report = good.clone();
                report.hops[0].detail = Some("untrusted\u{1b}[2J".into());
                report
            },
            {
                let mut report = good.clone();
                report.hops[0].ttl = 0;
                report
            },
            {
                let mut report = good.clone();
                report.hops[0].source = Some(Ipv4Addr::LOCALHOST);
                report.hops[0].latency_us = Some(1_000_001);
                report
            },
            {
                let mut report = good.clone();
                report.timestamp = u64::MAX;
                report
            },
            {
                let mut report = good.clone();
                report.destination = Ipv4Addr::BROADCAST;
                report
            },
        ];
        for report in invalid {
            assert!(report.validate().is_err(), "{report:?}");
        }
    }

    #[test]
    fn trace_saved_report_requires_consistent_destination_completion_and_sequence() {
        let good = TraceReport {
            destination: Ipv4Addr::LOCALHOST,
            completed: true,
            outcome: TraceOutcome::DestinationReached,
            hops: vec![TraceHop {
                ttl: 1,
                source: Some(Ipv4Addr::LOCALHOST),
                latency_us: Some(1_000_000),
                outcome: HopOutcome::Destination,
                detail: Some("ICMP echo reply (0/0)".into()),
            }],
            ..TraceReport::default()
        };
        good.validate().unwrap();
        let mut report = good.clone();
        report.completed = false;
        assert!(report.validate().is_err());
        let mut report = good.clone();
        report.hops[0].source = Some(Ipv4Addr::new(127, 0, 0, 2));
        assert!(report.validate().is_err());
        let mut report = good.clone();
        report.hops[0].latency_us = None;
        assert!(report.validate().is_err());
        let mut report = good.clone();
        report.hops[0].source = Some(Ipv4Addr::BROADCAST);
        assert!(report.validate().is_err());
        let mut report = good.clone();
        report.hops.push(TraceHop {
            ttl: 2,
            ..TraceHop::default()
        });
        assert!(report.validate().is_err());
        let mut report = good.clone();
        report.hops[0].outcome = HopOutcome::Timeout;
        assert!(report.validate().is_err());
        let mut report = good;
        report.hops.clear();
        assert!(report.validate().is_err());
    }

    #[test]
    fn trace_no_io_inputs_and_serialization() {
        let stop = AtomicBool::new(true);
        assert_eq!(
            collect(Ipv4Addr::LOCALHOST, Duration::MAX, 255, &stop).outcome,
            TraceOutcome::Cancelled
        );
        stop.store(false, Ordering::Release);
        let report = collect(Ipv4Addr::LOCALHOST, Duration::ZERO, 255, &stop);
        assert_eq!(report.outcome, TraceOutcome::Deadline);
        assert!(report.hops.is_empty());
        assert_eq!(
            collect(Ipv4Addr::LOCALHOST, Duration::MAX, 0, &stop).outcome,
            TraceOutcome::HopLimit
        );
        assert_eq!(
            collect(Ipv4Addr::UNSPECIFIED, Duration::MAX, 30, &stop).outcome,
            TraceOutcome::Error
        );
        let json = serde_json::to_string(&report).unwrap();
        let restored: TraceReport = serde_json::from_str(&json).unwrap();
        restored.validate().unwrap();
        assert_eq!(restored.destination, Ipv4Addr::LOCALHOST);
        assert_eq!(restored.outcome, report.outcome);
        assert!(restored.summary().contains("deadline"));
    }

    #[test]
    fn trace_loopback_or_precise_unavailability() {
        let started = Instant::now();
        let report = collect(
            Ipv4Addr::LOCALHOST,
            Duration::from_millis(400),
            1,
            &AtomicBool::new(false),
        );
        assert!(
            matches!(
                report.outcome,
                TraceOutcome::DestinationReached | TraceOutcome::Unavailable
            ),
            "{report:?}"
        );
        if report.outcome == TraceOutcome::Unavailable {
            assert!(report.hops.is_empty());
            assert!(!report.warnings.is_empty());
        } else {
            assert!(report.completed);
            assert_eq!(report.hops[0].source, Some(Ipv4Addr::LOCALHOST));
        }
        report.validate().unwrap();
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
