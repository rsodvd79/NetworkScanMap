use network_scan_map::{
    discovery::{self, JobMessage, ProbeReport, ProbeResult, Target},
    model::{Link, LinkKind, Map, Observation, Settings, Status, now},
    monitor, storage,
};
use std::{
    net::{Ipv4Addr, TcpListener},
    sync::mpsc,
    time::Duration,
};

#[test]
fn loopback_discovery_save_reload_rescan_and_monitor_preserve_manual_data() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let settings = Settings {
        networks: "127.0.0.1/32".into(),
        icmp: false,
        tcp_ports: vec![listener.local_addr().unwrap().port()],
        ..Settings::default()
    };
    let (sender, receiver) = mpsc::channel();
    let job = discovery::start(
        7,
        vec![Target {
            id: 0,
            ip: Ipv4Addr::LOCALHOST,
        }],
        settings.clone(),
        vec![],
        true,
        sender,
    )
    .unwrap();
    let mut map = Map {
        settings,
        ..Map::default()
    };
    let mut found = None;
    loop {
        match receiver.recv_timeout(Duration::from_secs(10)).unwrap() {
            JobMessage::Host {
                job,
                target,
                result:
                    ProbeReport {
                        result: ProbeResult::Responding { method, .. },
                        ..
                    },
            } => {
                assert_eq!(job, 7);
                found = Some(map.merge(Observation {
                    ip: Some(target.ip),
                    context: map.settings.context.clone(),
                    group: "127.0.0.1/32".into(),
                    mac: None,
                    chassis: None,
                    name: String::new(),
                    description: String::new(),
                    method,
                    responding: true,
                }));
            }
            JobMessage::Finished {
                cancelled,
                local_problem,
                ..
            } => {
                assert!(!cancelled && !local_problem);
                break;
            }
            _ => {}
        }
    }
    job.handle.join().unwrap();
    let id = found.unwrap();
    map.devices[0].custom_name = "Server locale".into();
    map.devices[0].position = [150.0, 250.0];
    let other = map.merge(Observation {
        ip: Some(Ipv4Addr::new(127, 0, 0, 2)),
        context: map.settings.context.clone(),
        group: "Manuali".into(),
        mac: None,
        chassis: None,
        name: "Manuale".into(),
        description: String::new(),
        method: String::new(),
        responding: false,
    });
    map.add_link(Link {
        from: id,
        to: other,
        from_port: String::new(),
        to_port: String::new(),
        kind: LinkKind::Manual,
        evidence: "Inserito manualmente".into(),
        source: id,
        last_seen: now(),
        stale: false,
    });
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rete.json");
    storage::save(&path, &map).unwrap();
    let mut map = storage::load(&path).unwrap();
    let result = discovery::probe(
        Ipv4Addr::LOCALHOST,
        &map.settings,
        None,
        &std::sync::atomic::AtomicBool::new(false),
    );
    monitor::apply(&mut map, id, result.result);
    for _ in 0..3 {
        monitor::apply(&mut map, id, ProbeResult::Negative);
    }
    assert_eq!(map.devices[0].status, Status::Down);
    monitor::apply(
        &mut map,
        id,
        ProbeResult::Responding {
            method: "TCP".into(),
            latency: Duration::from_micros(800),
        },
    );
    assert_eq!(
        (
            map.devices[0].label(),
            map.devices[0].position,
            map.links.len(),
            map.devices[0].status
        ),
        ("Server locale".into(), [150.0, 250.0], 1, Status::Up)
    );
    storage::save(&path, &map).unwrap();
    assert_eq!(
        storage::load(&path).unwrap().links[0].kind,
        LinkKind::Manual
    );
}
