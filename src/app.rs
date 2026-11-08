use crate::{
    diagram::Diagram,
    discovery::{self, Job, JobMessage, ProbeResult, Target},
    model::{Link, LinkKind, Map, Observation, Status, now},
    monitor,
    platform::{self, NetworkInfo},
    storage,
    topology::Profile,
};
use eframe::egui::{self, Color32};
use std::{
    net::Ipv4Addr,
    path::PathBuf,
    sync::{
        atomic::Ordering,
        mpsc::{self, Receiver, Sender},
    },
    time::{Duration, Instant},
};

enum FileMessage {
    Info(NetworkInfo),
    Loaded(Result<Option<Box<Map>>, String>, Option<PathBuf>),
    Saved(Result<Option<PathBuf>, String>, u64),
}

#[derive(Clone, Copy)]
enum Pending {
    New,
    Open,
    Close,
}

struct Active {
    job: Job,
    scan: bool,
    valid: bool,
    total: usize,
    processed: usize,
    results: Vec<(u64, ProbeResult)>,
}

pub struct NetworkApp {
    pub map: Map,
    diagram: Diagram,
    info: NetworkInfo,
    receiver: Receiver<JobMessage>,
    sender: Sender<JobMessage>,
    files: Receiver<FileMessage>,
    file_sender: Sender<FileMessage>,
    file_busy: bool,
    file_path: Option<PathBuf>,
    revision: u64,
    saved_revision: u64,
    active: Option<Active>,
    next_job: u64,
    monitoring: bool,
    next_cycle: Instant,
    last_frame: Instant,
    profiles: Vec<Profile>,
    community: String,
    snmp_port: u16,
    snmp_target: String,
    manual_ip: String,
    ports_text: String,
    error: String,
    pending: Option<Pending>,
    continue_after_save: bool,
    allow_close: bool,
    delete_device: Option<u64>,
    smoke: bool,
    frames: usize,
}

impl NetworkApp {
    pub fn new(smoke: bool, demo: bool) -> Self {
        let (sender, receiver) = mpsc::channel();
        let (file_sender, files) = mpsc::channel();
        let info_sender = file_sender.clone();
        let _ = std::thread::Builder::new()
            .name("network-info".into())
            .spawn(move || {
                let _ = info_sender.send(FileMessage::Info(platform::network_info()));
            });
        let mut map = Map::default();
        if demo {
            map.settings.networks = "192.0.2.0/24,198.51.100.0/24".into();
            for index in 0..500u32 {
                let ip = Ipv4Addr::from(if index < 250 {
                    0xc0000201 + index
                } else {
                    0xc6336401 + index - 250
                });
                map.merge(Observation {
                    ip: Some(ip),
                    context: "Dimostrazione".into(),
                    group: discovery::group_for(ip, &map.settings.networks),
                    mac: None,
                    chassis: None,
                    name: format!("Apparato {}", index + 1),
                    description: "Dati sintetici, nessuna scansione".into(),
                    method: "Demo".into(),
                    responding: false,
                });
                if let Some(d) = map.devices.last_mut() {
                    d.status = match index % 4 {
                        0 => Status::Up,
                        1 => Status::Down,
                        2 => Status::Checking,
                        _ => Status::Unknown,
                    };
                }
            }
        }
        let mut diagram = Diagram::default();
        if demo {
            diagram.rearrange(&mut map);
        }
        Self {
            map,
            diagram,
            info: NetworkInfo::default(),
            receiver,
            sender,
            files,
            file_sender,
            file_busy: false,
            file_path: None,
            revision: 0,
            saved_revision: 0,
            active: None,
            next_job: 1,
            monitoring: false,
            next_cycle: Instant::now(),
            last_frame: Instant::now(),
            profiles: vec![],
            community: String::new(),
            snmp_port: 161,
            snmp_target: String::new(),
            manual_ip: String::new(),
            ports_text: "22,80,443".into(),
            error: String::new(),
            pending: None,
            continue_after_save: false,
            allow_close: false,
            delete_device: None,
            smoke,
            frames: 0,
        }
    }

    fn changed(&mut self) {
        self.revision = self.revision.saturating_add(1);
    }
    fn dirty(&self) -> bool {
        self.revision != self.saved_revision
    }

    fn stop_job(&mut self, invalidate: bool) {
        if let Some(active) = &mut self.active {
            active.job.cancel.store(true, Ordering::Relaxed);
            if invalidate {
                active.valid = false;
            }
        }
    }

    fn reset_map(&mut self, map: Map, path: Option<PathBuf>) {
        self.stop_job(true);
        self.monitoring = false;
        self.map = map;
        self.profiles.clear();
        self.community.clear();
        self.file_path = path;
        self.ports_text = self
            .map
            .settings
            .tcp_ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",");
        self.diagram = Diagram::default();
        self.delete_device = None;
        self.revision = self.revision.saturating_add(1);
        self.saved_revision = self.revision;
    }

    fn request(&mut self, action: Pending, ctx: &egui::Context) {
        if self.file_busy {
            return;
        }
        if self.dirty() {
            self.pending = Some(action);
        } else {
            self.execute(action, ctx);
        }
    }

    fn execute(&mut self, action: Pending, ctx: &egui::Context) {
        self.pending = None;
        match action {
            Pending::New => self.reset_map(Map::default(), None),
            Pending::Close => {
                self.allow_close = true;
                self.stop_job(true);
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            Pending::Open => {
                self.stop_job(true);
                self.monitoring = false;
                self.file_busy = true;
                let sender = self.file_sender.clone();
                let spawn = std::thread::Builder::new()
                    .name("load-map".into())
                    .spawn(move || {
                        let path = rfd::FileDialog::new()
                            .add_filter("Mappa JSON", &["json"])
                            .pick_file();
                        let result = match &path {
                            Some(path) => storage::load(path)
                                .map(|m| Some(Box::new(m)))
                                .map_err(|e| format!("{e:#}")),
                            None => Ok(None),
                        };
                        let _ = sender.send(FileMessage::Loaded(result, path));
                    });
                if let Err(e) = spawn {
                    self.error = e.to_string();
                    self.file_busy = false;
                }
            }
        }
    }

    fn save(&mut self, choose_path: bool) {
        if self.file_busy {
            return;
        }
        self.file_busy = true;
        let map = self.map.clone();
        let existing = if choose_path {
            None
        } else {
            self.file_path.clone()
        };
        let sender = self.file_sender.clone();
        let revision = self.revision;
        let spawn = std::thread::Builder::new()
            .name("save-map".into())
            .spawn(move || {
                let path = existing.or_else(|| {
                    rfd::FileDialog::new()
                        .add_filter("Mappa JSON", &["json"])
                        .set_file_name("rete.json")
                        .save_file()
                });
                let result = match path {
                    Some(path) => storage::save(&path, &map)
                        .map(|()| Some(path))
                        .map_err(|e| format!("{e:#}")),
                    None => Ok(None),
                };
                let _ = sender.send(FileMessage::Saved(result, revision));
            });
        if let Err(e) = spawn {
            self.error = e.to_string();
            self.file_busy = false;
        }
    }

    fn launch(&mut self, scan: bool) -> anyhow::Result<()> {
        if self.active.is_some() {
            return Ok(());
        }
        let ports = self
            .ports_text
            .split([',', ' ', ';'])
            .filter(|s| !s.is_empty())
            .map(str::parse::<u16>)
            .collect::<Result<Vec<_>, _>>()?;
        anyhow::ensure!(
            ports == self.map.settings.tcp_ports,
            "Correggere le porte TCP prima di avviare"
        );
        self.map.settings.validate()?;
        let targets = if scan {
            discovery::targets(&self.map.settings.networks, self.map.settings.max_addresses)?
                .into_iter()
                .map(|ip| Target { id: 0, ip })
                .collect::<Vec<_>>()
        } else {
            let authorized = discovery::networks(&self.map.settings.networks)?;
            let mut counts = std::collections::HashMap::new();
            for device in self
                .map
                .devices
                .iter()
                .filter(|d| d.context == self.map.settings.context)
            {
                if let Some(ip) = device.ip {
                    *counts.entry(ip).or_insert(0usize) += 1;
                }
            }
            for device in self
                .map
                .devices
                .iter_mut()
                .filter(|d| d.context == self.map.settings.context)
            {
                if device
                    .ip
                    .is_some_and(|ip| counts.get(&ip).copied().unwrap_or(0) > 1)
                {
                    device.status = Status::Unknown;
                    device.failures = 0;
                    device.last_method =
                        "IP condiviso / identita ambigua: monitoraggio sospeso".into();
                }
            }
            self.map
                .devices
                .iter()
                .filter(|d| {
                    d.context == self.map.settings.context
                        && d.ip
                            .is_some_and(|ip| counts.get(&ip).copied().unwrap_or(0) == 1)
                        && (d.manual
                            || d.ip
                                .is_some_and(|ip| authorized.iter().any(|net| net.contains(&ip))))
                })
                .filter_map(|d| d.ip.map(|ip| Target { id: d.id, ip }))
                .collect()
        };
        anyhow::ensure!(
            !targets.is_empty(),
            "Nessun apparato monitorabile nel contesto selezionato"
        );
        let mut profiles = self.profiles.clone();
        if scan {
            anyhow::ensure!(
                profiles
                    .iter()
                    .all(|p| targets.iter().any(|t| t.ip == p.target)),
                "Un profilo SNMP e fuori dalle subnet configurate"
            );
        }
        if !self.community.is_empty() {
            for target in &targets {
                if !profiles.iter().any(|p| p.target == target.ip) {
                    profiles.push(Profile {
                        target: target.ip,
                        port: self.snmp_port,
                        community: self.community.clone(),
                    });
                }
            }
        }
        profiles.retain(|p| targets.iter().any(|t| t.ip == p.target));
        let total = targets.len();
        let job = discovery::start(
            self.next_job,
            targets,
            self.map.settings.clone(),
            profiles,
            scan,
            self.sender.clone(),
        )?;
        self.next_job += 1;
        self.active = Some(Active {
            job,
            scan,
            valid: true,
            total,
            processed: 0,
            results: vec![],
        });
        if scan {
            for device in self
                .map
                .devices
                .iter_mut()
                .filter(|d| d.context == self.map.settings.context)
            {
                device.status = Status::Unknown;
                device.failures = 0;
            }
            self.map
                .event("Scansione avviata; le informazioni precedenti saranno conservate");
            self.changed();
        }
        Ok(())
    }

    fn poll(&mut self, ctx: &egui::Context) {
        while let Ok(message) = self.files.try_recv() {
            match message {
                FileMessage::Info(info) => {
                    if self.revision == 0
                        && self.map.settings.networks.is_empty()
                        && self.file_path.is_none()
                        && !self.file_busy
                        && self.active.is_none()
                        && let Some(network) = suggested_local_network(&info)
                    {
                        self.map.settings.networks = network;
                    }
                    self.info = info;
                }
                FileMessage::Loaded(result, path) => {
                    self.file_busy = false;
                    match result {
                        Ok(Some(map)) => self.reset_map(*map, path),
                        Ok(None) => {}
                        Err(e) => self.error = e,
                    }
                }
                FileMessage::Saved(result, revision) => {
                    self.file_busy = false;
                    match result {
                        Ok(Some(path)) => {
                            self.file_path = Some(path);
                            self.saved_revision = revision;
                            if self.continue_after_save && !self.dirty() {
                                self.continue_after_save = false;
                                if let Some(action) = self.pending.take() {
                                    self.execute(action, ctx);
                                }
                            }
                        }
                        Ok(None) => self.continue_after_save = false,
                        Err(e) => {
                            self.error = e;
                            self.continue_after_save = false;
                        }
                    }
                }
            }
        }
        while let Ok(message) = self.receiver.try_recv() {
            let job_id = match &message {
                JobMessage::Host { job, .. }
                | JobMessage::Topology { job, .. }
                | JobMessage::NetworkInfo { job, .. }
                | JobMessage::Warning { job, .. }
                | JobMessage::Finished { job, .. } => *job,
            };
            let Some(active) = &self.active else { continue };
            if active.job.id != job_id {
                continue;
            }
            let valid = active.valid;
            let scan = active.scan;
            match message {
                JobMessage::Host { target, result, .. } if valid => {
                    if let Some(a) = &mut self.active {
                        a.processed += 1;
                        if !scan {
                            a.results.push((target.id, result.clone()));
                        }
                    }
                    if scan && let ProbeResult::Responding(method) = result {
                        let mac = neighbor_mac(&self.info, target.ip, &self.map.settings.interface);
                        let id = self.map.merge(Observation {
                            ip: Some(target.ip),
                            context: self.map.settings.context.clone(),
                            group: discovery::group_for(target.ip, &self.map.settings.networks),
                            mac,
                            chassis: None,
                            name: String::new(),
                            description: String::new(),
                            method,
                            responding: true,
                        });
                        if let Some(active) = &mut self.active {
                            active
                                .results
                                .push((id, ProbeResult::Responding("Scansione".into())));
                        }
                        self.changed();
                    }
                }
                JobMessage::NetworkInfo { info, .. } if valid => {
                    self.info = *info;
                    let seen: Vec<_> = self
                        .active
                        .as_ref()
                        .map_or_else(Vec::new, |a| a.results.iter().map(|(id, _)| *id).collect());
                    let observations: Vec<_> = self
                        .map
                        .devices
                        .iter()
                        .filter(|d| seen.contains(&d.id))
                        .filter_map(|d| {
                            let ip = d.ip?;
                            let mac = neighbor_mac(&self.info, ip, &self.map.settings.interface)?;
                            let chassis = if d.mac.as_ref().is_none_or(|old| old == &mac) {
                                d.chassis.clone()
                            } else {
                                None
                            };
                            Some(Observation {
                                ip: Some(ip),
                                context: d.context.clone(),
                                group: d.group.clone(),
                                mac: Some(mac),
                                chassis,
                                name: String::new(),
                                description: String::new(),
                                method: d.last_method.clone(),
                                responding: true,
                            })
                        })
                        .collect();
                    for obs in observations {
                        self.map.merge(obs);
                    }
                    self.changed();
                }
                JobMessage::Topology { snapshot, .. } if valid => {
                    let context = self.map.settings.context.clone();
                    let group = discovery::group_for(snapshot.target, &self.map.settings.networks);
                    self.map.apply_topology(*snapshot, &context, &group);
                    self.changed();
                }
                JobMessage::Warning { text, .. } if valid => {
                    self.map.event(text);
                    self.changed();
                }
                JobMessage::Finished {
                    cancelled,
                    local_problem,
                    ..
                } => {
                    if let Some(active) = self.active.take() {
                        // Finished is sent after all host events; joining here cannot await network work.
                        let _ = active.job.handle.join();
                        if valid {
                            if !scan && !cancelled {
                                for (id, result) in active.results {
                                    let result = if local_problem
                                        && !matches!(result, ProbeResult::Responding(_))
                                    {
                                        ProbeResult::Unknown(
                                            "Ciclo incompleto / problema locale".into(),
                                        )
                                    } else {
                                        result
                                    };
                                    monitor::apply(&mut self.map, id, result);
                                }
                            }
                            if scan {
                                self.map.event(if cancelled {
                                    "Scansione annullata; risultati parziali conservati"
                                } else {
                                    "Scansione terminata; apparati non ritrovati conservati"
                                });
                                self.add_gateway_hints();
                                self.diagram.fit();
                            }
                            if local_problem {
                                self.map.event("Copertura parziale: verificare sonde disponibili, rete locale e permessi");
                            }
                            self.changed();
                        }
                    }
                    self.next_cycle =
                        Instant::now() + Duration::from_secs(self.map.settings.interval_secs);
                }
                _ => {}
            }
        }
    }

    fn add_gateway_hints(&mut self) {
        let mut links = vec![];
        for device in &self.map.devices {
            if device.context != self.map.settings.context {
                continue;
            }
            let Some(ip) = device.ip else { continue };
            let route = self
                .info
                .routes
                .iter()
                .filter(|r| {
                    r.network.contains(&ip)
                        && (self.map.settings.interface.is_empty()
                            || r.interface == self.map.settings.interface)
                })
                .max_by_key(|r| r.network.prefix_len());
            if let Some(gateway) = route.and_then(|r| r.gateway)
                && let Some(gw) = self.map.devices.iter().find(|d| {
                    d.ip == Some(gateway) && d.context == device.context && d.id != device.id
                })
            {
                links.push(Link {
                    from: gw.id,
                    to: device.id,
                    from_port: String::new(),
                    to_port: String::new(),
                    kind: LinkKind::Inferred,
                    evidence: "Route locale via gateway; relazione logica, non cavo diretto".into(),
                    source: gw.id,
                    last_seen: now(),
                    stale: false,
                });
            }
        }
        for link in links {
            self.map.add_link(link);
        }
    }

    fn configuration(&mut self, ui: &mut egui::Ui) {
        ui.heading("Scansione IPv4");
        ui.label("Una o piu subnet CIDR");
        if ui
            .text_edit_multiline(&mut self.map.settings.networks)
            .changed()
        {
            self.changed();
        }
        ui.label("Contesto rete (separa reti con IP uguali)");
        if ui
            .text_edit_singleline(&mut self.map.settings.context)
            .changed()
        {
            self.profiles.clear();
            self.community.clear();
            self.changed();
        }
        egui::ComboBox::from_label("Interfaccia / evidenze")
            .selected_text(if self.map.settings.interface.is_empty() {
                "Automatica"
            } else {
                &self.map.settings.interface
            })
            .show_ui(ui, |ui| {
                if ui
                    .selectable_value(
                        &mut self.map.settings.interface,
                        String::new(),
                        "Automatica",
                    )
                    .changed()
                {
                    self.revision += 1;
                }
                for interface in &self.info.interfaces {
                    if ui
                        .selectable_value(
                            &mut self.map.settings.interface,
                            interface.name.clone(),
                            format!(
                                "{} {}/{}",
                                interface.name, interface.address, interface.prefix
                            ),
                        )
                        .changed()
                    {
                        self.revision += 1;
                    }
                }
            });
        ui.small("Le sonde seguono le route del sistema; la scelta filtra le evidenze MAC/gateway, non vincola il socket.");
        egui::CollapsingHeader::new("Limiti e sonde").show(ui, |ui| {
            let settings = &mut self.map.settings;
            let mut changed = ui
                .checkbox(&mut settings.icmp, "ICMP (fallback TCP se non disponibile)")
                .changed();
            ui.label("Porte TCP (max 16)");
            if ui.text_edit_singleline(&mut self.ports_text).changed() {
                match self
                    .ports_text
                    .split([',', ' ', ';'])
                    .filter(|s| !s.is_empty())
                    .map(str::parse::<u16>)
                    .collect::<Result<Vec<_>, _>>()
                {
                    Ok(ports) if ports.len() <= 16 && !ports.contains(&0) => {
                        settings.tcp_ports = ports;
                        changed = true;
                        self.error.clear();
                    }
                    _ => self.error = "Porte TCP non valide".into(),
                }
            }
            ui.horizontal(|ui| {
                ui.label("Max indirizzi");
                changed |= ui
                    .add(egui::DragValue::new(&mut settings.max_addresses).range(1..=1_048_576))
                    .changed();
            });
            ui.horizontal(|ui| {
                ui.label("Worker");
                changed |= ui
                    .add(egui::DragValue::new(&mut settings.concurrency).range(1..=128))
                    .changed();
            });
            ui.horizontal(|ui| {
                ui.label("Timeout ms");
                changed |= ui
                    .add(egui::DragValue::new(&mut settings.timeout_ms).range(50..=10_000))
                    .changed();
            });
            ui.horizontal(|ui| {
                ui.label("Monitoraggio sec");
                changed |= ui
                    .add(egui::DragValue::new(&mut settings.interval_secs).range(1..=86400))
                    .changed();
            });
            ui.horizontal(|ui| {
                ui.label("Cicli negativi");
                changed |= ui
                    .add(egui::DragValue::new(&mut settings.failure_threshold).range(1..=100))
                    .changed();
            });
            if changed {
                self.changed();
            }
        });
        egui::CollapsingHeader::new("SNMPv2c / topologia").show(ui, |ui| {
            ui.colored_label(Color32::YELLOW, "Sola lettura; community NON cifrata.");
            ui.small("Credenziali solo in memoria. Nessun tentativo con community predefinite.");
            ui.label("Community comune alle subnet (opzionale)");
            ui.add(egui::TextEdit::singleline(&mut self.community).password(true));
            ui.horizontal(|ui| { ui.label("Porta UDP"); ui.add(egui::DragValue::new(&mut self.snmp_port).range(1..=65535)); });
            ui.label("Profilo specifico: IP");
            ui.text_edit_singleline(&mut self.snmp_target);
            if ui.button("Assegna community a questo IP").clicked() {
                match self.snmp_target.parse::<Ipv4Addr>() {
                    Ok(target) if !self.community.is_empty() => {
                        self.profiles.retain(|p| p.target != target);
                        self.profiles.push(Profile { target, port: self.snmp_port, community: self.community.clone() });
                        self.community.clear();
                    }
                    _ => self.error = "Inserire IP e community".into(),
                }
            }
            for p in &self.profiles { ui.label(format!("Profilo {}:{}", p.target, p.port)); }
            if ui.button("Rimuovi credenziali in memoria").clicked() { self.profiles.clear(); self.community.clear(); }
            ui.small("LLDP rileva adiacenze. FDB e subnet sono solo indizi; nessuna esplorazione fuori dalle subnet.");
        });
        if let Some(active) = &self.active {
            ui.add(
                egui::ProgressBar::new(active.processed as f32 / active.total.max(1) as f32).text(
                    format!(
                        "{}/{} — {}",
                        active.processed,
                        active.total,
                        if active.scan {
                            "Scansione / SNMP"
                        } else {
                            "Monitoraggio"
                        }
                    ),
                ),
            );
            if ui.button("Annulla operazione").clicked() {
                self.stop_job(false);
            }
        } else if ui.button("Scansiona / aggiorna mappa").clicked()
            && let Err(e) = self.launch(true)
        {
            self.error = format!("{e:#}");
        }
        if ui
            .checkbox(&mut self.monitoring, "Monitoraggio attivo")
            .changed()
        {
            self.next_cycle = Instant::now();
            if !self.monitoring && self.active.as_ref().is_some_and(|a| !a.scan) {
                self.stop_job(false);
            }
        }
        ui.small("Non raggiungibile non significa certamente spento.");
        ui.separator();
        ui.label("Aggiungi apparato manuale (IPv4)");
        ui.text_edit_singleline(&mut self.manual_ip);
        if ui.button("Aggiungi").clicked() {
            match self.manual_ip.parse::<Ipv4Addr>() {
                Ok(ip)
                    if ip.octets()[0] > 0
                        && ip.octets()[0] < 224
                        && !self.map.settings.context.trim().is_empty() =>
                {
                    let id = self.map.merge(Observation {
                        ip: Some(ip),
                        context: self.map.settings.context.clone(),
                        group: discovery::group_for(ip, &self.map.settings.networks),
                        mac: None,
                        chassis: None,
                        name: String::new(),
                        description: String::new(),
                        method: String::new(),
                        responding: false,
                    });
                    if let Some(device) = self.map.devices.iter_mut().find(|d| d.id == id) {
                        device.manual = true;
                    }
                    self.diagram.selected = Some(id);
                    self.diagram.fit();
                    self.changed();
                    self.manual_ip.clear();
                }
                _ => self.error = "IPv4 unicast non valido".into(),
            }
        }
        egui::CollapsingHeader::new("Interfacce e limiti locali").show(ui, |ui| {
            for interface in &self.info.interfaces {
                ui.label(format!(
                    "{} {}/{}",
                    interface.name, interface.address, interface.prefix
                ));
            }
            for warning in &self.info.warnings {
                ui.colored_label(Color32::YELLOW, warning);
            }
            ui.small("Tabelle vicini locali: non provano che un host sia acceso.");
        });
    }

    fn details(&mut self, ui: &mut egui::Ui) {
        ui.heading("Apparato");
        let Some(id) = self.diagram.selected else {
            ui.label("Seleziona un nodo");
            return;
        };
        if let Some(device) = self.map.devices.iter_mut().find(|d| d.id == id) {
            ui.label(device.label());
            ui.label(device.status.label());
            ui.label(format!(
                "IP: {}",
                device
                    .ip
                    .map_or_else(|| "Non monitorabile".into(), |ip| ip.to_string())
            ));
            ui.label(format!(
                "MAC: {}",
                device.mac.as_deref().unwrap_or("Non disponibile")
            ));
            ui.label(format!(
                "Chassis: {}",
                device.chassis.as_deref().unwrap_or("Non disponibile")
            ));
            ui.label(format!("Ultima risposta: {:?} (Unix)", device.last_seen));
            ui.label(format!("Storico: {}", device.historical_status.label()));
            ui.label(format!("Sonda: {}", device.last_method));
            ui.label(&device.description);
            ui.label("Nome personalizzato");
            let mut changed = ui.text_edit_singleline(&mut device.custom_name).changed();
            ui.label("Note");
            changed |= ui.text_edit_multiline(&mut device.notes).changed();
            if changed {
                self.changed();
            }
        }
        ui.separator();
        ui.label("Collegamenti (porta, evidenza, data)");
        let mut remove = None;
        for (index, link) in self
            .map
            .links
            .iter()
            .enumerate()
            .filter(|(_, l)| l.from == id || l.to == id)
        {
            ui.group(|ui| {
                let other = if link.from == id { link.to } else { link.from };
                let name = self
                    .map
                    .devices
                    .iter()
                    .find(|d| d.id == other)
                    .map_or_else(|| "?".into(), |d| d.label());
                ui.label(format!(
                    "{} -> {name} {} <> {}",
                    link.kind.label(),
                    link.from_port,
                    link.to_port
                ));
                ui.small(&link.evidence);
                ui.small(format!(
                    "Unix {}{}",
                    link.last_seen,
                    if link.stale { " (storico)" } else { "" }
                ));
                if link.kind == LinkKind::Manual
                    && ui.small_button("Rimuovi collegamento").clicked()
                {
                    remove = Some(index);
                }
            });
        }
        if let Some(index) = remove {
            self.map.links.remove(index);
            self.changed();
        }
        egui::CollapsingHeader::new("Collega manualmente a...").show(ui, |ui| {
            let mut target = None;
            for d in self.map.devices.iter().filter(|d| d.id != id) {
                if ui.button(d.label()).clicked() {
                    target = Some(d.id);
                }
            }
            if let Some(target) = target {
                self.map.add_link(Link {
                    from: id,
                    to: target,
                    from_port: String::new(),
                    to_port: String::new(),
                    kind: LinkKind::Manual,
                    evidence: "Collegamento inserito dall'utente".into(),
                    source: id,
                    last_seen: now(),
                    stale: false,
                });
                self.changed();
            }
        });
        if ui.button("Rimuovi apparato dalla mappa...").clicked() {
            self.delete_device = Some(id);
        }
    }
}

impl eframe::App for NetworkApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.poll(&ctx);
        let frame_gap = self.last_frame.elapsed();
        self.last_frame = Instant::now();
        if self.monitoring
            && frame_gap > Duration::from_secs(self.map.settings.interval_secs.max(5) * 2)
        {
            self.stop_job(false);
            for d in &mut self.map.devices {
                d.status = Status::Unknown;
                d.failures = 0;
            }
        }
        if self.monitoring
            && self.active.is_none()
            && !self.file_busy
            && self.pending.is_none()
            && Instant::now() >= self.next_cycle
            && let Err(e) = self.launch(false)
        {
            self.error = format!("{e:#}");
            self.monitoring = false;
        }
        if ctx.input(|i| i.viewport().close_requested()) && !self.allow_close {
            if self.dirty() || self.file_busy {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                if !self.file_busy {
                    self.pending = Some(Pending::Close);
                }
            } else {
                self.allow_close = true;
                self.stop_job(true);
            }
        }
        egui::Panel::top("toolbar").resizable(false).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.heading("NetworkScanMap");
                if ui
                    .add_enabled(!self.file_busy, egui::Button::new("Nuova"))
                    .clicked()
                {
                    self.request(Pending::New, &ctx);
                }
                if ui
                    .add_enabled(!self.file_busy, egui::Button::new("Apri"))
                    .clicked()
                {
                    self.request(Pending::Open, &ctx);
                }
                if ui
                    .add_enabled(!self.file_busy, egui::Button::new("Salva"))
                    .clicked()
                {
                    self.save(false);
                }
                if ui
                    .add_enabled(!self.file_busy, egui::Button::new("Salva come"))
                    .clicked()
                {
                    self.save(true);
                }
                ui.label(if self.dirty() {
                    "* Non salvata"
                } else {
                    "Salvata / nuova"
                });
                if let Some(path) = &self.file_path {
                    ui.small(path.display().to_string());
                }
                if ui.button("Adatta vista").clicked() {
                    self.diagram.fit();
                }
                if ui.button("Ridisponi").clicked() {
                    self.diagram.rearrange(&mut self.map);
                    self.changed();
                }
                ui.label("Cerca:");
                ui.text_edit_singleline(&mut self.diagram.query);
            });
            ui.horizontal_wrapped(|ui| {
                ui.colored_label(Color32::LIGHT_BLUE, "Linea blu: LLDP");
                ui.colored_label(Color32::YELLOW, "Tratteggio: dedotto");
                ui.colored_label(Color32::from_rgb(200, 120, 235), "Viola: manuale");
                ui.label(format!(
                    "{} apparati / {} collegamenti",
                    self.map.devices.len(),
                    self.map.links.len()
                ));
            });
            if !self.error.is_empty() {
                ui.horizontal_wrapped(|ui| {
                    ui.colored_label(Color32::LIGHT_RED, &self.error);
                    if ui.small_button("Chiudi errore").clicked() {
                        self.error.clear();
                    }
                });
            }
            for warning in self
                .info
                .warnings
                .iter()
                .filter(|warning| warning.starts_with("MAC:"))
            {
                ui.colored_label(Color32::YELLOW, warning);
            }
        });
        egui::Panel::bottom("events")
            .resizable(true)
            .show(ui, |ui| {
                egui::CollapsingHeader::new("Registro eventi (ultimi 10000)")
                    .default_open(true)
                    .show(ui, |ui| {
                        egui::ScrollArea::vertical()
                            .max_height(100.0)
                            .stick_to_bottom(true)
                            .show_rows(ui, 18.0, self.map.events.len(), |ui, range| {
                                for index in range {
                                    let event = &self.map.events[index];
                                    ui.label(format!("{}  {}", event.time, event.message));
                                }
                            });
                    });
            });
        egui::Panel::left("configuration")
            .resizable(true)
            .show(ui, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.add_enabled_ui(
                        self.active.is_none() && !self.file_busy && self.pending.is_none(),
                        |ui| self.configuration(ui),
                    );
                    // Cancellation remains available even while configuration is locked.
                    if self.active.is_some() {
                        ui.label(format!(
                            "Operazione in corso: {}/{}",
                            self.active.as_ref().map_or(0, |a| a.processed),
                            self.active.as_ref().map_or(0, |a| a.total)
                        ));
                        if ui.button("Annulla").clicked() {
                            self.stop_job(false);
                        }
                        if ui.button("Ferma monitoraggio").clicked() {
                            self.monitoring = false;
                            if self.active.as_ref().is_some_and(|a| !a.scan) {
                                self.stop_job(false);
                            }
                        }
                    }
                });
            });
        egui::Panel::right("details")
            .resizable(true)
            .show(ui, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.add_enabled_ui(!self.file_busy && self.pending.is_none(), |ui| {
                        self.details(ui)
                    });
                });
            });
        egui::CentralPanel::default().show(ui, |ui| {
            if self.diagram.show(ui, &mut self.map) {
                self.changed();
            }
        });
        if let Some(action) = self.pending {
            egui::Modal::new(egui::Id::unique("unsaved")).show(&ctx, |ui| {
                ui.heading("Modifiche non salvate");
                ui.label("Salvare la mappa prima di continuare?");
                ui.add_enabled_ui(!self.file_busy, |ui| {
                    ui.horizontal(|ui| {
                        if ui.button("Salva e continua").clicked() {
                            self.monitoring = false;
                            self.stop_job(true);
                            self.continue_after_save = true;
                            self.save(false);
                        }
                        if ui.button("Scarta modifiche").clicked() {
                            self.execute(action, &ctx);
                        }
                        if ui.button("Annulla").clicked() {
                            self.pending = None;
                            self.continue_after_save = false;
                        }
                    });
                });
            });
        }
        if let Some(id) = self.delete_device {
            egui::Modal::new(egui::Id::unique("delete-device")).show(&ctx, |ui| {
                ui.heading("Rimuovere l'apparato?");
                ui.label("Saranno rimossi anche i suoi collegamenti. Una nuova scansione puo rilevarlo nuovamente.");
                ui.horizontal(|ui| {
                    if ui.button("Rimuovi").clicked() {
                        self.map.devices.retain(|d| d.id != id);
                        self.map.links.retain(|l| l.from != id && l.to != id && l.source != id);
                        self.diagram.selected = None;
                        self.delete_device = None;
                        self.changed();
                    }
                    if ui.button("Annulla").clicked() { self.delete_device = None; }
                });
            });
        }
        self.frames += 1;
        if self.smoke && self.frames >= 5 {
            self.allow_close = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        ctx.request_repaint_after(Duration::from_millis(
            if self.active.is_some() || self.file_busy {
                100
            } else {
                500
            },
        ));
    }
}

impl Drop for NetworkApp {
    fn drop(&mut self) {
        self.stop_job(true);
    }
}

fn suggested_local_network(info: &NetworkInfo) -> Option<String> {
    let candidates: Vec<_> = info
        .interfaces
        .iter()
        .filter(|interface| {
            !interface.address.is_loopback()
                && interface.address.octets()[0] > 0
                && interface.address.octets()[0] < 224
                && (1..=32).contains(&interface.prefix)
        })
        .collect();
    let preferred = info
        .routes
        .iter()
        .filter(|route| route.network.prefix_len() == 0)
        .find_map(|route| {
            candidates
                .iter()
                .copied()
                .find(|interface| interface.name == route.interface)
        });
    let interface = preferred
        .or_else(|| {
            candidates
                .iter()
                .copied()
                .find(|interface| !interface.address.is_link_local())
        })
        .or_else(|| candidates.first().copied())?;
    ipnet::Ipv4Net::new(interface.address, interface.prefix)
        .ok()
        .map(|network| network.trunc().to_string())
}

fn neighbor_mac(info: &NetworkInfo, ip: Ipv4Addr, selected: &str) -> Option<String> {
    let route = info
        .routes
        .iter()
        .filter(|r| r.network.contains(&ip) && (selected.is_empty() || r.interface == selected))
        .max_by_key(|r| r.network.prefix_len());
    // A routed destination's neighbor is its next hop, not the destination itself.
    if route.is_some_and(|r| r.gateway.is_some_and(|gateway| gateway != ip)) {
        return None;
    }
    let interface = if selected.is_empty() {
        route.map_or("", |r| r.interface.as_str())
    } else {
        selected
    };
    let matches: std::collections::HashSet<_> = info
        .neighbors
        .iter()
        .filter(|n| n.ip == ip && (interface.is_empty() || n.interface == interface))
        .map(|n| n.mac.clone())
        .collect();
    if matches.len() == 1 {
        matches.into_iter().next()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::AtomicBool};

    fn local_info() -> NetworkInfo {
        NetworkInfo {
            interfaces: vec![
                platform::Interface {
                    name: "lo0".into(),
                    address: Ipv4Addr::LOCALHOST,
                    prefix: 8,
                },
                platform::Interface {
                    name: "other".into(),
                    address: Ipv4Addr::new(10, 0, 0, 15),
                    prefix: 16,
                },
                platform::Interface {
                    name: "en0".into(),
                    address: Ipv4Addr::new(192, 168, 1, 13),
                    prefix: 24,
                },
            ],
            routes: vec![platform::Route {
                network: "0.0.0.0/0".parse().unwrap(),
                gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
                interface: "en0".into(),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn startup_suggests_default_interface_subnet_without_starting_scan() {
        let mut app = NetworkApp::new(false, false);
        let (sender, receiver) = mpsc::channel();
        app.files = receiver;
        sender.send(FileMessage::Info(local_info())).unwrap();
        app.poll(&egui::Context::default());
        assert_eq!(app.map.settings.networks, "192.168.1.0/24");
        assert!(app.active.is_none() && !app.monitoring);
    }

    #[test]
    fn delayed_interface_info_does_not_overwrite_user_input_or_loaded_empty_map() {
        for loaded in [false, true] {
            let mut app = NetworkApp::new(false, false);
            if loaded {
                app.reset_map(Map::default(), Some(PathBuf::from("rete.json")));
            } else {
                app.map.settings.networks = "10.42.0.0/16".into();
                app.changed();
            }
            let expected = app.map.settings.networks.clone();
            let (sender, receiver) = mpsc::channel();
            app.files = receiver;
            sender.send(FileMessage::Info(local_info())).unwrap();
            app.poll(&egui::Context::default());
            assert_eq!(app.map.settings.networks, expected);
        }
    }

    #[test]
    fn suggestion_falls_back_to_non_loopback_interface_or_none() {
        let mut info = local_info();
        info.routes.clear();
        assert_eq!(
            suggested_local_network(&info).as_deref(),
            Some("10.0.0.0/16")
        );
        info.interfaces.truncate(1);
        assert_eq!(suggested_local_network(&info), None);
    }

    fn active(id: u64, scan: bool) -> Active {
        Active {
            job: Job {
                id,
                cancel: Arc::new(AtomicBool::new(false)),
                handle: std::thread::spawn(|| {}),
            },
            scan,
            valid: true,
            total: 1,
            processed: 0,
            results: vec![],
        }
    }

    #[test]
    fn stale_job_messages_cannot_modify_a_loaded_map() {
        let mut app = NetworkApp::new(false, false);
        app.active = Some(active(2, true));
        app.sender
            .send(JobMessage::Host {
                job: 1,
                target: Target {
                    id: 0,
                    ip: Ipv4Addr::LOCALHOST,
                },
                result: ProbeResult::Responding("TCP".into()),
            })
            .unwrap();
        app.poll(&egui::Context::default());
        assert!(app.map.devices.is_empty());
        app.active = None;
    }

    #[test]
    fn cancelled_monitor_cycle_does_not_apply_negative_results() {
        let mut app = NetworkApp::new(false, false);
        let id = app.map.merge(Observation {
            ip: Some(Ipv4Addr::LOCALHOST),
            context: "t".into(),
            group: "t".into(),
            mac: None,
            chassis: None,
            name: String::new(),
            description: String::new(),
            method: "TCP".into(),
            responding: true,
        });
        let mut active = active(1, false);
        active.results.push((id, ProbeResult::Negative));
        app.active = Some(active);
        app.sender
            .send(JobMessage::Finished {
                job: 1,
                cancelled: true,
                local_problem: false,
            })
            .unwrap();
        app.poll(&egui::Context::default());
        assert_eq!(
            (app.map.devices[0].status, app.map.devices[0].failures),
            (Status::Up, 0)
        );
    }

    #[test]
    fn gateway_mac_is_not_assigned_to_routed_destination() {
        let ip = Ipv4Addr::new(192, 0, 2, 1);
        let info = NetworkInfo {
            routes: vec![platform::Route {
                network: "0.0.0.0/0".parse().unwrap(),
                gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
                interface: "eth0".into(),
            }],
            neighbors: vec![platform::Neighbor {
                ip,
                mac: "00:01:02:03:04:05".into(),
                interface: "eth0".into(),
            }],
            ..Default::default()
        };
        assert_eq!(neighbor_mac(&info, ip, ""), None);
    }
}
