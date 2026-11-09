use crate::model::{LinkKind, Map, Status};
use eframe::egui::{self, Align2, Color32, FontId, Pos2, Rect, Sense, Stroke, StrokeKind, Vec2};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

pub struct Diagram {
    pub selected: Option<u64>,
    pub query: String,
    zoom: f32,
    offset: Vec2,
    fit: bool,
}

impl Default for Diagram {
    fn default() -> Self {
        Self {
            selected: None,
            query: String::new(),
            zoom: 1.0,
            offset: Vec2::new(50.0, 80.0),
            fit: true,
        }
    }
}

impl Diagram {
    pub fn fit(&mut self) {
        self.fit = true;
    }

    pub fn rearrange(&mut self, map: &mut Map) {
        let by_id: HashMap<_, _> = map
            .devices
            .iter()
            .enumerate()
            .map(|(index, device)| (device.id, index))
            .collect();
        let mut neighbors = vec![BTreeSet::new(); map.devices.len()];
        let mut sources = BTreeSet::new();
        for link in map.links.iter().filter(|link| !link.stale) {
            let (Some(&from), Some(&to)) = (by_id.get(&link.from), by_id.get(&link.to)) else {
                continue;
            };
            if from == to || map.devices[from].context != map.devices[to].context {
                continue;
            }
            neighbors[from].insert(to);
            neighbors[to].insert(from);
            if link.kind != LinkKind::Manual
                && let Some(&source) = by_id.get(&link.source)
                && (source == from || source == to)
            {
                sources.insert(source);
            }
        }
        // Connectivity is a layout hint, not an additional claim about device type.
        let mut hubs: Vec<_> = (0..map.devices.len())
            .filter(|&index| {
                neighbors[index].len() > 1
                    || (sources.contains(&index)
                        && neighbors[index].len() == 1
                        && neighbors[index]
                            .first()
                            .is_some_and(|&other| neighbors[other].len() == 1))
            })
            .collect();
        hubs.sort_by_key(|&index| {
            (
                map.devices[index].context.clone(),
                std::cmp::Reverse(neighbors[index].len()),
                map.devices[index].id,
            )
        });
        // Reciprocal observations of an isolated pair need only one center.
        let mut centers = Vec::new();
        let mut chosen = BTreeSet::new();
        for index in hubs {
            if neighbors[index].len() != 1
                || !neighbors[index].iter().any(|other| chosen.contains(other))
            {
                chosen.insert(index);
                centers.push(index);
            }
        }
        let mut placed = chosen;
        let mut y = 0.0;
        for &center in &centers {
            let leaves: Vec<_> = neighbors[center]
                .iter()
                .copied()
                .filter(|index| !placed.contains(index))
                .collect();
            let radius = if leaves.is_empty() {
                0.0
            } else {
                (leaves.len() as f32 * 200.0 / std::f32::consts::TAU).max(180.0)
            };
            map.devices[center].position = [radius, y + radius];
            for (slot, &index) in leaves.iter().enumerate() {
                let angle = std::f32::consts::TAU * slot as f32 / leaves.len() as f32;
                map.devices[index].position = [
                    radius + radius * angle.cos(),
                    y + radius + radius * angle.sin(),
                ];
                placed.insert(index);
            }
            y += radius * 2.0 + 220.0;
        }
        let mut groups: BTreeMap<(String, String), Vec<usize>> = BTreeMap::new();
        for (index, d) in map.devices.iter().enumerate() {
            if placed.contains(&index) {
                continue;
            }
            groups
                .entry((d.context.clone(), d.group.clone()))
                .or_default()
                .push(index);
        }
        for indices in groups.values() {
            for (slot, index) in indices.iter().enumerate() {
                map.devices[*index].position =
                    [(slot % 8) as f32 * 180.0, y + (slot / 8) as f32 * 100.0];
            }
            y += indices.len().div_ceil(8) as f32 * 100.0 + 140.0;
        }
        self.fit();
    }

    pub fn show(&mut self, ui: &mut egui::Ui, map: &mut Map) -> bool {
        let (area, background) =
            ui.allocate_exact_size(ui.available_size(), Sense::click_and_drag());
        let painter = ui.painter().with_clip_rect(area);
        painter.rect_filled(area, 0.0, Color32::from_rgb(20, 24, 32));
        if map.devices.is_empty() {
            painter.text(
                area.center(),
                Align2::CENTER_CENTER,
                "Configura le subnet e avvia una scansione,\no inserisci un apparato manualmente.",
                FontId::proportional(18.0),
                Color32::LIGHT_GRAY,
            );
            return false;
        }
        if self.fit {
            let bounds = map.devices.iter().fold(Rect::NOTHING, |r, d| {
                r.union(Rect::from_min_size(
                    Pos2::new(d.position[0], d.position[1]),
                    Vec2::new(150.0, 88.0),
                ))
            });
            self.zoom = ((area.width() - 100.0) / bounds.width().max(1.0))
                .min((area.height() - 100.0) / bounds.height().max(1.0))
                .clamp(0.05, 2.0);
            self.offset = area.size() * 0.5 - bounds.center().to_vec2() * self.zoom;
            self.fit = false;
        }
        if ui.rect_contains_pointer(area) {
            let scroll = ui.input(|i| i.smooth_scroll_delta.y);
            if scroll != 0.0 {
                let old = self.zoom;
                self.zoom = (self.zoom * (scroll * 0.002).exp()).clamp(0.05, 4.0);
                let anchor =
                    ui.input(|i| i.pointer.hover_pos()).unwrap_or(area.center()) - area.min;
                self.offset = anchor - (anchor - self.offset) * (self.zoom / old);
            }
        }
        let origin = area.min + self.offset;
        let screen = |p: [f32; 2]| origin + Vec2::new(p[0], p[1]) * self.zoom;
        let mut groups: BTreeMap<(&str, &str), Rect> = BTreeMap::new();
        for d in &map.devices {
            let r = Rect::from_min_size(screen(d.position), Vec2::new(150.0, 88.0) * self.zoom);
            let group = groups
                .entry((&d.context, &d.group))
                .or_insert(Rect::NOTHING);
            *group = group.union(r);
        }
        for ((context, group), bounds) in groups {
            let bounds = bounds.expand(18.0);
            painter.rect_stroke(
                bounds,
                8.0,
                Stroke::new(1.0, Color32::from_gray(65)),
                StrokeKind::Outside,
            );
            painter.text(
                bounds.left_top() - Vec2::new(0.0, 5.0),
                Align2::LEFT_BOTTOM,
                format!("{context} / {group} (gruppo logico)"),
                FontId::proportional(12.0),
                Color32::GRAY,
            );
        }
        let positions: HashMap<_, _> = map
            .devices
            .iter()
            .map(|d| (d.id, screen(d.position) + Vec2::new(75.0, 44.0) * self.zoom))
            .collect();
        let mut drawn = HashSet::new();
        for link in &map.links {
            if !drawn.insert((
                link.from,
                link.to,
                &link.from_port,
                &link.to_port,
                link.kind as u8,
            )) {
                continue;
            }
            let (Some(a), Some(b)) = (positions.get(&link.from), positions.get(&link.to)) else {
                continue;
            };
            if !area.intersects(Rect::from_two_pos(*a, *b)) {
                continue;
            }
            let color = if link.stale {
                Color32::DARK_GRAY
            } else {
                match link.kind {
                    LinkKind::Observed => Color32::from_rgb(80, 170, 250),
                    LinkKind::Inferred => Color32::from_rgb(210, 165, 70),
                    LinkKind::Manual => Color32::from_rgb(200, 120, 235),
                }
            };
            let stroke = Stroke::new(1.5, color);
            if link.kind == LinkKind::Inferred || link.stale {
                let delta = *b - *a;
                let length = delta.length();
                if length > 0.0 {
                    let direction = delta / length;
                    let steps = (length / 12.0).ceil().clamp(1.0, 512.0) as usize;
                    let stride = length / steps as f32;
                    for n in 0..steps {
                        let start = n as f32 * stride;
                        painter.line_segment(
                            [
                                *a + direction * start,
                                *a + direction * (start + stride * 0.5).min(length),
                            ],
                            stroke,
                        );
                    }
                }
            } else {
                painter.line_segment([*a, *b], stroke);
            }
            if self.zoom > 0.8
                && (self.selected == Some(link.from) || self.selected == Some(link.to))
            {
                painter.text(
                    a.lerp(*b, 0.5),
                    Align2::CENTER_BOTTOM,
                    format!("{} <> {}", link.from_port, link.to_port),
                    FontId::proportional(11.0),
                    color,
                );
            }
        }
        let mut moved = false;
        let query = self.query.to_lowercase();
        let mut node_dragging = false;
        for device in &mut map.devices {
            let rect =
                Rect::from_min_size(screen(device.position), Vec2::new(150.0, 88.0) * self.zoom);
            if !area.intersects(rect) {
                continue;
            }
            let response =
                ui.interact(rect, ui.scope_id().with(device.id), Sense::click_and_drag());
            if response.clicked() {
                self.selected = Some(device.id);
            }
            if response.dragged() {
                node_dragging = true;
                let delta = response.drag_delta() / self.zoom;
                device.position[0] += delta.x;
                device.position[1] += delta.y;
                moved |= delta != Vec2::ZERO;
            }
            let label = device.label();
            let matches = query.is_empty()
                || label.to_lowercase().contains(&query)
                || device.ip.is_some_and(|ip| ip.to_string().contains(&query));
            let color = if !matches {
                Color32::DARK_GRAY
            } else {
                match device.status {
                    Status::Up => Color32::from_rgb(75, 200, 135),
                    Status::Down => Color32::from_rgb(230, 95, 90),
                    Status::Checking => Color32::from_rgb(235, 185, 70),
                    Status::Unknown => Color32::GRAY,
                }
            };
            painter.rect_filled(rect, 6.0, Color32::from_rgb(35, 42, 54));
            painter.rect_stroke(
                rect,
                6.0,
                Stroke::new(
                    if self.selected == Some(device.id) {
                        3.0
                    } else {
                        1.0
                    },
                    color,
                ),
                StrokeKind::Inside,
            );
            if self.zoom > 0.3 {
                let name: String = label.chars().take(21).collect();
                painter.text(
                    rect.center_top() + Vec2::new(0.0, 8.0 * self.zoom),
                    Align2::CENTER_TOP,
                    name,
                    FontId::proportional((13.0 * self.zoom).clamp(8.0, 20.0)),
                    Color32::WHITE,
                );
                painter.text(
                    rect.center() - Vec2::new(0.0, 16.0 * self.zoom),
                    Align2::CENTER_CENTER,
                    device
                        .ip
                        .map_or_else(|| "Senza IP".into(), |ip| ip.to_string()),
                    FontId::monospace((11.0 * self.zoom).clamp(8.0, 18.0)),
                    Color32::LIGHT_GRAY,
                );
                painter.text(
                    rect.center(),
                    Align2::CENTER_CENTER,
                    device.mac.as_deref().unwrap_or("MAC: non disponibile"),
                    FontId::monospace((10.0 * self.zoom).clamp(7.0, 16.0)),
                    Color32::LIGHT_GRAY,
                );
                let latency = device.last_latency_us.map_or_else(
                    || "Ping: non disponibile".into(),
                    |microseconds| {
                        let method = if device.last_method == "ICMP" {
                            "Ping"
                        } else {
                            device
                                .last_method
                                .split_whitespace()
                                .next()
                                .unwrap_or("Risposta")
                        };
                        format!("{method}: {}", crate::model::latency_label(microseconds))
                    },
                );
                painter.text(
                    rect.center() + Vec2::new(0.0, 17.0 * self.zoom),
                    Align2::CENTER_CENTER,
                    latency,
                    FontId::proportional((10.0 * self.zoom).clamp(7.0, 16.0)),
                    Color32::LIGHT_GRAY,
                );
                painter.text(
                    rect.center_bottom() - Vec2::new(0.0, 5.0 * self.zoom),
                    Align2::CENTER_BOTTOM,
                    device.status.label(),
                    FontId::proportional((10.0 * self.zoom).clamp(7.0, 16.0)),
                    color,
                );
            }
            let mac_details = device
                .mac
                .as_deref()
                .and_then(crate::mac::describe)
                .map(|details| {
                    format!(
                        "Tipo MAC: {}\nPrefisso: {}\nProduttore probabile: {}",
                        details.address_type,
                        details.prefix,
                        details.manufacturer.unwrap_or("non identificato")
                    )
                })
                .unwrap_or_else(|| "Dettagli MAC non disponibili".into());
            let latency = device.last_latency_us.map_or_else(
                || "Tempo risposta: non disponibile".into(),
                |microseconds| {
                    format!(
                        "Tempo risposta: {}",
                        crate::model::latency_label(microseconds)
                    )
                },
            );
            response.on_hover_text(format!(
                "{}\nMAC: {}\n{}\n{}\n{}\n{}\n{}\nUltima risposta: {:?}\n{}",
                label,
                device.mac.as_deref().unwrap_or("Non disponibile"),
                mac_details,
                latency,
                device.ping.summary(),
                device.status.label(),
                device.last_method,
                device.last_seen,
                device.description
            ));
        }
        if background.dragged() && !node_dragging {
            self.offset += background.drag_delta();
        }
        moved
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Link, Observation};

    fn layout_map() -> Map {
        let mut map = Map::default();
        for index in 0..8 {
            map.merge(Observation {
                ip: Some(std::net::Ipv4Addr::new(192, 0, 2, index + 1)),
                context: "test".into(),
                group: if index == 3 { "Vicini LLDP" } else { "LAN" }.into(),
                mac: None,
                chassis: None,
                name: format!("Apparato {index}"),
                description: String::new(),
                method: String::new(),
                responding: false,
            });
        }
        map
    }

    #[test]
    fn connected_devices_surround_each_switch_without_overlap_or_moving_twice() {
        for kind in [LinkKind::Observed, LinkKind::Inferred, LinkKind::Manual] {
            let mut map = layout_map();
            for (from, to) in [(1, 2), (1, 3), (1, 4), (5, 6), (5, 7), (1, 5)] {
                map.add_link(Link {
                    from,
                    to,
                    from_port: String::new(),
                    to_port: String::new(),
                    kind,
                    evidence: String::new(),
                    source: from,
                    last_seen: 0,
                    stale: false,
                });
            }
            let mut diagram = Diagram::default();
            diagram.rearrange(&mut map);
            for (center, leaves) in [(0, &[1, 2, 3][..]), (4, &[5, 6][..])] {
                let center = Vec2::from(map.devices[center].position);
                let mut average = Vec2::ZERO;
                for &leaf in leaves {
                    let position = Vec2::from(map.devices[leaf].position);
                    assert!(((position - center).length() - 180.0).abs() < 0.01);
                    average += position;
                }
                assert!((average / leaves.len() as f32 - center).length() < 0.01);
            }
            for (index, device) in map.devices.iter().enumerate() {
                let rect = Rect::from_min_size(Pos2::from(device.position), Vec2::new(150.0, 88.0));
                for other in &map.devices[index + 1..] {
                    assert!(!rect.intersects(Rect::from_min_size(
                        Pos2::from(other.position),
                        Vec2::new(150.0, 88.0),
                    )));
                }
            }
            let positions: Vec<_> = map.devices.iter().map(|d| d.position).collect();
            diagram.rearrange(&mut map);
            assert_eq!(
                positions,
                map.devices.iter().map(|d| d.position).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn isolated_gateway_pair_uses_source_as_center_but_ignores_stale_and_cross_context_links() {
        let mut map = layout_map();
        map.devices[7].context = "Altra rete".into();
        for (from, to, stale) in [(2, 1, false), (2, 3, true), (2, 8, false)] {
            map.add_link(Link {
                from,
                to,
                from_port: String::new(),
                to_port: String::new(),
                kind: LinkKind::Inferred,
                evidence: String::new(),
                source: from,
                last_seen: 0,
                stale,
            });
        }
        Diagram::default().rearrange(&mut map);
        assert_eq!(map.devices[1].position, [180.0, 180.0]);
        assert_eq!(map.devices[0].position, [360.0, 180.0]);
        assert!(map.devices[2].position[1] > 360.0);
        assert!(map.devices[7].position[1] > 360.0);
    }

    #[test]
    fn mac_and_response_time_are_drawn_inside_the_device_node() {
        for (method, latency, expected) in [
            ("ICMP", Some(420), "Ping: 0.42 ms"),
            ("ICMP", Some(0), "Ping: <1 ms"),
            ("TCP 443", Some(1250), "TCP: 1.25 ms"),
            ("SNMPv2c", Some(2000), "SNMPv2c: 2.00 ms"),
            ("", None, "Ping: non disponibile"),
        ] {
            let mut map = Map::default();
            let mac = "02:03:04:05:06:07";
            map.merge(Observation {
                ip: Some(std::net::Ipv4Addr::LOCALHOST),
                context: "test".into(),
                group: "test".into(),
                mac: Some(mac.into()),
                chassis: None,
                name: "Host".into(),
                description: String::new(),
                method: method.into(),
                responding: true,
            });
            map.devices[0].last_latency_us = latency;
            let ctx = egui::Context::default();
            let mut diagram = Diagram::default();
            let mut output = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(Rect::from_min_size(Pos2::ZERO, Vec2::new(800.0, 600.0))),
                    ..Default::default()
                },
                |ui| {
                    diagram.show(ui, &mut map);
                },
            );
            let node = Rect::from_min_size(
                Pos2::ZERO + diagram.offset,
                Vec2::new(150.0, 88.0) * diagram.zoom,
            );
            for expected in [mac, expected] {
                assert!(
                    output.shapes.iter().any(|s| match &s.shape {
                        egui::epaint::Shape::Text(text) => {
                            text.galley.job.text == expected
                                && node.contains_rect(text.visual_bounding_rect())
                        }
                        _ => false,
                    }),
                    "Testo assente o fuori dal nodo: {expected}"
                );
            }
            output.textures_delta.clear();
        }
    }
    #[test]
    fn canvas_renders_five_hundred_nodes_and_fit_without_network() {
        let mut map = Map::default();
        for index in 1..=500u32 {
            map.merge(Observation {
                ip: Some(std::net::Ipv4Addr::from(0xc0000000 + index)),
                context: "demo".into(),
                group: "demo".into(),
                mac: None,
                chassis: None,
                name: format!("Host {index}"),
                description: String::new(),
                method: String::new(),
                responding: false,
            });
        }
        let ctx = egui::Context::default();
        let mut diagram = Diagram::default();
        let mut output = ctx.run_ui(
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, Vec2::new(1280.0, 800.0))),
                ..Default::default()
            },
            |ui| {
                egui::CentralPanel::default().show(ui, |ui| {
                    diagram.show(ui, &mut map);
                });
            },
        );
        assert!(!output.shapes.is_empty());
        assert!(diagram.zoom.is_finite());
        output.textures_delta.clear();
    }
}
