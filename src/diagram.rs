use crate::model::{LinkKind, Map, Status};
use eframe::egui::{self, Align2, Color32, FontId, Pos2, Rect, Sense, Stroke, StrokeKind, Vec2};
use std::collections::{BTreeMap, HashMap, HashSet};

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
        let mut groups: BTreeMap<(String, String), Vec<usize>> = BTreeMap::new();
        for (index, d) in map.devices.iter().enumerate() {
            groups
                .entry((d.context.clone(), d.group.clone()))
                .or_default()
                .push(index);
        }
        let mut y = 0.0;
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
                    rect.center(),
                    Align2::CENTER_CENTER,
                    device
                        .ip
                        .map_or_else(|| "Senza IP".into(), |ip| ip.to_string()),
                    FontId::monospace((11.0 * self.zoom).clamp(8.0, 18.0)),
                    Color32::LIGHT_GRAY,
                );
                painter.text(
                    rect.center() + Vec2::new(0.0, 18.0 * self.zoom),
                    Align2::CENTER_CENTER,
                    device.mac.as_deref().unwrap_or("MAC: non disponibile"),
                    FontId::monospace((10.0 * self.zoom).clamp(7.0, 16.0)),
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
            response.on_hover_text(format!(
                "{}\nMAC: {}\n{}\n{}\nUltima risposta: {:?}\n{}",
                label,
                device.mac.as_deref().unwrap_or("Non disponibile"),
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
    use crate::model::Observation;
    #[test]
    fn available_mac_is_drawn_on_the_device_node() {
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
            method: "TCP".into(),
            responding: true,
        });
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
        let drawn = output.shapes.iter().any(|s| match &s.shape {
            egui::epaint::Shape::Text(text) => text.galley.job.text.contains(mac),
            _ => false,
        });
        output.textures_delta.clear();
        assert!(drawn);
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
