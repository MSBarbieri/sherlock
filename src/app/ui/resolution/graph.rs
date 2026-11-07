use super::*;

const LANES: [Color32; 6] = [
    Color32::from_rgb(103, 194, 188),
    Color32::from_rgb(167, 151, 234),
    Color32::from_rgb(232, 164, 113),
    Color32::from_rgb(121, 172, 225),
    Color32::from_rgb(210, 133, 170),
    Color32::from_rgb(152, 195, 129),
];

/// Render Git's graph cells as lines. Cell positions come from `git log --graph`,
/// so the presentation does not infer parent relationships from branch names.
pub(super) fn show(
    ui: &mut egui::Ui,
    view: &HistoryView,
    branches: &[sherlock_git::RefSnapshot],
    checked: &[bool],
    selected: Option<&str>,
    known_values: &[String],
    busy: bool,
    id: &str,
) -> Option<String> {
    let mut choose = None;
    let lane_width = view
        .lines
        .iter()
        .map(|row| row.drawing.chars().count())
        .max()
        .unwrap_or(1) as f32
        * 8.0
        + 12.0;
    egui::ScrollArea::both()
        .id_salt(id)
        .max_height(360.0)
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            let mut rows = view.lines.iter().peekable();
            while let Some(line) = rows.next() {
                let collapsible = |row: &sherlock_git::GraphLine| {
                    row.commit.as_ref().is_some_and(|commit| {
                        row.parents.len() == 1
                            && row.drawing.chars().all(|c| c == '*' || c == ' ')
                            && !view
                                .history
                                .commits
                                .iter()
                                .any(|item| item.commit == *commit)
                            && !view
                                .history
                                .refs
                                .iter()
                                .any(|reference| reference.tip == *commit)
                    })
                };
                if collapsible(line) {
                    let mut stretch = vec![line];
                    while rows.peek().is_some_and(|row| collapsible(row)) {
                        stretch.push(rows.next().unwrap());
                    }
                    if stretch.len() > 1 {
                        let fold_id = ui.make_persistent_id((id, &line.commit));
                        let mut expanded =
                            ui.data_mut(|data| data.get_temp::<bool>(fold_id).unwrap_or(false));
                        let (rect, response) = ui.allocate_exact_size(
                            egui::vec2(ui.available_width().max(lane_width + 190.0), 32.0),
                            egui::Sense::click(),
                        );
                        if response.hovered() {
                            ui.painter()
                                .rect_filled(rect, 5.0, Color32::from_rgb(38, 36, 40));
                        }
                        let column = line
                            .drawing
                            .chars()
                            .position(|glyph| glyph == '*')
                            .unwrap_or(0);
                        let x = rect.left() + 10.0 + column as f32 * 8.0;
                        let color = LANES[(column / 2) % LANES.len()];
                        ui.painter().line_segment(
                            [egui::pos2(x, rect.top()), egui::pos2(x, rect.bottom())],
                            egui::Stroke::new(1.8_f32, color),
                        );
                        ui.painter()
                            .circle_filled(egui::pos2(x, rect.center().y), 3.0, color);
                        let label = format!(
                            "{} {} commits without known findings",
                            if expanded { "▾" } else { "▸" },
                            stretch.len()
                        );
                        response.widget_info(|| {
                            egui::WidgetInfo::labeled(egui::WidgetType::Button, true, &label)
                        });
                        ui.painter().text(
                            egui::pos2(rect.left() + lane_width, rect.center().y),
                            egui::Align2::LEFT_CENTER,
                            label,
                            egui::FontId::proportional(11.0),
                            Color32::from_rgb(156, 158, 169),
                        );
                        if response.clicked() {
                            expanded = !expanded;
                            ui.data_mut(|data| data.insert_temp(fold_id, expanded));
                        }
                        if expanded {
                            for row in stretch {
                                draw_row(
                                    ui,
                                    view,
                                    row,
                                    lane_width,
                                    branches,
                                    checked,
                                    selected,
                                    known_values,
                                    busy,
                                    &mut choose,
                                );
                            }
                        }
                        continue;
                    }
                }
                draw_row(
                    ui,
                    view,
                    line,
                    lane_width,
                    branches,
                    checked,
                    selected,
                    known_values,
                    busy,
                    &mut choose,
                );
            }
        });
    choose
}

#[allow(clippy::too_many_arguments)]
fn draw_row(
    ui: &mut egui::Ui,
    view: &HistoryView,
    row: &sherlock_git::GraphLine,
    lane_width: f32,
    branches: &[sherlock_git::RefSnapshot],
    checked: &[bool],
    selected: Option<&str>,
    known_values: &[String],
    busy: bool,
    choose: &mut Option<String>,
) {
    let occurrence = row
        .commit
        .as_ref()
        .and_then(|id| view.history.commits.iter().find(|item| item.commit == *id));
    let tip_refs: Vec<_> = row
        .commit
        .as_ref()
        .map(|id| {
            view.history
                .refs
                .iter()
                .filter(|reference| reference.tip == *id)
                .collect()
        })
        .unwrap_or_default();
    let is_commit = row.commit.is_some();
    let height = if is_commit {
        if tip_refs.is_empty() {
            48.0
        } else {
            66.0
        }
    } else {
        15.0
    };
    let width = ui.available_width().max(lane_width + 190.0);
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(width, height),
        if occurrence.is_some() && !busy {
            egui::Sense::click()
        } else {
            egui::Sense::hover()
        },
    );
    let painter = ui.painter();
    let is_selected = row.commit.as_deref().is_some_and(|id| Some(id) == selected);
    if is_commit && (response.hovered() || is_selected) {
        painter.rect_filled(
            rect.shrink2(egui::vec2(1.0, 1.0)),
            5.0,
            if is_selected {
                Color32::from_rgb(40, 67, 65)
            } else {
                Color32::from_rgb(38, 36, 40)
            },
        );
    }
    let center_y = rect.center().y;
    for (column, glyph) in row.drawing.chars().enumerate() {
        let x = rect.left() + 10.0 + column as f32 * 8.0;
        let color = LANES[(column / 2) % LANES.len()];
        let stroke = egui::Stroke::new(1.8_f32, color);
        let segment = |a: (f32, f32), b: (f32, f32)| {
            painter.line_segment([egui::pos2(a.0, a.1), egui::pos2(b.0, b.1)], stroke)
        };
        match glyph {
            '|' => {
                segment((x, rect.top()), (x, rect.bottom()));
            }
            '/' => {
                segment((x + 8.0, rect.top()), (x - 8.0, rect.bottom()));
            }
            '\\' => {
                segment((x - 8.0, rect.top()), (x + 8.0, rect.bottom()));
            }
            '_' | '-' => {
                segment((x - 4.0, center_y), (x + 4.0, center_y));
            }
            '*' | 'o' => {
                segment((x, rect.top()), (x, center_y));
                if !row.parents.is_empty() {
                    segment((x, center_y), (x, rect.bottom()));
                }
                let node = egui::pos2(x, center_y);
                if occurrence.is_some() {
                    painter.circle_filled(node, 6.0, Color32::from_rgb(237, 180, 96));
                    painter.circle_stroke(
                        node,
                        8.0,
                        egui::Stroke::new(1.2_f32, Color32::from_rgb(128, 92, 60)),
                    );
                } else if row.parents.len() > 1 {
                    let points = vec![
                        node + egui::vec2(0.0, -5.5),
                        node + egui::vec2(5.5, 0.0),
                        node + egui::vec2(0.0, 5.5),
                        node + egui::vec2(-5.5, 0.0),
                    ];
                    painter.add(egui::Shape::convex_polygon(
                        points,
                        Color32::from_rgb(30, 29, 32),
                        stroke,
                    ));
                } else {
                    painter.circle_filled(node, 4.2, Color32::from_rgb(29, 28, 31));
                    painter.circle_stroke(node, 4.2, stroke);
                }
            }
            _ => {}
        }
    }
    if let Some(id) = &row.commit {
        let text_x = rect.left() + lane_width;
        let clip = egui::Rect::from_min_max(egui::pos2(text_x, rect.top()), rect.max);
        let painter = painter.with_clip_rect(clip);
        let subject = if row.subject.is_empty() {
            "(no commit message)".to_owned()
        } else {
            mask_known_values(&row.subject, known_values)
        };
        painter.text(
            egui::pos2(text_x, rect.top() + 7.0),
            egui::Align2::LEFT_TOP,
            subject,
            egui::FontId::proportional(13.0),
            Color32::from_rgb(230, 228, 233),
        );
        let mut meta = mask_known_values(&id[..id.len().min(9)], known_values);
        if row.parents.len() > 1 {
            meta.push_str("  ·  merge");
        }
        if let Some(found) = occurrence {
            meta.push_str(&format!("  ·  {} observed", found.finding_indices.len()));
        }
        painter.text(
            egui::pos2(text_x, rect.top() + 26.0),
            egui::Align2::LEFT_TOP,
            meta,
            egui::FontId::monospace(11.0),
            if occurrence.is_some() {
                Color32::from_rgb(237, 180, 96)
            } else {
                Color32::from_rgb(146, 148, 159)
            },
        );
        if !tip_refs.is_empty() {
            let mut x = text_x;
            for reference in &tip_refs {
                let state = branches
                    .iter()
                    .position(|branch| branch.name == reference.name)
                    .and_then(|i| checked.get(i))
                    .copied();
                let short = reference
                    .name
                    .strip_prefix("refs/heads/")
                    .or_else(|| reference.name.strip_prefix("refs/remotes/"))
                    .unwrap_or(&reference.name);
                let label = format!(
                    "{}{}",
                    mask_known_values(short, known_values),
                    match state {
                        Some(true) => " · selected",
                        Some(false) => " · excluded",
                        None => "",
                    }
                );
                let color = if state == Some(false) {
                    Color32::from_rgb(166, 163, 169)
                } else {
                    Color32::from_rgb(136, 211, 198)
                };
                let galley = painter.layout_no_wrap(label, egui::FontId::proportional(10.5), color);
                let badge = egui::Rect::from_min_size(
                    egui::pos2(x, rect.top() + 45.0),
                    galley.size() + egui::vec2(12.0, 4.0),
                );
                painter.rect_filled(
                    badge,
                    4.0,
                    if state == Some(false) {
                        Color32::from_rgb(55, 51, 54)
                    } else {
                        Color32::from_rgb(35, 65, 62)
                    },
                );
                painter.galley(badge.min + egui::vec2(6.0, 2.0), galley, color);
                x = badge.right() + 4.0;
            }
        }
        if response.clicked() {
            *choose = Some(id.clone());
        }
        let refs = tip_refs
            .iter()
            .map(|reference| mask_known_values(&reference.name, known_values))
            .collect::<Vec<_>>()
            .join("\n");
        let action = if occurrence.is_some() {
            "Select to inspect observed findings"
        } else {
            "No scanner observation at this commit"
        };
        response.widget_info(|| {
            egui::WidgetInfo::labeled(
                if occurrence.is_some() {
                    egui::WidgetType::Button
                } else {
                    egui::WidgetType::Label
                },
                !busy,
                format!(
                    "{} · {} · {} {}",
                    mask_known_values(&row.subject, known_values),
                    mask_known_values(&id[..id.len().min(9)], known_values),
                    action,
                    refs
                ),
            )
        });
        response.on_hover_text(format!(
            "{}\n{}{}",
            mask_known_values(&row.subject, known_values),
            action,
            if refs.is_empty() {
                String::new()
            } else {
                format!("\n{refs}")
            }
        ));
    }
}
