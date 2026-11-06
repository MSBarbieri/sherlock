use super::*;

impl App {
    pub(super) fn render_file_tree(
        &mut self,
        ui: &mut egui::Ui,
        target: &Finding,
        related: &[usize],
        busy: bool,
        known_values: &[String],
    ) {
        ui.horizontal(|ui| {
            super::super::icons::show(ui, super::super::icons::Icon::File);
            ui.label(RichText::new("AFFECTED FILES").small().strong());
        });
        ui.add(egui::TextEdit::singleline(&mut self.file_search).hint_text("Search files"));
        let mut directories: std::collections::BTreeMap<String, Vec<usize>> =
            std::collections::BTreeMap::new();
        for &index in related {
            let file = mask_known_values(&self.findings[index].file, known_values);
            if !file
                .to_lowercase()
                .contains(&self.file_search.to_lowercase())
            {
                continue;
            }
            let directory = file
                .rsplit_once('/')
                .map(|(dir, _)| dir)
                .unwrap_or("/")
                .to_owned();
            directories.entry(directory).or_default().push(index);
        }
        egui::ScrollArea::vertical()
            .id_salt("affected_files")
            .max_height(240.0)
            .show(ui, |ui| {
                for (directory, indices) in directories {
                    egui::CollapsingHeader::new(directory)
                        .default_open(true)
                        .show(ui, |ui| {
                            for index in indices {
                                let finding = self.findings[index].clone();
                                let file = mask_known_values(&finding.file, known_values);
                                let name = file
                                    .rsplit('/')
                                    .next()
                                    .filter(|part| !part.is_empty())
                                    .unwrap_or("Unknown file");
                                ui.horizontal(|ui| {
                                    language_icon(ui, &finding.file);
                                    let label = format!(
                                        "{}  ·  {}",
                                        name,
                                        mask_known_values(&finding.commit, known_values)
                                            .chars()
                                            .take(9)
                                            .collect::<String>()
                                    );
                                    if ui
                                        .add_enabled(
                                            !busy,
                                            egui::Button::new(label).selected(
                                                self.file_preview
                                                    .as_ref()
                                                    .is_some_and(|(i, _)| *i == index),
                                            ),
                                        )
                                        .clicked()
                                    {
                                        let repo = self.repo();
                                        let commit = finding.commit.clone();
                                        let path = finding.file.clone();
                                        let value = target.secret.clone();
                                        self.file_preview = None;
                                        self.file_comparison = None;
                                        self.file_reveal = false;
                                        self.status = "Loading historical file…".into();
                                        self.task(move || {
                                            ResultMessage::FilePreview(
                                                index,
                                                sherlock_git::preview_file(
                                                    &repo, &commit, &path, &value,
                                                ),
                                            )
                                        });
                                    }
                                });
                            }
                        });
                }
            });
    }

    pub(super) fn render_file_preview(
        &mut self,
        ui: &mut egui::Ui,
        target: &Finding,
        related: &[usize],
        busy: bool,
        known_values: &[String],
    ) {
        let mut comparison_request = None;
        let mut show_preview = false;
        if let Some((index, result)) = &self.file_preview {
            let finding = &self.findings[*index];
            ui.horizontal_wrapped(|ui| {
                language_icon(ui, &finding.file);
                ui.label(RichText::new(mask_known_values(&finding.file, known_values)).strong());
                ui.label(
                    RichText::new(format!(
                        "@ {}",
                        mask_known_values(&finding.commit, known_values)
                    ))
                    .small()
                    .weak(),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui
                        .button(if self.file_reveal {
                            "Mask values"
                        } else {
                            "Reveal values"
                        })
                        .clicked()
                    {
                        self.file_reveal = !self.file_reveal;
                    }
                });
            });
            ui.separator();
            ui.checkbox(&mut self.file_side_by_side, "Side-by-side diff");
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new("PROPOSED PREVIEW")
                        .small()
                        .strong()
                        .color(Color32::from_rgb(132, 199, 190)),
                );
                ui.label("Exact value · selected commit and file only");
                ui.label(format!(
                    "Replacement: {}",
                    mask_known_values("[REDACTED]", known_values)
                ));
            });
            if known_values
                .iter()
                .any(|value| !value.is_empty() && "[REDACTED]".contains(value))
            {
                ui.colored_label(Color32::YELLOW, "The replacement contains a known value.");
            }
            let correspondence = self
                .prepared
                .as_ref()
                .filter(|p| p.source == self.repo() && p.value == target.secret)
                .and_then(|p| {
                    p.source_tips
                        .iter()
                        .position(|tip| tip == &finding.commit)
                        .map(|i| {
                            (
                                p.destination.clone(),
                                p.source_tips[i].clone(),
                                p.refs[i].clone(),
                            )
                        })
                });
            if self.prepared.is_some() {
                if let Some((repo, original, rewritten_ref)) = correspondence {
                    if ui
                        .add_enabled(!busy, egui::Button::new("Compare actual rewritten file"))
                        .clicked()
                    {
                        comparison_request =
                            Some((*index, repo, original, rewritten_ref, finding.file.clone()));
                    }
                } else {
                    ui.weak(
                        "Actual rewritten-commit correspondence is unavailable for this finding.",
                    );
                }
            }
            match result {
                Err(error) => {
                    ui.colored_label(Color32::YELLOW, mask_known_values(error, known_values));
                }
                Ok(preview) => {
                    let reported: Vec<usize> = related
                        .iter()
                        .filter_map(|&i| {
                            let item = &self.findings[i];
                            (item.secret == target.secret
                                && item.commit == finding.commit
                                && item.file == finding.file)
                                .then(|| item.line.parse().ok())
                                .flatten()
                        })
                        .collect();
                    ui.label(
                        RichText::new(format!(
                            "{} exact replacement(s) · hover removed lines for scanner evidence",
                            preview.replacements
                        ))
                        .small()
                        .weak(),
                    );
                    if !self.file_reveal
                        && known_values.iter().any(|value| {
                            value.contains(['\n', '\r'])
                                && (preview.original.contains(value)
                                    || preview.rewritten.contains(value))
                        })
                    {
                        ui.colored_label(Color32::YELLOW, "A known multiline value occurs in this file; reveal it to inspect the content.");
                    } else if let Some((comparison_index, Ok(comparison))) = &self.file_comparison {
                        if comparison_index == index {
                            ui.separator();
                            ui.label(
                                RichText::new(
                                    "ACTUAL REWRITE · recorded corresponding branch tips",
                                )
                                .small()
                                .strong()
                                .color(Color32::from_rgb(132, 199, 190)),
                            );
                            if ui.button("Show proposed preview").clicked() {
                                show_preview = true;
                            }
                            if !self.file_reveal
                                && known_values.iter().any(|value| {
                                    value.contains(['\n', '\r'])
                                        && (comparison.original.contains(value)
                                            || comparison.rewritten.contains(value))
                                })
                            {
                                ui.colored_label(Color32::YELLOW, "A known multiline value occurs in this file; reveal it to inspect the comparison.");
                            } else {
                                super::diff::render_diff(
                                    ui,
                                    "actual_diff",
                                    &finding.file,
                                    &comparison.original,
                                    &comparison.rewritten,
                                    known_values,
                                    self.file_reveal,
                                    self.file_side_by_side,
                                    &reported,
                                );
                            }
                        }
                    } else {
                        if let Some((comparison_index, Err(error))) = &self.file_comparison {
                            if comparison_index == index {
                                ui.colored_label(
                                    Color32::YELLOW,
                                    mask_known_values(error, known_values),
                                );
                            }
                        }
                        super::diff::render_diff(
                            ui,
                            "preview_diff",
                            &finding.file,
                            &preview.original,
                            &preview.rewritten,
                            known_values,
                            self.file_reveal,
                            self.file_side_by_side,
                            &reported,
                        );
                    }
                }
            }
        } else {
            ui.vertical_centered(|ui| {
                ui.add_space(60.0);
                ui.heading("Inspect an affected file");
                ui.weak("Choose a file in the panel to see its proposed redaction.");
            });
        }
        if show_preview {
            self.file_comparison = None;
        }
        if let Some((index, repo, original, rewritten_ref, path)) = comparison_request {
            self.file_comparison = None;
            self.task(move || ResultMessage::FileComparison(index, (|| {
                let refs = vec![rewritten_ref.name.clone()];
                let check = || -> Result<(), String> {
                    if sherlock_git::snapshot_refs(&repo, &refs)?[0].tip != rewritten_ref.tip { return Err("The rewritten branch changed since preparation; comparison is unavailable.".into()); }
                    Ok(())
                };
                check()?;
                let result = sherlock_git::compare_files(&repo, &original, &rewritten_ref.tip, &path)?;
                check()?;
                Ok(result)
            })()));
        }
    }
}

fn language_icon(ui: &mut egui::Ui, path: &str) {
    let ext = std::path::Path::new(path)
        .extension()
        .and_then(|part| part.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let (label, color) = match ext.as_str() {
        "rs" => ("R", Color32::from_rgb(235, 141, 83)),
        "py" => ("Py", Color32::from_rgb(112, 178, 222)),
        "js" | "jsx" => ("JS", Color32::from_rgb(230, 205, 90)),
        "ts" | "tsx" => ("TS", Color32::from_rgb(104, 162, 229)),
        "json" => ("{}", Color32::from_rgb(220, 195, 110)),
        "toml" | "yaml" | "yml" => ("⚙", Color32::from_rgb(171, 180, 196)),
        _ => ("·", Color32::from_rgb(150, 160, 174)),
    };
    let (rect, _) = ui.allocate_exact_size(egui::vec2(20.0, 20.0), egui::Sense::hover());
    if ext == "rs" {
        let points: Vec<_> = (0..32)
            .map(|i| {
                let angle = i as f32 * std::f32::consts::TAU / 32.0;
                let radius = if i % 2 == 0 { 9.0 } else { 7.0 };
                rect.center() + egui::vec2(angle.cos() * radius, angle.sin() * radius)
            })
            .collect();
        ui.painter().add(egui::Shape::closed_line(
            points,
            egui::Stroke::new(1.2_f32, color),
        ));
    } else {
        ui.painter()
            .circle_stroke(rect.center(), 8.0, egui::Stroke::new(1.4_f32, color));
    }
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        label,
        egui::FontId::proportional(if label.len() > 1 { 8.0 } else { 11.0 }),
        color,
    );
}
