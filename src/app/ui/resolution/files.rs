use super::*;

impl App {
    pub(super) fn render_file_inspection(
        &mut self,
        ui: &mut egui::Ui,
        target: &Finding,
        related: &[usize],
        busy: bool,
        known_values: &[String],
    ) {
        ui.separator();
        ui.label(
            RichText::new("AFFECTED FILES · PROPOSED PREVIEW")
                .small()
                .weak(),
        );
        ui.label("Choose a reported file and commit. The preview applies only to the selected exact value and file; other commits, files, and unreported values are not covered.");
        ui.add(
            egui::TextEdit::singleline(&mut self.file_search).hint_text("Search affected paths"),
        );
        ui.columns(2, |columns| {
            egui::ScrollArea::vertical().id_salt("affected_files").max_height(300.0).show(&mut columns[0], |ui| {
                for &index in related {
                    let finding = &self.findings[index];
                    let file = mask_known_values(&finding.file, known_values);
                    if !file.to_lowercase().contains(&self.file_search.to_lowercase()) { continue; }
                    let label = format!("{}\n{}", if file.is_empty() { "Unknown file" } else { &file }, mask_known_values(&finding.commit, known_values));
                    if ui.add_enabled(!busy, egui::Button::new(label).selected(self.file_preview.as_ref().is_some_and(|(i, _)| *i == index))).clicked() {
                        let repo = self.repo();
                        let commit = finding.commit.clone();
                        let path = finding.file.clone();
                        let value = target.secret.clone();
                        self.file_preview = None;
                        self.status = "Loading historical file…".into();
                        self.task(move || ResultMessage::FilePreview(index, sherlock_git::preview_file(&repo, &commit, &path, &value)));
                    }
                }
            });
            let ui = &mut columns[1];
            if let Some((index, result)) = &self.file_preview {
                let finding = &self.findings[*index];
                ui.label(format!("Preview · {} @ {}", mask_known_values(&finding.file, known_values), mask_known_values(&finding.commit, known_values)));
                ui.label("Replacement: [REDACTED] · branch context: reported commit; branch membership is shown in history below.");
                match result {
                    Err(error) => { ui.colored_label(Color32::YELLOW, mask_known_values(error, known_values)); }
                    Ok(preview) => {
                        ui.label(format!("{} exact replacement(s) in this file. Scanner reports and other exact matches may differ.", preview.replacements));
                        if known_values.iter().any(|value| value.contains(['\n', '\r']) && (preview.original.contains(value) || preview.rewritten.contains(value))) {
                            ui.colored_label(Color32::YELLOW, "A known multiline value occurs in this file; the content cannot be safely displayed in this preview.");
                            return;
                        }
                        egui::ScrollArea::both().id_salt("file_preview").max_height(300.0).show(ui, |ui| {
                            for (line_no, line) in preview.original.lines().enumerate() {
                                let reported = related.iter().any(|&i| self.findings[i].commit == finding.commit && self.findings[i].file == finding.file && self.findings[i].line.parse::<usize>().ok() == Some(line_no + 1));
                                let suffix = if reported { "  [scanner report]" } else { "  [other exact match]" };
                                if !target.secret.is_empty() && line.contains(&target.secret) {
                                    ui.monospace(format!("- {}{}", mask_known_values(line, known_values), suffix));
                                    ui.monospace(format!("+ {}", mask_known_values(&line.replace(&target.secret, "[REDACTED]"), known_values)));
                                } else {
                                    ui.monospace(format!("  {}", mask_known_values(line, known_values)));
                                }
                            }
                        });
                    }
                }
            } else {
                ui.label("Select an affected file to inspect its proposed changes.");
            }
        });
    }
}
