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
        ui.horizontal(|ui| {
            if ui
                .button(if self.file_reveal {
                    "Mask file values"
                } else {
                    "Reveal file values"
                })
                .clicked()
            {
                self.file_reveal = !self.file_reveal;
            }
            if ui.available_width() >= 400.0 {
                ui.checkbox(&mut self.file_side_by_side, "Side-by-side preview");
            }
        });
        ui.add(
            egui::TextEdit::singleline(&mut self.file_search).hint_text("Search affected paths"),
        );
        let mut comparison_request = None;
        ui.columns(2, |columns| {
            egui::ScrollArea::vertical().id_salt("affected_files").max_height(300.0).show(&mut columns[0], |ui| {
                let mut directories: std::collections::BTreeMap<String, Vec<usize>> = std::collections::BTreeMap::new();
                for &index in related {
                    let file = mask_known_values(&self.findings[index].file, known_values);
                    if !file.to_lowercase().contains(&self.file_search.to_lowercase()) { continue; }
                    let directory = file.rsplit_once('/').map(|(dir, _)| dir).unwrap_or("/").to_owned();
                    directories.entry(directory).or_default().push(index);
                }
                for (directory, indices) in directories {
                    egui::CollapsingHeader::new(directory).default_open(true).show(ui, |ui| {
                        for index in indices {
                            let finding = &self.findings[index];
                            let file = mask_known_values(&finding.file, known_values);
                            let name = file.rsplit('/').next().filter(|part| !part.is_empty()).unwrap_or("Unknown file");
                            let label = format!("{}\n{}", name, mask_known_values(&finding.commit, known_values));
                            if ui.add_enabled(!busy, egui::Button::new(label).selected(self.file_preview.as_ref().is_some_and(|(i, _)| *i == index))).clicked() {
                                let repo = self.repo();
                                let commit = finding.commit.clone();
                                let path = finding.file.clone();
                                let value = target.secret.clone();
                                self.file_preview = None;
                                self.file_comparison = None;
                                self.file_reveal = false;
                                self.status = "Loading historical file…".into();
                                self.task(move || ResultMessage::FilePreview(index, sherlock_git::preview_file(&repo, &commit, &path, &value)));
                            }
                        }
                    });
                }
            });
            let ui = &mut columns[1];
            if let Some((index, result)) = &self.file_preview {
                let finding = &self.findings[*index];
                ui.label(format!("Preview · {} @ {}", mask_known_values(&finding.file, known_values), mask_known_values(&finding.commit, known_values)));
                ui.label(format!("Replacement: {} · branch context: reported commit; branch membership is shown in history below.", mask_known_values("[REDACTED]", known_values)));
                if known_values.iter().any(|value| !value.is_empty() && "[REDACTED]".contains(value)) {
                    ui.colored_label(Color32::YELLOW, "The configured replacement contains a known value.");
                }
                let correspondence = self.prepared.as_ref().filter(|prepared| prepared.source == self.repo() && prepared.value == target.secret).and_then(|prepared| {
                    prepared.source_tips.iter().position(|tip| tip == &finding.commit).map(|position| (prepared.destination.clone(), prepared.source_tips[position].clone(), prepared.refs[position].clone()))
                });
                if self.prepared.is_some() {
                    if let Some((repo, original, rewritten_ref)) = correspondence {
                        if ui.add_enabled(!busy, egui::Button::new("Compare actual rewritten file")).clicked() {
                            let path = finding.file.clone();
                            let index = *index;
                            comparison_request = Some((index, repo, original, rewritten_ref, path));
                        }
                    } else {
                        ui.label("This is a proposed preview. Correspondence to an actual rewritten commit is not available for this finding.");
                    }
                }
                match result {
                    Err(error) => { ui.colored_label(Color32::YELLOW, mask_known_values(error, known_values)); }
                    Ok(preview) => {
                        ui.label(format!("{} exact replacement(s) in this file. Scanner reports and other exact matches may differ.", preview.replacements));
                        if !self.file_reveal && known_values.iter().any(|value| value.contains(['\n', '\r']) && (preview.original.contains(value) || preview.rewritten.contains(value))) {
                            ui.colored_label(Color32::YELLOW, "A known multiline value occurs in this file; the content cannot be safely displayed in this preview.");
                            return;
                        }
                        let display = |text: &str| if self.file_reveal { text.to_owned() } else { mask_known_values(text, known_values) };
                        if self.file_side_by_side && ui.available_width() >= 400.0 {
                            ui.columns(2, |columns| {
                                columns[0].label("Original · proposed preview");
                                columns[1].label("Proposed result");
                                for (line_no, line) in preview.original.lines().enumerate() {
                                    if !target.secret.is_empty() && line.contains(&target.secret) {
                                        let reported = related.iter().any(|&i| self.findings[i].secret == target.secret && self.findings[i].commit == finding.commit && self.findings[i].file == finding.file && self.findings[i].line.parse::<usize>().ok() == Some(line_no + 1));
                                        let marker = if reported { "reported line; may include other matches" } else { "unreported exact match" };
                                        columns[0].colored_label(Color32::YELLOW, format!("{}  [{marker}]", display(line)));
                                        columns[1].colored_label(Color32::LIGHT_GREEN, display(&line.replace(&target.secret, "[REDACTED]")));
                                    } else {
                                        columns[0].monospace(display(line));
                                        columns[1].monospace(display(line));
                                    }
                                }
                            });
                        } else { egui::ScrollArea::both().id_salt("file_preview").max_height(300.0).show(ui, |ui| {
                            for (line_no, line) in preview.original.lines().enumerate() {
                                let reported = related.iter().any(|&i| self.findings[i].secret == target.secret && self.findings[i].commit == finding.commit && self.findings[i].file == finding.file && self.findings[i].line.parse::<usize>().ok() == Some(line_no + 1));
                                let suffix = if reported { "  [reported line; may include other matches]" } else { "  [unreported exact match]" };
                                if !target.secret.is_empty() && line.contains(&target.secret) {
                                    ui.monospace(format!("- {}{}", display(line), suffix));
                                    ui.monospace(format!("+ {}", display(&line.replace(&target.secret, "[REDACTED]"))));
                                } else {
                                    ui.monospace(format!("  {}", display(line)));
                                }
                            }
                        }); }
                    }
                }
                if let Some((comparison_index, comparison)) = &self.file_comparison {
                    if comparison_index == index {
                        ui.separator();
                        ui.label("ACTUAL REWRITE · recorded corresponding branch tips");
                        match comparison {
                            Err(error) => { ui.colored_label(Color32::YELLOW, mask_known_values(error, known_values)); }
                            Ok(comparison) => {
                                if !self.file_reveal && known_values.iter().any(|value| value.contains(['\n', '\r']) && (comparison.original.contains(value) || comparison.rewritten.contains(value))) {
                                    ui.colored_label(Color32::YELLOW, "A known multiline value occurs in this file; reveal it to inspect this comparison.");
                                } else {
                                    ui.columns(2, |columns| {
                                        columns[0].label("Original file");
                                        columns[0].monospace(if self.file_reveal { comparison.original.clone() } else { mask_known_values(&comparison.original, known_values) });
                                        columns[1].label("Actual rewritten file");
                                        columns[1].monospace(if self.file_reveal { comparison.rewritten.clone() } else { mask_known_values(&comparison.rewritten, known_values) });
                                    });
                                }
                            }
                        }
                    }
                }
            } else {
                ui.label("Select an affected file to inspect its proposed changes.");
            }
        });
        if let Some((index, repo, original, rewritten_ref, path)) = comparison_request {
            self.file_comparison = None;
            self.task(move || {
                ResultMessage::FileComparison(index, (|| {
                    let refs = vec![rewritten_ref.name.clone()];
                    let check = || -> Result<(), String> {
                        if sherlock_git::snapshot_refs(&repo, &refs)?[0].tip != rewritten_ref.tip {
                            return Err("The rewritten branch changed since preparation; comparison is unavailable.".into());
                        }
                        Ok(())
                    };
                    check()?;
                    let result = sherlock_git::compare_files(&repo, &original, &rewritten_ref.tip, &path)?;
                    check()?;
                    Ok(result)
                })())
            });
        }
    }
}
