use super::super::*;

impl App {
    pub(in crate::app) fn render_discovery_sidebar(
        &mut self,
        ctx: &egui::Context,
        busy: bool,
        known_values: &[String],
    ) {
        if self.page == Page::Discovery {
            egui::SidePanel::left("sidebar")
                .resizable(true)
                .default_width(260.0)
                .show(ctx, |ui| {
                    ui.add_space(12.0);
                    ui.heading("Workspace");
                    ui.add_space(8.0);
                    ui.horizontal(|ui| { super::icons::show(ui, super::icons::Icon::Repository); ui.label("Current repository"); });
                    ui.label(mask_known_values(&self.repo, known_values));
                    ui.separator();
                    ui.label("Scanner");
                    let previous_scanner = self.scanner;
                    ui.add_enabled_ui(!busy, |ui| {
                        egui::ComboBox::from_id_salt("scanner")
                            .selected_text(self.scanner.label())
                            .show_ui(ui, |ui| {
                                ui.selectable_value(
                                    &mut self.scanner,
                                    Scanner::Both,
                                    "Both scanners",
                                );
                                ui.selectable_value(
                                    &mut self.scanner,
                                    Scanner::Gitleaks,
                                    "Gitleaks",
                                );
                                ui.selectable_value(
                                    &mut self.scanner,
                                    Scanner::TruffleHog,
                                    "TruffleHog",
                                );
                            });
                    });
                    if self.scanner != previous_scanner { self.request_scan(); }
                    if ui.horizontal(|ui| {
                        super::icons::show(ui, super::icons::Icon::Scan);
                        ui.add_enabled(!busy && !self.repo.is_empty(), egui::Button::new("Scan repository")).clicked()
                    }).inner
                    {
                        self.request_scan();
                    }
                    ui.label(RichText::new("Automatic scans cover committed Git history. Uncommitted files are not scanned.").small().weak());
                    ui.add_space(8.0);
                    if ui.horizontal(|ui| {
                        super::icons::show(ui, super::icons::Icon::Refresh);
                        ui.add_enabled(!busy && !self.repo.is_empty(), egui::Button::new("Fetch all remotes")).clicked()
                    }).inner
                    {
                        let p = self.repo();
                        self.branches.clear();
                        self.checked.clear();
                        self.status = "Fetching remotes…".into();
                        self.task(move || ResultMessage::Status(sherlock_git::fetch(&p)));
                    }
                    if !self.saved_links.is_empty() {
                        ui.separator(); ui.label("Saved value links");
                        ui.label(RichText::new("Opaque IDs do not reveal values. Not reported means absent from current scan results, not necessarily from history.").small().weak());
                        egui::ScrollArea::vertical().id_salt("saved_links").max_height(150.0).show(ui, |ui| {
                        for edge in self.saved_links.clone() {
                            let left = format!("{} ({})", &edge.left.id[..12], if edge.left.present { "reported" } else { "not reported" });
                            let right = format!("{} ({})", &edge.right.id[..12], if edge.right.present { "reported" } else { "not reported" });
                            ui.label(format!("{left} ↔ {right}"));
                            if ui.add_enabled(!busy, egui::Button::new("Remove this link")).clicked() {
                                let repo = self.link_repo.clone().unwrap_or_else(|| self.repo());
                                let values: Vec<String> = self.findings.iter().map(|finding| finding.secret.clone()).collect();
                                self.status = "Removing secret link…".into();
                                self.task(move || ResultMessage::LinkGroups(sherlock_reviews::links::LinkStore::standard().and_then(|store| {
                                    store.unlink_ids(&repo, &edge.left.id, &edge.right.id)?;
                                    load_link_data(&store, &repo, &values)
                                })));
                            }
                        }
                        });
                    }
                    ui.add_space(16.0);
                    ui.label(
                    RichText::new(
                        "Fetch updates local remote-tracking refs. Scans and rewrites run locally.",
                    )
                    .small()
                    .weak(),
                );
                });
        }
    }

    pub(in crate::app) fn render_discovery_content(
        &mut self,
        ctx: &egui::Context,
        busy: bool,
        known_values: &[String],
    ) {
        if self.page == Page::Discovery {
            egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                super::icons::show(ui, super::icons::Icon::Finding);
                ui.heading("Secret workspaces");
                ui.label(RichText::new(format!("{}", self.linked_groups.len())).weak());
            });
            ui.label(RichText::new("Select an investigation, then open its findings and actions.").weak());
            if ui.add_enabled(self.selected.is_some() && !busy, egui::Button::new("Open secret resolution →")).clicked() {
                self.page = Page::Resolution;
            }
            if !self.findings.is_empty() {
                ui.horizontal_wrapped(|ui| {
                    ui.label("Classification:");
                    ui.selectable_value(&mut self.filter, ReviewFilter::All, "All");
                    ui.selectable_value(&mut self.filter, ReviewFilter::Potential, "Potential secret");
                    ui.selectable_value(&mut self.filter, ReviewFilter::FalsePositive, "False positive");
                    ui.selectable_value(&mut self.filter, ReviewFilter::AcceptedRisk, "Accepted risk");
                });
                ui.add(egui::TextEdit::singleline(&mut self.search).hint_text("Search rule, path, commit, or scanner"));
            }
            ui.separator();
            let visible: Vec<usize> = self.findings.iter().enumerate()
                .filter(|(_, finding)| workspace_finding_matches(finding, &known_values, self.filter, &self.search))
                .map(|(i, _)| i).collect();
            if !self.findings.is_empty() {
                ui.label(RichText::new(format!("Showing {} of {} findings", visible.len(), self.findings.len())).weak());
                if self.selected.is_some_and(|index| !visible.contains(&index)) {
                    ui.label("The selected finding is hidden by the current filters; its details remain open.");
                }
            }
            egui::ScrollArea::vertical().show(ui, |ui| {
                if self.findings.is_empty() {
                    ui.add_space(60.0);
                    ui.vertical_centered(|ui| {
                        if busy {
                            ui.heading("Working…");
                            ui.label(mask_known_values(&self.status, &known_values));
                        } else if self.scan_completed {
                            ui.heading("No findings reported");
                            ui.label("The selected scanners did not report any findings. This does not guarantee the repository is free of secrets.");
                        } else {
                            ui.heading("Start an investigation");
                            ui.label("Select a scanner and run a scan on this repository.");
                        }
                    });
                } else {
                    if visible.is_empty() {
                        ui.label("No findings match these filters.");
                    }
                    for group in &self.linked_groups {
                        let Some(&i) = group.iter().find(|index| visible.contains(index)) else { continue; };
                        let f = &self.findings[i];
                        let potential = group.iter().filter(|&&index| self.findings[index].review == Review::Unreviewed).count();
                        let false_positives = group.iter().filter(|&&index| self.findings[index].review == Review::FalsePositive).count();
                        let accepted = group.iter().filter(|&&index| self.findings[index].review == Review::AcceptedRisk).count();
                        let text = format!(
                            "{}   ·   {} finding(s)\n{}:{}   ·   {}\n{} potential · {} false positive · {} accepted risk{}",
                            mask_known_values(&f.rule, &known_values),
                            group.len(),
                            mask_known_values(&f.file, &known_values),
                            mask_known_values(&f.line, &known_values),
                            mask_known_values(&f.commit, &known_values).chars().take(10).collect::<String>(),
                            potential, false_positives, accepted,
                            if f.secret.is_empty() { " · value unavailable" } else { "" }
                        );
                        if ui
                            .add_enabled(!busy, egui::Button::new(text).selected(self.selected.is_some_and(|selected| group.contains(&selected))))
                            .clicked()
                        {
                            self.history_output = None;
                            self.completion_output = None;
                            self.selected = Some(i);
                            self.revealed = None;
                            self.bulk_selected.clear();
                            self.bulk_confirm = false;
                            self.page = Page::Resolution;
                            self.branches.clear();
                            self.checked.clear();
                        }
                        ui.separator();
                    }
                }
            });
        });
        }
    }
}
