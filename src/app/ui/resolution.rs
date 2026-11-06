mod diff;
mod files;
mod redaction;
mod related;

use super::super::*;

impl App {
    pub(in crate::app) fn render_resolution(
        &mut self,
        ctx: &egui::Context,
        busy: bool,
        known_values: &[String],
    ) {
        let mut select_related = None;
        if self.page == Page::Resolution && !self.inspection_open {
            egui::SidePanel::left("workspace_list")
                .resizable(true)
                .default_width(310.0)
                .show(ctx, |ui| {
                    ui.heading("Secret workspaces");
                    ui.label(RichText::new(format!("{} investigations", self.linked_groups.len())).weak());
                    ui.add_space(8.0);
                    ui.add(egui::TextEdit::singleline(&mut self.search).hint_text("Search rule, path, commit, or scanner"));
                    egui::ComboBox::from_id_salt("workspace_filter")
                        .selected_text(match self.filter {
                            ReviewFilter::All => "All classifications",
                            ReviewFilter::Potential => "Potential secret",
                            ReviewFilter::FalsePositive => "False positive",
                            ReviewFilter::AcceptedRisk => "Accepted risk",
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.filter, ReviewFilter::All, "All classifications");
                            ui.selectable_value(&mut self.filter, ReviewFilter::Potential, "Potential secret");
                            ui.selectable_value(&mut self.filter, ReviewFilter::FalsePositive, "False positive");
                            ui.selectable_value(&mut self.filter, ReviewFilter::AcceptedRisk, "Accepted risk");
                        });
                    ui.separator();
                    egui::ScrollArea::vertical().id_salt("workspace_list_scroll").show(ui, |ui| {
                        let mut shown = 0;
                        for group in &self.linked_groups {
                            let Some(&index) = group.iter().find(|&&i| workspace_finding_matches(&self.findings[i], &known_values, self.filter, &self.search)) else { continue; };
                            shown += 1;
                            let finding = &self.findings[index];
                            let potential = group.iter().filter(|&&i| self.findings[i].review == Review::Unreviewed).count();
                            let false_positive = group.iter().filter(|&&i| self.findings[i].review == Review::FalsePositive).count();
                            let accepted = group.iter().filter(|&&i| self.findings[i].review == Review::AcceptedRisk).count();
                            let title = format!("{}  ·  {} finding(s)\n{}:{}\n{} potential  ·  {} false positive  ·  {} accepted{}",
                                mask_known_values(&finding.rule, &known_values), group.len(),
                                mask_known_values(&finding.file, &known_values), mask_known_values(&finding.line, &known_values),
                                potential, false_positive, accepted,
                                if finding.secret.is_empty() { "  ·  value unavailable" } else { "" });
                            if ui.add_enabled(!busy, egui::Button::new(title).selected(self.selected.is_some_and(|selected| group.contains(&selected)))).clicked() {
                                select_related = Some(index);
                                self.bulk_selected.clear();
                            }
                            ui.add_space(4.0);
                        }
                        if shown == 0 { ui.label("No workspaces match these filters."); }
                    });
                });
        }
        if self.page == Page::Resolution && self.inspection_open {
            self.render_inspection_workspace(ctx, busy, known_values);
            return;
        }
        if self.page == Page::Resolution && !self.inspection_open {
            egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(12.0); ui.heading("Secret resolution"); ui.separator();
            egui::ScrollArea::vertical().id_salt("detail_content").show(ui, |ui| {
            if let Some(index) = self.selected { let f = self.findings[index].clone();
                ui.horizontal(|ui| { super::icons::show(ui, super::icons::Icon::Finding); ui.label(RichText::new(mask_known_values(&f.rule, &known_values)).strong().color(Color32::from_rgb(197, 184, 255))); });
                ui.horizontal(|ui| { super::icons::show(ui, super::icons::Icon::File); ui.label(format!("{} · line {}", mask_known_values(&f.file, &known_values), mask_known_values(&f.line, &known_values))); });
                ui.horizontal(|ui| { super::icons::show(ui, super::icons::Icon::Commit); ui.label(format!("Commit  {}", mask_known_values(&f.commit, &known_values))); });
                ui.horizontal(|ui| {
                    if f.secret.is_empty() { ui.label("Secret value unavailable"); }
                    else {
                        ui.label(if self.revealed == Some(index) { f.secret.as_str() } else { "Secret  ••••••••••••" });
                        if ui.button(if self.revealed == Some(index) { "Hide value" } else { "Reveal value" }).clicked() {
                            self.revealed = if self.revealed == Some(index) { None } else { Some(index) };
                        }
                    }
                }); ui.add_space(12.0);
                ui.label(format!("Classification: {}", f.review.label()));
                ui.label(RichText::new("Scanner reports are potential secrets; online verification is disabled.").small().weak());
                let previous_review = self.findings[index].review.clone();
                egui::ComboBox::from_id_salt("review").selected_text(self.findings[index].review.label()).show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.findings[index].review, Review::Unreviewed, "Potential secret");
                    ui.selectable_value(&mut self.findings[index].review, Review::FalsePositive, "False positive");
                    ui.selectable_value(&mut self.findings[index].review, Review::AcceptedRisk, "Accepted risk");
                });
                if self.findings[index].review != previous_review {
                    match sherlock_reviews::ReviewStore::standard().and_then(|store| store.save(&self.repo(), &self.findings[index])) {
                        Ok(()) => self.status = "Review decision saved locally.".into(),
                        Err(e) => {
                            self.findings[index].review = previous_review;
                            self.status = format!("Could not save review: {e}");
                        }
                    }
                }
                if f.commit.is_empty() || f.file.is_empty() || f.line.is_empty() || f.secret.is_empty() {
                    ui.label(RichText::new("This finding is missing identifying data, so its review cannot be saved.").small().weak());
                } else {
                    ui.label(RichText::new("Review decisions are stored locally for this repository.").small().weak());
                }
                ui.label("Scanner evidence:");
                for report in &f.evidence { ui.label(format!("{} · {}", mask_known_values(report.scanner, &known_values), mask_known_values(&report.rule, &known_values))); }
                let related = self.linked_groups.iter().find(|group| group.contains(&index)).cloned().unwrap_or_else(|| vec![index]);
                self.render_related_findings(ui, index, &f, &related, busy, known_values, &mut select_related);
                if ui.add_enabled(!busy, egui::Button::new("Inspect history and file changes")).clicked() {
                    self.inspection_open = true;
                    self.file_preview = None;
                    self.file_comparison = None;
                    self.file_reveal = false;
                    let repo = self.repo();
                    let commit = f.commit.clone();
                    let file = f.file.clone();
                    let value = f.secret.clone();
                    self.status = "Loading historical file…".into();
                    self.task(move || ResultMessage::FilePreview(index, sherlock_git::preview_file(&repo, &commit, &file, &value)));
                }
                if !f.secret.is_empty() {
                    ui.separator();
                    ui.label("Link or unlink another detected value");
                    let candidates: Vec<usize> = self.findings.iter().enumerate().filter(|(_, candidate)| !candidate.secret.is_empty() && candidate.secret != f.secret).map(|(i, _)| i).collect();
                    if self.link_candidate.is_some_and(|candidate| !candidates.contains(&candidate)) { self.link_candidate = None; }
                    let candidate_label = self.link_candidate.map(|i| format!("{}:{} · {}", mask_known_values(&self.findings[i].file, &known_values), mask_known_values(&self.findings[i].line, &known_values), mask_known_values(&self.findings[i].rule, &known_values))).unwrap_or_else(|| "Select another finding".into());
                    ui.add_enabled_ui(!busy, |ui| { egui::ComboBox::from_id_salt("link_candidate").selected_text(candidate_label).show_ui(ui, |ui| {
                        for &i in &candidates { let item = &self.findings[i]; ui.selectable_value(&mut self.link_candidate, Some(i), format!("{}:{} · {}", mask_known_values(&item.file, &known_values), mask_known_values(&item.line, &known_values), mask_known_values(&item.rule, &known_values))); }
                    }); });
                    ui.label(RichText::new("Links persist locally using the system credential store. Unlink removes the direct link; other links may still connect the values.").small().weak());
                    ui.horizontal(|ui| { for (label, linked) in [("Link values", true), ("Unlink values", false)] {
                        if ui.add_enabled(!busy && self.link_candidate.is_some(), egui::Button::new(label)).clicked() {
                            let repo = self.link_repo.clone().unwrap_or_else(|| self.repo()); let candidate = self.link_candidate.unwrap(); let a = f.secret.clone(); let b = self.findings[candidate].secret.clone();
                            let values: Vec<String> = self.findings.iter().map(|finding| finding.secret.clone()).collect();
                            self.status = "Saving secret links…".into();
                            self.task(move || ResultMessage::LinkGroups(sherlock_reviews::links::LinkStore::standard().and_then(|store| {
                                store.set_link(&repo, &a, &b, linked)?;
                                load_link_data(&store, &repo, &values)
                            })));
                        }
                    }});
                }
                if !f.secret.is_empty() {
                    ui.separator();
                    if ui.add_enabled(!busy, egui::Button::new("View previous completion")).clicked() {
                        let repo = self.link_repo.clone().unwrap_or_else(|| self.repo()); let value = f.secret.clone();
                        self.completion_output = None;
                        self.task(move || ResultMessage::Completion(sherlock_reviews::links::LinkStore::standard().and_then(|store| store.previously_completed(&repo, &value))));
                    }
                    if let Some(record) = &self.completion_output { ui.label(mask_known_values(record, &known_values)); }
                }
                self.render_redaction(ui, &f, &related, busy, known_values);
            } else { ui.label(RichText::new("Select a finding to inspect its commit and affected branches.").weak()); }
            });
        });
        }
        if let Some(index) = select_related {
            self.revealed = None;
            self.history_output = None;
            self.file_preview = None;
            self.file_comparison = None;
            self.file_reveal = false;
            self.completion_output = None;
            self.selected = Some(index);
            self.inspection_open = false;
            self.branches.clear();
            self.checked.clear();
        }
    }

    fn render_inspection_workspace(
        &mut self,
        ctx: &egui::Context,
        busy: bool,
        known_values: &[String],
    ) {
        let Some(index) = self.selected else {
            self.inspection_open = false;
            return;
        };
        let finding = self.findings[index].clone();
        let related = self
            .linked_groups
            .iter()
            .find(|group| group.contains(&index))
            .cloned()
            .unwrap_or_else(|| vec![index]);
        egui::SidePanel::left("inspection_navigation")
            .resizable(true)
            .default_width(340.0)
            .min_width(240.0)
            .show(ctx, |ui| {
                if ui.button("← Finding details").clicked() {
                    self.inspection_open = false;
                    self.file_reveal = false;
                }
                ui.add_space(6.0);
                egui::ScrollArea::vertical()
                    .id_salt("inspection_navigation_scroll")
                    .show(ui, |ui| {
                        self.render_file_tree(ui, &finding, &related, busy, known_values);
                        ui.separator();
                        ui.label(RichText::new("HISTORY & BRANCHES").small().strong());
                        self.render_branch_selection(ui, &finding, &related, busy, known_values);
                    });
            });
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(8.0);
            self.render_file_preview(ui, &finding, &related, busy, known_values);
        });
    }
}
