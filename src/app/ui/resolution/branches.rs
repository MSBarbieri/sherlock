use super::*;

impl App {
    pub(super) fn render_branch_selection(
        &mut self,
        ui: &mut egui::Ui,
        f: &Finding,
        related: &[usize],
        busy: bool,
        known_values: &[String],
    ) {
        if ui
            .add_enabled(!busy, egui::Button::new("Find branches for this value"))
            .clicked()
        {
            let p = self.repo();
            let occurrences: Vec<Finding> = self
                .findings
                .iter()
                .filter(|item| !f.secret.is_empty() && item.secret == f.secret)
                .cloned()
                .collect();
            self.branches.clear();
            self.checked.clear();
            self.history_output = None;
            self.status = "Checking local and remote-tracking refs…".into();
            self.task(move || {
                ResultMessage::Branches(
                    sherlock_git::branches_for_findings(&p, &occurrences)
                        .and_then(|refs| sherlock_git::snapshot_refs(&p, &refs)),
                )
            });
        }
        if ui
            .add_enabled(
                !busy && !f.secret.is_empty(),
                egui::Button::new("Show related commit history"),
            )
            .clicked()
        {
            let repo = self.repo();
            let occurrences: Vec<Finding> =
                related.iter().map(|&i| self.findings[i].clone()).collect();
            self.history_output = None;
            self.status = "Loading reported commit history…".into();
            let finding_indices = related.to_vec();
            self.task(move || {
                ResultMessage::History((|| {
                    let mut names = std::collections::BTreeSet::new();
                    for finding in &occurrences {
                        if let Ok(refs) = sherlock_git::branches(&repo, &finding.commit) {
                            names.extend(refs);
                        }
                    }
                    let names: Vec<_> = names.into_iter().collect();
                    let history = sherlock_git::secret_history(&repo, &occurrences, &names)?;
                    let (lines, truncated) = sherlock_git::history_graph(&repo, &history)?;
                    Ok(HistoryView {
                        history,
                        lines,
                        truncated,
                        finding_indices,
                    })
                })())
            });
        }
        let mut navigate = None;
        if let Some(history) = &self.history_output {
            match history {
                Err(error) => {
                    ui.colored_label(
                        Color32::YELLOW,
                        format!(
                            "History incomplete: {}",
                            mask_known_values(error, known_values)
                        ),
                    );
                }
                Ok(view) => {
                    ui.label("Original history · dots mark scanner-reported occurrences. Unmarked commits are not known to be clean; no moves or disappearances are inferred.");
                    if view.history.shallow {
                        ui.colored_label(Color32::YELLOW, "This repository has incomplete shallow history. Obtain complete history before preparing a rewrite.");
                    }
                    if view.truncated {
                        ui.colored_label(
                            Color32::YELLOW,
                            "History is limited to 500 commits; older ancestry is not shown.",
                        );
                    }
                    egui::ScrollArea::both()
                        .id_salt("history_graph")
                        .max_height(320.0)
                        .show(ui, |ui| {
                            for line in &view.lines {
                                let Some(id) = &line.commit else {
                                    ui.monospace(&line.drawing);
                                    continue;
                                };
                                let occurrence =
                                    view.history.commits.iter().find(|c| c.commit == *id);
                                let mut labels = Vec::new();
                                for snapshot in &view.history.refs {
                                    if snapshot.tip == *id {
                                        let selection = self
                                            .branches
                                            .iter()
                                            .position(|b| b.name == snapshot.name)
                                            .map(|i| {
                                                if self.checked[i] {
                                                    "selected"
                                                } else {
                                                    "excluded"
                                                }
                                            })
                                            .unwrap_or("linked value");
                                        labels.push(format!(
                                            "{} ({selection})",
                                            mask_known_values(&snapshot.name, known_values)
                                        ));
                                    }
                                }
                                let marker = if occurrence.is_some() {
                                    "● observed"
                                } else {
                                    "○"
                                };
                                let title = format!(
                                    "{}{} {}  {}",
                                    line.drawing,
                                    &id[..id.len().min(10)],
                                    marker,
                                    labels.join(", ")
                                );
                                if let Some(commit) = occurrence {
                                    if ui
                                        .add(egui::Button::new(
                                            egui::RichText::new(title).monospace(),
                                        ))
                                        .clicked()
                                    {
                                        navigate = commit
                                            .finding_indices
                                            .first()
                                            .map(|i| view.finding_indices[*i]);
                                    }
                                } else {
                                    ui.monospace(title);
                                }
                            }
                        });
                    for unplaced in &view.history.unplaced {
                        let finding = &self.findings[view.finding_indices[unplaced.finding_index]];
                        ui.label(format!(
                            "Unplaced finding · {}:{} · {}",
                            mask_known_values(&finding.file, known_values),
                            mask_known_values(&finding.line, known_values),
                            unplaced.reason
                        ));
                    }
                }
            }
        }
        if let Some(index) = navigate {
            self.selected = Some(index);
            self.revealed = None;
            self.file_preview = None;
            self.branches.clear();
            self.checked.clear();
            self.history_output = None;
        }
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            crate::app::ui::icons::show(ui, crate::app::ui::icons::Icon::Branch);
            ui.label(
                RichText::new("CONTAINING REFS FOR SELECTED VALUE")
                    .small()
                    .weak(),
            );
        });
        egui::ScrollArea::vertical()
            .max_height(150.0)
            .show(ui, |ui| {
                for (i, branch) in self.branches.iter().enumerate() {
                    ui.add_enabled(
                        !busy,
                        egui::Checkbox::new(
                            &mut self.checked[i],
                            mask_known_values(&branch.name, &known_values),
                        ),
                    );
                }
            });
        if !self.branches.is_empty() {
            let selected_count = self.checked.iter().filter(|checked| **checked).count();
            let excluded_count = self.branches.len() - selected_count;
            ui.label(format!(
                "{selected_count} selected · {excluded_count} excluded"
            ));
            if excluded_count > 0 {
                ui.label(RichText::new("Excluded refs will not get redacted branches and may still contain this value.").color(Color32::YELLOW));
            }
            if self.findings.iter().any(|item| {
                !f.secret.is_empty() && item.secret == f.secret && item.commit.is_empty()
            }) {
                ui.label(RichText::new("Some findings have no commit, so their affected branches could not be identified.").color(Color32::YELLOW));
            }
        }
    }
}
