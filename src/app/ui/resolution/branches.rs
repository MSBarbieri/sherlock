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
            self.history_limit = 500;
            self.history_selected_commit = None;
            self.load_history(related);
        }
        let mut expand_history = false;
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
                            "Older ancestry is not shown until more history is loaded.",
                        );
                    }
                    if view.truncated
                        && ui
                            .add_enabled(!busy, egui::Button::new("Load more history"))
                            .clicked()
                    {
                        expand_history = true;
                    }
                    egui::ScrollArea::both()
                        .id_salt("history_graph")
                        .max_height(320.0)
                        .show(ui, |ui| {
                            let mut rows = view.lines.iter().peekable();
                            while let Some(line) = rows.next() {
                                let collapsible = |row: &sherlock_git::GraphLine| {
                                    row.commit.as_ref().is_some_and(|id| {
                                        row.drawing.chars().all(|c| c == '*' || c == ' ')
                                            && !view
                                                .history
                                                .commits
                                                .iter()
                                                .any(|commit| commit.commit == *id)
                                            && !view
                                                .history
                                                .refs
                                                .iter()
                                                .any(|reference| reference.tip == *id)
                                    })
                                };
                                if collapsible(line) {
                                    let mut stretch = vec![line];
                                    while rows.peek().is_some_and(|row| collapsible(row)) {
                                        stretch.push(rows.next().unwrap());
                                    }
                                    if stretch.len() > 1 {
                                        ui.collapsing(
                                            format!(
                                                "│  ⋯ {} commits without known findings",
                                                stretch.len()
                                            ),
                                            |ui| {
                                                for row in &stretch {
                                                    let id = row.commit.as_deref().unwrap_or("");
                                                    ui.monospace(format!(
                                                        "{}{} ○",
                                                        row.drawing,
                                                        mask_known_values(
                                                            &id[..id.len().min(10)],
                                                            known_values
                                                        )
                                                    ));
                                                }
                                            },
                                        );
                                        continue;
                                    }
                                }
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
                                    mask_known_values(&id[..id.len().min(10)], known_values),
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
                                        self.history_selected_commit = Some(commit.commit.clone());
                                    }
                                } else {
                                    ui.monospace(title);
                                }
                            }
                        });
                    if let Some(commit) = self.history_selected_commit.as_ref().and_then(|id| {
                        view.history
                            .commits
                            .iter()
                            .find(|commit| &commit.commit == id)
                    }) {
                        ui.label(format!(
                            "Observed findings at {}",
                            mask_known_values(&commit.commit, known_values)
                        ));
                        for local_index in &commit.finding_indices {
                            let index = view.finding_indices[*local_index];
                            let item = &self.findings[index];
                            let value = if item.secret == f.secret {
                                "current rewrite value"
                            } else {
                                "linked value"
                            };
                            let label = format!(
                                "{}:{} · {} · {value}",
                                mask_known_values(&item.file, known_values),
                                mask_known_values(&item.line, known_values),
                                mask_known_values(&item.rule, known_values)
                            );
                            if ui.add_enabled(!busy, egui::Button::new(label)).clicked() {
                                navigate = Some(index);
                            }
                        }
                    }
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
        if expand_history {
            self.history_limit = self.history_limit.saturating_add(500);
            self.load_history(related);
        }
        if let Some(index) = navigate {
            if self.findings[index].secret != f.secret {
                self.branches.clear();
                self.checked.clear();
            }
            self.selected = Some(index);
            self.revealed = None;
            self.file_preview = None;
            self.file_comparison = None;
            self.file_reveal = false;
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
        if self.branch_snapshot_stale {
            ui.colored_label(
                Color32::YELLOW,
                "Repository refs changed. Refresh affected branches before preparing a rewrite.",
            );
        }
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
    fn load_history(&mut self, related: &[usize]) {
        let repo = self.repo();
        let occurrences: Vec<Finding> = related.iter().map(|&i| self.findings[i].clone()).collect();
        let finding_indices = related.to_vec();
        let limit = self.history_limit;
        self.history_output = None;
        self.status = "Loading reported commit history…".into();
        self.task(move || {
            ResultMessage::History((|| {
                let placed = sherlock_git::secret_history(&repo, &occurrences, &[])?;
                let mut names = std::collections::BTreeSet::new();
                for commit in &placed.commits {
                    names.extend(sherlock_git::branches(&repo, &commit.commit)?);
                }
                let names: Vec<_> = names.into_iter().collect();
                let history = sherlock_git::secret_history(&repo, &occurrences, &names)?;
                let (lines, truncated) = sherlock_git::history_graph_page(&repo, &history, limit)?;
                Ok(HistoryView {
                    history,
                    lines,
                    truncated,
                    finding_indices,
                })
            })())
        });
    }
}
