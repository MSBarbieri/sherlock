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
            self.task(move || ResultMessage::History((|| {
                        let names = sherlock_git::branches_for_findings(&repo, &occurrences)?;
                        let history = sherlock_git::secret_history(&repo, &occurrences, &names)?;
                        let mut variants: Vec<&str> = Vec::new();
                        for occurrence in &occurrences { if !variants.contains(&occurrence.secret.as_str()) { variants.push(&occurrence.secret); } }
                        let mut text = String::from("Scanner-reported commits across linked values (descendants before ancestors; moves and disappearances are not inferred):\n");
                        for commit in history.commits {
                            text.push_str(&format!("{}\n", commit.commit));
                            for i in commit.finding_indices {
                                let occurrence = &occurrences[i];
                                let variant = variants.iter().position(|v| *v == occurrence.secret).unwrap_or(0) + 1;
                                let mut location = format!("{}:{}", occurrence.file, occurrence.line);
                                for value in &variants { if !value.is_empty() { location = location.replace(value, "[MASKED]"); } }
                                text.push_str(&format!("  Value {variant} · {location}\n"));
                            }
                            for name in commit.containing_refs { text.push_str(&format!("  {name}\n")); }
                        }
                        if !history.unplaced.is_empty() { text.push_str(&format!("{} finding(s) could not be placed in history.\n", history.unplaced.len())); }
                        Ok(text)
                    })()));
        }
        if let Some(history) = &self.history_output {
            ui.label(mask_known_values(history, &known_values));
        }
        ui.add_space(8.0);
        ui.label(
            RichText::new("CONTAINING REFS FOR SELECTED VALUE")
                .small()
                .weak(),
        );
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
