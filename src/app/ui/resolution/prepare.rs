use super::*;

impl App {
    pub(super) fn render_rewrite_preparation(
        &mut self,
        ui: &mut egui::Ui,
        f: &Finding,
        busy: bool,
    ) {
        ui.separator();
        ui.label(RichText::new("PREPARE REDACTED HISTORY").small().weak());
        ui.label("New mirror path");
        ui.add_enabled(!busy, egui::TextEdit::singleline(&mut self.destination));
        ui.label(RichText::new("Creates new branches in a separate mirror. Original refs in that mirror remain sensitive. No push is performed. Exact-value and scanner checks run after rewriting; review their coverage and results.").small().weak());
        if ui
            .add_enabled(
                !busy && self.checked.iter().any(|x| *x) && !self.destination.is_empty(),
                egui::Button::new("Create redacted branches"),
            )
            .clicked()
        {
            let p = self.repo();
            let d = PathBuf::from(&self.destination);
            let refs: Vec<sherlock_git::RefSnapshot> = self
                .branches
                .iter()
                .zip(&self.checked)
                .filter(|(_, c)| **c)
                .map(|(b, _)| b.clone())
                .collect();
            let excluded_refs: Vec<String> = self
                .branches
                .iter()
                .zip(&self.checked)
                .filter(|(_, checked)| !**checked)
                .map(|(branch, _)| branch.name.clone())
                .collect();
            let has_unplaced_findings = self.findings.iter().any(|item| {
                !f.secret.is_empty() && item.secret == f.secret && item.commit.is_empty()
            });
            let occurrences: Vec<Finding> = self
                .findings
                .iter()
                .filter(|item| !f.secret.is_empty() && item.secret == f.secret)
                .cloned()
                .collect();
            let value = f.secret.clone();
            self.prepared = None;
            self.verification_output = None;
            self.exact_locations.clear();
            self.exact_location_error = None;
            self.scanner_output = None;
            self.scanner_findings.clear();
            self.scanner_used = None;
            self.completion_output = None;
            self.status = "Preparing redacted branches…".into();
            self.task(move || {
                ResultMessage::Rewrite((|| {
                    let status = sherlock_git::rewrite_related_at(&p, &d, &occurrences, &refs)?;
                    let names: Vec<String> = (1..=refs.len())
                        .map(|i| format!("refs/heads/sherlock/redacted-{i}"))
                        .collect();
                    let output_refs = sherlock_git::snapshot_refs(&d, &names).map_err(|e| {
                        format!(
                            "Rewrite finished in {}, but output refs could not be recorded: {e}",
                            d.display()
                        )
                    })?;
                    Ok((
                        PreparedRewrite {
                            source: p,
                            destination: d,
                            source_refs: refs.iter().map(|entry| entry.name.clone()).collect(),
                            excluded_refs,
                            has_unplaced_findings,
                            refs: output_refs,
                            value,
                        },
                        status,
                    ))
                })())
            });
        }
    }
}
