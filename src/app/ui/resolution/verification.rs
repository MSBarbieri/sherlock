use super::*;

impl App {
    pub(super) fn render_rewrite_verification(
        &mut self,
        ui: &mut egui::Ui,
        f: &Finding,
        busy: bool,
        known_values: &[String],
    ) {
        if let Some(prepared) = self
            .prepared
            .clone()
            .filter(|prepared| prepared.source == self.repo() && prepared.value == f.secret)
        {
            ui.separator();
            ui.heading("Check rewritten history");
            ui.label(mask_known_values(
                &format!("Mirror: {}", prepared.destination.display()),
                &known_values,
            ));
            for (source, output) in prepared.source_refs.iter().zip(&prepared.refs) {
                ui.label(mask_known_values(
                    &format!("{source} → {}", output.name),
                    &known_values,
                ));
            }
            ui.label("Checks the exact detected value in file blobs at the recorded output tips, including binary files. Does not scan commit messages, LFS payloads, submodules, or other refs.");
            if ui
                .add_enabled(
                    !busy,
                    egui::Button::new("Check exact value in rewritten branches"),
                )
                .clicked()
            {
                let prepared = prepared.clone();
                self.status = "Checking rewritten history…".into();
                self.verification_output = None;
                self.exact_locations.clear();
                self.exact_location_error = None;
                self.task(move || ResultMessage::Verification(check_exact(&prepared)));
            }
            if let Some(result) = &self.verification_output {
                ui.separator();
                ui.label(mask_known_values(result, &known_values));
            }
            if ui
                .add_enabled(
                    !busy
                        && self
                            .verification_output
                            .as_ref()
                            .is_some_and(|result| result.contains("found in ")),
                    egui::Button::new("Locate exact matches in history"),
                )
                .clicked()
            {
                let prepared = prepared.clone();
                self.exact_locations.clear();
                self.exact_location_error = None;
                self.status = "Locating exact matches; large histories may take time…".into();
                self.task(move || {
                    ResultMessage::ExactLocations(sherlock_git::exact_history_locations(
                        &prepared.destination,
                        &prepared.refs,
                        &[prepared.value.as_bytes()],
                    ))
                });
            }
            if let Some(error) = &self.exact_location_error {
                ui.label(mask_known_values(
                    &format!("Location search incomplete: {error}"),
                    &known_values,
                ));
            }
            if !self.exact_locations.is_empty() {
                ui.label("Exact matches in reachable file snapshots (not inferred moves):");
                for location in &self.exact_locations {
                    let path = String::from_utf8_lossy(&location.path)
                        .replace(&prepared.value, "[MASKED]");
                    let lines = location
                        .matching_lines
                        .as_ref()
                        .map(|lines| {
                            format!(
                                "lines {}",
                                lines
                                    .iter()
                                    .map(usize::to_string)
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            )
                        })
                        .unwrap_or_else(|| "binary or non-UTF-8 content; line unavailable".into());
                    ui.label(mask_known_values(
                        &format!(
                            "{} · {} · {} · {}",
                            location.commit,
                            path,
                            lines,
                            location.containing_refs.join(", ")
                        ),
                        &known_values,
                    ));
                }
                ui.label(RichText::new("Binary blobs are detectable but are not rewritten by Sherlock. Non-UTF-8 paths are displayed approximately.").small().weak());
                if ui
                    .add_enabled(
                        !busy,
                        egui::Button::new("Review exact matches in the mirror →"),
                    )
                    .clicked()
                {
                    let mut findings = Vec::new();
                    for location in &self.exact_locations {
                        let utf8_path = std::str::from_utf8(&location.path).ok();
                        let file = utf8_path.unwrap_or("[non-UTF-8 path]").to_owned();
                        let lines: Vec<String> = if utf8_path.is_some() {
                            location
                                .matching_lines
                                .as_ref()
                                .map(|lines| lines.iter().map(usize::to_string).collect())
                                .unwrap_or_else(|| vec![String::new()])
                        } else {
                            vec![String::new()]
                        };
                        for line in lines {
                            findings.push(Finding {
                                scanner: "Exact-value check",
                                rule: if location.matching_lines.is_none() {
                                    "Exact value in binary or non-UTF-8 blob".into()
                                } else {
                                    "Exact value in file history".into()
                                },
                                file: file.clone(),
                                commit: location.commit.clone(),
                                line,
                                secret: prepared.value.clone(),
                                evidence: vec![],
                                review: Review::Unreviewed,
                            });
                        }
                    }
                    self.repo = prepared.destination.display().to_string();
                    self.destination = sherlock_git::suggested_destination(&prepared.destination)
                        .display()
                        .to_string();
                    self.findings = findings;
                    self.linked_groups = group_by_secret(&self.findings);
                    self.link_candidate = None;
                    self.selected = None;
                    self.branches.clear();
                    self.checked.clear();
                    self.history_output = None;
                    self.scan_completed = true;
                    self.page = Page::Discovery;
                    self.status = "Reviewing exact matches in the mirror. Binary blobs are not rewritten and original refs remain sensitive.".into();
                    let repo = self.link_repo.clone().unwrap_or_else(|| self.repo());
                    let values: Vec<String> = self
                        .findings
                        .iter()
                        .map(|finding| finding.secret.clone())
                        .collect();
                    self.task(move || {
                        ResultMessage::LinkGroups(
                            sherlock_reviews::links::LinkStore::standard()
                                .and_then(|store| load_link_data(&store, &repo, &values)),
                        )
                    });
                }
            }
            ui.separator();
            ui.add_enabled_ui(!busy, |ui| {
                egui::ComboBox::from_id_salt("verification_scanner")
                    .selected_text(self.scanner.label())
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.scanner, Scanner::Both, "Both scanners");
                        ui.selectable_value(&mut self.scanner, Scanner::Gitleaks, "Gitleaks");
                        ui.selectable_value(&mut self.scanner, Scanner::TruffleHog, "TruffleHog");
                    });
            });
            ui.label("Scanner coverage is limited; no findings does not guarantee that the history is clean.");
            if ui
                .add_enabled(!busy, egui::Button::new("Scan rewritten branches"))
                .clicked()
            {
                let prepared = prepared.clone();
                let scanner = self.scanner;
                self.scanner_output = None;
                self.scanner_findings.clear();
                self.status = "Scanning rewritten branches…".into();
                self.task(move || {
                    ResultMessage::ScannerCheck(scanner, scan_prepared(&prepared, scanner))
                });
            }
            if let Some(result) = &self.scanner_output {
                ui.separator();
                ui.label(mask_known_values(result, &known_values));
            }
            let exact_ok = self.verification_output.as_ref().is_some_and(|output| {
                output.starts_with("Exact-value check of reachable file blobs")
            });
            if ui
                .add_enabled(
                    !busy && exact_ok && self.scanner_used.is_some(),
                    egui::Button::new("Mark this workspace completed"),
                )
                .clicked()
            {
                let repo = self.link_repo.clone().unwrap_or_else(|| self.repo());
                let value = prepared.value.clone();
                let scanner = self.scanner_used.unwrap();
                let exact_summary = self.verification_output.clone().unwrap_or_default();
                let exact_matches = self
                    .scanner_findings
                    .iter()
                    .filter(|finding| finding.secret == value)
                    .count();
                let known_values: Vec<String> = self
                    .findings
                    .iter()
                    .chain(self.scanner_findings.iter())
                    .filter(|finding| !finding.secret.is_empty())
                    .map(|finding| finding.secret.clone())
                    .collect();
                let sanitize = |text: &str| {
                    let mut output = text.to_owned();
                    for value in &known_values {
                        output = output.replace(value, "[MASKED]");
                    }
                    output
                };
                let mapping = prepared
                    .source_refs
                    .iter()
                    .zip(&prepared.refs)
                    .map(|(source, output)| format!("{} → {}", sanitize(source), output.name))
                    .collect::<Vec<_>>()
                    .join(", ");
                let excluded = prepared
                    .excluded_refs
                    .iter()
                    .map(|name| sanitize(name))
                    .collect::<Vec<_>>()
                    .join(", ");
                let record = sherlock_reviews::links::CompletionRecord {
                            output_tips: prepared.refs.iter().map(|entry| sherlock_reviews::links::CompletionTip { reference: entry.name.clone(), commit: entry.tip.clone() }).collect(),
                            scanners: vec![scanner.label().into()],
                            checks_summary: format!("Mirror: {}\nSource to output: {mapping}\nExcluded known refs: {}\nUnplaced findings: {}\n{}Scanner: {} distinct finding(s), {exact_matches} with the selected exact value. Only this value received the exact check; linked variants were not covered. Scanner coverage is limited.", sanitize(&prepared.destination.display().to_string()), if excluded.is_empty() { "none" } else { &excluded }, if prepared.has_unplaced_findings { "yes" } else { "none known" }, sanitize(&exact_summary), self.scanner_findings.len()),
                        };
                self.completion_output = None;
                self.task(move || {
                    ResultMessage::Completion(
                        sherlock_reviews::links::LinkStore::standard().and_then(|store| {
                            store.set_completion(&repo, &value, Some(&record))?;
                            store.previously_completed(&repo, &value)
                        }),
                    )
                });
            }
            ui.label(RichText::new("Completion is a developer decision for these output tips. The exact check covers only the selected value, not other linked variants. It does not assert current or global cleanliness.").small().weak());
            if !self.scanner_findings.is_empty() {
                ui.label("Continue with the scanner findings in the new mirror. Its original refs are still sensitive; select branches carefully.");
                if ui
                    .add_enabled(!busy, egui::Button::new("Review findings in the mirror →"))
                    .clicked()
                {
                    self.repo = prepared.destination.display().to_string();
                    self.destination = sherlock_git::suggested_destination(&prepared.destination)
                        .display()
                        .to_string();
                    self.findings = std::mem::take(&mut self.scanner_findings);
                    self.linked_groups = group_by_secret(&self.findings);
                    self.link_candidate = None;
                    self.selected = None;
                    self.branches.clear();
                    self.checked.clear();
                    self.history_output = None;
                    self.scan_completed = true;
                    self.page = Page::Discovery;
                    self.status = "Reviewing scanner findings from the rewritten branches. Original refs in this mirror remain sensitive.".into();
                    let repo = self.link_repo.clone().unwrap_or_else(|| self.repo());
                    let values: Vec<String> = self
                        .findings
                        .iter()
                        .map(|finding| finding.secret.clone())
                        .collect();
                    self.task(move || {
                        ResultMessage::LinkGroups(
                            sherlock_reviews::links::LinkStore::standard()
                                .and_then(|store| load_link_data(&store, &repo, &values)),
                        )
                    });
                }
            }
        }
    }
}
