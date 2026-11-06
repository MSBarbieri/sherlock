use super::*;

pub(super) type LinkData = (Vec<Vec<usize>>, Vec<sherlock_reviews::links::LinkEdge>);
pub(super) fn load_link_data(
    store: &sherlock_reviews::links::LinkStore,
    repo: &std::path::Path,
    values: &[String],
) -> Result<LinkData, String> {
    let refs: Vec<&str> = values.iter().map(String::as_str).collect();
    Ok((store.groups(repo, &refs)?, store.edges(repo, &refs)?))
}
pub(super) enum ResultMessage {
    Rewrite(Result<(PreparedRewrite, String), String>),
    AutoChecks(
        Scanner,
        Result<(), String>,
        Result<String, String>,
        Result<(String, Vec<Finding>), String>,
    ),
    Verification(Result<String, String>),
    ExactLocations(Result<Vec<sherlock_git::ExactLocation>, String>),
    ScannerCheck(Scanner, Result<(String, Vec<Finding>), String>),
    Completion(Result<Option<sherlock_reviews::links::CompletionRecord>, String>),
    History(Result<String, String>),
    LinkGroups(Result<LinkData, String>),
    Scan(Result<Vec<Finding>, String>),
    Branches(Result<Vec<sherlock_git::RefSnapshot>, String>),
    Status(Result<String, String>),
}

impl App {
    pub(super) fn task(&mut self, f: impl FnOnce() -> ResultMessage + Send + 'static) {
        let (tx, rx) = mpsc::channel();
        self.receiver = Some(rx);
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
    }

    pub(super) fn poll_tasks(&mut self, ctx: &egui::Context) {
        if let Some(rx) = &self.receiver {
            match rx.try_recv() {
                Ok(message) => {
                    self.receiver = None;
                    match message {
                        ResultMessage::Scan(Ok(mut f)) => {
                            self.scan_stale =
                                self.automatic_scan_pending || self.monitor.error.is_some();
                            self.branches.clear();
                            self.checked.clear();
                            self.history_output = None;
                            self.prepared = None;
                            self.verification_output = None;
                            self.exact_locations.clear();
                            self.exact_location_error = None;
                            self.scanner_output = None;
                            self.scanner_findings.clear();
                            self.scanner_used = None;
                            self.completion_output = None;
                            let selected = self
                                .selected
                                .and_then(|index| self.findings.get(index))
                                .cloned();
                            self.status = match sherlock_reviews::ReviewStore::standard()
                                .and_then(|store| store.restore(&self.repo(), &mut f))
                            {
                                Ok(()) => format!("Scan complete · {} findings", f.len()),
                                Err(e) => format!(
                                    "Scan complete, but saved reviews could not be loaded: {e}"
                                ),
                            };
                            self.scan_completed = true;
                            let next_selected = selected.as_ref().and_then(|old| {
                                f.iter().position(|item| {
                                    item.commit == old.commit
                                        && item.file == old.file
                                        && item.line == old.line
                                        && item.secret == old.secret
                                })
                            });
                            if next_selected.is_none() {
                                self.branches.clear();
                                self.checked.clear();
                                self.revealed = None;
                                self.bulk_selected.clear();
                                self.bulk_confirm = false;
                                self.page = Page::Discovery;
                            }
                            self.findings = f;
                            self.linked_groups = group_by_secret(&self.findings);
                            self.link_candidate = None;
                            let repo = self.link_repo.clone().unwrap_or_else(|| self.repo());
                            self.link_repo = Some(repo.clone());
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
                            self.selected = next_selected;
                            // Batch selections contain indices and cannot survive a reordered scan.
                            self.bulk_selected.clear();
                            self.bulk_confirm = false;
                            self.revealed = None;
                        }
                        ResultMessage::Branches(Ok(b)) => {
                            self.status = format!("Found {} containing refs.", b.len());
                            self.checked = vec![true; b.len()];
                            self.branches = b;
                        }
                        ResultMessage::Rewrite(Ok((prepared, status))) => {
                            self.prepared = Some(prepared.clone());
                            self.status = format!("{status}\nChecking rewritten branches…");
                            let scanner = self.scanner;
                            self.task(move || {
                                let registration = sherlock_reviews::links::LinkStore::standard()
                                    .and_then(|store| {
                                        store.register_mirror(
                                            &prepared.source,
                                            &prepared.destination,
                                        )
                                    });
                                let exact = check_exact(&prepared);
                                let scanned = scan_prepared(&prepared, scanner);
                                ResultMessage::AutoChecks(scanner, registration, exact, scanned)
                            });
                        }
                        ResultMessage::ExactLocations(Ok(locations)) => {
                            self.exact_locations = locations;
                            self.exact_location_error = None;
                            self.status = format!(
                                "Located {} exact-value occurrence snapshot(s).",
                                self.exact_locations.len()
                            );
                        }
                        ResultMessage::ExactLocations(Err(error)) => {
                            self.exact_locations.clear();
                            self.exact_location_error = Some(error);
                            self.status = "Exact-value location search incomplete.".into();
                        }
                        ResultMessage::Verification(Ok(result)) => {
                            self.verification_output = Some(result);
                            self.status =
                                "Exact-value check complete. Review the results below.".into();
                        }
                        ResultMessage::Verification(Err(e)) => {
                            self.verification_output = Some(format!("Check incomplete: {e}"));
                            self.status = "Exact-value check failed.".into();
                        }
                        ResultMessage::AutoChecks(scanner, registration, exact, scanned) => {
                            self.verification_output = Some(match exact {
                                Ok(result) => result,
                                Err(e) => format!("Exact-value check incomplete: {e}"),
                            });
                            match scanned {
                                Ok((result, findings)) => {
                                    self.scanner_output = Some(result);
                                    self.scanner_used = Some(scanner);
                                    self.scanner_findings = findings;
                                }
                                Err(e) => {
                                    self.scanner_output =
                                        Some(format!("Scanner check incomplete: {e}"));
                                    self.scanner_findings.clear();
                                    self.scanner_used = None;
                                }
                            }
                            self.status = match registration {
                                Ok(()) => "Rewrite checks finished. Review each result and its coverage.".into(),
                                Err(error) => format!("Rewrite checks finished, but this mirror could not be linked to its original workspace: {error}. In this session links remain available; reopening the mirror may not restore them."),
                            };
                        }
                        ResultMessage::Completion(result) => {
                            self.completion_output = Some(match result {
                                Ok(Some(record)) => {
                                    let mut text = format!("Previously marked complete by a developer. This is historical and does not indicate current cleanliness or freshness.\nScanners: {}\n{}\n", record.scanners.join(", "), record.checks_summary);
                                    for tip in record.output_tips {
                                        text.push_str(&format!(
                                            "{} @ {}\n",
                                            tip.reference, tip.commit
                                        ));
                                    }
                                    text
                                }
                                Ok(None) => {
                                    "No previous completion record for this workspace.".into()
                                }
                                Err(e) => format!("Could not access completion record: {e}"),
                            });
                        }
                        ResultMessage::LinkGroups(Ok((groups, edges))) => {
                            self.linked_groups = groups;
                            self.saved_links = edges;
                            self.history_output = None;
                            self.completion_output = None;
                            self.status = "Secret links loaded.".into();
                        }
                        ResultMessage::LinkGroups(Err(e)) => {
                            self.status = format!("Could not load secret links: {e}");
                        }
                        ResultMessage::History(Ok(result)) => {
                            self.history_output = Some(result);
                            self.status = "Occurrence history ready.".into();
                        }
                        ResultMessage::History(Err(e)) => {
                            self.history_output = Some(format!("History incomplete: {e}"));
                            self.status = "Could not load occurrence history.".into();
                        }
                        ResultMessage::ScannerCheck(scanner, Ok((result, findings))) => {
                            self.scanner_findings = findings;
                            self.scanner_used = Some(scanner);
                            self.scanner_output = Some(result);
                            self.status =
                                "Scanner check complete. Review the results below.".into();
                        }
                        ResultMessage::ScannerCheck(_, Err(e)) => {
                            self.scanner_used = None;
                            self.scanner_output = Some(format!("Scanner check incomplete: {e}"));
                            self.status = "Scanner check failed.".into();
                        }
                        ResultMessage::Status(Ok(s)) => self.status = s,
                        ResultMessage::Scan(Err(e)) => {
                            self.scan_stale = true;
                            self.status = format!("History scan failed: {e}. Previous results remain visible and may be out of date.");
                        }
                        ResultMessage::Rewrite(Err(e))
                        | ResultMessage::Branches(Err(e))
                        | ResultMessage::Status(Err(e)) => self.status = format!("Error: {e}"),
                    }
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.receiver = None;
                    self.status = "Background operation stopped unexpectedly.".into();
                }
                Err(mpsc::TryRecvError::Empty) => {
                    ctx.request_repaint_after(std::time::Duration::from_millis(100))
                }
            }
        }
    }
}
