use eframe::egui::{self, Color32, RichText};
use sherlock_domain::{group_by_secret, Finding, Review};
use sherlock_scan::Scanner;
use std::{
    path::PathBuf,
    sync::mpsc::{self, Receiver},
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReviewFilter {
    All,
    Potential,
    FalsePositive,
    AcceptedRisk,
}

impl ReviewFilter {
    fn matches(self, review: &Review) -> bool {
        match self {
            Self::All => true,
            Self::Potential => *review == Review::Unreviewed,
            Self::FalsePositive => *review == Review::FalsePositive,
            Self::AcceptedRisk => *review == Review::AcceptedRisk,
        }
    }
}

#[cfg(test)]
fn mask_detected_value(text: &str, value: &str) -> String {
    if value.is_empty() {
        text.to_owned()
    } else {
        text.replace(value, "[MASKED]")
    }
}

fn mask_known_values(text: &str, values: &[String]) -> String {
    values
        .iter()
        .filter(|value| !value.is_empty())
        .fold(text.to_owned(), |masked, value| {
            masked.replace(value, "[MASKED]")
        })
}

fn workspace_finding_matches(
    finding: &Finding,
    values: &[String],
    filter: ReviewFilter,
    search: &str,
) -> bool {
    let query = search.trim().to_lowercase();
    filter.matches(&finding.review)
        && (query.is_empty()
            || [&finding.rule, &finding.file, &finding.commit, &finding.line]
                .iter()
                .any(|value| {
                    mask_known_values(value, values)
                        .to_lowercase()
                        .contains(&query)
                })
            || mask_known_values(finding.scanner, values)
                .to_lowercase()
                .contains(&query)
            || finding.evidence.iter().any(|report| {
                [report.scanner, report.rule.as_str()].iter().any(|value| {
                    mask_known_values(value, values)
                        .to_lowercase()
                        .contains(&query)
                })
            }))
}

#[cfg(test)]
fn finding_matches(finding: &Finding, filter: ReviewFilter, search: &str) -> bool {
    workspace_finding_matches(finding, &[finding.secret.clone()], filter, search)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Discovery,
    Resolution,
}

#[derive(Clone)]
struct PreparedRewrite {
    source: PathBuf,
    destination: PathBuf,
    source_refs: Vec<String>,
    excluded_refs: Vec<String>,
    has_unplaced_findings: bool,
    refs: Vec<sherlock_git::RefSnapshot>,
    value: String,
}

fn check_exact(prepared: &PreparedRewrite) -> Result<String, String> {
    let results = sherlock_git::verify_exact_values(
        &prepared.destination,
        &prepared.refs,
        &[prepared.value.as_bytes()],
    )?;
    let mut output =
        String::from("Exact-value check of reachable file blobs (not a scanner or a guarantee):\n");
    for result in results {
        let outcome = if result.matching_blobs.is_empty() {
            "not found".to_owned()
        } else {
            format!("found in {} blob(s)", result.matching_blobs.len())
        };
        output.push_str(&format!(
            "{} @ {}: {} commits checked; {}\n",
            result.name, result.tip, result.commits_checked, outcome
        ));
    }
    Ok(output)
}

fn scan_prepared(
    prepared: &PreparedRewrite,
    scanner: Scanner,
) -> Result<(String, Vec<Finding>), String> {
    let mut output = format!(
        "{} results (scanner coverage is limited):\n",
        scanner.label()
    );
    let mut findings = Vec::new();
    for entry in &prepared.refs {
        let branch = entry
            .name
            .strip_prefix("refs/heads/")
            .ok_or("Invalid output branch name")?;
        let report = sherlock_scan::scan_branch(&prepared.destination, branch, scanner)?;
        if report.tip != entry.tip {
            return Err(format!(
                "{} changed since rewrite; its scan results do not describe the recorded output.",
                entry.name
            ));
        }
        let exact = report
            .findings
            .iter()
            .filter(|finding| finding.secret == prepared.value)
            .count();
        output.push_str(&format!(
            "{} @ {}: {} finding(s), {} with the same exact value\n",
            entry.name,
            entry.tip,
            report.findings.len(),
            exact
        ));
        for finding in &report.findings {
            let clean = |text: &str| {
                let masked = if prepared.value.is_empty() {
                    text.to_owned()
                } else {
                    text.replace(&prepared.value, "[MASKED]")
                };
                if finding.secret.is_empty() {
                    masked
                } else {
                    masked.replace(&finding.secret, "[MASKED]")
                }
            };
            output.push_str(&format!(
                "  {} · {} · {}:{} · commit {}{}\n",
                clean(finding.scanner),
                clean(&finding.rule),
                clean(&finding.file),
                clean(&finding.line),
                clean(&finding.commit),
                if finding.secret == prepared.value {
                    " · same value"
                } else {
                    ""
                }
            ));
        }
        sherlock_domain::merge_findings(&mut findings, report.findings);
    }
    Ok((output, findings))
}

type LinkData = (Vec<Vec<usize>>, Vec<sherlock_reviews::links::LinkEdge>);
fn load_link_data(
    store: &sherlock_reviews::links::LinkStore,
    repo: &std::path::Path,
    values: &[String],
) -> Result<LinkData, String> {
    let refs: Vec<&str> = values.iter().map(String::as_str).collect();
    Ok((store.groups(repo, &refs)?, store.edges(repo, &refs)?))
}
enum ResultMessage {
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
pub struct App {
    page: Page,
    prepared: Option<PreparedRewrite>,
    verification_output: Option<String>,
    exact_locations: Vec<sherlock_git::ExactLocation>,
    exact_location_error: Option<String>,
    scanner_output: Option<String>,
    scanner_used: Option<Scanner>,
    completion_output: Option<String>,
    scanner_findings: Vec<Finding>,
    history_output: Option<String>,
    linked_groups: Vec<Vec<usize>>,
    saved_links: Vec<sherlock_reviews::links::LinkEdge>,
    link_candidate: Option<usize>,
    link_repo: Option<PathBuf>,
    repo: String,
    scanner: Scanner,
    findings: Vec<Finding>,
    selected: Option<usize>,
    revealed: Option<usize>,
    bulk_selected: std::collections::BTreeSet<usize>,
    bulk_review: Review,
    bulk_confirm: bool,
    branches: Vec<sherlock_git::RefSnapshot>,
    checked: Vec<bool>,
    status: String,
    receiver: Option<Receiver<ResultMessage>>,
    destination: String,
    scan_completed: bool,
    filter: ReviewFilter,
    search: String,
}
impl Default for App {
    fn default() -> Self {
        Self {
            page: Page::Discovery,
            prepared: None,
            verification_output: None,
            exact_locations: Vec::new(),
            exact_location_error: None,
            scanner_output: None,
            scanner_used: None,
            completion_output: None,
            scanner_findings: Vec::new(),
            history_output: None,
            linked_groups: Vec::new(),
            saved_links: Vec::new(),
            link_candidate: None,
            link_repo: None,
            repo: String::new(),
            scanner: Scanner::Both,
            findings: vec![],
            selected: None,
            revealed: None,
            bulk_selected: Default::default(),
            bulk_review: Review::FalsePositive,
            bulk_confirm: false,
            branches: vec![],
            checked: vec![],
            status: "Choose a repository to begin.".into(),
            receiver: None,
            destination: String::new(),
            scan_completed: false,
            filter: ReviewFilter::All,
            search: String::new(),
        }
    }
}
impl App {
    fn task(&mut self, f: impl FnOnce() -> ResultMessage + Send + 'static) {
        let (tx, rx) = mpsc::channel();
        self.receiver = Some(rx);
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
    }
    fn repo(&self) -> PathBuf {
        PathBuf::from(&self.repo)
    }
}
impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        if let Some(rx) = &self.receiver {
            match rx.try_recv() {
                Ok(message) => {
                    self.receiver = None;
                    match message {
                        ResultMessage::Scan(Ok(mut f)) => {
                            self.status = match sherlock_reviews::ReviewStore::standard()
                                .and_then(|store| store.restore(&self.repo(), &mut f))
                            {
                                Ok(()) => format!("Scan complete · {} findings", f.len()),
                                Err(e) => format!(
                                    "Scan complete, but saved reviews could not be loaded: {e}"
                                ),
                            };
                            self.scan_completed = true;
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
                            self.selected = None;
                            self.branches.clear();
                            self.checked.clear();
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
                        ResultMessage::Rewrite(Err(e))
                        | ResultMessage::Scan(Err(e))
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
        let busy = self.receiver.is_some();
        let mut known_values: Vec<String> = self
            .findings
            .iter()
            .chain(self.scanner_findings.iter())
            .map(|finding| finding.secret.clone())
            .filter(|value| !value.is_empty())
            .collect();
        known_values.sort_unstable_by_key(|value| std::cmp::Reverse(value.len()));
        known_values.dedup();
        if self.revealed != self.selected {
            self.revealed = None;
        }
        if self.selected.is_none() {
            self.bulk_selected.clear();
            self.bulk_confirm = false;
        }
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.heading(RichText::new("◈  SHERLOCK").color(Color32::from_rgb(160, 143, 255)));
                ui.label(RichText::new("  /  repository security").weak());
                ui.separator();
                ui.label(if self.repo.is_empty() {
                    "No repository selected".to_owned()
                } else {
                    mask_known_values(&self.repo, &known_values)
                });
            });
            ui.add_space(8.0);
        });
        egui::TopBottomPanel::bottom("status")
            .resizable(true)
            .default_height(42.0)
            .show(ctx, |ui| {
                ui.label(if busy {
                    "●  Working…"
                } else {
                    "●  Activity"
                });
                ui.label(mask_known_values(&self.status, &known_values));
            });
        egui::SidePanel::left("navigation_rail")
            .exact_width(66.0)
            .resizable(false)
            .show(ctx, |ui| {
                ui.add_space(12.0);
                ui.vertical_centered(|ui| {
                    if ui
                        .selectable_label(self.page == Page::Discovery, "⌂\nScan")
                        .on_hover_text("Repository and scan")
                        .clicked()
                    {
                        self.page = Page::Discovery;
                    }
                    ui.add_space(8.0);
                    if ui
                        .add_enabled(
                            self.selected.is_some(),
                            egui::Button::new("◈\nReview").selected(self.page == Page::Resolution),
                        )
                        .on_hover_text("Secret workspace")
                        .clicked()
                    {
                        self.page = Page::Resolution;
                    }
                });
            });
        if self.page == Page::Discovery {
            egui::SidePanel::left("sidebar")
                .resizable(true)
                .default_width(260.0)
                .show(ctx, |ui| {
                    ui.add_space(12.0);
                    ui.heading("Workspace");
                    ui.add_space(8.0);
                    ui.label("Repository");
                    if ui
                        .add_enabled(
                            !busy,
                            egui::TextEdit::singleline(&mut self.repo)
                                .hint_text("Select a local repository"),
                        )
                        .changed()
                    {
                        self.scan_completed = false;
                        self.link_repo = None;
                        self.saved_links.clear();
                        self.findings.clear();
                        self.selected = None;
                        self.branches.clear();
                        self.checked.clear();
                        self.destination = sherlock_git::suggested_destination(&self.repo())
                            .display()
                            .to_string();
                    }
                    if ui
                        .add_enabled(!busy, egui::Button::new("Choose folder…"))
                        .clicked()
                    {
                        if let Some(p) = rfd::FileDialog::new().pick_folder() {
                            self.scan_completed = false;
                            self.link_repo = None;
                            self.saved_links.clear();
                            self.repo = p.display().to_string();
                            self.destination = sherlock_git::suggested_destination(&p)
                                .display()
                                .to_string();
                            self.findings.clear();
                            self.selected = None;
                            self.branches.clear();
                            self.checked.clear();
                        }
                    }
                    ui.separator();
                    ui.label("Scanner");
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
                    if ui
                        .add_enabled(
                            !busy && !self.repo.is_empty(),
                            egui::Button::new("▶  Scan repository"),
                        )
                        .clicked()
                    {
                        let p = self.repo();
                        let s = self.scanner;
                        self.status = format!("Scanning with {}…", s.label());
                        self.scan_completed = false;
                        self.findings.clear();
                        self.selected = None;
                        self.branches.clear();
                        self.checked.clear();
                        self.task(move || ResultMessage::Scan(sherlock_scan::scan(&p, s)));
                    }
                    ui.add_space(8.0);
                    if ui
                        .add_enabled(
                            !busy && !self.repo.is_empty(),
                            egui::Button::new("↻  Fetch all remotes"),
                        )
                        .clicked()
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
        let mut select_related = None;
        if self.page == Page::Resolution {
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
        if self.page == Page::Resolution {
            egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(12.0); ui.heading("Secret resolution"); ui.separator();
            egui::ScrollArea::vertical().id_salt("detail_content").show(ui, |ui| {
            if let Some(index) = self.selected { let f = self.findings[index].clone();
                ui.label(RichText::new(mask_known_values(&f.rule, &known_values)).strong().color(Color32::from_rgb(197, 184, 255))); ui.label(format!("{} · line {}", mask_known_values(&f.file, &known_values), mask_known_values(&f.line, &known_values))); ui.label(format!("Commit  {}", mask_known_values(&f.commit, &known_values)));
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
                self.bulk_selected.retain(|selected| related.contains(selected));
                ui.separator();
                ui.label(RichText::new("RELATED FINDINGS").small().weak());
                if f.secret.is_empty() {
                    ui.label("No usable value was reported; this finding is kept separate.");
                } else {
                    ui.label(format!("{} finding(s) in this scan", related.len()));
                    ui.label(RichText::new("Exact values are grouped automatically; linked variants are distinct. Classification and redaction apply to each selected finding or value.").small().weak());
                }
                    egui::ScrollArea::vertical().id_salt("related_findings").max_height(180.0).show(ui, |ui| {
                        for related_index in related.iter().copied() {
                            let item = &self.findings[related_index];
                            let mut values: Vec<&str> = Vec::new();
                            for &i in &related { let value = self.findings[i].secret.as_str(); if !value.is_empty() && !values.contains(&value) { values.push(value); } }
                            let value_label = values.iter().position(|value| *value == item.secret).map(|position| format!("Value {} · ", position + 1)).unwrap_or_default();
                            let location = format!("{}{}:{} · {} · {}", value_label, if item.file.is_empty() { "Unknown file".into() } else { mask_known_values(&item.file, &known_values) }, if item.line.is_empty() { "?".into() } else { mask_known_values(&item.line, &known_values) }, if item.commit.is_empty() { "Unknown commit".to_owned() } else { mask_known_values(&item.commit, &known_values).chars().take(10).collect() }, item.review.label());
                            ui.horizontal(|ui| {
                                let mut checked = self.bulk_selected.contains(&related_index);
                                if ui.add_enabled(!busy, egui::Checkbox::new(&mut checked, "")).on_hover_text("Select finding for bulk review").changed() {
                                    if checked { self.bulk_selected.insert(related_index); } else { self.bulk_selected.remove(&related_index); }
                                    self.bulk_confirm = false;
                                }
                                if ui.add_enabled(!busy, egui::Button::new(location).selected(related_index == index)).clicked() {
                                    select_related = Some(related_index);
                                }
                            });
                        }
                    });
                if !self.bulk_selected.is_empty() {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(format!("{} selected", self.bulk_selected.len()));
                        let before = self.bulk_review.clone();
                        egui::ComboBox::from_id_salt("bulk_review").selected_text(self.bulk_review.label()).show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.bulk_review, Review::Unreviewed, "Potential secret");
                            ui.selectable_value(&mut self.bulk_review, Review::FalsePositive, "False positive");
                            ui.selectable_value(&mut self.bulk_review, Review::AcceptedRisk, "Accepted risk");
                        });
                        if before != self.bulk_review { self.bulk_confirm = false; }
                        if ui.add_enabled(!busy, egui::Button::new("Review selection…")).clicked() { self.bulk_confirm = true; }
                    });
                    if self.bulk_confirm {
                        ui.label(format!("Apply '{}' to {} selected findings? Findings without complete identity will be skipped.", self.bulk_review.label(), self.bulk_selected.len()));
                        ui.horizontal(|ui| {
                            if ui.add_enabled(!busy, egui::Button::new("Confirm review")).clicked() {
                                let selected: Vec<usize> = self.bulk_selected.iter().copied().collect();
                                let updates: Vec<Finding> = selected.iter().map(|&i| { let mut finding = self.findings[i].clone(); finding.review = self.bulk_review.clone(); finding }).collect();
                                match sherlock_reviews::ReviewStore::standard().and_then(|store| store.save_many(&self.repo(), &updates)) {
                                    Ok(result) => {
                                        for saved in &result.saved { self.findings[selected[*saved]].review = self.bulk_review.clone(); }
                                        let failure = result.rejected.iter().map(|(i, reason)| {
                                            let finding = &self.findings[selected[*i]];
                                            format!("{}:{}: {}", mask_known_values(&finding.file, &known_values), mask_known_values(&finding.line, &known_values), reason)
                                        }).collect::<Vec<_>>().join("; ");
                                        self.status = format!("Saved {} review(s); {} skipped. {}", result.saved.len(), result.rejected.len(), failure);
                                    }
                                    Err(error) => self.status = format!("No reviews saved: {error}"),
                                }
                                self.bulk_confirm = false;
                            }
                            if ui.button("Cancel").clicked() { self.bulk_confirm = false; }
                        });
                    }
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
                if ui.add_enabled(!busy, egui::Button::new("Find branches for this value")).clicked() { let p = self.repo(); let occurrences: Vec<Finding> = self.findings.iter().filter(|item| !f.secret.is_empty() && item.secret == f.secret).cloned().collect(); self.branches.clear(); self.checked.clear(); self.history_output = None; self.status = "Checking local and remote-tracking refs…".into(); self.task(move || ResultMessage::Branches(sherlock_git::branches_for_findings(&p, &occurrences).and_then(|refs| sherlock_git::snapshot_refs(&p, &refs)))); }
                if ui.add_enabled(!busy && !f.secret.is_empty(), egui::Button::new("Show related commit history")).clicked() {
                    let repo = self.repo();
                    let occurrences: Vec<Finding> = related.iter().map(|&i| self.findings[i].clone()).collect();
                    self.history_output = None; self.status = "Loading reported commit history…".into();
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
                if let Some(history) = &self.history_output { ui.label(mask_known_values(history, &known_values)); }
                ui.add_space(8.0); ui.label(RichText::new("CONTAINING REFS FOR SELECTED VALUE").small().weak());
                egui::ScrollArea::vertical().max_height(150.0).show(ui, |ui| { for (i, branch) in self.branches.iter().enumerate() { ui.add_enabled(!busy, egui::Checkbox::new(&mut self.checked[i], mask_known_values(&branch.name, &known_values))); } });
                if !self.branches.is_empty() {
                    let selected_count = self.checked.iter().filter(|checked| **checked).count();
                    let excluded_count = self.branches.len() - selected_count;
                    ui.label(format!("{selected_count} selected · {excluded_count} excluded"));
                    if excluded_count > 0 {
                        ui.label(RichText::new("Excluded refs will not get redacted branches and may still contain this value.").color(Color32::YELLOW));
                    }
                    if self.findings.iter().any(|item| !f.secret.is_empty() && item.secret == f.secret && item.commit.is_empty()) {
                        ui.label(RichText::new("Some findings have no commit, so their affected branches could not be identified.").color(Color32::YELLOW));
                    }
                }
                ui.separator(); ui.label(RichText::new("PREPARE REDACTED HISTORY").small().weak()); ui.label("New mirror path"); ui.add_enabled(!busy, egui::TextEdit::singleline(&mut self.destination));
                ui.label(RichText::new("Creates new branches in a separate mirror. Original refs in that mirror remain sensitive. No push is performed. Exact-value and scanner checks run after rewriting; review their coverage and results.").small().weak());
                if ui.add_enabled(!busy && self.checked.iter().any(|x| *x) && !self.destination.is_empty(), egui::Button::new("Create redacted branches")).clicked() {
                    let p = self.repo(); let d = PathBuf::from(&self.destination); let refs: Vec<sherlock_git::RefSnapshot> = self.branches.iter().zip(&self.checked).filter(|(_, c)| **c).map(|(b,_)| b.clone()).collect(); let excluded_refs: Vec<String> = self.branches.iter().zip(&self.checked).filter(|(_, checked)| !**checked).map(|(branch, _)| branch.name.clone()).collect(); let has_unplaced_findings = self.findings.iter().any(|item| !f.secret.is_empty() && item.secret == f.secret && item.commit.is_empty()); let occurrences: Vec<Finding> = self.findings.iter().filter(|item| !f.secret.is_empty() && item.secret == f.secret).cloned().collect(); let value = f.secret.clone(); self.prepared = None; self.verification_output = None; self.exact_locations.clear(); self.exact_location_error = None; self.scanner_output = None; self.scanner_findings.clear(); self.scanner_used = None; self.completion_output = None; self.status = "Preparing redacted branches…".into(); self.task(move || ResultMessage::Rewrite((|| { let status = sherlock_git::rewrite_related_at(&p, &d, &occurrences, &refs)?; let names: Vec<String> = (1..=refs.len()).map(|i| format!("refs/heads/sherlock/redacted-{i}")).collect(); let output_refs = sherlock_git::snapshot_refs(&d, &names).map_err(|e| format!("Rewrite finished in {}, but output refs could not be recorded: {e}", d.display()))?; Ok((PreparedRewrite { source: p, destination: d, source_refs: refs.iter().map(|entry| entry.name.clone()).collect(), excluded_refs, has_unplaced_findings, refs: output_refs, value }, status)) })()));
                }
                if let Some(prepared) = self.prepared.clone().filter(|prepared| prepared.source == self.repo() && prepared.value == f.secret) {
                    ui.separator();
                    ui.heading("Check rewritten history");
                    ui.label(mask_known_values(&format!("Mirror: {}", prepared.destination.display()), &known_values));
                    for (source, output) in prepared.source_refs.iter().zip(&prepared.refs) {
                        ui.label(mask_known_values(&format!("{source} → {}", output.name), &known_values));
                    }
                    ui.label("Checks the exact detected value in file blobs at the recorded output tips, including binary files. Does not scan commit messages, LFS payloads, submodules, or other refs.");
                    if ui.add_enabled(!busy, egui::Button::new("Check exact value in rewritten branches")).clicked() {
                        let prepared = prepared.clone();
                        self.status = "Checking rewritten history…".into(); self.verification_output = None; self.exact_locations.clear(); self.exact_location_error = None;
                        self.task(move || ResultMessage::Verification(check_exact(&prepared)));
                    }
                    if let Some(result) = &self.verification_output { ui.separator(); ui.label(mask_known_values(result, &known_values)); }
                    if ui.add_enabled(!busy && self.verification_output.as_ref().is_some_and(|result| result.contains("found in ")), egui::Button::new("Locate exact matches in history")).clicked() {
                        let prepared = prepared.clone(); self.exact_locations.clear(); self.exact_location_error = None;
                        self.status = "Locating exact matches; large histories may take time…".into();
                        self.task(move || ResultMessage::ExactLocations(sherlock_git::exact_history_locations(&prepared.destination, &prepared.refs, &[prepared.value.as_bytes()])));
                    }
                    if let Some(error) = &self.exact_location_error { ui.label(mask_known_values(&format!("Location search incomplete: {error}"), &known_values)); }
                    if !self.exact_locations.is_empty() {
                        ui.label("Exact matches in reachable file snapshots (not inferred moves):");
                        for location in &self.exact_locations {
                            let path = String::from_utf8_lossy(&location.path).replace(&prepared.value, "[MASKED]");
                            let lines = location.matching_lines.as_ref().map(|lines| format!("lines {}", lines.iter().map(usize::to_string).collect::<Vec<_>>().join(", "))).unwrap_or_else(|| "binary or non-UTF-8 content; line unavailable".into());
                            ui.label(mask_known_values(&format!("{} · {} · {} · {}", location.commit, path, lines, location.containing_refs.join(", ")), &known_values));
                        }
                        ui.label(RichText::new("Binary blobs are detectable but are not rewritten by Sherlock. Non-UTF-8 paths are displayed approximately.").small().weak());
                        if ui.add_enabled(!busy, egui::Button::new("Review exact matches in the mirror →")).clicked() {
                            let mut findings = Vec::new();
                            for location in &self.exact_locations {
                                let utf8_path = std::str::from_utf8(&location.path).ok();
                                let file = utf8_path.unwrap_or("[non-UTF-8 path]").to_owned();
                                let lines: Vec<String> = if utf8_path.is_some() { location.matching_lines.as_ref().map(|lines| lines.iter().map(usize::to_string).collect()).unwrap_or_else(|| vec![String::new()]) } else { vec![String::new()] };
                                for line in lines { findings.push(Finding { scanner: "Exact-value check", rule: if location.matching_lines.is_none() { "Exact value in binary or non-UTF-8 blob".into() } else { "Exact value in file history".into() }, file: file.clone(), commit: location.commit.clone(), line, secret: prepared.value.clone(), evidence: vec![], review: Review::Unreviewed }); }
                            }
                            self.repo = prepared.destination.display().to_string();
                            self.destination = sherlock_git::suggested_destination(&prepared.destination).display().to_string();
                            self.findings = findings; self.linked_groups = group_by_secret(&self.findings); self.link_candidate = None;
                            self.selected = None; self.branches.clear(); self.checked.clear(); self.history_output = None;
                            self.scan_completed = true; self.page = Page::Discovery;
                            self.status = "Reviewing exact matches in the mirror. Binary blobs are not rewritten and original refs remain sensitive.".into();
                            let repo = self.link_repo.clone().unwrap_or_else(|| self.repo()); let values: Vec<String> = self.findings.iter().map(|finding| finding.secret.clone()).collect();
                            self.task(move || ResultMessage::LinkGroups(sherlock_reviews::links::LinkStore::standard().and_then(|store| load_link_data(&store, &repo, &values))));
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
                    if ui.add_enabled(!busy, egui::Button::new("Scan rewritten branches")).clicked() {
                        let prepared = prepared.clone(); let scanner = self.scanner;
                        self.scanner_output = None; self.scanner_findings.clear(); self.status = "Scanning rewritten branches…".into();
                        self.task(move || ResultMessage::ScannerCheck(scanner, scan_prepared(&prepared, scanner)));
                    }
                    if let Some(result) = &self.scanner_output { ui.separator(); ui.label(mask_known_values(result, &known_values)); }
                    let exact_ok = self.verification_output.as_ref().is_some_and(|output| output.starts_with("Exact-value check of reachable file blobs"));
                    if ui.add_enabled(!busy && exact_ok && self.scanner_used.is_some(), egui::Button::new("Mark this workspace completed")).clicked() {
                        let repo = self.link_repo.clone().unwrap_or_else(|| self.repo()); let value = prepared.value.clone();
                        let scanner = self.scanner_used.unwrap();
                        let exact_summary = self.verification_output.clone().unwrap_or_default();
                        let exact_matches = self.scanner_findings.iter().filter(|finding| finding.secret == value).count();
                        let known_values: Vec<String> = self.findings.iter().chain(self.scanner_findings.iter()).filter(|finding| !finding.secret.is_empty()).map(|finding| finding.secret.clone()).collect();
                        let sanitize = |text: &str| { let mut output = text.to_owned(); for value in &known_values { output = output.replace(value, "[MASKED]"); } output };
                        let mapping = prepared.source_refs.iter().zip(&prepared.refs).map(|(source, output)| format!("{} → {}", sanitize(source), output.name)).collect::<Vec<_>>().join(", ");
                        let excluded = prepared.excluded_refs.iter().map(|name| sanitize(name)).collect::<Vec<_>>().join(", ");
                        let record = sherlock_reviews::links::CompletionRecord {
                            output_tips: prepared.refs.iter().map(|entry| sherlock_reviews::links::CompletionTip { reference: entry.name.clone(), commit: entry.tip.clone() }).collect(),
                            scanners: vec![scanner.label().into()],
                            checks_summary: format!("Mirror: {}\nSource to output: {mapping}\nExcluded known refs: {}\nUnplaced findings: {}\n{}Scanner: {} distinct finding(s), {exact_matches} with the selected exact value. Only this value received the exact check; linked variants were not covered. Scanner coverage is limited.", sanitize(&prepared.destination.display().to_string()), if excluded.is_empty() { "none" } else { &excluded }, if prepared.has_unplaced_findings { "yes" } else { "none known" }, sanitize(&exact_summary), self.scanner_findings.len()),
                        };
                        self.completion_output = None;
                        self.task(move || ResultMessage::Completion(sherlock_reviews::links::LinkStore::standard().and_then(|store| { store.set_completion(&repo, &value, Some(&record))?; store.previously_completed(&repo, &value) })));
                    }
                    ui.label(RichText::new("Completion is a developer decision for these output tips. The exact check covers only the selected value, not other linked variants. It does not assert current or global cleanliness.").small().weak());
                    if !self.scanner_findings.is_empty() {
                        ui.label("Continue with the scanner findings in the new mirror. Its original refs are still sensitive; select branches carefully.");
                        if ui.add_enabled(!busy, egui::Button::new("Review findings in the mirror →")).clicked() {
                            self.repo = prepared.destination.display().to_string();
                            self.destination = sherlock_git::suggested_destination(&prepared.destination).display().to_string();
                            self.findings = std::mem::take(&mut self.scanner_findings);
                            self.linked_groups = group_by_secret(&self.findings); self.link_candidate = None;
                            self.selected = None; self.branches.clear(); self.checked.clear(); self.history_output = None;
                            self.scan_completed = true; self.page = Page::Discovery;
                            self.status = "Reviewing scanner findings from the rewritten branches. Original refs in this mirror remain sensitive.".into();
                            let repo = self.link_repo.clone().unwrap_or_else(|| self.repo());
                            let values: Vec<String> = self.findings.iter().map(|finding| finding.secret.clone()).collect();
                            self.task(move || ResultMessage::LinkGroups(sherlock_reviews::links::LinkStore::standard().and_then(|store| {
                                load_link_data(&store, &repo, &values)
                            })));
                        }
                    }
                }
            } else { ui.label(RichText::new("Select a finding to inspect its commit and affected branches.").weak()); }
            });
        });
        }
        if let Some(index) = select_related {
            self.revealed = None;
            self.history_output = None;
            self.completion_output = None;
            self.selected = Some(index);
            self.branches.clear();
            self.checked.clear();
        }
        if self.page == Page::Discovery {
            egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(12.0);
            ui.horizontal(|ui| {
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
                            ui.heading("Start with a repository");
                            ui.label("Choose a local repository, select a scanner, and run a scan.");
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

#[cfg(test)]
mod tests {
    use super::*;
    use sherlock_domain::ScannerReport;

    #[test]
    fn finding_search_respects_classification_and_excludes_secret_values() {
        let mut finding = Finding {
            scanner: "Gitleaks",
            rule: "Example rule".into(),
            file: "config/settings.env".into(),
            commit: "abc123def".into(),
            line: "7".into(),
            secret: "synthetic-secret-value".into(),
            evidence: vec![ScannerReport {
                scanner: "TruffleHog",
                rule: "Other rule".into(),
                raw: Default::default(),
            }],
            review: Review::FalsePositive,
        };
        for query in [
            " SETTINGS ",
            "ABC123",
            "example",
            "trufflehog",
            "other rule",
        ] {
            assert!(finding_matches(
                &finding,
                ReviewFilter::FalsePositive,
                query
            ));
        }
        assert!(finding_matches(&finding, ReviewFilter::All, ""));
        assert!(!finding_matches(
            &finding,
            ReviewFilter::Potential,
            "settings"
        ));
        assert!(!finding_matches(&finding, ReviewFilter::AcceptedRisk, ""));
        assert!(!finding_matches(
            &finding,
            ReviewFilter::All,
            "synthetic-secret-value"
        ));
        assert!(!finding_matches(&finding, ReviewFilter::All, "unmatched"));
        finding.file = "config/synthetic-secret-value.env".into();
        finding.evidence[0].rule = "synthetic-secret-value".into();
        assert!(!finding_matches(
            &finding,
            ReviewFilter::All,
            "synthetic-secret-value"
        ));
        assert_eq!(
            mask_detected_value(&finding.file, &finding.secret),
            "config/[MASKED].env"
        );
    }
}
