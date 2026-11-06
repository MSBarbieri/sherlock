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

fn finding_matches(finding: &Finding, filter: ReviewFilter, search: &str) -> bool {
    let query = search.trim().to_lowercase();
    filter.matches(&finding.review)
        && (query.is_empty()
            || [&finding.rule, &finding.file, &finding.commit]
                .iter()
                .any(|value| value.to_lowercase().contains(&query))
            || finding.scanner.to_lowercase().contains(&query)
            || finding.evidence.iter().any(|report| {
                report.scanner.to_lowercase().contains(&query)
                    || report.rule.to_lowercase().contains(&query)
            }))
}

enum ResultMessage {
    Scan(Result<Vec<Finding>, String>),
    Branches(Result<Vec<sherlock_git::RefSnapshot>, String>),
    Status(Result<String, String>),
}
pub struct App {
    repo: String,
    scanner: Scanner,
    findings: Vec<Finding>,
    selected: Option<usize>,
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
            repo: String::new(),
            scanner: Scanner::Gitleaks,
            findings: vec![],
            selected: None,
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
                            self.selected = None;
                            self.branches.clear();
                            self.checked.clear();
                        }
                        ResultMessage::Branches(Ok(b)) => {
                            self.status = format!("Found {} containing refs.", b.len());
                            self.checked = vec![true; b.len()];
                            self.branches = b;
                        }
                        ResultMessage::Status(Ok(s)) => self.status = s,
                        ResultMessage::Scan(Err(e))
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
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.heading(RichText::new("◈  SHERLOCK").color(Color32::from_rgb(160, 143, 255)));
                ui.label(RichText::new("  /  repository security").weak());
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
                ui.label(&self.status);
            });
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
                            ui.selectable_value(&mut self.scanner, Scanner::Both, "Both scanners");
                            ui.selectable_value(&mut self.scanner, Scanner::Gitleaks, "Gitleaks");
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
                ui.add_space(16.0);
                ui.label(
                    RichText::new(
                        "Fetch updates local remote-tracking refs. Scans and rewrites run locally.",
                    )
                    .small()
                    .weak(),
                );
            });
        let mut select_related = None;
        egui::SidePanel::right("detail").resizable(true).default_width(360.0).show(ctx, |ui| {
            ui.add_space(12.0); ui.heading("Finding details"); ui.separator();
            egui::ScrollArea::vertical().id_salt("detail_content").show(ui, |ui| {
            if let Some(index) = self.selected { let f = self.findings[index].clone();
                ui.label(RichText::new(&f.rule).strong().color(Color32::from_rgb(197, 184, 255))); ui.label(format!("{} · line {}", f.file, f.line)); ui.label(format!("Commit  {}", f.commit)); ui.label("Secret  ••••••••••••"); ui.add_space(12.0);
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
                ui.label(RichText::new("Review decisions are stored locally for this repository.").small().weak());
                ui.label("Scanner evidence:");
                for report in &f.evidence { ui.label(format!("{} · {}", report.scanner, report.rule)); }
                let related = group_by_secret(&self.findings).into_iter().find(|group| group.contains(&index)).unwrap_or_default();
                ui.separator();
                ui.label(RichText::new("SAME DETECTED VALUE").small().weak());
                if f.secret.is_empty() {
                    ui.label("No usable value was reported; this finding is kept separate.");
                } else {
                    ui.label(format!("{} finding(s) in this scan", related.len()));
                    ui.label(RichText::new("Each finding keeps its own classification. This grouping is based on the exact value.").small().weak());
                    egui::ScrollArea::vertical().id_salt("related_findings").max_height(100.0).show(ui, |ui| {
                        for related_index in related {
                            let item = &self.findings[related_index];
                            let location = format!("{}:{} · {} · {}", if item.file.is_empty() { "Unknown file" } else { &item.file }, if item.line.is_empty() { "?" } else { &item.line }, if item.commit.is_empty() { "Unknown commit".to_owned() } else { item.commit.chars().take(10).collect() }, item.review.label());
                            if ui.add_enabled(!busy && related_index != index, egui::Button::new(location)).clicked() {
                                select_related = Some(related_index);
                            }
                        }
                    });
                }
                if ui.add_enabled(!busy, egui::Button::new("Find branches for this value")).clicked() { let p = self.repo(); let occurrences: Vec<Finding> = self.findings.iter().filter(|item| !f.secret.is_empty() && item.secret == f.secret).cloned().collect(); self.branches.clear(); self.checked.clear(); self.status = "Checking local and remote-tracking refs…".into(); self.task(move || ResultMessage::Branches(sherlock_git::branches_for_findings(&p, &occurrences).and_then(|refs| sherlock_git::snapshot_refs(&p, &refs)))); }
                ui.add_space(8.0); ui.label(RichText::new("CONTAINING REFS").small().weak());
                egui::ScrollArea::vertical().max_height(150.0).show(ui, |ui| { for (i, branch) in self.branches.iter().enumerate() { ui.add_enabled(!busy, egui::Checkbox::new(&mut self.checked[i], &branch.name)); } });
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
                ui.label(RichText::new("Creates new branches in a separate mirror. Original refs in that mirror remain sensitive. No push is performed. Rewritten history is not automatically verified.").small().weak());
                if ui.add_enabled(!busy && self.checked.iter().any(|x| *x) && !self.destination.is_empty(), egui::Button::new("Create redacted branches")).clicked() {
                    let p = self.repo(); let d = PathBuf::from(&self.destination); let refs: Vec<sherlock_git::RefSnapshot> = self.branches.iter().zip(&self.checked).filter(|(_, c)| **c).map(|(b,_)| b.clone()).collect(); let occurrences: Vec<Finding> = self.findings.iter().filter(|item| !f.secret.is_empty() && item.secret == f.secret).cloned().collect(); self.status = "Preparing redacted branches…".into(); self.task(move || ResultMessage::Status(sherlock_git::rewrite_related_at(&p, &d, &occurrences, &refs)));
                }
            } else { ui.label(RichText::new("Select a finding to inspect its commit and affected branches.").weak()); }
            });
        });
        if let Some(index) = select_related {
            self.selected = Some(index);
            self.branches.clear();
            self.checked.clear();
        }
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                ui.heading("Findings");
                ui.label(RichText::new(format!("{}", self.findings.len())).weak());
            });
            ui.label(RichText::new("Review potential secrets before changing history.").weak());
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
                .filter(|(_, finding)| finding_matches(finding, self.filter, &self.search))
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
                            ui.label(&self.status);
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
                    for i in visible {
                        let f = &self.findings[i];
                        let text = format!(
                            "{}   ·   {} · {}\n{}:{}   ·   {}",
                            f.rule,
                            f.review.label(),
                            f.scanner,
                            f.file,
                            f.line,
                            f.commit.chars().take(10).collect::<String>()
                        );
                        if ui
                            .add_enabled(!busy, egui::Button::new(text).selected(self.selected == Some(i)))
                            .clicked()
                        {
                            self.selected = Some(i);
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

#[cfg(test)]
mod tests {
    use super::*;
    use sherlock_domain::ScannerReport;

    #[test]
    fn finding_search_respects_classification_and_excludes_secret_values() {
        let finding = Finding {
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
    }
}
