use eframe::egui::{self, Color32, RichText};
use sherlock_domain::{Finding, Review};
use sherlock_scan::Scanner;
use std::{
    path::PathBuf,
    sync::mpsc::{self, Receiver},
};

enum ResultMessage {
    Scan(Result<Vec<Finding>, String>),
    Branches(Result<Vec<String>, String>),
    Status(Result<String, String>),
}
pub struct App {
    repo: String,
    scanner: Scanner,
    findings: Vec<Finding>,
    selected: Option<usize>,
    branches: Vec<String>,
    checked: Vec<bool>,
    status: String,
    receiver: Option<Receiver<ResultMessage>>,
    destination: String,
    scan_completed: bool,
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
        egui::SidePanel::right("detail").resizable(true).default_width(360.0).show(ctx, |ui| {
            ui.add_space(12.0); ui.heading("Finding details"); ui.separator();
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
                if ui.add_enabled(!busy, egui::Button::new("Find containing branches")).clicked() { let p = self.repo(); let c = f.commit.clone(); self.branches.clear(); self.status = "Checking local and remote-tracking refs…".into(); self.task(move || ResultMessage::Branches(sherlock_git::branches(&p, &c))); }
                ui.add_space(8.0); ui.label(RichText::new("CONTAINING REFS").small().weak());
                egui::ScrollArea::vertical().max_height(150.0).show(ui, |ui| { for (i, branch) in self.branches.iter().enumerate() { ui.checkbox(&mut self.checked[i], branch); } });
                ui.separator(); ui.label(RichText::new("PREPARE REDACTED HISTORY").small().weak()); ui.label("New mirror path"); ui.text_edit_singleline(&mut self.destination);
                ui.label(RichText::new("Creates new branches in a separate mirror. Original refs in that mirror remain sensitive. No push is performed.").small().weak());
                if ui.add_enabled(!busy && self.checked.iter().any(|x| *x) && !self.destination.is_empty(), egui::Button::new("Create redacted branches")).clicked() {
                    let p = self.repo(); let d = PathBuf::from(&self.destination); let refs: Vec<String> = self.branches.iter().zip(&self.checked).filter(|(_, c)| **c).map(|(b,_)| b.clone()).collect(); self.status = "Preparing redacted branches…".into(); self.task(move || ResultMessage::Status(sherlock_git::rewrite(&p, &d, &f, &refs)));
                }
            } else { ui.label(RichText::new("Select a finding to inspect its commit and affected branches.").weak()); }
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                ui.heading("Findings");
                ui.label(RichText::new(format!("{}", self.findings.len())).weak());
            });
            ui.label(RichText::new("Review potential secrets before changing history.").weak());
            ui.separator();
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
                    for (i, f) in self.findings.iter().enumerate() {
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
                            .selectable_label(self.selected == Some(i), text)
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
