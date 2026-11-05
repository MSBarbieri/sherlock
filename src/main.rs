mod core;
use core::Finding;
use eframe::egui::{self, Color32, RichText};
use std::{
    path::PathBuf,
    sync::mpsc::{self, Receiver},
};

enum ResultMessage {
    Scan(Result<Vec<Finding>, String>),
    Branches(Result<Vec<String>, String>),
    Status(Result<String, String>),
}
struct App {
    repo: String,
    scanner: String,
    findings: Vec<Finding>,
    selected: Option<usize>,
    branches: Vec<String>,
    checked: Vec<bool>,
    status: String,
    receiver: Option<Receiver<ResultMessage>>,
    destination: String,
}
impl Default for App {
    fn default() -> Self {
        Self {
            repo: String::new(),
            scanner: "Gitleaks".into(),
            findings: vec![],
            selected: None,
            branches: vec![],
            checked: vec![],
            status: "Choose a repository to begin.".into(),
            receiver: None,
            destination: String::new(),
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
                        ResultMessage::Scan(Ok(f)) => {
                            self.status = format!("Scan complete · {} findings", f.len());
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
                if ui.text_edit_singleline(&mut self.repo).changed() {
                    self.findings.clear();
                    self.selected = None;
                    self.branches.clear();
                    self.checked.clear();
                    self.destination = core::suggested_destination(&self.repo())
                        .display()
                        .to_string();
                }
                if ui
                    .add_enabled(!busy, egui::Button::new("Choose folder…"))
                    .clicked()
                {
                    if let Some(p) = rfd::FileDialog::new().pick_folder() {
                        self.repo = p.display().to_string();
                        self.destination = core::suggested_destination(&p).display().to_string();
                        self.findings.clear();
                        self.selected = None;
                        self.branches.clear();
                    }
                }
                ui.separator();
                ui.label("Scanner");
                egui::ComboBox::from_id_salt("scanner")
                    .selected_text(&self.scanner)
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.scanner, "Gitleaks".into(), "Gitleaks");
                        ui.selectable_value(&mut self.scanner, "TruffleHog".into(), "TruffleHog");
                    });
                if ui
                    .add_enabled(
                        !busy && !self.repo.is_empty(),
                        egui::Button::new("▶  Scan repository"),
                    )
                    .clicked()
                {
                    let p = self.repo();
                    let s = self.scanner.clone();
                    self.status = format!("Scanning with {s}…");
                    self.findings.clear();
                    self.selected = None;
                    self.branches.clear();
                    self.task(move || ResultMessage::Scan(core::scan(&p, &s)));
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
                    self.task(move || ResultMessage::Status(core::fetch(&p)));
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
                if ui.add_enabled(!busy, egui::Button::new("Find containing branches")).clicked() { let p = self.repo(); let c = f.commit.clone(); self.branches.clear(); self.status = "Checking local and remote-tracking refs…".into(); self.task(move || ResultMessage::Branches(core::branches(&p, &c))); }
                ui.add_space(8.0); ui.label(RichText::new("CONTAINING REFS").small().weak());
                egui::ScrollArea::vertical().max_height(150.0).show(ui, |ui| { for (i, branch) in self.branches.iter().enumerate() { ui.checkbox(&mut self.checked[i], branch); } });
                ui.separator(); ui.label(RichText::new("PREPARE REDACTED HISTORY").small().weak()); ui.label("New mirror path"); ui.text_edit_singleline(&mut self.destination);
                ui.label(RichText::new("Creates new branches in a separate mirror. Original refs in that mirror remain sensitive. No push is performed.").small().weak());
                if ui.add_enabled(!busy && self.checked.iter().any(|x| *x) && !self.destination.is_empty(), egui::Button::new("Create redacted branches")).clicked() {
                    let p = self.repo(); let d = PathBuf::from(&self.destination); let refs: Vec<String> = self.branches.iter().zip(&self.checked).filter(|(_, c)| **c).map(|(b,_)| b.clone()).collect(); self.status = "Preparing redacted branches…".into(); self.task(move || ResultMessage::Status(core::rewrite(&p, &d, &f, &refs)));
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
                        ui.heading("No findings to show");
                        ui.label("Choose a repository and run a scan.");
                    });
                } else {
                    for (i, f) in self.findings.iter().enumerate() {
                        let text = format!(
                            "{}   ·   {}\n{}:{}   ·   {}",
                            f.rule,
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
fn main() -> eframe::Result {
    eframe::run_native(
        "Sherlock",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1280.0, 780.0])
                .with_min_inner_size([900.0, 600.0]),
            ..Default::default()
        },
        Box::new(|cc| {
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Ok(Box::new(App::default()))
        }),
    )
}
