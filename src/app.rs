mod automation;
mod investigation;
mod project;
mod rewrite;
mod tasks;
mod ui;

use eframe::egui::{self, Color32, RichText};
use sherlock_domain::{group_by_secret, Finding, Review};
use sherlock_scan::Scanner;
use std::{
    path::PathBuf,
    sync::mpsc::{self, Receiver},
};

use investigation::{mask_known_values, workspace_finding_matches, ReviewFilter};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Discovery,
    Resolution,
}

use rewrite::{check_exact, scan_prepared, PreparedRewrite};

use tasks::{load_link_data, ResultMessage};

pub struct App {
    logo_light: Option<egui::TextureHandle>,
    logo_dark: Option<egui::TextureHandle>,
    project_root: Option<PathBuf>,
    project_input: String,
    automatic_scan_pending: bool,
    scan_target: Option<PathBuf>,
    scan_stale: bool,
    monitor: automation::RepositoryMonitor,
    page: Page,
    prepared: Option<PreparedRewrite>,
    verification_output: Option<String>,
    exact_locations: Vec<sherlock_git::ExactLocation>,
    exact_location_error: Option<String>,
    scanner_output: Option<String>,
    scanner_used: Option<Scanner>,
    completion_output: Option<String>,
    scanner_findings: Vec<Finding>,
    history_output: Option<Result<HistoryView, String>>,
    file_preview: Option<(usize, Result<sherlock_git::FilePreview, String>)>,
    file_search: String,
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
struct HistoryView {
    history: sherlock_git::SecretHistory,
    lines: Vec<sherlock_git::GraphLine>,
    truncated: bool,
    finding_indices: Vec<usize>,
}
impl Default for App {
    fn default() -> Self {
        Self {
            logo_light: None,
            logo_dark: None,
            project_root: None,
            project_input: String::new(),
            automatic_scan_pending: false,
            scan_target: None,
            scan_stale: true,
            monitor: Default::default(),
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
            file_preview: None,
            file_search: String::new(),
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
    fn logo(&mut self, ctx: &egui::Context, dark_mode: bool) -> &egui::TextureHandle {
        let texture = if dark_mode {
            &mut self.logo_dark
        } else {
            &mut self.logo_light
        };
        texture.get_or_insert_with(|| {
            let mut icon = eframe::icon_data::from_png_bytes(include_bytes!(
                "../assets/icons/sherlock-256.png"
            ))
            .expect("embedded Sherlock logo must be a valid PNG");
            // The original navy mark has too little contrast against the dark UI.
            if dark_mode {
                for pixel in icon.rgba.chunks_exact_mut(4) {
                    if pixel[0] < 60 && pixel[1] < 80 && pixel[2] < 100 {
                        pixel[..3].copy_from_slice(&[232, 230, 229]);
                    }
                }
            }
            ctx.load_texture(
                if dark_mode {
                    "sherlock-logo-dark"
                } else {
                    "sherlock-logo-light"
                },
                egui::ColorImage::from_rgba_unmultiplied(
                    [icon.width as usize, icon.height as usize],
                    &icon.rgba,
                ),
                egui::TextureOptions::LINEAR,
            )
        })
    }
    fn repo(&self) -> PathBuf {
        PathBuf::from(&self.repo)
    }
}
impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        self.poll_tasks(ctx);
        self.poll_automatic_scan(ctx);
        let busy = self.receiver.is_some();
        if self.project_root.is_none() {
            self.render_project_welcome(ctx);
            return;
        }
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
        self.render_shell(ctx, busy, &known_values);
        self.render_discovery_sidebar(ctx, busy, &known_values);
        self.render_resolution(ctx, busy, &known_values);
        self.render_discovery_content(ctx, busy, &known_values);
    }
}
