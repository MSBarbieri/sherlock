use super::super::*;

impl App {
    pub(in crate::app) fn render_shell(
        &mut self,
        ctx: &egui::Context,
        busy: bool,
        known_values: &[String],
    ) {
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.add(
                    egui::Image::new(self.logo(ctx, ui.visuals().dark_mode))
                        .fit_to_exact_size(egui::vec2(28.0, 28.0)),
                );
                ui.heading(RichText::new("SHERLOCK").color(Color32::from_rgb(160, 143, 255)));
                ui.label(RichText::new("  /  repository security").weak());
                ui.separator();
                let project = self.project_root.as_ref().expect("project is open");
                let project_name = project
                    .file_name()
                    .unwrap_or(project.as_os_str())
                    .to_string_lossy();
                ui.label(format!(
                    "Project: {}",
                    mask_known_values(&project_name, known_values)
                ));
                if ui
                    .add_enabled(!busy, egui::Button::new("Switch repository…"))
                    .on_hover_text("Open another repository as a new project")
                    .clicked()
                {
                    self.choose_project();
                }
                if self
                    .project_root
                    .as_ref()
                    .is_some_and(|root| root != &self.repo())
                {
                    ui.label(
                        RichText::new(format!(
                            "Reviewing mirror: {}",
                            mask_known_values(&self.repo, known_values)
                        ))
                        .weak(),
                    );
                }
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
                if self.scan_completed && self.scan_stale {
                    ui.label(
                        RichText::new("History results may be out of date.").color(Color32::YELLOW),
                    );
                }
                if let Some(error) = &self.monitor.error {
                    ui.label(
                        RichText::new(format!(
                            "Automatic monitoring unavailable: {}",
                            mask_known_values(error, known_values)
                        ))
                        .color(Color32::YELLOW),
                    );
                } else if self.monitor.worktree_dirty {
                    ui.label(
                        RichText::new(
                            "Uncommitted changes detected; history scans do not cover them.",
                        )
                        .color(Color32::YELLOW),
                    );
                }
                if self.automatic_scan_pending && busy {
                    ui.label("A history scan is queued after the current operation.");
                }
            });
        egui::SidePanel::left("navigation_rail")
            .exact_width(66.0)
            .resizable(false)
            .show(ctx, |ui| {
                ui.add_space(12.0);
                ui.vertical_centered(|ui| {
                    super::icons::show(ui, super::icons::Icon::Scan);
                    if ui
                        .selectable_label(self.page == Page::Discovery, "Scan")
                        .on_hover_text("Repository and scan")
                        .clicked()
                    {
                        self.page = Page::Discovery;
                        self.revealed = None;
                    }
                    ui.add_space(8.0);
                    super::icons::show(ui, super::icons::Icon::Finding);
                    if ui
                        .add_enabled(
                            self.selected.is_some(),
                            egui::Button::new("Review").selected(self.page == Page::Resolution),
                        )
                        .on_hover_text("Secret workspace")
                        .clicked()
                    {
                        self.page = Page::Resolution;
                    }
                });
            });
    }
}
