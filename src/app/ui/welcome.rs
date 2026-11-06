use super::super::*;

impl App {
    pub(in crate::app) fn render_project_welcome(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(72.0);
            ui.vertical_centered(|ui| {
                ui.add(egui::Image::new(self.logo(ctx, ui.visuals().dark_mode)).fit_to_exact_size(egui::vec2(96.0, 96.0)));
                ui.add_space(8.0);
                ui.heading(RichText::new("SHERLOCK").color(Color32::from_rgb(160, 143, 255)));
                ui.add_space(20.0);
                ui.heading("Open a repository");
                ui.label("Choose a local Git repository to start a project workspace.");
                ui.add_space(18.0);
                if ui.button("Choose repository folder…").clicked() {
                    self.choose_project();
                }
                ui.add_space(12.0);
                ui.label("Or enter a repository path");
                let response = ui.add(
                    egui::TextEdit::singleline(&mut self.project_input)
                        .desired_width(400.0)
                        .hint_text("/path/to/repository"),
                );
                let open = ui
                    .add_enabled(
                        !self.project_input.trim().is_empty(),
                        egui::Button::new("Open repository"),
                    )
                    .clicked()
                    || (response.lost_focus()
                        && ui.input(|input| input.key_pressed(egui::Key::Enter))
                        && !self.project_input.trim().is_empty());
                if open {
                    let path = PathBuf::from(self.project_input.trim());
                    if let Err(error) = self.open_project(&path) {
                        self.status = error;
                    }
                }
                ui.add_space(12.0);
                ui.label(RichText::new(&self.status).weak());
            });
        });
    }
}
