#[path = "branches.rs"]
mod branches;
#[path = "prepare.rs"]
mod prepare;
#[path = "verification.rs"]
mod verification;

use super::*;

impl App {
    pub(super) fn render_redaction(
        &mut self,
        ui: &mut egui::Ui,
        f: &Finding,
        related: &[usize],
        busy: bool,
        known_values: &[String],
    ) {
        self.render_branch_selection(ui, f, related, busy, known_values);
        self.render_rewrite_preparation(ui, f, busy);
        self.render_rewrite_verification(ui, f, busy, known_values);
    }
}
