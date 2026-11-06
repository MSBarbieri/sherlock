mod app;
mod theme;
use eframe::egui;

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
            theme::install(&cc.egui_ctx);
            Ok(Box::new(app::App::default()))
        }),
    )
}
