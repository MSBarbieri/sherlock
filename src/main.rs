mod app;
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
            cc.egui_ctx.set_visuals(egui::Visuals::dark());
            Ok(Box::new(app::App::default()))
        }),
    )
}
