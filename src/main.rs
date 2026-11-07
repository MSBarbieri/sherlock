mod app;
mod theme;
use eframe::egui;

fn main() -> eframe::Result {
    let mut icon =
        eframe::icon_data::from_png_bytes(include_bytes!("../assets/icons/sherlock-256.png"))
            .expect("embedded Sherlock icon must be a valid PNG");
    // Composite the transparent mark over a rounded tile for the Dock and taskbar.
    let size = icon.width as f32;
    for (i, pixel) in icon.rgba.chunks_exact_mut(4).enumerate() {
        let x = (i as u32 % icon.width) as f32 + 0.5;
        let y = (i as u32 / icon.width) as f32 + 0.5;
        let inset = size * 0.05;
        let radius = size * 0.20;
        let dx = (x - size / 2.0).abs() - (size / 2.0 - inset - radius);
        let dy = (y - size / 2.0).abs() - (size / 2.0 - inset - radius);
        let distance = dx.max(0.0).hypot(dy.max(0.0)) + dx.max(dy).min(0.0) - radius;
        let background_alpha = (0.5 - distance).clamp(0.0, 1.0);
        let foreground_alpha = pixel[3] as f32 / 255.0;
        let alpha = foreground_alpha + background_alpha * (1.0 - foreground_alpha);
        if alpha > 0.0 {
            for (channel, background) in pixel[..3].iter_mut().zip([239.0, 239.0, 237.0]) {
                *channel = ((*channel as f32 * foreground_alpha
                    + background * background_alpha * (1.0 - foreground_alpha))
                    / alpha)
                    .round() as u8;
            }
        }
        pixel[3] = (alpha * 255.0).round() as u8;
    }
    eframe::run_native(
        "Sherlock",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_icon(icon)
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
