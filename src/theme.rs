//! Shared visual language for the desktop workspace.
use eframe::egui::{self, Color32, CornerRadius, FontFamily, FontId, Stroke, TextStyle, Vec2};

pub fn install(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    let mut visuals = egui::Visuals::dark();

    // Warm charcoal surfaces and subtle outlines keep dense information legible.
    let surface = Color32::from_rgb(29, 27, 27);
    let raised = Color32::from_rgb(38, 36, 36);
    let border = Color32::from_rgb(76, 72, 72);
    let text = Color32::from_rgb(232, 230, 229);
    let accent = Color32::from_rgb(43, 158, 151);
    visuals.panel_fill = surface;
    visuals.window_fill = raised;
    visuals.extreme_bg_color = Color32::from_rgb(22, 20, 20);
    visuals.faint_bg_color = Color32::from_rgb(44, 41, 41);
    visuals.code_bg_color = Color32::from_rgb(34, 32, 32);
    visuals.window_stroke = Stroke::new(1.0_f32, border);
    visuals.window_corner_radius = CornerRadius::same(8);
    visuals.menu_corner_radius = CornerRadius::same(7);
    visuals.selection.bg_fill = Color32::from_rgb(35, 104, 101);
    visuals.selection.stroke = Stroke::new(1.0_f32, accent);
    visuals.hyperlink_color = Color32::from_rgb(103, 205, 197);
    visuals.warn_fg_color = Color32::from_rgb(234, 183, 92);
    visuals.error_fg_color = Color32::from_rgb(235, 105, 110);

    for widget in [
        &mut visuals.widgets.noninteractive,
        &mut visuals.widgets.inactive,
        &mut visuals.widgets.hovered,
        &mut visuals.widgets.active,
        &mut visuals.widgets.open,
    ] {
        widget.corner_radius = CornerRadius::same(6);
        widget.bg_stroke = Stroke::new(1.0_f32, border);
        widget.fg_stroke.color = text;
    }
    visuals.widgets.noninteractive.bg_fill = surface;
    visuals.widgets.noninteractive.weak_bg_fill = surface;
    visuals.widgets.inactive.bg_fill = raised;
    visuals.widgets.inactive.weak_bg_fill = raised;
    visuals.widgets.hovered.bg_fill = Color32::from_rgb(57, 54, 54);
    visuals.widgets.hovered.weak_bg_fill = visuals.widgets.hovered.bg_fill;
    visuals.widgets.active.bg_fill = Color32::from_rgb(44, 109, 105);
    visuals.widgets.active.weak_bg_fill = visuals.widgets.active.bg_fill;
    visuals.widgets.open.bg_fill = Color32::from_rgb(53, 50, 50);
    visuals.widgets.open.weak_bg_fill = visuals.widgets.open.bg_fill;

    style.visuals = visuals;
    style.spacing.item_spacing = Vec2::new(8.0, 6.0);
    style.spacing.button_padding = Vec2::new(10.0, 5.0);
    style.spacing.interact_size.y = 30.0;
    style.text_styles.insert(
        TextStyle::Heading,
        FontId::new(19.0, FontFamily::Proportional),
    );
    style
        .text_styles
        .insert(TextStyle::Body, FontId::new(14.0, FontFamily::Proportional));
    style.text_styles.insert(
        TextStyle::Button,
        FontId::new(14.0, FontFamily::Proportional),
    );
    style.text_styles.insert(
        TextStyle::Small,
        FontId::new(12.0, FontFamily::Proportional),
    );
    ctx.set_style(style);
}
