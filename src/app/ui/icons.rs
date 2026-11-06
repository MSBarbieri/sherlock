//! Small, font-independent outline icons for the desktop UI.
use eframe::egui::{self, vec2, Stroke};

#[derive(Clone, Copy)]
pub(super) enum Icon {
    Repository,
    Scan,
    Finding,
    File,
    Commit,
    Branch,
    Refresh,
}

/// Decorative icons accompany text labels, so controls keep their accessible names.
pub(super) fn show(ui: &mut egui::Ui, icon: Icon) {
    let (rect, _) = ui.allocate_exact_size(vec2(16.0, 16.0), egui::Sense::hover());
    if !ui.is_rect_visible(rect) {
        return;
    }
    let painter = ui.painter();
    let stroke = Stroke::new(1.5_f32, ui.visuals().text_color());
    let p = |x: f32, y: f32| rect.min + vec2(x, y);
    let line = |a, b| {
        painter.line_segment([a, b], stroke);
    };
    let circle = |x, y, radius| {
        painter.circle_stroke(p(x, y), radius, stroke);
    };
    match icon {
        Icon::Repository => {
            painter.rect_stroke(
                egui::Rect::from_min_max(p(3.0, 2.0), p(13.0, 14.0)),
                1.0,
                stroke,
                egui::StrokeKind::Inside,
            );
            line(p(5.5, 2.0), p(5.5, 14.0));
            line(p(8.0, 5.0), p(11.0, 5.0));
        }
        Icon::Scan => {
            circle(7.0, 7.0, 4.5);
            line(p(10.5, 10.5), p(14.0, 14.0));
        }
        Icon::Finding => {
            painter.line(
                vec![
                    p(8.0, 1.5),
                    p(14.0, 4.0),
                    p(13.0, 10.0),
                    p(8.0, 14.5),
                    p(3.0, 10.0),
                    p(2.0, 4.0),
                    p(8.0, 1.5),
                ],
                stroke,
            );
            line(p(8.0, 4.5), p(8.0, 9.0));
            circle(8.0, 11.5, 0.4);
        }
        Icon::File => {
            painter.line(
                vec![
                    p(3.0, 1.5),
                    p(9.0, 1.5),
                    p(13.0, 5.5),
                    p(13.0, 14.5),
                    p(3.0, 14.5),
                    p(3.0, 1.5),
                ],
                stroke,
            );
            painter.line(vec![p(9.0, 1.5), p(9.0, 5.5), p(13.0, 5.5)], stroke);
        }
        Icon::Commit => {
            line(p(1.0, 8.0), p(5.0, 8.0));
            circle(8.0, 8.0, 3.0);
            line(p(11.0, 8.0), p(15.0, 8.0));
        }
        Icon::Branch => {
            line(p(4.0, 4.0), p(4.0, 12.0));
            painter.line(vec![p(4.0, 10.0), p(11.0, 7.0), p(11.0, 4.0)], stroke);
            circle(4.0, 3.0, 1.5);
            circle(4.0, 13.0, 1.5);
            circle(11.0, 3.0, 1.5);
        }
        Icon::Refresh => {
            painter.line(
                vec![
                    p(13.0, 6.0),
                    p(12.0, 3.5),
                    p(9.0, 2.0),
                    p(5.0, 2.5),
                    p(2.5, 5.0),
                ],
                stroke,
            );
            painter.line(
                vec![
                    p(3.0, 10.0),
                    p(4.0, 12.5),
                    p(7.0, 14.0),
                    p(11.0, 13.5),
                    p(13.5, 11.0),
                ],
                stroke,
            );
            painter.line(vec![p(10.0, 6.0), p(13.0, 6.0), p(13.0, 3.0)], stroke);
            painter.line(vec![p(6.0, 10.0), p(3.0, 10.0), p(3.0, 13.0)], stroke);
        }
    }
}
