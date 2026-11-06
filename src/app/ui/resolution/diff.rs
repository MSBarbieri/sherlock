use super::*;
use egui::{text::LayoutJob, FontId, TextFormat};
use similar::{ChangeTag, TextDiff};
use std::{
    hash::{Hash, Hasher},
    sync::OnceLock,
};
use syntect::{easy::HighlightLines, highlighting::ThemeSet, parsing::SyntaxSet};

struct DiffRow {
    tag: ChangeTag,
    old: Option<usize>,
    new: Option<usize>,
    code: LayoutJob,
    reported: bool,
}

pub(in crate::app) struct DiffCache {
    key: u64,
    rows: Vec<DiffRow>,
}

fn syntax_assets() -> &'static (SyntaxSet, ThemeSet) {
    static ASSETS: OnceLock<(SyntaxSet, ThemeSet)> = OnceLock::new();
    ASSETS.get_or_init(|| {
        (
            SyntaxSet::load_defaults_newlines(),
            ThemeSet::load_defaults(),
        )
    })
}

fn highlighted_line(
    highlighter: &mut HighlightLines<'_>,
    syntax: &SyntaxSet,
    text: &str,
) -> LayoutJob {
    let mut job = LayoutJob::default();
    let fallback = Color32::from_rgb(215, 218, 229);
    if let Ok(parts) = highlighter.highlight_line(text, syntax) {
        for (style, part) in parts {
            let part = part.trim_end_matches(['\r', '\n']);
            let color = style.foreground;
            job.append(
                part,
                0.0,
                TextFormat {
                    font_id: FontId::monospace(14.0),
                    color: Color32::from_rgb(color.r, color.g, color.b),
                    ..Default::default()
                },
            );
        }
    } else {
        job.append(
            text.trim_end_matches(['\r', '\n']),
            0.0,
            TextFormat {
                font_id: FontId::monospace(14.0),
                color: fallback,
                ..Default::default()
            },
        );
    }
    job
}

pub(super) fn render_diff(
    ui: &mut egui::Ui,
    cache: &mut Option<DiffCache>,
    id: &str,
    path: &str,
    original: &str,
    rewritten: &str,
    values: &[String],
    reveal: bool,
    side_by_side: bool,
    reported_lines: &[usize],
) {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    (path, original, rewritten, values, reveal, reported_lines).hash(&mut hasher);
    let key = hasher.finish();
    if cache.as_ref().is_none_or(|cached| cached.key != key) {
        *cache = Some(DiffCache {
            key,
            rows: prepare_rows(path, original, rewritten, values, reveal, reported_lines),
        });
    }
    let rows = &cache.as_ref().expect("diff cache populated").rows;
    egui::ScrollArea::both()
        .id_salt(id)
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let mut cursor = 0;
            while cursor < rows.len() {
                if rows[cursor].tag != ChangeTag::Equal {
                    if side_by_side {
                        let start = cursor;
                        while cursor < rows.len() && rows[cursor].tag != ChangeTag::Equal {
                            cursor += 1;
                        }
                        let removed: Vec<_> = rows[start..cursor]
                            .iter()
                            .filter(|row| row.tag == ChangeTag::Delete)
                            .collect();
                        let added: Vec<_> = rows[start..cursor]
                            .iter()
                            .filter(|row| row.tag == ChangeTag::Insert)
                            .collect();
                        for i in 0..removed.len().max(added.len()) {
                            ui.columns(2, |columns| {
                                if let Some(row) = removed.get(i) {
                                    render_cell(&mut columns[0], row, row.old);
                                }
                                if let Some(row) = added.get(i) {
                                    render_cell(&mut columns[1], row, row.new);
                                }
                            });
                        }
                    } else {
                        render_row(ui, &rows[cursor], false);
                        cursor += 1;
                    }
                    continue;
                }
                let start = cursor;
                while cursor < rows.len() && rows[cursor].tag == ChangeTag::Equal {
                    cursor += 1;
                }
                let end = cursor;
                let leading = if start == 0 { 0 } else { 3.min(end - start) };
                let trailing = if end == rows.len() {
                    0
                } else {
                    3.min(end - start - leading)
                };
                for row in &rows[start..start + leading] {
                    render_row(ui, row, side_by_side);
                }
                let hidden = &rows[start + leading..end - trailing];
                if !hidden.is_empty() {
                    egui::CollapsingHeader::new(format!(
                        "{} unchanged lines · expand",
                        hidden.len()
                    ))
                    .id_salt((id, start))
                    .show(ui, |ui| {
                        for row in hidden {
                            render_row(ui, row, side_by_side);
                        }
                    });
                }
                for row in &rows[end - trailing..end] {
                    render_row(ui, row, side_by_side);
                }
            }
            if rows.is_empty() {
                ui.weak("This file is empty.");
            }
        });
}

fn prepare_rows(
    path: &str,
    original: &str,
    rewritten: &str,
    values: &[String],
    reveal: bool,
    reported_lines: &[usize],
) -> Vec<DiffRow> {
    let (syntaxes, themes) = syntax_assets();
    let syntax = std::path::Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .and_then(|ext| syntaxes.find_syntax_by_extension(ext))
        .unwrap_or_else(|| syntaxes.find_syntax_plain_text());
    let theme = &themes.themes["base16-ocean.dark"];
    let mut old_highlighter = HighlightLines::new(syntax, theme);
    let mut new_highlighter = HighlightLines::new(syntax, theme);
    let diff = TextDiff::from_lines(original, rewritten);
    let mut rows = Vec::new();
    for change in diff.iter_all_changes() {
        let raw = change.value();
        // Syntax parsing and layout never receive known values while masking is active.
        let safe = if reveal {
            raw.to_owned()
        } else {
            mask_known_values(raw, values)
        };
        let old = change.old_index().map(|n| n + 1);
        let new = change.new_index().map(|n| n + 1);
        let code = match change.tag() {
            ChangeTag::Delete => highlighted_line(&mut old_highlighter, syntaxes, &safe),
            ChangeTag::Insert => highlighted_line(&mut new_highlighter, syntaxes, &safe),
            ChangeTag::Equal => {
                let result = highlighted_line(&mut old_highlighter, syntaxes, &safe);
                let _ = highlighted_line(&mut new_highlighter, syntaxes, &safe);
                result
            }
        };
        rows.push(DiffRow {
            tag: change.tag(),
            old,
            new,
            code,
            reported: old.is_some_and(|line| reported_lines.contains(&line)),
        });
    }
    rows
}

fn render_row(ui: &mut egui::Ui, row: &DiffRow, side_by_side: bool) {
    if side_by_side {
        ui.columns(2, |columns| {
            if row.tag != ChangeTag::Insert {
                render_cell(&mut columns[0], row, row.old);
            }
            if row.tag != ChangeTag::Delete {
                render_cell(&mut columns[1], row, row.new);
            }
        });
    } else {
        render_cell(ui, row, None);
    }
}

fn render_cell(ui: &mut egui::Ui, row: &DiffRow, single_number: Option<usize>) {
    let (background, gutter, sign) = match row.tag {
        ChangeTag::Delete => (
            Color32::from_rgb(58, 29, 32),
            Color32::from_rgb(239, 105, 110),
            "−",
        ),
        ChangeTag::Insert => (
            Color32::from_rgb(27, 53, 40),
            Color32::from_rgb(100, 213, 147),
            "+",
        ),
        ChangeTag::Equal => (
            Color32::from_rgb(27, 26, 29),
            Color32::from_rgb(133, 136, 148),
            " ",
        ),
    };
    egui::Frame::NONE.fill(background).inner_margin(egui::Margin::symmetric(8, 2)).show(ui, |ui| {
        ui.set_min_width(ui.available_width());
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 4.0;
            let old = row.old.map_or_else(String::new, |n| n.to_string());
            let new = row.new.map_or_else(String::new, |n| n.to_string());
            if let Some(number) = single_number {
                ui.add_sized([46.0, 18.0], egui::Label::new(RichText::new(number.to_string()).monospace().color(gutter)));
            } else {
                ui.add_sized([46.0, 18.0], egui::Label::new(RichText::new(old).monospace().color(gutter)));
                ui.add_sized([46.0, 18.0], egui::Label::new(RichText::new(new).monospace().color(gutter)));
            }
            ui.label(RichText::new(sign).monospace().color(gutter));
            let response = ui.add(egui::Label::new(row.code.clone()).selectable(true));
            if row.tag == ChangeTag::Delete {
                response.on_hover_text(if row.reported { "A scanner reported the target value on this line; other changes may also be present." } else { "No scanner report for the target value on this line." });
            }
        });
    });
}
