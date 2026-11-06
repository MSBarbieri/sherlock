use super::*;

impl App {
    pub(super) fn render_related_findings(
        &mut self,
        ui: &mut egui::Ui,
        index: usize,
        f: &Finding,
        related: &[usize],
        busy: bool,
        known_values: &[String],
        select_related: &mut Option<usize>,
    ) {
        self.bulk_selected
            .retain(|selected| related.contains(selected));
        ui.separator();
        ui.label(RichText::new("RELATED FINDINGS").small().weak());
        if f.secret.is_empty() {
            ui.label("No usable value was reported; this finding is kept separate.");
        } else {
            ui.label(format!("{} finding(s) in this scan", related.len()));
            ui.label(RichText::new("Exact values are grouped automatically; linked variants are distinct. Classification and redaction apply to each selected finding or value.").small().weak());
        }
        egui::ScrollArea::vertical()
            .id_salt("related_findings")
            .max_height(180.0)
            .show(ui, |ui| {
                for related_index in related.iter().copied() {
                    let item = &self.findings[related_index];
                    let mut values: Vec<&str> = Vec::new();
                    for &i in related {
                        let value = self.findings[i].secret.as_str();
                        if !value.is_empty() && !values.contains(&value) {
                            values.push(value);
                        }
                    }
                    let value_label = values
                        .iter()
                        .position(|value| *value == item.secret)
                        .map(|position| format!("Value {} · ", position + 1))
                        .unwrap_or_default();
                    let location = format!(
                        "{}{}:{} · {} · {}",
                        value_label,
                        if item.file.is_empty() {
                            "Unknown file".into()
                        } else {
                            mask_known_values(&item.file, &known_values)
                        },
                        if item.line.is_empty() {
                            "?".into()
                        } else {
                            mask_known_values(&item.line, &known_values)
                        },
                        if item.commit.is_empty() {
                            "Unknown commit".to_owned()
                        } else {
                            mask_known_values(&item.commit, &known_values)
                                .chars()
                                .take(10)
                                .collect()
                        },
                        item.review.label()
                    );
                    ui.horizontal(|ui| {
                        let mut checked = self.bulk_selected.contains(&related_index);
                        if ui
                            .add_enabled(!busy, egui::Checkbox::new(&mut checked, ""))
                            .on_hover_text("Select finding for bulk review")
                            .changed()
                        {
                            if checked {
                                self.bulk_selected.insert(related_index);
                            } else {
                                self.bulk_selected.remove(&related_index);
                            }
                            self.bulk_confirm = false;
                        }
                        if ui
                            .add_enabled(
                                !busy,
                                egui::Button::new(location).selected(related_index == index),
                            )
                            .clicked()
                        {
                            *select_related = Some(related_index);
                        }
                    });
                }
            });
        if !self.bulk_selected.is_empty() {
            ui.horizontal_wrapped(|ui| {
                ui.label(format!("{} selected", self.bulk_selected.len()));
                let before = self.bulk_review.clone();
                egui::ComboBox::from_id_salt("bulk_review")
                    .selected_text(self.bulk_review.label())
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut self.bulk_review,
                            Review::Unreviewed,
                            "Potential secret",
                        );
                        ui.selectable_value(
                            &mut self.bulk_review,
                            Review::FalsePositive,
                            "False positive",
                        );
                        ui.selectable_value(
                            &mut self.bulk_review,
                            Review::AcceptedRisk,
                            "Accepted risk",
                        );
                    });
                if before != self.bulk_review {
                    self.bulk_confirm = false;
                }
                if ui
                    .add_enabled(!busy, egui::Button::new("Review selection…"))
                    .clicked()
                {
                    self.bulk_confirm = true;
                }
            });
            if self.bulk_confirm {
                ui.label(format!("Apply '{}' to {} selected findings? Findings without complete identity will be skipped.", self.bulk_review.label(), self.bulk_selected.len()));
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(!busy, egui::Button::new("Confirm review"))
                        .clicked()
                    {
                        let selected: Vec<usize> = self.bulk_selected.iter().copied().collect();
                        let updates: Vec<Finding> = selected
                            .iter()
                            .map(|&i| {
                                let mut finding = self.findings[i].clone();
                                finding.review = self.bulk_review.clone();
                                finding
                            })
                            .collect();
                        match sherlock_reviews::ReviewStore::standard()
                            .and_then(|store| store.save_many(&self.repo(), &updates))
                        {
                            Ok(result) => {
                                for saved in &result.saved {
                                    self.findings[selected[*saved]].review =
                                        self.bulk_review.clone();
                                }
                                let failure = result
                                    .rejected
                                    .iter()
                                    .map(|(i, reason)| {
                                        let finding = &self.findings[selected[*i]];
                                        format!(
                                            "{}:{}: {}",
                                            mask_known_values(&finding.file, &known_values),
                                            mask_known_values(&finding.line, &known_values),
                                            reason
                                        )
                                    })
                                    .collect::<Vec<_>>()
                                    .join("; ");
                                self.status = format!(
                                    "Saved {} review(s); {} skipped. {}",
                                    result.saved.len(),
                                    result.rejected.len(),
                                    failure
                                );
                            }
                            Err(error) => self.status = format!("No reviews saved: {error}"),
                        }
                        self.bulk_confirm = false;
                    }
                    if ui.button("Cancel").clicked() {
                        self.bulk_confirm = false;
                    }
                });
            }
        }
    }
}
