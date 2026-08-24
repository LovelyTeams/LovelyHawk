use std::{path::PathBuf, sync::Arc};

use gpui::{
    AnyElement, ClipboardItem, Context, Entity, EventEmitter, IntoElement, Render, SharedString,
    Subscription, Window, div, prelude::*,
};
use gpui_component::{Disableable, Sizable, button::ButtonVariants, scroll::ScrollableElement};
use lovelyres_core::{
    BackendServices, CoreError, CoreResult,
    detection::DetectionScanReport,
    report::{DisposalReport, ReportFormat},
    target::TargetGuard,
};

use crate::{app::SharedAppState, runtime::TokioBridge, theme::ThemeTokens};

const MAX_PREVIEW_LINES: usize = 2_000;
const MAX_PREVIEW_CHARS: usize = 200_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DisposalReportEvent {
    CloseRequested,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum PreviewMode {
    #[default]
    Summary,
    Markdown,
    Html,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReportBinding {
    target: TargetGuard,
    label: String,
}

impl ReportBinding {
    fn capture(shared: &SharedAppState) -> Option<Self> {
        let active = shared.active_ssh.as_ref()?;
        Some(Self {
            target: active.session.target().clone(),
            label: active.label.to_string(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReportLease {
    activation_generation: u64,
    request_id: u64,
    binding: ReportBinding,
}

#[derive(Debug, Default)]
struct DisposalReportModel {
    active: bool,
    activation_generation: u64,
    next_request_id: u64,
    binding: Option<ReportBinding>,
    latest_request: Option<u64>,
    report: Option<Arc<DisposalReport>>,
    preview: PreviewMode,
    saving: bool,
}

impl DisposalReportModel {
    fn activate(&mut self, binding: Option<ReportBinding>) {
        self.active = true;
        self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        self.binding = binding;
        self.latest_request = None;
        self.report = None;
        self.preview = PreviewMode::Summary;
        self.saving = false;
    }

    fn deactivate(&mut self) {
        self.active = false;
        self.latest_request = None;
        self.saving = false;
    }

    fn begin_request(&mut self, current: Option<ReportBinding>) -> CoreResult<ReportLease> {
        if !self.active || current != self.binding {
            return Err(CoreError::Validation {
                subject: "disposal report request",
                message: "report overlay is inactive or target binding changed".to_owned(),
            });
        }
        let binding = current.ok_or(CoreError::Validation {
            subject: "disposal report request",
            message: "an active SSH target is required".to_owned(),
        })?;
        self.next_request_id = self.next_request_id.wrapping_add(1).max(1);
        self.latest_request = Some(self.next_request_id);
        Ok(ReportLease {
            activation_generation: self.activation_generation,
            request_id: self.next_request_id,
            binding,
        })
    }

    fn accepts(&self, lease: &ReportLease, current: Option<&ReportBinding>) -> bool {
        self.active
            && self.activation_generation == lease.activation_generation
            && self.latest_request == Some(lease.request_id)
            && self.binding.as_ref() == Some(&lease.binding)
            && current == Some(&lease.binding)
    }

    fn apply_report(
        &mut self,
        lease: &ReportLease,
        current: Option<&ReportBinding>,
        report: DisposalReport,
    ) -> bool {
        if !self.accepts(lease, current) || report.snapshot.target != lease.binding.target {
            return false;
        }
        self.latest_request = None;
        self.report = Some(Arc::new(report));
        true
    }

    fn reject(&mut self, lease: &ReportLease, current: Option<&ReportBinding>) -> bool {
        if !self.accepts(lease, current) {
            return false;
        }
        self.latest_request = None;
        true
    }
}

pub struct DisposalReportOverlay {
    services: Arc<BackendServices>,
    tokio: Arc<TokioBridge>,
    shared: Entity<SharedAppState>,
    model: DisposalReportModel,
    detection: Option<DetectionScanReport>,
    generation_abort: Option<tokio::task::AbortHandle>,
    save_abort: Option<tokio::task::AbortHandle>,
    error: Option<SharedString>,
    notice: Option<SharedString>,
    _subscription: Subscription,
}

impl EventEmitter<DisposalReportEvent> for DisposalReportOverlay {}

impl DisposalReportOverlay {
    pub fn new(
        services: Arc<BackendServices>,
        tokio: Arc<TokioBridge>,
        shared: Entity<SharedAppState>,
        cx: &mut Context<Self>,
    ) -> Self {
        let subscription = cx.observe(&shared, |overlay, _, cx| {
            overlay.handle_shared_change(cx);
        });
        Self {
            services,
            tokio,
            shared,
            model: DisposalReportModel::default(),
            detection: None,
            generation_abort: None,
            save_abort: None,
            error: None,
            notice: None,
            _subscription: subscription,
        }
    }

    pub fn activate(&mut self, detection: Option<DetectionScanReport>, cx: &mut Context<Self>) {
        let binding = self.current_binding(cx);
        self.model.activate(binding.clone());
        self.detection = detection.filter(|report| {
            binding
                .as_ref()
                .is_some_and(|binding| report.target == binding.target)
        });
        self.error = None;
        self.notice = None;
        self.refresh(cx);
    }

    pub fn deactivate(&mut self, cx: &mut Context<Self>) {
        abort_task(&mut self.generation_abort);
        abort_task(&mut self.save_abort);
        self.model.deactivate();
        self.detection = None;
        cx.notify();
    }

    pub fn request_close(&mut self, cx: &mut Context<Self>) {
        cx.emit(DisposalReportEvent::CloseRequested);
    }

    fn current_binding(&self, cx: &Context<Self>) -> Option<ReportBinding> {
        ReportBinding::capture(self.shared.read(cx))
    }

    fn handle_shared_change(&mut self, cx: &mut Context<Self>) {
        if !self.model.active {
            return;
        }
        if self.current_binding(cx).as_ref() == self.model.binding.as_ref() {
            return;
        }
        abort_task(&mut self.generation_abort);
        abort_task(&mut self.save_abort);
        self.model.deactivate();
        cx.emit(DisposalReportEvent::CloseRequested);
    }

    fn refresh(&mut self, cx: &mut Context<Self>) {
        let current = self.current_binding(cx);
        let lease = match self.model.begin_request(current) {
            Ok(lease) => lease,
            Err(error) => {
                self.error = Some(format!("无法生成报告：{error}").into());
                cx.notify();
                return;
            }
        };
        abort_task(&mut self.generation_abort);
        self.error = None;
        self.notice = Some("正在汇总当前目标的审计与检测数据…".into());
        let service = self.services.report().clone();
        let target = lease.binding.target.clone();
        let label = lease.binding.label.clone();
        let detection = self.detection.clone();
        let task = self
            .tokio
            .spawn(async move { service.generate(&target, label, detection) });
        self.generation_abort = Some(task.abort_handle());
        cx.spawn(async move |overlay, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(overlay) = overlay.upgrade() {
                    overlay.update(cx, |overlay, cx| {
                        overlay.finish_refresh(lease, result, cx);
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_refresh(
        &mut self,
        lease: ReportLease,
        result: Result<CoreResult<DisposalReport>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        let current = self.current_binding(cx);
        match result {
            Ok(Ok(report)) => {
                if self.model.apply_report(&lease, current.as_ref(), report) {
                    self.generation_abort = None;
                    self.notice = Some("报告快照已生成；内容不含原始命令或凭据。".into());
                    self.error = None;
                    cx.notify();
                }
            }
            Err(error) if error.is_cancelled() => {}
            Ok(Err(error)) => {
                if self.model.reject(&lease, current.as_ref()) {
                    self.generation_abort = None;
                    self.error = Some(format!("报告生成失败：{error}").into());
                    self.notice = None;
                    cx.notify();
                }
            }
            Err(error) => {
                if self.model.reject(&lease, current.as_ref()) {
                    self.generation_abort = None;
                    self.error = Some(format!("报告任务失败：{error}").into());
                    self.notice = None;
                    cx.notify();
                }
            }
        }
    }

    fn set_preview(&mut self, preview: PreviewMode, cx: &mut Context<Self>) {
        self.model.preview = preview;
        cx.notify();
    }

    fn copy(&mut self, format: ReportFormat, cx: &mut Context<Self>) {
        let Some(report) = self.model.report.as_ref() else {
            return;
        };
        let text = match format {
            ReportFormat::Markdown => report.markdown.clone(),
            ReportFormat::Html => report.html.clone(),
        };
        cx.write_to_clipboard(ClipboardItem::new_string(text));
        self.notice = Some(format!("{} 已复制到剪贴板", format.label()).into());
        cx.notify();
    }

    fn choose_export_path(&mut self, format: ReportFormat, cx: &mut Context<Self>) {
        if self.model.saving || self.model.report.is_none() {
            return;
        }
        let initial = self
            .services
            .store()
            .root()
            .parent()
            .map_or_else(|| self.services.store().root().to_path_buf(), PathBuf::from);
        let suggested = format!(
            "LovelyRes-disposal-{}.{}",
            chrono::Utc::now().format("%Y%m%d-%H%M%S"),
            format.extension()
        );
        let activation_generation = self.model.activation_generation;
        let receiver = cx.prompt_for_new_path(&initial, Some(&suggested));
        cx.spawn(async move |overlay, cx| {
            let selected = match receiver.await {
                Ok(Ok(Some(path))) => path,
                Ok(Ok(None)) => return,
                Ok(Err(error)) => {
                    let message = error.to_string();
                    let _ = cx.update(|cx| {
                        if let Some(overlay) = overlay.upgrade() {
                            overlay.update(cx, |overlay, cx| {
                                if overlay.model.active
                                    && overlay.model.activation_generation == activation_generation
                                {
                                    overlay.error =
                                        Some(format!("保存路径选择失败：{message}").into());
                                    cx.notify();
                                }
                            });
                        }
                    });
                    return;
                }
                Err(error) => {
                    let message = error.to_string();
                    let _ = cx.update(|cx| {
                        if let Some(overlay) = overlay.upgrade() {
                            overlay.update(cx, |overlay, cx| {
                                if overlay.model.active
                                    && overlay.model.activation_generation == activation_generation
                                {
                                    overlay.error =
                                        Some(format!("保存路径选择已取消：{message}").into());
                                    cx.notify();
                                }
                            });
                        }
                    });
                    return;
                }
            };
            let _ = cx.update(|cx| {
                if let Some(overlay) = overlay.upgrade() {
                    overlay.update(cx, |overlay, cx| {
                        overlay.start_export(activation_generation, format, selected, cx);
                    });
                }
            });
        })
        .detach();
    }

    fn start_export(
        &mut self,
        activation_generation: u64,
        format: ReportFormat,
        destination: PathBuf,
        cx: &mut Context<Self>,
    ) {
        if !self.model.active
            || self.model.activation_generation != activation_generation
            || self.current_binding(cx).as_ref() != self.model.binding.as_ref()
        {
            return;
        }
        let Some(report) = self.model.report.clone() else {
            return;
        };
        abort_task(&mut self.save_abort);
        self.model.saving = true;
        self.error = None;
        self.notice = Some(format!("正在写入 {}…", destination.display()).into());
        let service = self.services.report().clone();
        let task = self.tokio.spawn(async move {
            service.write_new_export(&report, format, &destination)?;
            Ok::<_, CoreError>(destination)
        });
        self.save_abort = Some(task.abort_handle());
        cx.spawn(async move |overlay, cx| {
            let result = task.await;
            let _ = cx.update(|cx| {
                if let Some(overlay) = overlay.upgrade() {
                    overlay.update(cx, |overlay, cx| {
                        overlay.finish_export(activation_generation, result, cx);
                    });
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn finish_export(
        &mut self,
        activation_generation: u64,
        result: Result<CoreResult<PathBuf>, tokio::task::JoinError>,
        cx: &mut Context<Self>,
    ) {
        if !self.model.active
            || self.model.activation_generation != activation_generation
            || self.current_binding(cx).as_ref() != self.model.binding.as_ref()
        {
            return;
        }
        self.model.saving = false;
        self.save_abort = None;
        match result {
            Ok(Ok(path)) => {
                self.notice = Some(format!("报告已保存：{}", path.display()).into());
                self.error = None;
            }
            Ok(Err(error)) => {
                self.error = Some(format!("报告保存失败：{error}").into());
                self.notice = None;
            }
            Err(error) if error.is_cancelled() => return,
            Err(error) => {
                self.error = Some(format!("报告保存任务失败：{error}").into());
                self.notice = None;
            }
        }
        cx.notify();
    }
}

impl Render for DisposalReportOverlay {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens = self.shared.read(cx).theme.tokens();
        let report = self.model.report.clone();
        let loading = self.model.latest_request.is_some();
        let saving = self.model.saving;
        let preview = self.model.preview;
        let notice = self.notice.clone();
        let error = self.error.clone();
        let binding_label = self
            .model
            .binding
            .as_ref()
            .map(|binding| binding.label.clone())
            .unwrap_or_else(|| "未连接目标".to_owned());

        div()
            .id("disposal-report-overlay")
            .absolute()
            .inset_0()
            .p_4()
            .bg(tokens.background)
            .text_color(tokens.text)
            .flex()
            .flex_col()
            .gap_3()
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .child(
                                div()
                                    .text_2xl()
                                    .font_weight(gpui::FontWeight::SEMIBOLD)
                                    .child("处置交付报告"),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(tokens.muted)
                                    .child(binding_label),
                            ),
                    )
                    .child(
                        crate::buttons::button("disposal-report-refresh")
                            .label(if loading {
                                "生成中…"
                            } else {
                                "刷新快照"
                            })
                            .small()
                            .disabled(loading || saving)
                            .on_click(cx.listener(|this, _, _, cx| this.refresh(cx))),
                    )
                    .child(
                        crate::buttons::button("disposal-report-copy-markdown")
                            .label("复制 Markdown")
                            .small()
                            .disabled(report.is_none())
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.copy(ReportFormat::Markdown, cx);
                            })),
                    )
                    .child(
                        crate::buttons::button("disposal-report-save-markdown")
                            .label("保存 MD")
                            .small()
                            .disabled(report.is_none() || saving)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.choose_export_path(ReportFormat::Markdown, cx);
                            })),
                    )
                    .child(
                        crate::buttons::button("disposal-report-save-html")
                            .label("保存 HTML")
                            .small()
                            .disabled(report.is_none() || saving)
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.choose_export_path(ReportFormat::Html, cx);
                            })),
                    )
                    .child(
                        crate::buttons::close_button("disposal-report-close")
                            .small()
                            .on_click(cx.listener(|this, _, _, cx| this.request_close(cx))),
                    ),
            )
            .when_some(error, |root, message| {
                root.child(status_banner(message, tokens.danger, tokens))
            })
            .when_some(notice, |root, message| {
                root.child(status_banner(message, tokens.success, tokens))
            })
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_3()
                    .child(preview_button(
                        "disposal-report-summary-tab",
                        "摘要",
                        preview == PreviewMode::Summary,
                        PreviewMode::Summary,
                        cx,
                    ))
                    .child(preview_button(
                        "disposal-report-markdown-tab",
                        "Markdown 纯文本",
                        preview == PreviewMode::Markdown,
                        PreviewMode::Markdown,
                        cx,
                    ))
                    .child(preview_button(
                        "disposal-report-html-tab",
                        "HTML 源码",
                        preview == PreviewMode::Html,
                        PreviewMode::Html,
                        cx,
                    ))
                    .child(
                        div()
                            .text_xs()
                            .text_color(tokens.muted)
                            .child("预览始终按文本节点渲染，不执行 HTML 或远端内容"),
                    ),
            )
            .child(match report {
                Some(report) if preview == PreviewMode::Summary => summary_view(report, tokens),
                Some(report) => {
                    let text = if preview == PreviewMode::Markdown {
                        &report.markdown
                    } else {
                        &report.html
                    };
                    text_preview(text, tokens)
                }
                None => empty_view(
                    if loading {
                        "正在生成不可变报告快照…"
                    } else {
                        "尚无可预览报告"
                    },
                    tokens,
                ),
            })
    }
}

fn preview_button(
    id: &'static str,
    label: &'static str,
    selected: bool,
    mode: PreviewMode,
    cx: &mut Context<DisposalReportOverlay>,
) -> impl IntoElement {
    crate::buttons::button(id)
        .label(label)
        .small()
        .when(selected, ButtonVariants::primary)
        .on_click(cx.listener(move |this, _, _, cx| this.set_preview(mode, cx)))
}

fn status_banner(message: SharedString, color: gpui::Rgba, tokens: ThemeTokens) -> AnyElement {
    div()
        .rounded_md()
        .border_1()
        .border_color(color)
        .bg(tokens.surface)
        .px_3()
        .py_2()
        .text_sm()
        .text_color(color)
        .child(message)
        .into_any_element()
}

fn summary_view(report: Arc<DisposalReport>, tokens: ThemeTokens) -> AnyElement {
    let summary = &report.summary;
    let detection = report.snapshot.detection.as_ref().map_or_else(
        || "未附带快速检测".to_owned(),
        |detection| {
            let findings = detection
                .modules
                .iter()
                .map(|module| module.findings.len())
                .sum::<usize>();
            format!("可信评分 {} · {} 项发现", detection.overall_score, findings)
        },
    );
    div()
        .flex_1()
        .min_h_0()
        .overflow_y_scrollbar()
        .rounded_lg()
        .border_1()
        .border_color(tokens.border)
        .bg(tokens.surface)
        .p_4()
        .child(
            div()
                .grid()
                .grid_cols(6)
                .gap_3()
                .child(summary_card("审计操作", summary.total, tokens))
                .child(summary_card("成功", summary.succeeded, tokens))
                .child(summary_card("失败", summary.failed, tokens))
                .child(summary_card("已恢复", summary.restored, tokens))
                .child(summary_card("待核验", summary.uncertain, tokens))
                .child(summary_card("可恢复", summary.recoverable, tokens)),
        )
        .child(
            div()
                .mt_4()
                .text_sm()
                .child(format!("目标：{}", report.snapshot.target_label)),
        )
        .child(
            div()
                .mt_2()
                .text_sm()
                .child(format!("检测：{detection}")),
        )
        .child(
            div()
                .mt_2()
                .font_family("Cascadia Mono")
                .text_xs()
                .text_color(tokens.muted)
                .child(format!("快照 SHA-256：{}", report.snapshot_sha256)),
        )
        .child(
            div()
                .mt_4()
                .rounded_md()
                .bg(tokens.surface_alt)
                .p_3()
                .text_sm()
                .child("报告仅包含领域化摘要、验证结果与恢复说明；原始命令、凭据和任意 settings JSON 均不会导出。"),
        )
        .into_any_element()
}

fn summary_card(label: &'static str, value: usize, tokens: ThemeTokens) -> AnyElement {
    div()
        .rounded_md()
        .border_1()
        .border_color(tokens.border)
        .bg(tokens.surface_alt)
        .p_3()
        .child(div().text_xs().text_color(tokens.muted).child(label))
        .child(
            div()
                .mt_1()
                .text_xl()
                .font_weight(gpui::FontWeight::SEMIBOLD)
                .child(value.to_string()),
        )
        .into_any_element()
}

fn text_preview(text: &str, tokens: ThemeTokens) -> AnyElement {
    let (lines, truncated) = bounded_preview_lines(text);
    div()
        .flex_1()
        .min_h_0()
        .overflow_scrollbar()
        .rounded_lg()
        .border_1()
        .border_color(tokens.border)
        .bg(tokens.terminal_background)
        .p_3()
        .font_family("Cascadia Mono")
        .text_xs()
        .children(lines.into_iter().map(|line| {
            div().child(if line.is_empty() {
                " ".to_owned()
            } else {
                line
            })
        }))
        .when(truncated, |view| {
            view.child(
                div()
                    .mt_2()
                    .text_color(tokens.warning)
                    .child("预览已截断；复制和保存仍使用完整报告。"),
            )
        })
        .into_any_element()
}

fn bounded_preview_lines(text: &str) -> (Vec<String>, bool) {
    let mut lines = Vec::new();
    let mut chars = 0usize;
    let mut truncated = false;
    for line in text.lines() {
        let remaining = MAX_PREVIEW_CHARS.saturating_sub(chars);
        if lines.len() == MAX_PREVIEW_LINES || remaining == 0 {
            truncated = true;
            break;
        }
        let mut iter = line.chars();
        let bounded = iter.by_ref().take(remaining).collect::<String>();
        chars += bounded.chars().count();
        if iter.next().is_some() {
            truncated = true;
        }
        lines.push(bounded);
        if truncated {
            break;
        }
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    (lines, truncated)
}

fn empty_view(message: &'static str, tokens: ThemeTokens) -> AnyElement {
    div()
        .flex_1()
        .min_h_0()
        .rounded_lg()
        .border_1()
        .border_color(tokens.border)
        .bg(tokens.surface)
        .flex()
        .items_center()
        .justify_center()
        .text_color(tokens.muted)
        .child(message)
        .into_any_element()
}

fn abort_task(task: &mut Option<tokio::task::AbortHandle>) {
    if let Some(task) = task.take() {
        task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lovelyres_core::target::TargetIdentity;

    fn binding(id: &str, generation: u64) -> ReportBinding {
        ReportBinding {
            target: TargetGuard {
                identity: TargetIdentity::new(id).unwrap(),
                generation,
            },
            label: id.to_owned(),
        }
    }

    #[test]
    fn stale_target_and_lifecycle_leases_are_rejected() {
        let first = binding("target-a", 1);
        let mut model = DisposalReportModel::default();
        model.activate(Some(first.clone()));
        let lease = model.begin_request(Some(first.clone())).unwrap();
        assert!(model.accepts(&lease, Some(&first)));
        assert!(!model.accepts(&lease, Some(&binding("target-a", 2))));
        model.deactivate();
        assert!(!model.accepts(&lease, Some(&first)));
        model.activate(Some(first.clone()));
        assert!(!model.accepts(&lease, Some(&first)));
    }

    #[test]
    fn missing_target_cannot_begin_report() {
        let mut model = DisposalReportModel::default();
        model.activate(None);
        assert!(model.begin_request(None).is_err());
    }

    #[test]
    fn preview_is_bounded_by_lines_and_characters() {
        let text = (0..MAX_PREVIEW_LINES + 10)
            .map(|index| format!("line-{index}"))
            .collect::<Vec<_>>()
            .join("\n");
        let (lines, truncated) = bounded_preview_lines(&text);
        assert_eq!(lines.len(), MAX_PREVIEW_LINES);
        assert!(truncated);

        let oversized = "x".repeat(MAX_PREVIEW_CHARS + 10);
        let (lines, truncated) = bounded_preview_lines(&oversized);
        assert_eq!(lines[0].chars().count(), MAX_PREVIEW_CHARS);
        assert!(truncated);
    }

    #[test]
    fn hostile_markup_remains_literal_preview_text() {
        let hostile = "<script>alert(1)</script>\n<img src=x onerror=boom>";
        let (lines, truncated) = bounded_preview_lines(hostile);
        assert_eq!(
            lines,
            vec!["<script>alert(1)</script>", "<img src=x onerror=boom>"]
        );
        assert!(!truncated);
    }
}
