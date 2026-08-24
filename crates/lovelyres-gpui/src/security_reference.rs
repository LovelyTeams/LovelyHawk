use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

use gpui::{
    AnyElement, ClipboardItem, Context, Entity, IntoElement, Render, SharedString, Subscription,
    Window, div, prelude::*, px,
};
use gpui_component::{
    Selectable, Sizable,
    input::{Input, InputEvent, InputState},
    scroll::ScrollableElement,
};
use lovelyres_core::{
    BackendServices,
    settings::{SecurityReferenceSettings, is_security_reference_catalog_id},
};
use serde::Deserialize;

use crate::{app::SharedAppState, theme::ThemeTokens};

const EMBEDDED_CATALOG: &str = include_str!("../assets/security_reference.json");
const CATALOG_SCHEMA: &str = "lovelyres-security-reference/v1";
const FROZEN_SOURCE_SHA256: &str =
    "3a515486371b6d25b38aa6c5652ab589972434934bb90dc21a5696e9c8728b5d";
const LEGACY_SNIPPET_COUNT: usize = 107;
const LEGACY_LANGUAGE_COUNT: usize = 13;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct CatalogSource {
    pub path: String,
    pub sha256: String,
    pub snippet_count: usize,
    pub language_count: usize,
    pub language_counts: BTreeMap<String, usize>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct LanguageOption {
    pub key: String,
    pub label: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SecuritySnippet {
    pub id: String,
    pub lang: String,
    pub vuln: String,
    pub title: String,
    pub desc: String,
    pub bad: Option<String>,
    pub fix: String,
    pub oneliner: Option<String>,
    pub verify: Option<String>,
    pub cve: Option<String>,
    pub affected: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct SecurityReferenceCatalog {
    pub schema: String,
    pub source: CatalogSource,
    pub languages: Vec<LanguageOption>,
    pub snippets: Vec<SecuritySnippet>,
}

impl SecurityReferenceCatalog {
    pub fn parse(json: &str) -> Result<Self, String> {
        let catalog: Self = serde_json::from_str(json)
            .map_err(|error| format!("安全速查目录 JSON 无效：{error}"))?;
        catalog.validate()?;
        Ok(catalog)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != CATALOG_SCHEMA {
            return Err("安全速查目录 schema 不受支持".to_owned());
        }
        if self.source.path != "frozen/secfixData.ts"
            || self.source.sha256 != FROZEN_SOURCE_SHA256
            || self.source.snippet_count != LEGACY_SNIPPET_COUNT
            || self.source.language_count != LEGACY_LANGUAGE_COUNT
            || self.snippets.len() != LEGACY_SNIPPET_COUNT
            || self.languages.len() != LEGACY_LANGUAGE_COUNT
        {
            return Err("安全速查目录与冻结的 legacy 基线不一致".to_owned());
        }

        let mut language_keys = BTreeSet::new();
        for language in &self.languages {
            if language.key.is_empty()
                || language.label.is_empty()
                || !language_keys.insert(language.key.as_str())
            {
                return Err("安全速查语言登记为空或重复".to_owned());
            }
        }
        if self.languages.first().map(|language| language.key.as_str()) != Some("all") {
            return Err("安全速查语言登记必须以 all 开始".to_owned());
        }

        let concrete_languages: BTreeSet<_> = self
            .languages
            .iter()
            .filter(|language| language.key != "all")
            .map(|language| language.key.as_str())
            .collect();
        let mut snippet_ids = BTreeSet::new();
        let mut actual_counts = BTreeMap::<String, usize>::new();
        for snippet in &self.snippets {
            if snippet.id.is_empty()
                || snippet.lang.is_empty()
                || snippet.vuln.is_empty()
                || snippet.title.is_empty()
                || snippet.desc.is_empty()
                || snippet.fix.is_empty()
                || snippet.tags.is_empty()
            {
                return Err(format!("安全速查条目 {} 缺少必填字段", snippet.id));
            }
            if !is_security_reference_catalog_id(&snippet.id) {
                return Err(format!("安全速查条目 {} 不是冻结的稳定 ID", snippet.id));
            }
            if !snippet_ids.insert(snippet.id.as_str()) {
                return Err(format!("安全速查条目 ID 重复：{}", snippet.id));
            }
            if !concrete_languages.contains(snippet.lang.as_str()) {
                return Err(format!("安全速查条目 {} 引用了未知语言", snippet.id));
            }
            if snippet.tags.iter().any(|tag| tag.is_empty()) {
                return Err(format!("安全速查条目 {} 包含空标签", snippet.id));
            }
            *actual_counts.entry(snippet.lang.clone()).or_default() += 1;
        }
        if actual_counts != self.source.language_counts {
            return Err("安全速查语言统计与目录内容不一致".to_owned());
        }
        Ok(())
    }

    pub fn snippet(&self, id: &str) -> Option<&SecuritySnippet> {
        self.snippets.iter().find(|snippet| snippet.id == id)
    }
}

pub fn embedded_catalog() -> &'static SecurityReferenceCatalog {
    static CATALOG: OnceLock<SecurityReferenceCatalog> = OnceLock::new();
    CATALOG.get_or_init(|| {
        SecurityReferenceCatalog::parse(EMBEDDED_CATALOG)
            .expect("the embedded security reference catalog must pass its audit checks")
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClipboardField {
    Bad,
    Fix,
    Oneliner,
    Verify,
}

impl ClipboardField {
    const fn label(self) -> &'static str {
        match self {
            Self::Bad => "漏洞代码",
            Self::Fix => "修复代码",
            Self::Oneliner => "一键命令",
            Self::Verify => "验证命令",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClipboardIntent {
    pub text: String,
    pub notice: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnippetGroup {
    pub title: String,
    pub snippets: Vec<SecuritySnippet>,
}

#[derive(Debug)]
pub struct SecurityReferenceModel {
    catalog: &'static SecurityReferenceCatalog,
    current_language: String,
    query: String,
    favorites: BTreeSet<String>,
    favorites_only: bool,
    expanded_id: Option<String>,
    active: bool,
    activation_generation: u64,
}

impl SecurityReferenceModel {
    pub fn new(
        catalog: &'static SecurityReferenceCatalog,
        favorites: impl IntoIterator<Item = String>,
    ) -> Result<Self, String> {
        let favorites: BTreeSet<_> = favorites.into_iter().collect();
        if favorites.len() > 512 || favorites.iter().any(|id| catalog.snippet(id).is_none()) {
            return Err("收藏必须是目录中不超过 512 个稳定 ID".to_owned());
        }
        Ok(Self {
            catalog,
            current_language: "all".to_owned(),
            query: String::new(),
            favorites,
            favorites_only: false,
            expanded_id: None,
            active: false,
            activation_generation: 0,
        })
    }

    pub fn activate(&mut self) -> u64 {
        if !self.active {
            self.active = true;
            self.activation_generation = self.activation_generation.wrapping_add(1).max(1);
        }
        self.activation_generation
    }

    pub fn deactivate(&mut self) {
        self.active = false;
    }

    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub const fn activation_generation(&self) -> u64 {
        self.activation_generation
    }

    pub fn set_language(&mut self, language: &str) -> bool {
        if self
            .catalog
            .languages
            .iter()
            .any(|option| option.key == language)
        {
            self.current_language = language.to_owned();
            true
        } else {
            false
        }
    }

    pub fn set_query(&mut self, query: impl Into<String>) {
        self.query = query.into();
    }

    pub fn toggle_favorites_only(&mut self) {
        self.favorites_only = !self.favorites_only;
    }

    pub fn toggle_expanded(&mut self, id: &str) -> bool {
        if self.catalog.snippet(id).is_none() {
            return false;
        }
        if self.expanded_id.as_deref() == Some(id) {
            self.expanded_id = None;
        } else {
            self.expanded_id = Some(id.to_owned());
        }
        true
    }

    pub fn toggle_favorite(&mut self, id: &str) -> Result<bool, String> {
        if self.catalog.snippet(id).is_none() {
            return Err("无法收藏未知目录条目".to_owned());
        }
        if self.favorites.remove(id) {
            return Ok(false);
        }
        if self.favorites.len() >= 512 {
            return Err("收藏数量不能超过 512".to_owned());
        }
        self.favorites.insert(id.to_owned());
        Ok(true)
    }

    pub fn replace_favorites(&mut self, favorites: BTreeSet<String>) {
        self.favorites = favorites;
    }

    pub fn favorite_ids(&self) -> Vec<String> {
        self.favorites.iter().cloned().collect()
    }

    pub fn filtered(&self) -> Vec<SecuritySnippet> {
        let query = self.query.trim().to_lowercase();
        let mut snippets: Vec<_> = self
            .catalog
            .snippets
            .iter()
            .filter(|snippet| {
                (!self.favorites_only || self.favorites.contains(&snippet.id))
                    && (self.current_language == "all" || snippet.lang == self.current_language)
                    && (query.is_empty() || snippet_matches(snippet, &query))
            })
            .cloned()
            .collect();
        snippets.sort_by_key(|snippet| !self.favorites.contains(&snippet.id));
        snippets
    }

    pub fn groups(&self) -> Vec<SnippetGroup> {
        let mut groups = Vec::<SnippetGroup>::new();
        for snippet in self.filtered() {
            let title = format!("{} — {}", snippet.lang, snippet.vuln);
            if let Some(group) = groups.iter_mut().find(|group| group.title == title) {
                group.snippets.push(snippet);
            } else {
                groups.push(SnippetGroup {
                    title,
                    snippets: vec![snippet],
                });
            }
        }
        groups
    }

    pub fn is_favorite(&self, id: &str) -> bool {
        self.favorites.contains(id)
    }

    pub fn is_expanded(&self, id: &str) -> bool {
        self.expanded_id.as_deref() == Some(id)
    }

    pub fn copy_intent(&self, id: &str, field: ClipboardField) -> Option<ClipboardIntent> {
        let snippet = self.catalog.snippet(id)?;
        let text = match field {
            ClipboardField::Bad => snippet.bad.as_deref(),
            ClipboardField::Fix => Some(snippet.fix.as_str()),
            ClipboardField::Oneliner => snippet.oneliner.as_deref(),
            ClipboardField::Verify => snippet.verify.as_deref(),
        }?;
        Some(ClipboardIntent {
            text: text.to_owned(),
            notice: format!("已复制{}到剪贴板", field.label()),
        })
    }

    pub fn export_oneliners(&self, generated_at: &str) -> ClipboardIntent {
        let snippets = self.filtered();
        let count = snippets
            .iter()
            .filter(|snippet| snippet.oneliner.is_some())
            .count();
        let mut lines = vec![
            "# === LovelyRes SecFix Oneliners ===".to_owned(),
            format!(
                "# 筛选: lang={} query=\"{}\" favOnly={}",
                self.current_language, self.query, self.favorites_only
            ),
            format!("# 导出时间: {generated_at}"),
            format!("# 共 {count} 条 oneliner"),
            String::new(),
        ];
        for snippet in snippets {
            let Some(oneliner) = snippet.oneliner else {
                continue;
            };
            let cve = snippet
                .cve
                .map(|cve| format!(" ({cve})"))
                .unwrap_or_default();
            lines.push(format!(
                "# ---- {} / {}{} ----",
                snippet.lang, snippet.title, cve
            ));
            lines.push(oneliner);
            lines.push(String::new());
        }
        ClipboardIntent {
            text: lines.join("\n"),
            notice: format!("已导出 {count} 条 oneliner 到剪贴板（未执行）"),
        }
    }
}

fn snippet_matches(snippet: &SecuritySnippet, query: &str) -> bool {
    snippet.title.to_lowercase().contains(query)
        || snippet.vuln.to_lowercase().contains(query)
        || snippet.desc.to_lowercase().contains(query)
        || snippet
            .cve
            .as_deref()
            .is_some_and(|value| value.to_lowercase().contains(query))
        || snippet
            .affected
            .as_deref()
            .is_some_and(|value| value.to_lowercase().contains(query))
        || snippet
            .tags
            .iter()
            .any(|tag| tag.to_lowercase().contains(query))
        || snippet.fix.to_lowercase().contains(query)
}

pub struct SecurityReferencePage {
    services: Arc<BackendServices>,
    shared: Entity<SharedAppState>,
    model: SecurityReferenceModel,
    search_input: Entity<InputState>,
    notice: Option<(SharedString, bool)>,
    _subscriptions: Vec<Subscription>,
}

impl SecurityReferencePage {
    pub fn new(
        services: Arc<BackendServices>,
        shared: Entity<SharedAppState>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let (favorite_ids, notice) = match services.settings().load() {
            Ok(settings) => (settings.security_reference.favorite_ids, None),
            Err(error) => (
                Vec::new(),
                Some((format!("收藏读取失败：{error}").into(), true)),
            ),
        };
        let model = SecurityReferenceModel::new(embedded_catalog(), favorite_ids)
            .expect("typed settings only contain audited security reference IDs");
        let search_input =
            cx.new(|cx| InputState::new(window, cx).placeholder("搜索漏洞、CVE、标签或修复内容…"));
        let subscriptions = vec![cx.subscribe_in(
            &search_input,
            window,
            |page, input, event: &InputEvent, _, cx| {
                if matches!(event, InputEvent::Change) {
                    page.model.set_query(input.read(cx).value().to_string());
                    cx.notify();
                }
            },
        )];
        Self {
            services,
            shared,
            model,
            search_input,
            notice,
            _subscriptions: subscriptions,
        }
    }

    pub fn activate(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.model.activate();
        self.search_input.update(cx, |input, cx| {
            input.focus(window, cx);
        });
        cx.notify();
    }

    pub fn deactivate(&mut self, cx: &mut Context<Self>) {
        self.model.deactivate();
        cx.notify();
    }

    fn select_language(&mut self, language: &str, cx: &mut Context<Self>) {
        if self.model.set_language(language) {
            cx.notify();
        }
    }

    fn toggle_favorites_only(&mut self, cx: &mut Context<Self>) {
        self.model.toggle_favorites_only();
        cx.notify();
    }

    fn toggle_expanded(&mut self, id: &str, cx: &mut Context<Self>) {
        if self.model.toggle_expanded(id) {
            cx.notify();
        }
    }

    fn toggle_favorite(&mut self, id: &str, cx: &mut Context<Self>) {
        let previous = self.model.favorites.clone();
        let is_favorite = match self.model.toggle_favorite(id) {
            Ok(is_favorite) => is_favorite,
            Err(error) => {
                self.notice = Some((error.into(), true));
                cx.notify();
                return;
            }
        };
        let favorite_ids = self.model.favorite_ids();
        let result = self.services.settings().update(|settings| {
            settings.security_reference = SecurityReferenceSettings { favorite_ids };
            Ok(())
        });
        match result {
            Ok(_) => {
                let message = if is_favorite {
                    "已收藏并置顶"
                } else {
                    "已取消收藏"
                };
                self.notice = Some((message.into(), false));
            }
            Err(error) => {
                self.model.replace_favorites(previous);
                self.notice = Some((format!("收藏保存失败：{error}").into(), true));
            }
        }
        cx.notify();
    }

    fn copy(&mut self, id: &str, field: ClipboardField, cx: &mut Context<Self>) {
        match self.model.copy_intent(id, field) {
            Some(intent) => self.write_clipboard(intent, cx),
            None => {
                self.notice = Some(("该条目没有对应内容".into(), true));
                cx.notify();
            }
        }
    }

    fn export(&mut self, cx: &mut Context<Self>) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let intent = self.model.export_oneliners(&format!("unix-ms={timestamp}"));
        self.write_clipboard(intent, cx);
    }

    fn write_clipboard(&mut self, intent: ClipboardIntent, cx: &mut Context<Self>) {
        cx.write_to_clipboard(ClipboardItem::new_string(intent.text));
        self.notice = Some((intent.notice.into(), false));
        cx.notify();
    }
}

impl Render for SecurityReferencePage {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let tokens = self.shared.read(cx).theme.tokens();
        let groups = self.model.groups();
        let visible_count: usize = groups.iter().map(|group| group.snippets.len()).sum();
        let languages = self.model.catalog.languages.clone();
        let current_language = self.model.current_language.clone();
        let favorites_only = self.model.favorites_only;
        let favorite_count = self.model.favorites.len();
        let favorites = self.model.favorites.clone();
        let expanded_id = self.model.expanded_id.clone();
        let notice = self.notice.clone();

        div()
            .id("security-reference-page")
            .flex()
            .flex_col()
            .gap_4()
            .child(
                div()
                    .child(div().text_2xl().mb_2().child("安全速查"))
                    .child(
                        div()
                            .text_sm()
                            .text_color(tokens.muted)
                            .child("107 条离线修复参考；命令内容仅支持复制，不连接目标、不执行。"),
                    ),
            )
            .child(
                div()
                    .rounded_lg()
                    .border_1()
                    .border_color(tokens.border)
                    .bg(tokens.surface)
                    .p_3()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .gap_2()
                            .children(languages.into_iter().map(|language| {
                                let language_key = language.key.clone();
                                crate::buttons::button(SharedString::from(format!(
                                    "security-reference-language-{}",
                                    language.key
                                )))
                                .label(language.label)
                                .small()
                                .selected(current_language == language.key)
                                .on_click(cx.listener(
                                    move |this, _, _, cx| this.select_language(&language_key, cx),
                                ))
                            })),
                    )
                    .child(
                        div()
                            .flex()
                            .flex_wrap()
                            .items_center()
                            .gap_2()
                            .child(
                                div()
                                    .w(px(360.0))
                                    .max_w_full()
                                    .child(Input::new(&self.search_input).small()),
                            )
                            .child(
                                crate::buttons::button("security-reference-favorites-only")
                                    .label(format!("仅收藏 ({favorite_count})"))
                                    .small()
                                    .selected(favorites_only)
                                    .on_click(
                                        cx.listener(|this, _, _, cx| {
                                            this.toggle_favorites_only(cx)
                                        }),
                                    ),
                            )
                            .child(
                                crate::buttons::button("security-reference-export")
                                    .label("复制当前筛选 oneliners")
                                    .small()
                                    .on_click(cx.listener(|this, _, _, cx| this.export(cx))),
                            )
                            .child(
                                div()
                                    .ml_auto()
                                    .text_sm()
                                    .text_color(tokens.muted)
                                    .child(format!("当前 {visible_count} 条")),
                            ),
                    ),
            )
            .when_some(notice, |page, (message, is_error)| {
                page.child(
                    div()
                        .rounded_md()
                        .border_1()
                        .border_color(if is_error {
                            tokens.danger
                        } else {
                            tokens.success
                        })
                        .p_3()
                        .text_sm()
                        .text_color(if is_error {
                            tokens.danger
                        } else {
                            tokens.success
                        })
                        .child(message),
                )
            })
            .when(groups.is_empty(), |page| {
                page.child(
                    div()
                        .rounded_lg()
                        .border_1()
                        .border_color(tokens.border)
                        .bg(tokens.surface)
                        .p_6()
                        .text_center()
                        .text_color(tokens.muted)
                        .child("未找到匹配的修复代码"),
                )
            })
            .children(groups.into_iter().map(|group| {
                div()
                    .id(SharedString::from(format!(
                        "security-reference-group-{}",
                        group.title
                    )))
                    .child(
                        div()
                            .mb_2()
                            .text_sm()
                            .text_color(tokens.muted)
                            .child(group.title),
                    )
                    .children(group.snippets.into_iter().map(|snippet| {
                        let is_favorite = favorites.contains(&snippet.id);
                        let is_expanded = expanded_id.as_deref() == Some(&snippet.id);
                        security_snippet_card(snippet, is_favorite, is_expanded, tokens, cx)
                    }))
            }))
    }
}

fn security_snippet_card(
    snippet: SecuritySnippet,
    is_favorite: bool,
    is_expanded: bool,
    tokens: ThemeTokens,
    cx: &mut Context<SecurityReferencePage>,
) -> AnyElement {
    let favorite_id = snippet.id.clone();
    let expand_id = snippet.id.clone();
    let copy_fix_id = snippet.id.clone();
    let copy_oneliner_id = snippet.id.clone();
    let copy_verify_id = snippet.id.clone();
    let card_id = snippet.id.clone();
    div()
        .id(SharedString::from(format!(
            "security-reference-card-{card_id}"
        )))
        .mb_2()
        .rounded_lg()
        .border_1()
        .border_color(if is_favorite {
            tokens.accent
        } else {
            tokens.border
        })
        .bg(tokens.surface)
        .p_3()
        .child(
            div()
                .flex()
                .flex_wrap()
                .items_center()
                .gap_2()
                .child(
                    crate::buttons::button(SharedString::from(format!(
                        "security-reference-favorite-{}",
                        snippet.id
                    )))
                    .label(if is_favorite { "★" } else { "☆" })
                    .xsmall()
                    .selected(is_favorite)
                    .on_click(
                        cx.listener(move |this, _, _, cx| this.toggle_favorite(&favorite_id, cx)),
                    ),
                )
                .child(
                    div()
                        .rounded_sm()
                        .bg(tokens.surface_alt)
                        .px_2()
                        .py_1()
                        .text_xs()
                        .child(snippet.lang.clone()),
                )
                .child(div().flex_1().min_w(px(220.0)).child(snippet.title.clone()))
                .when_some(snippet.cve.clone(), |header, cve| {
                    header.child(
                        div()
                            .rounded_sm()
                            .border_1()
                            .border_color(tokens.warning)
                            .px_2()
                            .py_1()
                            .text_xs()
                            .text_color(tokens.warning)
                            .child(cve),
                    )
                })
                .when(snippet.oneliner.is_some(), |header| {
                    header.child(
                        crate::buttons::button(SharedString::from(format!(
                            "security-reference-copy-oneliner-{}",
                            snippet.id
                        )))
                        .label("复制命令（不执行）")
                        .xsmall()
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.copy(&copy_oneliner_id, ClipboardField::Oneliner, cx)
                        })),
                    )
                })
                .when(snippet.verify.is_some(), |header| {
                    header.child(
                        crate::buttons::button(SharedString::from(format!(
                            "security-reference-copy-verify-{}",
                            snippet.id
                        )))
                        .label("复制验证")
                        .xsmall()
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.copy(&copy_verify_id, ClipboardField::Verify, cx)
                        })),
                    )
                })
                .child(
                    crate::buttons::button(SharedString::from(format!(
                        "security-reference-copy-fix-{}",
                        snippet.id
                    )))
                    .label("复制修复")
                    .xsmall()
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.copy(&copy_fix_id, ClipboardField::Fix, cx)
                    })),
                )
                .child(
                    crate::buttons::button(SharedString::from(format!(
                        "security-reference-expand-{}",
                        snippet.id
                    )))
                    .label(if is_expanded { "收起" } else { "展开" })
                    .xsmall()
                    .on_click(
                        cx.listener(move |this, _, _, cx| this.toggle_expanded(&expand_id, cx)),
                    ),
                ),
        )
        .child(
            div()
                .mt_2()
                .text_sm()
                .text_color(tokens.muted)
                .child(snippet.desc.clone()),
        )
        .when(is_expanded, |card| {
            card.child(expanded_snippet(snippet, tokens, cx))
        })
        .into_any_element()
}

fn expanded_snippet(
    snippet: SecuritySnippet,
    tokens: ThemeTokens,
    cx: &mut Context<SecurityReferencePage>,
) -> AnyElement {
    let colors = ExpandedSnippetColors::from_tokens(tokens);
    let bad_id = snippet.id.clone();
    let fix_id = snippet.id.clone();
    let oneliner_id = snippet.id.clone();
    let verify_id = snippet.id.clone();
    div()
        .mt_3()
        .pt_3()
        .border_t_1()
        .border_color(tokens.border)
        .when_some(snippet.cve, |content, cve| {
            content.child(metadata_row("CVE", cve, colors))
        })
        .when_some(snippet.affected, |content, affected| {
            content.child(metadata_row("受影响", affected, colors))
        })
        .when_some(snippet.bad, |content, bad| {
            content.child(code_section(
                "[ BAD ] 漏洞代码",
                bad,
                bad_id,
                ClipboardField::Bad,
                tokens.danger,
                tokens,
                colors,
                cx,
            ))
        })
        .child(code_section(
            "[ FIX ] 修复代码",
            snippet.fix,
            fix_id,
            ClipboardField::Fix,
            tokens.success,
            tokens,
            colors,
            cx,
        ))
        .when_some(snippet.oneliner, |content, oneliner| {
            content.child(code_section(
                "[ CMD ] 一键修复 / 查找命令（仅复制）",
                oneliner,
                oneliner_id,
                ClipboardField::Oneliner,
                tokens.warning,
                tokens,
                colors,
                cx,
            ))
        })
        .when_some(snippet.verify, |content, verify| {
            content.child(code_section(
                "[ VERIFY ] 修复后验证（仅复制）",
                verify,
                verify_id,
                ClipboardField::Verify,
                tokens.accent,
                tokens,
                colors,
                cx,
            ))
        })
        .child(
            div()
                .mt_2()
                .flex()
                .flex_wrap()
                .gap_1()
                .children(snippet.tags.into_iter().map(|tag| {
                    div()
                        .rounded_sm()
                        .bg(tokens.surface_alt)
                        .px_2()
                        .py_1()
                        .text_xs()
                        .text_color(colors.tag_text)
                        .child(tag)
                })),
        )
        .into_any_element()
}

#[derive(Clone, Copy, Debug)]
struct ExpandedSnippetColors {
    metadata_label: gpui::Rgba,
    metadata_value: gpui::Rgba,
    tag_text: gpui::Rgba,
    code_text: gpui::Rgba,
}

impl ExpandedSnippetColors {
    fn from_tokens(tokens: ThemeTokens) -> Self {
        Self {
            metadata_label: tokens.muted,
            metadata_value: tokens.text,
            tag_text: tokens.text,
            code_text: higher_contrast_color(
                tokens.text,
                tokens.surface,
                tokens.terminal_background,
            ),
        }
    }
}

fn metadata_row(
    label: &'static str,
    value: String,
    colors: ExpandedSnippetColors,
) -> impl IntoElement {
    div()
        .mb_2()
        .flex()
        .gap_3()
        .text_sm()
        .child(
            div()
                .w(px(76.0))
                .flex_none()
                .text_color(colors.metadata_label)
                .child(label),
        )
        .child(div().text_color(colors.metadata_value).child(value))
}

#[allow(clippy::too_many_arguments)]
fn code_section(
    label: &'static str,
    text: String,
    snippet_id: String,
    field: ClipboardField,
    accent: gpui::Rgba,
    tokens: ThemeTokens,
    colors: ExpandedSnippetColors,
    cx: &mut Context<SecurityReferencePage>,
) -> AnyElement {
    let button_id = format!("security-reference-code-copy-{snippet_id}-{field:?}");
    let copy_id = snippet_id.clone();
    div()
        .mt_3()
        .child(
            div()
                .mb_1()
                .flex()
                .items_center()
                .justify_between()
                .text_xs()
                .text_color(readable_color(
                    accent,
                    tokens.surface,
                    colors.metadata_value,
                ))
                .child(label)
                .child(
                    crate::buttons::button(SharedString::from(button_id))
                        .label("复制")
                        .xsmall()
                        .on_click(
                            cx.listener(move |this, _, _, cx| this.copy(&copy_id, field, cx)),
                        ),
                ),
        )
        .child(
            div()
                .rounded_md()
                .border_1()
                .border_color(tokens.border)
                .bg(tokens.terminal_background)
                .p_3()
                .font_family("Cascadia Mono")
                .text_xs()
                .text_color(colors.code_text)
                .overflow_x_scrollbar()
                .children(text.split('\n').map(|line| {
                    div().child(if line.is_empty() {
                        " ".to_owned()
                    } else {
                        line.to_owned()
                    })
                })),
        )
        .into_any_element()
}

const MINIMUM_TEXT_CONTRAST: f32 = 4.5;

fn readable_color(
    preferred: gpui::Rgba,
    background: gpui::Rgba,
    fallback: gpui::Rgba,
) -> gpui::Rgba {
    if contrast_ratio(preferred, background) >= MINIMUM_TEXT_CONTRAST {
        preferred
    } else {
        fallback
    }
}

fn higher_contrast_color(
    first: gpui::Rgba,
    second: gpui::Rgba,
    background: gpui::Rgba,
) -> gpui::Rgba {
    if contrast_ratio(first, background) >= contrast_ratio(second, background) {
        first
    } else {
        second
    }
}

fn contrast_ratio(first: gpui::Rgba, second: gpui::Rgba) -> f32 {
    let first = relative_luminance(first);
    let second = relative_luminance(second);
    (first.max(second) + 0.05) / (first.min(second) + 0.05)
}

fn relative_luminance(color: gpui::Rgba) -> f32 {
    fn linearize(channel: f32) -> f32 {
        if channel <= 0.04045 {
            channel / 12.92
        } else {
            ((channel + 0.055) / 1.055).powf(2.4)
        }
    }

    0.2126 * linearize(color.r) + 0.7152 * linearize(color.g) + 0.0722 * linearize(color.b)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use gpui::{Focusable as _, TestAppContext};
    use uuid::Uuid;

    use super::*;
    use lovelyres_core::PortableStore;

    #[test]
    fn embedded_catalog_matches_legacy_count_languages_ids_and_source() {
        let catalog = embedded_catalog();
        assert_eq!(catalog.snippets.len(), 107);
        assert_eq!(catalog.languages.len(), 13);
        assert_eq!(catalog.source.language_counts.values().sum::<usize>(), 107);
        let expected_languages = [
            "all",
            "应急",
            "中间件",
            "CMS",
            "Shell",
            "Python",
            "PHP",
            "Java",
            "JavaScript",
            "Go",
            "C/C++",
            "SQL",
            "K8s/容器",
        ];
        assert_eq!(
            catalog
                .languages
                .iter()
                .map(|language| language.key.as_str())
                .collect::<Vec<_>>(),
            expected_languages
        );
        let ids: BTreeSet<_> = catalog
            .snippets
            .iter()
            .map(|snippet| snippet.id.as_str())
            .collect();
        assert_eq!(ids.len(), catalog.snippets.len());
        assert!(ids.iter().all(|id| is_security_reference_catalog_id(id)));

        assert_eq!(catalog.source.sha256, FROZEN_SOURCE_SHA256);

        let raw: serde_json::Value = serde_json::from_str(EMBEDDED_CATALOG).unwrap();
        let expected_fields = BTreeSet::from([
            "id", "lang", "vuln", "title", "desc", "bad", "fix", "oneliner", "verify", "cve",
            "affected", "tags",
        ]);
        for snippet in raw["snippets"].as_array().unwrap() {
            let actual_fields: BTreeSet<_> = snippet
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(actual_fields, expected_fields);
        }
    }

    #[test]
    fn search_covers_cve_tags_and_fix_content() {
        let mut model = SecurityReferenceModel::new(embedded_catalog(), []).unwrap();
        model.set_query("cve-2021-44228");
        assert_eq!(model.filtered()[0].id, "java-log4j");
        model.set_query("webshell查杀");
        assert!(
            model
                .filtered()
                .iter()
                .any(|snippet| snippet.id == "php-backdoor")
        );
        model.set_query("PreparedStatement ps = conn.prepareStatement");
        assert_eq!(model.filtered()[0].id, "java-sqli");
    }

    #[test]
    fn favorites_are_pinned_filterable_and_state_survives_lifecycle() {
        let mut model = SecurityReferenceModel::new(
            embedded_catalog(),
            ["java-log4j".to_owned(), "py-sqli".to_owned()],
        )
        .unwrap();
        model.set_language("Python");
        model.set_query("sql");
        model.toggle_expanded("py-sqli");
        assert_eq!(model.activate(), 1);
        model.deactivate();
        assert!(!model.is_active());
        assert!(model.is_expanded("py-sqli"));
        assert_eq!(model.filtered()[0].id, "py-sqli");

        model.toggle_favorites_only();
        assert_eq!(
            model
                .filtered()
                .iter()
                .map(|snippet| snippet.id.as_str())
                .collect::<Vec<_>>(),
            ["py-sqli"]
        );
    }

    #[test]
    fn export_uses_current_filter_and_clipboard_intents_are_copy_only() {
        let mut model = SecurityReferenceModel::new(embedded_catalog(), []).unwrap();
        model.set_language("C/C++");
        model.set_query("格式化字符串");
        let export = model.export_oneliners("fixed-time");
        assert!(export.text.contains("# 导出时间: fixed-time"));
        assert!(export.text.contains("C/C++ / 格式化字符串漏洞"));
        assert!(!export.text.contains("Python /"));

        let intent = model
            .copy_intent("java-log4j", ClipboardField::Fix)
            .unwrap();
        assert!(intent.text.contains("log4j2.formatMsgNoLookups"));
        assert!(
            model
                .copy_intent("py-sqli", ClipboardField::Verify)
                .is_none()
        );
    }

    #[test]
    fn page_source_has_no_remote_action_path() {
        let source = include_str!("security_reference.rs").to_lowercase();
        let forbidden = [
            ["exec", "ute_command"].concat(),
            ["run", "_command"].concat(),
            ["terminal", "transport"].concat(),
            ["planned", "operation"].concat(),
        ];
        for token in forbidden {
            assert!(!source.contains(&token), "forbidden action path: {token}");
        }
    }

    #[test]
    fn expanded_content_foregrounds_meet_contrast_in_every_theme() {
        for theme in crate::theme::ThemeId::ALL {
            let tokens = theme.tokens();
            let colors = ExpandedSnippetColors::from_tokens(tokens);
            let pairs = [
                ("metadata label", colors.metadata_label, tokens.surface),
                ("metadata value", colors.metadata_value, tokens.surface),
                ("tag", colors.tag_text, tokens.surface_alt),
                ("code", colors.code_text, tokens.terminal_background),
            ];
            for (role, foreground, background) in pairs {
                let ratio = contrast_ratio(foreground, background);
                assert!(
                    ratio >= MINIMUM_TEXT_CONTRAST,
                    "{} {role} contrast was {ratio:.2}:1",
                    theme.label()
                );
            }

            for (role, accent) in [
                ("bad", tokens.danger),
                ("fix", tokens.success),
                ("command", tokens.warning),
                ("verify", tokens.accent),
            ] {
                let foreground = readable_color(accent, tokens.surface, tokens.text);
                let ratio = contrast_ratio(foreground, tokens.surface);
                assert!(
                    ratio >= MINIMUM_TEXT_CONTRAST,
                    "{} {role} label contrast was {ratio:.2}:1",
                    theme.label()
                );
            }
        }
    }

    #[test]
    fn expanded_content_applies_explicit_foreground_colors() {
        let source = include_str!("security_reference.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for marker in [
            ".text_color(colors.metadata_label)",
            ".text_color(colors.metadata_value)",
            ".text_color(colors.tag_text)",
            ".text_color(colors.code_text)",
        ] {
            assert!(
                production.contains(marker),
                "missing foreground marker: {marker}"
            );
        }
    }

    #[gpui::test]
    fn native_page_focuses_search_and_retains_state_across_deactivation(cx: &mut TestAppContext) {
        let root =
            std::env::temp_dir().join(format!("lovelyres-security-reference-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let services =
            Arc::new(BackendServices::new(PortableStore::prepare(root.clone()).unwrap()).unwrap());
        cx.update(gpui_component::init);
        let page_slot = Arc::new(std::sync::Mutex::new(None));
        let window = cx.update(|cx| {
            let services = services.clone();
            let page_slot = page_slot.clone();
            cx.open_window(Default::default(), |window, cx| {
                let shared = cx.new(|_| SharedAppState::default());
                let page = cx.new(|cx| SecurityReferencePage::new(services, shared, window, cx));
                *page_slot.lock().unwrap() = Some(page.clone());
                cx.new(|cx| gpui_component::Root::new(page, window, cx))
            })
            .unwrap()
        });
        let page = page_slot.lock().unwrap().take().unwrap();

        window
            .update(cx, |_, window, cx| {
                page.update(cx, |page, cx| {
                    page.model.set_query("log4j");
                    page.activate(window, cx);
                    assert!(page.search_input.focus_handle(cx).is_focused(window));
                    page.deactivate(cx);
                    assert_eq!(page.model.query, "log4j");
                    assert!(!page.model.is_active());
                });
            })
            .unwrap();
        let _ = fs::remove_dir_all(root);
    }
}
