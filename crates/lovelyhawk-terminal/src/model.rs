use std::collections::VecDeque;
use std::sync::Arc;

use alacritty_terminal::Term;
use alacritty_terminal::event::{Event, EventListener};
use alacritty_terminal::grid::{Dimensions, Scroll};
use alacritty_terminal::index::{Column, Line, Point, Side};
use alacritty_terminal::selection::{Selection, SelectionType};
use alacritty_terminal::term::cell::Flags;
use alacritty_terminal::term::{Config as AlacrittyConfig, Osc52, TermMode};
use alacritty_terminal::vte::ansi::{Color, CursorShape, Processor};
use parking_lot::Mutex;
use regex::RegexBuilder;
use thiserror::Error;
use unicode_width::UnicodeWidthStr;
use url::Url;

use crate::{
    MouseEncoding, MouseProtocol, MouseTrackingMode, TerminalConfig, TerminalConfigError,
    TerminalSize,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelEvent {
    TitleChanged(String),
    TitleReset,
    Bell,
    Wakeup,
    ExitRequested,
    ChildExited(i32),
    PtyWrite(Vec<u8>),
    ClipboardStore { kind: String, text: String },
    ClipboardWriteRejected { bytes: usize },
    ClipboardLoadRequested { kind: String },
    ColorRequested { index: usize },
    TextAreaSizeRequested,
    CursorChanged,
}

/// Controls whether a remote OSC 52 sequence may write the local clipboard.
///
/// Reading the local clipboard through OSC 52 is always disabled in this crate.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OscClipboardPolicy {
    #[default]
    DenyRemoteWrite,
    AllowRemoteWrite {
        max_bytes: usize,
    },
}

#[derive(Clone, Default)]
struct ModelEventProxy {
    pending: Arc<Mutex<VecDeque<ModelEvent>>>,
}

impl ModelEventProxy {
    fn drain(&self) -> Vec<ModelEvent> {
        self.pending.lock().drain(..).collect()
    }
}

impl EventListener for ModelEventProxy {
    fn send_event(&self, event: Event) {
        let translated = match event {
            Event::Title(title) => ModelEvent::TitleChanged(title),
            Event::ResetTitle => ModelEvent::TitleReset,
            Event::ClipboardStore(kind, text) => ModelEvent::ClipboardStore {
                kind: format!("{kind:?}"),
                text,
            },
            Event::ClipboardLoad(kind, _) => ModelEvent::ClipboardLoadRequested {
                kind: format!("{kind:?}"),
            },
            Event::ColorRequest(index, _) => ModelEvent::ColorRequested { index },
            Event::PtyWrite(text) => ModelEvent::PtyWrite(text.into_bytes()),
            Event::TextAreaSizeRequest(_) => ModelEvent::TextAreaSizeRequested,
            Event::CursorBlinkingChange | Event::MouseCursorDirty => ModelEvent::CursorChanged,
            Event::Wakeup => ModelEvent::Wakeup,
            Event::Bell => ModelEvent::Bell,
            Event::Exit => ModelEvent::ExitRequested,
            Event::ChildExit(code) => ModelEvent::ChildExited(code),
        };
        self.pending.lock().push_back(translated);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedReport {
    pub bytes_processed: usize,
    pub model_events: Vec<ModelEvent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CellPosition {
    pub row: u16,
    pub column: u16,
}

impl CellPosition {
    pub const fn new(row: u16, column: u16) -> Self {
        Self { row, column }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CellColor {
    Named(String),
    Indexed(u8),
    Rgb(u8, u8, u8),
}

impl From<Color> for CellColor {
    fn from(color: Color) -> Self {
        match color {
            Color::Named(color) => Self::Named(format!("{color:?}")),
            Color::Indexed(index) => Self::Indexed(index),
            Color::Spec(rgb) => Self::Rgb(rgb.r, rgb.g, rgb.b),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalCell {
    pub character: char,
    pub combining: Vec<char>,
    pub foreground: CellColor,
    pub background: CellColor,
    pub wide: bool,
    pub wide_spacer: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalCursorShape {
    Block,
    Underline,
    Beam,
    HollowBlock,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderCursor {
    pub row: u16,
    pub column: u16,
    pub shape: TerminalCursorShape,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderCell {
    pub row: u16,
    pub column: u16,
    pub text: String,
    pub width: u8,
    pub foreground: CellColor,
    pub background: CellColor,
    pub bold: bool,
    pub dim: bool,
    pub italic: bool,
    pub underline: bool,
    pub strikeout: bool,
    pub inverse: bool,
    pub hidden: bool,
    pub selected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderSnapshot {
    pub size: TerminalSize,
    pub rows: Vec<Vec<RenderCell>>,
    pub cursor: Option<RenderCursor>,
    pub display_offset: usize,
    pub alternate_screen: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchOptions {
    pub case_sensitive: bool,
    pub regex: bool,
    pub max_results: usize,
}

impl Default for SearchOptions {
    fn default() -> Self {
        Self {
            case_sensitive: false,
            regex: false,
            max_results: 1_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchMatch {
    /// Alacritty grid line; negative values address scrollback history.
    pub line: i32,
    pub start_column: usize,
    pub end_column: usize,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LinkSource {
    Osc8,
    Detected,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LinkMatch {
    pub line: i32,
    pub start_column: usize,
    pub end_column: usize,
    pub uri: String,
    pub source: LinkSource,
}

#[derive(Debug, Error)]
pub enum TerminalModelError {
    #[error(transparent)]
    InvalidConfig(#[from] TerminalConfigError),
    #[error("cell ({row}, {column}) is outside terminal viewport {rows}x{columns}")]
    CellOutOfBounds {
        row: u16,
        column: u16,
        rows: u16,
        columns: u16,
    },
    #[error("invalid search expression: {0}")]
    InvalidSearch(String),
}

/// ANSI parser-backed terminal state without UI or SSH runtime ownership.
pub struct TerminalModel {
    config: TerminalConfig,
    terminal: Term<ModelEventProxy>,
    parser: Processor,
    event_proxy: ModelEventProxy,
    clipboard_policy: OscClipboardPolicy,
    total_bytes: u64,
}

impl TerminalModel {
    pub fn new(config: TerminalConfig) -> Result<Self, TerminalModelError> {
        config.validate()?;
        let event_proxy = ModelEventProxy::default();
        let alacritty_config = AlacrittyConfig {
            scrolling_history: config.scrollback_limit,
            // Parse remote copy requests so the LovelyHawk policy below can
            // make an explicit, auditable allow/deny decision. Remote reads
            // remain disabled by `OnlyCopy`.
            osc52: Osc52::OnlyCopy,
            ..Default::default()
        };
        let terminal = Term::new(alacritty_config, &config.size, event_proxy.clone());

        Ok(Self {
            config,
            terminal,
            parser: Processor::new(),
            event_proxy,
            clipboard_policy: OscClipboardPolicy::default(),
            total_bytes: 0,
        })
    }

    pub fn config(&self) -> &TerminalConfig {
        &self.config
    }

    pub fn size(&self) -> TerminalSize {
        self.config.size
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    pub fn feed_output(&mut self, bytes: &[u8]) -> FeedReport {
        self.parser.advance(&mut self.terminal, bytes);
        self.total_bytes = self.total_bytes.saturating_add(bytes.len() as u64);
        FeedReport {
            bytes_processed: bytes.len(),
            model_events: self.filter_model_events(self.event_proxy.drain()),
        }
    }

    pub fn drain_model_events(&self) -> Vec<ModelEvent> {
        self.filter_model_events(self.event_proxy.drain())
    }

    pub fn resize(&mut self, size: TerminalSize) -> Result<(), TerminalModelError> {
        size.validate()?;
        self.terminal.resize(size);
        self.config.size = size;
        Ok(())
    }

    pub fn is_alternate_screen(&self) -> bool {
        self.terminal.mode().contains(TermMode::ALT_SCREEN)
    }

    pub fn is_application_cursor(&self) -> bool {
        self.terminal.mode().contains(TermMode::APP_CURSOR)
    }

    pub fn is_application_keypad(&self) -> bool {
        self.terminal.mode().contains(TermMode::APP_KEYPAD)
    }

    pub fn reports_focus(&self) -> bool {
        self.terminal.mode().contains(TermMode::FOCUS_IN_OUT)
    }

    pub fn mouse_protocol(&self) -> MouseProtocol {
        let mode = self.terminal.mode();
        let tracking = if mode.contains(TermMode::MOUSE_MOTION) {
            MouseTrackingMode::AnyMotion
        } else if mode.contains(TermMode::MOUSE_DRAG) {
            MouseTrackingMode::ButtonMotion
        } else if mode.contains(TermMode::MOUSE_REPORT_CLICK) {
            MouseTrackingMode::Click
        } else {
            MouseTrackingMode::Off
        };
        let encoding = if mode.contains(TermMode::SGR_MOUSE) {
            MouseEncoding::Sgr
        } else {
            MouseEncoding::Legacy
        };
        MouseProtocol { tracking, encoding }
    }

    pub fn is_bracketed_paste(&self) -> bool {
        self.terminal.mode().contains(TermMode::BRACKETED_PASTE)
    }

    pub fn clipboard_policy(&self) -> OscClipboardPolicy {
        self.clipboard_policy
    }

    pub fn set_clipboard_policy(&mut self, policy: OscClipboardPolicy) {
        self.clipboard_policy = policy;
    }

    pub fn history_size(&self) -> usize {
        self.terminal.history_size()
    }

    pub fn display_offset(&self) -> usize {
        self.terminal.grid().display_offset()
    }

    pub fn scroll_lines(&mut self, delta: i32) {
        self.terminal.scroll_display(Scroll::Delta(delta));
    }

    pub fn scroll_page_up(&mut self) {
        self.terminal.scroll_display(Scroll::PageUp);
    }

    pub fn scroll_page_down(&mut self) {
        self.terminal.scroll_display(Scroll::PageDown);
    }

    pub fn scroll_to_top(&mut self) {
        self.terminal.scroll_display(Scroll::Top);
    }

    pub fn scroll_to_bottom(&mut self) {
        self.terminal.scroll_display(Scroll::Bottom);
    }

    pub fn viewport_lines(&self) -> Vec<String> {
        let first = -(self.display_offset() as i32);
        (0..self.config.size.rows)
            .map(|row| self.line_text(Line(first + row as i32)))
            .collect()
    }

    pub fn buffer_lines(&self) -> Vec<String> {
        self.buffer_lines_with_numbers()
            .into_iter()
            .map(|(_, text)| text)
            .collect()
    }

    pub fn visible_text(&self) -> String {
        self.viewport_lines().join("\n")
    }

    pub fn cell(&self, position: CellPosition) -> Result<TerminalCell, TerminalModelError> {
        let point = self.viewport_point(position)?;
        let cell = &self.terminal.grid()[point];
        Ok(TerminalCell {
            character: cell.c,
            combining: cell.zerowidth().unwrap_or_default().to_vec(),
            foreground: cell.fg.into(),
            background: cell.bg.into(),
            wide: cell.flags.contains(Flags::WIDE_CHAR),
            wide_spacer: cell.flags.contains(Flags::WIDE_CHAR_SPACER),
        })
    }

    pub fn render_snapshot(&self) -> RenderSnapshot {
        let display_offset = self.display_offset();
        let renderable = self.terminal.renderable_content();
        let selection = renderable.selection;
        let cursor_point = renderable.cursor.point;
        let cursor_shape = terminal_cursor_shape(renderable.cursor.shape);

        let mut rows = Vec::with_capacity(self.config.size.rows as usize);
        for viewport_row in 0..self.config.size.rows {
            let line = Line(viewport_row as i32 - display_offset as i32);
            let mut cells = Vec::with_capacity(self.config.size.columns as usize);
            for column in 0..self.config.size.columns {
                let point = Point::new(line, Column(column as usize));
                let cell = &self.terminal.grid()[point];
                let mut text = String::new();
                text.push(cell.c);
                if let Some(combining) = cell.zerowidth() {
                    text.extend(combining);
                }
                let wide = cell.flags.contains(Flags::WIDE_CHAR);
                let wide_spacer = cell.flags.contains(Flags::WIDE_CHAR_SPACER);
                let selected = selection.is_some_and(|range| {
                    range.contains(point)
                        || (wide && range.contains(Point::new(line, Column(column as usize + 1))))
                });
                cells.push(RenderCell {
                    row: viewport_row,
                    column,
                    text,
                    width: if wide_spacer {
                        0
                    } else if wide {
                        2
                    } else {
                        1
                    },
                    foreground: cell.fg.into(),
                    background: cell.bg.into(),
                    bold: cell.flags.contains(Flags::BOLD),
                    dim: cell.flags.contains(Flags::DIM),
                    italic: cell.flags.contains(Flags::ITALIC),
                    underline: cell.flags.intersects(Flags::ALL_UNDERLINES),
                    strikeout: cell.flags.contains(Flags::STRIKEOUT),
                    inverse: cell.flags.contains(Flags::INVERSE),
                    hidden: cell.flags.contains(Flags::HIDDEN),
                    selected,
                });
            }
            rows.push(cells);
        }

        let cursor = (display_offset == 0)
            .then_some(cursor_shape)
            .flatten()
            .and_then(|shape| {
                let row = u16::try_from(cursor_point.line.0).ok()?;
                let column = u16::try_from(cursor_point.column.0).ok()?;
                (row < self.config.size.rows && column < self.config.size.columns)
                    .then_some(RenderCursor { row, column, shape })
            });

        RenderSnapshot {
            size: self.config.size,
            rows,
            cursor,
            display_offset,
            alternate_screen: self.is_alternate_screen(),
        }
    }

    pub fn update_font(
        &mut self,
        font_size: f32,
        line_height: f32,
    ) -> Result<(), TerminalModelError> {
        let mut config = self.config.clone();
        config.font_size = font_size;
        config.line_height = line_height;
        config.validate()?;
        self.config.font_size = font_size;
        self.config.line_height = line_height;
        Ok(())
    }

    pub fn select(
        &mut self,
        start: CellPosition,
        end: CellPosition,
    ) -> Result<(), TerminalModelError> {
        let start = self.viewport_point(start)?;
        let end = self.viewport_point(end)?;
        let mut selection = Selection::new(SelectionType::Simple, start, Side::Left);
        selection.update(end, Side::Right);
        self.terminal.selection = Some(selection);
        Ok(())
    }

    pub fn clear_selection(&mut self) {
        self.terminal.selection = None;
    }

    pub fn selected_text(&self) -> Option<String> {
        self.terminal.selection_to_string()
    }

    /// Encode clipboard content according to DECSET 2004.
    ///
    /// Embedded bracket terminators are removed so pasted text cannot end the
    /// protected region early and inject following keystrokes outside it.
    pub fn paste_bytes(&self, text: &str) -> Vec<u8> {
        let text = text.replace("\u{1b}[200~", "").replace("\u{1b}[201~", "");
        if self.is_bracketed_paste() {
            let mut bytes = Vec::with_capacity(text.len() + 12);
            bytes.extend_from_slice(b"\x1b[200~");
            bytes.extend_from_slice(text.as_bytes());
            bytes.extend_from_slice(b"\x1b[201~");
            bytes
        } else {
            text.into_bytes()
        }
    }

    pub fn search(
        &self,
        query: &str,
        options: &SearchOptions,
    ) -> Result<Vec<SearchMatch>, TerminalModelError> {
        if query.is_empty() || options.max_results == 0 {
            return Ok(Vec::new());
        }

        let expression = if options.regex {
            query.to_owned()
        } else {
            regex::escape(query)
        };
        let regex = RegexBuilder::new(&expression)
            .case_insensitive(!options.case_sensitive)
            .build()
            .map_err(|error| TerminalModelError::InvalidSearch(error.to_string()))?;

        let mut results = Vec::new();
        for (line, text) in self.buffer_lines_with_numbers() {
            for found in regex.find_iter(&text) {
                results.push(SearchMatch {
                    line,
                    start_column: display_width(&text[..found.start()]),
                    end_column: display_width(&text[..found.end()]),
                    text: found.as_str().to_owned(),
                });
                if results.len() >= options.max_results {
                    return Ok(results);
                }
            }
        }
        Ok(results)
    }

    pub fn links(&self) -> Vec<LinkMatch> {
        let mut links = self.osc8_links();
        let detector = RegexBuilder::new(r#"(?i)(?:https?|ssh)://[^\s<>"']+"#)
            .build()
            .expect("static URL detector must compile");

        for (line, text) in self.buffer_lines_with_numbers() {
            for found in detector.find_iter(&text) {
                let candidate = found.as_str().trim_end_matches(|character| {
                    matches!(
                        character,
                        '.' | ',' | ';' | ':' | '!' | '?' | ')' | ']' | '}'
                    )
                });
                if candidate.is_empty() || Url::parse(candidate).is_err() {
                    continue;
                }
                let end_byte = found.start() + candidate.len();
                links.push(LinkMatch {
                    line,
                    start_column: display_width(&text[..found.start()]),
                    end_column: display_width(&text[..end_byte]),
                    uri: candidate.to_owned(),
                    source: LinkSource::Detected,
                });
            }
        }

        links.sort();
        links.dedup();
        links
    }

    pub fn hit_test_link(&self, position: CellPosition) -> Option<LinkMatch> {
        if position.row >= self.config.size.rows || position.column >= self.config.size.columns {
            return None;
        }
        let line = position.row as i32 - self.display_offset() as i32;
        let column = position.column as usize;
        self.links().into_iter().find(|link| {
            link.line == line && link.start_column <= column && column < link.end_column
        })
    }

    pub fn display_width(text: &str) -> usize {
        display_width(text)
    }

    fn viewport_point(&self, position: CellPosition) -> Result<Point, TerminalModelError> {
        if position.row >= self.config.size.rows || position.column >= self.config.size.columns {
            return Err(TerminalModelError::CellOutOfBounds {
                row: position.row,
                column: position.column,
                rows: self.config.size.rows,
                columns: self.config.size.columns,
            });
        }

        Ok(Point::new(
            Line(position.row as i32 - self.display_offset() as i32),
            Column(position.column as usize),
        ))
    }

    fn filter_model_events(&self, events: Vec<ModelEvent>) -> Vec<ModelEvent> {
        events
            .into_iter()
            .map(|event| match event {
                ModelEvent::ClipboardStore { kind, text } => {
                    let bytes = text.len();
                    match self.clipboard_policy {
                        OscClipboardPolicy::AllowRemoteWrite { max_bytes }
                            if bytes <= max_bytes =>
                        {
                            ModelEvent::ClipboardStore { kind, text }
                        }
                        OscClipboardPolicy::DenyRemoteWrite
                        | OscClipboardPolicy::AllowRemoteWrite { .. } => {
                            ModelEvent::ClipboardWriteRejected { bytes }
                        }
                    }
                }
                event => event,
            })
            .collect()
    }

    fn buffer_lines_with_numbers(&self) -> Vec<(i32, String)> {
        let top = self.terminal.topmost_line().0;
        let bottom = self.terminal.bottommost_line().0;
        (top..=bottom)
            .map(|line| (line, self.line_text(Line(line))))
            .collect()
    }

    fn line_text(&self, line: Line) -> String {
        let row = &self.terminal.grid()[line];
        let mut text = String::new();
        for cell in row {
            if cell
                .flags
                .intersects(Flags::WIDE_CHAR_SPACER | Flags::LEADING_WIDE_CHAR_SPACER)
            {
                continue;
            }
            text.push(cell.c);
            if let Some(combining) = cell.zerowidth() {
                text.extend(combining);
            }
        }
        text.trim_end_matches([' ', '\t']).to_owned()
    }

    fn osc8_links(&self) -> Vec<LinkMatch> {
        let mut links = Vec::new();
        let top = self.terminal.topmost_line().0;
        let bottom = self.terminal.bottommost_line().0;

        for line_number in top..=bottom {
            let row = &self.terminal.grid()[Line(line_number)];
            let mut active: Option<(String, usize)> = None;
            for (column, cell) in row.into_iter().enumerate() {
                let uri = cell.hyperlink().map(|link| link.uri().to_owned());
                match (&active, uri) {
                    (Some((active_uri, _)), Some(uri)) if *active_uri == uri => {}
                    (Some((active_uri, start)), next) => {
                        links.push(LinkMatch {
                            line: line_number,
                            start_column: *start,
                            end_column: column,
                            uri: active_uri.clone(),
                            source: LinkSource::Osc8,
                        });
                        active = next.map(|uri| (uri, column));
                    }
                    (None, Some(uri)) => active = Some((uri, column)),
                    (None, None) => {}
                }
            }
            if let Some((uri, start)) = active {
                links.push(LinkMatch {
                    line: line_number,
                    start_column: start,
                    end_column: row.len(),
                    uri,
                    source: LinkSource::Osc8,
                });
            }
        }
        links
    }
}

fn display_width(text: &str) -> usize {
    UnicodeWidthStr::width(text)
}

fn terminal_cursor_shape(shape: CursorShape) -> Option<TerminalCursorShape> {
    match shape {
        CursorShape::Block => Some(TerminalCursorShape::Block),
        CursorShape::Underline => Some(TerminalCursorShape::Underline),
        CursorShape::Beam => Some(TerminalCursorShape::Beam),
        CursorShape::HollowBlock => Some(TerminalCursorShape::HollowBlock),
        CursorShape::Hidden => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model(columns: u16, rows: u16) -> TerminalModel {
        let config = TerminalConfig {
            size: TerminalSize::new(columns, rows).unwrap(),
            ..Default::default()
        };
        TerminalModel::new(config).unwrap()
    }

    #[test]
    fn ansi_parser_tracks_truecolor_wide_and_combining_cells() {
        let mut model = model(20, 3);
        model.feed_output(b"\x1b[38;2;1;2;3mX\x1b[0m");
        model.feed_output("界e\u{301}".as_bytes());

        assert_eq!(
            model.cell(CellPosition::new(0, 0)).unwrap().foreground,
            CellColor::Rgb(1, 2, 3)
        );
        let wide = model.cell(CellPosition::new(0, 1)).unwrap();
        assert_eq!(wide.character, '界');
        assert!(wide.wide);
        assert!(model.cell(CellPosition::new(0, 2)).unwrap().wide_spacer);
        assert_eq!(
            model.cell(CellPosition::new(0, 3)).unwrap().combining,
            vec!['\u{301}']
        );
        assert_eq!(TerminalModel::display_width("A界e\u{301}"), 4);
    }

    #[test]
    fn scrollback_and_viewport_are_observable() {
        let mut model = model(12, 2);
        model.feed_output(b"one\r\ntwo\r\nthree");

        assert!(model.history_size() >= 1);
        assert_eq!(model.viewport_lines(), vec!["two", "three"]);
        model.scroll_to_top();
        assert!(model.display_offset() >= 1);
        assert_eq!(model.viewport_lines()[0], "one");
        model.scroll_to_bottom();
        assert_eq!(model.display_offset(), 0);
    }

    #[test]
    fn selection_copy_uses_terminal_grid() {
        let mut model = model(20, 2);
        model.feed_output(b"hello world");
        model
            .select(CellPosition::new(0, 0), CellPosition::new(0, 4))
            .unwrap();
        assert_eq!(model.selected_text().as_deref(), Some("hello"));
        model.clear_selection();
        assert_eq!(model.selected_text(), None);
    }

    #[test]
    fn search_reports_display_columns_for_cjk() {
        let mut model = model(30, 2);
        model.feed_output("前缀 target TARGET".as_bytes());
        let results = model.search("target", &SearchOptions::default()).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].start_column, 5);
        assert_eq!(results[0].text, "target");
    }

    #[test]
    fn detects_plain_and_osc8_links() {
        let mut model = model(80, 3);
        model.feed_output(b"plain https://example.com/path.\r\n");
        model.feed_output(b"\x1b]8;;ssh://host.example\x07remote\x1b]8;;\x07");
        let links = model.links();

        assert!(links.iter().any(|link| {
            link.uri == "https://example.com/path" && link.source == LinkSource::Detected
        }));
        assert!(
            links.iter().any(|link| {
                link.uri == "ssh://host.example" && link.source == LinkSource::Osc8
            })
        );
        assert_eq!(
            model
                .hit_test_link(CellPosition::new(0, 7))
                .map(|link| link.uri),
            Some("https://example.com/path".to_owned())
        );
        assert_eq!(model.hit_test_link(CellPosition::new(0, 0)), None);
    }

    #[test]
    fn dec_modes_expose_mouse_focus_and_application_keypad_state() {
        let mut model = model(20, 2);
        assert_eq!(model.mouse_protocol(), MouseProtocol::default());
        assert!(!model.reports_focus());
        assert!(!model.is_application_keypad());

        model.feed_output(b"\x1b[?1000h\x1b[?1006h\x1b[?1004h\x1b=");
        assert_eq!(
            model.mouse_protocol(),
            MouseProtocol {
                tracking: MouseTrackingMode::Click,
                encoding: MouseEncoding::Sgr,
            }
        );
        assert!(model.reports_focus());
        assert!(model.is_application_keypad());

        model.feed_output(b"\x1b[?1002h");
        assert_eq!(
            model.mouse_protocol().tracking,
            MouseTrackingMode::ButtonMotion
        );
        model.feed_output(b"\x1b[?1003h");
        assert_eq!(
            model.mouse_protocol().tracking,
            MouseTrackingMode::AnyMotion
        );
        model.feed_output(b"\x1b[?1003l\x1b[?1002l\x1b[?1000l\x1b[?1006l\x1b[?1004l\x1b>");
        assert_eq!(model.mouse_protocol(), MouseProtocol::default());
        assert!(!model.reports_focus());
        assert!(!model.is_application_keypad());
    }

    #[test]
    fn remote_osc52_clipboard_write_is_denied_by_default() {
        let mut model = model(20, 2);
        let report = model.feed_output(b"\x1b]52;c;aGVsbG8=\x07");
        assert_eq!(
            model.clipboard_policy(),
            OscClipboardPolicy::DenyRemoteWrite
        );
        assert!(
            report
                .model_events
                .iter()
                .any(|event| { matches!(event, ModelEvent::ClipboardWriteRejected { bytes: 5 }) })
        );
        assert!(
            !report
                .model_events
                .iter()
                .any(|event| matches!(event, ModelEvent::ClipboardStore { .. }))
        );

        model.set_clipboard_policy(OscClipboardPolicy::AllowRemoteWrite { max_bytes: 5 });
        let report = model.feed_output(b"\x1b]52;c;aGVsbG8=\x07");
        assert!(report.model_events.iter().any(|event| {
            matches!(
                event,
                ModelEvent::ClipboardStore { text, .. } if text == "hello"
            )
        }));

        model.set_clipboard_policy(OscClipboardPolicy::AllowRemoteWrite { max_bytes: 4 });
        let report = model.feed_output(b"\x1b]52;c;aGVsbG8=\x07");
        assert!(
            report
                .model_events
                .iter()
                .any(|event| { matches!(event, ModelEvent::ClipboardWriteRejected { bytes: 5 }) })
        );
    }

    #[test]
    fn alternate_screen_and_bracketed_paste_modes_follow_ansi() {
        let mut model = model(20, 3);
        model.feed_output(b"\x1b[?1049h\x1b[?2004h");
        assert!(model.is_alternate_screen());
        assert!(model.is_bracketed_paste());
        assert_eq!(
            model.paste_bytes("safe\x1b[201~tail"),
            b"\x1b[200~safetail\x1b[201~"
        );

        model.feed_output(b"\x1b[?1049l\x1b[?2004l");
        assert!(!model.is_alternate_screen());
        assert!(!model.is_bracketed_paste());
        assert_eq!(model.paste_bytes("plain"), b"plain");
    }

    #[test]
    fn resize_updates_model_and_bounds_checks() {
        let mut model = model(10, 2);
        model.resize(TerminalSize::new(30, 8).unwrap()).unwrap();
        assert_eq!(model.size().columns, 30);
        assert!(matches!(
            model.cell(CellPosition::new(8, 0)),
            Err(TerminalModelError::CellOutOfBounds { .. })
        ));
    }

    #[test]
    fn render_snapshot_preserves_cell_attributes_and_cursor() {
        let mut model = model(10, 2);
        model.feed_output(b"\x1b[1;3;4;9;38;2;10;20;30mX");
        let snapshot = model.render_snapshot();
        let cell = &snapshot.rows[0][0];
        assert_eq!(cell.text, "X");
        assert_eq!(cell.foreground, CellColor::Rgb(10, 20, 30));
        assert!(cell.bold);
        assert!(cell.italic);
        assert!(cell.underline);
        assert!(cell.strikeout);
        assert_eq!(
            snapshot.cursor,
            Some(RenderCursor {
                row: 0,
                column: 1,
                shape: TerminalCursorShape::Block,
            })
        );
    }
}
