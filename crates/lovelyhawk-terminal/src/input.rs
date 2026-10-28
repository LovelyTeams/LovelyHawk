use std::ops::Range;

use unicode_width::UnicodeWidthStr;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ImeLayoutRect {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
}

/// Ephemeral UTF-16 document exposed to a host platform IME.
/// Committed bytes are returned to the caller and never retained as terminal history.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImeState {
    text: String,
    selection: Range<usize>,
    marked: Option<Range<usize>>,
}

impl ImeState {
    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn selection(&self) -> Range<usize> {
        self.selection.clone()
    }

    pub fn marked(&self) -> Option<Range<usize>> {
        self.marked.clone()
    }

    pub fn text_for_range(&self, range: Range<usize>) -> Option<(Range<usize>, String)> {
        let adjusted = clamp_utf16_range(&self.text, range);
        let bytes = utf16_range_to_bytes(&self.text, adjusted.clone())?;
        Some((adjusted, self.text[bytes].to_owned()))
    }

    pub fn replace_and_mark(
        &mut self,
        replacement: Option<Range<usize>>,
        new_text: &str,
        new_selection: Option<Range<usize>>,
    ) {
        let replacement = self.replacement_range(replacement);
        let start = replacement.start;
        self.replace_utf16(replacement, new_text);
        let inserted_len = new_text.encode_utf16().count();
        self.marked = Some(start..start + inserted_len);
        self.selection = new_selection
            .map(|range| {
                let start_offset = range.start.min(inserted_len);
                let end_offset = range.end.min(inserted_len);
                start + start_offset..start + end_offset
            })
            .unwrap_or(start + inserted_len..start + inserted_len);
    }

    pub fn commit(&mut self, replacement: Option<Range<usize>>, text: &str) -> Vec<u8> {
        let replacement = self.replacement_range(replacement);
        self.replace_utf16(replacement, text);
        let committed = self.text.as_bytes().to_vec();
        self.reset();
        committed
    }

    pub fn unmark_and_commit(&mut self) -> Vec<u8> {
        let committed = self.text.as_bytes().to_vec();
        self.reset();
        committed
    }

    pub fn reset(&mut self) {
        self.text.clear();
        self.selection = 0..0;
        self.marked = None;
    }

    pub fn bounds_for_range(
        &self,
        range: Range<usize>,
        cursor_x: f32,
        cursor_y: f32,
        cell_width: f32,
        cell_height: f32,
    ) -> ImeLayoutRect {
        let adjusted = clamp_utf16_range(&self.text, range);
        let start = self
            .text_for_range(0..adjusted.start)
            .map(|(_, text)| UnicodeWidthStr::width(text.as_str()))
            .unwrap_or(0);
        let width = self
            .text_for_range(adjusted)
            .map(|(_, text)| UnicodeWidthStr::width(text.as_str()).max(1))
            .unwrap_or(1);
        ImeLayoutRect {
            x: cursor_x + start as f32 * cell_width,
            y: cursor_y,
            width: width as f32 * cell_width,
            height: cell_height,
        }
    }

    pub fn character_index_for_x(&self, x: f32, cursor_x: f32, cell_width: f32) -> usize {
        let target_column =
            ((x - cursor_x).max(0.0) / cell_width.max(f32::EPSILON)).floor() as usize;
        let mut width = 0;
        let mut utf16 = 0;
        for character in self.text.chars() {
            let character_width = unicode_width::UnicodeWidthChar::width(character).unwrap_or(0);
            if width + character_width > target_column {
                break;
            }
            width += character_width;
            utf16 += character.len_utf16();
        }
        utf16.min(self.text.encode_utf16().count())
    }

    fn replacement_range(&self, replacement: Option<Range<usize>>) -> Range<usize> {
        clamp_utf16_range(
            &self.text,
            replacement
                .or_else(|| self.marked.clone())
                .unwrap_or_else(|| self.selection.clone()),
        )
    }

    fn replace_utf16(&mut self, range: Range<usize>, text: &str) {
        let Some(bytes) = utf16_range_to_bytes(&self.text, range.clone()) else {
            return;
        };
        self.text.replace_range(bytes, text);
        let cursor = range.start + text.encode_utf16().count();
        self.selection = cursor..cursor;
        self.marked = None;
    }
}

fn clamp_utf16_range(text: &str, range: Range<usize>) -> Range<usize> {
    let len = text.encode_utf16().count();
    range.start.min(len)..range.end.max(range.start).min(len)
}

fn utf16_range_to_bytes(text: &str, range: Range<usize>) -> Option<Range<usize>> {
    let start = byte_index_for_utf16(text, range.start)?;
    let end = byte_index_for_utf16(text, range.end)?;
    Some(start..end)
}

fn byte_index_for_utf16(text: &str, offset: usize) -> Option<usize> {
    if offset == text.encode_utf16().count() {
        return Some(text.len());
    }
    let mut utf16 = 0;
    for (byte, character) in text.char_indices() {
        if utf16 == offset {
            return Some(byte);
        }
        utf16 += character.len_utf16();
        if utf16 > offset {
            return None;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composition_replacement_and_commit_use_utf16_ranges() {
        let mut ime = ImeState::default();
        ime.replace_and_mark(None, "ni", Some(2..2));
        assert_eq!(ime.marked(), Some(0..2));
        ime.replace_and_mark(Some(0..2), "你🙂", Some(3..3));
        assert_eq!(ime.text(), "你🙂");
        assert_eq!(ime.marked(), Some(0..3));
        assert_eq!(ime.selection(), 3..3);
        assert_eq!(ime.commit(Some(0..3), "你好"), "你好".as_bytes());
        assert_eq!(ime, ImeState::default());
    }

    #[test]
    fn unmark_commits_current_preedit() {
        let mut ime = ImeState::default();
        ime.replace_and_mark(None, "かな", None);
        assert_eq!(ime.unmark_and_commit(), "かな".as_bytes());
        assert!(ime.text().is_empty());
    }

    #[test]
    fn utf16_text_bounds_and_point_mapping_handle_surrogates_and_cjk() {
        let mut ime = ImeState::default();
        ime.replace_and_mark(None, "A🙂界", None);
        let (adjusted, text) = ime.text_for_range(1..3).unwrap();
        assert_eq!(adjusted, 1..3);
        assert_eq!(text, "🙂");
        let bounds = ime.bounds_for_range(3..4, 10.0, 20.0, 8.0, 16.0);
        assert_eq!(bounds.x, 34.0);
        assert_eq!(bounds.width, 16.0);
        assert_eq!(ime.character_index_for_x(34.0, 10.0, 8.0), 3);
    }
}
