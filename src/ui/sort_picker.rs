use crate::sort::{SortColumn, TabSortState};
use crate::theme::Theme;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Clear, Paragraph},
};

// -- state --

#[derive(Default)]
pub struct SortPickerState {
    open: bool,
    cursor: usize,
    filter: String,
    filtering: bool,
}

impl SortPickerState {
    pub fn is_open(&self) -> bool {
        self.open
    }
}

// -- actions returned to the caller --

pub enum PickerAction {
    None,
    Select(usize),
    ToggleDirection,
    Close,
}

impl SortPickerState {
    pub fn open(&mut self, current_column: usize, column_count: usize) {
        self.cursor = if column_count > 0 {
            current_column.min(column_count - 1)
        } else {
            0
        };
        self.filter.clear();
        self.filtering = false;
        self.open = true;
    }

    pub fn close(&mut self) {
        self.open = false;
        self.filter.clear();
        self.filtering = false;
    }

    pub fn filtered_columns<'a>(&self, columns: &'a [SortColumn]) -> Vec<(usize, &'a str)> {
        if self.filter.is_empty() {
            columns
                .iter()
                .enumerate()
                .map(|(i, c)| (i, c.name))
                .collect()
        } else {
            let needle = self.filter.to_lowercase();
            columns
                .iter()
                .enumerate()
                .filter(|(_, c)| c.name.to_lowercase().contains(&needle))
                .map(|(i, c)| (i, c.name))
                .collect()
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent, columns: &[SortColumn]) -> PickerAction {
        let filtered = self.filtered_columns(columns);
        let count = filtered.len().max(1);

        // clamp cursor after filter changes may have shrunk the list
        if self.cursor >= count {
            self.cursor = count.saturating_sub(1);
        }

        if self.filtering {
            match key.code {
                KeyCode::Esc => {
                    self.filter.clear();
                    self.filtering = false;
                    self.cursor = 0;
                }
                KeyCode::Enter => {
                    self.filtering = false;
                    self.cursor = 0;
                }
                KeyCode::Backspace => {
                    self.filter.pop();
                    self.cursor = 0;
                }
                KeyCode::Char(c) => {
                    self.filter.push(c);
                    self.cursor = 0;
                }
                _ => {}
            }
            return PickerAction::None;
        }

        match key.code {
            KeyCode::Esc | KeyCode::Char('s') | KeyCode::Char('q') => {
                self.close();
                PickerAction::Close
            }
            KeyCode::Char('/') => {
                self.filtering = true;
                self.filter.clear();
                self.cursor = 0;
                PickerAction::None
            }
            KeyCode::Char('j') | KeyCode::Down => {
                self.cursor = (self.cursor + 1) % count;
                PickerAction::None
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.cursor = (self.cursor + count - 1) % count;
                PickerAction::None
            }
            KeyCode::Enter => {
                if let Some((col_idx, _)) = filtered.get(self.cursor) {
                    let idx = *col_idx;
                    self.close();
                    PickerAction::Select(idx)
                } else {
                    PickerAction::None
                }
            }
            KeyCode::Char('S') => PickerAction::ToggleDirection,
            _ => PickerAction::None,
        }
    }
}

// -- rendering --

pub fn render(
    f: &mut Frame,
    state: &SortPickerState,
    columns: &[SortColumn],
    current_sort: Option<&TabSortState>,
    theme: &Theme,
    area: Rect,
) {
    if columns.is_empty() {
        return;
    }

    let filtered = state.filtered_columns(columns);

    let has_filter = state.filtering || !state.filter.is_empty();
    let filter_line_height = if has_filter { 1u16 } else { 0 };
    let row_count = filtered.len() as u16;
    let popup_height = (row_count + 4 + filter_line_height).min(area.height.saturating_sub(4));
    let popup_width = 30u16.min(area.width.saturating_sub(4));

    let x = area.x + (area.width.saturating_sub(popup_width)) / 2;
    let y = area.y + (area.height.saturating_sub(popup_height)) / 2;
    let popup = Rect::new(x, y, popup_width, popup_height);

    f.render_widget(Clear, popup);

    let block = Block::default()
        .title(" Sort by ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(theme.brand));
    let inner = block.inner(popup);
    f.render_widget(block, popup);

    let current_col = current_sort.map(|s| s.column);
    let ascending = current_sort.map(|s| s.ascending).unwrap_or(true);

    let content_y = if has_filter {
        let filter_text = if state.filtering {
            format!("/{}_", state.filter)
        } else {
            format!("/{}", state.filter)
        };
        let filter_line = Paragraph::new(Line::from(vec![Span::styled(
            filter_text,
            Style::default().fg(theme.key_hint),
        )]));
        f.render_widget(filter_line, Rect::new(inner.x, inner.y, inner.width, 1));
        inner.y + 1
    } else {
        inner.y
    };

    let mut lines: Vec<Line> = Vec::new();
    for (list_idx, (orig_idx, label)) in filtered.iter().enumerate() {
        let is_highlighted = list_idx == state.cursor;
        let is_active = current_col == Some(*orig_idx);

        let marker = if is_highlighted { "▶ " } else { "  " };
        let direction = if is_active {
            if ascending {
                " ▲"
            } else {
                " ▼"
            }
        } else {
            ""
        };

        let style = if is_highlighted {
            Style::default().fg(theme.active_tab).bold()
        } else if is_active {
            Style::default().fg(theme.text_primary).bold()
        } else {
            Style::default().fg(theme.text_muted)
        };

        lines.push(Line::from(vec![
            Span::styled(marker, style),
            Span::styled(format!("{label}{direction}"), style),
        ]));
    }

    if filtered.is_empty() {
        lines.push(Line::from(Span::styled(
            "  (no matches)",
            Style::default().fg(theme.text_muted).italic(),
        )));
    }

    let content_height = (inner.y + inner.height.saturating_sub(1)).saturating_sub(content_y);
    let content = Paragraph::new(lines);
    f.render_widget(
        content,
        Rect::new(inner.x, content_y, inner.width, content_height),
    );

    let footer = Paragraph::new(Line::from(vec![
        Span::styled("↑↓", Style::default().fg(theme.key_hint).bold()),
        Span::raw(":Move "),
        Span::styled("S", Style::default().fg(theme.key_hint).bold()),
        Span::raw(":Dir "),
        Span::styled("/", Style::default().fg(theme.key_hint).bold()),
        Span::raw(":Find "),
        Span::styled("Enter", Style::default().fg(theme.key_hint).bold()),
        Span::raw(":Ok "),
        Span::styled("Esc", Style::default().fg(theme.key_hint).bold()),
        Span::raw(":Cancel"),
    ]))
    .alignment(Alignment::Center);
    let footer_area = Rect::new(
        inner.x,
        inner.y + inner.height.saturating_sub(1),
        inner.width,
        1,
    );
    f.render_widget(footer, footer_area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn cols() -> &'static [SortColumn] {
        &[
            SortColumn { name: "Alpha" },
            SortColumn { name: "Beta" },
            SortColumn { name: "Gamma" },
        ]
    }

    #[test]
    fn cursor_wraps_forward() {
        let mut state = SortPickerState::default();
        state.open(0, 3);
        state.handle_key(key(KeyCode::Char('j')), cols());
        assert_eq!(state.cursor, 1);
        state.handle_key(key(KeyCode::Char('j')), cols());
        assert_eq!(state.cursor, 2);
        state.handle_key(key(KeyCode::Char('j')), cols());
        assert_eq!(state.cursor, 0); // wrapped
    }

    #[test]
    fn cursor_wraps_backward() {
        let mut state = SortPickerState::default();
        state.open(0, 3);
        state.handle_key(key(KeyCode::Char('k')), cols());
        assert_eq!(state.cursor, 2); // wrapped to end
    }

    #[test]
    fn enter_returns_select_with_column_index() {
        let mut state = SortPickerState::default();
        state.open(0, 3);
        state.handle_key(key(KeyCode::Down), cols());
        let action = state.handle_key(key(KeyCode::Enter), cols());
        assert!(matches!(action, PickerAction::Select(1)));
        assert!(!state.is_open()); // closed after select
    }

    #[test]
    fn esc_returns_close() {
        let mut state = SortPickerState::default();
        state.open(0, 3);
        let action = state.handle_key(key(KeyCode::Esc), cols());
        assert!(matches!(action, PickerAction::Close));
        assert!(!state.is_open());
    }

    #[test]
    fn shift_s_returns_toggle_direction() {
        let mut state = SortPickerState::default();
        state.open(0, 3);
        let action = state.handle_key(key(KeyCode::Char('S')), cols());
        assert!(matches!(action, PickerAction::ToggleDirection));
    }

    #[test]
    fn filter_narrows_results() {
        let mut state = SortPickerState::default();
        state.open(0, 3);
        // enter filter mode
        state.handle_key(key(KeyCode::Char('/')), cols());
        assert!(state.filtering);
        // type "bet"
        state.handle_key(key(KeyCode::Char('b')), cols());
        state.handle_key(key(KeyCode::Char('e')), cols());
        state.handle_key(key(KeyCode::Char('t')), cols());
        let filtered = state.filtered_columns(cols());
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].1, "Beta");
        // original index preserved
        assert_eq!(filtered[0].0, 1);
    }

    #[test]
    fn filter_esc_clears_filter() {
        let mut state = SortPickerState::default();
        state.open(0, 3);
        state.handle_key(key(KeyCode::Char('/')), cols());
        state.handle_key(key(KeyCode::Char('x')), cols());
        state.handle_key(key(KeyCode::Esc), cols());
        assert!(!state.filtering);
        assert!(state.filter.is_empty());
    }

    #[test]
    fn open_resets_state() {
        let mut state = SortPickerState::default();
        state.open(2, 3);
        // mutate state
        state.cursor = 5;
        state.filter = "old".into();
        state.filtering = true;
        // reopen should reset
        state.open(2, 3);
        assert_eq!(state.cursor, 2);
        assert!(state.filter.is_empty());
        assert!(!state.filtering);
        assert!(state.is_open());
    }

    #[test]
    fn open_clamps_cursor_to_column_count() {
        let mut state = SortPickerState::default();
        state.open(10, 3);
        assert_eq!(state.cursor, 2); // clamped to last column
    }

    #[test]
    fn cursor_clamped_after_filter_shrinks_list() {
        let mut state = SortPickerState::default();
        // open at cursor 2 (Gamma), then filter to only "Alpha"
        // — cursor 2 is now out of bounds
        state.open(2, 3);
        state.handle_key(key(KeyCode::Char('/')), cols());
        state.handle_key(key(KeyCode::Char('a')), cols());
        state.handle_key(key(KeyCode::Enter), cols());
        // next key press should clamp cursor
        state.handle_key(key(KeyCode::Char('j')), cols());
        assert!(state.cursor < state.filtered_columns(cols()).len());
    }
}
