//! The "Quit netwatch?" prompt `q` raises when `confirm_quit` is on (#94).

use ratatui::{
    prelude::*,
    widgets::{Clear, Paragraph},
};

use crate::app::App;
use crate::ui::widgets;

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let popup_w = 34.min(area.width);
    let popup_h = 4.min(area.height);
    let x = area.x + (area.width.saturating_sub(popup_w)) / 2;
    let y = area.y + (area.height.saturating_sub(popup_h)) / 2;
    let popup = Rect::new(x, y, popup_w, popup_h);

    f.render_widget(Clear, popup);
    widgets::paint_overlay_bg(f, t, popup);
    let block = widgets::panel_block(t)
        .title(" Quit netwatch? ")
        .border_style(Style::default().fg(t.status_warn));
    let inner = block.inner(popup);
    f.render_widget(block, popup);

    let key = |k: &'static str| Span::styled(k, Style::default().fg(t.key_hint).bold());
    let lines = vec![
        Line::from(vec![
            key(" y"),
            Span::raw(" / "),
            key("q"),
            Span::raw(" quit"),
        ]),
        Line::from(vec![key(" any other key"), Span::raw(" stay")]),
    ];
    f.render_widget(Paragraph::new(lines), inner);
}
