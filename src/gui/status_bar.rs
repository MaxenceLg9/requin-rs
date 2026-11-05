use gpui::{IntoElement, div, prelude::*, px};

use super::theme::ui_color;

pub(super) fn render(
    total_packets: u64,
    displayed_packets: usize,
    message: String,
    light_theme: bool,
) -> impl IntoElement {
    div()
        .flex()
        .h(px(25.))
        .flex_shrink_0()
        .items_center()
        .gap_3()
        .px_3()
        .bg(ui_color(0x202a35, light_theme))
        .text_size(px(11.))
        .text_color(ui_color(0x9aa9b8, light_theme))
        .child(format!(
            "{total_packets} packets  ·  {displayed_packets} displayed"
        ))
        .child(div().flex_1())
        .child(message)
}
