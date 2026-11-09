use gpui::{Context, Window, div, prelude::*, px};

use super::{app::AnalyzerUi, packet_view::toolbar_button, theme::ui_color};

pub(super) fn render(
    this: &mut AnalyzerUi,
    window: &mut Window,
    cx: &mut Context<AnalyzerUi>,
) -> impl IntoElement {
    let light_theme = this.light_theme;
    let filter_focus = this
        .filter_focus
        .get_or_insert_with(|| cx.focus_handle())
        .clone();
    let filter_focused = filter_focus.is_focused(window);
    let filter_preview = if this.filter_text.is_empty() {
        "Try: tcp.port == 443  ||  dns  ||  ip.src == 192.0.2.1".to_owned()
    } else if filter_focused {
        format!(
            "{}▏{}",
            &this.filter_text[..this.filter_cursor.min(this.filter_text.len())],
            &this.filter_text[this.filter_cursor.min(this.filter_text.len())..]
        )
    } else {
        this.filter_text.clone()
    };

    div()
        .flex()
        .h(px(46.))
        .flex_shrink_0()
        .items_center()
        .gap_2()
        .px_3()
        .bg(ui_color(0x171e26, light_theme))
        .border_b_1()
        .border_color(ui_color(0x303b48, light_theme))
        .child(
            div()
                .text_size(px(12.))
                .text_color(ui_color(0x9aa9b8, light_theme))
                .child("Display filter"),
        )
        .child(
            div()
                .id("display-filter-input")
                .key_context("DisplayFilter")
                .track_focus(&filter_focus)
                .flex_1()
                .h(px(30.))
                .flex()
                .items_center()
                .px_2()
                .rounded_sm()
                .border_1()
                .border_color(if this.filter_error.is_some() {
                    ui_color(0xc45c5c, light_theme)
                } else if filter_focused {
                    ui_color(0x62a8d7, light_theme)
                } else {
                    ui_color(0x435363, light_theme)
                })
                .bg(ui_color(0x101820, light_theme))
                .text_color(if this.filter_text.is_empty() {
                    ui_color(0x788897, light_theme)
                } else {
                    ui_color(0xdce9f3, light_theme)
                })
                .child(filter_preview)
                .on_click(move |_, window, cx| window.focus(&filter_focus, cx))
                .on_key_down(cx.listener(|this, event, _, cx| {
                    this.handle_filter_key(event, cx);
                })),
        )
        .child(
            toolbar_button("Clear", !this.filter_text.is_empty(), light_theme).on_click(
                cx.listener(|this, _, _, cx| {
                    this.filter_text.clear();
                    this.filter_cursor = 0;
                    this.update_display_filter(cx);
                }),
            ),
        )
        .child(
            div()
                .text_size(px(11.))
                .text_color(if this.filter_error.is_some() {
                    ui_color(0xe58c83, light_theme)
                } else {
                    ui_color(0x8493a1, light_theme)
                })
                .child(this.filter_error.clone().unwrap_or_else(|| {
                    format!("{} / {}", this.filtered_indices.len(), this.total_packets)
                })),
        )
}
