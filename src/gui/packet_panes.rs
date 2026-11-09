use gpui::{Context, IntoElement, div, prelude::*, px};

use super::{
    app::AnalyzerUi,
    packet_view::{
        HEX_PAGE_BYTES, bytes_copy_menu, hex_preview, icon_button, pane_heading, render_layers,
    },
    theme::ui_color,
};

pub(super) fn render(
    this: &mut AnalyzerUi,
    light_theme: bool,
    cx: &mut Context<AnalyzerUi>,
) -> impl IntoElement {
    let visible_layer_rows = render_layers(this, light_theme, cx);

    div()
        .flex()
        .flex_1()
        .min_h(px(190.))
        .flex_shrink_0()
        .border_t_1()
        .border_color(ui_color(0x3a4857, light_theme))
        .child(
            div()
                .flex()
                .flex_col()
                .flex_1()
                .min_w(px(0.))
                .border_r_1()
                .border_color(ui_color(0x303b48, light_theme))
                .child(pane_heading("Packet details", light_theme))
                .child(
                    div()
                        .flex()
                        .flex_1()
                        .flex_col()
                        .px_3()
                        .py_2()
                        .gap_1()
                        .min_h(px(0.))
                        .id("packet-details-scroll")
                        .overflow_y_scroll()
                        .children(visible_layer_rows),
                ),
        )
        .child(
            div()
                .flex()
                .flex_col()
                .flex_1()
                .min_w(px(0.))
                .child(
                    div()
                        .flex()
                        .h(px(35.))
                        .flex_shrink_0()
                        .relative()
                        .items_center()
                        .px_3()
                        .bg(ui_color(0x202a35, light_theme))
                        .child(div().text_size(px(13.)).child("Packet bytes"))
                        .child(div().flex_1())
                        .child(div().text_color(ui_color(0x9aa9b8, light_theme)).child(
                            this.selected_frame.as_ref().map_or_else(
                                || "—".to_owned(),
                                |frame| {
                                    format!(
                                        "{}–{} / {} bytes",
                                        this.hex_page_offset,
                                        this.hex_page_offset
                                            .saturating_add(HEX_PAGE_BYTES)
                                            .min(frame.raw_data.len()),
                                        frame.raw_data.len()
                                    )
                                },
                            ),
                        ))
                        .child(
                            icon_button("bytes-prev", "‹", light_theme).on_click(cx.listener(
                                |this, _, _, cx| {
                                    this.hex_page_offset =
                                        this.hex_page_offset.saturating_sub(HEX_PAGE_BYTES);
                                    cx.notify();
                                },
                            )),
                        )
                        .child(
                            icon_button("bytes-next", "›", light_theme).on_click(cx.listener(
                                |this, _, _, cx| {
                                    if let Some(frame) = &this.selected_frame {
                                        this.hex_page_offset = this
                                            .hex_page_offset
                                            .saturating_add(HEX_PAGE_BYTES)
                                            .min(
                                                frame.raw_data.len().saturating_sub(1)
                                                    / HEX_PAGE_BYTES
                                                    * HEX_PAGE_BYTES,
                                            );
                                    }
                                    cx.notify();
                                },
                            )),
                        )
                        .child(
                            div()
                                .id("copy-bytes")
                                .px_2()
                                .child("Copy ▾")
                                .cursor_pointer()
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.bytes_copy_menu_open = !this.bytes_copy_menu_open;
                                    this.copy_context_menu = None;
                                    cx.notify();
                                })),
                        )
                        .children(
                            this.bytes_copy_menu_open
                                .then(|| bytes_copy_menu(light_theme, cx).into_any_element()),
                        ),
                )
                .child(
                    div()
                        .id("packet-bytes-scroll")
                        .flex_1()
                        .min_h(px(0.))
                        .overflow_y_scroll()
                        .px_3()
                        .py_2()
                        .text_size(px(12.))
                        .text_color(ui_color(0xc2ced9, light_theme))
                        .child(hex_preview(
                            this.selected_frame.as_ref(),
                            this.hex_page_offset,
                        )),
                ),
        )
}
