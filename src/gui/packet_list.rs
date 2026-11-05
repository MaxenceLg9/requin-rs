use gpui::{Context, div, prelude::*, px, uniform_list};
use std::ops::Range;

use super::{
    app::AnalyzerUi,
    packet_view::{address, format_timestamp, packet_info, protocol_cell, table_cell},
    theme::ui_color,
};

pub(super) fn rows(this: &AnalyzerUi, cx: &mut Context<AnalyzerUi>) -> impl IntoElement {
    let filtered_count = this.filtered_indices.len();
    let entity = cx.entity();
    uniform_list(
        "packet-rows",
        filtered_count,
        cx.processor(move |this, range: Range<usize>, _window, _app| {
            range
                .filter_map(|row_index| {
                    let packet_index = *this.filtered_indices.get(row_index)?;
                    let packet = *this.packets.get(packet_index)?;
                    let selected = this.selected_index == Some(packet_index);
                    let light_theme = this.light_theme;
                    let row_entity = entity.clone();
                    Some(
                        div()
                            .id(format!("packet-{packet_index}"))
                            .flex()
                            .w_full()
                            .h(px(27.))
                            .items_center()
                            .px_2()
                            .gap_2()
                            .bg(if selected {
                                ui_color(0x244665, light_theme)
                            } else if packet_index % 2 == 0 {
                                ui_color(0x151b22, light_theme)
                            } else {
                                ui_color(0x19212a, light_theme)
                            })
                            .text_color(ui_color(0xdce5ef, light_theme))
                            .cursor_pointer()
                            .child(table_cell(packet.number.to_string(), 0.75))
                            .child(table_cell(format_timestamp(packet), 1.4))
                            .child(table_cell(address(packet.packet.source), 1.6))
                            .child(table_cell(address(packet.packet.destination), 1.6))
                            .child(protocol_cell(packet.packet.protocol, light_theme))
                            .child(table_cell(packet.captured_len.to_string(), 0.9))
                            .child(table_cell(packet_info(packet), 2.2))
                            .on_click(move |_, window, cx| {
                                row_entity.update(cx, |this, cx| {
                                    this.select_packet(packet_index, window, cx);
                                });
                            }),
                    )
                })
                .collect()
        }),
    )
    .w_full()
    .flex_grow_1()
    .min_h(px(0.))
}

pub(super) fn header(light_theme: bool) -> impl IntoElement {
    div()
        .flex()
        .h(px(28.))
        .flex_shrink_0()
        .items_center()
        .px_2()
        .gap_2()
        .w_full()
        .bg(ui_color(0x263342, light_theme))
        .text_color(ui_color(0xc0ccd8, light_theme))
        .child(table_cell("No.", 0.75))
        .child(table_cell("Time", 1.4))
        .child(table_cell("Source", 1.6))
        .child(table_cell("Destination", 1.6))
        .child(table_cell("Protocol", 0.9))
        .child(table_cell("Length", 0.9))
        .child(table_cell("Info", 2.2))
}
