use analyzer::{
    parser::{frame::Frame, pcap::CaptureSummary},
    proto::Address,
};
use gpui::{AnyElement, ClipboardItem, Context, IntoElement, div, prelude::*, px};

use super::{app::AnalyzerUi, theme::ui_color};

pub(super) const HEX_PAGE_BYTES: usize = 384;

pub(super) fn render_layers(
    this: &AnalyzerUi,
    light_theme: bool,
    cx: &mut Context<AnalyzerUi>,
) -> Vec<AnyElement> {
    let Some(frame) = &this.selected_frame else {
        return vec![
            div()
                .text_color(ui_color(0x8c9baa, light_theme))
                .child("Select a packet to inspect its decoded layers.")
                .into_any_element(),
        ];
    };
    if frame.layers.is_empty() {
        return vec![
            div()
                .text_color(ui_color(0x8c9baa, light_theme))
                .child("No decoded layer details are available for this frame.")
                .into_any_element(),
        ];
    }
    let mut elements = Vec::new();
    for (layer_index, layer) in frame.layers.iter().enumerate() {
        let expanded = this
            .expanded_layers
            .get(layer_index)
            .copied()
            .unwrap_or(true);
        elements.push(
            div()
                .id(format!("layer-{layer_index}"))
                .flex()
                .w_full()
                .items_center()
                .gap_2()
                .pt_1()
                .text_color(ui_color(0x8fc7f1, light_theme))
                .cursor_pointer()
                .child(if expanded { "▾" } else { "▸" })
                .child(layer.name.to_string())
                .child(div().flex_1())
                .child(
                    div()
                        .id(format!("copy-layer-{layer_index}"))
                        .px_2()
                        .text_color(ui_color(0x8c9baa, light_theme))
                        .child("Copy")
                        .on_click(cx.listener(move |this, _, _, cx| {
                            if let Some(layer) = this
                                .selected_frame
                                .as_ref()
                                .and_then(|frame| frame.layers.get(layer_index))
                            {
                                cx.write_to_clipboard(ClipboardItem::new_string(layer.to_string()));
                            }
                        })),
                )
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.toggle_layer(layer_index, cx);
                }))
                .into_any_element(),
        );
        if expanded {
            elements.push(
                div()
                    .flex()
                    .w_full()
                    .mt_1()
                    .px_2()
                    .py_1()
                    .bg(ui_color(0x202a35, light_theme))
                    .text_size(px(11.))
                    .text_color(ui_color(0x91a5b7, light_theme))
                    .child(table_cell("Field", 1.))
                    .child(table_cell("Value", 1.6))
                    .into_any_element(),
            );
            for (field_index, field) in layer.fields.iter().enumerate() {
                let field_name = field.offset.map_or_else(
                    || field.name.to_string(),
                    |offset| {
                        format!(
                            "{}  [{offset}+{}]",
                            field.name,
                            field.length.unwrap_or_default()
                        )
                    },
                );
                elements.push(
                    div()
                        .id(format!("field-{layer_index}-{field_index}"))
                        .flex()
                        .w_full()
                        .px_2()
                        .py_1()
                        .gap_2()
                        .bg(if field_index % 2 == 0 {
                            ui_color(0x19212a, light_theme)
                        } else {
                            ui_color(0x151b22, light_theme)
                        })
                        .text_color(ui_color(0xc2ced9, light_theme))
                        .child(table_cell(field_name, 1.))
                        .child(
                            div()
                                .flex_basis(px(0.))
                                .flex_grow(1.6)
                                .flex_shrink(1.)
                                .min_w(px(0.))
                                .overflow_hidden()
                                .child(field.value.to_string()),
                        )
                        .into_any_element(),
                );
            }
        }
    }
    elements
}

pub(super) fn toolbar_button(
    label: &'static str,
    enabled: bool,
    light_theme: bool,
) -> impl IntoElement + gpui::StatefulInteractiveElement {
    div()
        .id(label)
        .px_2()
        .py(px(3.))
        .rounded_md()
        .text_size(px(12.))
        .bg(if enabled {
            ui_color(0x34465a, light_theme)
        } else {
            ui_color(0x252d36, light_theme)
        })
        .text_color(if enabled {
            ui_color(0xe0e8f0, light_theme)
        } else {
            ui_color(0x718090, light_theme)
        })
        .child(label)
        .when(enabled, |element| element.cursor_pointer())
}

pub(super) fn icon_button(
    id: &'static str,
    label: &'static str,
    light_theme: bool,
) -> impl IntoElement + gpui::StatefulInteractiveElement {
    div()
        .id(id)
        .px_2()
        .rounded_md()
        .bg(ui_color(0x263342, light_theme))
        .cursor_pointer()
        .text_color(ui_color(0xc4d2df, light_theme))
        .child(label)
}

pub(super) fn pane_heading(title: &'static str, light_theme: bool) -> impl IntoElement {
    div()
        .flex()
        .h(px(31.))
        .flex_shrink_0()
        .items_center()
        .px_3()
        .bg(ui_color(0x202a35, light_theme))
        .child(div().text_size(px(13.)).child(title))
}

pub(super) fn table_cell(text: impl ToString, weight: f32) -> gpui::Div {
    div()
        .flex_basis(px(0.))
        .flex_grow(weight)
        .flex_shrink(1.)
        .min_w(px(0.))
        .overflow_hidden()
        .text_ellipsis()
        .whitespace_nowrap()
        .child(text.to_string())
}

pub(super) fn address(address: Option<Address>) -> String {
    address.map_or_else(|| "-".to_owned(), Address::format)
}

pub(super) fn packet_info(packet: CaptureSummary) -> String {
    match (packet.packet.source_port, packet.packet.destination_port) {
        (Some(source), Some(destination)) => match packet.packet.protocol {
            "DNS" => format!("DNS {source} → {destination}"),
            "HTTP" => format!("HTTP {source} → {destination}"),
            "TLS" => format!("TLS {source} → {destination}"),
            "DHCP" => format!("DHCP {source} → {destination}"),
            _ => format!("{source} → {destination}"),
        },
        _ => packet.packet.protocol.to_owned(),
    }
}

pub(super) fn protocol_cell(protocol: &'static str, light_theme: bool) -> gpui::Div {
    let color = match protocol {
        "TCP" | "HTTP" | "TLS" => ui_color(0x9bd18b, light_theme),
        "UDP" | "DNS" | "DHCP" => ui_color(0x82c9dc, light_theme),
        "ICMP" | "ICMPv6" | "ARP" => ui_color(0xe4c274, light_theme),
        "Malformed" => ui_color(0xec8b83, light_theme),
        _ => ui_color(0xdce5ef, light_theme),
    };
    table_cell(protocol, 1.).text_color(color)
}

pub(super) fn format_timestamp(summary: CaptureSummary) -> String {
    let timestamp = summary.timestamp;
    format!("{}.{:09}", timestamp.as_secs(), timestamp.subsec_nanos())
}

pub(super) fn hex_preview(frame: Option<&Frame>, offset: usize) -> String {
    let Some(frame) = frame else {
        return "Select a packet to inspect its captured bytes.".to_owned();
    };
    let start = offset.min(frame.raw_data.len());
    let end = start
        .saturating_add(HEX_PAGE_BYTES)
        .min(frame.raw_data.len());
    let mut output = String::new();
    for (row, bytes) in frame.raw_data[start..end].chunks(16).enumerate() {
        use std::fmt::Write;
        let _ = write!(output, "{:08x}  ", start + row * 16);
        for byte in bytes {
            let _ = write!(output, "{byte:02x} ");
        }
        for _ in bytes.len()..16 {
            output.push_str("   ");
        }
        output.push_str(" |");
        for byte in bytes {
            output.push(if byte.is_ascii_graphic() || *byte == b' ' {
                char::from(*byte)
            } else {
                '.'
            });
        }
        output.push_str("|\n");
    }
    output
}
