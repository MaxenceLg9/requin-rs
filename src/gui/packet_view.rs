use analyzer::{
    parser::{frame::Frame, layer::Layer, pcap::CaptureSummary},
    proto::Address,
};
use gpui::{
    AnyElement, Context, HighlightStyle, IntoElement, MouseButton, MouseDownEvent, MouseMoveEvent,
    StyledText, div, prelude::*, px,
};
use std::ops::Range;

use super::{app::AnalyzerUi, theme::ui_color};

pub(super) const HEX_PAGE_BYTES: usize = 384;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum CopyTarget {
    Frame,
    Layer(usize),
    Field { layer: usize, field: usize },
}

#[derive(Clone, Copy)]
pub(super) enum CopyFormat {
    Hex,
    Text,
    Bytes,
}

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
                .on_mouse_down(
                    MouseButton::Right,
                    cx.listener(move |this, event: &MouseDownEvent, window, cx| {
                        this.show_copy_context_menu(
                            CopyTarget::Layer(layer_index),
                            event.position,
                            window.viewport_size(),
                            cx,
                        );
                    }),
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
                let field_value = field.value.to_string();
                let field_name_id = format!("field-name-{layer_index}-{field_index}");
                let field_value_id = format!("field-value-{layer_index}-{field_index}");
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
                        .child(selectable_table_cell(
                            field_name,
                            field_name_id,
                            1.,
                            this,
                            cx,
                        ))
                        .child(selectable_table_cell(
                            field_value,
                            field_value_id,
                            1.6,
                            this,
                            cx,
                        ))
                        .on_mouse_down(
                            MouseButton::Right,
                            cx.listener(move |this, event: &MouseDownEvent, window, cx| {
                                this.show_copy_context_menu(
                                    CopyTarget::Field {
                                        layer: layer_index,
                                        field: field_index,
                                    },
                                    event.position,
                                    window.viewport_size(),
                                    cx,
                                );
                            }),
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

fn selectable_table_cell(
    text: String,
    id: String,
    weight: f32,
    this: &AnalyzerUi,
    cx: &mut Context<AnalyzerUi>,
) -> gpui::Stateful<gpui::Div> {
    let selected_range = this
        .detail_selection
        .as_ref()
        .filter(|selection| selection.id == id)
        .map(|selection| selection.anchor.min(selection.head)..selection.anchor.max(selection.head))
        .filter(|range| !range.is_empty());
    let mut styled_text = StyledText::new(text.clone());
    if let Some(range) = selected_range {
        styled_text = styled_text.with_highlights([(
            range,
            HighlightStyle {
                background_color: Some(ui_color(0x244665, this.light_theme)),
                ..Default::default()
            },
        )]);
    }
    let text_layout = styled_text.layout().clone();
    let selection_id = id.clone();
    let selection_text = text.clone();
    let focus_handle = cx.focus_handle();
    div()
        .id(id)
        .flex_basis(px(0.))
        .flex_grow(weight)
        .flex_shrink(1.)
        .min_w(px(0.))
        .overflow_hidden()
        .whitespace_nowrap()
        .key_context("FrameDetails")
        .track_focus(&focus_handle)
        .cursor(gpui::CursorStyle::IBeam)
        .child(styled_text)
        .on_mouse_down(MouseButton::Left, {
            let id = selection_id.clone();
            let text = selection_text.clone();
            let layout = text_layout.clone();
            cx.listener(move |this, event: &MouseDownEvent, window, cx| {
                let index = layout
                    .index_for_position(event.position)
                    .unwrap_or_else(|index| index)
                    .min(text.len());
                this.start_detail_selection(id.clone(), text.clone(), index, cx);
                window.focus(&focus_handle, cx);
            })
        })
        .on_mouse_move({
            let id = selection_id.clone();
            let layout = text_layout.clone();
            cx.listener(move |this, event: &MouseMoveEvent, _, cx| {
                let index = layout
                    .index_for_position(event.position)
                    .unwrap_or_else(|index| index);
                this.extend_detail_selection(&id, index, cx);
            })
        })
        .on_mouse_up(
            MouseButton::Left,
            cx.listener(|this, _, _, cx| {
                this.stop_detail_selection(cx);
            }),
        )
        .on_mouse_up_out(
            MouseButton::Left,
            cx.listener(|this, _, _, cx| {
                this.stop_detail_selection(cx);
            }),
        )
        .on_key_down(cx.listener(|this, event, _, cx| {
            this.handle_detail_key(event, cx);
        }))
}

pub(super) fn render_copy_context_menu(
    this: &AnalyzerUi,
    cx: &mut Context<AnalyzerUi>,
) -> Option<AnyElement> {
    let menu = this.copy_context_menu?;
    let hover_handler = cx.listener(|this, hovered, _, cx| {
        if *hovered {
            this.set_copy_submenu_open(true, cx);
        }
    });
    let mut menu_element = div()
        .absolute()
        .left(menu.position.x)
        .top(menu.position.y)
        .w(px(150.))
        .p_1()
        .rounded_md()
        .border_1()
        .border_color(ui_color(0x3a4857, this.light_theme))
        .bg(ui_color(0x202a35, this.light_theme))
        .shadow_lg()
        .child(
            div()
                .id("context-copy-trigger")
                .w_full()
                .px_2()
                .py_1()
                .rounded_sm()
                .cursor_pointer()
                .child("Copy  ›")
                .on_hover(hover_handler),
        );

    if menu.submenu_open {
        menu_element = menu_element.child(context_copy_submenu(menu.target, this.light_theme, cx));
    }
    Some(menu_element.into_any_element())
}

fn context_copy_submenu(
    target: CopyTarget,
    light_theme: bool,
    cx: &mut Context<AnalyzerUi>,
) -> impl IntoElement {
    div()
        .absolute()
        .left(px(148.))
        .top(px(0.))
        .w(px(150.))
        .p_1()
        .rounded_md()
        .border_1()
        .border_color(ui_color(0x3a4857, light_theme))
        .bg(ui_color(0x202a35, light_theme))
        .shadow_lg()
        .child(copy_option(
            "Copy as HEX",
            target,
            CopyFormat::Hex,
            light_theme,
            cx,
        ))
        .child(copy_option(
            "Copy as Text",
            target,
            CopyFormat::Text,
            light_theme,
            cx,
        ))
        .child(copy_option(
            "Copy as bytes",
            target,
            CopyFormat::Bytes,
            light_theme,
            cx,
        ))
}

fn copy_option(
    label: &'static str,
    target: CopyTarget,
    format: CopyFormat,
    light_theme: bool,
    cx: &mut Context<AnalyzerUi>,
) -> gpui::Stateful<gpui::Div> {
    div()
        .id(label)
        .w_full()
        .px_2()
        .py_1()
        .rounded_sm()
        .cursor_pointer()
        .text_size(px(12.))
        .text_color(ui_color(0xdce5ef, light_theme))
        .child(label)
        .on_click(cx.listener(move |this, _, _, cx| {
            this.copy_target(target, format, cx);
        }))
}

pub(super) fn copy_payload(
    frame: &Frame,
    target: CopyTarget,
    format: CopyFormat,
) -> Option<String> {
    let (text, bytes) = match target {
        CopyTarget::Frame => (
            String::from_utf8_lossy(&frame.raw_data).into_owned(),
            &frame.raw_data[..],
        ),
        CopyTarget::Layer(layer_index) => {
            let layer = frame.layers.get(layer_index)?;
            let range = layer_byte_range(layer)?;
            (layer.to_string(), frame.raw_data.get(range)?)
        }
        CopyTarget::Field { layer, field } => {
            let field = frame.layers.get(layer)?.fields.get(field)?;
            let value = field.value.to_string();
            let range = field.offset?..field.offset?.checked_add(field.length?)?;
            (value, frame.raw_data.get(range)?)
        }
    };
    Some(match format {
        CopyFormat::Hex => encode_hex(bytes),
        CopyFormat::Text => text,
        CopyFormat::Bytes => encode_bytes(bytes),
    })
}

fn layer_byte_range(layer: &Layer) -> Option<Range<usize>> {
    let start = layer.fields.iter().filter_map(|field| field.offset).min()?;
    let end = layer
        .fields
        .iter()
        .filter_map(|field| field.offset?.checked_add(field.length?))
        .max()?;
    (start < end).then_some(start..end)
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn encode_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut output = String::with_capacity(bytes.len() * 4);
    for byte in bytes {
        let _ = write!(output, "\\x{byte:02x}");
    }
    output
}

pub(super) fn bytes_copy_menu(light_theme: bool, cx: &mut Context<AnalyzerUi>) -> impl IntoElement {
    div()
        .absolute()
        .right(px(8.))
        .top(px(32.))
        .w(px(150.))
        .p_1()
        .rounded_md()
        .border_1()
        .border_color(ui_color(0x3a4857, light_theme))
        .bg(ui_color(0x202a35, light_theme))
        .shadow_lg()
        .child(copy_option(
            "Copy as HEX",
            CopyTarget::Frame,
            CopyFormat::Hex,
            light_theme,
            cx,
        ))
        .child(copy_option(
            "Copy as Text",
            CopyTarget::Frame,
            CopyFormat::Text,
            light_theme,
            cx,
        ))
        .child(copy_option(
            "Copy as bytes",
            CopyTarget::Frame,
            CopyFormat::Bytes,
            light_theme,
            cx,
        ))
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
            "NTP" => format!("NTP {source} → {destination}"),
            "TFTP" => format!("TFTP {source} → {destination}"),
            "SIP" => format!("SIP {source} → {destination}"),
            "FTP" => format!("FTP {source} → {destination}"),
            _ => format!("{source} → {destination}"),
        },
        _ => packet.packet.protocol.to_owned(),
    }
}

pub(super) fn protocol_cell(protocol: &'static str, light_theme: bool) -> gpui::Div {
    let color = match protocol {
        "TCP" | "HTTP" | "TLS" | "SSH" | "SMTP" | "IMAP" | "SIP" | "FTP" => {
            ui_color(0x9bd18b, light_theme)
        }
        "UDP" | "DNS" | "DHCP" | "DHCPv6" | "VXLAN" | "GSSAPI" | "NTP" | "TFTP" => {
            ui_color(0x82c9dc, light_theme)
        }
        "ICMP" | "ICMPv6" | "NDP" | "ARP" | "MPLS" | "GRE" | "IPsec" | "ESP" | "AH" => {
            ui_color(0xe4c274, light_theme)
        }
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use analyzer::parser::layer::{Field, Layer};

    use super::*;

    #[test]
    fn copies_field_values_as_text_hex_or_escaped_bytes() {
        let mut frame = Frame::new(1, Duration::ZERO, 3, 1, vec![0x41, 0x00, 0xff]);
        frame
            .layers
            .push(Layer::new("Test").field(Field::new("payload", "A").at(0, 3)));
        let target = CopyTarget::Field { layer: 0, field: 0 };

        assert_eq!(
            copy_payload(&frame, target, CopyFormat::Hex).as_deref(),
            Some("4100ff")
        );
        assert_eq!(
            copy_payload(&frame, target, CopyFormat::Text).as_deref(),
            Some("A")
        );
        assert_eq!(
            copy_payload(&frame, target, CopyFormat::Bytes).as_deref(),
            Some(r"\x41\x00\xff")
        );
    }

    #[test]
    fn copies_layer_bytes_using_its_field_offsets() {
        let mut frame = Frame::new(1, Duration::ZERO, 4, 1, vec![0xaa, 0xbb, 0xcc, 0xdd]);
        frame.layers.push(
            Layer::new("Test")
                .field(Field::new("first", 1u8).at(1, 1))
                .field(Field::new("last", 2u8).at(2, 1)),
        );

        assert_eq!(
            copy_payload(&frame, CopyTarget::Layer(0), CopyFormat::Hex).as_deref(),
            Some("bbcc")
        );
    }

    #[test]
    fn selection_offsets_are_clamped_to_utf8_boundaries() {
        let value = "éclair";
        assert_eq!(super::super::app::char_boundary_at_or_before(value, 1), 0);
        assert_eq!(super::super::app::char_boundary_at_or_before(value, 2), 2);
    }
}
