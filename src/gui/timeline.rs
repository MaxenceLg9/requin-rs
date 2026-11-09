use std::time::Duration;

use analyzer::parser::pcap::CaptureSummary;
use gpui::{
    Context, IntoElement, MouseDownEvent, MouseMoveEvent, MouseUpEvent, ScrollDelta,
    ScrollWheelEvent, Window, div, prelude::*, px,
};

use super::{app::AnalyzerUi, packet_view::toolbar_button, theme::ui_color};

const HISTOGRAM_BINS: usize = 120;
const HISTOGRAM_HEIGHT: f32 = 52.;

pub(super) fn render(
    this: &mut AnalyzerUi,
    window: &mut Window,
    cx: &mut Context<AnalyzerUi>,
) -> impl IntoElement {
    let light_theme = this.light_theme;
    let bounds = visible_time_bounds(&this.packets, this.timeline_zoom, this.timeline_center);
    let bars = histogram(&this.packets, bounds);
    let max_count = bars.iter().copied().max().unwrap_or_default().max(1);
    let viewport_width = window.viewport_size().width;
    let viewport_width_f32 = f32::from(viewport_width);
    let (selected_start, selected_end) = this
        .timeline_drag
        .map(|(start, end)| (start.min(end), start.max(end)))
        .or_else(|| {
            this.timeline_range.and_then(|(start, end)| {
                let (visible_start, visible_end) = bounds?;
                let span = (visible_end - visible_start).as_secs_f64();
                if span <= 0.0 {
                    return None;
                }
                Some((
                    ((start - visible_start).as_secs_f64() / span).clamp(0.0, 1.0) as f32,
                    ((end - visible_start).as_secs_f64() / span).clamp(0.0, 1.0) as f32,
                ))
            })
        })
        .unwrap_or((0.0, 0.0));
    let selection_active = this.timeline_drag.is_some() || this.timeline_range.is_some();
    let drag_handler = cx.listener(|this, event: &MouseDownEvent, window, cx| {
        this.begin_timeline_selection(timeline_pointer_ratio(event.position.x, window), cx);
    });
    let move_handler = cx.listener(|this, event: &MouseMoveEvent, window, cx| {
        if event.dragging() {
            this.extend_timeline_selection(timeline_pointer_ratio(event.position.x, window), cx);
        }
    });
    let up_handler = cx.listener(|this, _: &MouseUpEvent, _, cx| {
        this.finish_timeline_selection(cx);
    });
    let up_out_handler = cx.listener(|this, _: &MouseUpEvent, _, cx| {
        this.finish_timeline_selection(cx);
    });
    let wheel_handler = cx.listener(|this, event: &ScrollWheelEvent, window, cx| {
        let zoom_in = match event.delta {
            ScrollDelta::Pixels(delta) => delta.y < px(0.),
            ScrollDelta::Lines(delta) => delta.y < 0.0,
        };
        this.zoom_timeline(
            f64::from(timeline_pointer_ratio(event.position.x, window)),
            zoom_in,
            cx,
        );
    });
    div()
        .flex()
        .flex_col()
        .w_full()
        .flex_shrink_0()
        .border_b_1()
        .border_color(ui_color(0x303b48, light_theme))
        .bg(ui_color(0x171e26, light_theme))
        .child(
            div()
                .flex()
                .h(px(27.))
                .items_center()
                .gap_2()
                .px_3()
                .text_size(px(11.))
                .text_color(ui_color(0x9aa9b8, light_theme))
                .child("Packet timeline")
                .child(div().flex_1())
                .child(
                    div()
                        .text_color(ui_color(0x8493a1, light_theme))
                        .child(bounds.map_or_else(
                            || "No packets".to_owned(),
                            |(start, end)| {
                                format!(
                                    "{} — {}  ·  scroll to zoom",
                                    format_timestamp(start),
                                    format_timestamp(end)
                                )
                            },
                        )),
                )
                .when(this.timeline_range.is_some(), |bar| {
                    bar.child(toolbar_button("Clear range", true, light_theme).on_click(
                        cx.listener(|this, _, _, cx| {
                            this.clear_timeline_selection(cx);
                        }),
                    ))
                }),
        )
        .child(
            div()
                .relative()
                .flex()
                .h(px(HISTOGRAM_HEIGHT + 8.))
                .w_full()
                .items_end()
                .on_mouse_down(gpui::MouseButton::Left, drag_handler)
                .on_mouse_move(move_handler)
                .on_mouse_up(gpui::MouseButton::Left, up_handler)
                .on_mouse_up_out(gpui::MouseButton::Left, up_out_handler)
                .on_scroll_wheel(wheel_handler)
                .children(bars.into_iter().enumerate().map(|(index, count)| {
                    let height = 2. + HISTOGRAM_HEIGHT * (count as f32 / max_count as f32).sqrt();
                    let active = selection_active
                        && index as f32 / HISTOGRAM_BINS as f32 >= selected_start
                        && index as f32 / HISTOGRAM_BINS as f32 <= selected_end;
                    div().flex_1().h(px(height)).bg(if active {
                        ui_color(0x62a8d7, light_theme)
                    } else {
                        ui_color(0x3979a5, light_theme)
                    })
                }))
                .when(selection_active, |track| {
                    track.child(
                        div()
                            .absolute()
                            .left(px(viewport_width_f32 * selected_start))
                            .bottom(px(0.))
                            .w(px(viewport_width_f32 * (selected_end - selected_start)))
                            .h(px(HISTOGRAM_HEIGHT + 8.))
                            .bg(ui_color(0x244665, light_theme).opacity(0.25)),
                    )
                }),
        )
}

fn timeline_pointer_ratio(x: gpui::Pixels, window: &Window) -> f32 {
    let width = f32::from(window.viewport_size().width).max(1.0);
    (f32::from(x) / width).clamp(0.0, 1.0)
}

pub(super) fn capture_time_bounds(packets: &[CaptureSummary]) -> Option<(Duration, Duration)> {
    let mut timestamps = packets.iter().map(|packet| packet.timestamp);
    let first = timestamps.next()?;
    Some(timestamps.fold((first, first), |(min, max), time| {
        (min.min(time), max.max(time))
    }))
}

pub(super) fn visible_time_bounds(
    packets: &[CaptureSummary],
    zoom: f64,
    center: f64,
) -> Option<(Duration, Duration)> {
    let (start, end) = capture_time_bounds(packets)?;
    let total = (end - start).as_secs_f64().max(0.001);
    let span = (total * zoom.clamp(0.001 / total, 1.0)).clamp(0.001_f64.min(total), total);
    let start_fraction =
        (center.clamp(0.0, 1.0) - span / total * 0.5).clamp(0.0, 1.0 - span / total);
    let visible_start = start + Duration::from_secs_f64(total * start_fraction);
    Some((visible_start, visible_start + Duration::from_secs_f64(span)))
}

fn histogram(
    packets: &[CaptureSummary],
    bounds: Option<(Duration, Duration)>,
) -> [usize; HISTOGRAM_BINS] {
    let mut bins = [0; HISTOGRAM_BINS];
    let Some((start, end)) = bounds else {
        return bins;
    };
    let span = (end - start).as_secs_f64().max(0.001);
    for packet in packets {
        let Some(offset) = packet
            .timestamp
            .checked_sub(start)
            .map(|duration| duration.as_secs_f64())
        else {
            continue;
        };
        if !(0.0..=span).contains(&offset) {
            continue;
        }
        let index = ((offset / span) * HISTOGRAM_BINS as f64) as usize;
        bins[index.min(HISTOGRAM_BINS - 1)] += 1;
    }
    bins
}

fn format_timestamp(timestamp: Duration) -> String {
    format!("{}.{:03}", timestamp.as_secs(), timestamp.subsec_millis())
}

#[cfg(test)]
mod tests {
    use super::*;
    use analyzer::proto::PacketSummary;

    fn packet(number: u64, seconds: u64) -> CaptureSummary {
        CaptureSummary {
            number,
            timestamp: Duration::from_secs(seconds),
            original_len: 64,
            captured_len: 64,
            link_type: 1,
            packet: PacketSummary {
                source: None,
                destination: None,
                source_mac: None,
                destination_mac: None,
                protocol: "TCP",
                transport: Some("TCP"),
                ip_ttl: None,
                ipv6_hop_limit: None,
                tcp_sequence: None,
                tcp_acknowledgment: None,
                tcp_flags: None,
                tcp_window: None,
                udp_length: None,
                icmp_type: None,
                icmp_code: None,
                source_port: None,
                destination_port: None,
            },
        }
    }

    #[test]
    fn histogram_excludes_packets_outside_the_zoomed_time_window() {
        let packets = [packet(1, 0), packet(2, 5), packet(3, 10)];
        let bins = histogram(
            &packets,
            Some((Duration::from_secs(4), Duration::from_secs(6))),
        );

        assert_eq!(bins.iter().sum::<usize>(), 1);
        assert_eq!(bins[HISTOGRAM_BINS / 2], 1);
    }

    #[test]
    fn zoomed_time_bounds_stay_inside_capture() {
        let packets = [packet(1, 0), packet(2, 10)];
        let (start, end) = visible_time_bounds(&packets, 0.2, 0.5).unwrap();

        assert_eq!(start, Duration::from_secs(4));
        assert_eq!(end, Duration::from_secs(6));
    }
}
