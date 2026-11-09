use std::{
    io::Error,
    path::{Path, PathBuf},
    rc::Rc,
};

use super::{
    capture::{Arguments, CaptureData, load_capture, load_frame, parse_arguments},
    display_filter::{FilterParser, next_char_boundary, previous_char_boundary},
    filter_bar,
    menu_bar::{MenuAction, MenuBar, MenuBarEvent, MenuBarHandler, MenuBarState, MenuKind},
    packet_list, packet_panes,
    packet_view::{
        CopyFormat, CopyTarget, address, copy_payload, format_timestamp, packet_info,
        render_copy_context_menu,
    },
    status_bar,
    theme::ui_color,
    timeline,
};
use analyzer::parser::{frame::Frame, pcap::CaptureSummary};
use gpui::{
    App, Bounds, ClipboardItem, Context, FocusHandle, KeyDownEvent, PathPromptOptions, Point,
    Window, WindowBounds, WindowOptions, div, prelude::*, px, size,
};
use gpui_platform::application;

pub(super) struct AnalyzerUi {
    capture_path: Option<PathBuf>,
    plugins: Vec<PathBuf>,
    plugin_directories: Vec<PathBuf>,
    pub(super) packets: Vec<CaptureSummary>,
    pub(super) filtered_indices: Vec<usize>,
    pub(super) total_packets: u64,
    pub(super) selected_index: Option<usize>,
    pub(super) selected_frame: Option<Frame>,
    pub(super) expanded_layers: Vec<bool>,
    pub(super) hex_page_offset: usize,
    pub(super) filter_text: String,
    pub(super) filter_cursor: usize,
    pub(super) filter_error: Option<String>,
    pub(super) filter_focus: Option<FocusHandle>,
    pub(super) detail_selection: Option<DetailSelection>,
    pub(super) copy_context_menu: Option<CopyContextMenu>,
    pub(super) bytes_copy_menu_open: bool,
    pub(super) timeline_zoom: f64,
    pub(super) timeline_center: f64,
    pub(super) timeline_range: Option<(std::time::Duration, std::time::Duration)>,
    pub(super) timeline_drag: Option<(f32, f32)>,
    menu_bar_open: bool,
    open_menu: Option<MenuKind>,
    pub(super) light_theme: bool,
    selection_generation: u64,
    message: String,
}

#[derive(Clone)]
pub(super) struct DetailSelection {
    pub(super) id: String,
    pub(super) text: String,
    pub(super) anchor: usize,
    pub(super) head: usize,
    pub(super) dragging: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct CopyContextMenu {
    pub(super) target: CopyTarget,
    pub(super) position: Point<gpui::Pixels>,
    pub(super) submenu_open: bool,
}

impl AnalyzerUi {
    fn new(args: Arguments) -> Self {
        let mut ui = Self::empty();
        ui.plugins = args.plugins;
        ui.plugin_directories = args.plugin_directories;
        ui.message = "Open a capture to start analyzing packets.".to_owned();
        if let Some(path) = args.capture {
            match load_capture(&path, &ui.plugins, &ui.plugin_directories) {
                Ok(data) => ui.install_capture(path, data),
                Err(error) => ui.message = format!("Could not open capture: {error}"),
            }
        }
        ui
    }

    fn empty() -> Self {
        Self {
            capture_path: None,
            plugins: Vec::new(),
            plugin_directories: Vec::new(),
            packets: Vec::new(),
            filtered_indices: Vec::new(),
            total_packets: 0,
            selected_index: None,
            selected_frame: None,
            expanded_layers: Vec::new(),
            hex_page_offset: 0,
            filter_text: String::new(),
            filter_cursor: 0,
            filter_error: None,
            filter_focus: None,
            detail_selection: None,
            copy_context_menu: None,
            bytes_copy_menu_open: false,
            timeline_zoom: 1.0,
            timeline_center: 0.5,
            timeline_range: None,
            timeline_drag: None,
            menu_bar_open: false,
            open_menu: None,
            light_theme: true,
            selection_generation: 0,
            message: String::new(),
        }
    }

    fn install_capture(&mut self, path: PathBuf, data: CaptureData) {
        self.capture_path = Some(path);
        self.packets = data.packets;
        self.total_packets = data.total_packets;
        self.selected_index = None;
        self.selected_frame = None;
        self.expanded_layers.clear();
        self.hex_page_offset = 0;
        self.detail_selection = None;
        self.copy_context_menu = None;
        self.bytes_copy_menu_open = false;
        self.timeline_zoom = 1.0;
        self.timeline_center = 0.5;
        self.timeline_range = None;
        self.timeline_drag = None;
        self.filter_text.clear();
        self.filter_cursor = 0;
        self.filter_error = None;
        self.rebuild_filter();
        self.message = if self.total_packets > self.packets.len() as u64 {
            format!(
                "Showing the first {} of {} packets (index memory cap).",
                self.packets.len(),
                self.total_packets
            )
        } else {
            format!("Loaded {} packets.", self.total_packets)
        };
    }

    fn rebuild_filter(&mut self) {
        self.filtered_indices.clear();
        self.filtered_indices.extend(0..self.packets.len());
    }

    pub(super) fn update_display_filter(&mut self, cx: &mut Context<Self>) {
        let query = self.filter_text.trim();
        let expression = if query.is_empty() {
            Ok(None)
        } else {
            FilterParser::parse(query).map(Some)
        };
        match expression {
            Ok(expression) => {
                self.filtered_indices.clear();
                self.filtered_indices.extend(
                    self.packets
                        .iter()
                        .enumerate()
                        .filter(|(_, packet)| {
                            expression.as_ref().is_none_or(|expr| expr.matches(packet))
                                && self.timeline_range.is_none_or(|(start, end)| {
                                    packet.timestamp >= start && packet.timestamp <= end
                                })
                        })
                        .map(|(index, _)| index),
                );
                self.filter_error = None;
                self.message = format!("{} packets displayed.", self.filtered_indices.len());
            }
            Err(error) => {
                self.filter_error = Some(error.clone());
                self.message = error;
            }
        }
        self.selected_index = None;
        self.selected_frame = None;
        self.expanded_layers.clear();
        self.hex_page_offset = 0;
        self.detail_selection = None;
        self.copy_context_menu = None;
        self.bytes_copy_menu_open = false;
        cx.notify();
    }

    pub(super) fn handle_filter_key(&mut self, event: &KeyDownEvent, cx: &mut Context<Self>) {
        let key = event.keystroke.key.as_str();
        match key {
            "enter" => {
                self.update_display_filter(cx);
                return;
            }
            "backspace" if self.filter_cursor > 0 => {
                let start = previous_char_boundary(&self.filter_text, self.filter_cursor);
                self.filter_text.drain(start..self.filter_cursor);
                self.filter_cursor = start;
            }
            "delete" if self.filter_cursor < self.filter_text.len() => {
                let end = next_char_boundary(&self.filter_text, self.filter_cursor);
                self.filter_text.drain(self.filter_cursor..end);
            }
            "left" => {
                self.filter_cursor = previous_char_boundary(&self.filter_text, self.filter_cursor);
                cx.notify();
                return;
            }
            "right" => {
                self.filter_cursor = next_char_boundary(&self.filter_text, self.filter_cursor);
                cx.notify();
                return;
            }
            "home" => {
                self.filter_cursor = 0;
                cx.notify();
                return;
            }
            "end" => {
                self.filter_cursor = self.filter_text.len();
                cx.notify();
                return;
            }
            _ => {
                let Some(character) = event.keystroke.key_char.as_deref() else {
                    return;
                };
                if event.keystroke.modifiers.control || event.keystroke.modifiers.platform {
                    return;
                }
                let character = character
                    .chars()
                    .filter(|character| !character.is_control())
                    .collect::<String>();
                if character.is_empty() {
                    return;
                }
                self.filter_text.insert_str(self.filter_cursor, &character);
                self.filter_cursor += character.len();
            }
        }
        self.update_display_filter(cx);
    }

    fn choose_capture(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.open_menu = None;
        let receiver = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some("Open a packet capture".into()),
        });
        let plugins = self.plugins.clone();
        let plugin_directories = self.plugin_directories.clone();
        cx.spawn_in(window, async move |this, cx| {
            let selected = match receiver.await {
                Ok(Ok(Some(paths))) => paths.into_iter().next(),
                Ok(Ok(None)) => None,
                Ok(Err(error)) => {
                    report_update(this.update_in(cx, |this, _, cx| {
                        this.message = format!("File picker failed: {error}");
                        cx.notify();
                    }));
                    return;
                }
                Err(error) => {
                    report_update(this.update_in(cx, |this, _, cx| {
                        this.message = format!("File picker response failed: {error}");
                        cx.notify();
                    }));
                    return;
                }
            };
            let Some(path) = selected else {
                return;
            };
            let load_path = path.clone();
            let data = cx
                .background_executor()
                .spawn(async move { load_capture(&load_path, &plugins, &plugin_directories) })
                .await;
            report_update(this.update_in(cx, |this, _, _cx| match data {
                Ok(data) => this.install_capture(path, data),
                Err(error) => {
                    this.message = format!("Could not open capture: {error}");
                }
            }));
            report_update(this.update_in(cx, |_, _, cx| cx.notify()));
        })
        .detach();
    }

    fn export_displayed(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.capture_path.is_none() {
            self.message = "Open a capture before exporting packets.".to_owned();
            cx.notify();
            return;
        }
        let mut output = String::from("No.,Time,Source,Destination,Protocol,Length,Info\n");
        for packet in self
            .filtered_indices
            .iter()
            .filter_map(|index| self.packets.get(*index))
        {
            let values = [
                packet.number.to_string(),
                format_timestamp(*packet),
                address(packet.packet.source),
                address(packet.packet.destination),
                packet.packet.protocol.to_owned(),
                packet.captured_len.to_string(),
                packet_info(*packet),
            ];
            output.push_str(
                &values
                    .iter()
                    .map(|value| csv_field(value))
                    .collect::<Vec<_>>()
                    .join(","),
            );
            output.push('\n');
        }
        self.prompt_export(output, "requin-packets.csv", window, cx);
    }

    fn export_selected_frame(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(frame) = &self.selected_frame else {
            self.message = "Select a packet before exporting its decoded details.".to_owned();
            cx.notify();
            return;
        };
        let output = frame.to_string();
        self.prompt_export(output, "requin-frame.txt", window, cx);
    }

    fn prompt_export(
        &mut self,
        contents: String,
        suggested_name: &'static str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let directory = self
            .capture_path
            .as_deref()
            .and_then(Path::parent)
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let receiver = cx.prompt_for_new_path(&directory, Some(suggested_name));
        self.open_menu = None;
        cx.spawn_in(window, async move |this, cx| {
            let path = match receiver.await {
                Ok(Ok(Some(path))) => path,
                Ok(Ok(None)) => return,
                Ok(Err(error)) => {
                    report_update(this.update_in(cx, |this, _, cx| {
                        this.message = format!("Export dialog failed: {error}");
                        cx.notify();
                    }));
                    return;
                }
                Err(error) => {
                    report_update(this.update_in(cx, |this, _, cx| {
                        this.message = format!("Export dialog failed: {error}");
                        cx.notify();
                    }));
                    return;
                }
            };
            let result_path = path.clone();
            let result = cx
                .background_executor()
                .spawn(async move { std::fs::write(path, contents) })
                .await;
            report_update(this.update_in(cx, |this, _, cx| {
                this.message = match result {
                    Ok(()) => format!("Exported to {}.", result_path.display()),
                    Err(error) => format!("Could not export file: {error}"),
                };
                cx.notify();
            }));
        })
        .detach();
    }

    pub(super) fn select_packet(
        &mut self,
        index: usize,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(packet) = self.packets.get(index) else {
            return;
        };
        let number = packet.number;
        let Some(path) = self.capture_path.clone() else {
            return;
        };
        self.selected_index = Some(index);
        self.selected_frame = None;
        self.expanded_layers.clear();
        self.hex_page_offset = 0;
        self.detail_selection = None;
        self.copy_context_menu = None;
        self.bytes_copy_menu_open = false;
        self.selection_generation = self.selection_generation.wrapping_add(1);
        let generation = self.selection_generation;
        let plugins = self.plugins.clone();
        let plugin_directories = self.plugin_directories.clone();
        self.message = format!("Loading frame {number}…");
        cx.notify();

        cx.spawn_in(window, async move |this, cx| {
            let frame = cx
                .background_executor()
                .spawn(async move { load_frame(&path, number, &plugins, &plugin_directories) })
                .await;
            report_update(this.update_in(cx, |this, _, cx| {
                if this.selection_generation == generation {
                    match frame {
                        Ok(frame) => {
                            this.expanded_layers = vec![true; frame.layers.len()];
                            this.selected_frame = Some(frame);
                            this.message = "Frame details loaded.".to_owned();
                        }
                        Err(error) => {
                            this.message = format!("Could not reload selected frame: {error}");
                        }
                    }
                    cx.notify();
                }
            }));
        })
        .detach();
    }

    pub(super) fn toggle_layer(&mut self, index: usize, cx: &mut Context<Self>) {
        if let Some(expanded) = self.expanded_layers.get_mut(index) {
            *expanded = !*expanded;
            cx.notify();
        }
    }

    pub(super) fn zoom_timeline(
        &mut self,
        pointer_ratio: f64,
        zoom_in: bool,
        cx: &mut Context<Self>,
    ) {
        let Some((capture_start, capture_end)) = timeline::capture_time_bounds(&self.packets)
        else {
            return;
        };
        let total_span = (capture_end - capture_start).as_secs_f64().max(0.001);
        let old_span = (total_span * self.timeline_zoom).max(0.001).min(total_span);
        let anchor = (self.timeline_center * total_span - old_span * 0.5)
            + pointer_ratio.clamp(0.0, 1.0) * old_span;
        let new_span = if zoom_in {
            old_span * 0.8
        } else {
            old_span * 1.25
        }
        .clamp(0.001_f64.min(total_span), total_span);
        let start =
            (anchor - pointer_ratio.clamp(0.0, 1.0) * new_span).clamp(0.0, total_span - new_span);
        self.timeline_zoom = new_span / total_span;
        self.timeline_center = (start + new_span * 0.5) / total_span;
        cx.notify();
    }

    pub(super) fn begin_timeline_selection(&mut self, ratio: f32, cx: &mut Context<Self>) {
        let ratio = ratio.clamp(0.0, 1.0);
        self.timeline_drag = Some((ratio, ratio));
        cx.notify();
    }

    pub(super) fn extend_timeline_selection(&mut self, ratio: f32, cx: &mut Context<Self>) {
        if let Some((_, end)) = self.timeline_drag.as_mut() {
            *end = ratio.clamp(0.0, 1.0);
            cx.notify();
        }
    }

    pub(super) fn finish_timeline_selection(&mut self, cx: &mut Context<Self>) {
        if let Some((first, last)) = self.timeline_drag.take()
            && (last - first).abs() > 0.002
            && let Some((visible_start, visible_end)) = timeline::visible_time_bounds(
                &self.packets,
                self.timeline_zoom,
                self.timeline_center,
            )
        {
            let span = (visible_end - visible_start).as_secs_f64();
            let start_ratio = f64::from(first.min(last));
            let end_ratio = f64::from(first.max(last));
            self.timeline_range = Some((
                visible_start + std::time::Duration::from_secs_f64(span * start_ratio),
                visible_start + std::time::Duration::from_secs_f64(span * end_ratio),
            ));
            self.update_display_filter(cx);
        } else {
            cx.notify();
        }
    }

    pub(super) fn clear_timeline_selection(&mut self, cx: &mut Context<Self>) {
        self.timeline_range = None;
        self.timeline_drag = None;
        self.update_display_filter(cx);
    }

    pub(super) fn start_detail_selection(
        &mut self,
        id: String,
        text: String,
        index: usize,
        cx: &mut Context<Self>,
    ) {
        let index = char_boundary_at_or_before(&text, index);
        self.detail_selection = Some(DetailSelection {
            id,
            text,
            anchor: index,
            head: index,
            dragging: true,
        });
        cx.notify();
    }

    pub(super) fn extend_detail_selection(
        &mut self,
        id: &str,
        index: usize,
        cx: &mut Context<Self>,
    ) {
        if let Some(selection) = self
            .detail_selection
            .as_mut()
            .filter(|selection| selection.dragging && selection.id == id)
        {
            selection.head = char_boundary_at_or_before(&selection.text, index);
            cx.notify();
        }
    }

    pub(super) fn stop_detail_selection(&mut self, cx: &mut Context<Self>) {
        if let Some(selection) = self.detail_selection.as_mut() {
            selection.dragging = false;
        }
        cx.notify();
    }

    pub(super) fn handle_detail_key(&mut self, event: &KeyDownEvent, cx: &mut Context<Self>) {
        let key = event.keystroke.key.as_str();
        let command = event.keystroke.modifiers.control || event.keystroke.modifiers.platform;
        if !command {
            return;
        }

        match key {
            "c" => {
                if let Some(selection) = &self.detail_selection {
                    let start = selection.anchor.min(selection.head);
                    let end = selection.anchor.max(selection.head);
                    if start < end {
                        cx.write_to_clipboard(ClipboardItem::new_string(
                            selection.text[start..end].to_owned(),
                        ));
                    }
                }
            }
            "a" => {
                if let Some(selection) = self.detail_selection.as_mut() {
                    selection.anchor = 0;
                    selection.head = selection.text.len();
                    cx.notify();
                }
            }
            _ => {}
        }
    }

    pub(super) fn show_copy_context_menu(
        &mut self,
        target: CopyTarget,
        position: Point<gpui::Pixels>,
        viewport: gpui::Size<gpui::Pixels>,
        cx: &mut Context<Self>,
    ) {
        let max_x = (viewport.width - px(308.)).max(px(4.));
        let max_y = (viewport.height - px(112.)).max(px(4.));
        self.copy_context_menu = Some(CopyContextMenu {
            target,
            position: Point {
                x: position.x.clamp(px(4.), max_x),
                y: position.y.clamp(px(4.), max_y),
            },
            submenu_open: false,
        });
        self.bytes_copy_menu_open = false;
        cx.notify();
    }

    pub(super) fn set_copy_submenu_open(&mut self, open: bool, cx: &mut Context<Self>) {
        if let Some(menu) = self.copy_context_menu.as_mut() {
            menu.submenu_open = open;
            cx.notify();
        }
    }

    pub(super) fn copy_target(
        &mut self,
        target: CopyTarget,
        format: CopyFormat,
        cx: &mut Context<Self>,
    ) {
        if let Some(frame) = &self.selected_frame
            && let Some(text) = copy_payload(frame, target, format)
        {
            cx.write_to_clipboard(ClipboardItem::new_string(text));
        }
        self.copy_context_menu = None;
        self.bytes_copy_menu_open = false;
        cx.notify();
    }

    fn reload_capture(&mut self, cx: &mut Context<Self>) {
        let Some(path) = self.capture_path.clone() else {
            return;
        };
        let light_theme = self.light_theme;
        let args = Arguments {
            capture: Some(path),
            plugins: self.plugins.clone(),
            plugin_directories: self.plugin_directories.clone(),
        };
        *self = Self::new(args);
        self.light_theme = light_theme;
        self.open_menu = None;
        cx.notify();
    }

    fn handle_menu_event(
        &mut self,
        event: MenuBarEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        match event {
            MenuBarEvent::Toggle => {
                self.menu_bar_open = !self.menu_bar_open;
                if !self.menu_bar_open {
                    self.open_menu = None;
                }
            }
            MenuBarEvent::Hover(menu, true) if self.menu_bar_open => {
                self.open_menu = Some(menu);
            }
            MenuBarEvent::Hover(_, _) => {}
            MenuBarEvent::Activate(menu) => self.open_menu = Some(menu),
            MenuBarEvent::Action(action) => {
                match action {
                    MenuAction::OpenCapture => self.choose_capture(window, cx),
                    MenuAction::ReloadCapture => self.reload_capture(cx),
                    MenuAction::ExportDisplayed => self.export_displayed(window, cx),
                    MenuAction::ExportSelected => self.export_selected_frame(window, cx),
                    MenuAction::Quit => cx.quit(),
                    MenuAction::ClearFilter => {
                        self.filter_text.clear();
                        self.filter_cursor = 0;
                        self.update_display_filter(cx);
                    }
                    MenuAction::ToggleTheme => self.light_theme = !self.light_theme,
                    MenuAction::About => {
                        self.message = "Requin — fast packet analysis in Rust.".to_owned();
                    }
                }
                self.open_menu = None;
            }
        }
        cx.notify();
    }
}

impl Render for AnalyzerUi {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let light_theme = self.light_theme;
        let capture_name = self.capture_path.as_ref().map_or_else(
            || "No capture open".to_owned(),
            |path| path.display().to_string(),
        );
        let menu_entity = cx.entity();
        let menu_handler: MenuBarHandler = Rc::new(
            move |event: MenuBarEvent, window: &mut Window, app: &mut App| {
                menu_entity.update(app, |this, cx| {
                    this.handle_menu_event(event, window, cx);
                });
            },
        );

        div()
            .flex()
            .flex_col()
            .size_full()
            .overflow_hidden()
            .bg(ui_color(0x11161d, light_theme))
            .text_color(ui_color(0xdbe4ee, light_theme))
            .child(MenuBar::render(
                MenuBarState {
                    expanded: self.menu_bar_open,
                    active_menu: self.open_menu,
                    light_theme,
                    has_capture: self.capture_path.is_some(),
                    has_selected_frame: self.selected_frame.is_some(),
                    has_packets: !self.packets.is_empty(),
                    capture_name,
                },
                menu_handler,
            ))
            .child(
                div()
                    .id("main-content")
                    .flex()
                    .flex_col()
                    .w_full()
                    .flex_grow_1()
                    .min_h(px(0.))
                    .overflow_hidden()
                    .when(self.menu_bar_open, |content| {
                        content.on_click(cx.listener(|this, _, _, cx| {
                            this.menu_bar_open = false;
                            this.open_menu = None;
                            cx.notify();
                        }))
                    })
                    .child(filter_bar::render(self, _window, cx))
                    .child(timeline::render(self, _window, cx))
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .w_full()
                            .flex_grow_1()
                            .min_h(px(170.))
                            .px_2()
                            .pt_2()
                            .overflow_hidden()
                            .child(packet_list::header(light_theme))
                            .child(packet_list::rows(self, cx)),
                    )
                    .child(packet_panes::render(self, light_theme, cx))
                    .child(status_bar::render(
                        self.total_packets,
                        self.filtered_indices.len(),
                        self.message.clone(),
                        light_theme,
                    )),
            )
            .children(render_copy_context_menu(self, cx))
    }
}

fn csv_field(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn report_update<T, E: std::fmt::Display>(result: Result<T, E>) {
    if let Err(error) = result {
        eprintln!("Failed to update GUI state: {error}");
    }
}

pub(super) fn char_boundary_at_or_before(text: &str, index: usize) -> usize {
    let mut index = index.min(text.len());
    while !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

pub fn run() -> Result<(), Error> {
    let Some(args) = parse_arguments()? else {
        return Ok(());
    };
    let ui = AnalyzerUi::new(args);
    application().run(move |cx: &mut App| {
        if !crate::example_support::fonts::load_fonts(cx) {
            return;
        }
        let bounds = Bounds::centered(None, size(px(1440.0), px(900.0)), cx);
        cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                ..Default::default()
            },
            |_, cx| cx.new(|_| ui),
        )
        .unwrap();
        cx.activate(true);
    });
    Ok(())
}
