use std::rc::Rc;

use gpui::{
    AnyElement, App, Bounds, Display, Element, GlobalElementId, InspectorElementId, IntoElement,
    LayoutId, Pixels, Point, Style, Window, div, point, prelude::*, px, rgb,
};

const MENU_TRIGGER_HEIGHT: f32 = 42.;
const MENU_TRIGGER_CHAR_WIDTH: f32 = 7.5;
const MENU_TRIGGER_HORIZONTAL_PADDING: f32 = 16.;
const MENU_ITEM_HEIGHT: f32 = 28.;
const MENU_SEPARATOR_HEIGHT: f32 = 9.;
const MENU_POPUP_Y_ADJUSTMENT: f32 = 6.;
const REGISTERED_MENUS: [MenuKind; 4] = [
    MenuKind::File,
    MenuKind::Edit,
    MenuKind::View,
    MenuKind::Help,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MenuKind {
    File,
    Edit,
    View,
    Help,
}

#[derive(Clone, Copy, Debug)]
pub enum MenuAction {
    OpenCapture,
    ReloadCapture,
    ExportDisplayed,
    ExportSelected,
    Quit,
    ClearFilter,
    ToggleTheme,
    About,
}

#[derive(Clone, Copy)]
pub enum MenuBarEvent {
    Toggle,
    Hover(MenuKind, bool),
    Activate(MenuKind),
    Action(MenuAction),
}

pub type MenuBarHandler = Rc<dyn Fn(MenuBarEvent, &mut Window, &mut App)>;

pub struct MenuBarState {
    pub expanded: bool,
    pub active_menu: Option<MenuKind>,
    pub light_theme: bool,
    pub has_capture: bool,
    pub has_selected_frame: bool,
    pub has_packets: bool,
    pub capture_name: String,
}

pub struct MenuBar;

impl MenuBar {
    pub fn render(state: MenuBarState, handler: MenuBarHandler) -> impl IntoElement {
        let MenuBarState {
            expanded,
            active_menu,
            light_theme,
            has_capture,
            has_selected_frame,
            has_packets,
            capture_name,
        } = state;
        let toggle_handler = handler.clone();
        let mut bar = div()
            .flex()
            .h(px(MENU_TRIGGER_HEIGHT))
            .flex_shrink_0()
            .items_center()
            .gap_2()
            .px_3()
            .bg(color(0x202a35, light_theme))
            .border_b_1()
            .border_color(color(0x354352, light_theme))
            .child(
                div()
                    .pr_1()
                    .text_size(px(16.))
                    .text_color(color(0x1870a8, light_theme))
                    .child("Requin"),
            )
            .child(
                hamburger_button(expanded, light_theme).on_click(move |_, window, cx| {
                    toggle_handler(MenuBarEvent::Toggle, window, cx)
                }),
            );

        if expanded {
            bar = bar.children(REGISTERED_MENUS.into_iter().map(|menu| {
                register_menu(
                    menu,
                    active_menu,
                    light_theme,
                    has_capture,
                    has_selected_frame,
                    has_packets,
                    handler.clone(),
                )
            }));
        }

        bar.child(div().flex_1()).child(
            div()
                .max_w(px(580.))
                .overflow_hidden()
                .text_color(color(0x9eacba, light_theme))
                .child(capture_name),
        )
    }
}

fn register_menu(
    menu: MenuKind,
    active_menu: Option<MenuKind>,
    light_theme: bool,
    has_capture: bool,
    has_selected_frame: bool,
    has_packets: bool,
    handler: MenuBarHandler,
) -> impl IntoElement {
    let active = active_menu == Some(menu);
    let popup = match menu {
        MenuKind::File => register_file_menu(
            light_theme,
            has_capture,
            has_selected_frame,
            has_packets,
            handler.clone(),
        ),
        MenuKind::Edit => register_edit_menu(light_theme, has_selected_frame, handler.clone()),
        MenuKind::View => register_view_menu(light_theme, handler.clone()),
        MenuKind::Help => register_help_menu(light_theme, handler.clone()),
    };
    let menu_hover_handler = handler.clone();
    let menu_activate_handler = handler;
    let trigger = menu_trigger(menu, active, light_theme)
        .on_hover(move |hovered, window, cx| {
            menu_hover_handler(MenuBarEvent::Hover(menu, *hovered), window, cx);
        })
        .on_click(move |_, window, cx| {
            menu_activate_handler(MenuBarEvent::Activate(menu), window, cx);
        });

    MenuEntry::new(trigger, active.then_some(popup.absolute()))
}

fn menu_trigger(menu: MenuKind, active: bool, light_theme: bool) -> gpui::Stateful<gpui::Div> {
    let metrics = MenuMetrics::for_menu(menu);
    div()
        .id(match menu {
            MenuKind::File => "file-menu-trigger",
            MenuKind::Edit => "edit-menu-trigger",
            MenuKind::View => "view-menu-trigger",
            MenuKind::Help => "help-menu-trigger",
        })
        .h(px(MENU_TRIGGER_HEIGHT))
        .w(px(metrics.trigger_width))
        .flex()
        .items_center()
        .px_2()
        .rounded_sm()
        .text_size(px(13.))
        .text_color(color(0x9aa9b8, light_theme))
        .bg(if active {
            color(0x34465a, light_theme)
        } else {
            color(0x202a35, light_theme)
        })
        .cursor_pointer()
        .child(menu_label(menu))
}

#[derive(Clone, Copy)]
struct MenuMetrics {
    trigger_width: f32,
}

impl MenuMetrics {
    fn for_menu(menu: MenuKind) -> Self {
        let label_width = menu_label(menu).chars().count() as f32 * MENU_TRIGGER_CHAR_WIDTH
            + MENU_TRIGGER_HORIZONTAL_PADDING;
        Self {
            trigger_width: label_width,
        }
    }
}

struct MenuEntry {
    trigger: Option<AnyElement>,
    popup: Option<AnyElement>,
}

struct MenuEntryLayout {
    trigger: LayoutId,
    popup: Option<LayoutId>,
}

fn popup_origin(trigger_bounds: Bounds<Pixels>) -> Point<Pixels> {
    point(
        trigger_bounds.origin.x,
        trigger_bounds.origin.y + trigger_bounds.size.height - px(MENU_POPUP_Y_ADJUSTMENT),
    )
}

fn offset_to_popup_origin(
    target_origin: Point<Pixels>,
    popup_bounds: Bounds<Pixels>,
) -> Point<Pixels> {
    target_origin - popup_bounds.origin
}

impl MenuEntry {
    fn new(trigger: impl IntoElement, popup: Option<impl IntoElement>) -> Self {
        Self {
            trigger: Some(trigger.into_any_element()),
            popup: popup.map(IntoElement::into_any_element),
        }
    }
}

impl Element for MenuEntry {
    type RequestLayoutState = MenuEntryLayout;
    type PrepaintState = ();

    fn id(&self) -> Option<gpui::ElementId> {
        None
    }

    fn source_location(&self) -> Option<&'static core::panic::Location<'static>> {
        None
    }

    fn request_layout(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&InspectorElementId>,
        window: &mut Window,
        cx: &mut App,
    ) -> (LayoutId, Self::RequestLayoutState) {
        let trigger = self.trigger.as_mut().unwrap().request_layout(window, cx);
        let popup = self
            .popup
            .as_mut()
            .map(|popup| popup.request_layout(window, cx));
        let children = std::iter::once(trigger).chain(popup);
        let layout = window.request_layout(
            Style {
                display: Display::Flex,
                ..Style::default()
            },
            children,
            cx,
        );
        (layout, MenuEntryLayout { trigger, popup })
    }

    fn prepaint(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&InspectorElementId>,
        _bounds: Bounds<gpui::Pixels>,
        state: &mut Self::RequestLayoutState,
        window: &mut Window,
        cx: &mut App,
    ) {
        self.trigger.as_mut().unwrap().prepaint(window, cx);
        let Some(popup_layout) = state.popup else {
            return;
        };
        let trigger_bounds = window.layout_bounds(state.trigger);
        let popup_bounds = window.layout_bounds(popup_layout);
        let popup_size = popup_bounds.size;
        let mut popup_origin = popup_origin(trigger_bounds);
        let viewport = window.viewport_size();
        let margin = px(8.);
        if popup_origin.x + popup_size.width > viewport.width - margin {
            popup_origin.x = viewport.width - popup_size.width - margin;
        }
        if popup_origin.x < margin {
            popup_origin.x = margin;
        }
        if popup_origin.y + popup_size.height > viewport.height - margin {
            popup_origin.y = viewport.height - popup_size.height - margin;
        }
        if popup_origin.y < margin {
            popup_origin.y = margin;
        }
        let popup_offset = offset_to_popup_origin(popup_origin, popup_bounds);
        window.with_element_offset(popup_offset, |window| {
            window.defer_draw(self.popup.take().unwrap(), window.element_offset(), 2, None);
        });
    }

    fn paint(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&InspectorElementId>,
        _bounds: Bounds<gpui::Pixels>,
        _state: &mut Self::RequestLayoutState,
        _prepaint: &mut Self::PrepaintState,
        window: &mut Window,
        cx: &mut App,
    ) {
        self.trigger.as_mut().unwrap().paint(window, cx);
    }
}

impl IntoElement for MenuEntry {
    type Element = Self;

    fn into_element(self) -> Self::Element {
        self
    }
}

fn menu_label(menu: MenuKind) -> &'static str {
    match menu {
        MenuKind::File => "File",
        MenuKind::Edit => "Edit",
        MenuKind::View => "View",
        MenuKind::Help => "Help",
    }
}

fn hamburger_button(open: bool, light_theme: bool) -> gpui::Stateful<gpui::Div> {
    div()
        .id("menu-bar-toggle")
        .h(px(28.))
        .w(px(32.))
        .flex()
        .items_center()
        .justify_center()
        .rounded_md()
        .text_size(px(17.))
        .text_color(color(0xdce5ef, light_theme))
        .bg(if open {
            color(0x34465a, light_theme)
        } else {
            color(0x202a35, light_theme)
        })
        .cursor_pointer()
        .child("☰")
}

enum MenuItemDefinition {
    Action {
        label: &'static str,
        shortcut: &'static str,
        enabled: bool,
        action: MenuAction,
    },
    Separator,
}

fn register_file_menu(
    light_theme: bool,
    has_capture: bool,
    has_selected_frame: bool,
    has_packets: bool,
    handler: MenuBarHandler,
) -> gpui::Div {
    register_menu_items(
        light_theme,
        handler,
        [
            MenuItemDefinition::Action {
                label: "Open File…",
                shortcut: "Ctrl+O",
                enabled: true,
                action: MenuAction::OpenCapture,
            },
            MenuItemDefinition::Action {
                label: "Reload Capture",
                shortcut: "Ctrl+R",
                enabled: has_capture,
                action: MenuAction::ReloadCapture,
            },
            MenuItemDefinition::Separator,
            MenuItemDefinition::Action {
                label: "Export Displayed…",
                shortcut: "",
                enabled: has_packets,
                action: MenuAction::ExportDisplayed,
            },
            MenuItemDefinition::Action {
                label: "Export Selected…",
                shortcut: "",
                enabled: has_selected_frame,
                action: MenuAction::ExportSelected,
            },
            MenuItemDefinition::Separator,
            MenuItemDefinition::Action {
                label: "Quit",
                shortcut: "Ctrl+Q",
                enabled: true,
                action: MenuAction::Quit,
            },
        ],
    )
}

fn register_edit_menu(
    light_theme: bool,
    _has_selected_frame: bool,
    handler: MenuBarHandler,
) -> gpui::Div {
    register_menu_items(
        light_theme,
        handler,
        [MenuItemDefinition::Action {
            label: "Clear display filter",
            shortcut: "",
            enabled: true,
            action: MenuAction::ClearFilter,
        }],
    )
}

fn register_view_menu(light_theme: bool, handler: MenuBarHandler) -> gpui::Div {
    register_menu_items(
        light_theme,
        handler,
        [MenuItemDefinition::Action {
            label: if light_theme {
                "Switch to Dark Theme"
            } else {
                "Switch to Light Theme"
            },
            shortcut: "",
            enabled: true,
            action: MenuAction::ToggleTheme,
        }],
    )
}

fn register_help_menu(light_theme: bool, handler: MenuBarHandler) -> gpui::Div {
    register_menu_items(
        light_theme,
        handler,
        [MenuItemDefinition::Action {
            label: "About Requin",
            shortcut: "",
            enabled: true,
            action: MenuAction::About,
        }],
    )
}

fn register_menu_items(
    light_theme: bool,
    handler: MenuBarHandler,
    items: impl IntoIterator<Item = MenuItemDefinition>,
) -> gpui::Div {
    items
        .into_iter()
        .fold(menu_panel(light_theme), |panel, item| match item {
            MenuItemDefinition::Action {
                label,
                shortcut,
                enabled,
                action,
            } => panel.child(action_item(
                label,
                shortcut,
                enabled,
                action,
                light_theme,
                handler.clone(),
            )),
            MenuItemDefinition::Separator => panel.child(menu_separator(light_theme)),
        })
}

fn action_item(
    label: &'static str,
    shortcut: &'static str,
    enabled: bool,
    action: MenuAction,
    light_theme: bool,
    handler: MenuBarHandler,
) -> gpui::Stateful<gpui::Div> {
    let item = div()
        .id(label)
        .w_full()
        .h(px(MENU_ITEM_HEIGHT))
        .flex()
        .items_center()
        .gap_3()
        .px_2()
        .rounded_sm()
        .text_size(px(12.))
        .text_color(color(
            if enabled { 0xdce5ef } else { 0x718090 },
            light_theme,
        ))
        .when(enabled, |item| item.cursor_pointer())
        .child(label)
        .child(div().flex_1())
        .child(
            div()
                .text_size(px(10.))
                .text_color(color(0x8493a1, light_theme))
                .child(shortcut),
        );
    if enabled {
        item.on_click(move |_, window, cx| handler(MenuBarEvent::Action(action), window, cx))
    } else {
        item
    }
}

fn menu_panel(light_theme: bool) -> gpui::Div {
    div()
        .w(px(250.))
        .flex()
        .flex_col()
        .gap_0()
        .p_1()
        .rounded_md()
        .border_1()
        .border_color(color(0x3a4857, light_theme))
        .bg(color(0x202a35, light_theme))
        .shadow_lg()
}

fn menu_separator(light_theme: bool) -> gpui::Div {
    div()
        .w_full()
        .h(px(MENU_SEPARATOR_HEIGHT))
        .flex()
        .items_center()
        .child(div().w_full().h(px(1.)).bg(color(0x3a4857, light_theme)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpui::Size;

    #[test]
    fn popup_offset_aligns_to_trigger_regardless_of_static_popup_position() {
        let trigger_height = px(42.);
        let file_trigger = Bounds {
            origin: point(px(80.), px(12.)),
            size: Size {
                width: px(48.),
                height: trigger_height,
            },
        };
        let edit_trigger = Bounds {
            origin: point(px(136.), px(12.)),
            size: Size {
                width: px(48.),
                height: trigger_height,
            },
        };
        let file_popup_static_origin = point(px(18.), px(42.));
        let edit_popup_static_origin = point(px(67.), px(42.));
        let file_target = popup_origin(file_trigger);
        let edit_target = popup_origin(edit_trigger);
        let file_offset = offset_to_popup_origin(
            file_target,
            Bounds {
                origin: file_popup_static_origin,
                size: Size {
                    width: px(250.),
                    height: px(166.),
                },
            },
        );
        let edit_offset = offset_to_popup_origin(
            edit_target,
            Bounds {
                origin: edit_popup_static_origin,
                size: Size {
                    width: px(250.),
                    height: px(103.),
                },
            },
        );

        assert_eq!(file_target, point(px(80.), px(48.)));
        assert_eq!(edit_target, point(px(136.), px(48.)));
        assert_eq!(file_popup_static_origin + file_offset, file_target);
        assert_eq!(edit_popup_static_origin + edit_offset, edit_target);
        assert_ne!(file_offset.x, edit_offset.x);
    }
}

fn color(dark_color: u32, light_theme: bool) -> gpui::Hsla {
    let semantic_color = dark_color;
    let dark_color = match dark_color {
        0x202a35 => 0x0a1930,
        0x244665 => 0x153b70,
        0x34465a => 0x102748,
        0x354352 | 0x3a4857 => 0x152b4c,
        0xdce5ef => 0xdce5ef,
        _ => dark_color,
    };
    let light_color = match semantic_color {
        0x202a35 => 0xe7edf3,
        0x244665 => 0xd7eaff,
        0x34465a => 0xe0ebf5,
        0x354352 | 0x3a4857 => 0xcbd5df,
        0x1870a8 => 0x1870a8,
        0x9aa9b8 => 0x657586,
        0xdce5ef => 0x202b36,
        0x718090 => 0x8290a0,
        0x8493a1 => 0x657586,
        _ => semantic_color,
    };
    rgb(if light_theme { light_color } else { dark_color }).into()
}
