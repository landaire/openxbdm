use std::path::PathBuf;
use std::time::Duration;

use gpui_kit::AnyElement;
use gpui_kit::App;
use gpui_kit::AppContext as _;
use gpui_kit::Context;
use gpui_kit::Entity;
use gpui_kit::IntoElement;
use gpui_kit::ParentElement as _;
use gpui_kit::PathPromptOptions;
use gpui_kit::Render;
use gpui_kit::SharedString;
use gpui_kit::Styled as _;
use gpui_kit::Task;
use gpui_kit::Window;
use gpui_kit::WindowOptions;
use gpui_kit::assets;
use gpui_kit::base::StyledExt as _;
use gpui_kit::base::h_flex;
use gpui_kit::base::v_flex;
use gpui_kit::component::ActiveTheme as _;
use gpui_kit::component::Disableable as _;
use gpui_kit::component::button::Button;
use gpui_kit::component::button::ButtonVariants as _;
use gpui_kit::component::form::Field;
use gpui_kit::component::form::Form;
use gpui_kit::component::input::Input;
use gpui_kit::component::input::InputState;
use gpui_kit::component::radio::Radio;
use gpui_kit::component::radio::RadioGroup;
use gpui_kit::div;
use gpui_kit::init;
use gpui_kit::open_window;
use gpui_kit::px;
use openxbdm_client::commands::Gamepad;

use crate::gamepad::HardwareController;
use crate::gamepad::scan_controllers;
use crate::relay::RelayPhase;
use crate::relay::RelayRequest;
use crate::relay::RelaySnapshot;
use crate::relay::RelaySource;
use crate::relay::RelayWorker;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceKind {
    Hardware,
    Script,
}

pub struct ControllerApp {
    target: Entity<InputState>,
    script_path: Entity<InputState>,
    source_kind: SourceKind,
    controllers: Vec<HardwareController>,
    selected_controller: Option<usize>,
    scan_error: Option<String>,
    validation_error: Option<String>,
    worker: Option<RelayWorker>,
    snapshot: Option<RelaySnapshot>,
    scan_task: Option<Task<()>>,
    file_task: Option<Task<()>>,
    _status_task: Task<()>,
}

impl ControllerApp {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let target = cx.new(|cx| {
            InputState::new(window, cx)
                .default_value("192.168.1.27")
                .placeholder("Console IP or hostname")
        });
        let script_path = cx.new(|cx| {
            InputState::new(window, cx).placeholder("Path to a controller script (.json)")
        });
        let status_task = cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(50))
                    .await;
                if this.update(cx, |this, cx| this.poll_worker(cx)).is_err() {
                    break;
                }
            }
        });
        let mut app = Self {
            target,
            script_path,
            source_kind: SourceKind::Hardware,
            controllers: Vec::new(),
            selected_controller: None,
            scan_error: None,
            validation_error: None,
            worker: None,
            snapshot: None,
            scan_task: None,
            file_task: None,
            _status_task: status_task,
        };
        app.scan_controllers(cx);

        app
    }

    fn poll_worker(&mut self, cx: &mut Context<Self>) -> bool {
        let Some(worker) = self.worker.as_mut() else {
            return false;
        };

        if let Some(snapshot) = worker.snapshot() {
            self.snapshot = Some(snapshot);
        }
        if worker.is_finished() {
            if let Err(error) = worker.join() {
                self.validation_error = Some(error.to_string());
            }
            self.worker = None;
        }
        cx.notify();

        true
    }

    fn scan_controllers(&mut self, cx: &mut Context<Self>) {
        self.scan_error = None;
        self.scan_task = Some(cx.spawn(async move |this, cx| {
            let result = cx.background_spawn(async { scan_controllers() }).await;
            _ = this.update(cx, |this, cx| {
                match result {
                    Ok(controllers) => {
                        this.controllers = controllers;
                        this.selected_controller = (!this.controllers.is_empty()).then_some(0);
                    }
                    Err(error) => {
                        this.controllers.clear();
                        this.selected_controller = None;
                        this.scan_error = Some(error.to_string());
                    }
                }
                cx.notify();
            });
        }));
    }

    fn choose_script(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let receiver = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some(SharedString::from("Select controller script")),
        });
        self.file_task = Some(cx.spawn_in(window, async move |this, cx| {
            let Ok(result) = receiver.await else {
                return;
            };
            let Ok(Some(mut paths)) = result else {
                return;
            };
            let Some(path) = paths.pop() else {
                return;
            };

            _ = this.update_in(cx, |this, window, cx| {
                this.script_path.update(cx, |input, cx| {
                    input.set_value(path.to_string_lossy().into_owned(), window, cx);
                });
                this.source_kind = SourceKind::Script;
                this.validation_error = None;
                cx.notify();
            });
        }));
    }

    fn start_relay(&mut self, cx: &mut Context<Self>) {
        self.validation_error = None;
        let target = self.target.read(cx).value().trim().to_owned();
        if target.is_empty() {
            self.validation_error = Some("Enter a console IP address or hostname".to_owned());
            cx.notify();
            return;
        }

        let source = match self.source_kind {
            SourceKind::Hardware => {
                let Some(index) = self.selected_controller else {
                    self.validation_error =
                        Some("Select a connected hardware controller".to_owned());
                    cx.notify();
                    return;
                };
                let Some(controller) = self.controllers.get(index) else {
                    self.validation_error =
                        Some("Refresh and select a hardware controller".to_owned());
                    cx.notify();
                    return;
                };

                RelaySource::Hardware(controller.identity)
            }
            SourceKind::Script => {
                let path = self.script_path.read(cx).value().trim().to_owned();
                if path.is_empty() {
                    self.validation_error = Some("Select a controller script".to_owned());
                    cx.notify();
                    return;
                }

                RelaySource::Script(PathBuf::from(path))
            }
        };

        match RelayWorker::start(RelayRequest { target, source }) {
            Ok(worker) => {
                self.snapshot = worker.snapshot();
                self.worker = Some(worker);
            }
            Err(error) => {
                self.validation_error = Some(format!("Could not start relay worker: {error}"));
            }
        }
        cx.notify();
    }

    fn stop_relay(&mut self, cx: &mut Context<Self>) {
        if let Some(worker) = &self.worker {
            worker.stop();
        }
        cx.notify();
    }

    fn source_panel(&self, cx: &mut Context<Self>) -> AnyElement {
        let active = self.worker.is_some();
        let source_selector = RadioGroup::horizontal("source-kind")
            .children(["Hardware controller", "Controller script"])
            .selected_index(Some(match self.source_kind {
                SourceKind::Hardware => 0,
                SourceKind::Script => 1,
            }))
            .disabled(active)
            .on_change(cx.listener(|this, index, _, cx| {
                this.source_kind = if *index == 0 {
                    SourceKind::Hardware
                } else {
                    SourceKind::Script
                };
                this.validation_error = None;
                cx.notify();
            }));

        let source = match self.source_kind {
            SourceKind::Hardware => self.hardware_source(cx),
            SourceKind::Script => self.script_source(cx),
        };

        panel(cx, "Input source")
            .child(source_selector)
            .child(source)
            .into_any_element()
    }

    fn hardware_source(&self, cx: &mut Context<Self>) -> AnyElement {
        let active = self.worker.is_some();
        let mut group = RadioGroup::vertical("hardware-controller")
            .selected_index(self.selected_controller)
            .disabled(active)
            .on_change(cx.listener(|this, index, _, cx| {
                this.selected_controller = Some(*index);
                this.validation_error = None;
                cx.notify();
            }));
        for (index, controller) in self.controllers.iter().enumerate() {
            group = group.child(
                Radio::new(format!("controller-{index}"))
                    .label(controller.name.clone())
                    .child(
                        div()
                            .text_xs()
                            .text_color(cx.theme().muted_foreground)
                            .child(controller.identifier()),
                    ),
            );
        }

        let empty_message = if self.controllers.is_empty() {
            self.scan_error
                .as_deref()
                .unwrap_or("No connected controllers found")
        } else {
            ""
        };

        v_flex()
            .gap_3()
            .child(group)
            .child(
                div()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child(empty_message.to_owned()),
            )
            .child(
                Button::new("refresh-controllers")
                    .label("Refresh controllers")
                    .disabled(active)
                    .on_click(cx.listener(|this, _, _, cx| this.scan_controllers(cx))),
            )
            .into_any_element()
    }

    fn script_source(&self, cx: &mut Context<Self>) -> AnyElement {
        let active = self.worker.is_some();

        v_flex()
            .gap_2()
            .child(
                h_flex()
                    .gap_2()
                    .child(div().flex_1().child(Input::new(&self.script_path).disabled(active)))
                    .child(
                        Button::new("browse-script")
                            .label("Browse")
                            .disabled(active)
                            .on_click(cx.listener(|this, _, window, cx| {
                                this.choose_script(window, cx);
                            })),
                    ),
            )
            .child(
                div()
                    .text_xs()
                    .text_color(cx.theme().muted_foreground)
                    .child("JSON frames use normalized stick values from -1.0 to 1.0 and trigger values from 0.0 to 1.0."),
            )
            .into_any_element()
    }

    fn status_panel(&self, cx: &mut Context<Self>) -> AnyElement {
        let (phase, detail) = match &self.snapshot {
            Some(snapshot) => {
                let detail = match &snapshot.phase {
                    RelayPhase::Failed(message) => message.clone(),
                    _ => snapshot
                        .console_banner
                        .clone()
                        .unwrap_or_else(|| snapshot.target.clone()),
                };
                (snapshot.phase.label().to_owned(), detail)
            }
            None => (
                "Disconnected".to_owned(),
                "No active console session".to_owned(),
            ),
        };
        let color = match self.snapshot.as_ref().map(|snapshot| &snapshot.phase) {
            Some(RelayPhase::Relaying | RelayPhase::PlayingScript | RelayPhase::Completed) => {
                cx.theme().green
            }
            Some(RelayPhase::Failed(_)) => cx.theme().red,
            Some(RelayPhase::Preparing | RelayPhase::Connecting | RelayPhase::Stopping) => {
                cx.theme().yellow
            }
            _ => cx.theme().muted_foreground,
        };
        let packet = self
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.last_gamepad)
            .map(packet_text)
            .unwrap_or_else(|| "No controller packet sent".to_owned());
        let packets_sent = self
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.packets_sent)
            .unwrap_or(0);
        let script_progress = self.snapshot.as_ref().and_then(|snapshot| {
            let total = snapshot.script_frames?;
            let remaining = snapshot.script_frames_remaining?;
            Some(format!(
                "{} / {total} frames complete",
                total.saturating_sub(remaining)
            ))
        });

        panel(cx, "Connection status")
            .child(
                h_flex()
                    .gap_2()
                    .items_center()
                    .child(div().size(px(9.)).rounded_full().bg(color))
                    .child(div().font_semibold().child(phase)),
            )
            .child(
                div()
                    .text_sm()
                    .text_color(cx.theme().muted_foreground)
                    .child(detail),
            )
            .child(status_row("Packets sent", packets_sent.to_string(), cx))
            .child(status_row("Current state", packet, cx))
            .children(script_progress.map(|progress| status_row("Script", progress, cx)))
            .into_any_element()
    }
}

impl Render for ControllerApp {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let active = self.worker.is_some();
        let error = self.validation_error.clone();

        v_flex()
            .size_full()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .p_6()
            .gap_5()
            .child(
                v_flex()
                    .gap_1()
                    .child(div().text_2xl().font_bold().child("Controller Relay"))
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child("Send a local controller or timed script to an Xbox 360 console over XBDM."),
                    ),
            )
            .child(
                panel(cx, "Console")
                    .child(
                        Form::new().child(
                            Field::new()
                                .label("IP address or hostname")
                                .description("XBDM port 730 is used unless the target includes a port.")
                                .child(Input::new(&self.target).disabled(active)),
                        ),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(cx.theme().muted_foreground)
                            .child("Virtual controller slot: user 1"),
                    ),
            )
            .child(
                h_flex()
                    .items_start()
                    .gap_4()
                    .child(div().flex_1().child(self.source_panel(cx)))
                    .child(div().flex_1().child(self.status_panel(cx))),
            )
            .children(error.map(|message| {
                div()
                    .p_3()
                    .rounded(cx.theme().radius)
                    .bg(cx.theme().red.opacity(0.12))
                    .text_color(cx.theme().red)
                    .child(message)
            }))
            .child(
                h_flex()
                    .justify_end()
                    .gap_2()
                    .child(
                        Button::new("stop-relay")
                            .label("Stop")
                            .danger()
                            .outline()
                            .disabled(!active)
                            .on_click(cx.listener(|this, _, _, cx| this.stop_relay(cx))),
                    )
                    .child(
                        Button::new("start-relay")
                            .label("Connect and relay")
                            .primary()
                            .disabled(active)
                            .on_click(cx.listener(|this, _, _, cx| this.start_relay(cx))),
                    ),
            )
    }
}

fn panel(cx: &App, title: &'static str) -> gpui_kit::Div {
    v_flex()
        .gap_3()
        .p_4()
        .border_1()
        .border_color(cx.theme().border)
        .rounded(cx.theme().radius)
        .bg(cx.theme().secondary)
        .child(div().text_lg().font_semibold().child(title))
}

fn status_row(label: &'static str, value: String, cx: &App) -> gpui_kit::Div {
    v_flex()
        .gap_1()
        .child(
            div()
                .text_xs()
                .text_color(cx.theme().muted_foreground)
                .child(label),
        )
        .child(div().text_sm().child(value))
}

fn packet_text(packet: Gamepad) -> String {
    format!(
        "buttons 0x{:04x}, triggers {} / {}, left {} / {}, right {} / {}",
        packet.buttons.bits(),
        packet.left_trigger,
        packet.right_trigger,
        packet.left_thumb_x,
        packet.left_thumb_y,
        packet.right_thumb_x,
        packet.right_thumb_y,
    )
}

pub fn run() {
    gpui_kit::application()
        .with_assets(assets::Assets)
        .run(|cx| {
            init(cx);
            open_window(WindowOptions::default(), cx, |window, cx| {
                cx.new(|cx| ControllerApp::new(window, cx))
            })
            .expect("failed to open controller relay window");
        });
}
