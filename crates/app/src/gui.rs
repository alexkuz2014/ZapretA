//! Window and tray UI. All engine work happens in [`Controller`]; the UI only
//! sends commands and draws snapshots.

use crate::{
    controller::{Command, Controller, Paths, Phase, Snapshot, describe_signal},
    embedded::ENGINE_ID,
    lists::{self, ListKind},
    settings::Settings,
    winutil,
};
use eframe::egui::{self, Color32, RichText};
use std::{
    path::PathBuf,
    process::ExitCode,
    sync::mpsc::{self, Receiver},
    time::Duration,
};
use tray_icon::{
    Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent,
    menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem},
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Home,
    Sites,
    Ips,
    Excludes,
    Settings,
    Log,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TrayAction {
    Open,
    Toggle,
    Research,
    Quit,
}

struct ListEditor {
    kind: ListKind,
    text: String,
    message: Option<(bool, String)>,
}

impl ListEditor {
    fn load(kind: ListKind, root: &std::path::Path) -> Self {
        Self {
            kind,
            text: lists::read(root, kind).join("\n"),
            message: None,
        }
    }
}

struct App {
    controller: Controller,
    paths_settings: PathBuf,
    engine_root: PathBuf,
    app_dir: PathBuf,
    settings: Settings,
    autostart: bool,
    tab: Tab,
    editors: Vec<ListEditor>,
    snapshot: Snapshot,
    tray: Option<TrayIcon>,
    tray_rx: Receiver<TrayAction>,
    tray_state: Option<TrayState>,
    quitting: bool,
    toggle_item: Option<MenuItem>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum TrayState {
    Off,
    Busy,
    On,
    Error,
}

fn circle_rgba(size: u32, color: [u8; 3]) -> Vec<u8> {
    let mut rgba = Vec::with_capacity((size * size * 4) as usize);
    let center = (size as f32 - 1.0) / 2.0;
    let radius = size as f32 / 2.0 - 0.5;
    for y in 0..size {
        for x in 0..size {
            let dx = x as f32 - center;
            let dy = y as f32 - center;
            let distance = (dx * dx + dy * dy).sqrt();
            // Soft edge for a cleaner look at tray sizes.
            let alpha = (radius - distance + 0.5).clamp(0.0, 1.0);
            // Inner ring makes the icon readable on light and dark taskbars.
            let ring = distance > radius - 2.5;
            let [r, g, b] = if ring { [255, 255, 255] } else { color };
            rgba.extend_from_slice(&[r, g, b, (alpha * 255.0) as u8]);
        }
    }
    rgba
}

fn state_color(state: TrayState) -> [u8; 3] {
    match state {
        TrayState::Off => [120, 120, 128],
        TrayState::Busy => [230, 160, 30],
        TrayState::On => [40, 170, 90],
        TrayState::Error => [210, 60, 60],
    }
}

fn tray_icon(state: TrayState) -> Option<Icon> {
    Icon::from_rgba(circle_rgba(32, state_color(state)), 32, 32).ok()
}

fn tray_state(phase: &Phase) -> TrayState {
    match phase {
        Phase::Off => TrayState::Off,
        Phase::Preparing | Phase::Checking | Phase::Searching { .. } => TrayState::Busy,
        Phase::Running { .. } => TrayState::On,
        Phase::Failed(_) => TrayState::Error,
    }
}

fn phase_text(phase: &Phase) -> (String, Color32) {
    match phase {
        Phase::Off => ("Обход выключен".into(), Color32::GRAY),
        Phase::Preparing => ("Подготовка движка…".into(), Color32::from_rgb(230, 160, 30)),
        Phase::Checking => ("Проверяю сеть…".into(), Color32::from_rgb(230, 160, 30)),
        Phase::Searching { tried, total, .. } => (
            format!("Подбираю стратегию: {tried} из {total}"),
            Color32::from_rgb(230, 160, 30),
        ),
        Phase::Running { .. } => ("Обход работает".into(), Color32::from_rgb(40, 170, 90)),
        Phase::Failed(_) => ("Не получилось".into(), Color32::from_rgb(210, 60, 60)),
    }
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>, paths: Paths, app_dir: PathBuf) -> Self {
        let ctx = cc.egui_ctx.clone();
        let paths_settings = paths.settings.clone();
        let engine_root = paths.engine_root.clone();
        let repaint = ctx.clone();
        let controller = Controller::spawn(paths, Box::new(move || repaint.request_repaint()));

        let (tray_tx, tray_rx) = mpsc::channel();
        let open = MenuItem::new("Открыть ZapretA", true, None);
        let toggle = MenuItem::new("Выключить обход", true, None);
        let research = MenuItem::new("Подобрать заново", true, None);
        let quit = MenuItem::new("Выход", true, None);
        let menu = Menu::new();
        let _ = menu.append_items(&[
            &open,
            &toggle,
            &research,
            &PredefinedMenuItem::separator(),
            &quit,
        ]);
        let ids = [
            (open.id().clone(), TrayAction::Open),
            (toggle.id().clone(), TrayAction::Toggle),
            (research.id().clone(), TrayAction::Research),
            (quit.id().clone(), TrayAction::Quit),
        ];
        {
            let tx = tray_tx.clone();
            let ctx = ctx.clone();
            MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
                if let Some((_, action)) = ids.iter().find(|(id, _)| *id == event.id) {
                    if *action == TrayAction::Open {
                        winutil::show_window();
                    }
                    let _ = tx.send(*action);
                    ctx.request_repaint();
                }
            }));
        }
        {
            let tx = tray_tx;
            let ctx = ctx.clone();
            TrayIconEvent::set_event_handler(Some(move |event: TrayIconEvent| {
                if let TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } = event
                {
                    // Works even while the window is hidden and not repainting.
                    winutil::show_window();
                    let _ = tx.send(TrayAction::Open);
                    ctx.request_repaint();
                }
            }));
        }
        let mut builder = TrayIconBuilder::new()
            .with_tooltip("ZapretA")
            .with_menu(Box::new(menu))
            .with_menu_on_left_click(false);
        if let Some(icon) = tray_icon(TrayState::Off) {
            builder = builder.with_icon(icon);
        }
        let tray = builder.build().ok();

        let settings = Settings::load(&paths_settings);
        let editors = ListKind::ALL
            .iter()
            .map(|kind| ListEditor::load(*kind, &engine_root))
            .collect();
        Self {
            controller,
            paths_settings,
            engine_root,
            app_dir,
            settings,
            autostart: winutil::autostart_enabled(),
            tab: Tab::Home,
            editors,
            snapshot: Snapshot {
                phase: Phase::Off,
                log: Vec::new(),
                baseline: None,
            },
            tray,
            tray_rx,
            tray_state: None,
            quitting: false,
            toggle_item: Some(toggle),
        }
    }

    fn engine_active(&self) -> bool {
        !matches!(self.snapshot.phase, Phase::Off | Phase::Failed(_))
    }

    fn toggle(&self) {
        if self.engine_active() {
            self.controller.send(Command::Disable);
        } else {
            self.controller.send(Command::Enable);
        }
    }

    fn save_settings(&mut self) {
        // The worker writes the cached strategy; keep it when saving toggles.
        let on_disk = Settings::load(&self.paths_settings);
        self.settings.last_strategy = on_disk.last_strategy;
        self.settings.last_engine = on_disk.last_engine;
        let _ = self.settings.save(&self.paths_settings);
    }

    fn sync_tray(&mut self) {
        let state = tray_state(&self.snapshot.phase);
        if self.tray_state == Some(state) {
            return;
        }
        self.tray_state = Some(state);
        if let Some(tray) = &self.tray {
            let _ = tray.set_icon(tray_icon(state));
            let tip = match &self.snapshot.phase {
                Phase::Running { label } => format!("ZapretA: работает\n{label}"),
                phase => format!("ZapretA: {}", phase_text(phase).0),
            };
            let _ = tray.set_tooltip(Some(tip));
        }
        if let Some(item) = &self.toggle_item {
            item.set_text(if self.engine_active() {
                "Выключить обход"
            } else {
                "Включить обход"
            });
        }
    }

    fn header(&mut self, ui: &mut egui::Ui) {
        let (text, color) = phase_text(&self.snapshot.phase);
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::hover());
            ui.painter().circle_filled(rect.center(), 8.0, color);
            ui.label(RichText::new(text).size(22.0).strong());
        });
        match &self.snapshot.phase {
            Phase::Running { label } => {
                ui.label(format!("Стратегия: {label}"));
            }
            Phase::Searching {
                tried,
                total,
                label,
            } => {
                ui.add(
                    egui::ProgressBar::new(*tried as f32 / (*total).max(1) as f32)
                        .show_percentage(),
                );
                ui.label(RichText::new(format!("Пробую: {label}")).weak());
                ui.label(
                    RichText::new(
                        "Каждая неподходящая стратегия занимает до 10–15 секунд. Окно можно свернуть.",
                    )
                    .weak(),
                );
            }
            Phase::Failed(message) => {
                ui.label(RichText::new(message).color(Color32::from_rgb(210, 60, 60)));
            }
            _ => {}
        }
        if let Some(signal) = self.snapshot.baseline {
            ui.label(RichText::new(format!("Сеть без обхода: {}", describe_signal(signal))).weak());
        }
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            let (label, fill) = if self.engine_active() {
                ("Выключить", Color32::from_rgb(120, 120, 128))
            } else {
                ("Включить", Color32::from_rgb(40, 140, 80))
            };
            let button = egui::Button::new(RichText::new(label).size(18.0).color(Color32::WHITE))
                .fill(fill)
                .min_size(egui::vec2(150.0, 38.0));
            if ui.add(button).clicked() {
                self.toggle();
            }
            if ui
                .add(egui::Button::new("Подобрать заново").min_size(egui::vec2(0.0, 38.0)))
                .on_hover_text("Перебрать все стратегии, не доверяя сохранённой")
                .clicked()
            {
                self.controller.send(Command::Research);
            }
            if ui
                .add_enabled(
                    matches!(self.snapshot.phase, Phase::Running { .. }),
                    egui::Button::new("Открыть YouTube").min_size(egui::vec2(0.0, 38.0)),
                )
                .clicked()
            {
                winutil::open_url("https://www.youtube.com");
            }
        });
    }

    fn home(&mut self, ui: &mut egui::Ui) {
        ui.label(
            "ZapretA сам подбирает способ обхода замедления и блокировок: сначала 22 проверенных \
             профиля Flowseal, затем 29 собственных вариантов по методике blockcheck. \
             Трафик не уходит на сторонние серверы, это не VPN: меняются только пакеты на этом компьютере.",
        );
        ui.add_space(6.0);
        ui.label(
            "Обход действует для YouTube, Discord и сайтов из вкладок «Сайты» и «IP-адреса». \
             Пока программа работает (значок в трее у часов), обход включён.",
        );
        ui.add_space(6.0);
        ui.label(
            RichText::new(
                "Если ничего не помогает: отключите VPN и другие обходы (GoodbyeDPI, zapret), \
                 добавьте папку программы в исключения антивируса (он может блокировать драйвер WinDivert) \
                 и нажмите «Подобрать заново».",
            )
            .weak(),
        );
    }

    fn list_editor(&mut self, ui: &mut egui::Ui, index: usize, title: &str, hint: &str) {
        let editor = &mut self.editors[index];
        ui.label(RichText::new(title).strong());
        ui.label(RichText::new(hint).weak());
        egui::ScrollArea::vertical()
            .id_salt(index)
            .max_height(180.0)
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut editor.text)
                        .font(egui::TextStyle::Monospace)
                        .desired_rows(8)
                        .desired_width(f32::INFINITY),
                );
            });
        let mut saved = false;
        ui.horizontal(|ui| {
            if ui.button("Сохранить").clicked() {
                match lists::parse(editor.kind, &editor.text) {
                    Ok(entries) => match lists::write(&self.engine_root, editor.kind, &entries) {
                        Ok(()) => {
                            editor.text = entries.join("\n");
                            editor.message = Some((
                                true,
                                format!("Сохранено: {} шт. Изменения применены.", entries.len()),
                            ));
                            saved = true;
                        }
                        Err(error) => {
                            editor.message = Some((false, format!("Не удалось сохранить: {error}")))
                        }
                    },
                    Err(errors) => {
                        let lines = errors
                            .iter()
                            .take(5)
                            .map(|(line, text)| format!("строка {line}: «{}»", text.trim()))
                            .collect::<Vec<_>>()
                            .join("; ");
                        editor.message = Some((false, format!("Не сохранено, ошибки: {lines}")));
                    }
                }
            }
            if ui.button("Отменить изменения").clicked() {
                *editor = ListEditor::load(editor.kind, &self.engine_root);
            }
        });
        if let Some((ok, message)) = &editor.message {
            let color = if *ok {
                Color32::from_rgb(40, 170, 90)
            } else {
                Color32::from_rgb(210, 60, 60)
            };
            ui.label(RichText::new(message).color(color));
        }
        if saved {
            self.controller.send(Command::ReloadLists);
        }
    }

    fn settings_tab(&mut self, ui: &mut egui::Ui) {
        let mut changed = false;
        changed |= ui
            .checkbox(
                &mut self.settings.enable_on_start,
                "Включать обход при запуске программы",
            )
            .changed();
        changed |= ui
            .checkbox(
                &mut self.settings.minimize_to_tray,
                "При закрытии окна сворачивать в трей (обход продолжает работать)",
            )
            .changed();
        changed |= ui
            .checkbox(
                &mut self.settings.watchdog,
                "Следить за доступом и сам переподбирать стратегию при ухудшении",
            )
            .changed();
        changed |= ui
            .checkbox(
                &mut self.settings.test_user_sites,
                "Проверять мои сайты при подборе (первые три из списка)",
            )
            .changed();
        if changed {
            self.save_settings();
        }
        let mut autostart = self.autostart;
        if ui
            .checkbox(
                &mut autostart,
                "Запускать вместе с Windows (в трее, без запроса UAC)",
            )
            .changed()
        {
            let result = if autostart {
                winutil::enable_autostart(&self.app_dir)
            } else {
                winutil::disable_autostart()
            };
            if let Err(error) = result {
                winutil::message_box(&format!("Не удалось изменить автозапуск: {error}"));
            }
            self.autostart = winutil::autostart_enabled();
        }
        ui.add_space(10.0);
        ui.horizontal(|ui| {
            if ui.button("Забыть сохранённую стратегию").clicked() {
                let mut settings = Settings::load(&self.paths_settings);
                settings.last_strategy = None;
                settings.last_engine = None;
                let _ = settings.save(&self.paths_settings);
            }
            if ui.button("Открыть папку данных").clicked() {
                winutil::open_folder(&self.app_dir);
            }
        });
        ui.add_space(10.0);
        ui.label(
            RichText::new(format!(
                "ZapretA {} · движок {ENGINE_ID} (winws v72.9, WinDivert). Лицензия MIT; сторонние компоненты — \
                 под своими лицензиями (THIRD_PARTY_NOTICES).",
                env!("CARGO_PKG_VERSION")
            ))
            .weak(),
        );
    }

    fn log_tab(&mut self, ui: &mut egui::Ui) {
        if ui.button("Скопировать журнал").clicked() {
            ui.ctx().copy_text(self.snapshot.log.join("\n"));
        }
        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for line in &self.snapshot.log {
                    ui.label(RichText::new(line).monospace());
                }
            });
    }
}

impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.snapshot = self.controller.snapshot();
        while let Ok(action) = self.tray_rx.try_recv() {
            match action {
                TrayAction::Open => {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                TrayAction::Toggle => self.toggle(),
                TrayAction::Research => self.controller.send(Command::Research),
                TrayAction::Quit => {
                    self.quitting = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }
        if ctx.input(|i| i.viewport().close_requested())
            && self.settings.minimize_to_tray
            && self.tray.is_some()
            && !self.quitting
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }
        self.sync_tray();
        // Keep the progress fresh and the tray responsive while hidden.
        ctx.request_repaint_after(Duration::from_millis(500));
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::Panel::top("header").show(ui, |ui| {
            self.header(ui);
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                for (tab, title) in [
                    (Tab::Home, "Главная"),
                    (Tab::Sites, "Сайты"),
                    (Tab::Ips, "IP-адреса"),
                    (Tab::Excludes, "Исключения"),
                    (Tab::Settings, "Настройки"),
                    (Tab::Log, "Журнал"),
                ] {
                    ui.selectable_value(&mut self.tab, tab, title);
                }
            });
            ui.add_space(4.0);
        });
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| match self.tab {
                    Tab::Home => self.home(ui),
                    Tab::Sites => self.list_editor(
                        ui,
                        0,
                        "Мои сайты",
                        "По одному домену в строке, можно вставлять ссылки целиком. Поддомены включаются автоматически \
                         (example.com покрывает www.example.com). Если сайт блокируют через подмену DNS, \
                         одной этой программы может не хватить.",
                    ),
                    Tab::Ips => self.list_editor(
                        ui,
                        1,
                        "Мои IP-адреса и подсети",
                        "По одному в строке: 1.2.3.4, 10.0.0.0/8 или IPv6. Обход применяется к HTTPS (TCP 443) на эти адреса.",
                    ),
                    Tab::Excludes => {
                        self.list_editor(
                            ui,
                            2,
                            "Сайты-исключения",
                            "К этим доменам обход не применяется никогда (банки, госуслуги, рабочие сервисы).",
                        );
                        ui.add_space(12.0);
                        self.list_editor(ui, 3, "IP-исключения", "Адреса и подсети, которые обход не трогает.");
                    }
                    Tab::Settings => self.settings_tab(ui),
                    Tab::Log => self.log_tab(ui),
                });
        });
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.controller.shutdown();
    }
}

pub fn run(start_hidden: bool) -> ExitCode {
    let Some(_instance) = winutil::single_instance() else {
        if !winutil::show_window() {
            winutil::message_box("ZapretA уже запущен: значок у часов в трее.");
        }
        return ExitCode::SUCCESS;
    };
    let Some(paths) = Paths::default_paths() else {
        winutil::message_box("Не найдена папка %LOCALAPPDATA%.");
        return ExitCode::FAILURE;
    };
    let app_dir = paths
        .engine_root
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| paths.engine_root.clone());
    let icon = egui::IconData {
        rgba: circle_rgba(64, state_color(TrayState::On)),
        width: 64,
        height: 64,
    };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(winutil::WINDOW_TITLE)
            .with_inner_size([620.0, 560.0])
            .with_min_inner_size([480.0, 420.0])
            .with_visible(!start_hidden)
            .with_icon(icon),
        ..Default::default()
    };
    match eframe::run_native(
        winutil::WINDOW_TITLE,
        options,
        Box::new(move |cc| Ok(Box::new(App::new(cc, paths, app_dir)))),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            winutil::message_box(&format!("Не удалось открыть окно: {error}"));
            ExitCode::FAILURE
        }
    }
}
