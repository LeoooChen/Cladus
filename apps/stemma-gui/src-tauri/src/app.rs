//! Window, tray and the connection to the engine service.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::Serialize;
use stemma_ipc::Request;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{
    AppHandle, Emitter, Manager, PhysicalPosition, WebviewUrl, WebviewWindowBuilder, WindowEvent,
};
use tauri_plugin_dialog::DialogExt;

use crate::prefs::{self, Geometry, Prefs};
use crate::{autostart, commands, engine, icons, view};

const TRAY_ID: &str = "main";
const MIN_WIDTH: f64 = 900.0;
const MIN_HEIGHT: f64 = 600.0;

#[derive(Clone, Debug, Default, Serialize)]
pub struct EngineState {
    /// The service answered the last request.
    pub connected: bool,
    pub engaged: bool,
    /// Why the service is unreachable or refused to engage.
    pub message: Option<String>,
    /// DNS queries currently bypass the proxy because it failed.
    pub dns_fallback: bool,
}

pub struct AppState {
    pub prefs: Mutex<Prefs>,
    pub engine: Mutex<EngineState>,
    pub wake: tokio::sync::Notify,
    quitting: AtomicBool,
    lifecycle: tokio::sync::Mutex<()>,
    icons: Mutex<HashMap<String, Option<Vec<u8>>>>,
    names: Mutex<HashMap<String, u32>>,
}

/// UI strings shared with the web UI's Chinese catalog.
fn tr(key: &'static str, language: &str) -> String {
    static CATALOG: std::sync::OnceLock<HashMap<String, String>> = std::sync::OnceLock::new();
    if prefs::resolved_language(language) != "zh-CN" {
        return key.to_owned();
    }
    CATALOG
        .get_or_init(|| {
            serde_json::from_str(include_str!("../../src/i18n/zh-CN.json")).unwrap_or_default()
        })
        .get(key)
        .cloned()
        .unwrap_or_else(|| key.to_owned())
}

pub fn run() {
    let autostarted = std::env::args().any(|arg| arg == "--autostart");
    let quit_only = std::env::args().any(|arg| arg == "--quit");
    let prefs = prefs::load();
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, args, _| {
            if args.iter().any(|arg| arg == "--quit") {
                quit(app);
            } else {
                show_main(app);
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .manage(AppState {
            prefs: Mutex::new(prefs),
            engine: Mutex::new(EngineState::default()),
            wake: tokio::sync::Notify::new(),
            quitting: AtomicBool::new(false),
            lifecycle: tokio::sync::Mutex::new(()),
            icons: Mutex::new(HashMap::new()),
            names: Mutex::new(HashMap::new()),
        })
        .register_asynchronous_uri_scheme_protocol("icon", |context, request, responder| {
            let app = context.app_handle().clone();
            let name = percent_decode(request.uri().path().trim_start_matches('/'));
            tauri::async_runtime::spawn_blocking(move || {
                let response = match icon_png(&app, &name) {
                    Some(png) => tauri::http::Response::builder()
                        .header("Content-Type", "image/png")
                        .header("Cache-Control", "max-age=3600")
                        .body(png),
                    None => tauri::http::Response::builder()
                        .status(404)
                        .body(Vec::new()),
                };
                responder.respond(response.expect("valid response"));
            });
        })
        .invoke_handler(tauri::generate_handler![
            commands::frontend_ready,
            commands::engine_state,
            commands::get_ui_prefs,
            commands::set_ui_prefs,
            commands::window_cmd,
            commands::get_stats,
            commands::process_detail,
            commands::hijack,
            commands::unhijack,
            commands::batch_hijack,
            commands::connections,
            commands::list_rules,
            commands::create_rule,
            commands::update_rule,
            commands::set_rule_enabled,
            commands::delete_rule,
            commands::set_excluded,
            commands::get_config,
            commands::update_config,
            commands::list_groups,
            commands::create_group,
            commands::update_group,
            commands::delete_group,
            commands::migrate_group,
            commands::test_group,
            commands::check_group,
            commands::reveal_file,
            commands::browse_exe,
            commands::get_autostart,
            commands::set_autostart,
        ])
        .setup(move |app| {
            if quit_only {
                app.handle().exit(0);
                return Ok(());
            }
            autostart::repair();
            create_window(app.handle(), autostarted)?;
            create_tray(app.handle())?;
            tauri::async_runtime::spawn(poll(app.handle().clone()));
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("failed to start Stemma")
        .run(|app, event| {
            // Closing the last window must not end the app while it lives in the tray.
            if let tauri::RunEvent::ExitRequested {
                api, code: None, ..
            } = event
                && !app.state::<AppState>().quitting.load(Ordering::SeqCst)
            {
                api.prevent_exit();
            }
        });
}

fn data_dir() -> Option<PathBuf> {
    Some(PathBuf::from(std::env::var_os("LOCALAPPDATA")?).join("Stemma"))
}

fn create_window(app: &AppHandle, autostarted: bool) -> tauri::Result<()> {
    let state = app.state::<AppState>();
    let (geometry, hidden) = {
        let prefs = state.prefs.lock().unwrap();
        (prefs.window, autostarted && prefs.start_minimized)
    };
    let mut builder = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
        .title("Stemma")
        .decorations(false)
        .inner_size(
            geometry.map_or(1200.0, |g| g.width.max(MIN_WIDTH)),
            geometry.map_or(800.0, |g| g.height.max(MIN_HEIGHT)),
        )
        .min_inner_size(MIN_WIDTH, MIN_HEIGHT)
        .visible(false)
        .center();
    if let Some(dir) = data_dir() {
        builder = builder.data_directory(dir.join("WebView2"));
    }
    if cfg!(debug_assertions) || std::env::args().any(|arg| arg == "--devtools") {
        builder = builder.devtools(true);
    }
    let window = builder.build()?;
    // Never open larger than the work area of the monitor it lands on.
    if let (Some(monitor), Ok(size)) = (window.current_monitor()?, window.outer_size()) {
        let area = monitor.work_area().size;
        if size.width > area.width || size.height > area.height {
            let scale = monitor.scale_factor();
            let width = (size.width.min(area.width * 9 / 10) as f64 / scale).max(MIN_WIDTH);
            let height = (size.height.min(area.height * 9 / 10) as f64 / scale).max(MIN_HEIGHT);
            window.set_size(tauri::LogicalSize::new(width, height))?;
            window.center()?;
        }
    }
    if let Some(geometry) = geometry {
        // Only restore a position that is still on a connected monitor.
        let on_screen = window.available_monitors()?.iter().any(|m| {
            let (p, s) = (m.position(), m.size());
            geometry.x + 50 >= p.x
                && geometry.y >= p.y
                && geometry.x + 50 < p.x + s.width as i32
                && geometry.y + 20 < p.y + s.height as i32
        });
        if on_screen {
            window.set_position(PhysicalPosition::new(geometry.x, geometry.y))?;
        }
        if geometry.maximized {
            window.maximize()?;
        }
    }
    let handle = app.clone();
    window.on_window_event(move |event| match event {
        WindowEvent::CloseRequested { api, .. } => {
            api.prevent_close();
            close_requested(&handle);
        }
        WindowEvent::Resized(_) | WindowEvent::Moved(_) => {
            let _ = handle.emit("window_state", ());
        }
        _ => {}
    });
    if !hidden {
        window.show()?;
        window.set_focus()?;
    }
    Ok(())
}

fn save_geometry(app: &AppHandle) {
    let Some(window) = app.get_webview_window("main") else {
        return;
    };
    let state = app.state::<AppState>();
    let mut prefs = state.prefs.lock().unwrap();
    let maximized = window.is_maximized().unwrap_or(false);
    let visible = window.is_visible().unwrap_or(false) && !window.is_minimized().unwrap_or(false);
    let geometry = if maximized || !visible {
        // Keep the restored geometry; only remember the maximized state.
        prefs.window.map(|g| Geometry { maximized, ..g })
    } else {
        let (Ok(position), Ok(size), Ok(scale)) = (
            window.outer_position(),
            window.inner_size(),
            window.scale_factor(),
        ) else {
            return;
        };
        let logical = size.to_logical::<f64>(scale);
        Some(Geometry {
            x: position.x,
            y: position.y,
            width: logical.width,
            height: logical.height,
            maximized,
        })
    };
    if geometry != prefs.window {
        prefs.window = geometry;
        let _ = prefs::save(&prefs);
    }
}

pub fn show_main(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
        app.state::<AppState>().wake.notify_one();
    }
}

/// The window's close button: hide to the tray or quit, as configured.
pub fn close_requested(app: &AppHandle) {
    save_geometry(app);
    if app.state::<AppState>().prefs.lock().unwrap().close_to_tray {
        if let Some(window) = app.get_webview_window("main") {
            let _ = window.hide();
        }
    } else {
        quit(app);
    }
}

/// Quitting Stemma stops proxying; the service stays installed and idle.
pub fn quit(app: &AppHandle) {
    let state = app.state::<AppState>();
    if state.quitting.swap(true, Ordering::SeqCst) {
        return;
    }
    save_geometry(app);
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let state = app.state::<AppState>();
        let _lifecycle = state.lifecycle.lock().await;
        let result = tokio::time::timeout(Duration::from_secs(30), engine::ok(Request::Disengage))
            .await
            .map_err(|_| "The engine did not confirm shutdown in time.".to_owned())
            .and_then(|result| result);
        if result.is_ok() || matches!(stemma_platform_windows::service::is_running(), Ok(false)) {
            app.exit(0);
            return;
        }
        // A reply may have been lost after the stop completed.
        if matches!(tokio::time::timeout(Duration::from_secs(2), engine::status()).await,
            Ok(Ok(status)) if !status.engaged)
        {
            app.exit(0);
            return;
        }
        state.quitting.store(false, Ordering::SeqCst);
        let language = state.prefs.lock().unwrap().language.clone();
        let message = format!(
            "{}\n\n{}",
            tr(
                "Stemma could not confirm that proxying stopped. It will stay open so you can retry.",
                &language
            ),
            result.unwrap_err()
        );
        state.engine.lock().unwrap().message = Some(message.clone());
        show_main(&app);
        app.dialog()
            .message(message)
            .title("Stemma")
            .kind(tauri_plugin_dialog::MessageDialogKind::Error)
            .show(|_| {});
    });
}

fn tray_menu(app: &AppHandle) -> tauri::Result<Menu<tauri::Wry>> {
    let language = app
        .state::<AppState>()
        .prefs
        .lock()
        .unwrap()
        .language
        .clone();
    let show = MenuItem::with_id(
        app,
        "show",
        tr("Show Stemma", &language),
        true,
        None::<&str>,
    )?;
    let exit = MenuItem::with_id(app, "exit", tr("Exit", &language), true, None::<&str>)?;
    Menu::with_items(app, &[&show, &exit])
}

fn create_tray(app: &AppHandle) -> tauri::Result<()> {
    TrayIconBuilder::with_id(TRAY_ID)
        .icon(
            app.default_window_icon()
                .cloned()
                .expect("the app has an icon"),
        )
        .tooltip("Stemma")
        .menu(&tray_menu(app)?)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "show" => show_main(app),
            "exit" => quit(app),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main(tray.app_handle());
            }
        })
        .build(app)?;
    Ok(())
}

pub fn relabel_tray(app: &AppHandle) {
    if let (Some(tray), Ok(menu)) = (app.tray_by_id(TRAY_ID), tray_menu(app)) {
        let _ = tray.set_menu(Some(menu));
    }
}

fn window_visible(app: &AppHandle) -> bool {
    app.get_webview_window("main")
        .is_some_and(|w| w.is_visible().unwrap_or(false) && !w.is_minimized().unwrap_or(true))
}

/// Keeps the engine engaged while Stemma runs, and pushes state to the UI.
/// A service restarted after a crash comes back idle and is engaged again.
async fn poll(app: AppHandle) {
    let state = app.state::<AppState>();
    let mut last_tree = None;
    loop {
        if state.quitting.load(Ordering::SeqCst) {
            // Failed shutdown resets `quitting` and wakes this loop. Keep the
            // observer alive without re-engaging while shutdown is pending.
            state.wake.notified().await;
            continue;
        }
        let mut next = EngineState::default();
        match engine::status().await {
            Ok(status) => {
                next.connected = true;
                next.engaged = status.engaged;
                next.dns_fallback = status
                    .counters
                    .get("dns.fallback_active")
                    .copied()
                    .unwrap_or(0)
                    != 0;
                if !status.engaged {
                    let _lifecycle = state.lifecycle.lock().await;
                    if state.quitting.load(Ordering::SeqCst) {
                        continue;
                    }
                    match engine::ok(Request::Engage).await {
                        Ok(()) => next.engaged = true,
                        Err(err) => next.message = Some(err),
                    }
                }
            }
            Err(err) => next.message = Some(err),
        }
        let changed = {
            let mut current = state.engine.lock().unwrap();
            let changed = serde_json::to_value(&*current).ok() != serde_json::to_value(&next).ok();
            *current = next.clone();
            changed
        };
        if changed {
            let _ = app.emit("engine_state", &next);
            if let Some(tray) = app.tray_by_id(TRAY_ID) {
                let tip = match (&next.message, next.engaged) {
                    (Some(message), _) => format!("Stemma — {message}"),
                    (None, true) => "Stemma".to_owned(),
                    (None, false) => "Stemma (idle)".to_owned(),
                };
                let _ = tray.set_tooltip(Some(tip));
            }
        }
        if next.connected
            && window_visible(&app)
            && let Ok(processes) = engine::processes().await
        {
            *state.names.lock().unwrap() = processes
                .iter()
                .filter(|p| p.alive)
                .map(|p| (p.name.to_ascii_lowercase(), p.pid))
                .collect();
            let tree = view::tree(&processes);
            let json = serde_json::to_value(&tree).expect("tree serializes");
            if last_tree.as_ref() != Some(&json) {
                let _ = app.emit("process_update", &json);
                last_tree = Some(json);
            }
        } else if !window_visible(&app) {
            // Push a full snapshot as soon as the window shows again.
            last_tree = None;
        }
        let _ = tokio::time::timeout(Duration::from_secs(1), state.wake.notified()).await;
    }
}

fn icon_png(app: &AppHandle, name: &str) -> Option<Vec<u8>> {
    let state = app.state::<AppState>();
    let key = name.to_ascii_lowercase();
    if let Some(cached) = state.icons.lock().unwrap().get(&key) {
        return cached.clone();
    }
    let pid = state.names.lock().unwrap().get(&key).copied()?;
    let png = icons::image_path(pid).and_then(|path| icons::png_for(&path));
    state.icons.lock().unwrap().insert(key, png.clone());
    png
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(hex) = bytes.get(i + 1..i + 3)
            && let Some(byte) = std::str::from_utf8(hex)
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    #[test]
    fn percent_decoding() {
        assert_eq!(super::percent_decode("a%20b%E4%B8%AD.exe"), "a b中.exe");
        assert_eq!(super::percent_decode("100%"), "100%");
    }
}
