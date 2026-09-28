//! Commands the web UI invokes.

use serde::Serialize;
use serde_json::{Value, json};
use stemma_core::config::{Config, ProxyGroup, Rule};
use stemma_core::model::{GroupId, ProcessKey, ProcessView};
use stemma_ipc::{Request, Response};
use tauri::{AppHandle, Manager, State};

use crate::app::{AppState, EngineState};
use crate::view::{self, GroupInput, RuleInput};
use crate::{autostart, engine, prefs};

type Result<T> = std::result::Result<T, String>;

#[tauri::command]
pub fn frontend_ready(state: State<'_, AppState>) {
    state.wake.notify_one();
}

#[tauri::command]
pub fn engine_state(state: State<'_, AppState>) -> EngineState {
    state.engine.lock().unwrap().clone()
}

#[derive(Serialize)]
pub struct UiPrefs {
    language: String,
    close_to_tray: bool,
    start_minimized: bool,
}

#[tauri::command]
pub fn get_ui_prefs(state: State<'_, AppState>) -> UiPrefs {
    let prefs = state.prefs.lock().unwrap();
    UiPrefs {
        language: prefs.language.clone(),
        close_to_tray: prefs.close_to_tray,
        start_minimized: prefs.start_minimized,
    }
}

#[tauri::command(rename_all = "snake_case")]
pub fn set_ui_prefs(
    app: AppHandle,
    state: State<'_, AppState>,
    language: Option<String>,
    close_to_tray: Option<bool>,
) -> Result<()> {
    let mut prefs = state.prefs.lock().unwrap();
    let mut next = prefs.clone();
    if let Some(language) = language {
        next.language = match language.as_str() {
            "en" | "zh-CN" => language,
            _ => "system".to_owned(),
        };
    }
    if let Some(close_to_tray) = close_to_tray {
        next.close_to_tray = close_to_tray;
    }
    prefs::save(&next)?;
    *prefs = next;
    drop(prefs);
    crate::app::relabel_tray(&app);
    Ok(())
}

#[tauri::command(rename_all = "snake_case")]
pub fn window_cmd(app: AppHandle, cmd: String) -> Result<()> {
    let window = app.get_webview_window("main").ok_or("no window")?;
    let result = match cmd.as_str() {
        "minimize" => window.minimize(),
        "maximize" => {
            if window.is_maximized().unwrap_or(false) {
                window.unmaximize()
            } else {
                window.maximize()
            }
        }
        "close" => {
            crate::app::close_requested(&app);
            Ok(())
        }
        _ => return Err(format!("unknown window command {cmd}")),
    };
    result.map_err(|err| err.to_string())
}

#[tauri::command]
pub async fn get_stats() -> Result<Value> {
    let (config, processes) = (engine::config().await?, engine::processes().await?);
    Ok(json!({
        "hijacked_pids": processes.iter().filter(|p| p.alive && p.proxy.is_some()).count(),
        "auto_rules_count": config.rules.iter().filter(|r| r.enabled).count(),
    }))
}

/// The live identity of `pid`, so a PID reused meanwhile is never touched.
async fn key_of(pid: u32) -> Result<(ProcessKey, ProcessView)> {
    engine::processes()
        .await?
        .into_iter()
        .find(|p| p.alive && p.pid == pid)
        .map(|p| {
            (
                ProcessKey {
                    pid: p.pid,
                    instance: p.instance,
                },
                p,
            )
        })
        .ok_or_else(|| "The process has exited.".to_owned())
}

#[tauri::command(rename_all = "snake_case")]
pub async fn process_detail(pid: u32) -> Result<Value> {
    let (process, view) = key_of(pid).await?;
    let detail = match engine::call(Request::ProcessDetail { process }).await? {
        Response::ProcessDetail(detail) => detail,
        other => return Err(engine::unexpected(&other)),
    };
    let tree = view::tree(std::slice::from_ref(&view));
    let mut node = serde_json::to_value(&tree[0]).expect("serializes");
    node["cmdline"] = json!(detail.cmdline.unwrap_or_default());
    node["image_path"] = json!(
        detail
            .image_path
            .or_else(|| crate::icons::image_path(pid))
            .unwrap_or_default()
    );
    Ok(node)
}

async fn set_manual(pid: u32, group: Option<GroupId>) -> Result<()> {
    let (process, _) = key_of(pid).await?;
    engine::ok(Request::SetManual { process, group }).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn hijack(state: State<'_, AppState>, pid: u32, group_id: Option<u32>) -> Result<()> {
    set_manual(pid, Some(GroupId(group_id.unwrap_or(0)))).await?;
    state.wake.notify_one();
    Ok(())
}

#[tauri::command(rename_all = "snake_case")]
pub async fn unhijack(state: State<'_, AppState>, pid: u32) -> Result<()> {
    set_manual(pid, None).await?;
    state.wake.notify_one();
    Ok(())
}

#[tauri::command(rename_all = "snake_case")]
pub async fn batch_hijack(
    state: State<'_, AppState>,
    pids: Vec<u32>,
    action: String,
    group_id: Option<u32>,
) -> Result<()> {
    let group = (action == "hijack").then(|| GroupId(group_id.unwrap_or(0)));
    let processes = engine::processes().await?;
    let mut failures = 0;
    for pid in pids {
        let Some(p) = processes.iter().find(|p| p.alive && p.pid == pid) else {
            continue;
        };
        let process = ProcessKey {
            pid,
            instance: p.instance,
        };
        if engine::ok(Request::SetManual { process, group })
            .await
            .is_err()
        {
            failures += 1;
        }
    }
    state.wake.notify_one();
    if failures > 0 {
        return Err(format!("{failures} process(es) could not be changed"));
    }
    Ok(())
}

#[tauri::command(rename_all = "snake_case")]
pub async fn connections(pid: Option<u32>) -> Result<Vec<view::Connection>> {
    let (config, processes) = (engine::config().await?, engine::processes().await?);
    let entries =
        tauri::async_runtime::spawn_blocking(stemma_platform_windows::sockets::socket_table)
            .await
            .map_err(|err| err.to_string())?;
    Ok(view::connections(&entries, &processes, &config, pid))
}

#[tauri::command]
pub async fn list_rules() -> Result<Vec<view::AutoRule>> {
    let (config, processes) = (engine::config().await?, engine::processes().await?);
    Ok(view::rules(&config, &processes))
}

async fn find_rule(config: &Config, id: &str, processes: bool) -> Result<view::AutoRule> {
    let processes = if processes {
        engine::processes().await?
    } else {
        Vec::new()
    };
    view::rules(config, &processes)
        .into_iter()
        .find(|r| r.id == id)
        .ok_or_else(|| "The rule no longer exists.".to_owned())
}

#[tauri::command(rename_all = "snake_case")]
pub async fn create_rule(state: State<'_, AppState>, rule: RuleInput) -> Result<view::AutoRule> {
    let mut config = engine::config().await?;
    let mut new = Rule {
        id: view::new_rule_id(&config),
        ..Rule::default()
    };
    rule.apply(&mut new);
    let id = new.id.clone();
    config.rules.push(new);
    engine::set_config(config.clone()).await?;
    state.wake.notify_one();
    find_rule(&config, &id, false).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn update_rule(
    state: State<'_, AppState>,
    id: String,
    rule: RuleInput,
) -> Result<view::AutoRule> {
    let mut config = engine::config().await?;
    let existing = config
        .rules
        .iter_mut()
        .find(|r| r.id == id)
        .ok_or("The rule no longer exists.")?;
    rule.apply(existing);
    engine::set_config(config.clone()).await?;
    state.wake.notify_one();
    find_rule(&config, &id, true).await
}

#[tauri::command(rename_all = "snake_case")]
pub async fn set_rule_enabled(state: State<'_, AppState>, id: String, enabled: bool) -> Result<()> {
    let mut config = engine::config().await?;
    config
        .rules
        .iter_mut()
        .find(|r| r.id == id)
        .ok_or("The rule no longer exists.")?
        .enabled = enabled;
    engine::set_config(config).await?;
    state.wake.notify_one();
    Ok(())
}

#[tauri::command(rename_all = "snake_case")]
pub async fn delete_rule(state: State<'_, AppState>, id: String) -> Result<()> {
    let mut config = engine::config().await?;
    config.rules.retain(|r| r.id != id);
    engine::set_config(config).await?;
    state.wake.notify_one();
    Ok(())
}

#[tauri::command(rename_all = "snake_case")]
pub async fn set_excluded(
    state: State<'_, AppState>,
    rule_id: String,
    pid: u32,
    excluded: bool,
) -> Result<()> {
    let (process, _) = key_of(pid).await?;
    engine::ok(Request::SetExcluded {
        process,
        rule_id,
        excluded,
    })
    .await?;
    state.wake.notify_one();
    Ok(())
}

#[tauri::command]
pub async fn get_config() -> Result<Value> {
    Ok(serde_json::to_value(engine::config().await?).expect("configuration serializes"))
}

#[tauri::command(rename_all = "snake_case")]
pub async fn update_config(state: State<'_, AppState>, config: Value) -> Result<()> {
    let config: Config =
        serde_json::from_value(config).map_err(|err| format!("Invalid configuration: {err}"))?;
    engine::set_config(config).await?;
    state.wake.notify_one();
    Ok(())
}

#[tauri::command]
pub async fn list_groups() -> Result<Vec<view::ProxyGroupView>> {
    Ok(view::groups(&engine::config().await?))
}

fn apply_group(group: &mut ProxyGroup, input: GroupInput) {
    group.name = input.name.trim().to_owned();
    group.host = input.host.trim().to_owned();
    group.port = input.port;
    if !input.test_url.trim().is_empty() {
        group.test_url = input.test_url.trim().to_owned();
    }
}

#[tauri::command(rename_all = "snake_case")]
pub async fn create_group(group: GroupInput) -> Result<view::ProxyGroupView> {
    let mut config = engine::config().await?;
    let id = GroupId(
        config
            .proxy_groups
            .iter()
            .map(|g| g.id.0 + 1)
            .max()
            .unwrap_or(0),
    );
    let mut new = ProxyGroup {
        id,
        ..ProxyGroup::default()
    };
    apply_group(&mut new, group);
    config.proxy_groups.push(new);
    engine::set_config(config.clone()).await?;
    view::groups(&config)
        .into_iter()
        .find(|g| g.id == id)
        .ok_or_else(|| "missing group".to_owned())
}

#[tauri::command(rename_all = "snake_case")]
pub async fn update_group(id: u32, group: GroupInput) -> Result<()> {
    let mut config = engine::config().await?;
    let existing = config
        .proxy_groups
        .iter_mut()
        .find(|g| g.id == GroupId(id))
        .ok_or("The proxy group no longer exists.")?;
    apply_group(existing, group);
    engine::set_config(config).await
}

/// Deletes an unused group. A group in use is reported, not deleted.
#[tauri::command(rename_all = "snake_case")]
pub async fn delete_group(id: u32) -> Result<Value> {
    let id = GroupId(id);
    let (mut config, processes) = (engine::config().await?, engine::processes().await?);
    let rules: Vec<Value> = config
        .rules
        .iter()
        .filter(|r| r.proxy_group_id == id)
        .map(|r| json!({ "id": r.id, "name": r.name }))
        .collect();
    let manual = processes
        .iter()
        .filter(|p| {
            p.alive
                && p.proxy
                    .as_ref()
                    .is_some_and(|v| v.rule_id.is_none() && !v.inherited && v.group == id)
        })
        .count();
    if !rules.is_empty() || manual > 0 || config.dns.proxy_group_id == id {
        return Ok(
            json!({ "error": "group_in_use", "auto_rules": rules, "manual_hijack_count": manual }),
        );
    }
    if config.proxy_groups.len() == 1 {
        return Err("At least one proxy group is required.".to_owned());
    }
    config.proxy_groups.retain(|g| g.id != id);
    engine::set_config(config).await?;
    Ok(json!({ "success": true }))
}

/// Moves everything that uses group `id` to `target_group_id`, then deletes `id`.
#[tauri::command(rename_all = "snake_case")]
pub async fn migrate_group(
    state: State<'_, AppState>,
    id: u32,
    target_group_id: u32,
) -> Result<()> {
    let (from, to) = (GroupId(id), GroupId(target_group_id));
    if from == to {
        return Err("Choose a different proxy group.".to_owned());
    }
    let (mut config, processes) = (engine::config().await?, engine::processes().await?);
    if config.group(to).is_none() {
        return Err("The target proxy group no longer exists.".to_owned());
    }
    for process in processes.iter().filter(|p| {
        p.alive
            && p.proxy
                .as_ref()
                .is_some_and(|v| v.rule_id.is_none() && !v.inherited && v.group == from)
    }) {
        let process = ProcessKey {
            pid: process.pid,
            instance: process.instance,
        };
        let _ = engine::ok(Request::SetManual {
            process,
            group: Some(to),
        })
        .await;
    }
    for rule in config.rules.iter_mut().filter(|r| r.proxy_group_id == from) {
        rule.proxy_group_id = to;
    }
    if config.dns.proxy_group_id == from {
        config.dns.proxy_group_id = to;
    }
    config.proxy_groups.retain(|g| g.id != from);
    engine::set_config(config).await?;
    state.wake.notify_one();
    Ok(())
}

#[tauri::command(rename_all = "snake_case")]
pub async fn check_group(id: u32) -> Result<Value> {
    Ok(
        match engine::ok(Request::CheckProxy { group: GroupId(id) }).await {
            Ok(()) => json!({ "reachable": true }),
            Err(error) => json!({ "reachable": false, "error": error }),
        },
    )
}

#[tauri::command(rename_all = "snake_case")]
pub async fn test_group(id: u32) -> Result<Value> {
    Ok(
        match engine::call(Request::TestProxy { group: GroupId(id) }).await {
            Ok(Response::ProxyTest { latency_ms }) => json!({ "latency_ms": latency_ms }),
            Ok(other) => json!({ "error": engine::unexpected(&other) }),
            Err(err) => json!({ "error": err }),
        },
    )
}

#[tauri::command(rename_all = "snake_case")]
pub fn reveal_file(path: String) -> Result<()> {
    std::process::Command::new("explorer.exe")
        .arg(format!("/select,{path}"))
        .spawn()
        .map(drop)
        .map_err(|err| err.to_string())
}

#[tauri::command]
pub async fn browse_exe(app: AppHandle) -> Result<Value> {
    use tauri_plugin_dialog::DialogExt;
    let picked = tauri::async_runtime::spawn_blocking(move || {
        app.dialog()
            .file()
            .add_filter("Programs", &["exe"])
            .blocking_pick_file()
    })
    .await
    .map_err(|err| err.to_string())?;
    let Some(path) = picked.and_then(|p| p.into_path().ok()) else {
        return Ok(json!({ "cancelled": true }));
    };
    Ok(json!({
        "path": path.display().to_string(),
        "dir": path.parent().map(|d| format!("{}\\", d.display())).unwrap_or_default(),
        "name": path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
    }))
}

#[tauri::command]
pub fn get_autostart(state: State<'_, AppState>) -> Value {
    json!({ "enabled": autostart::enabled(), "start_minimized": state.prefs.lock().unwrap().start_minimized })
}

#[tauri::command(rename_all = "snake_case")]
pub fn set_autostart(
    state: State<'_, AppState>,
    enabled: bool,
    start_minimized: bool,
) -> Result<Value> {
    autostart::set(enabled)?;
    let mut prefs = state.prefs.lock().unwrap();
    let mut next = prefs.clone();
    next.start_minimized = start_minimized;
    prefs::save(&next)?;
    *prefs = next;
    drop(prefs);
    Ok(get_autostart(state))
}
