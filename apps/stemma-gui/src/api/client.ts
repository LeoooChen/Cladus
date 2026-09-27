import { invoke } from '@tauri-apps/api/core'
import { t } from '@/i18n'
import type { AutoRule, ProcessInfo, Stats, TcpConnection, NetworkConnection, ProxyGroup, GroupInUseError, ProxyTestResult } from './types'

// Every call goes to the Stemma desktop host (Tauri), which talks to the
// engine service over its named pipe. Errors arrive as English messages and
// are shown translated when the catalog has them.
export async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await invoke<T>(command, args)
  } catch (e) {
    throw new Error(t(typeof e === 'string' ? e : e instanceof Error ? e.message : String(e)))
  }
}

// -- Processes --
// The tree itself is pushed by the host; see useNotifications() in api/notify.ts.

export function getProcessDetail(pid: number): Promise<ProcessInfo> {
  return call<ProcessInfo>('process_detail', { pid })
}

// -- Manual proxying (always applies to the whole process tree) --

export function hijackProcess(pid: number, _tree = true, groupId = 0): Promise<void> {
  return call('hijack', { pid, group_id: groupId })
}

export function unhijackProcess(pid: number, _tree = true): Promise<void> {
  return call('unhijack', { pid })
}

export function batchHijack(pids: number[], action: 'hijack' | 'unhijack', groupId = 0): Promise<void> {
  return call('batch_hijack', { pids, action, group_id: groupId })
}

// -- Connections --

async function connections(protocol: 'TCP' | 'UDP', pid?: number): Promise<TcpConnection[]> {
  const all = await call<NetworkConnection[]>('connections', { pid: pid ?? null })
  return all.filter(c => c.protocol === protocol)
}

export function getTcpConnections(pid?: number): Promise<TcpConnection[]> {
  return connections('TCP', pid)
}

export function getUdpConnections(pid?: number): Promise<TcpConnection[]> {
  return connections('UDP', pid)
}

export function getNetworkConnections(pid?: number): Promise<NetworkConnection[]> {
  return call<NetworkConnection[]>('connections', { pid: pid ?? null })
}

// -- Auto Rules --

export function getAutoRules(): Promise<AutoRule[]> {
  return call<AutoRule[]>('list_rules')
}

export function createAutoRule(rule: Omit<AutoRule, 'id'>): Promise<AutoRule> {
  return call<AutoRule>('create_rule', { rule })
}

export async function updateAutoRule(id: string, rule: Partial<AutoRule>): Promise<AutoRule | void> {
  const keys = Object.keys(rule)
  if (keys.length === 1 && keys[0] === 'enabled') {
    return call('set_rule_enabled', { id, enabled: rule.enabled })
  }
  return call<AutoRule>('update_rule', { id, rule })
}

export function deleteAutoRule(id: string): Promise<void> {
  return call('delete_rule', { id })
}

export function excludePid(ruleId: string, pid: number): Promise<void> {
  return call('set_excluded', { rule_id: ruleId, pid, excluded: true })
}

export function unexcludePid(ruleId: string, pid: number): Promise<void> {
  return call('set_excluded', { rule_id: ruleId, pid, excluded: false })
}

// -- Engine configuration (the service's config.json) --

export function getConfig(): Promise<Record<string, unknown>> {
  return call<Record<string, unknown>>('get_config')
}

export function updateConfig(config: Record<string, unknown>): Promise<void> {
  return call('update_config', { config })
}

// -- UI preferences (per user, not part of the engine configuration) --

export interface UiPrefs {
  language: string
  close_to_tray: boolean
  start_minimized: boolean
}

export function getUiPrefs(): Promise<UiPrefs> {
  return call<UiPrefs>('get_ui_prefs')
}

export function setUiPrefs(prefs: { language?: string; close_to_tray?: boolean }): Promise<void> {
  return call('set_ui_prefs', { language: prefs.language ?? null, close_to_tray: prefs.close_to_tray ?? null })
}

// -- Proxy Groups --

export function getProxyGroups(): Promise<ProxyGroup[]> {
  return call<ProxyGroup[]>('list_groups')
}

export function createProxyGroup(group: Omit<ProxyGroup, 'id'>): Promise<ProxyGroup> {
  return call<ProxyGroup>('create_group', { group })
}

export function updateProxyGroup(id: number, group: Partial<ProxyGroup>): Promise<void> {
  return call('update_group', { id, group })
}

export function deleteProxyGroup(id: number): Promise<{ success: boolean } | GroupInUseError> {
  return call<{ success: boolean } | GroupInUseError>('delete_group', { id })
}

export function migrateProxyGroup(id: number, targetGroupId: number): Promise<void> {
  return call('migrate_group', { id, target_group_id: targetGroupId })
}

export function testProxyGroup(id: number): Promise<ProxyTestResult> {
  return call<ProxyTestResult>('test_group', { id })
}

// -- Stats --

export function getStats(): Promise<Stats> {
  return call<Stats>('get_stats')
}

// -- Shell --

export function revealFile(path: string): Promise<void> {
  return call('reveal_file', { path })
}

export function browseExe(): Promise<{ cancelled?: boolean; path?: string; dir?: string; name?: string }> {
  return call<{ cancelled?: boolean; path?: string; dir?: string; name?: string }>('browse_exe')
}

// -- Start at logon (HKCU Run; no elevation involved) --

export interface AutostartState {
  enabled: boolean
  start_minimized: boolean
}

export function getAutostart(): Promise<AutostartState> {
  return call<AutostartState>('get_autostart')
}

export function setAutostart(state: AutostartState): Promise<AutostartState> {
  return call<AutostartState>('set_autostart', { enabled: state.enabled, start_minimized: state.start_minimized })
}

// -- Window --

export function windowCommand(cmd: 'minimize' | 'maximize' | 'close'): Promise<void> {
  return call('window_cmd', { cmd })
}
