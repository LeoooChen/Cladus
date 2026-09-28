import { test, expect, type Page } from '@playwright/test'

// The desktop host is replaced by a mock of Tauri's IPC. Its state lives in
// the test process, so it survives page reloads.
async function mockBackend(page: Page, language = 'system', failSave = false, connections: unknown[] = []) {
  const prefs = { language, close_to_tray: false, start_minimized: false }
  const config = { version: 1, proxy_groups: [], rules: [], log_level: 'info', dns: { enabled: false, upstream: '8.8.8.8:53', strict: false } }
  await page.exposeFunction('__mockInvoke', (cmd: string, args: Record<string, unknown>) => {
    switch (cmd) {
      case 'get_ui_prefs': return prefs
      case 'set_ui_prefs':
        if (failSave) throw new Error('save failed')
        if (args.language) prefs.language = args.language as string
        return null
      case 'engine_state': return { connected: true, engaged: true, message: null, dns_fallback: false }
      case 'get_stats': return { hijacked_pids: 0, auto_rules_count: 0 }
      case 'get_autostart': return { enabled: false, start_minimized: false }
      case 'get_config': return config
      case 'list_groups': return [{ id: 0, name: 'default', host: '127.0.0.1', port: 7890, type: 'socks5', test_url: 'https://example.com' }]
      case 'connections': return connections
      case 'list_rules': return []
      default: return null
    }
  })
  await page.addInitScript(() => {
    let next = 1
    const w = window as unknown as Record<string, unknown>
    w.__TAURI_INTERNALS__ = {
      metadata: { currentWindow: { label: 'main' }, currentWebview: { windowLabel: 'main', label: 'main' } },
      transformCallback: () => next++,
      unregisterCallback: () => {},
      convertFileSrc: (path: string, protocol: string) => `http://${protocol}.localhost/${encodeURIComponent(path)}`,
      invoke: async (cmd: string, args: Record<string, unknown>) => {
        if (cmd.startsWith('plugin:')) return cmd.endsWith('|listen') ? next++ : null
        const call = (w.__mockInvoke as (c: string, a: unknown) => Promise<unknown>)
        try { return await call(cmd, args ?? {}) } catch (e) { throw String((e as Error).message ?? e) }
      },
    }
    w.__TAURI_EVENT_PLUGIN_INTERNALS__ = { unregisterListener: () => {} }
  })
  return () => prefs
}

async function settings(page: Page, label = '设置') {
  await page.getByRole('button', { name: label, exact: true }).click()
  await expect(page.getByLabel(label === 'Settings' ? 'Language' : '语言', { exact: true })).toBeVisible()
}

test('system Chinese, translated dialogs and settings at native scale', async ({ page }, info) => {
  await mockBackend(page)
  await page.goto('/')
  await expect(page.locator('html')).toHaveAttribute('lang', 'zh-CN')
  await expect(page.getByRole('button', { name: '所有进程' })).toBeVisible()
  await page.getByRole('button', { name: '规则', exact: true }).click()
  await page.getByRole('button', { name: '添加规则' }).click()
  await expect(page.getByText('自动规则编辑器', { exact: true })).toBeVisible()
  await page.getByLabel('规则名称', { exact: true }).fill('中文规则')
  await page.getByLabel('进程名称', { exact: true }).fill('程序.exe')
  await page.screenshot({ path: info.outputPath('rule-zh.png'), animations: 'disabled' })
  expect(await page.getByRole('dialog').evaluate(el => { const r = el.getBoundingClientRect(); return r.top >= 0 && r.bottom <= innerHeight })).toBe(true)
  await page.getByRole('button', { name: '取消', exact: true }).click()
  await settings(page)
  await page.screenshot({ path: info.outputPath('settings-zh.png'), animations: 'disabled' })
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
})

test('language is persisted and survives reload in both directions', async ({ page }) => {
  const prefs = await mockBackend(page)
  await page.goto('/')
  await settings(page)
  // Labels update before location.reload() commits. Wait for the app's reload
  // before asserting or issuing another navigation, otherwise ERR_ABORTED races.
  await Promise.all([
    page.waitForEvent('load'),
    page.getByLabel('语言', { exact: true }).selectOption('en'),
  ])
  await expect(page.getByLabel('Language', { exact: true })).toHaveValue('en')
  expect(prefs().language).toBe('en')
  await page.reload()
  await expect(page.locator('html')).toHaveAttribute('lang', 'en')
  await settings(page, 'Settings')
  await Promise.all([
    page.waitForEvent('load'),
    page.getByLabel('Language', { exact: true }).selectOption('zh-CN'),
  ])
  await expect(page.getByLabel('语言', { exact: true })).toHaveValue('zh-CN')
  expect(prefs().language).toBe('zh-CN')
  await page.reload()
  await expect(page.locator('html')).toHaveAttribute('lang', 'zh-CN')
})

test('failed language save keeps the current selection and reports failure', async ({ page }) => {
  await mockBackend(page, 'zh-CN', true)
  await page.goto('/')
  await settings(page)
  await page.getByLabel('语言', { exact: true }).selectOption('en')
  await expect(page.getByRole('alert')).toHaveText('保存失败')
  await expect(page.getByLabel('语言', { exact: true })).toHaveValue('zh-CN')
})

test('unsupported preference falls back to system; unsaved editor is protected', async ({ page }) => {
  await mockBackend(page, 'unsupported')
  await page.goto('/')
  await settings(page)
  await expect(page.getByLabel('语言', { exact: true })).toHaveValue('system')
  await page.getByRole('button', { name: '编辑', exact: true }).click()
  const editor = page.getByRole('textbox', { name: '编辑器内容', exact: true })
  await editor.focus()
  await page.keyboard.press('Control+Home')
  await page.keyboard.type(' ')
  await expect(page.getByText('有未保存的更改', { exact: true })).toBeVisible()
  page.once('dialog', dialog => dialog.dismiss())
  await page.getByLabel('语言', { exact: true }).selectOption('en')
  await expect(page.getByLabel('语言', { exact: true })).toHaveValue('system')
  await expect(page.getByText('有未保存的更改', { exact: true })).toBeVisible()
})

test('network grid headers, states, filtering and empty text are localized', async ({ page }) => {
  await mockBackend(page, 'zh-CN', false, [{
    pid: 100, process_name: '程序.exe', protocol: 'TCP', local_ip: '127.0.0.1', local_port: 45678,
    remote_ip: '1.1.1.1', remote_port: 443, dest: '1.1.1.1:443', state: 'ESTABLISHED', proxy_status: 'PROXIED',
    hijacked: true, pid_alive: true,
  }])
  await page.goto('/')
  await expect(page.getByRole('columnheader', { name: '连接状态' })).toBeVisible()
  await expect(page.getByText('已建立', { exact: true })).toBeVisible()
  await page.getByPlaceholder('筛选目标地址或连接状态…').fill('unmatched-address')
  await expect(page.getByText('无匹配行', { exact: true }).last()).toBeVisible()
  await expect(page.getByText('程序.exe', { exact: true })).toHaveCount(0)
})
