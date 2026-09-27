import { test, expect, type Page } from '@playwright/test'

async function mockBackend(page: Page, language = 'system', failSave = false) {
  let config = { ui: { language, close_to_tray: false }, log_level: 'info', dns: { enabled: false } }
  await page.route('http://127.0.0.1:5173/api/**', async route => {
    const path = new URL(route.request().url()).pathname
    if (path === '/api/config') {
      if (route.request().method() === 'PUT') {
        if (failSave) return route.fulfill({ status: 500, body: 'save failed' })
        config = route.request().postDataJSON()
        return route.fulfill({ json: { success: true } })
      }
      return route.fulfill({ json: config })
    }
    if (path === '/api/stats') return route.fulfill({ json: { hijacked_pids: 0, auto_rules_count: 0 } })
    if (path === '/api/autostart') return route.fulfill({ json: { enabled: false, start_minimized: false } })
    if (path === '/api/proxy-groups') return route.fulfill({ json: [{ id: 0, name: 'default', host: '127.0.0.1', port: 7890, type: 'socks5', test_url: 'https://example.com' }] })
    return route.fulfill({ json: [] })
  })
  return () => config
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
  const config = await mockBackend(page)
  await page.goto('/')
  await settings(page)
  // Labels update before location.reload() commits. Wait for the app's reload
  // before asserting or issuing another navigation, otherwise ERR_ABORTED races.
  await Promise.all([
    page.waitForEvent('load'),
    page.getByLabel('语言', { exact: true }).selectOption('en'),
  ])
  await expect(page.getByLabel('Language', { exact: true })).toHaveValue('en')
  expect(config().ui.language).toBe('en')
  await page.reload()
  await expect(page.locator('html')).toHaveAttribute('lang', 'en')
  await settings(page, 'Settings')
  await Promise.all([
    page.waitForEvent('load'),
    page.getByLabel('Language', { exact: true }).selectOption('zh-CN'),
  ])
  await expect(page.getByLabel('语言', { exact: true })).toHaveValue('zh-CN')
  expect(config().ui.language).toBe('zh-CN')
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
  await mockBackend(page, 'zh-CN')
  await page.route('**/api/tcp', route => route.fulfill({ json: [{
    pid: 100, process_name: '程序.exe', protocol: 'TCP', local_ip: '127.0.0.1', local_port: 45678,
    remote_ip: '1.1.1.1', remote_port: 443, state: 'ESTABLISHED', proxy_status: 'PROXIED', pid_alive: true,
  }] }))
  await page.goto('/')
  await expect(page.getByRole('columnheader', { name: '连接状态' })).toBeVisible()
  await expect(page.getByText('已建立', { exact: true })).toBeVisible()
  await page.getByPlaceholder('筛选目标地址或连接状态…').fill('unmatched-address')
  await expect(page.getByText('无匹配行', { exact: true }).last()).toBeVisible()
  await expect(page.getByText('程序.exe', { exact: true })).toHaveCount(0)
})
