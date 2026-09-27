import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: './tests',
  fullyParallel: true,
  timeout: 60000,
  expect: { timeout: 10000 },
  use: {
    baseURL: 'http://127.0.0.1:5173',
    locale: 'zh-CN',
    channel: process.env.PLAYWRIGHT_CHANNEL || undefined,
    screenshot: 'only-on-failure',
  },
  webServer: {
    command: 'npm run dev -- --host 127.0.0.1',
    url: 'http://127.0.0.1:5173',
    reuseExistingServer: !process.env.CI,
  },
  projects: [
    { name: '100%', use: { viewport: { width: 1200, height: 800 }, deviceScaleFactor: 1 } },
    { name: '125%', use: { viewport: { width: 1200, height: 800 }, deviceScaleFactor: 1.25 } },
    { name: '150%', use: { viewport: { width: 1000, height: 700 }, deviceScaleFactor: 1.5 } },
    { name: '200%', use: { viewport: { width: 900, height: 600 }, deviceScaleFactor: 2 } },
  ],
})
