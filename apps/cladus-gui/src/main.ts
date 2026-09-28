import { createApp } from 'vue'
import App from './App.vue'
import './style.css'
import { useTheme } from './composables/useTheme'
import { initLocale } from './i18n'

const { initTheme } = useTheme()
initTheme()

initLocale().then(() => createApp(App).mount('#app'))
