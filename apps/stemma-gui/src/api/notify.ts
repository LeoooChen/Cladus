import { ref, readonly } from 'vue'
import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import type { ProcessInfo } from './types'

// Host->UI push channel. The Stemma host emits Tauri events: the full
// process tree while the window is visible, and the engine's state.

export interface EngineState {
  connected: boolean
  engaged: boolean
  message: string | null
  dns_fallback: boolean
}

export interface NotificationEvents {
  process_update: ProcessInfo[]
  engine_state: EngineState
}

export type NotificationEvent = keyof NotificationEvents
export type NotificationHandler<T extends NotificationEvent = NotificationEvent>
  = (data: NotificationEvents[T]) => void

const engine = ref<EngineState>({ connected: false, engaged: false, message: null, dns_fallback: false })
const connected = ref(false)
const tree = ref<ProcessInfo[]>([])
const handlers = new Map<NotificationEvent, Set<NotificationHandler>>()

function dispatch<T extends NotificationEvent>(event: T, data: NotificationEvents[T]): void {
  if (event === 'process_update') tree.value = data as ProcessInfo[]
  if (event === 'engine_state') {
    engine.value = data as EngineState
    connected.value = engine.value.connected && engine.value.engaged
  }
  for (const h of handlers.get(event) ?? []) {
    try { h(data) } catch { /* don't let one handler kill others */ }
  }
}

let initialized = false
function init(): void {
  if (initialized) return
  initialized = true
  const events: NotificationEvent[] = ['process_update', 'engine_state']
  Promise.all(events.map(name => listen(name, e => dispatch(name, e.payload as never))))
    .then(async () => {
      dispatch('engine_state', await invoke<EngineState>('engine_state'))
      // Ask for an immediate push instead of waiting for the next tick.
      await invoke('frontend_ready')
    })
    .catch(e => console.warn('[notify] push channel unavailable', e))
}

export function useNotifications() {
  init()
  return {
    connected: readonly(connected),
    engine: readonly(engine),
    // Not readonly(): recursive helpers downstream take mutable types. This
    // module is the only writer.
    tree,
    on<T extends NotificationEvent>(event: T, handler: NotificationHandler<T>): void {
      if (!handlers.has(event)) handlers.set(event, new Set())
      handlers.get(event)!.add(handler as NotificationHandler)
    },
    off<T extends NotificationEvent>(event: T, handler: NotificationHandler<T>): void {
      handlers.get(event)?.delete(handler as NotificationHandler)
    },
  }
}

// Test bridge: module-scope refs are not reachable from page.evaluate().
;(window as unknown as { __stemma_debug: unknown }).__stemma_debug = {
  tree: () => tree.value,
  connected: () => connected.value,
}
