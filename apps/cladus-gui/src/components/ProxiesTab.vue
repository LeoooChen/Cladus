<script setup lang="ts">
import { t } from '@/i18n'
import { ref, computed, onMounted, onUnmounted, useId } from 'vue'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent } from '@/components/ui/card'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Button } from '@/components/ui/button'
import {
  getProxyGroups,
  getAutoRules,
  createProxyGroup,
  updateProxyGroup,
  deleteProxyGroup,
  migrateProxyGroup,
  testProxyGroup,
  checkProxyGroup,
} from '@/api/client'
import type { ProxyGroup, AutoRule, GroupInUseError, ProxyTestResult } from '@/api/types'
import { useStatusBus } from '@/composables/useStatusBus'
import { Plus, Search, X, Pencil, Trash2, Globe, RefreshCw, Loader2, ChevronDown } from 'lucide-vue-next'

const { pushError } = useStatusBus()

const groups = ref<ProxyGroup[]>([])
const autoRules = ref<AutoRule[]>([])
const searchQuery = ref('')

// Test results per group
const testResults = ref(new Map<number, { generation: number; loading: boolean; result?: ProxyTestResult }>())
type Health = { generation: number; signature: string; state: 'checking' | 'up' | 'down'; error?: string }
const health = ref(new Map<number, Health>())
let generation = 0
let disposed = false
let activeChecks = 0
const healthQueue: { id: number; generation: number }[] = []

function checkHealth(group: ProxyGroup) {
  const token = ++generation
  health.value.set(group.id, { generation: token, signature: JSON.stringify(group), state: 'checking' })
  healthQueue.push({ id: group.id, generation: token })
  drainHealthQueue()
}

function drainHealthQueue() {
  while (!disposed && activeChecks < 3 && healthQueue.length) {
    const job = healthQueue.shift()!
    if (health.value.get(job.id)?.generation !== job.generation) continue
    activeChecks++
    void checkProxyGroup(job.id).then(result => {
      const current = health.value.get(job.id)
      if (!disposed && current?.generation === job.generation) {
        health.value.set(job.id, { ...current, state: result.reachable ? 'up' : 'down', error: result.error })
      }
    }).catch(error => {
      const current = health.value.get(job.id)
      if (!disposed && current?.generation === job.generation) {
        health.value.set(job.id, { ...current, state: 'down', error: String(error) })
      }
    }).finally(() => {
      activeChecks--
      drainHealthQueue()
    })
  }
}

function healthLabel(id: number) {
  const state = health.value.get(id)
  if (!state || state.state === 'checking') return t('Checking proxy…')
  return state.state === 'up' ? t('Proxy reachable') : t('Proxy unreachable')
}

// Editor dialog
const editOpen = ref(false)
const editingGroup = ref<ProxyGroup | null>(null)
const formName = ref('')
const formHost = ref('127.0.0.1')
const formPort = ref('7890')
const formTestUrl = ref('https://www.google.com')

// a11y: unique ids for label/field association
const nameId = useId()
const hostId = useId()
const portId = useId()
const testUrlId = useId()
const migrateTargetLabelId = useId()

// Delete / migration dialog
const deleteOpen = ref(false)
const deletingGroup = ref<ProxyGroup | null>(null)
const deleteConflict = ref<GroupInUseError | null>(null)
const migrateTargetId = ref('0')

// Mock expansion
const expandedGroupId = ref<number | null>(null)

const filteredGroups = computed(() => {
  const q = searchQuery.value.toLowerCase().trim()
  if (!q) return groups.value
  return groups.value.filter(g => g.name.toLowerCase().includes(q) || g.host.includes(q))
})

function rulesCountForGroup(id: number): number {
  return autoRules.value.filter(r => r.proxy_group_id === id).length
}

function rulesForGroup(id: number): AutoRule[] {
  return autoRules.value.filter(r => r.proxy_group_id === id)
}

async function fetchData() {
  try {
    const [g, r] = await Promise.all([getProxyGroups(), getAutoRules()])
    if (disposed) return
    groups.value = g
    autoRules.value = r
    for (const id of health.value.keys()) {
      if (!g.some(group => group.id === id)) {
        health.value.delete(id)
        testResults.value.delete(id)
      }
    }
    for (const group of g) {
      if (health.value.get(group.id)?.signature !== JSON.stringify(group)) {
        testResults.value.delete(group.id)
        checkHealth(group)
      }
    }
  } catch (e) {
    console.error('[ProxiesTab] fetchData failed:', e)
  }
}

// Test
async function onTest(id: number) {
  if (testResults.value.get(id)?.loading) return
  const token = ++generation
  testResults.value.set(id, { generation: token, loading: true })
  try {
    const result = await testProxyGroup(id)
    if (!disposed && testResults.value.get(id)?.generation === token) {
      testResults.value.set(id, { generation: token, loading: false, result })
    }
  } catch (error) {
    if (!disposed && testResults.value.get(id)?.generation === token) {
      testResults.value.set(id, { generation: token, loading: false, result: { error: String(error) } })
    }
  }
}

// Editor
function openCreate() {
  editingGroup.value = null
  formName.value = ''
  formHost.value = '127.0.0.1'
  formPort.value = '7890'
  formTestUrl.value = 'https://www.google.com'
  editOpen.value = true
}

function openEdit(group: ProxyGroup) {
  editingGroup.value = group
  formName.value = group.name
  formHost.value = group.host
  formPort.value = String(group.port)
  formTestUrl.value = group.test_url
  editOpen.value = true
}

const saving = ref(false)

async function onSaveGroup() {
  if (saving.value) return
  saving.value = true
  try {
    const data = {
      name: formName.value,
      host: formHost.value,
      port: Number.parseInt(formPort.value, 10) || 7890,
      type: 'socks5' as const,
      test_url: formTestUrl.value,
    }
    if (editingGroup.value) {
      await updateProxyGroup(editingGroup.value.id, data)
      health.value.delete(editingGroup.value.id)
      testResults.value.delete(editingGroup.value.id)
    } else {
      await createProxyGroup(data as Omit<ProxyGroup, 'id'>)
    }
    editOpen.value = false
    await fetchData()
  } catch (e) {
    pushError(e, t('Save proxy group failed'))
  } finally {
    saving.value = false
  }
}

// Delete
async function onDelete(group: ProxyGroup) {
  if (saving.value) return
  saving.value = true
  try {
    const result = await deleteProxyGroup(group.id)
    if ('error' in result && result.error === 'group_in_use') {
      deletingGroup.value = group
      deleteConflict.value = result as GroupInUseError
      migrateTargetId.value = '0'
      deleteOpen.value = true
    } else {
      await fetchData()
    }
  } catch (e) {
    pushError(e, t('Delete proxy group failed'))
  } finally {
    saving.value = false
  }
}

async function onMigrateAndDelete() {
  if (!deletingGroup.value || saving.value) return
  saving.value = true
  try {
    await migrateProxyGroup(deletingGroup.value.id, Number.parseInt(migrateTargetId.value, 10))
    deleteOpen.value = false
    await fetchData()
  } catch (e) {
    pushError(e, t('Migrate proxy group failed'))
  } finally {
    saving.value = false
  }
}

function toggleExpand(id: number) {
  expandedGroupId.value = expandedGroupId.value === id ? null : id
}

onMounted(fetchData)
onUnmounted(() => {
  disposed = true
  healthQueue.length = 0
})
</script>

<template>
  <div class="flex-1 overflow-auto thin-scrollbar flex flex-col">
    <!-- Toolbar -->
    <div class="shrink-0 border-b border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-[#18181b]/50">
      <div class="h-12 flex items-center gap-3 px-4">
        <!-- Search -->
        <div class="relative flex-1 max-w-[240px]">
          <Search class="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400 pointer-events-none" />
          <input
            v-model="searchQuery"
            :placeholder="t('Search groups...')"
            class="w-full pl-8 pr-7 py-1.5 text-xs rounded-md border border-slate-200 dark:border-slate-700 bg-white dark:bg-[#101922] text-slate-800 dark:text-white placeholder:text-slate-400 outline-none focus:ring-1 focus:ring-blue-500 focus:border-blue-500 transition-colors"
          />
          <button
            v-if="searchQuery"
            @click="searchQuery = ''"
            class="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300"
          >
            <X class="w-3.5 h-3.5" />
          </button>
        </div>

        <span class="ml-auto text-xs text-slate-500 dark:text-slate-400 font-medium">
          {{ t('{count} groups', { count: groups.length }) }}
        </span>

        <button
          @click="openCreate"
          class="shrink-0 flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 rounded-md transition-colors shadow-sm shadow-blue-500/20 ml-2"
        >
          <Plus class="w-3.5 h-3.5" /> {{ t('New Group') }} </button>
      </div>
    </div>

    <!-- Group cards -->
    <div class="flex-1 overflow-auto thin-scrollbar p-4 space-y-3">
      <Card
        v-for="group in filteredGroups"
        :key="group.id"
        class="border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#18181b] shadow-sm"
      >
        <CardContent class="p-4 space-y-2">
          <!-- Row 1: name + badge + actions + rule count -->
          <div class="flex items-center gap-2">
            <span class="text-base font-bold text-slate-800 dark:text-slate-100">{{ group.name }}</span>
            <Badge variant="outline" class="h-5 px-2 text-[10px] font-bold uppercase text-blue-600 border-blue-300 dark:text-blue-400 dark:border-blue-700">SOCKS5</Badge>
            <button
              @click="openEdit(group)"
              :aria-label="`${t('Edit')}: ${group.name}`"
              class="p-1 rounded text-slate-400 hover:text-blue-600 dark:hover:text-blue-400 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
            >
              <Pencil class="w-3.5 h-3.5" />
            </button>
            <button
              v-if="group.id !== 0"
              :disabled="saving"
              @click="onDelete(group)"
              class="p-1 rounded text-slate-400 hover:text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:text-slate-400 disabled:hover:bg-transparent"
            >
              <Trash2 class="w-3.5 h-3.5" />
            </button>
            <span class="ml-auto text-xs text-slate-400 dark:text-slate-500 font-medium">
              {{ t('{count} rules', { count: rulesCountForGroup(group.id) }) }}
            </span>
          </div>

          <!-- Row 2: address -->
          <div class="flex items-center justify-between gap-2 text-sm font-mono text-slate-500 dark:text-slate-400">
            <span class="truncate">socks5://{{ group.host }}:{{ group.port }}</span>
            <button
              class="shrink-0 p-1 rounded focus-visible:outline-2 focus-visible:outline-blue-500"
              :aria-label="`${healthLabel(group.id)}: ${group.name}`"
              :title="health.get(group.id)?.error || `${healthLabel(group.id)}. ${t('Checks the proxy connection only; use the website test below for Internet access.')}`"
              :disabled="health.get(group.id)?.state === 'checking'"
              @click="checkHealth(group)"
            >
              <span class="block w-2.5 h-2.5 rounded-full" :class="health.get(group.id)?.state === 'up' ? 'bg-emerald-500' : health.get(group.id)?.state === 'down' ? 'bg-red-500' : 'bg-slate-400 animate-pulse'" />
            </button>
          </div>

          <!-- Row 3: test URL + test button + result -->
          <div class="flex items-center gap-2 pt-2 border-t border-slate-100 dark:border-slate-800/60">
            <Globe class="w-4 h-4 text-slate-400 shrink-0" />
            <span class="text-sm text-slate-500 dark:text-slate-400 flex-1 truncate">{{ group.test_url }}</span>

            <!-- Test button / result -->
            <template v-if="testResults.get(group.id)?.loading">
              <Loader2 class="w-4 h-4 text-blue-500 animate-spin shrink-0" />
            </template>
            <template v-else-if="testResults.get(group.id)?.result">
              <button
                @click="onTest(group.id)"
                class="shrink-0 text-sm font-bold px-2 py-0.5 rounded transition-colors"
                :title="testResults.get(group.id)!.result!.error || t('HTTP response time through the proxy, including TLS')"
                :class="testResults.get(group.id)!.result!.latency_ms != null
                  ? 'text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-900/20 hover:bg-emerald-100 dark:hover:bg-emerald-900/40'
                  : 'text-red-500 dark:text-red-400 bg-red-50 dark:bg-red-900/20 hover:bg-red-100 dark:hover:bg-red-900/40'"
              >
                <template v-if="testResults.get(group.id)!.result!.latency_ms != null">
                  {{ testResults.get(group.id)!.result!.latency_ms }}ms
                </template>
                <template v-else> {{ t('Test failed') }} </template>
              </button>
            </template>
            <template v-else>
              <button
                @click="onTest(group.id)"
                class="p-1 rounded text-slate-400 hover:text-blue-600 dark:hover:text-blue-400 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors shrink-0"
                :title="t('Test connectivity')"
              >
                <RefreshCw class="w-4 h-4" />
              </button>
            </template>
          </div>

          <!-- Mock expansion (demo only) -->
          <div v-if="rulesCountForGroup(group.id) > 0" class="pt-1">
            <button
              @click="toggleExpand(group.id)"
              class="flex items-center gap-1 text-xs text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 transition-colors"
            >
              <ChevronDown class="w-3 h-3 transition-transform" :class="expandedGroupId === group.id ? 'rotate-180' : ''" />
              {{ expandedGroupId === group.id ? t('Hide rules') : t('Show rules') }}
            </button>
            <div v-if="expandedGroupId === group.id" class="mt-2 space-y-1 pl-4 border-l-2 border-slate-200 dark:border-slate-700">
              <div
                v-for="rule in rulesForGroup(group.id)"
                :key="rule.id"
                class="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400"
              >
                <span class="font-medium text-slate-700 dark:text-slate-300">{{ rule.name }}</span>
                <span class="font-mono text-slate-400">{{ rule.process_name }}</span>
                <Badge v-if="!rule.enabled" variant="outline" class="h-4 px-1 py-0 text-[9px]"> {{ t('off') }} </Badge>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      <!-- Empty state -->
      <div v-if="filteredGroups.length === 0" class="py-16 flex flex-col items-center gap-3 text-slate-400">
        <p class="text-sm"> {{ t('No proxy groups found.') }} </p>
      </div>
    </div>

    <!-- Group Editor Dialog -->
    <Dialog :open="editOpen" @update:open="editOpen = $event">
      <DialogContent class="sm:max-w-[420px]"
        @interact-outside="(e: Event) => e.preventDefault()"
        @escape-key-down="(e: Event) => e.preventDefault()"
      >
        <DialogHeader>
          <DialogTitle>{{ editingGroup ? t('Edit Group') : t('New Proxy Group') }}</DialogTitle>
          <DialogDescription> {{ t('Configure a SOCKS5 proxy group.') }} </DialogDescription>
        </DialogHeader>
        <div class="space-y-4 py-2">
          <div class="space-y-1">
            <Label :for="nameId" class="text-slate-700 dark:text-slate-200"> {{ t('Name') }} </Label>
            <Input :id="nameId" v-model="formName" placeholder="my-proxy" />
          </div>
          <div class="flex gap-2">
            <div class="flex-1 space-y-1">
              <Label :for="hostId" class="text-slate-700 dark:text-slate-200"> {{ t('Host') }} </Label>
              <Input :id="hostId" v-model="formHost" placeholder="127.0.0.1" class="font-mono" />
            </div>
            <div class="w-24 space-y-1">
              <Label :for="portId" class="text-slate-700 dark:text-slate-200"> {{ t('Port') }} </Label>
              <Input :id="portId" v-model="formPort" placeholder="7890" class="font-mono" />
            </div>
          </div>
          <div class="space-y-1">
            <Label :for="testUrlId" class="text-slate-700 dark:text-slate-200"> {{ t('Test URL') }} </Label>
            <Input :id="testUrlId" v-model="formTestUrl" placeholder="https://www.google.com" class="font-mono text-sm" />
          </div>
        </div>
        <DialogFooter class="gap-2 sm:gap-0">
          <button
            @click="editOpen = false"
            class="inline-flex items-center justify-center rounded-md text-sm font-medium h-9 px-4 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
          > {{ t('Cancel') }} </button>
          <Button :disabled="saving" @click="onSaveGroup" class="bg-blue-600 hover:bg-blue-700 text-white">
            {{ saving ? t('Saving...') : (editingGroup ? t('Save') : t('Create')) }}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <!-- Delete / Migration Dialog -->
    <Dialog :open="deleteOpen" @update:open="deleteOpen = $event">
      <DialogContent class="sm:max-w-[480px]"
        @interact-outside="(e: Event) => e.preventDefault()"
        @escape-key-down="(e: Event) => e.preventDefault()"
      >
        <DialogHeader>
          <DialogTitle>{{ t('Cannot delete {name}', { name: deletingGroup?.name ?? '' }) }}</DialogTitle>
          <DialogDescription> {{ t('This proxy group is still in use. Migrate references to another group before deleting.') }} </DialogDescription>
        </DialogHeader>
        <div v-if="deleteConflict" class="space-y-3 py-2">
          <!-- Referencing auto rules -->
          <div v-if="deleteConflict.auto_rules.length > 0">
            <p class="text-sm font-medium text-slate-700 dark:text-slate-200 mb-1">{{ t('Auto Rules ({count})', { count: deleteConflict.auto_rules.length }) }}</p>
            <div class="space-y-1 pl-3 border-l-2 border-slate-200 dark:border-slate-700">
              <div v-for="r in deleteConflict.auto_rules" :key="r.id" class="text-xs text-slate-500 dark:text-slate-400">
                {{ r.name }}
              </div>
            </div>
          </div>
          <!-- Manual hijacks -->
          <div v-if="deleteConflict.manual_hijack_count > 0">
            <p class="text-sm font-medium text-slate-700 dark:text-slate-200">
              {{ t('Manual hijacks: {count} processes', { count: deleteConflict.manual_hijack_count }) }}
            </p>
          </div>
          <!-- Target group selector -->
          <div class="space-y-1 pt-2 border-t border-slate-200 dark:border-slate-800">
            <Label :for="migrateTargetLabelId" class="text-slate-700 dark:text-slate-200"> {{ t('Migrate to') }} </Label>
            <Select v-model="migrateTargetId">
              <SelectTrigger :id="migrateTargetLabelId">
                <SelectValue :placeholder="t('Select target group')" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem
                  v-for="g in groups.filter(g => g.id !== deletingGroup?.id)"
                  :key="g.id"
                  :value="String(g.id)"
                >
                  {{ g.name }} ({{ g.host }}:{{ g.port }})
                </SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
        <DialogFooter class="gap-2 sm:gap-0">
          <button
            @click="deleteOpen = false"
            class="inline-flex items-center justify-center rounded-md text-sm font-medium h-9 px-4 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
          > {{ t('Cancel') }} </button>
          <Button :disabled="saving" @click="onMigrateAndDelete" class="bg-red-600 hover:bg-red-700 text-white">
            {{ saving ? t('Processing...') : t('Migrate & Delete') }}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
