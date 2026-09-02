<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import {
  MiuixCard, MiuixBasicComponent, MiuixSmallTitle, MiuixInput, MiuixButton,
  MiuixIconButton, MiuixIcon, MiuixDivider, MiuixSwitchPreference, MiuixTopAppBar
} from 'miuix-vue'
import { Delete, ChevronBackward } from 'miuix-vue/icons'
import { api, notify, type ConfigJson } from '@/lib/ksu'
import { store } from '@/lib/store'

const emit = defineEmits<{ back: [] }>()

const cfg = ref<ConfigJson | null>(null)
const draftBasename = ref('')
const draftUid = ref('')
const draftPid = ref('')

const WATCH_GROUP_PRESETS = [
  { key: 'create', title: '创建' },
  { key: 'create_any', title: '目录创建' },
  { key: 'rename_', title: '重命名' },
  { key: 'delete', title: '删除' },
]

async function fetchConfig(): Promise<void> {
  try { cfg.value = await api.fetchConfig() } catch (e: unknown) { notify('读取失败: ' + (e instanceof Error ? e.message : String(e))) }
}
onMounted(fetchConfig)

async function commitConfig(transform: (c: ConfigJson) => void): Promise<void> {
  if (!cfg.value) return
  const snapshot = JSON.stringify(cfg.value)
  transform(cfg.value)
  try {
    await api.saveConfig(cfg.value)
    store.targets = [...(cfg.value.watch?.basenames ?? [])]
  } catch (e: unknown) {
    cfg.value = JSON.parse(snapshot)
    notify('保存失败: ' + (e instanceof Error ? e.message : String(e)))
}
}
const basenames = computed(() => cfg.value?.watch?.basenames ?? [])
const watchGroups = computed(() => new Set(cfg.value?.watch?.groups ?? []))
const uids = computed(() => cfg.value?.whitelist.uid ?? [])
const pids = computed(() => cfg.value?.whitelist.pid ?? [])
const verboseEnabled = computed(() => (cfg.value?.print?.groups.length ?? 0) > 0)

function ensureWatchConfig(c: ConfigJson): { basenames: string[]; groups: string[] } {
  c.watch = c.watch ?? { basenames: [], groups: [] }
  return c.watch
}

function addBasename(): void {
  const name = draftBasename.value.trim()
  if (!name) return
  if (!/^[A-Za-z0-9._@+\-]{1,63}$/.test(name)) { notify('仅字母数字 . _ @ + - ，≤63'); return }
  if (basenames.value.includes(name)) { notify('已存在'); return }
  commitConfig(c => { ensureWatchConfig(c).basenames.push(name) })
  draftBasename.value = ''
}
const removeBasename = (n: string): void => { void commitConfig(c => { const w = ensureWatchConfig(c); w.basenames = w.basenames.filter(x => x !== n) }) }

const setWatchGroup = (k: string, on: boolean): void => {
  void commitConfig(c => {
    const w = ensureWatchConfig(c)
    w.groups = on ? [...new Set([...w.groups, k])] : w.groups.filter(x => x !== k)
  })
}
const setVerboseLogging = (on: boolean): void => { void commitConfig(c => { c.print = on ? { groups: ['open_'] } : null }) }

function addWhitelistId(which: 'uid' | 'pid'): void {
  const src = which === 'uid' ? draftUid : draftPid
  const raw = src.value.trim()
  const v = Number(raw)
  if (!/^\d{1,7}$/.test(raw) || v > 4194304) { notify('请输入 0-4194304'); return }
  commitConfig(c => { const arr = which === 'uid' ? c.whitelist.uid : c.whitelist.pid; if (!arr.includes(v)) arr.push(v) })
  src.value = ''
}
const removeWhitelistId = (w: 'uid' | 'pid', v: number): void => {
  void commitConfig(c => { if (w === 'uid') c.whitelist.uid = c.whitelist.uid.filter(x => x !== v); else c.whitelist.pid = c.whitelist.pid.filter(x => x !== v) })
}
</script>

<template>
  <div class="cfg-overlay">
    <MiuixTopAppBar title="监视规则" class="cfg-topbar">
      <template #navigation>
        <MiuixIconButton aria-label="返回" @click="emit('back')">
          <MiuixIcon :icon="ChevronBackward" :size="24" />
        </MiuixIconButton>
      </template>
    </MiuixTopAppBar>
    <div class="cfg-scroll">
      <MiuixSmallTitle text="目标" />
      <MiuixCard class="sec-card" press-feedback="none">
        <MiuixBasicComponent v-for="n in basenames" :key="n" :title="n">
          <template #end>
            <MiuixIconButton aria-label="删除" @click="removeBasename(n)">
              <MiuixIcon :icon="Delete" :size="22" />
            </MiuixIconButton>
          </template>
        </MiuixBasicComponent>
        <MiuixBasicComponent v-if="!basenames.length" title="暂无" :disabled="true" />
        <MiuixDivider />
        <div class="add-row">
          <MiuixInput v-model="draftBasename" placeholder="basename" autocapitalize="off" spellcheck="false" @keyup.enter="addBasename" />
          <MiuixButton type="primary" @click="addBasename">添加</MiuixButton>
        </div>
      </MiuixCard>

      <MiuixSmallTitle text="操作" />
      <MiuixCard class="sec-card" press-feedback="none">
        <MiuixSwitchPreference
          v-for="g in WATCH_GROUP_PRESETS" :key="g.key"
          :title="g.title"
          :model-value="watchGroups.has(g.key)"
          @change="setWatchGroup(g.key, $event)" />
      </MiuixCard>

      <MiuixSmallTitle text="白名单" />
      <MiuixCard class="sec-card" press-feedback="none">
        <MiuixBasicComponent v-for="u in uids" :key="'u'+u" :title="`UID ${u}`">
          <template #end>
            <MiuixIconButton aria-label="删除" @click="removeWhitelistId('uid', u)">
              <MiuixIcon :icon="Delete" :size="22" />
            </MiuixIconButton>
          </template>
        </MiuixBasicComponent>
        <MiuixBasicComponent v-for="p in pids" :key="'p'+p" :title="`PID ${p}`">
          <template #end>
            <MiuixIconButton aria-label="删除" @click="removeWhitelistId('pid', p)">
              <MiuixIcon :icon="Delete" :size="22" />
            </MiuixIconButton>
          </template>
        </MiuixBasicComponent>
        <MiuixBasicComponent v-if="!uids.length && !pids.length" title="暂无" :disabled="true" />
        <MiuixDivider />
        <div class="add-row">
          <MiuixInput v-model="draftUid" type="number" placeholder="UID" @keyup.enter="addWhitelistId('uid')" />
          <MiuixButton @click="addWhitelistId('uid')">添加</MiuixButton>
        </div>
        <div class="add-row">
          <MiuixInput v-model="draftPid" type="number" placeholder="PID" @keyup.enter="addWhitelistId('pid')" />
          <MiuixButton @click="addWhitelistId('pid')">添加</MiuixButton>
        </div>
      </MiuixCard>

      <MiuixSmallTitle text="调试" />
      <MiuixCard class="sec-card" press-feedback="none">
        <MiuixSwitchPreference
          title="全量 open"
          :model-value="verboseEnabled"
          @change="setVerboseLogging" />
      </MiuixCard>
    </div>
  </div>
</template>

<style lang="scss" scoped>
.cfg-overlay {
  position: fixed;
  inset: 0;
  z-index: 30;
  background: var(--m-color-surface);
  display: flex;
  flex-direction: column;
}
.cfg-topbar {
  flex: none;
}
.cfg-scroll {
  flex: 1;
  min-height: 0;
  overflow-y: auto;
  overscroll-behavior: contain;
  padding: 12px 0 24px;
}
.sec-card { margin: 0 12px 12px; }
.add-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 16px;
  :deep(.m-input) { flex: 1; min-width: 0; }
}
</style>
