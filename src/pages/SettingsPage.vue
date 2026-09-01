<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import {
  MiuixCard, MiuixBasicComponent, MiuixSmallTitle, MiuixInput, MiuixButton,
  MiuixText, MiuixIconButton, MiuixIcon, MiuixDivider, MiuixSwitchPreference
} from 'miuix-vue'
import { Delete, Close } from 'miuix-vue/icons'
import PullToRefresh from '@/components/PullToRefresh.vue'
import { store, refresh } from '@/lib/store'
import { api, toast, classify, previewMode, type ConfigJson } from '@/lib/ksu'
import { displayName } from '@/lib/labels'

const cfg = ref<ConfigJson | null>(null)
const newName = ref('')
const newUid = ref('')
const newPid = ref('')

const WATCH_GROUPS = [
  { key: 'create', title: '创建（openat + O_CREAT）', summary: '直接以创建标志打开目标 basename 的进程' },
  { key: 'create_any', title: '目录与临时文件创建', summary: 'mkdirat / mkdir / creat / openat2（把目录名也加入目标可抓到 mkdir）' },
  { key: 'rename_', title: '改名成目标（原子写入）', summary: 'renameat* —— 下载器先写 .tmp 再改名的模式' },
  { key: 'delete', title: '删除目标', summary: 'unlinkat / unlink —— 谁在删除它' },
]

async function loadCfg(): Promise<void> {
  try {
    cfg.value = await api.getConfig()
  } catch (e: unknown) {
    toast('配置读取失败: ' + (e instanceof Error ? e.message : String(e)))
  }
}
onMounted(loadCfg)

async function refreshAll(): Promise<void> {
  await Promise.all([refresh(), loadCfg()])
}

// write-through edit: mutate the local mirror first, submit the whole
// config, and revert to the snapshot if the daemon rejects it — the UI
// always mirrors what the running daemon actually has
async function mutate(fn: (c: ConfigJson) => void): Promise<void> {
  if (!cfg.value) return
  const snapshot = JSON.stringify(cfg.value)
  fn(cfg.value)
  try {
    await api.setConfig(cfg.value)
    store.targets = [...(cfg.value.watch?.basenames ?? [])]
    refresh()
  } catch (e: unknown) {
    cfg.value = JSON.parse(snapshot)
    toast('保存失败: ' + (e instanceof Error ? e.message : String(e)))
  }
}

const basenames = computed(() => cfg.value?.watch?.basenames ?? [])
const watchGroups = computed(() => new Set(cfg.value?.watch?.groups ?? []))
const printOn = computed(() => (cfg.value?.print?.groups.length ?? 0) > 0)
const uids = computed(() => cfg.value?.whitelist.uid ?? [])
const pids = computed(() => cfg.value?.whitelist.pid ?? [])

function ensureWatch(c: ConfigJson): { basenames: string[]; groups: string[] } {
  c.watch = c.watch ?? { basenames: [], groups: [] }
  return c.watch
}

function addName(): void {
  const name = newName.value.trim()
  if (!name) return
  if (!/^[A-Za-z0-9._@+\-]{1,63}$/.test(name)) { toast('仅字母数字 . _ @ + - ，≤63 字符'); return }
  if (basenames.value.includes(name)) { toast('已存在'); return }
  mutate(c => { ensureWatch(c).basenames.push(name) })
  newName.value = ''
}
const rmName = (n: string): void => {
  void mutate(c => { const w = ensureWatch(c); w.basenames = w.basenames.filter(x => x !== n) })
}

const toggleGroup = (k: string, on: boolean): void => {
  void mutate(c => {
    const w = ensureWatch(c)
    w.groups = on ? [...new Set([...w.groups, k])] : w.groups.filter(x => x !== k)
  })
}

const togglePrint = (on: boolean): void => {
  void mutate(c => { c.print = on ? { groups: ['open_'] } : null })
}

function addNum(which: 'uid' | 'pid'): void {
  const src = which === 'uid' ? newUid : newPid
  const raw = src.value.trim()
  const v = Number(raw)
  if (!/^\d{1,7}$/.test(raw) || v > 4194304) { toast('请输入 0-4194304 的数字'); return }
  mutate(c => { const arr = which === 'uid' ? c.whitelist.uid : c.whitelist.pid; if (!arr.includes(v)) arr.push(v) })
  src.value = ''
}
const rmNum = (w: 'uid' | 'pid', v: number): void => {
  void mutate(c => { if (w === 'uid') c.whitelist.uid = c.whitelist.uid.filter(x => x !== v); else c.whitelist.pid = c.whitelist.pid.filter(x => x !== v) })
}

const topApps = computed(() => {
  const byPkg: Record<string, number> = {}
  for (const e of store.events) byPkg[displayName(e)] = (byPkg[displayName(e)] || 0) + 1
  return Object.keys(byPkg).sort((a, b) => byPkg[b] - byPkg[a]).slice(0, 5)
    .map(app => ({ app, count: byPkg[app] }))
})
const opSummary = computed(() => {
  const byOp: Record<string, number> = {}
  for (const e of store.events) byOp[classify(e).txt] = (byOp[classify(e).txt] || 0) + 1
  return Object.keys(byOp).sort((a, b) => byOp[b] - byOp[a])
    .map(o => o + ' ' + byOp[o]).join(' · ')
})
const kbSize = computed(() => (store.status.eventsBytes / 1024).toFixed(0) + ' KB')

async function clearEvents(): Promise<void> {
  await api.clear()
  toast('事件已清空')
  refresh()
}
</script>

<template>
  <PullToRefresh :on-refresh="refreshAll">
    <MiuixSmallTitle text="守护进程" />
    <MiuixCard class="sec-card" press-feedback="none">
      <MiuixBasicComponent
        :title="store.status.running ? '运行中' : '未运行（重启设备生效）'"
        :title-color="store.status.running ? 'var(--m-color-primary)' : 'var(--m-color-error)'"
        :summary="'内核 ' + (store.status.kernel || '-') + ' · BTF ' + (store.status.btf ? '正常' : '缺失') + ' · 事件 ' + kbSize" />
      <MiuixBasicComponent title="运行日志 (logcat)" summary="adb logcat -s ebpf-monitor" :disabled="true" />
      <MiuixBasicComponent v-if="!previewMode" title="清空事件记录" summary="删除 events.jsonl（seq 不回退）"
                           clickable @click="clearEvents">
        <template #end>
          <MiuixIcon :icon="Close" :size="20" color="var(--m-color-error)" />
        </template>
      </MiuixBasicComponent>
    </MiuixCard>

    <MiuixSmallTitle text="监视目标（basename）" />
    <MiuixCard class="sec-card" press-feedback="none">
      <MiuixBasicComponent v-for="n in basenames" :key="n" :title="n" summary="watch.basenames">
        <template #end>
          <MiuixIconButton aria-label="删除" @click="rmName(n)">
            <MiuixIcon :icon="Delete" :size="22" />
          </MiuixIconButton>
        </template>
      </MiuixBasicComponent>
      <MiuixBasicComponent v-if="!basenames.length" title="（无目标，添加后开始记录）" :disabled="true" />
      <MiuixDivider />
      <div class="add-row">
        <MiuixInput v-model="newName" placeholder="如 test.jpg 或目录名"
                    autocapitalize="off" spellcheck="false" @keyup.enter="addName" />
        <MiuixButton type="primary" @click="addName">添加</MiuixButton>
      </div>
    </MiuixCard>

    <MiuixSmallTitle text="监视操作" />
    <MiuixCard class="sec-card" press-feedback="none">
      <MiuixSwitchPreference
        v-for="g in WATCH_GROUPS" :key="g.key"
        :title="g.title" :summary="g.summary"
        :model-value="watchGroups.has(g.key)"
        @change="toggleGroup(g.key, $event)" />
    </MiuixCard>

    <MiuixSmallTitle text="白名单（这些进程不记录）" />
    <MiuixCard class="sec-card" press-feedback="none">
      <MiuixBasicComponent v-for="u in uids" :key="'u' + u" :title="'uid ' + u" summary="whitelist.uid">
        <template #end>
          <MiuixIconButton aria-label="删除" @click="rmNum('uid', u)">
            <MiuixIcon :icon="Delete" :size="22" />
          </MiuixIconButton>
        </template>
      </MiuixBasicComponent>
      <MiuixBasicComponent v-for="p in pids" :key="'p' + p" :title="'pid ' + p" summary="whitelist.pid">
        <template #end>
          <MiuixIconButton aria-label="删除" @click="rmNum('pid', p)">
            <MiuixIcon :icon="Delete" :size="22" />
          </MiuixIconButton>
        </template>
      </MiuixBasicComponent>
      <MiuixBasicComponent v-if="!uids.length && !pids.length" title="（空白名单，全部记录）" :disabled="true" />
      <MiuixDivider />
      <div class="add-row">
        <MiuixInput v-model="newUid" type="number" placeholder="uid，如 10263" @keyup.enter="addNum('uid')" />
        <MiuixButton @click="addNum('uid')">加 uid</MiuixButton>
        <MiuixInput v-model="newPid" type="number" placeholder="pid" @keyup.enter="addNum('pid')" />
        <MiuixButton @click="addNum('pid')">加 pid</MiuixButton>
      </div>
    </MiuixCard>

    <MiuixSmallTitle text="调试" />
    <MiuixCard class="sec-card" press-feedback="none">
      <MiuixSwitchPreference
        title="全量打印 openat"
        summary="所有打开操作进事件流（噪音极大，短时深挖用）"
        :model-value="printOn"
        @change="togglePrint" />
    </MiuixCard>

    <MiuixSmallTitle text="命中统计" />
    <MiuixCard class="sec-card" press-feedback="none">
      <MiuixBasicComponent v-if="!store.events.length" title="（尚无数据）" :disabled="true" />
      <template v-else>
        <MiuixBasicComponent :title="'总命中 ' + store.events.length" :summary="'来源 ' + topApps.length + ' 个'">
          <template #end>
            <MiuixText type="body1" color="var(--m-color-on-surface-variant-actions)">{{ store.events.length }}</MiuixText>
          </template>
        </MiuixBasicComponent>
        <MiuixBasicComponent v-for="a in topApps" :key="a.app" :title="a.app">
          <template #end>
            <MiuixText type="body1" color="var(--m-color-on-surface-variant-actions)">{{ a.count }}</MiuixText>
          </template>
        </MiuixBasicComponent>
        <MiuixBasicComponent v-if="opSummary" title="按操作" :summary="opSummary" />
      </template>
    </MiuixCard>

    <MiuixSmallTitle text="关于" />
    <MiuixCard class="sec-card" press-feedback="none">
      <MiuixBasicComponent title="配置即时生效" summary="所有改动经 daemon 校验后写 config.toml 并热重载 BPF 表" :disabled="true" />
      <MiuixBasicComponent title="存储位置" summary="/data/adb/ebpf-monitor（配置/事件持久，模块更新不丢）" :disabled="true" />
    </MiuixCard>
  </PullToRefresh>
</template>

<style lang="scss" scoped>
.sec-card { margin: 0 12px 12px; }
.add-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 16px;
  :deep(.m-input) { flex: 1; min-width: 0; }
}
</style>
