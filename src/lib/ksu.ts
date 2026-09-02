// SPDX-License-Identifier: GPL-3.0-or-later
// @ts-ignore
import * as Automerge from '@automerge/automerge'
import { exec, moduleInfo, toast as ksuToast } from 'kernelsu'
export const previewMode: boolean = typeof window.ksu === 'undefined'

function resolveModuleId(): string {
  try {
    const info = JSON.parse(moduleInfo()) as { id?: string }
    return info.id || 'ebpf-monitor'
  } catch {
    return 'ebpf-monitor'
  }
}

export const MODDIR = `/data/adb/modules/${previewMode ? 'ebpf-monitor' : resolveModuleId()}`
export const BIN = `${MODDIR}/ebpf-monitor`
export const BIN_CTL = `${MODDIR}/ebpf-monitor-ctl`
export const PERSIST = '/data/adb/ebpf-monitor'
export const CTL_SOCK = `${PERSIST}/ctl.sock`

export interface Status {
  running: boolean
  kernel: string
  btf: boolean
  eventsBytes: number
  newest: number
}

export interface EventRow {
  seq: number
  ts: string
  epoch_ms: number
  pid: number
  tid: number
  uid: number
  comm: string
  pkg: string
  op: string
  ret: number
  flags: number
  file: string
  cmd: string
  old_file?: string
}

interface CtlResp {
  ok: boolean
  error?: string
  events?: EventRow[]
  kernel?: string
  btf?: boolean
  events_bytes?: number
  newest?: number
  config?: ConfigJson
}

export interface ConfigJson {
  whitelist: { uid: number[]; pid: number[] }
  watch: { basenames: string[]; groups: string[] } | null
  print: { groups: string[] } | null
}

async function execute(cmd: string): Promise<string> {
  const { errno, stdout, stderr } = await exec(cmd, {})
  if (errno !== 0) throw new Error(stderr || stdout || `errno=${errno}`)
  return stdout
}

async function invokeCtl(args: string): Promise<CtlResp> {
  const out = (await execute(`${BIN_CTL} ${args}`)).trim()
  const j = JSON.parse(out.split('\n').pop() || '{}') as CtlResp
  if (typeof j !== 'object' || j === null) throw new Error('bad ctl response')
  if (j.ok !== true) throw new Error(j.error || 'ctl failed')
  return j
}

const MOCK_EVENTS: EventRow[] = [
  { seq: 8, ts: '08-31 14:09:58', epoch_ms: 0, pid: 16681, tid: 21305, uid: 10360, comm: 'pool-6-thread-3', pkg: 'bin.mt.plus', op: 'unlinkat', ret: 0, flags: 0, cmd: '', file: '/storage/emulated/0/123456789/test.jpg' },
  { seq: 7, ts: '08-31 14:09:51', epoch_ms: 0, pid: 10057, tid: 15294, uid: 10263, comm: 'Thread-9', pkg: 'com.android.providers.media.module', op: 'unlinkat', ret: 0, flags: 0, cmd: '', file: '/data/media/0/123456789/test.jpg' },
  { seq: 6, ts: '08-31 14:09:44', epoch_ms: 0, pid: 16681, tid: 16681, uid: 10360, comm: 'bin.mt.plus', pkg: 'bin.mt.plus', op: 'openat', ret: 172, flags: 0x241, cmd: '', file: '/storage/emulated/0/123456789/test.jpg' },
  { seq: 5, ts: '08-31 14:09:43', epoch_ms: 0, pid: 10057, tid: 10563, uid: 10263, comm: 'Thread-7', pkg: 'com.android.providers.media.module', op: 'openat', ret: 180, flags: 0x0, cmd: '', file: '/data/media/0/123456789/test.jpg' },
  { seq: 4, ts: '08-31 14:09:40', epoch_ms: 0, pid: 28914, tid: 28914, uid: 0, comm: 'sh', pkg: '-', op: 'openat', ret: 33, flags: 0x241, cmd: 'touch /storage/emulated/0/123456789/test.jpg', file: '/storage/emulated/0/123456789/test.jpg' },
  { seq: 3, ts: '08-31 14:08:12', epoch_ms: 0, pid: 20123, tid: 20456, uid: 10211, comm: 'gwd', pkg: 'com.tencent.mm', op: 'renameat', ret: 0, flags: 0, cmd: '', file: '/storage/emulated/0/123456789/test.jpg' },
  { seq: 2, ts: '08-31 14:08:11', epoch_ms: 0, pid: 20123, tid: 20456, uid: 10211, comm: 'gwd', pkg: 'com.tencent.mm', op: 'openat', ret: 88, flags: 0x241, cmd: '', file: '/storage/emulated/0/123456789/.test.jpg.tmp' },
  { seq: 1, ts: '08-31 14:07:02', epoch_ms: 0, pid: 31200, tid: 31200, uid: 0, comm: 'sh', pkg: '-', op: 'mkdirat', ret: 0, flags: 0, cmd: 'mkdir -p /storage/emulated/0/123456789', file: '/storage/emulated/0/123456789' }
]
const MOCK_CONFIG: ConfigJson = {
  whitelist: { uid: [1000], pid: [] },
  watch: { basenames: ['test.jpg', '123456789'], groups: ['create', 'create_any', 'rename_', 'delete'] },
  print: null,
}
const cloneConfig = (c: ConfigJson): ConfigJson => JSON.parse(JSON.stringify(c))

type ForestDoc = Automerge.Doc<{ forest: Record<string, EventRow[]> }>
async function loadForest(): Promise<ForestDoc | null> {
  try { const b64 = localStorage.getItem('forest'); if (!b64) return null; const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0)); return Automerge.load(bytes) } catch { return null }
}
async function saveForest(doc: ForestDoc): Promise<void> {
  try { const bytes = Automerge.save(doc); localStorage.setItem('forest', btoa(String.fromCharCode(...bytes))) } catch {}
}
function collectForest(doc: ForestDoc): EventRow[] {
  const out: EventRow[] = []
  if (typeof doc === 'object' && doc !== null && 'forest' in doc) {
    const forest = (doc as { forest: unknown }).forest
    if (forest && typeof forest === 'object') {
      for (const k of Object.keys(forest as Record<string, unknown>)) {
        const arr = (forest as Record<string, unknown>)[k]
        if (Array.isArray(arr)) for (const e of arr as EventRow[]) out.push(e)
      }
    }
  }
  return out.sort((a,b)=> a.epoch_ms - b.epoch_ms)
}
export function classifyEvent(e: EventRow): { c: string; txt: string } {
  if (e.ret < 0) return { c: 'fail', txt: '失败' }
  switch (e.op) {
    case 'openat': case 'openat2': case 'creat':
      return (e.flags & 0x40) ? { c: 'create', txt: '创建' } : { c: 'open', txt: '打开' }
    case 'mkdirat': case 'mkdir': return { c: 'mkdir', txt: '目录' }
    case 'renameat': case 'renameat2': case 'rename': return { c: 'rename', txt: '改名' }
    case 'unlinkat': case 'unlink': return { c: 'delete', txt: '删除' }
    default: return { c: 'open', txt: e.op }
  }
}

export const api = {
  async fetchStatus(): Promise<Status> {
    if (previewMode) return { running: true, kernel: '5.15.94-android13-8', btf: true, eventsBytes: 8123, newest: 8 }
    try {
      const j = await invokeCtl('status')
      return { running: true, kernel: j.kernel || '', btf: !!j.btf, eventsBytes: j.events_bytes || 0, newest: j.newest || 0 }
    } catch {
      return { running: false, kernel: '', btf: false, eventsBytes: 0, newest: 0 }
    }
  },

  async fetchEvents(after = 0): Promise<EventRow[]> {
    if (previewMode) return MOCK_EVENTS.filter(e => e.seq > after)
    const j = await invokeCtl(`events after ${after} limit 300`)
    return j.events || []
  },

  async syncEvents(after = 0): Promise<{ events: EventRow[]; truncated: boolean; oldest: number; newest: number }> {
    if (previewMode) return { events: MOCK_EVENTS.filter(e => e.seq > after), truncated: false, oldest: 1, newest: 8 }
    const local = await loadForest()
    const docBytes = local ? Automerge.save(local) : null
    const b64 = docBytes ? btoa(String.fromCharCode(...docBytes)) : ''
    const { promise, resolve, reject } = Promise.withResolvers<string>()
    const cmd = b64 ? `echo '${b64.replace(/'/g, "'\\''")}' | ${BIN_CTL} sync` : `${BIN_CTL} sync`
    execute(cmd).then(resolve).catch(reject)
    const out = await promise
    try {
      const raw: unknown = JSON.parse(out)
      if (raw && typeof raw === 'object' && 'doc' in raw) {
        const docField = (raw as { doc: unknown }).doc
        if (typeof docField === 'string' && docField) {
          const bytes = Uint8Array.from(atob(docField), c => c.charCodeAt(0))
          const remote = Automerge.load<ForestDoc>(bytes)
          if (local) { const merged = Automerge.merge(local, remote) as ForestDoc; await saveForest(merged); return { events: collectForest(merged), truncated: false, oldest: 0, newest: 0 } }
          const toSave = remote as ForestDoc; await saveForest(toSave); return { events: collectForest(toSave), truncated: false, oldest: 0, newest: 0 }
        }
      }
    } catch {}
    return { events: [], truncated: false, oldest: 0, newest: 0 }
  },
  async clearEvents(): Promise<void> {
    if (previewMode) return
    await invokeCtl('clear')
  },
  async fetchConfig(): Promise<ConfigJson> {
    const fetchValue = async (k: string, temp = false): Promise<string> => {
      const flag = temp ? '--temp ' : ''
      try { const out = await execute(`ksud module config get ${flag}${k} 2>/dev/null || true`); return out.trim() } catch { return '' }
    }
    const [bases, groups, uidStr, pidStr, printStr] = await Promise.all([
      fetchValue('watch.basenames'),
      fetchValue('watch.groups'),
      fetchValue('whitelist.uid'),
      fetchValue('whitelist.pid', true),
      fetchValue('print.groups')
    ])
    const cfg = cloneConfig(MOCK_CONFIG)
    try { const a = JSON.parse(bases); if (Array.isArray(a)) cfg.watch!.basenames = a } catch {}
    try { const a = JSON.parse(groups); if (Array.isArray(a)) cfg.watch!.groups = a } catch {}
    try { const a = JSON.parse(uidStr); if (Array.isArray(a)) cfg.whitelist.uid = a } catch {}
    try { const a = JSON.parse(pidStr); if (Array.isArray(a)) cfg.whitelist.pid = a } catch {}
    try { const a = JSON.parse(printStr); if (Array.isArray(a)) cfg.print = a.length ? { groups: a } : null } catch {}
    return cfg
  },

  async saveConfig(cfg: ConfigJson): Promise<void> {
    if (previewMode) { Object.assign(MOCK_CONFIG, cloneConfig(cfg)); return }
    const persistValue = async (k: string, v: string, temp = false) => {
      const esc = v.replace(/'/g, `'\\''`)
      const flag = temp ? '--temp ' : ''
      await execute(`ksud module config set ${flag}${k} '${esc}'`)
    }
    await persistValue('watch.basenames', JSON.stringify(cfg.watch?.basenames ?? []))
    await persistValue('watch.groups', JSON.stringify(cfg.watch?.groups ?? []))
    await persistValue('whitelist.uid', JSON.stringify(cfg.whitelist.uid ?? []))
    await persistValue('whitelist.pid', JSON.stringify(cfg.whitelist.pid ?? []), true)
    await persistValue('print.groups', JSON.stringify(cfg.print?.groups ?? []))
    try { await execute(`${BIN_CTL} reload`) } catch {}
  },

  async fetchTargets(): Promise<string[]> {
    return (await this.fetchConfig()).watch?.basenames ?? []
  },

  async saveTargets(list: string[]): Promise<void> {
    const cfg = await this.fetchConfig()
    cfg.watch = cfg.watch ?? { basenames: [], groups: [] }
    cfg.watch.basenames = list
    await this.saveConfig(cfg)
  },
}

export function notify(msg: string): void {
  if (!previewMode && ksuToast) {
    try {
      ksuToast(msg)
      return
    } catch { /* fall back to console */ }
  }
  console.log('[toast]', msg)
}

