// SPDX-License-Identifier: GPL-3.0-or-later
import { exec, moduleInfo, toast as ksuToast } from 'kernelsu'

export const previewMode: boolean = typeof window.ksu === 'undefined'

function safeModuleId(): string {
  try {
    const info = JSON.parse(moduleInfo()) as { id?: string }
    return info.id || 'ebpf-monitor'
  } catch {
    return 'ebpf-monitor'
  }
}

export const MODDIR = `/data/adb/modules/${previewMode ? 'ebpf-monitor' : safeModuleId()}`
export const BIN = `${MODDIR}/ebpf-monitor`
export const PERSIST = '/data/adb/ebpf-monitor'

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
  syscall: unknown[]
  syscall_groups: Array<{
    name: string
    syscalls: string[]
    watch_param?: string
    watch_flag_param?: string
    watch_flag_mask?: number
  }>
  print: { groups: string[] } | null
  watch: { basenames: string[]; groups: string[] } | null
}

async function run(cmd: string): Promise<string> {
  const { errno, stdout, stderr } = await exec(cmd, {})
  if (errno !== 0) throw new Error(stderr || stdout || `errno=${errno}`)
  return stdout
}

async function ctlJson(args: string): Promise<CtlResp> {
  const out = (await run(`${BIN} ${args}`)).trim()
  const parsed: unknown = JSON.parse(out.split('\n').pop() || '{}')
  if (typeof parsed !== 'object' || parsed === null) throw new Error('bad ctl response')
  const j = parsed as CtlResp
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
  syscall: [],
  syscall_groups: [],
  print: null,
  watch: { basenames: ['test.jpg', '123456789'], groups: ['create', 'create_any', 'rename_', 'delete'] }
}
const cloneCfg = (c: ConfigJson): ConfigJson => JSON.parse(JSON.stringify(c))

export function classify(e: EventRow): { c: string; txt: string } {
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
  async status(): Promise<Status> {
    if (previewMode) return { running: true, kernel: '5.15.94-android13-8', btf: true, eventsBytes: 8123, newest: 8 }
    try {
      const j = await ctlJson('ctl status')
      return { running: true, kernel: j.kernel || '', btf: !!j.btf, eventsBytes: j.events_bytes || 0, newest: j.newest || 0 }
    } catch {
      return { running: false, kernel: '', btf: false, eventsBytes: 0, newest: 0 }
    }
  },

  async events(after = 0): Promise<EventRow[]> {
    if (previewMode) return MOCK_EVENTS.filter(e => e.seq > after)
    const j = await ctlJson(`ctl events after=${after} limit=300`)
    return j.events || []
  },

  async clear(): Promise<void> {
    if (previewMode) return
    await ctlJson('ctl clear')
  },

  async getConfig(): Promise<ConfigJson> {
    if (previewMode) return cloneCfg(MOCK_CONFIG)
    const j = await ctlJson('ctl get-config')
    if (!j.config) throw new Error('get-config 无返回')
    return j.config
  },

  async setConfig(cfg: ConfigJson): Promise<void> {
    if (previewMode) {
      Object.assign(MOCK_CONFIG, cloneCfg(cfg))
      return
    }
    // transport through sh via base64: JSON body must survive any quoting;
    // unescape(encodeURIComponent(...)) makes btoa accept UTF-8
    const b64 = btoa(unescape(encodeURIComponent(JSON.stringify(cfg))))
    const pending = `${PERSIST}/pending.json`
    await run(`printf %s '${b64}' | base64 -d > ${pending} && ${BIN} ctl set-config ${pending} && rm -f ${pending}`)
  },

  async targets(): Promise<string[]> {
    return (await this.getConfig()).watch?.basenames ?? []
  },

  async setTargets(list: string[]): Promise<void> {
    const cfg = await this.getConfig()
    cfg.watch = cfg.watch ?? { basenames: [], groups: [] }
    cfg.watch.basenames = list
    await this.setConfig(cfg)
  }
}

export function toast(msg: string): void {
  if (!previewMode && ksuToast) {
    try {
      ksuToast(msg)
      return
    } catch { /* fall back to console */ }
  }
  console.log('[toast]', msg)
}
