// SPDX-License-Identifier: GPL-3.0-or-later
import { reactive } from 'vue'
import { api, previewMode, type EventRow, type Status } from '@/lib/ksu'
import { loadLabels } from '@/lib/labels'

export const store = reactive({
  status: { running: false, kernel: '', btf: false, eventsBytes: 0, newest: 0 } as Status,
  targets: [] as string[],
  events: [] as EventRow[],
  error: ''
})

let polling = false
let refreshing = false

export async function refresh(): Promise<void> {
  if (refreshing) return
  refreshing = true
  try {
    const st = await api.status()
    store.status = st
    const after = store.events.length
      ? store.events[store.events.length - 1].seq
      : Math.max(0, st.newest - 300)
    const evs = await api.events(after)
    if (evs.length) {
      const map = new Map<number, EventRow>(store.events.map(e => [e.seq, e] as const))
      for (const e of evs) map.set(e.seq, e)
      store.events = Array.from(map.values()).sort((a, b) => a.seq - b.seq).slice(-1000)
    }
    const tg = await api.targets()
    store.targets = tg
    store.error = ''
    loadLabels(store.events.map(e => e.pkg))
  } catch (e: unknown) {
    store.error = e instanceof Error ? e.message : String(e)
  } finally {
    refreshing = false
  }
}

export function startLoop(ms = 2500): void {
  if (polling) return
  polling = true
  refresh()
  if (previewMode) return
  window.setInterval(() => {
    if (polling && !document.hidden && !refreshing) refresh()
  }, ms)
}
