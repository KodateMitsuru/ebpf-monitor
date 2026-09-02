// SPDX-License-Identifier: GPL-3.0-or-later
import { reactive } from 'vue'
import { api, previewMode, type EventRow, type Status } from '@/lib/ksu'
import { preloadLabels } from '@/lib/labels'

export const store = reactive({
  status: { running: false, kernel: '', btf: false, eventsBytes: 0, newest: 0 } as Status,
  targets: [] as string[],
  events: [] as EventRow[],
  error: ''
})

let isPolling = false
let isSyncing = false

export async function synchronize(): Promise<void> {
  if (isSyncing) return
  isSyncing = true
  try {
    const st = await api.fetchStatus()
    store.status = st
    const after = store.events.length
      ? store.events[store.events.length - 1].seq
      : Math.max(0, st.newest - 300)
    const evs = await api.fetchEvents(after)
    if (evs.length) {
      const map = new Map<number, EventRow>(store.events.map(e => [e.seq, e] as const))
      for (const e of evs) map.set(e.seq, e)
      store.events = Array.from(map.values()).sort((a, b) => a.seq - b.seq).slice(-1000)
    }
    const tg = await api.fetchTargets()
    store.targets = tg
    store.error = ''
    preloadLabels(store.events.map(e => e.pkg))
  } catch (e: unknown) {
    store.error = e instanceof Error ? e.message : String(e)
  } finally {
    isSyncing = false
  }
}

export function startPolling(ms = 2500): void {
  if (isPolling) return
  isPolling = true
  synchronize()
  if (previewMode) return
  window.setInterval(() => {
    if (isPolling && !document.hidden && !isSyncing) synchronize()
  }, ms)
}

