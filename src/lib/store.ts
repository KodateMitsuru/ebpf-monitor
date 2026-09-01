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

export async function refresh(): Promise<void> {
  try {
    const [st, evs, tg] = await Promise.all([api.status(), api.events(), api.targets()])
    store.status = st
    store.events = evs
    store.targets = tg
    store.error = ''
    loadLabels(evs.map(e => e.pkg))
  } catch (e: unknown) {
    store.error = e instanceof Error ? e.message : String(e)
  }
}

export function startLoop(ms = 2500): void {
  if (polling) return
  polling = true
  refresh()
  if (previewMode) return
  window.setInterval(() => {
    if (polling && !document.hidden) refresh()
  }, ms)
}
