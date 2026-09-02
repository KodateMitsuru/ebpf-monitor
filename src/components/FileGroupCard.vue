<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { computed, ref } from 'vue'
import { MiuixCard, MiuixBasicComponent, MiuixText, MiuixIcon, MiuixDivider } from 'miuix-vue'
import { ExpandMore, Ok, Close } from 'miuix-vue/icons'
import { Motion, AnimatePresence } from 'motion-v'
import { classifyEvent, type EventRow } from '@/lib/ksu'
import { avatarUrl, resolveDisplayName } from '@/lib/labels'

const props = defineProps<{ file: string; events: EventRow[] }>()
const expanded = ref(false)
const toggle = () => { expanded.value = !expanded.value }

const main = computed(() => props.events[props.events.length - 1] || props.events[0])
const cls = computed(() => main.value ? classifyEvent(main.value) : { c: 'open', txt: '?' })
const isApp = computed(() => !!main.value && main.value.pkg !== '-' && main.value.pkg !== '')
const iconUrl = computed(() => isApp.value ? `ksu://icon/${main.value!.pkg}` : null)
const iconFailed = ref(false)
const iconSrc = computed(() => iconUrl.value && !iconFailed.value ? iconUrl.value! : avatarUrl(main.value?.pkg || main.value?.comm || ''))
const OP_COLOR: Record<string, string> = {
  create: 'var(--m-color-primary)',
  open: 'var(--m-color-on-surface-variant)',
  rename: 'var(--m-color-secondary)',
  mkdir: 'var(--m-color-on-surface-variant)',
  delete: 'var(--m-color-error)',
  fail: 'var(--m-color-error)'
}
const opColor = computed(() => OP_COLOR[cls.value.c] || 'var(--m-color-on-surface)')
const countTxt = computed(() => `${props.events.length} 次 · ${lifecycleSummary.value}`)
const lifecycleSummary = computed(() => {
  const m = new Map<string, number>()
  for (const e of props.events) { const k = classifyEvent(e).txt; m.set(k, (m.get(k)||0)+1) }
  return Array.from(m.entries()).map(([k,v]) => `${k}${v>1?`×${v}`:''}`).join(' → ')
})
const fileId = computed(() => (main.value as unknown as { file_id?: number })?.file_id || 0)
const ino = computed(() => (main.value as unknown as { ino?: number })?.ino || 0)
</script>

<template>
  <MiuixCard class="fg-card" press-feedback="none" @click="toggle">
    <MiuixBasicComponent
      :title="main ? resolveDisplayName(main) + ' · ' + cls.txt : file"
      :title-color="opColor"
      :summary="file">
      <template #start>
        <img class="fg-icon" :src="iconSrc" alt="" @error="iconFailed = true" />
      </template>
      <template #end>
        <span class="fg-end">
          <MiuixText type="footnote2" color="var(--m-color-on-surface-variant)">{{ countTxt }}</MiuixText>
          <MiuixIcon :icon="ExpandMore" :size="20" :style="{ transform: expanded ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform .2s' }" />
        </span>
      </template>
    </MiuixBasicComponent>
    <MiuixText type="footnote2" class="fg-meta" color="var(--m-color-on-surface-variant-summary)">
      {{ main?.ts || '' }} · {{ lifecycleSummary }} · ino {{ ino || fileId || '-' }}
    </MiuixText>

    <AnimatePresence :initial="false">
      <Motion v-if="expanded"
        :initial="{ height: 0, opacity: 0 }"
        :animate="{ height: 'auto', opacity: 1 }"
        :exit="{ height: 0, opacity: 0 }"
        :transition="{ duration: 0.22 }">
        <div class="fg-body">
          <MiuixDivider />
          <div v-for="(e,i) in events" :key="e.seq" class="fg-row">
            <div class="fg-timeline">
              <span class="fg-dot" :style="{ background: e.ret<0 ? 'var(--m-color-error)' : classifyEvent(e).c==='rename' ? 'var(--m-color-secondary)' : 'var(--m-color-primary)' }"></span>
              <span v-if="i < events.length - 1" class="fg-line"></span>
            </div>
            <div class="fg-content">
              <span class="fg-row-head">
                <MiuixIcon :icon="e.ret < 0 ? Close : Ok" :size="14" :color="e.ret < 0 ? 'var(--m-color-error)' : 'var(--m-color-primary)'" />
                <MiuixText type="footnote2" :color="classifyEvent(e).c==='rename' ? 'var(--m-color-secondary)' : 'var(--m-color-on-surface-variant)'">
                  {{ classifyEvent(e).txt }}
                </MiuixText>
                <MiuixText type="footnote2" class="mono fg-path">
                  <span v-if="e.op==='rename' && e.old_file">{{ e.old_file }} -&gt; {{ e.file }}</span>
                  <span v-else>{{ e.file }}</span>
                </MiuixText>
              </span>
              <MiuixText type="footnote2" color="var(--m-color-on-surface-variant-summary)">{{ e.ts }} · {{ e.comm }} · pid {{ e.pid }} · uid {{ e.uid }} · {{ e.pkg }}</MiuixText>
              <MiuixText v-if="e.cmd" type="footnote2" class="mono" color="var(--m-color-on-surface-variant-summary)">$ {{ e.cmd }}</MiuixText>
              <MiuixText type="footnote2" color="var(--m-color-on-surface-variant-summary)">seq {{ e.seq }} · ret {{ e.ret }} · flags 0x{{ e.flags.toString(16) }}</MiuixText>
            </div>
          </div>
        </div>
      </Motion>
    </AnimatePresence>
  </MiuixCard>
</template>

<style lang="scss" scoped>
.fg-card { margin: 0 12px 12px; cursor: pointer; }
.fg-icon { width: 40px; height: 40px; border-radius: var(--m-radius-md,10px); object-fit: cover; }
.fg-end { display: inline-flex; align-items: center; gap: 8px; }
.fg-meta { display: block; margin: 0 16px 8px; }
.fg-body { padding: 4px 16px 8px; display: flex; flex-direction: column; gap: 8px; }
.fg-row { display: flex; gap: 10px; padding: 6px 8px; border-radius: 10px; background: var(--m-color-surface-variant); }
.fg-timeline { display: flex; flex-direction: column; align-items: center; width: 12px; flex: none; padding-top: 4px; }
.fg-dot { width: 8px; height: 8px; border-radius: 50%; }
.fg-line { width: 2px; flex: 1; margin-top: 4px; background: var(--m-color-outline-variant); min-height: 24px; }
.fg-content { flex: 1; display: flex; flex-direction: column; gap: 2px; min-width: 0; }
.fg-row-head { display: inline-flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.fg-path { word-break: break-all; }
.mono { font-family: ui-monospace, monospace; }
</style>
