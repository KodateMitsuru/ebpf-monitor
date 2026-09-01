<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { computed, ref } from 'vue'
import { Motion } from 'motion-v'
import { MiuixProgressIndicator } from 'miuix-vue'

const props = defineProps<{ onRefresh: () => Promise<unknown> }>()

const TRIGGER = 72
const MAX = 120

const scroller = ref<HTMLElement | null>(null)
const pull = ref(0)
const pulling = ref(false)
const busy = ref(false)
let startY = 0
let active = false

function onStart(e: TouchEvent): void {
  const el = scroller.value
  if (!el || el.scrollTop > 0 || busy.value) { active = false; return }
  startY = e.touches[0].clientY
  active = true
}

function onMove(e: TouchEvent): void {
  if (!active) return
  const dy = e.touches[0].clientY - startY
  if (dy <= 0) {
    pull.value = 0
    return
  }
  pulling.value = true
  pull.value = Math.min(MAX, dy * 0.45)
  if (e.cancelable) e.preventDefault()
}

async function onEnd(): Promise<void> {
  if (!active) return
  active = false
  pulling.value = false
  if (pull.value >= TRIGGER && !busy.value) {
    busy.value = true
    pull.value = TRIGGER
    try { await props.onRefresh() } catch { /* swallow refresh errors */ } finally { busy.value = false }
  }
  pull.value = 0
}

const boxAnimate = computed(() => ({
  height: pull.value + 'px',
  opacity: pull.value > 6 || busy.value ? 1 : 0
}))
const boxTransition = computed(() =>
  pulling.value ? { duration: 0 } : { type: 'spring' as const, stiffness: 560, damping: 42 })
</script>

<template>
  <div class="ptr">
    <div ref="scroller" class="ptr__scroll"
         @touchstart="onStart" @touchmove="onMove" @touchend="onEnd" @touchcancel="onEnd">
      <Motion class="ptr__box" :animate="boxAnimate" :transition="boxTransition">
        <MiuixProgressIndicator v-if="busy || pull > 10" type="infinite" :size="20" />
      </Motion>
      <slot />
    </div>
  </div>
</template>

<style lang="scss" scoped>
.ptr {
  flex: 1;
  min-height: 0;
  display: flex;
  flex-direction: column;
}
.ptr__scroll {
  flex: 1;
  overflow-y: auto;
  overscroll-behavior: contain;
  padding-bottom: 12px;
}
.ptr__box {
  display: flex;
  align-items: center;
  justify-content: center;
  overflow: hidden;
}
</style>
