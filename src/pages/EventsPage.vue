<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { computed, ref } from 'vue'
import { MiuixInput, MiuixText } from 'miuix-vue'
import { AnimatePresence, Motion } from 'motion-v'
import EventCard from '@/components/EventCard.vue'
import PullToRefresh from '@/components/PullToRefresh.vue'
import { store, refresh } from '@/lib/store'

const filter = ref('')

const filtered = computed(() => {
  const q = filter.value.trim().toLowerCase()
  if (!q) return store.events
  return store.events.filter(e =>
    e.pkg.toLowerCase().includes(q) || e.comm.toLowerCase().includes(q) ||
    e.file.toLowerCase().includes(q) || e.cmd.toLowerCase().includes(q))
})
const shown = computed(() => filtered.value.slice(-200).slice().reverse())
</script>

<template>
  <div class="page">
    <div class="filter-block">
      <MiuixInput v-model="filter" placeholder="按应用/路径/进程/命令行过滤"
                  autocapitalize="off" spellcheck="false" />
    </div>

    <PullToRefresh :on-refresh="refresh">
      <MiuixText v-if="store.error" type="footnote2" class="errline">{{ store.error }}</MiuixText>

      <MiuixText v-if="!shown.length" type="footnote1"
                 color="var(--m-color-on-surface-variant-summary)" class="empty">
        （无命中记录 · 下拉刷新）
      </MiuixText>

      <AnimatePresence :initial="false">
        <Motion v-for="e in shown" :key="e.seq"
                :initial="{ opacity: 0, y: -16, scale: 0.98 }"
                :animate="{ opacity: 1, y: 0, scale: 1 }"
                :exit="{ opacity: 0 }"
                :transition="{ type: 'spring', stiffness: 500, damping: 38 }">
          <EventCard :ev="e" />
        </Motion>
      </AnimatePresence>
    </PullToRefresh>
  </div>
</template>

<style lang="scss" scoped>
.page {
  flex: 1;
  min-height: 0;
  display: flex;
  flex-direction: column;
}
.filter-block { flex: none; padding: 0 12px 12px; }
.empty { display: block; padding: 8px 16px; }
.errline { display: block; padding: 0 16px 8px; color: var(--m-color-error); }
</style>
