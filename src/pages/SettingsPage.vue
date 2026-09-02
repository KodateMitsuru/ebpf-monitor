<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { MiuixCard, MiuixBasicComponent, MiuixSmallTitle, MiuixText, MiuixIcon, MiuixArrowPreference } from 'miuix-vue'
import { Close } from 'miuix-vue/icons'
import PullToRefresh from '@/components/PullToRefresh.vue'
import SettingsConfigPage from '@/pages/SettingsConfigPage.vue'
import { store, synchronize } from '@/lib/store'
import { api, previewMode } from '@/lib/ksu'
import { resolveDisplayName } from '@/lib/labels'
import { classifyEvent } from '@/lib/ksu'

const isEditorOpen = ref(false)

async function handleRefresh(): Promise<void> {
  await synchronize()
}

const rankedApps = computed(() => {
  const byPkg: Record<string, number> = {}
  for (const e of store.events) byPkg[resolveDisplayName(e)] = (byPkg[resolveDisplayName(e)] || 0) + 1
  return Object.keys(byPkg).sort((a,b)=>byPkg[b]-byPkg[a]).slice(0,5).map(app=>({ app, count: byPkg[app] }))
})
const operationSummary = computed(() => {
  const byOp: Record<string, number> = {}
  for (const e of store.events) byOp[classifyEvent(e).txt] = (byOp[classifyEvent(e).txt]||0)+1
  return Object.keys(byOp).sort((a,b)=>byOp[b]-byOp[a]).map(o=>o+' '+byOp[o]).join(' · ')
})

async function purgeEvents(): Promise<void> {
  await api.clearEvents()
  synchronize()
}

onMounted(synchronize)
</script>

<template>
  <SettingsConfigPage v-if="isEditorOpen" @back="isEditorOpen=false" />
  <PullToRefresh v-else :on-refresh="handleRefresh">
    <MiuixSmallTitle text="状态" />
    <MiuixCard class="sec-card" press-feedback="none">
      <MiuixBasicComponent
        :title="store.status.running ? '运行中' : '未运行'"
        :title-color="store.status.running ? 'var(--m-color-primary)' : 'var(--m-color-error)'" />
      <MiuixBasicComponent v-if="!previewMode" title="清空记录" clickable @click="purgeEvents">
        <template #end>
          <MiuixIcon :icon="Close" :size="20" color="var(--m-color-error)" />
        </template>
      </MiuixBasicComponent>
    </MiuixCard>

    <MiuixSmallTitle text="配置" />
    <MiuixCard class="sec-card" press-feedback="none">
      <MiuixArrowPreference title="监视规则" @click="isEditorOpen=true" />
    </MiuixCard>

    <MiuixSmallTitle text="统计" />
    <MiuixCard class="sec-card" press-feedback="none">
      <MiuixBasicComponent v-if="!store.events.length" title="暂无数据" :disabled="true" />
      <template v-else>
        <MiuixBasicComponent :title="`总计 ${store.events.length}`">
          <template #end>
            <MiuixText type="body1">{{ store.events.length }}</MiuixText>
          </template>
        </MiuixBasicComponent>
        <MiuixBasicComponent v-for="a in rankedApps" :key="a.app" :title="a.app">
          <template #end>
            <MiuixText type="body1">{{ a.count }}</MiuixText>
          </template>
        </MiuixBasicComponent>
        <MiuixBasicComponent v-if="operationSummary" :title="operationSummary" :disabled="true" />
      </template>
    </MiuixCard>
  </PullToRefresh>
</template>

<style lang="scss" scoped>
.sec-card { margin: 0 12px 12px; }
</style>
