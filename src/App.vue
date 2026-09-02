<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import {
  MiuixNavigationBar, MiuixTopAppBar, MiuixIcon, useTheme,
  type MiuixNavigationItem,
} from 'miuix-vue'
import { ListView, Settings } from 'miuix-vue/icons'
import EventsPage from '@/pages/EventsPage.vue'
import SettingsPage from '@/pages/SettingsPage.vue'
import { synchronize, startPolling } from '@/lib/store'
import { previewMode } from '@/lib/ksu'

const { setThemeMode } = useTheme()
setThemeMode('system')

onMounted(() => {
  synchronize()
  startPolling()
})

const titles = ['事件', '设置']
const navItems: MiuixNavigationItem[] = titles.map(label => ({ label }))
const navIcons = [ListView, Settings]

const navIndex = ref(0)
const activePage = computed(() => (navIndex.value === 0 ? EventsPage : SettingsPage))
</script>

<template>
  <div class="app">
    <MiuixTopAppBar class="app__bar" :title="previewMode ? 'eBPF File Monitor · 预览' : 'eBPF File Monitor'" />

    <main class="app__main">
      <KeepAlive>
        <component :is="activePage" :key="navIndex" />
      </KeepAlive>
    </main>

    <div class="app__bottom">
      <MiuixNavigationBar v-model="navIndex" :items="navItems">
        <template #icon="{ index }">
          <MiuixIcon :icon="navIcons[index]" :size="26" />
        </template>
      </MiuixNavigationBar>
    </div>
  </div>
</template>

<style lang="scss" scoped>
.app {
  display: flex;
  flex-direction: column;
  height: 100dvh;
  min-height: 0;
  background: var(--m-color-surface);

  &__bar { flex: none; }
  &__main { flex: 1; min-height: 0; display: flex; flex-direction: column; }
  &__bottom { flex: none; z-index: 10; }
  &__bottom :deep(.m-navigation-bar) { background: var(--m-color-surface); }
}
</style>
