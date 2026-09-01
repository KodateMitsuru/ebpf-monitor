<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<script setup lang="ts">
import { computed, ref } from 'vue'
import { MiuixCard, MiuixBasicComponent, MiuixText, MiuixIcon } from 'miuix-vue'
import { Ok, Close } from 'miuix-vue/icons'
import { classify, type EventRow } from '@/lib/ksu'
import { avatarFor, displayName } from '@/lib/labels'

const props = defineProps<{ ev: EventRow }>()

const cls = computed(() => classify(props.ev))
const isApp = computed(() => props.ev.pkg !== '-' && props.ev.pkg !== '')

const OP_COLOR: Record<string, string> = {
  create: 'var(--m-color-primary)',
  open:   'var(--m-color-on-surface-variant)',
  rename: 'var(--m-color-secondary)',
  mkdir:  'var(--m-color-on-surface-variant)',
  delete: 'var(--m-color-error)',
  fail:   'var(--m-color-error)'
}
const opColor = computed(() => OP_COLOR[cls.value.c] || 'var(--m-color-on-surface)')
const retColor = computed(() => props.ev.ret < 0 ? 'var(--m-color-error)' : 'var(--m-color-primary)')

const iconUrl = computed(() => (isApp.value ? `ksu://icon/${props.ev.pkg}` : null))
const iconFailed = ref(false)
const iconSrc = computed(() => iconUrl.value && !iconFailed.value ? iconUrl.value! : avatarFor(props.ev.pkg || props.ev.comm))
</script>

<template>
  <MiuixCard class="ev-card" press-feedback="none">
    <MiuixBasicComponent
      :title="displayName(ev) + ' · ' + cls.txt"
      :title-color="opColor"
      :summary="ev.ts + ' · pid ' + ev.pid + ' · uid ' + ev.uid">
      <template #start>
        <img class="ev-icon" :src="iconSrc" alt="" @error="iconFailed = true">
      </template>
      <template #end>
        <span class="ev-ret">
          <MiuixIcon :icon="ev.ret < 0 ? Close : Ok" :size="16" :color="retColor" />
          <MiuixText type="footnote2" :color="retColor">{{ ev.ret < 0 ? -ev.ret : ev.ret }}</MiuixText>
        </span>
      </template>
    </MiuixBasicComponent>
    <MiuixText v-if="ev.file" type="footnote2" class="ev-line mono"
               color="var(--m-color-on-surface-variant)" :title="ev.file">{{ ev.file }}</MiuixText>
    <MiuixText v-if="ev.cmd" type="footnote2" class="ev-line mono"
               color="var(--m-color-on-surface-variant-summary)" :title="ev.cmd">$ {{ ev.cmd }}</MiuixText>
  </MiuixCard>
</template>

<style lang="scss" scoped>
.ev-card { margin: 0 12px 12px; }
.ev-icon { width: 40px; height: 40px; border-radius: var(--m-radius-md, 10px); object-fit: cover; }
.ev-ret { display: inline-flex; align-items: center; gap: 4px; }
.ev-line { display: block; margin: 0 16px 6px; word-break: break-all; }
</style>
