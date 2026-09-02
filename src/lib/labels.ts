// SPDX-License-Identifier: GPL-3.0-or-later
import { reactive } from 'vue'
import { getPackagesInfo } from 'kernelsu'
import { previewMode } from '@/lib/ksu'

export const labelStore = reactive(new Map<string, string>())
const requested = new Set<string>()

export function resolveAppLabel(pkg: string): string {
  if (!pkg || pkg === '-') return ''
  return labelStore.get(pkg) || pkg
}

export function preloadLabels(pkgs: string[]): void {
  if (previewMode) return
  const fresh = [...new Set(pkgs)].filter(p => p && p !== '-' && !requested.has(p))
  if (fresh.length === 0) return
  fresh.forEach(p => requested.add(p))
  try {
    for (const info of getPackagesInfo(fresh)) {
      if (info.appLabel) labelStore.set(info.packageName, info.appLabel)
    }
  } catch {
    fresh.forEach(p => requested.delete(p))
  }
}

function hashHue(pkg: string): number {
  let h = 0
  for (let i = 0; i < pkg.length; i++) h = (h * 31 + pkg.charCodeAt(i)) % 360
  return h
}

export function avatarUrl(pkg: string): string {
  const ch = (pkg && pkg[0] ? pkg[0] : '?').toUpperCase()
  const h = hashHue(pkg || '?')
  const svg =
    `<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48">` +
    `<rect width="48" height="48" rx="10" fill="hsl(${h},62%,58%)"/>` +
    `<text x="24" y="32" font-family="sans-serif" font-size="24" font-weight="600" ` +
    `fill="#fff" text-anchor="middle">${ch}</text></svg>`
  return 'data:image/svg+xml;utf8,' + encodeURIComponent(svg)
}

export function resolveDisplayName(e: { pkg: string; comm: string }): string {
  if (e.pkg && e.pkg !== '-') return resolveAppLabel(e.pkg)
  return e.comm || '?'
}

