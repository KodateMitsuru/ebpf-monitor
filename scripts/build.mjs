// SPDX-License-Identifier: GPL-3.0-or-later
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createWriteStream, existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import yazl from 'yazl';

const root = fileURLToPath(new URL('..', import.meta.url));
const rs = join(root, 'src-rs');
const node = (f) => execFileSync(process.execPath, [join(root, 'scripts', f)], { cwd: root, stdio: 'inherit' });

node('daemon.mjs');
console.log('==> frontend: pnpm run build:web (typecheck + vite -> dist/webroot)');
execFileSync('pnpm', ['run', 'build:web'], { cwd: root, stdio: 'inherit' });
const bin = join(rs, 'target/aarch64-linux-android/release/ebpf-monitor');
const ctlBin = join(rs, 'target/aarch64-linux-android/release/ebpf-monitor-ctl');
const tpl = join(root, 'template');
const webroot = join(root, 'dist/webroot');
if (!existsSync(join(webroot, 'index.html'))) {
  console.error('dist/webroot missing (frontend build did not run?)');
  process.exit(1);
}

const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const [maj, min, pat] = pkg.version.split('.').map(Number);
const versionCode = maj * 10000 + min * 100 + pat;
const rendered = readFileSync(join(tpl, 'module.prop'), 'utf8')
  .replaceAll('${VERSION}', pkg.version)
  .replaceAll('${VERSION_CODE}', String(versionCode));

const DATA = 0o644, EXEC = 0o755;
const z = new yazl.ZipFile();
z.addBuffer(Buffer.from(rendered, 'utf8'), 'module.prop', { mode: DATA });
for (const [name, mode] of [
  ['sepolicy.rule', DATA],
  ['customize.sh', EXEC], ['service.sh', EXEC], ['uninstall.sh', EXEC], ['action.sh', EXEC],
]) {
  z.addFile(join(tpl, name), name, { mode });
}
z.addFile(bin, 'ebpf-monitor', { mode: EXEC });
if (existsSync(ctlBin)) z.addFile(ctlBin, 'ebpf-monitor-ctl', { mode: EXEC });

(function walk(dir, prefix) {
  z.addEmptyDirectory(prefix, { mode: EXEC });
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) walk(p, `${prefix}/${e}`);
    else z.addFile(p, `${prefix}/${e}`, { mode: DATA });
  }
})(webroot, 'webroot');

const out = join(root, 'dist');
z.outputStream.pipe(createWriteStream(join(out, 'ebpf-monitor.zip')));
z.end();
await new Promise((r) => z.outputStream.on('close', r));

const buf = readFileSync(join(out, 'ebpf-monitor.zip'));
console.log(`==> 模块包: dist/ebpf-monitor.zip (${buf.length} 字节, sha256 ${createHash('sha256').update(buf).digest('hex').slice(0, 16)}…)`);
