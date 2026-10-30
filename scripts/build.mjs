import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const root = fileURLToPath(new URL('../', import.meta.url));
const version = process.argv[2];
if (!/^v\d+\.\d+\.\d+$/.test(version ?? '')) throw new Error('Usage: node scripts/build.mjs vX.Y.Z');
const go = process.env.GO_BINARY || 'go';
const run = (args, env = {}) => {
  const result = spawnSync(go, args, { cwd: root, env: { ...process.env, GOTOOLCHAIN: 'local', ...env }, encoding: 'utf8' });
  if (result.error || result.status !== 0) throw new Error(`Go command failed: ${result.error?.message || result.stderr}`);
  return result.stdout.trim();
};
const expectedGo = readFileSync(join(root, 'go.mod'), 'utf8').match(/^go (.+)$/m)[1];
if (!run(['version']).includes(`go${expectedGo} `)) throw new Error(`Build with Go ${expectedGo} to reproduce release checksums`);
mkdirSync(join(root, 'dist'), { recursive: true });
const assets = {};
for (const arch of ['amd64', 'arm64']) {
  const name = `tower-agent-linux-${arch}`;
  run(['build', '-trimpath', '-buildvcs=false', '-ldflags', `-s -w -X main.version=${version}`, '-o', join(root, 'dist', name), '.'], {
    CGO_ENABLED: '0', GOOS: 'linux', GOARCH: arch, GOAMD64: 'v1', GOARM64: 'v8.0', GOEXPERIMENT: '', GOFLAGS: '',
  });
  const data = readFileSync(join(root, 'dist', name));
  assets[arch] = { name, size: data.length, sha256: createHash('sha256').update(data).digest('hex') };
}
const installer = readFileSync(join(root, 'scripts/install.sh.in'), 'utf8')
  .replaceAll('__VERSION__', version).replaceAll('__AMD64_SHA256__', assets.amd64.sha256).replaceAll('__ARM64_SHA256__', assets.arm64.sha256);
writeFileSync(join(root, 'dist/install.sh'), installer, { mode: 0o755 });
writeFileSync(join(root, 'dist/manifest.json'), JSON.stringify({ version, protocol: 4, assets }, null, 2) + '\n');
const files = [...Object.values(assets).map(a => a.name), 'install.sh', 'manifest.json'];
writeFileSync(join(root, 'dist/checksums.txt'), files.map(name => `${createHash('sha256').update(readFileSync(join(root, 'dist', name))).digest('hex')}  ${name}\n`).join(''));
console.log(`Built ${version}: ${files.join(', ')}`);
