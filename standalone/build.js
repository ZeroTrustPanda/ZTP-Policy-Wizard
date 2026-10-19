/**
 * Build the standalone executables.
 *   node standalone/build.js            -> all targets
 *   node standalone/build.js linux-x64  -> one target
 * Needs: `npm ci` in the repo root (express) and in standalone/ (bun, esbuild, react, fonts).
 * Needs python3 (re-signs the macOS builds ad-hoc) and zip.
 * Output: standalone/release/ZTP-Wizard-<version>-<target>.zip
 */
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const version = require(path.join(root, 'package.json')).version;
const TARGETS = {
  'windows-x64':  { bun: 'bun-windows-x64',  exe: 'ZTP-Wizard.exe' },
  'macos-arm64':  { bun: 'bun-darwin-arm64', exe: 'ZTP-Wizard' },
  'macos-x64':    { bun: 'bun-darwin-x64',   exe: 'ZTP-Wizard' },
  'linux-x64':    { bun: 'bun-linux-x64',    exe: 'ZTP-Wizard' }
};
const wanted = process.argv.slice(2).length ? process.argv.slice(2) : ['windows-x64', 'macos-arm64', 'macos-x64'];
// The npm "bun" package names its binary bun.exe on every OS
const bunBin = path.join(__dirname, 'node_modules', 'bun', 'bin', 'bun.exe');
if (!fs.existsSync(bunBin)) throw new Error('Bun not found. Run "npm ci" in standalone/ first.');

execFileSync(process.execPath, [path.join(__dirname, 'build-ui.js')], { stdio: 'inherit' });

const outDir = path.join(__dirname, 'release');
fs.mkdirSync(outDir, { recursive: true });
for (const name of wanted) {
  const t = TARGETS[name];
  if (!t) throw new Error(`Unknown target ${name}. Use: ${Object.keys(TARGETS).join(', ')}`);
  const dir = path.join(__dirname, 'build', name);
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  const exe = path.join(dir, t.exe);
  console.log(`[build] ${name} ...`);
  execFileSync(bunBin, ['build', path.join(__dirname, 'main.js'), '--compile', '--minify', `--target=${t.bun}`, '--outfile', exe], { stdio: 'inherit', cwd: root });
  if (name.startsWith('macos')) {
    // Bun's cross-compiled macOS signature doesn't match the final file; Apple Silicon won't run it.
    execFileSync(process.platform === 'win32' ? 'python' : 'python3', [path.join(__dirname, 'adhoc-sign.py'), exe], { stdio: 'inherit' });
  }
  fs.copyFileSync(path.join(__dirname, 'README-standalone.txt'), path.join(dir, 'README.txt'));
  const zip = path.join(outDir, `ZTP-Wizard-${version}-${name}.zip`);
  fs.rmSync(zip, { force: true });
  execFileSync('zip', ['-q', '-9', '-j', zip, exe, path.join(dir, 'README.txt')], { stdio: 'inherit' }); // -j: flat; keeps the exec bit
  console.log(`[build] ${name}: ${(fs.statSync(exe).size / 1048576).toFixed(1)} MB -> ${path.basename(zip)} ${(fs.statSync(zip).size / 1048576).toFixed(1)} MB`);
}
console.log(`[build] done: ${outDir}`);
