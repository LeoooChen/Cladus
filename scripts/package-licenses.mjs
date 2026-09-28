// Collect the exact locked dependencies' notices, including build dependencies.
// Run after npm ci. Missing license texts fail packaging instead of being omitted.
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const gui = join(root, 'apps/cladus-gui');
const output = join(root, 'target/installer-dependencies/DEPENDENCY_LICENSES.txt');
const metadata = JSON.parse(execFileSync('cargo', [
  'metadata', '--locked', '--format-version', '1', '--filter-platform', 'x86_64-pc-windows-msvc',
], { cwd: root, encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 }));
const sections = ['Cladus dependency licenses\nGenerated from Cargo.lock and package-lock.json.\nIncludes build tools; some listed code may not be present in the final binary.'];

function texts(dir) {
  return readdirSync(dir, { withFileTypes: true })
    .filter(e => /^(licen[cs]e|copying|notice)([._-]|$)/i.test(e.name))
    .sort((a, b) => a.name.localeCompare(b.name))
    .flatMap(e => e.isFile() ? [readFileSync(join(dir, e.name), 'utf8')] :
      e.isDirectory() ? readdirSync(join(dir, e.name), { withFileTypes: true })
        .filter(f => f.isFile()).map(f => readFileSync(join(dir, e.name, f.name), 'utf8')) : []);
}

function add(name, license, source, contents) {
  if (!contents.length) throw new Error(`No license text for ${name}`);
  sections.push(`${'='.repeat(78)}\n${name}\nLicense: ${license}\nSource: ${source}\n\n${contents.join('\n\n')}`);
}

// These crates omit their repository-root license from the published archive.
// Provenance and pinned versions are recorded in installer/licenses/README.md.
const supplemental = {
  'alloc-stdlib@0.3.0': 'alloc-stdlib.txt',
  'defmt-parser@1.0.0': 'defmt-parser.txt',
  'selectors@0.38.0': 'selectors.txt',
  'tauri-plugin@2.7.0': 'tauri-plugin.txt',
  'webview2-com@0.39.1': 'webview2-rs.txt',
  'webview2-com-macros@0.8.1': 'webview2-rs.txt',
  'webview2-com-sys@0.39.1': 'webview2-rs.txt',
};
for (const p of metadata.packages.filter(p => p.source).sort((a, b) => `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`))) {
  const dir = dirname(p.manifest_path);
  const contents = texts(dir);
  if (p.license_file && !contents.length) contents.push(readFileSync(resolve(dir, p.license_file), 'utf8'));
  if (!contents.length && supplemental[`${p.name}@${p.version}`]) {
    contents.push(readFileSync(join(root, 'installer/licenses', supplemental[`${p.name}@${p.version}`]), 'utf8'));
  }
  add(`Rust: ${p.name} ${p.version}`, p.license, `https://crates.io/crates/${p.name}/${p.version} (${p.repository || p.source})`, contents);
}

const lock = JSON.parse(readFileSync(join(gui, 'package-lock.json'), 'utf8'));
for (const [path, entry] of Object.entries(lock.packages).sort(([a], [b]) => a.localeCompare(b))) {
  if (!path) continue;
  const dir = join(gui, path);
  // Platform-specific optional packages may not be installed on Windows.
  if (!existsSync(dir)) {
    if (entry.optional) continue;
    throw new Error(`Missing npm dependency: ${path}; run npm ci`);
  }
  const p = JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8'));
  const contents = texts(dir);
  const parent = p.name.startsWith('@esbuild/') ? 'esbuild' :
    p.name.startsWith('@rollup/rollup-') ? 'rollup' : null;
  if (!contents.length && parent) {
    const parentDir = join(gui, 'node_modules', parent);
    const parentPackage = JSON.parse(readFileSync(join(parentDir, 'package.json'), 'utf8'));
    if (parentPackage.version !== p.version) throw new Error(`License version mismatch for ${p.name}`);
    contents.push(...texts(parentDir));
  }
  add(`npm: ${p.name} ${p.version}`, p.license || entry.license,
    entry.resolved || p.homepage || '', contents);
}
mkdirSync(dirname(output), { recursive: true });
writeFileSync(output, sections.join('\n\n') + '\n');
console.log(`Collected ${sections.length - 1} dependency notices: ${output}`);
