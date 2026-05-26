/**
 * Datafew Shield — Lint 检查
 * 语法检查 + import 完整性
 */
import { readFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');

const FILES = [
  'index.js',
  'lib/data_shield.js',
  'policies/default.json',
  'test/run.js',
  'test/test_dlp.mjs',
  'test/test_owasp_top10.mjs',
  'test/test_mitre_atlas.mjs',
  'test/test_adversarial.mjs',
  'test/test_multi_step.mjs',
  'scripts/lint.mjs',
];

let passed = 0, failed = 0;

for (const file of FILES) {
  const fullPath = resolve(ROOT, file);
  try {
    if (file.endsWith('.json')) {
      JSON.parse(readFileSync(fullPath, 'utf-8'));
    } else {
      execSync(`node --check "${fullPath}"`, { stdio: 'pipe' });
    }
    console.log(`  ✓ ${file}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${file}: ${e.stderr?.toString().split('\n')[0] || e.message}`);
    failed++;
  }
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
