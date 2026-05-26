/**
 * Download AI safety benchmarks via Puppeteer (bypasses firewall).
 * Uses browser's network stack which has access to HuggingFace.
 */
import puppeteer from 'puppeteer';
import { writeFileSync, existsSync, mkdirSync } from 'node:fs';

var SAVE_DIR = 'D:\\ProgramData\\No-Human\\datafew-shield\\data\\external';
mkdirSync(SAVE_DIR, { recursive: true });

var browser = await puppeteer.launch({ headless: true, args: ['--no-sandbox'] });
var page = await browser.newPage();

async function fetch(url) {
  return await page.evaluate(async function(u) {
    var r = await fetch(u, { signal: AbortSignal.timeout(60000) });
    if (r.ok) return await r.text();
    if (r.status === 401) return 'AUTH_REQUIRED';
    return 'HTTP_' + r.status;
  }, url);
}

async function download(name, urls) {
  for (var url of urls) {
    var fname = name + '.' + url.split('.').pop();
    var fpath = SAVE_DIR + '\\' + fname;
    if (existsSync(fpath)) { console.log('  ✓ ' + fname + ' (cached)'); continue; }

    var data = await fetch(url);
    if (data === 'AUTH_REQUIRED') {
      console.log('  ~ ' + fname + ': auth required, trying alternative...');
      continue;
    }
    if (data.startsWith('HTTP_')) {
      console.log('  ✗ ' + fname + ': ' + data);
      continue;
    }
    writeFileSync(fpath, data, 'utf-8');
    var lines = data.trim().split('\n').length;
    var size = (data.length / 1024).toFixed(0);
    console.log('  ✓ ' + fname + ': ' + lines + ' lines, ' + size + ' KB');
    return; // success on first URL
  }
}

console.log('\n=== Downloading safety benchmarks ===\n');

// BAAI SafetyBench (Chinese safety)
await download('safetybench_cn', [
  'https://huggingface.co/datasets/BAAI/SafetyBench/raw/main/data/chinese_test.json',
  'https://huggingface.co/datasets/BAAI/SafetyBench/resolve/main/data/chinese_test.json',
]);

// BAAI SafetyBench (English)
await download('safetybench_en', [
  'https://huggingface.co/datasets/BAAI/SafetyBench/raw/main/data/english_test.json',
]);

// CValues (Chinese values alignment) - try multiple paths
await download('cvalues_harm', [
  'https://huggingface.co/datasets/BAAI/CValues/raw/main/data/harm_test.json',
  'https://huggingface.co/datasets/BAAI/CValues/resolve/main/data/harm_test.json',
]);
await download('cvalues_responsibility', [
  'https://huggingface.co/datasets/BAAI/CValues/raw/main/data/responsibility_test.json',
]);

// Do-Not-Answer
await download('donotanswer', [
  'https://raw.githubusercontent.com/wendlerc/Do-Not-Answer/main/data/test_cases.json',
  'https://huggingface.co/datasets/heegyu/Do-Not-Answer/raw/main/data/test.json',
]);

// PKU-SafeRLHF (already downloaded, but get more splits)
await download('pku_saferlhf_helpful', [
  'https://huggingface.co/datasets/PKU-Alignment/PKU-SafeRLHF/resolve/main/data/Helpful/test.jsonl',
]);

// HEx-PHI (harmful behaviors from AdvBench)
await download('hex_phi_harmful', [
  'https://raw.githubusercontent.com/llm-attacks/llm-attacks/main/data/advbench/harmful_behaviors.csv',
]);

// Anthropic red team dataset (sample)
await download('anthropic_redteam', [
  'https://huggingface.co/datasets/Anthropic/hh-rlhf/raw/main/red-team-attempts/test.jsonl',
]);

// ToxicChat
await download('toxicchat', [
  'https://huggingface.co/datasets/lmsys/toxic-chat/raw/main/data/train.jsonl',
]);

// Deepset prompt injection
await download('deepset_prompt_injection', [
  'https://huggingface.co/datasets/deepset/prompt-injection/raw/main/data/test.jsonl',
  'https://huggingface.co/datasets/deepset/prompt-injection/resolve/main/data/test.json',
]);

// WalledAI AttackBench
await download('attackbench', [
  'https://huggingface.co/datasets/walledai/AttackBench/raw/main/data/test.json',
]);

await browser.close();
console.log('\nDone. Check data/external/ for downloaded files.');
