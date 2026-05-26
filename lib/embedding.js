import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { request as httpRequest } from 'node:http';
import { spawn } from 'node:child_process';

import {
  EMBEDDING_SERVER_PORT, EMBEDDING_TIMEOUT_MS, EMBEDDING_SERVER_CHECK_INTERVAL_MS,
  EMBEDDING_HEALTH_POLL_MS, FALLBACK_HIGH_SCORE, DEFAULT_SCORE,
  L1_HIGH_CONFIDENCE_THRESHOLD, L1_HIGH_SCORE_OFFSET,
  L3_IMMEDIATE_RISK_RATIO, SEMANTIC_RISK_LOCK_THRESHOLD,
} from './constants.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

let embeddingRefs = null;
let embeddingServer = null;
let EMBEDDING_SERVER_READY = false;
let L3_IMMEDIATE_LOCK = null;
let LAST_EMBEDDING_SERVER_CHECK = 0;
let SHIELD_AUTH_TOKEN = process.env.SHIELD_AUTH_TOKEN || '';

export const FALLBACK_DANGEROUS = [
  { re: /^rm -rf \/$/i, reason: 'root_delete' },
  { re: /^rm -rf \/\s*--no-preserve-root/i, reason: 'root_delete' },
  { re: /bash -i\s*[&>].*\/dev\/tcp\//i, reason: 'reverse_shell' },
  { re: /nc\s+-[le]\s+\d+\s+-e\s+/i, reason: 'reverse_shell' },
  { re: /mkfs\.\w+\s+\/dev\//i, reason: 'disk_destroy' },
  { re: /dd\s+if=\/dev\/\w+\s+of=\/dev\//i, reason: 'disk_destroy' },
];

export function cosine(a, b) {
  let dot = 0, na = 0, nb = 0;
  for (let i = 0; i < a.length; i++) { dot += a[i] * b[i]; na += a[i] * a[i]; nb += b[i] * b[i]; }
  return dot / (Math.sqrt(na) * Math.sqrt(nb) + 1e-10);
}

function getAuthHeaders() {
  if (!SHIELD_AUTH_TOKEN) return {};
  return { 'Authorization': 'Bearer ' + SHIELD_AUTH_TOKEN };
}

export function queryEmbeddingServer(text, timeoutMs = EMBEDDING_TIMEOUT_MS) {
  return new Promise(function (resolve) {
    try {
      const body = JSON.stringify({ texts: [text] });
      const headers = {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        ...getAuthHeaders(),
      };
      const options = {
        hostname: 'localhost', port: EMBEDDING_SERVER_PORT, path: '/score', method: 'POST', headers,
      };
      let settled = false;
      const req = httpRequest(options, function (res) {
        let data = '';
        res.on('data', function (c) { data += c; });
        res.on('end', function () {
          if (settled) return; settled = true;
          try { const j = JSON.parse(data); if (j.results && j.results[0]) resolve(j.results[0]); else resolve(null); }
          catch (e) { resolve(null); }
        });
      });
      const settle = function () { if (settled) return; settled = true; req.destroy(); resolve(null); };
      req.on('error', settle);
      req.setTimeout(timeoutMs, settle);
      req.write(body);
      req.end();
    } catch (e) { resolve(null); }
  });
}

export function checkEmbeddingServer(cb) {
  if (Date.now() - LAST_EMBEDDING_SERVER_CHECK > EMBEDDING_SERVER_CHECK_INTERVAL_MS) {
    LAST_EMBEDDING_SERVER_CHECK = Date.now();
    let settled = false;
    const req = httpRequest({ hostname: 'localhost', port: EMBEDDING_SERVER_PORT, path: '/health', method: 'GET', headers: getAuthHeaders() }, function (res) {
      let d = '';
      res.on('data', function (c) { d += c; });
      res.on('end', function () {
        if (settled) return; settled = true;
        try { const j = JSON.parse(d); EMBEDDING_SERVER_READY = j.status === 'ok'; }
        catch (e) { EMBEDDING_SERVER_READY = false; }
        cb(EMBEDDING_SERVER_READY);
      });
    });
    const settle = function () { if (settled) return; settled = true; req.destroy(); EMBEDDING_SERVER_READY = false; cb(false); };
    req.on('error', settle);
    req.setTimeout(2000, settle);
    req.end();
  } else {
    process.nextTick(function () { cb(EMBEDDING_SERVER_READY); });
  }
}

export function startEmbeddingServer() {
  const scriptPath = resolve(__dirname, '..', 'scripts', 'embedding_server.py');
  if (!existsSync(scriptPath)) return;
  try {
    const args = [scriptPath, '--port', String(EMBEDDING_SERVER_PORT)];
    if (SHIELD_AUTH_TOKEN) {
      args.push('--auth-token', SHIELD_AUTH_TOKEN);
    }
    const env = { ...process.env, TF_CPP_MIN_LOG_LEVEL: '3' };
    embeddingServer = spawn('python', args, { stdio: 'ignore', detached: true, env });
    embeddingServer.unref();
    console.error('[L1] Embedding server starting on :' + EMBEDDING_SERVER_PORT);
    embeddingServer.on('exit', function () { embeddingServer = null; EMBEDDING_SERVER_READY = false; });
    (function poll() {
      const req = httpRequest({ hostname: 'localhost', port: EMBEDDING_SERVER_PORT, path: '/health', method: 'GET', headers: getAuthHeaders() }, function (res) {
        let d = '';
        res.on('data', function (c) { d += c; });
        res.on('end', function () {
          try { const j = JSON.parse(d); if (j.status === 'ok') { EMBEDDING_SERVER_READY = true; console.error('[L1] Embedding server ready'); return; } } catch (e) { /* not ready yet */ }
          setTimeout(poll, EMBEDDING_HEALTH_POLL_MS);
        });
      });
      req.on('error', function () { setTimeout(poll, EMBEDDING_HEALTH_POLL_MS); });
      req.setTimeout(5000, function () { req.destroy(); setTimeout(poll, EMBEDDING_HEALTH_POLL_MS); });
      req.end();
    })();
  } catch (e) { console.error('[L1] Start failed:', e.message); }
}

export function loadEmbeddingRefs() {
  try {
    const refsPath = resolve(__dirname, '..', 'data', 'embedding_refs.json');
    if (existsSync(refsPath)) {
      embeddingRefs = JSON.parse(readFileSync(refsPath, 'utf-8'));
      const th = embeddingRefs.benchmark?.lr_threshold
        || embeddingRefs.benchmark?.classifier_threshold
        || embeddingRefs.benchmark?.optimal_threshold
        || SEMANTIC_RISK_LOCK_THRESHOLD;
      EMBEDDING_THRESHOLD = th;
      L3_IMMEDIATE_LOCK = th;
      console.error('[L1] Embedding refs: ' + embeddingRefs.harmful?.count + ' harmful, ' + embeddingRefs.safe?.count + ' safe, threshold=' + th);
      return true;
    }
  } catch (e) { console.error('[L1] Load failed:', e.message); }
  return false;
}

export function embeddingScore(emb) {
  if (!embeddingRefs || !emb) return DEFAULT_SCORE;
  let maxH = -1, maxS = -1;
  for (let i = 0; i < embeddingRefs.harmful.embeddings.length; i++) { const sim = cosine(emb, embeddingRefs.harmful.embeddings[i]); if (sim > maxH) maxH = sim; }
  for (let i = 0; i < embeddingRefs.safe.embeddings.length; i++) { const sim = cosine(emb, embeddingRefs.safe.embeddings[i]); if (sim > maxS) maxS = sim; }
  const h = (maxH + 1) / 2, s = (maxS + 1) / 2;
  if (h + s < 0.01) return DEFAULT_SCORE;
  return h / (h + s);
}

export let EMBEDDING_THRESHOLD = SEMANTIC_RISK_LOCK_THRESHOLD;
export function setEmbeddingThreshold(v) { EMBEDDING_THRESHOLD = v; }

export function fallbackScore(text) {
  if (!text) return DEFAULT_SCORE;
  const t = String(text);
  for (let i = 0; i < FALLBACK_DANGEROUS.length; i++) {
    if (FALLBACK_DANGEROUS[i].re.test(t)) return FALLBACK_HIGH_SCORE;
  }
  return DEFAULT_SCORE;
}

// Embedding server init at import time
export const embeddingRefsLoaded = loadEmbeddingRefs();

if (embeddingRefs) {
  checkEmbeddingServer(function (ready) {
    if (!ready && process.env.DISABLE_EMBEDDING_SERVER !== '1') {
      startEmbeddingServer();
    }
  });
}

export function getEmbeddingRefs() { return embeddingRefs; }
export function getEmbeddingServerReady() { return EMBEDDING_SERVER_READY; }
export function setEmbeddingServerReady(v) { EMBEDDING_SERVER_READY = !!v; }
export function getL3ImmediateLock() { return L3_IMMEDIATE_LOCK; }
export function setL3ImmediateLock(v) { L3_IMMEDIATE_LOCK = v; }
export function getEmbeddingServer() { return embeddingServer; }
export function setAuthToken(token) { SHIELD_AUTH_TOKEN = token; }
