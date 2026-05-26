import { request as httpRequest } from 'node:http';
import {
  MAX_FEEDBACK_TEXT_LENGTH, MAX_FEEDBACK_RATE_PER_MIN, MAX_FEEDBACK_LOG_SIZE,
  EMBEDDING_SERVER_PORT,
} from './constants.js';
import { getEmbeddingServerReady } from './embedding.js';

export const FEEDBACK_LOG = [];
export let LEARN_COUNT = 0;
export const VALID_OUTCOMES = new Set(['false_positive', 'false_negative', 'correct']);
export const feedbackRateCounts = new Map();

export function recordFeedback(auditId, actualOutcome, text) {
  const outcome = VALID_OUTCOMES.has(actualOutcome) ? actualOutcome : 'correct';
  const sanitized = typeof text === 'string' ? text.slice(0, MAX_FEEDBACK_TEXT_LENGTH) : '';

  FEEDBACK_LOG.push({ auditId, outcome, text: sanitized, time: Date.now() });
  if (FEEDBACK_LOG.length > MAX_FEEDBACK_LOG_SIZE) FEEDBACK_LOG.shift();
  LEARN_COUNT++;

  if (sanitized && getEmbeddingServerReady()) {
    let learnType = null;
    if (outcome === 'false_positive') learnType = 'safe';
    else if (outcome === 'false_negative') learnType = 'harmful';

    if (learnType) {
      const body = JSON.stringify({ texts: [sanitized], type: learnType, category: 'feedback_' + outcome });
      const opts = {
        hostname: 'localhost', port: EMBEDDING_SERVER_PORT, path: '/learn', method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      };
      const req = httpRequest(opts, function (res) {
        let d = '';
        res.on('data', function (c) { d += c; });
        res.on('end', function () {
          try { const j = JSON.parse(d); console.error('[L4] Auto-learned: ' + j.learned + ' ' + learnType + ' sample'); }
          catch (e) { /* ignore parse errors */ }
        });
      });
      req.on('error', function () { /* ignore network errors */ });
      req.write(body);
      req.end();
    }
  }

  return { ok: true, total: LEARN_COUNT };
}

export function cleanupFeedbackRates() {
  const cutoff = Date.now() - 120_000;
  for (const key of feedbackRateCounts.keys()) {
    const arr = feedbackRateCounts.get(key);
    const filtered = arr.filter(t => t > cutoff);
    if (filtered.length === 0) feedbackRateCounts.delete(key);
    else feedbackRateCounts.set(key, filtered);
  }
}

const feedbackCleanupTimer = setInterval(cleanupFeedbackRates, 300_000);
if (feedbackCleanupTimer.unref) feedbackCleanupTimer.unref();
