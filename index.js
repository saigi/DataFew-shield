#!/usr/bin/env node

import { resolve } from 'node:path';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

import { Shield as ShieldClass } from './lib/shield.js';
import { startProxy as startProxyFn, addApiKey as addApiKeyFn } from './lib/server.js';

export const Shield = ShieldClass;
export default ShieldClass;
export { SandboxManager } from './lib/sandbox.js';
export { AuditEngine } from './lib/audit.js';
export { PolicyEngine } from './lib/policy.js';
export {
  classifyPath, scanContent, dataDecision, classifyResource,
  DataRegistry, CLASSIFICATION, SENSITIVE_PATTERNS, CONTENT_PATTERNS,
} from './lib/classify.js';
export {
  getSessionProfile, getVisitorProfile, recordIdentity, searchIdentities,
  VISITOR_STORE, SESSION_STORE,
} from './lib/session.js';
export {
  FALLBACK_DANGEROUS, EMBEDDING_THRESHOLD, fallbackScore,
  cosine, queryEmbeddingServer, checkEmbeddingServer,
  getEmbeddingRefs, getEmbeddingServerReady, setEmbeddingServerReady,
  getL3ImmediateLock,
} from './lib/embedding.js';

import { setEmbeddingServerReady as _setEmbeddingReady } from './lib/embedding.js';
export const setEmbeddingReady = _setEmbeddingReady;
export const addApiKey = addApiKeyFn;
export const startProxy = startProxyFn;

// ============================================================================
// CLI
// ============================================================================

const args = process.argv.slice(2);
if (args.length > 0 && !args[0].startsWith('--')) {
  const opts = { port: 8080 };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--port') opts.port = parseInt(args[++i]) || 8080;
    else if (args[i] === '--policies') opts.policyDir = resolve(args[++i]);
  }
  const shield = new ShieldClass(opts);
  startProxyFn(shield, opts.port);
}
