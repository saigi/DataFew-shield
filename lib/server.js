import { createServer } from 'node:http';
import { request as httpRequest } from 'node:http';

import {
  RATE_LIMIT_WINDOW_MS, RATE_LIMIT_MAX, MAX_BODY_SIZE,
  SHIELD_PORT, MAX_FEEDBACK_TEXT_LENGTH, MAX_FEEDBACK_RATE_PER_MIN,
} from './constants.js';
import { VALID_OUTCOMES, feedbackRateCounts } from './feedback.js';
import { VISITOR_STORE, SESSION_STORE, searchIdentities } from './session.js';
import { getEmbeddingRefs } from './embedding.js';
import { classifyPath, scanContent, dataDecision } from './classify.js';

const requestCounts = new Map();
let API_KEYS = new Set();

export function addApiKey(key) { API_KEYS.add(key); }
export function clearApiKeys() { API_KEYS = new Set(); }

export function startProxy(shield, port) {
  port = port || SHIELD_PORT;
  const server = createServer(function (req, res) {
    const allowedOrigin = process.env.SHIELD_CORS_ORIGIN;
    if (allowedOrigin) {
      res.setHeader('Access-Control-Allow-Origin', allowedOrigin);
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Api-Key');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

    // Auth check
    const authHeader = req.headers['authorization'] || req.headers['x-api-key'] || '';
    const apiKey = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;
    if (API_KEYS.size > 0 && !API_KEYS.has(apiKey)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'unauthorized' }));
      return;
    }

    // Rate limit
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown';
    const now = Date.now();
    if (!requestCounts.has(clientIp)) requestCounts.set(clientIp, []);
    const timestamps = requestCounts.get(clientIp).filter(t => now - t < RATE_LIMIT_WINDOW_MS);
    if (timestamps.length >= RATE_LIMIT_MAX) {
      res.writeHead(429, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'rate_limit_exceeded', limit: RATE_LIMIT_MAX, windowMs: RATE_LIMIT_WINDOW_MS }));
      return;
    }
    timestamps.push(now);
    requestCounts.set(clientIp, timestamps);

    const respond = function (code, data) {
      res.writeHead(code, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(data));
    };

    let u;
    try { u = new URL(req.url, 'http://' + req.headers.host); } catch (e) { respond(400, { error: 'invalid url' }); return; }

    // GET routes
    if (req.method === 'GET') {
      if (u.pathname === '/health') {
        let highRiskVisitors = 0, lockedSessions = 0;
        VISITOR_STORE.forEach(function (v) { if (v.risk > 0.5) highRiskVisitors++; });
        SESSION_STORE.forEach(function (s) { if (s.locked) lockedSessions++; });
        respond(200, {
          status: 'ok', mode: 'proxy',
          layers: { L1: !!getEmbeddingRefs(), L2: true, L3: true, L4: true },
          metrics: shield.auditEngine.getMetrics(),
          visitors: { total: VISITOR_STORE.size, highRisk: highRiskVisitors },
          sessions: { total: SESSION_STORE.size, locked: lockedSessions },
        });
        return;
      }
      if (u.pathname === '/metrics') { respond(200, shield.auditEngine.getMetrics()); return; }
      if (u.pathname === '/audit') {
        respond(200, shield.auditEngine.recent(parseInt(u.searchParams.get('limit') || '100')));
        return;
      }
      if (u.pathname === '/visitors') {
        const list = [];
        VISITOR_STORE.forEach(function (v) {
          list.push({ id: v.id, risk: v.risk, sessions: v.sessionCount, blocked: v.blockedCount, tags: v.tags, identities: v.identities });
        });
        respond(200, { total: VISITOR_STORE.size, visitors: list.sort((a, b) => b.risk - a.risk).slice(0, 50) });
        return;
      }
      if (u.pathname === '/identities') {
        const q = u.searchParams.get('q') || '';
        respond(200, { query: q, total: VISITOR_STORE.size, results: searchIdentities(q) });
        return;
      }
      respond(404, { error: 'unknown', endpoints: ['/health', '/metrics', '/audit', '/inspect', '/sandbox/create', '/feedback', '/classify', '/visitors', '/identities', '/proxy/llm'] });
      return;
    }

    // POST routes — read body first
    if (req.method !== 'POST') {
      respond(405, { error: 'method_not_allowed' });
      return;
    }

    readBody(req, res, function (body) {
      try {
        handlePost(shield, u, body, respond);
      } catch (e) {
        respond(400, { error: e.message });
      }
    });
  });

  server.listen(port, function () { console.error('[Shield] Running on :' + port + ' (4 layers)'); });
  return server;
}

function handlePost(shield, u, body, respond) {
  const data = JSON.parse(body);

  if (u.pathname === '/inspect') {
    (async function () {
      const r = await shield.inspect(data);
      respond(r.allowed ? 200 : 403, r);
    })();
    return;
  }

  if (u.pathname === '/sandbox/create') {
    const sb = shield.sandboxManager.createSandbox(data.id, data.config);
    respond(200, { id: sb.id, state: sb.state });
    return;
  }

  if (u.pathname === '/feedback') {
    if (!data.outcome) { respond(400, { error: 'missing outcome' }); return; }
    if (!VALID_OUTCOMES.has(data.outcome)) { respond(400, { error: 'invalid outcome', valid: [...VALID_OUTCOMES] }); return; }
    if (typeof data.text === 'string' && data.text.length > MAX_FEEDBACK_TEXT_LENGTH) { respond(400, { error: 'text_too_long', max: MAX_FEEDBACK_TEXT_LENGTH }); return; }

    const clientIp = 'feedback:' + (data.clientIp || 'unknown');
    const fNow = Date.now();
    if (!feedbackRateCounts.has(clientIp)) feedbackRateCounts.set(clientIp, []);
    const fTimes = feedbackRateCounts.get(clientIp).filter(t => fNow - t < 60_000);
    if (fTimes.length >= MAX_FEEDBACK_RATE_PER_MIN) { respond(429, { error: 'feedback_rate_exceeded' }); return; }
    fTimes.push(fNow);
    feedbackRateCounts.set(clientIp, fTimes);

    const r = shield.feedback(data.requestId, data.outcome, data.text);
    respond(200, r);
    return;
  }

  if (u.pathname === '/classify') {
    let level = classifyPath(data.path || '');
    if (data.content) {
      const cl = scanContent(data.content);
      const RANK = { P0: 0, P1: 1, P2: 2, P3: 3, P4: 4 };
      if (RANK[cl] < RANK[level]) level = cl;
    }
    respond(200, { path: data.path, classification: level, decision: dataDecision(level) });
    return;
  }

  // P2: Output Monitoring
  if (u.pathname === '/proxy/llm') {
    handleProxyLLM(shield, data, respond);
    return;
  }

  respond(404, { error: 'unknown', endpoints: ['/health', '/metrics', '/audit', '/inspect', '/sandbox/create', '/feedback', '/classify', '/visitors', '/identities', '/proxy/llm'] });
}

async function handleProxyLLM(shield, reqData, respond) {
  try {
    const prompt = reqData.prompt || reqData.messages?.[reqData.messages.length - 1]?.content || '';
    const sessionId = reqData.session_id || 'llm-proxy';
    const llmUrl = reqData.llm_url || 'http://localhost:4000/v1/chat/completions';
    const visitorId = reqData.visitor_id || null;

    const inputResult = await shield.inspect({
      type: 'chat', tool: 'llm', args: prompt,
      session_id: sessionId, visitor_id: visitorId,
    });

    if (!inputResult.allowed) {
      respond(403, { error: 'input_blocked', reason: inputResult.reason, layer: inputResult.layer, isInputBlock: true });
      return;
    }

    const llmBody = JSON.stringify({
      model: reqData.model || 'MiniMax-M2.7-highspeed',
      messages: reqData.messages || [{ role: 'user', content: prompt }],
      max_tokens: reqData.max_tokens || 512,
      stream: false,
    });

    const llmHeaders = { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(llmBody) };
    if (reqData.api_key) {
      llmHeaders['Authorization'] = 'Bearer ' + reqData.api_key;
    }

    const llmResponse = await new Promise(function (resolve, reject) {
      let settled = false;
      const llmReq = httpRequest(llmUrl, { method: 'POST', headers: llmHeaders }, function (llmRes) {
        let d = '';
        llmRes.on('data', function (c) { d += c; });
        llmRes.on('end', function () {
          if (settled) return; settled = true;
          try { resolve(JSON.parse(d)); }
          catch (e) { reject(new Error('LLM parse error: ' + e.message)); }
        });
      });
      const fail = function (e) { if (settled) return; settled = true; llmReq.destroy(); reject(e || new Error('LLM request failed')); };
      llmReq.on('error', fail);
      llmReq.setTimeout(30000, fail);
      llmReq.write(llmBody);
      llmReq.end();
    });

    let outputText = '';
    if (llmResponse.choices?.[0]) {
      outputText = llmResponse.choices[0].message?.content || llmResponse.choices[0].text || '';
    } else if (llmResponse.content) {
      outputText = typeof llmResponse.content === 'string' ? llmResponse.content : (llmResponse.content[0]?.text || '');
    } else if (llmResponse.response) {
      outputText = llmResponse.response;
    }

    const outputResult = await shield.inspectOutput(outputText);

    if (outputResult.block) {
      respond(403, {
        error: 'output_blocked', reason: 'output_unsafe',
        outputScore: outputResult.score, outputThreshold: outputResult.threshold,
        isInputBlock: false, llmPreview: outputText.slice(0, 100),
      });
      return;
    }

    respond(200, {
      ...llmResponse,
      safety: {
        inputAllowed: true, inputLayer: inputResult.layer, inputRisk: inputResult.risk,
        outputScore: outputResult.score, outputHarmful: outputResult.harmful,
        outputPassed: !outputResult.block,
      },
    });

  } catch (e) {
    respond(500, { error: 'proxy_error', message: e.message });
  }
}

function readBody(req, res, cb) {
  let buf = '', done = false;
  req.on('data', function (c) {
    if (done) return;
    if (buf.length + c.length > MAX_BODY_SIZE) {
      done = true; req.pause();
      try { res.writeHead(413, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'body_too_large', maxSize: MAX_BODY_SIZE })); } catch (e) { /* ignore */ }
      return;
    }
    buf += c;
  });
  req.on('end', function () { if (!done) cb(buf); });
}

export function cleanupRequestCounts() {
  const cutoff = Date.now() - RATE_LIMIT_WINDOW_MS;
  for (const key of requestCounts.keys()) {
    const arr = requestCounts.get(key);
    const filtered = arr.filter(t => t > cutoff);
    if (filtered.length === 0) requestCounts.delete(key);
    else requestCounts.set(key, filtered);
  }
}

const requestCleanupTimer = setInterval(cleanupRequestCounts, 60_000);
if (requestCleanupTimer.unref) requestCleanupTimer.unref();
