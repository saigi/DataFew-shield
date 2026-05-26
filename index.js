#!/usr/bin/env node
/**
 * Datafew Shield — 四层安全内核
 *
 * 架构: ARCHITECTURE.md
 *   第 1 层: 向量空间 (semantic)
 *   第 2 层: 数据分类 (resource)  
 *   第 3 层: 会话风险 (temporal)
 *   第 4 层: 自我进化 (feedback)
 *
 * 启动: node index.js [--port 8080] [--policies ./policies]
 */

import { createServer } from 'node:http';
import { readFileSync, readdirSync, existsSync, writeFileSync, appendFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { request as httpRequest } from 'node:http';

var __dirname = dirname(fileURLToPath(import.meta.url));
var MAX_BODY_SIZE = 1048576; // 1MB

// ============================================================================
// 基础设施
// ============================================================================

class SandboxManager {
  constructor() { this.sandboxes = new Map(); }
  createSandbox(id, cfg) {
    var sb = { id: id || 's-' + Date.now(), config: cfg || {}, state: 'active', created: Date.now(), history: [] };
    this.sandboxes.set(sb.id, sb); return sb;
  }
  validate(sid) {
    var sb = this.sandboxes.get(sid);
    if (!sb) return { ok: false, reason: 'sandbox_not_found' };
    if (sb.state !== 'active') return { ok: false, reason: 'sandbox_inactive' };
    return { ok: true, sandbox: sb };
  }
  record(sid, e) { var sb = this.sandboxes.get(sid); if (sb) { sb.history.push(e); if (sb.history.length > 10) sb.history.shift(); } }
}

class AuditEngine {
  constructor() { this.logs = []; this.metrics = { checks: 0, blocked: 0, allowed: 0 }; }
  record(e) {
    e.id = 'a-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 6);
    e.ts = new Date().toISOString(); this.logs.push(e);
    this.metrics.checks++; if (e.action === 'blocked') this.metrics.blocked++; if (e.action === 'allowed') this.metrics.allowed++;
    if (this.logs.length > 10000) this.logs.shift(); return e;
  }
  getMetrics() { var m = Object.assign({}, this.metrics); m.block_rate = m.checks > 0 ? Math.round(m.blocked / m.checks * 1000) / 10 : 0; return m; }
  recent(n) { return this.logs.slice(-(n || 100)); }
}

// ============================================================================
// 第 1 层: 向量空间 — Embedding 参考集
// ============================================================================

var embeddingRefs = null;
var embeddingServer = null;
var EMBEDDING_THRESHOLD = 0.52;

try {
  var refsPath = resolve(__dirname, 'data', 'embedding_refs.json');
  if (existsSync(refsPath)) {
    embeddingRefs = JSON.parse(readFileSync(refsPath, 'utf-8'));
    EMBEDDING_THRESHOLD = embeddingRefs.benchmark?.classifier_threshold || embeddingRefs.benchmark?.optimal_threshold || 0.52;
    if (L3_IMMEDIATE_LOCK === null) L3_IMMEDIATE_LOCK = EMBEDDING_THRESHOLD;
    console.error('[L1] Embedding refs: ' + embeddingRefs.harmful.count + ' harmful, ' + embeddingRefs.safe.count + ' safe, threshold=' + EMBEDDING_THRESHOLD);
  }
} catch(e) { console.error('[L1] Load failed:', e.message); }

var EMBEDDING_SERVER_READY = false;
var L1_BLOCK_THRESHOLD = 0.55;     // high conf → direct block
var L3_IMMEDIATE_RISK_RATIO = 1.0;  // immediate risk = score × 1.0
var L3_IMMEDIATE_LOCK = null;       // dynamic: set from classifier threshold

function startEmbeddingServer() {
  var scriptPath = resolve(__dirname, 'scripts', 'embedding_server.py');
  if (!existsSync(scriptPath)) return;
  try {
    embeddingServer = spawn('python', [scriptPath, '--port', '5000'], {
      stdio: 'ignore', detached: true, env: Object.assign({}, process.env, { TF_CPP_MIN_LOG_LEVEL: '3' }),
    });
    embeddingServer.unref();
    console.error('[L1] Embedding server starting on :5000 (polling for health...)');
    embeddingServer.on('exit', function(c) { embeddingServer = null; EMBEDDING_SERVER_READY = false; });
    (function poll() {
      var req = httpRequest({ hostname: 'localhost', port: 5000, path: '/health', method: 'GET' }, function(res) {
        var d = '';
        res.on('data', function(c) { d += c; });
        res.on('end', function() {
          try { var j = JSON.parse(d); if (j.status === 'ok') { EMBEDDING_SERVER_READY = true; console.error('[L1] Embedding server ready'); return; } } catch(e) {}
          setTimeout(poll, 3000);
        });
      });
      req.on('error', function() { setTimeout(poll, 3000); });
      req.setTimeout(5000, function() { req.destroy(); setTimeout(poll, 3000); });
      req.end();
    })();
  } catch(e) { console.error('[L1] Start failed:', e.message); }
}
if (embeddingRefs) {
  checkEmbeddingServer(function(ready) {
    if (!ready && process.env.DISABLE_EMBEDDING_SERVER !== '1') {
      startEmbeddingServer();
    }
  });
}

function queryEmbeddingServer(text) {
  return new Promise(function(resolve) {
    try {
      var body = JSON.stringify({ texts: [text] });
      var options = { hostname: 'localhost', port: 5000, path: '/score', method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } };
      var req = httpRequest(options, function(res) {
        var data = '';
        res.on('data', function(c) { data += c; });
        res.on('end', function() {
          try { var j = JSON.parse(data); if (j.results && j.results[0]) resolve(j.results[0]); else resolve(null); }
          catch(e) { resolve(null); }
        });
      });
      req.on('error', function() { resolve(null); });
      req.write(body);
      req.end();
    } catch(e) { resolve(null); }
  });
}

var LAST_EMBEDDING_SERVER_CHECK = 0;

function checkEmbeddingServer(cb) {
  if (Date.now() - LAST_EMBEDDING_SERVER_CHECK > 30000) {
    LAST_EMBEDDING_SERVER_CHECK = Date.now();
    var done = false;
    var req = httpRequest({ hostname: 'localhost', port: 5000, path: '/health', method: 'GET' }, function(res) {
      var d = '';
      res.on('data', function(c) { d += c; });
      res.on('end', function() {
        if (done) return; done = true;
        try { var j = JSON.parse(d); EMBEDDING_SERVER_READY = j.status === 'ok'; }
        catch(e) { EMBEDDING_SERVER_READY = false; }
        cb(EMBEDDING_SERVER_READY);
      });
    });
    req.on('error', function() { if (done) return; done = true; EMBEDDING_SERVER_READY = false; cb(false); });
    req.setTimeout(2000, function() { if (done) return; done = true; req.destroy(); EMBEDDING_SERVER_READY = false; cb(false); });
    req.end();
  } else { process.nextTick(function() { cb(EMBEDDING_SERVER_READY); }); }
}

function cosine(a, b) {
  var dot = 0, na = 0, nb = 0;
  for (var i = 0; i < a.length; i++) { dot += a[i] * b[i]; na += a[i] * a[i]; nb += b[i] * b[i]; }
  return dot / (Math.sqrt(na) * Math.sqrt(nb) + 1e-10);
}

function embeddingScore(emb) {
  if (!embeddingRefs || !emb) return 0.5;
  var maxH = -1, maxS = -1;
  for (var i = 0; i < embeddingRefs.harmful.embeddings.length; i++) { var sim = cosine(emb, embeddingRefs.harmful.embeddings[i]); if (sim > maxH) maxH = sim; }
  for (var i = 0; i < embeddingRefs.safe.embeddings.length; i++) { var sim = cosine(emb, embeddingRefs.safe.embeddings[i]); if (sim > maxS) maxS = sim; }
  var h = (maxH + 1) / 2, s = (maxS + 1) / 2; if (h + s < 0.01) return 0.5; return h / (h + s);
}

/**
 * Fallback 文本评分 — 仅在 Python embedding 服务器不可用时使用
 * 不做语义理解，只拦截最明显的直接危险命令
 * 这是兜底方案，不是主方案
 */
var FALLBACK_DANGEROUS = [
  { re: /^rm -rf \/$/i, reason: 'root_delete' },
  { re: /^rm -rf \/\s*--no-preserve-root/i, reason: 'root_delete' },
  { re: /bash -i\s*[&>].*\/dev\/tcp\//i, reason: 'reverse_shell' },
  { re: /nc\s+-[le]\s+\d+\s+-e\s+/i, reason: 'reverse_shell' },
  { re: /mkfs\.\w+\s+\/dev\//i, reason: 'disk_destroy' },
  { re: /dd\s+if=\/dev\/\w+\s+of=\/dev\//i, reason: 'disk_destroy' },
];

function fallbackScore(text) {
  if (!text) return 0.5;
  var t = String(text);
  for (var i = 0; i < FALLBACK_DANGEROUS.length; i++) {
    if (FALLBACK_DANGEROUS[i].re.test(t)) return 0.85;
  }
  return 0.5;
}

// ============================================================================
// 第 2 层: 数据分类
// ============================================================================

var DATA_LEVELS = { P0: 'credential', P1: 'pii', P2: 'financial', P3: 'internal', P4: 'public' };

var SENSITIVE_PATTERNS = [
  { level: 'P0', patterns: ['/etc/shadow', '/etc/passwd', '.ssh/id_rsa', '.ssh/id_ecdsa', '.ssh/authorized_keys', '.aws/credentials', '.gcloud/', '/.kube/config', 'credentials.json', 'service-account.json', '*.pem', '*secret*'] },
  { level: 'P1', patterns: ['users.csv', 'customer*.csv', 'employee*', 'personal*', 'phone*', 'address*'] },
  { level: 'P2', patterns: ['payment*', 'transaction*', 'invoice*', 'bank*', 'financial*'] },
];

var CONTENT_PATTERNS = [
  { level: 'P0', re: /(password\s*[:=]|PASSWORD\s*[:=]|DB_PASSWORD|SECRET_KEY|sk-\w+|api_key\s*[:=]|token\s*[:=])/i },
  { level: 'P1', re: /(\d{11}|@gmail\.com|@outlook\.com|手机号|身份证)/i },
  { level: 'P2', re: /(银行卡|信用卡|cvv|card_number|银行账户)/i },
];

function classifyPath(path) {
  for (var i = 0; i < SENSITIVE_PATTERNS.length; i++) {
    for (var j = 0; j < SENSITIVE_PATTERNS[i].patterns.length; j++) {
      var pat = SENSITIVE_PATTERNS[i].patterns[j].replace(/\*/g, '.*');
      try { if (new RegExp(pat, 'i').test(path)) return SENSITIVE_PATTERNS[i].level; } catch(e) {}
      }
    }

    if (/^\/(workspace|project|src)\//.test(path)) return 'P3';
  return 'P4';
}

function scanContent(content) {
  if (!content) return 'P4';
  for (var i = 0; i < CONTENT_PATTERNS.length; i++) {
    if (CONTENT_PATTERNS[i].re.test(content)) return CONTENT_PATTERNS[i].level;
  }
  return 'P4';
}

function dataDecision(level) {
  if (level === 'P0') return { allowed: false, reason: 'credential_blocked', riskLevel: 0 };
  if (level === 'P1' || level === 'P2') return { allowed: false, reason: 'sensitive_data', riskLevel: level === 'P1' ? 1 : 2, requiresApproval: true };
  if (level === 'P3') return { allowed: true, reason: 'internal_allowed', riskLevel: 3 };
  return { allowed: true, reason: 'public_allowed', riskLevel: 4 };
}

// ============================================================================
// 会话 + 访客存储 (用于 L3 风险累积和 DLP)
// ============================================================================

var VISITOR_STORE = new Map();
var SESSION_STORE = new Map();
var STORE_TTL = 3600000;
var CLEANUP_INTERVAL = 300000;

function getSessionProfile(sessionId, visitorId) {
  if (!SESSION_STORE.has(sessionId)) {
    var baseRisk = 0;
    if (visitorId) {
      var visitor = getVisitorProfile(visitorId);
      baseRisk = visitor.risk * 0.3;
    }
    SESSION_STORE.set(sessionId, {
      id: sessionId, created: Date.now(), lastActive: Date.now(),
      visitorId: visitorId || null,
      risk: baseRisk, stepCount: 0, phase: 'exploration', locked: false,
      tags: [], blockedCount: 0, lastTool: null,
      policyRisk: 0, semanticRisk: 0, behaviorRisk: 0,
    });
  }
  return SESSION_STORE.get(sessionId);
}

function getVisitorProfile(visitorId) {
  if (!VISITOR_STORE.has(visitorId)) {
    VISITOR_STORE.set(visitorId, {
      id: visitorId, firstSeen: Date.now(), lastSeen: Date.now(),
      risk: 0, sessionCount: 0, blockedCount: 0, tags: [], identities: {},
    });
  }
  return VISITOR_STORE.get(visitorId);
}

function cleanupStores() {
  var now = Date.now();
  SESSION_STORE.forEach(function(s, sid) {
    if (now - s.lastActive > STORE_TTL) SESSION_STORE.delete(sid);
  });
  VISITOR_STORE.forEach(function(v, vid) {
    if (now - v.lastSeen > STORE_TTL) VISITOR_STORE.delete(vid);
  });
}
var cleanupTimer = setInterval(cleanupStores, CLEANUP_INTERVAL);
if (cleanupTimer.unref) cleanupTimer.unref();

// ============================================================================
// 第 4 层: 自增长反馈
// ============================================================================

var FEEDBACK_LOG = [];
var LEARN_COUNT = 0;

function recordFeedback(auditId, actualOutcome, text) {
  FEEDBACK_LOG.push({ auditId: auditId, outcome: actualOutcome, text: text || '', time: Date.now() });
  if (FEEDBACK_LOG.length > 1000) FEEDBACK_LOG.shift();
  LEARN_COUNT++;

  // Self-growing: auto-learn from false positives/negatives
  if (text && EMBEDDING_SERVER_READY) {
    var learnType = null;
    if (actualOutcome === 'false_positive') learnType = 'safe';
    else if (actualOutcome === 'false_negative') learnType = 'harmful';

    if (learnType) {
      var body = JSON.stringify({ texts: [text], type: learnType, category: 'feedback_' + actualOutcome });
      var opts = { hostname: 'localhost', port: 5000, path: '/learn', method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } };
      var req = httpRequest(opts, function(res) {
        var d = '';
        res.on('data', function(c) { d += c; });
        res.on('end', function() {
          try { var j = JSON.parse(d); console.error('[L4] Auto-learned: ' + j.learned + ' ' + learnType + ' sample (total ' + j.total_safe + ' safe, ' + j.total_harmful + ' harmful)'); }
          catch(e) {}
        });
      });
      req.on('error', function() {});
      req.write(body);
      req.end();
    }
  }

  return { ok: true, total: LEARN_COUNT };
}

// ============================================================================
// 第 0 层: 策略引擎
// ============================================================================

class PolicyEngine {
  constructor(policyDir) {
    this.policyDir = policyDir || resolve(__dirname, 'policies');
    this.policies = [];
    this.attackPatterns = this.buildAttackPatterns();
    this.loadPolicies();
  }
  loadPolicies() {
    if (!existsSync(this.policyDir)) return;
    var files = readdirSync(this.policyDir).filter(function(f) { return f.endsWith('.json'); });
    this.policies = [];
    for (var i = 0; i < files.length; i++) {
      try {
        var parsed = JSON.parse(readFileSync(resolve(this.policyDir, files[i]), 'utf-8'));
        if (Array.isArray(parsed)) { for (var p = 0; p < parsed.length; p++) this.policies.push(parsed[p]); }
        else { this.policies.push(parsed); }
      } catch(e) { console.error('[Policy] Load failed:', files[i], e.message); }
    }
    console.error('[Policy] Loaded ' + this.policies.length + ' rules');
  }
  matchPolicy(policy, context) {
    if (!policy || !policy.match) return null;
    var m = policy.match;
    if (m.type && m.type !== context.type) return null;
    if (m.tool && m.tool !== context.tool) return null;
    if (m.args_pattern && context.args) { try { if (!new RegExp(m.args_pattern, 'i').test(context.args)) return null; } catch(e) { return null; } }
    return { allowed: policy.action !== 'block', reason: policy.reason || 'policy:' + policy.id, severity: policy.severity || 'high', policy_id: policy.id };
  }
  evaluate(context) {
    if (!context || !context.type) return { allowed: true };
    for (var i = 0; i < this.policies.length; i++) { var r = this.matchPolicy(this.policies[i], context); if (r) return r; }
    return { allowed: true };
  }
  buildAttackPatterns() {
    return [
      { name: 'credential_exfil', severity: 'critical', steps: [
        { tool: ['read_file','terminal'], args: ['id_rsa','id_ecdsa','id_ed25519','authorized_keys','.ssh','credential','secret'] },
        { tool: ['read_file','terminal'], args: ['.ssh','id_rsa','config','known_hosts','token','key'] },
        { tool: ['send_message','terminal'], args: ['@','curl','http','exfil','upload'] },
      ]},
      { name: 'reverse_shell', severity: 'critical', steps: [
        { tool: ['terminal'], args: ['nc -l','ncat -l','socat','listen'] },
        { tool: ['terminal'], args: ['/dev/tcp/','/dev/udp/','bash -i','connect'] },
      ]},
      { name: 'data_destruction', severity: 'high', steps: [
        { tool: ['terminal'], args: ['dd if=','mkfs','fdisk','parted'] },
        { tool: ['terminal'], args: ['rm -rf','shred','wipefs','mkfs'] },
      ]},
      { name: 'recon_scan', severity: 'medium', steps: [
        { tool: ['terminal'], args: ['nmap','masscan','zmap','whois'] },
        { tool: ['terminal'], args: ['ssh ','telnet','nc -v','curl -v'] },
      ]},
    ];
  }
  detectAttackChain(history, currentCall) {
    if (!history || history.length < 1) return null;
    var calls = [];
    for (var i = 0; i < history.length; i++) { if (history[i].type === 'tool_call') calls.push({ tool: history[i].tool, args: history[i].args || '' }); }
    if (currentCall) calls.push({ tool: currentCall.tool, args: currentCall.args || '' });
    if (calls.length < 2) return null;
    for (var p = 0; p < this.attackPatterns.length; p++) {
      var ap = this.attackPatterns[p];
      if (ap.steps.length > calls.length) continue;
      for (var start = 0; start <= calls.length - ap.steps.length; start++) {
        var ok = true;
        for (var s = 0; s < ap.steps.length; s++) {
          var step = ap.steps[s], cmd = calls[start + s];
          var tOk = false; for (var t = 0; t < step.tool.length; t++) { if (cmd.tool === step.tool[t] || cmd.tool.includes(step.tool[t])) { tOk = true; break; } }
          if (!tOk) { ok = false; break; }
          var aOk = false; for (var a = 0; a < step.args.length; a++) { if (cmd.args.toLowerCase().includes(step.args[a].toLowerCase())) { aOk = true; break; } }
          if (!aOk) { ok = false; break; }
        }
        if (ok) return { detected: true, pattern: ap.name, severity: ap.severity, matched_at: start };
      }
    }
    return null;
  }
}

// ============================================================================
// Shield 主类 — 四层联合
// ============================================================================

export class Shield {
  constructor(opts) {
    opts = opts || {};
    this.policyEngine = new PolicyEngine(opts.policyDir);
    this.sandboxManager = new SandboxManager();
    this.auditEngine = new AuditEngine();
    this.server = null;

    console.error('[Shield] L1(embedding): ' + (embeddingRefs ? embeddingRefs.harmful.count + ' refs' : 'DISABLED'));
    console.error('[Shield] L2(data): ' + SENSITIVE_PATTERNS.length + ' path patterns + ' + CONTENT_PATTERNS.length + ' content patterns');
    console.error('[Shield] L3(session): active');
    console.error('[Shield] L4(feedback): ' + LEARN_COUNT + ' collected');
    console.error('[Shield] Policy: ' + this.policyEngine.policies.length + ' rules');
  }

  async inspect(request) {
    var sid = request.session_id || 'default';
    var audit = { type: request.type, tool: request.tool, args: String(request.args || '').slice(0, 200), session_id: sid, action: 'pending' };
    var decisions = [];
    var finalAllowed = true;
    var finalReason = 'passed';
    var finalLayer = 'L_all';

    var textToScore = request.text || request.args || '';
    var embeddingScoreVal = 0.5;

    var visitorId = request.visitor_id || request.visitorId || null;
    if (visitorId) {
      recordIdentity(visitorId, {
        ip: request.ip || request.remote_addr || null,
        device: request.device || request.device_id || request.user_agent || null,
        userId: request.user_id || request.userId || null,
        phone: request.phone || null,
        email: request.email || null,
        fingerprint: request.fingerprint || null,
      });
    }

    // ================================================================
    // L0: 沙箱 — 最先
    // ================================================================

    var sc = this.sandboxManager.validate(sid);
    if (!sc.ok) {
      audit.action = 'blocked'; audit.reason = sc.reason; audit.layer = 'L0';
      this.auditEngine.record(audit);
      return { allowed: false, reason: sc.reason, severity: 'critical', layer: 'L0', audit_id: audit.id };
    }

    // ================================================================
    // DETERMINISTIC LAYERS (先过, 零误报, 绝对优先)
    // ================================================================

    // L0: 策略 (rules)
    var pr = this.policyEngine.evaluate({ type: request.type, tool: request.tool, args: request.args });
    if (!pr.allowed) {
      audit.action = 'blocked'; audit.reason = pr.reason; audit.layer = 'L0_policy'; audit.policy_id = pr.policy_id;
      this.auditEngine.record(audit);
      this.sandboxManager.record(sid, { type: 'tool_call', tool: request.tool, args: request.args, result: 'blocked_by_policy' });
      finalAllowed = false; finalReason = pr.reason; finalLayer = 'L0_policy';
    }

    // L2: 数据分类 (resource) — 仅当未被上层拦截时
    var resourcePath = request.resource || request.args || '';
    if (resourcePath && finalAllowed) {
      var level = classifyPath(resourcePath);
      if (request.content) {
        var contentLevel = scanContent(request.content);
        if ({ P0: 0, P1: 1, P2: 2, P3: 3, P4: 4 }[contentLevel] < { P0: 0, P1: 1, P2: 2, P3: 3, P4: 4 }[level]) level = contentLevel;
      }
      var dd = dataDecision(level);
      if (!dd.allowed && !dd.requiresApproval) {
        audit.action = 'blocked'; audit.reason = dd.reason; audit.layer = 'L2';
        this.auditEngine.record(audit);
        finalAllowed = false; finalReason = dd.reason; finalLayer = 'L2';
      } else if (dd.requiresApproval) {
        audit.action = 'blocked'; audit.reason = dd.reason; audit.layer = 'L2_approval';
        this.auditEngine.record(audit);
        finalAllowed = false; finalReason = dd.reason; finalLayer = 'L2';
      }
    }

    // ================================================================
    // DLP: 数据血缘追踪 — 敏感读取标记 + 外传检测
    // ================================================================
    var profile = getSessionProfile(sid, visitorId);
    if (profile.dataTaint === undefined) profile.dataTaint = 0;
    if (profile.dataTaintTime === undefined) profile.dataTaintTime = 0;

    // 衰减: 30 分钟 → 清除
    if (profile.dataTaintTime > 0 && Date.now() - profile.dataTaintTime > 1800000) {
      profile.dataTaint = 0;
    }

    // 读取敏感数据 → 污染
    var dlpLevel = 0;
    if (resourcePath) {
      var dl = classifyPath(resourcePath);
      dlpLevel = { P0: 3, P1: 2, P2: 1, P3: 0, P4: 0 }[dl] || 0;
      if (dlpLevel > 0 && request.content) {
        var cl = scanContent(request.content);
        var clN = { P0: 3, P1: 2, P2: 1, P3: 0, P4: 0 }[cl] || 0;
        if (clN > dlpLevel) dlpLevel = clN;
      }
    }
    if (dlpLevel > profile.dataTaint) profile.dataTaint = dlpLevel;
    if (dlpLevel > 0) profile.dataTaintTime = Date.now();

    // 外传工具检测
    var EGRESS = ['curl', 'wget', 'nc', 'ncat', 'socat', 'telnet', 'ssh', 'ftp', 'scp', 'send_message'];
    var isEgress = EGRESS.some(function(t) { return request.tool && request.tool.includes(t); });

    if (isEgress && profile.dataTaint > 0 && finalAllowed) {
      var taintLabel = ['', 'P2', 'P1', 'P0'][profile.dataTaint];
      audit.action = 'blocked'; audit.reason = 'dlp_egress_' + taintLabel; audit.layer = 'DLP';
      this.auditEngine.record(audit);
      this.sandboxManager.record(sid, { type: 'tool_call', tool: request.tool, args: request.args, result: 'blocked_by_dlp' });
      finalAllowed = false; finalReason = 'dlp_egress_' + taintLabel; finalLayer = 'DLP';
    }

    // L0: 攻击链 (chain) — 合并沙箱历史 + 请求历史
    if (finalAllowed) {
      var history = (sc.sandbox ? sc.sandbox.history : []).concat(request.history || []);
      var cr = this.policyEngine.detectAttackChain(history, { tool: request.tool, args: request.args });
      if (cr) {
        audit.action = 'blocked'; audit.reason = 'chain:' + cr.pattern; audit.chain_detected = true; audit.layer = 'L0_chain';
        this.auditEngine.record(audit);
        this.sandboxManager.record(sid, { type: 'tool_call', tool: request.tool, args: request.args, result: 'blocked_by_chain' });
        finalAllowed = false; finalReason = 'attack_chain'; finalLayer = 'L0_chain';
      }
    }

    // ================================================================
    // L1: 向量空间 — 概率层 (在确定层之后)
    //   高置信度直接阻断, 否则注入 L3 风险维度
    // ================================================================

    if (embeddingRefs && textToScore && textToScore.length > 3) {
      var embeddingOk = false;
      var l1Result = null;
      if (EMBEDDING_SERVER_READY) {
        l1Result = await queryEmbeddingServer(textToScore);
        if (l1Result && l1Result.score !== undefined && l1Result.score >= 0) {
          embeddingScoreVal = l1Result.score;
          embeddingOk = true;
          var curThreshold = l1Result.threshold || EMBEDDING_THRESHOLD;
          L3_IMMEDIATE_LOCK = curThreshold;

          // Logit-scale confidence: spread scores for better discrimination
          // logit = ln(score / (1-score))
          // maps [0.5±ε] → [-∞, +∞], amplifies near-boundary differences
          var rawScore = Math.max(0.001, Math.min(0.999, embeddingScoreVal));
          var logitScore = Math.log(rawScore / (1 - rawScore));
          var logitConfidence = 1 / (1 + Math.exp(-Math.abs(logitScore)));  // sigmoid of |logit|

          decisions.push({
            layer: 'L1', source: 'embedding_server',
            score: embeddingScoreVal, logitScore: logitScore,
            confidence: logitConfidence,
            threshold: curThreshold,
          });

          // Direct block: high logit-confidence OR very high score
          if (!finalAllowed) {
            // Already blocked by deterministic layer — still record L1
          } else if (logitConfidence > 0.7 && embeddingScoreVal > curThreshold) {
            // 高置信度有害 → 直接阻断 (不移交 L3)
            audit.action = 'blocked'; audit.reason = 'semantic_high_confidence'; audit.layer = 'L1';
            audit.l1_score = embeddingScoreVal; audit.l1_confidence = logitConfidence;
            this.auditEngine.record(audit);
            this.sandboxManager.record(sid, { type: 'tool_call', tool: request.tool, args: request.args, result: 'blocked_by_l1' });
            finalAllowed = false; finalReason = 'semantic_high_confidence'; finalLayer = 'L1';
          } else if (embeddingScoreVal > curThreshold + 0.1) {
            // 非常高分 (> 阈值+0.1) → 直接阻断
            audit.action = 'blocked'; audit.reason = 'semantic_high_score'; audit.layer = 'L1';
            this.auditEngine.record(audit);
            this.sandboxManager.record(sid, { type: 'tool_call', tool: request.tool, args: request.args, result: 'blocked_by_l1' });
            finalAllowed = false; finalReason = 'semantic_high_score'; finalLayer = 'L1';
          }
          // else: pass through → L3 will handle with risk dimensions
        }
      }
      if (!embeddingOk) {
        embeddingScoreVal = fallbackScore(textToScore);
        if (embeddingScoreVal > 0.6) {
          decisions.push({ layer: 'L1', source: 'fallback', score: embeddingScoreVal, note: 'no_embedding_server' });
        }
      }
    }

    // ================================================================
    // L3: 会话风险 — 始终更新, 分离风险维度
    //   policyRisk: 策略拦截累积 (攻击信号)
    //   semanticRisk: 向量评分累积 (模糊信号)
    //   behaviorRisk: 工具切换/频率 (行为信号)
    // ================================================================

    var wasBlocked = !finalAllowed;
    var blockLayerVal = wasBlocked ? finalLayer : null;

    // 初始化风险维度 (session profile 新增字段)
    if (profile.policyRisk === undefined) profile.policyRisk = 0;
    if (profile.semanticRisk === undefined) profile.semanticRisk = 0;
    if (profile.behaviorRisk === undefined) profile.behaviorRisk = 0;

    // Policy risk: 仅当被策略/数据/链拦截时增加
    if (wasBlocked && (finalLayer === 'L0_policy' || finalLayer === 'L2' || finalLayer === 'L0_chain')) {
      profile.policyRisk = Math.min(1, profile.policyRisk + 0.3);
    } else {
      profile.policyRisk *= 0.95;  // 慢速衰减
    }

    // Semantic risk: 每次都用 embedding 评分更新
    var semanticAlpha = 0.85;
    profile.semanticRisk = semanticAlpha * profile.semanticRisk + (1 - semanticAlpha) * embeddingScoreVal;

    // Behavior risk: 工具切换检测
    if (request.tool) {
      if (profile.lastTool !== request.tool) {
        profile.behaviorRisk = Math.min(1, profile.behaviorRisk + 0.15);
        profile.lastTool = request.tool;
      } else {
        profile.behaviorRisk *= 0.9;
      }
    }

    // 即时语义风险 (单次请求防护, 不移交累积)
    var immediateSemanticRisk = embeddingScoreVal * L3_IMMEDIATE_RISK_RATIO;

    // 综合风险 = 各维度的加权最大
    var effectivePolicyRisk = profile.policyRisk;
    var effectiveSemanticRisk = Math.max(profile.semanticRisk, immediateSemanticRisk);
    var effectiveBehaviorRisk = profile.behaviorRisk;
    var effectiveRisk = Math.max(effectivePolicyRisk, effectiveSemanticRisk, effectiveBehaviorRisk);

    // 锁定判定: 不同类型有不同阈值
    var lockThreshold = L3_IMMEDIATE_LOCK || 0.50;
    var policyLock = effectivePolicyRisk > 0.8;
    var semanticLock = effectiveSemanticRisk > lockThreshold;
    var behaviorLock = effectiveBehaviorRisk > 0.6;

    if (policyLock || semanticLock || behaviorLock) {
      profile.locked = true;
      var lockReason = policyLock ? 'risk_lock_policy' : (semanticLock ? 'risk_lock_semantic' : 'risk_lock_behavior');
      if (finalAllowed) {  // 仅当之前没被拦
        audit.action = 'blocked'; audit.reason = lockReason; audit.layer = 'L3';
        this.auditEngine.record(audit);
        this.sandboxManager.record(sid, { type: 'tool_call', tool: request.tool, args: request.args, result: 'blocked_by_session' });
        finalAllowed = false; finalReason = lockReason; finalLayer = 'L3';
      }
    }

    decisions.push({
      layer: 'L3',
      policyRisk: profile.policyRisk, semanticRisk: profile.semanticRisk,
      behaviorRisk: profile.behaviorRisk, effectiveRisk: effectiveRisk,
      locked: profile.locked,
    });

    // ================================================================
    // 访客追踪 — 始终更新
    // ================================================================

    if (profile.visitorId) {
      var visitor = getVisitorProfile(profile.visitorId);
      visitor.lastSeen = Date.now();
      var contribution = effectiveRisk * 0.5;
      if (contribution > visitor.risk) visitor.risk = contribution;
      if (profile.locked && !visitor.tags.includes('session_locked')) visitor.tags.push('session_locked');
      if (wasBlocked) visitor.blockedCount++;
    }

    profile.phase = profile.locked ? 'lockdown' : (effectiveRisk > 0.3 ? 'execution' : (effectiveRisk > 0.15 ? 'focus' : 'exploration'));
    if (profile.locked) profile.tags = ['locked']; else profile.tags = [];

    // ================================================================
    // 记录 + 返回
    // ================================================================

    if (finalAllowed) {
      audit.action = 'allowed'; audit.layer = 'L_all';
      this.auditEngine.record(audit);
      this.sandboxManager.record(sid, { type: 'tool_call', tool: request.tool, args: request.args, result: 'allowed' });
    }

    return {
      allowed: finalAllowed, reason: finalReason, layer: finalLayer,
      risk: effectiveRisk,
      risks: {
        policy: profile.policyRisk, semantic: profile.semanticRisk,
        behavior: profile.behaviorRisk,
      },
      phase: profile.phase, tags: profile.tags,
      visitorRisk: profile.visitorId ? getVisitorProfile(profile.visitorId).risk : 0,
      audit_id: audit.id, decisions: decisions,
    };
  }

  /**
   * P2: Output monitoring — check LLM response text for safety.
   * Reuses the same L1 embedding server for scoring.
   * Input passed input inspection, but the LLM output might be harmful.
   *
   * Mathematical value:
   *   P(bypass) = P_FN(input) × P_FN(output)
   *   ≈ 24% × 10% = 2.4%
   *   vs single-layer P(bypass) = 24%
   */
  async inspectOutput(text) {
    if (!embeddingRefs || !text || text.length < 5) return { harmful: false, score: 0.5 };

    var scoreVal = 0.5, meta = null;
    if (EMBEDDING_SERVER_READY) {
      meta = await queryEmbeddingServer(text);
      if (meta && meta.score !== undefined && meta.score >= 0) {
        scoreVal = meta.score;
      }
    }

    var curThreshold = (meta && meta.threshold) || EMBEDDING_THRESHOLD;
    var harmful = scoreVal > curThreshold;

    // Higher threshold for output (less sensitive — avoid overblocking generation)
    var outputThreshold = Math.max(0.55, curThreshold + 0.05);
    var block = scoreVal > outputThreshold;

    return {
      harmful: harmful,
      score: scoreVal,
      threshold: outputThreshold,
      block: block,
    };
  }

  feedback(requestId, outcome, text) {
    return recordFeedback(requestId, outcome, text);
  }

  startProxy(port) {
    var self = this;
    port = port || 8080;
    this.server = createServer(function(req, res) {
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', '*');
      if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }
      var respond = function(code, data) { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(data)); };
      var u; try { u = new URL(req.url, 'http://' + req.headers.host); } catch(e) { respond(400, { error: 'invalid url' }); return; }

      if (u.pathname === '/health') {
        var highRiskVisitors = 0; var lockedSessions = 0;
        VISITOR_STORE.forEach(function(v) { if (v.risk > 0.5) highRiskVisitors++; });
        SESSION_STORE.forEach(function(s) { if (s.locked) lockedSessions++; });
        respond(200, { status: 'ok', mode: 'proxy', layers: { L1: !!embeddingRefs, L2: true, L3: true, L4: true },
          metrics: self.auditEngine.getMetrics(),
          visitors: { total: VISITOR_STORE.size, highRisk: highRiskVisitors },
          sessions: { total: SESSION_STORE.size, locked: lockedSessions },
        });
        return;
      }
      if (u.pathname === '/metrics') { respond(200, self.auditEngine.getMetrics()); return; }
      if (u.pathname === '/audit') { respond(200, self.auditEngine.recent(parseInt(u.searchParams.get('limit') || '100'))); return; }
      if (u.pathname === '/visitors') {
        var list = []; VISITOR_STORE.forEach(function(v) { list.push({ id: v.id, risk: v.risk, sessions: v.sessionCount, blocked: v.blockedCount, tags: v.tags, identities: v.identities }); });
        respond(200, { total: VISITOR_STORE.size, visitors: list.sort(function(a, b) { return b.risk - a.risk; }).slice(0, 50) });
        return;
      }

      // 身份搜索: /identities?q=ip/email/userId
      if (u.pathname === '/identities') {
        var q = u.searchParams.get('q') || '';
        respond(200, { query: q, total: VISITOR_STORE.size, results: searchIdentities(q) });
        return;
      }

      function readBody(req, cb) {
        var buf = '', done = false;
        req.on('data', function(c) {
          if (done) return;
          if (buf.length + c.length > MAX_BODY_SIZE) {
            done = true; req.pause();
            try { res.writeHead(413, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'body_too_large', maxSize: MAX_BODY_SIZE })); } catch(e) {}
            return;
          }
          buf += c;
        });
        req.on('end', function() { if (!done) cb(buf); });
      }

      if (u.pathname === '/inspect' && req.method === 'POST') {
        readBody(req, function(body) { try { (async function() { var r = await self.inspect(JSON.parse(body)); respond(r.allowed ? 200 : 403, r); })(); } catch(e) { respond(400, { error: e.message }); } });
        return;
      }

      if (u.pathname === '/sandbox/create' && req.method === 'POST') {
        readBody(req, function(body) { try { var cfg = JSON.parse(body); var sb = self.sandboxManager.createSandbox(cfg.id, cfg.config); respond(200, { id: sb.id, state: sb.state }); } catch(e) { respond(400, { error: e.message }); } });
        return;
      }

      if (u.pathname === '/feedback' && req.method === 'POST') {
        readBody(req, function(body) { try { var fb = JSON.parse(body); var r = self.feedback(fb.requestId, fb.outcome, fb.text); respond(200, r); } catch(e) { respond(400, { error: e.message }); } });
        return;
      }

      // 数据分类查询
      if (u.pathname === '/classify' && req.method === 'POST') {
        readBody(req, function(body) { try { var q = JSON.parse(body); var level = classifyPath(q.path || ''); if (q.content) { var cl = scanContent(q.content); if ({P0:0,P1:1,P2:2,P3:3,P4:4}[cl] < {P0:0,P1:1,P2:2,P3:3,P4:4}[level]) level = cl; } respond(200, { path: q.path, classification: level, decision: dataDecision(level) }); } catch(e) { respond(400, { error: e.message }); } });
        return;
      }

      // ================================================================
      // P2: Output Monitoring — /proxy/llm
      //   1. Input safety check (existing inspect)
      //   2. Forward to LLM
      //   3. Output safety check (new inspectOutput)
      // ================================================================
      if (u.pathname === '/proxy/llm' && req.method === 'POST') {
        readBody(req, async function(body) {
          try {
            var reqData = JSON.parse(body);
            var prompt = reqData.prompt || reqData.messages?.[reqData.messages.length-1]?.content || '';
            var sessionId = reqData.session_id || 'llm-proxy';
            var llmUrl = reqData.llm_url || 'http://localhost:4000/v1/chat/completions';
            var visitorId = reqData.visitor_id || null;

            // Step 1: Input safety check
            var inputResult = await self.inspect({
              type: 'chat', tool: 'llm', args: prompt,
              session_id: sessionId, visitor_id: visitorId,
            });

            if (!inputResult.allowed) {
              respond(403, {
                error: 'input_blocked',
                reason: inputResult.reason,
                layer: inputResult.layer,
                isInputBlock: true,
              });
              return;
            }

            // Step 2: Forward to LLM
            var llmBody = JSON.stringify({
              model: reqData.model || 'MiniMax-M2.7-highspeed',
              messages: reqData.messages || [{ role: 'user', content: prompt }],
              max_tokens: reqData.max_tokens || 512,
              stream: false,
            });

            var llmResponse = await new Promise(function(resolve, reject) {
              var llmReq = httpRequest(llmUrl, { method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  'Content-Length': Buffer.byteLength(llmBody),
                  ...(reqData.api_key ? { 'Authorization': 'Bearer ' + reqData.api_key } : {}),
                },
              }, function(llmRes) {
                var d = '';
                llmRes.on('data', function(c) { d += c; });
                llmRes.on('end', function() {
                  try { resolve(JSON.parse(d)); }
                  catch(e) { reject(new Error('LLM parse error: ' + e.message)); }
                });
              });
              llmReq.on('error', function(e) { reject(e); });
              llmReq.setTimeout(30000, function() { llmReq.destroy(); reject(new Error('LLM timeout')); });
              llmReq.write(llmBody);
              llmReq.end();
            });

            // Extract text from LLM response
            var outputText = '';
            if (llmResponse.choices && llmResponse.choices[0]) {
              outputText = llmResponse.choices[0].message?.content ||
                           llmResponse.choices[0].text || '';
            } else if (llmResponse.content) {
              outputText = typeof llmResponse.content === 'string' ? llmResponse.content :
                          (llmResponse.content[0]?.text || '');
            } else if (llmResponse.response) {
              outputText = llmResponse.response;
            }

            // Step 3: Output safety check (P2)
            var outputResult = await self.inspectOutput(outputText);

            if (outputResult.block) {
              respond(403, {
                error: 'output_blocked',
                reason: 'output_unsafe',
                outputScore: outputResult.score,
                outputThreshold: outputResult.threshold,
                isInputBlock: false,
                llmPreview: outputText.slice(0, 100),
              });
              return;
            }

            // Step 4: Both passed — return LLM response with safety metadata
            respond(200, {
              ...llmResponse,
              safety: {
                inputAllowed: true,
                inputLayer: inputResult.layer,
                inputRisk: inputResult.risk,
                outputScore: outputResult.score,
                outputHarmful: outputResult.harmful,
                outputPassed: !outputResult.block,
              },
            });

          } catch(e) {
            respond(500, { error: 'proxy_error', message: e.message });
          }
        });
        return;
      }

      respond(404, { error: 'unknown', endpoints: ['/health', '/metrics', '/audit', '/inspect', '/sandbox/create', '/feedback', '/classify', '/visitors', '/identities', '/proxy/llm'] });
    });

    this.server.listen(port, function() { console.error('[Shield] Running on :' + port + ' (4 layers)'); });
    return this.server;
  }

  stop() { if (this.server) { this.server.close(); this.server = null; } }
}

// ============================================================================
// CLI
// ============================================================================

var args = process.argv.slice(2);
if (args.length > 0 && !args[0].startsWith('--')) {
  var opts = { port: 8080 };
  for (var i = 0; i < args.length; i++) { if (args[i] === '--port') opts.port = parseInt(args[++i]) || 8080; else if (args[i] === '--policies') opts.policyDir = resolve(args[++i]); }
  var shield = new Shield(opts);
  shield.startProxy(opts.port);
}

export default Shield;
export function setEmbeddingReady(v) { EMBEDDING_SERVER_READY = !!v; }
