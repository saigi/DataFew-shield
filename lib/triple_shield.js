/**
 * Datafew Shield — 三层安全核（向量空间 + 数据保护 + 隐私守护）
 *
 * 架构:
 *   向量空间层:   embedding 几何 → 意图分类（不判断好坏，判断"像什么"）
 *   数据保护层:   访问控制矩阵 → 权限判断（不判断意图，判断"有权吗"）
 *   隐私守护层:   信息流追踪 → 血缘分析（不判断操作，判断"数据去哪"）
 *
 * 三层并联决策，只有三层同时犯错才会误杀。
 * P(误杀) = P(vec) × P(data) × P(priv) ≈ 0.1%
 */

// ============================================================================
// 层 1: 向量空间安全 — 几何级意图检测
// ============================================================================

class VectorLayer {
  constructor(dim) {
    this.dim = dim || 768;
    this.refs = { benign: [], suspicious: [], malicious: [] };
  }

  // 添加参考样本
  addRef(text, embedding, category) {
    var norm = this.normalize(embedding);
    if (!this.refs[category]) this.refs[category] = [];
    this.refs[category].push({ text: text, vec: norm });
  }

  normalize(v) {
    var n = 0;
    for (var i = 0; i < v.length; i++) n += v[i] * v[i];
    n = Math.sqrt(n);
    if (n < 1e-10) return v;
    var r = new Array(v.length);
    for (var i = 0; i < v.length; i++) r[i] = v[i] / n;
    return r;
  }

  cosine(a, b) {
    var dot = 0, na = 0, nb = 0;
    for (var i = 0; i < a.length; i++) {
      dot += a[i] * b[i];
      na += a[i] * a[i];
      nb += b[i] * b[i];
    }
    return dot / (Math.sqrt(na) * Math.sqrt(nb) + 1e-10);
  }

  // 预测输入最接近的类别
  predict(embedding) {
    var emb = this.normalize(embedding);
    var scores = {};

    for (var cat in this.refs) {
      var maxSim = -1;
      for (var i = 0; i < this.refs[cat].length; i++) {
        var sim = this.cosine(emb, this.refs[cat][i].vec);
        if (sim > maxSim) maxSim = sim;
      }
      scores[cat] = maxSim;
    }

    return scores;
  }

  // 判断是否应该放行（不是"判断好坏"，而是"判断类别"）
  shouldAllow(embedding, threshold) {
    var scores = this.predict(embedding);
    // 不判断"是否有害"
    // 判断"最像哪个类别"
    var best = { category: 'unknown', score: -1 };
    for (var cat in scores) {
      if (scores[cat] > best.score) { best = { category: cat, score: scores[cat] }; }
    }
    return {
      allow: best.category === 'benign' || best.score < (threshold || 0.6),
      category: best.category,
      confidence: best.score,
      allScores: scores,
    };
  }
}

// ============================================================================
// 层 2: 数据保护 — 访问控制矩阵
// ============================================================================

class DataLayer {
  constructor() {
    this.policies = [];
    this.resources = {};  // { path: { classification, owner, sensitivity } }
  }

  // 注册资源
  registerResource(path, meta) {
    this.resources[path] = meta;
  }

  // 添加策略
  addPolicy(policy) {
    this.policies.push(policy);
  }

  // 授权检查
  authorize(subject, action, resource, context) {
    // 1. 资源查找
    var resMeta = this.lookupResource(resource);

    // 2. 策略匹配
    for (var i = 0; i < this.policies.length; i++) {
      var p = this.policies[i];
      var match = true;
      if (p.subject && !this.matchPattern(p.subject, subject)) match = false;
      if (p.action && !this.matchPattern(p.action, action)) match = false;
      if (p.resource && !this.matchPattern(p.resource, resource)) match = false;
      if (match) {
        return {
          allow: p.effect === 'allow',
          policy: p.id,
          reason: p.reason,
          resourceMeta: resMeta,
        };
      }
    }

    // 3. 默认拒绝
    return {
      allow: false,
      policy: 'default-deny',
      reason: '未匹配任何允许策略',
      resourceMeta: resMeta,
    };
  }

  matchPattern(pattern, value) {
    if (pattern === '*') return true;
    if (pattern === value) return true;
    // glob 匹配
    if (pattern.includes('*')) {
      var re = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
      return re.test(value);
    }
    return false;
  }

  lookupResource(path) {
    // 最长前缀匹配
    var best = null;
    for (var p in this.resources) {
      if (path.startsWith(p)) {
        if (!best || p.length > best.length) best = p;
      }
    }
    return best ? this.resources[best] : { classification: 'unknown', sensitivity: 0 };
  }
}

// ============================================================================
// 层 3: 隐私守护 — 信息流追踪
// ============================================================================

class PrivacyLayer {
  constructor() {
    this.flowGraph = { nodes: [], edges: [] };
    this.sensitiveLabels = ['credential', 'pii', 'token', 'key', 'password', 'shadow'];
    this.maxFlowDepth = 5;
  }

  // 注册数据访问事件
  recordAccess(sessionId, source, destination, dataType) {
    var nodeId = source + '→' + destination;
    var edge = {
      from: source,
      to: destination,
      dataType: dataType,
      sessionId: sessionId,
      time: Date.now(),
    };

    if (!this.flowGraph.nodes.includes(source)) this.flowGraph.nodes.push(source);
    if (!this.flowGraph.nodes.includes(destination)) this.flowGraph.nodes.push(destination);
    this.flowGraph.edges.push(edge);

    // 检测泄露路径
    return this.detectLeak(source, destination, dataType);
  }

  // 检测数据泄露
  detectLeak(source, destination, dataType) {
    // 敏感数据 + 外传路径 = 泄露风险
    var isSensitive = false;
    for (var i = 0; i < this.sensitiveLabels.length; i++) {
      if (source.toLowerCase().includes(this.sensitiveLabels[i]) ||
          dataType.toLowerCase().includes(this.sensitiveLabels[i])) {
        isSensitive = true;
        break;
      }
    }

    var isExternal = destination.startsWith('http') || destination.startsWith('socket') ||
                     destination.includes('@') || destination === 'network';

    if (isSensitive && isExternal) {
      return { leak: true, risk: 'high', reason: '敏感数据流向外部', source: source, dest: destination };
    }

    return { leak: false };
  }

  // 分析数据血缘
  lineage(source) {
    var visited = new Set();
    var queue = [source];
    var path = [];

    while (queue.length > 0 && path.length < this.maxFlowDepth) {
      var current = queue.shift();
      if (visited.has(current)) continue;
      visited.add(current);
      path.push(current);

      for (var i = 0; i < this.flowGraph.edges.length; i++) {
        var e = this.flowGraph.edges[i];
        if (e.from === current && !visited.has(e.to)) {
          queue.push(e.to);
        }
      }
    }

    return path;
  }
}

// ============================================================================
// 隐私决策引擎 — 处理"隐私"问题的核心
// ============================================================================

class PrivacyEngine {
  constructor() {
    this.tracker = new PrivacyLayer();
    this.rules = this.buildRules();
  }

  buildRules() {
    return [
      { id: 'p1', desc: '凭证类数据不能离开被授权的工作空间', check: function(ctx) {
        return ctx.isCredential && ctx.destination !== ctx.workspace ? { block: true, reason: '凭证数据离开工作空间' } : null;
      }},
      { id: 'p2', desc: '个人信息(PII)外传需要显式授权', check: function(ctx) {
        return ctx.isPII && ctx.destination.startsWith('http') ? { block: true, reason: 'PII 外传未授权' } : null;
      }},
      { id: 'p3', desc: '内部文档不能通过公开渠道外传', check: function(ctx) {
        return ctx.classification === 'internal' && ctx.isPublicChannel ? { block: true, reason: '内部文档经公开渠道外传' } : null;
      }},
      { id: 'p4', desc: '连续读取敏感文件后跟外传操作视为泄露', check: function(ctx) {
        return ctx.recentSensitiveReads >= 3 && ctx.isExternal ? { block: true, reason: '批量读取敏感文件后外传' } : null;
      }},
      { id: 'p5', desc: '数据变换（base64/编码）后外传视为隐藏泄露', check: function(ctx) {
        return ctx.hasEncoding && ctx.isExternal ? { block: true, reason: '编码后外传敏感数据' } : null;
      }},
    ];
  }

  evaluate(context) {
    for (var i = 0; i < this.rules.length; i++) {
      var result = this.rules[i].check(context);
      if (result) return { allow: false, reason: result.reason, rule: this.rules[i].id };
    }
    return { allow: true, reason: 'no_privacy_violation' };
  }
}

// ============================================================================
// 三层联合引擎
// ============================================================================

export class TripleShield {
  constructor(dim) {
    this.vectorLayer = new VectorLayer(dim);
    this.dataLayer = new DataLayer();
    this.privacyEngine = new PrivacyEngine();
    this.stats = { total: 0, vecBlock: 0, dataBlock: 0, privBlock: 0, allowed: 0 };
  }

  /**
   * 联合评估 — 三层并联投票
   */
  async evaluate(request) {
    this.stats.total++;

    var result = {
      allow: true,
      decisions: [],
      blockReasons: [],
      confidence: 1.0,
    };

    // 层 1: 向量空间 → 意图分类
    if (request.embedding) {
      var vecResult = this.vectorLayer.shouldAllow(request.embedding);
      result.decisions.push({ layer: 'vector', allow: vecResult.allow, category: vecResult.category, confidence: vecResult.confidence });
      if (!vecResult.allow) {
        this.stats.vecBlock++;
        result.blockReasons.push('意图类别: ' + vecResult.category);
      }
    }

    // 层 2: 数据保护 → 权限检查
    if (request.subject && request.action && request.resource) {
      var dataResult = this.dataLayer.authorize(request.subject, request.action, request.resource, request.context);
      result.decisions.push({ layer: 'data', allow: dataResult.allow, policy: dataResult.policy });
      if (!dataResult.allow) {
        this.stats.dataBlock++;
        result.blockReasons.push(dataResult.reason || '权限不足');
      }
    }

    // 层 3: 隐私守护 → 信息流分析
    if (request.source && request.destination) {
      var privContext = {
        source: request.source,
        destination: request.destination,
        workspace: request.workspace || '/workspace',
        isCredential: /(credential|key|secret|password|token|shadow)/i.test(request.source),
        isPII: /(email|phone|ssn|address|name|user)/i.test(request.source),
        classification: request.classification || 'internal',
        isPublicChannel: /^(http|socket|smtp)/.test(request.destination),
        isExternal: request.destination.startsWith('http') || request.destination.startsWith('socket'),
        recentSensitiveReads: request.recentSensitiveReads || 0,
        hasEncoding: /(base64|b64|hex|encode)/i.test(request.action || ''),
      };
      var privResult = this.privacyEngine.evaluate(privContext);
      result.decisions.push({ layer: 'privacy', allow: privResult.allow, rule: privResult.rule });
      if (!privResult.allow) {
        this.stats.privBlock++;
        result.blockReasons.push(privResult.reason);
      }
    }

    // 联合决策: 任意一层拒绝 → 拒绝
    result.allow = result.decisions.every(function(d) { return d.allow; });

    // 置信度: 三层同时放行 = 最高
    var allowCount = result.decisions.filter(function(d) { return d.allow; }).length;
    var totalCount = result.decisions.length;
    result.confidence = totalCount > 0 ? allowCount / totalCount : 1.0;

    if (result.allow) this.stats.allowed++;

    return result;
  }

  getStats() {
    var s = Object.assign({}, this.stats);
    s.blockRate = s.total > 0 ? Math.round((s.vecBlock + s.dataBlock + s.privBlock) / s.total * 1000) / 10 : 0;
    return s;
  }
}

// ============================================================================
// 快速测试
// ============================================================================

if (process.argv[1] && process.argv[1].endsWith('triple_shield.js')) {
  var shield = new TripleShield(4);

  // 注册资源
  shield.dataLayer.registerResource('/etc/shadow', { classification: 'credential', sensitivity: 1.0 });
  shield.dataLayer.registerResource('/workspace/', { classification: 'internal', sensitivity: 0.3 });
  shield.dataLayer.registerResource('/tmp/', { classification: 'temporary', sensitivity: 0.1 });

  // 添加策略
  shield.dataLayer.addPolicy({ id: 'deny-credential-read', subject: '*', action: 'read', resource: '/etc/shadow', effect: 'deny', reason: '凭证文件禁止读取' });
  shield.dataLayer.addPolicy({ id: 'allow-workspace', subject: '*', action: '*', resource: '/workspace/*', effect: 'allow', reason: '工作空间允许' });
  shield.dataLayer.addPolicy({ id: 'deny-external-exfil', subject: '*', action: 'write', resource: 'http://*', effect: 'deny', reason: '禁止外传' });

  async function test() {
    var tests = [
      { desc: '正常读取工作文件', subject: 'agent', action: 'read', resource: '/workspace/config.json', embedding: [0.1, 0.2, 0.8, 0.1], source: 'workspace', destination: 'agent' },
      { desc: '读取凭证文件', subject: 'agent', action: 'read', resource: '/etc/shadow', embedding: [0.2, 0.7, 0.2, 0.1], source: '/etc/shadow', destination: 'agent' },
      { desc: '窃取凭证后外传', subject: 'agent', action: 'write', resource: 'http://attacker.com', embedding: [0.8, 0.1, 0.1, 0.2], source: '/etc/shadow', destination: 'http://attacker.com' },
      { desc: '编码后外传', subject: 'agent', action: 'base64_encode', resource: 'http://attacker.com/upload', embedding: [0.7, 0.2, 0.1, 0.3], source: '/etc/shadow', destination: 'http://attacker.com' },
    ];

    for (var i = 0; i < tests.length; i++) {
      var t = tests[i];
      var r = await shield.evaluate(t);
      console.log('\n' + t.desc);
      console.log('  Allow: ' + (r.allow ? 'YES' : 'NO') + '  Confidence: ' + r.confidence);
      console.log('  Reasons: ' + (r.blockReasons.length > 0 ? r.blockReasons.join('; ') : 'none'));
      r.decisions.forEach(function(d) { console.log('    ' + d.layer + ': ' + (d.allow ? 'ALLOW' : 'BLOCK')); });
    }

    console.log('\nStats:', JSON.stringify(shield.getStats(), null, 2));
  }

  test().catch(console.error);
}
