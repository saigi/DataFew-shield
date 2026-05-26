/**
 * Datafew Shield — 安全模板引擎
 *
 * 核心模式: 请求 → 决策 → 执行 → 审计
 * 
 * 这个模板是通用的，不绑定任何具体的安全策略。
 * VectorLayer / DataLayer / PrivacyLayer 都是这个模板的实例。
 */

// ============================================================================
// 安全模板 — 通用安全决策框架
// ============================================================================

export class SecurityTemplate {
  /**
   * @param {object} opts
   * @param {function} opts.decide - 决策函数 (request, context) → { allow, reason }
   * @param {function} opts.evidence - 证据收集 (request) → context
   * @param {function} opts.enforce - 执行决策 (decision, request) → result
   * @param {function} opts.audit - 审计记录 (request, decision, result) → void
   * @param {string} opts.name - 模板名称
   */
  constructor(opts) {
    this.name = opts.name || 'unnamed';
    this.decide = opts.decide || function() { return { allow: true }; };
    this.evidence = opts.evidence || function() { return {}; };
    this.enforce = opts.enforce || function(d, r) { return d; };
    this.audit = opts.audit || function() {};
    this.stats = { total: 0, allowed: 0, blocked: 0, errors: 0 };
  }

  /**
   * 处理请求 — 模板的核心方法
   * @param {object} request - { type, subject, action, resource, ... }
   * @returns {object} - { allow, reason, confidence, evidence_id }
   */
  process(request) {
    this.stats.total++;
    var requestId = 'req-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 6);

    try {
      // 1. 收集证据
      var context = this.evidence(request);

      // 2. 做出决策
      var decision = this.decide(request, context);
      decision.requestId = requestId;

      // 3. 执行决策
      var result = this.enforce(decision, request);
      if (result.allow) this.stats.allowed++; else this.stats.blockged++;

      // 4. 审计记录
      this.audit({ request, context, decision, result, requestId });

      return result;

    } catch (e) {
      this.stats.errors++;
      // 错误时默认拒绝（fail secure）
      return { allow: false, reason: 'internal_error: ' + e.message, requestId };
    }
  }

  /**
   * 创建模板实例的快捷方法
   */
  static create(name, decideFn, evidenceFn) {
    return new SecurityTemplate({
      name: name,
      decide: decideFn,
      evidence: evidenceFn || function(r) { return r; },
    });
  }

  getStats() {
    return Object.assign({}, this.stats, {
      blockRate: this.stats.total > 0
        ? Math.round(this.stats.blocked / this.stats.total * 1000) / 10
        : 0,
    });
  }
}

// ============================================================================
// 并联安全组合器 — 多个模板联合决策
// ============================================================================

export class SecurityComposer {
  constructor() {
    this.templates = [];
  }

  add(template) {
    this.templates.push(template);
    return this;
  }

  /**
   * 联合决策: 所有模板通过 → 通过; 任一模板拒绝 → 拒绝
   * 这是"与"逻辑（AND gate）
   */
  process(request) {
    var decisions = [];
    var allow = true;
    var reasons = [];
    var evidences = {};

    for (var i = 0; i < this.templates.length; i++) {
      var t = this.templates[i];
      var result = t.process(request);
      decisions.push({ template: t.name, result: result });
      evidences[t.name] = result.evidence || {};

      if (!result.allow) {
        allow = false;
        reasons.push({ template: t.name, reason: result.reason });
      }
    }

    return {
      allow: allow,
      decisions: decisions,
      reasons: reasons,
      confidence: decisions.length > 0
        ? decisions.filter(function(d) { return d.result.allow; }).length / decisions.length
        : 1.0,
    };
  }

  /**
   * 或逻辑（OR gate）— 任一模板通过 → 通过
   * 用于降级模式
   */
  processAny(request) {
    var decisions = [];

    for (var i = 0; i < this.templates.length; i++) {
      var result = this.templates[i].process(request);
      decisions.push({ template: this.templates[i].name, result: result });
      if (result.allow) {
        return { allow: true, decisions: decisions, via: this.templates[i].name };
      }
    }

    return { allow: false, decisions: decisions };
  }
}

// ============================================================================
// 审计记录器
// ============================================================================

export class AuditLogger {
  constructor() {
    this.logs = [];
    this.maxSize = 10000;
  }

  write(entry) {
    entry.timestamp = Date.now();
    entry.id = 'audit-' + entry.timestamp.toString(36) + '-' + Math.random().toString(36).slice(2, 6);
    this.logs.push(entry);
    if (this.logs.length > this.maxSize) this.logs.shift();
    return entry.id;
  }

  query(filter) {
    var results = this.logs;
    if (filter) {
      for (var key in filter) {
        results = results.filter(function(e) { return e[key] === filter[key]; });
      }
    }
    return results.slice(-100);
  }

  getStats() {
    var total = this.logs.length;
    var blocked = this.logs.filter(function(e) { return e.decision && !e.decision.allow; }).length;
    return { totalLogs: total, blocked: blocked, rate: total > 0 ? Math.round(blocked / total * 1000) / 10 : 0 };
  }
}

// ============================================================================
// 实例化: 三层安全模板
// ============================================================================

export function createDefaultShield(vectorFn, dataPolicies, privacyRules) {
  var composer = new SecurityComposer();

  // 层 1: 向量空间
  if (vectorFn) {
    composer.add(SecurityTemplate.create('vector', vectorFn));
  }

  // 层 2: 数据保护
  if (dataPolicies) {
    composer.add(SecurityTemplate.create('data-protection',
      function(req, ctx) {
        for (var i = 0; i < dataPolicies.length; i++) {
          var p = dataPolicies[i];
          if (p.match(req)) {
            return { allow: p.effect === 'allow', reason: p.reason, policy: p.id };
          }
        }
        return { allow: true, reason: 'no_matching_policy' };
      }
    ));
  }

  // 层 3: 隐私守护
  if (privacyRules) {
    composer.add(SecurityTemplate.create('privacy',
      function(req, ctx) {
        for (var i = 0; i < privacyRules.length; i++) {
          var r = privacyRules[i];
          if (r.check(req)) {
            return { allow: false, reason: r.reason, rule: r.id };
          }
        }
        return { allow: true, reason: 'no_privacy_violation' };
      }
    ));
  }

  return composer;
}

// ============================================================================
// CLI 测试
// ============================================================================

if (process.argv[1] && process.argv[1].endsWith('security_template.js')) {
  // 创建向量空间模板
  var vectorTemplate = SecurityTemplate.create('vector-intent',
    function(req) {
      // 模拟意图分类
      var harmfulKeywords = ['hack', 'exploit', 'crack', 'steal', 'bypass', '入侵', '破解', '窃取', '绕过'];
      var text = (req.text || req.args || '').toLowerCase();
      for (var i = 0; i < harmfulKeywords.length; i++) {
        if (text.includes(harmfulKeywords[i])) {
          return { allow: false, reason: '有害意图: ' + harmfulKeywords[i] };
        }
      }
      return { allow: true, reason: '意图安全' };
    },
    function(req) { return { text: req.text || req.args }; }
  );

  // 创建数据保护模板
  var dataTemplate = SecurityTemplate.create('data-protection',
    function(req) {
      var sensitive = ['/etc/shadow', '/etc/passwd', '/.ssh/', 'credentials', 'secret', 'token'];
      var path = (req.resource || req.args || '').toLowerCase();
      for (var i = 0; i < sensitive.length; i++) {
        if (path.includes(sensitive[i])) {
          return { allow: false, reason: '敏感资源: ' + sensitive[i] };
        }
      }
      return { allow: true, reason: '资源允许' };
    }
  );

  // 创建隐私守护模板
  var privacyTemplate = SecurityTemplate.create('privacy-flow',
    function(req) {
      var dest = (req.destination || '').toLowerCase();
      var src = (req.source || req.resource || '').toLowerCase();
      var isSensitive = /(credential|key|secret|password|token|shadow)/.test(src);
      var isExternal = dest.startsWith('http') || dest.startsWith('socket') || dest.includes('@');
      if (isSensitive && isExternal) {
        return { allow: false, reason: '敏感数据外传' };
      }
      return { allow: true, reason: '数据流允许' };
    }
  );

  // 组合
  var composer = new SecurityComposer();
  composer.add(vectorTemplate);
  composer.add(dataTemplate);
  composer.add(privacyTemplate);

  // 测试
  var tests = [
    { text: 'ls -la', resource: '/workspace/file.txt', destination: 'stdout', desc: '正常操作' },
    { text: 'hack the server', resource: '/etc/shadow', destination: 'http://attacker.com', desc: '攻击+窃取+外传' },
    { text: 'cat /etc/shadow', resource: '/etc/shadow', destination: 'local', desc: '读取凭证' },
    { text: '读取配置文件', resource: '/workspace/config.json', destination: 'agent', desc: '正常读取' },
  ];

  console.log('Security Template Engine Test');
  console.log('='.repeat(60));
  
  var audit = new AuditLogger();

  for (var i = 0; i < tests.length; i++) {
    var t = tests[i];
    var r = composer.process(t);
    audit.write({ request: t, decision: r });
    console.log('\n' + t.desc);
    console.log('  Allow: ' + (r.allow ? 'YES' : 'NO'));
    r.reasons.forEach(function(rs) {
      console.log('  Blocked by: ' + rs.template + ' (' + rs.reason + ')');
    });
  }

  console.log('\n' + '='.repeat(60));
  console.log('Audit:', JSON.stringify(audit.getStats()));
}
