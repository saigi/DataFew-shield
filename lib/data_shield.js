/**
 * Datafew Shield — 核心数据标记与访问控制
 *
 * 哲学: 不判断"是否恶意"，只判断"是否有权"。
 * 
 * 数据分类:
 *   P0: 凭证明文 (密码/key/token)            → 任何读取都拒绝
 *   P1: 个人隐私 (PII/手机/地址)              → 需明确授权
 *   P2: 财务数据 (银行卡/支付/交易)            → 需明确授权
 *   P3: 内部文档 (代码/配置/策略)              → 工作空间内允许
 *   P4: 公开数据 (公开文档/开源代码)          → 允许
 *
 * 每条数据被标记后，任何试图访问的操作都会被拦截或弹出授权。
 */

// ============================================================================
// 1. 数据标记注册表
// ============================================================================

const CLASSIFICATION = {
  CREDENTIAL: 'credential',
  PII: 'pii',
  FINANCIAL: 'financial',
  INTERNAL: 'internal',
  PUBLIC: 'public',
};

class DataRegistry {
  constructor() {
    this.resources = [];      // 已注册的资源
    this.patterns = [];       // 自动匹配模式
    this.initDefaultPatterns();
  }

  initDefaultPatterns() {
    // P0: 凭证
    this.register(CLASSIFICATION.CREDENTIAL, [
      '/etc/shadow', '/etc/passwd', '/etc/security/',
      '~/.ssh/id_rsa', '~/.ssh/id_ecdsa', '~/.ssh/id_ed25519',
      '~/.ssh/authorized_keys', '~/.ssh/config',
      '~/.aws/credentials', '~/.aws/config',
      '~/.gcloud/', '~/.kube/config',
      '**/credentials.json', '**/service-account.json',
      '**/*.pem', '**/*key*', '**/secret*',
    ]);

    // P1: 个人隐私
    this.register(CLASSIFICATION.PII, [
      '**/users.csv', '**/customer*.csv',
      '**/employee*.xlsx', '**/personal*.json',
      '**/phone*.txt', '**/address*.csv',
    ]);

    // P2: 财务数据
    this.register(CLASSIFICATION.FINANCIAL, [
      '**/payment*.csv', '**/transaction*.csv',
      '**/invoice*.pdf', '**/bank*.xlsx',
      '**/financial*.json',
    ]);

    // P3: 内部文档
    this.register(CLASSIFICATION.INTERNAL, [
      '/workspace/**', '/project/**', '/src/**',
      '**/*.env', '**/config.*',
      '**/Dockerfile', '**/docker-compose.yml',
      '**/*.yaml', '**/*.yml', '**/*.tf',
    ]);

    // 动态模式（关键词匹配文件内容）
    this.patterns.push(
      { level: 'P0', name: 'password_in_content', patterns: ['password=', 'PASSWORD=', 'DB_PASSWORD', 'passwd:', 'pwd:'], severity: 'critical' },
      { level: 'P0', name: 'api_key_in_content', patterns: ['api_key', 'API_KEY', 'apiKey', 'secret_key', 'SECRET_KEY', 'sk-'], severity: 'critical' },
      { level: 'P0', name: 'token_in_content', patterns: ['token=', 'TOKEN=', 'auth_token', 'bearer '], severity: 'high' },
      { level: 'P1', name: 'email_content', patterns: ['@gmail.com', '@outlook.com', '@qq.com', '@163.com'], severity: 'medium' },
      { level: 'P1', name: 'phone_content', patterns: ['1[3-9]\\d{9}', '手机号', '联系电话'], severity: 'medium' },
      { level: 'P2', name: 'card_content', patterns: ['银行卡', '信用卡', 'card_number', 'cvv', '银行账户'], severity: 'high' },
    );
  }

  register(classification, globs) {
    for (var i = 0; i < globs.length; i++) {
      this.resources.push({
        classification: classification,
        glob: this.globToRegex(globs[i]),
        original: globs[i],
        registered: Date.now(),
      });
    }
  }

  globToRegex(glob) {
    const re = glob
      .replace(/\*\*/g, '<<DOUBLE_STAR>>')
      .replace(/\*/g, '[^/]*')
      .replace(/<<DOUBLE_STAR>>/g, '.*')
      .replace(/\?/g, '.')
      .replace(/\./g, '\\.');
    return new RegExp('^' + re + '$', 'i');
  }

  /**
   * 查询资源分类
   */
  classify(path) {
    for (var i = 0; i < this.resources.length; i++) {
      if (this.resources[i].glob.test(path)) {
        return {
          classification: this.resources[i].classification,
          level: this.levelOf(this.resources[i].classification),
          matchedBy: this.resources[i].original,
        };
      }
    }
    return { classification: CLASSIFICATION.PUBLIC, level: 4 };
  }

  /**
   * 内容级检测（扫描文件内容中的敏感模式）
   */
  scanContent(content) {
    if (!content || typeof content !== 'string') return [];
    const matches = [];
    for (var i = 0; i < this.patterns.length; i++) {
      for (var j = 0; j < this.patterns[i].patterns.length; j++) {
        try {
          const re = new RegExp(this.patterns[i].patterns[j], 'i');
          if (re.test(content)) {
            matches.push({ level: this.patterns[i].level, name: this.patterns[i].name, severity: this.patterns[i].severity });
            break;
          }
        } catch(e) { /* invalid regex */ }
      }
    }
    return matches;
  }

  levelOf(classification) {
    const levels = { credential: 0, pii: 1, financial: 2, internal: 3, public: 4 };
    return levels[classification] !== undefined ? levels[classification] : 4;
  }
}

// ============================================================================
// 2. 访问控制授权器
// ============================================================================

class AccessController {
  constructor() {
    this.registry = new DataRegistry();
    this.pendingApprovals = new Map();  // sessionId → { resource, action, callback }
    this.approvalTimeout = 30000;       // 30s 超时
  }

  /**
   * 检查访问权限
   *
   * @param {string} sessionId - 会话ID
   * @param {string} action - read/write/delete/execute
   * @param {string} resource - 资源路径
   * @param {string} content - 文件内容（可选，用于内容扫描）
   * @returns {object} { allow, reason, requiresApproval, suggestedAction }
   */
  check(sessionId, action, resource, content) {
    // 1. 路径分类
    const classification = this.registry.classify(resource);

    // 2. 内容扫描（如果有内容）
    const contentMatches = content ? this.registry.scanContent(content) : [];

    // 3. 计算风险等级
    let riskLevel = classification.level;
    if (contentMatches.length > 0) {
      const minLevel = Math.min.apply(null, contentMatches.map(function(m) { return { critical: 0, high: 1, medium: 2 }[m.severity] || 3; }));
      riskLevel = Math.min(riskLevel, minLevel);
    }

    // 4. 决策矩阵
    if (riskLevel === 0) {
      return { allowed: false, reason: 'credential_access_denied', riskLevel: 0, classification: classification.classification };
    }
    if (riskLevel === 1 || riskLevel === 2) {
      return {
        allowed: false,
        requiresApproval: true,
        reason: 'sensitive_data_access',
        riskLevel: riskLevel,
        classification: classification.classification,
        suggestedAction: 'prompt_approval',
      };
    }
    if (riskLevel === 3) {
      return { allowed: true, reason: 'internal_allowed', riskLevel: 3, classification: classification.classification };
    }
    return { allowed: true, reason: 'public_allowed', riskLevel: 4, classification: classification.classification };
  }

  /**
   * 发起授权请求
   */
  requestApproval(sessionId, action, resource, riskLevel) {
    return new Promise(function(resolve, reject) {
      const approvalId = 'app-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 6);

      const pending = {
        id: approvalId,
        sessionId: sessionId,
        action: action,
        resource: resource,
        riskLevel: riskLevel,
        time: Date.now(),
        timeout: setTimeout(function() {
          this.pendingApprovals.delete(sessionId);
          resolve({ allowed: false, reason: 'approval_timeout' });
        }, this.approvalTimeout),
        resolve: resolve,
      };

      this.pendingApprovals.set(sessionId, pending);

      // 触发授权弹窗（外部系统接管）
      this.onApprovalRequested(pending);
    });
  }

  /**
   * 处理授权结果
   */
  handleApproval(sessionId, approved) {
    const pending = this.pendingApprovals.get(sessionId);
    if (!pending) return { error: 'no_pending_approval' };
    clearTimeout(pending.timeout);
    this.pendingApprovals.delete(sessionId);
    pending.resolve({ allowed: approved, reason: approved ? 'user_approved' : 'user_denied' });
    return { ok: true };
  }

  onApprovalRequested(pending) {
    // 外部系统需重写此方法来实现实际弹窗
    console.log('[AccessControl] Approval needed: ' + pending.action + ' ' + pending.resource);
    console.log('[AccessControl]  Approval ID: ' + pending.id);
    console.log('[AccessControl]  Auto-deny in ' + this.approvalTimeout / 1000 + 's');
  }
}

// ============================================================================
// 3. 安全层集成
// ============================================================================

export class DataShield {
  constructor() {
    this.registry = new DataRegistry();
    this.access = new AccessController();
    this.stats = { checks: 0, blocked: 0, approved: 0, denied: 0 };
  }

  evaluate(request) {
    this.stats.checks++;
    let result = { allowed: true, reason: 'passed', riskLevel: 4 };

    // 检测是否是文件/数据访问
    const resource = request.resource || request.args || '';
    const action = request.action || request.type || 'read';
    const content = request.content || null;

    if (resource) {
      const check = this.access.check(request.session_id, action, resource, content);
      if (!check.allowed && check.requiresApproval) {
        this.stats.blocked++;
        return Object.assign({}, check, {
          allowed: false,
          approvalRequired: true,
          message: '需要授权才能访问 ' + resource,
        });
      }
      if (!check.allowed) {
        this.stats.blocked++;
        return Object.assign({}, check, { allowed: false });
      }
      result = check;
    }

    return result;
  }

  /**
   * 处理授权结果（外部系统调用）
   */
  approve(sessionId, approved) {
    const r = this.access.handleApproval(sessionId, approved);
    if (approved) this.stats.approved++; else this.stats.denied++;
    return r;
  }

  /**
   * 注册自定义敏感资源
   */
  addSensitiveResource(classification, path) {
    this.registry.register(classification, [path]);
  }

  getStats() {
    return Object.assign({}, this.stats, {
      registeredResources: this.registry.resources.length,
      pendingApprovals: this.access.pendingApprovals.size,
    });
  }
}

// ============================================================================
// CLI 演示
// ============================================================================

if (process.argv[1] && process.argv[1].endsWith('data_shield.js')) {
  const shield = new DataShield();

  console.log('Data Classification & Access Control Demo');
  console.log('='.repeat(60));

  const tests = [
    { session: 's1', action: 'read', resource: '/etc/shadow' },
    { session: 's1', action: 'read', resource: '~/.aws/credentials' },
    { session: 's1', action: 'read', resource: '/workspace/src/main.js' },
    { session: 's2', action: 'read', resource: '/workspace/.env', content: 'DB_PASSWORD= secret123' },
    { session: 's3', action: 'read', resource: '/tmp/public.txt' },
  ];

  (async function() {
    for (var i = 0; i < tests.length; i++) {
      const t = tests[i];
      const r = shield.evaluate(t);
      console.log('\n[' + t.session + '] ' + t.action + ' ' + t.resource);
      console.log('  ' + (r.allowed ? 'ALLOW' : 'BLOCK') + ' | ' + r.reason);
      if (r.riskLevel !== undefined) console.log('  riskLevel: P' + r.riskLevel);
      if (r.approvalRequired) console.log('  ⚠️需要授权弹窗');
    }
    console.log('\nStats:', JSON.stringify(shield.getStats()));
  })();
}
