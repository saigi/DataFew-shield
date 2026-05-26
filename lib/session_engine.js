/**
 * Datafew Shield v2 — 会话级安全引擎架构
 *
 * 核心转变:
 *   从"单条请求过滤" → "会话轨迹分析"
 *   从"检测已发生的攻击链" → "预测即将发生的攻击链"
 *   从"二进制拦截" → "累积风险评分 + 自适应降级"
 */

// ============================================================================
// 1. 会话画像 — 跟踪每条 session 的嵌入轨迹
// ============================================================================

class SessionProfile {
  constructor(sessionId) {
    this.id = sessionId;
    this.created = Date.now();
    this.embeddingTrajectory = [];  // embedding 时序轨迹
    this.steps = [];                // 操作历史
    this.riskScore = 0.0;           // 累积风险 [0, 1]
    this.riskVelocity = 0.0;        // 风险变化率
    this.stepTypes = {};            // 操作类型计数
    this.lastAlertTime = 0;
  }

  addStep(step) {
    this.steps.push(step);
    if (step.embedding) this.embeddingTrajectory.push(step.embedding);

    // 更新操作类型计数
    var type = step.tool || 'unknown';
    this.stepTypes[type] = (this.stepTypes[type] || 0) + 1;

    // 累积风险: 越近的步骤权重越高
    var riskDelta = (1 - (step.score || 0.5)) * 0.3;
    this.riskScore = Math.min(1, this.riskScore * 0.85 + riskDelta);

    // 风险变化率: 最近 3 步的平均变化
    var recent = this.steps.slice(-3);
    if (recent.length >= 2) {
      var delta1 = (1 - (recent[recent.length - 1].score || 0.5));
      var delta2 = (1 - (recent[0].score || 0.5));
      this.riskVelocity = delta1 - delta2;
    }
  }

  // 是否是攻击链的开始
  isChainStart() {
    // 风险快速上升 + 敏感操作类型 → 可能开始攻击链
    return this.riskVelocity > 0.3 && this.riskScore > 0.4;
  }

  // 需要锁定会话
  needsLockdown() {
    return this.riskScore > 0.8 || this.riskVelocity > 0.5;
  }

  // 会话熵: 操作类型的多样性
  entropy() {
    var total = Object.values(this.stepTypes).reduce(function(a, b) { return a + b; }, 0);
    if (total === 0) return 0;
    var e = 0;
    for (var k in this.stepTypes) {
      var p = this.stepTypes[k] / total;
      if (p > 0) e -= p * Math.log(p);
    }
    return e;
  }
}

// ============================================================================
// 2. 轨迹匹配 — 用 embedding 时序匹配已知攻击模式
// ============================================================================

class TrajectoryMatcher {
  constructor() {
    this.knownChains = [];  // [{ name, embedding_sequence: [...] }]
  }

  /**
   * 注册已知攻击链的嵌入轨迹
   */
  registerChain(name, embeddingSequence) {
    this.knownChains.push({
      name: name,
      sequence: embeddingSequence,
    });
  }

  /**
   * 匹配当前轨迹与已知攻击链
   * 使用 DTW (Dynamic Time Warping) 或简单滑动窗口相似度
   */
  match(trajectory) {
    if (trajectory.length < 2 || this.knownChains.length === 0) return null;

    for (var c = 0; c < this.knownChains.length; c++) {
      var chain = this.knownChains[c];
      if (chain.sequence.length > trajectory.length) continue;

      // 滑动窗口匹配
      var startIdx = trajectory.length - chain.sequence.length;
      if (startIdx < 0) continue;

      var matchScore = 0;
      for (var s = 0; s < chain.sequence.length; s++) {
        var sim = this.cosine(trajectory[startIdx + s], chain.sequence[s]);
        matchScore += sim;
      }
      matchScore /= chain.sequence.length;

      if (matchScore > 0.7) {
        return { chainName: chain.name, similarity: matchScore, matchedLen: chain.sequence.length };
      }
    }
    return null;
  }

  cosine(a, b) {
    var dot = 0, na = 0, nb = 0;
    for (var i = 0; i < a.length; i++) {
      dot += a[i] * b[i]; na += a[i] * a[i]; nb += b[i] * b[i];
    }
    return dot / (Math.sqrt(na) * Math.sqrt(nb) + 1e-10);
  }

  /**
   * 预测下一步: 给定当前轨迹，最可能的下一个有害操作是什么？
   */
  predictNext(trajectory) {
    if (trajectory.length < 1) return null;

    for (var c = 0; c < this.knownChains.length; c++) {
      var chain = this.knownChains[c];
      if (chain.sequence.length <= trajectory.length) continue;

      // 检查当前轨迹是否匹配攻击链的前缀
      var prefix = chain.sequence.slice(0, trajectory.length);
      var matchScore = 0;
      for (var s = 0; s < trajectory.length; s++) {
        matchScore += this.cosine(trajectory[s], prefix[s]);
      }
      matchScore /= trajectory.length;

      if (matchScore > 0.75) {
        // 返回预测的下一步
        return {
          predictedChain: chain.name,
          nextStep: chain.sequence[trajectory.length],
          confidence: matchScore,
          stepNumber: trajectory.length + 1,
        };
      }
    }
    return null;
  }
}

// ============================================================================
// 3. 自适应阈值 — 根据会话上下文动态调整
// ============================================================================

class AdaptiveThreshold {
  constructor(baseThreshold) {
    this.base = baseThreshold || 0.52;
    this.sessionThresholds = new Map();
  }

  getThreshold(sessionId, profile) {
    if (!profile) return this.base;

    // 基础阈值
    var t = this.base;

    // 步骤数越多，阈值越低（更敏感）
    t -= Math.min(0.1, profile.steps.length * 0.01);

    // 风险变化率越快，阈值越低
    if (profile.riskVelocity > 0.2) t -= 0.05;
    if (profile.riskVelocity > 0.4) t -= 0.08;

    // 操作类型熵越低（单一操作重复），越可疑
    var e = profile.entropy();
    if (e < 0.5) t -= 0.03;

    // 最小阈值保护
    return Math.max(0.25, t);
  }
}

// ============================================================================
// 4. 联合决策引擎 v2
// ============================================================================

export class SessionAwareShield {
  constructor(opts) {
    opts = opts || {};
    this.sessions = new Map();        // sessionId → SessionProfile
    this.matcher = new TrajectoryMatcher();
    this.threshold = new AdaptiveThreshold(opts.threshold);
    this.policyEngine = opts.policyEngine || null;
    this.stats = { totalSessions: 0, lockdowns: 0, predictions: 0 };
  }

  async evaluate(request) {
    var sessionId = request.session_id || 'default';
    if (!this.sessions.has(sessionId)) {
      this.sessions.set(sessionId, new SessionProfile(sessionId));
      this.stats.totalSessions++;
    }
    var profile = this.sessions.get(sessionId);

    // ================================================================
    // Step 1: 单步评估（现有各层）
    // ================================================================

    var stepResult = {
      allowed: true,
      score: 0.5,
      reason: 'passed',
      embedding: null,
    };

    // ... 调用现有 vector/policy/chain 层 ...

    // ================================================================
    // Step 2: 更新会话画像
    // ================================================================

    profile.addStep({
      tool: request.tool,
      text: request.args || request.text || '',
      embedding: stepResult.embedding,
      score: stepResult.score,
      allowed: stepResult.allowed,
      reason: stepResult.reason,
    });

    // ================================================================
    // Step 3: 预测性攻击链检测
    // ================================================================

    if (profile.embeddingTrajectory.length >= 1) {
      var prediction = this.matcher.predictNext(profile.embeddingTrajectory);
      if (prediction) {
        this.stats.predictions++;
        // 如果预测的下一步是高危操作，提前阻止
        if (prediction.confidence > 0.8) {
          return {
            allowed: false,
            reason: 'predictive_block: ' + prediction.predictedChain,
            prediction: prediction,
            riskScore: profile.riskScore,
          };
        }
      }
    }

    // ================================================================
    // Step 4: 累积风险检查
    // ================================================================

    var adaptiveT = this.threshold.getThreshold(sessionId, profile);
    stepResult.adaptiveThreshold = adaptiveT;

    if (profile.isChainStart()) {
      // 开始降级: 放行但增加延迟
      stepResult.degraded = true;
      stepResult.delayMs = Math.min(5000, profile.riskScore * 5000);
    }

    if (profile.needsLockdown()) {
      this.stats.lockdowns++;
      return {
        allowed: false,
        reason: 'session_lockdown',
        riskScore: profile.riskScore,
        riskVelocity: profile.riskVelocity,
        stepCount: profile.steps.length,
      };
    }

    return stepResult;
  }
}
