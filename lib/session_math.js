/**
 * Datafew Shield — 会话级安全引擎数学底层
 *
 * 核心数学模型:
 *   1. 累积风险: Rₙ = α·Rₙ₋₁ + (1-α)·g(rₙ, Δₙ)
 *   2. 会话分割: embedding 位移 + 时间间隔 + 工具切换
 *   3. 风险速度: vₙ = Rₙ - Rₙ₋₁
 *   4. 风险加速度: aₙ = vₙ - vₙ₋₁
 *   5. 轨迹概率: P(s₁...sₙ) ≈ Π cos(eᵢ, eᵢ₋₁)
 */

// ============================================================================
// 1. 数学基础：向量运算
// ============================================================================

class VecMath {
  static cosine(a, b) {
    var dot = 0, na = 0, nb = 0;
    for (var i = 0; i < a.length; i++) {
      dot += a[i] * b[i]; na += a[i] * a[i]; nb += b[i] * b[i];
    }
    return dot / (Math.sqrt(na) * Math.sqrt(nb) + 1e-10);
  }

  static distance(a, b) {
    var sum = 0;
    for (var i = 0; i < a.length; i++) sum += (a[i] - b[i]) * (a[i] - b[i]);
    return Math.sqrt(sum);
  }

  static magnitude(v) {
    var sum = 0;
    for (var i = 0; i < v.length; i++) sum += v[i] * v[i];
    return Math.sqrt(sum);
  }

  // 归一化
  static normalize(v) {
    var m = this.magnitude(v);
    if (m < 1e-10) return v;
    var r = new Array(v.length);
    for (var i = 0; i < v.length; i++) r[i] = v[i] / m;
    return r;
  }

  // Sigmoid 映射到 [0, 1]
  static sigmoid(x, k, x0) {
    return 1 / (1 + Math.exp(-k * (x - x0)));
  }
}

// ============================================================================
// 2. 会话画像 — 核心数学模型
// ============================================================================

export class SessionMathModel {
  constructor(opts) {
    opts = opts || {};
    this.alpha = opts.alpha || 0.85;         // 时间衰减因子 [0, 1]
    this.beta = opts.beta || 0.3;            // embedding 位移权重
    this.gamma = opts.gamma || 0.2;          // 加速度预警阈值
    this.decayHalfLife = opts.halfLife || 5;  // 半衰期（步数）
    this.segmentInterval = opts.segmentInterval || 1800000; // 30分钟会话分割
  }

  /**
   * 创建新会话画像
   */
  createProfile(sessionId) {
    return {
      id: sessionId,
      created: Date.now(),
      lastActive: Date.now(),

      // 轨迹数据
      embeddings: [],           // embedding 时序 [e₁, e₂, ..., eₙ]
      rawScores: [],            // 单步原始风险 [r₁, r₂, ..., rₙ]
      toolTypes: [],            // 工具类型 [t₁, t₂, ..., tₙ]
      timestamps: [],           // 时间戳 [ts₁, ts₂, ..., tsₙ]
      deviations: [],           // embedding 位移 [0, Δ₂, Δ₃, ..., Δₙ]

      // 累积风险
      risk: 0,                  // 当前累积风险 Rₙ
      riskHistory: [],          // 风险历史 [R₁, R₂, ..., Rₙ]

      // 风险动力学
      velocity: 0,              // 风险速度 vₙ
      acceleration: 0,          // 风险加速度 aₙ

      // 分割信息
      segment: 0,               // 当前分割段编号
      segmentStarts: [0],       // 分割起始索引
      segmentRisks: [],         // 段内平均风险

      // 会话统计
      stepCount: 0,
      phase: 'exploration',     // exploration | focus | execution | lockdown
      locked: false,
    };
  }

  /**
   * 核心: 累积风险计算
   *
   * Rₙ = α · Rₙ₋₁ + (1-α) · g(rₙ, Δₙ)
   *
   * g(rₙ, Δₙ) = rₙ + β · sigmoid(Δₙ - δ₀)
   *
   * 其中:
   *   rₙ    = 单步原始风险 (embedding 评分)
   *   Δₙ    = embedding 位移 |eₙ - eₙ₋₁|
   *   β     = 位移惩罚权重
   *   δ₀    = 位移基准线
   *   α     = 时间衰减
   */
  addStep(profile, embedding, rawScore, toolType) {
    var n = profile.stepCount;
    profile.stepCount = n + 1;

    // 记录数据
    profile.embeddings.push(embedding);
    profile.rawScores.push(rawScore);
    profile.toolTypes.push(toolType);
    profile.timestamps.push(Date.now());
    profile.lastActive = Date.now();

    // 计算 embedding 位移
    var deviation = 0;
    if (n > 0) {
      deviation = VecMath.distance(embedding, profile.embeddings[n - 1]);
    }
    profile.deviations.push(deviation);

    // ================================================================
    // 风险贡献函数 g(rₙ, Δₙ)
    // ================================================================

    // 基线位移: 前 5 步的平均位移
    var baselineDev = this.calcBaselineDeviation(profile);

    // 位移惩罚: 超过基线越多，风险越高
    var devPenalty = 0;
    if (baselineDev > 0.01 && n > 2) {
      devPenalty = this.beta * VecMath.sigmoid(deviation / baselineDev - 1.5, 3, 0);
    }

    // 风险贡献 = 原始风险 + 位移惩罚
    var riskContribution = Math.min(1, rawScore + devPenalty);

    // ================================================================
    // 累积风险 Rₙ = α·Rₙ₋₁ + (1-α)·riskContribution
    // ================================================================

    // 时间衰减 α 根据时间间隔调整
    var adjustedAlpha = this.alpha;
    if (n > 0) {
      var timeGap = profile.timestamps[n] - profile.timestamps[n - 1];
      // 时间间隔越大，衰减越快（旧信息更不相关）
      if (timeGap > 60000) adjustedAlpha *= Math.exp(-timeGap / 3600000);
    }

    profile.risk = adjustedAlpha * profile.risk + (1 - adjustedAlpha) * riskContribution;
    profile.riskHistory.push(profile.risk);

    // ================================================================
    // 风险动力学: 速度 + 加速度
    // ================================================================

    if (n >= 1) {
      profile.velocity = profile.risk - profile.riskHistory[n - 1];
    }
    if (n >= 2) {
      var prevVelocity = profile.riskHistory[n - 1] - profile.riskHistory[n - 2];
      profile.acceleration = profile.velocity - prevVelocity;
    }

    // ================================================================
    // 会话分割检测
    // ================================================================

    this.detectSegment(profile);

    // ================================================================
    // 阶段判定
    // ================================================================

    profile.phase = this.classifyPhase(profile);

    return {
      risk: profile.risk,
      velocity: profile.velocity,
      acceleration: profile.acceleration,
      deviation: deviation,
      riskContribution: riskContribution,
      phase: profile.phase,
      segment: profile.segment,
    };
  }

  /**
   * 计算基线位移（前 K 步的平均位移）
   */
  calcBaselineDeviation(profile) {
    var deviations = profile.deviations;
    if (deviations.length < 3) return 0;

    var sum = 0, count = 0;
    for (var i = Math.max(1, deviations.length - 5); i < deviations.length; i++) {
      sum += deviations[i];
      count++;
    }
    return count > 0 ? sum / count : 0;
  }

  /**
   * 会话分割检测
   *
   * 分割条件:
   *   1. 时间间隔 > segmentInterval → 新段
   *   2. embedding 位移 > 3× 基线 → 新段（操作模式突变）
   *   3. 工具切换 → 新段（探索→利用变化）
   */
  detectSegment(profile) {
    var n = profile.stepCount - 1;
    if (n < 1) return;

    // 条件 1: 时间间隔
    var timeGap = profile.timestamps[n] - profile.timestamps[n - 1];
    if (timeGap > this.segmentInterval) {
      profile.segment++;
      profile.segmentStarts.push(n);
      this.finalizeSegment(profile);
      return;
    }

    // 条件 2: embedding 位移异常
    var baseline = this.calcBaselineDeviation(profile);
    if (baseline > 0.01 && profile.deviations[n] > baseline * 3) {
      profile.segment++;
      profile.segmentStarts.push(n);
      this.finalizeSegment(profile);
      return;
    }

    // 条件 3: 工具切换
    if (n > 0 && profile.toolTypes[n] !== profile.toolTypes[n - 1]) {
      // 只在连续同类型工具操作后才触发生成分割
      var sameToolCount = 0;
      for (var i = n - 1; i >= Math.max(0, n - 5); i--) {
        if (profile.toolTypes[i] === profile.toolTypes[n]) sameToolCount++;
        else break;
      }
      if (sameToolCount >= 3) {
        profile.segment++;
        profile.segmentStarts.push(n);
        this.finalizeSegment(profile);
      }
    }
  }

  finalizeSegment(profile) {
    // 计算段内平均风险
    var start = profile.segmentStarts[profile.segmentStarts.length - 2] || 0;
    var end = profile.riskHistory.length;
    var segment = profile.riskHistory.slice(start, end);
    var avg = segment.reduce(function(a, b) { return a + b; }, 0) / segment.length;
    profile.segmentRisks.push(avg);
  }

  /**
   * 阶段分类
   *
   * exploration: 低风险, 高熵（多种工具尝试）
   * focus:       中风险, 低熵（聚焦特定任务）
   * execution:   高风险, 低熵（执行具体操作）
   * lockdown:    超高累积风险 + 快速上升
   */
  classifyPhase(profile) {
    if (profile.locked) return 'lockdown';
    if (profile.risk > 0.8) return 'lockdown';

    var n = profile.stepCount;
    if (n < 3) return 'exploration';

    // 计算工具类型熵
    var toolCounts = {};
    for (var i = 0; i < profile.toolTypes.length; i++) {
      var t = profile.toolTypes[i];
      toolCounts[t] = (toolCounts[t] || 0) + 1;
    }
    var total = profile.toolTypes.length;
    var entropy = 0;
    for (var k in toolCounts) {
      var p = toolCounts[k] / total;
      if (p > 0) entropy -= p * Math.log(p);
    }

    // 低熵 + 高风险 = execution
    if (entropy < 0.5 && profile.risk > 0.3) return 'execution';
    // 中熵 + 中风险 = focus
    if (entropy < 1.0 && profile.risk > 0.15) return 'focus';
    // 高熵 + 低风险 = exploration
    return 'exploration';
  }

  /**
   * 是否应该锁定会话
   */
  shouldLockdown(profile) {
    // 累积风险过高
    if (profile.risk > 0.8) return true;

    // 风险加速度过快 (aₙ > γ)
    if (profile.acceleration > this.gamma && profile.velocity > 0.1) return true;

    // 连续高风险步
    if (profile.stepCount >= 3) {
      var last3 = profile.riskHistory.slice(-3);
      if (last3.every(function(r) { return r > 0.6; })) return true;
    }

    return false;
  }
}

// ============================================================================
// 3. 数学验证
// ============================================================================

export function mathematicalValidation() {
  var model = new SessionMathModel({ alpha: 0.85, beta: 0.3 });
  var dim = 4;

  // 模拟安全会话: 低风险、平稳过渡
  var safeSession = model.createProfile('safe-test');
  for (var i = 0; i < 10; i++) {
    var emb = [0.1, 0.2, 0.1 + i * 0.01, 0.3];
    model.addStep(safeSession, emb, 0.3, 'read');
  }

  // 模拟攻击会话: 快速风险上升
  var attackSession = model.createProfile('attack-test');
  var attackSteps = [
    [0.1, 0.2, 0.3, 0.4],         // 步骤1: ls
    [0.15, 0.25, 0.35, 0.3],       // 步骤2: cd ~/.ssh
    [0.3, 0.5, 0.6, 0.2],          // 步骤3: cat id_rsa  ← 位移增大
    [0.5, 0.7, 0.8, 0.1],          // 步骤4: curl exfil   ← 高风险
  ];

  for (var i = 0; i < attackSteps.length; i++) {
    var score = 0.3 + i * 0.15;  // 风险递增
    model.addStep(attackSession, attackSteps[i], score, 'terminal');
  }

  return {
    safeSession: {
      finalRisk: safeSession.risk,
      finalVelocity: safeSession.velocity,
      finalPhase: safeSession.phase,
      locked: model.shouldLockdown(safeSession),
    },
    attackSession: {
      finalRisk: attackSession.risk,
      finalVelocity: attackSession.velocity,
      finalPhase: attackSession.phase,
      locked: model.shouldLockdown(attackSession),
      steps: attackSession.riskHistory,
      segments: attackSession.segmentRisks,
    },
  };
}

// ============================================================================
// 4. 轨道验证
// ============================================================================

if (process.argv[1] && process.argv[1].endsWith('session_math.js')) {
  var result = mathematicalValidation();
  console.log('Mathematical Validation');
  console.log('='.repeat(60));
  console.log('\nSafe session:');
  console.log(JSON.stringify(result.safeSession, null, 2));
  console.log('\nAttack session:');
  console.log('  Final risk:', result.attackSession.finalRisk.toFixed(4));
  console.log('  Final velocity:', result.attackSession.finalVelocity.toFixed(4));
  console.log('  Phase:', result.attackSession.finalPhase);
  console.log('  Locked:', result.attackSession.locked);
  console.log('  Risk trajectory:', result.attackSession.steps.map(function(r) { return r.toFixed(3); }).join(' → '));
  console.log('  Segments:', result.attackSession.segments.map(function(r) { return r.toFixed(3); }).join(', '));
}
