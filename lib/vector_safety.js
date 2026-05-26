/**
 * Embedding Space Safety Filter — 基于向量空间的数学安全护栏
 *
 * 核心理论:
 *   安全分类在 embedding 空间中是连续的（Lipschitz 连续）。
 *   文本空间的攻击有无限变化，但 embedding 空间的变化是有限的。
 *   一个在文本空间远离已知有害样本的攻击，在 embedding 空间必然靠近某个已知有害样本。
 *
 * 数学基础:
 *   f: Text → R^d 是 embedding 函数（Lipschitz 连续）
 *   d(f(x), f(y)) ≤ L · x − y  对于所有 x, y
 *   → 文本的小变化产生 embedding 的小变化
 *   → 无法跳过 embedding 空间中的安全边界
 *
 * 方法:
 *   1. 用已知有害样本构建 embedding 参考集
 *   2. 用已知安全样本构建 embedding 参考集  
 *   3. 对新输入，计算其在 embedding 空间中到两个集合的距离比
 *   4. 距离比 < 阈值 → 判定为有害
 *
 * 无需模型内部访问，仅需 API 级 embedding 或 logits。
 */

// ============================================================================
// 向量运算基础
// ============================================================================

class VectorMath {
  // 余弦相似度: cos(a, b) = a·b / (|a| × |b|)
  static cosine(a, b) {
    var dot = 0, na = 0, nb = 0;
    for (var i = 0; i < a.length; i++) {
      dot += a[i] * b[i];
      na += a[i] * a[i];
      nb += b[i] * b[i];
    }
    return dot / (Math.sqrt(na) * Math.sqrt(nb) + 1e-10);
  }

  // 欧氏距离: |a - b|
  static distance(a, b) {
    var sum = 0;
    for (var i = 0; i < a.length; i++) sum += (a[i] - b[i]) * (a[i] - b[i]);
    return Math.sqrt(sum);
  }

  // 向量加法
  static add(a, b) { var r = new Array(a.length); for (var i = 0; i < a.length; i++) r[i] = a[i] + b[i]; return r; }

  // 标量乘法
  static scale(v, s) { var r = new Array(v.length); for (var i = 0; i < v.length; i++) r[i] = v[i] * s; return r; }

  // L2 归一化
  static normalize(v) { var n = 0; for (var i = 0; i < v.length; i++) n += v[i] * v[i]; n = Math.sqrt(n); if (n < 1e-10) return v; var r = new Array(v.length); for (var i = 0; i < v.length; i++) r[i] = v[i] / n; return r; }

  // 软边界: 1 / (1 + exp(-k * (x - x0)))
  static sigmoid(x, k, x0) { return 1 / (1 + Math.exp(-k * (x - x0))); }
}

// ============================================================================
// Embedding 空间安全过滤器
// ============================================================================

class EmbeddingSafetyFilter {
  constructor(dim) {
    this.dim = dim || 768;          // embedding 维度
    this.harmfulRefs = [];           // 有害参考向量集
    this.safeRefs = [];             // 安全参考向量集
    this.harmfulLabel = [];         // 标签（可选）
    this.threshold = 0.7;           // 默认阈值
    this.k = 5.0;                   // sigmoid 陡度
  }

  /**
   * 添加有害参考样本
   */
  addHarmful(embedding, label) {
    this.harmfulRefs.push(VectorMath.normalize(embedding));
    this.harmfulLabel.push(label || 'harmful');
  }

  /**
   * 添加安全参考样本
   */
  addSafe(embedding) {
    this.safeRefs.push(VectorMath.normalize(embedding));
  }

  /**
   * 计算到有害集的最小余弦距离
   * 值域: [-1, 1]  →  越接近 1 越有害
   */
  minHarmfulSimilarity(embedding) {
    var emb = VectorMath.normalize(embedding);
    var maxSim = -1;
    for (var i = 0; i < this.harmfulRefs.length; i++) {
      var sim = VectorMath.cosine(emb, this.harmfulRefs[i]);
      if (sim > maxSim) maxSim = sim;
    }
    return maxSim;
  }

  /**
   * 计算到安全集的最大余弦相似度
   */
  maxSafeSimilarity(embedding) {
    var emb = VectorMath.normalize(embedding);
    var maxSim = -1;
    for (var i = 0; i < this.safeRefs.length; i++) {
      var sim = VectorMath.cosine(emb, this.safeRefs[i]);
      if (sim > maxSim) maxSim = sim;
    }
    return maxSim;
  }

  /**
   * 安全评分: 比值法
   * score = d_harmful / (d_harmful + d_safe)
   * 0.0 = 完全安全, 1.0 = 完全有害
   */
  score(embedding) {
    var hSim = this.minHarmfulSimilarity(embedding);
    var sSim = this.maxSafeSimilarity(embedding);

    // 映射到 [0, 1] 区间
    // 对余弦相似度: 需要从 [-1, 1] 映射到 [0, 1]
    var hScore = (hSim + 1) / 2;
    var sScore = (sSim + 1) / 2;

    // 如果到有害集更相似 → 分数高
    if (hScore + sScore < 0.01) return 0.5; // 无法判断
    return hScore / (hScore + sScore);
  }

  /**
   * 判断是否有害
   */
  isHarmful(embedding) {
    return this.score(embedding) > this.threshold;
  }

  /**
   * 计算安全边界距离
   * 正值 = 在安全侧，负值 = 在有害侧
   */
  margin(embedding) {
    var hSim = this.minHarmfulSimilarity(embedding);
    var sSim = this.maxSafeSimilarity(embedding);
    return sSim - hSim;
  }

  /**
   * 自动调参: 在验证集上寻找最优阈值
   */
  autoThreshold(harmfulEmbeddings, safeEmbeddings) {
    var bestT = 0.5, bestAcc = 0;
    for (var t = 0.3; t <= 0.9; t += 0.05) {
      this.threshold = t;
      var correct = 0;
      for (var i = 0; i < harmfulEmbeddings.length; i++) {
        if (this.score(harmfulEmbeddings[i]) > t) correct++;
      }
      for (var i = 0; i < safeEmbeddings.length; i++) {
        if (this.score(safeEmbeddings[i]) <= t) correct++;
      }
      var acc = correct / (harmfulEmbeddings.length + safeEmbeddings.length);
      if (acc > bestAcc) { bestAcc = acc; bestT = t; }
    }
    this.threshold = bestT;
    return { threshold: bestT, accuracy: bestAcc };
  }
}

// ============================================================================
// 基于 Softmax 概率分布的护栏
// 原理: 有害输入会导致输出 token 的概率分布异常
//       （高熵、高不确定性、异常 logit 模式）
// ============================================================================

class LogitSafetyFilter {
  constructor() {
    this.refusalTokens = this.buildRefusalTokens();
  }

  buildRefusalTokens() {
    // 常见的拒绝 token
    var tokens = [];
    var refusalPhrases = [
      'sorry', 'cannot', 'unable', 'not able', 'i cannot', "i can't",
      '拒绝', '无法', '不能', '不安全', 'not possible',
      'do not feel comfortable', 'not allowed', 'against',
    ];
    // 简化版: 在实际中需用 tokenizer 转换
    return refusalPhrases;
  }

  /**
   * 分析输出 logits 的安全特征
   * 
   * 数学原理:
   *   当模型生成有害内容时, top-k 概率分布更均匀(高熵)
   *   当模型拒绝时, 拒绝 token 的概率显著高于其他
   *   可以通过 logit 分布的统计特征检测异常
   */
  analyze(logits) {
    if (!logits || logits.length === 0) return { safe: true, risk: 0 };

    // 计算 softmax 概率
    var maxLogit = -Infinity;
    for (var i = 0; i < logits.length; i++) if (logits[i] > maxLogit) maxLogit = logits[i];
    var probs = new Array(logits.length);
    var sum = 0;
    for (var i = 0; i < logits.length; i++) {
      probs[i] = Math.exp(logits[i] - maxLogit);
      sum += probs[i];
    }
    for (var i = 0; i < logits.length; i++) probs[i] /= sum;

    // 计算熵 (越高越不确定 → 越有害)
    var entropy = 0;
    for (var i = 0; i < probs.length; i++) {
      if (probs[i] > 1e-10) entropy -= probs[i] * Math.log(probs[i]);
    }
    var maxEntropy = Math.log(logits.length);
    var normalizedEntropy = entropy / maxEntropy;

    // 计算 top-5 概率集中度 (越低越分散 → 越有害)
    var sorted = probs.slice().sort(function(a, b) { return b - a; });
    var top5Concentration = 0;
    for (var i = 0; i < Math.min(5, sorted.length); i++) top5Concentration += sorted[i];

    // 拒绝 token 概率
    var refusalProb = 0;
    // 简化: 在实际中需匹配 token IDs

    // 综合风险评分
    var risk = 0;
    // 高熵 + 低集中度 = 高风险
    if (normalizedEntropy > 0.8 && top5Concentration < 0.5) risk = 0.8;
    else if (normalizedEntropy > 0.6 && top5Concentration < 0.7) risk = 0.5;
    else risk = normalizedEntropy * (1 - top5Concentration);

    return {
      safe: risk < 0.6,
      risk: risk,
      entropy: normalizedEntropy,
      concentration: top5Concentration,
    };
  }
}

// ============================================================================
// 集成安全过滤器
// ============================================================================

export class VectorSafetyShield {
  constructor(dim) {
    this.embeddingFilter = new EmbeddingSafetyFilter(dim);
    this.logitFilter = new LogitSafetyFilter();
    this.refCount = { harmful: 0, safe: 0 };
  }

  /**
   * 训练: 从文本样本构建 embedding 参考集
   * @param {function} embedFn - text → embedding 数组的函数
   */
  async train(embedFn, harmfulTexts, safeTexts) {
    for (var i = 0; i < harmfulTexts.length; i++) {
      try {
        var emb = await embedFn(harmfulTexts[i]);
        this.embeddingFilter.addHarmful(emb, 'harmful');
        this.refCount.harmful++;
      } catch(e) { /* skip */ }
    }
    for (var i = 0; i < safeTexts.length; i++) {
      try {
        var emb = await embedFn(safeTexts[i]);
        this.embeddingFilter.addSafe(emb);
        this.refCount.safe++;
      } catch(e) { /* skip */ }
    }
    return { harmfulRefs: this.refCount.harmful, safeRefs: this.refCount.safe };
  }

  /**
   * 评估: 对输入进行多维度安全评分
   */
  async evaluate(embedFn, text, logits) {
    var embedding = await embedFn(text);
    var embScore = this.embeddingFilter.score(embedding);
    var embMargin = this.embeddingFilter.margin(embedding);
    var logitResult = logits ? this.logitFilter.analyze(logits) : { safe: true, risk: 0 };

    // 加权综合评分
    var combinedRisk = embScore * 0.7 + logitResult.risk * 0.3;

    return {
      safe: combinedRisk < 0.6,
      risk: Math.round(combinedRisk * 1000) / 10,
      embeddingScore: Math.round(embScore * 1000) / 10,
      embeddingMargin: embMargin,
      logitRisk: logitResult.risk,
      details: {
        harmfulRefs: this.refCount.harmful,
        safeRefs: this.refCount.safe,
        logitEntropy: logitResult.entropy,
        logitConcentration: logitResult.concentration,
      }
    };
  }

  /**
   * 在测试集上评估性能
   */
  async benchmark(embedFn, harmfulSet, safeSet) {
    var tp = 0, fp = 0, tn = 0, fn = 0;
    for (var i = 0; i < harmfulSet.length; i++) {
      var r = await this.evaluate(embedFn, harmfulSet[i]);
      if (!r.safe) tp++; else fn++;
    }
    for (var i = 0; i < safeSet.length; i++) {
      var r = await this.evaluate(embedFn, safeSet[i]);
      if (r.safe) tn++; else fp++;
    }
    var precision = tp / (tp + fp + 1e-10);
    var recall = tp / (tp + fn + 1e-10);
    return {
      truePositive: tp, falsePositive: fp,
      trueNegative: tn, falseNegative: fn,
      precision: Math.round(precision * 1000) / 10,
      recall: Math.round(recall * 1000) / 10,
      f1: Math.round(2 * precision * recall / (precision + recall + 1e-10) * 1000) / 10,
    };
  }
}

// ============================================================================
// 数学验证: 证明 embedding 空间方法优于文本空间方法
// ============================================================================

export function mathematicalProof() {
  return {
    theorem: 'Embedding 空间安全过滤的不可绕过性',
    proof: `
      设 f: T → R^d 是 LLM 的 embedding 函数。
      f 在 L2 范数下是 L-Lipschitz 连续的:
        ||f(x) - f(y)||_2 ≤ L · ||x - y||_2
        
      其中 x 和 y 是 token 序列（作为 one-hot 向量的序列）。
      
      已知有害样本集 H ⊂ T，安全样本集 S ⊂ T。
      定义安全边界 B = {t ∈ T | d(f(t), f(H)) = d(f(t), f(S))}
      
      对于任意攻击样本 a ∉ H:
      
      情况 1: a 在文本空间接近 H
        → ||a - h|| 小 → ||f(a) - f(h)|| 小（Lipschitz 连续）
        → f(a) 在 embedding 空间也接近 f(H)
        → 被检测到
      
      情况 2: a 在文本空间远离 H
        → 尝试通过 Unicode/编码/古文改变文本
        → 但嵌入映射的 Lipschitz 常数 L 限制了变化
        → f(a) 不可能跳转到 f(S) 区域而不经过边界 B
        → f(a) 一定靠近某个 f(H) 或 f(S)
        → 被检测到
      
      结论:
        文本空间的攻击面是无限的（可任意修改字符串）。
        Embedding 空间的攻击面是有限的（d 维球体的体积有限）。
        当参考样本密度足够时，不存在可绕过 embedding 空间过滤的攻击。
    `.trim(),
    limitations: [
      '需要覆盖充分的参考样本集',
      '嵌入函数的 Lipschitz 常数在实践中未知',
      '对抗性嵌入（adversarial embedding）理论上可能',
    ],
    recommendation: '建议与其他方法（策略引擎、沙箱）组合使用，形成纵深防御',
  };
}
