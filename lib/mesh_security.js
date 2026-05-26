/**
 * Datafew Shield — Mesh 路由安全层
 *
 * 为去中心化 Mesh VPN (Nostr Mesh) 提供三层安全防护:
 *   Layer 1: 向量空间 — 检测路由请求的异常 embedding 聚合
 *   Layer 2: 数据保护 — 节点信任分 + 带宽配额 + 速率限制
 *   Layer 3: 隐私守护 — 签名路径验证 + 退火降级 + 突发广播
 *
 * 所有决策在本地完成，无需中心化协调。
 * Nostr relay 仅用于交换 Burst Report（签名不可抵赖）。
 */

// ============================================================================
// Layer 0: 基础数据结构
// ============================================================================

class PeerRecord {
  constructor(pubkey) {
    this.pubkey = pubkey;
    this.firstSeen = Date.now();
    this.lastSeen = Date.now();
    this.totalRequests = 0;
    this.totalForwarded = 0;
    this.burstCount = 0;           // 当前突发计数
    this.burstHistory = [];        // 突发时间戳窗口
    this.score = 0.5;              // 信任分 [0, 1]
    this.ageDays = 0;
    this.bandwidthMbps = 0;
    this.wotScore = 0.5;           // Web of Trust 评分
    this.exitViolations = 0;
  }
}

class RouteRequest {
  constructor(event) {
    this.srcPubkey = event.pubkey;
    this.dstPubkey = event?.content?.target || '';
    this.path = event?.content?.path || [];
    this.embedding = event?.embedding || null;
    this.timestamp = event?.created_at || Date.now();
    this.sessionId = event?.id || '';
  }
}

// ============================================================================
// Layer 1: 向量空间 — 路由请求的异常模式检测
// ============================================================================

class VectorRouteFilter {
  constructor() {
    this.recentEmbeddings = [];     // 最近的请求 embedding 窗口
    this.windowSize = 100;         // 滑动窗口大小
    this.burstThreshold = 0.3;     // 方差阈值（低于此值 = 突发）
  }

  /**
   * 评估路由请求的异常程度
   * DDoS 攻击的特征: 大量请求集中在 embedding 空间的小区域
   * 正常路由: 请求的 embedding 分散、多样化
   */
  evaluate(embedding) {
    if (!embedding || embedding.length === 0) {
      return { anomalous: false, score: 0 };
    }

    // 加入滑动窗口
    this.recentEmbeddings.push(embedding);
    if (this.recentEmbeddings.length > this.windowSize) {
      this.recentEmbeddings.shift();
    }

    if (this.recentEmbeddings.length < 10) {
      return { anomalous: false, score: 0, reason: 'warming_up' };
    }

    // 计算 embedding 中心
    var dim = embedding.length;
    var centroid = new Array(dim).fill(0);
    for (var i = 0; i < this.recentEmbeddings.length; i++) {
      for (var j = 0; j < dim; j++) {
        centroid[j] += this.recentEmbeddings[i][j];
      }
    }
    for (var j = 0; j < dim; j++) centroid[j] /= this.recentEmbeddings.length;

    // 计算方差（嵌入空间中的离散程度）
    var variance = 0;
    for (var i = 0; i < this.recentEmbeddings.length; i++) {
      var d2 = 0;
      for (var j = 0; j < dim; j++) {
        var diff = this.recentEmbeddings[i][j] - centroid[j];
        d2 += diff * diff;
      }
      variance += d2;
    }
    variance /= this.recentEmbeddings.length;

    // 余弦相似度聚合检验
    var avgSimilarity = 0;
    var pairs = Math.min(20, this.recentEmbeddings.length);
    for (var k = 0; k < pairs; k++) {
      var a = this.recentEmbeddings[k];
      var b = this.recentEmbeddings[this.recentEmbeddings.length - 1 - k];
      var dot = 0, na = 0, nb = 0;
      for (var j = 0; j < dim; j++) {
        dot += a[j] * b[j];
        na += a[j] * a[j];
        nb += b[j] * b[j];
      }
      avgSimilarity += dot / (Math.sqrt(na) * Math.sqrt(nb) + 1e-10);
    }
    avgSimilarity /= pairs;

    // 低方差 + 高相似度 = 异常突发
    var normalizedVar = variance / (dim * 4);  // 归一化到 [0, 1]
    var anomalousScore = (1 - normalizedVar) * avgSimilarity;

    return {
      anomalous: anomalousScore > this.burstThreshold,
      score: anomalousScore,
      variance: normalizedVar,
      avgSimilarity: avgSimilarity,
      windowSize: this.recentEmbeddings.length,
      reason: anomalousScore > this.burstThreshold ? 'embedding_burst_detected' : 'normal',
    };
  }
}

// ============================================================================
// Layer 2: 节点信任 + 配额
// ============================================================================

class PeerTrustManager {
  constructor() {
    this.peers = new Map();          // pubkey → PeerRecord
    this.globalRateLimit = 1000;     // 全局速率上限
    this.basePerPeerRate = 100;      // 单节点基础速率
  }

  getOrCreate(pubkey) {
    if (!this.peers.has(pubkey)) {
      this.peers.set(pubkey, new PeerRecord(pubkey));
    }
    return this.peers.get(pubkey);
  }

  /**
   * 信任分计算
   * score = α·age + β·(1-burst) + γ·wot + δ·forward_ratio
   */
  calculateScore(peer) {
    var ageWeight = Math.min(1, peer.ageDays / 30);         // 30天成熟
    var burstWeight = 1 - Math.min(1, peer.burstCount / 100);
    var wotWeight = peer.wotScore;
    var fwdWeight = peer.totalRequests > 0
      ? peer.totalForwarded / peer.totalRequests
      : 0.5;

    peer.score = (
      0.25 * ageWeight +
      0.35 * burstWeight +
      0.25 * wotWeight +
      0.15 * fwdWeight
    );
    return peer.score;
  }

  /**
   * 获取节点的速率限制
   * 高信任 → 高速率；低信任 → 低速率
   */
  getRateLimit(pubkey) {
    var peer = this.getOrCreate(pubkey);
    var score = this.calculateScore(peer);
    return Math.max(1, Math.floor(this.basePerPeerRate * score));
  }

  /**
   * 报告突发
   */
  reportBurst(pubkey) {
    var peer = this.getOrCreate(pubkey);
    peer.burstCount++;
    peer.burstHistory.push(Date.now());

    // 滑动窗口: 只保留最近 1 小时
    var cutoff = Date.now() - 3600000;
    peer.burstHistory = peer.burstHistory.filter(function(t) { return t > cutoff; });
    peer.burstCount = peer.burstHistory.length;

    // 更新信任分
    this.calculateScore(peer);
  }

  /**
   * 处理 Nostr Burst Report
   */
  handleBurstReport(report) {
    // 验证签名（简化: 实际需验签）
    if (!report.sig) return;

    // 多个独立节点报告同一来源 → 累积扣分
    var target = report.suspectedSrc;
    if (target) {
      var peer = this.getOrCreate(target);
      peer.burstCount += report.burstCount || 1;
      this.calculateScore(peer);
    }
  }

  /**
   * 获取信任表摘要（用于 Nostr 广播）
   */
  getTrustSummary() {
    var summary = [];
    this.peers.forEach(function(peer, pubkey) {
      summary.push({
        pubkey: pubkey,
        score: peer.score,
        burstCount: peer.burstCount,
        ageDays: peer.ageDays,
      });
    });
    return summary.sort(function(a, b) { return a.score - b.score; });
  }
}

// ============================================================================
// Layer 3: 路径验证 + 退火降级
// ============================================================================

class PathVerifier {
  constructor() {
    this.recentPaths = new Map();    // sessionId → path
    this.maxPathLength = 8;          // 最大跳数
    this.loopDetector = new Set();
  }

  /**
   * 验证路由路径的合法性
   */
  verify(request) {
    if (!request.path || request.path.length === 0) {
      return { valid: false, reason: 'empty_path' };
    }

    if (request.path.length > this.maxPathLength) {
      return { valid: false, reason: 'path_too_long' };
    }

    // 环路检测
    var seen = new Set();
    for (var i = 0; i < request.path.length; i++) {
      var node = request.path[i];
      if (seen.has(node.pubkey)) {
        return { valid: false, reason: 'loop_detected', loopAt: node.pubkey };
      }
      seen.add(node.pubkey);

      // 签名验证（简化）
      if (!node.sig || node.sig.length < 10) {
        return { valid: false, reason: 'invalid_signature_at_' + i };
      }
    }

    // 重复路径检查
    var pathKey = request.path.map(function(n) { return n.pubkey; }).join('-');
    if (this.recentPaths.has(pathKey)) {
      var lastSeen = this.recentPaths.get(pathKey);
      if (Date.now() - lastSeen < 1000) {
        return { valid: false, reason: 'path_replay', lastSeen: lastSeen };
      }
    }
    this.recentPaths.set(pathKey, Date.now());

    return { valid: true };
  }
}

class AnnealingDropper {
  constructor() {
    this.delayTable = new Map();     // pubkey → currentDelay(ms)
    this.maxDelay = 10000;          // 最大退火延迟
    this.recoveryRate = 0.9;        // 每次恢复乘数
  }

  /**
   * 退火降级：不是直接拒绝，而是逐步增加延迟
   * 攻击者等不起，合法用户不受影响
   */
  degrade(request, burstCount) {
    var pubkey = request.srcPubkey;
    var currentDelay = this.delayTable.get(pubkey) || 0;

    if (burstCount > 10) {
      // 严重突发: 显著增加延迟
      currentDelay = Math.min(this.maxDelay, currentDelay + 1000);
    } else if (burstCount > 5) {
      currentDelay = Math.min(this.maxDelay, currentDelay + 500);
    } else {
      currentDelay = Math.min(this.maxDelay, currentDelay + 100);
    }

    this.delayTable.set(pubkey, currentDelay);

    return {
      action: 'delayed',
      delayMs: currentDelay,
      willTimeout: currentDelay >= this.maxDelay,
      reason: 'annealing_backpressure',
    };
  }

  /**
   * 定期恢复延迟（没有突发的节点逐渐恢复正常）
   */
  tickRecovery() {
    this.delayTable.forEach(function(delay, pubkey) {
      var newDelay = Math.floor(delay * this.recoveryRate);
      if (newDelay < 10) {
        this.delayTable.delete(pubkey);
      } else {
        this.delayTable.set(pubkey, newDelay);
      }
    });
  }
}

// ============================================================================
// Nostr 广播器 — 控制平面通信
// ============================================================================

class NostrBroadcaster {
  constructor(nodePrivkey) {
    this.nodePrivkey = nodePrivkey;
    this.relays = [];
    this.eventQueue = [];
  }

  addRelay(url) { this.relays.push(url); }

  /**
   * 创建并广播 Burst Report (Kind 31105)
   */
  broadcastBurstReport(suspectedSrc, burstCount) {
    var event = {
      kind: 31105,
      pubkey: this.getPublicKey(),
      content: {
        suspectedSrc: suspectedSrc,
        burstCount: burstCount,
        timestamp: Date.now(),
        nodeInfo: {
          version: 'datafew-shield-0.1',
          region: process.env.REGION || 'unknown',
        },
      },
      tags: [
        ['p', suspectedSrc],
        ['t', 'mesh-burst'],
        ['t', 'security-alert'],
      ],
      created_at: Math.floor(Date.now() / 1000),
    };
    // 实际中需签名
    event.sig = 'fake_sig_' + Date.now();
    this.eventQueue.push(event);
    return event;
  }

  /**
   * 公告节点状态 (Kind 31100)
   */
  announceNode(bandwidth, exitPolicy) {
    return {
      kind: 31100,
      content: {
        bandwidth_mbps: bandwidth,
        exit_policy: exitPolicy,
        protocols: ['wireguard', 'noise'],
        last_seen: new Date().toISOString(),
      },
    };
  }

  getPublicKey() {
    // 简化
    return 'node_' + this.nodePrivkey.slice(0, 8);
  }
}

// ============================================================================
// Mesh 安全层 (整合)
// ============================================================================

export class MeshSecurityLayer {
  constructor(opts) {
    opts = opts || {};
    this.vectorFilter = new VectorRouteFilter();
    this.trustManager = new PeerTrustManager();
    this.pathVerifier = new PathVerifier();
    this.annealer = new AnnealingDropper();
    this.broadcaster = new NostrBroadcaster(opts.nodePrivkey || 'default');
    this.stats = { totalRequests: 0, allowed: 0, blocked: 0, annealing: 0 };
  }

  /**
   * 核心方法：处理路由请求
   * 三层防护串联
   */
  handleRouteRequest(request) {
    this.stats.totalRequests++;

    // ============================================================
    // Layer 1: 向量空间 — 检测异常嵌入聚合
    // ============================================================
    if (request.embedding) {
      var vecResult = this.vectorFilter.evaluate(request.embedding);
      if (vecResult.anomalous) {
        this.stats.blocked++;
        // 广播突发告警
        this.broadcaster.broadcastBurstReport(request.srcPubkey, vecResult.score);
        return {
          allowed: false,
          layer: 'vector',
          reason: 'embedding_burst',
          score: vecResult.score,
        };
      }
    }

    // ============================================================
    // Layer 2: 节点信任 + 速率限制
    // ============================================================
    var peer = this.trustManager.getOrCreate(request.srcPubkey);
    peer.totalRequests++;

    // 信任分过滤
    var score = this.trustManager.calculateScore(peer);
    if (score < 0.1) {
      this.stats.blocked++;
      return { allowed: false, layer: 'trust', reason: 'trust_score_too_low', score: score };
    }

    // 速率限制
    var rateLimit = this.trustManager.getRateLimit(request.srcPubkey);
    if (peer.totalRequests > rateLimit) {
      // 退火降级
      var annealResult = this.annealer.degrade(request, peer.burstCount);
      this.stats.annealing++;

      // 如果退火达到上限，拦截
      if (annealResult.willTimeout) {
        this.trustManager.reportBurst(request.srcPubkey);
        this.broadcaster.broadcastBurstReport(request.srcPubkey, peer.burstCount);
        this.stats.blocked++;
        return { allowed: false, layer: 'rate_limit', reason: annealResult.reason, delayMs: annealResult.delayMs };
      }

      peer.lastSeen = Date.now();
      this.stats.allowed++;
      return {
        allowed: true,
        layer: 'rate_limit',
        action: 'delayed',
        delayMs: annealResult.delayMs,
        reason: 'rate_limit_backpressure',
      };
    }

    // ============================================================
    // Layer 3: 路径验证
    // ============================================================
    if (request.path && request.path.length > 0) {
      var pathResult = this.pathVerifier.verify(request);
      if (!pathResult.valid) {
        this.trustManager.reportBurst(request.srcPubkey);
        this.stats.blocked++;
        return { allowed: false, layer: 'path', reason: pathResult.reason };
      }
    }

    // ============================================================
    // 通过：转发请求
    // ============================================================
    peer.lastSeen = Date.now();
    peer.totalForwarded++;
    this.stats.allowed++;

    return {
      allowed: true,
      layer: 'all',
      reason: 'passed',
      score: score,
      trustLevel: score > 0.7 ? 'high' : score > 0.3 ? 'medium' : 'low',
    };
  }

  /**
   * 接收 Nostr Burst Report
   */
  handleBurstReport(report) {
    this.trustManager.handleBurstReport(report);
  }

  /**
   * 心跳：恢复退火、广播节点状态
   */
  tick() {
    this.annealer.tickRecovery();
  }

  getStats() {
    var s = Object.assign({}, this.stats);
    s.blockRate = s.totalRequests > 0
      ? Math.round(s.blocked / s.totalRequests * 1000) / 10
      : 0;
    s.peersTracked = this.trustManager.peers.size;
    return s;
  }

  getLowTrustPeers() {
    return this.trustManager.getTrustSummary().filter(function(p) { return p.score < 0.3; });
  }
}

// ============================================================================
// CLI 演示
// ============================================================================

if (process.argv[1] && process.argv[1].endsWith('mesh_security.js')) {
  console.log('Datafew Shield — Mesh Security Layer Demo');
  console.log('='.repeat(70));

  var mesh = new MeshSecurityLayer({ nodePrivkey: 'demo-node' });

  // 模拟正常路由请求
  console.log('\n1. Normal route requests (分散的 embedding):');
  for (var i = 0; i < 20; i++) {
    var req = new RouteRequest({
      pubkey: 'peer-normal-' + (i % 3),
      content: { target: 'node-' + i },
      embedding: [Math.random(), Math.random(), Math.random()],
    });
    mesh.handleRouteRequest(req);
  }
  console.log('  Allowed:', mesh.stats.allowed, 'Blocked:', mesh.stats.blocked);

  // 模拟 DDoS 攻击（相同 embedding 区域）
  console.log('\n2. DDoS attack (embedding burst, same region):');
  var attackVector = [0.8, 0.1, 0.3];
  for (var i = 0; i < 30; i++) {
    var req = new RouteRequest({
      pubkey: 'attacker-' + (i % 5),
      content: { target: 'victim-node' },
      embedding: [
        attackVector[0] + (Math.random() - 0.5) * 0.05,
        attackVector[1] + (Math.random() - 0.5) * 0.05,
        attackVector[2] + (Math.random() - 0.5) * 0.05,
      ],
    });
    var r = mesh.handleRouteRequest(req);
    process.stdout.write(r.allowed ? '.' : 'x');
  }
  console.log('\n  Allowed:', mesh.stats.allowed, 'Blocked:', mesh.stats.blocked);

  // 统计
  console.log('\n3. Mesh Security Stats:');
  console.log(JSON.stringify(mesh.getStats(), null, 2));

  console.log('\n4. Low trust peers:');
  var low = mesh.getLowTrustPeers();
  low.forEach(function(p) {
    console.log('  ' + p.pubkey + ' score=' + p.score.toFixed(2) + ' bursts=' + p.burstCount);
  });
}
