import {
  POLICY_DECAY_FACTOR, POLICY_RISK_INCREMENT, POLICY_RISK_LOCK_THRESHOLD,
  SEMANTIC_EMA_ALPHA, SEMANTIC_RISK_LOCK_THRESHOLD,
  BEHAVIOR_RISK_INCREMENT, BEHAVIOR_RISK_DECAY, BEHAVIOR_RISK_LOCK_THRESHOLD,
  L3_IMMEDIATE_RISK_RATIO,
  L1_HIGH_CONFIDENCE_THRESHOLD, L1_HIGH_SCORE_OFFSET,
  MAX_AUDIT_TEXT_LENGTH, MAX_FEEDBACK_TEXT_LENGTH, MAX_FEEDBACK_RATE_PER_MIN,
} from './constants.js';
import { SandboxManager } from './sandbox.js';
import { AuditEngine } from './audit.js';
import { PolicyEngine } from './policy.js';
import {
  getEmbeddingRefs, getEmbeddingServerReady, getL3ImmediateLock, setL3ImmediateLock,
  EMBEDDING_THRESHOLD, queryEmbeddingServer, fallbackScore,
} from './embedding.js';
import { classifyPath, scanContent, dataDecision } from './classify.js';
import {
  getSessionProfile, getVisitorProfile, recordIdentity,
  VISITOR_STORE, SESSION_STORE, searchIdentities, checkDLP,
} from './session.js';
import { recordFeedback, VALID_OUTCOMES, feedbackRateCounts } from './feedback.js';

export class Shield {
  constructor(opts) {
    opts = opts || {};
    this.policyEngine = new PolicyEngine(opts.policyDir);
    this.sandboxManager = new SandboxManager();
    this.auditEngine = new AuditEngine();
    this.server = null;

    const refs = getEmbeddingRefs();
    console.error('[Shield] L1(embedding): ' + (refs ? refs.harmful.count + ' refs' : 'DISABLED'));
    console.error('[Shield] L2(data): active');
    console.error('[Shield] L3(session): active');
    console.error('[Shield] L4(feedback): active');
    console.error('[Shield] Policy: ' + this.policyEngine.policies.length + ' rules');
  }

  async inspect(request) {
    const sid = request.session_id || 'default';
    const audit = {
      type: request.type, tool: request.tool,
      args: String(request.args || '').slice(0, MAX_AUDIT_TEXT_LENGTH),
      session_id: sid, action: 'pending',
    };
    let finalAllowed = true, finalReason = 'passed', finalLayer = 'L_all';

    const textToScore = request.text || request.args || '';
    const visitorId = request.visitor_id || request.visitorId || null;

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

    // L0: 沙箱
    const sc = this.sandboxManager.validate(sid);
    if (!sc.ok) {
      audit.action = 'blocked'; audit.reason = sc.reason; audit.layer = 'L0';
      this.auditEngine.record(audit);
      return { allowed: false, reason: sc.reason, severity: 'critical', layer: 'L0', audit_id: audit.id };
    }

    // L0: 策略
    const pr = this.policyEngine.evaluate({ type: request.type, tool: request.tool, args: request.args });
    if (!pr.allowed) {
      audit.action = 'blocked'; audit.reason = pr.reason; audit.layer = 'L0_policy'; audit.policy_id = pr.policy_id;
      this.auditEngine.record(audit);
      this.sandboxManager.record(sid, { type: 'tool_call', tool: request.tool, args: request.args, result: 'blocked_by_policy' });
      finalAllowed = false; finalReason = pr.reason; finalLayer = 'L0_policy';
    }

    // L2: 数据分类
    const resourcePath = request.resource || request.args || '';
    if (resourcePath && finalAllowed) {
      let level = classifyPath(resourcePath);
      if (request.content) {
        const contentLevel = scanContent(request.content);
        const RANK = { P0: 0, P1: 1, P2: 2, P3: 3, P4: 4 };
        if (RANK[contentLevel] < RANK[level]) level = contentLevel;
      }
      const dd = dataDecision(level);
      if (!dd.allowed) {
        audit.action = 'blocked'; audit.reason = dd.reason; audit.layer = 'L2';
        this.auditEngine.record(audit);
        finalAllowed = false; finalReason = dd.reason; finalLayer = 'L2';
      }
    }

    // DLP: 数据血缘追踪
    const profile = getSessionProfile(sid, visitorId);
    const dlpResult = checkDLP(profile, request, resourcePath, request.content);
    if (dlpResult.blocked && finalAllowed) {
      audit.action = 'blocked'; audit.reason = dlpResult.reason; audit.layer = 'DLP';
      this.auditEngine.record(audit);
      this.sandboxManager.record(sid, { type: 'tool_call', tool: request.tool, args: request.args, result: 'blocked_by_dlp' });
      finalAllowed = false; finalReason = dlpResult.reason; finalLayer = 'DLP';
    }

    // L0: 攻击链
    if (finalAllowed) {
      const history = (sc.sandbox ? sc.sandbox.history : []).concat(request.history || []);
      const cr = this.policyEngine.detectAttackChain(history, { tool: request.tool, args: request.args });
      if (cr) {
        audit.action = 'blocked'; audit.reason = 'chain:' + cr.pattern; audit.chain_detected = true; audit.layer = 'L0_chain';
        this.auditEngine.record(audit);
        this.sandboxManager.record(sid, { type: 'tool_call', tool: request.tool, args: request.args, result: 'blocked_by_chain' });
        finalAllowed = false; finalReason = 'attack_chain'; finalLayer = 'L0_chain';
      }
    }

    // L1: 向量空间
    const decisions = [];
    let embeddingScoreVal = 0.5;
    const refs = getEmbeddingRefs();

    if (refs && textToScore && textToScore.length > 3) {
      let embeddingOk = false;
      if (getEmbeddingServerReady()) {
        const l1Result = await queryEmbeddingServer(textToScore);
        if (l1Result && l1Result.score !== undefined && l1Result.score >= 0) {
          embeddingScoreVal = l1Result.score;
          embeddingOk = true;
          const curThreshold = l1Result.threshold || EMBEDDING_THRESHOLD;
          setL3ImmediateLock(curThreshold);

          const rawScore = Math.max(0.001, Math.min(0.999, embeddingScoreVal));
          const logitScore = Math.log(rawScore / (1 - rawScore));
          const logitConfidence = 1 / (1 + Math.exp(-Math.abs(logitScore)));

          decisions.push({
            layer: 'L1', source: 'embedding_server',
            score: embeddingScoreVal, logitScore,
            confidence: logitConfidence,
            threshold: curThreshold,
          });

          if (!finalAllowed) {
            // Already blocked by deterministic layer
          } else if (logitConfidence > L1_HIGH_CONFIDENCE_THRESHOLD && embeddingScoreVal > curThreshold) {
            audit.action = 'blocked'; audit.reason = 'semantic_high_confidence'; audit.layer = 'L1';
            audit.l1_score = embeddingScoreVal; audit.l1_confidence = logitConfidence;
            this.auditEngine.record(audit);
            this.sandboxManager.record(sid, { type: 'tool_call', tool: request.tool, args: request.args, result: 'blocked_by_l1' });
            finalAllowed = false; finalReason = 'semantic_high_confidence'; finalLayer = 'L1';
          } else if (embeddingScoreVal > curThreshold + L1_HIGH_SCORE_OFFSET) {
            audit.action = 'blocked'; audit.reason = 'semantic_high_score'; audit.layer = 'L1';
            this.auditEngine.record(audit);
            this.sandboxManager.record(sid, { type: 'tool_call', tool: request.tool, args: request.args, result: 'blocked_by_l1' });
            finalAllowed = false; finalReason = 'semantic_high_score'; finalLayer = 'L1';
          }
        }
      }
      if (!embeddingOk) {
        embeddingScoreVal = fallbackScore(textToScore);
        if (embeddingScoreVal > 0.6) {
          decisions.push({ layer: 'L1', source: 'fallback', score: embeddingScoreVal, note: 'no_embedding_server' });
        }
      }
    }

    // L3: 会话风险
    const wasBlocked = !finalAllowed;

    if (profile.policyRisk === undefined) profile.policyRisk = 0;
    if (profile.semanticRisk === undefined) profile.semanticRisk = 0;
    if (profile.behaviorRisk === undefined) profile.behaviorRisk = 0;

    if (wasBlocked && (finalLayer === 'L0_policy' || finalLayer === 'L2' || finalLayer === 'L0_chain')) {
      profile.policyRisk = Math.min(1, profile.policyRisk + POLICY_RISK_INCREMENT);
    } else {
      profile.policyRisk *= POLICY_DECAY_FACTOR;
    }

    profile.semanticRisk = SEMANTIC_EMA_ALPHA * profile.semanticRisk + (1 - SEMANTIC_EMA_ALPHA) * embeddingScoreVal;

    if (request.tool) {
      if (profile.lastTool !== request.tool) {
        profile.behaviorRisk = Math.min(1, profile.behaviorRisk + BEHAVIOR_RISK_INCREMENT);
        profile.lastTool = request.tool;
      } else {
        profile.behaviorRisk *= BEHAVIOR_RISK_DECAY;
      }
    }

    const immediateSemanticRisk = embeddingScoreVal * L3_IMMEDIATE_RISK_RATIO;
    const effectivePolicyRisk = profile.policyRisk;
    const effectiveSemanticRisk = Math.max(profile.semanticRisk, immediateSemanticRisk);
    const effectiveBehaviorRisk = profile.behaviorRisk;
    const effectiveRisk = Math.max(effectivePolicyRisk, effectiveSemanticRisk, effectiveBehaviorRisk);

    const lockThreshold = getL3ImmediateLock() || SEMANTIC_RISK_LOCK_THRESHOLD;
    const policyLock = effectivePolicyRisk > POLICY_RISK_LOCK_THRESHOLD;
    const semanticLock = effectiveSemanticRisk > lockThreshold;
    const behaviorLock = effectiveBehaviorRisk > BEHAVIOR_RISK_LOCK_THRESHOLD;

    if (policyLock || semanticLock || behaviorLock) {
      profile.locked = true;
      const lockReason = policyLock ? 'risk_lock_policy' : (semanticLock ? 'risk_lock_semantic' : 'risk_lock_behavior');
      if (finalAllowed) {
        audit.action = 'blocked'; audit.reason = lockReason; audit.layer = 'L3';
        this.auditEngine.record(audit);
        this.sandboxManager.record(sid, { type: 'tool_call', tool: request.tool, args: request.args, result: 'blocked_by_session' });
        finalAllowed = false; finalReason = lockReason; finalLayer = 'L3';
      }
    }

    decisions.push({
      layer: 'L3',
      policyRisk: profile.policyRisk, semanticRisk: profile.semanticRisk,
      behaviorRisk: profile.behaviorRisk, effectiveRisk,
      locked: profile.locked,
    });

    if (profile.visitorId) {
      const visitor = getVisitorProfile(profile.visitorId);
      visitor.lastSeen = Date.now();
      const contribution = effectiveRisk * 0.5;
      if (contribution > visitor.risk) visitor.risk = contribution;
      if (profile.locked && !visitor.tags.includes('session_locked')) visitor.tags.push('session_locked');
      if (wasBlocked) visitor.blockedCount++;
    }

    profile.phase = profile.locked ? 'lockdown' : (effectiveRisk > 0.3 ? 'execution' : (effectiveRisk > 0.15 ? 'focus' : 'exploration'));
    if (profile.locked) profile.tags = ['locked']; else profile.tags = [];

    // 记录最终结果
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
      audit_id: audit.id, decisions,
    };
  }

  async inspectOutput(text) {
    const refs = getEmbeddingRefs();
    if (!refs || !text || text.length < 5) return { harmful: false, score: 0.5 };

    let scoreVal = 0.5, meta = null;
    if (getEmbeddingServerReady()) {
      meta = await queryEmbeddingServer(text);
      if (meta?.score !== undefined && meta.score >= 0) {
        scoreVal = meta.score;
      }
    }

    const curThreshold = meta?.threshold || EMBEDDING_THRESHOLD;
    const harmful = scoreVal > curThreshold;
    const outputThreshold = Math.max(0.55, curThreshold + 0.05);
    const block = scoreVal > outputThreshold;

    return { harmful, score: scoreVal, threshold: outputThreshold, block };
  }

  feedback(requestId, outcome, text) {
    return recordFeedback(requestId, outcome, text);
  }
}
