import { DataRegistry, CLASSIFICATION, classifyPath, scanContent, classifyResource } from './classify.js';

class AccessController {
  constructor() {
    this.registry = new DataRegistry();
    this.pendingApprovals = new Map();
    this.approvalTimeout = 30000;
  }

  check(sessionId, action, resource, content) {
    const classification = this.registry.classify(resource);
    const contentMatches = content ? this.registry.scanContentFull(content) : [];
    let riskLevel = classification.level;
    if (contentMatches.length > 0) {
      const minLevel = Math.min(...contentMatches.map(m => ({ critical: 0, high: 1, medium: 2 }[m.severity] || 3)));
      riskLevel = Math.min(riskLevel, minLevel);
    }
    if (riskLevel === 0) {
      return { allowed: false, reason: 'credential_access_denied', riskLevel: 0, classification: classification.classification };
    }
    if (riskLevel === 1 || riskLevel === 2) {
      return { allowed: false, requiresApproval: true, reason: 'sensitive_data_access', riskLevel, classification: classification.classification, suggestedAction: 'prompt_approval' };
    }
    if (riskLevel === 3) {
      return { allowed: true, reason: 'internal_allowed', riskLevel: 3, classification: classification.classification };
    }
    return { allowed: true, reason: 'public_allowed', riskLevel: 4, classification: classification.classification };
  }

  requestApproval(sessionId, action, resource, riskLevel) {
    return new Promise((resolve) => {
      const approvalId = 'app-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 6);
      const pending = {
        id: approvalId, sessionId, action, resource, riskLevel, time: Date.now(),
        timeout: setTimeout(() => { this.pendingApprovals.delete(sessionId); resolve({ allowed: false, reason: 'approval_timeout' }); }, this.approvalTimeout),
        resolve,
      };
      this.pendingApprovals.set(sessionId, pending);
      this.onApprovalRequested(pending);
    });
  }

  handleApproval(sessionId, approved) {
    const pending = this.pendingApprovals.get(sessionId);
    if (!pending) return { error: 'no_pending_approval' };
    clearTimeout(pending.timeout);
    this.pendingApprovals.delete(sessionId);
    pending.resolve({ allowed: approved, reason: approved ? 'user_approved' : 'user_denied' });
    return { ok: true };
  }

  onApprovalRequested(pending) {
    console.log('[AccessControl] Approval needed: ' + pending.action + ' ' + pending.resource);
    console.log('[AccessControl]  Approval ID: ' + pending.id);
    console.log('[AccessControl]  Auto-deny in ' + this.approvalTimeout / 1000 + 's');
  }
}

export class DataShield {
  constructor() {
    this.registry = new DataRegistry();
    this.access = new AccessController();
    this.stats = { checks: 0, blocked: 0, approved: 0, denied: 0 };
  }

  evaluate(request) {
    this.stats.checks++;
    let result = { allowed: true, reason: 'passed', riskLevel: 4 };
    const resource = request.resource || request.args || '';
    const action = request.action || request.type || 'read';
    const content = request.content || null;
    if (resource) {
      const check = this.access.check(request.session_id, action, resource, content);
      if (!check.allowed && check.requiresApproval) {
        this.stats.blocked++;
        return { ...check, allowed: false, approvalRequired: true, message: '需要授权才能访问 ' + resource };
      }
      if (!check.allowed) {
        this.stats.blocked++;
        return { ...check, allowed: false };
      }
      result = check;
    }
    return result;
  }

  approve(sessionId, approved) {
    const r = this.access.handleApproval(sessionId, approved);
    if (approved) this.stats.approved++; else this.stats.denied++;
    return r;
  }

  addSensitiveResource(classification, path) {
    this.registry.register(classification, [path]);
  }

  getStats() {
    return { ...this.stats, registeredResources: this.registry.resources.length, pendingApprovals: this.access.pendingApprovals.size };
  }
}
