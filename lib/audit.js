import { MAX_AUDIT_LOG_SIZE } from './constants.js';

export class AuditEngine {
  constructor() {
    this.logs = [];
    this.metrics = { checks: 0, blocked: 0, allowed: 0 };
  }

  record(e) {
    e.id = 'a-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 6);
    e.ts = new Date().toISOString();
    this.logs.push(e);
    this.metrics.checks++;
    if (e.action === 'blocked') this.metrics.blocked++;
    if (e.action === 'allowed') this.metrics.allowed++;
    if (this.logs.length > MAX_AUDIT_LOG_SIZE) this.logs.shift();
    return e;
  }

  getMetrics() {
    const m = { ...this.metrics };
    m.block_rate = m.checks > 0 ? Math.round(m.blocked / m.checks * 1000) / 10 : 0;
    return m;
  }

  recent(n) {
    return this.logs.slice(-(n || 100));
  }
}
