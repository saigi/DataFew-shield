import { MAX_SANDBOX_HISTORY } from './constants.js';

export class SandboxManager {
  constructor() {
    this.sandboxes = new Map();
  }

  createSandbox(id, cfg) {
    const sb = {
      id: id || 's-' + Date.now(),
      config: cfg || {},
      state: 'active',
      created: Date.now(),
      history: [],
    };
    this.sandboxes.set(sb.id, sb);
    return sb;
  }

  validate(sid) {
    if (!sid) return { ok: false, reason: 'sandbox_not_found' };
    const sb = this.sandboxes.get(sid);
    if (!sb) return { ok: false, reason: 'sandbox_not_found' };
    if (sb.state !== 'active') return { ok: false, reason: 'sandbox_inactive' };
    return { ok: true, sandbox: sb };
  }

  record(sid, e) {
    const sb = this.sandboxes.get(sid);
    if (!sb) return;
    sb.history.push(e);
    if (sb.history.length > MAX_SANDBOX_HISTORY) sb.history.shift();
  }
}
