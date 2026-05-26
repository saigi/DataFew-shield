import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));

export class PolicyEngine {
  constructor(policyDir) {
    this.policyDir = policyDir || resolve(__dirname, '..', 'policies');
    this.policies = [];
    this.attackPatterns = this.buildAttackPatterns();
    this.loadPolicies();
  }

  loadPolicies() {
    if (!existsSync(this.policyDir)) return;
    const files = readdirSync(this.policyDir).filter(f => f.endsWith('.json'));
    this.policies = [];
    for (let i = 0; i < files.length; i++) {
      try {
        const parsed = JSON.parse(readFileSync(resolve(this.policyDir, files[i]), 'utf-8'));
        if (Array.isArray(parsed)) { for (let p = 0; p < parsed.length; p++) this.policies.push(parsed[p]); }
        else { this.policies.push(parsed); }
      } catch (e) { console.error('[Policy] Load failed:', files[i], e.message); }
    }
    console.error('[Policy] Loaded ' + this.policies.length + ' rules');
  }

  matchPolicy(policy, context) {
    if (!policy?.match) return null;
    const m = policy.match;
    if (m.type && m.type !== context.type) return null;
    if (m.tool && m.tool !== context.tool) return null;
    if (m.args_pattern) {
      if (!context.args) return null;
      const normalized = String(context.args)
        .normalize('NFKC')
        .replace(/[\u200B-\u200D\uFEFF]/g, '')
        .replace(/[\uFF01-\uFF5E]/g, c => String.fromCharCode(c.charCodeAt(0) - 0xFEE0));
      try { if (!new RegExp(m.args_pattern, 'i').test(normalized)) return null; } catch (e) { return null; }
    }
    return { allowed: policy.action !== 'block', reason: policy.reason || 'policy:' + policy.id, severity: policy.severity || 'high', policy_id: policy.id };
  }

  evaluate(context) {
    if (!context?.type) return { allowed: true };
    for (let i = 0; i < this.policies.length; i++) { const r = this.matchPolicy(this.policies[i], context); if (r) return r; }
    return { allowed: true };
  }

  buildAttackPatterns() {
    return [
      { name: 'credential_exfil', severity: 'critical', steps: [
        { tool: ['read_file', 'terminal'], args: ['id_rsa', 'id_ecdsa', 'id_ed25519', 'authorized_keys', '.ssh', 'credential', 'secret'] },
        { tool: ['read_file', 'terminal'], args: ['.ssh', 'id_rsa', 'config', 'known_hosts', 'token', 'key'] },
        { tool: ['send_message', 'terminal'], args: ['@', 'curl', 'http', 'exfil', 'upload'] },
      ]},
      { name: 'reverse_shell', severity: 'critical', steps: [
        { tool: ['terminal'], args: ['nc -l', 'ncat -l', 'socat', 'listen'] },
        { tool: ['terminal'], args: ['/dev/tcp/', '/dev/udp/', 'bash -i', 'connect'] },
      ]},
      { name: 'data_destruction', severity: 'high', steps: [
        { tool: ['terminal'], args: ['dd if=', 'mkfs', 'fdisk', 'parted'] },
        { tool: ['terminal'], args: ['rm -rf', 'shred', 'wipefs', 'mkfs'] },
      ]},
      { name: 'recon_scan', severity: 'medium', steps: [
        { tool: ['terminal'], args: ['nmap', 'masscan', 'zmap', 'whois'] },
        { tool: ['terminal'], args: ['ssh ', 'telnet', 'nc -v', 'curl -v'] },
      ]},
    ];
  }

  detectAttackChain(history, currentCall) {
    if (!history || history.length < 1) return null;
    const calls = [];
    for (let i = 0; i < history.length; i++) { if (history[i].type === 'tool_call') calls.push({ tool: history[i].tool, args: history[i].args || '' }); }
    if (currentCall) calls.push({ tool: currentCall.tool, args: currentCall.args || '' });
    if (calls.length < 2) return null;
    for (let p = 0; p < this.attackPatterns.length; p++) {
      const ap = this.attackPatterns[p];
      if (ap.steps.length > calls.length) continue;
      for (let start = 0; start <= calls.length - ap.steps.length; start++) {
        let ok = true;
        for (let s = 0; s < ap.steps.length; s++) {
          const step = ap.steps[s], cmd = calls[start + s];
          let tOk = false; for (let t = 0; t < step.tool.length; t++) { if (cmd.tool === step.tool[t] || cmd.tool.includes(step.tool[t])) { tOk = true; break; } }
          if (!tOk) { ok = false; break; }
          let aOk = false; for (let a = 0; a < step.args.length; a++) { if (cmd.args.toLowerCase().includes(step.args[a].toLowerCase())) { aOk = true; break; } }
          if (!aOk) { ok = false; break; }
        }
        if (ok) return { detected: true, pattern: ap.name, severity: ap.severity, matched_at: start };
      }
    }
    return null;
  }
}
