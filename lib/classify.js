import { SEVERITY_RANK } from './constants.js';

const CLASSIFICATION = {
  CREDENTIAL: 'credential',
  PII: 'pii',
  FINANCIAL: 'financial',
  INTERNAL: 'internal',
  PUBLIC: 'public',
};

const SENSITIVE_PATTERNS = [
  { level: 'P0', patterns: ['/etc/shadow', '/etc/passwd', '.ssh/id_rsa', '.ssh/id_ecdsa', '.ssh/authorized_keys', '.aws/credentials', '.gcloud/', '/.kube/config', 'credentials.json', 'service-account.json', '*.pem', '*secret*'] },
  { level: 'P1', patterns: ['users.csv', 'customer*.csv', 'employee*', 'personal*', 'phone*', 'address*'] },
  { level: 'P2', patterns: ['payment*', 'transaction*', 'invoice*', 'bank*', 'financial*'] },
];

const CONTENT_PATTERNS = [
  { level: 'P0', re: /(password\s*[:=]|PASSWORD\s*[:=]|DB_PASSWORD|SECRET_KEY|sk-\w+|api_key\s*[:=]|token\s*[:=])/i },
  { level: 'P1', re: /(\d{11}|@gmail\.com|@outlook\.com|手机号|身份证)/i },
  { level: 'P2', re: /(银行卡|信用卡|cvv|card_number|银行账户)/i },
];

function pathToRegex(pattern) {
  const escaped = pattern
    .replace(/\*\*/g, '<<DS>>')
    .replace(/\*/g, '[^/]*')
    .replace(/<<DS>>/g, '.*')
    .replace(/\?/g, '.')
    .replace(/\./g, '\\.');
  return new RegExp('^' + escaped + '$', 'i');
}

export function classifyPath(path) {
  if (!path || typeof path !== 'string') return 'P4';
  const resolved = resolvePath(path);
  for (let i = 0; i < SENSITIVE_PATTERNS.length; i++) {
    for (let j = 0; j < SENSITIVE_PATTERNS[i].patterns.length; j++) {
      const pat = SENSITIVE_PATTERNS[i].patterns[j].replace(/\*/g, '.*');
      try {
        if (new RegExp(pat, 'i').test(resolved)) return SENSITIVE_PATTERNS[i].level;
      } catch (e) { /* skip invalid pattern */ }
    }
  }
  if (/^\/(workspace|project|src)\//.test(resolved)) return 'P3';
  return 'P4';
}

function resolvePath(path) {
  if (!path || typeof path !== 'string') return '';
  const parts = path.replace(/\\/g, '/').split('/');
  const resolved = [];
  for (const p of parts) {
    if (p === '..') {
      if (resolved.length > 0) resolved.pop();
    } else if (p !== '.' && p !== '') {
      resolved.push(p);
    }
  }
  return '/' + resolved.join('/');
}

export function scanContent(content) {
  if (!content || typeof content !== 'string') return 'P4';
  for (let i = 0; i < CONTENT_PATTERNS.length; i++) {
    if (CONTENT_PATTERNS[i].re.test(content)) return CONTENT_PATTERNS[i].level;
  }
  return 'P4';
}

export function dataDecision(level) {
  if (level === 'P0') return { allowed: false, reason: 'credential_blocked', riskLevel: 0 };
  if (level === 'P1' || level === 'P2') return { allowed: false, reason: 'sensitive_data', riskLevel: level === 'P1' ? 1 : 2, requiresApproval: true };
  if (level === 'P3') return { allowed: true, reason: 'internal_allowed', riskLevel: 3 };
  return { allowed: true, reason: 'public_allowed', riskLevel: 4 };
}

export function classifyResource(path, content) {
  let level = classifyPath(path);
  if (content) {
    const contentLevel = scanContent(content);
    const RANK = { P0: 0, P1: 1, P2: 2, P3: 3, P4: 4 };
    if (RANK[contentLevel] < RANK[level]) level = contentLevel;
  }
  return { level, decision: dataDecision(level) };
}

class DataRegistry {
  constructor() {
    this.resources = [];
    this.patterns = [];
    this.initDefaultPatterns();
  }

  initDefaultPatterns() {
    this.register(CLASSIFICATION.CREDENTIAL, [
      '/etc/shadow', '/etc/passwd', '/etc/security/',
      '~/.ssh/id_rsa', '~/.ssh/id_ecdsa', '~/.ssh/id_ed25519',
      '~/.ssh/authorized_keys', '~/.ssh/config',
      '~/.aws/credentials', '~/.aws/config',
      '~/.gcloud/', '~/.kube/config',
      '**/credentials.json', '**/service-account.json',
      '**/*.pem', '**/*key*', '**/secret*',
    ]);
    this.register(CLASSIFICATION.PII, [
      '**/users.csv', '**/customer*.csv',
      '**/employee*.xlsx', '**/personal*.json',
      '**/phone*.txt', '**/address*.csv',
    ]);
    this.register(CLASSIFICATION.FINANCIAL, [
      '**/payment*.csv', '**/transaction*.csv',
      '**/invoice*.pdf', '**/bank*.xlsx',
      '**/financial*.json',
    ]);
    this.register(CLASSIFICATION.INTERNAL, [
      '/workspace/**', '/project/**', '/src/**',
      '**/*.env', '**/config.*',
      '**/Dockerfile', '**/docker-compose.yml',
      '**/*.yaml', '**/*.yml', '**/*.tf',
    ]);
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
    for (let i = 0; i < globs.length; i++) {
      this.resources.push({
        classification,
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

  classify(path) {
    const resolved = resolvePath(path);
    for (let i = 0; i < this.resources.length; i++) {
      if (this.resources[i].glob.test(resolved)) {
        return {
          classification: this.resources[i].classification,
          level: this.levelOf(this.resources[i].classification),
          matchedBy: this.resources[i].original,
        };
      }
    }
    return { classification: CLASSIFICATION.PUBLIC, level: 4 };
  }

  scanContentFull(content) {
    if (!content || typeof content !== 'string') return [];
    const matches = [];
    for (let i = 0; i < this.patterns.length; i++) {
      for (let j = 0; j < this.patterns[i].patterns.length; j++) {
        try {
          const re = new RegExp(this.patterns[i].patterns[j], 'i');
          if (re.test(content)) {
            matches.push({ level: this.patterns[i].level, name: this.patterns[i].name, severity: this.patterns[i].severity });
            break;
          }
        } catch (e) { /* invalid regex */ }
      }
    }
    return matches;
  }

  levelOf(classification) {
    const levels = { credential: 0, pii: 1, financial: 2, internal: 3, public: 4 };
    return levels[classification] !== undefined ? levels[classification] : 4;
  }
}

export { DataRegistry, CLASSIFICATION, SENSITIVE_PATTERNS, CONTENT_PATTERNS };
