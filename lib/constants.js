export const RATE_LIMIT_WINDOW_MS = 60_000;
export const RATE_LIMIT_MAX = 100;
export const MAX_BODY_SIZE = 1_048_576;

export const EMBEDDING_SERVER_PORT = 5000;
export const EMBEDDING_TIMEOUT_MS = 5000;
export const EMBEDDING_SERVER_CHECK_INTERVAL_MS = 30_000;
export const EMBEDDING_HEALTH_POLL_MS = 3000;

export const FALLBACK_HIGH_SCORE = 0.85;
export const DEFAULT_SCORE = 0.5;

export const MAX_AUDIT_TEXT_LENGTH = 200;
export const MAX_SANDBOX_HISTORY = 10;
export const MAX_AUDIT_LOG_SIZE = 10000;

export const STORE_TTL_MS = 3_600_000;
export const STORE_CLEANUP_INTERVAL_MS = 300_000;
export const MAX_STORE_ENTRIES = 10_000;

export const DLP_TAINT_DECAY_MS = 1_800_000;

export const POLICY_DECAY_FACTOR = 0.95;
export const POLICY_RISK_INCREMENT = 0.3;
export const POLICY_RISK_LOCK_THRESHOLD = 0.8;

export const SEMANTIC_EMA_ALPHA = 0.85;
export const SEMANTIC_RISK_LOCK_THRESHOLD = 0.62;

export const BEHAVIOR_RISK_INCREMENT = 0.15;
export const BEHAVIOR_RISK_DECAY = 0.9;
export const BEHAVIOR_RISK_LOCK_THRESHOLD = 0.6;

export const L3_IMMEDIATE_RISK_RATIO = 1.0;

export const L1_HIGH_CONFIDENCE_THRESHOLD = 0.7;
export const L1_HIGH_SCORE_OFFSET = 0.1;

export const MAX_FEEDBACK_TEXT_LENGTH = 1000;
export const MAX_FEEDBACK_RATE_PER_MIN = 60;
export const MAX_FEEDBACK_LOG_SIZE = 1000;

export const APPROVAL_TIMEOUT_MS = 30000;

export const EGRESS_TOOLS = ['curl', 'wget', 'nc', 'ncat', 'socat', 'telnet', 'ssh', 'ftp', 'scp', 'send_message'];

export const DATA_LEVELS = { P0: 'credential', P1: 'pii', P2: 'financial', P3: 'internal', P4: 'public' };
export const DATA_LEVEL_RANK = { P0: 0, P1: 1, P2: 2, P3: 3, P4: 4 };
export const DLP_TAINT_RANK = { P0: 3, P1: 2, P2: 1, P3: 0, P4: 0 };
export const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

export const SHIELD_PORT = 8080;
export const DEFAULT_DLP_TAINT = 0;

export const MAX_IDENTITY_VALUES_PER_KEY = 100;
export const MAX_IDENTITY_SEARCH_RESULTS = 50;
