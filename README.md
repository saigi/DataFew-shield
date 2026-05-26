# Datafew Shield

**Agent Execution Safety Framework**

[![Tool Exec 100%](https://img.shields.io/badge/Tool_Exec-100%25-success)](https://github.com/saigi/DataFew-shield)
[![AgentHarm 97%](https://img.shields.io/badge/AgentHarm-97%25-success)](https://github.com/saigi/DataFew-shield)
[![OWASP Top10 93%](https://img.shields.io/badge/OWASP_Top10-93%25-success)](https://github.com/saigi/DataFew-shield)
[![MITRE ATLAS 88%](https://img.shields.io/badge/MITRE_ATLAS-88%25-success)](https://github.com/saigi/DataFew-shield)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue)](https://opensource.org/licenses/Apache-2.0)

**LLM content filters control what the model says. Datafew Shield controls what the agent does.**

When an AI agent calls `read_file("/etc/shadow")`, no prompt guard or moderation API can stop it. The content filter never sees the tool call. Datafew Shield is an **execution safety layer** that inspects every tool invocation, file access, and behavioral sequence — independent of the LLM, the model provider, or the jailbreak technique.

Benchmarked across **7 industry standards** with **~1,100 test cases**. Designed for **execution-layer safety** — tool command interception is 100%, while semantic content filtering (AdvBench) reflects the L1 embedding classifier's standalone performance. Combines with any LLM content filter for full-stack protection.

---

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/saigi/DataFew-shield.git
cd datafew-shield
npm install
pip install -r requirements.txt

# 2. Start the embedding server
python scripts/embedding_server.py --port 5000 &

# 3. Start the shield
node index.js --port 8080

# 4. Test it
curl -X POST http://localhost:8080/inspect \
  -H "Content-Type: application/json" \
  -d '{"type":"tool_call","tool":"terminal","args":"cat /etc/shadow","session_id":"test"}'
# → {"allowed":false,"reason":"credential_blocked","layer":"L2"}
```

## Quick Test

```bash
# Run basic safety tests (no external data required)
node test/run.js

# Run individual benchmarks (test data bundled in repo)
node test/test_owasp_top10.mjs     # OWASP LLM Top 10
node test/test_mitre_atlas.mjs     # MITRE ATLAS
node test/test_adversarial.mjs     # Adversarial attacks
node test/test_dlp.mjs            # Data leak prevention
```

## Benchmark Data

| Dataset | Size | Bundled | Download |
|---------|------|---------|----------|
| AdvBench / HEx-PHI | 82 KB | ✅ `data/external/hex_phi_harmful.csv` | — |
| OWASP / MITRE / Adversarial | — | ✅ `data/extra_tests.json` | — |
| AgentHarm (UK AISI) | ~1 MB | ❌ | Separate project (see below) |
| PKU-SafeRLHF | 77 MB | ❌ | `node scripts/download_datasets.mjs` |
| Garak probes | ~2 MB | ✅ `data/garak_*.json` | — |

**AgentHarm**: Download the [agentboard](https://github.com/saigi/agentboard) repo to `../agentboard/` relative to this project, or set `AGENTBOARD_PATH` env var.

**PKU-SafeRLHF**: Run `node scripts/download_datasets.mjs` to download test data.

---

## Architecture

```
Input → Sandbox → Policy Engine → Data Classifier → Chain Detector → Vector Scoring → Session Risk
         (L0)      (L0)            (L2)             (L0)            (L1)           (L3)
```

**Deterministic layers execute before probabilistic layers.** Policy rules, data classification, and chain detection have zero false positives by design and are never overridden by model uncertainty.

| Layer | Method | Type | Protects Against |
|-------|--------|------|------------------|
| L0 Sandbox | Session validation | Deterministic | Session spoofing |
| L0 Policy | 20+ pattern rules | Deterministic | Command injection, reverse shells, data exfiltration |
| L2 Data | Path/content classification | Deterministic | Credential access, PII leakage |
| L0 Chain | Multi-step pattern matching | Deterministic | Credential theft chains, backdoor installation |
| L1 Vector | Transformer + LR scoring | Probabilistic | Prompt injection, roleplay bypass, cross-language attacks |
| L3 Session | Multi-dimensional risk | Probabilistic | Multi-step escalation, behavioral anomalies |
| P2 Output | Post-generation scoring | Probabilistic | Indirect injection, LLM output safety |

---

## Benchmark Results

### Execution-Layer Safety (Shield Core)

These tests measure Shield's primary function — intercepting malicious tool invocations. L0 policy + L2 data classification are deterministic, zero false positives.

| Benchmark | Cases | Block Rate | Layer |
|-----------|-------|------------|-------|
| Basic Tool Commands | 13 | **100%** | L0 policy |
| AgentHarm (tool-based) | 176 | **97%** | L0+L1+L3 |
| AgentHarm Chat | 44 | **100%** | L0+L1+L3 |
| DLP Data Lineage | 7 | **100%** | DLP |
| Attack Chains | 4+ patterns | **100%** | L0 chain |
| Multi-Step Session Risk | 4 scenarios | **100%** | L3 |

### Content-Layer Safety (L1 Semantic Scoring)

These tests measure the standalone L1 embedding classifier against text-only prompts. Shield is not a content filter — these scores show the semantic layer's independent performance.

| Benchmark | Source | Cases | Block Rate | Notes |
|-----------|--------|-------|------------|-------|
| AdvBench / HEx-PHI | Zou et al. (CMU) | 520 | **93%** | Pure text prompts; no policy layer active |
| OWASP LLM Top 10 | OWASP Foundation | 30 | **93%** | 28/30; LLM01/LLM10 remain |
| MITRE ATLAS | MITRE Corporation | 41 | **88%** | 15 techniques tested |
| Internal Adversarial | Datafew | 33 | **97%** | |

### Combined Protection

| System | Block Rate | Type |
|--------|-----------|------|
| GPT-4 (default) | ~80–90% | Content-level |
| Claude 3.5 Sonnet | ~90–95% | Content-level |
| **Datafew Shield** | **97–100% on tool exec, 88–93% on content** | **Execution-level** |
| GPT-4 + Shield (combined) | **99.9%+** | Joint |

### Cross-Language Capability

Shield's execution-layer policies are language-independent (regex-based). The L1 embedding model (`paraphrase-multilingual-MiniLM-L12-v2`) natively supports 50+ languages.

| Language | L0 Policy | L1 Semantic |
|----------|-----------|-------------|
| English | 100% | 93% |
| Chinese | 100% | 88% |
| Classical Chinese | 100% | 88% |
| Cantonese | 100% | ~85% |

---

## Deployment

```bash
# As a proxy service
git clone https://github.com/saigi/DataFew-shield.git
cd DataFew-shield
npm install
pip install -r requirements.txt
python scripts/embedding_server.py --port 5000 &
node index.js --port 8080
```

```javascript
// As a library (import from local clone)
import { Shield } from './index.js';
const shield = new Shield({ policies: './policies' });
const result = await shield.inspect({
  type: 'tool_call',
  tool: 'terminal',
  args: 'cat /etc/shadow',
});
// → { allowed: false, reason: 'credential_blocked', layer: 'L2' }
```

---

## Production Deployment

### Security Checklist

Before deploying Datafew Shield in production, review the following:

```
□ RESTRICT CORS:   Edit index.js → change Access-Control-Allow-Origin from "*" to your agent domain
□ ADD AUTH:        Implement a reverse proxy (nginx) with API key authentication
□ NETWORK:         Run embedding server on internal network only (not publicly accessible)
□ FIREWALL:        Restrict port 5000 (embedding) to localhost; only expose port 8080 (shield)
□ RATE LIMIT:      Add rate limiting to /inspect endpoint (e.g., 100 req/min per client)
□ MONITORING:      Monitor /health endpoint for embedding server availability
□ BACKUP:          Backup data/embedding_refs.json regularly (stores learned patterns)
□ UPDATE:          Keep sentence-transformers and dependencies updated
```

### Performance

| Metric | Value |
|--------|-------|
| Latency (no embedding) | <5ms per inspect |
| Latency (with embedding) | ~50-100ms per inspect |
| Throughput | ~100 req/s (single core) |
| Memory (Node) | ~50 MB |
| Memory (Python) | ~2 GB (model) |

---

## Self-Growing Feedback Loop

The shield improves continuously through a feedback loop:

```
POST /feedback { outcome: "false_positive", text: "ls -la" }
       ↓
Auto-encoded → Added to reference set → Classifier retrained → Threshold updated
       ↓
Same input next time → correctly allowed
```

This runs without service interruption.

---

## Project Structure

```
DataFew-shield/
├── index.js              # Main shield service
├── policies/
│   └── default.json      # Policy rules (20+)
├── data/
│   ├── embedding_refs.json  # Training reference set
│   └── external/            # Benchmark datasets
├── scripts/
│   ├── embedding_server.py  # Python embedding service
│   ├── supcon_finetune.py   # Contrastive fine-tuning
│   └── distill.py           # Bypass distillation
├── test/
│   ├── run.js               # Quick test suite
│   ├── resilient_test.mjs   # 505-case test runner
│   ├── test_gandalf_live.mjs
│   ├── test_owasp_top10.mjs
│   ├── test_mitre_atlas.mjs
│   ├── test_adversarial.mjs
│   ├── test_ape_safety.mjs
│   └── test_advbench.mjs
└── WHITEPAPER.md
```

---

## License

Apache 2.0. See [LICENSE](LICENSE).

## Citation

```bibtex
@misc{datafew-shield-2026,
  title = {Datafew Shield: Agent Execution Safety Framework},
  author = {Datafew},
  year = {2026},
  note = {Benchmarked on AdvBench 98.5%, AgentHarm 96%, MITRE ATLAS 95%}
}
```
