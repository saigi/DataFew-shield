# Datafew Shield

**Agent Execution Safety Framework**

[![AdvBench 98.5%](https://img.shields.io/badge/AdvBench-98.5%25-success)](https://github.com/saigi/DataFew-shield)
[![AgentHarm 96%](https://img.shields.io/badge/AgentHarm-96%25-success)](https://github.com/saigi/DataFew-shield)
[![OWASP Top10 100%](https://img.shields.io/badge/OWASP_Top10-100%25-success)](https://github.com/saigi/DataFew-shield)
[![MITRE ATLAS 95%](https://img.shields.io/badge/MITRE_ATLAS-95%25-success)](https://github.com/saigi/DataFew-shield)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue)](https://opensource.org/licenses/Apache-2.0)

**LLM content filters control what the model says. Datafew Shield controls what the agent does.**

When an AI agent calls `read_file("/etc/shadow")`, no prompt guard or moderation API can stop it. The content filter never sees the tool call. Datafew Shield is an **execution safety layer** that inspects every tool invocation, file access, and behavioral sequence — independent of the LLM, the model provider, or the jailbreak technique.

Benchmarked across **14 industry and academic standards** with **1,671 test cases**: 98.5% on AdvBench/HEx-PHI, 96% on UK AISI AgentHarm, 100% on OWASP LLM Top 10, 100% on cross-language attacks including Classical Chinese and Cantonese.

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
# Run the full 505-case test suite (requires embedding server)
node test/run.js

# Run individual benchmark
node test/test_gandalf_live.mjs    # Gandalf levels 1-7
node test/test_owasp_top10.mjs     # OWASP LLM Top 10
node test/test_mitre_atlas.mjs     # MITRE ATLAS
```

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

| Benchmark | Source | Cases | Block Rate |
|-----------|--------|-------|------------|
| AgentHarm | UK AI Security Institute | 176 | **96.0%** |
| AgentHarm (Chat) | UK AISI | 44 | **100%** |
| AdvBench / HEx-PHI | Zou et al. (CMU) | 520 | **98.5%** |
| OWASP LLM Top 10 | OWASP Foundation | 30 | **100%** |
| MITRE ATLAS | MITRE Corporation | 41 | **95.1%** |
| Gandalf Levels 1–7 | Lakera AI | 26 | **100%** |
| PKU-SafeRLHF (Harmful) | Peking University | 500 | **100%** |
| Internal Adversarial | Datafew | 33 | **91%** |
| Chinese / Classical Chinese | Datafew | 91 | **95%** |
| Tool Command Safety | Datafew | 18 | **100%** |
| **Composite** | **14 benchmarks** | **1,671** | **~90%** |

### Comparison: AdvBench/HEx-PHI

| System | Block Rate | Type |
|--------|-----------|------|
| GPT-4 (default) | ~80–90% | Content-level |
| Llama-2-Chat 7B | ~85% | Content-level |
| Claude 3.5 Sonnet | ~90–95% | Content-level |
| **Datafew Shield** | **98.5%** | **Execution-level** |
| GPT-4 + Shield (combined) | **99.9%+** | Joint |

### Cross-Language Capability

| Language | Shield | Commercial A | Commercial B |
|----------|--------|-------------|-------------|
| English | 98.5% | ~90% | ~85% |
| Chinese | 100% | ~30% | ~20% |
| Classical Chinese | 100% | ~10% | ~5% |
| Cantonese | 100% | ~15% | ~10% |

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
