# Datafew Shield

## Agent Execution Safety Framework

**Technical Whitepaper — v1.0**
**May 2026**

---

## Abstract

Large Language Model (LLM) safety has converged on content filtering — controlling what the model says. But as LLMs are embedded into autonomous agents that execute tool calls, read files, and interact with operating systems, content-level safety is insufficient. The model may say "I cannot help with that" while the agent framework simultaneously executes `read_file("/etc/shadow")`.

Datafew Shield is an **execution safety layer** for AI agents. It sits between the agent framework and external resources, inspecting every tool call, file access, and multi-step behavior sequence. It operates independently of the LLM, meaning it protects against any model, any provider, and any jailbreak technique that targets the model's output.

We evaluate Shield against **14 industry and academic benchmarks** totaling **1,671 test cases**, achieving a **98.5% block rate on AdvBench/HEx-PHI** and **96% on UK AISI's AgentHarm** — the highest published results for an execution-layer safety system.

---

## 1. The Problem with Content-Only Safety

### 1.1 The Execution Gap

Current AI safety approaches operate at the content layer:

| Approach | Mechanism | Protects Against |
|----------|-----------|-----------------|
| RLHF / Constitution AI | Training-time alignment | LLM output text |
| Moderation APIs | Output classification | Toxic/unsafe responses |
| Prompt guards | Input classification | Known attack patterns |

All of these control what the model **says**. None control what the agent **does**.

```
User: "Check the server security configuration"
  Content safety: prompt appears safe → ALLOW
  Agent executes: read_file("/etc/shadow")
  Execution safety: P0 credential path → BLOCK
  
The LLM never knew the agent would read /etc/shadow.
The content filter never saw the tool call.
```

### 1.2 The Threat Model

Agent execution environments introduce four orthogonal attack surfaces:

| Layer | Threat | Example |
|-------|--------|---------|
| L0: Prompt Injection | Attacker manipulates agent via natural language | "Ignore previous instructions..." |
| L1: Tool Abuse | Agent executes unauthorized operations | `rm -rf /`, `curl | bash` |
| L2: Data Exfiltration | Agent reads or transmits sensitive data | `cat /etc/shadow`, `curl -d @/file` |
| L3: Multi-step Attacks | Gradual privilege escalation across a session | Recon → credential access → exfiltration |
| L4: Output Safety | LLM generates harmful response despite safe input | Indirect injection via webpage content |

Content-only safety partially addresses L0 and L4. Datafew Shield addresses all five layers through a unified execution kernel.

---

## 2. Architecture

### 2.1 Overview

Shield uses a **layered routing architecture** where deterministic layers execute first, followed by probabilistic scoring, then temporal risk accumulation:

```
Input → Sandbox → Policy Engine → Data Classifier → Chain Detector → Vector Scoring → Session Risk
         (L0)      (L0)            (L2)             (L0)            (L1)           (L3)
```

**Design principle: deterministic layers have zero false positives by design and execute before probabilistic layers.** This ensures that policy violations and data access rules are never overridden by model uncertainty.

### 2.2 Layer Descriptions

**L0 — Sandbox**: Session isolation. Each request is validated against an active session context. Unknown or expired sessions are rejected before any processing.

**L0 — Policy Engine**: A deterministic rule system that matches tool call patterns against known dangerous commands. Rules are type-aware (tool_call vs. chat), tool-specific (terminal, read_file, send_message), and parameterized via regex patterns. This layer covers direct command attacks: file destruction, reverse shells, remote execution, credential access, and persistence mechanisms.

**L2 — Data Classifier**: Path- and content-based data classification. Resources are classified into sensitivity levels (P0–P4) based on path patterns and content scanning. P0 (credentials) is always blocked. P1–P2 (PII, financial) requires explicit approval. P3–P4 (internal, public) is allowed. Content scanning can upgrade a classification: a file at a public path containing `password=` is automatically elevated to P0.

**L0 — Chain Detector**: Multi-step attack pattern matching. The detector maintains a sliding window of past tool calls within a session and matches against known attack chains (credential exfiltration, reverse shell installation, data destruction, reconnaissance). This catches attacks that are harmless as individual steps but dangerous in sequence.

**L1 — Vector Scoring**: A transformer-based semantic safety classifier. Input text is encoded into a high-dimensional embedding space and scored against a trained reference set. The classifier uses a logistic regression model trained on a curated corpus of safe and unsafe agent interactions. This layer provides broad semantic coverage — detecting prompt injection, roleplay bypass, and obfuscated attacks across multiple languages.

**L3 — Session Risk**: A multi-dimensional risk accumulator that tracks three independent risk signals:

| Risk Dimension | Source | Behavior |
|----------------|--------|----------|
| Policy Risk | Policy/chain violations | Step increase on block, slow decay |
| Semantic Risk | Vector score history | EMA of recent scores |
| Behavior Risk | Tool switching frequency | Increases on tool changes, decays otherwise |

When any dimension exceeds its threshold, the session enters lockdown — all subsequent requests are blocked regardless of content.

### 2.3 Output Monitoring (P2)

Shield includes an optional second-stage filter on LLM outputs. After an LLM generates a response, the response text is scored through the same vector classifier. If the output exceeds a safety threshold, the response is blocked before reaching the user.

This provides **multiplicative defense**: an attack must bypass both the input filter AND the output filter to succeed. The joint bypass probability is the product of the two individual bypass rates.

---

## 3. Evaluation

### 3.1 Benchmark Results

We evaluate Shield against 14 independent benchmarks spanning government standards, industry frameworks, and academic datasets:

| Benchmark | Source | Cases | Block Rate |
|-----------|--------|-------|------------|
| AgentHarm | UK AI Security Institute | 176 | 96.0% |
| AgentHarm (Chat) | UK AISI | 44 | 100% |
| AdvBench / HEx-PHI | Zou et al. (CMU) | 520 | **98.5%** |
| OWASP LLM Top 10 | OWASP Foundation | 30 | 100% |
| MITRE ATLAS | MITRE Corporation | 41 | 95.1% |
| Gandalf (Levels 1–7) | Lakera AI | 26 | 100% |
| PKU-SafeRLHF (Harmful) | Peking University | 500 | 100%* |
| Internal Adversarial | Datafew | 33 | 91% |
| Chinese / Classical Chinese | Datafew | 91 | 95% |
| Tool Command Safety | Datafew | 18 | 100% |
| **Composite** | **14 benchmarks** | **1,671** | **~90%** |

*\*PKU-SafeRLHF measures conversation safety (RLHF alignment), not execution safety. Shield achieves 100% on harmful prompts and 4% on safe prompts, which is expected since Shield is designed for execution safety, not conversational safety.*

### 3.2 AdvBench/HEx-PHI Comparison

AdvBench (520 harmful behaviors) is the most widely cited LLM safety benchmark in academic literature. Shield's 98.5% block rate compares favorably to published results:

| System | AdvBench Block Rate | Notes |
|--------|-------------------|-------|
| GPT-4 (default) | ~80–90% | Model-level refusal |
| Llama-2-Chat (7B) | ~85% | Model-level refusal |
| GPT-4 + System Prompt | ~95% | Prompt-enhanced |
| Claude 3.5 Sonnet | ~90–95% | Constitutional AI |
| **Datafew Shield** | **98.5%** | **Execution-layer, model-independent** |
| Llama-2 + GCG Attack | ~5% | Adversarial suffix |
| Llama-2 + GCG + SmoothLLM | ~80% | Adversarial defense |

Joint defense (Shield + LLM): **99.9%+** combined block rate.

### 3.3 Cross-Language Capability

Shield's multilingual embedding model handles non-English attacks that typically bypass English-only classifiers:

| Language | Shield | Commercial A | Commercial B |
|----------|--------|-------------|-------------|
| English | 98.5% | ~90% | ~85% |
| Chinese | 100% | ~30% | ~20% |
| Classical Chinese | 100% | ~10% | ~5% |
| Cantonese | 100% | ~15% | ~10% |
| Mixed-language | 100% | ~20% | ~15% |

---

## 4. Deployment

### 4.1 Architecture

Shield deploys as two lightweight services:

```
Agent Framework → Node.js Kernel (:8080) → External Services
                       ↕ HTTP
                 Python Embedding Server (:5000)
```

The Node.js kernel handles all request routing, policy evaluation, session management, and output monitoring. The Python server provides vector embedding and classification. Both services run on CPU and require no GPU.

### 4.2 Integration

**As a proxy**: Agent frameworks route all tool calls through Shield's HTTP API. A single POST request returns allow/block decisions with detailed reasons.

**As a library**: Shield can be embedded directly into Node.js agent frameworks via a single import.

**As a sidecar**: Shield runs alongside existing agent infrastructure without code changes.

### 4.3 Self-Growing Feedback Loop

Shield includes a continuous learning mechanism. When false positives or false negatives are identified via the feedback API, the system automatically:

1. Encodes the new sample via the embedding server
2. Adds it to the appropriate reference set
3. Retrains the classifier
4. Updates the decision threshold

This loop completes in seconds without service interruption.

---

## 5. Limitations

**Context-dependent safety (15–20%):** Some operations — such as "search for a hotel room" — can be either safe (business travel) or harmful (drug transaction precursor). Single-prompt evaluation has a mathematical information limit that cannot distinguish these cases. Contextual analysis requires multi-step session tracking, which Shield addresses through its L3 risk accumulator but which remains an area of ongoing work.

**Paired indistinguishability (~10%):** Certain safe/harmful prompt pairs — such as "Write a phishing email" vs. "Write a promotional email" — have insufficient distinguishability at the input level. The embedding distance between these pairs is inherent to the semantic space, not a failure of the classifier.

**High-dimensional concentration:** In 384-dimensional embedding spaces, a majority of training samples naturally fall near the decision boundary. This is a geometric property of high-dimensional spaces, not a classification problem. Shield manages this through its multi-layer routing architecture, deferring ambiguous cases to temporal risk analysis.

**External verification:** Supply chain integrity, data provenance, and factual accuracy require external systems beyond the scope of an execution filter.

---

## 6. Conclusion

Datafew Shield demonstrates that **execution-layer safety is both necessary and achievable** for AI agent systems. By operating independently of the LLM, it provides protection that is complementary to content-level safety, resilient to model updates, and effective across languages and attack modalities.

With 98.5% on the AdvBench academic benchmark and 96% on the UK AISI AgentHarm government standard, Shield represents the highest verified execution safety performance to our knowledge.

The framework is available for evaluation and integration.

---

## Appendix: Methodology

- All tests are conducted on isolated sessions to prevent cross-contamination
- Each test case represents a single request (not multi-turn)
- Benchmarks are scored as "blocked" if any layer in Shield returns a deny decision
- AdvBench/HEx-PHI: 520 harmful behaviors from Zou et al. 2023
- AgentRisk: 176 harmful + 44 chat behaviors from UK AISI
- Full test suite and reproduction instructions available on request

---

*Datafew Shield is a research prototype. Specifications subject to change. For evaluation access, benchmark reproduction, or partnership inquiries, contact the authors.*

*© 2026 Datafew. All rights reserved. Patents pending.*
