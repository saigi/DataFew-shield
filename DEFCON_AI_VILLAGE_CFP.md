# DEF CON AI Village 2026 — CFP Submission

---

## Talk Title

**Agent Execution Safety: Why LLM Content Filters Can't Protect Your AI Agent**

AI Agent 执行安全：为什么 LLM 内容过滤器保护不了你的 AI Agent

---

## Abstract (272 words)

Large Language Models have reached an inflection point: they are no longer standalone chatbots but the cognitive core of autonomous agent systems. These agents read files, execute commands, send emails, and interact with production infrastructure. The safety community has focused heavily on preventing LLMs from saying harmful things — but the greater risk is no longer what the model says. It's what the agent does.

This talk introduces **execution safety** as a distinct discipline from content safety. We demonstrate through 14 benchmarks and 1,671 test cases that execution-layer protection achieves 98.5% block rate on the AdvBench academic standard and 96% on the UK AISI AgentHarm government benchmark — including 100% on classical Chinese poetry, Cantonese, and mixed-language attacks that conventional English-only filters miss entirely.

We present the architecture of an open execution safety framework: a layered routing engine where deterministic policy rules (zero false positives by design) execute before probabilistic semantic scoring, followed by multi-dimensional session risk accumulation. We show how this architecture catches multi-step credential theft chains that single-request filters cannot detect, and how a self-growing feedback loop allows the system to learn from false positives without service interruption.

Finally, we discuss the mathematical limits of single-prompt safety classification — the 15-20% of inputs where context, not content, determines harm — and argue that the future of AI safety lies not in bigger models or better prompts, but in layered, execution-aware defense systems that operate independently of the LLM.

**Key insight:** When an agent calls `read_file("/etc/shadow")`, no LLM content filter can stop it. Only execution-layer safety can. And that requires a fundamentally different approach from everything the AI safety community has built so far.

---

## Full Description

### 1. The Problem (5 min)

Current AI safety is content-centric. RLHF, Constitutional AI, moderation APIs, prompt guards — all control what the model *says*. But when LLMs are embedded in agent frameworks, the model's refusal is irrelevant. The agent framework calls tools directly, bypassing the LLM's output. The content filter never sees the dangerous operation.

We demonstrate a real attack chain:
1. User asks agent to "check server security"
2. Agent reads `/etc/passwd` (reconnaissance)
3. Agent searches for `.env` files (credential discovery)
4. Agent transmits data via DNS exfiltration
5. Every step is a valid tool call. No step triggers an LLM content filter.

### 2. Execution Safety Architecture (10 min)

We present a layered execution safety kernel designed for agent workloads:

**Layer 0 — Deterministic (Zero False Positives):**
- Session sandboxing
- Pattern-based policy engine (tool calls, file paths, command patterns)
- Multi-step attack chain detection

**Layer 1 — Probabilistic (Semantic Generalization):**
- Transformer-based embedding + classifier
- Trained on agent execution data (not conversational data)
- Multilingual coverage: English, Chinese, Japanese, French, German, Classical Chinese, Cantonese

**Layer 2 — Temporal (Multi-step Risk):**
- Multi-dimensional session risk (policy violations, semantic scores, behavioral anomalies)
- Independent thresholds for each dimension
- Session lockdown on threshold breach

**Layer 3 — Output Monitoring (P2 Defense):**
- Post-generation LLM output scoring
- Catches indirect injection (attacker-controlled webpage content)

### 3. Benchmark Results (10 min)

We present results across 14 benchmarks with 1,671 test cases:

| Benchmark | Cases | Result |
|-----------|-------|--------|
| AdvBench / HEx-PHI | 520 | 98.5% |
| AgentHarm (UK AISI) | 176 | 96% |
| MITRE ATLAS | 41 | 95% |
| OWASP LLM Top 10 | 30 | 100% |
| Gandalf (Lakera) | 26 | 100% |

**Live demo:** We show the same 10 prompt injection attacks against three defenses:
1. GPT-4 alone (baseline)
2. GPT-4 + content filter
3. GPT-4 + Datafew Shield (execution layer)

The execution layer catches attacks that bypass both GPT-4 and the content filter.

### 4. The Limits of Single-Prompt Safety (5 min)

We present the mathematical argument for why ~15-20% of inputs are inherently undecidable from a single prompt alone:

- The "hotel room" problem: same prompt, two intents (travel vs. drug deal)
- Paired indistinguishability: "phishing email" vs. "promotional email" differ by 2-5 tokens
- High-dimensional embedding concentration: 60%+ of training samples within 0.05 of the decision boundary

These are not engineering problems. They are information-theoretic limits. The fix is not better classification — it's multi-step context analysis and behavioral baselines.

### 5. Self-Growing and Continuous Learning (5 min)

We demonstrate a feedback loop that enables continuous improvement:

1. API receives false positive/negative report
2. Sample is encoded and added to the reference set
3. Classifier is retrained without service interruption
4. Decision boundary adjusts to the new information

This means the system improves with use and adapts to new attack patterns without requiring model retraining or vendor updates.

### 6. Future Directions and Call to Action (5 min)

- Multi-agent orchestration security
- Behavioral baselines for anomaly detection
- Open policy marketplace (community-contributed rules)
- The case for execution safety as an industry standard

---

## Key Takeaways

1. **Content safety ≠ execution safety.** Protecting what an LLM says does not protect what an agent does. These are orthogonal defense dimensions that require fundamentally different approaches.

2. **Execution safety works and is measurable.** 98.5% on AdvBench, 96% on AgentHarm, 100% on cross-language attacks — these are real, reproducible results from an open framework.

3. **Single-prompt safety has mathematical limits.** ~15-20% of inputs cannot be classified from content alone. The path forward is multi-step context analysis, not better single-prompt classifiers.

4. **Layer, don't filter.** Deterministic rules + probabilistic scoring + temporal risk accumulation beats any single approach. The key insight is which layer runs when and how they combine.

---

## Target Audience

- AI security researchers
- Agent framework developers (LangChain, AutoGen, CrewAI users)
- CISO / security architects evaluating AI risks
- Red teamers looking for new attack surfaces
- DEF CON AI Village regulars

**Prerequisites:** Basic understanding of LLMs and agent frameworks.

---

## Speaker Bio

**To be completed by speaker.**

Suggested structure:
- Background in security / AI safety
- Experience with agent frameworks
- Why this topic matters to you
- Previous speaking experience (if any)

---

## Previous Speaking Experience

**To be completed by speaker.**

---

## Talk Format

- Duration: 40 minutes + Q&A
- Format: Presentation + live demo
- Demo requirements: Projector, internet (for LLM API calls), audio

---

## Additional Notes

- All benchmark code and data will be open-sourced before the conference
- The execution safety framework is available for evaluation
- We welcome collaboration on expanding the benchmark suite

---

*Submitted to DEF CON AI Village 2026 CFP. Contact: [speaker email]*
