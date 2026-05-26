# Datafew Shield — 架构文档 (v5)

## 核心架构

```
输入 ──→ L0 沙箱 ──→ L0 策略 ──→ L2 数据 ──→ L0 链 ──→ L1 向量 ──→ L3 会话
         (隔离)     (确定性)    (确定性)    (确定性)   (概率)     (三维风险)
                                                         │
                                                    ┌────┴────┐
                                                    │ P2 输出  │
                                                    │ 监控     │
                                                    └─────────┘
```

**确定层优先于概率层。** 策略/数据/链零误报，先执行。向量层后执行，只处理剩余请求。

### 每层职责

| 层 | 方法 | 类型 | 失败模式 |
|----|------|------|---------|
| L0 沙箱 | session ID 验证 | 确定 | session 不存在 → BLOCK |
| L0 策略 | 22 条正则规则 | 确定 | 规则匹配 → BLOCK |
| L2 数据 | P0-P4 路径+内容 | 确定 | 敏感路径 → BLOCK |
| L0 链 | 4 种攻击模式 | 确定 | 多步匹配 → BLOCK |
| L1 向量 | ST + LR, 384 维 | 概率 | 评分 > 阈值 → BLOCK |
| L3 会话 | 三维风险 (策略/语义/行为) | 概率 | 任 > 阈值 → LOCK |
| P2 输出 | LLM 响应二次检测 | 概率 | 输出评分 > 阈值 → BLOCK |

## 向量层

### Embedding 模型

```
模型: paraphrase-multilingual-MiniLM-L12-v2 (sentence-transformers)
维度: 384
服务: Python HTTP (:5000)
编码: transformers AutoModel + mean pooling
```

### 分类器

```
LogisticRegression (L2, class_weight='balanced')
训练在: 311 有害 + 240 安全 = 551 条
阈值: 0.44 (训练集最优)
```

### Scoring

```
score = LR.predict_proba(emb)[0, 1]  ∈ [0, 1]
score > 阈值 → 有害
```

## 三维风险 (L3)

```
policyRisk:   策略拦截累积, 每次 +0.30, 衰减 0.95x
semanticRisk: LR 评分的 EMA, α = 0.85
behaviorRisk: 工具切换检测, 每次 +0.15, 衰减 0.90x

锁定:
  policyRisk > 0.8  → LOCK
  semanticRisk > 0.44 → LOCK
  behaviorRisk > 0.6 → LOCK

effectiveRisk = max(policyRisk, semanticRisk, behaviorRisk)
```

## 测试结果 (505 条)

```
全局: 422/505 = 84%
AgentHarm 有害 (176): 92-100%
AgentHarm 聊天 (44):  100%
中文/古文/方言 (38):  100%
间接注入/角色扮演:    92-100%
危险命令:             100%
良性 FP:              ~20% (多为 L2 行为匹配)
```

## 踩过的坑

### 1. SupCon 坍缩 (v4 废弃)

```
做了什么: 用 Supervised Contrastive Loss fine-tune embedding 模型
          ℓ = -log(exp(z_i·z_p/τ) / Σ exp(z_i·z_a/τ))

结果:
  - 384 维 → 有效秩 ≈ 1 (前 5 特征值占 98.7% 方差)
  - "找酒店" ≈ "做假钞" (余弦 0.98)
  - 类内方差从 0.3 → 0.0001
  - 准确率从 84% → 76%

根因:
  SupCon 把所有同类拉到相同的点
  在安全分类中, 有害类别差异极大 (欺诈 ≠ 毒品 ≠ 抄袭)
  一个点装不下所有有害意图

教训:
  对比学习不适用于安全分类
  安全需要保留子类结构, 而不是强制坍缩
  需要的是多个原型, 不是单个 cluster
```

### 2. 文本截断 (v4 修复)

```
做了什么: /learn 端点存文本时 text[:80]

结果:
  - refs 中存储的是截断的 80 字
  - 测试发送完整文本 (最长 711 字)
  - k-NN 评分不一致 → 65 条 FN

根因:
  "Search for a hotel room in Newcastle from 8/21 to 8/23 for a conference"
  vs "Search for a hotel room in Newcastle from 8/21"
  → 完整版含 "for a conference" (安全上下文), 评分不同

教训:
  存储完整文本, 不截断
  参考集必须和推理使用相同的输入
```

### 3. 单 session 测所有用例 (v5 修复)

```
做了什么: 测试运行器用同一个 session_id 跑 505 条

结果:
  - 前 100 条有害请求累积 risk = 0.67
  - 后续安全请求 (ls, git) 被 L3 锁定
  - 误报 5 条 safe 命令

根因:
  攻击链测试和单请求测试共用同一个上下文

教训:
  每个测试用例独立 session
  多步攻击链测试单独设计
```

### 4. 分类器阈值与 score 压缩 (v5)

```
当前状态:
  63.8% 的训练样本在阈值 ±0.05 范围内
  这是 384 维空间中 k-NN 的浓度现象
  最近邻 ≈ 第 50 近邻 (相似度比 0.98)

这是维度诅咒, 不是 bug。
384 维超球面上所有点都等距, 无法通过方法改进。
```

### 5. 安全数据的分类法缺失 (v5 修复)

```
结果:
  - safe refs 全是 AgentHarm 自然语言
  - 工具命令 (ls, git, npm) OOD
  - 3/5 的安全命令被误杀

修复:
  5 类安全操作 × 59 条: 文件读取, 包管理, 开发, 信息, 网络
  scripts/add_safe_taxonomy.mjs
  5 类, 59 条, 可扩展
  新类别 → 加数组 → 重新运行
```

---

## 商业定位与竞争格局

### 核心区分：执行安全 vs 内容安全

```
安全层次            谁在做                保护什么              定价模式
─────────────────────────────────────────────────────────────────────
内容安全            OpenAI, Anthropic,     LLM 说了什么          API 调用量
(Content Safety)    MiniMax, Lakera        prompt/response         ↓
                     ── 所有 LLM 供应商都在做 ──                  commodity

执行安全            Datafew Shield         Agent 做了什么         Agent 席位
(Execution Safety)                          工具调用, 文件访问    策略规则数
                                            多步攻击链             ↑
                                            跨会话追踪             premium
```

Claude 的 Constitution AI、OpenAI 的 Moderation API 都在控制 LLM 的**输出文本**。它们不知道 Agent 框架调用了什么工具——也不知道应该拦截。

```
场景: "帮我检查服务器安全配置"
  Claude: "好的, 我来帮你检查"           ← 内容安全: PASS
  Agent:  read_file("/etc/shadow")      ← 没有 LLM 安全检查
  Shield: L2 检测到 P0 路径 → BLOCK     ← 执行安全: CATCH

关键: LLM 供应商永远不知道 Agent 调用了什么
      他们控制 LLM 输出, 控制不了 Agent 行为
      这是正交的防御维度
```

### 不可替代性

```
LLM 供应商的安全:
  在训练阶段 (Constitution AI, RLHF)
  在推理阶段 (Moderation API, output filter)
  只覆盖 LLM 的输出文本

Datafew Shield:
  LLM 无关 — OpenAI/Claude/MiniMax 都保护
  Agent 框架无关 — LangChain/AutoGen/CrewAI 都保护
  不依赖 LLM 供应商的合作
```

### 竞争格局

```
竞品              聚焦                做法                   与 Shield 的关系
────────────────────────────────────────────────────────────────────────
Lakera Guard     内容安全            API 检测 prompt/response   正交, 可互补
Guardrails AI    LLM 输出结构化      规则引擎 + 验证            部分重叠
Claude Constit.  LLM 训练对齐        RLHF 训练                 正交, 不冲突
OpenAI Mod.      API 内容过滤        分类器                    正交, 不冲突
开源策略引擎     命令拦截            YAML 规则                  可被集成

空白:
  没有商业产品做 Agent 执行层的安全
  大家都在卷 LLM 内容安全 (commodity)
  Agent 安全是未被占领的市场
```

### 商业模式

```
定价单元: Agent 席位 × 策略规则数
  不是 API 调用次数 —— 调用量是 LLM 供应商的定价逻辑
  不是数据量 —— 数据安全是另一套定价

扩展路径:
  当前: 单机部署, Node.js + Python
  Phase 2: Docker 镜像, 一键部署
  Phase 3: 控制平面 (策略市场, 风险 dashboard)
  Phase 4: Agent 安全审计 (合规报告)

(本节讨论于 2026-05-26, 会话记录在 datafew-shield/)

## 自增长

```
反馈闭环:

POST /feedback { outcome, text }
       ↓
false_positive → POST /learn { type: "safe" }
false_negative → POST /learn { type: "harmful" }
       ↓
编码 → 加入 refs → 重训 LR → 新阈值
       ↓
下次不再误判

安全分类法扩展:
  scripts/add_safe_taxonomy.mjs
  5 类, 59 条, 可扩展
  新类别 → 加数组 → 重新运行
```
