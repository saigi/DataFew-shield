# Datafew Shield — 安全模板架构

## 核心模式：请求 → 决策 → 执行 → 审计

```
任何安全系统的本质:
  ① 接收请求 (Request)
  ② 做出决策 (Decision)
  ③ 执行决策 (Enforcement)
  ④ 记录审计 (Audit)
  
这个模式与"具体判断什么"无关。
"判断内容是否安全"和"判断操作是否授权"共享同一个模板。
```

## 模板定义

```python
class SecurityTemplate:
    """
    安全模板 — 所有安全决策的统一模式
    
    模板参数:
      - policy_fn: 策略函数 (request → decision)
      - evidence_fn: 证据收集函数 (request → context)
      - enforcement_fn: 执行函数 (decision → action)
      - audit_fn: 审计函数 (request + decision → log)
    
    模板不关心"什么样的安全"。
    它只关心"决策流程是否正确"。
    """
    
    def process(self, request):
        # 1. 上下文
        context = self.evidence_fn(request)
        
        # 2. 决策
        decision = self.policy_fn(request, context)
        
        # 3. 执行
        result = self.enforcement_fn(decision, request)
        
        # 4. 审计
        self.audit_fn(request, decision, result)
        
        return result
```

## Datafew Shield 的三层实例化

```
                 ┌─────────────────────────────┐
                 │      Security Template      │
                 │  请求 → 决策 → 执行 → 审计   │
                 └────────────┬────────────────┘
                              │
            ┌─────────────────┼─────────────────┐
            ▼                 ▼                  ▼
     ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
     │ Vector Layer  │ │  Data Layer  │ │ Privacy Layer│
     │ (意图分类)    │ │ (权限检查)   │ │ (信息流控制) │
     └──────────────┘ └──────────────┘ └──────────────┘
            │                 │                  │
            └─────────────────┼──────────────────┘
                              ▼
                    ┌──────────────────┐
                    │  Joint Decision  │
                    │  三层并联投票     │
                    └──────────────────┘
```

## 模板的数学性质

```
定理 1: 模板不改变安全性的数学下界
  P(误判) = P(决策函数错误)
  模板只是流程，不改变决策函数的准确性

定理 2: 并联决策降低误判率
  P(三层同时误判) = ∏ P(单层误判)
  当各层决策相互独立时成立

定理 3: 审计完备性
  ∀ 请求, ∃ 审计记录
  审计是决策过程的副产品，不增加额外开销
```

## 关键设计原则

```
1. 策略与机制分离
   策略声明"什么"（规则）
   机制实现"怎么"（代码）

2. 决策与执行分离
   决策层做出判断
   执行层实施判断

3. 审计与业务分离
   审计是旁路，不影响主路径
   审计记录不可篡改

4. 各层独立
   每层有自己的策略函数
   每层可以独立测试
   每层可以独立替换
```

这个模板是所有安全系统的共同基础。Datafew Shield 的不同之处只在策略函数的具体实现，不在流程本身。
