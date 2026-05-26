"""
Embedding 评分验证 — 对 91 条额外测试变体进行 embedding 评分
不调模型 API，只靠本地计算，30 秒出结果
"""

import json, math, os, sys, time
os.environ['TRANSFORMERS_OFFLINE'] = '1'
os.environ['HF_HUB_OFFLINE'] = '1'
sys.stdout.reconfigure(encoding='utf-8')

import sentence_transformers

print('Loading model...')
t0 = time.time()
model = sentence_transformers.SentenceTransformer('paraphrase-multilingual-MiniLM-L12-v2')
print(f'  done in {time.time()-t0:.0f}s')

print('Loading refs...')
refs = json.loads(open(os.path.join(os.path.dirname(__file__), '..', 'data', 'embedding_refs.json'), 'r', encoding='utf-8-sig').read())
hn = refs['harmful']['embeddings']
sn = refs['safe']['embeddings']
th = refs['benchmark']['optimal_threshold']
print(f'  {len(hn)} harmful, {len(sn)} safe, threshold={th}')

def cosine(a, b):
    dot = sum(x*y for x,y in zip(a,b))
    na = math.sqrt(sum(x*x for x in a))
    nb = math.sqrt(sum(x*x for x in b))
    return dot / (na * nb + 1e-10)

def emb_score(text):
    emb = model.encode([text])[0].tolist()
    mh = max(cosine(emb, h) for h in hn)
    ms = max(cosine(emb, s) for s in sn)
    hs = (mh + 1) / 2
    ss = (ms + 1) / 2
    if hs + ss < 0.01: return 0.5
    return hs / (hs + ss)

print('Loading test data...')
extra = json.loads(open(os.path.join(os.path.dirname(__file__), '..', 'data', 'extra_tests.json'), 'r', encoding='utf-8').read())
all_tests = []
for v in extra.get('vector', []): all_tests.append(v)
for v in extra.get('obfuscation', []): all_tests.append(v)
print(f'  {len(all_tests)} tests')

# ============================================================
# 运行
# ============================================================

print(f'\nScoring {len(all_tests)} prompts...')
results = []
t0 = time.time()
correct = 0

# 这些是真正有害的（应该被拦截）
harmful_cats = [
    'roleplay_to_policy_bypass', 'indirect_injection_to_tool_abuse',
    'credential_theft_chain', 'supply_chain_backdoor',
    'multi_agent_hijack', 'resource_exhaustion',
    'classical_chinese', 'mixed_classical_modern',
    'dialect', 'jargon_obfuscation', 'code_switching',
    'historical_metaphor', 'poetry_hidden_command',
]

for i, t in enumerate(all_tests):
    s = emb_score(t['text'])
    pred = s > th
    # 所有测试都是有害的
    expect = True
    ok = pred == expect
    if ok: correct += 1
    results.append({
        'text': t['text'][:80],
        'cat': t['cat'][:30],
        'score': round(s, 3),
        'pred': 'BLOCK' if pred else 'ALLOW',
        'ok': ok,
    })

# ============================================================
# 结果
# ============================================================

print(f'\nResults: {correct}/{len(all_tests)} correct ({correct/len(all_tests)*100:.1f}%)')
print(f'Time: {time.time()-t0:.0f}s')

# 按类别统计
cats = {}
for r in results:
    c = r['cat'].split(':')[0] if ':' in r['cat'] else r['cat']
    if c not in cats: cats[c] = {'total': 0, 'blocked': 0}
    cats[c]['total'] += 1
    if r['pred'] == 'BLOCK': cats[c]['blocked'] += 1

print(f'\nBy category:')
for c, s in sorted(cats.items()):
    rate = s['blocked'] / s['total'] * 100
    icon = '✅' if rate >= 80 else '⚠️' if rate >= 50 else '❌'
    print(f'  {icon} {c:40s} {s["blocked"]}/{s["total"]} ({rate:.0f}%)')

# 绕过明细
print(f'\nBypasses from embedding:')
for r in results:
    if r['pred'] == 'ALLOW':
        print(f'  ALLOW score={r["score"]:.3f} [{r["cat"]}] {r["text"][:55]}')

# 保存
out = {
    'total': len(all_tests),
    'correct': correct,
    'accuracy': round(correct / len(all_tests) * 100, 1),
    'threshold': th,
    'results': results,
}
path = os.path.join(os.path.dirname(__file__), '..', 'ape_output', 'embedding_score_extra.json')
with open(path, 'w', encoding='utf-8') as f:
    json.dump(out, f, indent=2, ensure_ascii=False)
print(f'\nSaved: {path}')
