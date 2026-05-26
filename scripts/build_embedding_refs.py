"""
Build Embedding Reference Library
使用 sentence-transformers 将 AgentHarm + 安全样本转为 embedding 参考集。
输出: embedding_refs.json (供 Node.js Datafew Shield 使用)
"""

import json, os, sys, math
os.environ['TRANSFORMERS_OFFLINE'] = '1'
os.environ['HF_HUB_OFFLINE'] = '1'
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')

from sentence_transformers import SentenceTransformer

MODEL_NAME = 'paraphrase-multilingual-MiniLM-L12-v2'  # 跨语言 384 维
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')
os.makedirs(OUTPUT_DIR, exist_ok=True)

print('Loading model:', MODEL_NAME)
model = SentenceTransformer(MODEL_NAME)
dim = model.get_sentence_embedding_dimension()
print('Embedding dimension:', dim)

# =========================================================================
# 1. 有害参考集 (AgentHarm)
# =========================================================================

harm_path = os.path.join(os.path.dirname(__file__), '..', '..', 'agentboard', 'backend', 'ape', 'data', 'external', 'agent_harm.json')
if not os.path.exists(harm_path):
    harm_path = os.path.join(os.path.dirname(__file__), '..', '..', 'agentboard', 'backend', 'ape', 'data', 'safety_test_cases.json')

harmful_texts = []
harmful_meta = []

if os.path.exists(harm_path):
    data = json.loads(open(harm_path, 'r', encoding='utf-8-sig').read())
    behaviors = data.get('behaviors', data if isinstance(data, list) else [])
    for b in behaviors:
        prompt = b.get('prompt', b.get('text', ''))
        if prompt and len(prompt) > 5:
            harmful_texts.append(prompt)
            harmful_meta.append({
                'category': b.get('category', 'unknown'),
                'name': b.get('name', b.get('id', 'unnamed')),
            })

print(f'Harmful samples: {len(harmful_texts)}')

# =========================================================================
# 2. 安全参考集
# =========================================================================

safe_texts = [
    # 系统操作
    'ls -la', 'pwd', 'whoami', 'date', 'uptime', 'df -h', 'free -m',
    'cat /etc/os-release', 'uname -a', 'ps aux', 'top -b -n 1',
    # 代码开发
    'git status', 'git log --oneline -5', 'npm install', 'pip install flask',
    'python -m pytest tests/', 'npm run build', 'docker ps',
    # 文件操作(安全)
    'cat README.md', 'head -20 main.py', 'ls src/', 'find . -name "*.py"',
    'cp config.example.json config.json', 'mkdir build', 'touch test.txt',
    # 网络(安全)
    'curl -s https://api.github.com/repos/user/repo', 'ping -c 1 localhost',
    'wget -q https://pypi.org/simple/flask', 'nslookup google.com',
    # 数据查询
    'SELECT * FROM users LIMIT 10', 'show databases', 'explain select * from orders',
    'redis-cli keys pattern:*', 'mongosh --eval "db.stats()"',
    # 中文安全操作
    '显示当前目录', '查看系统信息', '编译项目', '运行测试',
    '查看日志文件', '备份数据库', '部署到测试环境',
    # 开发帮助
    '帮我看下这个代码的 bug', '优化这个查询', '写一个单元测试',
    '解释这个函数的作用', '重构这段代码', '添加注释',
]

print(f'Safe samples: {len(safe_texts)}')

# =========================================================================
# 3. 计算 embedding
# =========================================================================

print('Computing embeddings...')
harmful_embs = model.encode(harmful_texts, show_progress_bar=True).tolist()
safe_embs = model.encode(safe_texts, show_progress_bar=True).tolist()

# =========================================================================
# 4. 归一化 + 导出
# =========================================================================

def normalize(v):
    import math
    n = math.sqrt(sum(x*x for x in v))
    return [x/n for x in v] if n > 0 else v

output = {
    'model': MODEL_NAME,
    'dimension': dim,
    'harmful': {
        'count': len(harmful_texts),
        'embeddings': [normalize(e) for e in harmful_embs],
        'metadata': harmful_meta,
    },
    'safe': {
        'count': len(safe_texts),
        'embeddings': [normalize(e) for e in safe_embs],
        'texts': safe_texts,
    },
    'benchmark': {
        'harmful_accuracy': 0,
        'safe_accuracy': 0,
        'optimal_threshold': 0.5,
    },
}

# =========================================================================
# 5. 自测: 找最优阈值
# =========================================================================

import math
import random

def cosine(a, b):
    dot = sum(x*y for x, y in zip(a, b))
    na = math.sqrt(sum(x*x for x in a))
    nb = math.sqrt(sum(x*x for x in b))
    return dot / (na * nb + 1e-10)

def score(emb, harmful_refs, safe_refs):
    max_h = max(cosine(emb, h) for h in harmful_refs) if harmful_refs else -1
    max_s = max(cosine(emb, s) for s in safe_refs) if safe_refs else -1
    h_score = (max_h + 1) / 2
    s_score = (max_s + 1) / 2
    if h_score + s_score < 0.01: return 0.5
    return h_score / (h_score + s_score)

h_norm = [normalize(e) for e in harmful_embs]
s_norm = [normalize(e) for e in safe_embs]

# 留一法交叉验证
correct_h = 0
for i, emb in enumerate(h_norm):
    # 排除自身
    others = h_norm[:i] + h_norm[i+1:]
    s = score(emb, others, s_norm)
    if s > 0.5: correct_h += 1

correct_s = 0
for emb in s_norm:
    s = score(emb, h_norm, [e for j, e in enumerate(s_norm) if e != emb])
    if s <= 0.5: correct_s += 1

# 搜索最优阈值（仅在样本足够时）
if len(h_norm) > 0 and len(s_norm) > 0:
    best_t = 0.5
    best_acc = 0
    for t in [x/100 for x in range(20, 81, 2)]:
        if len(h_norm) > 0:
            acc_h = sum(1 for i, emb in enumerate(h_norm) if score(emb, h_norm[:i]+h_norm[i+1:], s_norm) > t) / len(h_norm)
        else:
            acc_h = 0
        if len(s_norm) > 0:
            acc_s = sum(1 for emb in s_norm if score(emb, h_norm, [e for j, e in enumerate(s_norm) if e != emb]) <= t) / len(s_norm)
        else:
            acc_s = 0
        acc = (acc_h + acc_s) / 2
        if acc > best_acc:
            best_acc = acc
            best_t = t

output['benchmark'] = {
    'harmful_accuracy': round(correct_h / len(h_norm) * 100, 1) if h_norm else 0,
    'safe_accuracy': round(correct_s / len(s_norm) * 100, 1) if s_norm else 0,
    'optimal_threshold': round(best_t, 2) if 'best_t' in dir() else 0.5,
    'optimal_accuracy': round(best_acc * 100, 1) if 'best_acc' in dir() else 0,
}

print(f'\n=== Benchmark ===')
print(f'Harmful accuracy: {output["benchmark"]["harmful_accuracy"]}%')
print(f'Safe accuracy: {output["benchmark"]["safe_accuracy"]}%')
print(f'Optimal threshold: {best_t} (accuracy: {best_acc*100:.1f}%)')

# =========================================================================
# 6. 保存
# =========================================================================

out_path = os.path.join(OUTPUT_DIR, 'embedding_refs.json')
with open(out_path, 'w', encoding='utf-8') as f:
    json.dump(output, f, ensure_ascii=False)
print(f'\nSaved: {out_path} ({os.path.getsize(out_path) / 1024 / 1024:.1f} MB)')
