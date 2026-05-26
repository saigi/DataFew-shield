"""
Rebuild embedding refs with FULL texts (not truncated).
Loads original sources, encodes with SupCon model, saves.
"""
import json, os, sys, time
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

import torch
import torch.nn.functional as F
from transformers import AutoModel, AutoTokenizer

BASE = os.path.dirname(os.path.abspath(__file__))
REFS_PATH = os.path.join(BASE, '..', 'data', 'embedding_refs.json')
SUPCON_PATH = None  # force base model
MODEL_NAME = 'sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2'

print('Loading base model:', MODEL_NAME)
t0 = time.time()
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model = AutoModel.from_pretrained(MODEL_NAME)

def load_agentharm(path):
    raw = open(path, 'r', encoding='utf-8-sig').read()
    if raw.startswith('\ufeff'): raw = raw[1:]
    data = json.loads(raw)
    if isinstance(data, dict) and 'behaviors' in data:
        return [b['prompt'] for b in data['behaviors']]
    return []

print('Loading base model:', MODEL_NAME)
t0 = time.time()
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, local_files_only=True)
model = AutoModel.from_pretrained(MODEL_NAME, local_files_only=True)
model.eval()
print(f'Model loaded in {time.time()-t0:.0f}s')

def mean_pooling(token_embs, mask):
    token_embs = token_embs * mask.unsqueeze(-1)
    return token_embs.sum(dim=1) / mask.sum(dim=1, keepdim=True).clamp(min=1e-9)

def encode(texts, batch_size=32):
    all_embs = []
    for i in range(0, len(texts), batch_size):
        batch = texts[i:i+batch_size]
        inputs = tokenizer(batch, padding=True, truncation=True, max_length=128, return_tensors='pt')
        with torch.no_grad():
            outputs = model(**inputs)
        embs = mean_pooling(outputs.last_hidden_state, inputs['attention_mask'])
        embs = F.normalize(embs, dim=1)
        all_embs.append(embs)
    return torch.cat(all_embs, dim=0).tolist()

# ─── Collect all texts from original sources ───
harmful_texts = []
safe_texts = []

# 1. AgentHarm harmful (original, full prompts)
ah = load_agentharm(os.path.join(BASE, '..', '..', 'agentboard', 'backend', 'ape', 'data', 'external', 'agent_harm.json'))
for t in ah:
    harmful_texts.append(t)
print(f'AgentHarm harmful: {len(ah)}')

# 2. AgentHarm chat (full prompts)
ah_chat = load_agentharm(os.path.join(BASE, '..', '..', 'agentboard', 'backend', 'ape', 'data', 'external', 'agent_harm_chat.json'))
for t in ah_chat:
    harmful_texts.append(t)
print(f'AgentHarm chat: {len(ah_chat)}')

# 3. extra_tests (all are harmful)
extra = json.loads(open(os.path.join(BASE, '..', 'data', 'extra_tests.json'), 'r', encoding='utf-8').read())
extra_count = 0
for k in extra:
    for item in extra[k]:
        harmful_texts.append(item['text'])
        extra_count += 1
print(f'extra_tests: {extra_count}')

# 4. AgentHarm benign (safe)
ah_benign = load_agentharm(os.path.join(BASE, '..', '..', 'agentboard', 'backend', 'ape', 'data', 'external', 'agent_harm_benign.json'))
for t in ah_benign:
    safe_texts.append(t)
print(f'AgentHarm benign: {len(ah_benign)}')

# 5. Safe commands
safe_cmds = ['ls -la', 'git status', 'pip install flask', 'echo hello', 'cat README.md']
for t in safe_cmds:
    safe_texts.append(t)
print(f'Safe commands: {len(safe_cmds)}')

print(f'\nTotal: {len(harmful_texts)} harmful + {len(safe_texts)} safe = {len(harmful_texts)+len(safe_texts)}')

# ─── Encode all ───
print('\nEncoding harmful...')
t0 = time.time()
harm_embs = encode(harmful_texts)
print(f'  done in {time.time()-t0:.0f}s')

print('Encoding safe...')
t0 = time.time()
safe_embs = encode(safe_texts)
print(f'  done in {time.time()-t0:.0f}s')

# ─── Build refs ───
refs = {
    'model': MODEL_NAME,
    'dimension': 384,
    'harmful': {
        'count': len(harm_embs),
        'embeddings': harm_embs,
        'metadata': [{'name': t} for t in harmful_texts],
    },
    'safe': {
        'count': len(safe_embs),
        'embeddings': safe_embs,
        'metadata': [{'name': t} for t in safe_texts],
    },
    'benchmark': {},
}

# ─── Verify separation ───
import math
import torch
h_t = torch.tensor(harm_embs)
s_t = torch.tensor(safe_embs)
print(f'\nSeparation: intra_h={h_t.mean().item():.3f} '
      f'intra_s={s_t.mean().item():.3f} '
      f'cross={(h_t @ s_t.T).mean().item():.3f}')

# ─── Compute k-NN threshold ───
def cosine(a, b):
    dot = sum(x*y for x,y in zip(a,b))
    na = math.sqrt(sum(x*x for x in a))
    nb = math.sqrt(sum(x*x for x in b))
    return dot / (na * nb + 1e-10)

def knn_score(emb, h_embs, s_embs):
    max_h = max(cosine(emb, h) for h in h_embs) if h_embs else -1
    max_s = max(cosine(emb, s) for s in s_embs) if s_embs else -1
    h_s = (max_h + 1) / 2
    s_s = (max_s + 1) / 2
    if h_s + s_s < 0.01: return 0.5
    return h_s / (h_s + s_s)

print('Computing threshold...')
t0 = time.time()
h_scores = [knn_score(e, harm_embs, safe_embs) for e in harm_embs]
s_scores = [knn_score(e, safe_embs, harm_embs) for e in safe_embs]
print(f'  scored in {time.time()-t0:.0f}s')

best_t, best_acc = 0.5, 0
for t in [x/100 for x in range(10, 95)]:
    h_ok = sum(1 for s in h_scores if s > t)
    s_ok = sum(1 for s in s_scores if s <= t)
    acc = (h_ok + s_ok) / (len(h_scores) + len(s_scores))
    if acc > best_acc:
        best_acc, best_t = acc, t

refs['benchmark']['knn_threshold'] = best_t
refs['benchmark']['knn_accuracy'] = round(best_acc, 4)
print(f'Threshold: {best_t}, accuracy: {best_acc:.4f}')

# ─── Save ───
with open(REFS_PATH, 'w', encoding='utf-8') as f:
    json.dump(refs, f, ensure_ascii=False)
print(f'\nSaved to {REFS_PATH}')
print(f'  {refs["harmful"]["count"]} harmful, {refs["safe"]["count"]} safe')
print(f'  Max harmful text len: {max(len(t) for t in harmful_texts)}')
print(f'  Max safe text len: {max(len(t) for t in safe_texts)}')
