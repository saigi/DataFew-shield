"""
Embedding Safety Server — Python HTTP 服务
为 Datafew Shield (Node.js) 提供实时 embedding 安全评分。
启动: python embedding_server.py [--port 5000] [--auth-token <token>]
安全: 建议设置 SHIELD_AUTH_TOKEN 环境变量或 --auth-token 参数
"""

import json, os, sys, argparse, math, torch, re, time, tempfile, shutil
sys.stdout.reconfigure(encoding='utf-8')
sys.stderr.reconfigure(encoding='utf-8')
from http.server import HTTPServer, BaseHTTPRequestHandler
from transformers import AutoModel, AutoTokenizer
from sklearn.linear_model import LogisticRegression
import numpy as np

BASE = os.path.dirname(os.path.abspath(__file__))
REFS_PATH = os.path.join(BASE, '..', 'data', 'embedding_refs.json')
MODEL_NAME = 'sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2'

# Auth token from env or CLI
AUTH_TOKEN = os.environ.get('SHIELD_AUTH_TOKEN', '')
# Rate limiting
RATE_LIMIT = {}
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX = 30

print('Using base model:', MODEL_NAME)

def mean_pooling(token_embs, attention_mask):
    token_embs = token_embs * attention_mask.unsqueeze(-1)
    return token_embs.sum(dim=1) / attention_mask.sum(dim=1, keepdim=True).clamp(min=1e-9)

print('Loading tokenizer:', MODEL_NAME)
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, local_files_only=True)
print('Loading model:', MODEL_NAME)
model = AutoModel.from_pretrained(MODEL_NAME, local_files_only=True)
model.eval()
DIM = model.config.hidden_size
print(f'Model loaded, dim={DIM}')

def encode(texts):
    inputs = tokenizer(texts, padding=True, truncation=True, max_length=128, return_tensors='pt')
    with torch.no_grad():
        outputs = model(**inputs)
    embs = mean_pooling(outputs.last_hidden_state, inputs['attention_mask'])
    return embs.tolist()

def normalize(v):
    n = math.sqrt(sum(x*x for x in v))
    return [x/n for x in v] if n > 0 else v

print('Loading refs:', REFS_PATH)
with open(REFS_PATH, 'r', encoding='utf-8') as f:
    refs = json.load(f)
refs['harmful']['embeddings'] = [normalize(e) for e in refs['harmful']['embeddings']]
refs['safe']['embeddings'] = [normalize(e) for e in refs['safe']['embeddings']]

THRESHOLD = refs['benchmark'].get('lr_threshold', refs['benchmark'].get('optimal_threshold', 0.5))
CLF = None

def cosine(a, b):
    dot = sum(x*y for x, y in zip(a, b))
    na = math.sqrt(sum(x*x for x in a))
    nb = math.sqrt(sum(x*x for x in b))
    return dot / (na * nb + 1e-10)

def train_classifier():
    global CLF, THRESHOLD
    X_h = refs['harmful']['embeddings']
    X_s = refs['safe']['embeddings']
    if len(X_h) < 2 or len(X_s) < 2:
        return

    X = np.array(X_h + X_s)
    y = np.array([1] * len(X_h) + [0] * len(X_s))

    clf = LogisticRegression(
        penalty='l2', C=1.0, class_weight='balanced',
        solver='lbfgs', max_iter=1000, random_state=42,
    )
    clf.fit(X, y)

    probs = clf.predict_proba(X)[:, 1]
    best_t, best_acc = 0.5, 0
    for t in [x / 100 for x in range(10, 95)]:
        preds = (probs > t).astype(int)
        acc = (preds == y).mean()
        if acc > best_acc:
            best_acc, best_t = acc, t

    THRESHOLD = best_t
    CLF = clf
    refs['benchmark']['lr_threshold'] = round(best_t, 4)
    refs['benchmark']['lr_accuracy'] = round(best_acc, 4)
    refs['benchmark']['lr_samples'] = len(X_h) + len(X_s)
    print(f'[LR] trained: {len(X_h)}H+{len(X_s)}S, threshold={best_t}, accuracy={best_acc:.3f}')

def score(emb, return_metadata=False):
    if CLF is None:
        h_sim = max(cosine(emb, h) for h in refs['harmful']['embeddings']) if refs['harmful']['embeddings'] else -1
        s_sim = max(cosine(emb, s) for s in refs['safe']['embeddings']) if refs['safe']['embeddings'] else -1
        hs = (h_sim + 1) / 2
        ss = (s_sim + 1) / 2
        s = hs / (hs + ss + 1e-10)
    else:
        try:
            s = float(CLF.predict_proba(np.array([emb]))[0, 1])
        except Exception:
            s = 0.5

    meta = {'method': 'lr' if CLF else 'cosine', 'density': 0.5, 'confidence': abs(2*s - 1)}
    if return_metadata:
        return s, meta
    return s

def persist_refs():
    """Atomically write refs to disk using tempfile + rename."""
    tmp_path = REFS_PATH + '.tmp.' + str(os.getpid())
    try:
        with open(tmp_path, 'w', encoding='utf-8') as f:
            json.dump(refs, f, ensure_ascii=False)
        shutil.move(tmp_path, REFS_PATH)
    except Exception as e:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise

def check_rate_limit(client_ip):
    now = time.time()
    if client_ip not in RATE_LIMIT:
        RATE_LIMIT[client_ip] = []
    RATE_LIMIT[client_ip] = [t for t in RATE_LIMIT[client_ip] if now - t < RATE_LIMIT_WINDOW]
    if len(RATE_LIMIT[client_ip]) >= RATE_LIMIT_MAX:
        return False
    RATE_LIMIT[client_ip].append(now)
    return True

def check_auth(headers):
    if not AUTH_TOKEN:
        return True
    auth = headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        return auth[7:] == AUTH_TOKEN
    return headers.get('X-Auth-Token', '') == AUTH_TOKEN

train_classifier()

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            self.send_json(200, {
                'status': 'ok',
                'model': MODEL_NAME,
                'dimension': refs['dimension'],
                'harmful_refs': refs['harmful']['count'],
                'safe_refs': refs['safe']['count'],
                'threshold': THRESHOLD,
                'auth_required': bool(AUTH_TOKEN),
            })
        else:
            self.send_json(404, {'error': 'unknown endpoint'})

    def do_POST(self):
        client_ip = self.client_address[0]

        if not check_rate_limit(client_ip):
            self.send_json(429, {'error': 'rate_limit_exceeded'})
            return

        if not check_auth(self.headers):
            self.send_json(401, {'error': 'unauthorized'})
            return

        if self.path == '/score':
            self.handle_score()
        elif self.path == '/learn':
            self.handle_learn()
        elif self.path == '/distill':
            self.handle_distill()
        else:
            self.send_json(404, {'error': 'unknown endpoint'})

    def handle_score(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode()
        data = json.loads(body) if body else {}
        texts = data.get('texts', [data.get('text', '')])
        if isinstance(texts, str):
            texts = [texts]

        if not texts or not texts[0]:
            self.send_json(400, {'error': 'no text provided'})
            return

        cur_th = THRESHOLD
        results = []
        embs = encode(texts)
        for i, emb in enumerate(embs):
            s, meta = score(normalize(emb), return_metadata=True)
            results.append({
                'text': texts[i][:100],
                'score': round(s, 4),
                'harmful': s > cur_th,
                'threshold': cur_th,
                'confidence': meta.get('confidence', 0),
                'density': meta.get('density', 0),
                'method': meta.get('method', 'unknown'),
            })

        self.send_json(200, {
            'results': results,
            'summary': {
                'total': len(results),
                'harmful': sum(1 for r in results if r['harmful']),
                'safe': sum(1 for r in results if not r['harmful']),
            }
        })

    def handle_learn(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode()
        data = json.loads(body) if body else {}
        texts = data.get('texts', [data.get('text', '')]) or []
        category = data.get('category', 'learned')
        learn_type = data.get('type', 'harmful')
        if isinstance(texts, str):
            texts = [texts]
        if not texts:
            self.send_json(400, {'error': 'no texts'})
            return

        embs = encode(texts)
        target = refs['harmful'] if learn_type == 'harmful' else refs['safe']
        if 'metadata' not in target:
            target['metadata'] = target.get('texts', [])
        added = 0
        for i, text in enumerate(texts):
            target['embeddings'].append(embs[i])
            if isinstance(target['metadata'], list):
                target['metadata'].append({'category': category, 'name': text})
            added += 1

        refs['harmful']['count'] = len(refs['harmful']['embeddings'])
        refs['safe']['count'] = len(refs['safe']['embeddings'])

        train_classifier()
        persist_refs()

        self.send_json(200, {
            'learned': added,
            'type': learn_type,
            'total_harmful': refs['harmful']['count'],
            'total_safe': refs['safe']['count'],
            'new_threshold': THRESHOLD,
        })

    def handle_distill(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode()
        data = json.loads(body) if body else {}
        text = data.get('text', '')
        if not text:
            self.send_json(400, {'error': 'no text'})
            return

        result = {'text': text[:100], 'score': None, 'above_threshold': False, 'recommendations': []}

        emb = encode([text])[0]
        s = score(normalize(emb))
        result['score'] = round(s, 4)
        result['above_threshold'] = s > THRESHOLD

        policy_patterns = [
            {'name': 'etc_config_read', 're': r'/etc/.*\.(json|yml|yaml|conf|cfg|ini)', 'tool': 'read_file',
             'desc': '读取系统配置文件'},
            {'name': 'bash_history', 're': r'\.bash_history', 'tool': 'terminal', 'desc': '读取 bash 历史'},
            {'name': 'download_and_check', 're': r'(wget|curl).*(检查|check|安全|security)', 'tool': 'terminal',
             'desc': '下载外部资源后检查'},
            {'name': 'env_grep_key', 're': r'(env|printenv).*(KEY|TOKEN|SECRET|PASSWORD)', 'tool': 'terminal',
             'desc': '环境变量搜凭证'},
            {'name': 'find_secret', 're': r'find.*(password|secret|key|cred)', 'tool': 'terminal',
             'desc': '搜索敏感文件'},
            {'name': 'python_http_server', 're': r'python.*http\.server', 'tool': 'terminal',
             'desc': '启动文件服务器'},
            {'name': 'curl_exfil', 're': r'curl.*POST.*secret', 'tool': 'terminal', 'desc': 'curl 外传'},
            {'name': 'base64_exfil', 're': r'base64.*(curl|nc|dns|http)', 'tool': 'terminal', 'desc': 'base64 编码后外传'},
        ]

        matched_policies = []
        for p in policy_patterns:
            try:
                if re.search(p['re'], text, re.IGNORECASE):
                    matched_policies.append(p)
            except re.error:
                pass

        if matched_policies:
            result['recommendations'].append({
                'type': 'policy_rule', 'count': len(matched_policies),
                'patterns': matched_policies, 'action': 'add to policies/default.json',
            })

        if s > THRESHOLD and not matched_policies:
            result['recommendations'].append({'type': 'embedding_ref', 'action': 'call /learn endpoint to add to refs'})

        if not matched_policies and s <= THRESHOLD:
            result['recommendations'].append({'type': 'human_analysis', 'action': 'no automatic protection available, review manually'})

        self.send_json(200, result)

    def send_json(self, code, data):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def log_message(self, format, *args):
        pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=5000)
    parser.add_argument('--auth-token', type=str, default='', help='Auth token for /learn and /distill endpoints')
    args = parser.parse_args()

    if args.auth_token:
        AUTH_TOKEN = args.auth_token

    server = HTTPServer(('127.0.0.1', args.port), Handler)
    print(f'Embedding server running on http://127.0.0.1:{args.port}')
    print(f'  Threshold: {THRESHOLD}')
    print(f'  Harmful refs: {refs["harmful"]["count"]}')
    print(f'  Safe refs: {refs["safe"]["count"]}')
    print(f'  Auth required: {bool(AUTH_TOKEN)}')
    server.serve_forever()
