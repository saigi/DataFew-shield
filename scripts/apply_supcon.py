"""
Re-encode all reference texts with the SupCon fine-tuned model.
Updates embedding_refs.json with new embeddings.
"""
import json, os, sys, time
sys.stdout.reconfigure(encoding='utf-8')
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

import torch
import torch.nn.functional as F
from transformers import AutoModel, AutoTokenizer

BASE = os.path.dirname(os.path.abspath(__file__))
REFS_PATH = os.path.join(BASE, '..', 'data', 'embedding_refs.json')
SUPCON_PATH = os.path.join(BASE, '..', 'data', 'supcon_model')

print('Loading fine-tuned model...')
t0 = time.time()
tokenizer = AutoTokenizer.from_pretrained(SUPCON_PATH)
model = AutoModel.from_pretrained(SUPCON_PATH)
model.eval()
print(f'Loaded in {time.time()-t0:.0f}s')

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

# Load refs
refs = json.loads(open(REFS_PATH, 'r', encoding='utf-8').read())

# Collect all texts from metadata
def extract_texts(metadata):
    texts = []
    for m in metadata:
        if isinstance(m, dict):
            texts.append(m.get('name', ''))
        elif isinstance(m, str):
            texts.append(m)
    return [t for t in texts if len(t) > 3]

harmful_texts = extract_texts(refs['harmful']['metadata'])
safe_texts = extract_texts(refs['safe'].get('metadata', refs['safe'].get('texts', [])))

print(f'Re-encoding {len(harmful_texts)} harmful + {len(safe_texts)} safe...')
t0 = time.time()

harm_embs = encode(harmful_texts)
print(f'  Harmful done in {time.time()-t0:.0f}s')

safe_embs = encode(safe_texts)
print(f'  Safe done in {time.time()-t0:.0f}s')

# Update refs
refs['harmful']['embeddings'] = harm_embs
refs['safe']['embeddings'] = safe_embs
refs['harmful']['count'] = len(harm_embs)
refs['safe']['count'] = len(safe_embs)

# Clear old benchmark metrics — will be recalculated by build_classifier()
if 'classifier_threshold' in refs['benchmark']:
    del refs['benchmark']['classifier_threshold']
if 'classifier_accuracy' in refs['benchmark']:
    del refs['benchmark']['classifier_accuracy']

# Verify separation
harm_t = torch.tensor(harm_embs)
safe_t = torch.tensor(safe_embs)
intra_h = (harm_t @ harm_t.T).mean().item()
intra_s = (safe_t @ safe_t.T).mean().item()
cross = (harm_t @ safe_t.T).mean().item()
margin = intra_h + intra_s - 2 * cross
print(f'\nSeparation: intra_h={intra_h:.3f} intra_s={intra_s:.3f} cross={cross:.3f} margin={margin:.3f}')

# Save
with open(REFS_PATH, 'w', encoding='utf-8') as f:
    json.dump(refs, f, ensure_ascii=False)
print(f'\nSaved to {REFS_PATH}')
print(f'  Harmful: {refs["harmful"]["count"]} embeddings')
print(f'  Safe: {refs["safe"]["count"]} embeddings')
