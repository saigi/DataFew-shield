/*
 * Embedding 验证测试
 * 加载真实 embedding refs，验证各测试样本得分
 * 真实部署依赖 Python embedding_server.py 提供 384 维评分
 * 这里只做参考集加载验证，不模拟评分
 */

import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

var __dirname = dirname(fileURLToPath(import.meta.url));
var REFS_PATH = resolve(__dirname, '..', 'data', 'embedding_refs.json');

console.log('Loading embedding refs...');
var refs = JSON.parse(readFileSync(REFS_PATH, 'utf-8'));
console.log('  Model:', refs.model);
console.log('  Dimension:', refs.dimension);
console.log('  Harmful refs:', refs.harmful.count);
console.log('  Safe refs:', refs.safe.count);
console.log('  Optimal threshold:', refs.benchmark.optimal_threshold);

function cosine(a, b) {
  var dot = 0, na = 0, nb = 0;
  for (var i = 0; i < a.length; i++) { dot += a[i] * b[i]; na += a[i] * a[i]; nb += b[i] * b[i]; }
  return dot / (Math.sqrt(na) * Math.sqrt(nb) + 1e-10);
}

function score(emb) {
  var hEmbeddings = refs.harmful.embeddings;
  var sEmbeddings = refs.safe.embeddings;
  var maxH = -1;
  for (var i = 0; i < hEmbeddings.length; i++) { var sim = cosine(emb, hEmbeddings[i]); if (sim > maxH) maxH = sim; }
  var maxS = -1;
  for (var i = 0; i < sEmbeddings.length; i++) { var sim = cosine(emb, sEmbeddings[i]); if (sim > maxS) maxS = sim; }
  var hScore = (maxH + 1) / 2;
  var sScore = (maxS + 1) / 2;
  if (hScore + sScore < 0.01) return 0.5;
  return hScore / (hScore + sScore);
}

// Test the first harmful embedding to verify refs load correctly
console.log('\nFirst harmful embedding score (self-test):', score(refs.harmful.embeddings[0]).toFixed(4));
console.log('First safe embedding score (self-test):', score(refs.safe.embeddings[0]).toFixed(4));

console.log('\nRefs loaded successfully. Real embedding scoring requires running:');
console.log('  python scripts/embedding_server.py --port 5000');
console.log('Then Shield will use it automatically for L1 scoring.');
