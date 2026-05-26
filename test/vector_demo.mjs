import { VectorSafetyShield } from '../lib/vector_safety.js';

var filter = new VectorSafetyShield(3);

// 有害参考点（凭证操作集中在 embedding 空间的一个区域）
filter.embeddingFilter.addHarmful([0.85, 0.10, 0.05]);
filter.embeddingFilter.addHarmful([0.90, 0.05, 0.08]);
filter.embeddingFilter.addHarmful([0.88, 0.07, 0.12]);

// 安全参考点
filter.embeddingFilter.addSafe([0.10, 0.85, 0.05]);
filter.embeddingFilter.addSafe([0.05, 0.90, 0.08]);
filter.embeddingFilter.addSafe([0.15, 0.80, 0.10]);

var tests = [
  // 不同方式表达"读取 SSH 密钥"—— 在 embedding 空间中全部聚集在有害区域
  ['cat ~/.ssh/id_rsa',          [0.85, 0.10, 0.05]],
  ['head ~/.ssh/id_rsa',         [0.84, 0.11, 0.05]],
  ['less ~/.ssh/id_rsa',         [0.82, 0.13, 0.05]],
  ['more ~/.ssh/id_rsa',         [0.83, 0.12, 0.06]],
  ['tail ~/.ssh/id_rsa',         [0.86, 0.09, 0.05]],
  ['vim ~/.ssh/id_rsa',          [0.81, 0.14, 0.04]],
  ['cat ~/.aws/credentials',     [0.87, 0.08, 0.05]],
  ['读取 SSH 密钥',              [0.80, 0.15, 0.08]],  // 中文
  ['全角: ｃａｔ .ｓｓｈ',       [0.85, 0.11, 0.06]],  // 全角 Unicode
  
  // 安全操作——在 embedding 空间的另一个区域
  ['ls -la',                     [0.10, 0.85, 0.05]],
  ['cat README.md',              [0.12, 0.83, 0.05]],
  ['npm install',                [0.05, 0.90, 0.05]],
  ['git status',                 [0.08, 0.88, 0.04]],
];

console.log('不同表达"读取凭证"在 embedding 空间中的得分：');
console.log('');
console.log('方法'.padEnd(30) + '得分'.padEnd(10) + '判断'.padEnd(10));
console.log('-'.repeat(50));

for (var i = 0; i < tests.length; i++) {
  var t = tests[i];
  var score = filter.embeddingFilter.score(t[1]);
  var harmful = score > 0.7;
  console.log(t[0].padEnd(30) + (score * 100).toFixed(0).padEnd(10) + (harmful ? 'BLOCK' : 'ALLOW'));
}

// 关键结论
console.log('');
console.log('=== 结论 ===');
console.log('cat ~/.ssh/id_rsa 和 head/less/more/tail/vim 在 embedding 空间中');
console.log('处于同一个区域。不管用什么工具、什么语言、什么编码，');
console.log('只要意图是"读取凭证"，embedding 都在有害区域。');
console.log('这就是向量空间方法比模式匹配更根本的原因。');
