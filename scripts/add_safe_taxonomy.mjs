/**
 * Add safe operation taxonomy to embedding refs.
 * 5 categories × 10-20 samples each = ~75 safe tool commands.
 * Self-growing: this script can be re-run to add more categories.
 */
import { request as h } from 'node:http';

async function learn(texts, category) {
  return new Promise(function(resolve) {
    var body = JSON.stringify({ texts: texts, type: 'safe', category: category });
    var req = h({
      hostname: 'localhost', port: 5000, path: '/learn', method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    }, function(res) {
      var d = ''; res.on('data', function(c) { d += c; });
      res.on('end', function() { try { resolve(JSON.parse(d)); } catch(e) { resolve(null); } });
    });
    req.on('error', function() { resolve(null); });
    req.write(body); req.end();
  });
}

// ─── Safe Operation Taxonomy ───
var TAXONOMY = {

  'safe_file_read': [
    'cat README.md',
    'cat package.json',
    'head -n 20 log.txt',
    'tail -n 50 server.log',
    'ls -la',
    'ls /workspace',
    'find /workspace -name "*.js"',
    'grep -r "TODO" /workspace/src',
    'wc -l src/index.js',
    'diff file1.txt file2.txt',
    'cat docs/architecture.md',
    'less CHANGELOG.md',
    'more README.md',
    'tree /workspace/src',
  ],

  'safe_package': [
    'npm install express',
    'npm install lodash',
    'pip install flask',
    'pip install pandas numpy',
    'apt-get update',
    'npm update',
    'npm run build',
    'npm run dev',
    'npm test',
    'go mod tidy',
    'cargo build',
    'nuget restore',
  ],

  'safe_dev': [
    'git status',
    'git diff',
    'git commit -m "fix bug"',
    'git push origin main',
    'git pull origin main',
    'git log --oneline -5',
    'git checkout -b feature/new',
    'npm run lint',
    'npm run format',
    'npm run typecheck',
    'node --version',
    'python --version',
    'tsc --noEmit',
  ],

  'safe_info': [
    'echo hello world',
    'date',
    'whoami',
    'pwd',
    'uname -a',
    'df -h',
    'free -m',
    'uptime',
    'which node',
    'env | grep PATH',
    'lsb_release -a',
    'cat /proc/cpuinfo | head -5',
  ],

  'safe_network': [
    'curl -I https://example.com',
    'curl https://api.github.com/repos/nodejs/node',
    'ping -c 1 8.8.8.8',
    'nslookup google.com',
    'dig github.com',
    'wget -q -O /dev/null https://example.com',
    'curl -s https://registry.npmjs.org/express',
    'ssh -v localhost',
  ],
};

var total = 0;
var categories = Object.keys(TAXONOMY);

for (var i = 0; i < categories.length; i++) {
  var cat = categories[i];
  var texts = TAXONOMY[cat];
  console.log('[' + (i+1) + '/' + categories.length + '] ' + cat + ': ' + texts.length + ' samples');
  var r = await learn(texts, cat);
  if (r) {
    console.log('  learned=' + r.learned + ' total_safe=' + r.total_safe + ' thresh=' + r.new_threshold);
    total += r.learned;
  } else {
    console.log('  FAILED');
  }
}

console.log('\nTotal learned: ' + total + ' safe samples');
console.log('Categories: ' + categories.length);
console.log('\nSelf-growing: re-run this script to add more categories.');
console.log('New FPs from test suite → identify category → add here → re-run → LR retrains.');
