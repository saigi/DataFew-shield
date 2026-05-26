/**
 * Batch learn safe prompts into embedding refs
 * Run: node scripts/batch_learn_safe.mjs
 */
import { request as httpReq } from 'node:http';
import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

var __d = dirname(fileURLToPath(import.meta.url));

function loadJSON(path) {
  try {
    var raw = readFileSync(path, 'utf-8');
    if (raw.charCodeAt(0) === 0xFEFF) raw = raw.slice(1);
    return JSON.parse(raw);
  } catch(e) { return null; }
}

async function learn(texts, type, category) {
  return new Promise(function(resolve) {
    var body = JSON.stringify({ texts: texts, type: type, category: category });
    var req = httpReq({
      hostname: 'localhost', port: 5000, path: '/learn', method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
    }, function(res) {
      var d = '';
      res.on('data', function(c) { d += c; });
      res.on('end', function() { try { resolve(JSON.parse(d)); } catch(e) { resolve(null); } });
    });
    req.on('error', function() { resolve(null); });
    req.write(body);
    req.end();
  });
}

// 1. Learn 176 AgentHarm benign as safe samples
var benignPath = resolve(__d, '..', '..', 'agentboard', 'backend', 'ape', 'data', 'external', 'agent_harm_benign.json');
var benignData = loadJSON(benignPath);
if (benignData && benignData.behaviors) {
  var texts = benignData.behaviors.map(function(b) { return b.prompt; });
  console.log('Learning ' + texts.length + ' safe samples...');
  for (var i = 0; i < texts.length; i += 20) {
    var batch = texts.slice(i, i + 20);
    var r = await learn(batch, 'safe', 'agentharm_benign');
    if (r) {
      console.log('  batch ' + (i/20 + 1) + ': learned=' + r.learned + ' safe=' + r.total_safe + ' harmful=' + r.total_harmful + ' thresh=' + r.new_threshold);
    } else {
      console.log('  batch ' + (i/20 + 1) + ': FAILED');
    }
  }
}

// 2. Also learn the 5 safe commands that should never be blocked
var safeCmds = ['ls -la', 'git status', 'pip install flask', 'echo hello', 'cat README.md'];
console.log('\nLearning ' + safeCmds.length + ' safe commands...');
var r2 = await learn(safeCmds, 'safe', 'safe_commands');
console.log('  learned=' + (r2 ? r2.learned : 'FAILED'));

  // 3. Check result
function checkServer() {
  return new Promise(function(resolve) {
    httpReq({ hostname: 'localhost', port: 5000, path: '/health', method: 'GET' }, function(res) {
      var d = ''; res.on('data', function(c) { d += c; });
      res.on('end', function() { try { resolve(JSON.parse(d)); } catch(e) { resolve(null); } });
    }).on('error', function() { resolve(null); }).end();
  });
}
var hlth = await checkServer();
if (hlth) console.log('\nFinal: ' + hlth.harmful_refs + 'H ' + hlth.safe_refs + 'S thresh=' + hlth.threshold);
