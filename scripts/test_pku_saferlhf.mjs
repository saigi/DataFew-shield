/**
 * Test Shield against PKU-SafeRLHF benchmark.
 * 3036 safe/harmful question-response pairs.
 * Tests if Shield correctly blocks harmful prompts and allows safe ones.
 */
import { Shield, setEmbeddingReady } from '../index.js';
import { request as h } from 'node:http';
import { createInterface } from 'node:readline';
import { createReadStream } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
var __dirname = dirname(fileURLToPath(import.meta.url));

var TEST_FILE = resolve(__dirname, '..', 'data', 'external', 'pku_saferlhf_test.jsonl');
var MAX_TEST = 500; // sample 500 due to time

async function checkEmbed() {
  return new Promise(function(r) {
    h({hostname:'localhost',port:5000,path:'/health',method:'GET'},function(res){
      var d='';res.on('data',function(c){d+=c});res.on('end',function(){try{r(JSON.parse(d))}catch(e){r(null)}})
    }).on('error',function(){r(null)}).end();
  });
}

var health = await checkEmbed();
setEmbeddingReady(health && health.status === 'ok');
var shield = new Shield({ policyDir: resolve(__dirname, '..', 'policies') });

// Read dataset, find harmful/safe pairs
var items = [];
var rl = createInterface({ input: createReadStream(TEST_FILE) });
for await (var line of rl) {
  try {
    var item = JSON.parse(line);
    // PKU-SafeRLHF: prompt + two responses with safety labels per response
    var isHarmful = false;
    if (item.is_response_0_safe !== undefined && item.is_response_1_safe !== undefined) {
      isHarmful = item.is_response_0_safe === false || item.is_response_1_safe === false;
    }
    
    var prompt = item.question || item.prompt || item.input || '';
    if (prompt.length > 10) {
      items.push({ prompt: prompt, harmful: isHarmful });
    }
  } catch(e) {}
}
console.log('PKU-SafeRLHF: ' + items.length + ' labeled items');
console.log('  Harmful: ' + items.filter(function(i) { return i.harmful; }).length);
console.log('  Safe: ' + items.filter(function(i) { return !i.harmful; }).length);

// Sample for testing
var sample = items.slice(0, MAX_TEST);
console.log('Testing ' + sample.length + ' samples...\n');

var total = 0, passed = 0, tStart = Date.now();
var byLabel = { safe: { ok: 0, total: 0 }, harmful: { ok: 0, total: 0 } };

for (var i = 0; i < sample.length; i++) {
  var item = sample[i];
  var sid = 'pku-' + i;
  await shield.sandboxManager.createSandbox(sid, {});

  var r = await shield.inspect({ type: 'chat', tool: 'llm', args: item.prompt, session_id: sid });
  var blocked = !r.allowed;
  var correct = blocked === item.harmful;
  total++;
  if (correct) passed++;

  var label = item.harmful ? 'harmful' : 'safe';
  byLabel[label].total++;
  if (correct) byLabel[label].ok++;

  if ((i + 1) % 100 === 0) {
    var elapsed = ((Date.now() - tStart) / 1000).toFixed(0);
    console.log('  ' + (i+1) + '/' + sample.length + ' (' + passed + '/' + total + ' correct) ' + elapsed + 's');
  }
}

console.log('\nResults:');
console.log('  Harmful prompts: ' + byLabel.harmful.ok + '/' + byLabel.harmful.total + ' blocked (' + Math.round(byLabel.harmful.ok / byLabel.harmful.total * 100) + '%)');
console.log('  Safe prompts:    ' + byLabel.safe.ok + '/' + byLabel.safe.total + ' allowed (' + Math.round(byLabel.safe.ok / byLabel.safe.total * 100) + '%)');
console.log('  Overall:         ' + passed + '/' + total + ' (' + Math.round(passed / total * 100) + '%)');
console.log('  Time: ' + ((Date.now() - tStart) / 1000).toFixed(0) + 's');
