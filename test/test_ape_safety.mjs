/**
 * Test APE-specific safety test cases (16 cases, all should be blocked).
 */
import { Shield, setEmbeddingReady } from '../index.js';
import { request as h } from 'node:http';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

var __d = dirname(fileURLToPath(import.meta.url));

async function checkEmbed() {
  return new Promise(function(r) {
    h({hostname:'localhost',port:5000,path:'/health',method:'GET'},function(res){
      var d='';res.on('data',function(c){d+=c});res.on('end',function(){try{r(JSON.parse(d))}catch(e){r(null)}})
    }).on('error',function(){r(null)}).end();
  });
}

var health = await checkEmbed();
setEmbeddingReady(health && health.status === 'ok');
var shield = new Shield({ policyDir: resolve(__d, '..', 'policies') });

// Load APE safety test cases
var testPath = resolve(__d, '..', '..', 'agentboard', 'backend', 'ape', 'data', 'safety_test_cases.json');
var raw = readFileSync(testPath, 'utf-8');
if (raw.charCodeAt(0) === 0xFEFF) raw = raw.slice(1);
var cases = JSON.parse(raw);

var TOTAL = cases.length;
var PASS = 0;

console.log('APE Safety Test Cases (' + TOTAL + ')\n');

for (var i = 0; i < cases.length; i++) {
  var tc = cases[i];
  var sid = 'ape-' + tc.id;
  await shield.sandboxManager.createSandbox(sid, {});

  var r = await shield.inspect({
    type: 'tool_call', tool: 'terminal', args: tc.prompt, session_id: sid,
  });

  // All test cases expect refusal (BLOCK)
  var correct = !r.allowed;
  if (correct) PASS++;
  var icon = correct ? '✓' : '✗';
  var layer = r.layer;
  console.log(icon + ' ' + tc.id + ' (' + tc.category + ') L=' + layer);
}

console.log('\nResult: ' + PASS + '/' + TOTAL + ' (' + Math.round(PASS/TOTAL*100) + '%)');
console.log('Failures:');
for (var i = 0; i < cases.length; i++) {
  var tc = cases[i];
  var sid = 'ape-' + tc.id;
  // Can't re-inspect without new session, just report from earlier
}
