/**
 * Test Shield against AdvBench (HEx-PHI) — 520 harmful behaviors.
 * Standard academic benchmark for LLM safety.
 */
import { Shield, setEmbeddingReady } from '../index.js';
import { request as h } from 'node:http';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
var __dirname = dirname(fileURLToPath(import.meta.url));

async function checkEmbed() {
  return new Promise(function(r) {
    h({hostname:'localhost',port:5000,path:'/health',method:'GET'},function(res){
      var d='';res.on('data',function(c){d+=c});res.on('end',function(){try{r(JSON.parse(d))}catch(e){r(null)}})
    }).on('error',function(){r(null)}).end();
  });
}

// Parse CSV
var csv = readFileSync(resolve(__dirname, '..', 'data', 'external', 'hex_phi_harmful.csv'), 'utf-8');
var lines = csv.trim().split('\n');
var goals = [];
for (var i = 1; i < lines.length; i++) {
  // CSV: goal,target (simple format, no quoting issues for this dataset)
  var commaIdx = lines[i].indexOf(',');
  if (commaIdx > 0) {
    var goal = lines[i].slice(0, commaIdx);
    goals.push(goal);
  }
}

console.log('AdvBench: ' + goals.length + ' harmful goals\n');

var health = await checkEmbed();
setEmbeddingReady(health && health.status === 'ok');
var shield = new Shield({ policyDir: resolve(__dirname, '..', 'policies') });

var total = 0, blocked = 0, tStart = Date.now();
var byLayer = {};

for (var i = 0; i < goals.length; i++) {
  var sid = 'adv-' + i;
  await shield.sandboxManager.createSandbox(sid, {});

  var r = await shield.inspect({ type: 'chat', tool: 'llm', args: goals[i], session_id: sid });
  var isBlocked = !r.allowed;
  total++;
  if (isBlocked) {
    blocked++;
    byLayer[r.layer] = (byLayer[r.layer] || 0) + 1;
  }

  if ((i + 1) % 100 === 0) {
    var elapsed = ((Date.now() - tStart) / 1000).toFixed(0);
    console.log('  ' + (i + 1) + '/' + goals.length + ' (' + blocked + '/' + total + ' blocked) ' + elapsed + 's');
  }
}

console.log('\nResults:');
console.log('  AdvBench harmful goals: ' + blocked + '/' + total + ' (' + Math.round(blocked / total * 100) + '%)');
console.log('  By layer:');
var layers = Object.keys(byLayer).sort(function(a, b) { return byLayer[b] - byLayer[a]; });
for (var l of layers) {
  console.log('    ' + l + ': ' + byLayer[l] + ' (' + Math.round(byLayer[l] / total * 100) + '%)');
}
console.log('  Time: ' + ((Date.now() - tStart) / 1000).toFixed(0) + 's');
