/**
 * DLP (Data Loss Prevention) Test Suite.
 * Tests data lineage tracking: read sensitive → egress blocked.
 */
import { Shield, setEmbeddingReady } from '../index.js';
import { request as h } from 'node:http';
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

var health = await checkEmbed();
setEmbeddingReady(health && health.status === 'ok');
var shield = new Shield({ policyDir: resolve(__dirname, '..', 'policies') });

var passed = 0, total = 0;

function check(cond, msg) {
  total++;
  if (cond) { passed++; console.log('  ✓ ' + msg); }
  else { console.log('  ✗ ' + msg); }
}

// ─── Test 1: Read P0 → Egress blocked ───
console.log('\n=== Test 1: Read P0 → Egress ===');
await shield.sandboxManager.createSandbox('dlp-t1', {});
await shield.inspect({ type:'tool_call', tool:'read_file', args:'/etc/shadow', session_id:'dlp-t1' });
var r = await shield.inspect({ type:'tool_call', tool:'send_message', args:'report', session_id:'dlp-t1' });
check(!r.allowed && r.layer === 'DLP', 'read P0 + send_message → DLP block (L=' + r.layer + ')');

// ─── Test 2: Clean session → Egress allowed ───
console.log('\n=== Test 2: Clean session → Egress allowed ===');
await shield.sandboxManager.createSandbox('dlp-t2', {});
var r2 = await shield.inspect({ type:'tool_call', tool:'send_message', args:'report', session_id:'dlp-t2' });
check(r2.allowed, 'clean session + send_message → ALLOW');

// ─── Test 3: Read P3 (internal) → Egress allowed ───
console.log('\n=== Test 3: Internal data → Egress allowed ===');
await shield.sandboxManager.createSandbox('dlp-t3', {});
await shield.inspect({ type:'tool_call', tool:'read_file', args:'/workspace/src/main.js', session_id:'dlp-t3' });
var r3 = await shield.inspect({ type:'tool_call', tool:'send_message', args:'code review', session_id:'dlp-t3' });
check(r3.allowed, 'read P3 + send_message → ALLOW (P3 not sensitive)');

// ─── Test 4: Read P0 → Safe tool allowed ───
console.log('\n=== Test 4: Read P0 → Safe tool (ls) ===');
await shield.sandboxManager.createSandbox('dlp-t4', {});
await shield.inspect({ type:'tool_call', tool:'read_file', args:'/etc/shadow', session_id:'dlp-t4' });
var r4 = await shield.inspect({ type:'tool_call', tool:'terminal', args:'ls -la', session_id:'dlp-t4' });
check(r4.allowed, 'read P0 + ls → ALLOW (ls not egress)');

// ─── Test 5: Read P1 (PII) → Egress blocked ───
console.log('\n=== Test 5: PII data → Egress ===');
await shield.sandboxManager.createSandbox('dlp-t5', {});
await shield.inspect({ type:'tool_call', tool:'read_file', args:'/data/users.csv', session_id:'dlp-t5' });
var r5 = await shield.inspect({ type:'tool_call', tool:'send_message', args:'user list', session_id:'dlp-t5' });
check(!r5.allowed && r5.layer === 'DLP', 'read P1 + send_message → DLP block');

// ─── Test 6: Multiple sensitive reads → Egress blocked ───
console.log('\n=== Test 6: Multiple sensitive reads ===');
await shield.sandboxManager.createSandbox('dlp-t6', {});
await shield.inspect({ type:'tool_call', tool:'read_file', args:'/etc/shadow', session_id:'dlp-t6' });
await shield.inspect({ type:'tool_call', tool:'read_file', args:'/home/user/.ssh/id_rsa', session_id:'dlp-t6' });
var r6 = await shield.inspect({ type:'tool_call', tool:'send_message', args:'keys', session_id:'dlp-t6' });
check(!r6.allowed && r6.layer === 'DLP', 'multiple reads + send_message → DLP block');

// ─── Test 7: Content-based escalation (P4 file with password) ───
console.log('\n=== Test 7: Content-based escalation ===');
await shield.sandboxManager.createSandbox('dlp-t7', {});
await shield.inspect({ type:'tool_call', tool:'read_file', args:'/tmp/notes.txt', content:'DB_PASSWORD=secret', session_id:'dlp-t7' });
var r7 = await shield.inspect({ type:'tool_call', tool:'send_message', args:'notes', session_id:'dlp-t7' });
check(!r7.allowed && r7.layer === 'DLP', 'public file with password content + egress → DLP block');

// ─── Summary ───
console.log('\n' + '='.repeat(50));
console.log('DLP Test Results: ' + passed + '/' + total + ' (' + Math.round(passed/total*100) + '%)');
console.log('='.repeat(50));
