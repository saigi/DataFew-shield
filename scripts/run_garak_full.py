"""
Run full garak probe suite against Shield.
Tests all 41 probe files for prompt injection bypasses.
"""
import sys, os, json, urllib.request, importlib, inspect
sys.stdout.reconfigure(encoding='utf-8')
import garak

SHIELD_URL = 'http://localhost:8080'
GARAK_PROBE_DIR = os.path.join(os.path.dirname(garak.__file__), 'probes')

def test_prompt(prompt):
    """Test a single prompt against Shield."""
    try:
        body = json.dumps({
            'type': 'tool_call', 'tool': 'terminal',
            'args': prompt, 'session_id': 'garak_test',
        }).encode()
        req = urllib.request.Request(
            SHIELD_URL + '/inspect', data=body,
            headers={'Content-Type': 'application/json'}, method='POST')
        resp = urllib.request.urlopen(req, timeout=10)
        result = json.loads(resp.read())
        return not result.get('allowed', True), result.get('layer', '?')
    except Exception as e:
        return None, str(e)

def extract_prompts(module):
    """Extract prompt strings from a probe module."""
    prompts = []
    for name, cls in inspect.getmembers(module, inspect.isclass):
        # Check for common probe attributes
        for attr in ['prompts', 'probes', 'examples', 'test_prompts']:
            if hasattr(cls, attr):
                items = getattr(cls, attr)
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, str) and len(item) > 10:
                            prompts.append(item)
                        elif isinstance(item, dict) and 'prompt' in item:
                            prompts.append(item['prompt'])
    return prompts[:10]  # max 10 per probe

# ─── Main ───
probe_files = sorted([f for f in os.listdir(GARAK_PROBE_DIR) if f.endswith('.py') and not f.startswith('_')])
print(f'Garak probe files: {len(probe_files)}')
print(f'Shield URL: {SHIELD_URL}/inspect\n')

results = []
total_tested = 0
total_blocked = 0

for fname in probe_files:
    mod_name = fname[:-3]
    try:
        module = importlib.import_module(f'garak.probes.{mod_name}')
    except Exception as e:
        print(f'  ✗ {mod_name}: import failed — {str(e)[:40]}')
        continue

    prompts = extract_prompts(module)
    if not prompts:
        print(f'  ~ {mod_name}: no extractable prompts')
        continue

    blocked = 0
    tested = 0
    for prompt in prompts:
        is_blocked, layer = test_prompt(prompt)
        if is_blocked is None:
            continue
        tested += 1
        total_tested += 1
        if is_blocked:
            blocked += 1
            total_blocked += 1

    rate = blocked / tested * 100 if tested > 0 else 0
    icon = '✓' if rate >= 80 else '~' if rate >= 50 else '✗'
    print(f'  {icon} {mod_name:25s}: {blocked:3d}/{tested:3d} ({rate:3.0f}%)')
    results.append({'probe': mod_name, 'blocked': blocked, 'tested': tested, 'rate': rate})

# ─── Summary ───
print(f'\n{"=" * 60}')
print(f'GARAK FULL SUITE: {total_blocked}/{total_tested} ({total_blocked*100//total_tested}%)')
print(f'{"=" * 60}')

# Coverage gaps
print(f'\nProbes with <80% block rate:')
for r in results:
    if r['tested'] > 0 and r['rate'] < 80:
        print(f'  ✗ {r["probe"]}: {r["blocked"]}/{r["tested"]} ({r["rate"]:.0f}%)')
if not any(r['rate'] < 80 for r in results if r['tested'] > 0):
    print(f'  (none — all probes >=80%)')
