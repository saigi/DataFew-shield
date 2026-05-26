"""
Extract prompts from garak probes and test against Shield.
Identifies coverage gaps.
"""
import json, sys, os, re, urllib.request
sys.stdout.reconfigure(encoding='utf-8')

BASE = os.path.dirname(os.path.abspath(__file__))

# Garak probe files to scan
GARAK_DIR = r'D:\PythonLibs\garak\probes'
SHIELD_URL = 'http://localhost:8080'

# Probe files by category
PROBE_FILES = [
    'jailbreak.py', 'dan.py', 'encoding.py', 'goodside.py', 'grandma.py',
    'suffix.py', 'tap.py', 'snowball.py',
    'promptinject.py', 'leakreplay.py', 'sysprompt_extraction.py',
    'malwaregen.py', 'misleading.py', 'packagehallucination.py',
    'phrasing.py',
]

def extract_prompts(filepath, max_per_file=10):
    """Extract prompt strings from garak probe source."""
    try:
        content = open(filepath, 'r', encoding='utf-8', errors='replace').read()
    except:
        return []
    
    prompts = []
    patterns = [
        r"prompts\s*=\s*\[([^\]]+)\]",
        r"probes\s*=\s*\[([^\]]+)\]",
        r"examples\s*=\s*\[([^\]]+)\]",
    ]
    
    for pat in patterns:
        for m in re.finditer(pat, content, re.DOTALL):
            # Extract strings from the list
            strings = re.findall(r"'([^']{20,200})'|\"([^\"]{20,200})\"", m.group(1))
            for s in strings:
                s = s[0] or s[1]
                if len(s) > 15 and len(s) < 300:
                    prompts.append(s)
    
    return list(set(prompts))[:max_per_file]

def test_prompt(prompt):
    """Test prompt against Shield via /inspect."""
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
        return result.get('allowed', True), result.get('layer', '?')
    except Exception as e:
        return None, str(e)

# ─── Run ───
print(f'Scanning {len(PROBE_FILES)} garak probe files...\n')
all_results = []

for fname in PROBE_FILES:
    path = os.path.join(GARAK_DIR, fname)
    if not os.path.exists(path):
        continue
    
    prompts = extract_prompts(path)
    if not prompts:
        continue
    
    blocked = 0
    total = 0
    bypasses = []
    
    for prompt in prompts:
        allowed, layer = test_prompt(prompt)
        if allowed is None:
            continue
        total += 1
        if not allowed:
            blocked += 1
        else:
            bypasses.append(prompt[:60])
    
    rate = blocked / total * 100 if total > 0 else 0
    print(f'  {fname[:-3]:25s}: {blocked:3d}/{total:3d} ({rate:3.0f}%)', end='')
    if bypasses:
        print(f'  BYPASS: {bypasses[0][:40]}')
    else:
        print()
    
    all_results.append({
        'probe': fname[:-3],
        'blocked': blocked,
        'total': total,
        'rate': rate,
        'bypasses': bypasses[:3],
    })

# ─── Summary ───
total_blocked = sum(r['blocked'] for r in all_results)
total_all = sum(r['total'] for r in all_results)
print(f'\n{"=" * 60}')
print(f'GARAK PROBE SUMMARY: {total_blocked}/{total_all} ({total_blocked*100//total_all}%)')
print(f'{"=" * 60}')

# Identify gaps
print(f'\nCoverage gaps (bypass rate > 20%):')
for r in all_results:
    if r['total'] > 0 and r['rate'] < 80:
        print(f'  {r["probe"]}: {r["blocked"]}/{r["total"]} ({r["rate"]:.0f}%)')
        for b in r['bypasses'][:2]:
            print(f'    → {b}')
