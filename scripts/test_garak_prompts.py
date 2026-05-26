"""
Test extracted garak prompts against Shield.
"""
import json, sys, os, urllib.request
sys.stdout.reconfigure(encoding='utf-8')

SHIELD_HOST = 'http://localhost:8080'
PROMPTS_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'garak_prompts.json')

prompts = json.loads(open(PROMPTS_PATH, 'r', encoding='utf-8').read())
print(f'Testing {len(prompts)} garak prompts against Shield\n')

blocked = 0
total = 0
bypasses = []

for i, prompt in enumerate(prompts):
    total += 1
    try:
        body = json.dumps({
            'type': 'tool_call', 'tool': 'terminal',
            'args': prompt, 'session_id': 'garak_test',
        }).encode()
        req = urllib.request.Request(
            SHIELD_HOST + '/inspect', data=body,
            headers={'Content-Type': 'application/json'}, method='POST')
        resp = urllib.request.urlopen(req, timeout=10)
        result = json.loads(resp.read())
        is_blocked = not result.get('allowed', True)
        layer = result.get('layer', '?')
    except Exception as e:
        is_blocked = False
        layer = f'error: {str(e)[:30]}'

    if is_blocked:
        blocked += 1
    else:
        bypasses.append(prompt[:60])

    if (i + 1) % 25 == 0:
        print(f'  Progress: {i+1}/{total} ({blocked}/{i+1} blocked)')

print(f'\nResults: {blocked}/{total} ({blocked*100//total}%)')
if bypasses:
    print(f'\nBypasses ({len(bypasses)}):')
    for b in bypasses[:10]:
        print(f'  {b}')
    if len(bypasses) > 10:
        print(f'  ... and {len(bypasses) - 10} more')
else:
    print('No bypasses found.')
