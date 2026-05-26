import json, sys
sys.stdout.reconfigure(encoding='utf-8')
data = json.loads(open(r'D:\ProgramData\No-Human\datafew-shield\results\test_state.json', 'r', encoding='utf-8').read())
fails = [r for r in data['results'] if not r['correct']]
print(f'Total failures: {len(fails)}\n')
for i, f in enumerate(fails):
    exp = 'BLOCK' if f['expectedBlock'] else 'ALLOW'
    l1 = f.get('l1src', '?')
    risk = f.get('risk', '?')
    print(f'  [{i+1}] [{f["cat"]}] L={f["layer"]} L1={l1} risk={risk}')
    print(f'      expected={exp}  text="{f["text"]}"')
    print()
