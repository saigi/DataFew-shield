import json, sys
sys.stdout.reconfigure(encoding='utf-8')

# AgentHarm
for name in ['agent_harm.json', 'agent_harm_benign.json', 'agent_harm_chat.json']:
    path = fr'D:\ProgramData\No-Human\agentboard\backend\ape\data\external\{name}'
    try:
        data = json.loads(open(path, 'r', encoding='utf-8-sig').read())
        behaviors = data.get('behaviors', []) if isinstance(data, dict) else data
        print(f'{name}: {len(behaviors)} items', end='')
        if isinstance(data, dict) and 'categories' in data:
            print(f'  categories={data["categories"]}', end='')
        print()
    except Exception as e:
        print(f'{name}: ERROR {e}')

# extra_tests
extra = json.loads(open(r'D:\ProgramData\No-Human\datafew-shield\data\extra_tests.json', 'r', encoding='utf-8').read())
print(f'\nextra_tests.json:')
for k in extra:
    items = extra[k]
    cats = {}
    for item in items:
        cat = item.get('cat', '?').split(':')[0]
        cats[cat] = cats.get(cat, 0) + 1
    print(f'  {k}: {len(items)} items across {len(cats)} categories')
    for c, n in sorted(cats.items(), key=lambda x: -x[1]):
        print(f'    {c}: {n}')
