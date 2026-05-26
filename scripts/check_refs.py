import json
refs = json.loads(open(r'D:\ProgramData\No-Human\datafew-shield\data\embedding_refs.json', 'r', encoding='utf-8').read())
print(f'Harmful: {refs["harmful"]["count"]}')
print(f'Safe: {refs["safe"]["count"]}')
print(f'LR threshold: {refs["benchmark"].get("lr_threshold", "?")}')
print(f'LR accuracy: {refs["benchmark"].get("lr_accuracy", "?")}')

# Check if git pull is in safe metadata
for m in refs['safe'].get('metadata', []):
    if isinstance(m, dict) and 'git pull' in m.get('name', ''):
        print(f'Found in safe refs: {m["name"]}')
        break
else:
    print('git pull NOT in safe refs')
