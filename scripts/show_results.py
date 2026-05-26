import json, sys
sys.stdout.reconfigure(encoding='utf-8')

refs = json.loads(open(r'D:\ProgramData\No-Human\datafew-shield\data\embedding_refs.json', 'r', encoding='utf-8').read())
data = json.loads(open(r'D:\ProgramData\No-Human\datafew-shield\data\test_embeddings.json', 'r', encoding='utf-8').read())

print('Threshold:', data['threshold'])
print()
for r in sorted(data['results'], key=lambda x: x['score'], reverse=True):
    icon = '+' if r['ok'] else '-'
    print(f"  {icon} score={r['score']:.3f} pred={r['predicted']} exp={r['expected']} | {r['text'][:50]}")

print(f"\nAccuracy: {data['correct']}/{data['total']} ({data['accuracy']}%)")
