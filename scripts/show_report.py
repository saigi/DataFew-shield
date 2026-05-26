import json, sys
sys.stdout.reconfigure(encoding='utf-8')
d = json.loads(open(r'D:\ProgramData\No-Human\datafew-shield\results\test_state.json', 'r', encoding='utf-8').read())
r = d['results']
total = len(r)
passing = sum(1 for x in r if x['correct'])

cats = {}
for x in r:
    c = x.get('cat', '?')
    if c not in cats:
        cats[c] = {'total': 0, 'pass': 0, 'blocked': 0, 'fp': 0, 'fn': 0, 'layers': {}}
    cats[c]['total'] += 1
    cats[c]['blocked'] += 1 if x['blocked'] else 0
    cats[c]['pass'] += 1 if x['correct'] else 0
    if not x['correct']:
        if x['expectedBlock']:
            cats[c]['fn'] += 1
        else:
            cats[c]['fp'] += 1
    l = x.get('layer', '?')
    cats[c]['layers'][l] = cats[c]['layers'].get(l, 0) + 1

print('=' * 75)
print(f'DATAFEW SHIELD — FINAL TEST REPORT (505 cases)')
print(f'Overall: {passing}/{total} ({passing * 100 // total}%)')
print('=' * 75)

# Sort by pass rate ascending (worst first)
sorted_cats = sorted(cats.items(), key=lambda kv: kv[1]['pass'] / kv[1]['total'])
for c, s in sorted_cats:
    pct = s['pass'] * 100 // s['total']
    bpct = s['blocked'] * 100 // s['total']
    icon = '✓' if pct >= 90 else '~' if pct >= 50 else '✗'
    layers_sorted = sorted(s['layers'].items(), key=lambda x: -x[1])[:3]
    lay = ', '.join(f'{l}={n}' for l, n in layers_sorted)
    print(f'  {icon} {c:35s} {s["pass"]:3d}/{s["total"]:3d} ({pct:2d}%) block={bpct:2d}% | {lay}')

total_fp = sum(c['fp'] for c in cats.values())
total_fn = sum(c['fn'] for c in cats.values())
print(f'\nFalse positives (benign blocked): {total_fp}')
print(f'False negatives (attacks missed): {total_fn}')

fp_list = [(x['cat'], x['layer'], x['text'][:50]) for x in r if not x['correct'] and not x['expectedBlock']]
fn_list = [(x['cat'], x['layer'], x['text'][:50]) for x in r if not x['correct'] and x['expectedBlock']]

print(f'\nFirst 5 FPs:')
for c, l, t in fp_list[:5]:
    print(f'  L={l:12s} [{c:20s}] {t}')

print(f'\nFirst 5 FNs:')
for c, l, t in fn_list[:5]:
    print(f'  L={l:12s} [{c:20s}] {t}')

# Summary
print(f'\n{"=" * 75}')
print(f'LAYER SUMMARY')
print(f'=' * 75)
layers = {}
for x in r:
    l = x.get('layer', '?')
    if l not in layers:
        layers[l] = {'total': 0, 'blocked': 0}
    layers[l]['total'] += 1
    if x['blocked']:
        layers[l]['blocked'] += 1
for l, s in sorted(layers.items(), key=lambda kv: -kv[1]['blocked']):
    print(f'  {l:12s}: blocked {s["blocked"]:4d}/{s["total"]:4d}')
