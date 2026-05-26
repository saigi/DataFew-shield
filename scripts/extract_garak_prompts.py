"""
Extract prompts from garak probe source files via regex.
Does not require garak runtime — just parses .py source files.
"""
import os, re, sys, json
sys.stdout.reconfigure(encoding='utf-8')

garak_dir = r'D:\PythonLibs\garak\probes'
output_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'garak_prompts.json')

total_prompts = 0
all_prompts = []

for fname in sorted(os.listdir(garak_dir)):
    if not fname.endswith('.py') or fname.startswith('_'):
        continue
    path = os.path.join(garak_dir, fname)
    content = open(path, 'r', encoding='utf-8', errors='replace').read()

    # Find string literals in probe class definitions
    prompts = re.findall(r"""['"]([A-Z][a-zA-Z0-9\s\.,;:!?'\-]{20,300})['"]""", content)
    # Filter
    valid = []
    for p in prompts:
        if (not p.startswith('http') and not p.startswith('/') 
            and 'import' not in p and 'def ' not in p 
            and 'class ' not in p and len(p) > 25
            and not p.startswith('The ') and not p.startswith('This ')):
            valid.append(p)

    if valid:
        print(f'{fname:30s}: {len(valid)} prompts')
        total_prompts += len(valid)
        all_prompts.extend(valid[:5])  # max 5 per probe

print(f'\nTotal: {total_prompts} prompts from garak source')
print(f'Selected: {len(all_prompts)} for testing')

json.dump(all_prompts, open(output_path, 'w', encoding='utf-8'))
print(f'Saved to {output_path}')
