"""
Manual extraction of garak probe prompts.
Reads source files directly, finds prompt list definitions.
No garak dependencies needed.
"""
import os, sys, re, json
sys.stdout.reconfigure(encoding='utf-8')

garak_dir = r'D:\PythonLibs\garak\probes'
output_dir = os.path.dirname(__file__)

def extract_prompts_from_file(filepath, max_prompts=15):
    """Read a garak probe .py file and extract prompt strings."""
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()

    prompts = []

    # Pattern 1: Class-level prompt lists
    # garak probes define prompts as class attributes:
    #   prompts = ["text1", "text2"]
    #   probes = ["text1", "text2"]
    #   examples = [("text", "category"), ...]
    #   prompt = "text"
    for pat in [
        r'prompts\s*=\s*\[([^\]]+)\]',
        r'probes\s*=\s*\[([^\]]+)\]',
        r'examples\s*=\s*\[([^\]]+)\]',
        r'prompt\s*=\s*["\']([^"\']+)["\']',
    ]:
        for m in re.finditer(pat, content, re.DOTALL):
            block = m.group(1)
            # Extract strings from the list
            strings = re.findall(r"""['"]([^'"]{15,300})['"]""", block)
            for s in strings:
                if (len(s) > 15 and len(s) < 300 
                    and not s.startswith('http') and not s.startswith('/')
                    and 'import ' not in s and 'def ' not in s):
                    prompts.append(s)

    # Pattern 2: Tuple-style examples: ("prompt", "category")
    for m in re.finditer(r"""\(\s*['"]([^'"]{15,300})['"]\s*,\s*['"]""", content):
        s = m.group(1)
        if len(s) > 15 and len(s) < 300:
            prompts.append(s)

    # De-duplicate while preserving order
    seen = set()
    unique = []
    for p in prompts:
        if p not in seen:
            seen.add(p)
            unique.append(p)

    return unique[:max_prompts]

# ─── Process all probe files ───
results = {}
total_prompts = 0

for fname in sorted(os.listdir(garak_dir)):
    if not fname.endswith('.py') or fname.startswith('_'):
        continue
    path = os.path.join(garak_dir, fname)
    prompts = extract_prompts_from_file(path)
    if prompts:
        results[fname[:-3]] = prompts
        total_prompts += len(prompts)
        print(f'  {fname:30s}: {len(prompts)} prompts')
        for p in prompts[:2]:
            print(f'    → {p[:60]}')

print(f'\nTotal: {total_prompts} prompts from {len(results)} probes')

# Save
output = {
    'source': 'garak_probes_via_manual_extraction',
    'total_probes': len(results),
    'total_prompts': total_prompts,
    'by_probe': results,
}
path = os.path.join(output_dir, '..', 'data', 'garak_prompts_manual.json')
json.dump(output, open(path, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
print(f'Saved to {path}')

# Also save flat list for testing
flat = []
for probe, prompts in results.items():
    for p in prompts:
        flat.append(p)
flat_path = os.path.join(output_dir, '..', 'data', 'garak_flat_prompts.json')
json.dump(flat, open(flat_path, 'w', encoding='utf-8'), ensure_ascii=False)
print(f'Flat list: {len(flat)} prompts -> {flat_path}')
