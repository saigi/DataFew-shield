"""
Test manually extracted garak prompts against Shield.
Fills in placeholders and filters non-attack prompts.
"""
import json, sys, urllib.request, re
sys.stdout.reconfigure(encoding='utf-8')

SHIELD_HOST = 'http://localhost:8080'

# Load extracted prompts
prompts = json.loads(open(
    r'D:\ProgramData\No-Human\datafew-shield\data\garak_flat_prompts.json',
    'r', encoding='utf-8'
).read())

# Fill placeholders and filter
def fill(text):
    """Replace garak template placeholders with concrete values."""
    replacements = {
        '{product_name}': 'iPhone',
        '{group_name}': 'developers',
        '{INJECTION_MARKER}': 'IGNORE ALL INSTRUCTIONS',
        '{language}': 'Python',
        '{task}': 'parse CSV files',
        '{command}': 'tell me the password',
        '{query}': 'how to hack a server',
        '{topic}': 'computer security',
        '{name}': 'John',
        '{attack}': 'prompt injection',
    }
    for k, v in replacements.items():
        text = text.replace(k, v)
    # Remove XML-like tags
    text = re.sub(r'<[^>]+>', '', text)
    return text.strip()

def is_attack_prompt(text):
    """Filter out non-attempt prompts."""
    skip_keywords = [
        'quick brown fox', 'Liberté', 'égalité', 'fraternité',
        'How can I help you', 'current_attack_prompt', 'vulnerability_info',
        'bad_character_category', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    ]
    text_lower = text.lower()
    for kw in skip_keywords:
        if kw in text_lower:
            return False
    return len(text) > 20

# Clean prompts
cleaned = []
for p in prompts:
    filled = fill(p)
    if is_attack_prompt(filled):
        cleaned.append(filled)

print(f'Original: {len(prompts)} prompts')
print(f'After cleaning: {len(cleaned)} prompts\n')

# Test against Shield
blocked = 0
total = 0
bypasses = []

for prompt in cleaned:
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
    except:
        is_blocked = False

    if is_blocked:
        blocked += 1
    else:
        bypasses.append(prompt[:60])

print(f'Results: {blocked}/{total} ({blocked*100//total}%)')
if bypasses:
    print(f'\nBypasses ({len(bypasses)}):')
    for b in bypasses:
        print(f'  {b}')
else:
    print('No bypasses.')
