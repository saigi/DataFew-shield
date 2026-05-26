"""
Inventory all security standards/benchmarks for AI Agent safety.
Marks tested vs untested.
"""
import json, os, sys
sys.stdout.reconfigure(encoding='utf-8')

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

standards = [
    # ─── UK / US Government Standards ───
    {
        "name": "AgentHarm (UK AISI)",
        "org": "UK AI Security Institute",
        "type": "Government",
        "items": 176,
        "tested": True,
        "score": "96%",
        "file": os.path.join(BASE, '..', 'agentboard', 'backend', 'ape', 'data', 'external', 'agent_harm.json'),
        "notes": "8 categories: Fraud, Harassment, Drugs, Copyright, Disinformation, Hate, Cybercrime, Sexual",
    },
    {
        "name": "AgentHarm Benign",
        "org": "UK AISI",
        "type": "Government",
        "items": 176,
        "tested": True,
        "score": "~80%",
        "file": os.path.join(BASE, '..', 'agentboard', 'backend', 'ape', 'data', 'external', 'agent_harm_benign.json'),
        "notes": "Paired design, intentionally near-identical to harmful. ~80% is expected.",
    },
    {
        "name": "AgentHarm Chat",
        "org": "UK AISI",
        "type": "Government",
        "items": 44,
        "tested": True,
        "score": "100%",
        "file": os.path.join(BASE, '..', 'agentboard', 'backend', 'ape', 'data', 'external', 'agent_harm_chat.json'),
        "notes": "Chat-specific variants of AgentHarm",
    },

    # ─── OWASP ───
    {
        "name": "OWASP LLM Top 10",
        "org": "OWASP",
        "type": "Industry Standard",
        "items": 30,
        "tested": True,
        "score": "100%",
        "file": "test/test_owasp_top10.mjs",
        "notes": "LLM01-LLM10 all covered. LLM03/04/09 need external systems for complete coverage.",
    },

    # ─── Lakera ───
    {
        "name": "Gandalf Challenge (Levels 1-7)",
        "org": "Lakera",
        "type": "Industry Challenge",
        "items": 26,
        "tested": True,
        "score": "100%",
        "file": "test/test_gandalf_live.mjs",
        "notes": "Known Gandalf bypass techniques all blocked",
    },

    # ─── MITRE ───
    {
        "name": "MITRE ATLAS",
        "org": "MITRE",
        "type": "Government Framework",
        "items": 0,
        "tested": False,
        "score": "—",
        "file": None,
        "notes": "ATT&CK for AI systems. Need to build test cases from the 100+ techniques. RECOMMENDED NEXT.",
    },

    # ─── Garak ───
    {
        "name": "Garak Probes (full)",
        "org": "NVIDIA/Community",
        "type": "Open Source Tool",
        "items": 100,
        "tested": False,
        "score": "—",
        "file": "D:\\PythonLibs\\garak\\probes",
        "notes": "41 probe files, ~100+ techniques. Dependency conflicts block installation. Need to fix or extract manually.",
    },

    # ─── APE Internal ───
    {
        "name": "APE Safety Test Cases",
        "org": "AgentBoard",
        "type": "Internal",
        "items": 16,
        "tested": True,
        "score": "100%",
        "file": os.path.join(BASE, '..', 'agentboard', 'backend', 'ape', 'data', 'safety_test_cases.json'),
        "notes": "Agent-specific safety scenarios",
    },

    # ─── Internal Adversarial ───
    {
        "name": "Internal Adversarial (33 variants)",
        "org": "Datafew",
        "type": "Internal",
        "items": 33,
        "tested": True,
        "score": "91%",
        "file": "test/test_adversarial.mjs",
        "notes": "Jailbreak, encoding, injection, malware, leakage, pretexting, obfuscation",
    },

    # ─── Internal Extra Tests ───
    {
        "name": "Extra Tests (Chinese/Obfuscation)",
        "org": "Datafew",
        "type": "Internal",
        "items": 91,
        "tested": True,
        "score": "95%",
        "file": os.path.join(BASE, 'data', 'extra_tests.json'),
        "notes": "Classical Chinese, dialect, poetry, historical metaphor, code switching, jargon",
    },

    # ─── Tool Commands ───
    {
        "name": "Tool Command Safety",
        "org": "Datafew",
        "type": "Internal",
        "items": 18,
        "tested": True,
        "score": "100%",
        "file": "test/resilient_test.mjs",
        "notes": "rm -rf, dd, mkfs, nc, nmap, curl pipe, crontab...",
    },

    # ─── Bugcrowd / Bounty ───
    {
        "name": "OpenAI Bug Bounty",
        "org": "OpenAI",
        "type": "Bounty Program",
        "items": 0,
        "tested": False,
        "score": "—",
        "file": None,
        "notes": "Need API key ($5). Prompt injection bounty. scripts/bounty_scanner.mjs ready.",
    },
    {
        "name": "Anthropic Bug Bounty",
        "org": "Anthropic",
        "type": "Bounty Program",
        "items": 0,
        "tested": False,
        "score": "—",
        "file": None,
        "notes": "Need API key ($5). scripts/bounty_scanner.mjs compatible.",
    },
]

# Check which standards have test files
for s in standards:
    if s['file'] and os.path.exists(s['file']):
        s['file_ok'] = True
    else:
        s['file_ok'] = s['file'] is None and not s['tested']

print(f'{"=" * 80}')
print(f'AI AGENT SAFETY — STANDARDS & BENCHMARKS INVENTORY')
print(f'{"=" * 80}')
print(f'')
print(f'{"STATUS":8s} {"TYPE":20s} {"ITEMS":6s} {"SCORE":8s} {"NAME":40s}')
print(f'{"-" * 82}')

# Count
total = len(standards)
tested = sum(1 for s in standards if s['tested'])
untested = total - tested
tested_items = sum(s['items'] for s in standards if s['tested'])
avail_items = sum(s['items'] for s in standards)

for s in sorted(standards, key=lambda x: (x['tested'], x['type'])):
    status = '✓ TESTED' if s['tested'] else '○ UNTESTED'
    items = str(s['items']) if s['items'] > 0 else 'N/A'
    score = s['score'] if s['score'] != '—' else '—'
    print(f'{status:8s} {s["type"]:20s} {items:6s} {score:8s} {s["name"]:40s}')
    if s.get('notes'):
        print(f'{"":8s} {"":20s} {"":6s} {"":8s} {s["notes"]:40s}')

print(f'{"-" * 82}')
print(f'')
print(f'Coverage: {tested}/{total} standards tested, {tested_items}+ test cases executed')
print(f'')
print(f'Next steps (by effort):')
print(f'  [1h]  MITRE ATLAS — build test cases from the ATT&CK taxonomy')
print(f'  [2h]  Garak — fix dependencies or extract prompts manually')
print(f'  [1d]  OpenAI Bug Bounty — register API key, run auto-scan, submit findings')
print(f'  [1d]  Anthropic Bug Bounty — same process')
print(f'')
print(f'Recommended: MITRE ATLAS (highest coverage-to-effort ratio)')
