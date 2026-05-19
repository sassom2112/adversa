"""
Migrates brain_state.json from the corrupted 7,000+ iteration state
back to the clean 3,000-iteration operational_rules.json baseline.

Preserves: signals, weights, and technique names from operational_rules.json.
Clears:    history, metrics, red_evasions (contaminated by broken training).
Sets:      iteration to 3000 (continuing from clean checkpoint).
"""
import json
import os

_PROJECT_ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
_REPORTS = os.path.join(_PROJECT_ROOT, 'reports')

with open(os.path.join(_REPORTS, 'operational_rules.json')) as f:
    ops = json.load(f)

rules = ops['rules']
techniques = list(rules.keys())

blue_patterns = {}
for tid, data in rules.items():
    blue_patterns[tid] = {
        'name': data['name'],
        'signals': list(data['signals']),
        'weight': data['weight'],
    }

clean_state = {
    'iteration': 3000,
    'blue_patterns': blue_patterns,
    'red_evasions': {},
    'history': [],
    'metrics': {
        'iterations': [],
        'blue_scores': [],
        'detection_flags': [],
        'red_generations': [],
        'blue_pattern_counts': [],
        'weights': {t: [] for t in techniques},
    }
}

out_path = os.path.join(_REPORTS, 'brain_state.json')
with open(out_path, 'w') as f:
    json.dump(clean_state, f, indent=2)

print(f"Clean brain_state.json written.")
print(f"  Iteration:  {clean_state['iteration']}")
print(f"  Techniques: {len(blue_patterns)}")
total_signals = sum(len(d['signals']) for d in blue_patterns.values())
print(f"  Signals:    {total_signals}")
for tid, d in blue_patterns.items():
    print(f"    {tid}  weight={d['weight']}  signals={len(d['signals'])}")
