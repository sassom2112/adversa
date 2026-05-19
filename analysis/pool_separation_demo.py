"""
pool_separation_demo.py — Discriminative signal extraction demo

Demonstrates set-theoretic pool separation:
    discriminative_signals = field_values(attack_pool) - field_values(benign_pool)

Shows what the improved architecture would produce and validates how many of the
current 83 signals in operational_rules.json would survive the filter.

IMPORTANT CAVEAT documented in output:
    The current benign pool is 7 synthetic BENIGN_TEMPLATES in mordor_agent.py.
    This is NOT a real benign baseline (BETH would have ~1M events).
    Results show the methodology; the guarantee is only as strong as the benign pool.

Reads: datasets/, reports/operational_rules.json, custom-agent/mordor_agent.py
Writes: analysis/pool_separation_demo.md
"""
import json
import os
import sys
from datetime import datetime, timezone

_ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
sys.path.insert(0, os.path.join(_ROOT, 'custom-agent'))

_OPS  = os.path.join(_ROOT, 'reports', 'operational_rules.json')
_OUT  = os.path.join(_ROOT, 'analysis', 'pool_separation_demo.md')

# ── Load Mordor attack events ─────────────────────────────────────────────────
print("Loading Mordor attack events...")
from mordor_agent import MordorRedAgent, BENIGN_TEMPLATES, DATASET_MAP

agent = MordorRedAgent(project_root=_ROOT)

# ── Load operational_rules.json (83 clean signals) ───────────────────────────
with open(_OPS) as f:
    ops = json.load(f)
current_signals = {
    tid: set(data['signals'])
    for tid, data in ops['rules'].items()
}
total_current = sum(len(s) for s in current_signals.values())
print(f"Loaded {total_current} current signals across {len(current_signals)} techniques")

# ── Extract benign pool values ────────────────────────────────────────────────
def extract_values(event_dict, min_len=4):
    """Extract all string field values from an event dict."""
    values = set()
    for v in event_dict.values():
        if isinstance(v, str) and len(v) >= min_len:
            values.add(v.lower().strip())
            # Also add path components for file paths
            if '\\' in v:
                for part in v.lower().split('\\'):
                    if len(part) >= min_len:
                        values.add(part)
    return values

benign_values = set()
for template in BENIGN_TEMPLATES:
    benign_values |= extract_values(template)

print(f"\nBenign pool: {len(BENIGN_TEMPLATES)} synthetic templates → {len(benign_values)} unique values")
print("  ⚠️  CAVEAT: benign pool is synthetic. Real BETH baseline would have ~1M+ events.")

# ── Extract attack pool values per technique ──────────────────────────────────
print("\nExtracting attack field values per technique...")
attack_values = {}
for tid, events in agent.events.items():
    vals = set()
    for event in events:
        vals |= extract_values(event)
    attack_values[tid] = vals
    print(f"  {tid}: {len(events)} events → {len(vals)} unique values")

# ── Discriminative extraction ─────────────────────────────────────────────────
print("\nComputing discriminative signals (attack - benign)...")
discriminative = {}
for tid in attack_values:
    discriminative[tid] = attack_values[tid] - benign_values

# ── Validate current signals against discriminative set ──────────────────────
print("\nValidating current operational_rules.json signals...")

results = {}
for tid, signals in current_signals.items():
    disc = discriminative.get(tid, set())
    surviving   = set()
    fp_risk     = set()
    not_in_mordor = set()

    for sig in signals:
        sig_lower = sig.lower()
        # Check if this signal value appears in the benign pool
        in_benign = any(sig_lower in bv or bv in sig_lower
                        for bv in benign_values if len(bv) >= 4)
        # Check if it appears in the attack pool
        in_attack = any(sig_lower in av or av in sig_lower
                        for av in attack_values.get(tid, set()))

        if in_benign:
            fp_risk.add(sig)
        elif in_attack:
            surviving.add(sig)
        else:
            not_in_mordor.add(sig)  # likely nromanoff-specific or synthetic

    results[tid] = {
        'total': len(signals),
        'surviving': surviving,
        'fp_risk': fp_risk,
        'not_in_mordor': not_in_mordor,
    }

# ── Write report ──────────────────────────────────────────────────────────────
lines = []
lines.append("# Pool Separation Demo — Discriminative Signal Extraction")
lines.append(f"\n**Source:** Mordor attack datasets + BENIGN_TEMPLATES in mordor_agent.py  ")
lines.append(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}  ")
lines.append(f"**Current signals evaluated:** {total_current} (from operational_rules.json)  ")

lines.append("""
## Methodology

For each MITRE technique:
1. Extract all string field values from every Mordor attack event (attack pool).
2. Extract all string field values from BENIGN_TEMPLATES (benign pool).
3. Compute: `discriminative = attack_pool_values - benign_pool_values`
4. Classify each current signal as:
   - **Surviving** — present in attack pool, absent from benign pool (safe to use)
   - **FP risk** — present in benign pool (would fire on benign events)
   - **Not in Mordor** — not found in either pool (campaign-specific IOC or synthetic)
""")

lines.append("""
> **Caveat on benign pool strength:**
> The current benign pool contains 7 synthetic Windows event templates.
> A production-grade filter requires a real baseline (e.g., BETH dataset, ~1M events).
> Results below demonstrate the *methodology* and structural approach.
> FP-risk classifications may be underestimated due to the thin benign baseline.
""")

lines.append("---\n")

total_surviving = total_fp_risk = total_not_mordor = 0

for tid, r in sorted(results.items()):
    bp_name = ops['rules'].get(tid, {}).get('name', tid)
    lines.append(f"## {tid} — {bp_name}\n")
    lines.append(f"| Category | Count | % of signals |")
    lines.append(f"|----------|-------|--------------|")
    lines.append(f"| Surviving (discriminative) | {len(r['surviving'])} | "
                 f"{len(r['surviving'])/r['total']*100:.0f}% |")
    lines.append(f"| FP risk (in benign pool) | {len(r['fp_risk'])} | "
                 f"{len(r['fp_risk'])/r['total']*100:.0f}% |")
    lines.append(f"| Campaign-specific / not in Mordor | {len(r['not_in_mordor'])} | "
                 f"{len(r['not_in_mordor'])/r['total']*100:.0f}% |")
    lines.append("")

    if r['surviving']:
        lines.append("**Surviving signals (safe):**")
        for s in sorted(r['surviving'])[:10]:
            lines.append(f"- `{s}`")
        if len(r['surviving']) > 10:
            lines.append(f"- ... and {len(r['surviving'])-10} more")
        lines.append("")

    if r['fp_risk']:
        lines.append("**FP-risk signals (appear in benign pool):**")
        for s in sorted(r['fp_risk'])[:5]:
            lines.append(f"- `{s}`")
        lines.append("")

    if r['not_in_mordor']:
        lines.append("**Campaign-specific (not in Mordor — likely nromanoff IOCs):**")
        for s in sorted(r['not_in_mordor'])[:5]:
            lines.append(f"- `{s}`")
        lines.append("")

    lines.append("---\n")
    total_surviving  += len(r['surviving'])
    total_fp_risk    += len(r['fp_risk'])
    total_not_mordor += len(r['not_in_mordor'])

# ── Summary table ─────────────────────────────────────────────────────────────
lines.append("## Summary\n")
lines.append("| | Count | % |")
lines.append("|---|---|---|")
lines.append(f"| Total current signals | {total_current} | 100% |")
lines.append(f"| Would survive pool filter | {total_surviving} | "
             f"{total_surviving/total_current*100:.0f}% |")
lines.append(f"| FP risk (in benign pool) | {total_fp_risk} | "
             f"{total_fp_risk/total_current*100:.0f}% |")
lines.append(f"| Campaign-specific IOCs | {total_not_mordor} | "
             f"{total_not_mordor/total_current*100:.0f}% |")

lines.append("""
## Architectural Implication

Signals in the **surviving** category are discriminative by construction:
they appear in documented attack telemetry and are absent from the benign baseline.
No hallucination possible at extraction — the value is present in real Sysmon data.

Signals in the **campaign-specific** category are the generalization gap:
they detect the nromanoff/Mordor campaigns specifically, not the technique generally.
A new campaign with different tooling would produce zero hits from these signals.

The **production fix** is pool separation against a real benign baseline (BETH):
    discriminative_signals = field_values(Mordor[T]) - field_values(BETH)
This makes false signal introduction structurally impossible and campaign-specific
IOCs identifiable at training time, not after deployment.
""")

report = "\n".join(lines)
with open(_OUT, 'w') as f:
    f.write(report)

print(f"\nReport written to {_OUT}")
print(f"\nSummary:")
print(f"  Surviving (discriminative): {total_surviving}/{total_current} "
      f"({total_surviving/total_current*100:.0f}%)")
print(f"  FP risk:                    {total_fp_risk}/{total_current} "
      f"({total_fp_risk/total_current*100:.0f}%)")
print(f"  Campaign-specific:          {total_not_mordor}/{total_current} "
      f"({total_not_mordor/total_current*100:.0f}%)")
