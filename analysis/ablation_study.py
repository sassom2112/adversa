#!/usr/bin/env python3
"""
Ablation study: IOC-only vs ASL-only vs Combined, with 80/20 holdout split.

Three scoring conditions run over the same 20%-holdout Mordor events:
  combined  — current system (conjunction scoring + protected-signal half-weight)
  ioc_only  — only PROTECTED_SIGNALS count; single match → full weight
  asl_only  — all learned signals, NO protected status; strict conjunction (2+ required)

Output: reports/ablation_study.json
Source of truth for paper section on out-of-sample detection and signal ablation.
"""

import json
import os
import sys
from datetime import datetime, timezone

# ── Paths ─────────────────────────────────────────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.normpath(os.path.join(_HERE, '..'))
REPORTS_DIR = os.path.join(PROJECT_ROOT, 'reports')

# Import BENIGN_TEMPLATES from mordor_agent.py (read-only, no side effects)
sys.path.insert(0, os.path.join(PROJECT_ROOT, 'custom-agent'))
from mordor_agent import BENIGN_TEMPLATES, DATASET_MAP

# ── PROTECTED_SIGNALS (copied verbatim from brain.py) ─────────────────────────
PROTECTED_SIGNALS = [
    'psexesvc', 'psexec', 'mimikatz', 'hydrakatz',
    'lsass', '0x1fffff', 'dllhost\\\\svchost',
    '12.190.135.235', '199.73.28.114', 'winclient',
    'sekurlsa', 'spinlock', 'system4.rar',
    'eventid=7045', 'sc.exe create', '\\admin$\\',
    'invoke-expression', 'powershell -enc',
    'fodhelper', 'net user /domain', 'samr',
    'record_mic', 'audiocapture',
]

DETECTION_THRESHOLD = 40  # matches brain.py run()


# ── Event formatting (mirror of mordor_agent.MordorRedAgent._format_event) ────
def format_event(event):
    parts = []
    event_id = event.get('EventID', 0)

    if event_id == 1:
        if event.get('Image'):        parts.append(f"Process={event['Image']}")
        if event.get('CommandLine'):  parts.append(f"CommandLine={event['CommandLine'][:100]}")
        if event.get('ParentImage'):  parts.append(f"Parent={event['ParentImage']}")
        if event.get('AccountName'): parts.append(f"User={event['AccountName']}")
    elif event_id == 10:
        if event.get('SourceImage'):  parts.append(f"Source={event['SourceImage']}")
        if event.get('TargetImage'):  parts.append(f"Target={event['TargetImage']}")
        if event.get('GrantedAccess'):parts.append(f"Access={event['GrantedAccess']}")
        if event.get('CallTrace'):    parts.append(f"CallTrace={event['CallTrace'][:100]}")
    elif event_id == 13:
        if event.get('TargetObject'): parts.append(f"Registry={event['TargetObject']}")
        if event.get('Details'):      parts.append(f"Value={event['Details'][:100]}")
        if event.get('EventType'):    parts.append(f"Type={event['EventType']}")
    elif event_id == 3:
        if event.get('Image'):        parts.append(f"Process={event['Image']}")
        if event.get('DestinationIp'):parts.append(f"DestIP={event['DestinationIp']}")
        if event.get('DestinationPort'):parts.append(f"DestPort={event['DestinationPort']}")
    elif event_id == 11:
        if event.get('TargetFilename'):parts.append(f"File={event['TargetFilename']}")
        if event.get('Image'):        parts.append(f"Process={event['Image']}")
    elif event_id == 8:
        if event.get('SourceImage'):  parts.append(f"Source={event['SourceImage']}")
        if event.get('TargetImage'):  parts.append(f"Target={event['TargetImage']}")
        if event.get('StartAddress'): parts.append(f"StartAddr={event['StartAddress']}")
    elif event_id in (4103, 800):
        if event.get('ScriptBlockText'):parts.append(f"ScriptBlock={event['ScriptBlockText'][:120]}")
        if event.get('CommandLine'):  parts.append(f"CommandLine={event['CommandLine'][:100]}")
        if event.get('Image'):        parts.append(f"Process={event['Image']}")
    elif event.get('CommandLine'):
        parts.append(f"CommandLine={event['CommandLine'][:100]}")
        if event.get('Image'):        parts.append(f"Process={event['Image']}")
        if event.get('ParentImage'):  parts.append(f"Parent={event['ParentImage']}")
    else:
        for key in ['Image', 'TargetObject', 'TargetImage', 'CommandLine', 'Details', 'DestinationIp']:
            if event.get(key):
                parts.append(f"{key}={str(event[key])[:80]}")

    parts.append(f"EventID={event_id}")
    if event.get('Hostname'):
        parts.append(f"Host={event['Hostname']}")

    return " | ".join(parts) if parts else str(event)[:200]


# ── Scoring engine ─────────────────────────────────────────────────────────────
def score_event(text, rules, condition):
    """
    Score a formatted artifact string under one condition.

    combined : 2+ signals → full weight; 1 protected → half weight; 1 generic → 0
    ioc_only : only signals present in PROTECTED_SIGNALS; single hit → full weight
    asl_only : all learned signals; strict conjunction — 2+ required, single → 0
    """
    text_norm = text.lower().replace('\\\\', '\\')
    total = 0
    matched = {}

    for tid, rule in rules.items():
        signals = rule['signals']
        weight  = rule['weight']

        if condition == 'ioc_only':
            ioc_sigs = [s for s in signals
                        if any(p.lower() in s.lower() for p in PROTECTED_SIGNALS)]
            hits = [s for s in ioc_sigs
                    if s.lower().replace('\\\\', '\\') in text_norm]
            if hits:
                total += weight
                matched[tid] = hits

        elif condition == 'asl_only':
            hits = [s for s in signals
                    if s.lower().replace('\\\\', '\\') in text_norm]
            if len(hits) >= 2:
                total += weight
                matched[tid] = hits
            # single hit → 0, no protected boost

        else:  # combined (current system)
            hits = [s for s in signals
                    if s.lower().replace('\\\\', '\\') in text_norm]
            if not hits:
                continue
            if len(hits) >= 2:
                w = weight
            else:
                is_prot = any(p.lower() in hits[0].lower() for p in PROTECTED_SIGNALS)
                w = weight // 2 if is_prot else 0
            if w > 0:
                total += w
                matched[tid] = hits

    return total, matched


# ── Evaluation ─────────────────────────────────────────────────────────────────
def has_any_signal(text, rules):
    """True if ANY signal from ANY technique matches the formatted artifact."""
    t = text.lower().replace('\\\\', '\\')
    for rule in rules.values():
        for s in rule['signals']:
            if s.lower().replace('\\\\', '\\') in t:
                return True
    return False


def evaluate(events_by_technique, benign_pool, rules, condition):
    tp = fp = fn = tn = 0
    any_signal_count = 0     # events where at least one signal fires (pre-threshold)
    per_technique = {}

    for tid, events in events_by_technique.items():
        t_tp = t_fn = 0
        for ev in events:
            artifact = format_event(ev)
            if has_any_signal(artifact, rules):
                any_signal_count += 1
            score, _ = score_event(artifact, rules, condition)
            if score >= DETECTION_THRESHOLD:
                t_tp += 1; tp += 1
            else:
                t_fn += 1; fn += 1
        n = len(events)
        per_technique[tid] = {
            'detected': t_tp,
            'missed':   t_fn,
            'total':    n,
            'detection_rate': round(t_tp / n, 3) if n else 0,
        }

    for ev in benign_pool:
        artifact = format_event(ev)
        score, _ = score_event(artifact, rules, condition)
        if score >= DETECTION_THRESHOLD:
            fp += 1
        else:
            tn += 1

    total_attack  = tp + fn
    total_benign  = fp + tn
    precision = tp / (tp + fp)  if (tp + fp)  > 0 else 0.0
    recall    = tp / total_attack if total_attack > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) > 0 else 0.0)
    fp_rate   = fp / total_benign if total_benign > 0 else 0.0
    # signal_presence: fraction of attack events that matched at least one signal
    signal_presence = any_signal_count / total_attack if total_attack > 0 else 0.0

    return {
        'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
        'total_attack':    total_attack,
        'total_benign':    total_benign,
        'signal_presence': round(signal_presence, 3),
        'detection_rate':  round(recall,    3),
        'precision':       round(precision, 3),
        'f1':              round(f1,        3),
        'fp_rate':         round(fp_rate,   3),
        'per_technique':   per_technique,
    }


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    # Load operational rules
    rules_path = os.path.join(REPORTS_DIR, 'operational_rules.json')
    with open(rules_path) as f:
        rules_data = json.load(f)
    rules = rules_data['rules']
    total_signals = sum(len(r['signals']) for r in rules.values())
    print(f"Rules loaded: {len(rules)} techniques, {total_signals} signals")

    # Load Mordor events
    print("\nLoading Mordor events...")
    all_events = {}
    total_loaded = 0
    for tid, config in DATASET_MAP.items():
        raw_paths = config.get('files', [config['file']] if 'file' in config else [])
        paths = [os.path.join(PROJECT_ROOT, p) for p in raw_paths]
        evs = []
        for fpath in paths:
            try:
                with open(fpath) as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                evs.append(json.loads(line))
                            except json.JSONDecodeError:
                                pass
            except FileNotFoundError:
                print(f"  WARNING: {os.path.basename(fpath)} not found")
        all_events[tid] = evs
        total_loaded += len(evs)
        print(f"  {tid}: {len(evs):,} events")
    print(f"  Total: {total_loaded:,} events")

    # 80/20 deterministic holdout — last 20% of each technique's events
    # No shuffling: preserves original event ordering, fully reproducible
    print("\n80/20 split (last 20% = holdout):")
    train_events   = {}
    holdout_events = {}
    for tid, evs in all_events.items():
        n         = len(evs)
        n_holdout = max(1, int(round(n * 0.20)))
        train_events[tid]   = evs[: n - n_holdout]
        holdout_events[tid] = evs[n - n_holdout :]
        print(f"  {tid}: train={len(train_events[tid]):,}  holdout={len(holdout_events[tid]):,}")

    print(f"\nBenign pool: {len(BENIGN_TEMPLATES)} templates")
    print("  NOTE: 8-event benign pool is statistically thin. "
          "FP rate should be interpreted qualitatively, not as a population estimate.")

    # EventID distribution — documents that most events are background telemetry
    from collections import Counter
    eid_dist = Counter()
    for evs in all_events.values():
        for ev in evs:
            eid_dist[ev.get('EventID', 0)] += 1
    total_evs = sum(eid_dist.values())
    eid_dist_pct = {str(k): {'count': v, 'pct': round(v/total_evs, 3)}
                    for k, v in eid_dist.most_common(15)}
    print("\nEventID distribution (top 10 of 49,519 events):")
    for eid, cnt in eid_dist.most_common(10):
        print(f"  EventID={eid:>5}  {cnt:>6}  ({cnt/total_evs:.1%})")
    print("  NOTE: EventID 800/4103 are PowerShell pipeline events whose attack-relevant")
    print("        content lives in 'Message'/'Payload' fields not extracted by format_event().")
    print("        These events format to bare 'EventID=800|Host=...' strings.")

    # Run ablation
    print("\nRunning ablation study...")
    conditions = ['combined', 'ioc_only', 'asl_only']
    results = {}
    for cond in conditions:
        train_res   = evaluate(train_events,   BENIGN_TEMPLATES, rules, cond)
        holdout_res = evaluate(holdout_events, BENIGN_TEMPLATES, rules, cond)
        results[cond] = {'train': train_res, 'holdout': holdout_res}
        print(f"\n  [{cond}]")
        print(f"    Train   — presence={train_res['signal_presence']:.1%}  "
              f"detection={train_res['detection_rate']:.1%}  "
              f"F1={train_res['f1']:.3f}")
        print(f"    Holdout — presence={holdout_res['signal_presence']:.1%}  "
              f"detection={holdout_res['detection_rate']:.1%}  "
              f"F1={holdout_res['f1']:.3f}")

    # Write output
    output = {
        'generated':   datetime.now(timezone.utc).isoformat(),
        'eventid_distribution': eid_dist_pct,
        'methodology': {
            'split':              '80/20 deterministic (last 20% per technique = holdout)',
            'ordering':           'original JSONL file order — no shuffle',
            'detection_threshold': DETECTION_THRESHOLD,
            'benign_pool_size':   len(BENIGN_TEMPLATES),
            'benign_pool_note':   '8 synthetic templates — FP rate is illustrative, not a population estimate',
            'total_signals':      total_signals,
            'protected_signals':  len(PROTECTED_SIGNALS),
            'techniques_with_mordor_data': list(DATASET_MAP.keys()),
            'techniques_ioc_only': ['T1071.001'],
        },
        'event_counts': {
            tid: {
                'train':   len(train_events[tid]),
                'holdout': len(holdout_events[tid]),
                'total':   len(all_events[tid]),
            }
            for tid in all_events
        },
        'conditions': results,
    }

    out_path = os.path.join(REPORTS_DIR, 'ablation_study.json')
    with open(out_path, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nResults written to {out_path}")

    # Summary table for quick review
    print("\n── Summary (holdout only) ───────────────────────────────────────")
    print(f"{'Condition':<12}  {'Presence':>8}  {'Detection':>9}  {'F1':>6}  {'FP rate':>7}")
    print("-" * 56)
    for cond in conditions:
        r = results[cond]['holdout']
        print(f"{cond:<12}  {r['signal_presence']:>7.1%}  "
              f"{r['detection_rate']:>8.1%}  {r['f1']:>5.3f}  {r['fp_rate']:>6.1%}")
    print()
    print("Presence = fraction of holdout events where ≥1 signal matches the formatted string.")
    print("Detection = fraction where score >= threshold (requires conjunction in combined/asl_only).")
    print()
    print("Interpretation: The Mordor JSONL files capture full telemetry windows (attack +")
    print("background Windows noise). EventID 800/4103 events (PowerShell) dominate the")
    print("T1003.001 dataset but format to bare EventID strings, suppressing signal presence.")
    print("The training loop's 75% was measured over a random sample using the EVOLVING")
    print("signal set with raw event context — a different measurement than this holdout eval.")


if __name__ == '__main__':
    main()
