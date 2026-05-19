#!/usr/bin/env python3
"""
investigate.py -- Adversarial Investigation Orchestrator

Sequences: Triage Agent (The Optimist) -> Forensic Auditor (The Cynic)
Produces a unified report and argumentation transcript.

The transcript (every Triage finding + every Auditor challenge + every
verdict) is the primary submission artifact demonstrating the adversarial
verification loop.

Usage:
    python3 custom-agent/investigate.py /mnt/nromanoff
    python3 custom-agent/investigate.py /mnt/nfury --no-synthesis
    python3 custom-agent/investigate.py /mnt/controller --no-synthesis
"""

import argparse
import asyncio
import glob
import json
import os
import sys
from datetime import datetime, timezone

_HERE    = os.path.dirname(os.path.abspath(__file__))
_REPORTS = os.path.normpath(os.path.join(_HERE, '..', 'reports'))

# Import agents from the same directory
sys.path.insert(0, _HERE)
import blue_agent
from auditor_agent import ForensicAuditor
from extract_iocs import extract_iocs, merge_iocs
from html_report import generate_report

# Techniques that warrant HIGH verdict regardless of numeric score
_HIGH_VALUE_TECHNIQUES = {'T1003.001', 'T1071.001', 'T1569.002', 'T1547.001'}


# ── Verdict helper ─────────────────────────────────────────────────────────

def _final_verdict(score: int, confirmed: list = None) -> str:
    if confirmed and any(t in _HIGH_VALUE_TECHNIQUES for t in confirmed):
        return 'HIGH — Active compromise confirmed (high-value technique verified on disk)'
    if score >= 70:
        return 'HIGH — Active compromise confirmed'
    elif score >= 40:
        return 'MEDIUM — Suspicious activity, manual review required'
    else:
        return 'LOW — No confirmed compromise indicators'


# ── IOC auto-detection ─────────────────────────────────────────────────────

def _autoload_campaign_iocs(target_path: str, reports_dir: str) -> dict | None:
    """
    When --ioc-file is not passed, look for IOC files from other hosts in reports/.
    Merges all found IOC files and returns the merged dict (or None if none found).
    """
    host = os.path.basename(target_path.rstrip('/'))
    pattern = os.path.join(reports_dir, '*-iocs.json')
    all_ioc_files = sorted(glob.glob(pattern))
    # Exclude the current target's own IOC file (from a previous run)
    other_iocs = [p for p in all_ioc_files
                  if os.path.basename(p) != f'{host}-iocs.json']
    if not other_iocs:
        return None

    print(f"\n  ⚡ Auto-detected campaign IOC files ({len(other_iocs)}):")
    for p in other_iocs:
        print(f"     {os.path.basename(p)}")

    merged = merge_iocs(*other_iocs)
    n_ips   = len(merged.get('c2_ips', []))
    n_files = len(merged.get('filenames', []))
    n_accts = len(merged.get('accounts', []))
    print(f"  ✓  Merged: {n_ips} C2 IPs, {n_files} filenames, {n_accts} accounts\n")
    return merged


# ── Main orchestration loop ────────────────────────────────────────────────

async def run_investigation(target_path: str, no_synthesis: bool = False,
                            ioc_data: dict = None) -> dict:
    """
    Full Triage -> Audit pipeline. Returns unified report dict.
    """
    host = os.path.basename(target_path.rstrip('/'))
    started = datetime.now(timezone.utc)

    print(f"\n{'═'*60}")
    print(f"  ADVERSARIAL INVESTIGATION ORCHESTRATOR")
    print(f"  Framework:  ADVERSA (Adversarial Signal Learning)")
    print(f"  Target:     {target_path}")
    print(f"  Started:    {started.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(f"{'═'*60}")

    # ── Phase 1: Triage Agent (The Optimist) ──────────────────────────────
    print(f"\n{'━'*60}")
    print(f"  PHASE 1  —  TRIAGE AGENT  (The Optimist)")
    print(f"{'━'*60}")

    rules = blue_agent.load_operational_rules()
    triage_score, triage_hits = await blue_agent.investigate(
        target_path, rules, no_synthesis=no_synthesis, ioc_data=ioc_data
    )

    triage_report_path = os.path.join(_REPORTS, f'{host}-custom-agent-report.json')
    if not os.path.exists(triage_report_path):
        print(f"\nERROR: Triage report not written to {triage_report_path}")
        sys.exit(1)

    with open(triage_report_path) as f:
        triage_report = json.load(f)

    techniques_found = triage_report.get('techniques_detected', [])

    if not techniques_found:
        print("\n  Triage Agent found no techniques — skipping Auditor phase.")
        unified = {
            'generated':     datetime.now(timezone.utc).isoformat(),
            'target':        target_path,
            'framework':     'ADVERSA — Adversarial Signal Learning',
            'pipeline':      'Triage Agent -> Forensic Auditor',
            'triage':        {'score': triage_score, 'techniques_detected': [],
                              'report_path': triage_report_path},
            'audit':         {'skipped': True, 'reason': 'no_triage_findings'},
            'final_verdict': _final_verdict(triage_score),  # no confirmed list — triage only
            'convergence':   'no_findings_to_challenge',
        }
        _save_unified(host, unified)
        return unified

    # ── Phase 2: Forensic Auditor (The Cynic) ─────────────────────────────
    print(f"\n{'━'*60}")
    print(f"  PHASE 2  —  FORENSIC AUDITOR  (The Cynic)")
    print(f"{'━'*60}")

    auditor = ForensicAuditor()
    confirmed, inconclusive, refuted, transcript, adjusted_score = await auditor.audit(
        target_path, triage_report
    )

    transcript_path = os.path.join(_REPORTS, f'{host}-auditor-transcript.json')

    # Count total argumentation rounds
    total_rounds = sum(len(e['challenges']) for e in transcript)

    # ── Phase 3: Unified report ────────────────────────────────────────────
    print(f"\n{'━'*60}")
    print(f"  PHASE 3  —  UNIFIED REPORT")
    print(f"{'━'*60}")

    elapsed = (datetime.now(timezone.utc) - started).total_seconds()

    unified = {
        'generated':   datetime.now(timezone.utc).isoformat(),
        'target':      target_path,
        'framework':   'ADVERSA — Adversarial Signal Learning',
        'pipeline':    'Triage Agent -> Forensic Auditor',
        'elapsed_s':   round(elapsed, 1),
        'triage': {
            'score':               triage_score,
            'techniques_detected': list(triage_hits.keys()),
            'report_path':         triage_report_path,
        },
        'audit': {
            'adjusted_score':        adjusted_score,
            'confirmed':             confirmed,
            'inconclusive':          inconclusive,
            'refuted':               refuted,
            'argumentation_rounds':  total_rounds,
            'transcript_path':       transcript_path,
        },
        'final_verdict':  _final_verdict(adjusted_score, confirmed=confirmed),
        'convergence':    'all_findings_processed',
    }

    unified_path = _save_unified(host, unified)

    print(f"\n{'═'*60}")
    print(f"  INVESTIGATION COMPLETE  ({elapsed:.0f}s)")
    print(f"")
    print(f"  Triage score:          {triage_score}")
    print(f"  After audit:           {adjusted_score}")
    print(f"  Confirmed techniques:  {confirmed}")
    print(f"  Inconclusive:          {inconclusive}")
    print(f"  Refuted  techniques:   {refuted}")
    print(f"  Argumentation rounds:  {total_rounds}")
    print(f"  Final verdict:         {unified['final_verdict']}")
    print(f"")
    html_path = generate_report(host, _REPORTS)

    # Auto-extract IOCs from confirmed findings for use on subsequent images
    ioc_result  = extract_iocs(host, _REPORTS)
    ioc_path    = os.path.join(_REPORTS, f'{host}-iocs.json')
    with open(ioc_path, 'w') as f:
        import json as _json
        _json.dump(ioc_result, f, indent=2)

    print(f"  Reports written:")
    print(f"    Triage     ->  {triage_report_path}")
    print(f"    Transcript ->  {transcript_path}")
    print(f"    Unified    ->  {unified_path}")
    print(f"    HTML       ->  {html_path}")
    print(f"    IOCs       ->  {ioc_path}  "
          f"({len(ioc_result['c2_ips'])} IPs, "
          f"{len(ioc_result['filenames'])} files, "
          f"{len(ioc_result['accounts'])} accounts)")
    print(f"{'═'*60}\n")

    return unified


def _save_unified(host: str, report: dict) -> str:
    path = os.path.join(_REPORTS, f'{host}-investigation.json')
    os.makedirs(_REPORTS, exist_ok=True)
    with open(path, 'w') as f:
        json.dump(report, f, indent=2)
    return path


# ── CLI entry point ────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Adversarial Investigation Orchestrator — '
                    'Triage Agent -> Forensic Auditor -> Unified Report'
    )
    parser.add_argument('target',
                        help='Mounted image path (e.g. /mnt/nromanoff)')
    parser.add_argument('--no-synthesis', action='store_true',
                        help='Skip LLM synthesis in Triage phase (faster, '
                             'deterministic two-pass scan only)')
    parser.add_argument('--ioc-file', metavar='PATH',
                        help='JSON file of case-specific IOCs to add to Pass 1 '
                             '(c2_ips, filenames, accounts, registry_keys, directories)')
    args = parser.parse_args()

    if not os.path.isdir(args.target):
        print(f"ERROR: {args.target} not found or not mounted")
        sys.exit(1)

    ioc_data = None
    if args.ioc_file:
        if not os.path.exists(args.ioc_file):
            print(f"ERROR: IOC file not found: {args.ioc_file}")
            sys.exit(1)
        with open(args.ioc_file) as f:
            import json as _json
            ioc_data = _json.load(f)
        n = sum(len(v) for v in ioc_data.values() if isinstance(v, list))
        print(f"  IOC file: {args.ioc_file} ({n} IOCs)")
    else:
        # Auto-detect IOC files from prior investigations in this campaign
        ioc_data = _autoload_campaign_iocs(args.target, _REPORTS)

    os.environ['BLUE_TARGET'] = args.target
    asyncio.run(run_investigation(args.target, no_synthesis=args.no_synthesis,
                                  ioc_data=ioc_data))


if __name__ == '__main__':
    main()
