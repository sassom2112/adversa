#!/usr/bin/env python3
"""
extract_iocs.py — Extract confirmed IOCs from a completed ADVERSA investigation.

Reads the triage report + auditor transcript for a host and writes a structured
IOC JSON file that can be passed to subsequent investigations via --ioc-file.

Usage:
    python3 custom-agent/extract_iocs.py <host>
    python3 custom-agent/extract_iocs.py nromanoff
    python3 custom-agent/extract_iocs.py nfury --reports-dir /path/to/reports

Output: reports/<host>-iocs.json
"""

import argparse
import ipaddress
import json
import os
import re
import sys

_HERE    = os.path.dirname(os.path.abspath(__file__))
_REPORTS = os.path.normpath(os.path.join(_HERE, '..', 'reports'))

# Regex patterns for artifact extraction
_IP_RE       = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
_FNAME_RE    = re.compile(
    r'(?:^|[\s/\\])([A-Za-z0-9_\-]+\.(?:exe|dll|bin|dmp|ps1|vbs|bat|cmd|rar|zip|7z))\b',
    re.IGNORECASE,
)
_REGVAL_RE   = re.compile(
    r'(?:CurrentVersion\\Run|RunOnce|Winlogon|AppInit)[^\n]*?[:=]\s*([^\n]{3,80})',
    re.IGNORECASE,
)
_ACCOUNT_RE  = re.compile(
    r'(?:user|account|profile)[:\s]+([A-Za-z][A-Za-z0-9_\-.]{2,19})\b',
    re.IGNORECASE,
)

# IPs that are never IOCs
_BORING_PREFIXES = ('127.', '0.', '255.', '169.254.', '10.', '192.168.', '172.')


def _is_routable(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_global
    except ValueError:
        return False


def _extract_from_text(text: str, iocs: dict) -> None:
    for ip in _IP_RE.findall(text):
        if _is_routable(ip) and ip not in iocs['c2_ips']:
            iocs['c2_ips'].append(ip)

    for m in _FNAME_RE.finditer(text):
        fname = m.group(1).lower()
        # Skip obvious system / installer filenames
        if fname not in iocs['filenames'] and not any(
            fname.startswith(p) for p in ('setup', 'install', 'update', 'msi')
        ):
            iocs['filenames'].append(fname)


def extract_iocs(host: str, reports_dir: str) -> dict:
    """
    Build an IOC dict from a completed investigation.
    Only includes artifacts from CONFIRMED techniques.
    """
    iocs: dict = {
        'source_host':   host,
        'c2_ips':        [],
        'filenames':     [],
        'accounts':      [],
        'registry_keys': [],
        'directories':   [],
    }

    triage_path = os.path.join(reports_dir, f'{host}-custom-agent-report.json')
    audit_path  = os.path.join(reports_dir, f'{host}-auditor-transcript.json')

    if not os.path.exists(triage_path):
        print(f"  ERROR: triage report not found: {triage_path}")
        return iocs

    with open(triage_path) as f:
        triage = json.load(f)

    # Signals that matched in triage (only from confirmed techniques if audit exists)
    confirmed_ids: set[str] = set()

    if os.path.exists(audit_path):
        with open(audit_path) as f:
            audit = json.load(f)
        confirmed_ids = {
            e['finding_id']
            for e in audit.get('transcript', [])
            if e.get('final_verdict') == 'CONFIRMED'
        }
        # Mine tool output from confirmed findings
        for entry in audit.get('transcript', []):
            if entry.get('final_verdict') != 'CONFIRMED':
                continue
            for ch in entry.get('challenges', []):
                _extract_from_text(ch.get('tool_output_preview', ''), iocs)
                _extract_from_text(ch.get('reasoning', ''), iocs)
    else:
        # No audit — use all triage findings
        confirmed_ids = set(triage.get('techniques_detected', []))

    # Signals from confirmed techniques
    matched = triage.get('matched_signals', {})
    for tid in confirmed_ids:
        for sig in matched.get(tid, []):
            if re.match(r'\d+\.\d+\.\d+\.\d+', sig) and _is_routable(sig):
                if sig not in iocs['c2_ips']:
                    iocs['c2_ips'].append(sig)
            elif re.search(r'\.(?:exe|dll|bin|dmp|ps1)$', sig, re.I):
                fname = os.path.basename(sig).lower()
                if fname not in iocs['filenames']:
                    iocs['filenames'].append(fname)
            elif '\\' in sig and sig not in iocs['registry_keys']:
                iocs['registry_keys'].append(sig)

    # Analysis text (file paths, IPs mentioned by the agent)
    _extract_from_text(triage.get('claude_analysis', ''), iocs)

    # Deduplicate and sort
    for key in ('c2_ips', 'filenames', 'registry_keys', 'directories', 'accounts'):
        iocs[key] = sorted(set(iocs[key]))

    return iocs


def merge_iocs(*ioc_files: str) -> dict:
    """Merge multiple IOC files into one, deduplicating all lists."""
    merged: dict = {
        'source_hosts':  [],
        'c2_ips':        [],
        'filenames':     [],
        'accounts':      [],
        'registry_keys': [],
        'directories':   [],
    }
    for path in ioc_files:
        with open(path) as f:
            data = json.load(f)
        host = data.get('source_host') or data.get('source_hosts', [])
        if isinstance(host, str):
            merged['source_hosts'].append(host)
        elif isinstance(host, list):
            merged['source_hosts'].extend(host)
        for key in ('c2_ips', 'filenames', 'accounts', 'registry_keys', 'directories'):
            merged[key].extend(data.get(key, []))

    for key in ('c2_ips', 'filenames', 'accounts', 'registry_keys', 'directories'):
        merged[key] = sorted(set(merged[key]))
    merged['source_hosts'] = sorted(set(merged['source_hosts']))
    return merged


def main():
    parser = argparse.ArgumentParser(
        description='Extract confirmed IOCs from a completed ADVERSA investigation'
    )
    parser.add_argument('host', help='Host name (e.g. nromanoff, nfury)')
    parser.add_argument('--reports-dir', default=_REPORTS,
                        help='Reports directory (default: ../reports)')
    parser.add_argument('--merge', nargs='+', metavar='IOC_FILE',
                        help='Merge these IOC files together instead of extracting')
    parser.add_argument('--output', '-o', metavar='PATH',
                        help='Output path (default: reports/<host>-iocs.json)')
    args = parser.parse_args()

    if args.merge:
        missing = [f for f in args.merge if not os.path.exists(f)]
        if missing:
            print(f"ERROR: files not found: {missing}")
            sys.exit(1)
        result = merge_iocs(*args.merge)
        out = args.output or os.path.join(args.reports_dir, f'{args.host}-campaign-iocs.json')
    else:
        result = extract_iocs(args.host, args.reports_dir)
        out = args.output or os.path.join(args.reports_dir, f'{args.host}-iocs.json')

    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, 'w') as f:
        json.dump(result, f, indent=2)

    print(f"IOC file written: {out}")
    print(f"  C2 IPs:        {result['c2_ips']}")
    print(f"  Filenames:     {result['filenames']}")
    print(f"  Accounts:      {result['accounts']}")
    print(f"  Registry keys: {result['registry_keys']}")
    print(f"  Directories:   {result['directories']}")


if __name__ == '__main__':
    main()
