---
title: Try It Out
nav_order: 2
---

# ADVERSA — Try It Out

Adversarial forensic verification for Windows incident response.
A dual-agent pipeline: Triage Agent finds evidence, Forensic Auditor challenges every
finding independently. Only confirmed physical artifacts survive.

SANS FIND EVIL! Hackathon 2026 | Category 7: Persistent Learning Loop

---

## Requirements

| Requirement | Notes |
|------------|-------|
| SANS SIFT Ubuntu workstation | Ubuntu 20.04+ with SIFT toolset pre-installed |
| Python 3.10+ | `python3 --version` |
| Anthropic API key | `export ANTHROPIC_API_KEY=sk-ant-...` |
| Mounted disk image | Accessible at a path like `/mnt/hostname` |
| MSTICPy (optional) | `pip install msticpy` — enables dynamic Mordor dataset discovery |

```bash
python3 -m venv ~/adversa-env && source ~/adversa-env/bin/activate
pip install anthropic mcp matplotlib numpy
```

---

## Path A: Fast Triage — No API Key Needed (< 10 seconds)

Deterministic IOC sweep using pre-trained ASL rules. No LLM, no training required.

```bash
cd /home/sansforensics/find-evil-2026
python3 fast-triage/fast_triage.py /mnt/hostname
```

**Expected output:**
```
[FAST TRIAGE] /mnt/hostname
  T1569.002  PsExec                 MATCH  +35  PSEXESVC.EXE found
  T1547.001  Registry Run Key       MATCH  +35  dllhost\svchost run key
  T1003.001  Credential Dumping     MATCH  +35  hydrakatz.exe, lsass access
  T1071.001  C2 Web Protocol        MATCH  +17  12.190.135.235
  ...
Score: 122  →  HIGH CONFIDENCE — escalating to full pipeline
```

---

## Path B: Full Adversarial Investigation (recommended)

Runs the complete Triage → Auditor → HTML report pipeline.

```bash
# Terminal 1 — start the forensic MCP tool server
python3 custom-agent/sift_server.py

# Terminal 2 — run the adversarial pipeline
export ANTHROPIC_API_KEY=sk-ant-...
python3 custom-agent/investigate.py /mnt/hostname
```

**What you will see:**

**Phase 1 — Triage Agent** (The Optimist):
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  PHASE 1  —  TRIAGE AGENT  (The Optimist)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Pass 1: deterministic sweep (~60s)
    [P1] check_known_iocs: 2341 bytes
    [P1] get_credential_artifacts: 1089 bytes
    ...
  Score: 67/100
    • OS Credential Dumping (+35) [IOC] via: ['hydrakatz', 'lsass']
    • Registry Run Key (+35) [ASL] via: ['currentversion\\run']
    • C2 Web Protocol (+17) [IOC] via: ['12.190.135.235']

  Pass 2: 75-call agentic loop (operator checkpoint at 25 calls)
    [agent] Checking prefetch for execution evidence...
    [agent] Scanning event logs for service installation...
```

**Phase 2 — Forensic Auditor** (The Cynic):
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  PHASE 2  —  FORENSIC AUDITOR  (The Cynic)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Challenging T1003.001 (OS Credential Dumping)
    Round 1: grep -r "hydrakatz" /mnt/hostname/Windows/ → CONFIRMED
  Challenging T1036.005 (Masquerading)
    Round 1: find /mnt/hostname -name "svchost.exe" -not -path "*/System32/*"
    Round 2: fls -r /mnt/hostname | grep -i svchost → not found
    Verdict: REFUTED — no masqueraded binary on disk
```

**Phase 3 — Reports written:**
```
  Triage     →  reports/hostname-custom-agent-report.json
  Transcript →  reports/hostname-auditor-transcript.json
  Unified    →  reports/hostname-investigation.json
  HTML       →  reports/hostname-report.html
  IOCs       →  reports/hostname-iocs.json
```

### Campaign mode — IOCs carry forward automatically

```bash
# IOCs from completed hosts are auto-detected for subsequent runs
python3 custom-agent/investigate.py /mnt/host1
python3 custom-agent/investigate.py /mnt/host2   # uses host1 IOCs
python3 custom-agent/investigate.py /mnt/host3   # uses host1+host2 IOCs
```

---

## Path C: Retrain ASL on New Evidence

Run the adversarial training loop on Mordor datasets (download first — see DATASET.md).

```bash
export ANTHROPIC_API_KEY=sk-ant-...
python3 custom-agent/brain.py
# ~10 min for 1,000 iterations, ~30 min for 3,000
# Checkpoints every 100 iterations → reports/brain_state.json
```

Export learned patterns:
```bash
python3 custom-agent/export_patterns.py
# → reports/operational_rules.json  (loaded by investigate.py)
# → reports/sigma_rules/*.yml

python3 custom-agent/sigma_exporter.py
```

---

## Output Files

| File | Description |
|------|-------------|
| `reports/operational_rules.json` | ASL-trained detection rules — loaded at investigation startup |
| `reports/sigma_rules/*.yml` | Adversarially-validated Sigma rules per technique |
| `reports/accuracy_report.json` | Per-technique detection rates, F1, precision, recall |
| `reports/hostname-report.html` | Full HTML investigation report with exec summary |
| `reports/hostname-investigation.json` | Unified pipeline output — confirmed, inconclusive, refuted |
| `reports/hostname-auditor-transcript.json` | Full agent-to-agent argumentation log |
| `analysis/forensic_audit.log` | Chain-of-custody audit log — all tool calls with timestamps |

---

## Hackathon Category

**Category 7 — Persistent Learning Loop**

The system trains itself on real attack telemetry, adapts when the Red Agent
evades detection, and deploys the learned rules into a live dual-agent forensic
investigator — closing the loop between training and deployment automatically.

Detection is backed by 11 ASL-trained operational rules covering 9 MITRE ATT&CK
techniques, trained over 3,000 iterations on ~49,519 real Mordor/OTRF Sysmon events.
