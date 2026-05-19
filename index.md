---
title: ADVERSA
nav_order: 1
description: Adversarial forensic verification for Windows incident response
---

# ADVERSA
{: .fs-9 }

Adversarial forensic verification for Windows incident response.
{: .fs-6 .fw-300 }

[Try It Out](submission){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }
[GitHub](https://github.com/sassom2112/find-evil-2026){: .btn .fs-5 .mb-4 .mb-md-0 }

---

## What ADVERSA does

A Triage Agent finds evidence. A Forensic Auditor challenges every finding independently. Only confirmed physical disk artifacts survive.

```
python3 custom-agent/investigate.py /mnt/hostname
```

| Stat | Value |
|------|-------|
| APT machines investigated | 4 |
| False positives caught by Auditor | 2 |
| Confirmed findings verified on disk | 100% |
| MCP security layers | 4 |
| ASL-trained operational rules | 11 |
| MITRE ATT&CK techniques covered | 9 |
| Training iterations | 3,000 |
| Real Sysmon events trained on | 49,519 |

---

## The core idea

Every LLM-based forensic tool has the same problem: the model *wants* to find evidence. Give it a disk image and ask whether credential dumping occurred, and it will find something that looks like credential dumping — whether or not the binary is actually on disk.

ADVERSA makes hallucinating a confirmed finding **structurally impossible**. A finding is only CONFIRMED when a second independent agent — instructed to distrust the first — calls a forensic tool and reads the actual bytes off disk. If the file is not there, the technique is REFUTED.

---

## Three-phase pipeline

**Phase 1 — Triage Agent** (The Optimist)
~25 deterministic SIFT commands, no LLM, scores against 11 ASL-trained rules.

**Phase 2 — Agentic deep investigation**
75-call Claude loop targeting uncovered domains: event logs, prefetch, SAM hive, WER dumps, network artifacts.

**Phase 3 — Forensic Auditor** (The Cynic)
Independent parallel re-verification of every finding. CONFIRMED requires a physical artifact on disk. Budget exhaustion without positive evidence → INCONCLUSIVE.

---

## Live results (SANS FIND EVIL! 2026 case data)

| Host | Confirmed | Inconclusive | Refuted | Score | Verdict |
|------|-----------|-------------|---------|-------|---------|
| tdungan | T1003.001, T1204.002, T1059 | T1071.001 | — | 100 | HIGH |
| nfury | T1003.001, T1087.001 | — | — | 95 | HIGH |
| controller | T1003.001 | — | T1036.005, T1087.001 | 50 | HIGH |

The controller is the strongest demonstration: triage score 145, two techniques refuted by the Auditor on physical evidence, final score 50 with one confirmed finding.
