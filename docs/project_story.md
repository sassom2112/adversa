---
title: Project Story
nav_order: 4
permalink: /story
---

# ADVERSA — Adversarial Forensic Verification for Windows Incident Response

**SANS FIND EVIL! Hackathon 2026 | Persistent Learning Loop**

**9** MITRE techniques covered &nbsp;·&nbsp;
**800+** labeled malware samples in corpus &nbsp;·&nbsp;
**100%** of confirmed findings verified against disk artifacts &nbsp;·&nbsp;
**4-layer** MCP security boundary &nbsp;·&nbsp;
**17 minutes · $14** per full disk + memory investigation

---

## Inspiration

A coordinated intrusion compromised the GTG-1002 domain in under ten minutes. The bits recording that fact were frozen the moment the images were acquired. And yet a traditional DFIR team would take days to fully characterize what happened — not because the evidence is missing, but because of a fundamental orchestration bottleneck.

A senior examiner sitting at a SIFT workstation does not lack tools or knowledge. They lack machine-speed synthesis. Manually invoking Volatility, RegRipper, The Sleuth Kit, and YARA, then translating fragmented text output from each into a cohesive timeline, is inherently sequential and inherently slow. When fifty endpoints are hit simultaneously, you cannot scale human analysts to match.

The question we set out to answer: **can we compress Time-to-Understanding from 48 hours to under 30 minutes without sacrificing forensic integrity?**

The harder question we did not expect to face: **can we prevent the AI itself from manufacturing the findings we asked it to find?**

LLMs hallucinate because they are trained to be helpful. Ask one whether credential dumping occurred on a disk image and it will find something that looks like credential dumping — whether or not the binary is actually on disk. The standard answer is prompt engineering: tell the model to be skeptical. Prompt controls are not security controls. They can be overridden, forgotten, or ignored when the model is confident.

ADVERSA is built around a different premise. **A finding is only CONFIRMED when a second independent agent — one instructed to distrust the first — calls a forensic tool and reads the actual bytes off the disk.** If the file is not there, the technique is refuted. No amount of model confidence changes that.

---

## What It Does

ADVERSA investigates any mounted Windows forensic image through a four-phase pipeline, fully autonomous from invocation to HTML report.

**Phase 1 — Deterministic triage.** Approximately 25 generic SIFT commands run in under 60 seconds with no LLM involvement. The image is scored against corpus-calibrated signal weights: log-odds ratios computed from 800+ labeled malware samples sourced from MalwareBazaar and HybridAnalysis, covering 9 MITRE ATT&CK techniques. Every command is invariant across investigations — nothing from a previous case contaminates the baseline sweep. The triage net is deliberately wide; the Auditor narrows it.

**Phase 2 — Agentic deep investigation.** A Claude-powered loop with a 75-call tool budget investigates the gaps: event log content, prefetch binary parsing, shellbags, SAM/SECURITY hive extraction, LNK files, hash verification. Critically, the agent receives raw artifacts only — no Pass 1 score, no technique labels. This is an architectural decision, not a prompt instruction. Passing the triage score created measurable confirmation bias: the LLM anchored to what it was told was suspicious rather than reasoning from evidence. The fix was decoupling the two passes entirely.

**Memory analysis — Volatility 3 in parallel.** A separate memory analysis path runs concurrently against the raw memory image, surfacing process injection, VAD anomalies, and runtime artifacts invisible on disk. Techniques confirmed in memory without disk evidence are scored independently and correlated at the auditor stage.

**Phase 3 — Forensic Auditor.** After triage completes, the Auditor challenges every detected technique in parallel (`asyncio.gather`), running up to 5 rounds of 2 independent tool calls per technique. The Auditor receives the findings list only — no access to triage reasoning, no shared session state. Its mandate: *assume every finding is a false positive until the filesystem proves otherwise.* A CONFIRMED verdict requires a positive tool return value. REFUTED requires evidence of absence. Model confidence produces neither.

Confirmed IOCs propagate automatically to subsequent host investigations. The same attacker account, C2 IP, or malware hash found on nfury is injected as a priority signal when controller is investigated next.

---

## How We Built It

**Signal weights from real malware, not hand-authored rules.**
Detection signals are weighted using log-odds ratios:

```
log_odds = log2( (p_malware + 0.05) / (p_benign + 0.05) )
weight   = normalize(log_odds) → [0, 1]
```

800+ labeled samples from MalwareBazaar and HybridAnalysis provide the malware frequency estimates. A curated benign baseline of common Windows system strings provides the denominator. Cross-technique tokens are dampened (IDF-equivalent). Signals from confirmed cases retain a floor weight. Every weight is traceable to a source SHA256 — not a model parameter, not an analyst's intuition.

Sysmon-domain signals trained adversarially on 49,519 real OTRF/Mordor events supplement this corpus. A Red Agent evolves evasion variants; a Blue Agent extracts discriminating field values from misses. These rules fire on Sysmon telemetry-adjacent artifacts but carry a documented domain gap on raw disk forensic output — acknowledged, not claimed as disk-validated.

**One tool, four security layers.**
Every forensic action flows through a single MCP primitive: `run_terminal_command`. Behind it is a four-gate validator enforced in Python before any subprocess call:

1. **22 hard-blocked tokens** — destructive ops (`shred`, `mkfs`, `fdisk`), exfil (`wget`, `curl`, `nc`, `ssh`), privilege escalation (`sudo`, `pkexec`), injection (`$(`, `` ` ``, `${`, `system(`), specific service control verbs
2. **53-binary SIFT allowlist** — unknown binaries rejected unconditionally; `sed` excluded because its `-e` flag passes the pattern space to the shell
3. **Quote-aware pipeline parser** — each pipe segment validated independently; handles `grep -iE '(http|https|ftp)'` without splitting on `|` inside quoted arguments
4. **Write-target guard** — all `>`, `>>`, and `tee` targets resolved with `os.path.realpath` and must land inside `reports/`; symlink traversal and `../` injection fail at the math level

Evidence modification is structurally impossible — not prompt-dependent.

**Append-only audit log.**
Every command is atomically appended via `os.open + os.write` before `subprocess.run` is called. Blocked commands log `blocked_reason`. The audit trail cannot be overwritten through a tool call. A reviewer can open `reports/audit_log.jsonl` and reproduce any finding with one shell command on the same mounted image.

---

## Challenges We Ran Into

**Confirmation bias in the agentic pass.** The original design passed the Pass 1 triage score and technique labels into the Pass 2 system prompt. In practice the LLM anchored to those labels and found supporting evidence for what it was already told was suspicious. The fix required treating Pass 1 and Pass 2 as fully decoupled: Pass 2 receives raw artifact strings and nothing else. The triage score is computed independently after both passes complete.

**The validator blocking legitimate forensic commands.** The first version split on `|` and checked each segment's leading binary. The first time the agent ran `grep -iE '(http|https|ftp)'`, the validator split on the `|` characters inside the single-quoted regex and rejected `https` as an unlisted binary. Fixing this required a quote-aware parser that tracks single-quoted substrings and treats `|` inside them as argument content, not a pipeline separator.

**Over-broad security blocking.** `'service '` was hard-blocked to prevent service management commands. It also blocked every EvtxECmd invocation that queried EventID 7045 (service installs) — which is how PsExec leaves forensic traces. The block was narrowed to specific control verbs (`service start`, `service stop`, `service restart`, `service delete`). T1569.002 went from wrongly refuted to correctly challenged.

**Case sensitivity on Linux NTFS mounts.** Windows XP stores hives at `WINDOWS/system32/config/`. Windows 7 uses `Windows/System32/config/`. On a Linux NTFS mount these are different paths. Every hardcoded path assumption silently fails. The fix was runtime path probing via `os.listdir()` wrapped in helper functions shared across the pipeline.

**Registry hive encoding.** `strings` extracts ASCII. Windows registry hives store content as UTF-16LE. Half of our early false negatives from SOFTWARE and SYSTEM hive queries were caused by this single environment quirk — fixed by switching to `strings -e l`.

**Signal noise from the corpus.** MalwareBazaar and HybridAnalysis metadata contains AV classification labels (`generic`, `trojan`, `bounty`) that appear across virtually every sample. Without filtering, these tokens dominated the corpus and produced high weights for content-free strings. The fix was an AV noise frozenset and a version string regex applied at corpus ingestion time.

---

## Accomplishments

**nfury — full pipeline confirmed an APT1 attack chain autonomously.**

The image scored 100/100 on triage (disk and memory). The Auditor processed 9 flagged techniques across 25 argumentation rounds. Two survived:

- **T1003.002** — SAM credential dump confirmed via registry hive extraction
- **T1055** — Process injection confirmed via memory analysis of the `a.exe` loader

Seven were refuted. The attack chain: httppump C2 at `199.73.28.114/ads/`, attacker account `vibranium` (domain SID -1673), lateral movement via PsExec, exfiltration via `system4.rar`. Total runtime: 17 minutes. Total cost: $14.

**The auditor refutation rate is the result, not a failure.** On nfury: 9 detected, 2 confirmed. An analyst who received 9 unverified technique flags would open 9 investigation threads. An analyst who receives 2 confirmed findings with physical artifact citations and 7 explicit refutals with reasoning opens 2. The Auditor's job is to narrow — and it did.

**Architectural anti-hallucination.** The controller investigation (earlier pipeline version) produced a triage score of 145 across 3 techniques. The Auditor refuted 2 on physical evidence — legitimate `svchost.exe` in WinSxS, a user profile directory mistaken for active enumeration. Final score: 50. One confirmed technique, zero false accusations.

**Every confirmed finding is independently reproducible.** The audit log contains the exact command, the exact output, and the exact timestamp. There are no findings that require trusting the model.

---

## What We Learned

**Architectural separation is the only reliable anti-hallucination mechanism.** Prompt instructions telling the model to be skeptical produce a skeptical-sounding model. A second agent with its own MCP session that physically cannot confirm a finding without a positive tool return value produces a verified finding. These are not equivalent.

**Decoupling passes eliminates anchoring bias.** Passing triage results into the investigative pass creates a model that confirms what it was told to look for. Passing only raw artifacts creates a model that reasons from evidence. The difference in output quality was immediately measurable.

**Generic signals and case IOCs are fundamentally different things.** A signal that fires on `psexesvc` in a malware corpus generalizes. A signal that fires on `199.73.28.114` is a case-specific IOC. Baking IOCs into the detection layer inflates scores on familiar images without generalizing to new ones. ADVERSA separates these explicitly — corpus weights are generic, IOC files are opt-in at runtime.

**One confirmed case is more defensible than ten unverified ones.** The pressure to show results on all four hackathon hosts is real. The honest answer is that the full-pipeline system (corpus-calibrated weights, decoupled passes, fixed auditor) was validated on nfury. Earlier results on controller and tdungan reflect a different version of the pipeline. We report them separately.

---

## What's Next

**Second case validation.** nfury is one data point. The honest next step is running the current system on a host it has never seen and measuring false positive rate, missed techniques, and auditor correction rate independently.

**Technique coverage expansion.** Corpus weights cover 9 MITRE techniques. The MalwareBazaar and HybridAnalysis APIs can scale this to 50+ with additional corpus collection runs.

**Timeline correlation.** Plaso is on every SIFT workstation. Filtering a supertimeline to the 4-minute window around a confirmed technique execution turns individual artifact matches into activity chains — the difference between "this binary existed on disk" and "this binary ran at 14:32:07, four minutes before this network connection."

**Memory-resident technique coverage.** Techniques that deliberately avoid disk artifacts require memory-first analysis. The Volatility 3 path exists; expanding it to cover process hollowing, DKOM, and kernel rootkit signatures is the next engineering target.
