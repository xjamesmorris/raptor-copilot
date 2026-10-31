# Copilot integration patch map

This document helps reviewers and automated agents distinguish patches that
directly implement the guarded Copilot CLI work from reusable infrastructure
and independent LLM improvements.

The original fourteen-patch series remained **offline and deny-by-default**.
The current tree additionally enables an explicitly selected, native Linux
Copilot CLI as the interactive decision frontend after verifying its live
process contract. It still does not register a Copilot LLM provider or admit
the synthetic receipt/probe path to production authority.

## Summary

- **Independent LLM improvements:** patches 01-02
- **Required foundations for the guarded Copilot architecture:**
  patches 03-08, 10, 13-14
- **Fake-only validation and future lifecycle foundations:**
  patches 09, 11-12

The feature branch contains all fourteen patches because it carries the
complete offline foundation.

## Patch classification

| Patch | Change | Classification |
|---:|---|---|
| 01 | Route-aware accounting and policy | **Independent** |
| 02 | Accounting and report propagation | **Independent** |
| 03 | Sandbox capture, cancellation, fake CLI and fake executable | **Generic required prerequisite** |
| 04 | Copilot candidate parser and synthetic probe | **Direct Copilot integration** |
| 05 | Strict receipt schema and verifier | **Required security foundation** |
| 06 | Linux receipt collector | **Required by the receipt architecture** |
| 07 | Receipt state and persistence | **Required security foundation** |
| 08 | Ownerless host-v2 session registry | **Required host/session foundation** |
| 09 | Owned native runtime fake | **Test infrastructure and future integration proof** |
| 10 | Run fences, pins, snapshots and lineage | **Required authority boundary** |
| 11 | Authenticated fake terminal mechanics | **Fake-only future lifecycle foundation** |
| 12 | Exact fake-only lifecycle binding | **Fake-only validation; no production authority** |
| 13 | Host events and shared coverage ingestion | **Direct integration and shared infrastructure** |
| 14 | `--frontend copilot` selector and refusal gate | **Direct user-facing integration** |

## Independent accounting work

Patches 01-02 deliberately have no runtime dependency on the Copilot parser,
probe, receipt system, host integration, or launcher.

They provide:

- typed cost bases and accounting summaries;
- exact provider/model route and cache identity;
- strict budget policy;
- scorecard authority rules;
- package and report accounting propagation.

A future real Copilot provider would eventually need accounting, but the
current fake-only candidate probe does not. These patches can be reviewed and
merged as generic LLM improvements.

## Guarded Copilot dependency path

```text
patch 03 execution substrate
  ├─> patch 04 candidate parser/probe
  └─> patch 05 receipt schema
       -> patch 06 collector
       -> patch 07 state/persistence
       -> patch 08 host registry
       -> patch 10 run fences/lineage

patch 04 + patch 10 -> patch 13 host events/coverage
patch 08 + patch 10 + patch 13 -> patch 14 launcher selector/gate
```

Together these patches:

- parse synthetic candidate output;
- execute only a repository-owned fake under the strict sandbox;
- model host and session identity without granting authority;
- prevent project, lifecycle, pin and coverage escalation;
- expose explicit `--frontend copilot` selection;
- refuse before privileged effects because live verification is incomplete.

## Current interactive frontend activation

The post-series launcher activation is deliberately narrower than provider or
runtime-receipt admission:

- only `raptor --frontend copilot` opts in;
- the selected executable must be a directly identifiable native Linux ELF;
- session authority retains the token, pid starttime, boot ID, pid namespace,
  uid, and exact executable device/inode checks;
- Copilot's observed `MainThread` process name is treated as
  non-authoritative, never as a replacement for executable identity;
- launch passes `--no-auto-update` so the captured executable identity cannot
  hand off to a different cached binary;
- initial RAPTOR dispatch uses Copilot's interactive `-i` contract;
- the existing commands, skills, agents, and coverage plugin use Copilot's
  documented Claude-compatibility surfaces.

This activation does not make `core.llm.copilot_probe` a real provider, grant
receipt-backed runs project authority, or enable live candidate admission.

## Fake-only validation layers

Patches 09, 11 and 12 do not enable production Copilot execution.

- **Patch 09** launches and finalizes an owned native fake.
- **Patch 11** provides an authenticated sequenced-packet terminal channel,
  direct-child credential checks and descriptor transfer.
- **Patch 12** binds process-local fake capabilities to exact run metadata and
  lifecycle effects.

These patches validate the future lifecycle design while remaining
unreachable from an installed Copilot executable.

## Independent corrections

The series also carries generic quality and reviewability fixes:

- stricter typing at LLM accounting and sandbox metadata seams;
- removal of history-dependent test fixtures;
- replacement of physical line-number hashes with semantic and observable
  launcher tests;
- baseline, report-writer and type-check cleanup.

These changes do not enable Copilot behavior.

## Smallest guarded series

For a minimal guarded Copilot series:

- omit patches 01-02;
- omit patches 11-12;
- retain patches 03-08, 10 and 13-14.

Patch 09 is logically test-only, but patch 10's current test construction uses
its stable fake-runtime helpers. Removing patch 09 therefore requires a small
restack of those tests and helper dependencies.

## Related documentation

- [LLM providers and the synthetic probe boundary](llm.md)
- [Runtime environment and receipt constraints](environment.md)
- [Security model](security.md)
- [Coverage and project concepts](concepts.md)
- [Developer guide](developers.md)
