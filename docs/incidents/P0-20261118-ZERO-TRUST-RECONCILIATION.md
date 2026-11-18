# P0 Zero-Trust Security and Customer Release Reconciliation — 18 Nov 2026

**State: ISOLATED / UNMERGED / NOT DEPLOYED / CUSTOMER RELEASE NO-GO**

Baseline: main `059e9dfc5a8d7bef5c3585522c7cb96260351b96` (PR #1024 already merged).
Work branch: `fix/p0-zero-trust-reconcile-20261118-r1`.
Previous worktree `fix/p0-report-fetchback-evidence-20261118` passed 36 Python and 36 Node local tests at `7ed22cf2c8d73fd27512802228830d3f16d0db57`, per user-operated WSL log `log-966.txt`. The new branch is a separately reconciled tree with new egress restrictions; its **exact-head tests have not yet run**.

## Observed P0 findings, not assumptions

| Severity | Observed evidence | Release disposition |
| --- | --- | --- |
| P0 customer report delivery | [Publisher run 44242983679](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/actions/runs/44242983679): R2 integrity 44/44 clean, Phase 5 five historical URLs HTTP 404 expected policy denials, no delivered historical positive evidence; governance `DEPLOYMENT_FAILED` | **HOLD**; do not reinterpret 404 as HTTP 200 or disable Phase 5 |
| P0 commercial customer journey | [Commercial run 44227796120](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/actions/runs/44227796120): PRO live canary `FAIL fetch failed`; other MSSP/rotation/auth tests passed | **HOLD** paid PRO certification |
| P0 security baseline | [Full scheduled SAST run 44225426036](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/actions/runs/44225426036): 529 Python files, 90 Bandit HIGH/HIGH findings. First 50 logged findings: 35 B310 URL-open, 9 B108 temporary paths, 4 B314 XML, 2 B104 all-interface binding | **HOLD** full-source SAST certification; scope and triage all 90 |
| P0 branch governance | Active ruleset #21556637 mandates PR and linear history but has **no required_status_checks**; legacy branch checks enforcement OFF | **HOLD** until exact-head required checks are enforced |
| P0 budget | Shared Cloudflare R2, Workers, Pages and GitHub Actions have prior quota/overage concerns | **HOLD** additional full publisher, Cloudflare writes or expensive CI until verified budget headroom |

## Implemented here, on isolated branch only

1. Restore **bounded, fail-closed report fetch-back classification**: allowlisted HTTP and mismatch reasons only; no exception bodies or customer secrets; still three report GETs maximum.
2. Enforce **catalog EPSS provenance parity**: same verified FIRST.org `epss_percent` authority as dossier HTML S8. Reject unverified mixed-scale claims rather than converting heuristic scores into probabilities.
3. Add **R2 chronology/registry rejection diagnostics** with bounded validator defect excerpts. Existing reject/no-publish behavior is unchanged.
4. Limit upstream feed HTTP responses to **8 MiB** before decode; RSS XML to **2 MiB**. Reject DTD/ENTITY markup before XML parser; never process unbounded external XML.
5. **Pin this collector's outbound egress to its seven known upstream HTTPS hosts**. Reject credentials, non-HTTPS schemes, fragments, explicit ports, unlisted hosts and cross-origin redirects before following them. Never forward GitHub or OTX authentication headers off-origin. Logging uses exception class only, no raw URL/query/header/token strings.
6. Include negative/security tests for XML entity rejection, oversize responses, origin allowlist, redirect isolation, EPSS parity, publication gate and catalog chronology/registry.
7. Preserve [workflow inventory snapshot](P0-20261118-WORKFLOW-RELEASE-INVENTORY.md) of 73 YAML definitions; a filename inventory **does not** certify that every workflow passed.

## Verification and release gates

- [ ] Exact **new branch HEAD** fetched and clean; run `python3 -m compileall`, the three targeted Python suites and Node fetch-back tests in WSL with real exit codes.
- [ ] Run production-script **FULL baseline** Bandit + Semgrep scope, not merely changed-file SAST; review each original HIGH/HIGH finding and demonstrate no new findings. Do not blanket `nosec` or remove paths from scope.
- [ ] Confirm the seven permitted feeds are still reachable and that benign same-host redirects work in a bounded test; verify off-origin redirects and source-size violations remain blocked.
- [ ] Run only an approved, cost-bounded publisher with **historical HTTP 200** content identity and valid TLP/provenance; independently verify sampled customer-ready report EPSS/severity/actor parity.
- [ ] Validate PRO paid entitlement, customer API responses and negative authorization/tenant isolation without using real customer records or real charges.
- [ ] Enforce required checks at protected main; check Cloudflare account-wide budget, current GitHub Actions headroom, rollback and DNS/route identity before deploy.
- [ ] Verify fresh public dashboard/feed reports and customer delivery after gated deployment. No synthetic success timestamps or fabricated purchases.

**Rollback:** No Cloudflare or production mutations were performed by these code changes. Delete/discard the work branch or revert its individual commits; protect current main until acceptance tests pass.

**Known residual risk:** hostname pinning does not prove DNS resolution or vendor security. High/high B310 findings in other fetchers and the rest of the original full SAST set remain unresolved pending individual triage.
