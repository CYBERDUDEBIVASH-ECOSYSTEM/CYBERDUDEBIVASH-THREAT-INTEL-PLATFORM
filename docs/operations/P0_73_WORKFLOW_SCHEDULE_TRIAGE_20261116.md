# P0 Threat Intel workflow schedule rationalization — 2026-11-16

**Audit basis:** 73 YAML workflow files at exact source `main` `005a08434b1aac2f70f63623ffc14d2c8132e752`. Static `on:`/cron inventory via connected GitHub file reads; NOT hosted job execution, a Cloudflare audit, verified dependencies, or GitHub billable-minutes report. No production activity performed.

## Quantified schedule exposure

- Workflow definitions: **73**.
- Scheduled workflows: **41**. Non-scheduled workflows: **32**, of which some still auto-run on source events.
- Expected **daily cron trigger opportunities from daily/every-N-minute cron patterns: 450/day**. These are nominal source schedules, not observed completed runs or billable usage; GitHub can delay/drop schedules, and account-level Actions is currently disabled.
- Seven weekly workflows add seven scheduled opportunities/week, plus `telegram-revenue.yml` has one weekly schedule; one monthly cron is present in `sentinel-apex.yml`. Thus a normal full week would have around **3,158** configured trigger opportunities (3,150 daily + 8 weekly), before a possible monthly trigger.
- Four highest-frequency monitors account for **336 nominal opportunities/day**: `sla-heartbeat.yml` 144, `deploy-drift-watchdog.yml` 96, `intel-freshness-guard.yml` 48, and `enterprise-alerts.yml` 48.
- Source schedules must not be equated to background automation currently running or to cost; this is a scenario if all workflows were eligible and cron events delivered.

## Complete 41-scheduled-workflow inventory

**Cron timezone:** UTC. **Rates:** nominal opportunities on a typical day; weekly entries only count on their designated day. `telegram-revenue.yml` has an additional Monday 06:00 UTC schedule; `sentinel-apex.yml` has an additional monthly first-day schedule.

| Workflow | Schedule | Typical daily triggers | Proposed disposition (not a deletion decision) |
|---|---|---:|---|
| [`sla-heartbeat.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/sla-heartbeat.yml) | `*/10 * * * *` | 144 | PROTECT/CONSOLIDATE: uptime evidence, reduce duplicate probes |
| [`deploy-drift-watchdog.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/deploy-drift-watchdog.yml) | `4,19,34,49 * * * *` | 96 | P0 REVIEW: scheduled dispatch can trigger Pages publication |
| [`enterprise-alerts.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/enterprise-alerts.yml) | `*/30 * * * *` | 48 | PROTECT: alerting; consolidate with freshness/SLA by evidence |
| [`intel-freshness-guard.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/intel-freshness-guard.yml) | `7,37 * * * *` | 48 | PROTECT: genuine report freshness gate; avoid false LIVE |
| [`enterprise-governance.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/enterprise-governance.yml) | `45 1,3,5,7,9,11,13,15,17,19,21,23 * * *` | 12 | PROTECT/CONSOLIDATE: TLP, duplicates, governance |
| [`self-healing.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/self-healing.yml) | `15 */2 * * *` | 12 | REVIEW: mutation and rollback authority |
| [`enterprise-intel-quality.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/enterprise-intel-quality.yml) | `15 2,6,10,14,18,22 * * *` | 6 | REVIEW: derived enrichment, output/customer proof |
| [`enterprise-observability.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/enterprise-observability.yml) | `30 2,6,10,14,18,22 * * *` | 6 | CONSOLIDATE: validation and observability |
| [`multi-source-intel.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/multi-source-intel.yml) | `45 1,5,9,13,17,21 * * *` | 6 | PROTECT: real upstream ingestion; verify authoritative R2 writes |
| [`sentinel-apex.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/sentinel-apex.yml) | `17 */4 * * *` | 6 | PROTECT: authoritative publisher |
| [`ui-file-guardian.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/ui-file-guardian.yml) | `0 */4 * * *` | 6 | PROTECT/CONSOLIDATE: frontend integrity |
| [`ai-predictions.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/ai-predictions.yml) | `30 */6 * * *` | 4 | REVIEW: AI/R2 writer; check paid endpoint use |
| [`dashboard-feeds-sync.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/dashboard-feeds-sync.yml) | `30 3,9,15,21 * * *` | 4 | PROTECT: customer dashboard R2 publisher; reconcile writer keys |
| [`generate-and-sync.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/generate-and-sync.yml) | `0 3,9,15,21 * * *` | 4 | PROTECT/REVIEW: R2 and Git writer conflict risk |
| [`genesis-powerhouse.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/genesis-powerhouse.yml) | `45 */6 * * *` | 4 | REVIEW: high-cost derived engine and Git/R2 writer |
| [`pipeline-staleness-monitor.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/pipeline-staleness-monitor.yml) | `0 0,6,12,18 * * *` | 4 | CONSOLIDATE: health overlap |
| [`production-hardening-final.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/production-hardening-final.yml) | `0 1,7,13,19 * * *` | 4 | REVIEW: engine smoke, compare PR validation |
| [`sovereign-platform.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/sovereign-platform.yml) | `15 */6 * * *` | 4 | REVIEW: derived Git/R2 writer |
| [`zerodayhunter.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/zerodayhunter.yml) | `45 */6 * * *` | 4 | REVIEW: derived git-writer |
| [`ai-threat-analyst.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/ai-threat-analyst.yml) | `30 */8 * * *` | 3 | REVIEW: optional analyst output |
| [`bughunter-resilient.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/bughunter-resilient.yml) | `15 */8 * * *` | 3 | REVIEW: recon engine, authorize target/scope |
| [`precognition-engine.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/precognition-engine.yml) | `0 */8 * * *` | 3 | REVIEW: prediction git-writer |
| [`status-monitor.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/status-monitor.yml) | `0 0,8,16 * * *` | 3 | REVIEW: overlaps SLA/alerting; Pages publishing |
| [`autonomous-guardian.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/autonomous-guardian.yml) | `30 0,12 * * *` | 2 | REVIEW: overlapping recovery/guardian role |
| [`convergence.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/convergence.yml) | `0 */12 * * *` | 2 | REVIEW: optional derived engine |
| [`detection-engine.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/detection-engine.yml) | `30 */12 * * *` | 2 | REVIEW: rules generator git-writer |
| [`omnishield.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/omnishield.yml) | `15 */12 * * *` | 2 | REVIEW: derived engine |
| [`telegram-revenue.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/telegram-revenue.yml) | `0 8 * * *; 0 10 * * *` | 2 | COMMERCIAL REVIEW: permissioned marketing, hard limits |
| [`arsenal.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/arsenal.yml) | `0 6 * * *` | 1 | REVIEW: git-writer; product dependency needed |
| [`automated-backup.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/automated-backup.yml) | `0 1 * * *` | 1 | PROTECT: durable backup and recovery |
| [`commercial-customer-ops-certification.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/commercial-customer-ops-certification.yml) | `17 2 * * *` | 1 | PROTECT: paid customer acceptance, review live credential use |
| [`lead_autoresponder.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/lead_autoresponder.yml) | `0 8 * * *` | 1 | COMMERCIAL REVIEW: consent/suppression, real lead delivery |
| [`revenue-orchestrator.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/revenue-orchestrator.yml) | `0 0 * * *` | 1 | PROTECT: paid entitlement, billing event reconciliation |
| [`sast-security-scan.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/sast-security-scan.yml) | `0 2 * * *` | 1 | PROTECT: security; consider PR+periodic distinct scopes |
| [`report-engine.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/report-engine.yml) | `0 6 * * 1` | weekly | REVIEW: potential overlap weekly PRO brief |
| [`repository-integrity-check.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/repository-integrity-check.yml) | `17 6 * * 1` | weekly | PROTECT: code/registry integrity check |
| [`sbom-generation.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/sbom-generation.yml) | `0 3 * * 1` | weekly | PROTECT: supply chain transparency |
| [`storage-governance.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/storage-governance.yml) | `0 3 * * 1` | weekly | PROTECT/REVIEW: storage pruning and archive semantics |
| [`storage-lifecycle-governance.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/storage-lifecycle-governance.yml) | `0 2 * * 0` | weekly | PROTECT/REVIEW: cold archive, retention checks |
| [`weekly-analyst-briefing.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/weekly-analyst-briefing.yml) | `0 8 * * 1` | weekly | REVIEW: overlap weekly PRO brief; could publish Pages |
| [`weekly-threat-brief.yml`](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/weekly-threat-brief.yml) | `30 2 * * 1` | weekly | PROTECT: PRO subscriber report value |

## 32 workflows without `on.schedule` at inspected revision

- `access-governance-gate.yml`
- `apply-security-headers.yml`
- `bughunter-recon.yml`
- `deploy-revenue-engine.yml`
- `deploy-swarm-live.yml`
- `deploy-worker.yml`
- `enterprise-rollback-governance.yml`
- `environment-promotion.yml`
- `frontend-integrity-sync.yml`
- `gumroad-refresh.yml`
- `intel-gateway-regression-gate.yml`
- `malware-customer-benchmark.yml`
- `master-deployment-orchestrator.yml`
- `nexus-intelligence.yml`
- `p0-r19-live-intel-release-truth.yml`
- `p0-r2-stix-manifest-diagnostic.yml`
- `pages-fast-publish.yml`
- `platform-build-deploy.yml`
- `post-deploy-validation.yml`
- `r2-data-sync.yml`
- `r2-finops-regression-gate.yml`
- `report-generator-regression-gate.yml`
- `revenue-manual-payment-authority-gate.yml`
- `security-key-rotation-audit.yml`
- `sentinel-branding-check.yml`
- `sentinel-factory.yml`
- `swarm-live-regression-gate.yml`
- `swarm-v4470-authenticated-e2e-cert.yml`
- `sync-dashboard.yml`
- `syndicate.yml`
- `telemetry-fabric.yml`
- `v149-hardening.yml`

**Warning:** 'No schedule' DOES NOT mean 'cannot auto-run'. `push`, `pull_request`, `workflow_run`, `release`, and `repository_dispatch` may still start jobs. Some manual workflows can also write production if dispatched. Inspect each top-level trigger and exact `jobs.*.if` independently.

## Production safety disposition

### P0 — protect pending verified replacement
- Authoritative public intel publisher `sentinel-apex.yml`, ingestion `multi-source-intel.yml`, `dashboard-feeds-sync.yml`, report freshness gate `intel-freshness-guard.yml`, customer-paid weekly brief `weekly-threat-brief.yml`.
- Data integrity, backup, customer auth, payment/revenue authority, feed TLP compliance, R2/FinOps budget, VDP security controls, supply-chain checks and rollback.
- Static dependency inventory MUST establish every mutable R2 prefix, cloud Worker, Pages target, external provider, Git writer, package and input secret before de-scheduling these.

### P0 — remove unsafe production auto-mutation only after review
- `deploy-swarm-live.yml` (push-to-Worker production deploy) and `swarm-v4470-authenticated-e2e-cert.yml` (push-to-production-credential mission) are **isolated in draft PR #1018** to become exact-SHA manual-only; do not claim merged.
- `deploy-drift-watchdog.yml` runs 96 times/day and can invoke the publishing workflow; `pages-fast-publish.yml` may auto-publish from pushes/merged PRs. These require a separate **manual release authority / alert-only replacement design** with customer availability consideration; do not turn off before release replacement exists.

### P1 — consolidation candidates, must prove zero missing customer coverage
- Monitor cluster: `sla-heartbeat.yml` + `intel-freshness-guard.yml` + `enterprise-alerts.yml` + `pipeline-staleness-monitor.yml` + `status-monitor.yml` + `enterprise-observability.yml`. Consolidation target: one authoritative freshness/uptime metric, one alert signal, no repeated reader bills and independent external monitor.
- Weekly report cluster: `weekly-threat-brief.yml` is explicitly designed for PRO subscribers; `report-engine.yml` and `weekly-analyst-briefing.yml` need product/endpoints/subscriber comparison before de-scheduling.
- Experimental and supplemental engines: `ai-threat-analyst.yml`, `arsenal.yml`, `bughunter-resilient.yml`, `convergence.yml`, `genesis-powerhouse.yml`, `omnishield.yml`, `precognition-engine.yml`, `sovereign-platform.yml`, `zerodayhunter.yml`, `detection-engine.yml`, and `ai-predictions.yml`. Preserve any real paid API/output dependencies first.
- Revenue outreach: `lead_autoresponder.yml`, `telegram-revenue.yml`, and `revenue-orchestrator.yml` require separate consent, unsubscribes, marketing integrity and order/entitlement verification. Never disable paid entitlement processing because it superficially resembles marketing.

## Acceptance gates for the actual scheduled workflow reduction

1. Full-tree source call graph and mutable R2/Git/Cloudflare/Pages target map; compare with live deployed SHA.
2. Historical run, runtime/CPU, billing/minutes and provider write evidence, not merely file titles.
3. Named customer/API/feed/product coverage and no regression in paid entitlements, latest genuine intel, publisher deduplication, rollback and public release provenance.
4. Benchmarked full suite and actionlint, tested on exact current branch in isolated worktree, with backup and post-change checks.
5. Dedicated **draft** de-scheduling PR(s), no deletes; preserve on-demand emergency workflows and restore tests.
6. Written GitHub Support clearance regarding account restriction, destination account access, staged 10-platform acceptance and approved cutover.

**Current state:** inventory & recommended disposition only. No schedules disabled in this document, no workflow executed, no live product changed.
