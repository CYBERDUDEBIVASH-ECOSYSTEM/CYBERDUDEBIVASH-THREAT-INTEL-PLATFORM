# SENTINEL APEX — P0 workflow/release inventory (2026-11-18 UTC)

**Evidence only; no production mutation authorized by this document.** Source repo: `CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM`. Snapshot based on main `f593e0a39608155aa390f0217a3d823eaa1979eb`, source files under `.github/workflows`, and the newest 100 Actions runs (latest observed `2026-11-18T04:31:13Z`). The newest 100 runs do NOT establish 100% workflow health across the 73 definitions.

## Scope/coverage
- **Workflow YAML definitions in main:** 73
- **Distinct named workflows among newest 100 GitHub Actions runs:** 33
- **Known latest failure/cancellation among that window:** 5
- **Unchecked workflows:** anything without an observed current-head run remains NOT CERTIFIED (skipped, disabled, draft, conditional, schedule-only, never-run jobs are not PASS)
- **Ruleset:** #21556637 is `active` but has no `required_status_checks` rule. Main branch's legacy required contexts were empty and enforcement OFF. See #817.

## Observed red/cancelled workflows (do not rerun publisher speculatively)
| Name | Last observed run | Conclusion | Customer impact / next evidence |
|---|---|---|---|
| SENTINEL APEX -- Commercial Customer Operations Certification v201.0 | [44227796120](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/actions/runs/44227796120) | failure | PRO-tier live canary fetch failure; no paid release certification |
| SAST Security Scan -- Bandit + Safety + Semgrep v201.0 | [44225426036](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/actions/runs/44225426036) | failure | 90 Bandit HIGH/HIGH findings, source remediation needed |
| CDB Multi-Source Intelligence Enrichment v201.0 | [44224596730](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/actions/runs/44224596730) | cancelled | Cancelled during ingestion; determine concurrency cause |
| SENTINEL APEX - Production Intel Publisher v201.0 | [44216316892](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/actions/runs/44216316892) | failure | Public report fetch-back mismatch, customer-ready delivery blocked |
| Pipeline Staleness Monitor v201.0 | [44211371855](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/actions/runs/44211371855) | failure | Publisher fully-successful cadence still overdue |

## P0 repository branch with isolated fixes
`fix/p0-report-fetchback-evidence-20261118` — **NOT merged, NOT deployed.** Contains read-only fail-closed report fetch-back diagnostics, R2 report catalogue chronology/registry diagnostics, canonical EPSS percentage parity, bounded untrusted RSS XML+HTTP parsing, and corresponding regression tests. Full Python/Node CI and end-to-end browser validation still pending.

## Release acceptance gates (all mandatory)
1. Enforce exact current-head required checks in #21556637 and demonstrate that one intentionally red check blocks merge. No admin bypass.
2. Resolve each actionable high/high production-scripts SAST finding with reviewable patches or independently justified reviewed exclusions; do not lower scanner sensitivity or skip scripts.
3. Two consecutively successful publisher cycles at the prescribed cadence, with source-backed feed freshness <6h, public health 200, report catalogue generated_at <24h, valid TLP/provenance and nonzero approved public HTML reports returning 200 and matching the catalogue's EPSS/severity/actor metadata.
4. Paid-tier auth, revocation, tenant isolation, checkout/entitlement negative tests and PRO/MSSP/Enterprise live canaries pass on real customer-safe test identities. Do not fabricate transactions or mutate customer records.
5. Operational dashboards, report download, CDN cache and Blogger/CTI distribution (if enabled) independently verified via browser/integration tests with actual 200 responses and content identity.
6. Cloudflare shared-account R2/Workers/Pages quota and current GitHub Actions budget headroom verified, with zero approved overage and a rollback plan; no duplicate R2 publisher.
7. Fail-closed semantics retained for restricted/TLP reports and corrupted manifests; no fake timestamps, sample advisories, suppressed failures, or credentials in logs.

## All main workflow YAML definitions (73, inventory only)
- [`access-governance-gate.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/access-governance-gate.yml)
- [`ai-predictions.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/ai-predictions.yml)
- [`ai-threat-analyst.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/ai-threat-analyst.yml)
- [`apply-security-headers.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/apply-security-headers.yml)
- [`arsenal.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/arsenal.yml)
- [`automated-backup.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/automated-backup.yml)
- [`autonomous-guardian.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/autonomous-guardian.yml)
- [`bughunter-recon.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/bughunter-recon.yml)
- [`bughunter-resilient.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/bughunter-resilient.yml)
- [`commercial-customer-ops-certification.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/commercial-customer-ops-certification.yml)
- [`convergence.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/convergence.yml)
- [`dashboard-feeds-sync.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/dashboard-feeds-sync.yml)
- [`deploy-drift-watchdog.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/deploy-drift-watchdog.yml)
- [`deploy-revenue-engine.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/deploy-revenue-engine.yml)
- [`deploy-swarm-live.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/deploy-swarm-live.yml)
- [`deploy-worker.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/deploy-worker.yml)
- [`detection-engine.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/detection-engine.yml)
- [`enterprise-alerts.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/enterprise-alerts.yml)
- [`enterprise-governance.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/enterprise-governance.yml)
- [`enterprise-intel-quality.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/enterprise-intel-quality.yml)
- [`enterprise-observability.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/enterprise-observability.yml)
- [`enterprise-rollback-governance.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/enterprise-rollback-governance.yml)
- [`environment-promotion.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/environment-promotion.yml)
- [`frontend-integrity-sync.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/frontend-integrity-sync.yml)
- [`generate-and-sync.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/generate-and-sync.yml)
- [`genesis-powerhouse.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/genesis-powerhouse.yml)
- [`gumroad-refresh.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/gumroad-refresh.yml)
- [`intel-freshness-guard.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/intel-freshness-guard.yml)
- [`intel-gateway-regression-gate.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/intel-gateway-regression-gate.yml)
- [`lead_autoresponder.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/lead_autoresponder.yml)
- [`malware-customer-benchmark.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/malware-customer-benchmark.yml)
- [`master-deployment-orchestrator.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/master-deployment-orchestrator.yml)
- [`multi-source-intel.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/multi-source-intel.yml)
- [`nexus-intelligence.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/nexus-intelligence.yml)
- [`omnishield.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/omnishield.yml)
- [`p0-r19-live-intel-release-truth.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/p0-r19-live-intel-release-truth.yml)
- [`p0-r2-stix-manifest-diagnostic.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/p0-r2-stix-manifest-diagnostic.yml)
- [`pages-fast-publish.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/pages-fast-publish.yml)
- [`pipeline-staleness-monitor.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/pipeline-staleness-monitor.yml)
- [`platform-build-deploy.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/platform-build-deploy.yml)
- [`post-deploy-validation.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/post-deploy-validation.yml)
- [`precognition-engine.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/precognition-engine.yml)
- [`production-hardening-final.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/production-hardening-final.yml)
- [`r2-data-sync.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/r2-data-sync.yml)
- [`r2-finops-regression-gate.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/r2-finops-regression-gate.yml)
- [`report-engine.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/report-engine.yml)
- [`report-generator-regression-gate.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/report-generator-regression-gate.yml)
- [`repository-integrity-check.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/repository-integrity-check.yml)
- [`revenue-manual-payment-authority-gate.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/revenue-manual-payment-authority-gate.yml)
- [`revenue-orchestrator.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/revenue-orchestrator.yml)
- [`sast-security-scan.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/sast-security-scan.yml)
- [`sbom-generation.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/sbom-generation.yml)
- [`security-key-rotation-audit.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/security-key-rotation-audit.yml)
- [`self-healing.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/self-healing.yml)
- [`sentinel-apex.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/sentinel-apex.yml)
- [`sentinel-branding-check.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/sentinel-branding-check.yml)
- [`sentinel-factory.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/sentinel-factory.yml)
- [`sla-heartbeat.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/sla-heartbeat.yml)
- [`sovereign-platform.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/sovereign-platform.yml)
- [`status-monitor.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/status-monitor.yml)
- [`storage-governance.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/storage-governance.yml)
- [`storage-lifecycle-governance.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/storage-lifecycle-governance.yml)
- [`swarm-live-regression-gate.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/swarm-live-regression-gate.yml)
- [`swarm-v4470-authenticated-e2e-cert.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/swarm-v4470-authenticated-e2e-cert.yml)
- [`sync-dashboard.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/sync-dashboard.yml)
- [`syndicate.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/syndicate.yml)
- [`telegram-revenue.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/telegram-revenue.yml)
- [`telemetry-fabric.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/telemetry-fabric.yml)
- [`ui-file-guardian.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/ui-file-guardian.yml)
- [`v149-hardening.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/v149-hardening.yml)
- [`weekly-analyst-briefing.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/weekly-analyst-briefing.yml)
- [`weekly-threat-brief.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/weekly-threat-brief.yml)
- [`zerodayhunter.yml`](https://github.com/CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/blob/main/.github/workflows/zerodayhunter.yml)

**Operational status:** P0 active / global customer release **NO-GO**. This document is an inventory and a release contract, **not** 73 independently passed workflow tests.
