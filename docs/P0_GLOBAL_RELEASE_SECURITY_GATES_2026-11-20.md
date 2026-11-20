# SENTINEL APEX — P0 Global Security & Customer Release Gates

**Evidence checkpoint:** 2026-11-20 (Asia/Kolkata).  
**Repository:** `CYBERDUDEBIVASH-ECOSYSTEM/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM`  
**Integration candidate:** `fix/p0-mesh-jwt-and-landing-xss-20261120-r1`  
**Observed baseline:** `main` SHA `911995b7f85f8c18588e575225373a7c3bd51af3`.  
**Verdict:** **NO-GO**. This document does not authorize deployment, payment processing, resource upgrades, publishing, or customer communication.

## Release policy

A PASS is supported only by an immutable artifact, test/run ID, executable command, captured result, and timestamp. Source code appearing correct is **IMPLEMENTED**, not **TESTED** or **DEPLOYED**. A public page rendering does not certify the Worker API. All customer identities, API keys, payment tokens and service secrets must be omitted/redacted from release evidence.

- **P0:** customer-impacting outage, denied/refunded access bypass, customer data leakage, secret exposure, incorrect paid billing, report-publication corruption, R2 integrity failure, unauthenticated mutation, or unverified commercial intelligence served as live
- **P1:** browser trust-boundary inconsistencies, insufficient audit metadata, weak CSP, residual library risk, or unvalidated rollback
- **P2:** documentation, nonblocking presentation, or developer experience gaps

Required gate result is **GO** only if *every* P0 requirement below is independently PASS and rollout/rollback approvals exist. Missing, skipped, flaky, expired, or unverifiable evidence counts as **BLOCKED**.

## Mandatory certification matrix

| Gate | Scope and minimum negative control | Required evidence | Current state |
|---|---|---|---|
| SEC-01 Source integrity | Pin exact commit; compare branch to fresh main; review all changed paths and dependency lock files; reject unexpected changes | commit SHA, diff, independent reviewer | OPEN |
| SEC-02 Branch protection | No-bypass main protection, required checks (Node/Python/SAST/secret scanning), signed/reviewed merge where enforced | ruleset readback + attempted rejected unsafe merge (non-production probe) | OPEN (#817) |
| SEC-03 Authentication | Missing/invalid/expired JWT, wrong issuer/audience, refunded key, revoked token, expired entitlement, forged admin identity all denied | isolated suite + integration test log | OPEN (#596/#913) |
| SEC-04 Strong consistency | Suspended/refunded customer denied *before* private Mesh admission; reactivated customer accepted after authoritative check; authority outage fails closed; flag-off incurs zero DO reads | Node tests + controlled staging trace and DO request budget | BRANCH FIX; NOT PROD VERIFIED |
| SEC-05 Mesh response certification | Admission and completion bound to same mission/execution; rejected or contradictory completion never receives certified header; oversized output fails closed | full Worker integration test and Mesh contract canary | BRANCH FIX; NOT PROD VERIFIED |
| SEC-06 Authorization / IDOR | FREE/PRO/ENTERPRISE/MSSP tier boundaries, per-tenant isolation, route scopes, unauthenticated mutations and admin routes | matrix of 401/403/2xx from dedicated test identities, cross-tenant negative controls | OPEN |
| SEC-07 Webhooks / payments | Razorpay HMAC signature mismatch and replay, Gumroad secret/duplicate handling, unexpected order state, refund and chargeback access cutoff | sandbox fixtures and idempotency state readback; NO real charge | OPEN (#913) |
| SEC-08 CORS + cache | Unknown Origin never reflected on authenticated responses, public read-only wildcard only, preflight no auth bypass, private/cache-control barriers | OPTIONS + authenticated response/cached-variant tests | OPEN |
| SEC-09 Browser XSS / redirect | API errors rendered as text, forbidden checkout redirect blocked, support link noopener/noreferrer, malicious HTML payload inert | Node DOM tests, browser CSP checks | BRANCH FIX; FULL BROWSER TEST PENDING |
| SEC-10 SSRF / egress | Webhook destination DNS/IP private ranges and redirects rejected; external fetch paths allowlisted; bounded request timeout/body | SSRF test harness; no live targets | OPEN |
| SEC-11 Intelligence provenance | Public TLP-CLEAR only, report retirement not valid, source evidence and IOCs supported, internal/private reports never public | publisher artifact signatures/provenance and customer route negative controls | OPEN (#721/#925) |
| SEC-12 R2 + catalogs | HEAD 404 distinguished from permission/network; no catalog purge on failed verification; exact-key catalog parity; report HTML byte identity through public CDN | complete pytest + authenticated HEAD/sampled checksum + publication audit | BRANCH FIX; LIVE IDENTITY OPEN (#1041) |
| SEC-13 Freshness & truth | Last authoritative UTC generation within defined SLA; stale feed withheld from realtime; no stale-as-live demos, badges or paid data | matching API/Worker/Pages timestamps + customer browser canary | OPEN (#788/#1040) |
| SEC-14 CI/SAST/SCA | Negative controls trip required Node/Python/Bandit/Semgrep/secret/dependency gates; no skipped scanner can count PASS | run links, reports, policy enforcement | OPEN (#806/#817) |
| SEC-15 Availability and abuse | Health, live JSON, paid 2xx, auth 401, quota 429, retry-after, rate-limiter continuity, dependency failure behavior | staged HTTP traces under bounded load | OPEN |
| SEC-16 DR + rollback | Approved known-good Worker/Pages SHA, restore dry run for R2/D1/KV, backup integrity, canary rollback with independent readback | runbook, pre/post hashes and authorized rollback plan | OPEN (#815) |
| SEC-17 FinOps | Daily and monthly bound for Worker invocations, R2 PUT/HEAD/GET, KV, DO, Actions, D1, Pages; confirmed plan and zero overage | authenticated usage/plan readback + incremental cost assessment | OPEN (#810) |
| SEC-18 Commercial delivery | Legitimate sandbox checkout → payment evidence → customer key/entitlement → fresh paid data → export → refund/expiry denial | documented controlled customer test IDs; no fabricated collected revenue | OPEN (#913) |
| SEC-19 Observability/privacy | Non-secret request ID, auth-denial/freshness/error classifications, safe retention, no raw tokens in logs or URLs | log excerpts with PII redacted and retention setting | OPEN |
| SEC-20 Operational approval | Named reviewer, protected merge approval, staged deployment approval, verified canary, rollback owner; no unapproved customer contact | approvals and release-signoff record | OPEN |

## Branch-only regression entry points

Use the existing `Report Generator Regression Gate` rather than creating a new cron/job. On a disposable runner with the repository checked out at the exact candidate SHA:

```bash
# Root of repository: no cloud calls from these unit test paths
node --test tests/landing-dom-xss.test.cjs \
  workers/intel-gateway/src/__tests__/apex-mesh-boundary.test.js

python -m pytest -q \
  tests/test_r2_integrity_head_tristate.py \
  tests/test_r2_report_publisher_bounded_io.py \
  tests/test_r2_retired_report_validation_state.py \
  tests/test_report_registry_single_writer.py
```

Run the rest of the required workflow, SAST, secret scanning, dependency audit, and cross-Worker negative controls too. These commands **have not been certified as full-suite PASS** at this checkpoint.

## Specific metered-cost release hazard

The baseline `workers/intel-gateway/wrangler.toml` **sets**
`AUTH_STRONG_CONSISTENCY_ENABLED="true"` in default and production variables. The new
Mesh pre-admission checks reuse the existing `GUMROAD_PROVISIONING_LOCK`
Durable Object, adding up to **one extra strong-auth read per JWT** or **two
per API key** before the core gateway's own authority reads. When the flag
is absent/false there are no incremental strong-auth reads.

This changes usage but provisions no new resource. **Do not deploy until**
current Cloudflare plan limits and actual DO request volume are verified, an
upper bound is approved, and the new security cost is explicitly accepted.
No quota increase or new subscription is authorized by this document.

## Safe rollout sequence (requires separately obtained authorization)

1. Freeze and hash existing production Worker and Pages artifacts; record current public API behavior and live report identity
2. Validate exact candidate branch through protected required checks and security reviewer
3. Reconcile R2 provenance and current authoritative feed; do not delete stale catalogs or re-date historical evidence to fabricate freshness
4. Run read-only production probes and approved sandbox customer identity/payment tests
5. Check Cloudflare/Actions usage budget, alert thresholds, and rollback resources
6. Obtain explicit guarded release approval and stage a small canary with monitored error-rate, freshness, billing/auth and report-delivery metrics
7. Stop and roll back if any P0 regression or cost threshold is crossed; revalidate original baselines
8. Only after customer smoke and rollback proof, record the release artifact and global GO signoff

**Never promote an isolated code change as deployed, an extracted-function test as full CI, or a public homepage as proof of authenticated customer delivery.**
