# P0 Swarm production authority quarantine — 2026-11-16

**Status:** REVIEW ONLY / NOT DEPLOYED / NO ACTIONS RUN.  
**Base:** `005a08434b1aac2f70f63623ffc14d2c8132e752`.  
**Scope:** Two source-defined production-affecting Swarm workflows; preserve all live Cloudflare Worker and customer infrastructure.

## Finding and impact

1. `.github/workflows/deploy-swarm-live.yml` previously deployed the Cloudflare `sentinel-apex-swarm-live` Worker automatically when specific files were pushed to `main`. This violated the operator's manual production-release policy, and could take effect unexpectedly upon Actions reinstatement.
2. `.github/workflows/swarm-v4470-authenticated-e2e-cert.yml` previously triggered an authenticated production mission on `push`; the job creates a short-lived demo credential and revokes it later. An ordinary source merge must never create production credentials or consume billable production capacity.
3. The non-mutating `swarm-live-regression-gate.yml` already runs `npm test` and Wrangler dry-run. Preserve this code-validation route while preventing unapproved release/mission execution.

## Changes proposed on this branch only

- Remove `on.push` from the Worker release and authenticated production certification workflows.
- Require `workflow_dispatch.inputs.approved_commit_sha`, a manual dispatch on `refs/heads/main`, and exact equality to `github.sha`.
- Retain non-bot enforcement; keep the existing deploy preflight, post-deploy validation, credential creation, mission checks and revocation steps unchanged.
- Extend existing non-mutating Swarm regression gate to check this invariant on PRs touching these workflows, with `node --test tests/p0-swarm-manual-production-authority.test.mjs`.
- No change to `sentinel-apex.yml`, intelligence freshness, production R2/D1/KV, entitlements, APIs, secrets, or customer-facing routes.

## Local verification command (operator read-only)

```powershell
Set-Location C:\CDB\repos\CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM
git fetch origin hardening/p0-manual-only-swarm-production-authority-20261116
git worktree add --detach C:\CDB\repos\ti-manual-authority-review FETCH_HEAD
Set-Location C:\CDB\repos\ti-manual-authority-review
node --version
node --test tests/p0-swarm-manual-production-authority.test.mjs
```

Expected: 3 tests passed (2 manual-only release authority checks + 1 preserved regression eligibility). This does **not** certify cloud deployment, YAML schema, production credential cleanup on failure, or historical Actions eligibility. Do not run production dispatch.

## Additional release gates

- Use `actionlint` or an equivalent pinned YAML Actions linter against all three changed workflow files.
- Independently verify the default-branch HEAD still corresponds to the reviewed immutable SHA.
- Review every `workflow_run` caller and the production Worker route/bindings before any merge.
- Inspect whether the demo credential is revoked on **every failure path**, not just success; require proof before any authenticated production E2E use.
- Keep manual deployment separately approved; preserve rollback SHA and Cloudflare binding parity.
- Wait for GitHub Support to resolve/approve Actions account ownership. This PR does not restore Actions.

## Rollback

Revert this PR after review, not by forcing a push or enabling scheduled/automatic production deployment. A temporary return to automatic deployment is **not** authorized just because Actions becomes available. Production Worker scripts/routes are untouched here.

**Disposition:** DRAFT / NO-GO for merge until owner validates policy, 3 local tests, workflow YAML lint and clean PR diff. No production changes have been made.
