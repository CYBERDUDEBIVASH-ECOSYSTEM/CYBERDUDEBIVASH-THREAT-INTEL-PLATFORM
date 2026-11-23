#!/usr/bin/env python3
"""P0: bounded, fail-closed Semgrep gate for changed Gateway JavaScript.

Only the exact PR/push source diff is scanned, without executing source code,
accessing Cloudflare/customer data, or permitting success-shaped fake reports.
Manual runs and first pushes scan the full source inventory explicitly.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

SOURCE = "workers/intel-gateway/src/"
EXTENSIONS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx"}
SHA = re.compile(r"^[0-9a-fA-F]{40}$")
MAX_TARGETS = 1000
REPORT = ".gateway-js-sast-semgrep.json"


def source_targets(root: Path, names: list[str]) -> list[str]:
    root = root.resolve()
    source_dir = (root / SOURCE).resolve()
    result = []
    for name in names:
        if not isinstance(name, str) or not name.startswith(SOURCE):
            raise ValueError("JS_SAST_UNTRUSTED_PATH")
        if "\\" in name or "\x00" in name:
            raise ValueError("JS_SAST_UNTRUSTED_PATH")
        posix = PurePosixPath(name)
        if posix.is_absolute() or ".." in posix.parts:
            raise ValueError("JS_SAST_UNTRUSTED_PATH")
        if posix.suffix not in EXTENSIONS:
            continue
        path = root / name
        if path.is_symlink():
            raise ValueError("JS_SAST_SYMLINK_SOURCE")
        actual = path.resolve()
        if not actual.is_relative_to(source_dir):
            raise ValueError("JS_SAST_PATH_ESCAPE")
        if not path.exists():
            continue  # Removed file: no source exists to inspect.
        if not path.is_file():
            raise ValueError("JS_SAST_NOT_A_FILE")
        result.append(path.relative_to(root).as_posix())
    result = sorted(set(result))
    if len(result) > MAX_TARGETS:
        raise ValueError("JS_SAST_TOO_MANY_TARGETS")
    return result


def verify_checkout(root: Path, head: str) -> None:
    if not SHA.fullmatch(head):
        raise ValueError("JS_SAST_INVALID_HEAD_SHA")
    current = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True,
        capture_output=True, text=True,
    ).stdout.strip()
    if current.lower() != head.lower():
        raise ValueError("JS_SAST_HEAD_MISMATCH")


def select_targets(root: Path, event: str, base: str, head: str) -> list[str]:
    if event in {"pull_request", "push"} and SHA.fullmatch(base or "") and base != "0" * 40:
        if not SHA.fullmatch(head or ""):
            raise ValueError("JS_SAST_INVALID_HEAD_SHA")
        subprocess.run(
            ["git", "fetch", "--quiet", "--no-tags", "--depth=1",
             "--filter=blob:none", "origin", base, head],
            cwd=root, check=True, capture_output=True,
        )
        diff = subprocess.run(
            ["git", "diff", "--name-only", "--no-renames", "--diff-filter=ACM",
             "-z", base, head, "--", SOURCE],
            cwd=root, check=True, capture_output=True,
        ).stdout
        return source_targets(root, [x.decode("utf-8") for x in diff.split(b"\0") if x])

    if event == "pull_request" or (event == "push" and base != "0" * 40):
        raise ValueError("JS_SAST_MISSING_DIFF_AUTHORITY")
    # Explicit manual execution and the first-ever push cannot infer a diff.
    return source_targets(
        root, [p.relative_to(root).as_posix()
               for p in (root / SOURCE).rglob("*") if p.is_file()]
    )


def build_scope(root: Path, destination: Path) -> int:
    event = os.environ.get("SAST_EVENT", "")
    if event not in {"pull_request", "push", "workflow_dispatch"}:
        raise ValueError("JS_SAST_UNEXPECTED_EVENT")
    head = os.environ.get("SAST_HEAD_SHA", "")
    base = os.environ.get("SAST_BASE_SHA", "")
    verify_checkout(root, head)
    targets = select_targets(root, event, base, head)
    destination.write_text(json.dumps({
        "event": event, "base_sha": base, "head_sha": head,
        "target_count": len(targets), "targets": targets,
    }, indent=2), encoding="utf-8")
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write(f"need_scan={'true' if targets else 'false'}\n")
    print(f"Gateway JavaScript SAST: {len(targets)} exact-head targets; event={event}")
    return 0


def validate_report(report: object, targets: list[str]) -> list[dict]:
    if not isinstance(report, dict) or not isinstance(report.get("version"), str):
        raise ValueError("JS_SAST_REPORT_INVALID")
    findings, errors = report.get("results"), report.get("errors")
    paths = report.get("paths")
    if not isinstance(findings, list) or not isinstance(errors, list) or not isinstance(paths, dict):
        raise ValueError("JS_SAST_REPORT_INVALID")
    scanned = paths.get("scanned")
    if not isinstance(scanned, list) or not all(isinstance(x, str) for x in scanned):
        raise ValueError("JS_SAST_SCAN_COVERAGE_UNKNOWN")
    normalized = {PurePosixPath(x).as_posix().removeprefix("./") for x in scanned}
    if not set(targets).issubset(normalized):
        raise ValueError("JS_SAST_INCOMPLETE_SCAN")
    if errors:
        raise RuntimeError("JS_SAST_SCANNER_REPORTED_ERRORS")
    if not all(isinstance(x, dict) for x in findings):
        raise ValueError("JS_SAST_FINDINGS_INVALID")
    return findings


def scan(root: Path, manifest: Path) -> int:
    doc = json.loads(manifest.read_text(encoding="utf-8"))
    names = doc.get("targets")
    head = doc.get("head_sha")
    if (not isinstance(names, list) or len(names) > MAX_TARGETS
            or not all(isinstance(x, str) for x in names)
            or not isinstance(head, str)):
        raise ValueError("JS_SAST_INVALID_MANIFEST")
    verify_checkout(root, head)
    targets = source_targets(root, names)
    if targets != names or doc.get("target_count") != len(targets):
        raise ValueError("JS_SAST_TARGET_MANIFEST_MISMATCH")
    if not targets:
        print("JS_SAST_NON_APPLICABLE: exact diff has no Gateway JS/TS source")
        return 0
    report_path = root / REPORT
    if report_path.exists():
        report_path.unlink()  # Never trust a stale report from a previous scan.
    result = subprocess.run(
        ["semgrep", "scan", "--config", "p/javascript",
         "--config", "p/secrets", "--severity", "ERROR", "--error",
         "--timeout", "45", "--jobs", "2", "--metrics=off",
         "--json", "--output", str(report_path), *targets],
        cwd=root, capture_output=True, text=True, timeout=450,
    )
    if not report_path.is_file():
        raise RuntimeError("JS_SAST_REPORT_MISSING")
    findings = validate_report(
        json.loads(report_path.read_text(encoding="utf-8")), targets
    )
    # Log metadata only: finding code excerpts can contain real secrets.
    for item in findings[:30]:
        path = str(item.get("path", ""))
        rule = str(item.get("check_id", "UNKNOWN"))[:100]
        start = item.get("start") if isinstance(item.get("start"), dict) else {}
        if path not in targets:
            path = "UNKNOWN_TARGET"
        print(json.dumps({"scanner": "semgrep", "path": path,
                          "rule": rule, "line": start.get("line")}))
    if result.returncode != 0:
        raise RuntimeError("JS_SAST_SCANNER_FAILED_OR_FINDINGS")
    if findings:
        raise RuntimeError("JS_SAST_SECURITY_FINDINGS")
    print(f"JS_SAST_PASS: Semgrep ERROR rules checked {len(targets)} exact-head JS/TS sources")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--scope-file", type=Path)
    mode.add_argument("--scan-from", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        return (build_scope(root, args.scope_file.resolve())
                if args.scope_file is not None else scan(root, args.scan_from.resolve()))
    except (OSError, ValueError, RuntimeError, UnicodeError, json.JSONDecodeError,
            subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        # Never echo subprocess stderr or source snippets: secret-safe failure.
        print(f"::error::Gateway JavaScript SAST fail-closed: {type(exc).__name__}",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
