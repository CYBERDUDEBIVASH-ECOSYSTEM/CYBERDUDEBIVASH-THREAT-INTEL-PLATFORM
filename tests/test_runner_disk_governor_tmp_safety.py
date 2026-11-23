"""P0 zero-trust: disk reclaim never deletes files outside owned runner scratch."""
from __future__ import annotations

import os
from pathlib import Path
import time

import pytest

from scripts import runner_disk_governor as governor


MARKER = "SENTINEL_APEX_RUNNER_SCRATCH_V1"


def setup_runner(tmp_path, monkeypatch, *, mark=True):
    runner = tmp_path / "runner-temp"
    runner.mkdir()
    scratch = runner / "cdb-apex-scratch"
    scratch.mkdir()
    if mark:
        (scratch / ".cdb-apex-owned").write_text(MARKER, encoding="utf-8")
    monkeypatch.setenv("RUNNER_TEMP", str(runner))
    return runner, scratch


def age(path: Path):
    old = time.time() - 2 * 86400
    os.utime(path, (old, old))


def test_missing_runner_temp_is_safe_noop(tmp_path, monkeypatch):
    monkeypatch.delenv("RUNNER_TEMP", raising=False)
    unrelated = tmp_path / "important.log"
    unrelated.write_text("must survive")
    assert governor.reclaim_tmp() == 0
    assert unrelated.read_text() == "must survive"


@pytest.mark.parametrize("marker", ["missing", "wrong", "symlink"])
def test_absent_or_untrusted_marker_preserves_scratch(tmp_path, monkeypatch, marker):
    runner, scratch = setup_runner(tmp_path, monkeypatch, mark=False)
    sensitive = scratch / "operator.zip"
    sensitive.write_text("keep")
    age(sensitive)
    proof = scratch / ".cdb-apex-owned"
    if marker == "wrong":
        proof.write_text("arbitrary")
    elif marker == "symlink":
        target = runner / "outside-proof"
        target.write_text(MARKER)
        try:
            proof.symlink_to(target)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks unavailable")
    assert governor.reclaim_tmp() == 0
    assert sensitive.read_text() == "keep"


def test_only_stale_owned_direct_children_reclaimed(tmp_path, monkeypatch):
    runner, scratch = setup_runner(tmp_path, monkeypatch)
    stale_file = scratch / "stale.tmp"
    stale_file.write_text("old")
    age(stale_file)
    stale_dir = scratch / "stale-files"
    stale_dir.mkdir()
    (stale_dir / "old.bin").write_text("old")
    age(stale_dir)
    recent_file = scratch / "current.tmp"
    recent_file.write_text("keep")
    unrelated = runner / "operator.log"
    unrelated.write_text("protected")
    pip_dir = runner / "pip-unrelated"
    pip_dir.mkdir()
    (pip_dir / "active.txt").write_text("protected")
    assert governor.reclaim_tmp() == 2
    assert not stale_file.exists()
    assert not stale_dir.exists()
    assert recent_file.read_text() == "keep"
    assert unrelated.read_text() == "protected"
    assert (pip_dir / "active.txt").read_text() == "protected"
    assert (scratch / ".cdb-apex-owned").read_text() == MARKER


def test_symlink_inside_owned_scratch_is_never_removed(tmp_path, monkeypatch):
    runner, scratch = setup_runner(tmp_path, monkeypatch)
    outside = tmp_path / "customer-data.json"
    outside.write_text("must survive")
    alias = scratch / "old-link.json"
    try:
        alias.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    assert governor.reclaim_tmp() == 0
    assert alias.is_symlink()
    assert outside.read_text() == "must survive"


def test_symlink_scratch_root_is_rejected(tmp_path, monkeypatch):
    runner = tmp_path / "runner-temp"
    runner.mkdir()
    elsewhere = tmp_path / "unrelated"
    elsewhere.mkdir()
    (elsewhere / ".cdb-apex-owned").write_text(MARKER)
    stale = elsewhere / "private.tmp"
    stale.write_text("must survive")
    age(stale)
    try:
        (runner / "cdb-apex-scratch").symlink_to(elsewhere, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    monkeypatch.setenv("RUNNER_TEMP", str(runner))
    assert governor.reclaim_tmp() == 0
    assert stale.read_text() == "must survive"


def test_relative_runner_temp_cannot_select_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "runner-temp").mkdir()
    monkeypatch.setenv("RUNNER_TEMP", "runner-temp")
    assert governor.reclaim_tmp() == 0
