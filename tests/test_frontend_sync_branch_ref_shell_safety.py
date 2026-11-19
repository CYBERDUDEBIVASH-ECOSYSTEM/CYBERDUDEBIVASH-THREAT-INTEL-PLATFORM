"""Regression gate: never splice untrusted PR refs into privileged shell commands."""
import os
from pathlib import Path
import subprocess
import unittest

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/frontend-integrity-sync.yml"
STEP = "      - name: Commit and push onto this PR\'s own branch if the registry changed\n"


def _push_step():
    source = WORKFLOW.read_text(encoding="utf-8")
    assert source.count(STEP) == 1, "Expected exactly one checksum sync push step"
    part = source.split(STEP, 1)[1]
    return part.split("\n  # ---------------------------------------------------------------------------", 1)[0]


class TestFrontendSyncShellTrustBoundary(unittest.TestCase):
    def test_pr_head_ref_bound_as_data_not_inserted_into_run_script(self):
        step = _push_step()
        self.assertIn("PR_HEAD_REF: ${{ github.head_ref }}", step)
        self.assertEqual(step.count("        run: |"), 1)
        run = step.split("        run: |", 1)[1]
        self.assertNotIn("${{ github.head_ref }}", run, "Untrusted branch names must not enter bash source text")
        self.assertIn('git push origin "HEAD:${PR_HEAD_REF}"', run)
        self.assertIn('git fetch origin "${PR_HEAD_REF}"', run)
        self.assertIn('git rebase "origin/${PR_HEAD_REF}"', run)
        self.assertNotIn("eval ", run)

    def test_shell_metacharacters_in_branch_name_are_literal_data(self):
        # Git accepts ref names with command-substitution characters.
        # The shell MUST receive them from the environment after parsing.
        value = "fix/$(printf P0_INJECTION_SENTINEL)`printf SECOND_SENTINEL`"
        env = dict(os.environ, PR_HEAD_REF=value)
        result = subprocess.run(
            ["bash", "-c", 'printf "%s" "HEAD:${PR_HEAD_REF}"'],
            env=env, text=True, capture_output=True, check=True,
        )
        self.assertEqual(result.stdout, "HEAD:" + value)
        self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
