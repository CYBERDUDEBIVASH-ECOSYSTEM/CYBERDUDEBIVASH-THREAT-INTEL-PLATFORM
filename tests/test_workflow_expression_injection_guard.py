"""Static regression guard: no workflow may splice attacker-influenced text, or a secret, into script source.

GitHub expands ``${{ ... }}`` as TEXT before a ``run:`` script (or an ``actions/github-script`` ``script:``) is
parsed. A free-text workflow_dispatch input, a PR/issue/comment body or a branch name placed there becomes shell,
Python or JavaScript source. The safe pattern is to pass the value through ``env:`` and read it as ``"$NAME"``
(or ``os.environ`` / ``process.env``); secrets belong in ``env:`` too.

Not flagged, because they cannot carry arbitrary text:
  * ``choice`` / ``boolean`` / ``environment`` / ``number`` workflow inputs (GitHub rejects other values), and
  * an input the job-level ``if:`` pins to the checked-out commit (``inputs.x == github.sha``), which is how
    deploy-revenue-engine.yml proves its approved SHA before any step runs.

Read-only: parses YAML only, never runs a workflow.
"""
import re
from pathlib import Path

import pytest
import yaml

WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"

ALWAYS_UNTRUSTED = re.compile(
    r"\$\{\{[^}]*?\b(?:github\.head_ref|github\.event\.(?:"
    r"pull_request\.(?:title|body|head\.ref|head\.label|head\.repo\.full_name)"
    r"|issue\.(?:title|body)|comment\.body|review\.body|review_comment\.body"
    r"|head_commit\.(?:message|author\.(?:name|email))"
    r"|workflow_run\.(?:head_branch|head_commit\.message|display_title|head_repository\.full_name)"
    r"|client_payload))\b[^}]*\}\}"
)
INPUT_EXPR = re.compile(r"\$\{\{[^}]*?\b(?:github\.event\.)?inputs\.([A-Za-z0-9_-]+)[^}]*\}\}")
SECRET_EXPR = re.compile(r"\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}")
ENFORCED_TYPES = {"choice", "boolean", "environment", "number"}


def _declared_inputs(doc):
    on = doc.get("on", doc.get(True)) or {}
    if not isinstance(on, dict):
        return {}
    declared = {}
    for trigger in ("workflow_dispatch", "workflow_call"):
        for name, spec in ((on.get(trigger) or {}).get("inputs") or {}).items():
            declared[name] = (spec or {}).get("type", "string")
    return declared


def find_violations(doc, filename="workflow"):
    """Return ``[(kind, where, expression)]`` for every unsafe interpolation in script source."""
    out = []
    declared = _declared_inputs(doc)
    for job_name, job in (doc.get("jobs") or {}).items():
        guard = str(job.get("if") or "")
        pinned = {
            name for name in declared
            if re.search(rf"(?:github\.event\.)?inputs\.{re.escape(name)}\s*==\s*github\.sha", guard)
            or re.search(rf"github\.sha\s*==\s*(?:github\.event\.)?inputs\.{re.escape(name)}\b", guard)
        }
        for index, step in enumerate(job.get("steps") or []):
            where = f"{filename}:{job_name}:{step.get('name', f'step-{index}')}"
            sources = []
            if isinstance(step.get("run"), str):
                sources.append(step["run"])
            if str(step.get("uses", "")).startswith("actions/github-script") and isinstance((step.get("with") or {}).get("script"), str):
                sources.append(step["with"]["script"])
            for text in sources:
                for m in ALWAYS_UNTRUSTED.finditer(text):
                    out.append(("untrusted-expression", where, m.group(0)))
                for m in INPUT_EXPR.finditer(text):
                    name = m.group(1)
                    if declared.get(name) in ENFORCED_TYPES or name in pinned:
                        continue
                    out.append(("free-text-input", where, m.group(0)))
                for m in SECRET_EXPR.finditer(text):
                    out.append(("secret-in-script", where, m.group(0)))
    return out


def _wf(on, steps, job_if=None):
    job = {"steps": steps}
    if job_if:
        job["if"] = job_if
    return {"on": on, "jobs": {"j": job}}


DISPATCH = {"workflow_dispatch": {"inputs": {
    "note": {"type": "string"}, "mode": {"type": "choice", "options": ["a", "b"]},
    "dry": {"type": "boolean"}, "sha": {"type": "string"}}}}


class TestDetector:
    def test_flags_free_text_input_in_shell(self):
        v = find_violations(_wf(DISPATCH, [{"name": "s", "run": 'echo "${{ github.event.inputs.note }}"'}]))
        assert [k for k, *_ in v] == ["free-text-input"]

    def test_flags_short_inputs_form_and_defaulted_expression(self):
        for expr in ("inputs.note", "github.event.inputs.note || 'N/A'", "inputs.note || 'x'"):
            v = find_violations(_wf(DISPATCH, [{"name": "s", "run": "echo \"${{ %s }}\"" % expr}]))
            assert len(v) == 1, expr

    def test_flags_undeclared_input(self):
        assert find_violations(_wf(DISPATCH, [{"name": "s", "run": 'echo "${{ inputs.ghost }}"'}]))

    def test_choice_and_boolean_inputs_are_enforced_by_github(self):
        run = 'echo "${{ github.event.inputs.mode }} ${{ inputs.dry }}"'
        assert find_violations(_wf(DISPATCH, [{"name": "s", "run": run}])) == []

    def test_input_pinned_to_the_commit_by_the_job_if_is_safe(self):
        wf = _wf(DISPATCH, [{"name": "s", "run": 'test "$X" = "${{ inputs.sha }}"'}],
                 job_if="github.event_name == 'workflow_dispatch' && inputs.sha == github.sha")
        assert find_violations(wf) == []
        unpinned = _wf(DISPATCH, [{"name": "s", "run": 'test "$X" = "${{ inputs.sha }}"'}],
                       job_if="github.event_name == 'workflow_dispatch'")
        assert find_violations(unpinned)

    def test_flags_branch_name_and_pr_issue_text(self):
        for expr in ("github.head_ref", "github.event.pull_request.title", "github.event.issue.body",
                     "github.event.comment.body", "github.event.head_commit.message"):
            v = find_violations(_wf({"pull_request": {}}, [{"name": "s", "run": "echo \"${{ %s }}\"" % expr}]))
            assert [k for k, *_ in v] == ["untrusted-expression"], expr

    def test_flags_secret_in_script_and_untrusted_text_in_github_script(self):
        assert find_violations(_wf(DISPATCH, [{"name": "s", "run": '[ -z "${{ secrets.TOKEN }}" ]'}]))[0][0] == "secret-in-script"
        gs = {"name": "g", "uses": "actions/github-script@abc", "with": {"script": "const t = '${{ github.event.inputs.note }}';"}}
        assert len(find_violations(_wf(DISPATCH, [gs]))) == 1

    def test_accepts_the_env_pattern_and_non_script_contexts(self):
        safe = [
            {"name": "env", "env": {"NOTE": "${{ github.event.inputs.note }}", "T": "${{ secrets.TOKEN }}"},
             "run": 'echo "$NOTE"; [ -n "$T" ]'},
            {"name": "with", "uses": "actions/checkout@abc", "with": {"ref": "${{ github.head_ref }}"}},
            {"name": "trusted", "run": 'echo "${{ github.run_id }} ${{ github.sha }} ${{ github.actor }}"'},
        ]
        assert find_violations(_wf(DISPATCH, safe)) == []


@pytest.mark.parametrize("path", sorted(WORKFLOWS.glob("*.y*ml")), ids=lambda p: p.name)
def test_workflow_has_no_unsafe_interpolation_in_script_source(path):
    doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    violations = find_violations(doc, path.name)
    assert not violations, (
        "Move each value into the step's env: block and read it as \"$NAME\" (or os.environ):\n"
        + "\n".join(f"  {k}  {w}  {e}" for k, w, e in violations)
    )
