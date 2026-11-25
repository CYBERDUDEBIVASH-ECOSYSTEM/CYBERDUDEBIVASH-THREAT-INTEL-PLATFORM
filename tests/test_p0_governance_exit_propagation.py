"""Check every tee-based governance phase and actual Bash exit semantics."""
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/enterprise-governance.yml"


def test_governance_captures_both_pipeline_statuses_immediately():
    source = WORKFLOW.read_text(encoding="utf-8")
    captures = re.findall(
        r'\| tee /tmp/\w+_output\.txt\n'
        r'          PHASE_PIPE_STATUS=\("\$\{PIPESTATUS\[@\]\}"\)\n'
        r'          set -e\n'
        r'          if \[ "\$\{#PHASE_PIPE_STATUS\[@\]\}" -ne 2 \] \|\| '
        r'\[ "\$\{PHASE_PIPE_STATUS\[1\]\}" -ne 0 \]; then\n'
        r'            echo "[^"\n]+"\n'
        r'            exit 1\n'
        r'          fi\n'
        r'          ([A-Z_]+_EXIT)=\$\{PHASE_PIPE_STATUS\[0\]\}', source,
    )
    assert len(captures) == 14
    assert len(set(captures)) == 14
    assert not re.search(r'_EXIT=\$\?', source)


@pytest.mark.parametrize("validator, logger, expected", [
    (0, 0, 0), (1, 0, 1), (3, 0, 3), (127, 0, 127), (0, 1, 1),
])
def test_bash_pipeline_exit_propagation(validator, logger, expected):
    import shutil
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("Bash is required for GitHub runner shell regression")
    script = r'''
set +e
(exit "$1") | (exit "$2")
PHASE_PIPE_STATUS=("${PIPESTATUS[@]}")
set -e
if [ "${#PHASE_PIPE_STATUS[@]}" -ne 2 ] || [ "${PHASE_PIPE_STATUS[1]}" -ne 0 ]; then
  exit 1
fi
exit "${PHASE_PIPE_STATUS[0]}"
'''
    result = subprocess.run([bash, "-e", "-c", script, "test", str(validator), str(logger)],
                            capture_output=True, timeout=10, check=False)
    assert result.returncode == expected
