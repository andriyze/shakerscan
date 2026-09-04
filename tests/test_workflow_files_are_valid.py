"""Every workflow file must parse, and its heredocs must survive YAML.

`release-candidate.yml` shipped with a heredoc body at column 0 inside a
`run: |` block. That closes the block scalar early, so the file did not parse:
GitHub could not read its `on:` trigger, ran it on every push, and failed the
run in zero seconds with "a workflow file issue" -- a permanently red check
that no test covered.
"""
from __future__ import annotations

import pathlib
import re
import subprocess

import pytest
import yaml


_WORKFLOWS = sorted(
    (pathlib.Path(__file__).resolve().parent.parent / ".github" / "workflows").glob("*.yml")
)


def _ids(path):
    return path.name


assert _WORKFLOWS, "no workflow files found"


@pytest.mark.parametrize("path", _WORKFLOWS, ids=_ids)
def test_workflow_parses_and_declares_its_triggers(path):
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(document, dict), f"{path.name} is not a YAML mapping"
    # PyYAML resolves the bare `on` key to the boolean True.
    triggers = document.get("on", document.get(True))
    assert triggers, f"{path.name} declares no triggers"
    assert document.get("jobs"), f"{path.name} declares no jobs"


@pytest.mark.parametrize("path", _WORKFLOWS, ids=_ids)
def test_embedded_heredocs_reach_the_shell_intact(path):
    """A heredoc must end at column 0 after YAML strips block indentation."""
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    for job in (document.get("jobs") or {}).values():
        for step in job.get("steps") or []:
            script = step.get("run")
            if not isinstance(script, str):
                continue
            for marker in ("PY", "EOF", "SH", "JSON"):
                opener = f"<<'{marker}'"
                if opener not in script:
                    continue
                body = script[script.index(opener):].split("\n")
                terminators = [line for line in body if line.strip() == marker]
                assert terminators, (
                    f"{path.name}: heredoc {marker} in step "
                    f"{step.get('name')!r} has no terminator"
                )
                assert terminators[0] == marker, (
                    f"{path.name}: heredoc {marker} terminator in step "
                    f"{step.get('name')!r} is indented ({terminators[0]!r}); "
                    "the shell will not close the heredoc"
                )


def test_embedded_python_programs_compile():
    """A heredoc fed to python3 must be a valid program after YAML processing."""
    for path in _WORKFLOWS:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job in (document.get("jobs") or {}).values():
            for step in job.get("steps") or []:
                script = step.get("run")
                if not isinstance(script, str) or "python3 - " not in script:
                    continue
                for chunk in script.split("python3 - ")[1:]:
                    if "<<'PY'" not in chunk.split("\n", 1)[0]:
                        continue
                    body = chunk.split("\n")[1:]
                    if "PY" not in [line.strip() for line in body]:
                        continue
                    program = "\n".join(body[:[l.strip() for l in body].index("PY")])
                    compile(program, f"<{path.name}>", "exec")


_EXPRESSION = re.compile(r"\$\{\{.*?\}\}", re.DOTALL)


@pytest.mark.parametrize("path", _WORKFLOWS, ids=_ids)
def test_bash_run_blocks_parse(path):
    """Release candidate 33904804151 died in `validate` with "unexpected EOF while looking for
    matching `'`": a run block nested single quotes inside a command substitution, and nothing
    executed that shell before a candidate reached the job. Every bash step must at least parse,
    with workflow expressions replaced by a placeholder."""
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    for job_name, job in (document.get("jobs") or {}).items():
        job_shell = ((job.get("defaults") or {}).get("run") or {}).get("shell")
        for step in job.get("steps") or []:
            script = step.get("run")
            if not isinstance(script, str):
                continue
            shell = str(step.get("shell") or job_shell or "bash")
            if not shell.startswith("bash"):
                continue
            stub = _EXPRESSION.sub("EXPRESSION", script)
            result = subprocess.run(
                ["bash", "-n"], input=stub, text=True, capture_output=True, check=False
            )
            assert result.returncode == 0, (
                f"{path.name}: job {job_name!r} step {step.get('name')!r} does not parse: "
                f"{result.stderr.strip()}"
            )
