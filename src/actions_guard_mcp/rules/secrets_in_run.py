"""AGMCP-105: a secret interpolated directly into a `run:` shell step
instead of passed through `env:`. `with:` inputs and `env:` assignments
are the intended, structured ways to hand a secret to an action or a
script; dropping `${{ secrets.X }}` straight into `run:` puts the raw
value on the shell command line, where it's more exposed than it needs
to be (process listings, shell history in some configurations, and
easier to accidentally echo or log).

Matching runs against the bracket-normalized form of the expression (see
`parser.normalize_expression`) so `${{ secrets['API_TOKEN'] }}` is caught
the same as `${{ secrets.API_TOKEN }}` — GitHub Actions treats the two
as identical, and matching only the dot form would silently miss the
bracket one.
"""

from __future__ import annotations

import re

from ..models import Finding
from ..parser import iter_run_expressions, normalize_expression

RULE_ID = "AGMCP-105"

_SECRET_RE = re.compile(r"\bsecrets\.[A-Za-z_][A-Za-z0-9_]*", re.IGNORECASE)


def check(workflow: dict, triggers: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for job_id, idx, expr in iter_run_expressions(workflow):
        # findall, not search: "${{ secrets.A || secrets.B }}" names two
        # different secrets in one expression — report both, not just
        # whichever the regex happens to see first.
        for secret_ref in _SECRET_RE.findall(normalize_expression(expr)):
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    severity="medium",
                    message=(
                        f"`{secret_ref}` is interpolated directly into a `run:` shell command. "
                        "Pass it through `env:` and reference the environment variable instead — "
                        "the raw secret value stays out of the command line that way."
                    ),
                    location=f"jobs.{job_id}.steps[{idx}].run",
                )
            )
    return findings
