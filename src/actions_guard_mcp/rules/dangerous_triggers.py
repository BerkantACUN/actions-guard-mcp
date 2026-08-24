"""AGMCP-101: pull_request_target / workflow_run combined with checking
out the triggering PR's own head ref (or its own fork/repository) — the
exact CoreShop pwn-request shape. Those triggers run with the base
repository's token and secrets, but if the workflow then checks out and
executes the fork's own code, anyone who can open a PR gets that token.

The trigger alone isn't the finding — `pull_request_target` without
touching fork code (e.g. just labeling the PR) is fine. It's the
combination with a checkout of the fork's ref *or* its repository that
matters — `with.repository: ${{ github.event.pull_request.head.repo.full_name }}`
is the same attack shape as `with.ref`, just naming the fork instead of
a commit inside it.

Known limitation: this only reads the literal expression text inside
`with.ref`/`with.repository`. Routing the same value through an `env:`
variable first (`env: {HEAD_SHA: ${{ github.event.pull_request.head.sha }}}`
then `with: {ref: ${{ env.HEAD_SHA }}}`) is functionally identical but
isn't caught — there's no data-flow tracking across steps or `env:`
indirection. Treat a clean scan as "no *direct* fork-checkout expression
found", not a guarantee.
"""

from __future__ import annotations

from ..models import Finding
from ..parser import iter_jobs, iter_steps, normalize_expression

RULE_ID = "AGMCP-101"

_DANGEROUS_TRIGGERS = {"pull_request_target", "workflow_run"}

_PR_HEAD_MARKERS = (
    "github.event.pull_request.head",
    "github.event.workflow_run.head",
    "github.head_ref",
    # github.head_ref covers the ref name GitHub exposes for this exact
    # purpose, but the raw event payload names the same fork branch too
    # — a workflow reading it that way is just as exploitable and isn't
    # caught by the marker above alone.
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.repo.full_name",
    "github.event.pull_request.head.repo.owner.login",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_repository.full_name",
)


def _matches_pr_head(value: object) -> bool:
    if not isinstance(value, str):
        return False
    # Debracket + lowercase before matching: GitHub Actions expressions
    # are case-insensitive and treat github.event['pull_request']['head']
    # as identical to github.event.pull_request.head — matching only the
    # literal dot-notation string above would silently miss both.
    normalized = normalize_expression(value).lower()
    return any(marker in normalized for marker in _PR_HEAD_MARKERS)


def check(workflow: dict, triggers: set[str]) -> list[Finding]:
    active_dangerous = triggers & _DANGEROUS_TRIGGERS
    if not active_dangerous:
        return []

    trigger_list = ", ".join(sorted(active_dangerous))

    findings: list[Finding] = []
    for job_id, job in iter_jobs(workflow):
        for idx, step in iter_steps(job):
            uses = step.get("uses")
            if not isinstance(uses, str) or not uses.startswith("actions/checkout"):
                continue

            with_block = step.get("with")
            if not isinstance(with_block, dict):
                continue

            ref = with_block.get("ref")
            repository = with_block.get("repository")
            fork_field = next(
                (
                    (name, value)
                    for name, value in (("ref", ref), ("repository", repository))
                    if _matches_pr_head(value)
                ),
                None,
            )
            if fork_field is None:
                continue

            field_name, _field_value = fork_field
            findings.append(
                Finding(
                    rule_id=RULE_ID,
                    severity="critical",
                    message=(
                        f"Trigger {trigger_list} runs with the base repository's token, but this "
                        f"step's `with.{field_name}` checks out the triggering PR/run's own code — "
                        "anyone who can open a PR (or trigger the source workflow) can get code "
                        "executed with that token's privileges. See the CoreShop incident for the "
                        "exact shape of this attack."
                    ),
                    location=f"jobs.{job_id}.steps[{idx}]",
                )
            )
    return findings
