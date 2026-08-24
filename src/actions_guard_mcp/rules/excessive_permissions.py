"""AGMCP-104: broad `write` permissions granted — at the workflow level
or a job level — on a workflow that also has a risky trigger
(pull_request_target / workflow_run). The narrower the token's actual
scope, the less a pwn-request-shaped compromise (see dangerous_triggers.py)
can actually do with it. Job-level `permissions:` is a common, legitimate
way to scope tokens per job, and a job-level `write-all` is exactly the
same risk as a workflow-level one — both are checked the same way.
"""

from __future__ import annotations

from ..models import Finding
from ..parser import iter_jobs

RULE_ID = "AGMCP-104"

_RISKY_TRIGGERS = {"pull_request_target", "workflow_run"}


def _findings_for_permissions(permissions, location_prefix: str) -> list[Finding]:
    findings: list[Finding] = []
    if permissions == "write-all":
        findings.append(
            Finding(
                rule_id=RULE_ID,
                severity="high",
                message=(
                    f"`{location_prefix}: write-all` grants every scope the GITHUB_TOKEN supports, "
                    "on a workflow triggered by pull_request_target/workflow_run. Scope this down to "
                    "the specific permissions actually needed."
                ),
                location=location_prefix,
            )
        )
    elif isinstance(permissions, dict):
        for scope, level in permissions.items():
            if level == "write":
                findings.append(
                    Finding(
                        rule_id=RULE_ID,
                        severity="medium",
                        message=(
                            f"`{location_prefix}.{scope}: write` is granted on a workflow triggered "
                            "by pull_request_target/workflow_run. Confirm this actually needs write "
                            f"access to {scope}, not just read."
                        ),
                        location=f"{location_prefix}.{scope}",
                    )
                )
    return findings


def check(workflow: dict, triggers: set[str]) -> list[Finding]:
    if not (triggers & _RISKY_TRIGGERS):
        return []

    findings: list[Finding] = []
    findings.extend(_findings_for_permissions(workflow.get("permissions"), "permissions"))

    for job_id, job in iter_jobs(workflow):
        findings.extend(
            _findings_for_permissions(job.get("permissions"), f"jobs.{job_id}.permissions")
        )

    return findings
