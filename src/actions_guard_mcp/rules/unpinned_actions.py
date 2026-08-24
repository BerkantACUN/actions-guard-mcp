"""AGMCP-103: a third-party action or reusable workflow referenced by a
mutable tag or branch instead of a pinned commit SHA — the tj-actions
shape. When a tag gets silently repointed (compromised maintainer
account, compromised publish token, ...), every workflow using `@v4`
starts running the new code with no version bump anyone would notice.

Checks both step-level `uses:` (a regular action) and job-level `uses:`
(a reusable workflow call, `jobs.<id>.uses: owner/repo/.github/workflows/x.yml@ref`
— a job shaped this way has no `steps:` at all, so it needs its own walk)
since both name a mutable-or-pinned ref the exact same way.
"""

from __future__ import annotations

import re

from ..models import Finding
from ..parser import iter_jobs, iter_reusable_workflow_calls, iter_steps

RULE_ID = "AGMCP-103"

# Git/GitHub resolve hex commit SHAs case-insensitively — a SHA pasted
# in uppercase is exactly as pinned as one in lowercase.
_FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)

# GitHub's own org. Still worth pinning in principle, but a materially
# different trust boundary than an arbitrary third party — flagging it
# by default would bury every real third-party finding in noise.
_FIRST_PARTY_OWNERS = {"actions", "github"}


def _unpinned_finding(uses: str, location: str) -> Finding | None:
    if uses.startswith("./"):
        return None  # local composite action — pinned by definition, same commit as the workflow

    if uses.startswith("docker://"):
        # A Docker image ref is exactly as mutable as a git tag unless
        # it names a content digest — `alpine:3.18`, or a bare `alpine`
        # (implicit `latest`), can be repointed to different bytes at
        # any time with no version bump to notice.
        image_ref = uses[len("docker://") :]
        if "@sha256:" in image_ref:
            return None
        return Finding(
            rule_id=RULE_ID,
            severity="high",
            message=(
                f"`{uses}` is a Docker image reference not pinned to a sha256 digest. "
                "A mutable tag (or the implicit `latest`) can be repointed to a different "
                "image with no version bump to notice. Pin with `@sha256:<digest>` instead."
            ),
            location=location,
        )

    if "@" not in uses:
        return None

    path, ref = uses.rsplit("@", 1)
    owner = path.split("/", 1)[0]
    if owner in _FIRST_PARTY_OWNERS:
        return None
    if _FULL_SHA_RE.match(ref):
        return None

    return Finding(
        rule_id=RULE_ID,
        severity="high",
        message=(
            f"`{uses}` is pinned to a mutable ref (`{ref}`), not a commit SHA. "
            f"If `{owner}` is ever compromised, this ref can be repointed to malicious "
            "code with no version bump to notice. Pin to the full 40-character commit SHA."
        ),
        location=location,
    )


def check(workflow: dict, triggers: set[str]) -> list[Finding]:
    findings: list[Finding] = []

    for job_id, job in iter_jobs(workflow):
        for idx, step in iter_steps(job):
            uses = step.get("uses")
            if not isinstance(uses, str):
                continue
            finding = _unpinned_finding(uses, f"jobs.{job_id}.steps[{idx}]")
            if finding is not None:
                findings.append(finding)

    for job_id, uses in iter_reusable_workflow_calls(workflow):
        finding = _unpinned_finding(uses, f"jobs.{job_id}.uses")
        if finding is not None:
            findings.append(finding)

    return findings
