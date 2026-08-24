"""Shared helpers for walking a parsed GitHub Actions workflow — trigger
normalization (on: can be a string, a list, or a mapping), job/step
iteration, and ${{ }} expression extraction, so every rule walks the
structure and reads expressions the same way. A regex or a walk copied
into two rule files instead of shared here is exactly how one rule gets
a fix the other silently doesn't — see EXPR_RE's docstring."""

from __future__ import annotations

import re
from collections.abc import Iterator


def get_triggers(workflow: dict) -> set[str]:
    """Normalize `on:` (a bare string, a list of strings, or a mapping)
    into the set of trigger names it declares. YAML parses the bare
    word `on` as the boolean True, so this checks both keys."""
    on = workflow.get("on", workflow.get(True))
    if on is None:
        return set()
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {t for t in on if isinstance(t, str)}
    if isinstance(on, dict):
        return {k for k in on if isinstance(k, str)}
    return set()


def iter_jobs(workflow: dict) -> Iterator[tuple[str, dict]]:
    jobs = workflow.get("jobs")
    if not isinstance(jobs, dict):
        return
    for job_id, job in jobs.items():
        if isinstance(job, dict):
            yield job_id, job


def iter_steps(job: dict) -> Iterator[tuple[int, dict]]:
    steps = job.get("steps")
    if not isinstance(steps, list):
        return
    for idx, step in enumerate(steps):
        if isinstance(step, dict):
            yield idx, step


def iter_reusable_workflow_calls(workflow: dict) -> Iterator[tuple[str, str]]:
    """Yield (job_id, uses) for every job that calls a reusable workflow
    (`jobs.<id>.uses: owner/repo/.github/workflows/x.yml@ref`) instead of
    running its own `steps:` — a job shaped this way has no steps list at
    all, so iter_steps never visits it; rules that also care about
    reusable-workflow calls read this separately."""
    for job_id, job in iter_jobs(workflow):
        uses = job.get("uses")
        if isinstance(uses, str):
            yield job_id, uses


# Matches a single ${{ ... }} expression block.
#
# Two deliberate hardening choices, both needed — neither is sufficient
# alone against a `run:` block engineered to contain many "${{ " with no
# closing "}}" at all (a real security review's own crafted PoC):
#
# 1. [^}]*? instead of .*?: stops the captured group from consuming a
#    lone "}" and re-trying longer matches across it. Matters once a
#    stray single "}" is present in the input.
# 2. {0,500} bounding the group: without a cap, an *unclosed* "${{ "
#    still forces the engine to scan every remaining character before
#    giving up on that start position — [^}]*? alone measured ~155s
#    against 20,000 repeats of "${{ " with zero "}" anywhere. Capping
#    the group means a failed match at one position costs at most ~500
#    chars, not "however much text is left" — turning the worst case
#    from O(n^2) into O(n * 500), i.e. linear. A real expression body is
#    a handful of words; 500 chars is generous headroom above anything
#    legitimate while still bounding the adversarial case.
EXPR_RE = re.compile(r"\$\{\{\s*([^}]{0,500}?)\s*\}\}")

# Matches GitHub Actions' bracket-notation property access, e.g.
# github.event['issue']['title'] or secrets["API_TOKEN"]. GitHub Actions
# expressions treat this as identical to the dot form (github.event.issue.title
# / secrets.API_TOKEN) — a rule matching only the dot form is silently
# blind to any workflow written with brackets instead. Every marker/regex
# check against expression text should run on normalize_expression()'s
# output, not the raw expression, so both forms are always caught the
# same way.
_BRACKET_ACCESS_RE = re.compile(r"\[\s*['\"]([A-Za-z0-9_]+)['\"]\s*\]")


def normalize_expression(expr: str) -> str:
    """Convert bracket-notation property access into the equivalent dot
    form (case preserved) so a marker or regex written once in dot
    notation also matches the bracket form. Does not lowercase — GitHub
    Actions expressions are case-insensitive, but callers that need that
    should lowercase the result themselves so they control whether a
    literal (case-sensitive) part of the expression, like a secret name
    shown back to the user, keeps its original case."""
    return _BRACKET_ACCESS_RE.sub(r".\1", expr)


def iter_run_expressions(workflow: dict) -> Iterator[tuple[str, int, str]]:
    """Yield (job_id, step_index, expression) for every ${{ }} block in
    every step's `run:` value, across every job. The shared walk that
    template_injection.py and secrets_in_run.py both read from — a rule
    that needs `${{ }}` expressions from somewhere other than `run:`
    (there are none yet) would need its own walk, but these two don't."""
    for job_id, job in iter_jobs(workflow):
        for idx, step in iter_steps(job):
            run = step.get("run")
            if not isinstance(run, str):
                continue
            for expr in EXPR_RE.findall(run):
                yield job_id, idx, expr
