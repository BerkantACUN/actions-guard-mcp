"""Top-level entry point: parse a workflow's YAML and run every rule
against it."""

from __future__ import annotations

import yaml

from .models import Finding
from .parser import get_triggers
from .rules import (
    dangerous_triggers,
    excessive_permissions,
    secrets_in_run,
    template_injection,
    unpinned_actions,
)

_RULES = (
    dangerous_triggers,
    template_injection,
    unpinned_actions,
    excessive_permissions,
    secrets_in_run,
)


class WorkflowParseError(ValueError):
    """Raised when the given text isn't valid YAML, or isn't shaped
    like a workflow (not a mapping at the top level)."""


def scan_workflow_yaml(yaml_text: str) -> list[Finding]:
    try:
        workflow = yaml.safe_load(yaml_text)
    except (yaml.YAMLError, RecursionError) as e:
        # RecursionError isn't a yaml.YAMLError — PyYAML's own parser
        # recurses on nested flow collections and Python's recursion
        # limit is the only thing that stops "[[[[[...]]]]]" a few
        # hundred levels deep (confirmed: ~1.8KB of nesting is enough).
        # Without this, that input crashes the MCP tool call outright
        # instead of returning the typed parse error this function
        # already promises for every other kind of bad input.
        raise WorkflowParseError(f"Not valid YAML: {e}") from e

    if not isinstance(workflow, dict):
        raise WorkflowParseError("Workflow must be a YAML mapping at the top level")

    triggers = get_triggers(workflow)

    findings: list[Finding] = []
    for rule in _RULES:
        findings.extend(rule.check(workflow, triggers))
    return findings
