"""
MCP tool surface for actions-guard-mcp.

Two tools: scan a workflow by file path, or scan raw YAML content
directly (useful when an agent is drafting a workflow that hasn't been
written to disk yet). Both funnel into the same scan_workflow_yaml(),
so there's exactly one place the rule set lives.
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    from mcp.server import MCPServer as _MCPServerImpl
except ImportError:  # SDK < 2.0
    from mcp.server.fastmcp import FastMCP as _MCPServerImpl  # type: ignore[no-redef]

from .scanner import WorkflowParseError, scan_workflow_yaml

mcp = _MCPServerImpl("actions-guard-mcp")

# Real workflow files are a few KB at most. This is a generous ceiling
# (nothing legitimate gets rejected), not a tight budget — it exists so
# an oversized input is turned away with a clear typed error before it
# ever reaches yaml.safe_load or the ${{ }} regexes, as defense in depth
# alongside the parser/regex hardening in scanner.py and parser.py.
_MAX_YAML_BYTES = 2 * 1024 * 1024  # 2 MiB


def _too_large_error(size: int) -> dict:
    return {
        "error": "WorkflowTooLarge",
        "message": f"{size} bytes exceeds the {_MAX_YAML_BYTES}-byte limit for a workflow file.",
    }


def _scan(yaml_text: str) -> dict:
    try:
        findings = scan_workflow_yaml(yaml_text)
    except WorkflowParseError as e:
        return {"error": "WorkflowParseError", "message": str(e)}
    return {
        "findings": [f.to_dict() for f in findings],
        "finding_count": len(findings),
    }


@mcp.tool()
def scan_workflow_file(path: str) -> dict:
    """Scan a GitHub Actions workflow file on disk for dangerous
    triggers, template injection, unpinned actions, excessive
    permissions, and secrets interpolated into shell commands."""
    file_path = Path(path)
    if not file_path.is_file():
        return {"error": "FileNotFoundError", "message": f"No such file: {path}"}
    try:
        size = file_path.stat().st_size
        if size > _MAX_YAML_BYTES:
            return _too_large_error(size)
        yaml_text = file_path.read_text(encoding="utf-8")
    except OSError as e:
        return {"error": type(e).__name__, "message": str(e)}
    except UnicodeDecodeError as e:
        # A workflow file is never anything but UTF-8 text; a decode
        # failure means this isn't a real workflow file. read_text()
        # raises UnicodeDecodeError (a ValueError, not an OSError) for
        # that, so it needs its own clause rather than falling through.
        return {"error": "UnicodeDecodeError", "message": str(e)}
    return _scan(yaml_text)


@mcp.tool()
def scan_workflow_content(yaml_content: str) -> dict:
    """Scan raw GitHub Actions workflow YAML content directly — for a
    workflow being drafted that isn't written to disk yet."""
    size = len(yaml_content.encode("utf-8"))
    if size > _MAX_YAML_BYTES:
        return _too_large_error(size)
    return _scan(yaml_content)


def main() -> None:
    print("actions-guard-mcp: ready — no configuration needed.", file=sys.stderr)
    mcp.run()


if __name__ == "__main__":
    main()
