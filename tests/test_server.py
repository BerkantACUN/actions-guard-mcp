"""Integration tests for the MCP tool layer."""

import actions_guard_mcp.server as server_module

VULNERABLE_YAML = """
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: some-org/some-action@v1
      - run: |
          echo "${{ github.event.pull_request.title }}"
"""

CLEAN_YAML = """
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo "${{ github.sha }}"
"""


class TestScanWorkflowContent:
    def test_flags_multiple_real_issues_in_one_pass(self):
        result = server_module.scan_workflow_content(VULNERABLE_YAML)
        rule_ids = {f["rule_id"] for f in result["findings"]}
        assert "AGMCP-101" in rule_ids
        assert "AGMCP-102" in rule_ids
        assert "AGMCP-103" in rule_ids
        assert result["finding_count"] == len(result["findings"])

    def test_clean_workflow_has_no_findings(self):
        result = server_module.scan_workflow_content(CLEAN_YAML)
        assert result["findings"] == []
        assert result["finding_count"] == 0

    def test_invalid_yaml_is_a_typed_error_not_a_crash(self):
        result = server_module.scan_workflow_content("not: valid: yaml: [unterminated")
        assert result["error"] == "WorkflowParseError"

    def test_oversized_content_is_a_typed_error_not_a_full_scan_attempt(self):
        # Rejected before yaml.safe_load / the ${{ }} regexes ever see
        # it — defense in depth alongside the parser/regex hardening,
        # not a substitute for it.
        oversized = "on: push\njobs: {}\n# " + ("x" * (server_module._MAX_YAML_BYTES + 1))
        result = server_module.scan_workflow_content(oversized)
        assert result["error"] == "WorkflowTooLarge"

    def test_content_at_exactly_the_limit_is_still_scanned(self):
        padding_needed = server_module._MAX_YAML_BYTES - len(CLEAN_YAML.encode("utf-8"))
        exactly_at_limit = CLEAN_YAML + ("#" * padding_needed)
        assert len(exactly_at_limit.encode("utf-8")) == server_module._MAX_YAML_BYTES
        result = server_module.scan_workflow_content(exactly_at_limit)
        assert "error" not in result


class TestScanWorkflowFile:
    def test_reads_and_scans_a_real_file(self, tmp_path):
        workflow_file = tmp_path / "ci.yml"
        workflow_file.write_text(VULNERABLE_YAML, encoding="utf-8")
        result = server_module.scan_workflow_file(str(workflow_file))
        assert result["finding_count"] > 0

    def test_missing_file_is_a_typed_error(self):
        result = server_module.scan_workflow_file("does-not-exist.yml")
        assert result["error"] == "FileNotFoundError"

    def test_oversized_file_is_rejected_before_being_read_into_memory(self, tmp_path):
        workflow_file = tmp_path / "huge.yml"
        workflow_file.write_bytes(b"#" * (server_module._MAX_YAML_BYTES + 1))
        result = server_module.scan_workflow_file(str(workflow_file))
        assert result["error"] == "WorkflowTooLarge"

    def test_non_utf8_file_is_a_typed_error_not_a_crash(self, tmp_path):
        # read_text(encoding="utf-8") raises UnicodeDecodeError — a
        # ValueError, not an OSError — for bytes that aren't valid UTF-8;
        # a workflow file is never anything else, so this means the path
        # doesn't point at a real workflow.
        workflow_file = tmp_path / "binary.yml"
        workflow_file.write_bytes(b"\xff\xfe\x00\x01not utf-8")
        result = server_module.scan_workflow_file(str(workflow_file))
        assert result["error"] == "UnicodeDecodeError"
