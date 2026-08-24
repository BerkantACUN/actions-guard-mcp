"""Unit tests for parser.py's shared helpers, isolated from any specific
rule — normalize_expression() in particular, since every marker-matching
rule (AGMCP-101/102/105) depends on it to catch bracket notation."""

from actions_guard_mcp.parser import iter_reusable_workflow_calls, normalize_expression


class TestNormalizeExpression:
    def test_leaves_plain_dot_notation_unchanged(self):
        assert normalize_expression("github.event.issue.title") == "github.event.issue.title"

    def test_converts_single_bracket_access_to_dot_form(self):
        assert normalize_expression("secrets['API_TOKEN']") == "secrets.API_TOKEN"

    def test_converts_double_quoted_bracket_access_to_dot_form(self):
        assert normalize_expression('secrets["API_TOKEN"]') == "secrets.API_TOKEN"

    def test_converts_chained_bracket_access(self):
        assert (
            normalize_expression("github.event['pull_request']['head']['sha']")
            == "github.event.pull_request.head.sha"
        )

    def test_preserves_case_does_not_lowercase(self):
        # Case-insensitivity is the caller's responsibility (via
        # .lower() or re.IGNORECASE) so a caller that needs to show the
        # original-case value back to the user still can.
        assert normalize_expression("Secrets['API_Token']") == "Secrets.API_Token"


class TestIterReusableWorkflowCalls:
    def test_yields_job_level_uses_for_a_reusable_workflow_call(self):
        workflow = {
            "on": "push",
            "jobs": {
                "call-reusable": {
                    "uses": "some-org/some-repo/.github/workflows/deploy.yml@main",
                },
            },
        }
        assert list(iter_reusable_workflow_calls(workflow)) == [
            ("call-reusable", "some-org/some-repo/.github/workflows/deploy.yml@main"),
        ]

    def test_ignores_regular_jobs_with_steps(self):
        workflow = {
            "on": "push",
            "jobs": {
                "build": {"runs-on": "ubuntu-latest", "steps": [{"run": "echo hi"}]},
            },
        }
        assert list(iter_reusable_workflow_calls(workflow)) == []

    def test_no_jobs_key_yields_nothing(self):
        assert list(iter_reusable_workflow_calls({"on": "push"})) == []
