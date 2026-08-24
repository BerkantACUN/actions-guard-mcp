"""
Tests for the rule engine, written directly against real incident shapes:
the CoreShop pwn-request (pull_request_target + checkout of fork code +
run the fork's script), the tj-actions supply-chain compromise (a
tag-pinned third-party action silently repointed to malicious code), and
the generic ${{ }}-in-run template-injection pattern that GitHub's own
security docs warn about.
"""

import pytest

from actions_guard_mcp.scanner import scan_workflow_yaml


def _rule_ids(findings):
    return {f.rule_id for f in findings}


class TestDangerousTriggers_AGMCP101:
    """The exact CoreShop shape: pull_request_target runs with the base
    repo's token and secrets, but checks out the PR's own head ref —
    so a forked PR's code runs with privileges it should never have."""

    def test_pull_request_target_checking_out_pr_head_is_flagged(self):
        yaml_text = """
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: ./build.sh
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-101" in _rule_ids(findings)

    def test_workflow_run_checking_out_pr_head_is_also_flagged(self):
        yaml_text = """
on: workflow_run
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.workflow_run.head_sha }}
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-101" in _rule_ids(findings)

    def test_pull_request_target_without_checking_out_fork_code_is_not_flagged(self):
        # The trigger alone isn't the vulnerability — it's combined with
        # checking out and running untrusted code that makes it one.
        yaml_text = """
on: pull_request_target
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/labeler@v5
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-101" not in _rule_ids(findings)

    def test_ordinary_pull_request_trigger_is_never_flagged(self):
        # Plain `pull_request` runs with a read-only, fork-scoped token —
        # this is the safe default the dangerous triggers deliberately
        # differ from.
        yaml_text = """
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-101" not in _rule_ids(findings)

    def test_default_checkout_ref_under_pull_request_target_is_not_flagged(self):
        # No explicit `ref:` means checkout uses the merge commit into
        # the base branch, not the fork's own code — not the pwn-request
        # shape.
        yaml_text = """
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-101" not in _rule_ids(findings)

    def test_checking_out_the_forks_repository_field_is_flagged(self):
        # Naming the fork's repository is the same attack shape as
        # naming a ref inside it — actions/checkout will happily clone
        # a different repo entirely if told to.
        yaml_text = """
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          repository: ${{ github.event.pull_request.head.repo.full_name }}
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-101" in _rule_ids(findings)

    def test_bracket_notation_ref_is_flagged(self):
        # GitHub Actions treats github.event['pull_request']['head']['sha']
        # as identical to the dot form — a rule matching only dots would
        # silently miss this.
        yaml_text = """
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event['pull_request']['head']['sha'] }}
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-101" in _rule_ids(findings)

    def test_mixed_case_marker_is_flagged(self):
        # GitHub Actions context/property names are case-insensitive at
        # runtime; the marker check must be too.
        yaml_text = """
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.Event.Pull_Request.Head.Sha }}
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-101" in _rule_ids(findings)

    def test_pr_head_branch_name_marker_is_flagged(self):
        # A distinct value from github.head_ref (already covered) —
        # the raw event payload names the same fork branch, and an
        # attacker fully controls their own branch name.
        yaml_text = """
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-101" in _rule_ids(findings)

    def test_env_indirection_is_a_known_undetected_limitation(self):
        # Documents a real gap rather than hiding it: routing the same
        # dangerous value through an env: variable first is functionally
        # identical to a direct ref, but there's no data-flow tracking
        # across steps, so this rule can't see it. If this test starts
        # failing because the rule got smarter, that's a welcome surprise
        # — update the docstring in dangerous_triggers.py accordingly.
        yaml_text = """
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - env:
          HEAD_SHA: ${{ github.event.pull_request.head.sha }}
      - uses: actions/checkout@v4
        with:
          ref: ${{ env.HEAD_SHA }}
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-101" not in _rule_ids(findings)


class TestTemplateInjection_AGMCP102:
    """The shape GitHub's own docs warn about: an attacker-controlled
    value dropped straight into a shell command via ${{ }}, instead of
    passed through env: (where the shell never re-interprets it)."""

    @pytest.mark.parametrize(
        "expr",
        [
            "github.event.issue.title",
            "github.event.pull_request.title",
            "github.event.comment.body",
            "github.event.review.body",
            "github.head_ref",
        ],
    )
    def test_attacker_controlled_context_in_run_is_flagged(self, expr):
        yaml_text = f"""
on: issues
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{{{ {expr} }}}}"
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-102" in _rule_ids(findings)

    def test_the_same_value_passed_through_env_is_not_flagged(self):
        # This is the actual fix: the shell never sees the raw value,
        # only an environment variable expansion.
        yaml_text = """
on: issues
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - env:
          TITLE: ${{ github.event.issue.title }}
        run: echo "$TITLE"
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-102" not in _rule_ids(findings)

    def test_safe_context_values_in_run_are_not_flagged(self):
        yaml_text = """
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.sha }} on ${{ runner.os }}"
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-102" not in _rule_ids(findings)

    def test_bracket_notation_marker_is_flagged(self):
        yaml_text = """
on: issues
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event['issue']['title'] }}"
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-102" in _rule_ids(findings)

    def test_mixed_case_marker_is_flagged(self):
        yaml_text = """
on: issues
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.Event.Issue.Title }}"
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-102" in _rule_ids(findings)

    def test_tojson_github_event_whole_payload_dump_is_flagged(self):
        # Dumps every attacker-controlled field into the shell at once —
        # at least as dangerous as any single flagged field.
        yaml_text = """
on: issues
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - run: echo '${{ toJSON(github.event) }}'
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-102" in _rule_ids(findings)


class TestUnpinnedActions_AGMCP103:
    """The tj-actions shape: a third-party action referenced by a
    mutable tag/branch. When that tag gets silently repointed
    (compromised maintainer, compromised token, ...), every workflow
    using it runs the new code with no version bump to notice."""

    def test_action_pinned_to_a_tag_is_flagged(self):
        yaml_text = """
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: tj-actions/changed-files@v42
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-103" in _rule_ids(findings)

    def test_action_pinned_to_a_branch_is_flagged(self):
        yaml_text = """
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: someorg/someaction@main
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-103" in _rule_ids(findings)

    def test_action_pinned_to_a_full_commit_sha_is_not_flagged(self):
        yaml_text = """
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@8410ad0602e1e429cee44a835ae9f77f654a6694
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-103" not in _rule_ids(findings)

    def test_first_party_actions_action_is_not_flagged_even_on_a_tag(self):
        # `actions/*` is GitHub's own org — still worth pinning in
        # principle, but a materially different trust boundary than an
        # arbitrary third party, and flagging it by default would bury
        # every real third-party finding in noise.
        yaml_text = """
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-103" not in _rule_ids(findings)

    def test_local_action_reference_is_not_flagged(self):
        yaml_text = """
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/my-local-action
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-103" not in _rule_ids(findings)

    def test_uppercase_commit_sha_is_not_flagged(self):
        # Git/GitHub resolve hex SHAs case-insensitively — a SHA pasted
        # in uppercase is exactly as pinned as lowercase, not a
        # different, unpinned ref.
        yaml_text = """
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@8410AD0602E1E429CEE44A835AE9F77F654A6694
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-103" not in _rule_ids(findings)

    def test_reusable_workflow_call_pinned_to_a_branch_is_flagged(self):
        # jobs.<id>.uses: has no steps: at all — a separate walk from
        # the regular step-level uses: check is required to see it.
        yaml_text = """
on: push
jobs:
  call-reusable:
    uses: some-org/some-repo/.github/workflows/deploy.yml@main
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-103" in _rule_ids(findings)

    def test_reusable_workflow_call_pinned_to_a_sha_is_not_flagged(self):
        yaml_text = """
on: push
jobs:
  call-reusable:
    uses: some-org/some-repo/.github/workflows/deploy.yml@8410ad0602e1e429cee44a835ae9f77f654a6694
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-103" not in _rule_ids(findings)

    def test_docker_ref_without_a_digest_is_flagged(self):
        # A Docker Hub tag (or the implicit `latest`) is exactly as
        # mutable as a git tag — the same supply-chain risk class.
        yaml_text = """
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://someorg/some-image:latest
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-103" in _rule_ids(findings)

    def test_docker_ref_pinned_to_a_digest_is_not_flagged(self):
        yaml_text = """
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: docker://alpine@sha256:c0d488a800e4127c334ad20d61d7bc21b4097540327217dfab52262adc02380
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-103" not in _rule_ids(findings)


class TestExcessivePermissions_AGMCP104:
    def test_write_all_is_flagged(self):
        yaml_text = """
on: pull_request_target
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-104" in _rule_ids(findings)

    def test_broad_explicit_write_scopes_on_a_risky_trigger_are_flagged(self):
        yaml_text = """
on: pull_request_target
permissions:
  contents: write
  actions: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-104" in _rule_ids(findings)

    def test_read_only_permissions_are_not_flagged(self):
        yaml_text = """
on: pull_request_target
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-104" not in _rule_ids(findings)

    def test_narrow_write_scope_on_a_safe_trigger_is_not_flagged(self):
        yaml_text = """
on: push
permissions:
  contents: write
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-104" not in _rule_ids(findings)

    def test_job_level_write_all_with_no_top_level_permissions_is_flagged(self):
        # No workflow-level `permissions:` block at all — the risk is
        # expressed entirely at the job level, which a workflow-level-only
        # check would miss completely.
        yaml_text = """
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    permissions: write-all
    steps:
      - run: echo hi
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-104" in _rule_ids(findings)

    def test_job_level_broad_write_scope_is_flagged(self):
        yaml_text = """
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - run: echo hi
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-104" in _rule_ids(findings)

    def test_job_level_read_only_permissions_are_not_flagged(self):
        yaml_text = """
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - run: echo hi
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-104" not in _rule_ids(findings)


class TestSecretsInRun_AGMCP105:
    def test_secret_interpolated_directly_into_run_is_flagged(self):
        yaml_text = """
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -H "Authorization: ${{ secrets.API_TOKEN }}" https://example.com
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-105" in _rule_ids(findings)

    def test_secret_passed_through_env_is_not_flagged(self):
        yaml_text = """
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - env:
          API_TOKEN: ${{ secrets.API_TOKEN }}
        run: |
          curl -H "Authorization: $API_TOKEN" https://example.com
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-105" not in _rule_ids(findings)

    def test_secret_used_in_a_with_block_is_not_flagged(self):
        # `with:` values go to the action's typed inputs, not a shell —
        # this is the normal, safe way to pass a secret to an action.
        yaml_text = """
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: some/action@8410ad0602e1e429cee44a835ae9f77f654a6694
        with:
          token: ${{ secrets.API_TOKEN }}
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-105" not in _rule_ids(findings)

    def test_multiple_secrets_in_one_expression_are_all_flagged(self):
        # "${{ secrets.A || secrets.B }}" names two different secrets in
        # one expression — findall, not search, so both get reported.
        yaml_text = """
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -H "Authorization: ${{ secrets.PRIMARY_TOKEN || secrets.FALLBACK_TOKEN }}" https://example.com
"""
        findings = scan_workflow_yaml(yaml_text)
        hits = [f for f in findings if f.rule_id == "AGMCP-105"]
        assert len(hits) == 2
        assert any("PRIMARY_TOKEN" in f.message for f in hits)
        assert any("FALLBACK_TOKEN" in f.message for f in hits)

    def test_bracket_notation_secret_is_flagged(self):
        yaml_text = """
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -H "Authorization: ${{ secrets['API_TOKEN'] }}" https://example.com
"""
        findings = scan_workflow_yaml(yaml_text)
        assert "AGMCP-105" in _rule_ids(findings)


class TestFindingQuality:
    def test_a_finding_names_its_location(self):
        yaml_text = """
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""
        findings = scan_workflow_yaml(yaml_text)
        hit = next(f for f in findings if f.rule_id == "AGMCP-101")
        assert "build" in hit.location

    def test_scanning_invalid_yaml_is_a_clear_error_not_a_crash(self):
        from actions_guard_mcp.scanner import WorkflowParseError

        with pytest.raises(WorkflowParseError):
            scan_workflow_yaml("not: valid: yaml: [unterminated")

    def test_scanning_an_empty_workflow_returns_no_findings(self):
        assert scan_workflow_yaml("on: push\njobs: {}\n") == []


class TestScannerHardening:
    """Regression coverage for the security review's algorithmic-DoS
    findings: a deeply-nested YAML payload crashing the scanner outright
    (RecursionError, not a yaml.YAMLError) and a crafted `run:` string
    exhibiting quadratic-time behavior in the shared ${{ }} regex."""

    def test_deeply_nested_yaml_is_a_clear_parse_error_not_a_crash(self):
        from actions_guard_mcp.scanner import WorkflowParseError

        # PyYAML's flow-collection parser recurses per nesting level;
        # ~1000 levels is enough to exceed Python's default recursion
        # limit and raise RecursionError, which isn't a yaml.YAMLError.
        bomb = "on: push\njobs: " + "[" * 2000 + "]" * 2000
        with pytest.raises(WorkflowParseError):
            scan_workflow_yaml(bomb)

    def test_unterminated_expression_markers_scan_in_bounded_time(self):
        import time

        from actions_guard_mcp.scanner import scan_workflow_yaml as scan

        # The security review's actual PoC shape: many "${{ " substrings
        # with no closing "}}" anywhere in the text. [^}]*? alone still
        # measured ~155s against this (confirmed while fixing this test)
        # — only the {0,500} length bound on the group makes a single
        # failed match cheap regardless of how much unclosed text follows
        # it. This is the regression test for that specific finding.
        run_body = "echo ${{ " * 20000
        yaml_text = f"""
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          {run_body}
"""
        start = time.monotonic()
        scan(yaml_text)
        elapsed = time.monotonic() - start
        assert elapsed < 2.0, f"scan took {elapsed:.2f}s — regex may have regressed to quadratic"

    def test_expressions_near_the_length_bound_still_match(self):
        from actions_guard_mcp.parser import EXPR_RE

        # Real GitHub Actions expressions are a handful of words; this
        # confirms the 500-char cap added for the fix above doesn't
        # clip anything a real workflow would actually write.
        body = "a" * 400
        matches = EXPR_RE.findall("${{ " + body + " }}")
        assert matches == [body]
