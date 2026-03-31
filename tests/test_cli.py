"""
Tests for gitlab_ioc_scanner.cli module.

Covers:
- setup_logging(): log level configuration
- parse_args(): defaults, env var fallbacks, validation, multi-branch parsing, --report-dir
- main(): end-to-end with mocked GitLabClient
  - clean scan → exit 0
  - CRITICAL findings → exit 2
  - HIGH findings → exit 3
  - no projects → exit 1
  - IOC load failure → exit 1
  - multi-branch resolution
  - branch-strict skipping all → exit 1
  - project deduplication across groups
  - reports written into --report-dir
"""

from __future__ import annotations

import logging
import os
from unittest.mock import MagicMock, patch

import pytest

from gitlab_ioc_scanner.cli import main, parse_args, setup_logging

# ─────────────────────────────────────────────────────────────────────────────
# setup_logging
# ─────────────────────────────────────────────────────────────────────────────


class TestSetupLogging:
    def test_sets_debug_level(self):
        setup_logging("DEBUG")
        log = logging.getLogger("ioc_scanner")
        assert log.level == logging.DEBUG

    def test_sets_info_level(self):
        setup_logging("INFO")
        log = logging.getLogger("ioc_scanner")
        assert log.level == logging.INFO

    def test_sets_warning_level(self):
        setup_logging("WARNING")
        log = logging.getLogger("ioc_scanner")
        assert log.level == logging.WARNING

    def test_invalid_level_defaults_to_info(self):
        setup_logging("NONEXISTENT")
        log = logging.getLogger("ioc_scanner")
        assert log.level == logging.INFO


# ─────────────────────────────────────────────────────────────────────────────
# parse_args
# ─────────────────────────────────────────────────────────────────────────────


class TestParseArgs:
    def test_required_args(self):
        args = parse_args(["--token", "tok", "--group", "cis"])
        assert args.token == "tok"
        assert args.group == "cis"

    def test_default_gitlab_url(self):
        args = parse_args(["--token", "tok", "--group", "cis"])
        assert "gitlab.com" in args.gitlab_url

    def test_custom_gitlab_url(self):
        # Note: rstrip("/") only applied to env var default, not CLI arg
        args = parse_args(
            ["--token", "tok", "--group", "cis", "--gitlab-url", "https://gl.corp.com"]
        )
        assert args.gitlab_url == "https://gl.corp.com"

    def test_default_format(self):
        args = parse_args(["--token", "tok", "--group", "cis"])
        assert args.format == ["csv"]

    def test_multiple_formats(self):
        args = parse_args(["--token", "tok", "--group", "cis", "-f", "csv", "json", "html"])
        assert set(args.format) == {"csv", "json", "html"}

    def test_default_workers(self):
        args = parse_args(["--token", "tok", "--group", "cis"])
        assert args.workers == 4

    def test_custom_workers(self):
        args = parse_args(["--token", "tok", "--group", "cis", "--workers", "8"])
        assert args.workers == 8

    def test_branch_parsing(self):
        args = parse_args(["--token", "tok", "--group", "cis", "--branch", "main,develop,dev"])
        assert args.branch == "main,develop,dev"

    def test_branch_strict(self):
        args = parse_args(["--token", "tok", "--group", "cis", "--branch-strict"])
        assert args.branch_strict is True

    def test_debug_flag_sets_log_level(self):
        args = parse_args(["--token", "tok", "--group", "cis", "--debug"])
        assert args.log_level == "DEBUG"

    def test_debug_shortcut(self):
        args = parse_args(["--token", "tok", "--group", "cis", "-d"])
        assert args.log_level == "DEBUG"

    def test_default_log_level(self):
        args = parse_args(["--token", "tok", "--group", "cis"])
        assert args.log_level == "INFO"

    def test_missing_token_exits(self):
        with pytest.raises(SystemExit):
            parse_args(["--group", "cis"])

    def test_missing_group_exits(self):
        with pytest.raises(SystemExit):
            parse_args(["--token", "tok"])

    def test_project_filter(self):
        args = parse_args(["--token", "tok", "--group", "cis", "--project", "web-app"])
        assert args.project == "web-app"

    def test_default_ioc_file(self):
        args = parse_args(["--token", "tok", "--group", "cis"])
        assert args.ioc_file == "iocs.json"

    def test_custom_ioc_file(self):
        args = parse_args(["--token", "tok", "--group", "cis", "-i", "custom_iocs.json"])
        assert args.ioc_file == "custom_iocs.json"

    def test_default_report_dir(self):
        args = parse_args(["--token", "tok", "--group", "cis"])
        assert args.report_dir == "reports"

    def test_custom_report_dir(self):
        args = parse_args(["--token", "tok", "--group", "cis", "--report-dir", "/tmp/out"])
        assert args.report_dir == "/tmp/out"

    # ── Env var fallbacks ────────────────────────────────────────────────

    @patch.dict(os.environ, {"GL_TOKEN": "env-token", "GL_GROUP": "env-group"})
    def test_env_var_token_and_group(self):
        args = parse_args([])
        assert args.token == "env-token"
        assert args.group == "env-group"

    @patch.dict(os.environ, {"GL_TOKEN": "tok", "GL_GROUP": "g", "GL_URL": "https://gl.corp.com/"})
    def test_env_var_gl_url(self):
        args = parse_args([])
        assert args.gitlab_url == "https://gl.corp.com"

    @patch.dict(os.environ, {"GL_TOKEN": "tok", "GL_GROUP": "g", "GL_BRANCH": "main,develop"})
    def test_env_var_gl_branch(self):
        args = parse_args([])
        assert args.branch == "main,develop"

    @patch.dict(os.environ, {"GL_TOKEN": "tok", "GL_GROUP": "g", "GL_BRANCH_STRICT": "1"})
    def test_env_var_branch_strict(self):
        args = parse_args([])
        assert args.branch_strict is True

    @patch.dict(os.environ, {"GL_TOKEN": "tok", "GL_GROUP": "g", "GL_BRANCH_STRICT": "false"})
    def test_env_var_branch_strict_false(self):
        args = parse_args([])
        assert args.branch_strict is False

    @patch.dict(os.environ, {"GL_TOKEN": "tok", "GL_GROUP": "g", "SCAN_DEBUG": "1"})
    def test_env_var_scan_debug(self):
        args = parse_args([])
        assert args.log_level == "DEBUG"

    @patch.dict(os.environ, {"GL_TOKEN": "tok", "GL_GROUP": "g", "SCAN_WORKERS": "16"})
    def test_env_var_workers(self):
        args = parse_args([])
        assert args.workers == 16

    @patch.dict(os.environ, {"GL_TOKEN": "tok", "GL_GROUP": "g", "IOC_FILE": "custom.json"})
    def test_env_var_ioc_file(self):
        args = parse_args([])
        assert args.ioc_file == "custom.json"

    @patch.dict(os.environ, {"GL_TOKEN": "tok", "GL_GROUP": "g", "SCAN_OUTPUT": "my_report"})
    def test_env_var_output(self):
        args = parse_args([])
        assert args.output == "my_report"

    @patch.dict(os.environ, {"GL_TOKEN": "tok", "GL_GROUP": "g", "SCAN_REPORT_DIR": "/opt/reports"})
    def test_env_var_report_dir(self):
        args = parse_args([])
        assert args.report_dir == "/opt/reports"

    @patch.dict(os.environ, {"GL_TOKEN": "tok", "GL_GROUP": "g", "LOG_LEVEL": "WARNING"})
    def test_env_var_log_level(self):
        args = parse_args([])
        assert args.log_level == "WARNING"

    # ── CLI args override env vars ───────────────────────────────────────

    @patch.dict(os.environ, {"GL_TOKEN": "env-tok", "GL_GROUP": "env-grp"})
    def test_cli_overrides_env(self):
        args = parse_args(["--token", "cli-tok", "--group", "cli-grp"])
        assert args.token == "cli-tok"
        assert args.group == "cli-grp"


# ─────────────────────────────────────────────────────────────────────────────
# main()
# ─────────────────────────────────────────────────────────────────────────────


def _mock_iocs():
    """Return a minimal valid IOC list."""
    return [
        {
            "indicator": "evil-pkg",
            "pattern": "evil-pkg",
            "files": ["requirements.txt"],
            "severity": "HIGH",
            "attack": "Test Attack",
            "note": "Test note",
            "references": [],
        }
    ]


def _mock_project(pid: int = 1, name: str = "cis/proj1") -> dict:
    return {
        "id": pid,
        "path_with_namespace": name,
        "web_url": f"https://gl.x/{name}",
        "default_branch": "main",
    }


def _configure_mock_client(client: MagicMock) -> None:
    """Set integer counter attributes on a mock GitLabClient so metadata is JSON-safe."""
    client.api_calls = 0
    client.api_calls_search = 0
    client.api_calls_file = 0
    client.api_calls_branch = 0
    client.api_calls_other = 0
    client.retries = 0
    client.errors = 0


class TestMain:
    @patch("gitlab_ioc_scanner.cli.time.sleep")
    @patch("gitlab_ioc_scanner.cli.scan_project")
    @patch("gitlab_ioc_scanner.cli.GitLabClient")
    @patch("gitlab_ioc_scanner.cli.load_iocs")
    def test_clean_scan_exit_0(self, mock_load, mock_client_cls, mock_scan, mock_sleep, tmp_path):
        """Clean scan with no findings returns exit code 0."""
        mock_load.return_value = _mock_iocs()
        client = MagicMock()
        _configure_mock_client(client)
        mock_client_cls.return_value = client
        client.get_all_projects.return_value = [_mock_project()]
        mock_scan.return_value = []

        result = main(
            [
                "--token",
                "tok",
                "--group",
                "cis",
                "--output",
                "report",
                "--report-dir",
                str(tmp_path),
            ]
        )
        assert result == 0

    @patch("gitlab_ioc_scanner.cli.time.sleep")
    @patch("gitlab_ioc_scanner.cli.scan_project")
    @patch("gitlab_ioc_scanner.cli.GitLabClient")
    @patch("gitlab_ioc_scanner.cli.load_iocs")
    def test_critical_finding_exit_2(
        self, mock_load, mock_client_cls, mock_scan, mock_sleep, tmp_path
    ):
        """CRITICAL findings return exit code 2."""
        mock_load.return_value = _mock_iocs()
        client = MagicMock()
        _configure_mock_client(client)
        mock_client_cls.return_value = client
        client.get_all_projects.return_value = [_mock_project()]
        mock_scan.return_value = [
            {
                "project": "cis/proj1",
                "url": "https://gl.x/cis/proj1",
                "branch": "main",
                "file": "requirements.txt",
                "attack": "Test",
                "indicator": "evil-pkg",
                "severity": "CRITICAL",
                "note": "bad",
                "references": "",
                "timestamp": "2026-03-31T10:00:00+00:00",
            }
        ]

        result = main(
            [
                "--token",
                "tok",
                "--group",
                "cis",
                "--output",
                "report",
                "--report-dir",
                str(tmp_path),
            ]
        )
        assert result == 2

    @patch("gitlab_ioc_scanner.cli.time.sleep")
    @patch("gitlab_ioc_scanner.cli.scan_project")
    @patch("gitlab_ioc_scanner.cli.GitLabClient")
    @patch("gitlab_ioc_scanner.cli.load_iocs")
    def test_high_finding_exit_3(self, mock_load, mock_client_cls, mock_scan, mock_sleep, tmp_path):
        """HIGH findings (no CRITICAL) return exit code 3."""
        mock_load.return_value = _mock_iocs()
        client = MagicMock()
        _configure_mock_client(client)
        mock_client_cls.return_value = client
        client.get_all_projects.return_value = [_mock_project()]
        mock_scan.return_value = [
            {
                "project": "cis/proj1",
                "url": "https://gl.x/cis/proj1",
                "branch": "main",
                "file": "requirements.txt",
                "attack": "Test",
                "indicator": "evil-pkg",
                "severity": "HIGH",
                "note": "bad",
                "references": "",
                "timestamp": "2026-03-31T10:00:00+00:00",
            }
        ]

        result = main(
            [
                "--token",
                "tok",
                "--group",
                "cis",
                "--output",
                "report",
                "--report-dir",
                str(tmp_path),
            ]
        )
        assert result == 3

    @patch("gitlab_ioc_scanner.cli.time.sleep")
    @patch("gitlab_ioc_scanner.cli.GitLabClient")
    @patch("gitlab_ioc_scanner.cli.load_iocs")
    def test_no_projects_exit_1(self, mock_load, mock_client_cls, mock_sleep):
        """No projects found returns exit code 1."""
        mock_load.return_value = _mock_iocs()
        client = MagicMock()
        _configure_mock_client(client)
        mock_client_cls.return_value = client
        client.get_all_projects.return_value = []

        result = main(["--token", "tok", "--group", "empty"])
        assert result == 1

    @patch("gitlab_ioc_scanner.cli.load_iocs")
    def test_ioc_load_file_not_found_exit_1(self, mock_load):
        """IOC file not found returns exit code 1."""
        mock_load.side_effect = FileNotFoundError("iocs.json not found")
        result = main(["--token", "tok", "--group", "cis", "--ioc-file", "missing.json"])
        assert result == 1

    @patch("gitlab_ioc_scanner.cli.load_iocs")
    def test_ioc_load_value_error_exit_1(self, mock_load):
        """Invalid IOC file returns exit code 1."""
        mock_load.side_effect = ValueError("No IOCs found")
        result = main(["--token", "tok", "--group", "cis"])
        assert result == 1

    @patch("gitlab_ioc_scanner.cli.load_iocs")
    def test_ioc_load_generic_error_exit_1(self, mock_load):
        """Generic IOC load error returns exit code 1."""
        mock_load.side_effect = RuntimeError("something broke")
        result = main(["--token", "tok", "--group", "cis"])
        assert result == 1

    @patch("gitlab_ioc_scanner.cli.time.sleep")
    @patch("gitlab_ioc_scanner.cli.scan_project")
    @patch("gitlab_ioc_scanner.cli.GitLabClient")
    @patch("gitlab_ioc_scanner.cli.load_iocs")
    def test_multi_group_scanning(
        self, mock_load, mock_client_cls, mock_scan, mock_sleep, tmp_path
    ):
        """Multiple groups are scanned and projects deduplicated."""
        mock_load.return_value = _mock_iocs()
        client = MagicMock()
        _configure_mock_client(client)
        mock_client_cls.return_value = client

        # Same project appears in both groups
        shared_proj = _mock_project(1, "shared/proj")
        proj2 = _mock_project(2, "devops/proj2")
        client.get_all_projects.side_effect = [
            [shared_proj],  # cis group
            [shared_proj, proj2],  # devops group
        ]
        mock_scan.return_value = []

        result = main(
            [
                "--token",
                "tok",
                "--group",
                "cis,devops",
                "--output",
                "report",
                "--report-dir",
                str(tmp_path),
            ]
        )
        assert result == 0
        # scan_project should be called 2 times (deduplicated), not 3
        assert mock_scan.call_count == 2

    @patch("gitlab_ioc_scanner.cli.time.sleep")
    @patch("gitlab_ioc_scanner.cli.scan_project")
    @patch("gitlab_ioc_scanner.cli.GitLabClient")
    @patch("gitlab_ioc_scanner.cli.load_iocs")
    def test_multi_branch_scanning(
        self, mock_load, mock_client_cls, mock_scan, mock_sleep, tmp_path
    ):
        """Multi-branch scanning checks each branch per project."""
        mock_load.return_value = _mock_iocs()
        client = MagicMock()
        _configure_mock_client(client)
        mock_client_cls.return_value = client
        client.get_all_projects.return_value = [_mock_project()]

        # main exists, develop exists, dev does not
        def branch_exists_side(pid, br):
            return br in ("main", "develop")

        client.branch_exists.side_effect = branch_exists_side
        mock_scan.return_value = []

        result = main(
            [
                "--token",
                "tok",
                "--group",
                "cis",
                "--branch",
                "main,develop,dev",
                "--output",
                "report",
                "--report-dir",
                str(tmp_path),
            ]
        )
        assert result == 0
        # scan_project called twice: once for main, once for develop
        assert mock_scan.call_count == 2

    @patch("gitlab_ioc_scanner.cli.time.sleep")
    @patch("gitlab_ioc_scanner.cli.GitLabClient")
    @patch("gitlab_ioc_scanner.cli.load_iocs")
    def test_branch_strict_skips_all_exit_1(self, mock_load, mock_client_cls, mock_sleep):
        """branch-strict mode with no matching branches exits 1."""
        mock_load.return_value = _mock_iocs()
        client = MagicMock()
        _configure_mock_client(client)
        mock_client_cls.return_value = client
        client.get_all_projects.return_value = [_mock_project()]
        client.branch_exists.return_value = False  # no branch matches

        result = main(
            [
                "--token",
                "tok",
                "--group",
                "cis",
                "--branch",
                "nonexistent",
                "--branch-strict",
            ]
        )
        assert result == 1

    @patch("gitlab_ioc_scanner.cli.time.sleep")
    @patch("gitlab_ioc_scanner.cli.scan_project")
    @patch("gitlab_ioc_scanner.cli.GitLabClient")
    @patch("gitlab_ioc_scanner.cli.load_iocs")
    def test_branch_fallback_to_default(
        self, mock_load, mock_client_cls, mock_scan, mock_sleep, tmp_path
    ):
        """Without strict mode, falls back to default branch if none match."""
        mock_load.return_value = _mock_iocs()
        client = MagicMock()
        _configure_mock_client(client)
        mock_client_cls.return_value = client
        client.get_all_projects.return_value = [_mock_project()]
        client.branch_exists.return_value = False
        mock_scan.return_value = []

        result = main(
            [
                "--token",
                "tok",
                "--group",
                "cis",
                "--branch",
                "nonexistent",
                "--output",
                "report",
                "--report-dir",
                str(tmp_path),
            ]
        )
        assert result == 0
        # scan_project called once with fallback branch
        assert mock_scan.call_count == 1

    @patch("gitlab_ioc_scanner.cli.time.sleep")
    @patch("gitlab_ioc_scanner.cli.scan_project")
    @patch("gitlab_ioc_scanner.cli.GitLabClient")
    @patch("gitlab_ioc_scanner.cli.load_iocs")
    def test_multiple_formats(self, mock_load, mock_client_cls, mock_scan, mock_sleep, tmp_path):
        """All three report formats are generated in --report-dir."""
        mock_load.return_value = _mock_iocs()
        client = MagicMock()
        _configure_mock_client(client)
        mock_client_cls.return_value = client
        client.get_all_projects.return_value = [_mock_project()]
        mock_scan.return_value = []

        result = main(
            [
                "--token",
                "tok",
                "--group",
                "cis",
                "--output",
                "report",
                "--report-dir",
                str(tmp_path),
                "-f",
                "csv",
                "json",
                "html",
            ]
        )
        assert result == 0
        assert (tmp_path / "report.csv").exists()
        assert (tmp_path / "report.json").exists()
        assert (tmp_path / "report.html").exists()

    @patch("gitlab_ioc_scanner.cli.time.sleep")
    @patch("gitlab_ioc_scanner.cli.scan_project")
    @patch("gitlab_ioc_scanner.cli.GitLabClient")
    @patch("gitlab_ioc_scanner.cli.load_iocs")
    def test_scan_exception_handled(
        self, mock_load, mock_client_cls, mock_scan, mock_sleep, tmp_path
    ):
        """Exception in scan_project is caught and logged, doesn't crash."""
        mock_load.return_value = _mock_iocs()
        client = MagicMock()
        _configure_mock_client(client)
        mock_client_cls.return_value = client
        client.get_all_projects.return_value = [_mock_project()]
        mock_scan.side_effect = RuntimeError("scan crashed")

        result = main(
            [
                "--token",
                "tok",
                "--group",
                "cis",
                "--output",
                "report",
                "--report-dir",
                str(tmp_path),
            ]
        )
        # Should still complete (exit 0, no findings recorded)
        assert result == 0

    @patch("gitlab_ioc_scanner.cli.time.sleep")
    @patch("gitlab_ioc_scanner.cli.scan_project")
    @patch("gitlab_ioc_scanner.cli.GitLabClient")
    @patch("gitlab_ioc_scanner.cli.load_iocs")
    def test_default_output_prefix(
        self, mock_load, mock_client_cls, mock_scan, mock_sleep, tmp_path
    ):
        """When no --output, generates timestamped prefix inside --report-dir."""
        mock_load.return_value = _mock_iocs()
        client = MagicMock()
        _configure_mock_client(client)
        mock_client_cls.return_value = client
        client.get_all_projects.return_value = [_mock_project()]
        mock_scan.return_value = []

        result = main(["--token", "tok", "--group", "cis", "--report-dir", str(tmp_path)])
        assert result == 0
        # Report file should exist in tmp_path with auto-generated name
        csv_files = list(tmp_path.glob("ioc_report_cis_*.csv"))
        assert len(csv_files) == 1

    @patch("gitlab_ioc_scanner.cli.time.sleep")
    @patch("gitlab_ioc_scanner.cli.scan_project")
    @patch("gitlab_ioc_scanner.cli.GitLabClient")
    @patch("gitlab_ioc_scanner.cli.load_iocs")
    def test_clean_projects_tracked(
        self, mock_load, mock_client_cls, mock_scan, mock_sleep, tmp_path
    ):
        """Clean projects appear in the JSON report."""
        mock_load.return_value = _mock_iocs()
        client = MagicMock()
        _configure_mock_client(client)
        mock_client_cls.return_value = client
        client.get_all_projects.return_value = [
            _mock_project(1, "cis/clean1"),
            _mock_project(2, "cis/clean2"),
        ]
        mock_scan.return_value = []

        main(
            [
                "--token",
                "tok",
                "--group",
                "cis",
                "--output",
                "report",
                "--report-dir",
                str(tmp_path),
                "-f",
                "json",
            ]
        )

        import json

        with open(tmp_path / "report.json") as f:
            report = json.load(f)

        assert len(report["summary"]["clean_projects"]) == 2

    @patch("gitlab_ioc_scanner.cli.time.sleep")
    @patch("gitlab_ioc_scanner.cli.scan_project")
    @patch("gitlab_ioc_scanner.cli.GitLabClient")
    @patch("gitlab_ioc_scanner.cli.load_iocs")
    def test_report_dir_auto_created(
        self, mock_load, mock_client_cls, mock_scan, mock_sleep, tmp_path
    ):
        """Report directory is automatically created if it doesn't exist."""
        mock_load.return_value = _mock_iocs()
        client = MagicMock()
        _configure_mock_client(client)
        mock_client_cls.return_value = client
        client.get_all_projects.return_value = [_mock_project()]
        mock_scan.return_value = []

        nested_dir = tmp_path / "sub" / "reports"
        assert not nested_dir.exists()

        result = main(
            [
                "--token",
                "tok",
                "--group",
                "cis",
                "--output",
                "report",
                "--report-dir",
                str(nested_dir),
            ]
        )
        assert result == 0
        assert nested_dir.exists()
        assert (nested_dir / "report.csv").exists()
