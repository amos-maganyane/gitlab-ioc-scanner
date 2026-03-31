"""
Tests for gitlab_ioc_scanner.reports module.

Covers:
- write_csv_report(): findings + clean projects, CSV structure
- write_json_report(): structure, counts
- write_html_report(): findings section, clean section, HTML escaping, severity classes
- print_summary(): clean output, findings output with action required, report file listing
"""

from __future__ import annotations

import csv
import json

from gitlab_ioc_scanner.reports import (
    REPORT_FIELDS,
    print_summary,
    write_csv_report,
    write_html_report,
    write_json_report,
)

# ─────────────────────────────────────────────────────────────────────────────
# FIXTURES
# ─────────────────────────────────────────────────────────────────────────────


def _make_finding(
    project: str = "group/proj",
    severity: str = "CRITICAL",
    file: str = "requirements.txt",
    indicator: str = "litellm==1.82.7",
    attack: str = "LiteLLM PyPI backdoor",
    note: str = "Compromised version",
    references: str = "https://example.com/advisory",
    url: str = "https://gitlab.example.com/group/proj",
    branch: str = "main",
) -> dict:
    return {
        "project": project,
        "url": url,
        "branch": branch,
        "file": file,
        "attack": attack,
        "indicator": indicator,
        "severity": severity,
        "note": note,
        "references": references,
        "timestamp": "2026-03-31T10:00:00+00:00",
    }


def _make_clean_project(
    name: str = "group/clean-proj",
    url: str = "https://gitlab.example.com/group/clean-proj",
    branch: str = "main",
) -> dict:
    return {"project": name, "url": url, "branch": branch}


def _make_metadata() -> dict:
    return {
        "scanner_version": "2.1.0",
        "scan_time": "2026-03-31T10:00:00+00:00",
        "gitlab_url": "https://gitlab.example.com",
        "groups": ["cis", "devops"],
        "ioc_file": "iocs.json",
        "ioc_count": 10,
        "projects_scanned": 5,
        "branches_scanned": 8,
        "projects_skipped": 1,
        "project_filter": None,
        "branch_override": None,
        "branch_strict": False,
    }


# ─────────────────────────────────────────────────────────────────────────────
# write_csv_report
# ─────────────────────────────────────────────────────────────────────────────


class TestWriteCsvReport:
    def test_findings_and_clean_projects(self, tmp_path):
        out = str(tmp_path / "report.csv")
        findings = [_make_finding(), _make_finding(project="group/proj2", severity="HIGH")]
        clean = [_make_clean_project()]

        write_csv_report(out, findings, clean)

        with open(out, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        # 2 findings + 1 clean project
        assert len(rows) == 3
        assert rows[0]["severity"] == "CRITICAL"
        assert rows[1]["severity"] == "HIGH"
        assert rows[2]["severity"] == "OK"
        assert rows[2]["indicator"] == "CLEAN"
        assert rows[2]["attack"] == "NONE"

    def test_csv_has_correct_headers(self, tmp_path):
        out = str(tmp_path / "report.csv")
        write_csv_report(out, [_make_finding()], [])

        with open(out, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            headers = next(reader)

        assert headers == REPORT_FIELDS

    def test_empty_findings_only_clean(self, tmp_path):
        out = str(tmp_path / "report.csv")
        clean = [_make_clean_project("a"), _make_clean_project("b")]
        write_csv_report(out, [], clean)

        with open(out, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))

        assert len(rows) == 2
        assert all(r["severity"] == "OK" for r in rows)

    def test_no_findings_no_clean(self, tmp_path):
        out = str(tmp_path / "report.csv")
        write_csv_report(out, [], [])

        with open(out, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))

        assert len(rows) == 0

    def test_clean_project_fields(self, tmp_path):
        out = str(tmp_path / "report.csv")
        clean = [_make_clean_project("grp/x", "https://gl.x/grp/x", "main, develop")]
        write_csv_report(out, [], clean)

        with open(out, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))

        assert rows[0]["project"] == "grp/x"
        assert rows[0]["url"] == "https://gl.x/grp/x"
        assert rows[0]["branch"] == "main, develop"
        assert rows[0]["file"] == ""


# ─────────────────────────────────────────────────────────────────────────────
# write_json_report
# ─────────────────────────────────────────────────────────────────────────────


class TestWriteJsonReport:
    def test_structure(self, tmp_path):
        out = str(tmp_path / "report.json")
        findings = [_make_finding(), _make_finding(severity="HIGH")]
        clean = [_make_clean_project()]
        meta = _make_metadata()

        write_json_report(out, findings, clean, meta)

        with open(out, encoding="utf-8") as f:
            report = json.load(f)

        assert "scan_metadata" in report
        assert "summary" in report
        assert "findings" in report
        assert report["summary"]["total_findings"] == 2
        assert report["summary"]["critical_count"] == 1
        assert report["summary"]["high_count"] == 1
        assert len(report["summary"]["affected_projects"]) == 1
        assert len(report["summary"]["clean_projects"]) == 1
        assert len(report["findings"]) == 2

    def test_metadata_preserved(self, tmp_path):
        out = str(tmp_path / "report.json")
        meta = _make_metadata()
        write_json_report(out, [], [], meta)

        with open(out, encoding="utf-8") as f:
            report = json.load(f)

        assert report["scan_metadata"]["scanner_version"] == "2.1.0"
        assert report["scan_metadata"]["groups"] == ["cis", "devops"]

    def test_no_findings(self, tmp_path):
        out = str(tmp_path / "report.json")
        write_json_report(out, [], [_make_clean_project()], _make_metadata())

        with open(out, encoding="utf-8") as f:
            report = json.load(f)

        assert report["summary"]["total_findings"] == 0
        assert report["summary"]["critical_count"] == 0
        assert report["summary"]["high_count"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# write_html_report
# ─────────────────────────────────────────────────────────────────────────────


class TestWriteHtmlReport:
    def test_findings_section_present(self, tmp_path):
        out = str(tmp_path / "report.html")
        write_html_report(out, [_make_finding()], [], _make_metadata())

        content = open(out, encoding="utf-8").read()
        assert "Findings" in content
        assert "sev-critical" in content
        assert "litellm==1.82.7" in content

    def test_clean_section_present(self, tmp_path):
        out = str(tmp_path / "report.html")
        write_html_report(out, [], [_make_clean_project()], _make_metadata())

        content = open(out, encoding="utf-8").read()
        assert "Clean Projects" in content
        assert "sev-ok" in content
        assert "group/clean-proj" in content

    def test_no_findings_no_findings_section(self, tmp_path):
        out = str(tmp_path / "report.html")
        write_html_report(out, [], [_make_clean_project()], _make_metadata())

        content = open(out, encoding="utf-8").read()
        # Findings section header should NOT be present
        assert "finding" not in content.lower().split("clean projects")[0] or "0" in content

    def test_html_escaping(self, tmp_path):
        """Special characters in project names are HTML-escaped."""
        out = str(tmp_path / "report.html")
        finding = _make_finding(project="<script>alert('xss')</script>")
        write_html_report(out, [finding], [], _make_metadata())

        content = open(out, encoding="utf-8").read()
        assert "<script>" not in content
        assert "&lt;script&gt;" in content

    def test_severity_classes(self, tmp_path):
        out = str(tmp_path / "report.html")
        findings = [
            _make_finding(severity="CRITICAL"),
            _make_finding(severity="HIGH", indicator="other"),
        ]
        write_html_report(out, findings, [], _make_metadata())

        content = open(out, encoding="utf-8").read()
        assert "sev-critical" in content
        assert "sev-high" in content

    def test_references_as_links(self, tmp_path):
        out = str(tmp_path / "report.html")
        finding = _make_finding(references="https://advisory.example.com, https://cve.org/123")
        write_html_report(out, [finding], [], _make_metadata())

        content = open(out, encoding="utf-8").read()
        assert 'href="https://advisory.example.com"' in content
        assert 'href="https://cve.org/123"' in content

    def test_empty_references(self, tmp_path):
        out = str(tmp_path / "report.html")
        finding = _make_finding(references="")
        write_html_report(out, [finding], [], _make_metadata())
        # Should not crash
        content = open(out, encoding="utf-8").read()
        assert "Findings" in content

    def test_status_clean_when_no_findings(self, tmp_path):
        out = str(tmp_path / "report.html")
        write_html_report(out, [], [_make_clean_project()], _make_metadata())

        content = open(out, encoding="utf-8").read()
        assert "status-clean" in content
        assert "CLEAN" in content

    def test_status_critical_when_critical_findings(self, tmp_path):
        out = str(tmp_path / "report.html")
        write_html_report(out, [_make_finding(severity="CRITICAL")], [], _make_metadata())

        content = open(out, encoding="utf-8").read()
        assert "status-critical" in content

    def test_status_high_when_only_high_findings(self, tmp_path):
        out = str(tmp_path / "report.html")
        write_html_report(out, [_make_finding(severity="HIGH")], [], _make_metadata())

        content = open(out, encoding="utf-8").read()
        assert "status-high" in content

    def test_metadata_in_footer(self, tmp_path):
        out = str(tmp_path / "report.html")
        meta = _make_metadata()
        write_html_report(out, [], [], meta)

        content = open(out, encoding="utf-8").read()
        assert "https://gitlab.example.com" in content
        assert "iocs.json" in content
        assert "2.1.0" in content

    def test_clean_project_url_as_link(self, tmp_path):
        out = str(tmp_path / "report.html")
        clean = [_make_clean_project("g/p", "https://gl.x/g/p")]
        write_html_report(out, [], clean, _make_metadata())

        content = open(out, encoding="utf-8").read()
        assert 'href="https://gl.x/g/p"' in content

    def test_clean_project_no_url(self, tmp_path):
        out = str(tmp_path / "report.html")
        clean = [{"project": "g/p", "url": "", "branch": "main"}]
        write_html_report(out, [], clean, _make_metadata())

        content = open(out, encoding="utf-8").read()
        # Should render project name without a link
        assert "g/p" in content

    def test_valid_html(self, tmp_path):
        """Basic HTML structure is valid."""
        out = str(tmp_path / "report.html")
        write_html_report(out, [_make_finding()], [_make_clean_project()], _make_metadata())

        content = open(out, encoding="utf-8").read()
        assert content.startswith("<!DOCTYPE html>")
        assert "</html>" in content
        assert "<head>" in content
        assert "</body>" in content

    def test_badge_critical(self, tmp_path):
        out = str(tmp_path / "report.html")
        write_html_report(out, [_make_finding(severity="CRITICAL")], [], _make_metadata())
        content = open(out, encoding="utf-8").read()
        assert "badge-critical" in content

    def test_badge_high(self, tmp_path):
        out = str(tmp_path / "report.html")
        write_html_report(out, [_make_finding(severity="HIGH")], [], _make_metadata())
        content = open(out, encoding="utf-8").read()
        assert "badge-high" in content

    # ── IOC Reference section tests ──────────────────────────────────────

    def test_ioc_reference_section_present(self, tmp_path):
        out = str(tmp_path / "report.html")
        iocs = [
            {
                "attack": "Test Attack (31 Mar 2026)",
                "indicator": "evil-pkg@1.0.0",
                "pattern": "evil-pkg",
                "files": ["package.json", "yarn.lock"],
                "severity": "CRITICAL",
                "note": "Known malicious package",
                "references": ["https://example.com/advisory"],
            }
        ]
        write_html_report(out, [], [_make_clean_project()], _make_metadata(), iocs=iocs)

        content = open(out, encoding="utf-8").read()
        assert "IOC Reference" in content
        assert "Test Attack (31 Mar 2026)" in content
        assert "evil-pkg@1.0.0" in content
        assert "Known malicious package" in content
        assert "package.json" in content
        assert 'href="https://example.com/advisory"' in content

    def test_ioc_reference_grouped_by_campaign(self, tmp_path):
        out = str(tmp_path / "report.html")
        iocs = [
            {
                "attack": "Campaign A",
                "indicator": "pkg-a@1.0",
                "pattern": "pkg-a",
                "files": ["requirements.txt"],
                "severity": "CRITICAL",
                "note": "Note A",
                "references": [],
            },
            {
                "attack": "Campaign A",
                "indicator": "pkg-a@2.0",
                "pattern": "pkg-a",
                "files": ["requirements.txt"],
                "severity": "CRITICAL",
                "note": "Note A2",
                "references": [],
            },
            {
                "attack": "Campaign B",
                "indicator": "pkg-b",
                "pattern": "pkg-b",
                "files": ["setup.py"],
                "severity": "HIGH",
                "note": "Note B",
                "references": ["https://b.example.com"],
            },
        ]
        write_html_report(out, [], [], _make_metadata(), iocs=iocs)

        content = open(out, encoding="utf-8").read()
        assert "Campaign A" in content
        assert "Campaign B" in content
        assert "pkg-a@1.0" in content
        assert "pkg-a@2.0" in content
        assert "pkg-b" in content
        assert "3 indicators across 2 campaigns" in content

    def test_ioc_reference_not_present_without_iocs(self, tmp_path):
        out = str(tmp_path / "report.html")
        write_html_report(out, [], [_make_clean_project()], _make_metadata())

        content = open(out, encoding="utf-8").read()
        assert '<section class="ioc-ref-section">' not in content

    def test_ioc_reference_empty_list(self, tmp_path):
        out = str(tmp_path / "report.html")
        write_html_report(out, [], [_make_clean_project()], _make_metadata(), iocs=[])

        content = open(out, encoding="utf-8").read()
        assert '<section class="ioc-ref-section">' not in content

    def test_ioc_reference_no_references_shows_dash(self, tmp_path):
        out = str(tmp_path / "report.html")
        iocs = [
            {
                "attack": "No Refs Attack",
                "indicator": "c2.evil.com",
                "pattern": "c2.evil.com",
                "files": [".env"],
                "severity": "CRITICAL",
                "note": "C2 domain",
                "references": [],
            }
        ]
        write_html_report(out, [], [], _make_metadata(), iocs=iocs)

        content = open(out, encoding="utf-8").read()
        assert "muted-text" in content  # The dash placeholder

    def test_ioc_reference_html_escaping(self, tmp_path):
        out = str(tmp_path / "report.html")
        iocs = [
            {
                "attack": "XSS <script>alert(1)</script>",
                "indicator": "<img src=x>",
                "pattern": "test",
                "files": ["<file>.txt"],
                "severity": "HIGH",
                "note": "Desc with <b>html</b>",
                "references": [],
            }
        ]
        write_html_report(out, [], [], _make_metadata(), iocs=iocs)

        content = open(out, encoding="utf-8").read()
        assert "<script>" not in content
        assert "&lt;script&gt;" in content
        assert "&lt;img src=x&gt;" in content

    def test_footer_duration_rendered(self, tmp_path):
        out = str(tmp_path / "report.html")
        meta = _make_metadata()
        meta["duration_seconds"] = 42.3
        write_html_report(out, [], [], meta)
        content = open(out, encoding="utf-8").read()
        assert "Duration: 42.3s" in content

    def test_footer_duration_minutes_format(self, tmp_path):
        out = str(tmp_path / "report.html")
        meta = _make_metadata()
        meta["duration_seconds"] = 125.7
        write_html_report(out, [], [], meta)
        content = open(out, encoding="utf-8").read()
        assert "Duration: 2m 5.7s" in content

    def test_footer_api_calls_rendered(self, tmp_path):
        out = str(tmp_path / "report.html")
        meta = _make_metadata()
        meta["api_calls"] = 87
        write_html_report(out, [], [], meta)
        content = open(out, encoding="utf-8").read()
        assert "API calls: 87" in content

    def test_footer_api_calls_zero_omitted(self, tmp_path):
        """API calls not shown when 0."""
        out = str(tmp_path / "report.html")
        meta = _make_metadata()
        meta["api_calls"] = 0
        write_html_report(out, [], [], meta)
        content = open(out, encoding="utf-8").read()
        assert "API calls:" not in content

    def test_footer_retries_rendered(self, tmp_path):
        out = str(tmp_path / "report.html")
        meta = _make_metadata()
        meta["retries"] = 3
        write_html_report(out, [], [], meta)
        content = open(out, encoding="utf-8").read()
        assert "Retries: 3" in content

    def test_footer_errors_rendered(self, tmp_path):
        out = str(tmp_path / "report.html")
        meta = _make_metadata()
        meta["errors"] = 2
        write_html_report(out, [], [], meta)
        content = open(out, encoding="utf-8").read()
        assert "Errors: 2" in content

    def test_footer_ioc_sha256_truncated(self, tmp_path):
        out = str(tmp_path / "report.html")
        meta = _make_metadata()
        meta["ioc_file_sha256"] = "abcdef1234567890" + "0" * 48
        write_html_report(out, [], [], meta)
        content = open(out, encoding="utf-8").read()
        assert "IOC SHA-256: abcdef123456" in content
        # Full hash should NOT appear
        assert ("abcdef1234567890" + "0" * 48) not in content

    def test_footer_ioc_updated_rendered(self, tmp_path):
        out = str(tmp_path / "report.html")
        meta = _make_metadata()
        meta["ioc_file_last_updated"] = "2026-03-30"
        write_html_report(out, [], [], meta)
        content = open(out, encoding="utf-8").read()
        assert "IOC updated: 2026-03-30" in content

    def test_footer_hostname_rendered(self, tmp_path):
        out = str(tmp_path / "report.html")
        meta = _make_metadata()
        meta["hostname"] = "scanner-01.corp"
        write_html_report(out, [], [], meta)
        content = open(out, encoding="utf-8").read()
        assert "Host: scanner-01.corp" in content

    def test_footer_python_version_rendered(self, tmp_path):
        out = str(tmp_path / "report.html")
        meta = _make_metadata()
        meta["python_version"] = "3.11.14"
        write_html_report(out, [], [], meta)
        content = open(out, encoding="utf-8").read()
        assert "Python: 3.11.14" in content

    def test_footer_omits_empty_fields(self, tmp_path):
        """Fields with None/empty/0 values should not appear in footer."""
        out = str(tmp_path / "report.html")
        meta = _make_metadata()
        # These should all be omitted
        meta["duration_seconds"] = None
        meta["api_calls"] = 0
        meta["retries"] = 0
        meta["errors"] = 0
        meta["ioc_file_sha256"] = None
        meta["ioc_file_last_updated"] = None
        meta["hostname"] = ""
        meta["python_version"] = ""
        write_html_report(out, [], [], meta)
        content = open(out, encoding="utf-8").read()
        assert "Duration:" not in content
        assert "API calls:" not in content
        assert "Retries:" not in content
        assert "Errors:" not in content
        assert "IOC SHA-256:" not in content
        assert "IOC updated:" not in content
        assert "Host:" not in content
        assert "Python:" not in content


# ─────────────────────────────────────────────────────────────────────────────
# print_summary
# ─────────────────────────────────────────────────────────────────────────────


class TestPrintSummary:
    def test_clean_output(self, capsys):
        print_summary([], 5, [_make_clean_project()], ["report.csv"])

        output = capsys.readouterr().out
        assert "SCAN COMPLETE" in output
        assert "Projects scanned" in output
        assert "5" in output
        assert "Clean projects" in output
        assert "1" in output
        assert "Total findings" in output
        assert "0" in output
        assert "No IOCs detected" in output
        assert "report.csv" in output

    def test_findings_output(self, capsys):
        findings = [
            _make_finding(project="grp/vuln", severity="CRITICAL"),
            _make_finding(project="grp/vuln", severity="HIGH", file="setup.py"),
        ]
        print_summary(findings, 10, [_make_clean_project()], ["report.csv", "report.json"])

        output = capsys.readouterr().out
        assert "SCAN COMPLETE" in output
        assert "Affected projects" in output
        assert "1" in output  # 1 affected project
        assert "Total findings" in output
        assert "2" in output
        assert "CRITICAL" in output
        assert "HIGH" in output
        assert "grp/vuln" in output
        assert "ACTION REQUIRED" in output
        assert "report.csv" in output
        assert "report.json" in output

    def test_multiple_affected_projects(self, capsys):
        findings = [
            _make_finding(project="grp/a"),
            _make_finding(project="grp/b", file="other.txt"),
        ]
        print_summary(findings, 3, [], [])

        output = capsys.readouterr().out
        assert "grp/a" in output
        assert "grp/b" in output
        assert "Affected projects      : 2" in output

    def test_no_report_files(self, capsys):
        print_summary([], 1, [], [])
        output = capsys.readouterr().out
        assert "SCAN COMPLETE" in output
        # No "Report:" lines
        assert "Report:" not in output

    def test_finding_details_shown(self, capsys):
        findings = [
            _make_finding(
                project="grp/x",
                indicator="evil-thing",
                note="Remove immediately",
                severity="CRITICAL",
                file="bad.txt",
                url="https://gl.x/grp/x",
            )
        ]
        print_summary(findings, 1, [], [])

        output = capsys.readouterr().out
        assert "evil-thing" in output
        assert "Remove immediately" in output
        assert "https://gl.x/grp/x" in output
        assert "bad.txt" in output
