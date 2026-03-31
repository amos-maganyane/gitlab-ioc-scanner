"""
Tests for gitlab_ioc_scanner.scanner module.

Covers:
- resolve_file_targets(): exact files, glob patterns, mixed, tree cache, empty patterns
- extract_subdirectory_paths(): subdirectory discovery from search blobs
- scan_project(): full scan with mocked GitLabClient
"""

from __future__ import annotations

import re
from unittest.mock import MagicMock, patch

from gitlab_ioc_scanner.scanner import (
    extract_subdirectory_paths,
    resolve_file_targets,
    scan_project,
)

# ─────────────────────────────────────────────────────────────────────────────
# FIXTURES
# ─────────────────────────────────────────────────────────────────────────────


def _make_ioc(
    indicator: str = "test-ioc",
    pattern: str = "evil-pkg",
    files: list[str] | None = None,
    severity: str = "HIGH",
    context: str = "",
    attack: str = "Test Attack",
    note: str = "Test note",
) -> dict:
    """Helper to build an IOC dict."""
    ioc = {
        "indicator": indicator,
        "pattern": pattern,
        "files": files or ["requirements.txt"],
        "severity": severity,
        "attack": attack,
        "note": note,
        "references": ["https://example.com"],
    }
    if context:
        ioc["context"] = context
        ioc["_context_re"] = re.compile(context, re.IGNORECASE | re.DOTALL)
    return ioc


def _make_project(
    pid: int = 1,
    name: str = "group/test-project",
    url: str = "https://gitlab.example.com/group/test-project",
    default_branch: str = "main",
) -> dict:
    return {
        "id": pid,
        "path_with_namespace": name,
        "web_url": url,
        "default_branch": default_branch,
    }


def _mock_client() -> MagicMock:
    """Create a mock GitLabClient."""
    client = MagicMock()
    client.get_repository_tree.return_value = []
    client.get_raw_file.return_value = None
    client.search_blobs.return_value = []
    return client


# ─────────────────────────────────────────────────────────────────────────────
# resolve_file_targets
# ─────────────────────────────────────────────────────────────────────────────


class TestResolveFileTargets:
    def test_exact_files_only_no_tree_call(self):
        """When all patterns are exact filenames, no tree API call is made."""
        client = _mock_client()
        cache: dict[int, list[str]] = {}
        result = resolve_file_targets(client, 1, "main", ["package.json", "yarn.lock"], cache)
        assert result == ["package.json", "yarn.lock"]
        client.get_repository_tree.assert_not_called()
        assert 1 not in cache

    def test_glob_patterns_resolve_from_tree(self):
        """Glob patterns get resolved against the repository tree."""
        client = _mock_client()
        client.get_repository_tree.return_value = [
            {"path": "requirements.txt", "type": "blob"},
            {"path": "src/requirements.txt", "type": "blob"},
            {"path": "src/main.py", "type": "blob"},
            {"path": "src", "type": "tree"},  # directories filtered out
        ]
        cache: dict[int, list[str]] = {}
        # fnmatch("src/requirements.txt", "**/requirements.txt") matches but
        # fnmatch("requirements.txt", "**/requirements.txt") does NOT (no dir prefix).
        # Use *.txt to test basic glob resolution
        result = resolve_file_targets(client, 1, "main", ["*.txt"], cache)
        assert "requirements.txt" in result
        # tree entries (type=tree) are NOT in the cache
        assert "src" not in cache.get(1, [])

    def test_mixed_exact_and_glob(self):
        """Exact files come first, then sorted glob matches."""
        client = _mock_client()
        client.get_repository_tree.return_value = [
            {"path": "a/Dockerfile", "type": "blob"},
            {"path": "b/Dockerfile", "type": "blob"},
            {"path": "c/other.txt", "type": "blob"},
        ]
        cache: dict[int, list[str]] = {}
        result = resolve_file_targets(client, 1, "main", ["package.json", "*/Dockerfile"], cache)
        assert result[0] == "package.json"  # exact first
        assert "a/Dockerfile" in result
        assert "b/Dockerfile" in result
        assert "c/other.txt" not in result

    def test_tree_cache_reuse(self):
        """Second call with same project ID reuses cache, no API call."""
        client = _mock_client()
        client.get_repository_tree.return_value = [
            {"path": "lib/foo.py", "type": "blob"},
        ]
        cache: dict[int, list[str]] = {}
        # First call populates cache
        resolve_file_targets(client, 42, "main", ["*.py"], cache)
        assert 42 in cache
        assert client.get_repository_tree.call_count == 1

        # Second call reuses cache
        resolve_file_targets(client, 42, "main", ["*.py"], cache)
        assert client.get_repository_tree.call_count == 1  # no additional call

    def test_empty_patterns(self):
        """Empty pattern list returns empty result."""
        client = _mock_client()
        cache: dict[int, list[str]] = {}
        result = resolve_file_targets(client, 1, "main", [], cache)
        assert result == []

    def test_question_mark_glob(self):
        """'?' glob character triggers tree resolution."""
        client = _mock_client()
        client.get_repository_tree.return_value = [
            {"path": "a.py", "type": "blob"},
            {"path": "ab.py", "type": "blob"},
        ]
        cache: dict[int, list[str]] = {}
        result = resolve_file_targets(client, 1, "main", ["?.py"], cache)
        assert "a.py" in result
        assert "ab.py" not in result  # ? matches single char only

    def test_bracket_glob(self):
        """'[' glob character triggers tree resolution."""
        client = _mock_client()
        client.get_repository_tree.return_value = [
            {"path": "a.py", "type": "blob"},
            {"path": "b.py", "type": "blob"},
            {"path": "c.py", "type": "blob"},
        ]
        cache: dict[int, list[str]] = {}
        result = resolve_file_targets(client, 1, "main", ["[ab].py"], cache)
        assert "a.py" in result
        assert "b.py" in result
        assert "c.py" not in result

    def test_glob_no_matches(self):
        """Glob that matches nothing returns only exact files."""
        client = _mock_client()
        client.get_repository_tree.return_value = [
            {"path": "readme.md", "type": "blob"},
        ]
        cache: dict[int, list[str]] = {}
        result = resolve_file_targets(client, 1, "main", ["exact.txt", "*.nonexistent"], cache)
        assert result == ["exact.txt"]


# ─────────────────────────────────────────────────────────────────────────────
# extract_subdirectory_paths
# ─────────────────────────────────────────────────────────────────────────────


class TestExtractSubdirectoryPaths:
    def test_basic_subdirectory_discovery(self):
        """Blobs in subdirectories generate additional file paths."""
        blobs = [
            {"path": "web/package.json", "filename": "package.json"},
        ]
        patterns = ["package.json", "package-lock.json", "yarn.lock"]
        result = extract_subdirectory_paths(blobs, patterns)
        assert "web/package.json" in result
        assert "web/package-lock.json" in result
        assert "web/yarn.lock" in result

    def test_root_level_blobs_no_extra_paths(self):
        """Blobs at root level don't generate extra paths."""
        blobs = [
            {"path": "package.json", "filename": "package.json"},
        ]
        patterns = ["package.json", "package-lock.json"]
        result = extract_subdirectory_paths(blobs, patterns)
        assert result == []

    def test_multiple_subdirectories(self):
        """Blobs in different subdirectories expand all combinations."""
        blobs = [
            {"path": "web/package.json"},
            {"path": "apps/frontend/package.json"},
        ]
        patterns = ["package.json", "yarn.lock"]
        result = extract_subdirectory_paths(blobs, patterns)
        assert "web/package.json" in result
        assert "web/yarn.lock" in result
        assert "apps/frontend/package.json" in result
        assert "apps/frontend/yarn.lock" in result

    def test_empty_blobs(self):
        """Empty blob list returns no extra paths."""
        result = extract_subdirectory_paths([], ["package.json"])
        assert result == []

    def test_globs_not_expanded(self):
        """Glob patterns in file_patterns are NOT expanded for subdirs."""
        blobs = [{"path": "web/something.js"}]
        patterns = ["package.json", "*.config.js"]
        result = extract_subdirectory_paths(blobs, patterns)
        assert "web/package.json" in result
        # Glob should NOT be expanded
        assert "web/*.config.js" not in result

    def test_existing_patterns_not_duplicated(self):
        """Paths already in file_patterns are not duplicated."""
        blobs = [{"path": "web/package.json"}]
        patterns = ["package.json", "web/package.json"]  # already includes subdir path
        result = extract_subdirectory_paths(blobs, patterns)
        assert "web/package.json" not in result  # already in patterns

    def test_fallback_field_uses_filename(self):
        """Falls back to 'filename' when 'path' is missing."""
        blobs = [{"filename": "src/requirements.txt"}]
        patterns = ["requirements.txt"]
        result = extract_subdirectory_paths(blobs, patterns)
        assert "src/requirements.txt" in result

    def test_blobs_without_path_or_filename(self):
        """Blobs with neither 'path' nor 'filename' are skipped."""
        blobs = [{"data": "some content", "_fallback": True}]
        patterns = ["package.json"]
        result = extract_subdirectory_paths(blobs, patterns)
        assert result == []

    def test_deeply_nested_paths(self):
        """Multi-level subdirectory paths are correctly extracted."""
        blobs = [{"path": "packages/frontend/web/package.json"}]
        patterns = ["package.json", "package-lock.json"]
        result = extract_subdirectory_paths(blobs, patterns)
        assert "packages/frontend/web/package.json" in result
        assert "packages/frontend/web/package-lock.json" in result

    def test_result_is_sorted(self):
        """Results are returned sorted."""
        blobs = [
            {"path": "z-dir/file.txt"},
            {"path": "a-dir/file.txt"},
        ]
        patterns = ["file.txt", "other.txt"]
        result = extract_subdirectory_paths(blobs, patterns)
        assert result == sorted(result)

    def test_question_mark_glob_not_expanded(self):
        """'?' glob patterns are NOT expanded for subdirectories."""
        blobs = [{"path": "web/setup.py"}]
        patterns = ["setup.py", "?.cfg"]
        result = extract_subdirectory_paths(blobs, patterns)
        assert "web/setup.py" in result
        assert "web/?.cfg" not in result

    def test_bracket_glob_not_expanded(self):
        """'[' glob patterns are NOT expanded for subdirectories."""
        blobs = [{"path": "lib/config.yml"}]
        patterns = ["config.yml", "[Dd]ockerfile"]
        result = extract_subdirectory_paths(blobs, patterns)
        assert "lib/config.yml" in result
        assert "lib/[Dd]ockerfile" not in result


# ─────────────────────────────────────────────────────────────────────────────
# scan_project
# ─────────────────────────────────────────────────────────────────────────────


class TestScanProject:
    @patch("gitlab_ioc_scanner.scanner.time.sleep")
    def test_finding_detected(self, mock_sleep):
        """When a file matches an IOC, a finding is returned."""
        client = _mock_client()
        client.search_blobs.return_value = [{"data": "evil-pkg"}]
        client.get_raw_file.return_value = "depends on evil-pkg==1.0.0"

        project = _make_project()
        ioc = _make_ioc(files=["requirements.txt"])
        findings = scan_project(client, project, [ioc])

        assert len(findings) == 1
        assert findings[0]["project"] == "group/test-project"
        assert findings[0]["file"] == "requirements.txt"
        assert findings[0]["severity"] == "HIGH"
        assert findings[0]["attack"] == "Test Attack"
        assert findings[0]["indicator"] == "test-ioc"
        assert findings[0]["url"] == "https://gitlab.example.com/group/test-project"
        assert findings[0]["branch"] == "main"
        assert "timestamp" in findings[0]

    @patch("gitlab_ioc_scanner.scanner.time.sleep")
    def test_clean_project(self, mock_sleep):
        """When no files match, empty findings list is returned."""
        client = _mock_client()
        client.search_blobs.return_value = [{"data": "something"}]
        client.get_raw_file.return_value = "nothing suspicious here"

        project = _make_project()
        ioc = _make_ioc()
        findings = scan_project(client, project, [ioc])
        assert findings == []

    @patch("gitlab_ioc_scanner.scanner.time.sleep")
    def test_search_api_prefilter_skips_ioc(self, mock_sleep):
        """When search API returns no blobs, file scan is skipped."""
        client = _mock_client()
        client.search_blobs.return_value = []  # no hits

        project = _make_project()
        ioc = _make_ioc()
        findings = scan_project(client, project, [ioc])

        assert findings == []
        # get_raw_file should NOT have been called since search said no hits
        client.get_raw_file.assert_not_called()

    @patch("gitlab_ioc_scanner.scanner.time.sleep")
    def test_search_api_error_falls_back(self, mock_sleep):
        """When search API raises an exception, file scan proceeds."""
        client = _mock_client()
        client.search_blobs.side_effect = Exception("search unavailable")
        client.get_raw_file.return_value = "contains evil-pkg here"

        project = _make_project()
        ioc = _make_ioc()
        findings = scan_project(client, project, [ioc])

        # Should still find the IOC via file scan fallback
        assert len(findings) == 1
        client.get_raw_file.assert_called_once()

    @patch("gitlab_ioc_scanner.scanner.time.sleep")
    def test_file_404_handling(self, mock_sleep):
        """When get_raw_file returns None (404), file is skipped gracefully."""
        client = _mock_client()
        client.search_blobs.return_value = [{"data": "hit"}]
        client.get_raw_file.return_value = None  # file not found

        project = _make_project()
        ioc = _make_ioc()
        findings = scan_project(client, project, [ioc])
        assert findings == []

    @patch("gitlab_ioc_scanner.scanner.time.sleep")
    def test_use_search_api_false(self, mock_sleep):
        """When use_search_api=False, search API is not called."""
        client = _mock_client()
        client.get_raw_file.return_value = "contains evil-pkg here"

        project = _make_project()
        ioc = _make_ioc()
        findings = scan_project(client, project, [ioc], use_search_api=False)

        client.search_blobs.assert_not_called()
        assert len(findings) == 1

    @patch("gitlab_ioc_scanner.scanner.time.sleep")
    def test_branch_override(self, mock_sleep):
        """branch_override replaces default branch in the scan."""
        client = _mock_client()
        client.search_blobs.return_value = [{"data": "hit"}]
        client.get_raw_file.return_value = "evil-pkg found"

        project = _make_project(default_branch="main")
        ioc = _make_ioc()
        findings = scan_project(client, project, [ioc], branch_override="develop")

        assert findings[0]["branch"] == "develop"
        # Verify the raw file call used the override branch
        call_args = client.get_raw_file.call_args
        assert call_args[0][2] == "develop"

    @patch("gitlab_ioc_scanner.scanner.time.sleep")
    def test_project_without_default_branch(self, mock_sleep):
        """When project has no default_branch, falls back to 'main'."""
        client = _mock_client()
        client.search_blobs.return_value = [{"data": "hit"}]
        client.get_raw_file.return_value = "evil-pkg detected"

        project = {"id": 1, "path_with_namespace": "g/p", "web_url": "http://x"}
        ioc = _make_ioc()
        findings = scan_project(client, project, [ioc])
        assert findings[0]["branch"] == "main"

    @patch("gitlab_ioc_scanner.scanner.time.sleep")
    def test_multiple_iocs_multiple_files(self, mock_sleep):
        """Multiple IOCs scanning multiple files returns all findings."""
        client = _mock_client()
        client.search_blobs.return_value = [{"data": "hit"}]

        def raw_file_side_effect(pid, fpath, ref):
            if fpath == "requirements.txt":
                return "evil-pkg"
            if fpath == "package.json":
                return '{"dependencies": {"bad-npm": "1.0"}}'
            return None

        client.get_raw_file.side_effect = raw_file_side_effect

        project = _make_project()
        ioc1 = _make_ioc(indicator="ioc-1", pattern="evil-pkg", files=["requirements.txt"])
        ioc2 = _make_ioc(indicator="ioc-2", pattern="bad-npm", files=["package.json"])

        findings = scan_project(client, project, [ioc1, ioc2])
        assert len(findings) == 2
        indicators = {f["indicator"] for f in findings}
        assert indicators == {"ioc-1", "ioc-2"}

    @patch("gitlab_ioc_scanner.scanner.time.sleep")
    def test_references_joined(self, mock_sleep):
        """References list is joined as comma-separated string."""
        client = _mock_client()
        client.search_blobs.return_value = [{"data": "hit"}]
        client.get_raw_file.return_value = "evil-pkg"

        project = _make_project()
        ioc = _make_ioc()
        ioc["references"] = ["https://a.com", "https://b.com"]

        findings = scan_project(client, project, [ioc])
        assert findings[0]["references"] == "https://a.com, https://b.com"

    @patch("gitlab_ioc_scanner.scanner.time.sleep")
    def test_duplicate_search_pattern_not_searched_twice(self, mock_sleep):
        """If two IOCs share the same pattern, search API is called once."""
        client = _mock_client()
        client.search_blobs.return_value = []

        project = _make_project()
        ioc1 = _make_ioc(indicator="ioc-a", pattern="shared-pattern", files=["a.txt"])
        ioc2 = _make_ioc(indicator="ioc-b", pattern="shared-pattern", files=["b.txt"])

        scan_project(client, project, [ioc1, ioc2])
        # search_blobs called once for "shared-pattern", not twice
        assert client.search_blobs.call_count == 1

    @patch("gitlab_ioc_scanner.scanner.time.sleep")
    def test_project_minimal_fields(self, mock_sleep):
        """Project dict with minimal fields still works."""
        client = _mock_client()
        client.search_blobs.return_value = [{"data": "hit"}]
        client.get_raw_file.return_value = "evil-pkg"

        project = {"id": 99, "name": "minimal"}
        ioc = _make_ioc()
        findings = scan_project(client, project, [ioc])
        assert findings[0]["project"] == "minimal"
        assert findings[0]["url"] == ""

    @patch("gitlab_ioc_scanner.scanner.time.sleep")
    def test_glob_files_in_ioc(self, mock_sleep):
        """IOC with glob file patterns triggers tree resolution."""
        client = _mock_client()
        client.search_blobs.return_value = [{"data": "hit"}]
        client.get_repository_tree.return_value = [
            {"path": "apps/service-a/requirements.txt", "type": "blob"},
            {"path": "apps/service-b/requirements.txt", "type": "blob"},
        ]

        def raw_file_side_effect(pid, fpath, ref):
            return "evil-pkg"

        client.get_raw_file.side_effect = raw_file_side_effect

        project = _make_project()
        ioc = _make_ioc(files=["**/requirements.txt"])
        findings = scan_project(client, project, [ioc])
        assert len(findings) == 2

    @patch("gitlab_ioc_scanner.scanner.time.sleep")
    def test_subdirectory_discovery_from_search_blobs(self, mock_sleep):
        """When search blobs include subdirectory paths, scanner checks those paths too."""
        client = _mock_client()
        # Search finds hit in web/package.json (subdirectory)
        client.search_blobs.return_value = [
            {"path": "web/package.json", "filename": "package.json", "data": "1.14.1"},
        ]

        def raw_file_side_effect(pid, fpath, ref):
            if fpath == "package.json":
                return None  # root-level doesn't exist
            if fpath == "package-lock.json":
                return None
            if fpath == "web/package.json":
                return '{"dependencies": {"axios": "1.14.1"}}'
            if fpath == "web/package-lock.json":
                return None
            return None

        client.get_raw_file.side_effect = raw_file_side_effect

        project = _make_project()
        ioc = _make_ioc(
            indicator="axios@1.14.1",
            pattern="1.14.1",
            files=["package.json", "package-lock.json"],
            context=r'"axios"\s*:\s*"[^"]*1\.14\.1',
        )

        findings = scan_project(client, project, [ioc])
        assert len(findings) == 1
        assert findings[0]["file"] == "web/package.json"
        assert findings[0]["indicator"] == "axios@1.14.1"

    @patch("gitlab_ioc_scanner.scanner.time.sleep")
    def test_subdirectory_discovery_multiple_dirs(self, mock_sleep):
        """Subdirectory discovery works with multiple subdirectories."""
        client = _mock_client()
        client.search_blobs.return_value = [
            {"path": "frontend/package.json"},
            {"path": "admin/package.json"},
        ]

        found_paths = []

        def raw_file_side_effect(pid, fpath, ref):
            found_paths.append(fpath)
            if fpath in ("frontend/package.json", "admin/package.json"):
                return "evil-pkg inside"
            return None

        client.get_raw_file.side_effect = raw_file_side_effect

        project = _make_project()
        ioc = _make_ioc(files=["package.json"])

        findings = scan_project(client, project, [ioc])
        # Should find evil-pkg in both subdirectory package.json files
        assert len(findings) == 2
        found_files = {f["file"] for f in findings}
        assert "frontend/package.json" in found_files
        assert "admin/package.json" in found_files

    @patch("gitlab_ioc_scanner.scanner.time.sleep")
    def test_subdirectory_not_added_when_search_api_disabled(self, mock_sleep):
        """When use_search_api=False, subdirectory discovery doesn't run."""
        client = _mock_client()
        client.get_raw_file.return_value = None  # nothing at root

        project = _make_project()
        ioc = _make_ioc(files=["package.json"])
        findings = scan_project(client, project, [ioc], use_search_api=False)

        assert findings == []
        # Only root-level file should be checked
        client.get_raw_file.assert_called_once_with(1, "package.json", "main")

    @patch("gitlab_ioc_scanner.scanner.time.sleep")
    def test_search_error_fallback_no_subdir_expansion(self, mock_sleep):
        """When search API errors, fallback sentinel doesn't generate subdir paths."""
        client = _mock_client()
        client.search_blobs.side_effect = Exception("search unavailable")
        client.get_raw_file.return_value = "contains evil-pkg here"

        project = _make_project()
        ioc = _make_ioc(files=["requirements.txt"])
        findings = scan_project(client, project, [ioc])

        # Should still find via fallback (root file)
        assert len(findings) == 1
        # Only root-level file checked (sentinel has no path field)
        client.get_raw_file.assert_called_once_with(1, "requirements.txt", "main")

    # ── Blob path promotion ──────────────────────────────────────────────

    @patch("gitlab_ioc_scanner.scanner.time.sleep")
    def test_blob_path_promoted_when_not_in_targets(self, mock_sleep):
        """Search blob paths outside predefined file list get promoted and scanned."""
        client = _mock_client()
        # Search finds hit in a non-standard file not in the IOC's "files" list
        client.search_blobs.return_value = [
            {"path": "scripts/custom-deps.json", "data": "evil-pkg"},
        ]

        def raw_file_side_effect(pid, fpath, ref):
            if fpath == "scripts/custom-deps.json":
                return "evil-pkg is here"
            return None  # requirements.txt doesn't exist

        client.get_raw_file.side_effect = raw_file_side_effect

        project = _make_project()
        ioc = _make_ioc(files=["requirements.txt"])  # custom-deps.json not listed
        findings = scan_project(client, project, [ioc])

        assert len(findings) == 1
        assert findings[0]["file"] == "scripts/custom-deps.json"

    @patch("gitlab_ioc_scanner.scanner.time.sleep")
    def test_blob_path_not_duplicated_when_already_in_targets(self, mock_sleep):
        """Blob paths already in the target list are not fetched twice."""
        client = _mock_client()
        client.search_blobs.return_value = [
            {"path": "requirements.txt", "data": "evil-pkg"},
        ]
        client.get_raw_file.return_value = "evil-pkg here"

        project = _make_project()
        ioc = _make_ioc(files=["requirements.txt"])
        findings = scan_project(client, project, [ioc])

        # requirements.txt is already in the predefined file list, so it should
        # only be fetched once, not twice
        raw_calls = [c[0][1] for c in client.get_raw_file.call_args_list]
        assert raw_calls.count("requirements.txt") == 1
        assert len(findings) == 1

    @patch("gitlab_ioc_scanner.scanner.time.sleep")
    def test_blob_path_promotion_skips_empty_paths(self, mock_sleep):
        """Blobs without path or filename (e.g. fallback sentinel) are not promoted."""
        client = _mock_client()
        client.search_blobs.return_value = [
            {"data": "just data, no path field"},
        ]
        client.get_raw_file.return_value = None

        project = _make_project()
        ioc = _make_ioc(files=["requirements.txt"])
        scan_project(client, project, [ioc])

        # Only the predefined requirements.txt should be checked
        raw_calls = [c[0][1] for c in client.get_raw_file.call_args_list]
        assert raw_calls == ["requirements.txt"]

    @patch("gitlab_ioc_scanner.scanner.time.sleep")
    def test_blob_path_promotion_uses_filename_fallback(self, mock_sleep):
        """Blob promotion falls back to 'filename' field when 'path' is missing."""
        client = _mock_client()
        client.search_blobs.return_value = [
            {"filename": "vendor/deps.txt", "data": "evil-pkg"},
        ]

        def raw_file_side_effect(pid, fpath, ref):
            if fpath == "vendor/deps.txt":
                return "evil-pkg"
            return None

        client.get_raw_file.side_effect = raw_file_side_effect

        project = _make_project()
        ioc = _make_ioc(files=["requirements.txt"])
        findings = scan_project(client, project, [ioc])

        assert len(findings) == 1
        assert findings[0]["file"] == "vendor/deps.txt"

    @patch("gitlab_ioc_scanner.scanner.time.sleep")
    def test_blob_path_promotion_with_context_regex(self, mock_sleep):
        """Promoted blob path content is still validated against context regex."""
        client = _mock_client()
        client.search_blobs.return_value = [
            {"path": "custom/manifest.json", "data": "1.14.1"},
        ]

        def raw_file_side_effect(pid, fpath, ref):
            if fpath == "custom/manifest.json":
                # Contains the version but NOT for axios — should NOT match
                return '{"dependencies": {"lodash": "1.14.1"}}'
            return None

        client.get_raw_file.side_effect = raw_file_side_effect

        project = _make_project()
        ioc = _make_ioc(
            indicator="axios@1.14.1",
            pattern="1.14.1",
            files=["package.json"],
            context=r'"axios"\s*:\s*"[^"]*1\.14\.1',
        )
        findings = scan_project(client, project, [ioc])

        # The promoted file was fetched and scanned but context regex rejects it
        assert findings == []
