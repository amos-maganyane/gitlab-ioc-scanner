"""
Tests for gitlab_ioc_scanner.client module.

Covers:
- GitLabClient.__init__ (normal, GL_INSECURE=1)
- _request() (JSON, raw, 404, 401, 403, 429, 500, URLError, JSONDecodeError, retries exhausted)
- api_get(), get_raw_file()
- get_all_projects() (single page, multi-page, project_filter, empty group)
- get_repository_tree() (with path, recursive, pagination)
- search_blobs() (normal, non-list result)
- branch_exists() (true, false)

All network calls are mocked via unittest.mock.patch on urllib.request.urlopen.
"""

from __future__ import annotations

import urllib.error
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest

from gitlab_ioc_scanner.client import GitLabClient

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────


def _mock_response(body: str | bytes, status: int = 200, headers: dict | None = None) -> MagicMock:
    """Create a mock HTTP response object."""
    if isinstance(body, str):
        body = body.encode("utf-8")
    resp = MagicMock()
    resp.read.return_value = body
    resp.status = status
    resp.headers = headers or {}
    return resp


def _make_http_error(code: int, headers: dict | None = None) -> urllib.error.HTTPError:
    """Create an HTTPError with the given code."""
    err = urllib.error.HTTPError(
        url="https://gitlab.example.com/api/v4/test",
        code=code,
        msg=f"HTTP {code}",
        hdrs=MagicMock(),
        fp=BytesIO(b"error"),
    )
    if headers:
        err.headers = headers
    else:
        err.headers = {}
    return err


# ─────────────────────────────────────────────────────────────────────────────
# __init__
# ─────────────────────────────────────────────────────────────────────────────


class TestGitLabClientInit:
    def test_normal_init(self):
        c = GitLabClient("https://gitlab.example.com/", "test-token")
        assert c.base_url == "https://gitlab.example.com"  # trailing slash stripped
        assert c.token == "test-token"
        assert c._ssl_context is None

    @patch.dict("os.environ", {"GL_INSECURE": "1"})
    def test_insecure_mode(self):
        c = GitLabClient("https://gitlab.example.com", "tok")
        assert c._ssl_context is not None
        assert c._ssl_context.check_hostname is False

    @patch.dict("os.environ", {"GL_INSECURE": "true"})
    def test_insecure_mode_true_string(self):
        c = GitLabClient("https://gitlab.example.com", "tok")
        assert c._ssl_context is not None

    @patch.dict("os.environ", {"GL_INSECURE": "no"})
    def test_insecure_mode_no(self):
        c = GitLabClient("https://gitlab.example.com", "tok")
        assert c._ssl_context is None

    @patch.dict("os.environ", {}, clear=False)
    def test_no_insecure_env(self):
        import os

        os.environ.pop("GL_INSECURE", None)
        c = GitLabClient("https://gitlab.example.com", "tok")
        assert c._ssl_context is None


# ─────────────────────────────────────────────────────────────────────────────
# _request
# ─────────────────────────────────────────────────────────────────────────────


class TestRequest:
    @patch("urllib.request.urlopen")
    def test_successful_json(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response('{"key": "value"}')
        c = GitLabClient("https://gl.example.com", "tok")
        result = c._request("https://gl.example.com/api/v4/test")
        assert result == {"key": "value"}

    @patch("urllib.request.urlopen")
    def test_successful_raw(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response("raw file content here")
        c = GitLabClient("https://gl.example.com", "tok")
        result = c._request("https://gl.example.com/api/v4/raw", raw=True)
        assert result == "raw file content here"

    @patch("urllib.request.urlopen")
    def test_404_returns_none(self, mock_urlopen):
        mock_urlopen.side_effect = _make_http_error(404)
        c = GitLabClient("https://gl.example.com", "tok")
        result = c._request("https://gl.example.com/api/v4/notfound")
        assert result is None

    @patch("urllib.request.urlopen")
    def test_401_exits(self, mock_urlopen):
        mock_urlopen.side_effect = _make_http_error(401)
        c = GitLabClient("https://gl.example.com", "tok")
        with pytest.raises(SystemExit):
            c._request("https://gl.example.com/api/v4/unauthorized")

    @patch("urllib.request.urlopen")
    def test_403_returns_none(self, mock_urlopen):
        mock_urlopen.side_effect = _make_http_error(403)
        c = GitLabClient("https://gl.example.com", "tok")
        result = c._request("https://gl.example.com/api/v4/forbidden")
        assert result is None

    @patch("gitlab_ioc_scanner.client.time.sleep")
    @patch("urllib.request.urlopen")
    def test_429_retries_with_backoff(self, mock_urlopen, mock_sleep):
        """429 retries then succeeds on second attempt."""
        error = _make_http_error(429, headers={"Retry-After": "2"})
        mock_urlopen.side_effect = [error, _mock_response('{"ok": true}')]
        c = GitLabClient("https://gl.example.com", "tok")
        result = c._request("https://gl.example.com/api/v4/ratelimit")
        assert result == {"ok": True}
        mock_sleep.assert_called_once()
        # Wait should be max(retry_after=2, backoff=1.0)
        assert mock_sleep.call_args[0][0] >= 2

    @patch("gitlab_ioc_scanner.client.time.sleep")
    @patch("urllib.request.urlopen")
    def test_500_retries(self, mock_urlopen, mock_sleep):
        """500 retries with exponential backoff then succeeds."""
        error = _make_http_error(500)
        mock_urlopen.side_effect = [error, _mock_response('{"recovered": true}')]
        c = GitLabClient("https://gl.example.com", "tok")
        result = c._request("https://gl.example.com/api/v4/server-error")
        assert result == {"recovered": True}
        mock_sleep.assert_called_once()

    @patch("gitlab_ioc_scanner.client.time.sleep")
    @patch("urllib.request.urlopen")
    def test_url_error_retries(self, mock_urlopen, mock_sleep):
        """URLError (network failure) retries then succeeds."""
        mock_urlopen.side_effect = [
            urllib.error.URLError("Connection refused"),
            _mock_response('{"ok": true}'),
        ]
        c = GitLabClient("https://gl.example.com", "tok")
        result = c._request("https://gl.example.com/api/v4/network")
        assert result == {"ok": True}
        mock_sleep.assert_called_once()

    @patch("urllib.request.urlopen")
    def test_json_decode_error_returns_none(self, mock_urlopen):
        """Non-JSON body in non-raw mode returns None."""
        mock_urlopen.return_value = _mock_response("this is not json {{{")
        c = GitLabClient("https://gl.example.com", "tok")
        result = c._request("https://gl.example.com/api/v4/bad-json")
        assert result is None

    @patch("gitlab_ioc_scanner.client.time.sleep")
    @patch("urllib.request.urlopen")
    def test_retries_exhausted_returns_none(self, mock_urlopen, mock_sleep):
        """After MAX_RETRIES attempts on 500, returns None."""
        mock_urlopen.side_effect = _make_http_error(500)
        c = GitLabClient("https://gl.example.com", "tok")
        result = c._request("https://gl.example.com/api/v4/always-500")
        assert result is None
        assert mock_urlopen.call_count == c.MAX_RETRIES

    @patch("gitlab_ioc_scanner.client.time.sleep")
    @patch("urllib.request.urlopen")
    def test_url_error_retries_exhausted(self, mock_urlopen, mock_sleep):
        """After MAX_RETRIES URLErrors, returns None."""
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
        c = GitLabClient("https://gl.example.com", "tok")
        result = c._request("https://gl.example.com/api/v4/always-down")
        assert result is None
        assert mock_urlopen.call_count == c.MAX_RETRIES

    @patch("urllib.request.urlopen")
    def test_other_http_error_returns_none(self, mock_urlopen):
        """Other HTTP errors (e.g. 418) return None without retry."""
        mock_urlopen.side_effect = _make_http_error(418)
        c = GitLabClient("https://gl.example.com", "tok")
        result = c._request("https://gl.example.com/api/v4/teapot")
        assert result is None
        assert mock_urlopen.call_count == 1

    @patch("urllib.request.urlopen")
    def test_ssl_context_used_when_set(self, mock_urlopen):
        """When _ssl_context is set, urlopen receives it."""
        mock_urlopen.return_value = _mock_response('{"ok": true}')
        c = GitLabClient("https://gl.example.com", "tok")
        import ssl

        c._ssl_context = ssl.create_default_context()
        c._ssl_context.check_hostname = False
        c._ssl_context.verify_mode = ssl.CERT_NONE

        c._request("https://gl.example.com/api/v4/secure")
        call_kwargs = mock_urlopen.call_args
        assert (
            "context" in call_kwargs.kwargs
            or (len(call_kwargs.args) > 2 if call_kwargs.args else False)
            or any(k == "context" for k in (call_kwargs.kwargs or {}))
        )

    @patch("gitlab_ioc_scanner.client.time.sleep")
    @patch("urllib.request.urlopen")
    def test_429_no_retry_after_header(self, mock_urlopen, mock_sleep):
        """429 without Retry-After header uses default '5'."""
        error = _make_http_error(429, headers={})
        # Make headers.get return default "5"
        error.headers = MagicMock()
        error.headers.get.return_value = "5"
        mock_urlopen.side_effect = [error, _mock_response('{"ok": true}')]

        c = GitLabClient("https://gl.example.com", "tok")
        result = c._request("https://gl.example.com/api/v4/rate")
        assert result == {"ok": True}


# ─────────────────────────────────────────────────────────────────────────────
# api_get
# ─────────────────────────────────────────────────────────────────────────────


class TestApiGet:
    @patch("urllib.request.urlopen")
    def test_with_params(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response('[{"id": 1}]')
        c = GitLabClient("https://gl.example.com", "tok")
        result = c.api_get("/projects/1/search", {"scope": "blobs", "search": "test"})
        assert result == [{"id": 1}]
        # Verify URL construction
        call_url = mock_urlopen.call_args[0][0].full_url
        assert "/api/v4/projects/1/search?" in call_url
        assert "scope=blobs" in call_url

    @patch("urllib.request.urlopen")
    def test_empty_params(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response('{"status": "ok"}')
        c = GitLabClient("https://gl.example.com", "tok")
        result = c.api_get("/test", {})
        assert result == {"status": "ok"}
        call_url = mock_urlopen.call_args[0][0].full_url
        assert call_url == "https://gl.example.com/api/v4/test"


# ─────────────────────────────────────────────────────────────────────────────
# get_raw_file
# ─────────────────────────────────────────────────────────────────────────────


class TestGetRawFile:
    @patch("urllib.request.urlopen")
    def test_returns_content(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response("file content here")
        c = GitLabClient("https://gl.example.com", "tok")
        result = c.get_raw_file(1, "src/main.py", "main")
        assert result == "file content here"
        call_url = mock_urlopen.call_args[0][0].full_url
        assert "/repository/files/" in call_url
        assert "ref=main" in call_url

    @patch("urllib.request.urlopen")
    def test_returns_none_on_404(self, mock_urlopen):
        mock_urlopen.side_effect = _make_http_error(404)
        c = GitLabClient("https://gl.example.com", "tok")
        result = c.get_raw_file(1, "nonexistent.py", "main")
        assert result is None

    @patch("urllib.request.urlopen")
    def test_encodes_filepath(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response("content")
        c = GitLabClient("https://gl.example.com", "tok")
        c.get_raw_file(1, "path/to/deep/file.py", "main")
        call_url = mock_urlopen.call_args[0][0].full_url
        # '/' in filepath should be encoded as %2F
        assert "path%2Fto%2Fdeep%2Ffile.py" in call_url


# ─────────────────────────────────────────────────────────────────────────────
# get_all_projects
# ─────────────────────────────────────────────────────────────────────────────


class TestGetAllProjects:
    @patch("gitlab_ioc_scanner.client.time.sleep")
    @patch.object(GitLabClient, "api_get")
    def test_single_page(self, mock_api_get, mock_sleep):
        """Single page of projects (< 100 items)."""
        mock_api_get.return_value = [
            {"id": 1, "name": "proj1", "path_with_namespace": "grp/proj1"},
            {"id": 2, "name": "proj2", "path_with_namespace": "grp/proj2"},
        ]
        c = GitLabClient("https://gl.example.com", "tok")
        result = c.get_all_projects("grp")
        assert len(result) == 2
        mock_api_get.assert_called_once()

    @patch("gitlab_ioc_scanner.client.time.sleep")
    @patch.object(GitLabClient, "api_get")
    def test_multi_page_pagination(self, mock_api_get, mock_sleep):
        """Multiple pages paginated correctly."""
        page1 = [{"id": i, "name": f"p{i}", "path_with_namespace": f"g/p{i}"} for i in range(100)]
        page2 = [{"id": 100, "name": "p100", "path_with_namespace": "g/p100"}]
        mock_api_get.side_effect = [page1, page2]
        c = GitLabClient("https://gl.example.com", "tok")
        result = c.get_all_projects("grp")
        assert len(result) == 101
        assert mock_api_get.call_count == 2

    @patch("gitlab_ioc_scanner.client.time.sleep")
    @patch.object(GitLabClient, "api_get")
    def test_project_filter(self, mock_api_get, mock_sleep):
        mock_api_get.return_value = [
            {"id": 1, "name": "web-app", "path_with_namespace": "grp/web-app"},
            {"id": 2, "name": "api-service", "path_with_namespace": "grp/api-service"},
            {"id": 3, "name": "web-frontend", "path_with_namespace": "grp/web-frontend"},
        ]
        c = GitLabClient("https://gl.example.com", "tok")
        result = c.get_all_projects("grp", project_filter="web")
        assert len(result) == 2
        assert all("web" in p["name"].lower() for p in result)

    @patch("gitlab_ioc_scanner.client.time.sleep")
    @patch.object(GitLabClient, "api_get")
    def test_empty_group(self, mock_api_get, mock_sleep):
        mock_api_get.return_value = []
        c = GitLabClient("https://gl.example.com", "tok")
        result = c.get_all_projects("empty-group")
        assert result == []

    @patch("gitlab_ioc_scanner.client.time.sleep")
    @patch.object(GitLabClient, "api_get")
    def test_none_response_breaks_pagination(self, mock_api_get, mock_sleep):
        """If api_get returns None (error), pagination stops."""
        mock_api_get.return_value = None
        c = GitLabClient("https://gl.example.com", "tok")
        result = c.get_all_projects("grp")
        assert result == []


# ─────────────────────────────────────────────────────────────────────────────
# get_repository_tree
# ─────────────────────────────────────────────────────────────────────────────


class TestGetRepositoryTree:
    @patch("gitlab_ioc_scanner.client.time.sleep")
    @patch.object(GitLabClient, "api_get")
    def test_basic_tree(self, mock_api_get, mock_sleep):
        mock_api_get.return_value = [
            {"path": "src/main.py", "type": "blob"},
            {"path": "src", "type": "tree"},
        ]
        c = GitLabClient("https://gl.example.com", "tok")
        result = c.get_repository_tree(1, "main")
        assert len(result) == 2

    @patch("gitlab_ioc_scanner.client.time.sleep")
    @patch.object(GitLabClient, "api_get")
    def test_with_path(self, mock_api_get, mock_sleep):
        mock_api_get.return_value = [{"path": "src/lib/util.py", "type": "blob"}]
        c = GitLabClient("https://gl.example.com", "tok")
        c.get_repository_tree(1, "main", path="src/lib")
        call_args = mock_api_get.call_args
        assert call_args[0][1]["path"] == "src/lib"

    @patch("gitlab_ioc_scanner.client.time.sleep")
    @patch.object(GitLabClient, "api_get")
    def test_recursive(self, mock_api_get, mock_sleep):
        mock_api_get.return_value = [{"path": "a/b/c.py", "type": "blob"}]
        c = GitLabClient("https://gl.example.com", "tok")
        c.get_repository_tree(1, "main", recursive=True)
        call_args = mock_api_get.call_args
        assert call_args[0][1]["recursive"] == "true"

    @patch("gitlab_ioc_scanner.client.time.sleep")
    @patch.object(GitLabClient, "api_get")
    def test_pagination(self, mock_api_get, mock_sleep):
        page1 = [{"path": f"f{i}.py", "type": "blob"} for i in range(100)]
        page2 = [{"path": "last.py", "type": "blob"}]
        mock_api_get.side_effect = [page1, page2]
        c = GitLabClient("https://gl.example.com", "tok")
        result = c.get_repository_tree(1, "main")
        assert len(result) == 101

    @patch("gitlab_ioc_scanner.client.time.sleep")
    @patch.object(GitLabClient, "api_get")
    def test_empty_tree(self, mock_api_get, mock_sleep):
        mock_api_get.return_value = []
        c = GitLabClient("https://gl.example.com", "tok")
        result = c.get_repository_tree(1, "main")
        assert result == []


# ─────────────────────────────────────────────────────────────────────────────
# search_blobs
# ─────────────────────────────────────────────────────────────────────────────


class TestSearchBlobs:
    @patch.object(GitLabClient, "api_get")
    def test_returns_results(self, mock_api_get):
        mock_api_get.return_value = [{"data": "match1"}, {"data": "match2"}]
        c = GitLabClient("https://gl.example.com", "tok")
        result = c.search_blobs(1, "evil-pkg")
        assert len(result) == 2

    @patch.object(GitLabClient, "api_get")
    def test_non_list_result_returns_empty(self, mock_api_get):
        """When API returns non-list (e.g. error dict), returns empty list."""
        mock_api_get.return_value = {"error": "something went wrong"}
        c = GitLabClient("https://gl.example.com", "tok")
        result = c.search_blobs(1, "test")
        assert result == []

    @patch.object(GitLabClient, "api_get")
    def test_none_result_returns_empty(self, mock_api_get):
        mock_api_get.return_value = None
        c = GitLabClient("https://gl.example.com", "tok")
        result = c.search_blobs(1, "test")
        assert result == []


# ─────────────────────────────────────────────────────────────────────────────
# branch_exists
# ─────────────────────────────────────────────────────────────────────────────


class TestBranchExists:
    @patch.object(GitLabClient, "api_get")
    def test_branch_exists_true(self, mock_api_get):
        mock_api_get.return_value = {"name": "main", "commit": {"id": "abc"}}
        c = GitLabClient("https://gl.example.com", "tok")
        assert c.branch_exists(1, "main") is True

    @patch.object(GitLabClient, "api_get")
    def test_branch_exists_false(self, mock_api_get):
        mock_api_get.return_value = None
        c = GitLabClient("https://gl.example.com", "tok")
        assert c.branch_exists(1, "nonexistent") is False

    @patch.object(GitLabClient, "api_get")
    def test_branch_name_encoded(self, mock_api_get):
        mock_api_get.return_value = {"name": "feature/test"}
        c = GitLabClient("https://gl.example.com", "tok")
        c.branch_exists(1, "feature/test")
        call_args = mock_api_get.call_args[0][0]
        assert "feature%2Ftest" in call_args


# ─────────────────────────────────────────────────────────────────────────────
# API call counters
# ─────────────────────────────────────────────────────────────────────────────


class TestCounters:
    """Verify that API call, retry and error counters increment correctly."""

    def test_counters_init_zero(self):
        c = GitLabClient("https://gl.example.com", "tok")
        assert c.api_calls == 0
        assert c.api_calls_search == 0
        assert c.api_calls_file == 0
        assert c.api_calls_branch == 0
        assert c.api_calls_other == 0
        assert c.retries == 0
        assert c.errors == 0

    @patch("urllib.request.urlopen")
    def test_successful_request_increments_api_calls(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response('{"ok": true}')
        c = GitLabClient("https://gl.example.com", "tok")
        c._request("https://gl.example.com/api/v4/test")
        assert c.api_calls == 1

    @patch("urllib.request.urlopen")
    def test_404_increments_api_calls(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError("url", 404, "Not Found", {}, BytesIO(b""))
        c = GitLabClient("https://gl.example.com", "tok")
        c._request("https://gl.example.com/api/v4/test")
        assert c.api_calls == 1
        assert c.errors == 0  # 404 is not an error

    @patch("urllib.request.urlopen")
    def test_403_increments_api_calls(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError("url", 403, "Forbidden", {}, BytesIO(b""))
        c = GitLabClient("https://gl.example.com", "tok")
        c._request("https://gl.example.com/api/v4/test")
        assert c.api_calls == 1
        assert c.errors == 0  # 403 is not an error

    @patch("gitlab_ioc_scanner.client.time.sleep")
    @patch("urllib.request.urlopen")
    def test_429_increments_retries(self, mock_urlopen, mock_sleep):
        # First call 429, second success
        mock_urlopen.side_effect = [
            urllib.error.HTTPError("url", 429, "Rate Limit", {"Retry-After": "1"}, BytesIO(b"")),
            _mock_response('{"ok": true}'),
        ]
        c = GitLabClient("https://gl.example.com", "tok")
        c._request("https://gl.example.com/api/v4/test")
        assert c.retries == 1
        assert c.api_calls == 1  # only the successful one counts

    @patch("gitlab_ioc_scanner.client.time.sleep")
    @patch("urllib.request.urlopen")
    def test_500_increments_retries(self, mock_urlopen, mock_sleep):
        # First 500, then success
        mock_urlopen.side_effect = [
            urllib.error.HTTPError("url", 500, "Server Error", {}, BytesIO(b"")),
            _mock_response('{"ok": true}'),
        ]
        c = GitLabClient("https://gl.example.com", "tok")
        c._request("https://gl.example.com/api/v4/test")
        assert c.retries == 1
        assert c.api_calls == 1

    @patch("gitlab_ioc_scanner.client.time.sleep")
    @patch("urllib.request.urlopen")
    def test_url_error_increments_retries(self, mock_urlopen, mock_sleep):
        mock_urlopen.side_effect = [
            urllib.error.URLError("Connection refused"),
            _mock_response('{"ok": true}'),
        ]
        c = GitLabClient("https://gl.example.com", "tok")
        c._request("https://gl.example.com/api/v4/test")
        assert c.retries == 1

    @patch("gitlab_ioc_scanner.client.time.sleep")
    @patch("urllib.request.urlopen")
    def test_max_retries_increments_errors(self, mock_urlopen, mock_sleep):
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
        c = GitLabClient("https://gl.example.com", "tok")
        c._request("https://gl.example.com/api/v4/test")
        assert c.retries == 3  # MAX_RETRIES = 3
        assert c.errors == 1
        assert c.api_calls == 1

    @patch("urllib.request.urlopen")
    def test_non_retryable_http_error_increments_errors(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "url", 400, "Bad Request", {}, BytesIO(b"")
        )
        c = GitLabClient("https://gl.example.com", "tok")
        c._request("https://gl.example.com/api/v4/test")
        assert c.api_calls == 1
        assert c.errors == 1

    @patch("urllib.request.urlopen")
    def test_json_decode_error_increments_errors(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response("not json at all")
        c = GitLabClient("https://gl.example.com", "tok")
        c._request("https://gl.example.com/api/v4/test")
        assert c.api_calls == 1
        assert c.errors == 1

    @patch.object(GitLabClient, "api_get")
    def test_search_blobs_increments_search_counter(self, mock_api_get):
        mock_api_get.return_value = []
        c = GitLabClient("https://gl.example.com", "tok")
        c.search_blobs(1, "test")
        assert c.api_calls_search == 1
        assert c.api_calls_other == 0

    @patch("urllib.request.urlopen")
    def test_get_raw_file_increments_file_counter(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response("file content")
        c = GitLabClient("https://gl.example.com", "tok")
        c.get_raw_file(1, "README.md", "main")
        assert c.api_calls_file == 1

    @patch.object(GitLabClient, "api_get")
    def test_branch_exists_increments_branch_counter(self, mock_api_get):
        mock_api_get.return_value = {"name": "main"}
        c = GitLabClient("https://gl.example.com", "tok")
        c.branch_exists(1, "main")
        assert c.api_calls_branch == 1
        assert c.api_calls_other == 0

    @patch.object(GitLabClient, "api_get")
    def test_get_all_projects_increments_other_counter(self, mock_api_get):
        mock_api_get.return_value = [{"id": 1, "path_with_namespace": "g/p", "name": "p"}]
        c = GitLabClient("https://gl.example.com", "tok")
        c.get_all_projects("group")
        assert c.api_calls_other == 1
