"""Thin GitLab REST API v4 client with retry and rate-limit handling."""

from __future__ import annotations

import json
import logging
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

log = logging.getLogger("ioc_scanner")


class GitLabClient:
    """Thin GitLab REST API v4 client with retry and rate-limit handling."""

    MAX_RETRIES = 3
    BACKOFF_BASE = 1.0  # seconds

    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip("/")
        self.token = token
        # API call counters — useful for operational metadata
        self.api_calls = 0
        self.api_calls_search = 0
        self.api_calls_file = 0
        self.api_calls_branch = 0
        self.api_calls_other = 0
        self.retries = 0
        self.errors = 0
        # Allow self-signed certs in enterprise environments when explicitly set
        self._ssl_context: ssl.SSLContext | None = None
        if os.environ.get("GL_INSECURE", "").lower() in ("1", "true", "yes"):
            self._ssl_context = ssl.create_default_context()
            self._ssl_context.check_hostname = False
            self._ssl_context.verify_mode = ssl.CERT_NONE
            log.warning("SSL certificate verification is DISABLED (GL_INSECURE=1)")

    # ── Core request method ──────────────────────────────────────────────

    def _request(self, url: str, *, raw: bool = False, timeout: int = 30) -> Any:
        """
        Make an authenticated GET request.

        Parameters
        ----------
        url : str
            Full URL to fetch.
        raw : bool
            If True, return response body as string (for /raw endpoints).
            If False, parse response as JSON.
        timeout : int
            Request timeout in seconds.

        Returns
        -------
        Parsed JSON (dict/list) or str (raw mode), or None on 404/403.
        """
        req = urllib.request.Request(url, headers={"PRIVATE-TOKEN": self.token})

        for attempt in range(1, self.MAX_RETRIES + 1):
            try:
                t0 = time.monotonic()
                if self._ssl_context:
                    resp = urllib.request.urlopen(req, timeout=timeout, context=self._ssl_context)
                else:
                    resp = urllib.request.urlopen(req, timeout=timeout)

                body = resp.read().decode("utf-8", errors="replace")
                elapsed = (time.monotonic() - t0) * 1000
                log.debug(
                    "API %d %s  (%.0fms, %d bytes)",
                    resp.status,
                    url.split("/api/v4")[-1][:120],
                    elapsed,
                    len(body),
                )

                self.api_calls += 1
                if raw:
                    return body
                return json.loads(body)

            except urllib.error.HTTPError as e:
                if e.code == 404:
                    self.api_calls += 1
                    return None
                if e.code == 401:
                    self.api_calls += 1
                    self.errors += 1
                    log.error(
                        "401 Unauthorized — check that GL_TOKEN is valid "
                        "and has read_api + read_repository scopes."
                    )
                    import sys

                    sys.exit(1)
                if e.code == 403:
                    self.api_calls += 1
                    log.debug("403 Forbidden on %s — skipping", url)
                    return None
                if e.code == 429:
                    self.retries += 1
                    retry_after = int(e.headers.get("Retry-After", "5"))
                    wait = max(retry_after, self.BACKOFF_BASE * (2 ** (attempt - 1)))
                    log.warning(
                        "429 Rate limited. Waiting %.1fs (attempt %d/%d)",
                        wait,
                        attempt,
                        self.MAX_RETRIES,
                    )
                    time.sleep(wait)
                    continue
                if e.code >= 500:
                    self.retries += 1
                    wait = self.BACKOFF_BASE * (2 ** (attempt - 1))
                    log.warning(
                        "Server error %d on %s. Retrying in %.1fs (attempt %d/%d)",
                        e.code,
                        url,
                        wait,
                        attempt,
                        self.MAX_RETRIES,
                    )
                    time.sleep(wait)
                    continue
                # Non-retryable HTTP error (e.g. 400, 405, etc.)
                self.api_calls += 1
                self.errors += 1
                log.debug("HTTP %d on %s", e.code, url)
                return None

            except urllib.error.URLError as e:
                self.retries += 1
                wait = self.BACKOFF_BASE * (2 ** (attempt - 1))
                log.warning(
                    "Network error on %s: %s. Retrying in %.1fs (attempt %d/%d)",
                    url,
                    e.reason,
                    wait,
                    attempt,
                    self.MAX_RETRIES,
                )
                time.sleep(wait)

            except json.JSONDecodeError:
                # api_calls already incremented above after successful HTTP response
                self.errors += 1
                log.debug("Non-JSON response from %s", url)
                return None

        self.api_calls += 1
        self.errors += 1
        log.error("Max retries exhausted for %s", url)
        return None

    # ── High-level endpoints ─────────────────────────────────────────────

    def api_get(self, endpoint: str, params: dict) -> Any:
        """Convenience method: build URL from endpoint + query params and fetch."""
        qs = urllib.parse.urlencode(params)
        url = (
            f"{self.base_url}/api/v4{endpoint}?{qs}" if qs else f"{self.base_url}/api/v4{endpoint}"
        )
        return self._request(url)

    def get_raw_file(self, project_id: int, filepath: str, ref: str) -> str | None:
        """Fetch raw file content as a string. Returns None if absent."""
        self.api_calls_file += 1
        encoded = urllib.parse.quote(filepath, safe="")
        url = (
            f"{self.base_url}/api/v4/projects/{project_id}"
            f"/repository/files/{encoded}/raw?" + urllib.parse.urlencode({"ref": ref})
        )
        return self._request(url, raw=True)

    def get_all_projects(self, group: str, project_filter: str = "") -> list[dict]:
        """Fetch all non-archived projects in a group (including subgroups)."""
        projects: list[dict] = []
        page = 1
        encoded_group = urllib.parse.quote(group, safe="")
        log.info("Fetching projects from group '%s' ...", group)

        while True:
            self.api_calls_other += 1
            batch = self.api_get(
                f"/groups/{encoded_group}/projects",
                {
                    "per_page": 100,
                    "page": page,
                    "include_subgroups": "true",
                    "archived": "false",
                    "order_by": "name",
                    "sort": "asc",
                },
            )
            if not batch:
                break
            projects.extend(batch)
            log.debug("  page %d: +%d projects (total: %d)", page, len(batch), len(projects))
            if len(batch) < 100:
                break
            page += 1
            time.sleep(0.2)

        # Apply optional project name filter
        if project_filter:
            pf = project_filter.lower()
            projects = [
                p
                for p in projects
                if pf in p.get("path_with_namespace", "").lower() or pf in p.get("name", "").lower()
            ]
            log.info(
                "  Filtered to %d project(s) matching '%s'",
                len(projects),
                project_filter,
            )

        log.info("  Found %d project(s) in group '%s'", len(projects), group)
        return projects

    def get_repository_tree(
        self, project_id: int, ref: str, path: str = "", recursive: bool = False
    ) -> list[dict]:
        """List files/dirs in a repository path."""
        params: dict[str, Any] = {
            "per_page": 100,
            "ref": ref,
        }
        if path:
            params["path"] = path
        if recursive:
            params["recursive"] = "true"

        all_items: list[dict] = []
        page = 1
        while True:
            params["page"] = page
            self.api_calls_other += 1
            batch = self.api_get(f"/projects/{project_id}/repository/tree", params)
            if not batch:
                break
            all_items.extend(batch)
            if len(batch) < 100:
                break
            page += 1
            time.sleep(0.1)

        return all_items

    def search_blobs(self, project_id: int, search_term: str) -> list[dict]:
        """
        Server-side code search within a project.
        Returns list of blob matches or empty list on failure.
        """
        self.api_calls_search += 1
        results = self.api_get(
            f"/projects/{project_id}/search",
            {"scope": "blobs", "search": search_term, "per_page": 20},
        )
        if isinstance(results, list):
            return results
        return []

    def branch_exists(self, project_id: int, branch_name: str) -> bool:
        """Check whether a branch exists in a project (single API call)."""
        self.api_calls_branch += 1
        encoded = urllib.parse.quote(branch_name, safe="")
        result = self.api_get(f"/projects/{project_id}/repository/branches/{encoded}", {})
        return result is not None
