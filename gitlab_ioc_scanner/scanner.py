"""Project scanning — file resolution, IOC matching, and scan orchestration."""

from __future__ import annotations

import fnmatch
import logging
import time
from datetime import datetime, timezone

from gitlab_ioc_scanner.client import GitLabClient

log = logging.getLogger("ioc_scanner")


# ─────────────────────────────────────────────────────────────────────────────
# GLOB RESOLUTION
# ─────────────────────────────────────────────────────────────────────────────


def resolve_file_targets(
    client: GitLabClient,
    project_id: int,
    ref: str,
    file_patterns: list[str],
    tree_cache: dict[int, list[str]],
) -> list[str]:
    """
    Expand a mixed list of exact filenames and glob patterns into concrete
    file paths that exist in the repository.

    Uses a per-project tree cache to avoid repeated API calls.
    """
    exact_files: list[str] = []
    glob_patterns: list[str] = []

    for fp in file_patterns:
        if "*" in fp or "?" in fp or "[" in fp:
            glob_patterns.append(fp)
        else:
            exact_files.append(fp)

    if not glob_patterns:
        return exact_files

    # Build tree listing (cached per project)
    if project_id not in tree_cache:
        tree = client.get_repository_tree(project_id, ref, recursive=True)
        tree_cache[project_id] = [item["path"] for item in tree if item.get("type") == "blob"]
        log.debug(
            "Tree cache built for project %d: %d files", project_id, len(tree_cache[project_id])
        )

    all_paths = tree_cache[project_id]

    matched: set[str] = set()
    for pattern in glob_patterns:
        before = len(matched)
        for fpath in all_paths:
            if fnmatch.fnmatch(fpath, pattern):
                matched.add(fpath)
        log.debug("  Glob '%s' → %d new match(es)", pattern, len(matched) - before)

    return exact_files + sorted(matched)


# ─────────────────────────────────────────────────────────────────────────────
# SUBDIRECTORY DISCOVERY
# ─────────────────────────────────────────────────────────────────────────────


def extract_subdirectory_paths(
    blobs: list[dict],
    file_patterns: list[str],
) -> list[str]:
    """
    Discover subdirectory file paths from Search API blob results.

    When a search hit is in a subdirectory (e.g. ``web/package.json``), the
    standard file target list (``["package.json"]``) will miss it because
    ``get_raw_file`` only looks at root. This function extracts directory
    prefixes from blob paths and generates subdirectory variants of exact
    file targets.

    Only exact filenames (no globs) are expanded — glob patterns are already
    resolved against the full tree by ``resolve_file_targets``.

    Returns a deduplicated, sorted list of additional subdirectory paths
    not already in ``file_patterns``.
    """
    if not blobs:
        return []

    # Collect unique directory prefixes from blob paths
    dir_prefixes: set[str] = set()
    for blob in blobs:
        blob_path = blob.get("path") or blob.get("filename") or ""
        if "/" in blob_path:
            # e.g. "web/package.json" → "web/"
            dir_prefixes.add(blob_path.rsplit("/", 1)[0] + "/")

    if not dir_prefixes:
        return []

    # Only expand exact filenames (not globs)
    exact_files = {fp for fp in file_patterns if "*" not in fp and "?" not in fp and "[" not in fp}
    existing = set(file_patterns)

    extra_paths: set[str] = set()
    for prefix in dir_prefixes:
        for fname in exact_files:
            candidate = prefix + fname
            if candidate not in existing:
                extra_paths.add(candidate)

    result = sorted(extra_paths)
    if result:
        log.debug("  Subdirectory paths from search blobs: %s", result[:10])
    return result


# ─────────────────────────────────────────────────────────────────────────────
# MATCHING
# ─────────────────────────────────────────────────────────────────────────────


def match_ioc(content: str, ioc: dict) -> bool:
    """
    Check whether file content matches an IOC.

    Uses compiled context regex if available; falls back to case-insensitive
    substring search on the pattern field.
    """
    compiled = ioc.get("_context_re")
    if compiled:
        hit = compiled.search(content) is not None
        if hit:
            log.debug("    Context regex HIT for '%s'", ioc["indicator"])
        return hit

    hit = ioc["pattern"].lower() in content.lower()
    if hit:
        log.debug("    Substring HIT for '%s' (pattern='%s')", ioc["indicator"], ioc["pattern"])
    return hit


# ─────────────────────────────────────────────────────────────────────────────
# PROJECT SCANNER
# ─────────────────────────────────────────────────────────────────────────────


def scan_project(
    client: GitLabClient,
    project: dict,
    iocs: list[dict],
    use_search_api: bool = True,
    branch_override: str = "",
) -> list[dict]:
    """
    Scan a single project for all IOCs.
    Returns a list of finding dicts.
    """
    pid = project["id"]
    pname = project.get("path_with_namespace", project.get("name", str(pid)))
    purl = project.get("web_url", "")
    branch = branch_override or project.get("default_branch") or "main"

    findings: list[dict] = []
    tree_cache: dict[int, list[str]] = {}
    log.debug("[%s] Scanning on branch '%s' (%d IOCs to check)", pname, branch, len(iocs))

    # ── Phase A: Quick pre-filter via search API ─────────────────────────
    # Check which IOC patterns have *any* hits in the project. For those
    # that don't match server-side, skip the expensive file-by-file fetch.
    # Store actual blob results so we can extract subdirectory paths later.
    search_blobs: dict[str, list[dict]] = {}  # pattern -> blob list
    if use_search_api:
        for ioc in iocs:
            pattern = ioc["pattern"]
            if pattern in search_blobs:
                continue
            try:
                blobs = client.search_blobs(pid, pattern)
                search_blobs[pattern] = blobs
                if blobs:
                    log.debug(
                        "[%s] Search API: '%s' → %d blob(s) found", pname, pattern, len(blobs)
                    )
                else:
                    log.debug("[%s] Search API: '%s' → no hits, skipping file scan", pname, pattern)
            except Exception:
                # Search API unavailable — fall back to file fetch
                search_blobs[pattern] = [{"_fallback": True}]  # sentinel: assume possible match
                log.debug(
                    "[%s] Search API: '%s' → error, falling back to file scan", pname, pattern
                )
            time.sleep(0.05)

    # ── Phase B: File-level scan ─────────────────────────────────────────
    files_fetched = 0
    files_matched = 0
    for ioc in iocs:
        pattern = ioc["pattern"]

        # Skip if search API confirmed no hits
        blobs = search_blobs.get(pattern)
        if use_search_api and not blobs:
            continue

        # Resolve file targets (handles globs)
        targets = resolve_file_targets(client, pid, branch, ioc["files"], tree_cache)

        # Discover subdirectory paths from search blob results
        if use_search_api and blobs:
            subdir_paths = extract_subdirectory_paths(blobs, ioc["files"])
            if subdir_paths:
                targets = targets + subdir_paths

        # Promote actual blob paths from search API that aren't already
        # in targets.  This closes the gap where a dependency appears in
        # a file type not listed in the IOC's predefined "files" list
        # (e.g. a custom deps.json or monorepo workspace file).
        if use_search_api and blobs:
            target_set = set(targets)
            for blob in blobs:
                blob_path = blob.get("path") or blob.get("filename") or ""
                if blob_path and blob_path not in target_set:
                    targets.append(blob_path)
                    target_set.add(blob_path)
                    log.debug("[%s]   Promoted blob path: %s", pname, blob_path)

        log.debug(
            "[%s] IOC '%s': %d target file(s) to check %s",
            pname,
            ioc["indicator"],
            len(targets),
            targets[:8],
        )

        for fpath in targets:
            content = client.get_raw_file(pid, fpath, branch)
            if content is None:
                log.debug("[%s]   %s → not found (404)", pname, fpath)
                continue
            files_fetched += 1

            if match_ioc(content, ioc):
                files_matched += 1
                log.debug("[%s]   %s → MATCH for '%s'", pname, fpath, ioc["indicator"])
                findings.append(
                    {
                        "project": pname,
                        "url": purl,
                        "branch": branch,
                        "file": fpath,
                        "attack": ioc["attack"],
                        "indicator": ioc["indicator"],
                        "severity": ioc["severity"],
                        "note": ioc["note"],
                        "references": ", ".join(ioc.get("references", [])),
                        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    }
                )
                log.warning("  MATCH  %-8s  %-45s  %s", ioc["severity"], fpath, ioc["indicator"])

    if not findings:
        log.info("  [CLEAN]  %s", pname)

    log.debug(
        "[%s] Done: %d files fetched, %d matches, %d findings",
        pname,
        files_fetched,
        files_matched,
        len(findings),
    )
    return findings
