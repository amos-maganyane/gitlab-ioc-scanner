"""CLI entry point — argument parsing, logging setup, and main orchestration."""

from __future__ import annotations

import argparse
import logging
import os
import platform
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from gitlab_ioc_scanner import __version__
from gitlab_ioc_scanner.client import GitLabClient
from gitlab_ioc_scanner.ioc_loader import ioc_file_metadata, load_iocs
from gitlab_ioc_scanner.reports import (
    print_summary,
    write_csv_report,
    write_html_report,
    write_json_report,
)
from gitlab_ioc_scanner.scanner import scan_project

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────────────────

LOG_FORMAT = "%(asctime)s  %(levelname)-8s  %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

log = logging.getLogger("ioc_scanner")


def setup_logging(level_name: str) -> None:
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(format=LOG_FORMAT, datefmt=LOG_DATE_FORMAT, level=level)
    log.setLevel(level)


# ─────────────────────────────────────────────────────────────────────────────
# CLI ARGUMENT PARSING
# ─────────────────────────────────────────────────────────────────────────────


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="gitlab_ioc_scanner",
        description="Scan GitLab group projects for supply-chain IOCs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--group",
        "-g",
        default=os.environ.get("GL_GROUP", ""),
        help="Comma-separated GitLab group(s) to scan. Env fallback: GL_GROUP  [required]",
    )
    p.add_argument(
        "--gitlab-url",
        "-u",
        default=os.environ.get("GL_URL", "https://gitlab.com").rstrip("/"),
        help="GitLab instance base URL. Env fallback: GL_URL  [default: https://gitlab.com]",
    )
    p.add_argument(
        "--token",
        "-t",
        default=os.environ.get("GL_TOKEN", ""),
        help="GitLab private/personal access token (read_api + read_repository). "
        "Env fallback: GL_TOKEN  [required]",
    )
    p.add_argument(
        "--ioc-file",
        "-i",
        default=os.environ.get("IOC_FILE", "iocs.json"),
        help="Path to IOC definitions JSON file  [default: iocs.json]",
    )
    p.add_argument(
        "--output",
        "-o",
        default=os.environ.get("SCAN_OUTPUT", ""),
        help="Output file name prefix (without extension). Default: ioc_report_<group>_<timestamp>",
    )
    p.add_argument(
        "--report-dir",
        default=os.environ.get("SCAN_REPORT_DIR", "reports"),
        help="Directory to write report files into. Auto-created if missing. "
        "Env fallback: SCAN_REPORT_DIR  [default: reports]",
    )
    p.add_argument(
        "--format",
        "-f",
        nargs="+",
        choices=["csv", "json", "html"],
        default=["csv"],
        help="Output format(s). Specify one or more.  [default: csv]",
    )
    p.add_argument(
        "--workers",
        "-w",
        type=int,
        default=int(os.environ.get("SCAN_WORKERS", "4")),
        help="Number of concurrent project scanning threads  [default: 4]",
    )
    p.add_argument(
        "--project",
        "-p",
        default="",
        help="Filter to a specific project path or name (substring match). "
        "Useful for targeted scans.",
    )
    p.add_argument(
        "--branch",
        "-b",
        default=os.environ.get("GL_BRANCH", ""),
        help="Comma-separated branch(es) to scan instead of each project's "
        "default branch (e.g. main,develop,dev). Each branch that exists "
        "in a project is scanned independently. Env fallback: GL_BRANCH",
    )
    p.add_argument(
        "--branch-strict",
        action="store_true",
        default=os.environ.get("GL_BRANCH_STRICT", "").lower() in ("1", "true", "yes"),
        help="When --branch is set, skip projects where NONE of the listed "
        "branches exist instead of falling back to the default branch. "
        "Env fallback: GL_BRANCH_STRICT=1",
    )
    p.add_argument(
        "--log-level",
        default=os.environ.get("LOG_LEVEL", "INFO"),
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity  [default: INFO]",
    )
    p.add_argument(
        "--debug",
        "-d",
        action="store_true",
        default=os.environ.get("SCAN_DEBUG", "").lower() in ("1", "true", "yes"),
        help="Shortcut for --log-level DEBUG. Shows every API call, file fetch, "
        "regex match attempt, and timing. Env fallback: SCAN_DEBUG=1",
    )
    p.add_argument(
        "--version",
        "-V",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    args = p.parse_args(argv)

    # --debug is a shortcut for --log-level DEBUG
    if args.debug:
        args.log_level = "DEBUG"

    # Validation
    if not args.token:
        p.error("GitLab token is required. Use --token or set GL_TOKEN env var.")
    if not args.group:
        p.error("At least one GitLab group is required. Use --group or set GL_GROUP env var.")

    return args


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    setup_logging(args.log_level)

    log.info("GitLab IOC Scanner v%s starting", __version__)
    log.info("GitLab instance: %s", args.gitlab_url)
    log.debug(
        "Config: groups=%s, ioc_file=%s, format=%s, workers=%d, "
        "branch=%s, branch_strict=%s, project_filter=%s",
        args.group,
        args.ioc_file,
        args.format,
        args.workers,
        args.branch or "(default)",
        args.branch_strict,
        args.project or "(none)",
    )

    # Load IOCs
    try:
        iocs = load_iocs(args.ioc_file)
    except (FileNotFoundError, ValueError) as exc:
        log.error("%s", exc)
        return 1
    except Exception as exc:
        log.error("Failed to load IOC file: %s", exc)
        return 1

    log.debug(
        "Loaded %d IOCs: %s",
        len(iocs),
        [i["indicator"] for i in iocs],
    )

    # Initialize API client
    client = GitLabClient(args.gitlab_url, args.token)

    # Parse groups
    groups = [g.strip() for g in args.group.split(",") if g.strip()]
    log.info("Groups to scan: %s", ", ".join(groups))

    # Collect all projects across groups
    all_projects: list[dict] = []
    for group in groups:
        projects = client.get_all_projects(group, args.project)
        if not projects:
            log.warning(
                "No projects found in group '%s'. Check group name and "
                "token permissions (read_api + read_repository).",
                group,
            )
        all_projects.extend(projects)

    # Deduplicate by project ID (a project may appear in multiple groups)
    seen_ids: set[int] = set()
    unique_projects: list[dict] = []
    for p in all_projects:
        if p["id"] not in seen_ids:
            seen_ids.add(p["id"])
            unique_projects.append(p)

    if not unique_projects:
        log.error("No projects to scan. Exiting.")
        return 1

    log.info("Total unique projects to scan: %d", len(unique_projects))

    # ── Branch resolution ────────────────────────────────────────────────
    target_branches = [b.strip() for b in args.branch.split(",") if b.strip()]
    skipped_projects: list[dict] = []

    if target_branches:
        log.info(
            "Target branch(es): %s (strict=%s)",
            ", ".join(target_branches),
            args.branch_strict,
        )
        resolved_projects: list[tuple[dict, str]] = []  # (project, branch)

        for p in unique_projects:
            pid = p["id"]
            pname = p.get("path_with_namespace", p.get("name", "?"))
            matched_any = False

            for br in target_branches:
                if client.branch_exists(pid, br):
                    resolved_projects.append((p, br))
                    matched_any = True
                    log.debug("  %-50s  branch '%s' found", pname, br)
                else:
                    log.debug("  %-50s  branch '%s' not found", pname, br)
                time.sleep(0.05)

            if not matched_any:
                if args.branch_strict:
                    skipped_projects.append(p)
                    log.info(
                        "  %-50s  SKIPPED (none of %s found, strict mode)",
                        pname,
                        target_branches,
                    )
                else:
                    fallback = p.get("default_branch") or "main"
                    resolved_projects.append((p, fallback))
                    log.info(
                        "  %-50s  none of %s found, falling back to '%s'",
                        pname,
                        target_branches,
                        fallback,
                    )

        if skipped_projects:
            log.info(
                "Skipped %d project(s) without any target branch. Scanning %d project+branch pair(s).",
                len(skipped_projects),
                len(resolved_projects),
            )
    else:
        resolved_projects = [(p, "") for p in unique_projects]

    if not resolved_projects:
        log.error("No projects to scan after branch resolution. Exiting.")
        return 1

    # ── Concurrent scanning ──────────────────────────────────────────────
    scan_start = time.monotonic()
    all_findings: list[dict] = []
    completed = 0

    def _scan_wrapper(project: dict, branch: str) -> tuple[dict, list[dict]]:
        return project, scan_project(client, project, iocs, branch_override=branch)

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(_scan_wrapper, proj, branch): proj for proj, branch in resolved_projects
        }
        for future in as_completed(futures):
            completed += 1
            proj = futures[future]
            pname = proj.get("path_with_namespace", proj.get("name", "?"))
            try:
                _, project_findings = future.result()
                all_findings.extend(project_findings)
                status = "FINDINGS" if project_findings else "clean"
                log.info("[%3d/%d] %-50s  %s", completed, len(resolved_projects), pname, status)
            except Exception as exc:
                log.error(
                    "[%3d/%d] %-50s  ERROR: %s",
                    completed,
                    len(resolved_projects),
                    pname,
                    exc,
                )

    # ── Determine clean projects ─────────────────────────────────────────
    # A project may have been scanned on multiple branches. Collect all
    # branches scanned per project and which project+branch combos had findings.
    project_branches: dict[str, list[str]] = {}  # pname → [branch, ...]
    project_data: dict[str, dict] = {}  # pname → project dict
    for proj, branch in resolved_projects:
        pname = proj.get("path_with_namespace", proj.get("name", ""))
        effective_branch = branch or proj.get("default_branch", "main")
        project_branches.setdefault(pname, []).append(effective_branch)
        project_data[pname] = proj

    affected_names = {f["project"] for f in all_findings}
    clean_projects: list[dict] = [
        {
            "project": pname,
            "url": project_data[pname].get("web_url", ""),
            "branch": ", ".join(sorted(set(branches))),
        }
        for pname, branches in project_branches.items()
        if pname not in affected_names
    ]

    # ── Generate reports ─────────────────────────────────────────────────
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    group_slug = "_".join(g.replace("/", "-") for g in groups)
    basename = args.output if args.output else f"ioc_report_{group_slug}_{ts}"

    # Ensure report directory exists
    report_dir = Path(args.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    prefix = str(report_dir / basename)

    total_projects_scanned = len(project_branches)

    duration_seconds = round(time.monotonic() - scan_start, 1)
    ioc_meta = ioc_file_metadata(args.ioc_file)

    scan_metadata = {
        "scanner_version": __version__,
        "scan_time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "gitlab_url": args.gitlab_url,
        "groups": groups,
        "ioc_file": args.ioc_file,
        "ioc_count": len(iocs),
        "ioc_file_sha256": ioc_meta["sha256"],
        "ioc_file_last_updated": ioc_meta["last_updated"],
        "projects_scanned": total_projects_scanned,
        "branches_scanned": len(resolved_projects),
        "projects_skipped": len(skipped_projects),
        "project_filter": args.project or None,
        "branch_override": target_branches or None,
        "branch_strict": args.branch_strict,
        "duration_seconds": duration_seconds,
        "api_calls": client.api_calls,
        "api_calls_search": client.api_calls_search,
        "api_calls_file": client.api_calls_file,
        "api_calls_branch": client.api_calls_branch,
        "api_calls_other": client.api_calls_other,
        "retries": client.retries,
        "errors": client.errors,
        "python_version": sys.version.split()[0],
        "hostname": platform.node(),
    }

    report_files: list[str] = []
    if "csv" in args.format:
        csv_path = f"{prefix}.csv"
        write_csv_report(csv_path, all_findings, clean_projects)
        report_files.append(csv_path)

    if "json" in args.format:
        json_path = f"{prefix}.json"
        write_json_report(json_path, all_findings, clean_projects, scan_metadata)
        report_files.append(json_path)

    if "html" in args.format:
        html_path = f"{prefix}.html"
        write_html_report(html_path, all_findings, clean_projects, scan_metadata, iocs=iocs)
        report_files.append(html_path)

    # ── Console output ───────────────────────────────────────────────────
    print_summary(all_findings, total_projects_scanned, clean_projects, report_files)

    # ── Exit code ────────────────────────────────────────────────────────
    has_critical = any(f["severity"] == "CRITICAL" for f in all_findings)
    has_high = any(f["severity"] == "HIGH" for f in all_findings)

    if has_critical:
        return 2
    if has_high:
        return 3
    return 0
