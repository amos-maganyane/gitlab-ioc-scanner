#!/usr/bin/env python3
"""
IOC Validation & Testing Helper
================================
Validates IOC entries in iocs.json and lets you test them against sample file
content before deploying to production scans.

Usage
-----
    # Validate all IOCs in iocs.json (schema + regex compilation)
    python3 validate_ioc.py

    # Test a specific IOC against sample content (should match)
    python3 validate_ioc.py --test "axios@1.14.1" --content '{"dependencies": {"axios": "1.14.1"}}'

    # Test against a local file
    python3 validate_ioc.py --test "axios@1.14.1" --file sample_package.json

    # Test that something should NOT match (expect no hit)
    python3 validate_ioc.py --test "axios@1.14.1" --content '{"dependencies": {"lodash": "1.14.1"}}' --expect-clean

    # Interactive mode: add a new IOC with guided prompts
    python3 validate_ioc.py --new
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# COLORS (terminal)
# ─────────────────────────────────────────────────────────────────────────────

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def ok(msg: str) -> str:
    return f"  {GREEN}PASS{RESET}  {msg}"


def fail(msg: str) -> str:
    return f"  {RED}FAIL{RESET}  {msg}"


def warn(msg: str) -> str:
    return f"  {YELLOW}WARN{RESET}  {msg}"


def info(msg: str) -> str:
    return f"  {CYAN}INFO{RESET}  {msg}"


# ─────────────────────────────────────────────────────────────────────────────
# VALIDATION
# ─────────────────────────────────────────────────────────────────────────────

REQUIRED_FIELDS = {"attack", "indicator", "pattern", "files", "severity", "note"}
VALID_SEVERITIES = {"CRITICAL", "HIGH"}


def validate_ioc_entry(ioc: dict, index: int) -> list[str]:
    """Validate a single IOC entry. Returns list of error strings (empty = valid)."""
    errors: list[str] = []

    # Required fields
    missing = REQUIRED_FIELDS - set(ioc.keys())
    if missing:
        errors.append(f"Missing required fields: {', '.join(sorted(missing))}")

    # Severity
    sev = ioc.get("severity", "")
    if sev and sev not in VALID_SEVERITIES:
        errors.append(f"Invalid severity '{sev}' — must be CRITICAL or HIGH")

    # Files must be a non-empty list
    files = ioc.get("files")
    if files is not None and (not isinstance(files, list) or len(files) == 0):
        errors.append("'files' must be a non-empty list of filename patterns")

    # Context regex compilation
    ctx = ioc.get("context", "")
    if ctx:
        try:
            re.compile(ctx, re.IGNORECASE)
        except re.error as e:
            errors.append(f"Invalid context regex: {e}")

    # Warnings (non-fatal)
    warnings: list[str] = []
    if not ctx:
        warnings.append(
            "No 'context' regex — will fall back to simple substring match. "
            "This may cause false positives for generic patterns."
        )

    refs = ioc.get("references", [])
    if not refs:
        warnings.append("No 'references' — consider adding advisory URLs for analyst context.")

    return errors, warnings


def validate_all(ioc_file: str) -> bool:
    """Validate all IOC entries. Returns True if all pass."""
    path = Path(ioc_file)
    if not path.is_file():
        print(fail(f"IOC file not found: {ioc_file}"))
        return False

    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(fail(f"Invalid JSON: {e}"))
        return False

    iocs = data.get("iocs", [])
    if not iocs:
        print(fail("No IOC entries found in 'iocs' array"))
        return False

    print(f"\n{BOLD}Validating {len(iocs)} IOC entries in {ioc_file}{RESET}\n")

    all_ok = True
    indicators_seen: set[str] = set()

    for i, ioc in enumerate(iocs):
        indicator = ioc.get("indicator", f"<entry {i}>")
        errors, warnings = validate_ioc_entry(ioc, i)

        # Duplicate check
        if indicator in indicators_seen:
            warnings.append(f"Duplicate indicator '{indicator}'")
        indicators_seen.add(indicator)

        if errors:
            all_ok = False
            print(fail(f"[{i}] {indicator}"))
            for e in errors:
                print(f"        {RED}{e}{RESET}")
        else:
            print(ok(f"[{i}] {indicator}"))

        for w in warnings:
            print(f"        {YELLOW}{w}{RESET}")

    print()
    if all_ok:
        print(f"{GREEN}{BOLD}All {len(iocs)} IOC entries are valid.{RESET}\n")
    else:
        print(f"{RED}{BOLD}Validation failed — fix errors above.{RESET}\n")

    return all_ok


# ─────────────────────────────────────────────────────────────────────────────
# TESTING IOCs AGAINST CONTENT
# ─────────────────────────────────────────────────────────────────────────────


def match_ioc(content: str, ioc: dict) -> bool:
    """Same matching logic as the scanner."""
    ctx = ioc.get("context", "")
    if ctx:
        return re.search(ctx, content, re.IGNORECASE) is not None
    return ioc["pattern"].lower() in content.lower()


def test_ioc(ioc_file: str, indicator: str, content: str, expect_clean: bool) -> bool:
    """Test a specific IOC against provided content."""
    path = Path(ioc_file)
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    iocs = data.get("iocs", [])
    target = None
    for ioc in iocs:
        if ioc.get("indicator") == indicator:
            target = ioc
            break

    if target is None:
        # Try substring match
        matches = [ioc for ioc in iocs if indicator.lower() in ioc.get("indicator", "").lower()]
        if len(matches) == 1:
            target = matches[0]
        elif len(matches) > 1:
            print(fail(f"Ambiguous indicator '{indicator}'. Matches:"))
            for m in matches:
                print(f"        - {m['indicator']}")
            return False
        else:
            print(fail(f"IOC not found: '{indicator}'"))
            print(info("Available indicators:"))
            for ioc in iocs:
                print(f"        - {ioc['indicator']}")
            return False

    print(f"\n{BOLD}Testing IOC: {target['indicator']}{RESET}")
    print(f"  Attack:   {target['attack']}")
    print(f"  Severity: {target['severity']}")
    print(f"  Pattern:  {target['pattern']}")
    print(f"  Context:  {target.get('context', '(none — substring fallback)')}")
    print()

    # Show content preview
    preview = content[:200] + ("..." if len(content) > 200 else "")
    print(f"  {DIM}Content:{RESET}")
    for line in preview.splitlines():
        print(f"    {DIM}{line}{RESET}")
    print()

    matched = match_ioc(content, target)

    if expect_clean:
        if matched:
            print(fail("Expected NO match but IOC matched — false positive!"))
            print(f"        This content should NOT trigger '{target['indicator']}'.")
            print("        The context regex may need tightening.")
            return False
        else:
            print(ok("Correctly did NOT match (no false positive)"))
            return True
    else:
        if matched:
            print(ok("Matched — IOC would be detected"))
            return True
        else:
            print(fail("Expected match but IOC did NOT match — detection gap!"))
            # Help debug
            ctx = target.get("context", "")
            if ctx:
                print(f"        Context regex: {ctx}")
                print("        Try adjusting the regex to match this content format.")
            else:
                print(f"        Pattern '{target['pattern']}' not found in content.")
            return False


# ─────────────────────────────────────────────────────────────────────────────
# INTERACTIVE: ADD NEW IOC
# ─────────────────────────────────────────────────────────────────────────────


def prompt(label: str, default: str = "", required: bool = True) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        val = input(f"  {label}{suffix}: ").strip()
        if not val and default:
            return default
        if not val and required:
            print(f"    {RED}Required field.{RESET}")
            continue
        return val


def interactive_new_ioc(ioc_file: str) -> bool:
    """Guided creation of a new IOC entry."""
    print(f"\n{BOLD}Add new IOC to {ioc_file}{RESET}\n")

    attack = prompt("Attack name (e.g. 'Axios RAT Supply Chain (31 Mar 2026)')")
    indicator = prompt("Indicator (e.g. 'axios@1.14.1' or 'evil-pkg')")
    pattern = prompt(
        "Search pattern (simple substring for pre-filter)",
        default=indicator.split("@")[0]
        if "@" in indicator
        else indicator.split("==")[0]
        if "==" in indicator
        else indicator,
    )
    severity = prompt("Severity", default="CRITICAL")
    while severity not in VALID_SEVERITIES:
        print(f"    {RED}Must be CRITICAL or HIGH{RESET}")
        severity = prompt("Severity", default="CRITICAL")

    note = prompt("Analyst note (what to do if found)")

    print(
        f"\n  {CYAN}Files to scan — enter filenames/globs, one per line. Empty line to finish.{RESET}"
    )
    files: list[str] = []
    while True:
        f = input("    file: ").strip()
        if not f:
            if files:
                break
            print(f"    {RED}At least one file pattern required.{RESET}")
            continue
        files.append(f)

    # Context regex
    print(f"\n  {CYAN}Context regex (optional but recommended to prevent false positives).{RESET}")
    print(f"  {DIM}For unique names like 'plain-crypto-js', the regex can just be the name.{RESET}")
    print(f"  {DIM}For versions, anchor to the package name, e.g.:{RESET}")
    print(f'  {DIM}  "axios"\\s*:\\s*"[^"]*1\\.14\\.1|axios@1\\.14\\.1{RESET}')
    context = prompt("Context regex", default=re.escape(pattern), required=False)

    # Validate regex
    if context:
        try:
            re.compile(context, re.IGNORECASE)
            print(ok("Regex compiles"))
        except re.error as e:
            print(fail(f"Invalid regex: {e}"))
            print("  Fix and retry.")
            return False

    # References
    print(f"\n  {CYAN}Reference URLs — one per line. Empty line to finish.{RESET}")
    refs: list[str] = []
    while True:
        r = input("    url: ").strip()
        if not r:
            break
        refs.append(r)

    new_ioc = {
        "attack": attack,
        "indicator": indicator,
        "pattern": pattern,
        "context": context,
        "files": files,
        "severity": severity,
        "note": note,
        "references": refs,
    }

    # Preview
    print(f"\n{BOLD}Preview:{RESET}")
    print(json.dumps(new_ioc, indent=2))

    # Validate
    errors, warnings = validate_ioc_entry(new_ioc, -1)
    if errors:
        for e in errors:
            print(fail(e))
        return False
    for w in warnings:
        print(warn(w))

    # Optional: test against sample content
    print(f"\n  {CYAN}Want to test against sample content? (y/N){RESET}")
    if input("  > ").strip().lower() in ("y", "yes"):
        print("  Paste sample file content (Ctrl+D to end):")
        lines = []
        try:
            while True:
                lines.append(input())
        except EOFError:
            pass
        sample = "\n".join(lines)
        if sample:
            matched = match_ioc(sample, new_ioc)
            if matched:
                print(ok("Matches sample content"))
            else:
                print(fail("Does NOT match sample content — check your regex"))
                print(f"  {YELLOW}Save anyway? (y/N){RESET}")
                if input("  > ").strip().lower() not in ("y", "yes"):
                    return False

    # Save
    print(f"\n  {CYAN}Save to {ioc_file}? (Y/n){RESET}")
    if input("  > ").strip().lower() in ("n", "no"):
        print("  Cancelled.")
        return False

    with open(ioc_file, encoding="utf-8") as f:
        data = json.load(f)

    data["iocs"].append(new_ioc)
    data["_meta"]["last_updated"] = __import__("datetime").date.today().isoformat()

    with open(ioc_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(ok(f"Added '{indicator}' to {ioc_file}"))
    print(info(f"Total IOCs: {len(data['iocs'])}"))
    print(info("Run tests to verify: uv run --with pytest pytest test_scanner.py -v"))
    return True


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────


def main() -> int:
    p = argparse.ArgumentParser(
        prog="validate_ioc",
        description="Validate and test IOC definitions for the GitLab IOC Scanner.",
    )
    p.add_argument(
        "--ioc-file",
        "-i",
        default="iocs.json",
        help="Path to IOC definitions file [default: iocs.json]",
    )
    p.add_argument(
        "--test",
        "-t",
        metavar="INDICATOR",
        help="Test a specific IOC indicator against sample content",
    )
    p.add_argument(
        "--content",
        "-c",
        help="Inline sample content to test against (use with --test)",
    )
    p.add_argument(
        "--file",
        "-f",
        help="Path to a sample file to test against (use with --test)",
    )
    p.add_argument(
        "--expect-clean",
        action="store_true",
        help="Expect the IOC NOT to match (verifies no false positive)",
    )
    p.add_argument(
        "--new",
        "-n",
        action="store_true",
        help="Interactive mode: add a new IOC with guided prompts",
    )

    args = p.parse_args()

    # Interactive new IOC
    if args.new:
        return 0 if interactive_new_ioc(args.ioc_file) else 1

    # Test a specific IOC
    if args.test:
        if args.file:
            content = Path(args.file).read_text(encoding="utf-8")
        elif args.content:
            content = args.content
        else:
            p.error("--test requires --content or --file")
        return 0 if test_ioc(args.ioc_file, args.test, content, args.expect_clean) else 1

    # Default: validate all
    return 0 if validate_all(args.ioc_file) else 1


if __name__ == "__main__":
    sys.exit(main())
