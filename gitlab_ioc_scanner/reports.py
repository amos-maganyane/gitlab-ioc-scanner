"""Report writers — CSV, JSON, HTML and console summary."""

from __future__ import annotations

import csv
import html as html_mod
import json
import logging
from datetime import datetime, timezone

log = logging.getLogger("ioc_scanner")


REPORT_FIELDS = [
    "project",
    "url",
    "branch",
    "file",
    "attack",
    "indicator",
    "severity",
    "note",
    "references",
    "timestamp",
]


def write_csv_report(filepath: str, findings: list[dict], clean_projects: list[dict]) -> None:
    """Write a CSV report including both findings and clean projects."""
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=REPORT_FIELDS)
        writer.writeheader()
        writer.writerows(findings)
        # Append clean rows so the report is a complete project inventory
        for proj in clean_projects:
            writer.writerow(
                {
                    "project": proj["project"],
                    "url": proj["url"],
                    "branch": proj["branch"],
                    "file": "",
                    "attack": "NONE",
                    "indicator": "CLEAN",
                    "severity": "OK",
                    "note": "No IOC patterns detected in any scanned file",
                    "references": "",
                    "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                }
            )
    log.info("CSV report written: %s", filepath)


def write_json_report(
    filepath: str, findings: list[dict], clean_projects: list[dict], scan_metadata: dict
) -> None:
    """Write a structured JSON report."""
    report = {
        "scan_metadata": scan_metadata,
        "summary": {
            "total_findings": len(findings),
            "critical_count": sum(1 for f in findings if f["severity"] == "CRITICAL"),
            "high_count": sum(1 for f in findings if f["severity"] == "HIGH"),
            "affected_projects": list({f["project"] for f in findings}),
            "clean_projects": clean_projects,
        },
        "findings": findings,
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    log.info("JSON report written: %s", filepath)


def write_html_report(
    filepath: str,
    findings: list[dict],
    clean_projects: list[dict],
    scan_metadata: dict,
    iocs: list[dict] | None = None,
) -> None:
    """Write a self-contained styled HTML report using Motion design tokens."""
    esc = html_mod.escape
    crit_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high_count = sum(1 for f in findings if f["severity"] == "HIGH")
    total_projects = scan_metadata.get("projects_scanned", 0)
    affected_projects = sorted({f["project"] for f in findings})
    status_class = "clean" if not findings else "critical" if crit_count else "high"
    status_label = "CLEAN" if not findings else f"{crit_count} CRITICAL, {high_count} HIGH"

    findings_rows = ""
    for f in findings:
        sev = f["severity"]
        sev_cls = "sev-critical" if sev == "CRITICAL" else "sev-high"
        refs_html = ""
        if f.get("references"):
            links = [
                f'<a href="{esc(r)}" target="_blank">{esc(r[:60])}</a>'
                for r in f["references"].split(", ")
                if r.strip()
            ]
            refs_html = "<br>".join(links)
        findings_rows += f"""<tr>
<td>{esc(f["project"])}</td>
<td><code>{esc(f["file"])}</code></td>
<td><span class="pill {sev_cls}">{esc(sev)}</span></td>
<td><code>{esc(f["indicator"])}</code></td>
<td>{esc(f["attack"])}</td>
<td class="note">{esc(f["note"])}</td>
<td class="refs">{refs_html}</td>
</tr>\n"""

    clean_rows = ""
    for proj in sorted(clean_projects, key=lambda p: p["project"]):
        url_cell = (
            f'<a href="{esc(proj["url"])}">{esc(proj["project"])}</a>'
            if proj["url"]
            else esc(proj["project"])
        )
        clean_rows += (
            f"<tr><td>{url_cell}</td>"
            f"<td><code>{esc(proj['branch'])}</code></td>"
            f'<td><span class="pill sev-ok">CLEAN</span></td></tr>\n'
        )

    groups_str = ", ".join(scan_metadata.get("groups", []))
    scan_time = scan_metadata.get("scan_time", "")

    # Build the header bar with logo and scan info
    header_html = f"""<header class="header">
  <div class="header-left">
    <svg class="logo-icon" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M12 22C6.477 22 2 17.523 2 12S6.477 2 12 2s10 4.477 10 10-4.477 10-10 10z" fill="#001950"/>
      <path d="M12 6.5L7.5 9.25v5.5L12 17.5l4.5-2.75v-5.5L12 6.5z" fill="#fff"/>
      <path d="M12 10a2 2 0 100 4 2 2 0 000-4z" fill="#e63b3b"/>
    </svg>
    <div>
      <h1>Supply-Chain IOC Scan Report</h1>
      <div class="subtitle">
        Groups: {esc(groups_str)} &middot;
        {esc(scan_time)} &middot;
        Scanner v{esc(scan_metadata.get("scanner_version", "?"))}
      </div>
    </div>
  </div>
  <div class="header-status status-{status_class}">
    {esc(status_label)}
  </div>
</header>"""

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>IOC Scan Report &mdash; {esc(groups_str)} &mdash; {esc(scan_time)}</title>
<style>
/* ── Motion Design System Tokens ──────────────────────────────── */
:root {{
  --mo-red: #e63b3b;
  --mo-red-dark: #c62828;
  --mo-blue: #0056ed;
  --mo-blue-dark: #004d99;
  --mo-blue-light: rgba(0,86,237,0.1);
  --mo-navy: #003366;
  --mo-navy-table: #001950;
  --mo-green: #4bb243;
  --mo-green-bg: rgba(75,178,67,0.08);
  --mo-gold: #f59d00;
  --mo-gold-bg: rgba(245,157,0,0.08);
  --mo-error: #e11b22;
  --mo-error-bg: rgba(225,27,34,0.06);
  --mo-grey-900: #1a1a1a;
  --mo-grey-700: #666666;
  --mo-grey-200: #949494;
  --mo-grey-100: #b4b4b4;
  --mo-grey-50: #f9f9f9;
  --mo-text: #1a1a2e;
  --mo-text-secondary: #666666;
  --mo-bg: #f8f9fa;
  --mo-card-bg: #ffffff;
  --mo-subtle-bg: #fcfcfc;
  --mo-border: rgba(0,0,0,0.08);
  --mo-card-shadow: 0 4px 20px rgba(0,0,0,0.05);
  --mo-font: Arial, sans-serif;
  /* Severity aliases */
  --critical: var(--mo-error);
  --critical-bg: var(--mo-error-bg);
  --high: var(--mo-gold);
  --high-bg: var(--mo-gold-bg);
  --ok: var(--mo-green);
  --ok-bg: var(--mo-green-bg);
}}

/* ── Staggered fade-in on page load ──────────────────────────── */
@keyframes fadeUp {{
  from {{ opacity: 0; transform: translateY(12px); }}
  to {{ opacity: 1; transform: translateY(0); }}
}}
@keyframes slideDown {{
  from {{ opacity: 0; transform: translateY(-8px); }}
  to {{ opacity: 1; transform: translateY(0); }}
}}
@keyframes fadeIn {{
  from {{ opacity: 0; }}
  to {{ opacity: 1; }}
}}

* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{
  font-family: var(--mo-font);
  background: var(--mo-bg);
  color: var(--mo-text);
  line-height: 1.6;
  font-size: 1rem;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}}
.container {{ max-width: 1400px; margin: 0 auto; padding: 0 2rem 2.5rem; }}

/* ── Header Bar ───────────────────────────────────────────────── */
.header {{
  background: linear-gradient(135deg, var(--mo-navy-table) 0%, #002040 100%);
  color: #fff;
  padding: 1.25rem 2rem;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1.5rem;
  margin-bottom: 2rem;
  animation: slideDown 0.4s ease-out both;
}}
.header-left {{
  display: flex;
  align-items: center;
  gap: 1rem;
}}
.logo-icon {{ width: 40px; height: 40px; flex-shrink: 0; }}
.header h1 {{
  font-size: 1.375rem;
  font-weight: 600;
  color: #fff;
  margin: 0;
  line-height: 1.3;
}}
.header .subtitle {{
  font-size: 0.75rem;
  color: rgba(255,255,255,0.6);
  margin: 0.125rem 0 0;
  letter-spacing: 0.01em;
}}
.header-status {{
  font-size: 0.875rem;
  font-weight: 600;
  letter-spacing: 0.089em;
  padding: 0.5rem 1.25rem;
  border-radius: 22px;
  white-space: nowrap;
  text-transform: uppercase;
}}
.header-status.status-clean {{
  background: rgba(75,178,67,0.15);
  color: #8fff8a;
}}
.header-status.status-critical {{
  background: rgba(225,27,34,0.2);
  color: #ff8a8a;
}}
.header-status.status-high {{
  background: rgba(245,157,0,0.2);
  color: #ffd080;
}}

/* ── Summary Cards ────────────────────────────────────────────── */
.cards {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: 1rem;
  margin-bottom: 2rem;
}}
.card {{
  background: var(--mo-card-bg);
  border-radius: 16px;
  padding: 1.5rem;
  box-shadow: var(--mo-card-shadow);
  transition: box-shadow 0.2s ease, transform 0.2s ease;
  animation: fadeUp 0.45s ease-out both;
}}
.card:nth-child(1) {{ animation-delay: 0.08s; }}
.card:nth-child(2) {{ animation-delay: 0.14s; }}
.card:nth-child(3) {{ animation-delay: 0.20s; }}
.card:nth-child(4) {{ animation-delay: 0.26s; }}
.card:hover {{
  box-shadow: 0 8px 30px rgba(0,0,0,0.08);
  transform: translateY(-2px);
}}
.card .label {{
  font-size: 0.6875rem;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--mo-text-secondary);
  margin-bottom: 0.5rem;
  font-weight: 600;
}}
.card .value {{
  font-size: 2rem;
  font-weight: 800;
  line-height: 1.2;
}}
.card .value.green {{ color: var(--mo-green); }}
.card .value.red {{ color: var(--mo-error); }}
.card .value.muted {{ color: var(--mo-text); }}

/* ── Sections ─────────────────────────────────────────────────── */
section {{
  background: var(--mo-card-bg);
  border-radius: 16px;
  padding: 1.75rem;
  margin-bottom: 1.5rem;
  box-shadow: var(--mo-card-shadow);
  animation: fadeUp 0.45s ease-out both;
  animation-delay: 0.3s;
}}
section + section {{ animation-delay: 0.4s; }}
section h2 {{
  font-size: 1.125rem;
  font-weight: 600;
  margin-bottom: 1.25rem;
  display: flex;
  align-items: center;
  gap: 0.625rem;
  color: var(--mo-text);
}}
section h2 .badge {{
  font-size: 0.75rem;
  padding: 0.2rem 0.75rem;
  border-radius: 22px;
  font-weight: 600;
}}
.badge-critical {{ background: var(--critical-bg); color: var(--critical); }}
.badge-high {{ background: var(--high-bg); color: var(--high); }}
.badge-ok {{ background: var(--ok-bg); color: var(--ok); }}

/* ── Tables (Motion navy-header style) ────────────────────────── */
.table-wrap {{
  overflow-x: auto;
  border-radius: 10px;
  border: 1px solid var(--mo-border);
}}
table {{
  width: 100%;
  border-collapse: collapse;
  font-size: 0.875rem;
}}
thead tr {{
  background: var(--mo-navy-table);
}}
th {{
  text-align: left;
  padding: 0.75rem 1rem;
  color: #ffffff;
  font-weight: 700;
  font-size: 0.8125rem;
  letter-spacing: 0.02em;
}}
td {{
  padding: 0.75rem 1rem;
  border-bottom: 1px solid var(--mo-border);
  vertical-align: top;
  color: rgba(0,0,0,0.87);
}}
tbody tr {{
  transition: background 0.15s ease;
}}
tbody tr:hover {{ background: var(--mo-grey-50); }}
tbody tr:last-child td {{ border-bottom: none; }}
td code {{
  font-family: 'SF Mono', SFMono-Regular, Consolas, 'Liberation Mono', Menlo, monospace;
  font-size: 0.8125rem;
  background: var(--mo-grey-50);
  padding: 0.125rem 0.4rem;
  border-radius: 4px;
  color: var(--mo-navy);
  border: 1px solid rgba(0,0,0,0.04);
}}

/* ── Severity pills ───────────────────────────────────────────── */
.pill {{
  display: inline-block;
  padding: 0.2rem 0.75rem;
  border-radius: 22px;
  font-size: 0.75rem;
  font-weight: 600;
  letter-spacing: 0.03em;
  white-space: nowrap;
}}
.sev-critical {{ background: var(--critical-bg); color: var(--critical); font-weight: 700; }}
.sev-high {{ background: var(--high-bg); color: var(--high); font-weight: 700; }}
.sev-ok {{ background: var(--ok-bg); color: var(--ok); font-weight: 600; }}
.note {{ max-width: 300px; font-size: 0.8125rem; color: var(--mo-text-secondary); line-height: 1.5; }}
.refs {{ max-width: 280px; font-size: 0.75rem; word-break: break-all; }}
.refs a {{
  color: var(--mo-blue);
  text-decoration: none;
  transition: color 0.15s ease;
}}
.refs a:hover {{ text-decoration: underline; color: var(--mo-blue-dark); }}

/* ── Footer meta ──────────────────────────────────────────────── */
.meta {{
  font-size: 0.75rem;
  color: var(--mo-text-secondary);
  margin-top: 2rem;
  padding: 1rem 1.75rem;
  background: var(--mo-card-bg);
  border-radius: 16px;
  box-shadow: var(--mo-card-shadow);
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 0.5rem 2rem;
  animation: fadeIn 0.5s ease-out both;
  animation-delay: 0.5s;
}}
.meta span {{
  white-space: nowrap;
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
}}
.meta span::before {{
  content: '';
  display: inline-block;
  width: 4px;
  height: 4px;
  background: var(--mo-grey-200);
  border-radius: 50%;
}}
.meta span:first-child::before {{ display: none; }}

/* ── IOC Reference Section ────────────────────────────────────── */
.ioc-ref-section {{ animation-delay: 0.45s; }}
.section-desc {{
  font-size: 0.8125rem;
  color: var(--mo-text-secondary);
  margin: -0.5rem 0 1.5rem;
  line-height: 1.6;
}}
.ioc-campaign {{
  margin-bottom: 1.5rem;
}}
.ioc-campaign:last-child {{ margin-bottom: 0; }}
.ioc-campaign h3 {{
  font-size: 0.9375rem;
  font-weight: 600;
  margin-bottom: 0.75rem;
  display: flex;
  align-items: center;
  gap: 0.625rem;
  color: var(--mo-navy);
}}
.ioc-files {{ font-size: 0.75rem; max-width: 220px; }}
.ioc-files code {{
  font-size: 0.6875rem;
  margin: 0 0.15rem 0.15rem 0;
  display: inline-block;
}}
.badge-ref {{ background: var(--mo-blue-light); color: var(--mo-blue); }}
.muted-text {{ color: var(--mo-grey-200); font-style: italic; }}

/* ── Print-friendly ───────────────────────────────────────────── */
@media print {{
  body {{ background: #fff; }}
  .header {{ background: var(--mo-navy-table) !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
  thead tr {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
  .card, section, .meta {{ box-shadow: none; border: 1px solid #ddd; }}
  .card, section, .meta, .header {{ animation: none !important; }}
}}

/* ── Responsive ───────────────────────────────────────────────── */
@media (max-width: 768px) {{
  .header {{ flex-direction: column; align-items: flex-start; padding: 1rem 1.25rem; }}
  .container {{ padding: 0 1.25rem 2rem; }}
  .cards {{ grid-template-columns: repeat(2, 1fr); }}
  section {{ padding: 1.25rem; }}
  .meta {{ flex-direction: column; gap: 0.25rem; }}
  .meta span::before {{ display: none; }}
}}
</style>
</head>
<body>
{header_html}
<div class="container">
  <div class="cards">
    <div class="card">
      <div class="label">Projects Scanned</div>
      <div class="value muted">{total_projects}</div>
    </div>
    <div class="card">
      <div class="label">Clean</div>
      <div class="value green">{len(clean_projects)}</div>
    </div>
    <div class="card">
      <div class="label">Affected</div>
      <div class="value {"red" if affected_projects else "green"}">{len(affected_projects)}</div>
    </div>
    <div class="card">
      <div class="label">Findings</div>
      <div class="value {"red" if crit_count else "muted" if not findings else "red"}">{len(findings)}</div>
    </div>
  </div>
"""

    if findings:
        page += f"""  <section>
    <h2>Findings <span class="badge {"badge-critical" if crit_count else "badge-high"}">{len(findings)} finding{"s" if len(findings) != 1 else ""}</span></h2>
    <div class="table-wrap">
    <table>
      <thead>
        <tr><th>Project</th><th>File</th><th>Severity</th><th>Indicator</th><th>Attack</th><th>Note</th><th>References</th></tr>
      </thead>
      <tbody>
        {findings_rows}
      </tbody>
    </table>
    </div>
  </section>
"""

    if clean_projects:
        page += f"""  <section>
    <h2>Clean Projects <span class="badge badge-ok">{len(clean_projects)}</span></h2>
    <div class="table-wrap">
    <table>
      <thead><tr><th>Project</th><th>Branch</th><th>Status</th></tr></thead>
      <tbody>
        {clean_rows}
      </tbody>
    </table>
    </div>
  </section>
"""

    # ── IOC Reference Section ─────────────────────────────────────────────
    if iocs:
        # Group by attack campaign
        campaigns: dict[str, list[dict]] = {}
        for ioc in iocs:
            campaigns.setdefault(ioc["attack"], []).append(ioc)

        ioc_cards = ""
        for attack, indicators in campaigns.items():
            sev = indicators[0].get("severity", "HIGH")
            sev_cls = "sev-critical" if sev == "CRITICAL" else "sev-high"
            # Build indicator rows
            indicator_rows = ""
            for ind in indicators:
                ind_sev = ind.get("severity", "HIGH")
                ind_cls = "sev-critical" if ind_sev == "CRITICAL" else "sev-high"
                files_str = ", ".join(f"<code>{esc(f)}</code>" for f in ind.get("files", []))
                refs_links = ""
                for ref in ind.get("references", []):
                    if ref.strip():
                        refs_links += (
                            f'<a href="{esc(ref)}" target="_blank"'
                            f' rel="noopener">{esc(ref[:80])}</a><br>'
                        )
                indicator_rows += f"""<tr>
<td><code>{esc(ind["indicator"])}</code></td>
<td><span class="pill {ind_cls}">{esc(ind_sev)}</span></td>
<td class="note">{esc(ind.get("note", ""))}</td>
<td class="ioc-files">{files_str}</td>
<td class="refs">{refs_links if refs_links else "<span class='muted-text'>—</span>"}</td>
</tr>\n"""

            ioc_cards += f"""<div class="ioc-campaign">
  <h3>{esc(attack)} <span class="pill {sev_cls}">{esc(sev)}</span></h3>
  <div class="table-wrap">
  <table>
    <thead><tr><th>Indicator</th><th>Severity</th><th>Description</th><th>Files Checked</th><th>References</th></tr></thead>
    <tbody>
      {indicator_rows}
    </tbody>
  </table>
  </div>
</div>\n"""

        page += f"""  <section class="ioc-ref-section">
    <h2>IOC Reference <span class="badge badge-ref">{len(iocs)} indicator{"s" if len(iocs) != 1 else ""} across {len(campaigns)} campaign{"s" if len(campaigns) != 1 else ""}</span></h2>
    <p class="section-desc">These are the indicators of compromise checked during this scan. Each maps to a known supply-chain attack campaign with specific file targets and detection patterns.</p>
    {ioc_cards}
  </section>
"""

    # ── Build footer metadata items ─────────────────────────────────────
    duration = scan_metadata.get("duration_seconds")
    if duration is not None:
        mins, secs = divmod(duration, 60)
        duration_str = f"{int(mins)}m {secs:.1f}s" if mins else f"{secs:.1f}s"
    else:
        duration_str = ""

    api_calls = scan_metadata.get("api_calls", 0)
    retries = scan_metadata.get("retries", 0)
    errors = scan_metadata.get("errors", 0)
    ioc_sha = scan_metadata.get("ioc_file_sha256") or ""
    ioc_sha_short = ioc_sha[:12] if ioc_sha else ""
    ioc_updated = scan_metadata.get("ioc_file_last_updated") or ""
    hostname = scan_metadata.get("hostname") or ""
    py_version = scan_metadata.get("python_version") or ""

    meta_items = [
        f"GitLab: {esc(scan_metadata.get('gitlab_url', ''))}",
        f"IOC file: {esc(scan_metadata.get('ioc_file', ''))}",
        f"IOCs checked: {scan_metadata.get('ioc_count', 0)}",
    ]
    if duration_str:
        meta_items.append(f"Duration: {duration_str}")
    if api_calls:
        meta_items.append(f"API calls: {api_calls}")
    if retries:
        meta_items.append(f"Retries: {retries}")
    if errors:
        meta_items.append(f"Errors: {errors}")
    if ioc_sha_short:
        meta_items.append(f"IOC SHA-256: {ioc_sha_short}&hellip;")
    if ioc_updated:
        meta_items.append(f"IOC updated: {esc(ioc_updated)}")
    if hostname:
        meta_items.append(f"Host: {esc(hostname)}")
    if py_version:
        meta_items.append(f"Python: {esc(py_version)}")

    meta_spans = "\n    ".join(f"<span>{item}</span>" for item in meta_items)

    page += f"""  <div class="meta">
    {meta_spans}
  </div>
</div>
</body>
</html>"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(page)
    log.info("HTML report written: %s", filepath)


# ─────────────────────────────────────────────────────────────────────────────
# CONSOLE SUMMARY
# ─────────────────────────────────────────────────────────────────────────────


def print_summary(
    findings: list[dict],
    total_projects: int,
    clean_projects: list[dict],
    report_files: list[str],
) -> None:
    """Print a human-readable summary to stdout."""
    crit_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high_count = sum(1 for f in findings if f["severity"] == "HIGH")
    affected = {f["project"] for f in findings}

    print()
    print("=" * 76)
    print("  SCAN COMPLETE")
    print("=" * 76)
    print(f"  Projects scanned       : {total_projects}")
    print(f"  Clean projects         : {len(clean_projects)}")
    print(f"  Affected projects      : {len(affected)}")
    print(f"  Total findings         : {len(findings)}")
    print(f"    CRITICAL             : {crit_count}")
    print(f"    HIGH                 : {high_count}")
    print()

    if findings:
        print("  ── AFFECTED PROJECTS " + "─" * 52)
        grouped: dict[str, list[dict]] = {}
        for f in findings:
            grouped.setdefault(f["project"], []).append(f)
        for pname, hits in grouped.items():
            print(f"\n  [!] {pname}")
            print(f"      URL: {hits[0]['url']}")
            for h in hits:
                print(f"      - [{h['severity']:8s}] {h['file']}")
                print(f"        Indicator: {h['indicator']}")
                print(f"        {h['note']}")
        print()
        print("  ACTION REQUIRED: Notify Cyber Security immediately for all")
        print("  CRITICAL findings. Do not merge or deploy from affected")
        print("  projects until cleared.")
    else:
        print("  [OK]  No IOCs detected. All scanned projects are CLEAN.")

    print()
    for rf in report_files:
        print(f"  Report: {rf}")
    print("=" * 76)
    print()
