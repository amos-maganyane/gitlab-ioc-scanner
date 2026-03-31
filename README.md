# GitLab IOC Scanner

Scans all projects within one or more GitLab groups for indicators of compromise (IOCs) related to known supply-chain attacks.

Zero external dependencies -- Python 3.10+ stdlib only.

## Quick start

```bash
export GL_TOKEN=glpat-xxxxxxxxxxxxxxxxxxxx
export GL_URL=https://gitlab.example.com

# Scan a single group
python3 gitlab_ioc_scanner.py --group cis

# Scan multiple groups, output CSV + JSON
python3 gitlab_ioc_scanner.py --group cis,devops,platform --format csv json

# Scan specific branches across all projects
python3 gitlab_ioc_scanner.py --group cis --branch main,develop,dev

# Strict mode — only scan projects that have at least one of the listed branches
python3 gitlab_ioc_scanner.py --group cis --branch main,master --branch-strict
```

## Requirements

- Python 3.10+
- GitLab personal access token with `read_api` + `read_repository` scopes

## Configuration

All CLI flags have env var fallbacks for unattended use (cron, CI/CD).

| Flag | Env var | Default | Description |
|---|---|---|---|
| `-g`, `--group` | `GL_GROUP` | *(required)* | Comma-separated group(s) to scan |
| `-t`, `--token` | `GL_TOKEN` | *(required)* | GitLab access token |
| `-u`, `--gitlab-url` | `GL_URL` | `https://gitlab.com` | GitLab base URL |
| `-i`, `--ioc-file` | `IOC_FILE` | `iocs.json` | IOC definitions file |
| `-o`, `--output` | `SCAN_OUTPUT` | auto-generated | Report file prefix (basename, not path) |
| `--report-dir` | `SCAN_REPORT_DIR` | `reports` | Directory for report files (auto-created) |
| `-f`, `--format` | -- | `csv` | `csv`, `json`, `html`, or any combination |
| `-w`, `--workers` | `SCAN_WORKERS` | `4` | Concurrent threads |
| `-p`, `--project` | -- | all | Filter to one project |
| `-b`, `--branch` | `GL_BRANCH` | *(default)* | Comma-separated branch(es) to scan |
| `--branch-strict` | `GL_BRANCH_STRICT` | `false` | Skip projects missing all listed branches |
| `-d`, `--debug` | `SCAN_DEBUG` | `false` | Shortcut for `--log-level DEBUG` |
| `--log-level` | `LOG_LEVEL` | `INFO` | `DEBUG`/`INFO`/`WARNING`/`ERROR` |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean -- no findings |
| `1` | Error -- config, network, or runtime failure |
| `2` | CRITICAL findings detected |
| `3` | HIGH findings (no CRITICAL) |

## Managing IOCs

IOCs live in `iocs.json` -- no code changes needed to add new threats.

### Add a new IOC interactively

```bash
python3 validate_ioc.py --new
```

Walks you through every field, validates the regex, and optionally tests against sample content before saving.

### Validate all IOCs

```bash
python3 validate_ioc.py
```

### Test an IOC against sample content

```bash
# Should match (true positive)
python3 validate_ioc.py --test "axios@1.14.1" --content '{"dependencies":{"axios":"1.14.1"}}'

# Should NOT match (false positive check)
python3 validate_ioc.py --test "axios@1.14.1" --content '{"dependencies":{"lodash":"1.14.1"}}' --expect-clean

# Test against a file
python3 validate_ioc.py --test "litellm==1.82.7" --file requirements.txt
```

### Currently tracked attacks

| Attack | Date | Severity |
|---|---|---|
| Axios npm supply chain | 31 Mar 2026 | CRITICAL |
| LiteLLM PyPI backdoor | 24 Mar 2026 | CRITICAL |
| Trivy GitHub Actions hijack | 20 Mar 2026 | HIGH |
| Telnyx PyPI compromise | 27 Mar 2026 | HIGH |

## Tests

```bash
uv run --with pytest pytest tests/ -v
```

253 tests covering true positive detection, false positive rejection, IOC loading validation, CLI argument parsing, report generation (including IOC reference section and metadata footer), subdirectory discovery, blob path promotion, API counter tracking, and end-to-end scan orchestration.

## GitLab CI/CD

```yaml
ioc-scan:
  stage: security
  # Pin to digest -- do not use mutable tags in security tooling
  image: python:3.12-slim@sha256:abcdef0123456789  # replace with current digest
  variables:
    GL_TOKEN: $GITLAB_SECURITY_TOKEN
    GL_GROUP: "cis,devops,platform"
    GL_URL: "https://gitlab.example.com"
  script:
    - python3 gitlab_ioc_scanner.py --format csv json html
  artifacts:
    paths:
      - reports/ioc_report_*.csv
      - reports/ioc_report_*.json
      - reports/ioc_report_*.html
    expire_in: 90 days
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
```

## Files

```
gitlab_ioc_scanner/     -- scanner package (v2.3.0)
  __init__.py           --   re-exports (load_iocs, match_ioc, main)
  __main__.py           --   python -m gitlab_ioc_scanner entry point
  cli.py                --   arg parsing, logging, main orchestration
  client.py             --   GitLab API client (retry, rate-limit, SSL)
  scanner.py            --   project scanning, glob resolution, subdirectory discovery, matching
  ioc_loader.py         --   IOC definition loading, validation + file metadata
  reports.py            --   CSV, JSON, HTML report writers + console summary
tests/                  -- test suite (253 tests, 100% coverage)
reports/                -- report output directory (auto-created)
gitlab_ioc_scanner.py   -- thin shim (uv run gitlab_ioc_scanner.py)
iocs.json               -- IOC definitions
validate_ioc.py         -- IOC validation and testing helper
pyproject.toml          -- packaging and linter config
```
