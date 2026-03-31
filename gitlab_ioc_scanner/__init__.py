"""
GitLab Group Supply-Chain IOC Scanner
=====================================
Scans all projects within one or more GitLab groups for Indicators of
Compromise (IOCs) related to known supply-chain attacks.

IOC definitions are loaded from an external JSON file (default: iocs.json)
so new threats can be added without modifying scanner code.
"""

from __future__ import annotations

__version__ = "2.3.0"

# Re-export key symbols so existing imports keep working:
#   from gitlab_ioc_scanner import load_iocs, match_ioc, main
from gitlab_ioc_scanner.cli import main
from gitlab_ioc_scanner.ioc_loader import load_iocs
from gitlab_ioc_scanner.scanner import match_ioc

__all__ = ["__version__", "load_iocs", "main", "match_ioc"]
