#!/usr/bin/env python3
"""
Thin shim — keeps `uv run gitlab_ioc_scanner.py` working.

All logic lives in the gitlab_ioc_scanner package.
"""

from __future__ import annotations

import sys

from gitlab_ioc_scanner.cli import main

sys.exit(main())
