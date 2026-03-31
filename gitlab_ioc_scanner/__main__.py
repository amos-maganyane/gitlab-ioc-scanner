"""Allow running as `python -m gitlab_ioc_scanner`."""

from __future__ import annotations

import sys

from gitlab_ioc_scanner.cli import main

sys.exit(main())
