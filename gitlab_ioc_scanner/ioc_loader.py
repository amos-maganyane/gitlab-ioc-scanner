"""Load and validate IOC definitions from JSON."""

from __future__ import annotations

import hashlib
import json
import logging
import re
from pathlib import Path

log = logging.getLogger("ioc_scanner")


def load_iocs(filepath: str) -> list[dict]:
    """Load and validate IOC definitions from a JSON file."""
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"IOC file not found: {filepath}")

    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    iocs = data.get("iocs", [])
    if not iocs:
        raise ValueError(f"No IOCs found in {filepath}")

    required_fields = {"attack", "indicator", "pattern", "files", "severity", "note"}
    for i, ioc in enumerate(iocs):
        missing = required_fields - set(ioc.keys())
        if missing:
            raise ValueError(f"IOC #{i} missing fields: {missing}")

        # Pre-compile context regex if present
        if ioc.get("context"):
            try:
                ioc["_context_re"] = re.compile(ioc["context"], re.IGNORECASE)
            except re.error as e:
                raise ValueError(f"IOC #{i} has invalid context regex: {e}") from e

    log.info("Loaded %d IOC definitions from %s", len(iocs), filepath)
    return iocs


def ioc_file_metadata(filepath: str) -> dict:
    """Return SHA-256 hash and last_updated date from an IOC definitions file.

    Returns
    -------
    dict with keys:
        sha256       : hex digest of the file contents
        last_updated : value from ``_meta.last_updated`` in the JSON, or None
    """
    path = Path(filepath)
    if not path.is_file():
        return {"sha256": None, "last_updated": None}

    raw = path.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()

    last_updated = None
    try:
        data = json.loads(raw)
        last_updated = data.get("_meta", {}).get("last_updated")
    except (json.JSONDecodeError, AttributeError):
        pass

    return {"sha256": sha, "last_updated": last_updated}
