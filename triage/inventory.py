"""Load an asset inventory from CSV.

Columns (header row required):
  id, vendor, model, firmware, role, zone, purdue_level, criticality,
  internet_exposed, patchable, platform

`platform` is a |-separated list of embedded OS/software (e.g. "Windows|Log4j").
`internet_exposed` and `patchable` accept true/false/yes/no/1/0.
"""
from __future__ import annotations

import csv

from .models import Asset


def _b(val: str, default: bool = False) -> bool:
    if val is None or val == "":
        return default
    return str(val).strip().lower() in ("1", "true", "yes", "y")


def load_inventory(path: str) -> list[Asset]:
    assets: list[Asset] = []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            platforms = [p.strip() for p in (row.get("platform") or "").split("|") if p.strip()]
            try:
                level = int(row.get("purdue_level") or 2)
            except ValueError:
                level = 2
            assets.append(Asset(
                id=row["id"].strip(),
                vendor=(row.get("vendor") or "").strip(),
                model=(row.get("model") or "").strip(),
                firmware=(row.get("firmware") or "").strip(),
                role=(row.get("role") or "").strip(),
                zone=(row.get("zone") or "").strip(),
                purdue_level=level,
                criticality=(row.get("criticality") or "medium").strip().lower(),
                internet_exposed=_b(row.get("internet_exposed")),
                patchable=_b(row.get("patchable"), default=True),
                platform=platforms,
            ))
    return assets
