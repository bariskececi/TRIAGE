"""Load vulnerability intelligence.

By default Triage runs fully offline from a bundled snapshot, which is what an
air-gapped OT site needs. `update()` refreshes the two feeds that change fastest
and matter most for prioritisation — CISA's Known Exploited list and FIRST's EPSS
scores — for the CVEs already in the set.
"""
from __future__ import annotations

import json
import os

from .models import Vuln

_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB = os.path.join(_HERE, "..", "data", "ot_vulns.json")

KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API = "https://api.first.org/data/v1/epss"


def load_vulns(path: str | None = None) -> list[Vuln]:
    with open(path or DEFAULT_DB, encoding="utf-8") as fh:
        data = json.load(fh)
    return [Vuln(**{k: v for k, v in row.items()}) for row in data["vulns"]]


def update(path: str | None = None) -> None:
    """Refresh KEV flags and EPSS scores from live feeds (needs internet)."""
    import urllib.request

    path = path or DEFAULT_DB
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    cves = [v["cve"] for v in data["vulns"]]

    # CISA KEV
    try:
        with urllib.request.urlopen(KEV_FEED, timeout=20) as r:
            kev = json.load(r)
        kev_set = {c["cveID"] for c in kev.get("vulnerabilities", [])}
        for v in data["vulns"]:
            v["kev"] = v["cve"] in kev_set
        print(f"KEV: {sum(1 for v in data['vulns'] if v['kev'])}/{len(cves)} flagged")
    except Exception as e:
        print(f"KEV refresh skipped ({e})")

    # EPSS (batch)
    try:
        q = EPSS_API + "?cve=" + ",".join(cves)
        with urllib.request.urlopen(q, timeout=20) as r:
            epss = json.load(r)
        scores = {d["cve"]: float(d["epss"]) for d in epss.get("data", [])}
        for v in data["vulns"]:
            if v["cve"] in scores:
                v["epss"] = round(scores[v["cve"]], 4)
        print(f"EPSS: {len(scores)}/{len(cves)} updated")
    except Exception as e:
        print(f"EPSS refresh skipped ({e})")

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    print(f"saved -> {path}")
