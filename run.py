#!/usr/bin/env python3
"""Triage — OT/ICS vulnerability prioritisation. Answers "what do I fix first?"

    python run.py scan samples/inventory.csv
    python run.py dashboard --results triage_results.json
    python run.py update            # refresh KEV + EPSS from live feeds
"""
from __future__ import annotations

import argparse
import json

from triage import PROJECT_NAME, __version__
from triage.feeds import load_vulns, update as update_feeds
from triage.inventory import load_inventory
from triage.match import match
from triage.score import prioritise, summarise

BAND_COLOR = {"fix_first": "\033[91m", "schedule": "\033[93m", "monitor": "\033[96m", "accept": "\033[90m"}
RESET = "\033[0m"
BAND_LABEL = {"fix_first": "FIX FIRST", "schedule": "SCHEDULE", "monitor": "MONITOR", "accept": "ACCEPT"}


def run_scan(args) -> None:
    assets = load_inventory(args.inventory)
    vulns = load_vulns(args.db)
    scored = prioritise(match(assets, vulns))
    summary = summarise(scored)

    print(f"\n{PROJECT_NAME} v{__version__}  —  {args.inventory}")
    print(f"{len(assets)} assets · {summary['total']} vuln instances · "
          f"{summary['kev']} actively exploited (KEV) · "
          f"{summary['bands']['fix_first']} to fix first\n")

    top = scored[: args.top]
    print(f"FIX THIS FIRST  (top {len(top)})")
    print("─" * 78)
    for s in top:
        c = BAND_COLOR.get(s.band, "")
        tag = f"{c}{BAND_LABEL[s.band]:9}{RESET}" if __import__("sys").stdout.isatty() else f"{BAND_LABEL[s.band]:9}"
        kev = " \033[91m[KEV]\033[0m" if s.vuln.kev and __import__("sys").stdout.isatty() else (" [KEV]" if s.vuln.kev else "")
        print(f"  {s.priority:>5.1f}  {tag} {s.vuln.cve:<17} {s.asset.id:<9} "
              f"{s.asset.vendor.split()[0]:<10} CVSS {s.vuln.cvss:<4} EPSS {int(s.factors['epss_pct'])}%{kev}")
        print(f"         └─ {s.action}")
    print()

    out = args.json or "triage_results.json"
    payload = {
        "meta": {"inventory": args.inventory, "db": args.db or "bundled",
                 "generated": PROJECT_NAME + " " + __version__},
        "summary": summary,
        "results": [s.to_dict() for s in scored],
    }
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    print(f"results -> {out}")
    print(f"dashboard:  python run.py dashboard --results {out}\n")


def run_dashboard(args) -> None:
    import os
    import uvicorn
    os.environ["TRIAGE_RESULTS"] = args.results
    uvicorn.run("dashboard.app:app", host=args.host, port=args.port, log_level="warning")


def run_update(args) -> None:
    update_feeds(args.db)


def main() -> None:
    ap = argparse.ArgumentParser(description=f"{PROJECT_NAME} OT vulnerability prioritisation")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="score an inventory and rank remediation")
    s.add_argument("inventory")
    s.add_argument("--db", help="vulnerability db json (default: bundled)")
    s.add_argument("--top", type=int, default=12)
    s.add_argument("--json", help="output path (default triage_results.json)")
    s.set_defaults(func=run_scan)

    d = sub.add_parser("dashboard", help="serve the risk-quadrant dashboard")
    d.add_argument("--results", default="triage_results.json")
    d.add_argument("--host", default="0.0.0.0")
    d.add_argument("--port", type=int, default=3004)
    d.set_defaults(func=run_dashboard)

    u = sub.add_parser("update", help="refresh KEV + EPSS from live feeds")
    u.add_argument("--db", help="vulnerability db json (default: bundled)")
    u.set_defaults(func=run_update)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
