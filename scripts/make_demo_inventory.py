#!/usr/bin/env python3
"""Write a realistic mixed OT plant inventory so Triage has something to score.

    python scripts/make_demo_inventory.py samples/inventory.csv
"""
from __future__ import annotations

import csv
import os
import sys

ROWS = [
    # id, vendor, model, firmware, role, zone, purdue_level, criticality, internet_exposed, patchable, platform
    ["PLC-01", "Siemens", "SIMATIC S7-1500", "V2.9", "PLC", "Control", 1, "safety", "false", "false", ""],
    ["PLC-02", "Siemens", "SIMATIC S7-1200", "V4.4", "PLC", "Control", 1, "high", "false", "false", ""],
    ["PLC-03", "Siemens", "SIMATIC S7-300", "V3.2", "PLC", "Control", 1, "high", "false", "false", ""],
    ["PLC-04", "Rockwell Automation", "ControlLogix 5570", "v32", "PLC", "Control", 1, "high", "false", "false", ""],
    ["PLC-05", "Schneider Electric", "Modicon M340", "v3.1", "PLC", "Control", 1, "high", "false", "false", ""],
    ["PLC-06", "Schneider Electric", "Modicon M580", "v3.2", "PLC", "Control", 1, "medium", "false", "false", ""],
    ["RLY-01", "Siemens", "SIPROTEC", "4.6", "Protection Relay", "Control", 0, "safety", "false", "false", ""],
    ["RTU-01", "Real Time Automation", "EtherNet/IP Stack", "499ES", "RTU", "Field", 1, "high", "false", "false", "VxWorks"],
    ["HMI-01", "Siemens", "SIMATIC S7-1500", "V2.9", "HMI", "Supervisory", 2, "medium", "false", "true", "Windows"],
    ["EWS-01", "Rockwell Automation", "ControlLogix 5570", "v32", "EWS", "Supervisory", 2, "high", "false", "true", "Windows|CodeMeter"],
    ["HIST-01", "Schneider Electric", "Modicon M340", "v3.1", "Historian", "Site Ops", 3, "high", "false", "true", "Windows|Log4j"],
    ["GW-01", "Siemens", "PROFINET", "PN", "Gateway", "DMZ", 3, "medium", "true", "true", "Linux"],
    ["SCADA-01", "Schneider Electric", "Modicon M580", "v3.2", "SCADA", "Supervisory", 2, "high", "false", "true", "Windows|Log4j"],
    ["OPS-01", "Rockwell Automation", "ControlLogix 5570", "v32", "Operator WS", "Supervisory", 2, "medium", "false", "true", "Windows"],
    ["LIC-01", "Wibu", "CodeMeter", "6.9", "License Server", "Site Ops", 3, "low", "false", "true", "CodeMeter|Windows"],
]
HEADER = ["id", "vendor", "model", "firmware", "role", "zone", "purdue_level",
          "criticality", "internet_exposed", "patchable", "platform"]


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "samples/inventory.csv"
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(HEADER)
        w.writerows(ROWS)
    print(f"wrote {len(ROWS)} assets -> {out}")


if __name__ == "__main__":
    main()
