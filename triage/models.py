"""Data models for the prioritisation engine.

The whole point of Triage is to turn two lists — your assets and the known
vulnerabilities — into one ranked answer: what to fix first. These are the
shapes that flow through it.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class Asset:
    id: str
    vendor: str
    model: str
    firmware: str = ""
    role: str = ""                 # PLC, HMI, EWS, Historian, RTU, Switch...
    zone: str = ""                 # Purdue zone label
    purdue_level: int = 2          # 0..5 (lower = closer to the process)
    criticality: str = "medium"    # low | medium | high | safety
    internet_exposed: bool = False
    patchable: bool = True         # can this asset realistically be patched?
    platform: list[str] = field(default_factory=list)  # embedded OS/software: Windows, Log4j, VxWorks...

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Vuln:
    cve: str
    vendor: str
    product: str                   # matches Asset.model (family)
    cvss: float
    epss: float = 0.0              # 0..1 probability of exploitation in the wild
    kev: bool = False              # on CISA Known Exploited Vulnerabilities list
    affected_firmware: str = ""    # human-readable version note
    title: str = ""
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Scored:
    asset: Asset
    vuln: Vuln
    priority: float                # 0..100 final ranking score
    band: str                      # fix_first | schedule | monitor | accept
    action: str                    # recommended remediation
    factors: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset": self.asset.to_dict(),
            "vuln": self.vuln.to_dict(),
            "priority": round(self.priority, 1),
            "band": self.band,
            "action": self.action,
            "factors": self.factors,
        }
