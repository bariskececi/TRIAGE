"""The prioritisation engine — the answer to "what do I fix first?"

A raw CVSS score ranks by how bad a vuln *could* be. That is not the same as what
you should fix first. Triage blends five signals into one 0-100 priority:

  - KEV       : is it being exploited right now? (the strongest single signal)
  - EPSS      : how likely is exploitation in the near term?
  - CVSS      : how severe if exploited?
  - criticality: how much does this asset matter (up to safety-critical)?
  - exposure  : how reachable is it (internet-facing, network position)?

Then it turns the score into an OT-aware action, because on a plant floor the
honest answer is often "you cannot patch this" — and the right move is a
compensating control, not a reboot.
"""
from __future__ import annotations

from .models import Asset, Vuln, Scored

W_KEV, W_EPSS, W_CVSS, W_CRIT, W_EXP = 0.30, 0.25, 0.20, 0.15, 0.10
CRIT_WEIGHT = {"low": 0.25, "medium": 0.5, "high": 0.8, "safety": 1.0}


def _exposure(a: Asset) -> float:
    if a.internet_exposed:
        return 1.0
    return {5: 0.5, 4: 0.5, 3: 0.35, 2: 0.25, 1: 0.2, 0: 0.2}.get(a.purdue_level, 0.3)


def _band(priority: float, v: Vuln) -> str:
    if priority >= 65 or (v.kev and v.cvss >= 7):
        return "fix_first"
    if priority >= 45:
        return "schedule"
    if priority >= 25:
        return "monitor"
    return "accept"


def _action(a: Asset, v: Vuln, band: str) -> str:
    if v.kev:
        if a.patchable:
            return "Patch now — this vulnerability is being actively exploited in the wild."
        return ("Actively exploited and not directly patchable — isolate the asset, "
                "restrict access to it, add a detection signature, and virtual-patch at the boundary.")
    if band == "fix_first":
        if a.patchable:
            return "Schedule an urgent patch in the next maintenance window."
        return ("High priority but not patchable — apply compensating controls: segment the zone, "
                "allow-list the protocol, and add monitoring for this technique.")
    if band == "schedule":
        return "Plan remediation: patch at the next window, or add a compensating control if patching is not viable."
    if band == "monitor":
        return "Track it. No immediate action required; watch for any change in exploitation status."
    return "Low priority — document a risk-acceptance decision and revisit next cycle."


def score_one(a: Asset, v: Vuln) -> Scored:
    kev = 1.0 if v.kev else 0.0
    epss = max(0.0, min(1.0, v.epss))
    cvss = max(0.0, min(10.0, v.cvss)) / 10.0
    crit = CRIT_WEIGHT.get(a.criticality, 0.5)
    exp = _exposure(a)

    raw = W_KEV * kev + W_EPSS * epss + W_CVSS * cvss + W_CRIT * crit + W_EXP * exp
    priority = round(raw * 100, 1)
    band = _band(priority, v)

    factors = {
        "kev": v.kev,
        "epss_pct": round(epss * 100, 1),
        "cvss": v.cvss,
        "criticality": a.criticality,
        "exposure": "internet-exposed" if a.internet_exposed else f"Purdue L{a.purdue_level}",
        "patchable": a.patchable,
        "contributions": {
            "actively_exploited": round(W_KEV * kev * 100, 1),
            "exploit_likelihood": round(W_EPSS * epss * 100, 1),
            "severity": round(W_CVSS * cvss * 100, 1),
            "asset_criticality": round(W_CRIT * crit * 100, 1),
            "exposure": round(W_EXP * exp * 100, 1),
        },
    }
    return Scored(asset=a, vuln=v, priority=priority, band=band,
                  action=_action(a, v, band), factors=factors)


def prioritise(pairs: list[tuple[Asset, Vuln]]) -> list[Scored]:
    scored = [score_one(a, v) for a, v in pairs]
    scored.sort(key=lambda s: s.priority, reverse=True)
    return scored


def summarise(scored: list[Scored]) -> dict:
    bands = {"fix_first": 0, "schedule": 0, "monitor": 0, "accept": 0}
    for s in scored:
        bands[s.band] = bands.get(s.band, 0) + 1
    return {
        "total": len(scored),
        "kev": sum(1 for s in scored if s.vuln.kev),
        "assets_affected": len({s.asset.id for s in scored}),
        "bands": bands,
    }
