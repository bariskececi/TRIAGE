"""Match an asset inventory against the vulnerability set.

Two ways a vuln lands on an asset:
  1. Device-native — same vendor and product family (a Siemens S7-1500 vuln on a
     Siemens S7-1500).
  2. Platform — embedded software or OS the asset runs (Log4j in a historian,
     Windows on an engineering workstation, VxWorks in a field device).
"""
from __future__ import annotations

from .models import Asset, Vuln

# Vendors whose entries are cross-cutting platforms rather than a device family.
_PLATFORM_VENDORS = {"Apache", "Microsoft", "Linux", "Wind River", "Wibu",
                     "Real Time Automation"}


def _norm(s: str) -> str:
    return "".join(ch for ch in s.lower() if ch.isalnum())


def _family_match(asset_model: str, vuln_product: str) -> bool:
    a, v = _norm(asset_model), _norm(vuln_product)
    return a in v or v in a


def match(assets: list[Asset], vulns: list[Vuln]) -> list[tuple[Asset, Vuln]]:
    pairs: list[tuple[Asset, Vuln]] = []
    for a in assets:
        a_platforms = {_norm(p) for p in a.platform}
        for v in vulns:
            if v.vendor in _PLATFORM_VENDORS:
                # match by platform/software the asset runs
                if _norm(v.product) in a_platforms:
                    pairs.append((a, v))
            else:
                # device-native: vendor + product family
                if _norm(v.vendor) in _norm(a.vendor) and _family_match(a.model, v.product):
                    pairs.append((a, v))
    return pairs
