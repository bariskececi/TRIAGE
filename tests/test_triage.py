"""Tests: matching finds the right vulns, and prioritisation puts actively
exploited, reachable, critical things at the top."""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from triage.feeds import load_vulns
from triage.inventory import load_inventory
from triage.match import match
from triage.models import Asset, Vuln
from triage.score import prioritise, score_one, summarise

HERE = os.path.dirname(__file__)
INV = os.path.join(HERE, "t_inventory.csv")


def setup_module(module):
    script = os.path.join(HERE, "..", "scripts", "make_demo_inventory.py")
    subprocess.run([sys.executable, script, INV], check=True)


def teardown_module(module):
    if os.path.exists(INV):
        os.remove(INV)


def test_device_native_match():
    assets = [Asset(id="a", vendor="Siemens", model="SIMATIC S7-1500")]
    vulns = [Vuln(cve="C1", vendor="Siemens", product="SIMATIC S7-1500", cvss=9.0),
             Vuln(cve="C2", vendor="Schneider Electric", product="Modicon M340", cvss=9.0)]
    pairs = match(assets, vulns)
    assert len(pairs) == 1 and pairs[0][1].cve == "C1"


def test_platform_match():
    assets = [Asset(id="h", vendor="Schneider Electric", model="Modicon M340",
                    platform=["Windows", "Log4j"])]
    vulns = [Vuln(cve="LOG", vendor="Apache", product="Log4j", cvss=10.0)]
    pairs = match(assets, vulns)
    assert len(pairs) == 1 and pairs[0][1].cve == "LOG"


def test_kev_outranks_higher_cvss():
    a = Asset(id="a", vendor="V", model="M", criticality="high", purdue_level=3)
    kev_lower_cvss = Vuln(cve="K", vendor="V", product="M", cvss=8.0, epss=0.9, kev=True)
    nonkev_max_cvss = Vuln(cve="N", vendor="V", product="M", cvss=10.0, epss=0.05, kev=False)
    s_kev = score_one(a, kev_lower_cvss)
    s_non = score_one(a, nonkev_max_cvss)
    assert s_kev.priority > s_non.priority
    assert s_kev.band == "fix_first"


def test_unpatchable_gets_compensating_control():
    a = Asset(id="plc", vendor="V", model="M", criticality="safety",
              patchable=False, internet_exposed=True)
    v = Vuln(cve="X", vendor="V", product="M", cvss=9.0, epss=0.9, kev=False)
    s = score_one(a, v)
    assert s.band == "fix_first"
    assert "compensating" in s.action.lower() or "not patchable" in s.action.lower()


def test_full_pipeline_ranks_kev_first():
    assets = load_inventory(INV)
    vulns = load_vulns()
    scored = prioritise(match(assets, vulns))
    assert scored[0].vuln.kev is True          # top of the list is actively exploited
    summ = summarise(scored)
    assert summ["total"] == len(scored)
    assert summ["kev"] >= 1
