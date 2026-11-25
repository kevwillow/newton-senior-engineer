"""Stage 10, the acceptance, through the read-only newton-audit login (the maintainer's
decision R2, 2026-11-15; DESIGN-1.5 "Decided", the stage table row 10).

Stage 10 reads through the 1.3 collector's login, not newton-ops and not
the build helper (stage 9 removed it): ``newton-build`` is gone from the
directory, and the 1.3 audit has no finding outside the plan's accepted
list, else the run stops ``build_account_remains`` or
``finding_outside_accepted``.

The collector here is a fake that answers the bytes of the existing 1.3
fixtures (``tests/ad/fixtures/win-dc-audit-r3.json``, the newton-audit
read of the lab's Windows DC), so the read is the real chain the 1.3 audit
tool runs: ``wire.parse`` against the query set, ``runner.run`` with the
identity guard, then the users query for the build account.

F4 of the part B triage: DC1's stage 9 answers done once its SYSTEM
cleanup task runs, and the task waits 15 s before its deletions, the
account last.  Stage 10 therefore reads again while the account is still
there, for a bound past the cleanup's wait, before it stops
``build_account_remains``; and the run reports stage 9 done only after a
read found the account gone.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from newton_mcp.ad.build import acceptance as build_acceptance
from newton_mcp.ad.build import config as build_config
from newton_mcp.ad.build import plan
from newton_mcp.ad.build import run as build_run
from ops_fixture import OPS  # type: ignore[import-not-found]
from test_build_run import PLAN_ID, Build, state_dir  # type: ignore[import-not-found]  # noqa: F401

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
AUDIT = FIXTURES / "win-dc-audit-r3.json"

#: What the fixture's audit finds and cannot prove (pinned once from the
#: 1.3 chain itself, so a change of the 1.3 catalogue is seen here).
FIXTURE_FINDINGS = [
    "AD-A-01", "AD-A-03", "AD-A-05", "AD-A-06", "AD-A-07", "AD-A-08", "AD-A-09", "AD-A-11",
    "AD-A-12", "AD-A-14", "AD-A-16", "AD-A-17", "AD-A-18", "AD-A-21", "AD-A-33", "AD-A-44",
    "AD-A-45", "AD-A-46", "AD-A-55",
]
FIXTURE_UNKNOWN = ["AD-A-10", "AD-A-20", "AD-A-23", "AD-A-35", "AD-A-36", "AD-A-37", "AD-A-38", "AD-A-57",
                    # the fixture predates the DNS queries, so those checks answer UNKNOWN
                    "AD-A-68a", "AD-A-68b", "AD-A-69a", "AD-A-69b"]

PLAN_INPUTS: dict[str, Any] = {
    "domain": {
        "dns_name": "win.newton.test",
        "netbios": "WIN",
        "functional_level": "Win2025",
        "site": "Default-First-Site-Name",
        "ou_tree": ["IT/Servers"],
        "groups": ["IT Admins"],
        "owner_admin": "owner-admin",
    },
    "servers": [
        {
            "device": "build1",
            "role": "dc1",
            "hostname": "DC1",
            "ip": "192.0.2.11",
            "prefix": 24,
            "gateway": "192.0.2.1",
            "forwarders": ["192.0.2.53"],
            "checkpoint": "hyperv",
        }
    ],
    "baseline": {"version": "2026.11", "options": {"administrator": "random-password"}},
    "accepted_findings": [],
    "ops": dict(OPS),
}


def _plan(accepted: list[str]) -> dict[str, Any]:
    inputs = copy.deepcopy(PLAN_INPUTS)
    inputs["accepted_findings"] = [{"id": one, "reason": "owner-accepted"} for one in accepted]
    return plan.plan_build(inputs)


def _with_build_account(raw: bytes, name: str = "newton-build") -> bytes:
    doc = json.loads(raw)
    row = copy.deepcopy(doc["queries"]["users"]["rows"][0])
    dn = f"CN={name},CN=Users," + doc["domain"]["domain_dn"]
    row["dn"] = dn
    row["a"]["sAMAccountName"] = [name]
    row["a"]["distinguishedName"] = [dn]
    row["a"]["objectSid"] = ["AQUAAAAAAAUVAAAApFSVoIXeFP1+seWeAAQAAA=="]
    row["a"]["adminCount"] = []
    doc["queries"]["users"]["rows"].append(row)
    return json.dumps(doc).encode("utf-8")


class FakeCollector:
    """The newton-audit login: each fetch answers the next document."""

    def __init__(self, *documents: bytes) -> None:
        self.documents = list(documents)
        self.targets: list[Any] = []

    def __call__(self, target: Any) -> bytes:
        self.targets.append(target)
        if len(self.documents) > 1:
            return self.documents.pop(0)
        return self.documents[0]


def _target() -> build_acceptance.AuditTarget:
    return build_acceptance.AuditTarget(host="192.0.2.11", port=22, key_file=Path("/k"), known_hosts=Path("/kh"))


def _read(raw: bytes, built: dict[str, Any]) -> dict[str, Any]:
    accept = build_acceptance.audit_acceptance(_target(), fetch=FakeCollector(raw))
    return dict(accept(built, built["servers"][0]))


# --------------------------------------------------------------------------
# the read
# --------------------------------------------------------------------------


def test_the_read_is_the_1_3_audit_of_the_newton_audit_login() -> None:
    built = _plan([])
    collector = FakeCollector(AUDIT.read_bytes())
    read = build_acceptance.audit_acceptance(_target(), fetch=collector)(built, built["servers"][0])
    assert read == {"build_account": "absent", "findings": FIXTURE_FINDINGS, "unknown": FIXTURE_UNKNOWN}
    target = collector.targets[0]
    # the read-only 1.3 login of the plan's domain, never newton-ops or
    # the build helper's newton-build
    assert (target.user, target.platform, target.auth) == ("newton-audit@win.newton.test", "ad-windows", "key")


def test_the_build_account_in_the_users_query_reads_present() -> None:
    built = _plan([])
    assert _read(_with_build_account(AUDIT.read_bytes()), built)["build_account"] == "present"
    assert _read(_with_build_account(AUDIT.read_bytes(), "NEWTON-BUILD"), built)["build_account"] == "present"
    assert _read(_with_build_account(AUDIT.read_bytes(), "newton-builder"), built)["build_account"] == "absent"


@pytest.mark.parametrize(
    "change",
    ["users-denied", "users-truncated", "other-domain", "not-json", "privileged-key", "samba-document"],
)
def test_a_read_that_cannot_prove_anything_is_unavailable(change: str) -> None:
    built = _plan([])
    doc = json.loads(AUDIT.read_bytes())
    if change == "users-denied":
        # in the wire's own grammar, so only the acceptance's users check
        # can refuse it
        doc["queries"]["users"]["status"] = "denied"
        doc["queries"]["users"]["error_code"] = "access_denied"
        doc["queries"]["users"]["rows"] = []
        raw = json.dumps(doc).encode()
    elif change == "users-truncated":
        # the rows kept do not prove that newton-build is not past the cut
        doc["queries"]["users"]["status"] = "truncated"
        doc["queries"]["users"]["error_code"] = "size_limit"
        raw = json.dumps(doc).encode()
    elif change == "other-domain":
        built = plan.plan_build(dict(copy.deepcopy(PLAN_INPUTS), domain=dict(PLAN_INPUTS["domain"], dns_name="other.newton.test")))
        raw = AUDIT.read_bytes()
    elif change == "not-json":
        raw = b"not a collector document"
    elif change == "privileged-key":
        doc["identity"]["token_group_sids"].append(doc["domain"]["domain_sid"] + "-512")
        raw = json.dumps(doc).encode()
    else:
        raw = (FIXTURES / "samba-dc-audit-r1.json").read_bytes()
    with pytest.raises(build_acceptance.AcceptanceUnavailable):
        _read(raw, built)


def test_the_read_is_of_dc1_only() -> None:
    """Stage 10 runs from DC1: the acceptance refuses to answer for another
    server of the plan."""
    built = _plan([])
    server = dict(built["servers"][0], role="dc2")
    collector = FakeCollector(AUDIT.read_bytes())
    with pytest.raises(build_acceptance.AcceptanceUnavailable):
        build_acceptance.audit_acceptance(_target(), fetch=collector)(built, server)
    assert collector.targets == []


def test_a_fetch_that_fails_is_unavailable() -> None:
    from newton_mcp.ad import transport as ad_transport

    def fail(target: Any) -> bytes:
        raise ad_transport.AdTransportError("the collector host did not answer")

    built = _plan([])
    with pytest.raises(build_acceptance.AcceptanceUnavailable):
        build_acceptance.audit_acceptance(_target(), fetch=fail)(built, built["servers"][0])


# --------------------------------------------------------------------------
# the runner's stage 10 with the newton-audit read
# --------------------------------------------------------------------------


class AuditBuild(Build):
    """A one-DC build of the run tests whose stage 10 reads the fixture
    through the newton-audit acceptance."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, collector: FakeCollector, accepted: list[str]) -> None:
        import test_build_run  # type: ignore[import-not-found]

        def inputs(two: bool) -> dict[str, Any]:
            out = copy.deepcopy(PLAN_INPUTS)
            out["accepted_findings"] = [{"id": one, "reason": "owner-accepted"} for one in accepted]
            return out

        monkeypatch.setattr(test_build_run, "_inputs", inputs)
        super().__init__(monkeypatch)
        self.collector = collector
        self.audit = build_acceptance.audit_acceptance(_target(), fetch=collector)

    def acceptance(self, built: Any, server: Any) -> Any:  # type: ignore[override]
        return self.audit(built, server)


def test_stage_10_through_newton_audit_ends_done_when_every_finding_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    build = AuditBuild(monkeypatch, FakeCollector(AUDIT.read_bytes()), FIXTURE_FINDINGS + FIXTURE_UNKNOWN)
    state = build.drive()
    assert (state["state"], state["stage"]) == ("done", "10"), state
    assert "9" in state["finished"]["build1"]
    assert not [r for _, r in build.transport.requests if r["stage"] == "10"]


def test_stage_10_stops_on_a_finding_outside_the_accepted_list(monkeypatch: pytest.MonkeyPatch) -> None:
    accepted = [one for one in FIXTURE_FINDINGS if one != "AD-A-33"] + FIXTURE_UNKNOWN
    build = AuditBuild(monkeypatch, FakeCollector(AUDIT.read_bytes()), accepted)
    state = build.drive()
    assert (state["state"], state["reason"], state["stage"]) == ("stopped", "finding_outside_accepted", "10")
    assert "AD-A-33" in state["detail"]


def test_stage_10_stops_on_a_check_it_cannot_prove_outside_the_accepted_list(monkeypatch: pytest.MonkeyPatch) -> None:
    accepted = FIXTURE_FINDINGS + [one for one in FIXTURE_UNKNOWN if one != "AD-A-57"]
    build = AuditBuild(monkeypatch, FakeCollector(AUDIT.read_bytes()), accepted)
    state = build.drive()
    assert (state["state"], state["reason"]) == ("stopped", "unknown_outside_accepted")
    assert "AD-A-57" in state["detail"]


def test_stage_10_waits_for_the_cleanup_to_delete_the_account(monkeypatch: pytest.MonkeyPatch) -> None:
    """F4: the first reads still find the account (the cleanup task waits
    15 s before its deletions); a later read finds it gone, and the run is
    done."""
    present = _with_build_account(AUDIT.read_bytes())
    collector = FakeCollector(present, present, AUDIT.read_bytes())
    build = AuditBuild(monkeypatch, collector, FIXTURE_FINDINGS + FIXTURE_UNKNOWN)
    state = build.drive()
    assert (state["state"], state["stage"]) == ("done", "10"), state
    assert len(collector.targets) == 3


def test_stage_10_stops_build_account_remains_once_the_wait_is_over(monkeypatch: pytest.MonkeyPatch) -> None:
    collector = FakeCollector(_with_build_account(AUDIT.read_bytes()))
    build = AuditBuild(monkeypatch, collector, FIXTURE_FINDINGS + FIXTURE_UNKNOWN)
    state = build.drive()
    assert (state["state"], state["reason"]) == ("stopped", "build_account_remains")
    assert len(collector.targets) >= 2
    waited = sum(build.clock.slept[-(len(collector.targets) - 1):])
    assert waited >= build_run.ACCEPTANCE_WAIT_S > build_acceptance.CLEANUP_DELAY_S


def test_stage_9_is_not_reported_done_before_a_read_found_the_account_gone(monkeypatch: pytest.MonkeyPatch) -> None:
    collector = FakeCollector(_with_build_account(AUDIT.read_bytes()))
    build = AuditBuild(monkeypatch, collector, FIXTURE_FINDINGS + FIXTURE_UNKNOWN)
    state = build.drive()
    assert state["reason"] == "build_account_remains"
    assert "9" not in state["finished"].get("build1", [])
    assert state["cleanup"] == {"build1": "registered"}


# --------------------------------------------------------------------------
# the owner's build config names the newton-audit login
# --------------------------------------------------------------------------

_SERVER = {"host": "192.0.2.11", "port": 22, "key_file": "/home/o/.ssh/nb", "known_hosts": "/home/o/.config/newton/kh"}
_AUDIT = {"host": "192.0.2.11", "port": 22, "key_file": "/home/o/.ssh/newton-audit", "known_hosts": "/home/o/.config/newton/kh"}


def test_the_config_builds_the_acceptance_of_its_audit_login(monkeypatch: pytest.MonkeyPatch) -> None:
    config = build_config.parse_config({"version": 1, "servers": {"build1": dict(_SERVER)}, "audit": dict(_AUDIT)})
    collector = FakeCollector(AUDIT.read_bytes())
    monkeypatch.setattr(build_acceptance, "_fetch", collector)
    accept = build_config.build_acceptance(config)
    assert accept is not None
    built = _plan([])
    assert accept(built, built["servers"][0])["build_account"] == "absent"
    target = collector.targets[0]
    assert (target.host, target.port, str(target.key_file)) == ("192.0.2.11", 22, "/home/o/.ssh/newton-audit")


def test_a_config_without_an_audit_login_gives_no_acceptance() -> None:
    config = build_config.parse_config({"version": 1, "servers": {"build1": dict(_SERVER)}})
    assert build_config.build_acceptance(config) is None


@pytest.mark.parametrize(
    "audit",
    [dict(_AUDIT, user="newton-ops"), dict(_AUDIT, key_file="relative"), {k: v for k, v in _AUDIT.items() if k != "host"}],
    ids=["a-user-key", "relative-path", "no-host"],
)
def test_the_audit_login_of_the_config_is_exact(audit: dict[str, Any]) -> None:
    with pytest.raises(build_config.BuildConfigError):
        build_config.parse_config({"version": 1, "servers": {"build1": dict(_SERVER)}, "audit": audit})


def test_run_build_without_a_transport_takes_the_configs_acceptance(monkeypatch: pytest.MonkeyPatch) -> None:
    """The MCP tool calls ``run_build(plan_id)``: the transport, the
    adapters and the acceptance all come from the owner's build config."""
    build = AuditBuild(monkeypatch, FakeCollector(AUDIT.read_bytes()), FIXTURE_FINDINGS + FIXTURE_UNKNOWN)
    config = build_config.parse_config({"version": 1, "servers": {"build1": dict(_SERVER)}, "audit": dict(_AUDIT)})
    monkeypatch.setattr(build_config, "load_config", lambda path=None: config)
    monkeypatch.setattr(build_config, "build_transport", lambda loaded: build.transport)
    monkeypatch.setattr(build_config, "build_adapters", lambda loaded, transport=None: build.adapters)
    monkeypatch.setattr(build_acceptance, "_fetch", build.collector)
    state = build_run.run_build(PLAN_ID, clock=build.clock, sleep=build.clock.sleep)
    for _ in range(12):
        if state["state"] != build_run.STOPPED_FOR_APPROVAL:
            break
        assert build.approve_stage(state["stage"]) == 0
        state = build_run.run_build(PLAN_ID, clock=build.clock, sleep=build.clock.sleep)
    assert (state["state"], state["stage"]) == ("done", "10"), state
    assert build.collector.targets
