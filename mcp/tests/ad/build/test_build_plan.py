"""The build plan of Newton 1.5 (PLAN-1.5 task 1, DESIGN-1.5 "The plan").

Every constant of this file comes from the two documents and from
nowhere else: the header line ``newton-ad-build-v1``, the stage digest
message ``newton-ad-build-stage-v1`` with its ``plan=``, ``stage=`` and
``checkpoint=`` lines, the two info strings of the derived secrets, the
stage ids ``0`` to ``10`` with their kinds, and the two stage graphs.

The golden plan's canonical bytes are written out here in full, so a
change of the encoding is a change of this file: the digest is pinned
against the bytes and the bytes are pinned against the rules of the
design.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from typing import Any

import pytest

from newton_mcp.ad import catalogue
from newton_mcp.ad.build import plan


#: The newton-ops public key of the golden plan (the maintainer's decision R1,
#: 2026-11-15): an ssh-ed25519 line with no comment or options.  The key
#: is synthetic: the blob holds the type and the bytes 0 to 31.
OPS_PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f"

#: Another key in the grammar: the bytes 32 to 63.
OPS_PUBLIC_KEY_2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/"

#: The sha256 of the 1.4 write helper the golden plan's stage 8 installs
#: (of a fixture's bytes, not of the package's write.ps1).
OPS_WRITE_HELPER_SHA256 = "d746ef0ab0a31002fac07f4462fc27a2c74ade4ce680a35cef75d30f54204005"

#: The newton-audit public key of the golden plan (the maintainer's decision on open
#: point 34, 2026-11-16: stage 8 installs the 1.3 audit login too): the
#: bytes 64 to 95.
AUDIT_PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEBBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f"

#: The ops section of the plans of this file.
OPS: dict[str, str] = {
    "audit_public_key": AUDIT_PUBLIC_KEY,
    "public_key": OPS_PUBLIC_KEY,
    "write_helper_sha256": OPS_WRITE_HELPER_SHA256,
}

#: The good plan: one domain, two servers, one baseline option, one
#: accepted finding.  Every value is synthetic (RFC 5737 addresses).
GOLDEN_INPUTS: dict[str, Any] = {
    "domain": {
        "dns_name": "ad-build.test",
        "netbios": "ADBUILD",
        "functional_level": "Win2025",
        "site": "Default-First-Site-Name",
        "ou_tree": ["IT/Servers", "IT/Workstations"],
        "groups": ["IT Admins", "IT Operators"],
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
        },
        {
            "device": "build2",
            "role": "dc2",
            "hostname": "DC2",
            "ip": "192.0.2.12",
            "prefix": 24,
            "gateway": "192.0.2.1",
            "forwarders": ["192.0.2.53"],
            "checkpoint": "proxmox",
            "vmgenid": "44387c6b-1f2e-4a5b-8c9d-0e1f2a3b4c5d",
            "agent": 1,
        },
    ],
    "baseline": {
        "version": "2026.11",
        "options": {"administrator": "random-password"},
    },
    "accepted_findings": [
        {"id": "AD-A-51", "reason": "owner-accepted"},
    ],
    "ops": dict(OPS),
}

#: The variant of the golden plan: one server with two forwarders, two
#: accepted findings and two baseline options.  The second baseline
#: setting is a fixture of this file; the table of the module holds one
#: setting until the baseline file of task 6 lands.
VARIANT_INPUTS: dict[str, Any] = {
    "domain": {
        "dns_name": "ad-build.test",
        "netbios": "ADBUILD",
        "functional_level": "Win2025",
        "site": "Default-First-Site-Name",
        "ou_tree": ["IT/Servers", "IT/Workstations"],
        "groups": ["IT Admins", "IT Operators"],
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
            "forwarders": ["192.0.2.53", "192.0.2.54"],
            "checkpoint": "hyperv",
        },
    ],
    "baseline": {
        "version": "2026.11",
        "options": {"administrator": "random-password", "second-setting": "option-a"},
    },
    "accepted_findings": [
        {"id": "AD-A-51", "reason": "owner-accepted"},
        {"id": "AD-A-52", "reason": "owner-accepted"},
    ],
    "ops": dict(OPS),
}

#: The canonical bytes of the golden plan, in full.
GOLDEN_CANONICAL = (
    "newton-ad-build-v1\n"
    "accepted_findings.0.id=AD-A-51\n"
    "accepted_findings.0.reason=owner-accepted\n"
    "baseline.options=administrator=random-password\n"
    "baseline.version=2026.11\n"
    "domain.dns_name=ad-build.test\n"
    "domain.functional_level=Win2025\n"
    "domain.groups=IT Admins,IT Operators\n"
    "domain.netbios=ADBUILD\n"
    "domain.ou_tree=IT/Servers,IT/Workstations\n"
    "domain.owner_admin=owner-admin\n"
    "domain.site=Default-First-Site-Name\n"
    "ops.audit_public_key=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEBBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f\n"
    "ops.public_key=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f\n"
    "ops.write_helper_sha256=d746ef0ab0a31002fac07f4462fc27a2c74ade4ce680a35cef75d30f54204005\n"
    "servers.0.checkpoint=hyperv\n"
    "servers.0.device=build1\n"
    "servers.0.forwarders=192.0.2.53\n"
    "servers.0.gateway=192.0.2.1\n"
    "servers.0.hostname=DC1\n"
    "servers.0.ip=192.0.2.11\n"
    "servers.0.prefix=24\n"
    "servers.0.role=dc1\n"
    "servers.1.agent=1\n"
    "servers.1.checkpoint=proxmox\n"
    "servers.1.device=build2\n"
    "servers.1.forwarders=192.0.2.53\n"
    "servers.1.gateway=192.0.2.1\n"
    "servers.1.hostname=DC2\n"
    "servers.1.ip=192.0.2.12\n"
    "servers.1.prefix=24\n"
    "servers.1.role=dc2\n"
    "servers.1.vmgenid=44387c6b-1f2e-4a5b-8c9d-0e1f2a3b4c5d\n"
    "stages.graph.dc1=0,1,2,3,4,5,6,7,8,9,10\n"
    "stages.graph.dc2=0,1,7,9\n"
    "stages.kind.0=read\n"
    "stages.kind.1=reversible\n"
    "stages.kind.10=read\n"
    "stages.kind.2=irreversible\n"
    "stages.kind.3=irreversible\n"
    "stages.kind.4=irreversible\n"
    "stages.kind.5=reversible\n"
    "stages.kind.6=irreversible\n"
    "stages.kind.7=irreversible\n"
    "stages.kind.8=reversible\n"
    "stages.kind.9=final\n"
)

#: The digest of the golden plan.  Re-pinned on 2026-11-15 when the plan
#: gained the ops section (the maintainer's decision R1); it was
#: 553670722495d920f00a047d278ff824b5c2582387e54296fa90238d2c201831.
#: Re-pinned again on 2026-11-16 when the ops section gained the
#: newton-audit key (the maintainer's decision on open point 34); it was
#: 5d06b49b024460b969146c73add92a8e861ee6521e8de418d49dcd5d51311e42.
GOLDEN_DIGEST = "93068eab7f0448446fdcb4a71bccf379607ca0d9bf36ef65ed514ba61f141140"

#: The pinned digest the stage digest and the derived secrets are pinned
#: over: the golden plan's digest before the ops section.  Those pins test
#: ``stage_digest`` and ``derive_secret``, not the plan's bytes, so they
#: keep their own digest.
PINNED_DIGEST = "553670722495d920f00a047d278ff824b5c2582387e54296fa90238d2c201831"

#: The stage digest of the golden plan, stage "2", one checkpoint id.
GOLDEN_STAGE_DIGEST = (
    "115c6810262ba0ad3fd187176df65298f2434a3505903eee5e74170adb106404"
)

#: The checkpoint id of the pinned stage digest.
CHECKPOINT_ID = "3f2b1c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d"

#: The canonical bytes of the variant plan, in full: the second
#: forwarder, the second finding and the second baseline option are in
#: them.
VARIANT_CANONICAL = (
    "newton-ad-build-v1\n"
    "accepted_findings.0.id=AD-A-51\n"
    "accepted_findings.0.reason=owner-accepted\n"
    "accepted_findings.1.id=AD-A-52\n"
    "accepted_findings.1.reason=owner-accepted\n"
    "baseline.options=administrator=random-password,second-setting=option-a\n"
    "baseline.version=2026.11\n"
    "domain.dns_name=ad-build.test\n"
    "domain.functional_level=Win2025\n"
    "domain.groups=IT Admins,IT Operators\n"
    "domain.netbios=ADBUILD\n"
    "domain.ou_tree=IT/Servers,IT/Workstations\n"
    "domain.owner_admin=owner-admin\n"
    "domain.site=Default-First-Site-Name\n"
    "ops.audit_public_key=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEBBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWltcXV5f\n"
    "ops.public_key=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f\n"
    "ops.write_helper_sha256=d746ef0ab0a31002fac07f4462fc27a2c74ade4ce680a35cef75d30f54204005\n"
    "servers.0.checkpoint=hyperv\n"
    "servers.0.device=build1\n"
    "servers.0.forwarders=192.0.2.53,192.0.2.54\n"
    "servers.0.gateway=192.0.2.1\n"
    "servers.0.hostname=DC1\n"
    "servers.0.ip=192.0.2.11\n"
    "servers.0.prefix=24\n"
    "servers.0.role=dc1\n"
    "stages.graph.dc1=0,1,2,3,4,5,6,8,9,10\n"
    "stages.kind.0=read\n"
    "stages.kind.1=reversible\n"
    "stages.kind.10=read\n"
    "stages.kind.2=irreversible\n"
    "stages.kind.3=irreversible\n"
    "stages.kind.4=irreversible\n"
    "stages.kind.5=reversible\n"
    "stages.kind.6=irreversible\n"
    "stages.kind.7=irreversible\n"
    "stages.kind.8=reversible\n"
    "stages.kind.9=final\n"
)

#: The K of the pinned secret: 32 bytes of 0x11, as in SPEC-1.4-REQUEST.
K_HEX = "11" * 32

#: The marker of the change that swaps the two servers of the plan.
#: The two roles are one change: the two servers trade their places
#: and their roles, so the plan stays the plan of ``plan_build``.
SWAP_SERVERS = object()

#: The in-grammar alternate of every leaf of the plan that has one.
#:
#: The key is the path of the leaf in the plan and the value is the
#: list of the changes that give the leaf another value.  A change is
#: a path and a value, and a change of the value None removes the
#: field it is at: a checkpoint that is not Proxmox holds no vmgenid
#: and no agent, and the two roles are swapped as a pair, so those
#: leaves carry more than one change.
ALTERNATES: dict[tuple[Any, ...], list[tuple[tuple[Any, ...], Any]]] = {
    ("domain", "dns_name"): [(("domain", "dns_name"), "ad-build2.test")],
    ("domain", "netbios"): [(("domain", "netbios"), "ADBUILD2")],
    ("domain", "site"): [(("domain", "site"), "Second-Site-Name")],
    ("domain", "ou_tree", 0): [(("domain", "ou_tree", 0), "IT/Servers2")],
    ("domain", "ou_tree", 1): [(("domain", "ou_tree", 1), "IT/Workstations2")],
    ("domain", "groups", 0): [(("domain", "groups", 0), "IT Admins2")],
    ("domain", "groups", 1): [(("domain", "groups", 1), "IT Operators2")],
    ("domain", "owner_admin"): [(("domain", "owner_admin"), "owner-admin2")],
    ("servers", 0, "device"): [(("servers", 0, "device"), "build3")],
    ("servers", 0, "role"): [(("servers",), SWAP_SERVERS)],
    ("servers", 0, "hostname"): [(("servers", 0, "hostname"), "DC1A")],
    ("servers", 0, "ip"): [(("servers", 0, "ip"), "192.0.2.13")],
    ("servers", 0, "prefix"): [(("servers", 0, "prefix"), 25)],
    ("servers", 0, "gateway"): [(("servers", 0, "gateway"), "192.0.2.2")],
    ("servers", 0, "forwarders", 0): [
        (("servers", 0, "forwarders", 0), "192.0.2.54")
    ],
    ("servers", 0, "checkpoint"): [(("servers", 0, "checkpoint"), "wbadmin")],
    ("servers", 1, "device"): [(("servers", 1, "device"), "build4")],
    ("servers", 1, "role"): [(("servers",), SWAP_SERVERS)],
    ("servers", 1, "hostname"): [(("servers", 1, "hostname"), "DC2A")],
    ("servers", 1, "ip"): [(("servers", 1, "ip"), "192.0.2.14")],
    ("servers", 1, "prefix"): [(("servers", 1, "prefix"), 25)],
    ("servers", 1, "gateway"): [(("servers", 1, "gateway"), "192.0.2.2")],
    ("servers", 1, "forwarders", 0): [
        (("servers", 1, "forwarders", 0), "192.0.2.54")
    ],
    ("servers", 1, "checkpoint"): [
        (("servers", 1, "checkpoint"), "wbadmin"),
        (("servers", 1, "vmgenid"), None),
        (("servers", 1, "agent"), None),
    ],
    ("servers", 1, "vmgenid"): [
        (("servers", 1, "vmgenid"), "44387c6b-1f2e-4a5b-8c9d-0e1f2a3b4c5e")
    ],
    ("baseline", "version"): [(("baseline", "version"), "2026.12")],
    ("baseline", "options", "administrator"): [
        (("baseline", "options", "administrator"), "disabled")
    ],
    ("accepted_findings", 0, "id"): [(("accepted_findings", 0, "id"), "AD-A-52")],
    ("accepted_findings", 0, "reason"): [
        (("accepted_findings", 0, "reason"), "owner-changed")
    ],
    ("ops", "public_key"): [(("ops", "public_key"), OPS_PUBLIC_KEY_2)],
    ("ops", "audit_public_key"): [(("ops", "audit_public_key"), OPS_PUBLIC_KEY_2)],
    ("ops", "write_helper_sha256"): [(("ops", "write_helper_sha256"), "0f" * 32)],
}

#: The leaves of the plan that hold one value only: the functional
#: level of the design and the guest agent of a Proxmox VM.  There is
#: no other value in the grammar of the two fields, so they are
#: compared in the canonical bytes and not with another plan.
SINGLE_VALUED: frozenset[tuple[Any, ...]] = frozenset(
    {("domain", "functional_level"), ("servers", 1, "agent")}
)

#: The DSRM secret of the pinned K, the pinned digest and the DSRM info.
GOLDEN_DSRM_SECRET = "Jg2&XH!XnQLgoENUVrBkPsSb"

#: The admin secret of the pinned K, the pinned digest and the admin info.
GOLDEN_ADMIN_SECRET = "Tn6&ypafgv@6FRVfJN9++TE@"

#: The key material of RFC 5869 test case A.1: 22 octets of 0x0b.
RFC5869_IKM = "0b" * 22

#: The salt of RFC 5869 test case A.1: 13 octets.
RFC5869_SALT = "000102030405060708090a0b0c"

#: The info of RFC 5869 test case A.1: 10 octets.
RFC5869_INFO = "f0f1f2f3f4f5f6f7f8f9"

#: The length of the OKM of RFC 5869 test case A.1: 42 octets.
RFC5869_LENGTH = 42

#: The OKM of RFC 5869 test case A.1.
RFC5869_OKM = (
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    "34007208d5b887185865"
)


def golden_plan() -> dict[str, Any]:
    """The golden plan, built fresh."""
    return plan.plan_build(copy.deepcopy(GOLDEN_INPUTS))


def variant_plan(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """The variant plan, built with the second baseline setting of the
    test."""
    monkeypatch.setitem(
        plan.BASELINE_OPTIONS, "second-setting", ("option-a", "option-b")
    )
    return plan.plan_build(copy.deepcopy(VARIANT_INPUTS))


def one_server_inputs() -> dict[str, Any]:
    """The good inputs with the DC2 removed."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    del inputs["servers"][1]
    return inputs


def inputs_with(**changes: Any) -> dict[str, Any]:
    """The good inputs with one top-level field changed."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs.update(changes)
    return inputs


# --------------------------------------------------------------------------
# The golden plan
# --------------------------------------------------------------------------


def test_the_golden_plan_builds() -> None:
    """The good inputs build a plan that holds what the design names."""
    built = golden_plan()

    assert built["domain"]["dns_name"] == "ad-build.test"
    assert built["domain"]["netbios"] == "ADBUILD"
    assert built["domain"]["ou_tree"] == ["IT/Servers", "IT/Workstations"]
    assert built["domain"]["groups"] == ["IT Admins", "IT Operators"]
    assert built["domain"]["owner_admin"] == "owner-admin"
    assert [server["role"] for server in built["servers"]] == ["dc1", "dc2"]
    assert built["servers"][0]["ip"] == "192.0.2.11"
    assert built["servers"][1]["vmgenid"] == "44387c6b-1f2e-4a5b-8c9d-0e1f2a3b4c5d"
    assert built["servers"][1]["agent"] == 1
    assert built["baseline"] == {
        "version": "2026.11",
        "options": {"administrator": "random-password"},
    }
    assert built["accepted_findings"] == [
        {"id": "AD-A-51", "reason": "owner-accepted"}
    ]


def test_the_golden_plan_canonical_bytes_are_pinned() -> None:
    """The canonical bytes of the golden plan are the ones of this file."""
    canonical = plan.canonical_bytes(golden_plan())

    assert canonical == GOLDEN_CANONICAL.encode("ascii")


def test_the_golden_plan_digest_is_pinned() -> None:
    """The digest of the golden plan is pinned, and it is the hash of
    the pinned bytes."""
    digest = plan.digest(golden_plan())

    assert digest == GOLDEN_DIGEST
    assert GOLDEN_DIGEST == hashlib.sha256(GOLDEN_CANONICAL.encode("ascii")).hexdigest()


def test_a_plan_survives_a_json_round_trip() -> None:
    """A plan that went through JSON is still the plan it was.

    The plan is approved as its canonical bytes and carried to the
    helpers as JSON, so the stage graphs come back from the round trip
    as lists and not as the tuples they were built as.  A plan that is
    refused after the round trip is a plan that cannot be resumed.
    """
    built = golden_plan()
    round_tripped = json.loads(json.dumps(built))

    assert plan.digest(round_tripped) == GOLDEN_DIGEST
    assert plan.digest(round_tripped) == plan.digest(built)
    assert plan.stage_graph(round_tripped, "dc2") == ("0", "1", "7", "9")

    resumed = plan.plan_build(inputs_with(resume_from="a" * 64, start_stage="3", secrets_from="a" * 64))
    resumed_round_tripped = json.loads(json.dumps(resumed))

    assert plan.digest(resumed_round_tripped) == plan.digest(resumed)
    assert plan.stage_graph(resumed_round_tripped, "dc2") == ("0", "1", "7", "9")


def test_the_canonical_bytes_are_ascii_and_lf() -> None:
    """The canonical bytes are ASCII, LF only, and end with a newline."""
    canonical = plan.canonical_bytes(golden_plan())

    assert canonical == canonical.decode("ascii").encode("ascii")
    assert b"\r" not in canonical
    assert canonical.endswith(b"\n")
    assert canonical.count(b"\n") == len(canonical.decode("ascii").splitlines())


def test_the_canonical_bytes_hold_one_pair_per_line() -> None:
    """Every line after the header holds one key=value pair."""
    lines = plan.canonical_bytes(golden_plan()).decode("ascii").splitlines()

    assert lines[0] == "newton-ad-build-v1"
    for line in lines[1:]:
        key, _, value = line.partition("=")
        assert key
        assert value


def test_the_canonical_bytes_sort_the_keys_by_byte_value() -> None:
    """The pairs are sorted ordinally, as in SPEC-1.4-REQUEST section 4."""
    lines = plan.canonical_bytes(golden_plan()).decode("ascii").splitlines()[1:]
    keys = [line.partition("=")[0] for line in lines]

    assert keys == sorted(keys)


def test_every_field_changes_the_digest() -> None:
    """No field of the plan is left out of the canonical bytes.

    Every leaf of the plan that is not derived is compared with
    another value of its own grammar, and the digest of the plan moves
    every time: a field that was left out of the bytes would leave the
    digest where it was.  A value that leaves the grammar of its field
    is not a comparison at all, so the alternates of this file are
    inside the grammar of the field they belong to.

    The two leaves that hold one value only are compared in the
    canonical bytes themselves: there is no other value in the
    grammar of the functional level of the design and of the guest
    agent of a Proxmox VM to compare the plan with.
    """
    built = golden_plan()
    golden = plan.digest(built)
    canonical = plan.canonical_bytes(built).decode("ascii")

    leaves = _plan_leaves(built)
    assert {path for path, _ in leaves} == set(ALTERNATES) | set(SINGLE_VALUED)

    for path, _ in leaves:
        assert _pair_of(built, path) in canonical, path
        changes = ALTERNATES.get(path)
        if changes is None:
            assert path in SINGLE_VALUED, path
        else:
            mutated = copy.deepcopy(built)
            for change_path, change_value in changes:
                _apply(mutated, change_path, change_value)
            assert plan.digest(mutated) != golden, path


def test_every_stage_of_the_plan_is_derived() -> None:
    """The stage graph and the stage kinds are derived from the design.

    A stage that was changed on the way is refused: the plan is
    rebuilt out of its own fields and the two must be the same plan.
    """
    built = golden_plan()

    for path, _ in _stage_leaves(built):
        mutated = copy.deepcopy(built)
        _set(mutated, path, "changed")
        with pytest.raises(plan.BuildPlanRefused) as caught:
            plan.digest(mutated)

        assert caught.value.code == "free_text", path


def test_the_variant_plan_canonical_bytes_are_pinned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The canonical bytes of the variant plan hold every item of it."""
    canonical = plan.canonical_bytes(variant_plan(monkeypatch))

    assert canonical == VARIANT_CANONICAL.encode("ascii")
    assert plan.digest(variant_plan(monkeypatch)) == hashlib.sha256(
        VARIANT_CANONICAL.encode("ascii")
    ).hexdigest()


def test_the_variant_plan_moves_the_digest_with_the_second_forwarder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The second forwarder is in the bytes, so it moves the digest."""
    built = variant_plan(monkeypatch)
    golden = plan.digest(built)
    other = copy.deepcopy(built)
    other["servers"][0]["forwarders"] = ["192.0.2.53", "192.0.2.55"]

    assert plan.digest(other) != golden


def test_the_variant_plan_moves_the_digest_with_the_second_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The second accepted finding is in the bytes, so it moves the
    digest."""
    built = variant_plan(monkeypatch)
    golden = plan.digest(built)
    other = copy.deepcopy(built)
    other["accepted_findings"][1]["reason"] = "owner-changed"

    assert plan.digest(other) != golden


def test_the_variant_plan_moves_the_digest_with_the_second_option(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The second baseline option is in the bytes, so it moves the
    digest."""
    built = variant_plan(monkeypatch)
    golden = plan.digest(built)
    other = copy.deepcopy(built)
    other["baseline"]["options"]["second-setting"] = "option-b"

    assert plan.digest(other) != golden


def test_the_canonical_bytes_of_a_resumed_plan_carry_the_resume() -> None:
    """A resumed plan carries resume_from and start_stage in its bytes."""
    inputs = inputs_with(
        resume_from="a" * 64,
        start_stage="3",
        secrets_from="a" * 64,
    )
    built = plan.plan_build(inputs)
    canonical = plan.canonical_bytes(built).decode("ascii")

    assert "resume_from=" + "a" * 64 + "\n" in canonical
    assert "start_stage=3\n" in canonical


def test_the_inputs_are_not_changed_by_the_plan() -> None:
    """The plan is built out of the inputs; the inputs stay as they were."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    before = copy.deepcopy(inputs)

    plan.plan_build(inputs)

    assert inputs == before


def test_the_plan_does_not_depend_on_the_order_of_the_servers() -> None:
    """The servers are sorted by role, so the digest does not move."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["servers"] = list(reversed(inputs["servers"]))

    assert plan.digest(plan.plan_build(inputs)) == plan.digest(golden_plan())


def test_the_canonical_bytes_refuse_a_value_that_is_not_ascii() -> None:
    """The canonical bytes are ASCII; a value that is not is refused."""
    built = golden_plan()
    built["domain"]["site"] = "Site-é"

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.canonical_bytes(built)

    assert caught.value.code == "free_text"


def test_the_refusal_codes_are_the_nine_of_the_plan() -> None:
    """The plan knows nine codes and no others."""
    assert plan.REFUSAL_CODES == (
        "bad_dns_name",
        "bad_netbios",
        "bad_ip",
        "duplicate_ip",
        "unknown_baseline_option",
        "free_text",
        "two_servers_same_name",
        "proxmox_without_vmgenid",
        "proxmox_without_agent",
    )


# --------------------------------------------------------------------------
# The plan is the plan of plan_build
# --------------------------------------------------------------------------


def test_the_canonical_bytes_refuse_a_newline_in_a_value() -> None:
    """A value with a newline in it would inject a line into the bytes."""
    built = golden_plan()
    built["domain"]["site"] = "Site\nName"

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.canonical_bytes(built)

    assert caught.value.code == "free_text"


def test_the_canonical_bytes_refuse_a_field_outside_the_plan() -> None:
    """A field the plan does not have is refused, not dropped."""
    built = golden_plan()
    built["domain"]["extra"] = "value"

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.canonical_bytes(built)

    assert caught.value.code == "free_text"


def test_the_canonical_bytes_refuse_a_field_of_the_plan_itself() -> None:
    """A field of the plan itself is refused, not dropped.

    The plan is rebuilt out of its own fields, so a field that the
    plan holds and the plan of ``plan_build`` does not is a plan that
    is not the plan of ``plan_build``.
    """
    built = golden_plan()
    built["extra"] = "x"

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.canonical_bytes(built)

    assert caught.value.code == "free_text"


def test_the_canonical_bytes_refuse_a_vmgenid_that_was_upper_cased() -> None:
    """The GUID of a Proxmox VM is held in lower case.

    The plan of an upper case vmgenid is the plan of the lower case
    one, so a plan that holds an upper case vmgenid is not the plan
    of ``plan_build``.
    """
    built = golden_plan()
    built["servers"][1]["vmgenid"] = GOLDEN_INPUTS["servers"][1]["vmgenid"].upper()

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.canonical_bytes(built)

    assert caught.value.code == "free_text"


def test_the_canonical_bytes_refuse_a_plan_with_one_resume_field() -> None:
    """A resumed plan carries resume_from and start_stage together.

    A plan that carries one of the two is not a plan of plan_build, so
    the canonical bytes refuse it.
    """
    built = golden_plan()
    built["resume_from"] = "a" * 64

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.canonical_bytes(built)

    assert caught.value.code == "free_text"

    built = golden_plan()
    built["start_stage"] = "3"

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.canonical_bytes(built)

    assert caught.value.code == "free_text"


def test_the_canonical_bytes_refuse_a_tampered_stage_kind() -> None:
    """A stage kind that was changed on the way is refused."""
    built = golden_plan()
    built["stages"]["kind"]["7"] = "reversible"

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.canonical_bytes(built)

    assert caught.value.code == "free_text"


def test_the_digest_refuses_a_plan_that_is_not_a_plan_of_plan_build() -> None:
    """The digest is the hash of the canonical bytes, so it refuses too."""
    built = golden_plan()
    built["stages"]["kind"]["7"] = "reversible"

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.digest(built)

    assert caught.value.code == "free_text"


def test_the_stage_graph_refuses_a_tampered_graph() -> None:
    """A stage graph that was changed on the way is refused."""
    built = golden_plan()
    built["stages"]["graph"]["dc1"] = ("0", "1")

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.stage_graph(built, "dc1")

    assert caught.value.code == "free_text"


# --------------------------------------------------------------------------
# The guards of the canonical bytes
# --------------------------------------------------------------------------


def test_the_joined_value_refuses_a_comma() -> None:
    """A value of a list holds no comma.

    The comma is the separator of the canonical form, so a value with
    one in it would be two values.
    """
    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan._joined(["a,b"], "a list")

    assert caught.value.code == "free_text"


@pytest.mark.parametrize(
    "value",
    [
        "a,b",
        "a=b",
    ],
)
def test_the_pairs_value_refuses_a_comma_or_an_equal(value: str) -> None:
    """A value of an object holds no comma and no equal.

    The comma and the equal are the separators of the canonical form,
    so a value with one of them in it would be two pairs.
    """
    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan._pairs({"k": value}, "an object")

    assert caught.value.code == "free_text"


# --------------------------------------------------------------------------
# The stage digest
# --------------------------------------------------------------------------


def test_the_stage_digest_is_pinned() -> None:
    """The stage digest of the pinned digest, stage and checkpoint."""
    stage_digest = plan.stage_digest(PINNED_DIGEST, "2", CHECKPOINT_ID)

    assert stage_digest == GOLDEN_STAGE_DIGEST


def test_the_stage_digest_holds_the_header_and_the_three_lines() -> None:
    """The stage digest is the sha256 of the message of the design."""
    message = (
        "newton-ad-build-stage-v1\n"
        f"plan={PINNED_DIGEST}\n"
        "stage=2\n"
        f"checkpoint={CHECKPOINT_ID}\n"
    )

    assert plan.stage_digest(PINNED_DIGEST, "2", CHECKPOINT_ID) == hashlib.sha256(
        message.encode("ascii")
    ).hexdigest()


def test_the_stage_digest_changes_with_the_checkpoint() -> None:
    """The checkpoint id is in the signed bytes."""
    other = plan.stage_digest(PINNED_DIGEST, "2", "another-checkpoint")

    assert other != plan.stage_digest(PINNED_DIGEST, "2", CHECKPOINT_ID)


def test_the_stage_digest_refuses_a_stage_that_is_not_one() -> None:
    """A stage outside the table of the design is refused."""
    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.stage_digest(PINNED_DIGEST, "11", CHECKPOINT_ID)

    assert caught.value.code == "free_text"


@pytest.mark.parametrize(
    "checkpoint_id",
    [
        "3f2b1c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d\n",
        "3f2b1c4d 5e6f 4a8b 9c0d 1e2f3a4b5c6d",
        "c" * 129,
    ],
)
def test_the_stage_digest_refuses_a_checkpoint_id_outside_its_grammar(
    checkpoint_id: str,
) -> None:
    """A checkpoint id is printable ASCII, no space, no newline.

    The checkpoint id is in the signed bytes of the stage, so it is
    one line of it: an id with a newline in it would be two lines.
    """
    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.stage_digest(PINNED_DIGEST, "2", checkpoint_id)

    assert caught.value.code == "free_text"


@pytest.mark.parametrize(
    "plan_digest",
    [
        "A" * 64,
        "zz",
    ],
)
def test_the_stage_digest_refuses_a_plan_digest_outside_its_grammar(
    plan_digest: str,
) -> None:
    """The plan digest of a stage is 64 lower case hexadecimal characters."""
    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.stage_digest(plan_digest, "2", CHECKPOINT_ID)

    assert caught.value.code == "free_text"


# --------------------------------------------------------------------------
# The stage graphs
# --------------------------------------------------------------------------


def test_the_graph_of_a_one_server_plan() -> None:
    """One server: DC1 runs every stage but stage 7."""
    built = plan.plan_build(one_server_inputs())

    assert plan.stage_graph(built, "dc1") == (
        "0",
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
        "8",
        "9",
        "10",
    )


def test_the_graph_of_a_two_server_plan() -> None:
    """Two servers: DC1 runs stage 7 and DC2 runs 0, 1, 7 and 9."""
    built = golden_plan()

    assert plan.stage_graph(built, "dc1") == (
        "0",
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
        "7",
        "8",
        "9",
        "10",
    )
    assert plan.stage_graph(built, "dc2") == ("0", "1", "7", "9")


def test_the_graph_takes_the_server_itself() -> None:
    """The graph of a server may be asked for with the server."""
    built = golden_plan()

    assert plan.stage_graph(built, built["servers"][0]) == plan.stage_graph(
        built, "dc1"
    )
    assert plan.stage_graph(built, built["servers"][1]) == plan.stage_graph(
        built, "dc2"
    )


def test_the_graph_refuses_a_server_that_is_not_in_the_plan() -> None:
    """A server the plan does not hold has no graph."""
    built = golden_plan()

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.stage_graph(built, "dc3")

    assert caught.value.code == "free_text"


def test_the_stage_kinds_are_the_table_of_the_design() -> None:
    """Every stage has the kind the design table gives it."""
    built = golden_plan()

    assert built["stages"]["kind"] == {
        "0": "read",
        "1": "reversible",
        "2": "irreversible",
        "3": "irreversible",
        "4": "irreversible",
        "5": "reversible",
        "6": "irreversible",
        "7": "irreversible",
        "8": "reversible",
        "9": "final",
        "10": "read",
    }


# --------------------------------------------------------------------------
# The refusals
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "dns_name",
    [
        "not a dns name",
        "10.0.0.1",
        "corp.123",
    ],
)
def test_the_plan_refuses_a_bad_dns_name(dns_name: str) -> None:
    """A DNS name outside its grammar is refused.

    The last label of a DNS name is not a number: a name whose last
    label is a number is the name of an address and not the name of a
    domain.
    """
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["domain"]["dns_name"] = dns_name

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "bad_dns_name"


@pytest.mark.parametrize(
    "netbios",
    [
        "A" * 16,
        "AD.BUILD",
        "12345",
    ],
)
def test_the_plan_refuses_a_bad_netbios(netbios: str) -> None:
    """A NetBIOS name of 16 characters or more, or with a dot, is refused.

    A NetBIOS name that is a number is not the name of a domain
    either.
    """
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["domain"]["netbios"] = netbios

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "bad_netbios"


@pytest.mark.parametrize(
    "address",
    [
        "192.0.2.256",
        "192.0.2",
        "not-an-address",
        "2001:db8::1",
    ],
)
def test_the_plan_refuses_a_bad_ip(address: str) -> None:
    """An address that is not an IPv4 address is refused."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["servers"][0]["ip"] = address

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "bad_ip"


def test_the_plan_refuses_a_bad_gateway() -> None:
    """The gateway is an IPv4 address too."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["servers"][0]["gateway"] = "192.0.2.999"

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "bad_ip"


@pytest.mark.parametrize(
    "changes,code",
    [
        pytest.param(
            {"ip": "0.0.0.0", "prefix": 0, "gateway": "8.8.8.8"},
            "free_text",
            id="a-prefix-of-zero",
        ),
        pytest.param(
            {"ip": "127.0.0.5", "prefix": 8, "gateway": "127.0.0.1"},
            "bad_ip",
            id="a-loopback-address",
        ),
        pytest.param(
            {"ip": "224.0.0.5", "prefix": 24, "gateway": "224.0.0.1"},
            "bad_ip",
            id="a-multicast-address",
        ),
        pytest.param(
            {"ip": "192.0.2.255", "prefix": 24, "gateway": "192.0.2.1"},
            "bad_ip",
            id="the-broadcast-address-of-the-network",
        ),
        pytest.param(
            {"gateway": "192.0.2.0"},
            "bad_ip",
            id="a-gateway-on-the-address-of-the-network",
        ),
        pytest.param(
            {"gateway": "192.0.2.11"},
            "bad_ip",
            id="a-gateway-equal-to-the-address-of-the-server",
        ),
        pytest.param(
            {"forwarders": ["192.0.2.11"]},
            "bad_ip",
            id="a-forwarder-equal-to-the-address-of-the-server",
        ),
        pytest.param(
            {"ip": "169.254.1.11", "prefix": 16, "gateway": "169.254.1.1"},
            "bad_ip",
            id="a-link-local-address",
        ),
        # The review's minors (T2): the gateway alone unusable (inside the
        # network, not its network or broadcast address, not the
        # server's), and the address alone unusable with a usable
        # gateway, so each usable check stops a plan on its own.
        pytest.param(
            {"ip": "10.0.0.5", "prefix": 1, "gateway": "127.0.0.1"},
            "bad_ip",
            id="a-loopback-gateway-with-a-usable-address",
        ),
        pytest.param(
            {"ip": "169.0.0.5", "prefix": 8, "gateway": "169.254.0.1"},
            "bad_ip",
            id="a-link-local-gateway-with-a-usable-address",
        ),
        pytest.param(
            {"ip": "200.0.0.5", "prefix": 1, "gateway": "224.0.0.1"},
            "bad_ip",
            id="a-multicast-gateway-with-a-usable-address",
        ),
        pytest.param(
            {"ip": "200.0.0.5", "prefix": 1, "gateway": "240.0.0.1"},
            "bad_ip",
            id="a-reserved-gateway-with-a-usable-address",
        ),
        pytest.param(
            {"ip": "127.0.0.5", "prefix": 1, "gateway": "10.0.0.1"},
            "bad_ip",
            id="a-loopback-address-with-a-usable-gateway",
        ),
        pytest.param(
            {"ip": "224.0.0.5", "prefix": 1, "gateway": "200.0.0.1"},
            "bad_ip",
            id="a-multicast-address-with-a-usable-gateway",
        ),
        pytest.param(
            {"ip": "169.254.0.5", "prefix": 8, "gateway": "169.0.0.1"},
            "bad_ip",
            id="a-link-local-address-with-a-usable-gateway",
        ),
        pytest.param(
            {"ip": "240.0.0.5", "prefix": 1, "gateway": "200.0.0.1"},
            "bad_ip",
            id="a-reserved-address-with-a-usable-gateway",
        ),
    ],
)
def test_the_plan_refuses_an_unusable_address(
    changes: dict[str, Any], code: str
) -> None:
    """An address a server cannot be reached at is refused.

    The address of the server, the address of its gateway and the
    addresses of its forwarders are addresses that the build can use:
    an unspecified, a loopback, a multicast, a link-local or a
    reserved address is not one of them, neither is the address of the
    network or the broadcast address of it, and the gateway and the
    forwarders are not the address of the server itself.
    """
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["servers"][0].update(changes)

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == code


@pytest.mark.parametrize(
    "forwarder",
    [
        "169.254.1.1",
        "255.255.255.255",
        "240.0.0.1",
    ],
)
def test_the_plan_refuses_an_unusable_forwarder(forwarder: str) -> None:
    """A forwarder the build cannot use is refused.

    A DNS forwarder is an address the build reaches, so it is refused
    for the same reasons the address of the server is: a link-local or
    a reserved address is not one of them.
    """
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["servers"][0]["forwarders"] = [forwarder]

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "bad_ip"


def test_the_plan_refuses_a_duplicate_ip() -> None:
    """Two servers may not hold the same address."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["servers"][1]["ip"] = inputs["servers"][0]["ip"]

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "duplicate_ip"


def test_the_plan_refuses_an_unknown_baseline_option() -> None:
    """An option that is not one of the known settings is refused."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["baseline"]["options"] = {"not-a-setting": "whatever"}

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "unknown_baseline_option"


def test_the_plan_refuses_an_unknown_baseline_option_value() -> None:
    """An option that is not one of the options of its setting is refused."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["baseline"]["options"] = {"administrator": "whatever"}

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "unknown_baseline_option"


def test_the_plan_refuses_a_baseline_without_the_administrator_option() -> None:
    """A setting that has options must have one of them chosen.

    The built-in Administrator is given a derived random password or
    is disabled: a baseline that says nothing about it leaves the
    choice to whoever runs the build.
    """
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["baseline"]["options"] = {}

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "free_text"


@pytest.mark.parametrize(
    "field,value",
    [
        ("groups", ["IT Admins, and more"]),
        ("owner_admin", "owner admin; rm -rf /"),
        ("site", "Site; rm -rf /"),
    ],
)
def test_the_plan_refuses_free_text(field: str, value: Any) -> None:
    """A value that is not from its grammar is refused."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["domain"][field] = value

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "free_text"


def _blob(key_type: bytes, body: bytes) -> str:
    return base64.b64encode(len(key_type).to_bytes(4, "big") + key_type + len(body).to_bytes(4, "big") + body).decode()


@pytest.mark.parametrize(
    "public_key",
    [
        OPS_PUBLIC_KEY + " owner@host",
        'restrict ' + OPS_PUBLIC_KEY,
        "ssh-rsa " + _blob(b"ssh-rsa", bytes(32)),
        "ssh-ed25519 " + _blob(b"ssh-rsa", bytes(28)),
        "ssh-ed25519 " + _blob(b"ssh-ed25518", bytes(32)),
        "ssh-ed25519 " + _blob(b"ssh-ed25519", bytes(31)),
        "ssh-ed25519 " + _blob(b"ssh-ed25519", bytes(32)) + "\n",
        "ssh-ed25519  " + _blob(b"ssh-ed25519", bytes(32)),
        "ssh-ed25519 " + _blob(b"ssh-ed25519", bytes(32))[:-1] + "!",
        "ssh-ed25519 " + _blob(b"ssh-ed25519", bytes(32) + b"\x00"),
        "",
        7,
    ],
    ids=["comment", "options", "rsa", "body-of-another-type", "blob-of-another-type-same-length", "short-key", "newline", "two-spaces",
         "not-base64", "trailing-byte", "empty", "int"],
)
def test_the_plan_refuses_an_ops_public_key_outside_its_grammar(public_key: Any) -> None:
    """The maintainer's decision R1: ssh-ed25519 only, a base64 body that is one
    ed25519 key, no comment, no options."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["ops"]["public_key"] = public_key
    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)
    assert caught.value.code == "free_text"


@pytest.mark.parametrize("sha", ["AB" * 32, "ab" * 31, "ab" * 33, "g" * 64, "", None], ids=["upper", "short", "long", "hex", "empty", "none"])
def test_the_plan_refuses_a_write_helper_sha256_outside_its_grammar(sha: Any) -> None:
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["ops"]["write_helper_sha256"] = sha
    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)
    assert caught.value.code == "free_text"


@pytest.mark.parametrize("change", ["missing", "extra-field", "missing-field", "not-an-object"])
def test_the_plan_refuses_an_ops_section_that_is_not_exactly_its_own(change: str) -> None:
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    if change == "missing":
        del inputs["ops"]
    elif change == "extra-field":
        inputs["ops"]["extra"] = "value"
    elif change == "missing-field":
        del inputs["ops"]["write_helper_sha256"]
    else:
        inputs["ops"] = OPS_PUBLIC_KEY
    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)
    assert caught.value.code == "free_text"


@pytest.mark.parametrize(
    "public_key",
    [
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ",
        OPS_PUBLIC_KEY + " comment",
        "restrict " + OPS_PUBLIC_KEY,
        OPS_PUBLIC_KEY[:-1],
        "ssh-ed25519 " + "A" * 68,
        "",
        None,
    ],
    ids=["rsa", "comment", "option", "short", "not-ed25519-blob", "empty", "none"],
)
def test_the_plan_refuses_an_audit_public_key_outside_its_grammar(public_key: Any) -> None:
    """The newton-audit key of stage 8 (the maintainer's decision on open point 34) is
    in the newton-ops key's grammar: ssh-ed25519 only, one ed25519 blob, no
    comment, no options (DESIGN-1.5, task 8 open points)."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["ops"]["audit_public_key"] = public_key
    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)
    assert caught.value.code == "free_text"


def test_the_plan_refuses_one_key_for_both_logins() -> None:
    """The newton-audit key is not the newton-ops key: with one key for
    both, the holder of the read-only login holds the write login too."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["ops"]["audit_public_key"] = inputs["ops"]["public_key"]
    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)
    assert caught.value.code == "free_text"


def test_the_plan_refuses_an_ops_section_without_the_audit_key() -> None:
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    del inputs["ops"]["audit_public_key"]
    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)
    assert caught.value.code == "free_text"


def test_the_plan_carries_the_ops_section() -> None:
    assert golden_plan()["ops"] == OPS


def test_the_plan_refuses_a_plan_without_a_dc1() -> None:
    """A plan without a DC1 has no forest root to build."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["servers"].pop(0)

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "free_text"


def test_the_plan_refuses_a_short_owner_admin() -> None:
    """The owner's admin account is an sAMAccountName of 8 to 20
    characters, so that the derived admin secret cannot hold it."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["domain"]["owner_admin"] = "adm"

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "free_text"


def test_the_plan_refuses_owner_admin_newton_build() -> None:
    """The build account of the design is not the owner's admin account."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["domain"]["owner_admin"] = "newton-build"

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "free_text"


@pytest.mark.parametrize(
    "name",
    ["DefaultAccount", "defaultaccount", "DEFAULTACCOUNT", "WDAGUtilityAccount", "Guest", "krbtgt",
     "Administrator", "newton-build"],
)
def test_the_plan_refuses_every_built_in_account_name(name: str) -> None:
    """IC4 of the task 6 triage: stage 5 adds an owner admin it finds to
    Domain Admins and Protected Users, so the owner admin may not be the
    name of an account a fresh forest already holds: the built-in
    Administrator, Guest, krbtgt and DefaultAccount, the WDAG utility
    account Windows creates, and the build account.  Guest and krbtgt are
    also too short for the grammar; they are refused by name as well."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["domain"]["owner_admin"] = name

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "free_text"
    assert {"administrator", "guest", "krbtgt", "defaultaccount", "wdagutilityaccount", "newton-build"} <= (
        plan.RESERVED_OWNER_ADMINS
    )


def test_the_plan_refuses_owner_admin_administrator() -> None:
    """The built-in Administrator is not the owner's admin account."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["domain"]["owner_admin"] = "Administrator"

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "free_text"


def test_the_plan_refuses_a_group_named_like_the_owner_admin() -> None:
    """A group and the owner's admin account are two different accounts."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["domain"]["groups"] = ["IT Admins", "Owner-Admin"]

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "free_text"


def test_the_plan_refuses_a_hostname_equal_to_the_netbios_name() -> None:
    """A server may not hold the name of the domain."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["servers"][0]["hostname"] = inputs["domain"]["netbios"].lower()

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "free_text"


def test_the_plan_refuses_a_role_that_is_not_one() -> None:
    """A role outside the two of the design is refused."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["servers"][0]["role"] = "dc3"

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "free_text"


def test_the_plan_refuses_a_checkpoint_method_that_is_not_one() -> None:
    """A checkpoint method outside the three of the design is refused."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["servers"][0]["checkpoint"] = "vmware"

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "free_text"


def test_the_plan_refuses_two_servers_with_the_same_name() -> None:
    """Two servers may not share a name."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["servers"][1]["device"] = inputs["servers"][0]["device"]

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "two_servers_same_name"


def test_the_plan_refuses_two_servers_with_the_same_hostname() -> None:
    """Two servers may not share a hostname either."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["servers"][1]["hostname"] = inputs["servers"][0]["hostname"]

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "two_servers_same_name"


def test_the_plan_refuses_a_proxmox_server_without_a_vmgenid() -> None:
    """A Proxmox VM without a vmgenid is refused."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    del inputs["servers"][1]["vmgenid"]

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "proxmox_without_vmgenid"


def test_the_plan_refuses_a_proxmox_server_without_an_agent() -> None:
    """A Proxmox VM without the guest agent is refused."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["servers"][1]["agent"] = 0

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "proxmox_without_agent"


def test_the_plan_refuses_a_field_it_does_not_have() -> None:
    """An input outside the plan is refused."""
    inputs = inputs_with(extra="value")

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "free_text"


# --------------------------------------------------------------------------
# The guards of the grammar
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "where",
    ["domain", "server", "baseline", "finding"],
)
def test_the_plan_refuses_a_field_the_object_does_not_have(where: str) -> None:
    """Every object of the plan holds exactly its own fields."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    if where == "domain":
        inputs["domain"]["extra"] = "value"
    elif where == "server":
        inputs["servers"][0]["extra"] = "value"
    elif where == "baseline":
        inputs["baseline"]["extra"] = "value"
    else:
        inputs["accepted_findings"][0]["extra"] = "value"

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "free_text"


def test_the_plan_refuses_two_hostnames_that_differ_in_case() -> None:
    """Two servers may not share a hostname, whatever its case is."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["servers"][1]["hostname"] = inputs["servers"][0]["hostname"].lower()

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "two_servers_same_name"


def test_the_plan_refuses_two_servers_with_the_same_vmgenid() -> None:
    """Two servers may not share the vmgenid of a Proxmox VM.

    The GUID of a VM is one value, so the plan holds it in lower case
    and a vmgenid in upper case is the vmgenid in lower case: two
    servers with one GUID are one VM.
    """
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["servers"][0]["checkpoint"] = "proxmox"
    inputs["servers"][0]["vmgenid"] = inputs["servers"][1]["vmgenid"]
    inputs["servers"][0]["agent"] = 1
    inputs["servers"][1]["vmgenid"] = inputs["servers"][1]["vmgenid"].upper()

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "two_servers_same_name"


def test_the_plan_refuses_two_servers_with_the_same_role() -> None:
    """Two servers may not hold the same role."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["servers"][1]["role"] = "dc1"

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "free_text"


def test_the_plan_refuses_no_servers() -> None:
    """The plan holds one server or two."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["servers"] = []

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "free_text"


def test_the_plan_refuses_three_servers() -> None:
    """The plan holds one server or two."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    third = copy.deepcopy(inputs["servers"][1])
    third["device"] = "build3"
    third["hostname"] = "DC3"
    third["ip"] = "192.0.2.13"
    inputs["servers"].append(third)

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "free_text"


def test_the_plan_checks_the_number_of_servers_before_the_servers() -> None:
    """The count of the servers is checked before they are read.

    A third server with an address of its own that is not an address
    is refused with the count's code and not with the address's.
    """
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    third = copy.deepcopy(inputs["servers"][1])
    third["device"] = "build3"
    third["hostname"] = "DC3"
    third["ip"] = "not-an-address"
    inputs["servers"].append(third)

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "free_text"


@pytest.mark.parametrize(
    "prefix",
    [
        31,
        33,
    ],
)
def test_the_plan_refuses_a_prefix_outside_the_range(prefix: int) -> None:
    """A prefix is 1 to 30."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["servers"][0]["prefix"] = prefix

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "free_text"


def test_the_plan_refuses_a_dns_name_with_a_space() -> None:
    """A DNS label holds no space."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["domain"]["dns_name"] = "ad.bad label"

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "bad_dns_name"


# --------------------------------------------------------------------------
# The grammar of the plan
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path,value,code",
    [
        pytest.param(
            ("domain", "functional_level"),
            "Win2016",
            "free_text",
            id="functional-level-outside-the-enum",
        ),
        pytest.param(
            ("domain", "groups"),
            ["IT Admins", "IT Admins"],
            "free_text",
            id="two-groups-with-one-name",
        ),
        pytest.param(
            ("domain", "groups"),
            ["IT Admins", "it admins"],
            "free_text",
            id="two-groups-with-one-name-in-another-case",
        ),
        pytest.param(
            ("domain", "ou_tree"),
            ["IT/Servers", "IT/Servers"],
            "free_text",
            id="two-ous-with-one-path",
        ),
        pytest.param(
            ("domain", "ou_tree"),
            ["IT/Servers", "it/servers"],
            "free_text",
            id="two-ous-with-one-path-in-another-case",
        ),
        pytest.param(
            ("domain", "dns_name"),
            ".".join(["a" * 63] * 4),
            "bad_dns_name",
            id="a-dns-name-longer-than-253",
        ),
        pytest.param(
            ("domain", "owner_admin"),
            "adm",
            "free_text",
            id="an-owner-admin-shorter-than-8",
        ),
        pytest.param(
            ("servers", 0, "forwarders"),
            [],
            "free_text",
            id="a-server-with-no-forwarder",
        ),
        pytest.param(
            ("servers", 0, "forwarders"),
            ["192.0.2.53", "192.0.2.53"],
            "free_text",
            id="two-forwarders-with-one-address",
        ),
        pytest.param(
            ("servers", 0, "hostname"),
            "DC1-",
            "free_text",
            id="a-hostname-with-a-trailing-hyphen",
        ),
        pytest.param(
            ("servers", 0, "hostname"),
            "12345",
            "free_text",
            id="a-hostname-of-digits-only",
        ),
        pytest.param(
            ("servers", 0, "prefix"),
            True,
            "free_text",
            id="a-prefix-that-is-a-bool",
        ),
        pytest.param(
            ("servers", 1, "agent"),
            True,
            "proxmox_without_agent",
            id="an-agent-that-is-a-bool",
        ),
        pytest.param(
            ("servers", 0, "gateway"),
            "198.51.100.1",
            "bad_ip",
            id="a-gateway-outside-the-network",
        ),
        pytest.param(
            ("accepted_findings",),
            [
                {"id": "AD-A-51", "reason": "owner-accepted"},
                {"id": "AD-A-51", "reason": "owner-changed"},
            ],
            "free_text",
            id="two-findings-with-one-id",
        ),
    ],
)
def test_the_plan_refuses_an_input_that_cannot_build(
    path: tuple[Any, ...], value: Any, code: str
) -> None:
    """An input the plan cannot be built of is refused, with its own code."""
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    _set(inputs, path, value)

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == code


def test_the_plan_lowercases_the_vmgenid() -> None:
    """A vmgenid in upper case is the vmgenid in lower case.

    The GUID of a VM is one value, so the plan holds it in lower case
    and the plan of an upper case vmgenid is the plan of the lower case
    one.
    """
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["servers"][1]["vmgenid"] = GOLDEN_INPUTS["servers"][1]["vmgenid"].upper()

    built = plan.plan_build(inputs)

    assert built["servers"][1]["vmgenid"] == GOLDEN_INPUTS["servers"][1]["vmgenid"]
    assert plan.digest(built) == GOLDEN_DIGEST


def test_the_plan_keeps_the_spelling_of_a_name() -> None:
    """A name of the domain is held as it was given.

    Two names that differ in their case are two names, so the plan
    holds the spelling of each one of them.
    """
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["domain"]["groups"] = ["IT Admins", "it operators"]
    inputs["domain"]["ou_tree"] = ["IT/Servers", "it/workstations"]

    built = plan.plan_build(inputs)

    assert built["domain"]["groups"] == ["IT Admins", "it operators"]
    assert built["domain"]["ou_tree"] == ["IT/Servers", "it/workstations"]


# --------------------------------------------------------------------------
# The grammar of a finding id
# --------------------------------------------------------------------------


def test_every_check_id_of_the_catalogue_is_in_the_finding_id_grammar() -> None:
    """Every id of the 1.3 catalogue is in the grammar of a finding id.

    A check whose id carries a letter is a check of the catalogue too,
    and the runner reads every id the audit answers at stage 10: an id
    outside the grammar stops the run with ``acceptance_unavailable``.
    """
    for check in catalogue.CHECKS:
        assert plan.FINDING_ID_RE.fullmatch(check.id) is not None, check.id


def test_the_plan_accepts_a_finding_id_with_a_letter() -> None:
    """A finding id with one lower case letter after its digits is one.

    The id is in the plan and in its canonical bytes, so the owner can
    accept that check the way the owner accepts any other one.
    """
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["accepted_findings"] = [{"id": "AD-A-68a", "reason": "owner-accepted"}]

    built = plan.plan_build(inputs)

    assert built["accepted_findings"] == [
        {"id": "AD-A-68a", "reason": "owner-accepted"}
    ]
    canonical = plan.canonical_bytes(built).decode("ascii")
    assert "accepted_findings.0.id=AD-A-68a\n" in canonical


@pytest.mark.parametrize(
    "identifier",
    [
        "AD-A-68A",
        "AD-A-68ab",
        "AD-A-68-a",
        "AD-A-6a",
        "AD-A-681",
        "AD-A-68a\n",
        "AD-A-68é",
    ],
    ids=[
        "an-upper-case-letter",
        "two-letters",
        "a-hyphen-in-the-suffix",
        "one-digit",
        "three-digits",
        "a-newline",
        "a-letter-outside-ascii",
    ],
)
def test_the_plan_refuses_a_finding_id_outside_the_grammar(identifier: str) -> None:
    """An id that is not in the grammar of a finding id is refused.

    The letter of the grammar is one lower case letter at the end: an
    upper case one, two letters, a hyphen, a digit count that is not
    two, a newline and a letter outside ASCII are all outside it.
    """
    inputs = copy.deepcopy(GOLDEN_INPUTS)
    inputs["accepted_findings"] = [{"id": identifier, "reason": "owner-accepted"}]

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "free_text"


# --------------------------------------------------------------------------
# The resumed plan
# --------------------------------------------------------------------------


def test_the_plan_refuses_a_start_stage_that_is_not_in_the_plan() -> None:
    """A one-server plan has no stage 7, so a resume cannot start there."""
    inputs = one_server_inputs()
    inputs["resume_from"] = "a" * 64
    inputs["start_stage"] = "7"
    inputs["secrets_from"] = "a" * 64

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "free_text"


def test_a_resumed_plan_carries_resume_from_and_start_stage() -> None:
    """A resumed plan carries the digest it continues and the stage it
    starts at."""
    inputs = inputs_with(
        resume_from="b" * 64,
        start_stage="4",
        secrets_from="e" * 64,
    )
    built = plan.plan_build(inputs)

    assert built["resume_from"] == "b" * 64
    assert built["start_stage"] == "4"
    assert built["secrets_from"] == "e" * 64
    canonical = plan.canonical_bytes(built).decode("ascii")
    assert "resume_from=" + "b" * 64 + "\n" in canonical
    assert "start_stage=4\n" in canonical
    # signed: the bytes the owner approves name the salt of the secrets
    assert "secrets_from=" + "e" * 64 + "\n" in canonical


def test_a_plan_without_a_resume_carries_none() -> None:
    """A plan that does not resume carries no resume."""
    built = golden_plan()

    assert "resume_from" not in built
    assert "start_stage" not in built
    assert "secrets_from" not in built
    canonical = plan.canonical_bytes(built).decode("ascii")
    assert "resume_from" not in canonical
    assert "start_stage" not in canonical
    assert "secrets_from" not in canonical


def test_the_plan_refuses_a_resume_without_a_start_stage() -> None:
    """A resume carries both fields or neither."""
    inputs = inputs_with(resume_from="c" * 64, secrets_from="c" * 64)

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "free_text"


def test_the_plan_refuses_a_start_stage_that_is_not_one() -> None:
    """A start stage outside the table of the design is refused."""
    inputs = inputs_with(resume_from="d" * 64, start_stage="11", secrets_from="d" * 64)

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs)

    assert caught.value.code == "free_text"


@pytest.mark.parametrize(
    "changes",
    [
        {"resume_from": "b" * 64, "start_stage": "4"},
        {"secrets_from": "b" * 64},
        {"resume_from": "b" * 64, "start_stage": "4", "secrets_from": "B" * 64},
        {"resume_from": "b" * 64, "start_stage": "4", "secrets_from": "b" * 63},
        {"resume_from": "b" * 64, "start_stage": "4", "secrets_from": 7},
    ],
    ids=["resume-without-secrets-from", "secrets-from-without-resume", "upper-case", "short", "not-text"],
)
def test_the_plan_refuses_a_secrets_from_out_of_its_rule(changes: dict[str, Any]) -> None:
    """DESIGN-1.5 open point 71: a resume plan names the digest its derived
    secrets come from (the build's first plan), and only a resume plan
    does; the value is a digest."""
    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.plan_build(inputs_with(**changes))

    assert caught.value.code == "free_text"


def test_the_canonical_bytes_refuse_a_plan_that_gained_a_secrets_from() -> None:
    """A secrets_from added to a plan that does not resume is not a plan of
    plan_build."""
    built = golden_plan()
    built["secrets_from"] = "a" * 64

    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.canonical_bytes(built)

    assert caught.value.code == "free_text"


def test_the_secrets_of_a_plan_are_salted_with_its_first_plan() -> None:
    """The salt of the derived secrets: the plan's own digest for a first
    plan, its secrets_from for a resume plan (open point 71)."""
    first = golden_plan()
    assert plan.secrets_digest(first) == plan.digest(first)

    resumed = plan.plan_build(
        inputs_with(resume_from="b" * 64, start_stage="4", secrets_from="e" * 64)
    )
    assert plan.digest(resumed) != "e" * 64
    assert plan.secrets_digest(resumed) == "e" * 64


# --------------------------------------------------------------------------
# The derived secrets
# --------------------------------------------------------------------------


def test_the_derived_dsrm_secret_is_pinned() -> None:
    """The DSRM secret of the pinned K and digest is pinned."""
    secret = plan.derive_secret(K_HEX, PINNED_DIGEST, plan.DSRM_INFO)

    assert secret == GOLDEN_DSRM_SECRET


def test_hkdf_matches_rfc5869_a1() -> None:
    """The HKDF of the module is the HKDF of RFC 5869.

    The test case A.1 of the RFC is the basic one with SHA-256: the
    key material, the salt, the info and the length are the ones of
    the RFC, and the OKM is the one of the RFC.
    """
    okm = plan._hkdf_sha256(
        bytes.fromhex(RFC5869_IKM),
        bytes.fromhex(RFC5869_SALT),
        bytes.fromhex(RFC5869_INFO),
        RFC5869_LENGTH,
    )

    assert okm.hex() == RFC5869_OKM


@pytest.mark.parametrize(
    "k_hex,plan_digest",
    [
        ("11" * 31, PINNED_DIGEST),
        ("11" * 32 + "11", PINNED_DIGEST),
        ("1G" * 32, PINNED_DIGEST),
        ("AB" * 32, PINNED_DIGEST),
        (K_HEX, "not-a-digest"),
        (K_HEX, "A" * 64),
    ],
)
def test_derive_secret_refuses_a_malformed_key_or_digest(
    k_hex: str, plan_digest: str
) -> None:
    """The key is 64 lower case hexadecimal characters and so is the
    digest."""
    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.derive_secret(k_hex, plan_digest, plan.DSRM_INFO)

    assert caught.value.code == "free_text"


def test_the_derived_admin_secret_is_pinned() -> None:
    """The admin secret of the pinned K and digest is pinned."""
    secret = plan.derive_secret(K_HEX, PINNED_DIGEST, plan.ADMIN_INFO)

    assert secret == GOLDEN_ADMIN_SECRET


def test_the_derived_secrets_meet_the_complexity_rules() -> None:
    """A derived secret is long enough and holds all four classes."""
    for info in (plan.DSRM_INFO, plan.ADMIN_INFO):
        secret = plan.derive_secret(K_HEX, PINNED_DIGEST, info)

        assert len(secret) >= 14
        assert any(character.isupper() for character in secret)
        assert any(character.islower() for character in secret)
        assert any(character.isdigit() for character in secret)
        assert any(not character.isalnum() for character in secret)


def test_the_two_secrets_differ() -> None:
    """The two info strings give two different secrets."""
    dsrm = plan.derive_secret(K_HEX, PINNED_DIGEST, plan.DSRM_INFO)
    admin = plan.derive_secret(K_HEX, PINNED_DIGEST, plan.ADMIN_INFO)

    assert dsrm != admin


def test_the_info_strings_are_the_ones_of_the_design() -> None:
    """The two info strings are the ones the design names."""
    assert plan.DSRM_INFO == "newton-ad-build-dsrm-v1"
    assert plan.ADMIN_INFO == "newton-ad-build-admin-v1"
    assert plan.INFO_STRINGS == (plan.DSRM_INFO, plan.ADMIN_INFO)


def test_derive_secret_refuses_another_info_string() -> None:
    """Only the two info strings of the design derive a secret."""
    with pytest.raises(plan.BuildPlanRefused) as caught:
        plan.derive_secret(K_HEX, PINNED_DIGEST, "anything-v9")

    assert caught.value.code == "free_text"


def test_the_secret_is_not_the_same_for_another_digest() -> None:
    """The plan digest is the salt of the derivation."""
    one = plan.derive_secret(K_HEX, PINNED_DIGEST, plan.DSRM_INFO)
    other = plan.derive_secret(K_HEX, "e" * 64, plan.DSRM_INFO)

    assert one != other


# --------------------------------------------------------------------------
# The reuse of the approve module
# --------------------------------------------------------------------------


def test_the_server_key_is_the_key_of_the_approve_module() -> None:
    """The K of a server is the approve module's key, never a second one."""
    from newton_mcp import approve

    assert plan.server_key(b"passphrase", "build1") == approve.derive_k(
        b"passphrase", "build1"
    )


def test_the_plan_token_is_the_token_of_the_approve_module() -> None:
    """The token of a plan is the approve module's token."""
    from newton_mcp import approve

    assert plan.plan_token(K_HEX, PINNED_DIGEST, 1800000000, 1800000600) == (
        approve.approval_token(K_HEX, PINNED_DIGEST, 1800000000, 1800000600)
    )


# --------------------------------------------------------------------------
# Helpers of the tests
# --------------------------------------------------------------------------


def _leaves(
    value: Any, path: tuple[Any, ...] = ()
) -> list[tuple[tuple[Any, ...], Any]]:
    """Every leaf of the plan, with the path that reaches it."""
    found: list[tuple[tuple[Any, ...], Any]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            found.extend(_leaves(item, path + (key,)))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            found.extend(_leaves(item, path + (index,)))
    else:
        found.append((path, value))
    return found


def _plan_leaves(
    built: dict[str, Any]
) -> list[tuple[tuple[Any, ...], Any]]:
    """Every leaf of the plan but the leaves of the stages.

    The stages are derived from the design and from the roles of the
    servers, so they are not leaves of the inputs of the plan.
    """
    return [
        (path, value) for path, value in _leaves(built) if path[:1] != ("stages",)
    ]


def _stage_leaves(
    built: dict[str, Any]
) -> list[tuple[tuple[Any, ...], Any]]:
    """Every leaf of the stages of the plan."""
    return [
        (path, value) for path, value in _leaves(built) if path[:1] == ("stages",)
    ]


def _pair_of(built: dict[str, Any], path: tuple[Any, ...]) -> str:
    """The pair of the canonical bytes that holds the leaf.

    The lists of the plan and the options of the baseline are joined
    into one value, so the pair of a leaf of a list is the pair of the
    list it is in.
    """
    parent: Any = built
    for step in path[:-1]:
        parent = parent[step]
    if isinstance(parent, list):
        key = ".".join(str(step) for step in path[:-1])
        value = ",".join(str(item) for item in parent)
    elif path[:-1] == ("baseline", "options"):
        key = "baseline.options"
        value = ",".join(
            f"{name}={option}" for name, option in sorted(parent.items())
        )
    else:
        key = ".".join(str(step) for step in path)
        value = str(parent[path[-1]])
    return f"{key}={value}"


def _apply(built: dict[str, Any], path: tuple[Any, ...], value: Any) -> None:
    """Make the change at the path of the plan.

    A value of None removes the field at the path, and the marker of
    the swap trades the two servers of the plan.
    """
    if value is SWAP_SERVERS:
        servers = built["servers"]
        built["servers"] = [
            {**copy.deepcopy(servers[1]), "role": servers[0]["role"]},
            {**copy.deepcopy(servers[0]), "role": servers[1]["role"]},
        ]
        return
    if value is None:
        _remove(built, path)
        return
    _set(built, path, value)


def _set(plan_dict: dict[str, Any], path: tuple[Any, ...], value: Any) -> None:
    """Set the value at the path of the plan."""
    here: Any = plan_dict
    for step in path[:-1]:
        here = here[step]
    here[path[-1]] = value


def _remove(plan_dict: dict[str, Any], path: tuple[Any, ...]) -> None:
    """Remove the field at the path of the plan."""
    here: Any = plan_dict
    for step in path[:-1]:
        here = here[step]
    del here[path[-1]]
