"""The undo planner.

``newton_mcp.undo_plan`` decides whether a confirmed change may be undone,
builds the ``uci batch`` that puts the router back the way it was, and writes
the explanation the owner reads next to it.

Everything here is local: no
device, no network, no shell, nothing written outside ``tmp_path``.  The
fixtures are real: real plan records, real audit lines, real receipts written
by ``change_receipt.write_receipt`` and real tar.gz backups.
"""

from __future__ import annotations

import io
import inspect
import json
import stat
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from exhelp import record_fields_display

import newton_mcp.change_receipt as cr
import newton_mcp.explanation as _explanation
import newton_mcp.undo as undo
import newton_mcp.undo_plan as undo_plan
from newton_mcp.plan import compute_plan_hash
from newton_mcp.policy import classify, parse_diff_line
from newton_mcp.server import Device
from newton_mcp.undo_plan import (
    UndoDraft,
    UndoRefused,
    draft_undo,
    mark_undo,
    record_after_hash,
    verify_plan_base,
)


SID = "fd595e20f2cd6c2b928fe3156f82d5db"
OTHER_SID = "1c595e20f2cd6c2b928fe3156f82d5db"
THIRD_SID = "2c595e20f2cd6c2b928fe3156f82d5db"
DEVICE = "quasar"
OTHER_DEVICE = "pulsar"
HOST = "192.0.2.1"
SECRET = "S3cr3tK3y!"

AGENT = {
    "intent": "Put the interface back the way the owner had it.",
    "risk": "A wrong value could break the network for the owner.",
}

STAMP_FIRST = "20261024T150000Z"
STAMP_LATER = "20261025T090000Z"

_COMPUTED = object()


def dev(profile="lab", mgmt_interface="lan", mgmt_zone="lan", wan_zones=("wan",)):
    """A lab device for the policy calls, in the shape the policy
    neighbour tests build (this module does not import test modules)."""
    return Device("quasar", "openwrt", "192.0.2.1", "root",
                  profile=profile, mgmt_interface=mgmt_interface,
                  mgmt_zone=mgmt_zone, wan_zones=wan_zones)


# --------------------------------------------------------------- the fixtures


class _Env:
    def __init__(self, root: Path, state: Path) -> None:
        self.root = root
        self.state = state


@pytest.fixture
def env(tmp_path, monkeypatch):
    state = tmp_path / "state"
    (state / "plans").mkdir(parents=True, mode=0o700)
    (state / "receipts" / "backups").mkdir(parents=True, mode=0o700)
    monkeypatch.setenv("OWRT_AUDIT_LOG", str(tmp_path / "audit.log"))
    monkeypatch.setenv("NEWTON_STATE_DIR", str(state))
    return _Env(tmp_path, state)


class _Clock:
    """A fixed clock for ``change_receipt.write_receipt``."""

    def __init__(self, moment: datetime) -> None:
        self._moment = moment

    def now(self, tz: Any = None) -> datetime:
        return self._moment


def _tarball(path: Path, configs: dict[str, str]) -> Path:
    """A backup tarball of /etc/config, exactly as the router makes one."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w:gz") as archive:
        for name, text in configs.items():
            data = text.encode("utf-8")
            info = tarfile.TarInfo(f"etc/config/{name}")
            info.size = len(data)
            info.mode = 0o600
            archive.addfile(info, io.BytesIO(data))
    return path


def _audit(root: Path, *lines: str) -> None:
    with (root / "audit.log").open("a", encoding="utf-8") as handle:
        for line in lines:
            handle.write(f"2026-10-24T15:01:00-04:00 root@192.0.2.1 {line}\n")


def _record(
    *,
    sid: str = SID,
    device: str = DEVICE,
    host: str = HOST,
    diff: str = "",
    backup_path: str = "",
    after_hash: dict[str, str] | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """A plan record with every hash-bound field the canonical identity needs."""
    record: dict[str, Any] = {
        "device": device,
        "host": host,
        "session_id": sid,
        "uci_batch": "",
        "diff": diff,
        "probes": [["fail"]],
        "timeout_s": 90,
        "base_hash": "8" * 64,
        "requires_approval": False,
        "router_digest": "3" * 64,
        "explanation": {
            "intent": "Make the requested change the owner asked for.",
            "steps": ["Change line 1 does part of the requested change."],
            "expect": [{"kind": "probe", "probe": ["iface-absent", "guestx"]}],
            "risk": "A wrong value could break the feature.",
        },
        "owner_confirmed_in_chat": True,
        **record_fields_display(),
        "created_at": "2026-10-24T15:00:00+00:00",
        "staged_at": "2026-10-24T15:00:00+00:00",
        "backup_path": backup_path,
    }
    if after_hash is not None:
        record["after_hash"] = after_hash
    record.update(extra)
    record["plan_hash"] = compute_plan_hash(record)
    return record


def _write_plan(env: _Env, record: dict[str, Any]) -> Path:
    path = env.state / "plans" / f"{record['session_id']}.json"
    path.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
    path.chmod(0o600)
    return path


def _write_receipt(
    env: _Env, record: dict[str, Any], outcome: str, stamp: str, monkeypatch
) -> Path:
    moment = datetime.strptime(stamp, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    monkeypatch.setattr(cr, "datetime", _Clock(moment))
    written = cr.write_receipt(env.state, record, outcome, "")
    assert written is not None
    return written


def _change(
    env: _Env,
    monkeypatch,
    *,
    sid: str = SID,
    device: str = DEVICE,
    host: str = HOST,
    diff: str = "",
    before: dict[str, str] | None = None,
    after: dict[str, str] | None = None,
    stamp: str = STAMP_FIRST,
    outcome: str = "confirmed",
    receipt_outcome: str | None = None,
    after_hash: Any = _COMPUTED,
    **extra: Any,
) -> tuple[dict[str, Any], Path]:
    """A finished change: a plan record, audit lines, a receipt and a backup copy.

    Returns the record and the path of the current backup (the config as it is
    right after the change).  ``after_hash`` defaults to the md5 of the config
    right after the change; pass None for a record that does not keep one.
    """
    before = before or {}
    after = after or {}
    backup = env.root / "backups" / f"{sid}.tar.gz"
    _tarball(backup, before)
    if after_hash is _COMPUTED:
        after_hash = {
            name: undo.md5_hex(text.encode("utf-8")) for name, text in after.items()
        }
    extra.setdefault("base_hash", undo.config_base_hash(backup))
    record = _record(
        sid=sid,
        device=device,
        host=host,
        diff=diff,
        backup_path=str(backup),
        after_hash=after_hash,
        **extra,
    )
    _write_plan(env, record)
    if outcome == "confirmed":
        _audit(
            env.root,
            f"APPLIED session={sid} rollback=90s",
            f"CONFIRMED session={sid} (3 consecutive passes)",
        )
    elif outcome == "rolled_back":
        _audit(
            env.root,
            f"APPLIED session={sid} rollback=90s",
            f"ROLLBACK WINDOW PASSED session={sid} - router reachable; rolled back by rpcd",
        )
    else:
        _audit(
            env.root,
            f"APPLIED session={sid} rollback=90s",
            f"ALERT session={sid} status=confirmed after the rollback window",
        )
    _write_receipt(env, record, receipt_outcome or outcome, stamp, monkeypatch)
    current = env.root / "current" / f"{sid}.tar.gz"
    _tarball(current, after)
    return record, current


NET_BEFORE = "config interface 'lan'\n\toption proto 'static'\n\toption ipaddr '10.0.0.1'\n"
NET_AFTER = "config interface 'lan'\n\toption proto 'static'\n\toption ipaddr '10.0.0.2'\n"

def _package_of(line: str) -> str:
    """The package one batch line is about."""
    verb, _, rest = line.partition(" ")
    if verb == "add":
        return rest.split(" ", 1)[0]
    return rest.split(".", 1)[0]


def _backup_values(tarball: Path, package: str) -> dict[tuple[str, str, str], str | tuple[str, ...]]:
    """The option values in one member of a current backup."""
    with tarfile.open(tarball, "r:gz") as archive:
        member = archive.extractfile(f"etc/config/{package}")
        assert member is not None
        text = member.read().decode("utf-8")
    return {
        (package, section.name, option): value
        for section in undo.parse_uci_config(text)
        if section.name is not None
        for option, value in section.options
    }


SCENARIOS: list[dict[str, Any]] = [
    {
        "name": "option set",
        "packages": ("network",),
        "before": {"network": NET_BEFORE},
        "after": {"network": NET_AFTER},
        "diff": "network.lan.ipaddr='10.0.0.2'",
        "expected": ["set network.lan.ipaddr='10.0.0.1'"],
    },
    {
        "name": "option added",
        "packages": ("network",),
        "before": {"network": "config interface 'lan'\n\toption proto 'static'\n"},
        "after": {"network": NET_AFTER},
        "diff": "network.lan.ipaddr='10.0.0.2'",
        "expected": ["delete network.lan.ipaddr"],
    },
    {
        "name": "option removed",
        "packages": ("network",),
        "before": {"network": NET_BEFORE},
        "after": {"network": "config interface 'lan'\n\toption proto 'static'\n"},
        "diff": "-network.lan.ipaddr",
        "expected": ["set network.lan.ipaddr='10.0.0.1'"],
    },
    {
        "name": "list value added",
        "packages": ("firewall",),
        "before": {"firewall": "config zone 'lan'\n\toption name 'lan'\n\tlist network 'lan'\n"},
        "after": {"firewall": "config zone 'lan'\n\toption name 'lan'\n\tlist network 'lan'\n\tlist network 'guest'\n"},
        "diff": "firewall.lan.network+='guest'",
        "expected": [
            "delete firewall.lan.network",
            "add_list firewall.lan.network='lan'",
        ],
    },
    {
        "name": "list value removed",
        "packages": ("firewall",),
        "before": {"firewall": "config zone 'lan'\n\toption name 'lan'\n\tlist network 'lan'\n\tlist network 'guest'\n"},
        "after": {"firewall": "config zone 'lan'\n\toption name 'lan'\n\tlist network 'lan'\n"},
        "diff": "-firewall.lan.network='guest'",
        "expected": [
            "delete firewall.lan.network",
            "add_list firewall.lan.network='lan'",
            "add_list firewall.lan.network='guest'",
        ],
    },
    {
        "name": "named section added",
        "packages": ("network",),
        "before": {"network": "config interface 'lan'\n\toption proto 'static'\n"},
        "after": {
            "network": "config interface 'lan'\n\toption proto 'static'\n"
            "config interface 'guest'\n\toption proto 'dhcp'\n"
        },
        "diff": "network.guest=interface",
        "expected": ["delete network.guest"],
    },
    {
        "name": "named section removed",
        "packages": ("network",),
        "before": {
            "network": "config interface 'lan'\n\toption proto 'static'\n"
            "config interface 'guest'\n\toption proto 'dhcp'\n"
        },
        "after": {"network": "config interface 'lan'\n\toption proto 'static'\n"},
        "diff": "-network.guest",
        "expected": [
            "set network.guest=interface",
            "set network.guest.proto='dhcp'",
        ],
    },
    {
        "name": "anonymous section added",
        "packages": ("firewall",),
        "before": {"firewall": "config defaults 'defaults'\n\toption input 'ACCEPT'\n"},
        "after": {
            "firewall": "config defaults 'defaults'\n\toption input 'ACCEPT'\n"
            "config rule\n\toption src 'wan'\n"
        },
        "diff": "firewall.cfg0a1b2c.dest_port='8443'",
        "expected": ["delete firewall.@rule[0]"],
    },
    {
        "name": "anonymous section removed from the middle",
        "packages": ("firewall",),
        "before": {
            "firewall": "config rule\n\toption src 'wan'\n"
            "config rule\n\toption src 'guest'\n"
            "config interface 'lan'\n\toption proto 'static'\n"
        },
        "after": {
            "firewall": "config rule\n\toption src 'wan'\n"
            "config interface 'lan'\n\toption proto 'static'\n"
        },
        "diff": "-firewall.cfg0a1b2c.src='guest'",
        "expected": [
            "add firewall rule",
            "set firewall.@rule[-1].src='guest'",
            "reorder firewall.@rule[1]=1",
        ],
    },
    {
        "name": "section renamed",
        "packages": ("network",),
        "before": {"network": "config interface 'old'\n\toption proto 'static'\n"},
        "after": {"network": "config interface 'new'\n\toption proto 'static'\n"},
        "diff": "-network.old\nnetwork.new=interface",
        "expected": [
            "delete network.new",
            "set network.old=interface",
            "set network.old.proto='static'",
        ],
    },
    {
        "name": "two packages in one change",
        "packages": ("dhcp", "network"),
        "before": {
            "network": NET_BEFORE,
            "dhcp": "config dhcp 'lan'\n\toption ignore '0'\n",
        },
        "after": {
            "network": NET_AFTER,
            "dhcp": "config dhcp 'lan'\n\toption ignore '1'\n",
        },
        "diff": "network.lan.ipaddr='10.0.0.2'\ndhcp.lan.ignore='1'",
        "expected": [
            "set dhcp.lan.ignore='0'",
            "set network.lan.ipaddr='10.0.0.1'",
        ],
    },
]


# ------------------------------------------------------------------- UN-01


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s["name"] for s in SCENARIOS])
def test_un01_every_shape_of_change_undoes_to_the_state_before_it(
    env, monkeypatch, scenario
):
    _record_out, current = _change(
        env,
        monkeypatch,
        diff=scenario["diff"],
        before=scenario["before"],
        after=scenario["after"],
    )
    draft = draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)

    assert draft.change_id == SID
    assert draft.packages == tuple(scenario["packages"])
    assert draft.batch == "".join(f"{line}\n" for line in scenario["expected"])
    assert draft.not_undone == (
        "packages",
        "passwords",
        "reboots",
        "client state such as leases and Wi-Fi associations",
    )
    assert draft.current_md5 == {
        name: undo.md5_hex(text.encode("utf-8"))
        for name, text in scenario["after"].items()
    }

    # the batch is proved: it turns the current config back into the backup
    for pkg in scenario["packages"]:
        after = undo.parse_uci_config(scenario["after"][pkg])
        before = undo.parse_uci_config(scenario["before"][pkg])
        lines = [
            line
            for line in draft.batch.splitlines()
            if _package_of(line) == pkg
        ]
        assert undo.apply_batch(pkg, after, lines) == before


def test_un01_the_first_two_shapes_have_the_expected_lines_exactly(env, monkeypatch):
    _record_out, current = _change(
        env,
        monkeypatch,
        diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE},
        after={"network": NET_AFTER},
    )
    draft = draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert draft.batch == "set network.lan.ipaddr='10.0.0.1'\n"

    _record_out, current = _change(
        env,
        monkeypatch,
        sid=OTHER_SID,
        stamp=STAMP_LATER,
        diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": "config interface 'lan'\n\toption proto 'static'\n"},
        after={"network": NET_AFTER},
    )
    draft = draft_undo(env.state, DEVICE, HOST, OTHER_SID, current, AGENT)
    assert draft.batch == "delete network.lan.ipaddr\n"


def test_un01_draft_carries_values_for_named_sections_only(env, monkeypatch):
    before = {
        "dhcp": (
            "config dhcp 'lan'\n"
            "\toption ignore '0'\n"
            "config host\n"
            "\toption name 'old'\n"
        )
    }
    after = {
        "dhcp": (
            "config dhcp 'lan'\n"
            "\toption ignore '0'\n"
            "\toption dhcp_option '6,192.0.2.1'\n"
            "config host\n"
            "\toption name 'old'\n"
            "\toption tag 'plain'\n"
        )
    }
    _record_out, current = _change(
        env,
        monkeypatch,
        diff="dhcp.lan.dhcp_option='6,192.0.2.1'\ndhcp.@host[0].tag='plain'",
        before=before,
        after=after,
    )

    draft = draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)

    assert draft.deleted_values[("dhcp", "lan", "dhcp_option")] == "6,192.0.2.1"
    assert ("dhcp", "@host[0]", "tag") not in draft.deleted_values
    # the undo deletes 'dhcp_option' only, so no other option keeps a value
    assert ("dhcp", "lan", "ignore") not in draft.deleted_values


def test_un01_a_value_of_an_option_the_batch_does_not_delete_is_absent(env, monkeypatch):
    """The draft carries a committed value only for an option the undo deletes.

    The value of an option the inverse batch leaves alone says nothing about
    the undo, so the policy must not read it.
    """
    before = {"dhcp": "config dhcp 'lan'\n\toption ignore '0'\n"}
    after = {
        "dhcp": (
            "config dhcp 'lan'\n"
            "\toption ignore '0'\n"
            "\toption dhcp_option '6,192.0.2.1'\n"
        )
    }
    _record_out, current = _change(
        env,
        monkeypatch,
        diff="dhcp.lan.dhcp_option='6,192.0.2.1'",
        before=before,
        after=after,
    )

    draft = draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)

    assert draft.batch == "delete dhcp.lan.dhcp_option\n"
    assert draft.deleted_values[("dhcp", "lan", "dhcp_option")] == "6,192.0.2.1"
    assert ("dhcp", "lan", "ignore") not in draft.deleted_values


def test_un01_draft_carries_anonymous_set_value_from_the_change_diff(env, monkeypatch):
    before = {"system": "config system\n\toption hostname 'p'\n"}
    after = {
        "system": (
            "config system\n"
            "\toption hostname 'p'\n"
            "\toption description 'dialog test'\n"
        )
    }
    _record_out, current = _change(
        env,
        monkeypatch,
        diff="system.cfg01e48a.description='dialog test'",
        before=before,
        after=after,
    )

    draft = draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)

    deleted_values = draft.deleted_values
    assert deleted_values[("system", "cfg01e48a", "description")] == "dialog test"
    assert classify(
        dev(),
        "",
        "-system.cfg01e48a.description",
        deleted_values=deleted_values,
    ) == {"requires_approval": False, "risk": "low", "reasons": []}


def test_un01_an_anonymous_path_value_from_the_change_diff_stays_critical(
    env, monkeypatch
):
    before = {"system": "config system\n\toption hostname 'p'\n"}
    after = {
        "system": (
            "config system\n"
            "\toption hostname 'p'\n"
            "\toption description 'a/b'\n"
        )
    }
    _record_out, current = _change(
        env,
        monkeypatch,
        diff="system.cfg01e48a.description='a/b'",
        before=before,
        after=after,
    )

    draft = draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)

    result = classify(
        dev(),
        "",
        "-system.cfg01e48a.description",
        deleted_values=draft.deleted_values,
    )
    assert result["risk"] == "critical"
    assert any(reason.startswith("path-option:") for reason in result["reasons"])


def test_un01_an_anonymous_value_set_then_deleted_in_the_change_diff_is_absent(
    env, monkeypatch
):
    record = _record(
        diff=(
            "system.cfg01e48a.description='dialog test'\n"
            "-system.cfg01e48a.description"
        )
    )

    assert ("system", "cfg01e48a", "description") not in undo_plan._set_values_from_diff(record)


def test_un01_an_anonymous_value_set_twice_in_the_change_diff_is_absent(
    env, monkeypatch
):
    record = _record(
        diff=(
            "system.cfg01e48a.x='/etc/x.conf'\n"
            "system.cfg01e48a.x='6,192.0.2.1'"
        )
    )
    current = {"system": b"config system\n\toption x '6,192.0.2.1'\n"}

    deleted_values = undo_plan._deleted_values(
        ["system"], current, record, ["delete system.@system[0].x"]
    )

    assert ("system", "cfg01e48a", "x") not in deleted_values


def test_un01_an_option_set_twice_in_the_change_diff_is_poisoned(env, monkeypatch):
    record = _record(
        diff=(
            "system.cfg01e48a.x='/etc/x.conf'\n"
            "system.cfg01e48a.x='6,192.0.2.1'"
        )
    )

    # a second plain set of the same option is ambiguous: the option may
    # hold a list, so it is poisoned rather than given the last value
    assert ("system", "cfg01e48a", "x") not in undo_plan._set_values_from_diff(record)


@pytest.mark.parametrize("value", ["<masked>", "<redacted:abc123>"])
def test_un01_a_masked_value_in_the_change_diff_is_not_a_value(env, monkeypatch, value):
    """The recorded diff is the masked diff: a placeholder is not a value.

    The masker turns the value of a secret-named option into ``<masked>``
    (or ``<masked: ...>`` / ``<redacted:...>``).  Reading the placeholder as
    the committed value would tell the policy that the option held a
    harmless string, so a set that carries one poisons the key instead.
    """
    record = _record(diff=f"wireless.cfg033579.key='{value}'")

    assert ("wireless", "cfg033579", "key") not in undo_plan._set_values_from_diff(record)


def test_un01_a_masked_value_leaves_the_policy_fail_safe(env, monkeypatch):
    """The committed value of a masked option is unknown, so the policy
    still asks for approval when the undo deletes that option."""
    before = {"wireless": "config wifi-iface\n\toption mode 'ap'\n"}
    after = {
        "wireless": (
            "config wifi-iface\n"
            "\toption mode 'ap'\n"
            "\toption key 'not-a-real-key'\n"
        )
    }
    _record_out, current = _change(
        env,
        monkeypatch,
        diff="wireless.cfg033579.key='<masked>'",
        before=before,
        after=after,
    )

    draft = draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)

    assert ("wireless", "cfg033579", "key") not in draft.deleted_values
    result = classify(
        dev(),
        "",
        "-wireless.cfg033579.key",
        deleted_values=draft.deleted_values,
    )
    assert result["risk"] == "critical"
    assert any(reason.startswith("path-option:") for reason in result["reasons"]), result


@pytest.mark.parametrize(
    "value",
    [
        "<masked: /etc/x>",
        "user:<masked>",
        "***",
        "<REDACTED:abc123>",
    ],
    ids=["masked-path", "embedded-masked", "bare-stars", "uppercase-redacted"],
)
def test_un01_every_placeholder_form_in_a_diff_leaves_the_policy_fail_safe(
    env, monkeypatch, value
):
    """A placeholder can be embedded anywhere in a value and is never a value."""
    record = _record(diff=f"wireless.cfg033579.key='{value}'")
    current = {"wireless": b"config wifi_iface\n\toption mode 'ap'\n"}

    deleted_values = undo_plan._deleted_values(
        ["wireless"], current, record, ["delete wireless.@wifi_iface[0].key"]
    )

    assert ("wireless", "cfg033579", "key") not in deleted_values
    result = classify(
        dev(),
        "",
        "-wireless.cfg033579.key",
        deleted_values=deleted_values,
    )
    assert result["risk"] == "critical"
    assert any(reason.startswith("path-option:") for reason in result["reasons"]), result


def test_un01_a_masked_named_backup_value_is_not_a_value(env, monkeypatch):
    """The current backup can carry a placeholder too; its key is dropped."""
    record = _record(diff="")
    current = {
        "system": b"config system 'main'\n\toption description '<MASKED>'\n"
    }

    deleted_values = undo_plan._deleted_values(
        ["system"], current, record, ["delete system.main.description"]
    )

    assert ("system", "main", "description") not in deleted_values


def test_un01_a_masked_named_backup_poisons_a_raw_diff_value(env, monkeypatch):
    """An unknown current backup value cannot be replaced by the diff."""
    record = _record(diff="system.main.description='plain'")
    current = {
        "system": b"config system 'main'\n\toption description '<MASKED>'\n"
    }

    deleted_values = undo_plan._deleted_values(
        ["system"], current, record, ["delete system.main.description"]
    )

    assert ("system", "main", "description") not in deleted_values
    result = classify(
        dev(),
        "",
        "-system.main.description",
        deleted_values=deleted_values,
    )
    assert result["risk"] == "critical"
    assert any(reason.startswith("path-option:") for reason in result["reasons"]), result


def test_un01_a_masked_item_in_a_backup_list_is_not_a_value(env, monkeypatch):
    """One unknown item makes the whole committed list unknown."""
    record = _record(diff="")
    current = {
        "system": (
            b"config system 'main'\n"
            b"\tlist description '<masked>'\n"
            b"\tlist description 'plain'\n"
        )
    }

    deleted_values = undo_plan._deleted_values(
        ["system"], current, record, ["delete system.main.description"]
    )

    assert ("system", "main", "description") not in deleted_values


@pytest.mark.parametrize("backup_value", ["plain", "/etc/x"], ids=["plain", "path"])
def test_un01_a_raw_named_backup_value_wins_over_a_masked_diff(
    env, monkeypatch, backup_value
):
    """For a named section, the current backup is the committed value."""
    record = _record(diff="system.main.description='<masked>'")
    current = {
        "system": f"config system 'main'\n\toption description '{backup_value}'\n".encode()
    }

    deleted_values = undo_plan._deleted_values(
        ["system"], current, record, ["delete system.main.description"]
    )

    assert deleted_values[("system", "main", "description")] == backup_value
    result = classify(
        dev(),
        "",
        "-system.main.description",
        deleted_values=deleted_values,
    )
    if backup_value == "plain":
        assert result == {"requires_approval": False, "risk": "low", "reasons": []}
    else:
        assert result["risk"] == "critical"
        assert any(reason.startswith("path-option:") for reason in result["reasons"]), result


@pytest.mark.parametrize(
    "line,expected_op",
    [
        ("firewall.cfg0e92bd=rule", ""),
        ("-firewall.cfg0592bd", "-"),
        ("^firewall.cfg03dc81='0'", "^"),
        ("@firewall.cfg07ac31='newname'", "@"),
        ("@firewall.cfg07ac31.oldopt='newopt'", "@"),
    ],
    ids=[
        "section add",
        "section delete",
        "reorder",
        "rename",
        "option rename",
    ],
)
def test_un01_a_section_change_in_the_change_diff_poisons_the_whole_config(
    env, monkeypatch, line, expected_op
):
    """uci's anonymous ids are positional, so a diff that moved a section
    says nothing about the ids of the file after the change.

    The record's diff names the sections of the file before the change and
    the undo's diff names them after it; the two agree only when the change
    added, deleted, renamed or reordered no section of that config.  A diff
    that did any of those (a line with no option: a section add or delete, or
    a rename ``@`` / reorder ``^`` line) therefore keeps no diff-derived value
    for ANY key of that config.
    """
    parsed = parse_diff_line(line)
    assert parsed is not None and parsed.parsed
    assert parsed.op == expected_op

    record = _record(diff=f"firewall.cfg02dc81.opt='A'\n{line}")

    assert ("firewall", "cfg02dc81", "opt") not in undo_plan._set_values_from_diff(record)


def test_un01_a_section_change_in_one_config_leaves_the_other_config_alone(
    env, monkeypatch
):
    record = _record(
        diff="system.cfg01e48a.description='x'\nfirewall.cfg0e92bd=rule"
    )

    values = undo_plan._set_values_from_diff(record)

    assert values[("system", "cfg01e48a", "description")] == "x"
    assert not any(key[0] == "firewall" for key in values)


def test_un01_an_anonymous_list_add_in_the_change_diff_is_absent(env, monkeypatch):
    record = _record(diff="system.cfg01e48a.x+='y'")

    assert ("system", "cfg01e48a", "x") not in undo_plan._set_values_from_diff(record)


def test_un01_an_unparseable_change_diff_has_no_anonymous_values(env, monkeypatch):
    record = _record(diff="system.cfg01e48a.description='dialog test'\nnot a diff line")
    current = {"dhcp": b"config dhcp 'lan'\n\toption ignore '1'\n"}

    deleted_values = undo_plan._deleted_values(
        ["dhcp"], current, record, ["delete dhcp.lan.ignore"]
    )

    assert ("system", "cfg01e48a", "description") not in deleted_values
    assert deleted_values[("dhcp", "lan", "ignore")] == "1"


def test_un01_diff_value_mismatching_named_section_value_keeps_the_backup_value(
    env, monkeypatch
):
    """The backup holds the value the router has now, so it wins.

    The change diff says one thing about the option and the backup another;
    the committed value is the backup's, so that is the value the policy
    reads.
    """
    record = _record(diff="system.main.description='diff value'")
    current = {
        "system": (
            b"config system 'main'\n"
            b"\toption hostname 'p'\n"
            b"\toption description 'actual value'\n"
        )
    }

    deleted_values = undo_plan._deleted_values(
        ["system"], current, record, ["delete system.main.description"]
    )

    assert deleted_values[("system", "main", "description")] == "actual value"


def test_un01_deleted_values_requires_the_batch_lines() -> None:
    """The batch is not optional: without it every option would look deleted."""
    parameter = inspect.signature(undo_plan._deleted_values).parameters["lines"]

    assert parameter.default is inspect.Parameter.empty


@pytest.mark.parametrize(
    "line,expected",
    [
        ("delete system.main.option_name", {("system", "option_name")}),
        ("delete system.@system[0].x", {("system", "x")}),
        ("delete system.@system[1000].x", {("system", "x")}),
        ("delete system.@system[-1].x", {("system", "x")}),
        ("delete system.@wifi-iface[0].x", {("system", "x")}),
        ("delete system.wifi_iface.option_name", {("system", "option_name")}),
        ("delete system.cfgx", set()),
        ("set system.main.x='v'", set()),
        ("not a batch line", set()),
    ],
    ids=[
        "named",
        "anonymous",
        "four-digit-index",
        "negative-index",
        "type-with-hyphen",
        "option-underscore",
        "whole-section",
        "set",
        "garbage",
    ],
)
def test_un01_deleted_options_uses_the_shared_uci_grammar(line: str, expected: set[tuple[str, str]]) -> None:
    assert undo_plan._deleted_options([line]) == expected


def test_un01_two_anonymous_sections_are_judged_separately(env, monkeypatch):
    """The undo deletes only the first option, not every option of its config."""
    before = {
        "system": (
            "config system\n"
            "\toption hostname 'p'\n"
            "config system\n"
            "\toption description '/etc/b'\n"
        )
    }
    after = {
        "system": (
            "config system\n"
            "\toption hostname 'p'\n"
            "\toption description 'a'\n"
            "config system\n"
            "\toption description '/etc/b'\n"
        )
    }
    _record_out, current = _change(
        env,
        monkeypatch,
        diff="system.cfg01e48a.description='a'",
        before=before,
        after=after,
    )

    draft = draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)

    assert draft.deleted_values[("system", "cfg01e48a", "description")] == "a"
    assert classify(
        dev(),
        "",
        "-system.cfg01e48a.description",
        deleted_values=draft.deleted_values,
    ) == {"requires_approval": False, "risk": "low", "reasons": []}
    result = classify(
        dev(),
        "",
        "-system.cfg02e48a.description",
        deleted_values=draft.deleted_values,
    )
    assert result["risk"] == "critical"
    assert any(reason.startswith("path-option:") for reason in result["reasons"]), result


def test_un01_a_positional_anonymous_diff_key_fails_safe(env, monkeypatch):
    """A draft's cfg id cannot answer for a positional diff key."""
    deleted_values = {("system", "cfg01e48a", "description"): "plain"}

    result = classify(
        dev(),
        "",
        "-system.@system[0].description",
        deleted_values=deleted_values,
    )

    assert result["risk"] == "critical"
    assert any(reason.startswith("path-option:") for reason in result["reasons"]), result


def test_un01_every_named_deleted_value_comes_from_the_current_backup(
    env, monkeypatch
):
    before = {"dhcp": "config dhcp 'lan'\n\toption ignore '0'\n"}
    after = {
        "dhcp": (
            "config dhcp 'lan'\n"
            "\toption ignore '0'\n"
            "\tlist dhcp_option '/etc/x.conf'\n"
            "\tlist dhcp_option '6,192.0.2.1'\n"
        )
    }
    _record_out, current = _change(
        env,
        monkeypatch,
        diff=(
            "dhcp.lan.dhcp_option='/etc/x.conf'\n"
            "dhcp.lan.dhcp_option='6,192.0.2.1'"
        ),
        before=before,
        after=after,
    )

    draft = draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    backup_values = _backup_values(current, "dhcp")

    assert draft.deleted_values
    for key, value in draft.deleted_values.items():
        assert value == backup_values[key]


def test_un01_a_list_option_keeps_every_value_for_the_undo(env, monkeypatch):
    """A list option holds several values, so the draft carries them
    all, and a committed value that is a path fails safe.

    The diff sets the option twice, which may be a list: it gives no single
    value, so the committed values come from the current backup."""
    before = {
        "dhcp": (
            "config dhcp 'lan'\n"
            "\toption ignore '0'\n"
        )
    }
    after = {
        "dhcp": (
            "config dhcp 'lan'\n"
            "\toption ignore '0'\n"
            "\tlist dhcp_option '/etc/x.conf'\n"
            "\tlist dhcp_option '6,192.0.2.1'\n"
        )
    }
    _record_out, current = _change(
        env,
        monkeypatch,
        diff=(
            "dhcp.lan.dhcp_option='/etc/x.conf'\n"
            "dhcp.lan.dhcp_option='6,192.0.2.1'"
        ),
        before=before,
        after=after,
    )

    draft = draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)

    deleted_values = draft.deleted_values
    assert deleted_values[("dhcp", "lan", "dhcp_option")] == (
        "/etc/x.conf",
        "6,192.0.2.1",
    )

    # the committed values of the deleted option are what the policy
    # reads: one of them holds a path, so the undo needs approval
    result = classify(
        dev(),
        "",
        "-dhcp.lan.dhcp_option",
        deleted_values=deleted_values,
    )
    assert result["risk"] == "critical"
    assert any(reason.startswith("path-option:") for reason in result["reasons"]), \
        result


# ------------------------------------------------------------------- UN-02


def test_un02_a_later_edit_of_a_touched_package_refuses_with_the_package_named(
    env, monkeypatch
):
    _record_out, _current = _change(
        env,
        monkeypatch,
        diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE},
        after={"network": NET_AFTER},
    )
    edited = _tarball(
        env.root / "edited.tar.gz",
        {"network": "config interface 'lan'\n\toption proto 'static'\n\toption ipaddr '10.0.0.9'\n"},
    )
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, DEVICE, HOST, SID, edited, AGENT)
    message = str(excinfo.value)
    assert "network" in message
    assert "changed since this change" in message


def test_un02_only_the_edited_package_is_named(env, monkeypatch):
    _record_out, _current = _change(
        env,
        monkeypatch,
        diff="network.lan.ipaddr='10.0.0.2'\ndhcp.lan.ignore='1'",
        before={
            "network": NET_BEFORE,
            "dhcp": "config dhcp 'lan'\n\toption ignore '0'\n",
        },
        after={
            "network": NET_AFTER,
            "dhcp": "config dhcp 'lan'\n\toption ignore '1'\n",
        },
    )
    edited = _tarball(
        env.root / "edited.tar.gz",
        {
            "network": NET_AFTER,
            "dhcp": "config dhcp 'lan'\n\toption ignore '9'\n",
        },
    )
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, DEVICE, HOST, SID, edited, AGENT)
    message = str(excinfo.value)
    assert "dhcp" in message
    assert "network" not in message
    assert "1 conflict(s)" in message


def test_un02_a_later_change_on_the_same_package_refuses_even_when_the_file_is_unchanged(
    env, monkeypatch
):
    _record_out, current = _change(
        env,
        monkeypatch,
        diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE},
        after={"network": NET_AFTER},
    )
    _later, _later_current = _change(
        env,
        monkeypatch,
        sid=OTHER_SID,
        stamp=STAMP_LATER,
        diff="network.lan.ipaddr='10.0.0.3'",
        before={"network": NET_AFTER},
        after={
            "network": "config interface 'lan'\n\toption proto 'static'\n\toption ipaddr '10.0.0.3'\n"
        },
    )
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    message = str(excinfo.value)
    assert "also changed by later change" in message
    assert OTHER_SID[:8] in message
    assert "network" in message


def test_un02_a_later_change_on_another_device_does_not_refuse(env, monkeypatch):
    _record_out, current = _change(
        env,
        monkeypatch,
        diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE},
        after={"network": NET_AFTER},
    )
    _later, _later_current = _change(
        env,
        monkeypatch,
        sid=OTHER_SID,
        device=OTHER_DEVICE,
        stamp=STAMP_LATER,
        diff="network.lan.ipaddr='10.0.0.3'",
        before={"network": NET_AFTER},
        after={
            "network": "config interface 'lan'\n\toption proto 'static'\n\toption ipaddr '10.0.0.3'\n"
        },
    )
    draft = draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert draft.batch == "set network.lan.ipaddr='10.0.0.1'\n"


def test_un02_a_later_change_on_another_package_does_not_refuse(env, monkeypatch):
    _record_out, current = _change(
        env,
        monkeypatch,
        diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE},
        after={"network": NET_AFTER},
    )
    _later, _later_current = _change(
        env,
        monkeypatch,
        sid=OTHER_SID,
        stamp=STAMP_LATER,
        diff="dhcp.lan.ignore='1'",
        before={"dhcp": "config dhcp 'lan'\n\toption ignore '0'\n"},
        after={"dhcp": "config dhcp 'lan'\n\toption ignore '1'\n"},
    )
    draft = draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert draft.batch == "set network.lan.ipaddr='10.0.0.1'\n"


# ------------------------------------------------------------------- UN-03


def test_un03_an_edit_to_a_package_the_change_did_not_touch_changes_nothing(
    env, monkeypatch
):
    _record_out, _current = _change(
        env,
        monkeypatch,
        diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE},
        after={"network": NET_AFTER},
    )
    current = _tarball(
        env.root / "current-extra.tar.gz",
        {
            "network": NET_AFTER,
            "dhcp": "config dhcp 'lan'\n\toption ignore '1'\n",
        },
    )
    draft = draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert draft.packages == ("network",)
    assert draft.batch == "set network.lan.ipaddr='10.0.0.1'\n"
    assert "dhcp" not in draft.current_md5


# ------------------------------------------------------------------- UN-04


def test_un04_a_bad_change_id_is_refused(env, monkeypatch):
    _record_out, current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
    )
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, DEVICE, HOST, "not-a-session-id", current, AGENT)
    assert "session id" in str(excinfo.value)


def test_un04_no_plan_record_is_refused(env, monkeypatch):
    _record_out, current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
    )
    (env.state / "plans" / f"{SID}.json").unlink()
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert "no verified plan record" in str(excinfo.value)


def test_un04_a_record_of_another_device_is_refused(env, monkeypatch):
    _record_out, current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
    )
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, OTHER_DEVICE, HOST, SID, current, AGENT)
    assert "no verified plan record" in str(excinfo.value)


def test_un04_a_record_of_another_host_is_refused(env, monkeypatch):
    _record_out, current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
    )
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, DEVICE, "192.0.2.9", SID, current, AGENT)
    assert "no verified plan record" in str(excinfo.value)


def test_un04_a_tampered_plan_hash_is_refused(env, monkeypatch):
    _record_out, current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
    )
    path = env.state / "plans" / f"{SID}.json"
    record = json.loads(path.read_text())
    record["diff"] = "network.lan.ipaddr='10.0.0.9'"
    path.write_text(json.dumps(record, sort_keys=True))
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert "no verified plan record" in str(excinfo.value)


def test_un04_a_rolled_back_change_cannot_be_undone(env, monkeypatch):
    _record_out, current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
        outcome="rolled_back",
    )
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert "only a change that ended CONFIRMED" in str(excinfo.value)
    assert "ROLLED BACK" in str(excinfo.value)


def test_un04_an_unknown_change_cannot_be_undone(env, monkeypatch):
    _record_out, current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
        outcome="unknown",
    )
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert "only a change that ended CONFIRMED" in str(excinfo.value)
    assert "UNKNOWN" in str(excinfo.value)


def test_un04_no_audit_lines_is_refused(env, monkeypatch):
    _record_out, current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
    )
    (env.root / "audit.log").write_text("", encoding="utf-8")
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert "no audit lines" in str(excinfo.value)


def test_un04_no_receipt_is_refused(env, monkeypatch):
    _record_out, current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
    )
    for path in (env.state / "receipts").glob("*.md"):
        path.unlink()
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert "receipt" in str(excinfo.value)


def test_un04_two_receipts_are_refused(env, monkeypatch):
    _record_out, current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
    )
    record = json.loads((env.state / "plans" / f"{SID}.json").read_text())
    _write_receipt(env, record, "confirmed", STAMP_LATER, monkeypatch)
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert "more than one receipt" in str(excinfo.value)


def test_un04_a_receipt_that_does_not_say_confirmed_is_refused(env, monkeypatch):
    _record_out, current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
        receipt_outcome="unknown",
    )
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert "receipt" in str(excinfo.value)


def test_un04_a_missing_backup_copy_is_refused(env, monkeypatch):
    _record_out, current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
    )
    (env.state / "receipts" / "backups" / f"{SID}.tar.gz").unlink()
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert "backup copy" in str(excinfo.value)


def test_un04_a_tampered_backup_copy_is_refused(env, monkeypatch):
    _record_out, current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
    )
    copy = env.state / "receipts" / "backups" / f"{SID}.tar.gz"
    copy.write_bytes(b"not the backup any more")
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert "backup copy" in str(excinfo.value)


def test_un04_a_change_without_after_hash_is_refused(env, monkeypatch):
    _record_out, current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
        after_hash=None,
    )
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert "restore its backup by hand" in str(excinfo.value)


def test_un04_a_malformed_after_hash_is_refused(env, monkeypatch):
    _record_out, current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
        after_hash={"network": "not-an-md5"},
    )
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert "restore its backup by hand" in str(excinfo.value)


def test_un04_a_change_that_is_already_undone_is_refused(env, monkeypatch):
    _record_out, current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
    )
    _undo_record, _undo_current = _change(
        env,
        monkeypatch,
        sid=OTHER_SID,
        stamp=STAMP_LATER,
        diff="network.lan.ipaddr='10.0.0.1'",
        before={"network": NET_AFTER},
        after={"network": NET_BEFORE},
    )
    path = env.state / "plans" / f"{OTHER_SID}.json"
    record = json.loads(path.read_text())
    record["undo_of"] = SID
    path.write_text(json.dumps(record, sort_keys=True))
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert "already undone by change" in str(excinfo.value)
    assert OTHER_SID[:8] in str(excinfo.value)


def test_un04_an_unreadable_diff_line_is_refused(env, monkeypatch):
    _record_out, current = _change(
        env, monkeypatch,
        diff="network.lan.ipaddr='10.0.0.2'\nthis line is not a change",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
    )
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert "a line of the change cannot be read" in str(excinfo.value)


def test_un04_a_change_with_nothing_to_undo_is_refused(env, monkeypatch):
    _record_out, current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.1'",
        before={"network": NET_BEFORE}, after={"network": NET_BEFORE},
    )
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert "nothing to undo" in str(excinfo.value)


def test_un04_too_many_lines_to_undo_is_refused(env, monkeypatch):
    options = "".join(f"\toption o{index} 'v{index}'\n" for index in range(250))
    _record_out, current = _change(
        env,
        monkeypatch,
        diff="network.lan.o0='v0'",
        before={"network": "config interface 'lan'\n" + options},
        after={"network": "config interface 'lan'\n"},
    )
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert "too many changes to undo" in str(excinfo.value)


# ------------------------------------------------------------------- UN-05


def test_un05_only_intent_and_risk_are_accepted(env, monkeypatch):
    _record_out, current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
    )
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(
            env.state, DEVICE, HOST, SID, current,
            {**AGENT, "steps": ["a step the agent made up"]},
        )
    assert "intent and risk" in str(excinfo.value)


def test_un05_a_missing_key_is_refused(env, monkeypatch):
    _record_out, current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
    )
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, DEVICE, HOST, SID, current, {"intent": AGENT["intent"]})
    assert "risk" in str(excinfo.value)


def test_un05_a_wrong_type_is_refused(env, monkeypatch):
    _record_out, current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
    )
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, DEVICE, HOST, SID, current, {**AGENT, "risk": 7})
    assert "risk" in str(excinfo.value)


def test_un05_one_step_per_batch_line_and_valid_claims(env, monkeypatch):
    _record_out, current = _change(
        env,
        monkeypatch,
        diff="network.lan.ipaddr='10.0.0.2'\ndhcp.lan.ignore='1'",
        before={
            "network": NET_BEFORE,
            "dhcp": "config dhcp 'lan'\n\toption ignore '0'\n",
        },
        after={
            "network": NET_AFTER,
            "dhcp": "config dhcp 'lan'\n\toption ignore '1'\n",
        },
    )
    draft = draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    lines = draft.batch.splitlines()
    assert len(draft.explanation["steps"]) == len(lines)
    assert {"kind": "uci_equals", "path": "network.lan.ipaddr", "equals": "10.0.0.1"} in draft.explanation["expect"]
    assert {"kind": "uci_equals", "path": "dhcp.lan.ignore", "equals": "0"} in draft.explanation["expect"]
    # the stored explanation is valid for the same validator the plans use
    stored = _explanation.parse_explanation(draft.explanation, change_lines=len(lines))
    assert stored == draft.explanation


def test_un05_a_planted_secret_never_reaches_the_explanation(env, monkeypatch):
    before = {
        "network": "config interface 'lan'\n\toption ipaddr '10.0.0.1'\n"
        f"\toption key '{SECRET}'\n"
    }
    after = {
        "network": "config interface 'lan'\n\toption ipaddr '10.0.0.2'\n"
        "\toption key 'othervalue'\n"
    }
    _record_out, current = _change(
        env,
        monkeypatch,
        diff="network.lan.ipaddr='10.0.0.2'\nnetwork.lan.key='othervalue'",
        before=before,
        after=after,
    )
    draft = draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)

    # the batch itself has to carry the old value back
    assert SECRET in draft.batch
    # and nothing the owner reads may carry it
    assert SECRET not in " ".join(draft.explanation["steps"])
    assert SECRET not in json.dumps(draft.explanation["expect"])
    assert SECRET not in draft.explanation["intent"]
    assert SECRET not in draft.explanation["risk"]
    assert SECRET not in draft.not_undone[0]


def test_un05_a_planted_secret_in_an_option_name_refuses_without_it(env, monkeypatch):
    """The other reading of the same rule: the secret is the option's name."""
    before = {"network": f"config interface 'lan'\n\toption {SECRET} 'value'\n"}
    after = {"network": "config interface 'lan'\n"}
    _record_out, current = _change(
        env, monkeypatch, diff="-network.lan." + SECRET,
        before=before, after=after,
    )
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert SECRET not in str(excinfo.value)


def test_un05_a_value_with_a_quote_refuses_and_names_the_path_not_the_value(
    env, monkeypatch
):
    before = {"network": "config interface 'lan'\n\toption desc 'say \"hi\"'\n"}
    after = {"network": "config interface 'lan'\n\toption desc 'plain'\n"}
    _record_out, current = _change(
        env,
        monkeypatch,
        diff="network.lan.desc='plain'",
        before=before,
        after=after,
    )
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    message = str(excinfo.value)
    assert "network.lan.desc" in message
    assert "say" not in message
    assert "hi" not in message
    # a refusal names no file path
    assert "/" not in message


def test_un05_a_batch_with_no_usable_claim_falls_back_to_the_ping(env, monkeypatch):
    _record_out, current = _change(
        env,
        monkeypatch,
        diff="-network.lan.key",
        before={"network": f"config interface 'lan'\n\toption key '{SECRET}'\n"},
        after={"network": "config interface 'lan'\n"},
    )
    draft = draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert draft.explanation["expect"] == [
        {"kind": "probe", "probe": ["ping", "127.0.0.1"]}
    ]
    assert "No config value could be claimed" in draft.explanation["risk"]
    assert "Config only:" in draft.explanation["risk"]


def test_un05_an_intent_that_is_too_long_is_refused(env, monkeypatch):
    _record_out, current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
    )
    long_intent = "x" * 200
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(
            env.state, DEVICE, HOST, SID, current,
            {"intent": long_intent, "risk": AGENT["risk"]},
        )
    assert "intent is too long" in str(excinfo.value)
    assert "160" in str(excinfo.value)


def test_un05_the_risk_always_says_what_is_not_undone(env, monkeypatch):
    _record_out, current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
    )
    draft = draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert "Config only: packages, passwords, reboots and client leases are not undone." in (
        draft.explanation["risk"]
    )
    assert draft.explanation["intent"].startswith(f"Undo change {SID[:8]}: ")


# ------------------------------------------------------------------- UN-06


def test_un06_the_same_backups_verify(env, monkeypatch):
    _record_out, current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
    )
    draft = draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    # the backup the plan made of the router when it staged the undo
    plan_backup = _tarball(env.root / "stage.tar.gz", {"network": NET_AFTER})
    assert verify_plan_base(draft, plan_backup) is None


def test_un06_a_changed_md5_refuses(env, monkeypatch):
    _record_out, current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
    )
    draft = draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    other = _tarball(
        env.root / "other.tar.gz",
        {"network": "config interface 'lan'\n\toption proto 'static'\n\toption ipaddr '10.0.0.7'\n"},
    )
    with pytest.raises(UndoRefused) as excinfo:
        verify_plan_base(draft, other)
    assert "changed while the undo was being planned" in str(excinfo.value)


def test_un06_a_package_in_one_backup_only_refuses(env, monkeypatch):
    draft = UndoDraft(
        change_id=SID,
        packages=("network",),
        batch="set network.lan.ipaddr='10.0.0.1'\n",
        explanation={},
        current_md5={"network": "0" * 32},
        deleted_values={},
        not_undone=(),
    )
    only_in_the_plan = _tarball(
        env.root / "plan.tar.gz",
        {"network": "config interface 'lan'\n\toption ipaddr '10.0.0.1'\n"},
    )
    with pytest.raises(UndoRefused):
        verify_plan_base(draft, only_in_the_plan)
    only_in_the_current = _tarball(env.root / "current.tar.gz", {"dhcp": "config dhcp 'lan'\n"})
    with pytest.raises(UndoRefused):
        verify_plan_base(draft, only_in_the_current)


# ------------------------------------------------------------------- UN-07


def test_un07_mark_undo_sets_undo_of_and_keeps_the_hash_and_the_mode(env, monkeypatch):
    _record_out, _current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
    )
    undo_record = _record(sid=OTHER_SID, diff="network.lan.ipaddr='10.0.0.1'")
    path = _write_plan(env, undo_record)

    assert mark_undo(env.state, OTHER_SID, SID) is True

    stored = json.loads(path.read_text())
    assert stored["undo_of"] == SID
    # undo_of is not a hash field: the plan hash still verifies
    assert compute_plan_hash(stored) == undo_record["plan_hash"]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_un07_mark_undo_refuses_bad_ids(env, monkeypatch):
    with pytest.raises(UndoRefused):
        mark_undo(env.state, "nope", SID)
    with pytest.raises(UndoRefused):
        mark_undo(env.state, OTHER_SID, "nope")


def test_un07_mark_undo_without_a_record_is_false(env, monkeypatch):
    assert mark_undo(env.state, OTHER_SID, SID) is False


def test_un07_record_after_hash_stores_the_hashes_and_keeps_the_hash_valid(
    env, monkeypatch
):
    _record_out, _current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
    )
    path = env.state / "plans" / f"{SID}.json"
    before = json.loads(path.read_text())
    text = f"{'a' * 32} network\n{'b' * 32} dhcp\n"
    assert record_after_hash(env.state, SID, text) is True
    stored = json.loads(path.read_text())
    assert stored["after_hash"] == {"network": "a" * 32, "dhcp": "b" * 32}
    assert compute_plan_hash(stored) == before["plan_hash"]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


BAD_HASH_TEXTS = [
    ("a bad line", "not a hash line\n"),
    ("a duplicate name", f"{'a' * 32} network\n{'b' * 32} network\n"),
    ("no line at all", "\n\n"),
    ("an upper case hash", f"{'A' * 32} network\n"),
    ("too many lines", "".join(f"{'a' * 32} name{index}\n" for index in range(201))),
]


@pytest.mark.parametrize(
    ("name", "text"), BAD_HASH_TEXTS, ids=[name for name, _ in BAD_HASH_TEXTS]
)
def test_un07_a_bad_confighash_writes_nothing(env, monkeypatch, name, text):
    _record_out, _current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
    )
    path = env.state / "plans" / f"{SID}.json"
    before = path.read_bytes()
    assert record_after_hash(env.state, SID, text) is False
    assert path.read_bytes() == before


def test_un07_record_after_hash_without_a_record_is_false(env, monkeypatch):
    assert record_after_hash(env.state, OTHER_SID, f"{'a' * 32} network\n") is False


# ------------------------------------------------------------------- UN-08


def test_un08_the_outcome_is_re_derived_not_read_from_the_record(env, monkeypatch):
    _record_out, current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
        outcome="rolled_back",
    )
    path = env.state / "plans" / f"{SID}.json"
    record = json.loads(path.read_text())
    record["outcome"] = "confirmed"
    record["plan_hash"] = compute_plan_hash(record)
    path.write_text(json.dumps(record, sort_keys=True))

    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert "only a change that ended CONFIRMED" in str(excinfo.value)


def test_un08_a_stored_outcome_field_does_not_refuse_a_confirmed_change(
    env, monkeypatch
):
    _record_out, current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
    )
    path = env.state / "plans" / f"{SID}.json"
    record = json.loads(path.read_text())
    record["outcome"] = "rolled_back"
    record["plan_hash"] = compute_plan_hash(record)
    path.write_text(json.dumps(record, sort_keys=True))

    draft = draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert draft.batch == "set network.lan.ipaddr='10.0.0.1'\n"


def test_un08_the_md5_of_the_current_file_is_compared(env, monkeypatch):
    _record_out, _current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
    )
    path = env.state / "plans" / f"{SID}.json"
    record = json.loads(path.read_text())
    record["after_hash"] = {"network": "f" * 32}
    record["plan_hash"] = compute_plan_hash(record)
    path.write_text(json.dumps(record, sort_keys=True))
    edited = _tarball(env.root / "edited.tar.gz", {"network": NET_AFTER})

    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, DEVICE, HOST, SID, edited, AGENT)
    assert "changed since this change" in str(excinfo.value)


def test_un08_the_later_receipt_rule_exists(env, monkeypatch):
    _record_out, current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
    )
    _later, _later_current = _change(
        env,
        monkeypatch,
        sid=OTHER_SID,
        stamp=STAMP_LATER,
        diff="network.lan.ipaddr='10.0.0.3'",
        before={"network": NET_AFTER},
        after={
            "network": "config interface 'lan'\n\toption proto 'static'\n\toption ipaddr '10.0.0.3'\n"
        },
    )
    with pytest.raises(UndoRefused):
        draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)


def test_un08_the_planner_never_imports_the_server():
    """The server imports the planner, so the planner must not import the server."""
    source = (Path(undo_plan.__file__)).read_text(encoding="utf-8")
    assert "from .server" not in source
    assert "import server" not in source
    assert "from newton_mcp.server" not in source


def test_un08_a_later_change_with_an_unreadable_diff_counts_as_a_conflict(
    env, monkeypatch
):
    """A later diff that cannot be read could name any of the packages."""
    _record_out, current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
    )
    _later, _later_current = _change(
        env,
        monkeypatch,
        sid=OTHER_SID,
        stamp=STAMP_LATER,
        diff="network.lan.ipaddr='10.0.0.3'\nnot a change line",
        before={"network": NET_AFTER},
        after={
            "network": "config interface 'lan'\n\toption proto 'static'\n\toption ipaddr '10.0.0.3'\n"
        },
    )
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert "also changed by later change" in str(excinfo.value)


def test_un05_values_are_claimed_only_for_packages_without_secrets(env, monkeypatch):
    """a password under an option name outside the catalog must not reach the owner's text."""
    before = {"wireless": "config wifi-iface 'ap'\n\toption note 'hunter2'\n"}
    after = {"wireless": "config wifi-iface 'ap'\n\toption note 'other'\n"}
    _record_out, current = _change(
        env, monkeypatch, diff="wireless.ap.note='other'", before=before, after=after,
    )
    draft = draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert "hunter2" in draft.batch
    assert "hunter2" not in json.dumps(draft.explanation)
    assert all(c["kind"] != "uci_equals" for c in draft.explanation["expect"])


def test_un02_a_later_change_in_the_same_second_still_refuses(env, monkeypatch):
    """receipt stamps have one-second resolution; an equal stamp is not 'earlier'."""
    _record_out, current = _change(
        env,
        monkeypatch,
        diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE},
        after={"network": NET_AFTER},
    )
    _later, _later_current = _change(
        env,
        monkeypatch,
        sid=OTHER_SID,
        stamp=STAMP_FIRST,
        diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_AFTER},
        after={"network": NET_AFTER},
    )
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert "also changed by later change" in str(excinfo.value)


def test_un02_a_later_confirmed_change_without_a_plan_record_counts_as_a_conflict(env, monkeypatch):
    """an unreadable record says nothing about what the later change touched."""
    _record_out, current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
    )
    _change(
        env, monkeypatch, sid=OTHER_SID, stamp=STAMP_LATER, diff="dhcp.lan.ignore='1'",
        before={"dhcp": "config dhcp 'lan'\n"}, after={"dhcp": "config dhcp 'lan'\n\toption ignore '1'\n"},
    )
    (env.state / "plans" / f"{OTHER_SID}.json").unlink()
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert "also changed by later change" in str(excinfo.value)


def test_un05_a_partly_checked_undo_says_so_in_the_risk(env, monkeypatch):
    before = {
        "network": NET_BEFORE,
        "wireless": "config wifi-iface 'ap'\n\toption note 'old'\n",
    }
    after = {
        "network": NET_AFTER,
        "wireless": "config wifi-iface 'ap'\n\toption note 'new'\n",
    }
    _record_out, current = _change(
        env, monkeypatch,
        diff="network.lan.ipaddr='10.0.0.2'\nwireless.ap.note='new'",
        before=before, after=after,
    )
    draft = draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert any(c["kind"] == "uci_equals" for c in draft.explanation["expect"])
    assert "Not every restored value" in draft.explanation["risk"]


# ----------------------------------------------- later review fixes


def test_un03_a_backup_that_is_not_the_planned_base_refuses(env, monkeypatch):
    """A config edit between the backup and the staging would be erased by restoring the older backup."""
    _record_out, current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
        base_hash="9" * 64,
    )
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert "planned on" in str(excinfo.value)


def test_un02_a_later_confirmed_change_without_a_receipt_counts_as_a_conflict(env, monkeypatch):
    _record_out, current = _change(
        env, monkeypatch, diff="network.lan.ipaddr='10.0.0.2'",
        before={"network": NET_BEFORE}, after={"network": NET_AFTER},
    )
    _change(
        env, monkeypatch, sid=OTHER_SID, stamp=STAMP_LATER, diff="network.lan.ipaddr='10.0.0.3'",
        before={"network": NET_AFTER}, after={"network": NET_AFTER},
    )
    for path in (env.state / "receipts").glob(f"*{OTHER_SID}.md"):
        path.unlink()
    with pytest.raises(UndoRefused) as excinfo:
        draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert "also changed by later change" in str(excinfo.value)


def test_un05_credentials_in_unlisted_network_options_are_not_claimed(env, monkeypatch):
    before = {"network": "config interface 'wan'\n\toption pppd_options 'user alice password hunter2'\n\toption proto 'pppoe'\n"}
    after = {"network": "config interface 'wan'\n\toption pppd_options 'x'\n\toption proto 'pppoe'\n"}
    _record_out, current = _change(
        env, monkeypatch, diff="network.wan.pppd_options='x'", before=before, after=after,
    )
    draft = draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert "hunter2" in draft.batch
    assert "hunter2" not in json.dumps(draft.explanation)


def test_un05_a_replaced_list_has_no_claim_that_the_option_is_absent(env, monkeypatch):
    before = {"network": "config interface 'lan'\n\tlist dns '1.1.1.1'\n\tlist dns '9.9.9.9'\n"}
    after = {"network": "config interface 'lan'\n\tlist dns '8.8.8.8'\n"}
    _record_out, current = _change(
        env, monkeypatch, diff="network.lan.dns+='8.8.8.8'", before=before, after=after,
    )
    draft = draft_undo(env.state, DEVICE, HOST, SID, current, AGENT)
    assert "delete network.lan.dns" in draft.batch and "add_list network.lan.dns" in draft.batch
    assert not any(c.get("probe", [""])[0] == "uci-unset" for c in draft.explanation["expect"])
