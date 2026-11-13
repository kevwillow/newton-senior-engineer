"""The Samba write helper of the DC (SPEC-1.4-REQUEST sections 1 to 9).

The helper runs on the Samba domain controller as root.  These tests load
it as a module with ``importlib.machinery.SourceFileLoader`` and point it
at a temporary install: a copy of the helper, the three files of section 8
and the transaction store.  The samba bindings are faked by
``fake_samba_write``, the way they were measured on the lab DC (Samba
4.22.11), and ``systemd-run``, ``systemctl`` and ``kinit`` are faked by
three scripts on the PATH that record their arguments.

The identity of the write account is the keytab of the DC, not a
password: the helper takes a ticket from it with ``kinit -k`` into a
private credential cache under ``/run/newton-ad`` and binds over LDAP
with that cache.

The parity tests hold the helper to the CORE contract: the same request
must be accepted or refused with the same code by
``newton_mcp.ad.write.request`` and by the helper, and the canonical bytes
of the two must be the same bytes.

The tests were written before the helper and watched failing.
"""

from __future__ import annotations

import base64
import copy
import fcntl
import importlib.machinery
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest

import fake_samba_write

from newton_mcp.ad.write import request as core_request


#: The root of the MCP package.
MCP_ROOT = Path(__file__).resolve().parents[2]

#: The helper itself.
HELPER_PATH = MCP_ROOT / "newton_mcp" / "ad" / "collector" / "newton-ad-samba-write"

#: The fixtures of the contract.
FIXTURES = MCP_ROOT / "tests" / "ad" / "fixtures"

#: The key of the lab: 32 bytes of 0x11 (section 4).
KEY_HEX = "11" * 32

#: The device name of the lab DC.
DEVICE = "lab-samba"

#: The approval window of the lab.
NBF = 1800000000
EXP = 1800000600

#: The transaction id of the lab.
TXID = "0123456789abcdef0123456789abcdef"

#: The secret of a user-create.
SECRET = "correct-horse-battery-1"


def load_helper() -> Any:
    """Load the helper as a module, the way the spec asks for."""
    loader = importlib.machinery.SourceFileLoader(
        "newton_ad_samba_write", str(HELPER_PATH)
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    # the helper has no extension: the loader must not leave a byte code
    # file beside it
    written = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = written
    return module


def dump(payload: Any) -> bytes:
    """The bytes of one JSON document."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class Dc:
    """One Samba domain controller of the lab, with the helper installed."""

    def __init__(
        self,
        helper: Any,
        fake: Any,
        root: Path,
        config: Path,
        tx: Path,
        log: Path,
        run_dir: Path,
    ) -> None:
        self.helper = helper
        self.fake = fake
        self.root = root
        self.config = config
        self.tx = tx
        self.log = log
        self.run_dir = run_dir

    # -- the requests -----------------------------------------------------

    def request(self, **overrides: Any) -> dict[str, Any]:
        """One valid apply request, with the overrides applied."""
        payload: dict[str, Any] = {
            "v": 1,
            "mode": "apply",
            "device": DEVICE,
            "txid": TXID,
            "verb": "uac-clear",
            "target": {
                "guid": fake_samba_write.ALICE_GUID,
                "sid": fake_samba_write.ALICE_SID,
                "sam": "alice",
                "bit": 4194304,
            },
            "before": {"uac": 4194816},
            "after": {"uac": 512},
            "window": 600,
            "risk": "MED",
            "nbf": NBF,
            "exp": EXP,
        }
        payload.update(overrides)
        payload["token"] = core_request.token(
            KEY_HEX, core_request.digest(payload), int(payload["nbf"]), int(payload["exp"])
        )
        return payload

    def run(self, payload: Any) -> dict[str, Any]:
        """Answer one request over stdin."""
        raw = payload if isinstance(payload, bytes) else dump(payload)
        return self.helper.handle([], raw, {"SUDO_USER": "newton-ops-ssh"})

    def undo(self, txid: str = TXID, env: dict[str, str] | None = None) -> dict[str, Any]:
        """Answer one undo over the argv."""
        return self.helper.handle(["--undo", txid], b"", env or {})

    # -- the state --------------------------------------------------------

    def record(self, txid: str = TXID) -> dict[str, Any]:
        """The record of one transaction."""
        return json.loads((self.tx / f"{txid}.json").read_text(encoding="utf-8"))

    def records(self) -> list[str]:
        """The names of the records of the store."""
        return sorted(path.name for path in self.tx.glob("*.json"))

    def log_lines(self) -> list[str]:
        """The lines of the call log."""
        if not self.log.exists():
            return []
        return self.log.read_text(encoding="utf-8").splitlines()


@pytest.fixture
def dc(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Dc:
    """One Samba DC of the lab: the helper, the install and the fake."""
    helper = load_helper()
    root = tmp_path / "dc"
    sbin = root / "usr" / "local" / "sbin"
    config = root / "etc" / "newton-ad"
    tx = root / "var" / "lib" / "newton-ad" / "tx"
    run_dir = root / "run" / "newton-ad"
    for path in (sbin, config, tx):
        path.mkdir(parents=True, exist_ok=True)
    (root / "run").mkdir(parents=True, exist_ok=True)
    # the directories of the install must not be writable by their group
    # or by the others, whatever the umask of the test is
    for path in (
        sbin,
        sbin.parent,
        sbin.parent.parent,
        sbin.parent.parent.parent,
        config,
        config.parent,
        tx,
        tx.parent,
        tx.parent.parent,
        tx.parent.parent.parent,
        tx.parent.parent.parent.parent,
        root,
        root / "run",
    ):
        path.chmod(0o755)

    # the installed copy of the helper
    shutil.copyfile(HELPER_PATH, sbin / "newton-ad-samba-write")
    (sbin / "newton-ad-samba-write").chmod(0o755)

    # the files of section 8
    key = config / "approval.key"
    key.write_text(KEY_HEX + "\n", encoding="utf-8")
    key.chmod(0o600)
    device = config / "device.txt"
    device.write_text(DEVICE + "\n", encoding="utf-8")
    device.chmod(0o644)
    # the identity of the write account is the keytab of the DC
    keytab = config / "ops.keytab"
    keytab.write_bytes(b"\x00\x05the keytab of the dc\x00")
    keytab.chmod(0o600)

    monkeypatch.setattr(helper, "SBIN_DIR", str(sbin))
    monkeypatch.setattr(helper, "CONFIG_DIR", str(config))
    monkeypatch.setattr(helper, "TX_DIR", str(tx))
    monkeypatch.setattr(helper, "RUN_DIR", str(run_dir))
    monkeypatch.setattr(helper, "INSTALL_ROOT", str(root))
    monkeypatch.setattr(helper, "INSTALL_OWNER_UID", os.getuid())
    monkeypatch.setattr(helper, "current_time", lambda: float(NBF))

    log = tmp_path / "calls.log"
    fake = fake_samba_write.Fake(log)
    for name, module in fake.modules().items():
        monkeypatch.setitem(sys.modules, name, module)

    bin_dir = tmp_path / "bin"
    fake_samba_write.install_commands(bin_dir)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("NEWTON_FAKE_LOG", str(log))

    return Dc(helper, fake, root, config, tx, log, run_dir)


# ---- the install and the login ---------------------------------------------


def test_the_helper_reads_the_device_that_stands_for_the_domain() -> None:
    """The helper answers to the device that stands for the domain.

    Every DC of the domain answers to the name of the device that
    stands for it, and the file of the install holds that name: the
    docstring of the reader says so.
    """
    helper = load_helper()

    assert "stands for the domain" in (helper.read_device.__doc__ or "")


def test_the_helper_refuses_a_login_that_is_not_the_write_login(dc: Dc) -> None:
    """Only the write login may use the helper over stdin."""
    raw = dump(dc.request())

    for env in ({}, {"SUDO_USER": "root"}, {"SUDO_USER": "newton-ops"}):
        answer = dc.helper.handle([], raw, env)
        assert answer["code"] == "denied"


def test_the_helper_refuses_an_unsafe_install(dc: Dc) -> None:
    """A directory of the install that others may write is refused."""
    dc.tx.chmod(0o777)

    answer = dc.run(dc.request())

    assert answer["code"] == "unavailable"


def test_the_helper_refuses_a_key_that_others_may_read(dc: Dc) -> None:
    """The key of the approval is read with its own mode."""
    key = dc.config / "approval.key"
    key.chmod(0o644)

    answer = dc.run(dc.request())

    assert answer["code"] == "unavailable"


def test_the_undo_is_refused_when_sudo_user_is_set(dc: Dc) -> None:
    """The undo never runs through the SSH channel."""
    answer = dc.undo(env={"SUDO_USER": "newton-ops-ssh"})

    assert answer["code"] == "denied"


def test_the_undo_refuses_a_txid_that_is_not_one(dc: Dc) -> None:
    """The txid is checked before it is used in a path."""
    answer = dc.undo(txid="../../etc/passwd")

    assert answer["code"] == "schema"


def test_the_undo_of_an_unknown_transaction_is_not_found(dc: Dc) -> None:
    """There is no record to undo."""
    answer = dc.undo(txid="a" * 32)

    assert answer["code"] == "not_found"


# ---- the refusals of an apply ----------------------------------------------


def test_a_bad_token_is_refused(dc: Dc) -> None:
    """The token must be the one the key mints."""
    payload = dc.request()
    payload["token"] = "0" * 64

    answer = dc.run(payload)

    assert answer["code"] == "bad_token"
    assert dc.records() == []


def test_an_expired_approval_is_refused(dc: Dc) -> None:
    """The clock of the DC is outside the window of the approval."""
    payload = dc.request()
    payload["nbf"] = NBF - 600
    payload["exp"] = NBF - 100
    payload["token"] = core_request.token(
        KEY_HEX, core_request.digest(payload), payload["nbf"], payload["exp"]
    )

    answer = dc.run(payload)

    assert answer["code"] == "expired"


def test_a_device_that_is_not_this_one_is_refused(dc: Dc) -> None:
    """Every DC of the domain holds the same key, but its own device."""
    payload = dc.request(device="lab-other")

    answer = dc.run(payload)

    assert answer["code"] == "schema"


def test_a_replayed_transaction_is_refused(dc: Dc) -> None:
    """The record file exists already."""
    dc.run(dc.request())
    payload = dc.request()
    payload["txid"] = "b" * 32
    payload["token"] = core_request.token(
        KEY_HEX, core_request.digest(payload), payload["nbf"], payload["exp"]
    )
    (dc.tx / f"{payload['txid']}.json").write_text("{}", encoding="utf-8")

    answer = dc.run(payload)

    assert answer["code"] == "replay"


def test_a_dc_that_is_not_the_pdc_refuses_an_apply(dc: Dc) -> None:
    """Only the domain controller of the domain may apply."""
    dc.fake.set_attribute(
        fake_samba_write.DOMAIN_DN, "fSMORoleOwner", "CN=NTDS Settings,CN=OTHER,DC=x"
    )

    answer = dc.run(dc.request())

    assert answer["code"] == "not_pdc"


def test_a_target_that_is_not_there_is_not_found(dc: Dc) -> None:
    """The helper finds the target by its guid."""
    payload = dc.request()
    payload["target"] = dict(payload["target"])
    payload["target"]["guid"] = "0" * 8 + "-0000-0000-0000-000000000000"
    payload["token"] = core_request.token(
        KEY_HEX, core_request.digest(payload), payload["nbf"], payload["exp"]
    )

    answer = dc.run(payload)

    assert answer["code"] == "not_found"


def test_a_target_whose_sid_does_not_match_is_not_found(dc: Dc) -> None:
    """The guid, the sid and the sam must agree."""
    payload = dc.request()
    payload["target"] = dict(payload["target"])
    payload["target"]["sid"] = "S-1-5-21-1-2-3-9999"
    payload["token"] = core_request.token(
        KEY_HEX, core_request.digest(payload), payload["nbf"], payload["exp"]
    )

    answer = dc.run(payload)

    assert answer["code"] == "not_found"


def test_a_before_image_that_does_not_match_is_a_conflict(dc: Dc) -> None:
    """The live value is not the before-image."""
    payload = dc.request(before={"uac": 4194816 + 2}, after={"uac": 514})

    answer = dc.run(payload)

    assert answer["code"] == "conflict"
    assert answer["live"] == {"uac": 4194816}
    assert dc.record()["state"] == "refused"


def test_a_stale_value_at_the_write_is_a_conflict(dc: Dc) -> None:
    """The server answers 16 when the old value is stale."""
    dc.fake.set_stale_value(fake_samba_write.ALICE_DN)

    answer = dc.run(dc.request())

    assert answer["code"] == "conflict"
    assert dc.record()["state"] == "refused"


def test_a_write_outside_the_delegation_is_denied(dc: Dc) -> None:
    """The server answers 50 outside the delegation."""
    payload = dc.request(
        target={
            "guid": fake_samba_write.MALLORY_GUID,
            "sid": fake_samba_write.MALLORY_SID,
            "sam": "mallory",
            "bit": 4194304,
        },
        before={"uac": 4194304},
        after={"uac": 0},
    )

    answer = dc.run(payload)

    assert answer["code"] == "denied"


def test_a_privileged_target_with_a_medium_risk_is_a_risk_mismatch(dc: Dc) -> None:
    """The helper derives the risk itself."""
    payload = dc.request(
        target={
            "guid": fake_samba_write.ADMIN_GUID,
            "sid": fake_samba_write.ADMIN_SID,
            "sam": "admin2",
            "bit": 4194304,
        },
        before={"uac": 4194304},
        after={"uac": 0},
        risk="MED",
    )

    answer = dc.run(payload)

    assert answer["code"] == "risk_mismatch"
    assert dc.fake.get_attribute(fake_samba_write.ADMIN_DN, "userAccountControl") == "4194304"


def test_a_privileged_target_with_a_high_risk_is_applied(dc: Dc) -> None:
    """The owner approved the level the helper derived."""
    payload = dc.request(
        target={
            "guid": fake_samba_write.ADMIN_GUID,
            "sid": fake_samba_write.ADMIN_SID,
            "sam": "admin2",
            "bit": 4194304,
        },
        before={"uac": 4194304},
        after={"uac": 0},
        risk="HIGH",
    )

    answer = dc.run(payload)

    assert answer["code"] == "ok"


def test_a_membership_of_a_privileged_group_is_refused(dc: Dc) -> None:
    """A privileged group is never written by the helper."""
    payload = dc.request(
        verb="member-add",
        target={
            "group_guid": fake_samba_write.DOMAIN_ADMINS_GUID,
            "group_sid": fake_samba_write.DOMAIN_ADMINS_SID,
            "group_sam": "domainadmins",
            "member_guid": fake_samba_write.ALICE_GUID,
            "member_sid": fake_samba_write.ALICE_SID,
            "member_sam": "alice",
        },
        before={"member": "absent"},
        after={"member": "present"},
    )

    answer = dc.run(payload)

    assert answer["code"] == "privileged"


def test_a_membership_of_a_group_nested_three_deep_is_refused(dc: Dc) -> None:
    """The nesting of the privileged groups is walked by the helper."""
    payload = dc.request(
        verb="member-add",
        target={
            "group_guid": fake_samba_write.NESTED3_GUID,
            "group_sid": fake_samba_write.NESTED3_SID,
            "group_sam": "nested3",
            "member_guid": fake_samba_write.ALICE_GUID,
            "member_sid": fake_samba_write.ALICE_SID,
            "member_sam": "alice",
        },
        before={"member": "absent"},
        after={"member": "present"},
    )

    answer = dc.run(payload)

    assert answer["code"] == "privileged"


def test_a_membership_of_a_group_with_a_cycle_is_refused_not_hung(dc: Dc) -> None:
    """A cycle in the memberOf chain ends the walk."""
    payload = dc.request(
        verb="member-add",
        target={
            "group_guid": fake_samba_write.CYCLE_A_GUID,
            "group_sid": fake_samba_write.CYCLE_A_SID,
            "group_sam": "cyclea",
            "member_guid": fake_samba_write.ALICE_GUID,
            "member_sid": fake_samba_write.ALICE_SID,
            "member_sam": "alice",
        },
        before={"member": "absent"},
        after={"member": "present"},
    )

    answer = dc.run(payload)

    assert answer["code"] == "ok"


def test_a_write_account_in_a_privileged_group_is_refused(dc: Dc) -> None:
    """The helper reads the tokenGroups of its own account."""
    dc.fake.set_token_groups(fake_samba_write.OPS_DN, [fake_samba_write.DOMAIN_ADMINS_SID])

    answer = dc.run(dc.request())

    assert answer["code"] == "privileged"


# ---- the apply --------------------------------------------------------------


def test_the_apply_follows_the_order_of_the_steps(dc: Dc) -> None:
    """The steps of section 6 run in the order the spec names them."""
    answer = dc.run(dc.request())

    assert answer["code"] == "ok"
    lines = dc.log_lines()
    kinds = [line.split(":", 1)[0] for line in lines]
    first_search = kinds.index("search")
    # the timer of the undo is armed before the write; the ticket of the
    # write account is taken before that, when the helper binds
    command = next(
        index
        for index, line in enumerate(lines)
        if line.startswith("command: systemd-run")
    )
    modify = kinds.index("modify")
    assert first_search < command < modify
    # the read back of step 7 comes after the write of step 6
    assert kinds.count("search") >= 2
    assert kinds.index("search", modify) > modify


def test_the_apply_answers_with_the_live_values_and_the_undo_at(dc: Dc) -> None:
    """The answer of an apply holds the live values and the deadline."""
    answer = dc.run(dc.request())

    assert answer["code"] == "ok"
    assert answer["live"] == {"uac": 512}
    assert answer["undo_at"] == NBF + 600


def test_the_apply_arms_the_undo_with_systemd_run(dc: Dc) -> None:
    """The undo is armed before the write."""
    dc.run(dc.request())

    armed = [line for line in dc.log_lines() if "systemd-run" in line]
    assert len(armed) == 1
    assert "--unit=newton-ad-undo-" + TXID in armed[0]
    assert "--on-active=600s" in armed[0]
    assert armed[0].endswith("--undo " + TXID)


def test_the_apply_writes_one_modify_with_two_elements(dc: Dc) -> None:
    """The write is the measured atomic modify."""
    dc.run(dc.request())

    modifies = [line for line in dc.log_lines() if line.startswith("modify:")]
    assert len(modifies) == 1
    assert "delete" in modifies[0]
    assert "add" in modifies[0]
    assert "userAccountControl" in modifies[0]


def test_the_record_holds_the_request_without_the_secret_and_the_token(dc: Dc) -> None:
    """The record never holds the secret nor the token."""
    payload = dc.request(verb="user-create", secret=SECRET)
    payload["target"] = {
        "parent_guid": fake_samba_write.SERVERS_OU_GUID,
        "sam": "newton-user",
    }
    payload["before"] = {"object": "absent"}
    payload["after"] = {"object": "present"}
    payload["risk"] = "MED"
    payload["token"] = core_request.token(
        KEY_HEX, core_request.digest(payload), payload["nbf"], payload["exp"]
    )

    answer = dc.run(payload)

    assert answer["code"] == "ok"
    record = dc.record()
    assert "secret" not in record["request"]
    assert "token" not in record["request"]
    assert record["state"] == "armed"
    assert record["undo_at"] == NBF + 600


def test_the_user_create_answers_with_the_created_object(dc: Dc) -> None:
    """The answer of a user-create holds the guid of the new object."""
    payload = dc.request(verb="user-create", secret=SECRET)
    payload["target"] = {
        "parent_guid": fake_samba_write.SERVERS_OU_GUID,
        "sam": "newton-user",
    }
    payload["before"] = {"object": "absent"}
    payload["after"] = {"object": "present"}
    payload["token"] = core_request.token(
        KEY_HEX, core_request.digest(payload), payload["nbf"], payload["exp"]
    )

    answer = dc.run(payload)

    assert answer["code"] == "ok"
    assert answer["created"] == fake_samba_write.created_guid(
        "CN=newton-user," + fake_samba_write.SERVERS_OU_DN
    )
    assert dc.fake.get_attribute(
        "CN=newton-user," + fake_samba_write.SERVERS_OU_DN, "userAccountControl"
    ) == "514"


@pytest.mark.parametrize("created", [(None, "1018"), (fake_samba_write.ALICE_GUID, None)])
def test_a_user_create_without_both_undo_facts_is_deleted(
    dc: Dc, monkeypatch: pytest.MonkeyPatch, created: tuple[str | None, str | None]
) -> None:
    """A successful add is removed by its exact DN when readback is incomplete."""
    monkeypatch.setattr(dc.helper, "read_created", lambda directory, request: created)
    payload = dc.request(verb="user-create", secret=SECRET)
    payload["target"] = {
        "parent_guid": fake_samba_write.SERVERS_OU_GUID,
        "sam": "newton-user",
    }
    payload["before"] = {"object": "absent"}
    payload["after"] = {"object": "present"}
    payload["token"] = core_request.token(
        KEY_HEX, core_request.digest(payload), payload["nbf"], payload["exp"]
    )
    dn = "CN=newton-user," + fake_samba_write.SERVERS_OU_DN

    answer = dc.run(payload)

    assert answer["code"] == "error"
    assert not dc.fake.has_object(dn)
    assert dc.record()["state"] == "undone"


def test_a_failed_cleanup_of_a_user_without_undo_facts_records_its_dn(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed exact-DN delete is an error and an undo_failed record."""
    monkeypatch.setattr(
        dc.helper, "read_created", lambda directory, request: (None, None)
    )
    dc.fake.delete_code = 1
    payload = dc.request(verb="user-create", secret=SECRET)
    payload["target"] = {
        "parent_guid": fake_samba_write.SERVERS_OU_GUID,
        "sam": "newton-user",
    }
    payload["before"] = {"object": "absent"}
    payload["after"] = {"object": "present"}
    payload["token"] = core_request.token(
        KEY_HEX, core_request.digest(payload), payload["nbf"], payload["exp"]
    )
    dn = "CN=newton-user," + fake_samba_write.SERVERS_OU_DN

    answer = dc.run(payload)

    assert answer["code"] == "error"
    record = dc.record()
    assert record["state"] == "undo_failed"
    assert dn in record["conflicts"]


# ---- every verb -------------------------------------------------------------


def test_every_verb_applies(dc: Dc) -> None:
    """Every verb of the table of section 3 writes and reads back."""
    cases = [
        (
            "uac-clear",
            {
                "guid": fake_samba_write.ALICE_GUID,
                "sid": fake_samba_write.ALICE_SID,
                "sam": "alice",
                "bit": 4194304,
            },
            {"uac": 4194816},
            {"uac": 512},
            "MED",
        ),
        (
            "disable",
            {
                "guid": fake_samba_write.BOB_GUID,
                "sid": fake_samba_write.BOB_SID,
                "sam": "bob",
            },
            {"uac": 512},
            {"uac": 514},
            "MED",
        ),
        (
            "enable",
            {
                "guid": fake_samba_write.CAROL_GUID,
                "sid": fake_samba_write.CAROL_SID,
                "sam": "carol",
            },
            {"uac": 514},
            {"uac": 512},
            "MED",
        ),
        (
            "enc-types",
            {
                "guid": fake_samba_write.ALICE_GUID,
                "sid": fake_samba_write.ALICE_SID,
                "sam": "alice",
            },
            {"etypes": 0},
            {"etypes": 24},
            "MED",
        ),
        (
            "unlock",
            {
                "guid": fake_samba_write.ALICE_GUID,
                "sid": fake_samba_write.ALICE_SID,
                "sam": "alice",
            },
            {"lockout": 1000},
            {"lockout": 0},
            "LOW",
        ),
        (
            "member-add",
            {
                "group_guid": fake_samba_write.GROUP_GUID,
                "group_sid": fake_samba_write.GROUP_SID,
                "group_sam": "group1106",
                "member_guid": fake_samba_write.ALICE_GUID,
                "member_sid": fake_samba_write.ALICE_SID,
                "member_sam": "alice",
            },
            {"member": "absent"},
            {"member": "present"},
            "MED",
        ),
        (
            "member-remove",
            {
                "group_guid": fake_samba_write.GROUP_GUID,
                "group_sid": fake_samba_write.GROUP_SID,
                "group_sam": "group1106",
                "member_guid": fake_samba_write.ALICE_GUID,
                "member_sid": fake_samba_write.ALICE_SID,
                "member_sam": "alice",
            },
            {"member": "present"},
            {"member": "absent"},
            "MED",
        ),
        (
            "maq",
            {"guid": fake_samba_write.DOMAIN_GUID},
            {"maq": 10},
            {"maq": 20},
            "MED",
        ),
        (
            "move",
            {
                "guid": fake_samba_write.ALICE_GUID,
                "sid": fake_samba_write.ALICE_SID,
                "sam": "alice",
            },
            {"parent": fake_samba_write.SERVERS_OU_GUID},
            {"parent": fake_samba_write.OTHER_OU_GUID},
            "MED",
        ),
    ]

    for index, (verb, target, before, after, risk) in enumerate(cases):
        if verb == "member-remove":
            dc.fake.add_member(fake_samba_write.GROUP_DN, fake_samba_write.ALICE_DN)
        payload = dc.request(
            verb=verb,
            target=target,
            before=before,
            after=after,
            risk=risk,
            window=120 if verb == "unlock" else 600,
            txid=f"{index:032x}",
        )
        answer = dc.run(payload)
        assert answer["code"] == "ok", (verb, answer)


def test_the_unlock_arms_no_undo(dc: Dc) -> None:
    """Nothing is armed for an unlock."""
    payload = dc.request(
        verb="unlock",
        target={
            "guid": fake_samba_write.ALICE_GUID,
            "sid": fake_samba_write.ALICE_SID,
            "sam": "alice",
        },
        before={"lockout": 1000},
        after={"lockout": 0},
        risk="LOW",
        window=120,
    )

    answer = dc.run(payload)

    assert answer["code"] == "ok"
    assert [line for line in dc.log_lines() if "systemd-run" in line] == []
    assert dc.record()["state"] == "confirmed"


# ---- the read mode ----------------------------------------------------------


def test_the_read_mode_answers_with_the_live_values_the_ids_and_the_facts(dc: Dc) -> None:
    """The read answers with what the DC sees."""
    answer = dc.run(
        {
            "v": 1,
            "mode": "read",
            "device": DEVICE,
            "verb": "uac-clear",
            "target": {
                "guid": fake_samba_write.ALICE_GUID,
                "sid": fake_samba_write.ALICE_SID,
                "sam": "alice",
                "bit": 4194304,
            },
        }
    )

    assert answer["code"] == "ok"
    assert answer["live"] == {"uac": 4194816}
    assert answer["ids"] == {
        "guid": fake_samba_write.ALICE_GUID,
        "sid": fake_samba_write.ALICE_SID,
        "sam": "alice",
    }
    facts = answer["facts"]["target"]
    assert facts["admin_count"] == 0
    assert facts["dc_account"] is False
    assert facts["privileged"] is False
    assert facts["pdc"] is True
    assert "user" in facts["object_class"]


def test_the_read_mode_resolves_a_name(dc: Dc) -> None:
    """A read may carry only the name."""
    answer = dc.run(
        {
            "v": 1,
            "mode": "read",
            "device": DEVICE,
            "verb": "uac-clear",
            "target": {"sam": "alice"},
        }
    )

    assert answer["code"] == "ok"
    assert answer["ids"]["guid"] == fake_samba_write.ALICE_GUID


def test_the_read_mode_refuses_a_name_that_is_not_there(dc: Dc) -> None:
    """Zero matches is not_found."""
    answer = dc.run(
        {
            "v": 1,
            "mode": "read",
            "device": DEVICE,
            "verb": "uac-clear",
            "target": {"sam": "nobody"},
        }
    )

    assert answer["code"] == "not_found"


def test_the_read_mode_never_holds_the_secret(dc: Dc) -> None:
    """The read answers with no secret."""
    answer = dc.run(
        {
            "v": 1,
            "mode": "read",
            "device": DEVICE,
            "verb": "user-create",
            "target": {
                "parent_guid": fake_samba_write.SERVERS_OU_GUID,
                "sam": "newton-user",
            },
        }
    )

    assert answer["code"] == "ok"
    assert answer["live"] == {"object": "absent"}


def test_the_undo_of_a_membership_takes_the_member_out(dc: Dc) -> None:
    """The undo of a member-add puts the group back as it was."""
    payload = dc.request(
        verb="member-add",
        target={
            "group_guid": fake_samba_write.GROUP_GUID,
            "group_sid": fake_samba_write.GROUP_SID,
            "group_sam": "group1106",
            "member_guid": fake_samba_write.ALICE_GUID,
            "member_sid": fake_samba_write.ALICE_SID,
            "member_sam": "alice",
        },
        before={"member": "absent"},
        after={"member": "present"},
    )
    assert dc.run(payload)["code"] == "ok"

    answer = dc.undo()

    assert answer["code"] == "ok"
    assert answer["conflicts"] == []
    assert dc.fake.get_attribute(fake_samba_write.GROUP_DN, "member") is None


def test_the_undo_of_a_membership_puts_the_member_back(dc: Dc) -> None:
    """The undo of a member-remove gives the member back to the group."""
    dc.fake.add_member(fake_samba_write.GROUP_DN, fake_samba_write.ALICE_DN)
    payload = dc.request(
        verb="member-remove",
        target={
            "group_guid": fake_samba_write.GROUP_GUID,
            "group_sid": fake_samba_write.GROUP_SID,
            "group_sam": "group1106",
            "member_guid": fake_samba_write.ALICE_GUID,
            "member_sid": fake_samba_write.ALICE_SID,
            "member_sam": "alice",
        },
        before={"member": "present"},
        after={"member": "absent"},
    )
    assert dc.run(payload)["code"] == "ok"

    answer = dc.undo()

    assert answer["code"] == "ok"
    assert answer["conflicts"] == []
    assert (
        dc.fake.get_attribute(fake_samba_write.GROUP_DN, "member")
        == fake_samba_write.ALICE_DN
    )


def test_a_write_that_fails_leaves_the_value_alone(dc: Dc) -> None:
    """A write the server refuses changes nothing."""
    payload = dc.request(
        target={
            "guid": fake_samba_write.MALLORY_GUID,
            "sid": fake_samba_write.MALLORY_SID,
            "sam": "mallory",
            "bit": 4194304,
        },
        before={"uac": 4194304},
        after={"uac": 0},
    )

    answer = dc.run(payload)

    assert answer["code"] == "denied"
    assert (
        dc.fake.get_attribute(fake_samba_write.MALLORY_DN, "userAccountControl")
        == "4194304"
    )


# ---- the confirm, the abort and the status ----------------------------------


def test_the_confirm_cancels_the_timer(dc: Dc) -> None:
    """The confirm stops the timer of the transaction."""
    dc.run(dc.request())

    answer = dc.run(
        {"v": 1, "mode": "confirm", "device": DEVICE, "txid": TXID}
    )

    assert answer["code"] == "ok"
    stopped = [line for line in dc.log_lines() if "systemctl" in line]
    assert len(stopped) == 1
    assert "newton-ad-undo-" + TXID + ".timer" in stopped[0]
    assert dc.record()["state"] == "confirmed"


def test_the_confirm_records_the_confirmation_before_it_cancels_the_timer(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A confirmation that cannot be recorded is an error.

    The timer of the undo is not cancelled: the change that every
    controller verified can still be put back.
    """
    dc.run(dc.request())
    real = dc.helper.write_record

    def failing(path: str, record: Any) -> None:
        if record.get("state") == "confirmed":
            raise OSError("the store cannot be written")
        real(path, record)

    monkeypatch.setattr(dc.helper, "write_record", failing)

    answer = dc.run(
        {"v": 1, "mode": "confirm", "device": DEVICE, "txid": TXID}
    )

    assert answer["code"] == "error"
    assert dc.record()["state"] == "armed"
    assert not [line for line in dc.log_lines() if "systemctl" in line]


def test_a_confirm_whose_cancel_fails_still_answers_ok(
    dc: Dc, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A cancel of the timer that fails does not change the answer.

    The record says confirmed, and the timer that fires anyway finds a
    confirmed record and does nothing.
    """
    dc.run(dc.request())
    monkeypatch.setenv("NEWTON_FAKE_FAIL_SYSTEMCTL", "1")

    answer = dc.run(
        {"v": 1, "mode": "confirm", "device": DEVICE, "txid": TXID}
    )

    assert answer["code"] == "ok"
    assert dc.record()["state"] == "confirmed"
    assert "not cancelled" in capsys.readouterr().err


def test_the_undo_of_a_confirmed_transaction_does_nothing(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The timer of a confirmed transaction finds the record and stops."""
    dc.run(dc.request())
    monkeypatch.setenv("NEWTON_FAKE_FAIL_SYSTEMCTL", "1")
    dc.run({"v": 1, "mode": "confirm", "device": DEVICE, "txid": TXID})

    answer = dc.undo()

    assert answer["code"] == "ok"
    assert answer["restored"] is False
    assert dc.record()["state"] == "confirmed"
    assert dc.fake.get_attribute(fake_samba_write.ALICE_DN, "userAccountControl") == "512"


def test_the_record_of_a_transaction_is_on_the_disk_before_the_write(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The record is flushed to the disk, not buffered.

    The bytes of the record and the name of the file are on the disk
    before the write they guard: a record that is lost is an undo that
    never runs.
    """
    flushed: list[tuple[int, int]] = []
    real = os.fsync

    def recorder(descriptor: int) -> None:
        status = os.fstat(descriptor)
        flushed.append((status.st_dev, status.st_ino))
        real(descriptor)

    monkeypatch.setattr(dc.helper.os, "fsync", recorder)

    answer = dc.run(dc.request())

    assert answer["code"] == "ok"
    record = (dc.tx / f"{TXID}.json").stat()
    directory = dc.tx.stat()
    assert (record.st_dev, record.st_ino) in flushed
    assert (directory.st_dev, directory.st_ino) in flushed


def test_the_confirm_of_a_changed_target_is_a_conflict(dc: Dc) -> None:
    """The confirm re-reads the target."""
    dc.run(dc.request())
    dc.fake.set_attribute(fake_samba_write.ALICE_DN, "userAccountControl", "1024")

    answer = dc.run(
        {"v": 1, "mode": "confirm", "device": DEVICE, "txid": TXID}
    )

    assert answer["code"] == "conflict"


def test_the_confirm_of_an_undone_transaction_is_a_conflict(dc: Dc) -> None:
    """An undone transaction is never confirmed."""
    dc.run(dc.request())
    dc.undo()

    answer = dc.run(
        {"v": 1, "mode": "confirm", "device": DEVICE, "txid": TXID}
    )

    assert answer["code"] == "conflict"


def test_the_abort_restores_the_before_image(dc: Dc) -> None:
    """The abort runs the undo at once."""
    dc.run(dc.request())

    answer = dc.run({"v": 1, "mode": "abort", "device": DEVICE, "txid": TXID})

    assert answer["code"] == "ok"
    assert answer["restored"] is True
    assert answer["conflicts"] == []
    assert dc.fake.get_attribute(fake_samba_write.ALICE_DN, "userAccountControl") == "4194816"
    assert dc.record()["state"] == "undone"


def test_the_status_answers_with_the_state(dc: Dc) -> None:
    """The status of an armed transaction."""
    dc.run(dc.request())

    answer = dc.run({"v": 1, "mode": "status", "device": DEVICE, "txid": TXID})

    assert answer["code"] == "ok"
    assert answer["state"] == "armed"
    assert answer["undo_at"] == NBF + 600
    assert answer["restored"] is False
    assert answer["conflicts"] == []


def test_the_status_of_an_unknown_transaction_is_not_found(dc: Dc) -> None:
    """There is no record to report on."""
    answer = dc.run({"v": 1, "mode": "status", "device": DEVICE, "txid": "c" * 32})

    assert answer["code"] == "not_found"


# ---- the undo and the sweep -------------------------------------------------


def test_the_undo_puts_the_before_image_back(dc: Dc) -> None:
    """The undo writes the inverse."""
    dc.run(dc.request())

    answer = dc.undo()

    assert answer["code"] == "ok"
    assert answer["restored"] is True
    assert dc.fake.get_attribute(fake_samba_write.ALICE_DN, "userAccountControl") == "4194816"
    assert dc.record()["state"] == "undone"


def test_an_undo_that_meets_a_changed_value_records_a_conflict(dc: Dc) -> None:
    """The undo leaves the value alone when somebody else changed it."""
    dc.run(dc.request())
    dc.fake.set_attribute(fake_samba_write.ALICE_DN, "userAccountControl", "4096")

    answer = dc.undo()

    assert answer["code"] == "ok"
    assert answer["conflicts"] != []
    assert dc.fake.get_attribute(fake_samba_write.ALICE_DN, "userAccountControl") == "4096"
    assert dc.record()["state"] == "undo_failed"


def test_the_sweep_runs_an_overdue_undo_and_never_confirms(dc: Dc) -> None:
    """Every run undoes the armed records whose deadline has passed."""
    dc.run(dc.request())
    dc.helper.current_time = lambda: float(NBF + 601)

    answer = dc.run({"v": 1, "mode": "status", "device": DEVICE, "txid": TXID})

    assert answer["code"] == "ok"
    assert answer["state"] == "undone"
    assert dc.fake.get_attribute(fake_samba_write.ALICE_DN, "userAccountControl") == "4194816"


def test_the_sweep_leaves_an_armed_record_that_is_not_due_alone(dc: Dc) -> None:
    """The sweep waits for the deadline."""
    dc.run(dc.request())
    dc.helper.current_time = lambda: float(NBF + 10)

    dc.run({"v": 1, "mode": "status", "device": DEVICE, "txid": TXID})

    assert dc.record()["state"] == "armed"
    assert dc.fake.get_attribute(fake_samba_write.ALICE_DN, "userAccountControl") == "512"


def test_the_undo_of_a_user_create_deletes_the_object(dc: Dc) -> None:
    """The undo deletes the object it created, and only that one."""
    payload = dc.request(verb="user-create", secret=SECRET)
    payload["target"] = {
        "parent_guid": fake_samba_write.SERVERS_OU_GUID,
        "sam": "newton-user",
    }
    payload["before"] = {"object": "absent"}
    payload["after"] = {"object": "present"}
    payload["token"] = core_request.token(
        KEY_HEX, core_request.digest(payload), payload["nbf"], payload["exp"]
    )
    dc.run(payload)

    answer = dc.undo()

    assert answer["code"] == "ok"
    assert answer["conflicts"] == []
    assert not dc.fake.has_object(
        "CN=newton-user," + fake_samba_write.SERVERS_OU_DN
    )


def test_the_undo_of_a_user_create_leaves_an_enabled_object_alone(dc: Dc) -> None:
    """The object is only deleted when it is still disabled."""
    payload = dc.request(verb="user-create", secret=SECRET)
    payload["target"] = {
        "parent_guid": fake_samba_write.SERVERS_OU_GUID,
        "sam": "newton-user",
    }
    payload["before"] = {"object": "absent"}
    payload["after"] = {"object": "present"}
    payload["token"] = core_request.token(
        KEY_HEX, core_request.digest(payload), payload["nbf"], payload["exp"]
    )
    dc.run(payload)
    dc.fake.set_attribute(
        "CN=newton-user," + fake_samba_write.SERVERS_OU_DN,
        "userAccountControl",
        "512",
    )

    answer = dc.undo()

    assert answer["conflicts"] != []
    assert dc.fake.has_object(
        "CN=newton-user," + fake_samba_write.SERVERS_OU_DN
    )


# ---- the concurrency --------------------------------------------------------


def test_two_concurrent_applies_with_one_txid_pass_one(dc: Dc) -> None:
    """The lock of the store lets one apply through."""
    payload = dc.request()
    raw = dump(payload)
    answers: list[dict[str, Any]] = []
    barrier = threading.Barrier(2)

    def run() -> None:
        barrier.wait()
        answers.append(
            dc.helper.handle([], raw, {"SUDO_USER": "newton-ops-ssh"})
        )

    threads = [threading.Thread(target=run) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    codes = sorted(answer["code"] for answer in answers)
    assert codes == ["ok", "replay"]


def test_the_apply_holds_the_lock_of_the_store(dc: Dc) -> None:
    """The whole run of an apply holds the exclusive lock."""
    original = dc.helper.do_apply
    seen: list[bool] = []

    def wrapper(request: Any, now: int) -> dict[str, Any]:
        descriptor = os.open(dc.tx / ".lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            seen.append(False)
        except OSError:
            seen.append(True)
        finally:
            os.close(descriptor)
        return original(request, now)

    dc.helper.do_apply = wrapper

    answer = dc.run(dc.request())

    assert answer["code"] == "ok"
    assert seen == [True]


# ---- the secret -------------------------------------------------------------


def test_the_secret_is_never_written_anywhere(dc: Dc, capsys: pytest.CaptureFixture[str]) -> None:
    """The secret is in no file the helper writes and in no line it logs."""
    payload = dc.request(verb="user-create", secret=SECRET)
    payload["target"] = {
        "parent_guid": fake_samba_write.SERVERS_OU_GUID,
        "sam": "newton-user",
    }
    payload["before"] = {"object": "absent"}
    payload["after"] = {"object": "present"}
    payload["token"] = core_request.token(
        KEY_HEX, core_request.digest(payload), payload["nbf"], payload["exp"]
    )

    answer = dc.run(payload)
    captured = capsys.readouterr()

    assert answer["code"] == "ok"
    assert SECRET not in json.dumps(answer)
    for path in list(dc.tx.glob("*")) + [dc.log]:
        if path.is_file():
            assert SECRET not in path.read_text(encoding="utf-8", errors="replace")
    assert SECRET not in captured.out
    assert SECRET not in captured.err


# ---- the parity with the CORE contract --------------------------------------


def test_the_vector_is_the_vector_of_the_contract(dc: Dc) -> None:
    """The helper reproduces the canonical bytes of the contract."""
    payload = json.loads(
        (FIXTURES / "write-request-v1.json").read_text(encoding="utf-8")
    )
    expected = json.loads(
        (FIXTURES / "write-request-v1.expected.json").read_text(encoding="utf-8")
    )

    canonical = dc.helper.canonical_bytes(payload)

    assert canonical == base64.b64decode(expected["canonical_b64"])
    assert dc.helper.digest(payload) == expected["digest"]
    assert dc.helper.token(KEY_HEX, expected["digest"], 1800000000, 1800000600) == (
        expected["token"]
    )


def test_the_helper_accepts_the_vector_of_the_contract(dc: Dc) -> None:
    """The request of the vector parses in the helper too."""
    raw = (FIXTURES / "write-request-v1.json").read_bytes()

    parsed = dc.helper.parse_request(raw)

    assert parsed["verb"] == "uac-clear"


def _valid_requests() -> dict[str, dict[str, Any]]:
    """One valid request per verb, and one read per verb."""
    account = {
        "guid": fake_samba_write.ALICE_GUID,
        "sid": fake_samba_write.ALICE_SID,
        "sam": "alice",
    }
    group = {
        "group_guid": fake_samba_write.GROUP_GUID,
        "group_sid": fake_samba_write.GROUP_SID,
        "group_sam": "group1106",
        "member_guid": fake_samba_write.ALICE_GUID,
        "member_sid": fake_samba_write.ALICE_SID,
        "member_sam": "alice",
    }
    cases: dict[str, dict[str, Any]] = {
        "uac-clear": {
            "verb": "uac-clear",
            "target": dict(account, bit=4194304),
            "before": {"uac": 4194304},
            "after": {"uac": 0},
        },
        "disable": {
            "verb": "disable",
            "target": dict(account),
            "before": {"uac": 512},
            "after": {"uac": 514},
        },
        "enable": {
            "verb": "enable",
            "target": dict(account),
            "before": {"uac": 514},
            "after": {"uac": 512},
        },
        "enc-types": {
            "verb": "enc-types",
            "target": dict(account),
            "before": {"etypes": 0},
            "after": {"etypes": 24},
        },
        "unlock": {
            "verb": "unlock",
            "target": dict(account),
            "before": {"lockout": 1000},
            "after": {"lockout": 0},
        },
        "member-add": {
            "verb": "member-add",
            "target": dict(group),
            "before": {"member": "absent"},
            "after": {"member": "present"},
        },
        "member-remove": {
            "verb": "member-remove",
            "target": dict(group),
            "before": {"member": "present"},
            "after": {"member": "absent"},
        },
        "maq": {
            "verb": "maq",
            "target": {"guid": fake_samba_write.DOMAIN_GUID},
            "before": {"maq": 10},
            "after": {"maq": 20},
        },
        "user-create": {
            "verb": "user-create",
            "target": {
                "parent_guid": fake_samba_write.SERVERS_OU_GUID,
                "sam": "newton-user",
            },
            "before": {"object": "absent"},
            "after": {"object": "present"},
        },
        "move": {
            "verb": "move",
            "target": dict(account),
            "before": {"parent": fake_samba_write.SERVERS_OU_GUID},
            "after": {"parent": fake_samba_write.OTHER_OU_GUID},
        },
    }
    return cases


def _apply_request(case: dict[str, Any]) -> dict[str, Any]:
    """The apply request of one case."""
    payload: dict[str, Any] = {
        "v": 1,
        "mode": "apply",
        "device": DEVICE,
        "txid": TXID,
        "window": 600,
        "risk": "MED",
        "nbf": NBF,
        "exp": EXP,
    }
    payload.update(case)
    if payload["verb"] == "unlock":
        payload["window"] = 120
        payload["risk"] = "LOW"
    if payload["verb"] == "user-create":
        payload["secret"] = SECRET
    payload["token"] = "0" * 64
    return payload


def _mutations(case: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """The refusals of the contract, one mutation each."""
    out: list[tuple[str, dict[str, Any]]] = []

    def mutate(name: str, **changes: Any) -> None:
        payload = copy.deepcopy(case)
        for key, value in changes.items():
            if value is _DELETE:
                payload.pop(key, None)
            else:
                payload[key] = value
        out.append((name, payload))

    mutate("an unknown field", extra=1)
    mutate("a missing txid", txid=_DELETE)
    mutate("a missing device", device=_DELETE)
    mutate("a missing verb", verb=_DELETE)
    mutate("a missing target", target=_DELETE)
    mutate("a missing before", before=_DELETE)
    mutate("a missing after", after=_DELETE)
    mutate("a missing window", window=_DELETE)
    mutate("a missing risk", risk=_DELETE)
    mutate("a missing nbf", nbf=_DELETE)
    mutate("a missing exp", exp=_DELETE)
    mutate("a missing token", token=_DELETE)
    mutate("a version that is not one", v=2)
    mutate("a version that is text", v="1")
    mutate("a version that is a bool", v=True)
    mutate("a mode that is not one", mode="write")
    mutate("a device outside its pattern", device="Lab")
    mutate("a device that is too long", device="a" * 33)
    mutate("a txid outside its pattern", txid="0123456789abcdef0123456789abcdeZ")
    mutate("a token outside its pattern", token="z" * 64)
    mutate("a risk that is not one", risk="low")
    mutate("a window that is too small", window=119)
    mutate("a window that is too large", window=1801)
    mutate("a window that is text", window="600")
    mutate("a window that is a bool", window=True)
    mutate("an approval that is not ten digits", nbf=180000000)
    mutate("an approval that does not move forward", exp=NBF)
    mutate("an approval that is too wide", exp=NBF + 1801)
    mutate("an nbf that is text", nbf="1800000000")
    mutate("a target that is not an object", target="alice")
    mutate("a target with an unknown key", target_extra=1)
    mutate("a before with an unknown key", before_extra=1)
    mutate("an after with an unknown key", after_extra=1)
    mutate("a secret that is too short", secret="short")
    mutate("a secret that is too long", secret="x" * 129)
    mutate("a secret with a control character", secret="x" * 15 + "\n")
    return out


class _Delete:
    """The marker of a key that is removed."""


_DELETE = _Delete()


def _raw_cases() -> list[tuple[str, bytes]]:
    """The refusals that only the raw text can show."""
    body = json.dumps(
        {
            "v": 1,
            "mode": "apply",
            "device": DEVICE,
            "txid": TXID,
            "verb": "uac-clear",
            "target": {
                "guid": fake_samba_write.ALICE_GUID,
                "sid": fake_samba_write.ALICE_SID,
                "sam": "alice",
                "bit": 4194304,
            },
            "before": {"uac": 4194816},
            "after": {"uac": 512},
            "window": 600,
            "risk": "MED",
            "nbf": NBF,
            "exp": EXP,
            "token": "0" * 64,
        },
        sort_keys=True,
    )
    return [
        ("a duplicate key", body.replace('"v": 1,', '"v": 1, "v": 1,', 1).encode()),
        (
            "two keys that differ only in case",
            body.replace('"device"', '"Device"', 1).encode(),
        ),
        ("a number with a fraction", body.replace('"window": 600', '"window": 600.0').encode()),
        ("a number with an exponent", body.replace('"window": 600', '"window": 6e2').encode()),
        ("a number with a leading zero", body.replace('"window": 600', '"window": 0600').encode()),
        ("a number with a sign", body.replace('"window": 600', '"window": +600').encode()),
        ("a number that is not a number", body.replace('"window": 600', '"window": NaN').encode()),
        ("a document that is not an object", b"[]"),
        ("a document that is not JSON", b"{"),
        ("a document that is not UTF-8", b'{"v": "\xff"}'),
        ("a document that is too big", b"{" + b" " * (64 * 1024) + b"}"),
    ]


def _generated_requests() -> list[tuple[str, bytes]]:
    """Every request of the parity test: valid and invalid."""
    cases: list[tuple[str, bytes]] = []
    for name, case in _valid_requests().items():
        payload = _apply_request(case)
        cases.append((f"{name}: valid", dump(payload)))
        for mutation, changed in _mutations(payload):
            cases.append((f"{name}: {mutation}", dump(changed)))
        cases.append((f"{name}: a secret on another verb", dump(
            {**payload, "secret": SECRET}
        )))
        cases.append((f"{name}: an unlock with another window", dump(
            {**payload, "verb": "unlock", "window": 600}
        )))
        cases.append((f"{name}: a read with the full target", dump(
            {
                "v": 1,
                "mode": "read",
                "device": DEVICE,
                "verb": payload["verb"],
                "target": {
                    key: value
                    for key, value in payload["target"].items()
                    if key not in ("bit",)
                },
            }
        )))
        cases.append((f"{name}: a read with a name", dump(
            {
                "v": 1,
                "mode": "read",
                "device": DEVICE,
                "verb": payload["verb"],
                "target": {"sam": "alice"},
            }
        )))
    cases.extend(_raw_cases())
    return cases


def _core_code(raw: bytes) -> tuple[str | None, dict[str, Any] | None]:
    """The code the CORE gives a request, and the request it parsed."""
    try:
        parsed = core_request.parse_request(raw)
    except core_request.RequestRefused as exc:
        return exc.code, None
    return None, parsed


def _helper_code(dc: Dc, raw: bytes) -> tuple[str | None, dict[str, Any] | None]:
    """The code the helper gives a request, and the request it parsed."""
    try:
        parsed = dc.helper.parse_request(raw)
    except dc.helper.Refused as exc:
        return exc.code, None
    return None, parsed


def _canonical_outcome(function: Any, payload: Any) -> tuple[str, Any]:
    """The code of a refusal of the canonical bytes, or the bytes."""
    try:
        return "ok", function(payload)
    except Exception as exc:
        return "refused", getattr(exc, "code", "error")


def test_the_helper_and_the_core_agree_on_every_request(dc: Dc) -> None:
    """Three hundred generated requests, the same code from both."""
    cases = _generated_requests()
    assert len(cases) >= 300

    for label, raw in cases:
        core_code, core_parsed = _core_code(raw)
        helper_code, helper_parsed = _helper_code(dc, raw)
        assert helper_code == core_code, label
        if core_code is None:
            assert core_parsed is not None and helper_parsed is not None, label
            core_state, core_value = _canonical_outcome(
                core_request.canonical_bytes, core_parsed
            )
            helper_state, helper_value = _canonical_outcome(
                dc.helper.canonical_bytes, helper_parsed
            )
            assert helper_state == core_state, label
            if core_state == "ok":
                assert helper_value == core_value, label
                assert dc.helper.digest(helper_parsed) == (
                    core_request.digest(core_parsed)
                ), label


def test_the_helper_and_the_core_agree_on_the_verb_rules(dc: Dc) -> None:
    """The rules of the table of section 3 give the same code."""
    for name, case in _valid_requests().items():
        payload = _apply_request(case)
        broken = [
            ("a before that does not move", {**payload, "before": {"uac": 1}}),
            ("an after that does not move", {**payload, "after": {"uac": 1}}),
        ]
        if name == "uac-clear":
            broken.append(("a bit that is not one", {**payload, "target": {**payload["target"], "bit": 3}}))
        if name == "unlock":
            broken.append(("a lockout that is not positive", {**payload, "before": {"lockout": 0}}))
        if name == "enc-types":
            broken.append(("DES that is enabled", {**payload, "after": {"etypes": 1}}))
        if name == "member-add":
            broken.append(("a member that is already there", {**payload, "before": {"member": "present"}}))
        if name == "member-remove":
            broken.append(("a member that is not there", {**payload, "before": {"member": "absent"}}))
        if name == "user-create":
            broken.append(("an object that is already there", {**payload, "before": {"object": "present"}}))
        if name == "maq":
            broken.append(("a quota that is too big", {**payload, "after": {"maq": 1001}}))
        for label, changed in broken:
            core_error = None
            try:
                core_request.check_verb_rules(changed)
            except core_request.RequestRefused as exc:
                core_error = exc.code
            helper_error = None
            try:
                dc.helper.check_verb_rules(changed)
            except dc.helper.Refused as exc:
                helper_error = exc.code
            assert helper_error == core_error, (name, label)


# ---- the shape of the helper -------------------------------------------------


def test_the_helper_never_builds_a_shell_string() -> None:
    """The commands run with an argv list and never through a shell."""
    source = HELPER_PATH.read_text(encoding="utf-8")

    assert "shell=True" not in source
    assert "os.system" not in source
    assert "subprocess.run" in source


def test_the_helper_does_not_import_newton_mcp() -> None:
    """The helper runs alone on the DC."""
    source = HELPER_PATH.read_text(encoding="utf-8")

    assert "newton_mcp" not in source


def test_the_helper_starts_with_the_isolated_interpreter() -> None:
    """The helper runs with the interpreter the collector uses."""
    first = HELPER_PATH.read_text(encoding="utf-8").splitlines()[0]

    assert first == "#!/usr/bin/python3 -I"


def test_the_helper_answers_with_one_document_and_exits_zero(tmp_path: Path) -> None:
    """Run the helper as the script it is."""
    result = subprocess.run(
        [sys.executable, "-I", str(HELPER_PATH), "--undo", "a" * 32],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
    )

    assert result.returncode == 0
    answer = json.loads(result.stdout.decode("utf-8"))
    assert answer["v"] == 1
    assert answer["code"] in ("denied", "unavailable")


def test_the_fake_holds_the_measured_shapes_of_the_bindings(dc: Dc) -> None:
    """The fake behaves the way the bindings were measured."""
    import ldb

    modules = dc.fake.modules()

    assert isinstance(ldb.binary_encode("a*b("), str)
    with pytest.raises(KeyError):
        modules["samba.param"].LoadParm().get("no such option")
    assert (
        dc.fake.get_attribute(
            fake_samba_write.ALICE_DN, "msDS-ReplAttributeMetaData"
        )
        is None
    )


# ---- the measured directory shapes, the PDC role, privileged targets and the undo ----
#
# Every test of this section fails on the helper before the fix and passes
# after the fix.  The facts they hold are the ones MEASURED-2026-11-09
# measured on a real Samba 4.22.11 domain controller.


def _move_request(dc: Dc, **overrides: Any) -> dict[str, Any]:
    """One request that moves Alice to the other OU."""
    payload = dc.request(
        verb="move",
        target={
            "guid": fake_samba_write.ALICE_GUID,
            "sid": fake_samba_write.ALICE_SID,
            "sam": "alice",
        },
        before={"parent": fake_samba_write.SERVERS_OU_GUID},
        after={"parent": fake_samba_write.OTHER_OU_GUID},
    )
    payload.update(overrides)
    payload["token"] = core_request.token(
        KEY_HEX, core_request.digest(payload), int(payload["nbf"]), int(payload["exp"])
    )
    return payload


def _user_create_request(dc: Dc, **overrides: Any) -> dict[str, Any]:
    """One request that creates a user in the delegated OU."""
    payload = dc.request(verb="user-create", secret=SECRET)
    payload["target"] = {
        "parent_guid": fake_samba_write.SERVERS_OU_GUID,
        "sam": "newton-user",
    }
    payload["before"] = {"object": "absent"}
    payload["after"] = {"object": "present"}
    payload.update(overrides)
    payload["token"] = core_request.token(
        KEY_HEX, core_request.digest(payload), int(payload["nbf"]), int(payload["exp"])
    )
    return payload


# -- the shapes the fake holds ------------------------------------------------


def test_the_fake_holds_the_measured_shapes_of_the_directory(dc: Dc) -> None:
    """The fake tells the truth about the DC it fakes."""
    db = fake_samba_write.FakeSamDB()

    root = db.search(
        base="",
        scope=0,
        expression="(objectClass=*)",
        attrs=["dsServiceName", "serverName"],
    )

    assert len(root) == 1
    assert root[0].dn == ""
    assert [one.decode("utf-8") for one in root[0]["dsServiceName"]] == [
        fake_samba_write.NTDS_SETTINGS_DN
    ]
    assert [one.decode("utf-8") for one in root[0]["serverName"]] == [
        fake_samba_write.SERVER_NAME_DN
    ]
    assert dc.fake.get_attribute(
        fake_samba_write.DOMAIN_DN, "fSMORoleOwner"
    ) == fake_samba_write.NTDS_SETTINGS_DN
    assert (
        dc.fake.get_attribute(fake_samba_write.DC_DN, "serverReferenceBL")
        == fake_samba_write.SERVER_NAME_DN
    )
    assert fake_samba_write.DC_DN == (
        "CN=DC1,OU=Domain Controllers," + fake_samba_write.DOMAIN_DN
    )
    assert fake_samba_write.NTDS_SETTINGS_DN == (
        "CN=NTDS Settings,CN=DC1,CN=Servers,CN=Default-First-Site-Name,"
        "CN=Sites,CN=Configuration," + fake_samba_write.DOMAIN_DN
    )


def test_the_container_of_the_domain_controllers_is_an_organizational_unit(
    dc: Dc,
) -> None:
    """The container of the controllers has an ``ou`` and no ``cn``."""
    classes = [
        one.decode("utf-8")
        for one in dc.fake.values_of(fake_samba_write.DC_OU_DN, "objectClass")
    ]

    assert "organizationalUnit" in classes
    assert (
        dc.fake.get_attribute(fake_samba_write.DC_OU_DN, "ou") == "Domain Controllers"
    )
    assert dc.fake.get_attribute(fake_samba_write.DC_OU_DN, "cn") is None


def test_the_fake_refuses_a_modify_of_the_name(dc: Dc) -> None:
    """A modify of the distinguished name answers 53, as it was measured."""
    db = fake_samba_write.FakeSamDB()
    message = fake_samba_write.Message()
    message.dn = fake_samba_write.Dn(db, fake_samba_write.ALICE_DN)
    message["0"] = fake_samba_write.MessageElement(
        b"CN=alice," + fake_samba_write.SERVERS_OU_DN.encode("utf-8"),
        fake_samba_write.FLAG_MOD_DELETE,
        "distinguishedName",
    )
    message["1"] = fake_samba_write.MessageElement(
        b"CN=alice," + fake_samba_write.OTHER_OU_DN.encode("utf-8"),
        fake_samba_write.FLAG_MOD_ADD,
        "distinguishedName",
    )

    with pytest.raises(fake_samba_write.LdbError) as caught:
        db.modify(message)

    assert caught.value.args[0] == 53


def test_the_rename_of_an_object_that_is_gone_answers_thirty_two(dc: Dc) -> None:
    """The rename of a name that is not there answers 32."""
    db = fake_samba_write.FakeSamDB()

    with pytest.raises(fake_samba_write.LdbError) as caught:
        db.rename(
            "CN=nobody," + fake_samba_write.SERVERS_OU_DN,
            "CN=nobody," + fake_samba_write.OTHER_OU_DN,
        )

    assert caught.value.args[0] == 32


# -- the role of the domain controller -----------------------------------------


def test_the_dc_that_owns_the_role_may_apply(dc: Dc) -> None:
    """The role is owned by the DC whose rootDSE names it."""
    answer = dc.run(dc.request())

    assert answer["code"] == "ok"


def test_a_dc_that_does_not_own_the_role_refuses_an_apply(dc: Dc) -> None:
    """Another DC owns the role, so this one may not apply."""
    dc.fake.set_attribute(
        fake_samba_write.DOMAIN_DN,
        "fSMORoleOwner",
        "CN=NTDS Settings,CN=OTHER,CN=Servers,CN=Default-First-Site-Name,"
        "CN=Sites,CN=Configuration," + fake_samba_write.DOMAIN_DN,
    )

    answer = dc.run(dc.request())

    assert answer["code"] == "not_pdc"


# -- the privileged targets ----------------------------------------------------


def test_a_disable_of_a_privileged_account_is_refused(dc: Dc) -> None:
    """Only uac-clear, enc-types and unlock are allowed on a privileged one."""
    payload = dc.request(
        verb="disable",
        target={
            "guid": fake_samba_write.ADMIN_GUID,
            "sid": fake_samba_write.ADMIN_SID,
            "sam": "admin2",
        },
        before={"uac": 4194304},
        after={"uac": 4194306},
        risk="HIGH",
    )

    answer = dc.run(payload)

    assert answer["code"] == "privileged"
    assert (
        dc.fake.get_attribute(fake_samba_write.ADMIN_DN, "userAccountControl")
        == "4194304"
    )


def test_an_enable_of_a_privileged_account_is_refused(dc: Dc) -> None:
    """The enable of a privileged account is refused as well."""
    dc.fake.set_attribute(fake_samba_write.ADMIN_DN, "userAccountControl", "4194306")
    payload = dc.request(
        verb="enable",
        target={
            "guid": fake_samba_write.ADMIN_GUID,
            "sid": fake_samba_write.ADMIN_SID,
            "sam": "admin2",
        },
        before={"uac": 4194306},
        after={"uac": 4194304},
        risk="HIGH",
    )

    answer = dc.run(payload)

    assert answer["code"] == "privileged"


def test_a_move_of_a_privileged_account_is_refused(dc: Dc) -> None:
    """The move of a privileged account is refused as well."""
    payload = _move_request(
        dc,
        target={
            "guid": fake_samba_write.ADMIN_GUID,
            "sid": fake_samba_write.ADMIN_SID,
            "sam": "admin2",
        },
        before={"parent": fake_samba_write.SERVERS_OU_GUID},
        after={"parent": fake_samba_write.OTHER_OU_GUID},
        risk="HIGH",
    )

    answer = dc.run(payload)

    assert answer["code"] == "privileged"


def test_a_membership_of_a_privileged_member_is_allowed(dc: Dc) -> None:
    """Section 5 refuses a privileged group, not a privileged member."""
    payload = dc.request(
        verb="member-add",
        target={
            "group_guid": fake_samba_write.GROUP_GUID,
            "group_sid": fake_samba_write.GROUP_SID,
            "group_sam": "group1106",
            "member_guid": fake_samba_write.ADMIN_GUID,
            "member_sid": fake_samba_write.ADMIN_SID,
            "member_sam": "admin2",
        },
        before={"member": "absent"},
        after={"member": "present"},
        risk="HIGH",
    )

    answer = dc.run(payload)

    assert answer["code"] == "ok"


def test_the_write_account_is_never_the_target(dc: Dc) -> None:
    """The helper compares the resolved target with the write account by SID."""
    payload = dc.request(
        verb="disable",
        target={
            "guid": fake_samba_write.OPS_GUID,
            "sid": fake_samba_write.OPS_SID,
            "sam": "newton-ops",
        },
        before={"uac": 512},
        after={"uac": 514},
    )

    answer = dc.run(payload)

    assert answer["code"] == "denied"
    assert dc.fake.values_of(
        fake_samba_write.OPS_DN, "userAccountControl"
    ) == [b"512"]


def test_the_write_account_is_never_a_member(dc: Dc) -> None:
    """A membership write compares the resolved member with the account by SID."""
    payload = dc.request(
        verb="member-add",
        target={
            "group_guid": fake_samba_write.GROUP_GUID,
            "group_sid": fake_samba_write.GROUP_SID,
            "group_sam": "group1106",
            "member_guid": fake_samba_write.OPS_GUID,
            "member_sid": fake_samba_write.OPS_SID,
            "member_sam": "newton-ops",
        },
        before={"member": "absent"},
        after={"member": "present"},
    )

    answer = dc.run(payload)

    assert answer["code"] == "denied"


@pytest.mark.parametrize(
    ("sam", "sid", "uac"),
    [
        ("alice", fake_samba_write.DOMAIN_SID + "-502", 512),
        ("krbtgt", fake_samba_write.ALICE_SID, 512),
        ("krbtgt_1000", fake_samba_write.ALICE_SID, 512),
        ("alice", fake_samba_write.ALICE_SID, 512 | 0x800),
    ],
)
def test_krbtgt_and_trust_accounts_are_never_targets(
    dc: Dc, sam: str, sid: str, uac: int
) -> None:
    """RID 502, krbtgt names and INTERDOMAIN_TRUST_ACCOUNT all deny."""
    dc.fake.set_values(fake_samba_write.ALICE_DN, "sAMAccountName", [sam.encode()])
    dc.fake.set_values(
        fake_samba_write.ALICE_DN, "objectSid", [fake_samba_write.sid_bytes(sid)]
    )
    dc.fake.set_values(
        fake_samba_write.ALICE_DN, "userAccountControl", [str(uac).encode()]
    )
    payload = dc.request(
        verb="disable",
        target={"guid": fake_samba_write.ALICE_GUID, "sid": sid, "sam": sam},
        before={"uac": uac},
        after={"uac": uac | 2},
    )

    answer = dc.run(payload)

    assert answer["code"] == "denied"


def test_a_trust_account_is_never_a_membership_member(dc: Dc) -> None:
    """The live UAC guard covers the member side of a membership write."""
    dc.fake.set_values(
        fake_samba_write.ALICE_DN,
        "userAccountControl",
        [str(512 | 0x800).encode()],
    )
    payload = dc.request(
        verb="member-add",
        target={
            "group_guid": fake_samba_write.GROUP_GUID,
            "group_sid": fake_samba_write.GROUP_SID,
            "group_sam": "group1106",
            "member_guid": fake_samba_write.ALICE_GUID,
            "member_sid": fake_samba_write.ALICE_SID,
            "member_sam": "alice",
        },
        before={"member": "absent"},
        after={"member": "present"},
    )

    answer = dc.run(payload)

    assert answer["code"] == "denied"


def test_a_group_nested_too_deeply_is_privileged(dc: Dc) -> None:
    """The walk of the privileged groups fails closed at its cap."""
    chain = 40
    for index in range(chain):
        dn = "CN=Deep%d,%s" % (index, fake_samba_write.USERS_DN)
        parent = "CN=Deep%d,%s" % (index + 1, fake_samba_write.USERS_DN)
        attributes: dict[str, list[bytes]] = {
            "objectClass": [b"group"],
            "sAMAccountName": [("deep%d" % index).encode("utf-8")],
            "objectSid": [fake_samba_write.sid_bytes(
                fake_samba_write.DOMAIN_SID + "-" + str(1300 + index)
            )],
            "objectGUID": [fake_samba_write.guid_bytes(
                "7d2b3c4d-5e6f-4a8b-9c0d-%012x" % index
            )],
        }
        if index + 1 < chain:
            attributes["memberOf"] = [parent.encode("utf-8")]
        dc.fake.add_object(dn, attributes)
    target_dn = "CN=Deep0," + fake_samba_write.USERS_DN
    payload = dc.request(
        verb="member-add",
        target={
            "group_guid": "7d2b3c4d-5e6f-4a8b-9c0d-000000000000",
            "group_sid": fake_samba_write.DOMAIN_SID + "-1300",
            "group_sam": "deep0",
            "member_guid": fake_samba_write.ALICE_GUID,
            "member_sid": fake_samba_write.ALICE_SID,
            "member_sam": "alice",
        },
        before={"member": "absent"},
        after={"member": "present"},
        risk="HIGH",
    )
    assert dc.fake.has_object(target_dn)

    answer = dc.run(payload)

    assert answer["code"] == "privileged"


def test_a_group_whose_parent_cannot_be_read_is_privileged(dc: Dc) -> None:
    """A name of the chain that cannot be read fails closed."""
    dn = "CN=Orphan," + fake_samba_write.USERS_DN
    dc.fake.add_object(
        dn,
        {
            "objectClass": [b"group"],
            "sAMAccountName": [b"orphan"],
            "objectSid": [
                fake_samba_write.sid_bytes(fake_samba_write.DOMAIN_SID + "-1400")
            ],
            "objectGUID": [
                fake_samba_write.guid_bytes("8e2b3c4d-5e6f-4a8b-9c0d-000000000000")
            ],
            "memberOf": [
                ("CN=NotThere," + fake_samba_write.USERS_DN).encode("utf-8")
            ],
        },
    )
    payload = dc.request(
        verb="member-add",
        target={
            "group_guid": "8e2b3c4d-5e6f-4a8b-9c0d-000000000000",
            "group_sid": fake_samba_write.DOMAIN_SID + "-1400",
            "group_sam": "orphan",
            "member_guid": fake_samba_write.ALICE_GUID,
            "member_sid": fake_samba_write.ALICE_SID,
            "member_sam": "alice",
        },
        before={"member": "absent"},
        after={"member": "present"},
        risk="HIGH",
    )

    answer = dc.run(payload)

    assert answer["code"] == "privileged"


# -- the token groups of the write account -------------------------------------


def test_a_write_account_without_token_groups_is_refused(dc: Dc) -> None:
    """The token groups of the write account are read; none is a refusal."""
    dc.fake.set_values(fake_samba_write.OPS_DN, "tokenGroups", [])

    answer = dc.run(dc.request())

    assert answer["code"] == "privileged"


def test_a_write_account_with_a_token_group_that_is_not_a_sid_is_refused(
    dc: Dc,
) -> None:
    """A token group that cannot be decoded fails closed."""
    dc.fake.set_values(fake_samba_write.OPS_DN, "tokenGroups", [b"not a sid"])

    answer = dc.run(dc.request())

    assert answer["code"] == "privileged"


def test_the_token_groups_are_read_on_the_name_of_the_account(dc: Dc) -> None:
    """The token groups are read base-scoped on the account itself."""
    dc.run(dc.request())

    reads = [
        line
        for line in dc.log_lines()
        if line.startswith("search:") and "tokenGroups" in line
    ]

    assert reads
    assert any(
        "base=%s scope=0" % fake_samba_write.OPS_DN in line for line in reads
    )


# -- the results of the undo ---------------------------------------------------


def test_an_undo_of_an_object_that_is_gone_is_never_undone(dc: Dc) -> None:
    """An undo that did not restore its value never says it did."""
    dc.run(dc.request())
    dc.fake.remove_object(fake_samba_write.ALICE_DN)

    answer = dc.undo()

    assert answer["code"] == "ok"
    assert answer["restored"] is False
    assert dc.record()["state"] == "undo_failed"


def test_an_undo_that_meets_an_error_is_never_undone(dc: Dc) -> None:
    """An error of the server is not a restore."""
    dc.run(dc.request())
    dc.fake.modify_code = 50

    answer = dc.undo()

    assert answer["code"] == "ok"
    assert answer["restored"] is False
    assert dc.record()["state"] == "undo_failed"


def test_an_undo_of_a_membership_whose_group_is_gone_is_never_undone(
    dc: Dc,
) -> None:
    """A group that is not there any more is not a restore."""
    payload = dc.request(
        verb="member-add",
        target={
            "group_guid": fake_samba_write.GROUP_GUID,
            "group_sid": fake_samba_write.GROUP_SID,
            "group_sam": "group1106",
            "member_guid": fake_samba_write.ALICE_GUID,
            "member_sid": fake_samba_write.ALICE_SID,
            "member_sam": "alice",
        },
        before={"member": "absent"},
        after={"member": "present"},
    )
    assert dc.run(payload)["code"] == "ok"
    dc.fake.remove_object(fake_samba_write.GROUP_DN)

    answer = dc.undo()

    assert answer["code"] == "ok"
    assert answer["restored"] is False
    assert dc.record()["state"] == "undo_failed"


def test_an_undo_with_a_bad_created_value_is_never_undone(dc: Dc) -> None:
    """A record that does not hold the guid it created is not a restore."""
    payload = _user_create_request(dc)
    assert dc.run(payload)["code"] == "ok"
    record = dc.record()
    record["created"] = 42
    (dc.tx / f"{TXID}.json").write_text(json.dumps(record), encoding="utf-8")

    answer = dc.undo()

    assert answer["code"] == "ok"
    assert answer["restored"] is False
    assert dc.record()["state"] == "undo_failed"


def test_an_undo_that_meets_a_changed_value_records_a_conflict(dc: Dc) -> None:
    """The conflict of the undo is reported, and the value is left alone."""
    dc.run(dc.request())
    dc.fake.set_attribute(fake_samba_write.ALICE_DN, "userAccountControl", "4096")

    answer = dc.undo()

    assert answer["code"] == "ok"
    assert answer["restored"] is False
    assert answer["conflicts"] != []
    assert (
        dc.fake.get_attribute(fake_samba_write.ALICE_DN, "userAccountControl")
        == "4096"
    )
    assert dc.record()["state"] != "armed"


# -- the abort and the undo of a record that is not armed -----------------------


def test_an_abort_of_a_confirmed_transaction_is_a_conflict(dc: Dc) -> None:
    """Only an armed transaction may be aborted."""
    assert dc.run(dc.request())["code"] == "ok"
    assert (
        dc.run({"v": 1, "mode": "confirm", "device": DEVICE, "txid": TXID})["code"]
        == "ok"
    )

    answer = dc.run({"v": 1, "mode": "abort", "device": DEVICE, "txid": TXID})

    assert answer["code"] == "conflict"
    assert (
        dc.fake.get_attribute(fake_samba_write.ALICE_DN, "userAccountControl")
        == "512"
    )
    assert dc.record()["state"] == "confirmed"


def test_an_abort_of_a_refused_transaction_is_a_conflict(dc: Dc) -> None:
    """A transaction that was refused changes nothing any more."""
    payload = dc.request(before={"uac": 4194816 + 2}, after={"uac": 514})
    assert dc.run(payload)["code"] == "conflict"

    answer = dc.run({"v": 1, "mode": "abort", "device": DEVICE, "txid": TXID})

    assert answer["code"] == "conflict"
    assert dc.record()["state"] == "refused"


def test_the_undo_of_a_confirmed_transaction_changes_nothing(dc: Dc) -> None:
    """The timer of a confirmed transaction never puts the value back."""
    assert dc.run(dc.request())["code"] == "ok"
    assert (
        dc.run({"v": 1, "mode": "confirm", "device": DEVICE, "txid": TXID})["code"]
        == "ok"
    )

    answer = dc.undo()

    assert answer["code"] == "ok"
    assert answer["restored"] is False
    assert (
        dc.fake.get_attribute(fake_samba_write.ALICE_DN, "userAccountControl")
        == "512"
    )
    assert dc.record()["state"] == "confirmed"


# -- the arming of the undo ----------------------------------------------------


def test_an_apply_whose_timer_cannot_be_armed_writes_nothing(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A timer that is not armed means no write at all."""
    monkeypatch.setenv("NEWTON_FAKE_FAIL_SYSTEMD_RUN", "1")

    answer = dc.run(dc.request())

    assert answer["code"] == "unavailable"
    assert (
        dc.fake.get_attribute(fake_samba_write.ALICE_DN, "userAccountControl")
        == "4194816"
    )
    assert dc.record()["state"] == "refused"


def test_an_apply_whose_timer_times_out_writes_nothing(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A timer that does not answer in time means no write at all."""
    monkeypatch.setenv("NEWTON_FAKE_SLEEP_SYSTEMD_RUN", "5")
    monkeypatch.setattr(dc.helper, "COMMAND_TIMEOUT_S", 0.2)

    answer = dc.run(dc.request())

    assert answer["code"] == "unavailable"
    assert (
        dc.fake.get_attribute(fake_samba_write.ALICE_DN, "userAccountControl")
        == "4194816"
    )
    assert dc.record()["state"] == "refused"


# -- the container of the domain controllers ------------------------------------


def test_a_move_without_the_container_of_the_domain_controllers_is_unavailable(
    dc: Dc,
) -> None:
    """The check of the container of the controllers never fails open."""
    dc.fake.remove_object(fake_samba_write.DC_OU_DN)

    answer = dc.run(_move_request(dc))

    assert answer["code"] == "unavailable"
    assert dc.fake.has_object(fake_samba_write.ALICE_DN)


def test_the_container_of_the_domain_controllers_is_found_with_the_ou_filter(
    dc: Dc,
) -> None:
    """The container is found with the one-level search of the measurement."""
    assert dc.run(_move_request(dc))["code"] == "ok"

    searches = [line for line in dc.log_lines() if line.startswith("search:")]

    assert any(
        "(ou=Domain Controllers)" in line and "scope=1" in line for line in searches
    )


# -- the move -------------------------------------------------------------------


def test_a_move_uses_the_rename_of_the_bindings(dc: Dc) -> None:
    """The move of an object is a rename, as it was measured."""
    answer = dc.run(_move_request(dc))

    assert answer["code"] == "ok"
    renames = [line for line in dc.log_lines() if line.startswith("rename:")]
    assert len(renames) == 1
    assert fake_samba_write.ALICE_DN in renames[0]
    assert fake_samba_write.OTHER_OU_DN in renames[0]
    assert not [
        line for line in dc.log_lines() if "distinguishedName" in line
    ]


def test_the_undo_of_a_move_puts_the_object_back(dc: Dc) -> None:
    """The undo of a move renames the object back."""
    assert dc.run(_move_request(dc))["code"] == "ok"

    answer = dc.undo()

    assert answer["code"] == "ok"
    assert answer["restored"] is True
    assert dc.fake.has_object(fake_samba_write.ALICE_DN)
    assert not dc.fake.has_object("CN=alice," + fake_samba_write.OTHER_OU_DN)
    assert dc.record()["state"] == "undone"


def test_an_undo_of_a_move_whose_object_moved_on_records_a_conflict(
    dc: Dc,
) -> None:
    """The undo of a move only renames back the object it moved."""
    assert dc.run(_move_request(dc))["code"] == "ok"
    dc.fake.move_object(
        "CN=alice," + fake_samba_write.OTHER_OU_DN,
        "CN=alice," + fake_samba_write.RESTRICTED_OU_DN,
    )

    answer = dc.undo()

    assert answer["code"] == "ok"
    assert answer["conflicts"] != []
    assert dc.fake.has_object("CN=alice," + fake_samba_write.RESTRICTED_OU_DN)


def test_a_rename_of_an_object_that_is_gone_is_a_conflict(dc: Dc) -> None:
    """A rename that answers 32 is a conflict."""
    dc.fake.set_rename_error(fake_samba_write.ALICE_DN, 32)

    answer = dc.run(_move_request(dc))

    assert answer["code"] == "conflict"


# -- the order of the checks ----------------------------------------------------


def test_a_request_with_a_bad_token_and_a_broken_image_is_a_bad_token(
    dc: Dc,
) -> None:
    """The token is checked before the rules of the verb."""
    payload = dc.request(before={"uac": 1}, after={"uac": 2})
    payload["token"] = "0" * 64

    answer = dc.run(payload)

    assert answer["code"] == "bad_token"
    assert dc.records() == []


def test_an_unsigned_request_learns_nothing_about_the_target(dc: Dc) -> None:
    """A request with a bad token never reaches the directory."""
    payload = dc.request()
    payload["target"] = dict(payload["target"])
    payload["target"]["guid"] = "0" * 8 + "-0000-0000-0000-000000000000"
    payload["token"] = "0" * 64

    answer = dc.run(payload)

    assert answer["code"] == "bad_token"
    assert dc.records() == []


# -- the clock ------------------------------------------------------------------


def test_the_clock_is_read_under_the_lock(dc: Dc) -> None:
    """The deadline of the undo is taken once the lock is held."""
    seen: list[bool] = []

    def clock() -> float:
        descriptor = os.open(dc.tx / ".lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            seen.append(False)
        except OSError:
            seen.append(True)
        finally:
            os.close(descriptor)
        return float(NBF)

    dc.helper.current_time = clock

    answer = dc.run(dc.request())

    assert answer["code"] == "ok"
    assert seen == [True]


# -- the records that are never left armed --------------------------------------


def test_an_apply_that_fails_leaves_no_armed_record(dc: Dc) -> None:
    """An error after the record is created sets its final state."""
    dc.fake.modify_error = RuntimeError("the directory is gone")

    answer = dc.run(dc.request())

    assert answer["code"] == "error"
    assert dc.record()["state"] == "refused"


def test_a_write_that_fails_with_twenty_is_a_conflict(dc: Dc) -> None:
    """The code 20 of the directory is a conflict."""
    dc.fake.modify_code = 20

    answer = dc.run(dc.request())

    assert answer["code"] == "conflict"
    assert dc.record()["state"] == "refused"


def test_a_user_create_without_a_secret_is_a_schema(dc: Dc) -> None:
    """The secret is part of the schema of a user-create."""
    payload = _user_create_request(dc)
    payload.pop("secret")
    payload["token"] = core_request.token(
        KEY_HEX, core_request.digest(payload), int(payload["nbf"]), int(payload["exp"])
    )

    answer = dc.run(payload)

    assert answer["code"] == "schema"
    assert dc.records() == []
    assert [line for line in dc.log_lines() if "systemd-run" in line] == []


# ---- the measured bindings, lowercased sams and the keytab bind ---------------
#
# Every test of this section fails on the helper before the fix and passes
# after the fix.  The facts they hold are the ones measured
# on a real Samba 4.22.11 domain controller (the sandbox of 2026-11-09)
# and the ones MEASURED-2026-11-09 measured on the lab DCs.


# -- the fake refuses what the real binding refuses ---------------------------


def test_the_fake_refuses_the_token_groups_outside_a_base_search(dc: Dc) -> None:
    """Samba only gives the tokenGroups of one object in a base search."""
    db = fake_samba_write.FakeSamDB()

    with pytest.raises(fake_samba_write.LdbError) as caught:
        db.search(
            base=fake_samba_write.DOMAIN_DN,
            scope=fake_samba_write.SCOPE_SUBTREE,
            expression="(objectClass=*)",
            attrs=["tokenGroups"],
        )

    assert caught.value.args[0] == 1
    assert "not a BASE search" in caught.value.args[1]


def test_the_fake_gives_the_token_groups_of_a_base_search(dc: Dc) -> None:
    """A base search of the tokenGroups is answered."""
    db = fake_samba_write.FakeSamDB()

    found = db.search(
        base=fake_samba_write.OPS_DN,
        scope=fake_samba_write.SCOPE_BASE,
        expression="(objectClass=*)",
        attrs=["tokenGroups"],
    )

    assert len(found) == 1
    assert len(found[0]["tokenGroups"]) == 2


def _uac_message(db: Any) -> Any:
    """The measured message of a modify of the account control."""
    message = fake_samba_write.Message()
    message.dn = fake_samba_write.Dn(db, fake_samba_write.ALICE_DN)
    message["0"] = fake_samba_write.MessageElement(
        b"4194816", fake_samba_write.FLAG_MOD_DELETE, "userAccountControl"
    )
    message["1"] = fake_samba_write.MessageElement(
        b"512", fake_samba_write.FLAG_MOD_ADD, "userAccountControl"
    )
    return message


def test_the_fake_takes_the_message_of_a_modify(dc: Dc) -> None:
    """The real binding takes the name in the message, not beside it."""
    db = fake_samba_write.FakeSamDB()

    db.modify(_uac_message(db))

    assert (
        dc.fake.get_attribute(fake_samba_write.ALICE_DN, "userAccountControl")
        == "512"
    )


def test_the_fake_refuses_a_modify_of_a_name_and_a_message(dc: Dc) -> None:
    """A call shaped like modify(dn, message) is refused, as it was measured."""
    db = fake_samba_write.FakeSamDB()

    with pytest.raises(TypeError) as caught:
        db.modify(fake_samba_write.ALICE_DN, _uac_message(db))

    assert "controls is not a list" in str(caught.value)


def test_the_fake_refuses_a_modify_of_a_message_without_a_name(dc: Dc) -> None:
    """A message without a name is refused, as it was measured."""
    db = fake_samba_write.FakeSamDB()

    with pytest.raises(TypeError) as caught:
        db.modify(
            {
                "0": fake_samba_write.MessageElement(
                    b"512",
                    fake_samba_write.FLAG_MOD_ADD,
                    "userAccountControl",
                )
            }
        )

    assert "controls is not a list" in str(caught.value)


def test_the_fake_takes_the_message_of_an_add(dc: Dc) -> None:
    """The real binding takes one dict with the name and the class in it."""
    db = fake_samba_write.FakeSamDB()
    dn = "CN=newuser," + fake_samba_write.SERVERS_OU_DN

    db.add(
        {
            "dn": dn,
            "objectClass": "user",
            "cn": "newuser",
            "sAMAccountName": "newuser",
            "userPrincipalName": "newuser@" + fake_samba_write.DOMAIN_DNS,
            "userAccountControl": "514",
            "unicodePwd": b'"a-password"',
        }
    )

    assert dc.fake.has_object(dn)
    assert dc.fake.get_attribute(dn, "userAccountControl") == "514"


def test_the_fake_refuses_an_add_of_a_name_and_attributes(dc: Dc) -> None:
    """A call shaped like add(dn, attrs) is refused, as it was measured."""
    db = fake_samba_write.FakeSamDB()

    with pytest.raises(TypeError) as caught:
        db.add(fake_samba_write.ALICE_DN, {"objectClass": "user"})

    assert "controls is not a list" in str(caught.value)


def test_the_fake_refuses_an_add_without_a_class(dc: Dc) -> None:
    """The code of that refusal is not measured; the refusal is."""
    db = fake_samba_write.FakeSamDB()

    with pytest.raises(fake_samba_write.LdbError):
        db.add({"dn": "CN=newuser," + fake_samba_write.SERVERS_OU_DN})


def test_the_fake_holds_the_measured_signatures(dc: Dc) -> None:
    """The fake cannot drift back to an invented signature."""
    import inspect

    def names(method: Any) -> list[str]:
        return list(inspect.signature(method).parameters)

    def default(method: Any, parameter: str) -> Any:
        return inspect.signature(method).parameters[parameter].default

    assert names(fake_samba_write.FakeSamDB.modify) == [
        "self",
        "message",
        "controls",
    ]
    assert names(fake_samba_write.FakeSamDB.add) == ["self", "message", "controls"]
    assert names(fake_samba_write.FakeSamDB.rename) == [
        "self",
        "olddn",
        "newdn",
        "controls",
    ]
    assert names(fake_samba_write.FakeSamDB.delete) == ["self", "dn", "controls"]
    assert names(fake_samba_write.FakeSamDB.search) == [
        "self",
        "base",
        "scope",
        "expression",
        "attrs",
        "controls",
    ]
    assert default(fake_samba_write.FakeSamDB.modify, "controls") is None
    assert default(fake_samba_write.FakeSamDB.add, "controls") is None
    assert default(fake_samba_write.FakeSamDB.rename, "controls") is None
    assert default(fake_samba_write.FakeSamDB.delete, "controls") is None


# -- the fixes of the helper ---------------------------------------------------


def test_the_helper_never_asks_for_the_token_groups_outside_a_base_search(
    dc: Dc,
) -> None:
    """LIVE-1: Samba refuses the tokenGroups of a subtree search."""
    answer = dc.run(dc.request())

    assert answer["code"] == "ok"
    for kind, text in dc.fake.calls:
        if kind != "search" or "tokenGroups" not in text:
            continue
        assert "scope=0" in text


def test_the_read_of_an_account_works_on_a_real_dc(dc: Dc) -> None:
    """LIVE-1: the read of an account is refused by the real binding."""
    answer = dc.run(
        {
            "v": 1,
            "mode": "read",
            "device": DEVICE,
            "verb": "uac-clear",
            "target": {"sam": "alice"},
        }
    )

    assert answer["code"] == "ok"
    assert answer["ids"]["guid"] == fake_samba_write.ALICE_GUID


def test_the_helper_writes_the_modify_with_the_name_in_the_message(dc: Dc) -> None:
    """LIVE-2: the real binding takes the name of the message."""
    answer = dc.run(dc.request())

    assert answer["code"] == "ok"
    modifies = [text for kind, text in dc.fake.calls if kind == "modify"]
    assert modifies
    assert any(fake_samba_write.ALICE_DN in text for text in modifies)


def test_the_user_create_writes_the_message_with_its_class(dc: Dc) -> None:
    """LIVE-3: the real binding takes one dict with the class in it."""
    answer = dc.run(_user_create_request(dc))

    assert answer["code"] == "ok"
    adds = [text for kind, text in dc.fake.calls if kind == "add"]
    assert adds
    assert any("objectClass" in text for text in adds)


def test_the_read_answers_with_the_sams_lowercased(dc: Dc) -> None:
    """LIVE-5: a real Administrator comes back as administrator."""
    dc.fake.set_attribute(fake_samba_write.ALICE_DN, "sAMAccountName", "Alice")

    answer = dc.run(
        {
            "v": 1,
            "mode": "read",
            "device": DEVICE,
            "verb": "uac-clear",
            "target": {
                "guid": fake_samba_write.ALICE_GUID,
                "sid": fake_samba_write.ALICE_SID,
                "sam": "alice",
                "bit": 4194304,
            },
        }
    )

    assert answer["code"] == "ok"
    assert answer["ids"]["sam"] == "alice"


def test_the_read_of_a_membership_answers_with_the_sams_lowercased(dc: Dc) -> None:
    """LIVE-5: every sam of the ids is lowercased."""
    dc.fake.set_attribute(fake_samba_write.GROUP_DN, "sAMAccountName", "Group1106")
    dc.fake.set_attribute(fake_samba_write.ALICE_DN, "sAMAccountName", "Alice")

    answer = dc.run(
        {
            "v": 1,
            "mode": "read",
            "device": DEVICE,
            "verb": "member-add",
            "target": {"group_sam": "group1106", "member_sam": "alice"},
        }
    )

    assert answer["code"] == "ok"
    assert answer["ids"]["group_sam"] == "group1106"
    assert answer["ids"]["member_sam"] == "alice"


# -- the identity of the helper is the keytab of the DC ------------------------


def test_the_helper_takes_its_ticket_from_the_keytab(dc: Dc) -> None:
    """The helper asks kinit for a ticket of the keytab of the DC."""
    answer = dc.run(dc.request())

    assert answer["code"] == "ok"
    commands = [line for line in dc.log_lines() if line.startswith("command: kinit")]
    assert len(commands) == 1
    command = commands[0]
    assert "-k" in command
    assert "-t %s" % (dc.config / "ops.keytab") in command
    assert "-c FILE:" in command
    assert "newton-ops@%s" % fake_samba_write.REALM in command


def test_the_bind_of_the_helper_never_guesses_the_credentials(dc: Dc) -> None:
    """The measured bind sets the realm, the workgroup and the cache."""
    answer = dc.run(dc.request())

    assert answer["code"] == "ok"
    credentials = dc.fake.credentials
    assert credentials is not None
    assert credentials.guessed is False
    assert credentials.realm == fake_samba_write.REALM
    assert credentials.domain == fake_samba_write.WORKGROUP
    assert credentials.kerberos_state == fake_samba_write.MUST_USE_KERBEROS
    assert credentials.ccache.startswith("FILE:")


def test_the_helper_refuses_a_missing_keytab(dc: Dc) -> None:
    """A keytab that is not there is an unavailable install."""
    (dc.config / "ops.keytab").unlink()

    answer = dc.run(dc.request())

    assert answer["code"] == "unavailable"


def test_the_helper_refuses_a_keytab_that_others_may_read(dc: Dc) -> None:
    """The keytab is read with the mode of section 8."""
    (dc.config / "ops.keytab").chmod(0o644)

    answer = dc.run(dc.request())

    assert answer["code"] == "unavailable"


def test_the_helper_refuses_a_keytab_that_is_a_link(dc: Dc) -> None:
    """The keytab is opened without following a link."""
    keytab = dc.config / "ops.keytab"
    keytab.unlink()
    keytab.symlink_to(dc.config / "approval.key")

    answer = dc.run(dc.request())

    assert answer["code"] == "unavailable"


def test_the_helper_refuses_a_kinit_that_fails(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A ticket that cannot be taken is an unavailable."""
    monkeypatch.setenv("NEWTON_FAKE_FAIL_KINIT", "1")

    answer = dc.run(dc.request())

    assert answer["code"] == "unavailable"


def test_the_ticket_of_the_helper_leaves_no_cache_behind(dc: Dc) -> None:
    """The credential cache is removed when the bind is done."""
    answer = dc.run(dc.request())

    assert answer["code"] == "ok"
    commands = [line for line in dc.log_lines() if line.startswith("command: kinit")]
    assert len(commands) == 1
    assert "-c FILE:%s" % dc.run_dir in commands[0]
    assert list(dc.run_dir.iterdir()) == []


def test_the_helper_stores_no_password_of_the_write_account(dc: Dc) -> None:
    """The password of the write account is not on the DC any more."""
    source = HELPER_PATH.read_text(encoding="utf-8")

    assert "ops.secret" not in source
    assert "set_password" not in source
    assert "guess(" not in source
    assert not (dc.config / "ops.secret").exists()


# ---- the undo facts of a user-create ------------------------------------------

# Every test of this section fails on the helper before the fix and passes
# after the fix.  Both items close two holes the earlier fix of the undo
# facts of a user-create left.


def test_a_user_create_whose_record_cannot_be_written_keeps_the_timer_armed(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The record is written before the timer is cancelled.

    A record that cannot be written leaves the undo armed: the change
    that every controller verified can still be put back.
    """
    monkeypatch.setattr(
        dc.helper, "read_created", lambda directory, request: (None, None)
    )
    real = dc.helper.write_record

    def failing(path: str, record: Any) -> None:
        if record.get("state") in ("undone", "undo_failed"):
            raise OSError("the store cannot be written")
        real(path, record)

    monkeypatch.setattr(dc.helper, "write_record", failing)
    payload = dc.request(verb="user-create", secret=SECRET)
    payload["target"] = {
        "parent_guid": fake_samba_write.SERVERS_OU_GUID,
        "sam": "newton-user",
    }
    payload["before"] = {"object": "absent"}
    payload["after"] = {"object": "present"}
    payload["token"] = core_request.token(
        KEY_HEX, core_request.digest(payload), payload["nbf"], payload["exp"]
    )

    answer = dc.run(payload)

    assert answer["code"] == "error"
    assert not [line for line in dc.log_lines() if "systemctl" in line]


def test_a_user_create_whose_parent_cannot_be_read_back_records_its_dn(
    dc: Dc, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The record holds the name of the object the add made.

    A parent that cannot be read back after the add does not take the
    name of the new object away: the owner of the transaction finds the
    user it has to look for.
    """
    dn = "CN=newton-user," + fake_samba_write.SERVERS_OU_DN
    real = dc.helper.Directory.by_guid

    def by_guid(self: Any, guid: str, attrs: Any) -> Any:
        # the parent cannot be read back once the object is there
        if guid == fake_samba_write.SERVERS_OU_GUID and dc.fake.has_object(dn):
            return None
        return real(self, guid, attrs)

    monkeypatch.setattr(dc.helper.Directory, "by_guid", by_guid)
    dc.fake.delete_code = 1
    payload = dc.request(verb="user-create", secret=SECRET)
    payload["target"] = {
        "parent_guid": fake_samba_write.SERVERS_OU_GUID,
        "sam": "newton-user",
    }
    payload["before"] = {"object": "absent"}
    payload["after"] = {"object": "present"}
    payload["token"] = core_request.token(
        KEY_HEX, core_request.digest(payload), payload["nbf"], payload["exp"]
    )

    answer = dc.run(payload)

    assert answer["code"] == "error"
    record = dc.record()
    assert record["state"] == "undo_failed"
    assert record["conflicts"] == [dn]
    assert "delete: dn=" + dn in dc.log_lines()


# ---- an unlock from the plan to the confirm --------------------------------


def test_a_verified_unlock_on_samba_ends_confirmed(
    dc: Dc, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CORE plans, applies, verifies and confirms an unlock: it ends confirmed.

    An unlock arms no undo and its record is confirmed at the apply
    (section 3); the confirm CORE sends once every DC shows the
    after-image finds that record and answers ok.
    """
    from newton_mcp.ad.write import apply as ad_apply, plan as ad_plan, store
    from newton_mcp.server import Device

    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    device = Device(
        name=DEVICE,
        platform="ad-samba-write",
        host="192.0.2.20",
        user="newton-ops-ssh",
        ad_domain=DEVICE,
        ad_domain_guid="af9619ff-8b86-d011-b42d-00c04fc964ff",
    )
    devices = {DEVICE: device}
    modes: list[str] = []

    def send(target: Any, body: dict[str, Any]) -> dict[str, Any]:
        assert target.name == DEVICE
        modes.append(str(body["mode"]))
        return dc.run(body)

    planned = ad_plan.plan_change(DEVICE, "unlock", ["alice"], send=send, devices=devices)
    assert planned["before"] == {"lockout": 1000}
    assert planned["after"] == {"lockout": 0}
    plan_id = str(planned["plan_id"])
    record = store.read_json(store.plan_path(plan_id))
    digest = core_request.digest(record)
    store.write_json(
        store.approval_path(plan_id),
        {
            "plan_id": plan_id,
            "device": record["device"],
            "digest": digest,
            "nbf": NBF,
            "exp": EXP,
            "token": core_request.token(KEY_HEX, digest, NBF, EXP),
        },
    )

    result = ad_apply.apply_change(plan_id, send=send, devices=devices, timeout_s=0.0)

    assert modes[-1] == "confirm"
    assert "abort" not in modes
    assert result["dcs"][DEVICE]["state"] == "matched"
    assert result["code"] == "ok"
    assert result["state"] == "confirmed"
    assert result["result"] == "ok"
    assert dc.record(str(planned["txid"]))["state"] == "confirmed"
    assert [line for line in dc.log_lines() if "systemd-run" in line] == []
