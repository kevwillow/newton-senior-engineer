"""The AD change plan (DESIGN-1.4 section 1).

The plan is built from two reads of the domain controller, it is written
under the state directory with mode 0600 and it never carries the
password of a user-create in its result.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import harness
import pytest

from newton_mcp.ad.write import plan, store
from newton_mcp.ad.write.errors import WriteError


@pytest.fixture(autouse=True)
def state_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The state directory of the test."""
    root = tmp_path / "state"
    monkeypatch.setenv("NEWTON_STATE_DIR", str(root))
    return root


def _lab(**kwargs: object) -> harness.Lab:
    lab = harness.Lab(**kwargs)  # type: ignore[arg-type]
    lab.add_user(uac=4260352)
    return lab


def test_the_plan_reads_the_pdc_twice() -> None:
    """The first read resolves the names, the second takes the before-image."""
    lab = _lab()
    calls: list[dict[str, object]] = []

    def send(target: object, request: dict[str, object]) -> dict[str, object]:
        calls.append({"device": target.name, **request})  # type: ignore[attr-defined]
        return lab.send(target, request)  # type: ignore[arg-type]

    result = plan.plan_change(
        harness.DOMAIN, "uac-clear", ["seed-asrep"], 4194304,
        send=send, devices=lab.devices,
    )

    assert result["result"] == "ok"
    reads = [one for one in calls if one["mode"] == "read"]
    assert len(reads) == 3  # one per DC to find the PDC, then the before-image
    assert reads[0]["target"] == {"sam": "seed-asrep"}
    assert reads[-1]["device"] == "win-dc1"
    assert reads[-1]["target"] == {
        "guid": harness.SEED_GUID,
        "sid": harness.SEED_SID,
        "sam": harness.SEED_SAM,
        "bit": 4194304,
    }


def test_the_plan_holds_the_before_and_the_after_image() -> None:
    """The plan holds the images the verb computes."""
    lab = _lab()

    result = plan.plan_change(
        harness.DOMAIN, "uac-clear", ["seed-asrep"], 4194304,
        send=lab.send, devices=lab.devices,
    )

    assert result["before"] == {"uac": 4260352}
    assert result["after"] == {"uac": 66048}
    assert result["risk"] == "MED"
    assert result["window"] == 600


def test_the_plan_is_written_with_mode_0600() -> None:
    """The plan file belongs to the owner alone."""
    lab = _lab()

    result = plan.plan_change(
        harness.DOMAIN, "uac-clear", ["seed-asrep"], 4194304,
        send=lab.send, devices=lab.devices,
    )

    path = store.plan_path(result["plan_id"])
    assert path.exists()
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600


def test_the_plan_holds_a_fresh_transaction_id() -> None:
    """Every plan gets its own transaction id."""
    lab = _lab()

    first = plan.plan_change(
        harness.DOMAIN, "uac-clear", ["seed-asrep"], 4194304,
        send=lab.send, devices=lab.devices,
    )
    second = plan.plan_change(
        harness.DOMAIN, "uac-clear", ["seed-asrep"], 4194304,
        send=lab.send, devices=lab.devices,
    )

    assert first["txid"] != second["txid"]
    assert len(first["txid"]) == 32
    assert first["plan_id"] != second["plan_id"]


def test_the_risk_of_an_unlock_is_low() -> None:
    """An unlock arms no undo."""
    lab = harness.Lab()
    lab.add_user(uac=512, lockout=5)

    result = plan.plan_change(
        harness.DOMAIN, "unlock", ["seed-asrep"], None,
        send=lab.send, devices=lab.devices,
    )

    assert result["risk"] == "LOW"
    assert result["window"] == 120


def test_the_risk_of_a_privileged_target_is_high() -> None:
    """A privileged target is HIGH."""
    lab = harness.Lab()
    lab.add_user(uac=4260352, privileged=True)

    result = plan.plan_change(
        harness.DOMAIN, "uac-clear", ["seed-asrep"], 4194304,
        send=lab.send, devices=lab.devices,
    )

    assert result["risk"] == "HIGH"


def test_the_risk_of_an_admin_count_of_one_is_high() -> None:
    """An adminCount of 1 is HIGH."""
    lab = harness.Lab()
    lab.add_user(uac=4260352, admin_count=1)

    result = plan.plan_change(
        harness.DOMAIN, "uac-clear", ["seed-asrep"], 4194304,
        send=lab.send, devices=lab.devices,
    )

    assert result["risk"] == "HIGH"


def test_the_risk_of_a_dc_account_is_high() -> None:
    """A domain controller account is HIGH."""
    lab = harness.Lab()
    lab.add_user(uac=4260352, dc_account=True)

    result = plan.plan_change(
        harness.DOMAIN, "uac-clear", ["seed-asrep"], 4194304,
        send=lab.send, devices=lab.devices,
    )

    assert result["risk"] == "HIGH"


def test_a_privileged_target_is_refused_for_a_disable() -> None:
    """Only uac-clear, enc-types and unlock touch a privileged target."""
    lab = harness.Lab()
    lab.add_user(uac=512, privileged=True)

    with pytest.raises(WriteError) as caught:
        plan.plan_change(
            harness.DOMAIN, "disable", ["seed-asrep"], None,
            send=lab.send, devices=lab.devices,
        )

    assert "privileged" in str(caught.value)


def test_a_builtin_privileged_group_is_refused_as_privileged() -> None:
    """member-add to BUILTIN Administrators names the privileged rule.

    Live 2026-11-13: the first read answered ok with privileged=true and
    the group SID S-1-5-32-544.  The full target carries that SID, which
    the request pattern ^S-1-5-21-... refuses (schema), so the plan used to
    fail with the generic read error instead of SPEC-1.4 section 5's
    privileged refusal.
    """
    lab = harness.Lab()
    lab.add_group(sid="S-1-5-32-544", sam="administrators", privileged=True)
    lab.add_other()

    with pytest.raises(WriteError) as caught:
        plan.plan_change(
            harness.DOMAIN, "member-add", ["administrators", "other"], None,
            send=lab.send, devices=lab.devices,
        )

    assert "the target is privileged" in str(caught.value)


def test_the_trust_bit_is_refused_at_plan() -> None:
    """Bit 524288 needs SeEnableDelegationPrivilege, which newton-ops lacks.

    Live 2026-11-13: every apply of a uac-clear of 524288 was denied by the
    directory on both platforms (LDAP error 50), so Newton refuses it
    before any read.
    """
    lab = harness.Lab()
    lab.add_user(uac=512 | 524288)
    sent: list[object] = []

    def send(target: object, body: dict[str, object]) -> dict[str, object]:
        sent.append(body)
        return lab.send(target, body)  # type: ignore[arg-type]

    with pytest.raises(WriteError) as caught:
        plan.plan_change(
            harness.DOMAIN, "uac-clear", ["seed-asrep"], 524288,
            send=send, devices=lab.devices,
        )

    assert "SeEnableDelegationPrivilege" in str(caught.value)
    assert sent == []


def test_a_dc_account_is_refused_for_a_disable() -> None:
    """A domain controller account is never disabled."""
    lab = harness.Lab()
    lab.add_user(uac=512, dc_account=True)

    with pytest.raises(WriteError) as caught:
        plan.plan_change(
            harness.DOMAIN, "disable", ["seed-asrep"], None,
            send=lab.send, devices=lab.devices,
        )

    assert "domain controller" in str(caught.value)


def test_the_plan_of_a_user_create_holds_the_password_in_the_file_only() -> None:
    """The password is written in the plan and nowhere else."""
    lab = harness.Lab()
    lab.add_user(uac=512)
    lab.add_group(guid=harness.DOMAIN_GUID, sid="S-1-5-21-1-2-3-1", sam="win")

    result = plan.plan_change(
        harness.DOMAIN, "user-create", ["newuser"], harness.DOMAIN_GUID,
        send=lab.send, devices=lab.devices,
    )

    assert "secret" not in result
    plan_file = store.read_json(store.plan_path(result["plan_id"]))
    secret = plan_file["secret"]
    assert len(secret) == 24
    assert all(0x21 <= ord(character) <= 0x7E for character in secret)
    assert secret not in json.dumps(result)


def test_the_plan_refuses_a_name_that_is_not_a_sam() -> None:
    """A DN, a filter or free text is never a name of the target."""
    lab = _lab()

    for name in ("CN=seed,OU=Users", "(objectClass=*)", "Seed Asrep", "*"):
        with pytest.raises(WriteError):
            plan.plan_change(
                harness.DOMAIN, "uac-clear", [name], 4194304,
                send=lab.send, devices=lab.devices,
            )


def test_the_plan_refuses_an_unknown_verb() -> None:
    """Only the verbs of the contract."""
    lab = _lab()

    with pytest.raises(WriteError):
        plan.plan_change(
            harness.DOMAIN, "reset-password", ["seed-asrep"], None,
            send=lab.send, devices=lab.devices,
        )


def test_the_plan_refuses_a_value_the_verb_does_not_take() -> None:
    """An unlock takes no value."""
    lab = _lab()

    with pytest.raises(WriteError):
        plan.plan_change(
            harness.DOMAIN, "unlock", ["seed-asrep"], 5,
            send=lab.send, devices=lab.devices,
        )


def test_the_plan_refuses_a_domain_without_a_write_entry() -> None:
    """A domain with no write entry has no plan."""
    lab = _lab()

    with pytest.raises(WriteError):
        plan.plan_change(
            "other-domain", "uac-clear", ["seed-asrep"], 4194304,
            send=lab.send, devices=lab.devices,
        )


def test_the_plan_refuses_a_domain_without_a_domain_controller() -> None:
    """A domain whose DCs are all secondaries has no plan."""
    lab = harness.Lab(pdc=False)
    lab.add_user(uac=4260352)

    with pytest.raises(WriteError) as caught:
        plan.plan_change(
            harness.DOMAIN, "uac-clear", ["seed-asrep"], 4194304,
            send=lab.send, devices=lab.devices,
        )

    assert "domain controller" in str(caught.value)


def test_the_plan_names_the_dcs_it_will_verify_and_warns_of_the_others() -> None:
    """The plan lists the DCs the apply reads back, and says it reads no other.

    Newton knows a DC only by its write entry: a DC of the domain without
    one is never read before the confirm, so the plan says so plainly.
    """
    lab = _lab()

    result = plan.plan_change(
        harness.DOMAIN, "uac-clear", ["seed-asrep"], 4194304,
        send=lab.send, devices=lab.devices,
    )

    assert result["dcs"] == ["win-dc1", "win-dc2"]
    assert isinstance(result["warning"], str)
    assert "write entry" in result["warning"]
    assert "never read" in result["warning"]


def test_a_dc_left_out_of_the_inventory_is_not_listed_in_the_plan() -> None:
    """A DC without a write entry is not among the DCs the plan names."""
    lab = _lab()
    devices = {name: one for name, one in lab.devices.items() if name != "win-dc2"}

    result = plan.plan_change(
        harness.DOMAIN, "uac-clear", ["seed-asrep"], 4194304,
        send=lab.send, devices=devices,
    )

    assert result["dcs"] == ["win-dc1"]
    assert "write entry" in result["warning"]


def test_the_plan_of_a_member_add_holds_the_two_accounts() -> None:
    """A membership names the group and the member."""
    lab = harness.Lab()
    lab.add_group()
    lab.add_user()
    lab.add_other()

    result = plan.plan_change(
        harness.DOMAIN, "member-add", ["seed-group", "other"], None,
        send=lab.send, devices=lab.devices,
    )

    assert result["target"]["group_sam"] == harness.GROUP_SAM
    assert result["target"]["member_sam"] == harness.OTHER_SAM
    assert result["before"] == {"member": "absent"}
    assert result["after"] == {"member": "present"}


def test_the_plan_of_a_maq_names_the_domain_head() -> None:
    """The quota of the domain head."""
    lab = harness.Lab()
    lab.add_domain_head()

    result = plan.plan_change(
        harness.DOMAIN, "maq", [], 0,
        send=lab.send, devices=lab.devices,
    )

    assert result["target"] == {"guid": harness.DOMAIN_GUID}
    assert result["before"] == {"maq": 10}
    assert result["after"] == {"maq": 0}


def test_the_plan_of_a_mixed_case_account_carries_the_lowercase_name() -> None:
    """The directory holds the name with its case; the request may not.

    A real DC names the administrator ``Administrator``; the request schema
    accepts only a lowercase name, so the plan carries ``administrator``.
    """
    lab = harness.Lab()
    lab.add_user(sam="Administrator", uac=4260352)

    result = plan.plan_change(
        harness.DOMAIN, "uac-clear", ["administrator"], 4194304,
        send=lab.send, devices=lab.devices,
    )

    assert result["target"]["sam"] == "administrator"
    assert result["target"]["guid"] == harness.SEED_GUID
    assert result["before"] == {"uac": 4260352}


def test_the_plan_of_a_mixed_case_membership_carries_the_lowercase_names() -> None:
    """A membership carries the two names in lowercase."""
    lab = harness.Lab()
    lab.add_group(sam="Seed-Group")
    lab.add_user(sam="Seed-Asrep")
    lab.add_other(sam="Other-User")

    result = plan.plan_change(
        harness.DOMAIN, "member-add", ["seed-group", "other-user"], None,
        send=lab.send, devices=lab.devices,
    )

    assert result["target"]["group_sam"] == "seed-group"
    assert result["target"]["member_sam"] == "other-user"
