"""the ops of an owner script, and the grammar they must pass.

ADR-021 point 7 and the design: for a change Newton may not apply
itself, Newton writes a script the owner approves byte for byte.  The
script may only carry what the router's own web API can read back, and
every value in it must be safe to write inside single quotes.

What is proved here:

  * every hostile value is refused, and the refusal never echoes it;
  * every value that passes ends up byte-exact;
  * the verbs, names, configs and secret-named options are refused;
  * the policy reasons that make a change unconfirmable are refused;
  * the diff, the expected values and the inverse ops are right.

The backups come from the measured answers (see ``noinstall_answers``
and ``owner_answers``); no router is contacted.
"""

from __future__ import annotations

import shlex

import pytest

from newton_mcp import owner_ops
from newton_mcp import undo
from newton_mcp.owner_backup import Backup
from newton_mcp.owner_ops import OwnerOp, OwnerScriptError
from newton_mcp.server import Device
from noinstall_answers import data
from owner_answers import data as firewall_data


# ---- the fixtures ----------------------------------------------------------


def _backup(**overrides) -> Backup:
    """The backup of the measured lab-r1 configs."""
    configs = {
        "dhcp": data("uci.get.dhcp")["values"],
        "firewall": firewall_data("uci.get.firewall")["values"],
        "network": data("uci.get.network")["values"],
        "system": data("uci.get.system")["values"],
    }
    return Backup(
        configs=configs,
        board="qemu-standard-pc-i440fx-piix-1996",
        **overrides,
    )


def _device(**overrides) -> Device:
    fields = {
        "name": "lab-r1",
        "platform": "openwrt",
        "host": "192.0.2.1",
        "user": "root",
        "profile": "lab",
        "access": "no-install",
    }
    fields.update(overrides)
    return Device(**fields)


def _line(verb: str, path: str, value: str | None = None) -> str:
    """One batch line with the value quoted the way an agent writes it."""
    if value is None:
        return f"{verb} {path}"
    return f"{verb} {path}={shlex.quote(value)}"


# ---- the grammar -----------------------------------------------------------


def test_a_plain_set_becomes_one_op() -> None:
    ops = owner_ops.parse_batch("set dhcp.lan.limit='150'", _backup(), _device())
    assert ops == [OwnerOp("set", "dhcp", "lan", "limit", "150", None)]


def test_a_list_verb_becomes_one_op() -> None:
    ops = owner_ops.parse_batch(
        _line("add_list", "dhcp.lan.ra_flags", "managed-config"),
        _backup(),
        _device(),
    )
    assert ops == [OwnerOp("add_list", "dhcp", "lan", "ra_flags", "managed-config", None)]


def test_a_delete_of_an_option_becomes_one_op() -> None:
    ops = owner_ops.parse_batch("delete dhcp.lan.limit", _backup(), _device())
    assert ops == [OwnerOp("delete", "dhcp", "lan", "limit", None, None)]


def test_a_delete_of_a_whole_section_becomes_one_op() -> None:
    ops = owner_ops.parse_batch("delete firewall.cfg0592bd", _backup(), _device())
    assert ops == [OwnerOp("delete", "firewall", "cfg0592bd", None, None, None)]


def test_a_delete_of_a_forwarding_is_refused_because_the_policy_cannot_see_it() -> None:
    """The diff of a deleted section shows no src and no dest.

    The policy fails safe on a forwarding whose src or dest the diff
    does not show, so an owner script may not delete one.
    """
    with pytest.raises(OwnerScriptError) as caught:
        owner_ops.parse_batch("delete firewall.cfg04ad58", _backup(), _device())
    assert "forwarding-mgmt" in str(caught.value)


@pytest.mark.parametrize(
    "address, name",
    [
        ("@zone[1]", "cfg03dc81"),
        ("@zone[2]", "labz"),
        ("@zone[-1]", "labz"),
        ("@zone[-2]", "cfg03dc81"),
        ("@rule[0]", "cfg0592bd"),
        ("@rule[1]", "cfg0692bd"),
        ("@rule[-1]", "cfg0d92bd"),
    ],
)
def test_an_anonymous_address_is_resolved_to_the_routers_own_name(
    address: str, name: str
) -> None:
    """The script may only ever name a section, never an @type[N].

    uci counts from 0 and from the end with a minus sign; measured on
    lab-r1 (``@zone[1]`` is wan,
    ``@system[0]`` is the system section, ``@dnsmasq[-1]`` the last).
    A lab run found the resolver counting from 1: ``@system[0]`` was refused
    and ``@zone[1]`` named the lan zone, so a script changed the wrong
    section."""
    option = "input" if address.startswith("@zone") else "enabled"
    value = "REJECT" if option == "input" else "0"
    ops = owner_ops.parse_batch(
        _line("set", f"firewall.{address}.{option}", value), _backup(), _device()
    )
    assert ops == [OwnerOp("set", "firewall", name, option, value, None)]


@pytest.mark.parametrize("address", ["@zone[3]", "@zone[-4]", "@zone[99]"])
def test_an_anonymous_address_past_the_end_is_refused(address: str) -> None:
    with pytest.raises(OwnerScriptError) as caught:
        owner_ops.parse_batch(
            _line("set", f"firewall.{address}.input", "REJECT"), _backup(), _device()
        )
    assert address in str(caught.value)


def test_an_anonymous_address_that_does_not_exist_is_refused() -> None:
    with pytest.raises(OwnerScriptError) as caught:
        owner_ops.parse_batch(
            _line("set", "firewall.@zone[99].input", "REJECT"), _backup(), _device()
        )
    assert "@zone[99]" in str(caught.value)


# ---- the hostile values ----------------------------------------------------


HOSTILE = (
    "$(touch X)",
    "`touch X`",
    "it's",
    "a;rm -rf /",
    "a\nb",
    "a\rb",
    "a\tb",
    "a\x00b",
    "café",
    "a‮b",
    "",
    "x" * 513,
)


@pytest.mark.parametrize("value", HOSTILE)
def test_a_hostile_value_is_refused_and_never_echoed(value: str) -> None:
    with pytest.raises(OwnerScriptError) as caught:
        owner_ops.parse_batch(
            _line("set", "dhcp.lan.limit", value), _backup(), _device()
        )
    message = str(caught.value)
    assert "dhcp.lan.limit" in message
    if value:
        assert value not in message


def test_a_value_of_exactly_512_bytes_is_accepted() -> None:
    value = "x" * 512
    ops = owner_ops.parse_batch(
        _line("set", "dhcp.lan.limit", value), _backup(), _device()
    )
    assert ops[0].value == value


def test_a_value_with_a_quote_is_refused_because_the_script_quotes_with_quotes() -> None:
    assert not owner_ops.check_value("it's")
    assert owner_ops.check_value("its")


def test_an_empty_value_is_refused_because_delete_is_the_way_to_remove_it() -> None:
    with pytest.raises(OwnerScriptError):
        owner_ops.parse_batch(
            _line("set", "dhcp.lan.limit", ""), _backup(), _device()
        )


# ---- the verbs -------------------------------------------------------------


def test_an_anonymous_add_is_refused_with_the_named_way_to_do_it() -> None:
    with pytest.raises(OwnerScriptError) as caught:
        owner_ops.parse_batch("add firewall", _backup(), _device())
    assert "add a named section: `set CFG.NAME=TYPE`" in str(caught.value)


@pytest.mark.parametrize(
    "line",
    [
        "rename dhcp.lan=other",
        "reorder dhcp.lan=0",
        "revert dhcp.lan",
        "commit dhcp",
        "import dhcp",
        "export dhcp",
    ],
)
def test_every_other_verb_is_refused(line: str) -> None:
    with pytest.raises(OwnerScriptError) as caught:
        owner_ops.parse_batch(line, _backup(), _device())
    assert "set" in str(caught.value)


def test_an_empty_batch_is_refused() -> None:
    with pytest.raises(OwnerScriptError) as caught:
        owner_ops.parse_batch("", _backup(), _device())
    assert "empty" in str(caught.value)


def test_a_comment_only_batch_is_refused() -> None:
    with pytest.raises(OwnerScriptError) as caught:
        owner_ops.parse_batch("# nothing to do\n", _backup(), _device())
    assert "empty" in str(caught.value)


def test_a_placeholder_is_refused() -> None:
    with pytest.raises(OwnerScriptError) as caught:
        owner_ops.parse_batch(
            "set dhcp.lan.limit='<redacted:abcd1234>'", _backup(), _device()
        )
    assert "placeholder" in str(caught.value)


def test_more_than_fifty_ops_are_refused() -> None:
    batch = "\n".join(
        _line("set", f"dhcp.lan.limit", str(index)) for index in range(51)
    )
    with pytest.raises(OwnerScriptError) as caught:
        owner_ops.parse_batch(batch, _backup(), _device())
    assert "50" in str(caught.value)


def test_exactly_fifty_ops_are_accepted() -> None:
    batch = "\n".join(
        _line("set", "dhcp.lan.limit", str(index)) for index in range(50)
    )
    assert len(owner_ops.parse_batch(batch, _backup(), _device())) == 50


# ---- the names and the configs ---------------------------------------------


@pytest.mark.parametrize("config", ["rpcd", "uhttpd", "dropbear", "luci", "nosuchconfig"])
def test_a_config_newton_cannot_read_is_refused(config: str) -> None:
    with pytest.raises(OwnerScriptError) as caught:
        owner_ops.parse_batch(
            _line("set", f"{config}.newthing.option", "x"), _backup(), _device()
        )
    assert "not available in no-install access in this version" in str(caught.value)


@pytest.mark.parametrize("option", ["key", "password", "psk"])
def test_a_secret_named_option_is_refused(option: str) -> None:
    with pytest.raises(OwnerScriptError) as caught:
        owner_ops.parse_batch(
            _line("set", f"wireless.radio0.{option}", "secretvalue"),
            _backup(),
            _device(),
        )
    assert "set it yourself in LuCI" in str(caught.value)
    assert "secretvalue" not in str(caught.value)


def test_a_bad_option_name_is_refused() -> None:
    with pytest.raises(OwnerScriptError):
        owner_ops.parse_batch(
            _line("set", "dhcp.lan.not-an-option", "x"), _backup(), _device()
        )


def test_a_section_that_is_not_on_the_router_is_refused() -> None:
    with pytest.raises(OwnerScriptError) as caught:
        owner_ops.parse_batch(
            _line("set", "dhcp.nosuchsection.limit", "x"), _backup(), _device()
        )
    assert "dhcp.nosuchsection" in str(caught.value)


def test_a_new_named_section_may_be_created_and_used() -> None:
    batch = "\n".join(
        [
            _line("set", "firewall.newzone", "zone"),
            _line("set", "firewall.newzone.name", "guest"),
        ]
    )
    ops = owner_ops.parse_batch(batch, _backup(), _device())
    assert ops == [
        OwnerOp("set", "firewall", "newzone", None, None, "zone"),
        OwnerOp("set", "firewall", "newzone", "name", "guest", None),
    ]


def test_a_new_section_name_must_be_a_lowercase_name() -> None:
    with pytest.raises(OwnerScriptError):
        owner_ops.parse_batch(
            _line("set", "firewall.New-Zone", "zone"), _backup(), _device()
        )


# ---- the policy ------------------------------------------------------------


def test_a_change_to_the_management_interface_is_refused() -> None:
    """Newton can only confirm from the address it reaches the router on."""
    with pytest.raises(OwnerScriptError) as caught:
        owner_ops.parse_batch(
            _line("set", "network.lan.proto", "static"), _backup(), _device()
        )
    assert "mgmt-interface" in str(caught.value)


def test_a_change_to_the_management_zone_is_refused() -> None:
    with pytest.raises(OwnerScriptError) as caught:
        owner_ops.parse_batch(
            _line("set", "firewall.cfg02dc81.input", "REJECT"), _backup(), _device()
        )
    assert "mgmt-zone" in str(caught.value)


def test_a_forwarding_of_the_management_zone_is_refused() -> None:
    with pytest.raises(OwnerScriptError) as caught:
        owner_ops.parse_batch(
            _line("set", "firewall.cfg04ad58.dest", "lan"), _backup(), _device()
        )
    assert "forwarding-mgmt" in str(caught.value)


def test_an_include_section_is_refused() -> None:
    with pytest.raises(OwnerScriptError) as caught:
        owner_ops.parse_batch(
            _line("set", "firewall.myinclude", "include"), _backup(), _device()
        )
    assert "exec-include" in str(caught.value)


def test_an_option_that_can_run_commands_is_refused() -> None:
    with pytest.raises(OwnerScriptError) as caught:
        owner_ops.parse_batch(
            _line("set", "dhcp.lan.dhcpscript", "/usr/bin/evil"),
            _backup(),
            _device(),
        )
    assert "exec-option" in str(caught.value)


def test_a_wan_exposure_is_kept_as_a_reason_and_not_refused() -> None:
    """The exposure reasons are shown to the owner, not refused."""
    ops = owner_ops.parse_batch(
        _line("set", "firewall.cfg03dc81.input", "ACCEPT"), _backup(), _device()
    )
    assert len(ops) == 1


# ---- the diff --------------------------------------------------------------


def test_the_diff_is_the_text_uci_changes_would_print() -> None:
    ops = [
        OwnerOp("set", "dhcp", "lan", "limit", "150", None),
        OwnerOp("add_list", "dhcp", "lan", "ra_flags", "managed-config", None),
        OwnerOp("del_list", "dhcp", "lan", "ra_flags", "other-config", None),
        OwnerOp("delete", "dhcp", "lan", "start", None, None),
        OwnerOp("set", "firewall", "newzone", None, None, "zone"),
        OwnerOp("delete", "firewall", "cfg0592bd", None, None, None),
    ]
    assert owner_ops.render_diff(ops, _backup()) == (
        "dhcp.lan.limit='150'\n"
        "dhcp.lan.ra_flags+='managed-config'\n"
        "dhcp.lan.ra_flags-='other-config'\n"
        "-dhcp.lan.start\n"
        "firewall.newzone=zone\n"
        "-firewall.cfg0592bd"
    )


def test_the_diff_of_no_ops_is_empty() -> None:
    assert owner_ops.render_diff([], _backup()) == ""


# ---- the expected values ---------------------------------------------------


def test_expected_after_reads_the_list_as_it_is() -> None:
    backup = _backup()
    ops = owner_ops.parse_batch(
        _line("add_list", "dhcp.lan.ra_flags", "managed-config"), backup, _device()
    )
    assert owner_ops.expected_after(ops, backup) == {
        ("dhcp", "lan", "ra_flags"): ("managed-config", "other-config", "managed-config")
    }


def test_expected_after_knows_a_deleted_option_is_absent() -> None:
    backup = _backup()
    ops = owner_ops.parse_batch("delete dhcp.lan.limit", backup, _device())
    assert owner_ops.expected_after(ops, backup) == {("dhcp", "lan", "limit"): None}


def test_expected_after_knows_a_new_value() -> None:
    backup = _backup()
    ops = owner_ops.parse_batch(
        _line("set", "dhcp.lan.limit", "150"), backup, _device()
    )
    assert owner_ops.expected_after(ops, backup) == {("dhcp", "lan", "limit"): "150"}


def test_expected_after_of_a_deleted_section_is_the_absence_of_the_section() -> None:
    """A deleted section is a proven absence, and it holds no options.

    A section that is gone has no options, so the router cannot answer
    for them: they are not expected values at all.
    """
    backup = _backup()
    ops = owner_ops.parse_batch("delete firewall.cfg0592bd", backup, _device())
    expected = owner_ops.expected_after(ops, backup)
    assert expected[("firewall", "cfg0592bd", None)] is None
    assert ("firewall", "cfg0592bd", "dest_port") not in expected
    assert ("firewall", "cfg0592bd", "src") not in expected


# ---- the inverse -----------------------------------------------------------


def _undo_sections(values: dict) -> list[undo.Section]:
    """The measured backup as undo's own section list."""
    sections = []
    for name in sorted(values, key=lambda item: values[item].get(".index", 0)):
        entry = values[name]
        options = []
        for key, value in entry.items():
            if key.startswith("."):
                continue
            options.append((key, tuple(value) if isinstance(value, list) else value))
        sections.append(undo.Section(entry[".type"], entry[".name"], tuple(options)))
    return sections


def _round_trip(config: str, values: dict, batch: str | None, ops=None) -> tuple[list, list]:
    backup = _backup()
    if ops is None:
        ops = owner_ops.parse_batch(batch, backup, _device())
    inverse = owner_ops.inverse_ops(ops, backup)
    before = _undo_sections(values)
    after = undo.apply_batch(config, before, owner_ops.batch_lines(ops))
    restored = undo.apply_batch(config, after, owner_ops.batch_lines(inverse))
    return before, restored


def _same_state(one: list, other: list) -> bool:
    """undo's own notion of "the same state" (the option order does not count)."""
    return undo._same_state(one, other)


def test_the_inverse_of_a_set_is_the_old_value() -> None:
    backup = _backup()
    ops = owner_ops.parse_batch(
        _line("set", "dhcp.lan.limit", "150"), backup, _device()
    )
    inverse = owner_ops.inverse_ops(ops, backup)
    assert inverse == [OwnerOp("set", "dhcp", "lan", "limit", "150", None)]


def test_the_inverse_of_a_set_of_a_new_option_is_a_delete() -> None:
    backup = _backup()
    ops = owner_ops.parse_batch(
        _line("set", "dhcp.lan.newoption", "x"), backup, _device()
    )
    inverse = owner_ops.inverse_ops(ops, backup)
    assert inverse == [OwnerOp("delete", "dhcp", "lan", "newoption", None, None)]


def test_the_inverse_of_a_list_change_rebuilds_the_list() -> None:
    backup = _backup()
    ops = owner_ops.parse_batch(
        _line("add_list", "dhcp.lan.ra_flags", "managed-config"), backup, _device()
    )
    inverse = owner_ops.inverse_ops(ops, backup)
    assert inverse == [
        OwnerOp("delete", "dhcp", "lan", "ra_flags", None, None),
        OwnerOp("add_list", "dhcp", "lan", "ra_flags", "managed-config", None),
        OwnerOp("add_list", "dhcp", "lan", "ra_flags", "other-config", None),
    ]


def test_the_inverse_of_a_deleted_section_recreates_it_with_a_new_name() -> None:
    backup = _backup(sid="0123456789abcdef0123456789abcdef")
    ops = [OwnerOp("delete", "firewall", "cfg0592bd", None, None, None)]
    inverse = owner_ops.inverse_ops(ops, backup)
    assert inverse[0] == OwnerOp("set", "firewall", "newton_r_01234567_4", None, None, "rule")
    assert inverse[1] == OwnerOp("set", "firewall", "newton_r_01234567_4", "dest_port", "68", None)
    assert OwnerOp("set", "firewall", "newton_r_01234567_4", "src", "wan", None) in inverse
    assert inverse[-1] == OwnerOp("reorder", "firewall", "newton_r_01234567_4", None, "4", None)


def test_the_inverse_restores_the_config_it_took_from() -> None:
    values = data("uci.get.dhcp")["values"]
    before, restored = _round_trip("dhcp", values, _line("set", "dhcp.lan.limit", "150"))
    assert _same_state(restored, before)


def test_the_inverse_restores_a_list() -> None:
    values = data("uci.get.dhcp")["values"]
    before, restored = _round_trip(
        "dhcp", values, _line("add_list", "dhcp.lan.ra_flags", "managed-config")
    )
    assert _same_state(restored, before)


def test_the_inverse_restores_a_deleted_option() -> None:
    values = data("uci.get.dhcp")["values"]
    before, restored = _round_trip("dhcp", values, "delete dhcp.lan.limit")
    assert _same_state(restored, before)


def test_the_inverse_restores_a_deleted_section_apart_from_its_name() -> None:
    values = firewall_data("uci.get.firewall")["values"]
    before, restored = _round_trip(
        "firewall", values, None, [OwnerOp("delete", "firewall", "cfg0592bd", None, None, None)]
    )
    assert len(restored) == len(before)
    for old, new in zip(before, restored):
        if old.name == "cfg0592bd":
            assert new.type == old.type
            assert dict(new.options) == dict(old.options)
            assert new.name != old.name
            assert new.name.startswith("newton_r_")
        else:
            assert new.type == old.type
            assert new.name == old.name
            assert dict(new.options) == dict(old.options)


# ---- the preconditions -----------------------------------------------------


def test_a_precondition_names_the_current_value_of_every_touched_option() -> None:
    backup = _backup()
    ops = owner_ops.parse_batch(
        _line("set", "dhcp.lan.limit", "150"), backup, _device()
    )
    assert owner_ops.preconditions(ops, backup) == (
        ("dhcp.lan.limit", "150"),
    )


def test_a_precondition_of_an_option_that_is_not_there_is_an_absence() -> None:
    backup = _backup()
    ops = owner_ops.parse_batch(
        _line("set", "dhcp.lan.newoption", "x"), backup, _device()
    )
    assert owner_ops.preconditions(ops, backup) == (
        ("dhcp.lan.newoption", None),
    )


def test_a_precondition_of_a_new_section_is_the_absence_of_the_section() -> None:
    backup = _backup()
    ops = owner_ops.parse_batch(
        _line("set", "network.newlan", "interface"), backup, _device()
    )
    assert owner_ops.preconditions(ops, backup) == (
        ("network.newlan", None),
    )


def test_a_router_value_that_cannot_be_written_safely_refuses_the_script() -> None:
    """The router's own value goes into the check, so it must be safe too."""
    broken = Backup(
        configs={
            "dhcp": {
                "lan": {
                    ".anonymous": False,
                    ".index": 1,
                    ".name": "lan",
                    ".type": "dhcp",
                    "limit": "100 $(id)",
                }
            }
        },
        board="test",
    )
    with pytest.raises(OwnerScriptError) as caught:
        owner_ops.parse_batch(
            _line("set", "dhcp.lan.limit", "150"), broken, _device()
        )
    assert "Newton cannot write a safe check for dhcp.lan.limit" in str(caught.value)
    assert "$(id)" not in str(caught.value)


# ---- several ops on one unit -----------------------------------------------
#
# A batch may touch the same unit more than once.  The expected values
# then have to follow the RUNNING state (what the previous op left),
# and the inverse has to restore every touched unit ONCE, from the
# backup.


def test_two_adds_on_one_option_keep_both_items() -> None:
    """Two add_list lines on one option: the list holds both items."""
    backup = _backup()
    ops = owner_ops.parse_batch(
        "\n".join(
            [
                _line("add_list", "dhcp.lan.ra_flags", "managed-config"),
                _line("add_list", "dhcp.lan.ra_flags", "other-config"),
            ]
        ),
        backup,
        _device(),
    )
    expected = owner_ops.expected_after(ops, backup)
    assert expected[("dhcp", "lan", "ra_flags")] == (
        "managed-config",
        "other-config",
        "managed-config",
        "other-config",
    )


def test_a_del_list_then_an_add_list_follow_the_running_state() -> None:
    """The APPLY_LISTS_PLAN case: the add follows the del, not the backup."""
    backup = _backup()
    ops = owner_ops.parse_batch(
        "\n".join(
            [
                _line("del_list", "dhcp.lan.ra_flags", "managed-config"),
                _line("add_list", "dhcp.lan.ra_flags", "third"),
            ]
        ),
        backup,
        _device(),
    )
    expected = owner_ops.expected_after(ops, backup)
    assert expected[("dhcp", "lan", "ra_flags")] == ("other-config", "third")


def test_a_set_then_a_delete_leaves_the_option_absent() -> None:
    """A set and then a delete of the same option: the option is gone."""
    backup = _backup()
    ops = owner_ops.parse_batch(
        "\n".join(
            [
                _line("set", "dhcp.lan.limit", "250"),
                "delete dhcp.lan.limit",
            ]
        ),
        backup,
        _device(),
    )
    expected = owner_ops.expected_after(ops, backup)
    assert expected[("dhcp", "lan", "limit")] is None


def test_the_inverse_restores_a_unit_that_was_touched_twice_once() -> None:
    """The inverse restores every touched unit ONCE, from the backup."""
    backup = _backup()
    ops = owner_ops.parse_batch(
        "\n".join(
            [
                _line("add_list", "dhcp.lan.ra_flags", "managed-config"),
                _line("add_list", "dhcp.lan.ra_flags", "other-config"),
            ]
        ),
        backup,
        _device(),
    )
    inverse = owner_ops.inverse_ops(ops, backup)
    assert inverse == [
        OwnerOp("delete", "dhcp", "lan", "ra_flags", None, None),
        OwnerOp("add_list", "dhcp", "lan", "ra_flags", "managed-config", None),
        OwnerOp("add_list", "dhcp", "lan", "ra_flags", "other-config", None),
    ]


def test_the_inverse_of_a_set_then_a_delete_is_the_old_value() -> None:
    """A unit that was set and then deleted goes back to its old value."""
    backup = _backup()
    ops = owner_ops.parse_batch(
        "\n".join(
            [
                _line("set", "dhcp.lan.limit", "250"),
                "delete dhcp.lan.limit",
            ]
        ),
        backup,
        _device(),
    )
    inverse = owner_ops.inverse_ops(ops, backup)
    assert inverse == [OwnerOp("set", "dhcp", "lan", "limit", "150", None)]


#: The batches that touch one unit several times.
BATCHES_THAT_TOUCH_A_UNIT_SEVERAL_TIMES = (
    [
        _line("set", "dhcp.lan.limit", "250"),
        _line("set", "dhcp.lan.limit", "260"),
    ],
    [
        _line("set", "dhcp.lan.limit", "250"),
        "delete dhcp.lan.limit",
    ],
    [
        "delete dhcp.lan.limit",
        _line("set", "dhcp.lan.limit", "250"),
    ],
    [
        _line("add_list", "dhcp.lan.ra_flags", "managed-config"),
        _line("add_list", "dhcp.lan.ra_flags", "other-config"),
    ],
    [
        _line("del_list", "dhcp.lan.ra_flags", "managed-config"),
        _line("add_list", "dhcp.lan.ra_flags", "third"),
    ],
    [
        _line("del_list", "dhcp.lan.ra_flags", "managed-config"),
        _line("del_list", "dhcp.lan.ra_flags", "other-config"),
    ],
)


@pytest.mark.parametrize("batch", BATCHES_THAT_TOUCH_A_UNIT_SEVERAL_TIMES)
def test_the_inverse_restores_a_batch_that_touches_a_unit_several_times(
    batch: list[str],
) -> None:
    """The undo round trip holds for every batch that touches a unit
    several times."""
    values = data("uci.get.dhcp")["values"]
    before, restored = _round_trip("dhcp", values, "\n".join(batch))
    assert _same_state(restored, before)


#: The list case of the golden scripts: a zone's network list.
APPLY_LISTS_CASE = [
    _line("del_list", "firewall.cfg03dc81.network", "wan6"),
    _line("add_list", "firewall.cfg03dc81.network", "wan3"),
]


def test_the_apply_lists_case_leaves_the_list_the_golden_restore_checks() -> None:
    """The list case of the golden scripts: the del and the add leave
    the list the golden restore script checks."""
    backup = _backup()
    ops = owner_ops.parse_batch("\n".join(APPLY_LISTS_CASE), backup, _device())
    expected = owner_ops.expected_after(ops, backup)
    assert expected[("firewall", "cfg03dc81", "network")] == (
        "wan",
        "wan2",
        "wan3",
    )


def test_the_inverse_of_the_apply_lists_case_rebuilds_the_list_once() -> None:
    """The inverse of the list case rebuilds the list ONCE, the way the
    golden restore script does."""
    backup = _backup()
    ops = owner_ops.parse_batch("\n".join(APPLY_LISTS_CASE), backup, _device())
    inverse = owner_ops.inverse_ops(ops, backup)
    assert inverse == [
        OwnerOp("delete", "firewall", "cfg03dc81", "network", None, None),
        OwnerOp("add_list", "firewall", "cfg03dc81", "network", "wan", None),
        OwnerOp("add_list", "firewall", "cfg03dc81", "network", "wan6", None),
        OwnerOp("add_list", "firewall", "cfg03dc81", "network", "wan2", None),
    ]


# ---- the list semantics ----------------------------------


def test_a_del_list_takes_every_item_that_is_equal() -> None:
    """uci's del_list takes EVERY item that is equal to the value.

    The measured router (``a3m-01``) removes all of them, not the
    first one, so the expected value holds what is left.
    """
    backup = _backup()
    ops = owner_ops.parse_batch(
        "\n".join(
            [
                _line("add_list", "dhcp.lan.ra_flags", "managed-config"),
                _line("del_list", "dhcp.lan.ra_flags", "managed-config"),
            ]
        ),
        backup,
        _device(),
    )
    expected = owner_ops.expected_after(ops, backup)
    assert expected[("dhcp", "lan", "ra_flags")] == ("other-config",)


def test_a_list_that_is_emptied_is_absent_and_not_an_empty_list() -> None:
    """Removing every item of a list makes the option ABSENT.

    That is what the router does (``[0]`` and "Entry not found"), so
    the expected value is None and never an empty tuple.
    """
    backup = _backup()
    ops = owner_ops.parse_batch(
        "\n".join(
            [
                _line("del_list", "dhcp.lan.ra_flags", "managed-config"),
                _line("del_list", "dhcp.lan.ra_flags", "other-config"),
            ]
        ),
        backup,
        _device(),
    )
    expected = owner_ops.expected_after(ops, backup)
    assert expected[("dhcp", "lan", "ra_flags")] is None


def test_an_emptied_list_still_has_a_safe_precondition() -> None:
    """The precondition of an emptied list is the value the router holds.

    The plan must not refuse the change with "Newton cannot write a
    safe check": the router's own value is still a safe check.
    """
    backup = _backup()
    ops = owner_ops.parse_batch(
        "\n".join(
            [
                _line("del_list", "dhcp.lan.ra_flags", "managed-config"),
                _line("del_list", "dhcp.lan.ra_flags", "other-config"),
            ]
        ),
        backup,
        _device(),
    )
    checks = owner_ops.preconditions(ops, backup)
    assert ("dhcp.lan.ra_flags", "managed-config other-config") in checks


def test_the_restore_of_an_emptied_list_brings_the_items_back() -> None:
    """The restore of an emptied list puts every item back."""
    backup = _backup()
    ops = owner_ops.parse_batch(
        "\n".join(
            [
                _line("del_list", "dhcp.lan.ra_flags", "managed-config"),
                _line("del_list", "dhcp.lan.ra_flags", "other-config"),
            ]
        ),
        backup,
        _device(),
    )
    inverse = owner_ops.inverse_ops(ops, backup)
    assert inverse == [
        OwnerOp("add_list", "dhcp", "lan", "ra_flags", "managed-config", None),
        OwnerOp("add_list", "dhcp", "lan", "ra_flags", "other-config", None),
    ]


# ---- a deleted section and its options ----------------------------


def test_the_expected_values_of_a_deleted_section_hold_no_options() -> None:
    """A section that is gone has no options: none of them is expected.

    An option the batch added to a section it also deletes is not an
    expected value either: the router will not hold it.
    """
    backup = _backup()
    ops = owner_ops.parse_batch(
        "\n".join(
            [
                _line("set", "dhcp.lan.newopt", "1"),
                "delete dhcp.lan",
            ]
        ),
        backup,
        _device(),
    )
    expected = owner_ops.expected_after(ops, backup)
    assert expected[("dhcp", "lan", None)] is None
    assert ("dhcp", "lan", "newopt") not in expected
    assert ("dhcp", "lan", "limit") not in expected


def test_the_restore_of_a_deleted_section_does_not_set_on_it() -> None:
    """The restore re-creates the section under a new name.

    It must not also set an option on the section that is gone: uci
    refuses that, and the restore would die on the router.
    """
    backup = _backup()
    ops = owner_ops.parse_batch(
        "\n".join(
            [
                _line("set", "dhcp.lan.limit", "250"),
                "delete dhcp.lan",
            ]
        ),
        backup,
        _device(),
    )
    inverse = owner_ops.inverse_ops(ops, backup)
    for op in inverse:
        assert op.section != "lan" or op.option is None, op
    # the section itself comes back, under a new name, with its old value
    restored = [op for op in inverse if op.type == "dhcp"]
    assert restored, inverse
    assert any(
        op.verb == "set" and op.option == "limit" and op.value == "150"
        for op in inverse
    ), inverse


def test_the_options_of_a_deleted_section_are_still_checked() -> None:
    """The script still checks the options of the section it deletes.

    The router may have changed them since the plan, and the change
    takes the whole section away, so the check is what proves that the
    router is still the router the plan was made against.
    """
    backup = _backup()
    ops = owner_ops.parse_batch(
        "\n".join(
            [
                _line("set", "dhcp.lan.limit", "250"),
                "delete dhcp.lan",
            ]
        ),
        backup,
        _device(),
    )
    checks = owner_ops.preconditions(ops, backup)
    assert ("dhcp.lan", "dhcp") in checks
    assert ("dhcp.lan.limit", "150") in checks


def test_the_touched_units_of_a_deleted_section_hold_its_options() -> None:
    """The units the change touches are the options of the section too.

    The read-back compares every unit that is not touched with the
    backup, so the options of a deleted section have to be touched: they
    are gone on the router, and that is the change.
    """
    backup = _backup()
    ops = owner_ops.parse_batch(
        "\n".join(
            [
                _line("set", "dhcp.lan.limit", "250"),
                "delete dhcp.lan",
            ]
        ),
        backup,
        _device(),
    )
    touched = owner_ops.touched_units(ops, backup)
    assert ("dhcp", "lan", "limit") in touched
    assert ("dhcp", "lan", None) in touched


# ---- the type of an existing section ------------------------------


def test_the_type_of_an_existing_section_is_not_an_absence() -> None:
    """``set CFG.SEC=TYPE`` on a section that is already there.

    The section is not absent: the script must check that the router
    holds it, with that type, and not that it does not hold it at all.
    """
    backup = _backup()
    ops = owner_ops.parse_batch("set dhcp.lan=dhcp", backup, _device())
    checks = owner_ops.preconditions(ops, backup)
    assert ("dhcp.lan", "dhcp") in checks
    assert ("dhcp.lan", None) not in checks


def test_the_type_of_an_existing_section_may_not_change() -> None:
    """A type that is not the type the router holds is refused.

    The message names the type the router holds and the one the batch
    asks for: Newton does not change what a section is.
    """
    with pytest.raises(OwnerScriptError) as excinfo:
        owner_ops.parse_batch("set dhcp.lan=dnsmasq", _backup(), _device())
    assert str(excinfo.value) == (
        "the batch changes the type of dhcp.lan from dhcp to dnsmasq; "
        "Newton does not do that"
    )


def test_a_new_section_is_still_an_absence() -> None:
    """A section the change creates must not be there yet."""
    backup = _backup()
    ops = owner_ops.parse_batch("set dhcp.newsection=dhcp", backup, _device())
    checks = owner_ops.preconditions(ops, backup)
    assert ("dhcp.newsection", None) in checks


# ---- the third review, defect 3: a change after a delete ------------------


def test_a_change_after_the_delete_of_a_section_is_refused() -> None:
    """A batch that deletes a section and then changes it is refused.

    The router does not take a change of a section that is not there:
    the two changes belong in two changes, one after the other.
    """
    with pytest.raises(OwnerScriptError) as caught:
        owner_ops.parse_batch(
            "delete dhcp.lan\nset dhcp.lan.limit='250'", _backup(), _device()
        )
    assert "the batch deletes dhcp.lan and then changes it" in str(caught.value)
    assert "split it into two changes" in str(caught.value)


def test_a_recreation_after_the_delete_of_a_section_is_refused() -> None:
    """The same when the batch re-creates the section it deleted."""
    with pytest.raises(OwnerScriptError) as caught:
        owner_ops.parse_batch(
            "delete dhcp.lan\nset dhcp.lan=dhcp", _backup(), _device()
        )
    assert "the batch deletes dhcp.lan and then changes it" in str(caught.value)


def test_a_change_of_another_section_after_a_delete_is_accepted() -> None:
    """A delete of one section and a change of another are one change."""
    ops = owner_ops.parse_batch(
        "delete dhcp.lan\nset dhcp.lab.leasetime='6h'", _backup(), _device()
    )
    assert [op.verb for op in ops] == ["delete", "set"]


def test_a_delete_of_an_option_after_a_delete_of_a_section_is_refused() -> None:
    """A delete of an option of a deleted section is refused too."""
    with pytest.raises(OwnerScriptError) as caught:
        owner_ops.parse_batch(
            "delete dhcp.lan\ndelete dhcp.lan.limit", _backup(), _device()
        )
    assert "the batch deletes dhcp.lan and then changes it" in str(caught.value)
