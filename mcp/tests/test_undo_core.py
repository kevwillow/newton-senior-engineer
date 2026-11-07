"""The pure core of "undo after confirm".

``newton_mcp.undo`` turns the config a change produced (C) back into the
config from before the change (B) as a ``uci batch``, one package at a time,
and proves every batch it builds by simulating it on C.

Everything here is pure: no
device, no network, no shell, nothing written outside ``tmp_path``.
"""

from __future__ import annotations

import io
import random
import tarfile
from pathlib import Path

import pytest

import newton_mcp.undo as undo
from newton_mcp.undo import Section, UndoError


SECRET = "s3cretV4lue"
VERBS = ("add", "set", "add_list", "del_list", "delete", "reorder")


# ---------------------------------------------------------------- UC-01


def test_uc01_parses_sections_options_lists_and_values():
    text = (
        "# firewall defaults\n"
        "package 'firewall'\n"
        "\n"
        "config defaults 'defaults'\n"
        "\toption input 'ACCEPT'\n"
        "\toption output \"ACCEPT\"\n"
        "\toption forward ACCEPT\n"
        "\toption input 'REJECT'\n"
        "\tlist network 'lan'\n"
        "\tlist network 'guest'\n"
        "\toption name 'it'\\''s'\n"
        "\n"
        "config zone\n"
        "\toption name 'lan'\n"
        "\tlist network 'lan'\n"
    )
    assert undo.parse_uci_config(text) == [
        Section(
            "defaults",
            "defaults",
            (
                ("input", "REJECT"),
                ("output", "ACCEPT"),
                ("forward", "ACCEPT"),
                ("network", ("lan", "guest")),
                ("name", "it's"),
            ),
        ),
        Section("zone", None, (("name", "lan"), ("network", ("lan",)))),
    ]


def test_uc01_a_repeated_option_keeps_the_first_place_and_the_last_value():
    text = (
        "config interface 'lan'\n"
        "option proto 'static'\n"
        "option ipaddr '10.0.0.1'\n"
        "option proto 'dhcp'\n"
    )
    assert undo.parse_uci_config(text) == [
        Section("interface", "lan", (("proto", "dhcp"), ("ipaddr", "10.0.0.1")))
    ]


def test_uc01_an_option_after_a_list_is_refused():
    text = "config zone 'lan'\nlist network 'lan'\noption network 'guest'\n"
    with pytest.raises(UndoError):
        undo.parse_uci_config(text)


BAD_TEXTS = [
    # an option before any config section
    f"option name {SECRET}\n",
    # a list before any config section
    f"list name {SECRET}\n",
    # an unknown keyword
    f"frobnicate {SECRET}\n",
    # an unterminated quote
    f"config zone\noption name '{SECRET}\n",
    # trailing junk after the value
    f"config zone\noption name {SECRET} extra\n",
    # a type that is not a name
    f"config '{SECRET} type'\n",
    # an option name that is not a name
    f"config zone\noption '{SECRET} name' value\n",
    # a backslash with nothing to escape
    f"config zone\noption name {SECRET}\\\n",
    # a backslash outside quotes: libuci may read it differently, so it is refused
    f"config zone\noption name a\\b{SECRET}\n",
    # an unquoted # inside a word: libuci may read it as a comment
    f"config zone\noption name {SECRET}#old\n",
    # one name as both an option and a list
    f"config zone\noption name {SECRET}\nlist name other\n",
    f"config zone\nlist name {SECRET}\noption name other\n",
]


@pytest.mark.parametrize("bad", BAD_TEXTS)
def test_uc01_malformed_lines_are_refused_without_the_value(bad):
    with pytest.raises(UndoError) as excinfo:
        undo.parse_uci_config(bad)
    message = str(excinfo.value)
    assert message.startswith("line ")
    assert SECRET not in message


# ---------------------------------------------------------------- UC-02


def test_uc02_apply_batch_verbs():
    base = [
        Section("interface", "lan", (("proto", "static"), ("ipaddr", "10.0.0.1"))),
        Section("rule", None, (("src", "wan"),)),
    ]
    # add: an anonymous section is appended
    out = undo.apply_batch("network", base, ["add network rule"])
    assert len(out) == 3
    assert out[-1] == Section("rule", None, ())
    # set on an option: the value is replaced, the place is kept
    out = undo.apply_batch("network", base, ["set network.lan.ipaddr='10.0.0.2'"])
    assert out[0].options == (("proto", "static"), ("ipaddr", "10.0.0.2"))
    # set on an option that is not there: it is appended
    out = undo.apply_batch("network", base, ["set network.lan.gateway='10.0.0.254'"])
    assert out[0].options == (
        ("proto", "static"),
        ("ipaddr", "10.0.0.1"),
        ("gateway", "10.0.0.254"),
    )
    # set on a section that is there: the type changes
    out = undo.apply_batch("network", base, ["set network.lan=zone"])
    assert out[0] == Section("zone", "lan", (("proto", "static"), ("ipaddr", "10.0.0.1")))
    # set on a section that is not there: it is appended
    out = undo.apply_batch("network", base, ["set network.wan=interface"])
    assert out[-1] == Section("interface", "wan", ())
    # delete a section
    out = undo.apply_batch("network", base, ["delete network.lan"])
    assert out == [Section("rule", None, (("src", "wan"),))]
    # delete an option
    out = undo.apply_batch("network", base, ["delete network.lan.ipaddr"])
    assert out[0].options == (("proto", "static"),)


def test_uc02_apply_batch_lists():
    base = [Section("zone", "lan", (("network", ("lan", "guest")),))]
    # a value is added to the list
    out = undo.apply_batch("firewall", base, ["add_list firewall.lan.network='iot'"])
    assert out[0].options == (("network", ("lan", "guest", "iot")),)
    # a value is taken out of the list
    out = undo.apply_batch("firewall", base, ["del_list firewall.lan.network='lan'"])
    assert out[0].options == (("network", ("guest",)),)
    # the last value of a list may go: the option goes with it
    out = undo.apply_batch("firewall", base, ["del_list firewall.lan.network='guest'"])
    assert out[0].options == (("network", ("lan",)),)
    out = undo.apply_batch(
        "firewall",
        base,
        ["del_list firewall.lan.network='lan'", "del_list firewall.lan.network='guest'"],
    )
    assert out[0].options == ()


def test_uc02_apply_batch_addresses():
    base = [
        Section("rule", None, (("src", "wan"),)),
        Section("rule", None, (("src", "lan"),)),
        Section("rule", None, (("src", "guest"),)),
    ]
    # @TYPE[K] counts the sections of that type from the start
    out = undo.apply_batch("firewall", base, ["set firewall.@rule[1].src='dmz'"])
    assert out[1].options == (("src", "dmz"),)
    # @TYPE[-1] counts from the end
    out = undo.apply_batch("firewall", base, ["set firewall.@rule[-1].src='dmz'"])
    assert out[2].options == (("src", "dmz"),)
    # out of range is refused
    with pytest.raises(UndoError):
        undo.apply_batch("firewall", base, ["set firewall.@rule[3].src='dmz'"])
    with pytest.raises(UndoError):
        undo.apply_batch("firewall", base, ["set firewall.@rule[-4].src='dmz'"])
    # a type that is not there is refused
    with pytest.raises(UndoError):
        undo.apply_batch("firewall", base, ["set firewall.@zone[0].src='dmz'"])


def test_uc02_apply_batch_reorder():
    base = [
        Section("interface", "lan", ()),
        Section("interface", "wan", ()),
        Section("interface", "guest", ()),
    ]
    out = undo.apply_batch("network", base, ["reorder network.guest=0"])
    assert [section.name for section in out] == ["guest", "lan", "wan"]
    out = undo.apply_batch("network", base, ["reorder network.lan=2"])
    assert [section.name for section in out] == ["wan", "guest", "lan"]


def test_uc02_apply_batch_refuses():
    base = [Section("interface", "lan", (("proto", "static"),))]
    # the package of the line must be the package of the call
    with pytest.raises(UndoError):
        undo.apply_batch("network", base, ["set wireless.lan.proto='dhcp'"])
    # deleting what is not there
    with pytest.raises(UndoError):
        undo.apply_batch("network", base, ["delete network.wan"])
    with pytest.raises(UndoError):
        undo.apply_batch("network", base, ["delete network.lan.metric"])
    # a single valued option cannot take a list value
    with pytest.raises(UndoError):
        undo.apply_batch("network", base, ["add_list network.lan.proto='dhcp'"])
    # a value that is not in the list
    with pytest.raises(UndoError):
        undo.apply_batch("network", base, ["del_list network.lan.proto='dhcp'"])
    # reorder out of bounds
    with pytest.raises(UndoError):
        undo.apply_batch("network", base, ["reorder network.lan=1"])
    with pytest.raises(UndoError):
        undo.apply_batch("network", base, ["reorder network.lan=-1"])
    # an empty line and a line with too many words
    with pytest.raises(UndoError):
        undo.apply_batch("network", base, [""])
    with pytest.raises(UndoError):
        undo.apply_batch("network", base, ["set network.lan.proto='a' b c d e"])
    # an unknown verb
    with pytest.raises(UndoError):
        undo.apply_batch("network", base, ["frobnicate network.lan.proto='a'"])


def test_uc02_apply_batch_does_not_mutate_the_input():
    base = [Section("interface", "lan", (("proto", "static"),))]
    snapshot = list(base)
    out = undo.apply_batch("network", base, ["set network.lan.proto='dhcp'"])
    assert base == snapshot
    assert out[0] is not base[0]


# ---------------------------------------------------------------- UC-03


def test_uc03_inverse_of_option_changes():
    current = [Section("interface", "lan", (("proto", "static"), ("ipaddr", "10.0.0.1")))]
    # an option with another value
    target = [Section("interface", "lan", (("proto", "static"), ("ipaddr", "10.0.0.2")))]
    assert undo.inverse_batch("network", current, target) == [
        "set network.lan.ipaddr='10.0.0.2'"
    ]
    # an option that is added
    target = [
        Section(
            "interface",
            "lan",
            (("proto", "static"), ("ipaddr", "10.0.0.1"), ("gateway", "10.0.0.254")),
        )
    ]
    assert undo.inverse_batch("network", current, target) == [
        "set network.lan.gateway='10.0.0.254'"
    ]
    # an option that is removed
    target = [Section("interface", "lan", (("proto", "static"),))]
    assert undo.inverse_batch("network", current, target) == ["delete network.lan.ipaddr"]


# ---------------------------------------------------------------- UC-04


def test_uc04_inverse_of_list_changes():
    current = [Section("zone", "lan", (("network", ("lan", "guest")),))]
    # a value is added
    target = [Section("zone", "lan", (("network", ("lan", "guest", "iot")),))]
    assert undo.inverse_batch("firewall", current, target) == [
        "delete firewall.lan.network",
        "add_list firewall.lan.network='lan'",
        "add_list firewall.lan.network='guest'",
        "add_list firewall.lan.network='iot'",
    ]
    # a value is removed
    target = [Section("zone", "lan", (("network", ("lan",)),))]
    assert undo.inverse_batch("firewall", current, target) == [
        "delete firewall.lan.network",
        "add_list firewall.lan.network='lan'",
    ]
    # the order of a list changed
    target = [Section("zone", "lan", (("network", ("guest", "lan")),))]
    assert undo.inverse_batch("firewall", current, target) == [
        "delete firewall.lan.network",
        "add_list firewall.lan.network='guest'",
        "add_list firewall.lan.network='lan'",
    ]
    # a list becomes a single value
    target = [Section("zone", "lan", (("network", "lan"),))]
    assert undo.inverse_batch("firewall", current, target) == [
        "delete firewall.lan.network",
        "set firewall.lan.network='lan'",
    ]
    # a single value becomes a list
    current = [Section("zone", "lan", (("network", "lan"),))]
    target = [Section("zone", "lan", (("network", ("lan", "guest")),))]
    assert undo.inverse_batch("firewall", current, target) == [
        "delete firewall.lan.network",
        "add_list firewall.lan.network='lan'",
        "add_list firewall.lan.network='guest'",
    ]


# ---------------------------------------------------------------- UC-05


def test_uc05_inverse_of_added_sections():
    # a named section that is not in the current state
    current = [Section("interface", "lan", (("proto", "static"),))]
    target = [
        Section("interface", "lan", (("proto", "static"),)),
        Section("interface", "wan", (("proto", "dhcp"),)),
    ]
    assert undo.inverse_batch("network", current, target) == [
        "set network.wan=interface",
        "set network.wan.proto='dhcp'",
    ]
    # an anonymous section that is not in the current state, in the middle
    current = [
        Section("rule", None, (("src", "wan"),)),
        Section("rule", None, (("src", "lan"),)),
    ]
    target = [
        Section("rule", None, (("src", "wan"),)),
        Section("rule", None, (("src", "dmz"),)),
        Section("rule", None, (("src", "lan"),)),
    ]
    assert undo.inverse_batch("firewall", current, target) == [
        "add firewall rule",
        "set firewall.@rule[-1].src='dmz'",
        "reorder firewall.@rule[2]=1",
    ]


def test_uc05_inverse_of_removed_sections():
    # a named section that is gone
    current = [Section("interface", "lan", ()), Section("interface", "wan", ())]
    target = [Section("interface", "lan", ())]
    assert undo.inverse_batch("network", current, target) == ["delete network.wan"]
    # an anonymous section in the middle of three of the same type
    current = [
        Section("rule", None, (("src", "wan"),)),
        Section("rule", None, (("src", "lan"),)),
        Section("rule", None, (("src", "guest"),)),
    ]
    target = [
        Section("rule", None, (("src", "wan"),)),
        Section("rule", None, (("src", "guest"),)),
    ]
    assert undo.inverse_batch("firewall", current, target) == ["delete firewall.@rule[1]"]


# ---------------------------------------------------------------- UC-06


def test_uc06_two_anonymous_deletions_of_the_same_type():
    current = [
        Section("rule", None, (("src", "wan"),)),
        Section("rule", None, (("src", "lan"),)),
        Section("rule", None, (("src", "guest"),)),
    ]
    assert undo.inverse_batch("firewall", current, []) == [
        "delete firewall.@rule[2]",
        "delete firewall.@rule[1]",
        "delete firewall.@rule[0]",
    ]


# ---------------------------------------------------------------- UC-07


def test_uc07_renamed_and_retyped_named_sections():
    # a renamed section is deleted and added again
    current = [Section("interface", "lan", (("proto", "static"),))]
    target = [Section("interface", "wan", (("proto", "static"),))]
    lines = undo.inverse_batch("network", current, target)
    assert lines == [
        "delete network.lan",
        "set network.wan=interface",
        "set network.wan.proto='static'",
    ]
    assert undo.apply_batch("network", current, lines) == target
    # a section with another type is deleted and added again
    target = [Section("zone", "lan", (("proto", "static"),))]
    lines = undo.inverse_batch("network", current, target)
    assert lines == [
        "delete network.lan",
        "set network.lan=zone",
        "set network.lan.proto='static'",
    ]
    assert undo.apply_batch("network", current, lines) == target


# ---------------------------------------------------------------- UC-08


def test_uc08_identical_states_need_no_lines():
    state = [
        Section("interface", "lan", (("proto", "static"),)),
        Section("rule", None, (("src", "wan"),)),
    ]
    assert undo.inverse_batch("network", state, list(state)) == []


# ---------------------------------------------------------------- UC-09


@pytest.mark.parametrize(
    "bad",
    [
        "it's",
        'say "hi"',
        "back\\slash",
        "two\nlines",
        "caf\u00e9",
    ],
)
def test_uc09_unsafe_values_are_refused(bad):
    current = [Section("interface", "lan", (("proto", "static"),))]
    target = [Section("interface", "lan", (("proto", bad),))]
    with pytest.raises(UndoError) as excinfo:
        undo.inverse_batch("network", current, target)
    message = str(excinfo.value)
    assert "network.lan.proto" in message
    assert bad not in message


def test_uc09_a_bad_option_name_is_refused():
    current = [Section("interface", "lan", (("proto", "static"),))]
    target = [Section("interface", "lan", (("proto", "static"), ("bad name", "x")))]
    with pytest.raises(UndoError):
        undo.inverse_batch("network", current, target)


# ------------------------------------------------------------- UC-10/11


TYPES = ("rule", "zone", "interface")
VALUES = ("a", "bb", "c-c", "d", "1", "2")


def _random_package(rng: random.Random) -> list[Section]:
    sections: list[Section] = []
    for index in range(rng.randrange(0, 9)):
        stype = rng.choice(TYPES)
        name = f"n{index}" if rng.random() < 0.5 else None
        options: list[tuple[str, str | tuple[str, ...]]] = []
        for slot in range(rng.randrange(0, 6)):
            oname = f"o{slot}"
            if rng.random() < 0.3:
                options.append((oname, tuple(rng.choice(VALUES) for _ in range(rng.randrange(1, 4)))))
            else:
                options.append((oname, rng.choice(VALUES)))
        sections.append(Section(stype, name, tuple(options)))
    return sections


def _mutate(rng: random.Random, sections: list[Section]) -> list[Section]:
    out = [Section(section.type, section.name, tuple(section.options)) for section in sections]
    for _ in range(rng.randrange(0, 4)):
        if not out:
            break
        index = rng.randrange(len(out))
        section = out[index]
        options = list(section.options)
        if options and rng.random() < 0.6:
            slot = rng.randrange(len(options))
            oname, value = options[slot]
            if isinstance(value, tuple):
                new: str | tuple[str, ...] = rng.choice(VALUES)
            else:
                new = tuple(rng.choice(VALUES) for _ in range(rng.randrange(1, 4)))
            options[slot] = (oname, new)
        else:
            oname = f"x{rng.randrange(0, 5)}"
            if any(name == oname for name, _ in options):
                continue
            value = rng.choice(VALUES)
            if rng.random() < 0.3:
                value = (value,)
            options.append((oname, value))
        out[index] = Section(section.type, section.name, tuple(options))
    if out and rng.random() < 0.4:
        del out[rng.randrange(len(out))]
    if rng.random() < 0.4:
        stype = rng.choice(TYPES)
        name = None
        if rng.random() < 0.5:
            candidate = f"m{rng.randrange(0, 10000)}"
            while any(section.name == candidate for section in out):
                candidate = f"m{rng.randrange(0, 10000)}"
            name = candidate
        out.append(Section(stype, name, ()))
    if len(out) > 1 and rng.random() < 0.5:
        first = rng.randrange(len(out))
        second = rng.randrange(len(out))
        out[first], out[second] = out[second], out[first]
    return out


def _cases(seed: int = 1234, count: int = 400) -> list[tuple[str, list[Section], list[Section]]]:
    rng = random.Random(seed)
    cases: list[tuple[str, list[Section], list[Section]]] = []
    for _ in range(count):
        before = _random_package(rng)
        cases.append(("network", before, _mutate(rng, before)))
    return cases


def _equivalent(left: list[Section], right: list[Section]) -> bool:
    """Same sections in the same order; the order of the options inside a section does not count."""
    if len(left) != len(right):
        return False
    for one, other in zip(left, right):
        if one.type != other.type or one.name != other.name:
            return False
        first = dict(one.options)
        second = dict(other.options)
        if first.keys() != second.keys():
            return False
        for key, value in first.items():
            mine = second[key]
            if isinstance(value, tuple) != isinstance(mine, tuple):
                return False
            if isinstance(value, tuple):
                if tuple(value) != tuple(mine):
                    return False
            elif value != mine:
                return False
    return True


def test_uc10_the_inverse_turns_the_current_state_into_the_target():
    for package, before, after in _cases():
        lines = undo.inverse_batch(package, after, before)
        result = undo.apply_batch(package, after, lines)
        assert _equivalent(result, before), (package, after, before, lines)
        for line in lines:
            assert line.split(" ", 1)[0] in VERBS, line


def test_uc11_every_line_is_one_verb_and_one_argument():
    for package, before, after in _cases():
        for line in undo.inverse_batch(package, after, before):
            assert "\n" not in line
            assert all(0x20 <= ord(char) <= 0x7E for char in line), line
            verb, separator, argument = line.partition(" ")
            assert separator == " "
            assert verb in VERBS, line
            assert argument, line
            assert "  " not in line, line


# ---------------------------------------------------------------- UC-12


def _write_tar(path: Path, members: list[tuple[str, bytes | None, int]]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, data, kind in members:
            info = tarfile.TarInfo(name)
            if kind == tarfile.DIRTYPE:
                info.type = tarfile.DIRTYPE
                info.size = 0
                archive.addfile(info)
            elif kind == tarfile.SYMTYPE:
                info.type = tarfile.SYMTYPE
                info.linkname = "etc/config/target"
                info.size = 0
                archive.addfile(info)
            else:
                payload = data or b""
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))


def test_uc12_read_config_members(tmp_path):
    tar_path = tmp_path / "backup.tar.gz"
    _write_tar(
        tar_path,
        [
            ("etc/config/firewall", b"config zone\n", tarfile.REGTYPE),
            ("etc/config/dhcp", b"config dnsmasq\n", tarfile.REGTYPE),
            ("./etc/config/wireless", b"config wifi-device\n", tarfile.REGTYPE),
            ("etc/config/link", None, tarfile.SYMTYPE),
            ("etc/config", None, tarfile.DIRTYPE),
            ("etc/config/../../x", b"nope\n", tarfile.REGTYPE),
        ],
    )
    got = undo.read_config_members(
        tar_path, {"firewall", "dhcp", "wireless", "link", "missing", "x"}
    )
    assert got["firewall"] == b"config zone\n"
    assert got["dhcp"] == b"config dnsmasq\n"
    assert got["wireless"] == b"config wifi-device\n"
    assert got["link"] is None
    assert got["missing"] is None
    assert got["x"] is None


def test_uc12_a_member_over_the_limit_is_refused(tmp_path):
    tar_path = tmp_path / "big.tar.gz"
    _write_tar(tar_path, [("etc/config/firewall", b"x" * 100, tarfile.REGTYPE)])
    with pytest.raises(UndoError, match="too large"):
        undo.read_config_members(tar_path, {"firewall"}, max_member_bytes=10)


def test_uc12_a_corrupt_tar_is_refused(tmp_path):
    broken = tmp_path / "broken.tar.gz"
    broken.write_bytes(b"this is not a tarball")
    with pytest.raises(UndoError, match="backup cannot be read"):
        undo.read_config_members(broken, {"firewall"})


def test_uc12_a_wanted_name_that_is_not_a_name_is_refused(tmp_path):
    tar_path = tmp_path / "backup.tar.gz"
    _write_tar(tar_path, [("etc/config/firewall", b"x", tarfile.REGTYPE)])
    with pytest.raises(ValueError):
        undo.read_config_members(tar_path, {"../etc/passwd"})


def test_uc12_only_the_wanted_members_are_read(tmp_path, monkeypatch):
    tar_path = tmp_path / "backup.tar.gz"
    _write_tar(
        tar_path,
        [
            ("etc/config/firewall", b"a", tarfile.REGTYPE),
            ("etc/config/dhcp", b"b", tarfile.REGTYPE),
        ],
    )
    read: list[str] = []
    original = tarfile.TarFile.extractfile

    def spy(self, member):
        read.append(member.name)
        return original(self, member)

    monkeypatch.setattr(tarfile.TarFile, "extractfile", spy)
    undo.read_config_members(tar_path, {"firewall"})
    assert read == ["etc/config/firewall"]


# ---------------------------------------------------------------- UC-13


def test_uc13_md5_known_vectors():
    assert undo.md5_hex(b"") == "d41d8cd98f00b204e9800998ecf8427e"
    assert undo.md5_hex(b"abc") == "900150983cd24fb0d6963f7d28e17f72"
    assert undo.md5_hex(b"newton") == "da6fa909f1c0188c539feb08d4496eb7"
    assert undo.md5_hex(b"undo after confirm") == "8598191ba5886fec14bb9c6d19f623d4"


# ---------------------------------------------------------------- UC-14


def test_uc14_the_self_check_refuses_when_the_simulation_disagrees(monkeypatch):
    current = [Section("interface", "lan", (("proto", "static"),))]
    target = [Section("interface", "lan", (("proto", "dhcp"),))]
    # without the break the inverse is one line that works
    assert undo.inverse_batch("network", current, target) == [
        "set network.lan.proto='dhcp'"
    ]

    def broken(package, sections, lines):
        return list(sections)

    monkeypatch.setattr(undo, "apply_batch", broken)
    with pytest.raises(UndoError, match="cannot build a safe inverse"):
        undo.inverse_batch("network", current, target)


def test_uc15_empty_values_cannot_be_restored_and_are_never_simulated_as_set():
    # measured on OpenWrt 25.12.5 (lab-r1, scratch config dir): `uci set pkg.sec.opt=''` creates nothing and
    # deletes an existing option, so an empty value in the backup cannot be written back
    target = undo.parse_uci_config("config rule 'a'\n\toption name 'x'\n\toption e ''\n")
    current = undo.parse_uci_config("config rule 'a'\n\toption name 'x'\n")
    with pytest.raises(undo.UndoError) as info:
        undo.inverse_batch("pkg", current, target)
    assert "pkg.a.e" in str(info.value)
    with pytest.raises(undo.UndoError):
        undo.apply_batch("pkg", current, ["set pkg.a.e=''"])
    with pytest.raises(undo.UndoError):
        undo.apply_batch("pkg", current, ["add_list pkg.a.l=''"])
    # a section that is re-added with an empty option is refused the same way
    with pytest.raises(undo.UndoError):
        undo.inverse_batch("pkg", [], target)
