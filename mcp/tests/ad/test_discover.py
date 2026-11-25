"""newton-ad-discover: the setup commands of a domain, found from DNS.

The tool asks DNS for the domain controllers and prints the commands the
owner would run.  DNS answers are untrusted, so the tests here feed it a
fake resolver (no network, no real domain) and check what it prints:
the order, the quoting, and what it refuses and why.

With ``--preflight`` the tool also checks every controller it found: the
ports 22, 389 and 88, and the clock skew, read-only, from the host the
tool runs on.  Those checks talk to the network, so the tests here feed
it fake sockets and a fixed clock: no test touches a network.
"""

from __future__ import annotations

import base64
import shlex
import shutil
import socket
import struct
import subprocess
from pathlib import Path
from typing import Any, Callable

import pytest

from newton_mcp.ad import discover


REPO_ROOT = Path(__file__).resolve().parents[3]
LAUNCHER = REPO_ROOT / "scripts" / "newton-ad-discover"
SKILL_MD = REPO_ROOT / "SKILL.md"
CHANGELOG_MD = REPO_ROOT / "CHANGELOG.md"
DESIGN_NOTE = REPO_ROOT / "docs" / "proposals" / "ad" / "DESIGN-dns-helpers.md"

DOMAIN = "corp.example.test"
DC_SRV = f"_ldap._tcp.dc._msdcs.{DOMAIN}"
PDC_SRV = f"_ldap._tcp.pdc._msdcs.{DOMAIN}"


def _key_line(fill: int = 0) -> str:
    payload = b"ssh-ed25519"
    blob = len(payload).to_bytes(4, "big") + payload + bytes([fill]) * 32
    return "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + "\n"


class FakeLookup:
    """A resolver that answers from a table and never touches a network.

    A value is a list of names (SRV targets or addresses) or an
    exception to raise.  A name that is not in the table is NXDOMAIN.
    """

    def __init__(self, table: dict[tuple[str, str], object]) -> None:
        self.table = table
        self.asked: list[tuple[str, str]] = []

    def _answer(self, name: str, kind: str) -> list[str]:
        self.asked.append((name, kind))
        value = self.table.get((name.lower(), kind), discover.NoSuchName())
        if isinstance(value, BaseException):
            raise value
        return list(value)  # type: ignore[arg-type]

    def srv_targets(self, name: str) -> list[str]:
        return self._answer(name, "SRV")

    def addresses(self, name: str, kind: str) -> list[str]:
        return self._answer(name, kind)


def _two_dc_table() -> dict[tuple[str, str], object]:
    return {
        (DC_SRV, "SRV"): [f"dc2.{DOMAIN}.", f"DC1.{DOMAIN}."],
        (PDC_SRV, "SRV"): [f"dc1.{DOMAIN}."],
        (f"dc1.{DOMAIN}", "A"): ["192.0.2.11"],
        (f"dc2.{DOMAIN}", "A"): ["192.0.2.12"],
    }


@pytest.fixture
def keyfile(tmp_path: Path) -> Path:
    path = tmp_path / "audit.pub"
    path.write_text(_key_line(), encoding="utf-8")
    return path


def _run(
    argv: list[str],
    lookup: FakeLookup,
    capsys,
    *,
    net: Any = None,
    now: Callable[[], float] | None = None,
    fraction: Callable[[], int] | None = None,
    keyscan: "FakeKeyscan | None" = None,
) -> tuple[int, str, str]:
    extra: dict[str, Any] = {}
    if fraction is not None:
        extra["fraction"] = fraction
    code = discover.main(argv, lookup=lookup, sockets=net, now=now, keyscan=keyscan, **extra)
    out = capsys.readouterr()
    return code, out.out, out.err


def _ops_keyfile(keyfile: Path) -> Path:
    """The operations key next to the audit key: a different key."""
    path = keyfile.parent / "ops.pub"
    if not path.exists():
        path.write_text(_key_line(1), encoding="utf-8")
    return path


def _args(keyfile: Path, *extra: str, platform: str = "windows") -> list[str]:
    """The arguments of a run; a --write run also gets the operations key."""
    argv = ["--domain", DOMAIN, "--platform", platform, "--pubkey", str(keyfile), *extra]
    if "--write" in extra and "--ops-pubkey" not in extra:
        argv += ["--ops-pubkey", str(_ops_keyfile(keyfile))]
    return argv


def test_a_normal_two_dc_domain_prints_the_read_commands(keyfile, capsys) -> None:
    code, out, _ = _run(_args(keyfile), FakeLookup(_two_dc_table()), capsys)

    assert code == 0
    assert f"newton-ad-setup windows --domain {DOMAIN} --pubkey {keyfile} --device dc1 --host dc1.{DOMAIN}" in out
    assert f"newton-ad-setup windows --domain {DOMAIN} --pubkey {keyfile} --device dc2 --host dc2.{DOMAIN}" in out
    assert "[devices.dc1]" in out and 'platform = "ad-windows"' in out
    assert "192.0.2.11" in out
    assert "check this list against your domain controllers" in out
    assert "newton-ad-setup write" not in out


def test_the_samba_platform_prints_the_samba_commands(keyfile, capsys) -> None:
    code, out, _ = _run(
        _args(keyfile, platform="samba"), FakeLookup(_two_dc_table()), capsys
    )

    assert code == 0
    assert "newton-ad-setup samba --domain" in out
    assert 'platform = "ad-samba"' in out


def test_the_pdc_is_marked_and_comes_first_in_the_write_commands(keyfile, capsys) -> None:
    ou = f"OU=Staff,DC=corp,DC=example,DC=test"
    code, out, _ = _run(
        _args(keyfile, "--write", "--ou", ou), FakeLookup(_two_dc_table()), capsys
    )

    assert code == 0
    assert f"dc1.{DOMAIN}  (PDC emulator)" in out
    lines = [line for line in out.splitlines() if line.startswith("newton-ad-setup write")]
    assert len(lines) == 2
    assert "--device dc1-ops" in lines[0] and "--domain-device" not in lines[0]
    assert "--device dc2-ops" in lines[1] and "--domain-device dc1-ops" in lines[1]
    assert f"--ou {shlex.quote(ou)}" in lines[0]
    assert f"--host dc1.{DOMAIN}" in lines[0]


def test_no_pdc_record_says_so_and_withholds_the_write_commands(keyfile, capsys) -> None:
    table = _two_dc_table()
    del table[(PDC_SRV, "SRV")]
    code, out, _ = _run(
        _args(keyfile, "--write", "--ou", "OU=Staff,DC=corp,DC=example,DC=test"),
        FakeLookup(table),
        capsys,
    )

    assert code == 6
    assert "no PDC emulator record" in out
    assert "newton-ad-setup write" not in out
    assert "newton-ad-setup windows" in out
    assert "samba-tool fsmo show" in out and "PDCEmulator" in out


def test_a_pdc_that_is_not_a_listed_dc_is_said_plainly(keyfile, capsys) -> None:
    table = _two_dc_table()
    table[(PDC_SRV, "SRV")] = [f"dc9.{DOMAIN}."]
    code, out, _ = _run(
        _args(keyfile, "--write", "--ou", "OU=Staff,DC=corp,DC=example,DC=test"),
        FakeLookup(table),
        capsys,
    )

    assert code == 6
    assert "the PDC emulator record names a host that is not in the DC list" in out
    assert "newton-ad-setup write" not in out


def test_a_domain_without_a_pdc_record_still_prints_read_commands_without_write(keyfile, capsys) -> None:
    table = _two_dc_table()
    table[(PDC_SRV, "SRV")] = discover.NoSuchName()
    code, out, _ = _run(_args(keyfile), FakeLookup(table), capsys)

    assert code == 0
    assert "no PDC emulator record" in out


HOSTILE = [
    "dc1.corp.example.test;touch$IFS/tmp/x.corp.example.test.",
    "$(id).corp.example.test.",
    "dc`id`.corp.example.test.",
    "dc1.evil.test.",
    "dc1.corp.example.test.evil.test.",
    "dc one.corp.example.test.",
    "-dc.corp.example.test.",
    "dc-.corp.example.test.",
    "dc1..corp.example.test.",
    ("a" * 64) + ".corp.example.test.",
    "\x1b[31mred.corp.example.test.",
    "dcé.corp.example.test.",
    "corp.example.test.",
    ".",
]


def test_hostile_names_are_skipped_with_a_reason_and_never_printed_as_commands(keyfile, capsys) -> None:
    table = _two_dc_table()
    table[(DC_SRV, "SRV")] = [f"dc1.{DOMAIN}.", *HOSTILE]
    code, out, _ = _run(_args(keyfile), FakeLookup(table), capsys)

    assert code == 0
    commands = [line for line in out.splitlines() if line.startswith("newton-ad-setup")]
    assert len(commands) == 1
    for line in out.splitlines():
        assert "\x1b" not in line
        assert "touch" not in line or line.startswith("skipped")
    assert out.count("skipped:") == len(HOSTILE)
    assert "not a valid host name" in out
    assert "outside the domain" in out


def test_an_overlong_name_is_refused(keyfile, capsys) -> None:
    label = "a" * 60
    long_name = ".".join([label] * 4) + f".{DOMAIN}."
    assert len(long_name) > 253
    table = _two_dc_table()
    table[(DC_SRV, "SRV")] = [f"dc1.{DOMAIN}.", long_name]
    code, out, _ = _run(_args(keyfile), FakeLookup(table), capsys)

    assert code == 0
    assert "longer than 253" in out
    assert len([l for l in out.splitlines() if l.startswith("newton-ad-setup")]) == 1


def test_too_many_records_are_capped_with_a_printed_reason(keyfile, capsys) -> None:
    names = [f"dc{n}.{DOMAIN}." for n in range(1, 41)]
    table: dict[tuple[str, str], object] = {(DC_SRV, "SRV"): names}
    for n in range(1, 41):
        table[(f"dc{n}.{DOMAIN}", "A")] = ["192.0.2.1"]
    code, out, _ = _run(_args(keyfile), FakeLookup(table), capsys)

    assert code == 0
    commands = [line for line in out.splitlines() if line.startswith("newton-ad-setup")]
    assert len(commands) == discover.MAX_DCS == 32
    assert "40 records, using the first 32" in out


def test_nxdomain_is_a_plain_error_with_exit_code_3(keyfile, capsys) -> None:
    code, out, err = _run(_args(keyfile), FakeLookup({}), capsys)

    assert code == 3
    assert out == ""
    assert "no domain controller records" in err
    assert DOMAIN in err


def test_a_timeout_is_a_plain_error_with_exit_code_4(keyfile, capsys) -> None:
    table = {(DC_SRV, "SRV"): discover.DnsTimeout()}
    code, out, err = _run(_args(keyfile), FakeLookup(table), capsys)

    assert code == 4
    assert out == ""
    assert "did not answer in time" in err


def test_only_hostile_records_leave_no_usable_dc_exit_5(keyfile, capsys) -> None:
    table: dict[tuple[str, str], object] = {(DC_SRV, "SRV"): ["dc1.evil.test."]}
    code, out, err = _run(_args(keyfile), FakeLookup(table), capsys)

    assert code == 5
    assert "no usable domain controller" in err
    assert "newton-ad-setup" not in out


def test_an_aaaa_only_dc_is_listed_with_its_address(keyfile, capsys) -> None:
    table: dict[tuple[str, str], object] = {
        (DC_SRV, "SRV"): [f"dc1.{DOMAIN}."],
        (PDC_SRV, "SRV"): [f"dc1.{DOMAIN}."],
        (f"dc1.{DOMAIN}", "A"): discover.NoAnswer(),
        (f"dc1.{DOMAIN}", "AAAA"): ["2001:db8::11"],
    }
    code, out, _ = _run(_args(keyfile), FakeLookup(table), capsys)

    assert code == 0
    assert "2001:db8::11" in out
    assert f"--host dc1.{DOMAIN}" in out


def test_a_dc_with_no_address_is_listed_with_a_warning(keyfile, capsys) -> None:
    table: dict[tuple[str, str], object] = {(DC_SRV, "SRV"): [f"dc1.{DOMAIN}."]}
    code, out, _ = _run(_args(keyfile), FakeLookup(table), capsys)

    assert code == 0
    assert "no address found" in out


def test_garbage_addresses_are_dropped(keyfile, capsys) -> None:
    table = _two_dc_table()
    table[(f"dc1.{DOMAIN}", "A")] = ["999.1.1.1", "192.0.2.11; rm -rf /"]
    code, out, _ = _run(_args(keyfile), FakeLookup(table), capsys)

    assert "rm -rf" not in out
    assert "999.1.1.1" not in out


def test_an_address_with_a_scope_id_is_dropped_with_an_escaped_reason(keyfile, capsys) -> None:
    """A scope id names an interface of the host: the tool never uses it."""
    scoped = "fe80::11%eth\x1b[31m"
    table = _two_dc_table()
    table[(f"dc1.{DOMAIN}", "A")] = [scoped]
    net = FakeSockets()

    code, out, _ = _preflight(keyfile, capsys, net, lookup=FakeLookup(table))

    assert "\x1b" not in out
    assert "fe80::11%eth\\x1b[31m" in out
    assert "scope id" in out
    assert scoped not in out
    # never connected to
    assert not any("%" in sock.connected[0] for sock in net.tcp)
    assert not any("%" in sock.connected[0] for sock in net.udp)
    assert len(net.tcp) == 3  # only the controller that has an address
    assert code == 1  # the clock of the controller without an address is unknown


def test_a_scope_id_address_does_not_cost_the_other_addresses(keyfile, capsys) -> None:
    table = _two_dc_table()
    table[(f"dc1.{DOMAIN}", "A")] = ["192.0.2.11", "fe80::11%eth0"]
    net = FakeSockets()

    code, out, _ = _preflight(keyfile, capsys, net, lookup=FakeLookup(table))

    assert "192.0.2.11" in out
    assert "scope id" in out
    assert net.udp[0].connected == ("192.0.2.11", 123)
    assert code == 0


def test_the_scope_id_refusals_of_one_host_are_capped(keyfile, capsys) -> None:
    """DNS is untrusted: the refusals of one host cannot fill the output."""
    table = _two_dc_table()
    table[(f"dc1.{DOMAIN}", "A")] = [f"fe80::{n}%eth0" for n in range(20)]

    code, out, _ = _run(_args(keyfile), FakeLookup(table), capsys)

    refusals = [line for line in out.splitlines() if "scope id" in line]
    assert len(refusals) == discover.MAX_REFUSALS
    # what was cut is said out loud
    assert (
        f"{20 - discover.MAX_REFUSALS} scope-id refusals past the first "
        f"{discover.MAX_REFUSALS} were not printed"
    ) in out


def test_the_address_records_of_one_host_are_capped(keyfile, capsys) -> None:
    """DNS is untrusted: the records read for one host are bounded too."""
    table = _two_dc_table()
    table[(f"dc1.{DOMAIN}", "A")] = [f"192.0.2.{n}" for n in range(1, 200)]

    code, out, _ = _run(_args(keyfile), FakeLookup(table), capsys)

    assert "192.0.2.1" in out
    # what was cut is said out loud
    assert (
        f"{199 - discover.MAX_ADDRESS_RECORDS} address records past the first "
        f"{discover.MAX_ADDRESS_RECORDS} were not read"
    ) in out


def test_the_aaaa_records_past_a_spent_budget_are_counted_once(keyfile, capsys) -> None:
    table = _two_dc_table()
    table[(f"dc1.{DOMAIN}", "A")] = [f"192.0.2.{n}" for n in range(1, 101)]
    table[(f"dc1.{DOMAIN}", "AAAA")] = [f"2001:db8::{n:x}" for n in range(1, 101)]

    code, out, _ = _run(_args(keyfile), FakeLookup(table), capsys)

    cut = 200 - discover.MAX_ADDRESS_RECORDS
    assert f"{cut} address records past the first" in out


def test_a_device_name_that_cannot_be_derived_is_skipped(keyfile, capsys) -> None:
    table = _two_dc_table()
    table[(DC_SRV, "SRV")] = [f"dc1.{DOMAIN}.", f"1dc.{DOMAIN}."]
    code, out, _ = _run(_args(keyfile), FakeLookup(table), capsys)

    assert "no device name" in out
    assert len([l for l in out.splitlines() if l.startswith("newton-ad-setup")]) == 1


def test_two_hosts_with_one_short_name_do_not_share_a_device(keyfile, capsys) -> None:
    table = _two_dc_table()
    table[(DC_SRV, "SRV")] = [f"dc1.{DOMAIN}.", f"dc1.site2.{DOMAIN}."]
    code, out, _ = _run(_args(keyfile), FakeLookup(table), capsys)

    assert "same device name" in out
    assert len([l for l in out.splitlines() if l.startswith("newton-ad-setup")]) == 1


def test_every_value_in_a_command_is_shell_quoted(tmp_path, capsys) -> None:
    key = tmp_path / "my key; id.pub"
    key.write_text(_key_line(), encoding="utf-8")
    ou = "OU=Sales Team,DC=corp,DC=example,DC=test"
    code, out, _ = _run(
        _args(key, "--write", "--ou", ou), FakeLookup(_two_dc_table()), capsys
    )

    assert code == 0
    for line in out.splitlines():
        if line.startswith("newton-ad-setup"):
            parts = shlex.split(line)
            if parts[1] == "write":
                assert str(_ops_keyfile(key)) in parts
                assert ou in parts
            else:
                assert str(key) in parts
    assert shlex.quote(str(key)) in out


OU_STAFF = "OU=Staff,DC=corp,DC=example,DC=test"


def test_the_write_commands_carry_the_operations_key_and_never_the_audit_key(keyfile, capsys) -> None:
    """Codex review 2026-11-24: the write setup authorises its key for
    newton-ops, so it must get the operations key; the audit key stays
    with the audit setup."""
    ops = _ops_keyfile(keyfile)
    code, out, _ = _run(_args(keyfile, "--write", "--ou", OU_STAFF), FakeLookup(_two_dc_table()), capsys)

    assert code == 0
    commands = [shlex.split(line) for line in out.splitlines() if line.startswith("newton-ad-setup")]
    writes = [parts for parts in commands if parts[1] == "write"]
    audits = [parts for parts in commands if parts[1] != "write"]
    assert len(writes) == 2 and len(audits) == 2
    for parts in writes:
        assert parts[parts.index("--pubkey") + 1] == str(ops)
        assert str(keyfile) not in parts
    for parts in audits:
        assert parts[parts.index("--pubkey") + 1] == str(keyfile)


def test_write_needs_the_operations_key(keyfile, capsys) -> None:
    argv = ["--domain", DOMAIN, "--platform", "windows", "--pubkey", str(keyfile), "--write", "--ou", OU_STAFF]
    code, out, err = _run(argv, FakeLookup(_two_dc_table()), capsys)

    assert code == 2
    assert "--ops-pubkey" in err
    assert "newton-ad-setup" not in out


def test_the_operations_key_must_not_be_the_audit_key(keyfile, capsys, tmp_path) -> None:
    same = tmp_path / "same.pub"
    same.write_text(keyfile.read_text(encoding="utf-8").strip() + " a-comment\n", encoding="utf-8")
    code, out, err = _run(
        _args(keyfile, "--write", "--ou", OU_STAFF, "--ops-pubkey", str(same)), FakeLookup(_two_dc_table()), capsys
    )

    assert code == 2
    assert "audit key" in err
    assert "newton-ad-setup" not in out


def test_the_operations_key_is_only_used_with_write(keyfile, capsys) -> None:
    code, out, err = _run(
        _args(keyfile, "--ops-pubkey", str(_ops_keyfile(keyfile))), FakeLookup(_two_dc_table()), capsys
    )

    assert code == 2
    assert "--ops-pubkey" in err


def test_write_needs_an_ou(keyfile, capsys) -> None:
    code, out, err = _run(_args(keyfile, "--write"), FakeLookup(_two_dc_table()), capsys)

    assert code == 2
    assert "--ou" in err


def test_an_ou_outside_the_domain_is_refused(keyfile, capsys) -> None:
    code, out, err = _run(
        _args(keyfile, "--write", "--ou", "OU=X,DC=other,DC=test"),
        FakeLookup(_two_dc_table()),
        capsys,
    )

    assert code == 2


def test_a_bad_domain_or_key_is_refused_before_any_lookup(tmp_path, capsys) -> None:
    lookup = FakeLookup(_two_dc_table())
    bad = tmp_path / "bad.pub"
    bad.write_text("not a key\n", encoding="utf-8")

    code, _, _ = _run(["--domain", "bad domain", "--platform", "windows", "--pubkey", str(bad)], lookup, capsys)
    assert code == 2
    code, _, _ = _run(["--domain", DOMAIN, "--platform", "windows", "--pubkey", str(bad)], lookup, capsys)
    assert code == 2
    assert lookup.asked == []


def test_it_asks_for_the_dc_and_pdc_records_and_the_addresses_only(keyfile, capsys) -> None:
    lookup = FakeLookup(_two_dc_table())
    _run(_args(keyfile), lookup, capsys)

    kinds = {(n, k) for n, k in lookup.asked}
    assert (DC_SRV, "SRV") in kinds and (PDC_SRV, "SRV") in kinds
    assert all(k in {"SRV", "A", "AAAA"} for _, k in kinds)


def test_the_setup_command_path_comes_from_the_launcher(keyfile, capsys, monkeypatch) -> None:
    monkeypatch.setenv("NEWTON_AD_SETUP", "/opt/newton dir/scripts/newton-ad-setup")
    code, out, _ = _run(_args(keyfile), FakeLookup(_two_dc_table()), capsys)

    assert "'/opt/newton dir/scripts/newton-ad-setup' windows --domain" in out


# ---- the real resolver, with dnspython's answers faked offline ---------------


def test_the_real_resolver_maps_dnspython_errors(monkeypatch) -> None:
    import dns.exception
    import dns.resolver

    resolver = discover.DnsLookup(resolver_ip=None)

    def raise_nx(self, *a, **k):
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", raise_nx)
    with pytest.raises(discover.NoSuchName):
        resolver.srv_targets("x.test")

    def raise_na(self, *a, **k):
        raise dns.resolver.NoAnswer()

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", raise_na)
    with pytest.raises(discover.NoAnswer):
        resolver.addresses("x.test", "A")

    def raise_to(self, *a, **k):
        raise dns.exception.Timeout()

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", raise_to)
    with pytest.raises(discover.DnsTimeout):
        resolver.srv_targets("x.test")

    def raise_nn(self, *a, **k):
        raise dns.resolver.NoNameservers()

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", raise_nn)
    with pytest.raises(discover.DnsTimeout):
        resolver.srv_targets("x.test")


def test_the_real_resolver_reads_srv_targets_and_uses_the_given_server(monkeypatch) -> None:
    import dns.rdata
    import dns.rdataclass
    import dns.rdatatype
    import dns.resolver

    seen = {}
    rdata = dns.rdata.from_text(
        dns.rdataclass.IN, dns.rdatatype.SRV, "0 100 389 dc1.corp.example.test."
    )

    def fake_resolve(self, name, rdtype, **kwargs):
        seen["nameservers"] = list(self.nameservers)
        seen["lifetime"] = self.lifetime
        return [rdata]

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", fake_resolve)
    lookup = discover.DnsLookup(resolver_ip="192.0.2.53")

    assert lookup.srv_targets("x.test") == ["dc1.corp.example.test."]
    assert seen["nameservers"] == ["192.0.2.53"]
    assert seen["lifetime"] <= 10


def test_a_resolver_flag_that_is_not_an_ip_is_refused(keyfile, capsys) -> None:
    code, _, err = _run(
        _args(keyfile, "--resolver", "not-an-ip; id"), FakeLookup(_two_dc_table()), capsys
    )

    assert code == 2


def test_the_resolver_flag_says_it_is_for_the_discovery_only(capsys) -> None:
    with pytest.raises(SystemExit) as stopped:
        discover.main(["--help"])

    assert stopped.value.code == 0
    help_text = " ".join(capsys.readouterr().out.split())
    assert "--resolver" in help_text
    assert "the lookups of the discovery" in help_text
    assert "system resolver" in help_text


def test_the_launcher_runs_and_refuses_bad_arguments(tmp_path) -> None:
    result = subprocess.run(
        [str(LAUNCHER), "--domain", "bad domain", "--platform", "windows", "--pubkey", "/nonexistent"],
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 2
    assert "error:" in result.stderr


# ---- the preflight ------------------------------------------------------------

NOW = 1_800_000_000.0  # a fixed Unix time, so the skew of a test is exact

# The byte offsets of an SNTP packet (RFC 4330, figure 1), written out
# here so the fake time server does not depend on the code it checks.
RFC_OFF_STRATUM = 1
RFC_OFF_REFERENCE = 16
RFC_OFF_ORIGINATE = 24
RFC_OFF_RECEIVE = 32
RFC_OFF_TRANSMIT = 40


def _ntp_seconds(when: float) -> int:
    """A Unix time as the seconds field of an NTP timestamp."""
    return int(when) + discover.NTP_EPOCH_OFFSET


def _sntp_reply(
    seconds: int,
    *,
    mode: int = 4,
    stratum: int = 2,
    fraction: int = 0,
    size: int = 48,
    leap: int = 0,
) -> bytes:
    """A reply of a time server, or one that must not be accepted.

    The reply is built the way RFC 4330 (figure 1) lays a packet out:
    the reference timestamp (bytes 16..23) and the receive timestamp
    (bytes 32..39) hold values of the fake server that are not the
    request's, the transmit timestamp (bytes 40..47) holds its time.
    The originate timestamp (bytes 24..31) is left empty: the fake
    socket fills it with the transmit timestamp of the request, the way
    a time server copies it.
    """
    packet = bytearray(size)
    if size >= 2:
        packet[0] = (leap << 6) | (4 << 3) | mode
        packet[RFC_OFF_STRATUM] = stratum
    if size >= 48:
        packet[RFC_OFF_REFERENCE : RFC_OFF_REFERENCE + 8] = struct.pack(
            ">II", _ntp_seconds(NOW) - 3600, 0
        )
        packet[RFC_OFF_RECEIVE : RFC_OFF_RECEIVE + 8] = struct.pack(
            ">II", _ntp_seconds(NOW) - 1, 0
        )
        packet[RFC_OFF_TRANSMIT : RFC_OFF_TRANSMIT + 8] = struct.pack(
            ">II", seconds, fraction
        )
    return bytes(packet)


class FakeSocket:
    """A socket object that never touches a network.

    ``answer`` builds the reply of the time server from the request it
    got, the way a real server does: the originate timestamp of the
    reply is the transmit timestamp of the request.
    """

    def __init__(
        self,
        reply: bytes = b"",
        error: BaseException | None = None,
        answer: Callable[[bytes], bytes] | None = None,
        family: int = 0,
    ) -> None:
        self.reply = reply
        self.error = error
        self.answer = answer
        self.family = family
        self.timeout: float | None = None
        self.connected: tuple[str, int] | None = None
        self.sent: list[bytes] = []
        self.received: bytes = b""
        self.closed = False

    def settimeout(self, value: float) -> None:
        self.timeout = value

    def connect(self, address: tuple[str, int]) -> None:
        self.connected = address

    def send(self, data: bytes) -> int:
        self.sent.append(bytes(data))
        return len(data)

    def recv(self, size: int) -> bytes:
        if self.error is not None:
            raise self.error
        if self.answer is not None:
            self.received = self.answer(self.sent[-1] if self.sent else b"")
        else:
            self.received = self.reply
        # A datagram socket hands over the whole datagram, cut short
        # when the buffer is smaller.
        return self.received[:size]

    def close(self) -> None:
        self.closed = True


class FakeSockets:
    """The socket calls of one preflight, answered from a table.

    A port is "open", "closed" or "timeout"; the time query always gets
    the one reply, whose originate timestamp is the transmit timestamp
    of the request, as a real time server sends it.
    """

    def __init__(
        self,
        ports: dict[int, str] | None = None,
        reply: bytes | None = None,
        error: BaseException | None = None,
        echo_origin: bool = True,
        echo_at: int = RFC_OFF_ORIGINATE,
    ) -> None:
        self.ports = ports or {}
        self.reply = reply if reply is not None else _sntp_reply(_ntp_seconds(NOW))
        self.error = error
        self.echo_origin = echo_origin
        self.echo_at = echo_at
        self.tcp: list[FakeSocket] = []
        self.udp: list[FakeSocket] = []

    def create_connection(self, address: tuple[str, int], timeout: float) -> FakeSocket:
        state = self.ports.get(address[1], "open")
        if state == "closed":
            raise ConnectionRefusedError("connection refused")
        if state == "timeout":
            raise socket.timeout("timed out")
        sock = FakeSocket()
        sock.timeout = timeout
        sock.connected = address
        self.tcp.append(sock)
        return sock

    def _answer(self, request: bytes) -> bytes:
        """The reply of the time server: the originate field is the request's.

        The transmit timestamp of the request is copied into the field
        at ``echo_at``: the originate timestamp (bytes 24..31) of a
        protocol-correct reply.
        """
        if not self.echo_origin or len(self.reply) < discover.NTP_PACKET_SIZE:
            return self.reply
        reply = bytearray(self.reply)
        reply[self.echo_at : self.echo_at + 8] = request[RFC_OFF_TRANSMIT : RFC_OFF_TRANSMIT + 8]
        return bytes(reply)

    def socket(self, family: int, socktype: int) -> FakeSocket:
        sock = FakeSocket(self.reply, self.error, self._answer, family)
        self.udp.append(sock)
        return sock


class NoSockets:
    """Fails every call: nothing may be probed without the flag."""

    def create_connection(self, address: tuple[str, int], timeout: float) -> FakeSocket:
        raise AssertionError("the preflight ran without its flag")

    def socket(self, family: int, socktype: int) -> FakeSocket:
        raise AssertionError("the preflight ran without its flag")


def _preflight(
    keyfile: Path,
    capsys,
    net: Any,
    *,
    lookup: FakeLookup | None = None,
    fraction: Callable[[], int] | None = None,
) -> tuple[int, str, str]:
    return _run(
        _args(keyfile, "--preflight"),
        lookup if lookup is not None else FakeLookup(_two_dc_table()),
        capsys,
        net=net,
        now=lambda: NOW,
        fraction=fraction,
    )


def test_the_preflight_reports_every_port_and_the_clock(keyfile, capsys) -> None:
    net = FakeSockets(ports={22: "open", 389: "closed", 88: "timeout"})

    code, out, _ = _preflight(keyfile, capsys, net)

    assert code == 1
    assert "22 SSH: open" in out
    assert "389 LDAP: closed" in out
    assert "88 Kerberos: timeout" in out
    assert "clock skew: +0.0 s" in out
    assert "FAIL" in out


@pytest.mark.parametrize("port", [389, 88])
@pytest.mark.parametrize("state", ["closed", "timeout"])
def test_a_required_port_that_is_not_open_fails_the_dc(keyfile, capsys, port: int, state: str) -> None:
    """LDAP 389 and Kerberos 88 must be open."""
    net = FakeSockets(ports={port: state})

    code, out, _ = _preflight(keyfile, capsys, net)

    assert code == 1
    assert "FAIL" in out
    assert "PASS" not in out
    assert "LDAP 389 and Kerberos 88 must be reachable" in out
    assert "sync the clocks" not in out


@pytest.mark.parametrize("state", ["closed", "timeout"])
def test_a_closed_ssh_port_alone_still_passes(keyfile, capsys, state: str) -> None:
    """Port 22 is only reported: the setup script installs SSH later."""
    net = FakeSockets(ports={22: state})

    code, out, _ = _preflight(keyfile, capsys, net)

    assert code == 0
    assert f"22 SSH: {state}" in out
    assert "PASS" in out
    assert "FAIL" not in out
    assert "must be reachable" not in out


def test_a_closed_ldap_port_fails_even_when_the_clock_cannot_be_read(keyfile, capsys) -> None:
    """FAIL wins over UNKNOWN."""
    net = FakeSockets(ports={389: "closed"}, reply=_sntp_reply(_ntp_seconds(NOW), mode=3))

    code, out, _ = _preflight(keyfile, capsys, net)

    assert code == 1
    assert "FAIL" in out
    assert "UNKNOWN" not in out
    assert "clock skew: unknown" in out
    assert "LDAP 389 and Kerberos 88 must be reachable" in out


def test_a_failed_port_does_not_hide_the_note_about_an_unreadable_clock(keyfile, capsys) -> None:
    net = FakeSockets(ports={389: "closed"}, reply=_sntp_reply(_ntp_seconds(NOW), mode=3))

    code, out, _ = _preflight(keyfile, capsys, net)

    assert code == 1
    assert "must be reachable" in out
    assert "check that the DC answers NTP on UDP 123" in out


def test_a_bad_clock_with_every_port_open_gives_the_clock_step(keyfile, capsys) -> None:
    net = FakeSockets(reply=_sntp_reply(_ntp_seconds(NOW + 301)))

    code, out, _ = _preflight(keyfile, capsys, net)

    assert code == 1
    assert "FAIL" in out
    assert "sync the clocks" in out
    assert "must be reachable" not in out
    assert "could not be checked" not in out


def test_a_valid_time_reply_gives_the_skew(keyfile, capsys) -> None:
    net = FakeSockets(reply=_sntp_reply(_ntp_seconds(NOW + 60)))

    code, out, _ = _preflight(keyfile, capsys, net)

    assert code == 0
    assert "clock skew: +60.0 s" in out


def test_a_reply_that_is_not_from_a_time_server_is_refused(keyfile, capsys) -> None:
    net = FakeSockets(reply=_sntp_reply(_ntp_seconds(NOW), mode=3))

    code, out, _ = _preflight(keyfile, capsys, net)

    assert code == 1
    assert "clock skew: unknown" in out
    assert "not from a time server" in out


def test_a_reply_with_stratum_zero_is_refused(keyfile, capsys) -> None:
    net = FakeSockets(reply=_sntp_reply(_ntp_seconds(NOW), stratum=0))

    code, out, _ = _preflight(keyfile, capsys, net)

    assert code == 1
    assert "clock skew: unknown" in out
    assert "stratum 0" in out


def test_a_short_reply_is_refused(keyfile, capsys) -> None:
    net = FakeSockets(reply=_sntp_reply(_ntp_seconds(NOW), size=20))

    code, out, _ = _preflight(keyfile, capsys, net)

    assert code == 1
    assert "clock skew: unknown" in out
    assert "20 bytes" in out


def test_a_skew_of_exactly_the_limit_passes(keyfile, capsys) -> None:
    net = FakeSockets(reply=_sntp_reply(_ntp_seconds(NOW + 300)))

    code, out, _ = _preflight(keyfile, capsys, net)

    assert code == 0
    assert "PASS" in out
    assert "FAIL" not in out


def test_a_skew_over_the_limit_fails_with_the_next_step(keyfile, capsys) -> None:
    net = FakeSockets(reply=_sntp_reply(_ntp_seconds(NOW + 301)))

    code, out, _ = _preflight(keyfile, capsys, net)

    assert code == 1
    assert "FAIL" in out
    assert "clock skew: +301.0 s" in out
    assert "sync the clocks: the DC with the PDC role is the domain's time source" in out


def test_the_preflight_sends_nothing_on_the_tcp_ports(keyfile, capsys) -> None:
    net = FakeSockets()

    code, _, _ = _preflight(keyfile, capsys, net)

    assert code == 0
    assert len(net.tcp) == 6  # three ports on each of the two controllers
    for sock in net.tcp:
        assert sock.sent == []
        assert sock.closed
        assert sock.timeout == 3.0


def test_the_time_request_is_a_client_packet_with_the_local_time(keyfile, capsys) -> None:
    net = FakeSockets()

    _preflight(keyfile, capsys, net, fraction=lambda: 0x0A0B0C0D)

    request = net.udp[0].sent[0]
    assert len(request) == 48
    assert request[0] == 0x23
    assert request[1:40] == bytes(39)
    seconds, fraction = struct.unpack(">II", request[40:48])
    assert seconds == int(NOW) + discover.NTP_EPOCH_OFFSET
    assert fraction == 0x0A0B0C0D
    assert net.udp[0].connected == ("192.0.2.11", 123)


def test_the_fraction_of_the_request_is_random(keyfile, capsys, monkeypatch) -> None:
    calls: list[int] = []

    def fake_randbits(bits: int) -> int:
        calls.append(bits)
        return 0x12345678

    monkeypatch.setattr(discover.secrets, "randbits", fake_randbits)
    net = FakeSockets()

    _preflight(keyfile, capsys, net)

    request = net.udp[0].sent[0]
    _, fraction = struct.unpack(">II", request[40:48])
    assert fraction == 0x12345678
    assert calls == [32] * len(net.udp)


def test_two_time_queries_do_not_share_their_fraction(keyfile, capsys) -> None:
    net = FakeSockets()

    _preflight(keyfile, capsys, net)

    fractions = [struct.unpack(">II", sock.sent[0][40:48])[1] for sock in net.udp]
    assert len(set(fractions)) == len(fractions)


def test_the_reply_carries_the_transmit_field_of_the_request(keyfile, capsys) -> None:
    net = FakeSockets()

    code, out, _ = _preflight(keyfile, capsys, net)

    request = net.udp[0].sent[0]
    reply = net.udp[0].received
    assert reply[RFC_OFF_ORIGINATE : RFC_OFF_ORIGINATE + 8] == request[
        RFC_OFF_TRANSMIT : RFC_OFF_TRANSMIT + 8
    ]
    assert code == 0
    assert "PASS" in out


def test_the_sntp_offsets_are_the_ones_of_rfc_4330(keyfile, capsys) -> None:
    """RFC 4330, figure 1: the layout of an SNTP packet."""
    assert discover.NTP_OFF_LEAP_MODE == 0
    assert discover.NTP_OFF_STRATUM == RFC_OFF_STRATUM
    assert discover.NTP_OFF_REFERENCE == RFC_OFF_REFERENCE
    assert discover.NTP_OFF_ORIGINATE == RFC_OFF_ORIGINATE
    assert discover.NTP_OFF_RECEIVE == RFC_OFF_RECEIVE
    assert discover.NTP_OFF_TRANSMIT == RFC_OFF_TRANSMIT
    assert discover.NTP_PACKET_SIZE == 48

    # A packet built byte by byte, with the offsets written out and not
    # taken from the code: the echo of the request is at 24..31 and the
    # time of the server at 40..47.
    echo = struct.pack(">II", _ntp_seconds(NOW), 0x0A0B0C0D)
    packet = bytearray(48)
    packet[0] = 0x24  # LI 0, version 4, mode 4 (a time server)
    packet[1] = 2  # stratum
    packet[24:32] = echo  # originate: the echo of the request
    packet[32:40] = struct.pack(">II", _ntp_seconds(NOW) - 1, 0)  # receive
    packet[40:48] = struct.pack(">II", _ntp_seconds(NOW + 60), 0)  # transmit
    net = FakeSockets(reply=bytes(packet), echo_origin=False)

    code, out, _ = _preflight(keyfile, capsys, net, fraction=lambda: 0x0A0B0C0D)

    assert code == 0
    assert "clock skew: +60.0 s" in out
    assert "PASS" in out

    # The same packet with the echo at 16..23 instead: it is a reply to
    # another query, so it is not the clock of the controller.
    wrong = bytearray(packet)
    wrong[16:24] = echo
    wrong[24:32] = bytes(8)
    net = FakeSockets(reply=bytes(wrong), echo_origin=False)

    code, out, _ = _preflight(keyfile, capsys, net, fraction=lambda: 0x0A0B0C0D)

    assert code == 1
    assert "clock skew: unknown" in out
    assert "does not belong" in out
    assert "PASS" not in out
    assert "FAIL" not in out


def test_a_protocol_correct_reply_is_the_clock_of_the_controller(keyfile, capsys) -> None:
    """The origin timestamp of the reply is the transmit timestamp of the request."""
    net = FakeSockets(reply=_sntp_reply(_ntp_seconds(NOW + 60)))

    code, out, _ = _preflight(keyfile, capsys, net)

    request = net.udp[0].sent[0]
    reply = net.udp[0].received
    assert reply[RFC_OFF_ORIGINATE : RFC_OFF_ORIGINATE + 8] == request[
        RFC_OFF_TRANSMIT : RFC_OFF_TRANSMIT + 8
    ]
    # the reference and the receive timestamps are the server's own
    assert reply[RFC_OFF_REFERENCE : RFC_OFF_REFERENCE + 8] != request[
        RFC_OFF_TRANSMIT : RFC_OFF_TRANSMIT + 8
    ]
    assert reply[RFC_OFF_RECEIVE : RFC_OFF_RECEIVE + 8] != request[
        RFC_OFF_TRANSMIT : RFC_OFF_TRANSMIT + 8
    ]
    assert code == 0
    assert "clock skew: +60.0 s" in out
    assert "PASS" in out


def test_a_reply_that_echoes_the_request_in_the_reference_field_is_refused(keyfile, capsys) -> None:
    """The echo belongs in the origin timestamp (24..31), not in 16..23."""
    net = FakeSockets(echo_at=RFC_OFF_REFERENCE)

    code, out, _ = _preflight(keyfile, capsys, net)

    request = net.udp[0].sent[0]
    reply = net.udp[0].received
    assert reply[RFC_OFF_REFERENCE : RFC_OFF_REFERENCE + 8] == request[
        RFC_OFF_TRANSMIT : RFC_OFF_TRANSMIT + 8
    ]
    assert reply[RFC_OFF_ORIGINATE : RFC_OFF_ORIGINATE + 8] != request[
        RFC_OFF_TRANSMIT : RFC_OFF_TRANSMIT + 8
    ]
    assert code == 1
    assert "clock skew: unknown" in out
    assert "does not belong" in out
    assert "PASS" not in out
    assert "FAIL" not in out


def test_a_reply_that_is_not_bound_to_the_request_is_refused(keyfile, capsys) -> None:
    net = FakeSockets(echo_origin=False)

    code, out, _ = _preflight(keyfile, capsys, net)

    assert code == 1
    assert "clock skew: unknown" in out
    assert "does not belong" in out
    assert "PASS" not in out
    assert "FAIL" not in out


def test_a_reply_longer_than_48_bytes_is_refused(keyfile, capsys) -> None:
    net = FakeSockets(reply=_sntp_reply(_ntp_seconds(NOW), size=60))

    code, out, _ = _preflight(keyfile, capsys, net)

    assert code == 1
    assert "clock skew: unknown" in out
    assert "60 bytes" in out


def test_a_datagram_past_the_read_size_is_cut_short_and_refused(keyfile, capsys) -> None:
    net = FakeSockets(reply=_sntp_reply(_ntp_seconds(NOW), size=600))

    code, out, _ = _preflight(keyfile, capsys, net)

    assert code == 1
    assert "clock skew: unknown" in out
    assert "512 bytes" in out


def test_a_leap_indicator_of_three_is_refused(keyfile, capsys) -> None:
    net = FakeSockets(reply=_sntp_reply(_ntp_seconds(NOW), leap=3))

    code, out, _ = _preflight(keyfile, capsys, net)

    assert code == 1
    assert "clock skew: unknown" in out
    assert "not synchronized" in out
    assert "PASS" not in out
    assert "FAIL" not in out


@pytest.mark.parametrize("leap", [0, 1, 2])
def test_the_other_leap_indicators_are_accepted(keyfile, capsys, leap: int) -> None:
    net = FakeSockets(reply=_sntp_reply(_ntp_seconds(NOW), leap=leap))

    code, out, _ = _preflight(keyfile, capsys, net)

    assert code == 0
    assert "PASS" in out
    assert "UNKNOWN" not in out


def test_a_reply_with_an_all_zero_transmit_timestamp_is_unknown(keyfile, capsys) -> None:
    """RFC 4330, section 5, check 4: the reply is discarded, not read.

    An all-zero transmit timestamp (bytes 40..47) is no time at all, so
    the clock of the controller is unknown; it is never a skew.
    """
    net = FakeSockets(reply=_sntp_reply(0))

    code, out, _ = _preflight(keyfile, capsys, net)

    assert code == 1
    assert "clock skew: unknown" in out
    assert "transmit timestamp" in out
    assert "PASS" not in out
    assert "FAIL" not in out


def test_an_ipv6_controller_is_asked_over_ipv6(keyfile, capsys) -> None:
    table: dict[tuple[str, str], object] = {
        (DC_SRV, "SRV"): [f"dc1.{DOMAIN}."],
        (PDC_SRV, "SRV"): [f"dc1.{DOMAIN}."],
        (f"dc1.{DOMAIN}", "A"): discover.NoAnswer(),
        (f"dc1.{DOMAIN}", "AAAA"): ["2001:db8::11"],
    }
    net = FakeSockets()

    code, out, _ = _preflight(keyfile, capsys, net, lookup=FakeLookup(table))

    assert code == 0
    assert "2001:db8::11" in out
    assert net.udp[0].family == socket.AF_INET6
    assert net.udp[0].connected == ("2001:db8::11", 123)


def test_an_ipv4_controller_is_asked_over_ipv4(keyfile, capsys) -> None:
    net = FakeSockets()

    _preflight(keyfile, capsys, net)

    assert net.udp[0].family == socket.AF_INET


def test_a_timeout_on_the_time_query_is_unknown(keyfile, capsys) -> None:
    net = FakeSockets(error=socket.timeout("timed out"))

    code, out, _ = _preflight(keyfile, capsys, net)

    assert code == 1
    assert "clock skew: unknown" in out
    assert "did not answer" in out
    assert "PASS" not in out
    assert "FAIL" not in out


def test_an_os_error_on_the_time_query_is_unknown(keyfile, capsys) -> None:
    net = FakeSockets(error=OSError("network is unreachable"))

    code, out, _ = _preflight(keyfile, capsys, net)

    assert code == 1
    assert "clock skew: unknown" in out
    assert "time query failed" in out
    assert "PASS" not in out
    assert "FAIL" not in out


def test_without_the_flag_nothing_is_probed(keyfile, capsys) -> None:
    code, out, _ = _run(
        _args(keyfile), FakeLookup(_two_dc_table()), capsys, net=NoSockets()
    )

    assert code == 0
    assert "Preflight" not in out


def test_the_preflight_says_it_probes_in_the_same_run(keyfile, capsys) -> None:
    """The owner must read the list before the probes: so it says how."""
    net = FakeSockets()

    code, out, _ = _preflight(keyfile, capsys, net)

    assert code == 0
    assert "in this same run" in out
    assert "without --preflight first" in out


def test_the_preflight_says_dns_is_read_again_in_the_second_run(keyfile, capsys) -> None:
    """The first list does not limit the second run: it must say so."""
    net = FakeSockets()

    code, out, _ = _preflight(keyfile, capsys, net)

    assert code == 0
    assert "the first list does not limit what the second run probes" in out
    assert "the addresses it probes are the ones printed here" in out


def test_the_preflight_says_how_many_controllers_it_checked(keyfile, capsys) -> None:
    net = FakeSockets()

    code, out, _ = _preflight(keyfile, capsys, net)

    assert code == 0
    assert "Preflight: 2 DCs checked, 2 passed, 0 failed, 0 unknown." in out


def test_a_controller_without_an_address_is_not_checked(keyfile, capsys) -> None:
    table = _two_dc_table()
    del table[(f"dc2.{DOMAIN}", "A")]
    net = FakeSockets()

    code, out, _ = _preflight(keyfile, capsys, net, lookup=FakeLookup(table))

    assert code == 1
    assert "no address" in out
    assert "UNKNOWN" in out
    assert len(net.tcp) == 3  # only the controller that has an address


# ---- what the docs say --------------------------------------------------------


def _flat(text: str) -> str:
    """The text as one line, so a claim is found however it is wrapped."""
    return " ".join(text.split())


def test_the_docs_say_dns_is_read_again_in_the_second_run() -> None:
    """The second run reads DNS again: the docs must say so everywhere.

    The first list does not limit what the second run probes, and the
    addresses it probes are the ones that run prints.
    """
    claim = "the first list does not limit what the second run probes"
    assert claim in _flat(discover.__doc__ or "")
    for path in (LAUNCHER, SKILL_MD, CHANGELOG_MD, DESIGN_NOTE):
        text = _flat(path.read_text(encoding="utf-8"))
        assert claim in text, path


def test_the_docs_do_not_say_a_long_datagram_is_seen_in_full() -> None:
    """Over 512 bytes the read cuts the datagram: it is not seen in full."""
    doc = _flat(discover.__doc__ or "")
    assert "seen in full" not in doc
    assert "up to 512 bytes are read" in doc
    assert "any length other than 48 is refused" in doc
    note = _flat(DESIGN_NOTE.read_text(encoding="utf-8"))
    assert "seen in full" not in note
    assert "up to 512 bytes are read" in note.lower()


# ---- the host keys, fetched with ssh-keyscan --------------------------------


def _blob(keytype: str, rest: bytes) -> str:
    """A public key blob of the given type, base64 as ssh-keyscan prints it."""
    payload = keytype.encode("ascii")
    raw = len(payload).to_bytes(4, "big") + payload + rest
    return base64.b64encode(raw).decode("ascii")


ED25519 = _blob("ssh-ed25519", bytes(range(32)))
ECDSA256 = _blob("ecdsa-sha2-nistp256", b"\x00\x00\x00\x07nistp256" + bytes(65))
ECDSA384 = _blob("ecdsa-sha2-nistp384", b"\x00\x00\x00\x07nistp384" + bytes(97))
ECDSA521 = _blob("ecdsa-sha2-nistp521", b"\x00\x00\x00\x07nistp521" + bytes(133))
RSA = _blob("ssh-rsa", bytes(4) + bytes(256))


def _scan_line(host: str, keytype: str, blob: str) -> str:
    """One line of ssh-keyscan output."""
    return f"{host} {keytype} {blob}\n"


class FakeKeyscan:
    """A fake ssh-keyscan: it answers from a table and never touches a network.

    The value of a host is the text ssh-keyscan would print, or the
    exception to raise (a timeout, a failure).
    """

    def __init__(self, table: dict[str, object]) -> None:
        self.table = table
        self.calls: list[list[str]] = []
        self.timeouts: list[float] = []

    def __call__(self, argv: list[str], timeout: float) -> str:
        self.calls.append(list(argv))
        self.timeouts.append(timeout)
        value = self.table.get(argv[-1], "")
        if isinstance(value, BaseException):
            raise value
        return str(value)


def _scan_run(
    keyfile: Path,
    runner: FakeKeyscan,
    capsys,
    lookup: FakeLookup | None = None,
) -> tuple[int, str, str]:
    """The tool with --fetch-host-keys and a fake scan."""
    return _run(
        _args(keyfile, "--fetch-host-keys"),
        lookup if lookup is not None else FakeLookup(_two_dc_table()),
        capsys,
        keyscan=runner,
    )


def test_without_the_flag_no_host_key_is_scanned(keyfile, capsys) -> None:
    runner = FakeKeyscan({})

    code, out, _ = _run(_args(keyfile), FakeLookup(_two_dc_table()), capsys, keyscan=runner)

    assert code == 0
    assert runner.calls == []
    assert "SHA256:" not in out
    assert "ssh-keyscan" not in out


def test_the_scan_is_one_ssh_keyscan_per_controller_with_an_argument_list(keyfile, capsys) -> None:
    runner = FakeKeyscan({f"dc1.{DOMAIN}": "", f"dc2.{DOMAIN}": ""})

    code, out, _ = _scan_run(keyfile, runner, capsys)

    assert code == 0
    assert runner.calls == [
        ["ssh-keyscan", "-T", "5", "-t", "ed25519,ecdsa,rsa", "-p", "22", f"dc1.{DOMAIN}"],
        ["ssh-keyscan", "-T", "5", "-t", "ed25519,ecdsa,rsa", "-p", "22", f"dc2.{DOMAIN}"],
    ]
    assert all(timeout > 0 for timeout in runner.timeouts)


def test_the_scan_of_one_host_gets_the_program_timeout(keyfile, capsys) -> None:
    from newton_mcp.ad import hostkeys

    runner = FakeKeyscan({f"dc1.{DOMAIN}": "", f"dc2.{DOMAIN}": ""})

    code, _, _ = _scan_run(keyfile, runner, capsys)

    assert code == 0
    # the program timeout is the ceiling of the scan of one host, so it is
    # what the runner is given; more than 5x ssh-keyscan's own timeout is a
    # margin for a slowly answering endpoint, not a count of sequential
    # rounds: the key types are asked at once (on OpenSSH 9.6, against a
    # silent endpoint, -T 3 takes 3.01 s with one key type and 3.01 s with
    # three: the connections open at the same moment)
    assert hostkeys.PROGRAM_TIMEOUT > 5 * int(hostkeys.SCAN_TIMEOUT)
    assert hostkeys.PROGRAM_TIMEOUT == 30.0
    assert runner.timeouts == [hostkeys.PROGRAM_TIMEOUT, hostkeys.PROGRAM_TIMEOUT]


def test_the_fingerprints_and_the_ready_known_hosts_lines_are_printed(keyfile, capsys) -> None:
    host = f"dc1.{DOMAIN}"
    runner = FakeKeyscan({host: _scan_line(host, "ssh-ed25519", ED25519)})

    code, out, _ = _scan_run(keyfile, runner, capsys)

    assert code == 0
    assert f"{host} ssh-ed25519 {ED25519}" in out
    fingerprints = [
        line.split()[1]
        for line in out.splitlines()
        if line.strip().startswith("ssh-ed25519 SHA256:")
    ]
    assert len(fingerprints) == 1
    assert fingerprints[0].startswith("SHA256:")
    assert "=" not in fingerprints[0]


def test_the_allowed_key_types_are_kept(keyfile, capsys) -> None:
    host = f"dc1.{DOMAIN}"
    runner = FakeKeyscan({
        host: "".join([
            _scan_line(host, "ssh-ed25519", ED25519),
            _scan_line(host, "ecdsa-sha2-nistp256", ECDSA256),
            _scan_line(host, "ecdsa-sha2-nistp384", ECDSA384),
            _scan_line(host, "ecdsa-sha2-nistp521", ECDSA521),
            _scan_line(host, "ssh-rsa", RSA),
        ])
    })

    code, out, _ = _scan_run(keyfile, runner, capsys)

    assert code == 0
    for keytype in (
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "ssh-rsa",
    ):
        assert f"{host} {keytype} " in out


def test_an_unknown_key_type_is_skipped(keyfile, capsys) -> None:
    host = f"dc1.{DOMAIN}"
    runner = FakeKeyscan({
        host: "".join([
            _scan_line(host, "ssh-dss", ED25519),
            _scan_line(host, "sk-ssh-ed25519@openssh.com", ED25519),
            _scan_line(host, "ssh-ed25519", ED25519),
        ])
    })

    code, out, _ = _scan_run(keyfile, runner, capsys)

    assert code == 0
    assert "ssh-dss" not in out
    assert "openssh.com" not in out
    assert f"{host} ssh-ed25519 {ED25519}" in out


def test_the_comment_lines_of_ssh_keyscan_are_ignored(keyfile, capsys) -> None:
    host = f"dc1.{DOMAIN}"
    runner = FakeKeyscan({
        host: f"# {host}:22 SSH-2.0-OpenSSH_9.6\n" + _scan_line(host, "ssh-ed25519", ED25519)
    })

    code, out, _ = _scan_run(keyfile, runner, capsys)

    assert code == 0
    assert "SSH-2.0-OpenSSH" not in out
    assert f"{host} ssh-ed25519 {ED25519}" in out


def test_a_key_with_a_broken_base64_is_dropped(keyfile, capsys) -> None:
    host = f"dc1.{DOMAIN}"
    runner = FakeKeyscan({host: _scan_line(host, "ssh-ed25519", "not-base64!!")})

    code, out, _ = _scan_run(keyfile, runner, capsys)

    assert code == 0
    assert "not-base64" not in out
    assert "no host key was scanned" in out


def test_a_key_whose_blob_is_not_of_the_type_it_names_is_dropped(keyfile, capsys) -> None:
    host = f"dc1.{DOMAIN}"
    runner = FakeKeyscan({host: _scan_line(host, "ssh-ed25519", ECDSA256)})

    code, out, _ = _scan_run(keyfile, runner, capsys)

    assert code == 0
    assert ECDSA256 not in out
    assert "no host key was scanned" in out


def test_a_scan_line_that_names_another_host_never_prints_that_name(keyfile, capsys) -> None:
    host = f"dc1.{DOMAIN}"
    hostile = ("attacker.evil.test", f"dc1.{DOMAIN};id")
    runner = FakeKeyscan({
        host: "".join(_scan_line(name, "ssh-ed25519", ED25519) for name in hostile),
    })

    code, out, _ = _scan_run(keyfile, runner, capsys)

    assert code == 0
    for name in hostile:
        assert name not in out
    # the name that is printed is the one that was asked for
    assert f"{host} ssh-ed25519 {ED25519}" in out


def test_more_keys_than_the_cap_are_capped(keyfile, capsys) -> None:
    from newton_mcp.ad import hostkeys

    host = f"dc1.{DOMAIN}"
    blobs = [
        _blob("ssh-ed25519", bytes([n]) * 32) for n in range(1, hostkeys.MAX_KEYS + 5)
    ]
    runner = FakeKeyscan({
        host: "".join(_scan_line(host, "ssh-ed25519", blob) for blob in blobs),
    })

    code, out, _ = _scan_run(keyfile, runner, capsys)

    assert code == 0
    printed = [
        line for line in out.splitlines() if line.strip().startswith("ssh-ed25519 SHA256:")
    ]
    assert len(printed) == hostkeys.MAX_KEYS
    # the keys past the cap are not printed
    assert blobs[hostkeys.MAX_KEYS] not in out


def test_a_cut_list_of_keys_is_said_so_the_owner_knows_it_is_not_all_of_them(
    keyfile, capsys
) -> None:
    from newton_mcp.ad import hostkeys

    host = f"dc1.{DOMAIN}"
    blobs = [
        _blob("ssh-ed25519", bytes([n]) * 32) for n in range(1, hostkeys.MAX_KEYS + 2)
    ]
    runner = FakeKeyscan({
        host: "".join(_scan_line(host, "ssh-ed25519", blob) for blob in blobs),
    })

    code, out, _ = _scan_run(keyfile, runner, capsys)

    assert code == 0
    assert "the list of host keys was cut" in out
    assert "not all of them" in out


def test_the_cut_note_says_the_ready_known_hosts_lines_are_incomplete_too(
    keyfile, capsys
) -> None:
    from newton_mcp.ad import hostkeys

    host = f"dc1.{DOMAIN}"
    blobs = [
        _blob("ssh-ed25519", bytes([n]) * 32) for n in range(1, hostkeys.MAX_KEYS + 2)
    ]
    runner = FakeKeyscan({
        host: "".join(_scan_line(host, "ssh-ed25519", blob) for blob in blobs),
    })

    code, out, _ = _scan_run(keyfile, runner, capsys)

    assert code == 0
    note = next(
        line for line in out.splitlines() if "the list of host keys was cut" in line
    )
    # the note says the fingerprints are not all of them, and that the ready
    # known_hosts lines below are not all of the keys either
    assert "the fingerprints above are not all of them" in note
    assert "known_hosts" in note
    assert "not all of the keys" in note
    # and the claim is true: one line fewer than the keys the scan gave
    ready = [line for line in out.splitlines() if line.strip().startswith(f"{host} ssh-ed25519 ")]
    assert len(ready) == hostkeys.MAX_KEYS == len(blobs) - 1


def test_a_list_of_exactly_the_cap_is_not_cut(keyfile, capsys) -> None:
    from newton_mcp.ad import hostkeys

    host = f"dc1.{DOMAIN}"
    blobs = [
        _blob("ssh-ed25519", bytes([n]) * 32) for n in range(1, hostkeys.MAX_KEYS + 1)
    ]
    runner = FakeKeyscan({
        host: "".join(_scan_line(host, "ssh-ed25519", blob) for blob in blobs),
    })

    code, out, _ = _scan_run(keyfile, runner, capsys)

    assert code == 0
    assert "the list of host keys was cut" not in out


def test_the_parser_says_when_the_key_list_was_cut() -> None:
    from newton_mcp.ad import hostkeys

    host = "dc1.corp.example.test"
    blobs = [
        _blob("ssh-ed25519", bytes([n]) * 32) for n in range(1, hostkeys.MAX_KEYS + 2)
    ]
    output = "".join(_scan_line(host, "ssh-ed25519", blob) for blob in blobs)

    keys, cut = hostkeys.parse_keys(output)

    assert len(keys) == hostkeys.MAX_KEYS
    assert cut is True


def test_the_parser_says_nothing_was_cut_when_the_list_fits() -> None:
    from newton_mcp.ad import hostkeys

    host = "dc1.corp.example.test"
    blobs = [
        _blob("ssh-ed25519", bytes([n]) * 32) for n in range(1, hostkeys.MAX_KEYS + 1)
    ]
    output = "".join(_scan_line(host, "ssh-ed25519", blob) for blob in blobs)

    keys, cut = hostkeys.parse_keys(output)

    assert len(keys) == hostkeys.MAX_KEYS
    assert cut is False


def test_a_repeated_key_past_the_cap_is_not_a_cut() -> None:
    from newton_mcp.ad import hostkeys

    host = "dc1.corp.example.test"
    blobs = [
        _blob("ssh-ed25519", bytes([n]) * 32) for n in range(1, hostkeys.MAX_KEYS + 1)
    ]
    output = "".join(_scan_line(host, "ssh-ed25519", blob) for blob in blobs)
    output += _scan_line(host, "ssh-ed25519", blobs[0])

    keys, cut = hostkeys.parse_keys(output)

    assert len(keys) == hostkeys.MAX_KEYS
    assert cut is False


def test_a_blob_longer_than_the_cap_is_skipped(keyfile, capsys) -> None:
    from newton_mcp.ad import hostkeys

    host = f"dc1.{DOMAIN}"
    big = _blob("ssh-ed25519", bytes(hostkeys.MAX_BLOB))
    assert len(big) > hostkeys.MAX_BLOB
    runner = FakeKeyscan({host: _scan_line(host, "ssh-ed25519", big)})

    code, out, _ = _scan_run(keyfile, runner, capsys)

    assert code == 0
    assert big not in out
    assert "no host key was scanned" in out


def test_a_scan_without_a_key_is_a_plain_line(keyfile, capsys) -> None:
    host = f"dc1.{DOMAIN}"
    runner = FakeKeyscan({host: ""})

    code, out, _ = _scan_run(keyfile, runner, capsys)

    assert code == 0
    assert "no host key was scanned" in out
    assert "placeholder" in out


def test_a_scan_timeout_is_a_plain_line_and_the_placeholder_stays(keyfile, capsys) -> None:
    host = f"dc1.{DOMAIN}"
    runner = FakeKeyscan({host: subprocess.TimeoutExpired(cmd="ssh-keyscan", timeout=5)})

    code, out, _ = _scan_run(keyfile, runner, capsys)

    assert code == 0
    assert "no host key was scanned" in out
    assert "did not answer in time" in out
    assert "placeholder" in out


def test_a_failing_scan_is_a_plain_line(keyfile, capsys) -> None:
    host = f"dc1.{DOMAIN}"
    runner = FakeKeyscan({host: OSError("ssh-keyscan is not installed")})

    code, out, _ = _scan_run(keyfile, runner, capsys)

    assert code == 0
    assert "no host key was scanned" in out
    assert "placeholder" in out


def test_the_owner_is_told_to_check_the_fingerprint_on_the_console(keyfile, capsys) -> None:
    host = f"dc1.{DOMAIN}"
    runner = FakeKeyscan({host: _scan_line(host, "ssh-ed25519", ED25519)})

    code, out, _ = _scan_run(keyfile, runner, capsys)

    assert code == 0
    assert "ssh-keygen -lf" in out
    assert "console" in out
    assert "spoofed" in out


def test_the_owner_is_told_the_scan_resolves_the_name_with_the_system_resolver(
    keyfile, capsys
) -> None:
    host = f"dc1.{DOMAIN}"
    runner = FakeKeyscan({host: _scan_line(host, "ssh-ed25519", ED25519)})

    code, out, _ = _scan_run(keyfile, runner, capsys)

    assert code == 0
    assert "system resolver" in out
    assert "--resolver" in out


def test_the_tool_writes_no_file(keyfile, capsys, tmp_path, monkeypatch) -> None:
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    host = f"dc1.{DOMAIN}"
    runner = FakeKeyscan({host: _scan_line(host, "ssh-ed25519", ED25519)})

    code, out, _ = _scan_run(keyfile, runner, capsys)

    assert code == 0
    assert list(work.iterdir()) == []


def test_the_real_runner_uses_an_argument_list_and_a_timeout(monkeypatch) -> None:
    from newton_mcp.ad import hostkeys

    seen: dict[str, object] = {}

    def fake_run(argv, **kwargs):
        seen["argv"] = list(argv)
        seen["kwargs"] = kwargs
        return subprocess.CompletedProcess(argv, 0, "the answer", "")

    monkeypatch.setattr(hostkeys.subprocess, "run", fake_run)

    assert hostkeys.run_program(["ssh-keyscan", "host"], 20.0) == "the answer"
    assert seen["argv"] == ["ssh-keyscan", "host"]
    assert seen["kwargs"].get("shell") in (None, False)
    assert seen["kwargs"]["timeout"] == 20.0


def test_run_program_passes_its_timeout_to_the_process(monkeypatch) -> None:
    from newton_mcp.ad import hostkeys

    seen: dict[str, object] = {}

    def fake_run(argv, **kwargs):
        seen["timeout"] = kwargs.get("timeout")
        return subprocess.CompletedProcess(argv, 0, "the answer", "")

    monkeypatch.setattr(hostkeys.subprocess, "run", fake_run)

    # a value of its own, so a hard-coded 30.0 in run_program would fail
    timeout = hostkeys.PROGRAM_TIMEOUT + 1.0
    hostkeys.run_program(["ssh-keyscan", "host"], timeout)

    assert seen["timeout"] == timeout


def test_the_real_runner_fails_when_the_program_fails(monkeypatch) -> None:
    from newton_mcp.ad import hostkeys

    def fake_run(argv, **kwargs):
        return subprocess.CompletedProcess(argv, 1, "", "no key")

    monkeypatch.setattr(hostkeys.subprocess, "run", fake_run)

    with pytest.raises(OSError):
        hostkeys.run_program(["ssh-keyscan", "host"], 20.0)


@pytest.mark.skipif(
    shutil.which("ssh-keygen") is None, reason="ssh-keygen is not installed"
)
def test_the_fingerprint_is_the_one_ssh_keygen_prints(tmp_path, keyfile, capsys) -> None:
    path = tmp_path / "hostkey"
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(path)],
        check=True,
        capture_output=True,
        timeout=60,
    )
    public = (tmp_path / "hostkey.pub").read_text(encoding="utf-8").split()
    listed = subprocess.run(
        ["ssh-keygen", "-lf", str(tmp_path / "hostkey.pub")],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    ).stdout
    fingerprint = listed.split()[1]
    host = f"dc1.{DOMAIN}"
    runner = FakeKeyscan({host: f"{host} {public[0]} {public[1]}\n"})

    code, out, _ = _scan_run(keyfile, runner, capsys)

    assert code == 0
    assert fingerprint in out



def test_the_preflight_and_the_host_key_scan_work_in_one_run(keyfile, capsys) -> None:
    host = f"dc1.{DOMAIN}"
    blob = _blob("ssh-ed25519", b"\x01" * 32)
    runner = FakeKeyscan({host: _scan_line(host, "ssh-ed25519", blob)})

    code, out, _ = _run(
        _args(keyfile, "--preflight", "--fetch-host-keys"),
        FakeLookup(_two_dc_table()),
        capsys,
        net=FakeSockets(),
        now=lambda: NOW,
        keyscan=runner,
    )

    assert code == 0
    assert "Preflight: 2 DCs checked, 2 passed" in out
    assert f"{host} ssh-ed25519 {blob}" in out
