"""``newton-doctor ad``: the read-only consistency check of the AD inventory.

Every test builds a temp inventory, keys, known_hosts files and a state
directory; nothing touches the network or the real state.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import base64
from pathlib import Path

import pytest

from newton_mcp import server
from newton_mcp.ad import doctor

DNS = "ad.example.com"
FP = "ab" * 32
PUBKEY = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l8GmJE"


class World:
    """A temp inventory with its key files, known_hosts and state dir."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.state = root / "state"
        (self.state / "approval-fp").mkdir(parents=True)
        self.inventory = root / "devices.toml"
        self.entries: dict[str, dict[str, object]] = {}

    def keys(self, name: str, host: str, *, mode: int = 0o600) -> tuple[str, str]:
        key = self.root / f"{name}.key"
        key.write_text("not a real key\n")
        key.chmod(mode)
        known = self.root / f"{name}.known_hosts"
        known.write_text(f"{host} ssh-ed25519 {PUBKEY}\n")
        known.chmod(0o600)
        return str(key), str(known)

    def read(self, name: str, host: str, domain: str = DNS, platform: str = "ad-samba") -> None:
        key, known = self.keys(name, host)
        self.entries[name] = {
            "platform": platform, "host": host, "user": f"newton-audit@{domain}",
            "experimental_readonly": True, "key_file": key, "known_hosts": known,
            "domain": domain,
        }

    def write(self, name: str, host: str, ad_domain: str, domain: str = DNS,
              platform: str = "ad-samba-write") -> None:
        key, known = self.keys(name, host)
        self.entries[name] = {
            "platform": platform, "ad_domain": ad_domain, "host": host,
            "user": f"newton-ops@{domain}", "key_file": key, "known_hosts": known,
            "domain": domain,
        }

    def fingerprint(self, device: str, text: str | None = None) -> None:
        (self.state / "approval-fp" / device).write_text(
            f"v1 {FP}\n" if text is None else text
        )

    def save(self) -> None:
        lines: list[str] = []
        for name, entry in self.entries.items():
            lines.append(f"[devices.{json.dumps(name)}]")
            for key, value in entry.items():
                if isinstance(value, bool):
                    lines.append(f"{key} = {'true' if value else 'false'}")
                elif isinstance(value, int):
                    lines.append(f"{key} = {value}")
                else:
                    lines.append(f"{key} = {json.dumps(value)}")
            lines.append("")
        self.inventory.write_text("\n".join(lines))
        self.inventory.chmod(0o600)

    def check(self, raw: str | None = None, **kw):
        if raw is None:
            self.save()
        else:
            self.inventory.write_text(raw)
            self.inventory.chmod(0o600)
        args = dict(
            inventory=self.inventory, state_dir=self.state,
            setup_command="/opt/newton/scripts/newton-ad-setup",
            owner_uid=os.geteuid(), expect_user=None,
        )
        args.update(kw)
        return doctor.check(**args)


@pytest.fixture
def world(tmp_path):
    w = World(tmp_path)
    w.read("dc1", "192.0.2.21")
    w.write("dc1-ops", "192.0.2.21", "dc1-ops")
    w.read("dc2", "192.0.2.22")
    w.write("dc2-ops", "192.0.2.22", "dc1-ops")
    w.fingerprint("dc1-ops")
    return w


def lines(report, level):
    return [x for x in report.lines if x.startswith(level + " ")]


def fails(report):
    return lines(report, "FAIL")


def next_steps(report) -> list[str]:
    """The next step of every line that carries one."""
    return [x.rpartition(" Next: ")[2] for x in report.lines if " Next: " in x]


def set_host(world: World, name: str, host: str) -> None:
    """Point an entry at a host and keep its pinned known_hosts in step."""
    world.entries[name]["host"] = host
    path = Path(str(world.entries[name]["known_hosts"]))
    path.write_text(f"{host} ssh-ed25519 {PUBKEY}\n")
    path.chmod(0o600)


def test_clean_inventory_has_no_findings(world):
    report = world.check()
    assert fails(report) == [] and lines(report, "INCONCLUSIVE") == [], report.lines
    assert report.exit_code == 0
    assert any(x.startswith("PASS ad-domain-link") for x in report.lines)
    assert any(x.startswith("PASS ad-key-file") for x in report.lines)
    assert report.summary.startswith("ad: ")


def test_no_ad_entries_is_info_and_clean(tmp_path):
    w = World(tmp_path)
    w.entries["r1"] = {"platform": "openwrt", "host": "192.0.2.1", "user": "root"}
    report = w.check()
    assert report.exit_code == 0
    assert any(x.startswith("INFO") and "no Active Directory" in x for x in report.lines)


def test_missing_inventory_is_a_finding(tmp_path):
    w = World(tmp_path)
    report = doctor.check(
        inventory=tmp_path / "nope.toml", state_dir=w.state,
        setup_command="x", owner_uid=os.geteuid(), expect_user=None,
    )
    assert report.exit_code == 1
    assert any("ad-inventory" in x and "Next:" in x for x in fails(report))


def test_ad_domain_names_unknown_device(world):
    world.entries["dc2-ops"]["ad_domain"] = "ghost"
    report = world.check()
    [line] = [x for x in fails(report) if "ad-domain-link[dc2-ops]" in x]
    assert "ghost" in line and "Next:" in line
    assert report.exit_code == 1


def test_ad_domain_names_a_read_entry(world):
    world.entries["dc2-ops"]["ad_domain"] = "dc1"
    report = world.check()
    assert any("ad-domain-link[dc2-ops]" in x and "not an AD write entry" in x for x in fails(report))


def test_ad_domain_names_a_device_that_is_not_the_domain_device(world):
    world.write("dc3-ops", "192.0.2.23", "dc2-ops")
    report = world.check()
    assert any("ad-domain-link[dc3-ops]" in x and "dc2-ops" in x for x in fails(report))


def test_ad_domain_missing(world):
    del world.entries["dc2-ops"]["ad_domain"]
    report = world.check()
    assert any("ad-domain-link[dc2-ops]" in x and "ad_domain" in x for x in fails(report))


def test_entry_dns_domain_differs_from_its_domain_device(world):
    world.entries["dc2-ops"]["domain"] = "other.example.org"
    report = world.check()
    assert any("ad-domain-link[dc2-ops]" in x and "other.example.org" in x for x in fails(report))


def test_two_domain_devices_for_one_domain(world):
    world.entries["dc2-ops"]["ad_domain"] = "dc2-ops"
    report = world.check()
    [line] = [x for x in fails(report) if "ad-domain-device" in x]
    assert "dc1-ops" in line and "dc2-ops" in line
    assert "newton-ad-setup write samba" in line and "--domain-device dc1-ops" in line


def test_two_domains_with_different_guids_are_not_one(world):
    guid_a = "11111111-1111-1111-1111-111111111111"
    guid_b = "22222222-2222-2222-2222-222222222222"
    world.entries["dc1-ops"]["ad_domain_guid"] = guid_a
    world.entries["dc2-ops"]["ad_domain"] = "dc2-ops"
    world.entries["dc2-ops"]["ad_domain_guid"] = guid_b
    world.fingerprint("dc2-ops")
    report = world.check()
    assert not [x for x in fails(report) if "ad-domain-device" in x], report.lines


def test_dc_with_read_entry_but_no_write_entry(world):
    del world.entries["dc2-ops"]
    report = world.check()
    [line] = [x for x in fails(report) if "ad-read-coverage[dc2]" in x]
    assert "never read back" in line
    assert (
        "Next: /opt/newton/scripts/newton-ad-setup write samba --domain ad.example.com "
        "--pubkey dc2-ops.pub --device dc2-ops --host 192.0.2.22 --ou '<DN of a location "
        "to change>' --domain-device dc1-ops" in line
    )


def test_read_and_write_entries_pair_when_the_host_case_differs(world):
    set_host(world, "dc1", "DC1.AD.EXAMPLE.COM")
    set_host(world, "dc1-ops", "dc1.ad.example.com")
    report = world.check()
    assert not [x for x in fails(report) if "ad-read-coverage" in x], report.lines
    assert report.exit_code == 0, report.lines


def test_read_and_write_entries_pair_when_the_host_has_a_trailing_dot(world):
    set_host(world, "dc1", "dc1.ad.example.com.")
    set_host(world, "dc1-ops", "dc1.ad.example.com")
    report = world.check()
    assert not [x for x in fails(report) if "ad-read-coverage" in x], report.lines
    assert report.exit_code == 0, report.lines


def test_dc_with_an_ip_read_entry_and_a_name_write_entry_is_inconclusive(world):
    set_host(world, "dc1-ops", "dc1.ad.example.com")
    report = world.check()
    assert not [x for x in fails(report) if "ad-read-coverage" in x], report.lines
    [line] = [x for x in lines(report, "INCONCLUSIVE") if "ad-read-coverage" in x]
    assert "dc1" in line and "dc1-ops" in line
    assert "could not be confirmed" in line
    assert not [x for x in report.lines if x.startswith("PASS ad-read-coverage")]
    assert report.exit_code == 3, report.lines


def test_dc_with_a_name_read_entry_and_an_ip_write_entry_is_inconclusive(world):
    set_host(world, "dc1", "dc1.ad.example.com")
    report = world.check()
    assert not [x for x in fails(report) if "ad-read-coverage" in x], report.lines
    [line] = [x for x in lines(report, "INCONCLUSIVE") if "ad-read-coverage" in x]
    assert "dc1" in line and "dc1-ops" in line
    assert "could not be confirmed" in line
    assert not [x for x in report.lines if x.startswith("PASS ad-read-coverage")]
    assert report.exit_code == 3, report.lines


def test_an_unconfirmable_pairing_names_the_unpaired_write_entries(tmp_path):
    """The doctor never picks one write entry as the partner."""
    w = World(tmp_path)
    w.read("dc1", "192.0.2.21")
    w.write("dc9-ops", "dc9.ad.example.com", "dc9-ops")
    w.fingerprint("dc9-ops")
    report = w.check()
    assert report.exit_code == 3, report.lines
    [line] = [x for x in lines(report, "INCONCLUSIVE") if "ad-read-coverage" in x]
    assert "dc9-ops" in line
    assert "dc9.ad.example.com" not in line, line
    assert "same host text" in line, line
    assert "both entries of a DC" in line, line
    assert not [x for x in report.lines if x.startswith("PASS ad-read-coverage")]
    assert not [x for x in report.lines if "no audit entry" in x]


def test_two_ip_reads_and_two_name_writes_are_all_inconclusive(tmp_path):
    w = World(tmp_path)
    w.read("dc1", "192.0.2.21")
    w.read("dc2", "192.0.2.22")
    w.write("dc9-ops", "dc9.ad.example.com", "dc9-ops")
    w.write("dc10-ops", "dc10.ad.example.com", "dc9-ops")
    w.fingerprint("dc9-ops")
    report = w.check()
    found = [x for x in lines(report, "INCONCLUSIVE") if "ad-read-coverage" in x]
    assert len(found) == 2, report.lines
    assert report.exit_code == 3, report.lines
    assert not [x for x in report.lines if "no audit entry" in x], report.lines
    assert not [x for x in report.lines if x.startswith("PASS ad-read-coverage")]


def test_the_unconfirmable_pairing_names_only_the_write_entry_that_differs(tmp_path):
    """A write entry that gives an IP address keeps its own note."""
    w = World(tmp_path)
    w.read("dc1", "192.0.2.21")
    w.write("dc9-ops", "dc9.ad.example.com", "dc9-ops")
    w.write("dc99-ops", "192.0.2.99", "dc9-ops")
    w.fingerprint("dc9-ops")
    report = w.check()
    [line] = [x for x in lines(report, "INCONCLUSIVE") if "ad-read-coverage" in x]
    assert "dc9-ops" in line, line
    assert "dc99-ops" not in line, line
    [note] = [x for x in lines(report, "INFO") if "no audit entry" in x]
    assert "192.0.2.99" in note, note
    assert report.exit_code == 3, report.lines
    assert not [x for x in report.lines if x.startswith("PASS ad-read-coverage")]


def test_a_write_entry_of_the_domain_that_gives_a_name_may_be_this_dc_s(tmp_path):
    """The write entry is paired with another audit entry: it may still be this DC's."""
    w = World(tmp_path)
    w.read("dc1", "192.0.2.21")
    w.read("dc1-again", "dc1.ad.example.com")
    w.write("dc1-ops", "dc1.ad.example.com", "dc1-ops")
    w.fingerprint("dc1-ops")
    report = w.check()
    assert not [x for x in fails(report) if "ad-read-coverage" in x], report.lines
    [line] = [x for x in lines(report, "INCONCLUSIVE") if "ad-read-coverage" in x]
    assert "dc1" in line and "dc1-ops" in line, line
    assert "could not be confirmed" in line, line
    assert not [x for x in report.lines if x.startswith("PASS ad-read-coverage")]
    assert report.exit_code == 3, report.lines
    # no command: the setup command would replace the write entry of the file
    for step in next_steps(report):
        assert "newton-ad-setup" not in step, step


def test_a_dc_whose_name_matches_no_write_entry_is_inconclusive_when_a_write_entry_gives_an_ip(world):
    """A write entry of the domain that gives an IP address may be this DC's."""
    set_host(world, "dc2", "dc2.other.example.com")
    set_host(world, "dc2-ops", "dc2.ad.example.com")
    report = world.check()
    assert not [x for x in fails(report) if "ad-read-coverage[dc2]" in x], report.lines
    [line] = [x for x in lines(report, "INCONCLUSIVE") if "ad-read-coverage[dc2]" in x]
    assert "dc1-ops" in line, line
    assert not [x for x in report.lines if x.startswith("PASS ad-read-coverage")]
    assert report.exit_code == 3, report.lines


def test_dc_whose_ip_matches_no_write_entry_is_still_a_finding(world):
    set_host(world, "dc2", "192.0.2.99")
    report = world.check()
    [line] = [x for x in fails(report) if "ad-read-coverage[dc2]" in x]
    assert "never read back" in line
    assert report.exit_code == 1, report.lines


def test_dc_whose_name_matches_no_write_entry_is_still_a_finding(world):
    """Every write entry of the domain gives a name, like this DC's audit entry."""
    set_host(world, "dc1", "dc1.ad.example.com")
    set_host(world, "dc1-ops", "dc1.ad.example.com")
    set_host(world, "dc2", "dc2.other.example.com")
    set_host(world, "dc2-ops", "dc2.ad.example.com")
    report = world.check()
    [line] = [x for x in fails(report) if "ad-read-coverage[dc2]" in x]
    assert "never read back" in line
    assert report.exit_code == 1, report.lines


def test_the_missing_write_finding_never_names_a_device_that_is_in_the_file(world):
    """The setup command would replace that entry of the file."""
    set_host(world, "dc1-ops", "192.0.2.99")
    report = world.check()
    [line] = [x for x in fails(report) if "ad-read-coverage[dc1]" in x]
    assert "never read back" in line
    step = line.rpartition(" Next: ")[2]
    assert step.startswith("fix that entry with sudoedit -u newton "), step
    assert "newton-ad-setup" not in step, step
    assert report.exit_code == 1, report.lines


def test_windows_read_entry_names_windows_in_the_command(world):
    del world.entries["dc2-ops"]
    world.entries["dc2"]["platform"] = "ad-windows"
    report = world.check()
    [line] = [x for x in fails(report) if "ad-read-coverage[dc2]" in x]
    assert "newton-ad-setup write windows" in line


def test_audit_only_domain_is_info_not_a_finding(world):
    for name in ("dc1-ops", "dc2-ops"):
        del world.entries[name]
    report = world.check()
    assert report.exit_code == 0, report.lines
    assert any(x.startswith("INFO") and "audit only" in x for x in report.lines)


def test_write_entry_without_read_entry_is_info(world):
    del world.entries["dc2"]
    report = world.check()
    assert report.exit_code == 0, report.lines
    assert any(x.startswith("INFO") and "dc2-ops" in x and "no audit entry" in x for x in report.lines)


def test_a_top_level_device_table_is_a_finding(tmp_path):
    w = World(tmp_path)
    report = w.check(raw='[device.dc1]\nplatform = "ad-samba"\n')
    assert report.exit_code == 1, report.lines
    assert [x for x in fails(report) if "ad-inventory" in x], report.lines
    assert not [x for x in report.lines if "nothing to check" in x]


def test_devices_must_be_a_table(tmp_path):
    w = World(tmp_path)
    report = w.check(raw='devices = "dc1"\n')
    assert report.exit_code == 1, report.lines
    assert [x for x in fails(report) if "ad-inventory" in x], report.lines
    assert not [x for x in report.lines if "nothing to check" in x]


def test_an_entry_that_is_not_a_table_is_a_finding(tmp_path):
    w = World(tmp_path)
    report = w.check(raw='[devices]\ndc1 = "ad-samba"\n')
    assert report.exit_code == 1, report.lines
    assert [x for x in fails(report) if "ad-inventory" in x], report.lines


def test_a_name_the_loader_refuses_is_a_finding(tmp_path):
    w = World(tmp_path)
    report = w.check(raw='[devices."DC1"]\nplatform = "ad-samba"\n')
    assert report.exit_code == 1, report.lines
    assert [x for x in fails(report) if "ad-inventory" in x], report.lines


def test_a_platform_newton_does_not_support_is_a_finding(tmp_path):
    w = World(tmp_path)
    report = w.check(raw='[devices.dc1]\nplatform = "ad-sambla"\n')
    assert report.exit_code == 1, report.lines
    assert [x for x in fails(report) if "ad-inventory" in x], report.lines


def test_every_refused_entry_is_reported(tmp_path):
    w = World(tmp_path)
    report = w.check(raw=(
        '[devices."DC1"]\nplatform = "ad-samba"\n'
        '[devices.dc2]\nplatform = "ad-sambla"\n'
    ))
    assert report.exit_code == 1, report.lines
    assert len([x for x in fails(report) if "ad-inventory" in x]) == 2, report.lines


@pytest.mark.parametrize("field,value", [
    ("host", None),
    ("host", "x; touch /tmp/p"),
    ("user", None),
    ("user", "newton audit"),
    ("port", 0),
    ("port", 70000),
    ("port", "22"),
    ("key_file", "/tmp/x; touch /tmp/p"),
    ("known_hosts", "/tmp/x y"),
])
def test_an_ad_entry_the_loader_refuses_is_a_finding(world, field, value):
    if value is None:
        del world.entries["dc1"][field]
    else:
        world.entries["dc1"][field] = value
    report = world.check()
    assert report.exit_code == 1, report.lines
    assert [x for x in fails(report) if "ad-inventory[dc1]" in x], report.lines


def test_an_inventory_of_one_refused_entry_never_says_nothing_to_check(tmp_path):
    w = World(tmp_path)
    report = w.check(raw='[devices.dc1]\nplatform = "ad-samba"\n')
    assert report.exit_code == 1, report.lines
    assert not [x for x in report.lines if "nothing to check" in x], report.lines


def test_a_valid_non_ad_device_stays_ignored(tmp_path):
    w = World(tmp_path)
    report = w.check(raw=(
        '[devices.r1]\nplatform = "openwrt"\nhost = "192.0.2.1"\nuser = "root"\n'
    ))
    assert report.exit_code == 0, report.lines
    assert not fails(report), report.lines
    assert [x for x in report.lines if "nothing to check" in x], report.lines


# ---- the inventory Newton itself loads ------------------------------------


def loader_message(world: World, monkeypatch) -> str:
    """What the loader Newton itself uses says about this inventory."""
    monkeypatch.setenv("NEWTON_INVENTORY", str(world.inventory))
    with pytest.raises(server.NewtonError) as caught:
        server.load_inventory()
    return str(caught.value)


def _openwrt_without_a_user(world: World) -> None:
    world.entries["r1"] = {"platform": "openwrt", "host": "192.0.2.1"}


def _write_without_a_domain(world: World) -> None:
    del world.entries["dc2-ops"]["domain"]


def _read_with_an_ad_domain(world: World) -> None:
    world.entries["dc2"]["ad_domain"] = "dc1-ops"


def _bad_auth(world: World) -> None:
    world.entries["dc2"]["auth"] = "token"


def _bad_profile(world: World) -> None:
    world.entries["dc2"]["profile"] = "staging"


def _bad_proxy_command(world: World) -> None:
    world.entries["dc2"]["proxy_command"] = "ssh jump"


def _missing_known_hosts(world: World) -> None:
    world.entries["vyos1"] = {
        "platform": "vyos", "host": "192.0.2.5", "user": "vyos",
        "experimental_readonly": True,
        "known_hosts": str(world.root / "absent.known_hosts"),
    }


REFUSED_BY_NEWTON = [
    ("openwrt-without-a-user", _openwrt_without_a_user),
    ("write-without-a-domain", _write_without_a_domain),
    ("read-with-an-ad-domain", _read_with_an_ad_domain),
    ("bad-auth", _bad_auth),
    ("bad-profile", _bad_profile),
    ("bad-proxy-command", _bad_proxy_command),
    ("missing-known-hosts", _missing_known_hosts),
]


@pytest.mark.parametrize("name,break_it", REFUSED_BY_NEWTON)
def test_an_inventory_newton_refuses_is_a_finding(world, name, break_it, monkeypatch):
    """Newton loads no device from it, so the doctor must not pass it."""
    break_it(world)
    report = world.check()
    assert report.exit_code == 1, report.lines
    [line] = [x for x in fails(report) if "ad-inventory" in x]
    assert "Newton loads no device from this inventory" in line, line
    assert not [x for x in report.lines if x.startswith("PASS")], report.lines
    step = line.rpartition(" Next: ")[2]
    assert step.startswith("fix it with sudoedit -u newton ") or \
        step.startswith("fix that entry with sudoedit -u newton "), step
    assert loader_message(world, monkeypatch) not in step, step


def test_the_refusal_of_the_loader_is_in_the_finding(world, monkeypatch):
    """The doctor says it in the loader's own words."""
    world.entries["dc2"]["auth"] = "token"
    report = world.check()
    [line] = [x for x in fails(report) if "ad-inventory" in x]
    assert loader_message(world, monkeypatch) in line, line


def test_an_entry_of_another_platform_without_its_known_hosts_is_a_finding(world, monkeypatch):
    """Newton needs the pinned host key of every device it loads."""
    _missing_known_hosts(world)
    report = world.check()
    assert report.exit_code == 1, report.lines
    [line] = [x for x in fails(report) if "ad-inventory" in x]
    assert "known_hosts" in line, line
    assert loader_message(world, monkeypatch) in line, line


def test_one_refused_entry_is_one_finding(world):
    """The doctor's own finding and the loader's refusal are one refusal."""
    del world.entries["dc1"]["user"]
    report = world.check()
    assert report.exit_code == 1, report.lines
    [line] = [x for x in fails(report) if "ad-inventory" in x]
    assert "the user is missing" in line, line
    assert "Newton loads no device from this inventory" in line, line


def test_every_bad_entry_is_still_named(world):
    """The loader stops at the first one; the doctor names them all."""
    del world.entries["dc1"]["user"]
    del world.entries["dc2"]["user"]
    report = world.check()
    assert report.exit_code == 1, report.lines
    names = [x for x in fails(report) if "ad-inventory" in x]
    assert len(names) == 2, report.lines
    assert any("dc1" in x for x in names), report.lines
    assert any("dc2" in x for x in names), report.lines


def test_an_unexpected_error_of_the_loader_is_inconclusive(world, monkeypatch):
    """An error the loader did not expect is not a verdict."""
    def boom(path=None):
        raise RuntimeError("the loader exploded")

    monkeypatch.setattr(server, "load_inventory", boom)
    report = world.check()
    assert report.exit_code == 3, report.lines
    assert [x for x in lines(report, "INCONCLUSIVE") if "ad-inventory" in x], report.lines
    assert not [x for x in report.lines if x.startswith("PASS")], report.lines


def test_the_doctor_asks_the_loader_about_its_own_inventory(world, monkeypatch):
    """The doctor judges the file it checks, not another one."""
    seen = []

    def fake(path=None):
        seen.append(path)
        return {}

    monkeypatch.setattr(server, "load_inventory", fake)
    world.check()
    assert seen == [world.inventory]


def test_a_refused_entry_hides_no_pairing_claim(world):
    """The doctor cannot judge a pairing until the inventory loads."""
    del world.entries["dc2-ops"]
    world.entries["bad"] = {"platform": "ad-sambla"}
    report = world.check()
    assert not [x for x in report.lines if "audit entries only" in x], report.lines
    assert not [x for x in report.lines if "has a write entry but no audit entry" in x], report.lines
    assert [x for x in lines(report, "INCONCLUSIVE") if "cannot be judged until the inventory loads" in x], \
        report.lines


def test_a_refused_entry_hides_no_audit_only_claim(world):
    """The domain may hold a write entry Newton does not load."""
    del world.entries["dc1-ops"]
    del world.entries["dc2-ops"]
    world.entries["bad"] = {"platform": "ad-sambla"}
    report = world.check()
    assert not [x for x in report.lines if "audit entries only" in x], report.lines
    assert [x for x in lines(report, "INCONCLUSIVE") if "cannot be judged until the inventory loads" in x], \
        report.lines


def test_ad_domain_naming_a_refused_entry_says_newton_does_not_load_it(world):
    """The entry is in the file, but Newton refuses to load it."""
    world.entries["dc2-ops"]["ad_domain"] = "bad"
    world.entries["bad"] = {"platform": "ad-sambla"}
    report = world.check()
    [line] = [x for x in fails(report) if "ad-domain-link[dc2-ops]" in x]
    assert "Newton does not load" in line, line
    assert "the inventory does not hold" not in line, line


def test_the_missing_write_claim_is_inconclusive_when_an_entry_is_refused(world):
    del world.entries["dc2-ops"]
    world.entries["bad"] = {"platform": "ad-sambla"}
    report = world.check()
    assert not [x for x in fails(report) if "ad-read-coverage" in x], report.lines
    assert [x for x in lines(report, "INCONCLUSIVE") if "ad-read-coverage" in x], report.lines
    assert report.exit_code == 1, report.lines


def test_a_refused_inventory_makes_no_pairing_claim(world):
    """The doctor cannot name a partner while the inventory does not load."""
    set_host(world, "dc1-ops", "dc1.ad.example.com")
    world.entries["bad"] = {"platform": "ad-sambla"}
    report = world.check()
    found = [x for x in lines(report, "INCONCLUSIVE") if "ad-read-coverage" in x]
    assert found, report.lines
    for line in found:
        assert "may be the same DC" not in line, line
        assert "cannot be judged until the inventory loads" in line, line
    assert report.exit_code == 1, report.lines


def test_an_unexpected_verdict_says_the_inventory_could_not_be_judged(world, monkeypatch):
    """The loader's verdict was an error: the doctor does not know whether it loads."""
    def boom(path=None):
        raise RuntimeError("the loader exploded")

    monkeypatch.setattr(server, "load_inventory", boom)
    del world.entries["dc2-ops"]
    report = world.check()
    [line] = [x for x in lines(report, "INCONCLUSIVE") if "ad-read-coverage" in x]
    assert "could not be judged" in line, line
    assert "does not load" not in line, line
    assert report.exit_code == 3, report.lines


def test_the_refusal_next_step_names_the_findings_of_that_entry_first(world):
    """The owner fixes what this run names for that entry before the sudoedit line."""
    del world.entries["dc1"]["user"]
    report = world.check()
    [line] = [x for x in fails(report) if "ad-inventory[dc1]" in x]
    assert "Newton loads no device from this inventory" in line, line
    step = line.rpartition(" Next: ")[2]
    assert "fix the findings this run names for dc1 first" in step, step
    assert "sudoedit" in step, step


def test_key_placeholder_is_a_finding(world):
    world.entries["dc1-ops"]["key_file"] = "<the private key of the write key, on the Newton host>"
    report = world.check()
    [line] = [x for x in fails(report) if "ad-key-file[dc1-ops]" in x]
    assert "placeholder" in line and "ssh-keygen" in line


@pytest.mark.parametrize("field,text", [
    ("key_file", "<the private key of the audit key, on the Newton host>"),
    ("known_hosts", "<the pinned known_hosts of the collector host>"),
    ("known_hosts", "<the pinned known_hosts of the controller>"),
])
def test_each_printed_placeholder_is_caught(world, field, text):
    world.entries["dc1"][field] = text
    report = world.check()
    check = "ad-key-file" if field == "key_file" else "ad-known-hosts"
    assert any(f"{check}[dc1]" in x and "placeholder" in x for x in fails(report))


def test_placeholder_constants_match_what_the_setup_prints():
    from newton_mcp.ad import setupgen, setupgen_write

    text = setupgen_write.__dict__
    source = Path(setupgen.__file__).read_text() + Path(setupgen_write.__file__).read_text()
    for placeholder in doctor.PLACEHOLDERS:
        assert placeholder in source, placeholder
    assert len(doctor.PLACEHOLDERS) == 4 and text


def test_any_angle_bracket_value_is_a_placeholder(world):
    world.entries["dc1"]["key_file"] = "<fill me in>"
    assert any("placeholder" in x for x in fails(world.check()))


def test_key_file_missing(world):
    Path(world.entries["dc1"]["key_file"]).unlink()
    [line] = [x for x in fails(world.check()) if "ad-key-file[dc1]" in x]
    assert "not found" in line and "ssh-keygen" in line


def test_key_file_mode(world):
    Path(world.entries["dc1"]["key_file"]).chmod(0o640)
    [line] = [x for x in fails(world.check()) if "ad-key-file[dc1]" in x]
    assert "0600" in line and "chmod 600" in line


def test_key_file_symlink(world, tmp_path):
    key = Path(world.entries["dc1"]["key_file"])
    real = tmp_path / "real.key"
    key.rename(real)
    key.symlink_to(real)
    assert any("ad-key-file[dc1]" in x and "symlink" in x for x in fails(world.check()))


def test_key_file_owned_by_someone_else(world):
    report = world.check(owner_uid=os.geteuid() + 1)
    [line] = [x for x in fails(report) if "ad-key-file[dc1]" in x]
    assert "owned by" in line and "chown" in line


def test_known_hosts_missing_file(world):
    Path(world.entries["dc1"]["known_hosts"]).unlink()
    assert any("ad-known-hosts[dc1]" in x and "not found" in x for x in fails(world.check()))


def test_known_hosts_without_a_key_for_the_host(world):
    Path(world.entries["dc1"]["known_hosts"]).write_text(f"192.0.2.99 ssh-ed25519 {PUBKEY}\n")
    [line] = [x for x in fails(world.check()) if "ad-known-hosts[dc1]" in x]
    assert "192.0.2.21" in line and "ssh-keyscan" in line and "known_hosts" in line


def test_known_hosts_group_writable(world):
    Path(world.entries["dc1"]["known_hosts"]).chmod(0o664)
    assert any("ad-known-hosts[dc1]" in x and "writable" in x for x in fails(world.check()))


def test_known_hosts_hashed_and_port_forms(world):
    salt = b"0123456789abcdefghij"
    digest = hmac.new(salt, b"192.0.2.21", hashlib.sha1).digest()
    hashed = f"|1|{base64.b64encode(salt).decode()}|{base64.b64encode(digest).decode()}"
    Path(world.entries["dc1"]["known_hosts"]).write_text(f"{hashed} ssh-ed25519 {PUBKEY}\n")
    world.entries["dc2"]["port"] = 2222
    Path(world.entries["dc2"]["known_hosts"]).write_text(
        f"[192.0.2.22]:2222,other ssh-ed25519 {PUBKEY}\n"
    )
    report = world.check()
    assert not [x for x in fails(report) if "ad-known-hosts" in x], report.lines


def test_known_hosts_revoked_line_does_not_count(world):
    Path(world.entries["dc1"]["known_hosts"]).write_text(f"@revoked 192.0.2.21 ssh-ed25519 {PUBKEY}\n")
    assert any("ad-known-hosts[dc1]" in x for x in fails(world.check()))


def test_fingerprint_missing_for_domain_device(world):
    (world.state / "approval-fp" / "dc1-ops").unlink()
    [line] = [x for x in fails(world.check()) if "ad-approval-fingerprint[dc1-ops]" in x]
    assert "sudo -u newton /usr/local/bin/newton-ad-setup approval-key dc1-ops" in line


def test_fingerprint_malformed(world):
    world.fingerprint("dc1-ops", "garbage\n")
    assert any("ad-approval-fingerprint[dc1-ops]" in x and "v1" in x for x in fails(world.check()))


def test_fingerprint_present_prints_the_compare_step(world):
    report = world.check()
    [line] = [x for x in lines(report, "INFO") if "approval-fingerprint[dc1-ops]" in x]
    assert FP in line and "Its fingerprint is" in line and "dc2-ops" in line
    assert not [x for x in fails(report) if "fingerprint" in x]


def test_fingerprint_is_only_for_domain_devices(world):
    # dc2-ops is a second DC: no fingerprint of its own is needed
    assert not [x for x in world.check().lines if "approval-fingerprint[dc2-ops]" in x]


def test_unreadable_fingerprint_is_inconclusive(world):
    path = world.state / "approval-fp" / "dc1-ops"
    path.unlink()
    path.mkdir()
    report = world.check()
    assert any("ad-approval-fingerprint[dc1-ops]" in x for x in lines(report, "INCONCLUSIVE"))
    assert report.exit_code == 3


def test_fail_beats_inconclusive_in_the_exit_code(world):
    path = world.state / "approval-fp" / "dc1-ops"
    path.unlink()
    path.mkdir()
    Path(world.entries["dc1"]["key_file"]).chmod(0o644)
    assert world.check().exit_code == 1


def test_wrong_account_is_refused(world):
    report = world.check(expect_user="newton")
    assert report.exit_code == 2
    assert "sudo -u newton /usr/local/bin/newton-doctor ad" in "\n".join(report.lines)


HOSTILE = [
    "x; touch /tmp/p",
    "$(id)",
    "`id`",
    "-leading-dash",
    "has space",
    "new\nline",
    "\x1b[2J",
]


@pytest.mark.parametrize("value", HOSTILE)
@pytest.mark.parametrize("field,entry_name", [
    ("host", "dc1"),
    ("user", "dc1"),
    ("port", "dc1"),
    ("key_file", "dc1"),
    ("known_hosts", "dc1"),
    ("domain", "dc1"),
    ("ad_domain", "dc1-ops"),
])
def test_no_printed_command_carries_a_hostile_inventory_value(world, field, entry_name, value):
    """A value that fails its grammar never reaches a command the owner runs."""
    world.entries[entry_name][field] = value
    report = world.check()
    for step in next_steps(report):
        assert value not in step, step


@pytest.mark.parametrize("value", HOSTILE)
def test_no_printed_command_carries_a_hostile_device_name(tmp_path, value):
    w = World(tmp_path)
    key, known = w.keys("dc1", "192.0.2.21")
    raw = "\n".join([
        f"[devices.{json.dumps(value)}]",
        'platform = "ad-samba"',
        'host = "192.0.2.21"',
        'user = "newton-audit@example.com"',
        f"key_file = {json.dumps(key)}",
        f"known_hosts = {json.dumps(known)}",
        'domain = "ad.example.com"',
        "",
    ])
    report = w.check(raw=raw)
    for step in next_steps(report):
        assert value not in step, step


@pytest.mark.parametrize("field", ["key_file", "known_hosts"])
def test_a_path_that_starts_with_a_dash_is_never_pasted_into_a_command(world, tmp_path, monkeypatch, field):
    monkeypatch.chdir(tmp_path)
    dash = tmp_path / "-rf"
    dash.write_text("not a real key\n")
    dash.chmod(0o664)
    world.entries["dc1"][field] = "-rf"
    report = world.check()
    assert [x for x in fails(report) if f"ad-{field.replace('_', '-')}[dc1]" in x], report.lines
    for step in next_steps(report):
        assert "-rf" not in step, step
    assert any("fix that entry with sudoedit" in step for step in next_steps(report)), report.lines


def test_untrusted_inventory_text_is_escaped(world):
    """A real escape byte and a real newline never reach the output raw."""
    esc = "\x1b[2J"
    # the who: the name of an entry
    world.entries[f"dc{esc}"] = dict(world.entries["dc1"])
    # the message and the next step: the host of an entry
    world.entries["dc2"]["host"] = f"192.0.2.22{esc}\n"
    # the message: the domain of an entry
    world.entries["dc2"]["domain"] = f"ad.example.com{esc}\n"
    report = world.check()
    assert not any("\x1b" in x for x in report.lines), report.lines
    assert not any("\n" in x for x in report.lines), report.lines
    assert any("\\x1b[2J" in x for x in report.lines), report.lines


def test_the_next_step_text_is_escaped_and_never_clipped(world):
    """The next step escapes the bytes outside 0x20-0x7e and is never cut short."""
    checker = doctor._Checker(world.inventory, world.state, "setup", os.geteuid())
    checker.emit("FAIL", "ad-test", "who", "a message", "next \x1b[2J\nstep " + "x" * 900)
    text = checker.out[0][2]
    assert "\x1b" not in text and "\n" not in text
    assert "\\x1b[2J" in text
    assert "x" * 900 in text


def test_main_prints_lines_and_summary_and_returns_the_code(world, capsys):
    world.save()
    rc = doctor.main(["--inventory", str(world.inventory), "--state-dir", str(world.state),
                      "--setup-command", "setup"])
    out = capsys.readouterr().out.splitlines()
    assert rc == 0 and out[-1].startswith("ad: ")


def test_main_usage_error(capsys):
    assert doctor.main(["--bogus"]) == 2
