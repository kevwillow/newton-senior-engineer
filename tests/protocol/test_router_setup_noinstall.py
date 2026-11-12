"""Tests of the no-install mode of scripts/newton-router-setup.

The no-install setup: every stop, the happy path (the exact login section
and the inventory fields), a re-setup of Newton's own section, the
refusals (a foreign rpcd.newton, another section with the username
newton), the verify failure, the password rules (the password never
leaves the host, the hash shape is checked).

The no-install uninstall: the happy path (the section, the sessions, the
host files and the inventory fields), the refusals (an apply pending, a
foreign section) and the "nothing to remove" path.

And the refusals of install and upgrade on a no-install device, plus the
installed uninstall, which must not change.
"""

import datetime
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import tomllib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from router_setup_env import setup_env  # noqa: E402
from router_setup_harness import DEFAULT_STATE  # noqa: E402
from test_router_setup_install import (  # noqa: E402
    GOOD_PW,
    PROG,
    install_ok,
    seed_known_hosts,
)

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "scripts" / "newton-router-setup"

sys.path.insert(0, str(REPO / "mcp"))
from newton_mcp.adapters.openwrt_rpcd import spki_pin  # noqa: E402

# the group lists (the fake newton-rpcd prints them)
READ_GROUPS = (
    "luci-base",
    "luci-base-network-status",
    "luci-mod-network-config",
    "luci-mod-network-dhcp",
    "luci-mod-network-diagnostics",
    "luci-mod-status-index",
    "luci-mod-status-logs",
)
WRITE_GROUPS = ("luci-base", "luci-mod-network-config")
ALL_GROUPS = tuple(dict.fromkeys(READ_GROUPS + WRITE_GROUPS))

# the pin the fake newton-rpcd prints
PIN = "A" * 43 + "="

# the closing lines of ADR-021 point 9: the two access modes
# side by side, one NOTE line per sentence
CLOSING_NOTES = [
    "NOTE no-install: Newton puts nothing on the router except one "
    "web-interface user.",
    "NOTE no-install: Every change uses OpenWrt's own undo timer.",
    "NOTE no-install: Limit: if the router reboots or its web service "
    "restarts while a change waits for confirmation, the change stays.",
    "NOTE no-install: Limit: whoever steals Newton's router password could "
    "take an interface down, restart Wi-Fi, kick a device off, or store "
    "files in /etc/luci-uploads, without your approval.",
    "NOTE no-install: Newton applies only DHCP static leases and DNS "
    "entries itself; every other change is a script you approve and run.",
    "NOTE installed: Newton puts a program on the router: a small set of "
    "shell scripts (6 files, about 216 KB), no packages and no compiled "
    "code.",
    "NOTE installed: Newton's key can run that program and nothing else, "
    "so the agent never gets a root shell.",
    "NOTE installed: If a Newton change is still waiting for "
    "confirmation at boot, the guard puts the last good settings back, so "
    "a reboot cannot leave that change stuck.",
    "NOTE installed: More checks can run, and fewer changes need a script.",
    "NOTE installed: uninstall removes Newton's program and key; it keeps "
    "the guard's saved settings and the rest of /etc/newton (its lock and "
    "log), the program directory, the WAN-health settings in "
    "/etc/config/newton_wanhealth, the keys from before swap-key and the "
    "sysupgrade file: the saved settings and the copy of your keys are "
    "what you restore by hand.",
]

RPCD_SECTION = "newton"
RPCD_OWNER = "newton-mcp"

STUB_TEMPLATE = '''#!/usr/bin/env python3
"""The fake newton-rpcd of the setup tests."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
GROUPS = __GROUPS__

argv = sys.argv[1:]
with open(os.path.join(HERE, "rpcd-calls.jsonl"), "a") as fh:
    fh.write(json.dumps(argv) + "\\n")


def login_refused():
    """True when the router has no rpcd.newton section any more."""
    root = os.environ.get("NEWTON_TEST_RPCD_ROUTER", "")
    path = os.path.join(root, "state.json")
    if not root or not os.path.exists(path):
        return True
    with open(path) as fh:
        state = json.load(fh)
    sections = (state.get("uci_sections") or {}).get("rpcd") or {}
    return "newton" not in sections


command = argv[0] if argv else ""
if command == "groups":
    for kind, group in GROUPS:
        print(kind + " " + group)
    sys.exit(0)
if command == "pin":
    if os.path.exists(os.path.join(HERE, "fail-pin")):
        print("FAIL the certificate cannot be read")
        sys.exit(1)
    print("__PIN__")
    sys.exit(0)
if command == "verify":
    if os.path.exists(os.path.join(HERE, "fail-verify")):
        print("FAIL the login was refused")
        sys.exit(1)
    print("PASS login and groups")
    sys.exit(0)
if command == "verify-refused":
    if os.path.exists(os.path.join(HERE, "fail-verify-refused")):
        print("FAIL the login still works")
        sys.exit(1)
    if not login_refused():
        print("FAIL the login still works")
        sys.exit(1)
    print("PASS the login is refused")
    sys.exit(0)
sys.exit(2)
'''

# The fake newton-rpcd whose `pin` command is the REAL one (the repo's own
# mcp/newton_mcp/rpcd_cli.py): the pin is computed from the bytes of the
# certificate file, so a transport that loses a byte shows up in the pin.
REAL_PIN_STUB_TEMPLATE = '''#!__PYTHON__
"""The fake newton-rpcd with the REAL pin command of the repo."""
import sys

sys.path.insert(0, __MCP_DIR__)

from newton_mcp.rpcd_cli import main as rpcd_main

GROUPS = __GROUPS__

argv = sys.argv[1:]
command = argv[0] if argv else ""
if command == "pin":
    sys.exit(rpcd_main(["pin", argv[1]]))
if command == "groups":
    for kind, group in GROUPS:
        print(kind + " " + group)
    sys.exit(0)
if command == "verify":
    print("PASS login and groups")
    sys.exit(0)
if command == "verify-refused":
    print("PASS the login is refused")
    sys.exit(0)
sys.exit(2)
'''


# -- helpers ----------------------------------------------------------------

def write_rpcd_stub(env):
    """The fake newton-rpcd: groups, pin, verify and verify-refused."""
    groups = ([("read", g) for g in READ_GROUPS]
              + [("write", g) for g in WRITE_GROUPS])
    text = (STUB_TEMPLATE
            .replace("__GROUPS__", repr(groups))
            .replace("__PIN__", PIN))
    path = env.tmp / "newton-rpcd"
    path.write_text(text)
    path.chmod(0o755)
    return path


def write_real_pin_stub(env):
    """The fake newton-rpcd whose `pin` command is the repo's own CLI."""
    groups = ([("read", g) for g in READ_GROUPS]
              + [("write", g) for g in WRITE_GROUPS])
    text = (REAL_PIN_STUB_TEMPLATE
            .replace("__PYTHON__", sys.executable)
            .replace("__MCP_DIR__", repr(str(REPO / "mcp")))
            .replace("__GROUPS__", repr(groups)))
    path = env.tmp / "newton-rpcd-real-pin"
    path.write_text(text)
    path.chmod(0o755)
    return path


def der_certificate():
    """A real DER certificate (it holds NUL bytes) for the fake router."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "router.lan")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (x509.CertificateBuilder()
                   .subject_name(name)
                   .issuer_name(name)
                   .public_key(key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(now - datetime.timedelta(days=1))
                   .not_valid_after(now + datetime.timedelta(days=1))
                   .sign(key, hashes.SHA256()))
    return certificate.public_bytes(serialization.Encoding.DER)


def scan_sections(text):
    """The exit status of the REAL rpcd_sections_scan on the given text."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("NEWTON_")}
    env["TOOL"] = str(TOOL)
    proc = subprocess.run(
        ["bash", "-c", '. "${TOOL:?}"; rpcd_sections_scan'],
        input=text.encode(), capture_output=True, env=env, timeout=60)
    return proc.returncode


def seed_acl(env, groups=ALL_GROUPS):
    """The LuCI ACL files of the fake router."""
    body = {group: {"ubus": {"uci": {"get": ["*"]}}} for group in groups}
    env.router.write("usr/share/rpcd/acl.d/luci.json",
                     json.dumps(body, indent=2))


def seed_https(env, listen="0.0.0.0:443", cert="/etc/uhttpd.crt",
               cert_file=True):
    """uhttpd with an HTTPS listener and a certificate file."""
    env.router.update_state(uci_sections={
        "uhttpd": {"main": {"type": "uhttpd",
                            "options": {"listen_https": listen, "cert": cert},
                            "lists": {}}},
    })
    if cert_file:
        env.router.write("etc/uhttpd.crt",
                         "-----BEGIN CERTIFICATE-----\nFAKE\n"
                         "-----END CERTIFICATE-----\n")


def set_section(env, pkg, name, section_type, options=None, lists=None):
    """One uci section of the fake router."""
    state = env.router.state()
    configs = state.get("uci_sections") or {}
    configs.setdefault(pkg, {})[name] = {
        "type": section_type,
        "options": dict(options or {}),
        "lists": dict(lists or {}),
    }
    env.router.update_state(uci_sections=configs)


def sections(env, pkg="rpcd"):
    """The uci sections of one config of the fake router."""
    return (env.router.state().get("uci_sections") or {}).get(pkg) or {}


def set_inventory(env, extra_lines=(), device="r1", auth="password"):
    """Rewrite the inventory of the test with the given extra lines.

    The auth is what the inventory states; ``"key"`` writes no auth
    line at all, so the device keeps the default of the tool (the
    plain key).
    """
    body = '[devices.%s]\nhost = "10.1.2.3"\nprofile = "lab"\n' % device
    if auth != "key":
        body += 'auth = "%s"\n' % auth
    body += "".join(line + "\n" for line in extra_lines)
    env.inventory.write_text(body)
    env.inventory.chmod(0o644)


def inventory_entry(env, device="r1"):
    """The parsed inventory entry of the device."""
    with open(env.inventory, "rb") as fh:
        return tomllib.load(fh)["devices"][device]


def run_noinstall(env, *args, typed=(GOOD_PW, GOOD_PW, GOOD_PW), extra=None,
                  rpcd=None, timeout=120, opts=()):
    """A no-install run with the fake newton-rpcd on the seam.

    The typed lines are the root password and the two answers of the
    approval passphrase (the closing step of the setup asks
    for the passphrase).  A run that stops before that step uses only
    the first line.
    """
    seam = {"NEWTON_SETUP_RPCD": str(rpcd or write_rpcd_stub(env)),
            "NEWTON_TEST_RPCD_ROUTER": str(env.router.root)}
    if extra:
        seam.update(extra)
    return env.run(*opts, "r1", "no-install", *args, typed=typed, env=seam,
                   timeout=timeout)


def run_uninstall(env, *args, typed=(GOOD_PW,)):
    """An uninstall run with the fake newton-rpcd on the seam."""
    seam = {"NEWTON_SETUP_RPCD": str(write_rpcd_stub(env)),
            "NEWTON_TEST_RPCD_ROUTER": str(env.router.root)}
    return env.run("r1", "uninstall", *args, typed=typed, env=seam)


def prepare_router(env):
    """A router that is ready for the no-install setup."""
    seed_known_hosts(env)
    seed_acl(env)
    seed_https(env)


def state_notes(result):
    return [l for l in result.out.splitlines() if l.startswith("NOTE state:")]


def fake_openssl(env, body):
    """A fake openssl on the PATH seam of the tool."""
    path = env.fakes / "openssl"
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)
    return path



def probe_output(env, calls):
    """The records the probe's script prints on the fake router.

    The probe sends one command to the router; the test runs that same
    command on the fake router's shell, so the records it prints (the
    three fixed words per field) can be read.
    """
    commands = [c.get("command") or "" for c in calls if c.get("tool") == "ssh"]
    scripts = [c for c in commands if "uci -q show rpcd" in c]
    assert scripts, commands
    router_env = {
        "PATH": "%s:%s" % (env.router.root / "bin", env.router.root / "hostbin"),
        "FAKE_ROUTER_ROOT": str(env.router.root),
        "FAKE_ROUTER_FS": str(env.router.root / "fs"),
    }
    proc = subprocess.run(["/bin/sh", "-c", scripts[-1]], env=router_env,
                          capture_output=True, timeout=60)
    return proc.stdout.decode("utf-8", "replace")


# -- 1. the happy path ------------------------------------------------------

def test_no_install_writes_the_section_and_the_inventory(setup_env):
    """The whole run: ten numbered PASS lines, the ten closing NOTE lines,
    the exact login section with its lists, the host password file and the
    inventory fields (every other field kept)."""
    env = setup_env
    prepare_router(env)
    r = run_noinstall(env)
    assert r.rc == 0, r.out + r.err
    lines = r.out.splitlines()
    assert lines[-1] == "DONE no-install r1"
    steps = [l for l in lines if l.startswith("PASS no-install step ")]
    assert len(steps) == 10, steps
    notes = [l for l in lines if l.startswith("NOTE ")]
    assert notes[:10] == CLOSING_NOTES

    config = env.router.read("etc/config/rpcd")
    assert "config login 'newton'" in config
    assert "option username 'newton'" in config
    assert "option newton_owner 'newton-mcp'" in config
    assert re.search(
        r"option password '\$6\$[./0-9A-Za-z]{1,16}\$[./0-9A-Za-z]{86}'",
        config), config
    for group in READ_GROUPS:
        assert "list read '%s'" % group in config, config
    for group in WRITE_GROUPS:
        assert "list write '%s'" % group in config, config

    pwfile = env.keys_dir / "r1.rpcd"
    assert pwfile.exists()
    assert stat.S_IMODE(os.stat(pwfile).st_mode) == 0o600
    assert len(pwfile.read_text().strip()) == 64

    entry = inventory_entry(env)
    assert entry["access"] == "no-install"
    assert entry["rpcd_password_file"] == str(pwfile)
    assert entry["https_spki"] == PIN
    assert entry["host"] == "10.1.2.3"
    assert entry["profile"] == "lab"


def test_no_install_fetches_the_certificate_over_the_admin_lane(setup_env):
    """The pin comes from the certificate the admin lane read, byte for byte:
    a DER certificate (it holds NUL bytes) survives the transport, and the
    pin in the inventory is the pin of exactly those bytes."""
    env = setup_env
    prepare_router(env)
    der = der_certificate()
    assert b"\x00" in der
    env.router.path("etc/uhttpd.crt").write_bytes(der)
    r = run_noinstall(env, rpcd=write_real_pin_stub(env))
    assert r.rc == 0, r.out + r.err
    cats = [c.get("command") or "" for c in r.calls if c.get("tool") == "ssh"]
    assert any("cat" in c and "uhttpd.crt" in c for c in cats), cats
    # the pin the real CLI computed over the fetched bytes is the pin of
    # the bytes the router holds
    assert inventory_entry(env)["https_spki"] == spki_pin(der)


def test_no_install_uses_the_group_lists_of_the_rpcd_cli(setup_env):
    """The group lists come from `newton-rpcd groups`; bash never holds
    them."""
    env = setup_env
    prepare_router(env)
    r = run_noinstall(env)
    assert r.rc == 0, r.out + r.err
    calls = [json.loads(line) for line
             in (env.tmp / "rpcd-calls.jsonl").read_text().splitlines()]
    assert calls[0] == ["groups"]
    verify = [c for c in calls if c and c[0] == "verify"]
    assert verify, calls
    argv = verify[0]
    assert "--host" in argv and "10.1.2.3" in argv
    assert "--port" in argv and "443" in argv
    assert "--pin" in argv and PIN in argv
    assert "--password-file" in argv
    assert argv[argv.index("--password-file") + 1] == str(env.keys_dir / "r1.rpcd")


# -- 2. the stops of the no-install setup -----------------------------------

def test_no_install_refuses_when_newton_is_installed(setup_env):
    """Newton's program on the router and an inventory without the
    no-install mode: the run stops and the router is unchanged."""
    env = setup_env
    prepare_router(env)
    env.router.write("usr/libexec/newton/newton-router", "#!/bin/sh\n")
    before = env.router.snapshot()
    r = run_noinstall(env)
    assert r.rc == 1
    lines = r.out.splitlines()
    assert lines[-1] == (
        "STOPPED no-install r1: Newton is installed on this router; run "
        "`uninstall` first, then `no-install`")
    assert "NOTE state: router unchanged" in lines
    assert env.router.snapshot() == before


def test_no_install_refuses_while_an_apply_is_pending(setup_env):
    """The measured pending detector (the undo window is open): the run
    stops and the router is unchanged.

    A real window holds one file per changed config, so the directory
    has an entry.
    """
    env = setup_env
    prepare_router(env)
    snapshot = env.router.path("var/run/rpcd/snapshot-files")
    snapshot.mkdir(parents=True, exist_ok=True)
    (snapshot / "dhcp").write_text("staged")
    before = env.router.snapshot()
    r = run_noinstall(env)
    assert r.rc == 1
    lines = r.out.splitlines()
    assert lines[-1] == (
        "STOPPED no-install r1: an apply is pending on the router (LuCI or "
        "Newton); wait for it to finish")
    assert "NOTE state: router unchanged" in lines
    assert env.router.snapshot() == before


def test_no_install_names_a_leftover_undo_file_and_the_way_out(setup_env):
    """An undo file the router forgot about says how to get rid of it.

    A restart of the router's web service forgets the window but leaves
    the undo file behind for good (measured, a4m-02).  The setup still
    refuses, and it says what the owner can do about it.
    """
    env = setup_env
    prepare_router(env)
    snapshot = env.router.path("var/run/rpcd/snapshot-files")
    snapshot.mkdir(parents=True, exist_ok=True)
    undo = snapshot / "dhcp"
    undo.write_text("staged")
    old = time.time() - 7200
    os.utime(undo, (old, old))
    r = run_noinstall(env)
    assert r.rc == 1
    lines = r.out.splitlines()
    assert lines[-1] == (
        "STOPPED no-install r1: the router has a leftover undo file from "
        "2 hours ago (its web service restarted during a change). If nobody "
        "is changing the router right now, reboot it, or as root run: "
        "rm -rf /var/run/rpcd/snapshot-files"
    ), lines


def test_no_install_goes_on_with_an_empty_leftover_directory(setup_env):
    """An empty snapshot directory is a leftover, not an undo window.

    A refused apply leaves the directory behind, empty, and it stays
    that way (measured on lab-r1).  The directory alone must not stop
    the setup for good.
    """
    env = setup_env
    prepare_router(env)
    (env.router.path("var/run/rpcd/snapshot-files")).mkdir(
        parents=True, exist_ok=True)
    r = run_noinstall(env)
    assert r.rc == 0, r.out + r.err
    lines = r.out.splitlines()
    assert lines[-1] == "DONE no-install r1"
    assert not any(
        "an apply is pending" in line for line in lines
    ), lines


def test_no_install_refuses_without_https(setup_env):
    """No HTTPS listener: the run stops with the luci-ssl message and the
    router is unchanged."""
    env = setup_env
    prepare_router(env)
    seed_https(env, listen="")
    before = env.router.snapshot()
    r = run_noinstall(env)
    assert r.rc == 1
    lines = r.out.splitlines()
    assert lines[-1] == (
        "STOPPED no-install r1: the router has no HTTPS web interface. "
        "Install the luci-ssl package on the router (System > Software in "
        "LuCI, or `apk add luci-ssl`), then run this again.")
    assert "NOTE state: router unchanged" in lines
    assert env.router.snapshot() == before


def test_no_install_refuses_without_the_certificate_file(setup_env):
    """A HTTPS listener whose certificate file is gone: the same refusal."""
    env = setup_env
    prepare_router(env)
    env.router.path("etc/uhttpd.crt").unlink()
    before = env.router.snapshot()
    r = run_noinstall(env)
    assert r.rc == 1
    assert "the router has no HTTPS web interface" in r.out.splitlines()[-1]
    assert env.router.snapshot() == before


def test_no_install_refuses_when_a_group_is_missing(setup_env):
    """A router without one of LuCI's groups: the run stops and names the
    group."""
    env = setup_env
    prepare_router(env)
    seed_acl(env, groups=[g for g in ALL_GROUPS
                           if g != "luci-mod-network-dhcp"])
    before = env.router.snapshot()
    r = run_noinstall(env)
    assert r.rc == 1
    lines = r.out.splitlines()
    assert lines[-1] == (
        "STOPPED no-install r1: this router lacks LuCI's "
        "luci-mod-network-dhcp group; no-install needs LuCI")
    assert "NOTE state: router unchanged" in lines
    assert env.router.snapshot() == before


def test_no_install_refuses_a_foreign_rpcd_newton(setup_env):
    """A rpcd.newton section that is not Newton's: the run stops and never
    touches it."""
    env = setup_env
    prepare_router(env)
    set_section(env, "rpcd", "newton", "login",
                {"username": "newton", "password": "$6$foreign$hash"})
    before = env.router.snapshot()
    r = run_noinstall(env)
    assert r.rc == 1
    lines = r.out.splitlines()
    assert lines[-1].startswith("STOPPED no-install r1:")
    assert "never overwrites" in lines[-1]
    assert "NOTE state: router unchanged" in lines
    assert env.router.snapshot() == before
    assert sections(env)["newton"]["options"]["password"] == "$6$foreign$hash"


def test_no_install_refuses_another_section_with_the_username_newton(setup_env):
    """Another login section with the username newton: the run stops and
    nothing is written."""
    env = setup_env
    prepare_router(env)
    set_section(env, "rpcd", "other", "login", {"username": "newton"})
    before = env.router.snapshot()
    r = run_noinstall(env)
    assert r.rc == 1
    lines = r.out.splitlines()
    assert lines[-1].startswith("STOPPED no-install r1:")
    assert "NOTE state: router unchanged" in lines
    assert env.router.snapshot() == before
    assert "newton" not in sections(env)


def test_no_install_resets_our_own_section(setup_env):
    """A rpcd.newton section with Newton's own tag is a re-setup: the run
    says so and writes a new password."""
    env = setup_env
    prepare_router(env)
    set_section(env, "rpcd", "newton", "login",
                {"username": "newton", "newton_owner": RPCD_OWNER})
    r = run_noinstall(env)
    assert r.rc == 0, r.out + r.err
    lines = r.out.splitlines()
    assert any("re-setup" in l for l in lines), lines
    assert lines[-1] == "DONE no-install r1"
    config = env.router.read("etc/config/rpcd")
    assert "config login 'newton'" in config
    assert "list read 'luci-base'" in config


def test_no_install_removes_the_section_when_the_verify_fails(setup_env):
    """The login does not work: the section is removed again and the run
    stops."""
    env = setup_env
    prepare_router(env)
    (env.tmp / "fail-verify").write_text("")
    r = run_noinstall(env)
    assert r.rc == 1
    lines = r.out.splitlines()
    assert lines[-1].startswith("STOPPED no-install r1:")
    assert "newton" not in sections(env)
    # the inventory was not changed
    assert "access" not in inventory_entry(env)
    # the state line says what is true: the login is gone, the router is
    # not "as it was"
    assert ("NOTE state: the newton login was removed; run no-install again"
            in lines), lines
    assert not any("as it was" in l for l in lines), lines


def test_no_install_says_the_login_may_still_be_on_the_router(setup_env):
    """The cleanup of a failed login fails too: the run says the login may
    still be on the router; it never says the router is as it was."""
    env = setup_env
    prepare_router(env)
    (env.tmp / "fail-verify").write_text("")
    # the removal of the login section does not run and fails
    env.router.update_state(fail_commands=["uci -q delete rpcd.newton"])
    r = run_noinstall(env)
    assert r.rc == 1
    lines = r.out.splitlines()
    assert lines[-1].startswith("STOPPED no-install r1:")
    assert ("NOTE state: the newton login may still be on the router; "
            "run uninstall") in lines, lines
    assert not any("as it was" in l for l in lines), lines
    # the section is still on the router
    assert "newton" in sections(env)


def test_no_install_re_setup_does_not_claim_the_router_is_as_it_was(setup_env):
    """A re-setup of Newton's own section whose login does not work: the
    section was Newton's own, so the run says the login was removed (and
    asks for another no-install run); it never says the router is as it
    was."""
    env = setup_env
    prepare_router(env)
    set_section(env, "rpcd", "newton", "login",
                {"username": "newton", "newton_owner": RPCD_OWNER})
    (env.tmp / "fail-verify").write_text("")
    r = run_noinstall(env)
    assert r.rc == 1
    lines = r.out.splitlines()
    assert ("NOTE state: the newton login was removed; run no-install again"
            in lines), lines
    assert not any("as it was" in l for l in lines), lines
    assert "newton" not in sections(env)


def test_no_install_refuses_an_owner_that_forges_the_protocol(setup_env):
    """An owner value with a newline and a second owner field cannot forge
    Newton's ownership: the run stops and the router is unchanged."""
    env = setup_env
    prepare_router(env)
    set_section(env, "rpcd", "newton", "login",
                {"username": "newton",
                 "newton_owner": "foreign-owner\nowner=newton-mcp"})
    before = env.router.snapshot()
    r = run_noinstall(env)
    assert r.rc == 1
    lines = r.out.splitlines()
    assert lines[-1].startswith("STOPPED no-install r1:")
    assert "never overwrites" in lines[-1]
    assert "NOTE state: router unchanged" in lines
    assert env.router.snapshot() == before
    assert sections(env)["newton"]["options"]["newton_owner"] == (
        "foreign-owner\nowner=newton-mcp")


def test_the_section_scanner_takes_no_value_twice():
    """The host scanner refuses a duplicate field and an unknown line: it
    never takes the last value of a forged field."""
    good = ("section\ntype=login\nuser=ours\nowner=ours\nnewton=yes\n"
            "end\n")
    assert scan_sections(good) == 0
    duplicated = ("section\ntype=login\nuser=ours\nowner=ours\n"
                  "owner=other\nnewton=yes\nend\n")
    assert scan_sections(duplicated) == 2
    unknown = ("section\ntype=login\nuser=ours\nowner=ours\nnewton=yes\n"
               "surprise=1\nend\n")
    assert scan_sections(unknown) == 2
    # a record without every field is refused as well
    assert scan_sections("section\ntype=login\nuser=ours\nend\n") == 2
    # a stream that was cut short is never read as a complete one
    assert scan_sections("section\ntype=login\nuser=ours\nowner=ours\n"
                         "newton=yes\n") == 2
    # an empty stream is refused too
    assert scan_sections("") == 2
    # and nothing may follow the "end" line
    assert scan_sections(good + "section\n") == 2


def test_no_install_stops_when_the_router_cannot_be_checked(setup_env):
    """The footprint check fails (the ssh call dies): the run stops and the
    router is unchanged; a failure is never read as 'not installed'."""
    env = setup_env
    prepare_router(env)
    env.router.update_state(rc_commands=[["test -e", 255]])
    before = env.router.snapshot()
    r = run_noinstall(env)
    assert r.rc == 1
    lines = r.out.splitlines()
    assert lines[-1] == "STOPPED no-install r1: cannot check the router"
    assert "NOTE state: router unchanged" in lines
    assert env.router.snapshot() == before


def test_no_install_refuses_to_corrupt_the_inventory(setup_env):
    """A description with a line that looks like the pin field: the run
    stops instead of editing the description, the inventory is unchanged,
    and the login it would have named is taken back off the router (a
    login the inventory does not name is one no action would remove)."""
    env = setup_env
    prepare_router(env)
    env.inventory.write_text(
        '[devices.r1]\nhost = "10.1.2.3"\nprofile = "lab"\n'
        'auth = "password"\n'
        'description = """\nfirst line\nhttps_spki = "example"\n"""\n')
    env.inventory.chmod(0o644)
    before = env.inventory.read_text()
    r = run_noinstall(env)
    assert r.rc == 1
    lines = r.out.splitlines()
    assert lines[-1] == "STOPPED no-install r1: no-install step 10 failed"
    assert any(l.startswith("FAIL ") and "cannot edit the inventory safely" in l
               for l in lines), lines
    assert ("NOTE state: the newton login was removed; fix the inventory, "
            "then run no-install again") in lines
    assert env.inventory.read_text() == before
    assert "newton" not in sections(env)
    assert not (env.keys_dir / "r1.rpcd").exists()


BAD_DESCRIPTION = 'description = """\nfirst line\nhttps_spki = "example"\n"""\n'


def test_no_install_again_keeps_the_named_password_file(setup_env):
    """A re-setup whose inventory write fails takes the login off the
    router but keeps the password file: the inventory still names it,
    and an entry whose file is gone is one the server refuses."""
    env = setup_env
    prepare_router(env)
    assert run_noinstall(env).rc == 0
    env.inventory.write_text(env.inventory.read_text().replace(
        "[devices.r1]\n", "[devices.r1]\n" + BAD_DESCRIPTION, 1))
    before = env.inventory.read_text()
    r = run_noinstall(env)
    assert r.rc == 1, r.out + r.err
    assert r.out.splitlines()[-1] == "STOPPED no-install r1: no-install step 10 failed"
    assert env.inventory.read_text() == before
    assert "newton" not in sections(env)
    assert (env.keys_dir / "r1.rpcd").exists()


def test_no_install_reports_a_password_file_it_cannot_remove(setup_env):
    """The inventory write fails and the new password file cannot be
    removed: the run says so instead of claiming a clean state."""
    env = setup_env
    prepare_router(env)
    env.inventory.write_text(
        '[devices.r1]\nhost = "10.1.2.3"\nprofile = "lab"\n'
        'auth = "password"\n' + BAD_DESCRIPTION)
    env.inventory.chmod(0o644)
    env.router.update_state(rpcd_sessions=[])
    # an rm on the seam that refuses only the password file of r1
    rm = env.fakes / "rm"
    rm.write_text(
        '#!/bin/sh\nfor a in "$@"; do\n'
        '\tcase "$a" in *r1.rpcd) exit 1 ;; esac\ndone\n'
        'exec %s "$@"\n' % shutil.which("rm"))
    rm.chmod(0o755)
    r = run_noinstall(env)
    assert r.rc == 1, r.out + r.err
    lines = r.out.splitlines()
    assert any(l.startswith("FAIL ") and "r1.rpcd" in l for l in lines), lines
    assert ("NOTE state: the newton login was removed; the rpcd password file "
            "is still on this host") in lines
    assert (env.keys_dir / "r1.rpcd").exists()
    assert "newton" not in sections(env)
    assert "access" not in inventory_entry(env)


def test_no_install_stops_when_the_pin_fails(setup_env):
    """The certificate cannot be pinned: the run stops before it writes
    anything."""
    env = setup_env
    prepare_router(env)
    (env.tmp / "fail-pin").write_text("")
    before = env.router.snapshot()
    r = run_noinstall(env)
    assert r.rc == 1
    assert "NOTE state: router unchanged" in r.out.splitlines()
    assert env.router.snapshot() == before


def test_no_install_refuses_a_device_that_is_not_openwrt(setup_env):
    """The no-install mode is for OpenWrt routers only."""
    env = setup_env
    prepare_router(env)
    set_inventory(env, ['platform = "vyos"'])
    before = env.router.snapshot()
    r = run_noinstall(env)
    assert r.rc == 1
    lines = r.out.splitlines()
    assert lines[-1].startswith("STOPPED no-install r1:")
    assert "OpenWrt" in lines[-1]
    assert "NOTE state: router unchanged" in lines
    assert env.router.snapshot() == before


def test_no_install_never_restarts_rpcd(setup_env):
    """A restart of rpcd drops a pending rollback (measured), so the run
    never asks for one."""
    env = setup_env
    prepare_router(env)
    r = run_noinstall(env)
    assert r.rc == 0, r.out + r.err
    commands = [c.get("command") or "" for c in r.calls]
    for command in commands:
        assert "init.d/rpcd" not in command
        assert "service rpcd" not in command
        assert "rpcd restart" not in command
        assert "rpcd reload" not in command


# -- 3. the password rules --------------------------------------------------

def test_the_rpcd_password_never_leaves_the_host(setup_env):
    """The password is in the host file only: never in the output, never in
    an argv, never on the router."""
    env = setup_env
    prepare_router(env)
    r = run_noinstall(env)
    assert r.rc == 0, r.out + r.err
    password = (env.keys_dir / "r1.rpcd").read_text().strip()
    assert password
    assert password not in r.out
    assert password not in r.err
    for call in r.calls:
        joined = " ".join(str(a) for a in call.get("argv") or [])
        assert password not in joined
        assert password not in (call.get("command") or "")
    for line in (env.tmp / "rpcd-calls.jsonl").read_text().splitlines():
        assert password not in line
    for path in env.router.root.rglob("*"):
        if path.is_file():
            assert password.encode() not in path.read_bytes(), path


def test_no_install_refuses_a_bad_password_hash(setup_env):
    """A hash that is not a sha512-crypt hash never reaches the router."""
    env = setup_env
    prepare_router(env)
    fake_openssl(env, 'if [ "$1" = "rand" ]; then\n'
                      '  printf "%s\\n" "$(printf "%064d" 0)"\n'
                      'else\n  printf "not-a-hash\\n"\nfi\n')
    before = env.router.snapshot()
    r = run_noinstall(env)
    assert r.rc == 1
    lines = r.out.splitlines()
    assert lines[-1].startswith("STOPPED no-install r1:")
    assert env.router.snapshot() == before
    assert not (env.keys_dir / "r1.rpcd").exists()


def test_no_install_stops_when_openssl_fails(setup_env):
    """No usable openssl on the host: a plain message, nothing written."""
    env = setup_env
    prepare_router(env)
    fake_openssl(env, "exit 1\n")
    before = env.router.snapshot()
    r = run_noinstall(env)
    assert r.rc == 1
    lines = r.out.splitlines()
    assert lines[-1].startswith("STOPPED no-install r1:")
    assert "openssl" in lines[-1]
    assert env.router.snapshot() == before


def test_the_rpcd_cli_is_needed(setup_env):
    """Without the newton-rpcd CLI the run stops with a plain message."""
    env = setup_env
    prepare_router(env)
    r = env.run("r1", "no-install", typed=(GOOD_PW,),
                env={"NEWTON_SETUP_RPCD": str(env.tmp / "no-such-rpcd")})
    assert r.rc != 0
    assert "newton-rpcd" in (r.out + r.err)


# -- 4. the no-install uninstall -------------------------------------------

def test_uninstall_no_install_removes_everything(setup_env):
    """The section, the sessions, the host file and the inventory fields."""
    env = setup_env
    prepare_router(env)
    assert run_noinstall(env).rc == 0
    env.router.update_state(rpcd_sessions=[
        {"id": "a" * 32, "username": "newton"},
        {"id": "b" * 32, "username": "root"},
    ])
    r = run_uninstall(env)
    assert r.rc == 0, r.out + r.err
    lines = r.out.splitlines()
    assert lines[-1] == "DONE uninstall r1"
    assert "newton" not in sections(env)
    sessions = env.router.state()["rpcd_sessions"]
    assert [s["id"] for s in sessions] == ["b" * 32]
    assert not (env.keys_dir / "r1.rpcd").exists()
    entry = inventory_entry(env)
    assert "access" not in entry
    assert "rpcd_password_file" not in entry
    assert "https_spki" not in entry
    assert entry["host"] == "10.1.2.3"


def test_uninstall_no_install_refuses_while_an_apply_is_pending(setup_env):
    """A pending undo must not be dropped by a teardown.

    A real window holds one file per changed config, so the directory
    has an entry.
    """
    env = setup_env
    prepare_router(env)
    assert run_noinstall(env).rc == 0
    snapshot = env.router.path("var/run/rpcd/snapshot-files")
    snapshot.mkdir(parents=True, exist_ok=True)
    (snapshot / "dhcp").write_text("staged")
    before = env.router.snapshot()
    r = run_uninstall(env)
    assert r.rc == 1
    lines = r.out.splitlines()
    assert lines[-1] == (
        "STOPPED uninstall r1: an rpcd restart or a teardown now could drop "
        "the pending undo")
    assert "NOTE state: router unchanged" in lines
    assert env.router.snapshot() == before


def test_uninstall_no_install_goes_on_with_an_empty_leftover_directory(
    setup_env,
):
    """An empty snapshot directory is a leftover, not an undo window.

    The teardown must not be stopped for good by the empty directory a
    refused apply leaves behind.
    """
    env = setup_env
    prepare_router(env)
    assert run_noinstall(env).rc == 0
    (env.router.path("var/run/rpcd/snapshot-files")).mkdir(
        parents=True, exist_ok=True)
    r = run_uninstall(env)
    assert r.rc == 0, r.out + r.err
    lines = r.out.splitlines()
    assert lines[-1] == "DONE uninstall r1"
    assert not any(
        "could drop the pending undo" in line for line in lines
    ), lines


def test_uninstall_no_install_refuses_a_foreign_section(setup_env):
    """A rpcd.newton section that is not Newton's is never touched."""
    env = setup_env
    prepare_router(env)
    set_inventory(env, ['access = "no-install"'])
    set_section(env, "rpcd", "newton", "login",
                {"username": "newton", "password": "$6$foreign$hash"})
    before = env.router.snapshot()
    r = run_uninstall(env)
    assert r.rc == 1
    lines = r.out.splitlines()
    assert lines[-1].startswith("STOPPED uninstall r1:")
    assert "NOTE state: router unchanged" in lines
    assert env.router.snapshot() == before
    assert sections(env)["newton"]["options"]["password"] == "$6$foreign$hash"


def test_uninstall_no_install_with_nothing_to_remove(setup_env):
    """No section on the router: the run says so and still cleans the host
    side."""
    env = setup_env
    prepare_router(env)
    set_inventory(env, ['access = "no-install"'])
    r = run_uninstall(env)
    assert r.rc == 0, r.out + r.err
    lines = r.out.splitlines()
    assert lines[-1] == "DONE uninstall r1"
    assert any("nothing to remove" in l for l in lines), lines


def test_uninstall_no_install_with_only_the_password_field(setup_env):
    """The pin field is gone and the password field is there (the device is
    the last table): the uninstall finishes."""
    env = setup_env
    prepare_router(env)
    assert run_noinstall(env).rc == 0
    text = env.inventory.read_text()
    env.inventory.write_text("".join(
        line for line in text.splitlines(keepends=True)
        if not line.startswith("https_spki")))
    env.inventory.chmod(0o644)
    r = run_uninstall(env)
    assert r.rc == 0, r.out + r.err
    assert r.out.splitlines()[-1] == "DONE uninstall r1"
    entry = inventory_entry(env)
    assert "rpcd_password_file" not in entry
    assert "https_spki" not in entry


def test_uninstall_refuses_to_corrupt_the_inventory(setup_env):
    """The same check on the uninstall edit: a description with a line that
    looks like the password-file field stops the run, and the inventory is
    unchanged."""
    env = setup_env
    prepare_router(env)
    assert run_noinstall(env).rc == 0
    env.inventory.write_text(
        '[devices.r1]\nhost = "10.1.2.3"\nprofile = "lab"\n'
        'auth = "password"\naccess = "no-install"\n'
        'description = """\nrpcd_password_file = "example"\n"""\n'
        'rpcd_password_file = "%s"\nhttps_spki = "%s"\n'
        % (env.keys_dir / "r1.rpcd", PIN))
    env.inventory.chmod(0o644)
    before = env.inventory.read_text()
    r = run_uninstall(env)
    assert r.rc == 1
    lines = r.out.splitlines()
    assert lines[-1].startswith("STOPPED uninstall r1:")
    assert "cannot edit the inventory safely" in lines[-1]
    assert env.inventory.read_text() == before
    # the inventory still names the password file, so the file stays:
    # the entry is never one whose password file is gone
    assert (env.keys_dir / "r1.rpcd").exists()


def test_uninstall_reports_a_failed_password_file_removal(setup_env):
    """The password file cannot be removed: the uninstall says which file,
    and it never says DONE."""
    env = setup_env
    prepare_router(env)
    assert run_noinstall(env).rc == 0
    pwfile = env.keys_dir / "r1.rpcd"
    os.chmod(env.keys_dir, 0o500)
    try:
        r = run_uninstall(env)
    finally:
        os.chmod(env.keys_dir, 0o700)
    assert r.rc == 1
    lines = r.out.splitlines()
    assert any(l.startswith("FAIL ") and "r1.rpcd" in l for l in lines), lines
    assert not any(l.startswith("DONE") for l in lines), lines
    assert pwfile.exists()
    # the inventory went first: it no longer names the file
    assert "rpcd_password_file" not in inventory_entry(env)


# -- 5. install and upgrade on a no-install device --------------------------

def test_install_is_refused_on_a_no_install_device(setup_env):
    """The installed mode and the no-install mode never mix: while the
    no-install login is still in the inventory, the install is refused
    and the router is unchanged."""
    env = setup_env
    prepare_router(env)
    assert run_noinstall(env).rc == 0
    before = env.router.snapshot()
    r = env.run("r1", "install", typed=(GOOD_PW,))
    assert r.rc == 1
    assert r.out.splitlines()[-1] == (
        "STOPPED install r1: this device uses no-install access; run "
        "`uninstall` first")
    assert env.router.snapshot() == before


def test_upgrade_is_refused_on_a_no_install_device(setup_env):
    """The same refusal for upgrade."""
    env = setup_env
    seed_known_hosts(env)
    set_inventory(env, ['access = "no-install"'])
    before = env.router.snapshot()
    r = env.run("r1", "upgrade", typed=(GOOD_PW,))
    assert r.rc == 1
    assert r.out.splitlines()[-1] == (
        "STOPPED upgrade r1: this device uses no-install access; run "
        "`uninstall` first")
    assert env.router.snapshot() == before


def fake_home(env):
    """Make the tool's home the test's own home, which has no plain key.

    The tool reads the home directory of the running user from
    ``getent passwd`` (not from ``$HOME``), so the fake ``getent`` on the
    PATH seam answers with the test's home.  That home holds no
    ``.ssh/id_ed25519``: the test never depends on the real user's
    files, and the plain-key path is a path that does not exist.
    """
    getent = env.fakes / "getent"
    getent.write_text(
        "#!/bin/sh\n"
        "# the fake passwd entry of the protocol tests: the home is the\n"
        "# test's own home, and it holds no plain key.\n"
        "if [ \"$1\" = passwd ]; then\n"
        "\tprintf '%s:x:1000:1000::%s:/bin/sh\\n' \"$2\" \"$HOME\"\n"
        "\texit 0\n"
        "fi\n"
        "exit 2\n"
    )
    getent.chmod(0o755)
    return getent


@pytest.mark.parametrize("args,auth,hosts", [
    (("profile", "lab"), "password", True),
    (("swap-key",), "password", True),
    (("add-key", "laptop", "read"), "password", True),
    (("revoke", "laptop"), "password", True),
    (("rollback",), "password", True),
    (("lab-snapshot", "--skip-gates"), "password", True),
    # install and upgrade run the install: they refuse on the default
    # auth (the plain key) of a host that has no plain key, and on a
    # device with no known_hosts.
    (("install",), "key", False),
    (("upgrade",), "key", False),
])
def test_every_installed_mode_action_is_refused_on_a_no_install_device(
        setup_env, args, auth, hosts):
    """Review of the A1 rebase: profile, swap-key, add-key, revoke,
    rollback, lab-snapshot, install and upgrade write Newton's files or
    keys, or run the install, on the router.  On a no-install device
    each one stops before anything is sent: the two modes never mix.

    The approval-key is not on this list any more: on a
    no-install device it does host-only work, so it is allowed and
    touches the router not at all.

    The refusal comes before the admin path is chosen, so it is the
    refusal the owner reads even on a host that has no plain key (and
    even with `--admin password` or a `--password-file`): the two
    modes never mix, whatever the admin path would have been.  The
    install and the upgrade are refused the same way, on an inventory
    that keeps the default auth (the plain key) and on a device with
    no known_hosts: the refusal comes first, so neither the key nor
    the known_hosts is ever needed.

    The inventory holds the two no-install login fields, so the device
    is a real no-install one: the install is refused while its login is
    still there (the uninstall takes the login away, and the
    install is then the owner saying otherwise).
    """
    env = setup_env
    fake_home(env)
    if hosts:
        seed_known_hosts(env)
    set_inventory(env, ['access = "no-install"',
                        'rpcd_password_file = "%s"'
                        % (env.keys_dir / "r1.rpcd"),
                        'https_spki = "%s"' % PIN], auth=auth)
    before = env.router.snapshot()
    r = env.run("r1", *args, typed=(GOOD_PW, GOOD_PW, GOOD_PW, "yes"))
    assert r.rc == 1, r.out + r.err
    assert r.out.splitlines()[-1] == (
        "STOPPED %s r1: this device uses no-install access; run "
        "`uninstall` first" % args[0])
    assert env.router.snapshot() == before
    # nothing reached the router, and no key was made on the host
    assert r.calls == []
    assert not (env.home / ".ssh" / "id_ed25519").exists()


# -- 6. the installed uninstall does not change -----------------------------

def test_the_installed_uninstall_is_unchanged(setup_env):
    """A device in the installed mode still gets the installed teardown:
    the program files go, no rpcd section is written."""
    env = setup_env
    install_ok(env)
    r = run_uninstall(env)
    assert r.rc == 0, r.out + r.err
    assert r.out.splitlines()[-1] == "DONE uninstall r1"
    assert not env.router.path(PROG).exists()
    assert sections(env) == {}


# -- 7. the review round r3 (items 1, 4, 5 and 6) -----------------------------


def test_no_install_refuses_when_newton_is_installed_on_a_no_install_device(
    setup_env,
):
    """The footprint check runs on every no-install run.

    The inventory may already say "no-install", but the router can
    still hold Newton's program: the check is not skipped, so the run
    stops and the router is unchanged.
    """
    env = setup_env
    prepare_router(env)
    set_inventory(env, ['access = "no-install"'])
    env.router.write("usr/libexec/newton/newton-router", "#!/bin/sh\n")
    before = env.router.snapshot()
    r = run_noinstall(env)
    assert r.rc == 1
    lines = r.out.splitlines()
    assert lines[-1] == (
        "STOPPED no-install r1: Newton is installed on this router; run "
        "`uninstall` first, then `no-install`")
    assert "NOTE state: router unchanged" in lines
    assert env.router.snapshot() == before


def test_no_install_stops_when_the_rpcd_config_cannot_be_read(setup_env):
    """A failed `uci show rpcd` is a failure, not "there are no sections".

    The listing runs into a variable and its own status is checked, so
    a broken listing stops the run instead of letting the setup
    overwrite a foreign rpcd.newton.
    """
    env = setup_env
    prepare_router(env)
    set_section(env, "rpcd", "newton", "login",
                {"username": "newton", "password": "$6$foreign$hash"})
    env.router.update_state(uci_fail=[["show rpcd", 1]])
    before = env.router.snapshot()
    r = run_noinstall(env)
    assert r.rc == 1
    lines = r.out.splitlines()
    assert lines[-1] == (
        "STOPPED no-install r1: cannot read the router's rpcd config")
    assert "NOTE state: router unchanged" in lines
    assert env.router.snapshot() == before
    assert sections(env)["newton"]["options"]["password"] == "$6$foreign$hash"


def test_uninstall_stops_when_the_rpcd_config_cannot_be_read(setup_env):
    """The same for the uninstall: it stops and never prints DONE."""
    env = setup_env
    prepare_router(env)
    assert run_noinstall(env).rc == 0
    env.router.update_state(uci_fail=[["show rpcd", 1]])
    r = run_uninstall(env)
    assert r.rc == 1
    lines = r.out.splitlines()
    assert lines[-1] == (
        "STOPPED uninstall r1: cannot read the router's rpcd config")
    assert not any(l.startswith("DONE") for l in lines), lines
    # the section is still there: nothing was removed
    assert "newton" in sections(env)


def test_no_install_does_not_claim_the_login_is_gone_when_the_delete_failed(
    setup_env,
):
    """A delete that failed and a commit that worked is not a removal.

    The delete and the commit are two commands, and the status of the
    commit alone proves nothing: the run says the login may still be
    on the router.
    """
    env = setup_env
    prepare_router(env)
    (env.tmp / "fail-verify").write_text("")
    env.router.update_state(uci_fail=[["delete rpcd.newton", 1]])
    r = run_noinstall(env)
    assert r.rc == 1
    lines = r.out.splitlines()
    assert ("NOTE state: the newton login may still be on the router; "
            "run uninstall") in lines, lines
    assert not any(l.startswith("DONE") for l in lines), lines
    assert "newton" in sections(env)


def test_no_install_proves_the_removal_before_it_says_the_login_is_gone(
    setup_env,
):
    """The removal is proved with the probe, not assumed.

    The delete succeeds and changes nothing: the section is still
    there, so the run must not say that the login was removed.
    """
    env = setup_env
    prepare_router(env)
    (env.tmp / "fail-verify").write_text("")
    env.router.update_state(uci_ignore=["delete rpcd.newton"])
    r = run_noinstall(env)
    assert r.rc == 1
    lines = r.out.splitlines()
    assert ("NOTE state: the newton login may still be on the router; "
            "run uninstall") in lines, lines
    assert not any("the newton login was removed" in l for l in lines), lines
    assert "newton" in sections(env)


def test_the_uninstall_does_not_claim_the_section_is_gone_when_the_delete_failed(
    setup_env,
):
    """The uninstall proves the removal too: it never prints DONE."""
    env = setup_env
    prepare_router(env)
    assert run_noinstall(env).rc == 0
    env.router.update_state(uci_fail=[["delete rpcd.newton", 1]])
    r = run_uninstall(env)
    assert r.rc == 1
    lines = r.out.splitlines()
    assert not any(l.startswith("DONE") for l in lines), lines
    assert any("may still be there" in l for l in lines), lines
    assert "newton" in sections(env)


def test_no_install_stops_when_the_write_failed(setup_env):
    """A uci set that failed stops the run: the section may be partly
    written.

    Every command of the write is checked, not just the last one, so a
    half written section is never reported as a written one.
    """
    env = setup_env
    prepare_router(env)
    env.router.update_state(uci_fail=[["set rpcd.newton.password", 1]])
    r = run_noinstall(env)
    assert r.rc == 1
    lines = r.out.splitlines()
    assert lines[-1] == "STOPPED no-install r1: no-install step 8 failed"
    assert ("NOTE state: the rpcd.newton login section may be partly "
            "written; run uninstall") in lines, lines
    assert not any(l.startswith("DONE") for l in lines), lines


def test_no_install_refuses_an_owner_with_a_trailing_newline(setup_env):
    """The owner is compared byte for byte.

    A command substitution drops the trailing newlines, so an owner of
    "newton-mcp\\n" used to look like Newton's own.  It is another
    owner now: the setup refuses and the router is unchanged.
    """
    env = setup_env
    prepare_router(env)
    set_section(env, "rpcd", "newton", "login",
                {"username": "newton", "newton_owner": "newton-mcp\n"})
    before = env.router.snapshot()
    r = run_noinstall(env)
    assert r.rc == 1
    lines = r.out.splitlines()
    assert "never overwrites" in lines[-1]
    assert "NOTE state: router unchanged" in lines
    assert env.router.snapshot() == before
    assert sections(env)["newton"]["options"]["newton_owner"] == (
        "newton-mcp\n")


def test_uninstall_refuses_an_owner_with_a_trailing_newline(setup_env):
    """The uninstall refuses it too, and it never touches the section."""
    env = setup_env
    prepare_router(env)
    set_section(env, "rpcd", "newton", "login",
                {"username": "newton", "newton_owner": "newton-mcp\n"})
    set_inventory(env, ['access = "no-install"'])
    before = env.router.snapshot()
    r = run_uninstall(env)
    assert r.rc == 1
    lines = r.out.splitlines()
    assert "never touches it" in lines[-1]
    assert "NOTE state: router unchanged" in lines
    assert not any(l.startswith("DONE") for l in lines), lines
    assert env.router.snapshot() == before


def test_the_probe_compares_the_owner_and_the_username_byte_for_byte(
    setup_env,
):
    """The probe says "other" for a value with a trailing newline.

    The value is read with a sentinel, so the trailing newline of the
    router's own value is part of the comparison and not a newline the
    shell drops.
    """
    env = setup_env
    prepare_router(env)
    set_section(env, "rpcd", "newton", "login",
                {"username": "newton\n", "newton_owner": "newton-mcp\n"})
    r = run_noinstall(env)
    assert r.rc == 1
    output = probe_output(env, r.calls)
    assert "user=other" in output, output
    assert "owner=other" in output, output
    assert "user=ours" not in output, output
    assert "owner=ours" not in output, output
    assert "type=login" in output, output


def test_the_probe_says_none_for_a_missing_owner_and_username(setup_env):
    """A missing option is "none", not "other".

    uci get prints nothing for an option that is not set, so the sentinel
    read gives "x" alone; that has to be "none".
    """
    env = setup_env
    prepare_router(env)
    set_section(env, "rpcd", "newton", "login", {})
    r = run_noinstall(env)
    output = probe_output(env, r.calls)
    assert "user=none" in output, output
    assert "owner=none" in output, output
    assert "user=other" not in output, output
    assert "owner=other" not in output, output


# -- 8. the approval passphrase of a no-install device --------

#: The passphrase the tests type at the approval prompt of a no-install
#: device.
APPROVAL_PP = "no-install-approval-passphrase"

#: The fingerprint file the setup writes on this host.
FP_RE = re.compile(r"^v1 [0-9a-f]{64}\n$")


def test_no_install_setup_stores_the_approval_fingerprint(setup_env):
    """The closing step asks for the approval passphrase and stores the
    host-side fingerprint.

    Nothing of the approval key goes on the router: the router keeps
    nothing of Newton but the web-interface user of the setup, and the
    fingerprint is the only thing this host keeps.
    """
    env = setup_env
    prepare_router(env)
    r = run_noinstall(env)
    assert r.rc == 0, r.out + r.err
    assert any("approval fingerprint" in l for l in r.out.splitlines()), r.out
    fp = env.fp_path()
    assert fp.exists(), "the setup stores the host-side fingerprint"
    assert stat.S_IMODE(os.stat(fp).st_mode) == 0o600
    assert FP_RE.match(fp.read_text()), fp.read_text()
    # the key itself never went to the router
    assert not env.router.path("etc/newton/approve.key").exists()
    assert not env.router.path(PROG).exists()


def test_approval_key_on_a_no_install_device_writes_no_router_file(setup_env):
    """The approval-key action is allowed on a no-install device and does
    host-only work.

    The device has no plain key and no known_hosts on purpose: a run
    that needs the admin lane (or a host key) would stop before it
    asked anything.  It must reach the router not at all.
    """
    env = setup_env
    fake_home(env)
    set_inventory(env, ['access = "no-install"'], auth="key")
    before = env.router.snapshot()
    r = env.run("r1", "approval-key", typed=(APPROVAL_PP, APPROVAL_PP))
    assert r.rc == 0, r.out + r.err
    assert r.calls == [], "a host-only action must not reach the router"
    assert env.router.snapshot() == before
    fp = env.fp_path()
    assert fp.exists()
    assert FP_RE.match(fp.read_text()), fp.read_text()
    assert not env.router.path("etc/newton/approve.key").exists()
    assert r.out.splitlines()[-1] == "DONE approval-key r1"


def test_approval_key_on_a_no_install_device_refuses_a_mismatch(setup_env):
    """The prompt rules are the ones of the installed approval step: the
    two answers must match and the passphrase must not be empty."""
    env = setup_env
    fake_home(env)
    set_inventory(env, ['access = "no-install"'], auth="key")
    r = env.run("r1", "approval-key", typed=(APPROVAL_PP, "other"))
    assert r.rc == 1, r.out + r.err
    assert r.out.splitlines()[-1] == (
        "STOPPED approval-key r1: the approval passphrases differ")
    assert not env.fp_path().exists()
    r = env.run("r1", "approval-key", typed=("", ""))
    assert r.rc == 1, r.out + r.err
    assert r.out.splitlines()[-1] == (
        "STOPPED approval-key r1: the approval passphrase is empty")
    assert not env.fp_path().exists()


def test_the_no_install_setup_keeps_the_fingerprint_of_a_re_run(setup_env):
    """A re-run keeps the fingerprint.

    The passphrase is the owner's, and the owner changes it with the
    approval-key action, exactly as on an installed device: the second
    setup asks for nothing and changes nothing.
    """
    env = setup_env
    prepare_router(env)
    assert run_noinstall(env).rc == 0
    first = env.fp_path().read_text()
    r = run_noinstall(env, typed=(GOOD_PW,))
    assert r.rc == 0, r.out + r.err
    assert env.fp_path().read_text() == first
    assert any("unchanged" in l for l in r.out.splitlines()), r.out


def test_the_uninstall_of_a_no_install_device_leaves_the_fingerprint(
    setup_env,
):
    """The teardown leaves the fingerprint, exactly as the installed
    uninstall leaves it: the passphrase is the owner's, and the owner
    changes it with approval-key."""
    env = setup_env
    prepare_router(env)
    assert run_noinstall(env).rc == 0
    fp = env.fp_path()
    text = fp.read_text()
    r = run_uninstall(env)
    assert r.rc == 0, r.out + r.err
    assert fp.exists()
    assert fp.read_text() == text


def test_the_installed_uninstall_leaves_the_fingerprint_too(setup_env):
    """The installed teardown leaves it as well: the two modes behave the
    same way about the owner's passphrase."""
    env = setup_env
    install_ok(env)
    r = env.run("r1", "approval-key", typed=(GOOD_PW, APPROVAL_PP, APPROVAL_PP))
    assert r.rc == 0, r.out + r.err
    fp = env.fp_path()
    assert fp.exists()
    text = fp.read_text()
    r = run_uninstall(env)
    assert r.rc == 0, r.out + r.err
    assert fp.exists()
    assert fp.read_text() == text


def test_a_failed_fingerprint_write_stops_the_no_install_setup(setup_env):
    """A fingerprint that cannot be written is a stop, not a DONE.

    The approval fingerprint is the only thing this host keeps of the
    owner's passphrase: a setup that could not write it has not done
    what it promised, so it stops and says so.  The router itself is
    untouched by this failure, so the state line says so too.
    """
    env = setup_env
    prepare_router(env)
    # the directory the fingerprint goes in is a plain file: the write
    # cannot succeed
    (env.state_dir / "approval-fp").write_text("not a directory\n")
    r = run_noinstall(env)
    assert r.rc == 1, r.out + r.err
    assert "STOPPED no-install r1: cannot write the approval fingerprint" in (
        r.out), r.out
    assert "NOTE state: router unchanged" in r.out, r.out
    assert not any(l.startswith("DONE ") for l in r.out.splitlines()), r.out


def test_a_failed_fingerprint_write_stops_the_approval_key_action(setup_env):
    """The approval-key action stops the same way.

    The action rewrites the owner's passphrase, so a run that could not
    store the new fingerprint must not claim it did.
    """
    env = setup_env
    fake_home(env)
    set_inventory(env, ['access = "no-install"'], auth="key")
    (env.state_dir / "approval-fp").write_text("not a directory\n")
    r = env.run("r1", "approval-key", typed=(APPROVAL_PP, APPROVAL_PP))
    assert r.rc == 1, r.out + r.err
    assert "STOPPED approval-key r1: cannot write the approval fingerprint" in (
        r.out), r.out
    assert "NOTE state: router unchanged" in r.out, r.out
    assert not any(l.startswith("DONE ") for l in r.out.splitlines()), r.out


# -- 7. the no-install admin login does not use the plain key ---------------

def make_plain_key(env):
    """A plain key pair at the default path of the fake home, with its
    unrestricted line on the router (an older setup left it there)."""
    ssh_dir = env.home / ".ssh"
    ssh_dir.mkdir(parents=True, exist_ok=True)
    key = ssh_dir / "id_ed25519"
    proc = subprocess.run(
        [str(env.fakes / "ssh-keygen"), "-q", "-t", "ed25519", "-N", "",
         "-C", "plain", "-f", str(key)],
        capture_output=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    env.router.add_authorized_key(
        key.with_name(key.name + ".pub").read_text().strip())
    return key


def admin_lanes(result):
    return [c.get("lane") for c in result.calls
            if c.get("tool") == "ssh" and c.get("lane")]


def test_no_install_defaults_to_the_password_lane_and_never_reads_the_plain_key(
        setup_env):
    """Without --admin, no-install logs in with the router's root password
    even when the plain key file exists: the plain key is never read and
    no ssh call uses the key lane."""
    env = setup_env
    fake_home(env)
    key = make_plain_key(env)
    set_inventory(env, auth="key")
    prepare_router(env)
    r = run_noinstall(env)
    assert r.rc == 0, r.out + r.err
    lanes = admin_lanes(r)
    assert lanes and set(lanes) == {"password"}, lanes
    for call in r.calls:
        assert str(key) not in repr(call), call


def test_no_install_device_defaults_to_the_password_lane_for_later_actions(
        setup_env):
    """A device whose inventory says access = no-install uses the password
    lane for check and uninstall too, with no auth line and a plain key
    on the host."""
    env = setup_env
    fake_home(env)
    key = make_plain_key(env)
    prepare_router(env)
    set_inventory(env, ['access = "no-install"',
                        'rpcd_password_file = "%s"'
                        % (env.keys_dir / "r1.rpcd"),
                        'https_spki = "%s"' % PIN], auth="key")
    r = run_uninstall(env)
    assert r.rc == 0, r.out + r.err
    lanes = admin_lanes(r)
    assert lanes and set(lanes) == {"password"}, lanes
    for call in r.calls:
        assert str(key) not in repr(call), call


def test_no_install_with_explicit_plain_key_still_uses_it(setup_env):
    """--admin plain-key --plain-key FILE is the owner asking for it."""
    env = setup_env
    fake_home(env)
    key = make_plain_key(env)
    set_inventory(env, auth="key")
    prepare_router(env)
    r = run_noinstall(env, opts=("--admin", "plain-key", "--plain-key",
                                 str(key)), typed=(GOOD_PW, GOOD_PW))
    assert r.rc == 0, r.out + r.err
    lanes = admin_lanes(r)
    assert lanes and set(lanes) == {"key"}, lanes


def test_no_install_with_only_plain_key_option_uses_the_key(setup_env):
    env = setup_env
    fake_home(env)
    key = make_plain_key(env)
    set_inventory(env, auth="key")
    prepare_router(env)
    r = run_noinstall(env, opts=("--plain-key", str(key)),
                      typed=(GOOD_PW, GOOD_PW))
    assert r.rc == 0, r.out + r.err
    assert set(admin_lanes(r)) == {"key"}


def test_no_install_says_an_old_plain_key_is_still_there_and_keeps_it(
        setup_env):
    """A plain key from an older setup is still in the router's authorized
    keys: one INFO line says so and how to remove it; the key stays."""
    env = setup_env
    fake_home(env)
    key = make_plain_key(env)
    set_inventory(env, auth="key")
    prepare_router(env)
    pub = key.with_name(key.name + ".pub").read_text().split()[1]
    r = run_noinstall(env)
    assert r.rc == 0, r.out + r.err
    infos = [l for l in r.out.splitlines()
             if l.startswith("INFO ") and "plain" in l and "key" in l
             and "authorized_keys" in l]
    assert len(infos) == 1, r.out
    assert "never removes" in infos[0]
    assert pub in "\n".join(env.router.authorized_keys())


def test_no_install_without_an_old_plain_key_prints_no_such_line(setup_env):
    env = setup_env
    fake_home(env)
    set_inventory(env, auth="key")
    prepare_router(env)
    r = run_noinstall(env)
    assert r.rc == 0, r.out + r.err
    assert "authorized_keys" not in r.out


def test_installed_device_default_stays_the_plain_key(setup_env):
    """A device with no no-install fields keeps the plain-key default."""
    env = setup_env
    fake_home(env)
    make_plain_key(env)
    seed_known_hosts(env)
    set_inventory(env, auth="key")
    r = env.run("r1", "check", typed=())
    assert admin_lanes(r) and set(admin_lanes(r)) == {"key"}, r.out + r.err
