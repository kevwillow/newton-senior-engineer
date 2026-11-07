"""The switch from the no-install mode to the installed mode.

The owner switches a router from the no-install mode to the installed
mode with two commands: ``uninstall`` (it removes the no-install login)
and then ``install`` (it puts Newton's program on the router).

The uninstall ends the no-install mode: it takes every no-install field
out of the inventory (access, rpcd_password_file, https_spki and
installed_offer), so the entry is a plain device in the default
(installed) mode.  Both loaders read such an entry, so the whole
inventory keeps loading; the device is not installed yet, the install
comes next.

The install refuses a device whose inventory still says no-install, and
it refuses a router that still holds the no-install login, whatever the
inventory says: the two modes never mix, and the router is the proof,
not the inventory.

The session proof of the uninstall fails closed: only a destroy that
rpcd answers "not found" (the expiry race) is ignored, and the final
listing has to be a session list before "no session" can be claimed.

The tests: the uninstall ends the mode and both loaders read the whole
inventory; the install works after the uninstall; the install is refused
while the router holds the no-install login (ours or a foreign one) and
when the rpcd config cannot be read; the install is refused while the
inventory says no-install; and the four session cases.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from router_setup_env import setup_env  # noqa: E402
from test_router_setup_disclosure import YES, seed_known_hosts  # noqa: E402
from test_router_setup_noinstall import (  # noqa: E402
    GOOD_PW,
    inventory_entry,
    prepare_router,
    run_noinstall,
    run_uninstall,
    set_section,
)
from test_router_setup_offer import run_noinstall_with_offer  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "scripts" / "newton-router-setup"

# the four fields that make a device a no-install device
NO_INSTALL_FIELDS = ("access", "rpcd_password_file", "https_spki",
                     "installed_offer")

# the setup loader on an inventory file: it prints the fields it read
SOURCE_RUN = (
    'source "$1"\n'
    'INVENTORY="$2"\n'
    'load_inventory r1\n'
    'printf "access=%s\\n" "$DEV_ACCESS"\n'
    'printf "rpcd_password_file=%s\\n" "$DEV_RPCD_PASSWORD_FILE"\n'
    'printf "https_spki=%s\\n" "$DEV_HTTPS_SPKI"\n'
)


# -- helpers ----------------------------------------------------------------

def add_mcp_fields(env):
    """Write the `platform` and `user` fields into the inventory.

    The setup loader defaults the platform to openwrt and the user to
    root, and it asks for the password on the terminal; the MCP loader
    wants the fields themselves and the password file.  Both loaders
    must read the same device the same way, so the fields are written
    once, before any run.
    """
    password_file = env.keys_dir / "r1.pw"
    password_file.write_text("synthetic-password\n")
    password_file.chmod(0o600)
    text = env.inventory.read_text()
    env.inventory.write_text(
        text.replace('[devices.r1]\n',
                     '[devices.r1]\nplatform = "openwrt"\nuser = "root"\n'
                     'password_file = "%s"\n' % password_file))
    env.inventory.chmod(0o644)


def add_second_device(env):
    """A second, unrelated device in the same inventory.

    The whole inventory has to load: a device that only the loader of
    one device reads is not a proof that the MCP server can work.
    """
    text = env.inventory.read_text()
    env.inventory.write_text(text + (
        '\n[devices.r2]\nhost = "10.1.2.4"\nprofile = "lab"\n'
        'platform = "openwrt"\nuser = "root"\n'))
    env.inventory.chmod(0o644)


def strip_fields(env, fields, device="r1"):
    """Take the given fields out of the inventory by hand.

    The owner may edit the inventory by hand.  The install must not
    trust that: the router is the proof.
    """
    text = env.inventory.read_text()
    keep = []
    for line in text.splitlines(keepends=True):
        name = line.split("=", 1)[0].strip()
        if name in fields:
            continue
        keep.append(line)
    env.inventory.write_text("".join(keep))
    env.inventory.chmod(0o644)


def setup_no_install(env):
    """A router in the no-install mode: the inventory says no-install and
    holds the two login fields."""
    prepare_router(env)
    r = run_noinstall(env)
    assert r.rc == 0, r.out + r.err
    entry = inventory_entry(env)
    assert entry["access"] == "no-install"
    assert entry["rpcd_password_file"]
    assert entry["https_spki"]
    return r


def run_install(env, answer=YES):
    """An install run: the typed root password and the answer the
    install asks for."""
    return env.run("r1", "install", typed=(GOOD_PW, answer))


def setup_loader_view(inventory):
    """The setup loader's own view of the device (its fields)."""
    proc = subprocess.run(
        ["bash", "-c", SOURCE_RUN, "bash", str(TOOL), str(inventory)],
        capture_output=True, text=True, timeout=60,
        env={k: v for k, v in os.environ.items()
             if not k.startswith("NEWTON_")})
    assert proc.returncode == 0, proc.stdout + proc.stderr
    fields = {}
    for line in proc.stdout.splitlines():
        key, _, value = line.partition("=")
        fields[key] = value
    return fields


def mcp_loader_view(inventory, monkeypatch):
    """The MCP server's own view of the whole inventory."""
    sys.path.insert(0, str(REPO / "mcp"))
    import newton_mcp.server as server
    monkeypatch.setenv("NEWTON_INVENTORY", str(inventory))
    return server.load_inventory()


# -- 1. the uninstall ends the no-install mode ------------------------------

def test_the_uninstall_ends_the_no_install_mode(setup_env, monkeypatch):
    """no-install, uninstall: every no-install field is gone from the
    inventory, so the entry is a plain device in the default (installed)
    mode."""
    env = setup_env
    add_mcp_fields(env)
    add_second_device(env)
    # the owner declines the offer: the field is there when the uninstall
    # runs and it has to go away with the others
    prepare_router(env)
    first = run_noinstall_with_offer(env, answer="no")
    assert first.rc == 0, first.out + first.err
    assert inventory_entry(env)["installed_offer"] == "declined"

    r = run_uninstall(env)
    assert r.rc == 0, r.out + r.err
    assert r.out.splitlines()[-1] == "DONE uninstall r1"

    entry = inventory_entry(env)
    for field in NO_INSTALL_FIELDS:
        assert field not in entry, entry
    assert entry["host"] == "10.1.2.3"
    assert entry["profile"] == "lab"


def test_the_whole_inventory_loads_after_the_uninstall(setup_env,
                                                       monkeypatch):
    """The setup loader and the MCP loader both read the whole inventory
    after the uninstall, and they see the device as an installed one."""
    env = setup_env
    add_mcp_fields(env)
    add_second_device(env)
    setup_no_install(env)
    assert run_uninstall(env).rc == 0

    # the setup loader's own view of the device
    fields = setup_loader_view(env.inventory)
    assert fields["access"] == "installed"
    assert fields["rpcd_password_file"] == ""
    assert fields["https_spki"] == ""

    # and the MCP loader's own view of the whole inventory
    devices = mcp_loader_view(env.inventory, monkeypatch)
    assert set(devices) == {"r1", "r2"}
    assert devices["r1"].access == "installed"
    assert devices["r1"].rpcd_password_file is None
    assert devices["r1"].https_spki is None


# -- 2. the install after the uninstall works -------------------------------

def test_the_install_after_the_uninstall_works(setup_env):
    """no-install, uninstall, install: the install runs, ends DONE and
    puts Newton's program on the router."""
    env = setup_env
    setup_no_install(env)
    assert run_uninstall(env).rc == 0
    rpcd = (env.router.state().get("uci_sections") or {}).get("rpcd") or {}
    assert "newton" not in rpcd

    r = run_install(env)
    assert r.rc == 0, r.out + r.err
    assert r.out.splitlines()[-1] == "DONE install r1"
    assert env.router.path("usr/libexec/newton/newton-router").exists()


# -- 3. the install checks the router ---------------------------------------

def test_the_install_is_refused_while_the_router_holds_the_no_install_login(
    setup_env,
):
    """The inventory says nothing about the no-install mode (the owner
    took the fields out by hand) but the login is still live on the
    router: the install is refused and the router is unchanged."""
    env = setup_env
    setup_no_install(env)
    strip_fields(env, NO_INSTALL_FIELDS)
    before_inventory = env.inventory.read_text()
    before_router = env.router.snapshot()

    r = run_install(env)
    assert r.rc == 1, r.out + r.err
    assert r.out.splitlines()[-1] == (
        "STOPPED install r1: the no-install login of Newton is still on the "
        "router; run `uninstall` first")
    assert "NOTE state: router unchanged" in r.out.splitlines()
    assert env.inventory.read_text() == before_inventory
    assert env.router.snapshot() == before_router
    assert not env.router.path("usr/libexec/newton/newton-router").exists()


def test_the_install_is_refused_when_the_rpcd_section_is_not_newtons(
    setup_env,
):
    """A rpcd.newton section that is not Newton's is not Newton's login,
    but it is a login: the install is refused and the router is
    unchanged."""
    env = setup_env
    seed_known_hosts(env)
    set_section(env, "rpcd", "newton", "login",
                {"username": "newton", "password": "$6$foreign$hash"})
    before_router = env.router.snapshot()

    r = run_install(env)
    assert r.rc == 1, r.out + r.err
    assert r.out.splitlines()[-1] == (
        "STOPPED install r1: the router has an rpcd.newton section that is "
        "not Newton's; Newton never touches it")
    assert "NOTE state: router unchanged" in r.out.splitlines()
    assert env.router.snapshot() == before_router


def test_the_install_is_refused_when_the_rpcd_config_cannot_be_read(
    setup_env,
):
    """The rpcd config cannot be read: the install fails closed, because
    "I could not look" is not "there is nothing there"."""
    env = setup_env
    seed_known_hosts(env)
    env.router.update_state(uci_fail=[["show rpcd", 1]])
    before_router = env.router.snapshot()

    r = run_install(env)
    assert r.rc == 1, r.out + r.err
    assert r.out.splitlines()[-1] == (
        "STOPPED install r1: cannot read the router's rpcd config")
    assert "NOTE state: router unchanged" in r.out.splitlines()
    assert env.router.snapshot() == before_router


# -- 4. the install is refused while the inventory says no-install ----------

@pytest.mark.parametrize("login_fields", [True, False])
def test_the_install_is_refused_while_the_inventory_says_no_install(
    setup_env,
    login_fields,
):
    """The inventory still says no-install: the install is refused, with
    or without the two login fields, and the router is not touched."""
    env = setup_env
    setup_no_install(env)
    if not login_fields:
        strip_fields(env, ("rpcd_password_file", "https_spki"))
    before_inventory = env.inventory.read_text()
    before_router = env.router.snapshot()

    r = run_install(env)
    assert r.rc == 1, r.out + r.err
    assert r.out.splitlines()[-1] == (
        "STOPPED install r1: this device uses no-install access; run "
        "`uninstall` first")
    assert env.inventory.read_text() == before_inventory
    assert env.router.snapshot() == before_router
    assert r.calls == []


# -- 5. the session proof of the uninstall fails closed ---------------------

def test_the_uninstall_goes_on_with_reordered_session_keys(setup_env):
    """The order of the members of a session object is not semantic: the
    fake router prints "data" (with the username) before the id, and the
    uninstall still finds and destroys the session."""
    env = setup_env
    setup_no_install(env)
    env.router.update_state(rpcd_sessions=[
        {"username": "newton", "id": "a" * 32},
    ])

    r = run_uninstall(env)
    assert r.rc == 0, r.out + r.err
    assert r.out.splitlines()[-1] == "DONE uninstall r1"
    assert env.router.state()["rpcd_sessions"] == []


def test_the_uninstall_stops_when_the_session_list_is_not_a_session_list(
    setup_env,
):
    """A status-0 answer that is not a session list is not "no session":
    the uninstall stops."""
    env = setup_env
    setup_no_install(env)
    env.router.update_state(rpcd_sessions=[
        {"id": "a" * 32, "username": "newton"},
    ])
    # the router answers the second listing with something else
    env.router.update_state(ubus_sessions='{"error": "not found"}')

    r = run_uninstall(env)
    assert r.rc == 1, r.out + r.err
    lines = r.out.splitlines()
    assert not any(line.startswith("DONE") for line in lines), lines
    assert not any("no rpcd session" in line for line in lines), lines


def test_the_uninstall_stops_when_a_destroy_fails(setup_env):
    """A destroy that fails for any other reason than the expiry race is a
    stop: the session may still be there."""
    env = setup_env
    setup_no_install(env)
    env.router.update_state(rpcd_sessions=[
        {"id": "a" * 32, "username": "newton"},
    ])
    env.router.update_state(ubus_fail=["session destroy"])

    r = run_uninstall(env)
    assert r.rc == 1, r.out + r.err
    lines = r.out.splitlines()
    assert lines[-1] == "STOPPED uninstall r1: uninstall step 3 failed"
    assert any("could not be destroyed" in line for line in lines), lines
    assert env.router.state()["rpcd_sessions"], env.router.state()


def test_the_uninstall_goes_on_when_the_session_expires_before_its_destroy(
    setup_env,
):
    """A session can time out on its own before the destroy reaches it
    (seen live on Pulsar): rpcd answers "Not found" (exit status 252,
    measured), and that is the one failed destroy the uninstall
    ignores."""
    env = setup_env
    setup_no_install(env)
    env.router.update_state(rpcd_sessions=[
        {"id": "a" * 32, "username": "newton", "expires_after_list": True},
    ])

    r = run_uninstall(env)
    assert r.rc == 0, r.out + r.err
    assert r.out.splitlines()[-1] == "DONE uninstall r1"
    assert env.router.state()["rpcd_sessions"] == []


def test_the_uninstall_stops_when_the_sessions_cannot_be_listed(setup_env):
    """The session listing fails: the uninstall stops; it never says that
    there is no session."""
    env = setup_env
    setup_no_install(env)
    env.router.update_state(rpcd_sessions=[
        {"id": "a" * 32, "username": "newton"},
    ])
    env.router.update_state(ubus_fail=["session list"])

    r = run_uninstall(env)
    assert r.rc == 1, r.out + r.err
    lines = r.out.splitlines()
    assert "cannot list sessions" in lines[-1]
    assert not any("no rpcd session" in line for line in lines), lines
    assert not any(line.startswith("DONE") for line in lines), lines


# The bytes of `ubus call session list` on Pulsar (OpenWrt 25.12,
# 2026-11-02, lab runner scenario a5p-00m), with the masked id and
# numbers put back as fixed values: rpcd's own unauthenticated session
# only, no newton session.
MEASURED_SESSION_LIST = """{
	"ubus_rpc_session": "00000000000000000000000000000000",
	"timeout": 0,
	"expires": 0,
	"acls": {
		"access-group": {
			"unauthenticated": [
				"read"
			]
		},
		"ubus": {
			"luci": [
				"getFeatures"
			],
			"session": [
				"access",
				"login"
			]
		}
	},
	"data": {
		
	}
}"""


def test_the_uninstall_reads_the_measured_session_list(setup_env):
    """The real answer of a router with no newton session is read as a
    session list that holds none: the uninstall finishes."""
    env = setup_env
    setup_no_install(env)
    env.router.update_state(ubus_sessions=MEASURED_SESSION_LIST)

    r = run_uninstall(env)
    assert r.rc == 0, r.out + r.err
    assert r.out.splitlines()[-1] == "DONE uninstall r1"


def test_the_uninstall_stops_on_an_empty_session_list(setup_env):
    """rpcd always lists its own session, so an empty answer with status
    0 is not "no session": the uninstall stops."""
    env = setup_env
    setup_no_install(env)
    env.router.update_state(ubus_sessions=" ")

    r = run_uninstall(env)
    assert r.rc == 1, r.out + r.err
    lines = r.out.splitlines()
    assert not any(line.startswith("DONE") for line in lines), lines
    assert "cannot list sessions" in lines[-1]


def test_the_uninstall_stops_on_an_object_that_is_not_a_session(setup_env):
    """An object with a 32-hex id but none of the other members rpcd
    prints for a session is not a session list."""
    env = setup_env
    setup_no_install(env)
    env.router.update_state(ubus_sessions=(
        '{\n\t"ubus_rpc_session": "' + "0" * 32 + '"\n}'))

    r = run_uninstall(env)
    assert r.rc == 1, r.out + r.err
    assert "cannot list sessions" in r.out.splitlines()[-1]


def test_the_uninstall_stops_without_the_unauthenticated_session(setup_env):
    """rpcd always lists its own unauthenticated session: a list without
    it is not rpcd's answer."""
    env = setup_env
    setup_no_install(env)
    env.router.update_state(ubus_sessions=MEASURED_SESSION_LIST.replace(
        "0" * 32, "c" * 32))

    r = run_uninstall(env)
    assert r.rc == 1, r.out + r.err
    assert "cannot list sessions" in r.out.splitlines()[-1]


def test_the_uninstall_stops_on_members_without_the_session_shapes(setup_env):
    """The all-zero id with null members is not rpcd's unauthenticated
    session: timeout and expires are numbers, acls and data objects."""
    env = setup_env
    setup_no_install(env)
    env.router.update_state(ubus_sessions=(
        '{\n\t"ubus_rpc_session": "' + "0" * 32 + '",\n'
        '\t"timeout": null,\n\t"expires": null,\n'
        '\t"acls": null,\n\t"data": null\n}'))

    r = run_uninstall(env)
    assert r.rc == 1, r.out + r.err
    assert "cannot list sessions" in r.out.splitlines()[-1]
