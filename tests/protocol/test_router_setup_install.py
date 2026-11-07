"""Tests of the install action of scripts/newton-router-setup (;
design 8.2, with 2.1 zones, 2.3 sysupgrade lines and
the 2.6 write rules): the lab and pulsar first installs, idempotence,
rotation, the sysupgrade merge, the failure/restore paths, the refusals,
the corrupted upload, the missing source file, the known_hosts gate and
the secret rules."""

import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from router_setup_env import setup_env, pulsar_env, build_src  # noqa: F401
from router_setup_harness import DEFAULT_STATE  # noqa: E402

GOOD_PW = DEFAULT_STATE["root_password"]
PROG_REL = "device/openwrt/newton-router/newton-router"
HELPER_REL = "scripts/owrt-safe-apply.sh"
PROG = "usr/libexec/newton/newton-router"
HELPER = "usr/libexec/newton/newton-safe-apply"
GUARD = "usr/libexec/newton-guard"
INIT = "etc/init.d/newton-guard"

# the four code files: src-relative path -> router path
CODE_FILES = [
	(PROG_REL, PROG),
	(HELPER_REL, HELPER),
	("device/openwrt/newton-guard/newton-guard", GUARD),
	("device/openwrt/newton-guard/newton-guard.init", INIT),
]

# design 2.3 (R9b+c): the thirteen lines in order -- the eight code/config
# lines, the four WAN-health lines (the rc.d start and stop symlinks the
# init's `enable` creates, the wan-health script and its init) and the
# approval key (a firmware upgrade used to lose it). /etc/config is kept by
# sysupgrade by default and stays out of this list.
SYSUPGRADE_LINES = [
	"/usr/libexec/newton/newton-router",
	"/usr/libexec/newton/newton-safe-apply",
	"/usr/libexec/newton-guard",
	"/etc/init.d/newton-guard",
	"/etc/rc.d/S09newton-guard",
	"/etc/rc.d/S95newton-wan-health",
	"/etc/rc.d/K10newton-wan-health",
	"/usr/libexec/newton/newton-wan-health",
	"/etc/init.d/newton-wan-health",
	"/etc/newton/device-id",
	"/etc/newton/profile",
	"/etc/newton/zones",
	"/etc/newton/approve.key",
]


def seed_known_hosts(env):
	"""Put the router's host key in the device known_hosts file, as a
	previous check run would have left it."""
	env.known_hosts.write_text("10.1.2.3 %s\n" % env.router.state()["host_key"])


def run_install(env, extra_env=None):
	"""An install run with the typed root password and the "yes" the
	install asks for."""
	return env.run(env.device, "install", typed=(GOOD_PW, "yes"), env=extra_env)


def install_ok(env, extra_env=None):
	"""A first install that must succeed; returns the result."""
	seed_known_hosts(env)
	r = run_install(env, extra_env=extra_env)
	assert r.rc == 0
	assert r.out.splitlines()[-1] == "DONE install %s" % env.device
	return r


def dir_mode(path):
	"""The octal mode string of a real directory or file."""
	return "0o%o" % stat.S_IMODE(os.stat(path).st_mode)


def state_notes(result):
	return [l for l in result.out.splitlines()
		if l.startswith("NOTE state:")]


def no_dot_files(snapshot):
	"""No .new or .prev path in a router snapshot."""
	return [p for p in snapshot if p.endswith(".new") or p.endswith(".prev")]


# -- 1. lab-like first install ----------------------------------------------

def test_install_lab_first(setup_env):
	"""Design 8.2 steps 2-7 and 2.1/2.3 formats on a fresh router."""
	env = setup_env
	r = install_ok(env)
	assert r.err.count("root password: ") == 1
	assert len(r.lines("PASS install step")) == 7
	snap = env.router.snapshot()
	for rel, router_path in CODE_FILES:
		assert env.router.read(router_path) == (env.src / rel).read_text()
		assert snap[router_path]["mode"] == "0o755"
	assert no_dot_files(snap) == []
	assert snap["etc/rc.d/S09newton-guard"]["link"] == "../init.d/newton-guard"
	assert env.router.read("etc/newton/device-id") == "r1\n"
	assert env.router.read("etc/newton/profile") == "lab\n"
	assert env.router.read("etc/newton/zones") == (
		"mgmt-interface lan\nmgmt-zone lan\nwan-zone wan\n")
	for name in ("device-id", "profile", "zones"):
		assert snap["etc/newton/" + name]["mode"] == "0o600"
	assert dir_mode(env.router.path("etc/newton")) == "0o700"
	assert dir_mode(env.router.path("usr/libexec/newton")) == "0o755"
	assert env.router.read("etc/sysupgrade.conf").splitlines() == SYSUPGRADE_LINES


# -- 2. pulsar-like prod install ---------------------------------------------

def test_install_pulsar_prod_zones(pulsar_env):
	"""Design 2.1: the inventory's profile, mgmt_interface, mgmt_zone and
	wan_zones give the exact zones file on a prod device."""
	env = pulsar_env
	seed_known_hosts(env)
	env.inventory.write_text(
		'[devices.pulsar]\nhost = "10.1.2.3"\nprofile = "prod"\n'
		'auth = "key"\nmgmt_interface = "lan2"\nmgmt_zone = "mgmt"\n'
		'wan_zones = ["wan", "wan6"]\n')
	r = env.run("--plain-key", env.plain_key, "pulsar", "install",
	            typed=("yes",))
	assert r.rc == 0
	assert r.out.splitlines()[-1] == "DONE install pulsar"
	assert env.router.read("etc/newton/profile") == "prod\n"
	assert env.router.read("etc/newton/zones") == (
		"mgmt-interface lan2\nmgmt-zone mgmt\n"
		"wan-zone wan\nwan-zone wan6\n")


# -- 3. idempotence -----------------------------------------------------------

def test_install_idempotent(setup_env):
	"""Addendum 2.6: a second run changes nothing and uploads no .new."""
	env = setup_env
	install_ok(env)
	before = env.router.snapshot()
	r = run_install(env)
	assert r.rc == 0
	assert env.router.snapshot() == before
	assert no_dot_files(env.router.snapshot()) == []
	for call in r.calls:
		if call.get("stdin_len"):
			assert ".new" not in (call.get("command") or "")


# -- 4. change and rotation ---------------------------------------------------

def test_install_rotates_prev(setup_env, tmp_path):
	"""Design 8.2 step 3: only the program and helper rotate .prev (the
	helper is unchanged here, so only the program rotates), guard and init
	never do; a third run keeps .prev unchanged."""
	env = setup_env
	install_ok(env)
	src2 = build_src(tmp_path / "src2", version="2.0.0")
	r = run_install(env, {"NEWTON_SETUP_SRC": str(src2)})
	assert r.rc == 0
	snap = env.router.snapshot()
	assert env.router.read(PROG) == (src2 / PROG_REL).read_text()
	assert env.router.read(PROG + ".prev") == (
		env.src / PROG_REL).read_text()
	assert snap[PROG + ".prev"]["mode"] == "0o644"
	assert HELPER + ".prev" not in snap
	assert GUARD + ".prev" not in snap
	assert INIT + ".prev" not in snap
	prev = snap[PROG + ".prev"]
	r3 = run_install(env, {"NEWTON_SETUP_SRC": str(src2)})
	assert r3.rc == 0
	assert env.router.snapshot()[PROG + ".prev"] == prev


# -- 5. existing sysupgrade.conf ----------------------------------------------

def test_install_sysupgrade_appends_missing(setup_env):
	"""Design 2.3: other lines stay verbatim, only missing lines append."""
	env = setup_env
	seed_known_hosts(env)
	env.router.write("etc/sysupgrade.conf", "## custom\n/etc/myfile")
	r = run_install(env)
	assert r.rc == 0
	text = env.router.read("etc/sysupgrade.conf")
	assert text.startswith("## custom\n/etc/myfile\n")
	assert text.splitlines() == ["## custom", "/etc/myfile"] + SYSUPGRADE_LINES


def test_install_sysupgrade_existing_lf_adds_no_blank(setup_env):
	"""An existing final LF stays one separator, not an empty line."""
	env = setup_env
	seed_known_hosts(env)
	env.router.write("etc/sysupgrade.conf", "## custom\n/etc/myfile\n")
	r = run_install(env)
	assert r.rc == 0
	assert env.router.read("etc/sysupgrade.conf").splitlines() == [
		"## custom", "/etc/myfile"] + SYSUPGRADE_LINES


# -- 6. failure with and without .prev ----------------------------------------

def test_install_failure_restores_from_prev(setup_env, tmp_path):
	"""Addendum 3.2: a broken program over a good v1 is rolled back from
	.prev and the v1 program answers hello again."""
	env = setup_env
	install_ok(env)
	broken = build_src(tmp_path / "broken", program="broken")
	r = run_install(env, {"NEWTON_SETUP_SRC": str(broken)})
	assert r.rc == 1
	assert r.out.splitlines()[-1].startswith("STOPPED install r1")
	notes = state_notes(r)
	assert notes and "restored from .prev" in notes[-1]
	assert env.router.read(PROG) == (env.src / PROG_REL).read_text()
	# hello works again: a further run with the good sources succeeds
	assert run_install(env).rc == 0


def test_install_broken_first_no_prev(setup_env, tmp_path):
	"""Addendum 3.2: a broken program on a first install leaves no .prev
	and NOTE state: says so."""
	env = setup_env
	seed_known_hosts(env)
	broken = build_src(tmp_path / "broken", program="broken")
	r = run_install(env, {"NEWTON_SETUP_SRC": str(broken)})
	assert r.rc == 1
	assert r.out.splitlines()[-1].startswith("STOPPED install r1")
	notes = state_notes(r)
	assert notes and "no .prev" in notes[-1]
	assert not env.router.path(PROG + ".prev").exists()


# -- 7. refusals ---------------------------------------------------------------

def test_install_refused_when_busy(setup_env):
	"""Design 8.2 step 1: guard pending/failed and a live helper lock
	refuse with the router unchanged; guard `restored` is accepted."""
	env = setup_env
	# the guard must be on the router to have a status: install once first
	install_ok(env)
	for status in ("pending t1", "failed t1 x"):
		env.router.write("etc/newton/guard-state", status + "\n")
		before = env.router.snapshot()
		r = run_install(env)
		assert r.rc == 1
		assert r.out.splitlines()[-1].startswith("STOPPED install r1")
		assert "NOTE state: router unchanged" in r.out.splitlines()
		assert env.router.snapshot() == before
	env.router.write("etc/newton/guard-state", "restored t1 boot\n")
	assert run_install(env).rc == 0
	assert state_notes(run_install(env)) == []


def test_install_refused_helper_lock(setup_env):
	"""Design 8.2 step 1: a helper lock whose sid the fake ubus lists
	refuses with the router unchanged."""
	env = setup_env
	seed_known_hosts(env)
	env.router.write("tmp/owrt-safe-apply.lock/sid", "0xdead\n")
	env.router.update_state(ubus_sessions='"sid": "0xdead"')
	before = env.router.snapshot()
	r = run_install(env)
	assert r.rc == 1
	assert r.out.splitlines()[-1].startswith("STOPPED install r1")
	assert "NOTE state: router unchanged" in r.out.splitlines()
	assert env.router.snapshot() == before


# -- 8. corrupted upload --------------------------------------------------------

def test_install_corrupt_upload(setup_env):
	"""Addendum 2.6: a sha256 mismatch fails the run, removes the .new and
	leaves every router file untouched."""
	env = setup_env
	seed_known_hosts(env)
	before = env.router.snapshot()
	env.router.update_state(corrupt_stdin=True)
	r = run_install(env)
	assert r.rc == 1
	assert r.out.splitlines()[-1].startswith("STOPPED install r1")
	after = env.router.snapshot()
	assert after == before
	assert no_dot_files(after) == []


# -- 9. missing source file ------------------------------------------------------

def test_install_missing_source(setup_env):
	"""Addendum 3.2: a missing source file is exit 2 naming the file,
	before any ssh call."""
	env = setup_env
	seed_known_hosts(env)
	(env.src / "device/openwrt/newton-guard/newton-guard.init").unlink()
	r = run_install(env)
	assert r.rc == 2
	assert "error:" in r.err
	assert "newton-guard.init" in r.err
	assert r.calls == []


# -- 9b. hello verification lies -----------------------------------------------

@pytest.mark.parametrize("lie, reported", [
	("prog=" + "0" * 64, "prog=" + "0" * 64),
	# the other three fields were not covered (a
	# planted defect that checked only prog and helper survived)
	("helper=" + "0" * 64, "helper=" + "0" * 64),
	("guard=" + "0" * 64, "guard=" + "0" * 64),
	("init=" + "0" * 64, "init=" + "0" * 64),
	("mode=test", "mode=test"),
])
def test_install_stops_when_hello_lies(setup_env, lie, reported):
	"""Step 7 reports first-install files left in place when hello's
	program hash or mode does not describe the installed router."""
	env = setup_env
	seed_known_hosts(env)
	env.router.write("etc/newton/fixture-lie", lie + "\n")
	r = run_install(env)
	assert r.rc == 1
	assert r.out.splitlines()[-1] == "STOPPED install r1: install step 7 failed"
	assert "no .prev existed (first install)" in r.out
	assert env.router.path(PROG).exists()
	assert not env.router.path(PROG + ".prev").exists()
	assert env.router.read("etc/newton/fixture-lie").strip() == reported


# -- 10. known_hosts gate ---------------------------------------------------------

def test_install_needs_known_hosts(setup_env):
	"""Addendum 2.4: install without known_hosts is exit 2, run check
	first."""
	env = setup_env
	r = run_install(env)
	assert r.rc == 2
	assert "error:" in r.err
	assert "run check first" in r.err


# -- 11. secrets -------------------------------------------------------------------

def test_install_no_secret_leaks(setup_env):
	"""Addendum 1.3/2.3: the typed root password never leaks."""
	env = setup_env
	env.register_secrets(GOOD_PW)
	seed_known_hosts(env)
	assert run_install(env).rc == 0
	assert env.leaks() == []


# -- 12. the next step after the install -------------------------------------

def test_install_names_the_approval_key_step(setup_env):
	"""The device has no approval passphrase yet (the fingerprint file
	is written by approval-key): the install names the next step, right
	before the DONE line."""
	env = setup_env
	r = install_ok(env)
	lines = r.out.splitlines()
	expected = ("INFO next: choose the approval passphrase: sudo -u newton "
	            "/usr/local/bin/newton-router-setup r1 approval-key")
	assert expected in lines, r.out
	assert lines[-1] == "DONE install r1"
	assert lines.index(expected) == len(lines) - 2


def test_install_says_nothing_when_the_approval_key_is_there(setup_env):
	"""A device that already has an approval fingerprint needs no next
	step: the install prints nothing but DONE."""
	env = setup_env
	fp = env.fp_path()
	fp.parent.mkdir(parents=True, exist_ok=True)
	fp.write_text("v1 %s\n" % ("0" * 64))
	r = install_ok(env)
	lines = r.out.splitlines()
	assert not any(line.startswith("INFO next:") for line in lines), r.out
	assert lines[-1] == "DONE install r1"
