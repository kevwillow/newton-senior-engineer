"""Tests of the WAN-health extras of
scripts/newton-router-setup: the install / upgrade / uninstall /
check wiring of the two router files
(/usr/libexec/newton/newton-wan-health and /etc/init.d/newton-wan-health)
and of /etc/config/newton_wanhealth. The tests follow the style of
test_router_setup_install.py and test_router_setup_lifecycle.py."""

import hashlib
import os
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from router_setup_env import setup_env, build_src  # noqa: F401
from router_setup_harness import DEFAULT_STATE  # noqa: E402
from test_router_setup_install import (  # noqa: E402
	install_ok, seed_known_hosts, GOOD_PW,
)

WANHEALTH = "usr/libexec/newton/newton-wan-health"
WANHEALTH_INIT = "etc/init.d/newton-wan-health"
WANHEALTH_SRC = "scripts/newton-wan-health.sh"
WANHEALTH_INIT_SRC = "scripts/newton-wan-health.init"
WANHEALTH_CONFIG = "etc/config/newton_wanhealth"
WANHEALTH_START_MARKER = "tmp/newton-wan-health.start"
WANHEALTH_STOP_MARKER = "tmp/newton-wan-health.stop"
WANHEALTH_RESTART_MARKER = "tmp/newton-wan-health.restart"
WANHEALTH_RESTART_PENDING_DIR = "wan-health-restart-pending"


def run(env, *args, src=None):
	"""Typed-password run; src, when given, overrides NEWTON_SETUP_SRC.
	The install also asks for the "yes", so the feed carries it."""
	extra = {"NEWTON_SETUP_SRC": str(src)} if src else None
	typed = (GOOD_PW,)
	if args and args[0] == "install":
		typed = typed + ("yes",)
	return env.run("r1", *args, typed=typed, env=extra)


def _calls_with(result, fragment):
	"""The current-run calls whose fixed remote command contains fragment."""
	return [call for call in result.calls
	        if fragment in (call.get("command") or "")]


def _restart_pending_marker(env, device=None):
	"""The host-side restart-pending marker for one inventory device."""
	return env.state_dir / WANHEALTH_RESTART_PENDING_DIR / (
		device or env.device)


# -- host-side restart-pending marker helpers ---------------------------


def _seed_restart_pending(env, device=None):
	"""Create the host-side marker exactly as upgrade would leave it."""
	marker = _restart_pending_marker(env, device)
	marker.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
	marker.write_text("v1\n")
	return marker


def _failed_restart_upgrade(env, tmp_path):
	"""Upgrade changed wan-health files but leave its restart pending."""
	src2 = build_src(tmp_path / "src2", version="2.0.0")
	for rel in (WANHEALTH_SRC, WANHEALTH_INIT_SRC):
		with (src2 / rel).open("a") as fh:
			fh.write("# v2\n")
	env.router.update_state(
		fail_commands=["init.d/newton-wan-health' restart"])
	assert run(env, "upgrade", src=src2).rc == 1
	env.router.update_state(fail_commands=[])
	return src2


# -- 1. install: the two files and the init enable -------------------------

def test_install_wan_health_files_and_init_enable(setup_env):
	"""Install puts /usr/libexec/newton/newton-wan-health and
	/etc/init.d/newton-wan-health at mode 755 with the source bytes,
	runs the init's enable (which makes the S95 symlink), and creates
	/etc/config/newton_wanhealth empty if it did not exist."""
	env = setup_env
	seed_known_hosts(env)
	assert env.router.path(WANHEALTH_CONFIG).exists() is False
	r = run(env, "install")
	assert r.rc == 0, r.out + r.err
	# the three extras pass lines
	lines = r.out.splitlines()
	assert "PASS install extras 1: wan-health code files in place" in lines
	assert "PASS install extras 2: wan-health config and init enabled" in lines
	assert "PASS install extras 3: wan-health sha256 verified" in lines
	# the two router files: correct bytes, mode 755
	snap = env.router.snapshot()
	assert snap[WANHEALTH]["mode"] == "0o755"
	assert snap[WANHEALTH_INIT]["mode"] == "0o755"
	assert env.router.read(WANHEALTH) == (env.src / WANHEALTH_SRC).read_text()
	assert env.router.read(WANHEALTH_INIT) == (
		env.src / WANHEALTH_INIT_SRC).read_text()
	# the init's enable made the S95 symlink
	assert snap["etc/rc.d/S95newton-wan-health"]["link"] == "../init.d/newton-wan-health"
	# /etc/config/newton_wanhealth was created empty, mode 600
	assert env.router.path(WANHEALTH_CONFIG).exists()
	assert env.router.read(WANHEALTH_CONFIG) == ""
	assert snap[WANHEALTH_CONFIG]["mode"] == "0o600"


# -- 2. install: pre-existing config is not overwritten --------------------

def test_install_does_not_overwrite_existing_wan_health_config(setup_env):
	"""A pre-existing /etc/config/newton_wanhealth (user data) is left
	 intact when install runs; the init's enable is the only effect."""
	env = setup_env
	seed_known_hosts(env)
	env.router.write(WANHEALTH_CONFIG,
		"config mysection 'user'\n\toption foo 'bar'\n",
		0o644)
	before_text = env.router.read(WANHEALTH_CONFIG)
	r = run(env, "install")
	assert r.rc == 0, r.out + r.err
	assert env.router.read(WANHEALTH_CONFIG) == before_text
	assert env.router.snapshot()[WANHEALTH_CONFIG]["mode"] == "0o644"


# -- 3. install: missing config is created empty ---------------------------

def test_install_creates_empty_wan_health_config_when_missing(setup_env):
	"""A router that has no /etc/config/newton_wanhealth gets the file
	 created empty (mode 600) so uci does not refuse later `uci set
	 newton_wanhealth.main.enabled=1` calls."""
	env = setup_env
	seed_known_hosts(env)
	assert not env.router.path(WANHEALTH_CONFIG).exists()
	r = run(env, "install")
	assert r.rc == 0
	assert env.router.path(WANHEALTH_CONFIG).exists()
	assert env.router.read(WANHEALTH_CONFIG) == ""
	assert env.router.snapshot()[WANHEALTH_CONFIG]["mode"] == "0o600"


# -- 4. install: sha mismatch on verify fails and removes the extras --------

def test_install_sha_mismatch_removes_wan_health_extras(setup_env):
	"""When the router-side file content does not match the source sha
	 the install fails at the verify step and install_restore rm -fs
	 both wan-health extras (no .prev to restore from)."""
	env = setup_env
	seed_known_hosts(env)
	# Corrupt both wan-health files AFTER the install_wan_health_config
	# call (call 23 in this flow) but BEFORE the install_wan_health_verify
	# call (call 24). The harness's corrupt_after_call_n hook fires after
	# the call number is logged; using n=23 corrupts the live files
	# between extras 2 and extras 3.
	env.router.update_state(corrupt_after_call_n=[
		(23, str(env.router.path(WANHEALTH))),
		(23, str(env.router.path(WANHEALTH_INIT))),
	])
	r = run(env, "install")
	assert r.rc == 1
	lines = r.out.splitlines()
	assert "PASS install extras 2: wan-health config and init enabled" in lines
	assert lines[-1] == "STOPPED install r1: install extras 3 failed"
	snap = env.router.snapshot()
	# the extras were removed
	assert WANHEALTH not in snap
	assert WANHEALTH_INIT not in snap
	# the CODE_FILES stay (no_prev behaviour for the rest)
	for code_rel, code_remote in (
		("device/openwrt/newton-router/newton-router",
			"usr/libexec/newton/newton-router"),
		("scripts/owrt-safe-apply.sh", "usr/libexec/newton/newton-safe-apply"),
		("device/openwrt/newton-guard/newton-guard", "usr/libexec/newton-guard"),
		("device/openwrt/newton-guard/newton-guard.init",
			"etc/init.d/newton-guard"),
	):
		assert env.router.read(code_remote) == (env.src / code_rel).read_text()


# -- 5. install: a missing source dies exit 2 with no router call ---------

def test_install_missing_wan_health_source_exits_2(setup_env):
	"""A missing scripts/newton-wan-health.sh source is exit 2, names
	the missing file, and never reaches the router."""
	env = setup_env
	seed_known_hosts(env)
	(env.src / WANHEALTH_SRC).unlink()
	r = run(env, "install")
	assert r.rc == 2
	assert "error:" in r.err
	assert WANHEALTH_SRC in r.err
	assert r.calls == []


def test_install_missing_wan_health_init_source_exits_2(setup_env):
	"""A missing scripts/newton-wan-health.init source is exit 2 as well."""
	env = setup_env
	seed_known_hosts(env)
	(env.src / WANHEALTH_INIT_SRC).unlink()
	r = run(env, "install")
	assert r.rc == 2
	assert "error:" in r.err
	assert WANHEALTH_INIT_SRC in r.err
	assert r.calls == []


# -- 6. upgrade: the extras are replaced (rotate=yes, R9b+c) --------------

def test_upgrade_replaces_wan_health_extras(setup_env, tmp_path):
	"""Upgrade puts the wan-health files whenever the guard is idle
	(when not idle, the extras are still uploaded because they don't
	 depend on guard status). The script and init are replaced with the
	new bytes; R9b+c added rotate=yes so a .prev holds the OLD bytes,
	mirroring the program and helper's behaviour."""
	env = setup_env
	install_ok(env)
	old_script = env.router.read(WANHEALTH)
	old_init = env.router.read(WANHEALTH_INIT)
	src2 = build_src(tmp_path / "src2", version="2.0.0")
	for rel in (WANHEALTH_SRC, WANHEALTH_INIT_SRC):
		with (src2 / rel).open("a") as fh:
			fh.write("# v2\n")
	r = run(env, "upgrade", src=src2)
	assert r.rc == 0, r.out + r.err
	lines = r.out.splitlines()
	assert "PASS upgrade extras 1: wan-health code files uploaded" in lines
	assert "PASS upgrade extras 2: wan-health sha256 verified" in lines
	assert env.router.read(WANHEALTH) == (src2 / WANHEALTH_SRC).read_text()
	assert env.router.read(WANHEALTH_INIT) == (
		src2 / WANHEALTH_INIT_SRC).read_text()
	# rotate=yes for the extras: a .prev holds the OLD bytes (R9b+c)
	assert env.router.path(WANHEALTH + ".prev").exists()
	assert env.router.read(WANHEALTH + ".prev") == old_script
	assert env.router.path(WANHEALTH_INIT + ".prev").exists()
	assert env.router.read(WANHEALTH_INIT + ".prev") == old_init


# -- 7. uninstall: stop, disable, rm; config left in place -----------------

def test_uninstall_stops_disables_and_removes_wan_health(setup_env, tmp_path):
	"""Uninstall stops the wan-health init (no-op when not started),
	disables it (removes the S95 symlink), and rm -f's both wan-health
	router files. /etc/config/newton_wanhealth is left alone (user data)."""
	env = setup_env
	install_ok(env)
	env.router.write(WANHEALTH_CONFIG,
		"config user 'kept'\n\toption key 'value'\n", 0o644)
	config_before = env.router.read(WANHEALTH_CONFIG)
	assert "etc/rc.d/S95newton-wan-health" in env.router.snapshot()
	r = run(env, "uninstall")
	assert r.rc == 0, r.out + r.err
	snap = env.router.snapshot()
	assert WANHEALTH not in snap
	assert WANHEALTH_INIT not in snap
	assert "etc/rc.d/S95newton-wan-health" not in snap
	# config file left in place
	assert env.router.read(WANHEALTH_CONFIG) == config_before
	# the uninstall step labels reflect the new order
	lines = r.out.splitlines()
	assert any(l.startswith("PASS uninstall step 2a:") for l in lines)
	assert any(l.startswith("PASS uninstall step 3: code files removed")
	           for l in lines)


def test_uninstall_idempotent_when_no_wan_health_init(setup_env, tmp_path):
	"""A second uninstall run on a router without the wan-health init
	exits 0 and the steps are all no-ops; the call to
	uninstall_wan_health_init still succeeds when the init file is
	absent."""
	env = setup_env
	install_ok(env)
	run(env, "uninstall")
	before = env.router.snapshot()
	r2 = run(env, "uninstall")
	assert r2.rc == 0
	assert env.router.snapshot() == before


# -- 8. check: three states, never changes verdict ------------------------

def test_check_wan_health_reports_installed(setup_env):
	"""After a successful install, check reports wan-health=installed
	 and the run still prints DONE check r1 (exit 0)."""
	env = setup_env
	install_ok(env)
	r = run(env, "check")
	assert r.rc == 0
	assert "DONE check r1" in r.out.splitlines()
	assert "INFO wan-health installed" in r.out.splitlines()
	# no FAIL line
	assert not [l for l in r.out.splitlines() if l.startswith("FAIL ")]


def test_check_wan_health_reports_not_installed(setup_env):
	"""Without an install, check reports wan-health=not-installed and
	 the run still exits 0."""
	env = setup_env
	r = run(env, "check")
	assert r.rc == 0
	assert "DONE check r1" in r.out.splitlines()
	assert "INFO wan-health not-installed" in r.out.splitlines()


def test_check_wan_health_reports_differs(setup_env):
	"""When the router-side file has different bytes from the source,
	 check reports wan-health=differs (still informational; never FAIL)."""
	env = setup_env
	seed_known_hosts(env)
	# pre-populate with content that doesn't match
	env.router.write(WANHEALTH, "totally different bytes\n", 0o755)
	env.router.write(WANHEALTH_INIT, "# also different\n", 0o755)
	r = run(env, "check")
	assert r.rc == 0
	assert "INFO wan-health differs from sources" in r.out.splitlines()
	# never a FAIL line
	assert not [l for l in r.out.splitlines() if l.startswith("FAIL ")]
	# never a wan-health WARN; the R5 restricted-key WARN (no key_file
	# in the inventory) is allowed but checked at the door elsewhere
	assert [l for l in r.out.splitlines() if l.startswith("WARN ")] \
		== ["WARN restricted-key proofs skipped: no key_file in the inventory"]


# -- 9. sha256 line in check_report: deterministic ----------------------------

def test_check_wan_health_reports_differ_when_only_init_differs(setup_env):
	"""A mismatched init alone produces wan-health=differs (the install
	 check sees both files' shas, not just one)."""
	env = setup_env
	seed_known_hosts(env)
	# put a file matching the source for the script...
	env.router.write(WANHEALTH, (env.src / WANHEALTH_SRC).read_text(), 0o755)
	# ...and a different file for the init
	env.router.write(WANHEALTH_INIT, "# different\n", 0o755)
	r = run(env, "check")
	assert r.rc == 0
	assert "INFO wan-health differs from sources" in r.out.splitlines()


def test_check_wan_health_reports_differ_when_only_script_differs(setup_env):
	"""A mismatched script alone produces wan-health=differs."""
	env = setup_env
	seed_known_hosts(env)
	env.router.write(WANHEALTH, "different script bytes\n", 0o755)
	env.router.write(WANHEALTH_INIT,
		(env.src / WANHEALTH_INIT_SRC).read_text(), 0o755)
	r = run(env, "check")
	assert r.rc == 0
	assert "INFO wan-health differs from sources" in r.out.splitlines()


def test_check_wan_health_reports_installed_when_one_file_present(setup_env):
	"""Only the script present (init missing) is reported as
	 not-installed, not installed and not differs."""
	env = setup_env
	seed_known_hosts(env)
	env.router.write(WANHEALTH, (env.src / WANHEALTH_SRC).read_text(), 0o755)
	r = run(env, "check")
	assert r.rc == 0
	assert "INFO wan-health not-installed" in r.out.splitlines()


# -- 10b. live finding: install must run `start` after `enable` ------------

WANHEALTH_INIT_MARKER = "tmp/newton-wan-health.start"


def _wanhealth_extras2_call(result):
	"""The single rsh_admin call of install_wan_health_config (extras 2):
	it is the only ssh call whose command text names the wan-health
	init in the `init.d/newton-wan-health" enable` shape. Return the
	matched call entry, or None when missing."""
	for call in result.calls:
		cmd = call.get("command") or ""
		if re.search(
			r'init\.d/newton-wan-health"\s+enable\b', cmd):
			return call
	return None


def test_install_runs_start_after_enable(setup_env):
	"""Live OpenWrt 25.12 finding: procd only registers
	`procd_add_reload_trigger newton_wanhealth` once the init script has
	been STARTED at least once (the start_service function, not enable,
	opens procd). Setup's install used to run only `enable`, so a later
	`uci set newton_wanhealth.main.enabled=1` from a Newton change
	would not start the daemon until the router rebooted. The fix is to
	run `start` immediately after `enable` in the same fixed-text
	rsh_admin call (start is a no-op until enabled=1, so it is still
	safe)."""
	env = setup_env
	seed_known_hosts(env)
	r = run(env, "install")
	assert r.rc == 0, r.out + r.err
	call = _wanhealth_extras2_call(r)
	assert call is not None, r.out
	cmd = call["command"]
	# locate the literal `.../init.d/newton-wan-health" enable` and
	# `.../init.d/newton-wan-health" start` invocations; matching on the
	# full quoted path keeps the test robust against the unrelated
	# `start` / `enable` substrings that appear in this test's tmp-path
	# name (e.g. `.../runs_start_after_enable_0/...`).
	enable_match = re.search(
		r'init\.d/newton-wan-health"\s+enable\b', cmd)
	start_match = re.search(
		r'init\.d/newton-wan-health"\s+start\b', cmd)
	assert enable_match is not None, cmd
	assert start_match is not None, cmd
	assert start_match.start() > enable_match.end(), cmd
	# the fixture init's start branch records the call by touching a
	# marker under the router's tmp/, so we know start actually ran
	# (not just appeared in the command text).
	assert env.router.path(WANHEALTH_INIT_MARKER).exists(), (
		"install must run `start` after `enable` so procd registers "
		"the newton_wanhealth reload trigger")
	# the S95 symlink is still created by enable (the link is what an
	# upgrade / reboot path would walk)
	snap = env.router.snapshot()
	assert snap["etc/rc.d/S95newton-wan-health"]["link"] \
		== "../init.d/newton-wan-health"


def test_install_skips_start_when_enable_step_fails(setup_env):
	"""When the init's enable cannot complete, the follow-up start is
	guarded by `&&` so install never silently runs the daemon. The
	extras 2 call returns non-zero, install_restore runs, the run stops
	STOPPED, and the start marker never appears (the marker also proves
	start was not invoked when the init's enable was forced to fail)."""
	env = setup_env
	seed_known_hosts(env)
	env.router.update_state(
		fail_commands=["init.d/newton-wan-health\" enable"])
	r = run(env, "install")
	assert r.rc == 1
	lines = r.out.splitlines()
	assert "STOPPED install r1: install extras 2 failed" in lines
	assert "PASS install extras 2: wan-health config and init enabled" \
		not in lines
	assert not env.router.path(WANHEALTH_INIT_MARKER).exists(), (
		"start must not run when the enable step of install_wan_"
		"health_config failed")


# -- 10. extras DO appear in SYSUPGRADE_LINES (R9b+c: they survive
#      a sysupgrade like the rest) ---------------------------------------

def test_extras_in_sysupgrade_lines(setup_env):
	"""R9b+c: install puts the WAN-health script, its init and the
	 /etc/rc.d start symlink the init's `enable` creates into
	 /etc/sysupgrade.conf; a sysupgrade would otherwise lose them.
	 /etc/config is kept by sysupgrade by default and stays out of
	 the list."""
	env = setup_env
	install_ok(env)
	lines = env.router.read("etc/sysupgrade.conf").splitlines()
	assert "/usr/libexec/newton/newton-wan-health" in lines
	assert "/etc/init.d/newton-wan-health" in lines
	assert "/etc/rc.d/S95newton-wan-health" in lines


# -- 11. uninstall removes the new sysupgrade lines too -------------------

def test_uninstall_removes_wan_health_sysupgrade_lines(setup_env):
	"""R9b+c: uninstall removes every SYSUPGRADE_LINES entry from
	 /etc/sysupgrade.conf, including the three new WAN-health ones
	 (the script, its init and the rc.d start symlink); unrelated
	 user lines stay verbatim and in their original order."""
	env = setup_env
	install_ok(env)
	# install leaves a sysupgrade.conf with the eleven SYSUPGRADE_LINES
	# entries; we add an unrelated head and tail line so uninstall can
	# be seen keeping them in their original order.
	with open(env.router.path("etc/sysupgrade.conf"), "a") as fh:
		fh.write("## custom tail\n/etc/myfile\n")
	original = env.router.read("etc/sysupgrade.conf")
	assert "/etc/rc.d/S95newton-wan-health" in original.splitlines()
	assert "/usr/libexec/newton/newton-wan-health" in original.splitlines()
	assert "/etc/init.d/newton-wan-health" in original.splitlines()
	assert "## custom tail" in original.splitlines()
	r = run(env, "uninstall")
	assert r.rc == 0, r.out + r.err
	text = env.router.read("etc/sysupgrade.conf")
	# every WAN-health line is gone
	for path in (
		"/usr/libexec/newton/newton-wan-health",
		"/etc/init.d/newton-wan-health",
		"/etc/rc.d/S95newton-wan-health",
	):
		assert path not in text.splitlines(), (path, text)
	# the unrelated tail stays
	kept = [l for l in text.splitlines() if l.strip()]
	assert "## custom tail" in kept


# -- 12. first install failure still removes the extras -------------------

def test_install_first_failure_removes_wan_health_extras(setup_env):
	"""R9b+c: a first install (the router had no wan-health files
	 before) that fails AFTER extras 1 (e.g. extras 3 verify) still
	 removes both extras; only on UPGRADE (the file already existed)
	 does restore leave the OLD bytes."""
	env = setup_env
	seed_known_hosts(env)
	assert not env.router.path(WANHEALTH).exists()
	assert not env.router.path(WANHEALTH_INIT).exists()
	env.router.update_state(corrupt_after_call_n=[
		(23, str(env.router.path(WANHEALTH))),
		(23, str(env.router.path(WANHEALTH_INIT))),
	])
	r = run(env, "install")
	assert r.rc == 1
	snap = env.router.snapshot()
	assert WANHEALTH not in snap
	assert WANHEALTH_INIT not in snap


# -- 13. upgrade failure leaves the OLD wan-health content -----------------

def test_upgrade_failure_restores_old_wan_health_content(setup_env, tmp_path):
	"""R9b+c: an upgrade over an already-installed router where a later
	 step fails (here verify_hello) leaves the WAN-health script and
	 init with their OLD bytes -- the upgrade took a .prev and
	 install_restore copies it back. The user does not lose a working
	 wan-health installation because of an upgrade-time hiccup."""
	env = setup_env
	install_ok(env)
	old_script = env.router.read(WANHEALTH)
	old_init = env.router.read(WANHEALTH_INIT)
	assert old_script != ""
	assert old_init != ""
	# a v2 source tree so the upgrade writes new bytes for the extras
	src2 = build_src(tmp_path / "src2", version="2.0.0")
	for rel in (WANHEALTH_SRC, WANHEALTH_INIT_SRC):
		with (src2 / rel).open("a") as fh:
			fh.write("# v2\n")
	# fail verify_hello (it calls newton-router hello NONCE)
	env.router.update_state(fail_commands=["hello"])
	r = run(env, "upgrade", src=src2)
	assert r.rc == 1, r.out + r.err
	assert any("STOPPED upgrade r1" in l for l in r.out.splitlines())
	# the extras hold their OLD bytes, not the v2 src2 bytes
	assert env.router.read(WANHEALTH) == old_script
	assert env.router.read(WANHEALTH_INIT) == old_init
	# the .prev files were created by the upgrade upload
	assert env.router.path(WANHEALTH + ".prev").read_text() == old_script
	assert env.router.path(WANHEALTH_INIT + ".prev").read_text() == old_init


def test_upgrade_replaces_wan_health_extras_with_prev(setup_env, tmp_path):
	"""R9b+c: upgrade uploads the new wan-health bytes and creates a
	 .prev holding the OLD bytes (rotate yes for the extras; the same
	 mechanism the other code files use). The no-rotation behaviour
	 belongs only to the first-install path."""
	env = setup_env
	install_ok(env)
	old_script = env.router.read(WANHEALTH)
	src2 = build_src(tmp_path / "src2", version="2.0.0")
	with (src2 / WANHEALTH_SRC).open("a") as fh:
		fh.write("# v2 script\n")
	with (src2 / WANHEALTH_INIT_SRC).open("a") as fh:
		fh.write("# v2 init\n")
	r = run(env, "upgrade", src=src2)
	assert r.rc == 0, r.out + r.err
	lines = r.out.splitlines()
	assert "PASS upgrade extras 1: wan-health code files uploaded" in lines
	assert "PASS upgrade extras 2: wan-health sha256 verified" in lines
	assert env.router.read(WANHEALTH) == (src2 / WANHEALTH_SRC).read_text()
	assert env.router.read(WANHEALTH_INIT) == (
		src2 / WANHEALTH_INIT_SRC).read_text()
	# rotate=yes for the extras: a .prev holds the OLD bytes
	assert env.router.path(WANHEALTH + ".prev").exists()
	assert env.router.read(WANHEALTH + ".prev") == old_script
	assert env.router.path(WANHEALTH_INIT + ".prev").exists()


# -- 14. first-install restore must stop/disable first -------

def test_install_first_failure_stops_disables_then_removes_wan_health(
		setup_env):
	"""A first install that reaches extras 2 has enabled and started the
	init; when a later step fails, restore must stop and disable it before
	removing the files, leaving neither a running daemon nor an S95 link."""
	env = setup_env
	seed_known_hosts(env)
	env.router.update_state(corrupt_after_call_n=[
		(23, str(env.router.path(WANHEALTH))),
		(23, str(env.router.path(WANHEALTH_INIT))),
	])
	r = run(env, "install")
	assert r.rc == 1, r.out + r.err
	assert env.router.path(WANHEALTH_START_MARKER).exists()
	assert env.router.path(WANHEALTH_STOP_MARKER).exists()
	stop = _calls_with(r, "init.d/newton-wan-health' stop")
	disable = _calls_with(r, "init.d/newton-wan-health' disable")
	remove = [call for call in _calls_with(r, "rm -f")
	          if WANHEALTH in (call.get("command") or "")
	          and WANHEALTH_INIT in (call.get("command") or "")]
	assert len(stop) == 1, r.calls
	assert len(disable) == 1, r.calls
	assert len(remove) == 1, r.calls
	assert stop[0]["n"] < disable[0]["n"] < remove[0]["n"]
	snap = env.router.snapshot()
	assert WANHEALTH not in snap
	assert WANHEALTH_INIT not in snap
	assert "etc/rc.d/S95newton-wan-health" not in snap


@pytest.mark.parametrize("failed_step", ["stop", "disable", "removal"])
def test_install_restore_failure_note_keeps_no_prev(
		setup_env, failed_step):
	"""A failed stop, disable or wan-health file removal during
	first-install restore keeps the no-.prev information and names the
	failed step plus both files that remain."""
	env = setup_env
	rm_wan = (
		f'rm -f "{env.router.path(WANHEALTH)}" '
		f'"{env.router.path(WANHEALTH_INIT)}"')
	failures = {
		"stop": "init.d/newton-wan-health' stop",
		"disable": "init.d/newton-wan-health' disable",
		"removal": rm_wan,
	}
	expected = {
		"stop": "wan-health stop failed; files remain: ",
		"disable": "wan-health disable failed; files remain: ",
		"removal": "wan-health file removal failed; files remain: ",
	}
	seed_known_hosts(env)
	env.router.update_state(
		corrupt_after_call_n=[
			(23, str(env.router.path(WANHEALTH))),
			(23, str(env.router.path(WANHEALTH_INIT))),
		],
		fail_commands=[failures[failed_step]],
	)
	r = run(env, "install")
	assert r.rc == 1, r.out + r.err
	lines = r.out.splitlines()
	note = next(line for line in lines if line.startswith("NOTE state: "))
	assert "no .prev existed (first install)" in note
	assert "hello: " in note
	assert expected[failed_step] in note
	assert f"/{WANHEALTH}" in note
	assert f"/{WANHEALTH_INIT}" in note
	assert "STOPPED install r1: install extras 3 failed" in lines
	assert env.router.path(WANHEALTH).exists()
	assert env.router.path(WANHEALTH_INIT).exists()
	if failed_step == "stop":
		# a failed stop aborts before disable; the start link stays.
		assert _calls_with(r, "init.d/newton-wan-health' disable") == []
		assert "etc/rc.d/S95newton-wan-health" in env.router.snapshot()


@pytest.mark.parametrize("failed_step", ["stop", "disable", "removal"])
def test_install_restore_failure_note_keeps_restored_paths(
		setup_env, tmp_path, failed_step):
	"""Review finding 7: when core tools are restored from .prev but a
	first-install wan-health stop, disable or file removal fails, one state
	note reports both facts and names both files that remain."""
	env = setup_env
	seed_known_hosts(env)
	install_ok(env)
	for path in (
		WANHEALTH,
		WANHEALTH_INIT,
		"etc/rc.d/S95newton-wan-health",
	):
		env.router.path(path).unlink()
	src2 = build_src(tmp_path / "src2", version="2.0.0")
	verify_wan = (
		f'{env.router.path(WANHEALTH)}" "{env.router.path(WANHEALTH_INIT)}')
	rm_wan = (
		f'rm -f "{env.router.path(WANHEALTH)}" '
		f'"{env.router.path(WANHEALTH_INIT)}"')
	failures = {
		"stop": "init.d/newton-wan-health' stop",
		"disable": "init.d/newton-wan-health' disable",
		"removal": rm_wan,
	}
	expected = {
		"stop": "wan-health stop failed; files remain: ",
		"disable": "wan-health disable failed; files remain: ",
		"removal": "wan-health file removal failed; files remain: ",
	}
	env.router.update_state(
		fail_commands=[verify_wan, failures[failed_step]])
	r = run(env, "install", src=src2)
	assert r.rc == 1, r.out + r.err
	lines = r.out.splitlines()
	note = next(line for line in lines if line.startswith("NOTE state: "))
	assert "restored from .prev:" in note
	assert "hello after restore: " in note
	assert expected[failed_step] in note
	assert f"/{WANHEALTH}" in note
	assert f"/{WANHEALTH_INIT}" in note
	assert "STOPPED install r1: install extras 3 failed" in lines
	assert env.router.read("usr/libexec/newton/newton-router") == (
		env.src / "device/openwrt/newton-router/newton-router").read_text()
	assert env.router.path(WANHEALTH).exists()
	assert env.router.path(WANHEALTH_INIT).exists()


def test_install_restore_stop_failure_with_only_wan_health_extras(
		setup_env):
	"""When only the wan-health extras were new, a failed stop keeps the
	files and reports them; it must not claim that the guarded removal
	branch removed the extras."""
	env = setup_env
	install_ok(env)
	for path in (
		WANHEALTH,
		WANHEALTH_INIT,
		"etc/rc.d/S95newton-wan-health",
	):
		env.router.path(path).unlink()
	verify_wan = (
		f'{env.router.path(WANHEALTH)}" "{env.router.path(WANHEALTH_INIT)}')
	env.router.update_state(
		fail_commands=[verify_wan, "init.d/newton-wan-health' stop"])
	r = run(env, "install")
	assert r.rc == 1, r.out + r.err
	note = next(line for line in r.out.splitlines()
	            if line.startswith("NOTE state: "))
	assert "removed the wan-health extras" not in note
	assert "restored from .prev:" not in note
	assert "no .prev existed" not in note
	assert "wan-health stop failed; files remain: " in note
	assert f"/{WANHEALTH}" in note
	assert f"/{WANHEALTH_INIT}" in note
	assert env.router.path(WANHEALTH).exists()
	assert env.router.path(WANHEALTH_INIT).exists()


# -- 15. upgrade restarts only an enabled daemon -------------

def test_upgrade_unchanged_enabled_wan_health_is_not_restarted(setup_env):
	"""Review finding 1: two upgrades from the same sources write nothing
	the second time; restarting the enabled daemon would run its restore
	path and could re-promote a link the daemon had marked dead, so the
	second run must not invoke restart."""
	env = setup_env
	install_ok(env)
	assert run(env, "upgrade").rc == 0
	marker = env.router.path(WANHEALTH_RESTART_MARKER)
	if marker.exists():
		marker.unlink()
	r = run(env, "upgrade")
	assert r.rc == 0, r.out + r.err
	assert _calls_with(r, "init.d/newton-wan-health' restart") == []
	assert not marker.exists()
	assert not _restart_pending_marker(env).exists()
	assert "INFO wan-health files are unchanged; daemon not restarted" \
		in r.out.splitlines()


def test_upgrade_restarts_enabled_wan_health_when_script_changes(
		setup_env, tmp_path):
	"""A changed wan-health script alone is enough to restart the enabled
	daemon after verification (the init need not also have changed)."""
	env = setup_env
	install_ok(env)
	src2 = build_src(tmp_path / "src2")
	with (src2 / WANHEALTH_SRC).open("a") as fh:
		fh.write("# changed script\n")
	r = run(env, "upgrade", src=src2)
	assert r.rc == 0, r.out + r.err
	assert len(_calls_with(r, "init.d/newton-wan-health' restart")) == 1
	assert env.router.path(WANHEALTH_RESTART_MARKER).exists()
	assert "PASS upgrade wan-health: enabled daemon restarted" \
		in r.out.splitlines()


def test_upgrade_restarts_enabled_wan_health_after_verification(
		setup_env, tmp_path):
	"""When the S95 link says the daemon is enabled, upgrade restarts it
	once only after the new files and the hello verification succeeded."""
	env = setup_env
	install_ok(env)
	src2 = build_src(tmp_path / "src2", version="2.0.0")
	for rel in (WANHEALTH_SRC, WANHEALTH_INIT_SRC):
		with (src2 / rel).open("a") as fh:
			fh.write("# v2\n")
	r = run(env, "upgrade", src=src2)
	assert r.rc == 0, r.out + r.err
	restart = _calls_with(r, "init.d/newton-wan-health' restart")
	assert len(restart) == 1, r.calls
	verify = _calls_with(r, "sha256sum")
	hello = _calls_with(r, 'newton-router" hello')
	assert verify and hello
	assert restart[0]["n"] > max(call["n"] for call in verify)
	assert restart[0]["n"] > max(call["n"] for call in hello)
	assert env.router.path(WANHEALTH_RESTART_MARKER).exists()
	assert "PASS upgrade wan-health: enabled daemon restarted" \
		in r.out.splitlines()


def test_upgrade_does_not_restart_disabled_wan_health(setup_env, tmp_path):
	"""Without the S95 link upgrade leaves the daemon unstarted and says
	so; it never invokes restart for a service the operator disabled."""
	env = setup_env
	install_ok(env)
	env.router.path("etc/rc.d/S95newton-wan-health").unlink()
	src2 = build_src(tmp_path / "src2", version="2.0.0")
	for rel in (WANHEALTH_SRC, WANHEALTH_INIT_SRC):
		with (src2 / rel).open("a") as fh:
			fh.write("# v2\n")
	r = run(env, "upgrade", src=src2)
	assert r.rc == 0, r.out + r.err
	assert _calls_with(r, "init.d/newton-wan-health' restart") == []
	assert not env.router.path(WANHEALTH_RESTART_MARKER).exists()
	assert not _restart_pending_marker(env).exists()
	assert "INFO wan-health init not enabled; daemon not restarted" \
		in r.out.splitlines()


def test_upgrade_restart_failure_keeps_new_files_and_stops(
		setup_env, tmp_path):
	"""A failed restart makes upgrade exit non-zero with a FAIL/stopped
	pair; the already-verified new files and their .prev backups remain."""
	env = setup_env
	install_ok(env)
	src2 = build_src(tmp_path / "src2", version="2.0.0")
	for rel in (WANHEALTH_SRC, WANHEALTH_INIT_SRC):
		with (src2 / rel).open("a") as fh:
			fh.write("# v2\n")
	env.router.update_state(
		fail_commands=["init.d/newton-wan-health' restart"])
	r = run(env, "upgrade", src=src2)
	assert r.rc == 1, r.out + r.err
	lines = r.out.splitlines()
	assert "FAIL upgrade wan-health restart: enabled daemon restart failed" \
		in lines
	note = next(line for line in lines if line.startswith("NOTE state: "))
	assert note.startswith(
		"NOTE state: the wan-health files are already upgraded; "
		"the daemon was not restarted")
	assert "rerunning upgrade will retry the restart" in note
	assert "/etc/init.d/newton-wan-health restart" in note
	assert "a manual restart does not clear the marker; " \
		"the next upgrade restarts the daemon once more (harmless)" in note
	assert "STOPPED upgrade r1: upgrade wan-health restart failed" in lines
	assert env.router.read(WANHEALTH) == (
		src2 / WANHEALTH_SRC).read_text()
	assert env.router.read(WANHEALTH_INIT) == (
		src2 / WANHEALTH_INIT_SRC).read_text()
	assert env.router.path(WANHEALTH + ".prev").exists()
	assert env.router.path(WANHEALTH_INIT + ".prev").exists()


def test_upgrade_restarts_wan_health_before_a_failed_sysupgrade_step(
		setup_env, tmp_path):
	"""The sysupgrade step runs after the WAN-health
	restart, so a failed sysupgrade write cannot leave an enabled daemon
	on old code with no pending marker for the rerun to find."""
	env = setup_env
	install_ok(env)
	src2 = build_src(tmp_path / "src2")
	with (src2 / WANHEALTH_SRC).open("a") as fh:
		fh.write("# changed script\n")
	env.router.update_state(fail_commands=["etc/sysupgrade.conf\""])
	r = run(env, "upgrade", src=src2)
	assert r.rc == 1, r.out + r.err
	lines = r.out.splitlines()
	assert len(_calls_with(r, "init.d/newton-wan-health' restart")) == 1
	assert "PASS upgrade wan-health: enabled daemon restarted" in lines
	assert not _restart_pending_marker(env).exists()
	assert "STOPPED upgrade r1: upgrade extras 3 failed" in lines


def test_upgrade_pending_restart_marker_survives_failed_restart(
		setup_env, tmp_path):
	"""A failed restart leaves a host-side, per-device marker so a later
	no-file-change upgrade retries the restart instead of reporting a clean
	no-op while the daemon still runs old code."""
	env = setup_env
	install_ok(env)
	src2 = build_src(tmp_path / "src2", version="2.0.0")
	for rel in (WANHEALTH_SRC, WANHEALTH_INIT_SRC):
		with (src2 / rel).open("a") as fh:
			fh.write("# v2\n")
	env.router.update_state(
		fail_commands=["init.d/newton-wan-health' restart"])
	first = run(env, "upgrade", src=src2)
	assert first.rc == 1, first.out + first.err
	marker = _restart_pending_marker(env)
	assert marker.exists()
	assert (marker.parent.stat().st_mode & 0o777) == 0o700
	env.router.update_state(fail_commands=[])
	second = run(env, "upgrade", src=src2)
	assert second.rc == 0, second.out + second.err
	assert len(_calls_with(
		second, "init.d/newton-wan-health' restart")) == 1
	assert "INFO wan-health restart pending from an earlier upgrade" \
		in second.out.splitlines()
	assert "PASS upgrade wan-health: enabled daemon restarted" \
		in second.out.splitlines()
	assert not marker.exists()


def test_upgrade_pending_restart_failure_names_manual_remedy(
		setup_env, tmp_path):
	"""A retry that still fails says that upgrade will retry again and
	gives the router-side restart command (or a reboot) as the manual fix."""
	env = setup_env
	install_ok(env)
	src2 = build_src(tmp_path / "src2", version="2.0.0")
	for rel in (WANHEALTH_SRC, WANHEALTH_INIT_SRC):
		with (src2 / rel).open("a") as fh:
			fh.write("# v2\n")
	env.router.update_state(
		fail_commands=["init.d/newton-wan-health' restart"])
	assert run(env, "upgrade", src=src2).rc == 1
	r = run(env, "upgrade", src=src2)
	assert r.rc != 0, r.out + r.err
	note = next(line for line in r.out.splitlines()
	            if line.startswith("NOTE state: "))
	assert "rerunning upgrade will retry the restart" in note
	assert "/etc/init.d/newton-wan-health restart" in note
	assert "reboot" in note
	assert _restart_pending_marker(env).exists()


def test_upgrade_unknown_enabled_state_keeps_pending_marker(
		setup_env, tmp_path):
	"""When upgrade cannot tell whether the enabled daemon needs a restart,
	it leaves the pending marker and tells the operator both retry paths."""
	env = setup_env
	install_ok(env)
	src2 = build_src(tmp_path / "src2", version="2.0.0")
	for rel in (WANHEALTH_SRC, WANHEALTH_INIT_SRC):
		with (src2 / rel).open("a") as fh:
			fh.write("# v2\n")
	enabled_check = (
		f"[ -e '{env.router.path('etc/rc.d/S95newton-wan-health')}' ]")
	env.router.update_state(drop_commands=[enabled_check])
	r = run(env, "upgrade", src=src2)
	assert r.rc == 1, r.out + r.err
	note = next(line for line in r.out.splitlines()
	            if line.startswith("NOTE state: "))
	assert "the daemon enabled state is unknown" in note
	assert "rerunning upgrade will retry the restart" in note
	assert "/etc/init.d/newton-wan-health restart" in note
	assert "a manual restart does not clear the marker; " \
		"the next upgrade restarts the daemon once more (harmless)" in note
	assert "reboot" in note
	assert _restart_pending_marker(env).exists()
	assert _calls_with(r, "init.d/newton-wan-health' restart") == []


def test_upgrade_pending_restart_marker_is_per_device(setup_env):
	"""A restart pending for another inventory device does not make this
	device's unchanged upgrade restart its daemon."""
	env = setup_env
	install_ok(env)
	other = _restart_pending_marker(env, device="other-device")
	other.parent.mkdir(mode=0o700)
	other.write_text("pending\n")
	r = run(env, "upgrade")
	assert r.rc == 0, r.out + r.err
	assert _calls_with(r, "init.d/newton-wan-health' restart") == []
	assert "INFO wan-health restart pending from an earlier upgrade" \
		not in r.out.splitlines()
	assert other.exists()
	assert not _restart_pending_marker(env).exists()


def test_upgrade_stops_when_pending_restart_marker_cannot_be_written(
		setup_env, tmp_path):
	"""Upgrade refuses to restart-or-forget the activation gap when it
	cannot first record the host-side pending-restart marker."""
	env = setup_env
	install_ok(env)
	src2 = build_src(tmp_path / "src2", version="2.0.0")
	for rel in (WANHEALTH_SRC, WANHEALTH_INIT_SRC):
		with (src2 / rel).open("a") as fh:
			fh.write("# v2\n")
	env.state_dir.joinpath(WANHEALTH_RESTART_PENDING_DIR).write_text("")
	r = run(env, "upgrade", src=src2)
	assert r.rc == 1, r.out + r.err
	lines = r.out.splitlines()
	assert "FAIL upgrade wan-health restart: cannot record pending restart" \
		in lines
	assert "STOPPED upgrade r1: upgrade wan-health restart marker failed" \
		in lines
	enabled_check = (
		f"[ -e '{env.router.path('etc/rc.d/S95newton-wan-health')}' ]")
	assert _calls_with(r, enabled_check) == []
	assert _calls_with(r, "init.d/newton-wan-health' restart") == []
	assert not env.router.path(WANHEALTH_RESTART_MARKER).exists()


def test_upgrade_refuses_pending_marker_under_group_writable_state_dir(
		setup_env, tmp_path):
	"""SW2 item 4: the host-side pending-restart marker is not written when
	the state dir (its PARENT) is group- or world-writable without the
	sticky bit.  Upgrade stops on the same "cannot record pending restart"
	refusal a marker it cannot create gets."""
	env = setup_env
	install_ok(env)
	src2 = build_src(tmp_path / "src2", version="2.0.0")
	for rel in (WANHEALTH_SRC, WANHEALTH_INIT_SRC):
		with (src2 / rel).open("a") as fh:
			fh.write("# v2\n")
	os.chmod(env.state_dir, 0o777)
	try:
		r = run(env, "upgrade", src=src2)
	finally:
		os.chmod(env.state_dir, 0o700)
	assert r.rc == 1, r.out + r.err
	lines = r.out.splitlines()
	assert "FAIL upgrade wan-health restart: cannot record pending restart" \
		in lines
	assert "STOPPED upgrade r1: upgrade wan-health restart marker failed" \
		in lines
	assert "group- or world-writable without the sticky bit" in r.err
	assert not (env.state_dir / WANHEALTH_RESTART_PENDING_DIR).exists()
	assert not env.router.path(WANHEALTH_RESTART_MARKER).exists()


# -- 16. explicit rollback covers the wan-health files -------

def test_rollback_restores_wan_health_prev_and_restarts_enabled_init(
		setup_env, tmp_path):
	"""Rollback restores both old wan-health bytes exactly like the two
	core tools, and restarts the enabled daemon after either changes."""
	env = setup_env
	install_ok(env)
	old_script = env.router.read(WANHEALTH)
	old_init = env.router.read(WANHEALTH_INIT)
	src2 = build_src(tmp_path / "src2", version="2.0.0")
	for rel in (WANHEALTH_SRC, WANHEALTH_INIT_SRC):
		with (src2 / rel).open("a") as fh:
			fh.write("# v2\n")
	run(env, "upgrade", src=src2)
	marker = env.router.path(WANHEALTH_RESTART_MARKER)
	if marker.exists():
		marker.unlink()
	r = run(env, "rollback")
	assert r.rc == 0, r.out + r.err
	assert env.router.read(WANHEALTH) == old_script
	assert env.router.read(WANHEALTH_INIT) == old_init
	assert len(_calls_with(r, "init.d/newton-wan-health' restart")) == 1
	assert env.router.path(WANHEALTH_RESTART_MARKER).exists()


def test_rollback_without_wan_health_prev_reports_info_and_passes(
		setup_env, tmp_path):
	"""Missing wan-health .prev files are informational (like the core
	files); rollback still succeeds and does not restart the daemon."""
	env = setup_env
	install_ok(env)
	src2 = build_src(tmp_path / "src2", version="2.0.0")
	for rel in (WANHEALTH_SRC, WANHEALTH_INIT_SRC):
		with (src2 / rel).open("a") as fh:
			fh.write("# v2\n")
	run(env, "upgrade", src=src2)
	env.router.path(WANHEALTH + ".prev").unlink()
	env.router.path(WANHEALTH_INIT + ".prev").unlink()
	marker = env.router.path(WANHEALTH_RESTART_MARKER)
	if marker.exists():
		marker.unlink()
	r = run(env, "rollback")
	assert r.rc == 0, r.out + r.err
	lines = r.out.splitlines()
	assert "INFO newton-wan-health has no .prev" in lines
	assert "INFO newton-wan-health.init has no .prev" in lines
	assert "DONE rollback r1" in lines
	assert _calls_with(r, "init.d/newton-wan-health' restart") == []
	assert not env.router.path(WANHEALTH_RESTART_MARKER).exists()


def test_rollback_clears_restart_pending_marker(setup_env, tmp_path):
	"""Rollback restores the previous wan-health files, so the pending
	restart for the upgraded files no longer applies."""
	env = setup_env
	install_ok(env)
	_failed_restart_upgrade(env, tmp_path)
	marker = _restart_pending_marker(env)
	other = _seed_restart_pending(env, "other-device")
	assert marker.exists()
	r = run(env, "rollback")
	assert r.rc == 0, r.out + r.err
	assert not marker.exists()
	assert other.exists()


def test_rollback_restart_marker_clear_failure_does_not_undo_rollback(
		setup_env, tmp_path):
	"""A failed host-side marker cleanup is visible as a FAIL line but
	cannot undo the completed router-side rollback."""
	env = setup_env
	install_ok(env)
	_failed_restart_upgrade(env, tmp_path)
	marker = _restart_pending_marker(env)
	marker.unlink()
	marker.mkdir()
	(marker / "child").write_text("blocked\n")
	r = run(env, "rollback")
	assert r.rc == 0, r.out + r.err
	lines = r.out.splitlines()
	assert f"FAIL rollback wan-health restart marker: " \
		f"cannot clear {marker}" in lines
	assert "DONE rollback r1" in lines
	assert marker.is_dir()


def test_uninstall_removes_wan_health_prev_files(setup_env, tmp_path):
	"""Uninstall removes the two upgrade .prev files together with the
	live wan-health files."""
	env = setup_env
	install_ok(env)
	src2 = build_src(tmp_path / "src2", version="2.0.0")
	for rel in (WANHEALTH_SRC, WANHEALTH_INIT_SRC):
		with (src2 / rel).open("a") as fh:
			fh.write("# v2\n")
	run(env, "upgrade", src=src2)
	assert env.router.path(WANHEALTH + ".prev").exists()
	assert env.router.path(WANHEALTH_INIT + ".prev").exists()
	r = run(env, "uninstall")
	assert r.rc == 0, r.out + r.err
	assert not env.router.path(WANHEALTH + ".prev").exists()
	assert not env.router.path(WANHEALTH_INIT + ".prev").exists()


def test_uninstall_clears_only_this_devices_restart_pending_marker(
		setup_env, tmp_path):
	"""Uninstall removes the daemon and its files, so no restart for those
	files remains pending; another device's marker is untouched."""
	env = setup_env
	install_ok(env)
	_failed_restart_upgrade(env, tmp_path)
	marker = _restart_pending_marker(env)
	other = _seed_restart_pending(env, "other-device")
	assert marker.exists()
	r = run(env, "uninstall")
	assert r.rc == 0, r.out + r.err
	assert not marker.exists()
	assert other.exists()
	assert not env.router.path(WANHEALTH).exists()
	assert not env.router.path(WANHEALTH_INIT).exists()


def test_uninstall_restart_marker_clear_failure_does_not_undo_uninstall(
		setup_env):
	"""A failed host-side marker cleanup is visible as a FAIL line but the
	router-side removal still finishes."""
	env = setup_env
	install_ok(env)
	marker = _restart_pending_marker(env)
	marker.parent.mkdir(mode=0o700)
	marker.mkdir()
	(marker / "child").write_text("blocked\n")
	r = run(env, "uninstall")
	assert r.rc == 0, r.out + r.err
	lines = r.out.splitlines()
	assert f"FAIL uninstall wan-health restart marker: " \
		f"cannot clear {marker}" in lines
	assert "DONE uninstall r1" in lines
	assert not env.router.path(WANHEALTH).exists()
	assert not env.router.path(WANHEALTH_INIT).exists()
	assert marker.is_dir()


# -- 17. a failed stop is never masked -----------------------

def test_uninstall_stop_failure_removes_nothing_and_skips_disable(setup_env):
	"""Uninstall treats a failed wan-health stop as fatal before disable
	or removal, with a state note that says nothing was removed."""
	env = setup_env
	install_ok(env)
	env.router.update_state(
		fail_commands=["init.d/newton-wan-health' stop"])
	r = run(env, "uninstall")
	assert r.rc == 1, r.out + r.err
	lines = r.out.splitlines()
	assert "NOTE state: wan-health stop failed; no code files removed; run uninstall again" in lines
	assert "STOPPED uninstall r1: uninstall step 2a failed" in lines
	assert _calls_with(r, "init.d/newton-wan-health' disable") == []
	assert env.router.path(WANHEALTH).exists()
	assert env.router.path(WANHEALTH_INIT).exists()
	assert "etc/rc.d/S95newton-wan-health" in env.router.snapshot()


def test_uninstall_disable_failure_stops_before_removal(setup_env):
	"""Review finding 7 coverage: when stop succeeds but disable fails,
	uninstall stops at step 2a and leaves both wan-health files in place."""
	env = setup_env
	install_ok(env)
	env.router.update_state(
		fail_commands=["init.d/newton-wan-health' disable"])
	r = run(env, "uninstall")
	assert r.rc == 1, r.out + r.err
	lines = r.out.splitlines()
	assert "NOTE state: wan-health disable failed; no code files removed; " \
		"run uninstall again" in lines
	assert "STOPPED uninstall r1: uninstall step 2a failed" in lines
	assert env.router.path(WANHEALTH).exists()
	assert env.router.path(WANHEALTH_INIT).exists()
	assert "etc/rc.d/S95newton-wan-health" in env.router.snapshot()
