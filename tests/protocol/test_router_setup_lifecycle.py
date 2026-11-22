"""Tests of the profile and upgrade actions of scripts/newton-router-setup:
the profile action (the refusal of a profile that differs from the
inventory, the set/already wording, lab round-trip and the dev rejection) and the
upgrade action happy path (the .prev rotation, the four step PASS lines,
the INFO skip and the PASS upgrade: prog line), idempotence, refusal
paths (pending guard, live helper lock, the failed and restored guards
that do not block), the broken-program restore, the repair of a broken
first install, the restricted-key check when the inventory has key_file,
and the leak scan over an install+upgrade pair."""

import hashlib
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from router_setup_env import setup_env, build_src  # noqa: E402
from test_router_setup_install import (  # noqa: E402
	install_ok, seed_known_hosts, GOOD_PW, no_dot_files, SYSUPGRADE_LINES,
)

PROG_REL = "device/openwrt/newton-router/newton-router"
HELPER_REL = "scripts/owrt-safe-apply.sh"
GUARD_REL = "device/openwrt/newton-guard/newton-guard"
INIT_REL = "device/openwrt/newton-guard/newton-guard.init"

PROG = "usr/libexec/newton/newton-router"
HELPER = "usr/libexec/newton/newton-safe-apply"
GUARD = "usr/libexec/newton-guard"
INIT = "etc/init.d/newton-guard"


def run(env, *args, src=None):
	"""Typed-password run; src, when given, overrides NEWTON_SETUP_SRC.
	The install also asks for the "yes", so the feed carries it."""
	extra = {"NEWTON_SETUP_SRC": str(src)} if src else None
	typed = (GOOD_PW,)
	if args and args[0] == "install":
		typed = typed + ("yes",)
	return env.run("r1", *args, typed=typed, env=extra)


def src2(tmp):
	"""build_src version 2.0.0 with # v2 appended to helper/guard/init
	(build_src only marks the program)."""
	dest = build_src(tmp / "src2", version="2.0.0")
	for rel in (HELPER_REL, GUARD_REL, INIT_REL):
		with (dest / rel).open("a") as fh:
			fh.write("# v2\n")
	return dest


def file_mode(path):
	return "0o%o" % stat.S_IMODE(os.stat(path).st_mode)


# -- 1. profile action ---------------------------------------------------

def _set_inventory_profile(env, value):
	"""Edit the inventory's profile, as the owner does in devices.toml."""
	text = env.inventory.read_text()
	old = 'profile = "%s"' % env.profile
	assert old in text
	env.inventory.write_text(text.replace(old, 'profile = "%s"' % value))
	env.inventory.chmod(0o644)
	env.profile = value


def test_profile_differing_from_the_inventory_is_refused(setup_env):
	"""Profile prod on a lab inventory is refused before any
	router contact (the controller refuses a router whose profile
	differs from the inventory), and the refusal names the inventory
	field to change first; the router keeps its profile."""
	env = setup_env
	install_ok(env)
	before = env.router.snapshot()
	r = run(env, "profile", "prod")
	assert r.rc == 1, r.out + r.err
	assert r.out.splitlines()[-1] == (
		"STOPPED profile r1: the inventory says lab for r1; set "
		'profile = "prod" in %s (owned by the newton account; edit it '
		'with sudo -u newton) first, then run profile prod again'
		% env.inventory)
	assert r.calls == []
	assert env.router.snapshot() == before
	assert env.router.read("etc/newton/profile") == "lab\n"


def test_profile_action_lab_round_trip_and_dev_rejected(setup_env):
	"""With the inventory changed first, profile prod prints PASS
	profile set to prod and DONE; a second profile prod is PASS profile
	already prod and the router snapshot is unchanged (no .new/.prev);
	back to lab with no NOTE; profile dev exits 2."""
	env = setup_env
	install_ok(env)
	_set_inventory_profile(env, "prod")
	r = run(env, "profile", "prod")
	assert r.rc == 0, r.out + r.err
	assert env.router.read("etc/newton/profile") == "prod\n"
	assert env.router.snapshot()["etc/newton/profile"]["mode"] == "0o600"
	lines = r.out.splitlines()
	assert [l for l in lines if l.startswith("NOTE ")] == []
	assert "PASS profile set to prod" in lines
	assert lines[-1] == "DONE profile r1"
	snap1 = env.router.snapshot()
	r2 = run(env, "profile", "prod")
	assert r2.rc == 0
	lines2 = r2.out.splitlines()
	assert "PASS profile already prod" in lines2
	assert "PASS profile set to prod" not in lines2
	assert lines2[-1] == "DONE profile r1"
	assert env.router.snapshot() == snap1
	assert no_dot_files(env.router.snapshot()) == []
	_set_inventory_profile(env, "lab")
	r3 = run(env, "profile", "lab")
	assert r3.rc == 0
	assert env.router.read("etc/newton/profile") == "lab\n"
	lines3 = r3.out.splitlines()
	assert [l for l in lines3 if l.startswith("NOTE ")] == []
	assert "PASS profile set to lab" in lines3
	assert lines3[-1] == "DONE profile r1"
	r4 = run(env, "profile", "dev")
	assert r4.rc == 2


# -- 2. upgrade happy path -----------------------------------------------

def test_upgrade_happy_path(setup_env, tmp_path):
	"""Upgrade to src2: program and helper replaced with .prev holding
	the OLD bytes at mode 0o644, guard and init replaced (no .prev),
	INFO restricted-key check skipped, PASS upgrade: prog=<first 12
	hex of src2 program sha256>, DONE."""
	env = setup_env
	install_ok(env)
	src2_path = src2(tmp_path)
	src2_prog = (src2_path / PROG_REL).read_text()
	src2_helper = (src2_path / HELPER_REL).read_text()
	src2_guard = (src2_path / GUARD_REL).read_text()
	src2_init = (src2_path / INIT_REL).read_text()
	v1_prog = (env.src / PROG_REL).read_text()
	v1_helper = (env.src / HELPER_REL).read_text()
	r = run(env, "upgrade", src=src2_path)
	assert r.rc == 0, r.err
	lines = r.out.splitlines()
	assert lines[-1] == "DONE upgrade r1"
	assert env.router.read(PROG) == src2_prog
	assert env.router.read(HELPER) == src2_helper
	assert env.router.read(PROG + ".prev") == v1_prog
	assert file_mode(env.router.path(PROG + ".prev")) == "0o644"
	assert env.router.read(HELPER + ".prev") == v1_helper
	assert file_mode(env.router.path(HELPER + ".prev")) == "0o644"
	assert env.router.read(GUARD) == src2_guard
	assert env.router.read(INIT) == src2_init
	assert not env.router.path(GUARD + ".prev").exists()
	assert not env.router.path(INIT + ".prev").exists()
	assert "INFO restricted-key check skipped: no key_file in the inventory" in lines
	expected = ("PASS upgrade: prog="
	            + hashlib.sha256(src2_prog.encode("utf-8")).hexdigest()[:12])
	assert expected in [l for l in lines if l.startswith("PASS ")]


# -- 3. second upgrade same tree is idempotent ----------------------------

def test_upgrade_second_run_is_idempotent(setup_env, tmp_path):
	"""A second upgrade with the same src2 tree changes nothing."""
	env = setup_env
	install_ok(env)
	src2_path = src2(tmp_path)
	run(env, "upgrade", src=src2_path)
	after_first = env.router.snapshot()
	r2 = run(env, "upgrade", src=src2_path)
	assert r2.rc == 0
	assert env.router.snapshot() == after_first
	for rel in (PROG, HELPER, GUARD, INIT):
		assert not env.router.path(rel + ".new").exists()


# -- 3b. upgrade adds the sysupgrade lines an older install lacks ---------

def test_upgrade_adds_the_missing_sysupgrade_lines_once(setup_env, tmp_path):
	"""A router installed before the approval key and the
	wan-health stop link were in SYSUPGRADE_LINES has only the old eleven
	lines; upgrade appends the two missing ones after the owner's own
	lines, and a second upgrade adds nothing."""
	env = setup_env
	install_ok(env)
	new = ["/etc/rc.d/K10newton-wan-health", "/etc/newton/approve.key"]
	old = [l for l in SYSUPGRADE_LINES if l not in new]
	env.router.write("etc/sysupgrade.conf",
	                 "## mine\n" + "\n".join(old) + "\n")
	src2_path = src2(tmp_path)
	r = run(env, "upgrade", src=src2_path)
	assert r.rc == 0, r.out + r.err
	assert env.router.read("etc/sysupgrade.conf").splitlines() \
		== ["## mine"] + old + new
	after_first = env.router.snapshot()
	r2 = run(env, "upgrade", src=src2_path)
	assert r2.rc == 0, r2.out + r2.err
	assert env.router.snapshot() == after_first


# -- 4. refusals (and the guards that do NOT block) -----------------------

def test_upgrade_pending_guard_refuses(setup_env, tmp_path):
	"""A pending guard: WARN upgrade refused, NOTE state: router
	unchanged, STOPPED upgrade r1, snapshot unchanged."""
	env = setup_env
	install_ok(env)
	src2_path = src2(tmp_path)
	env.router.write("etc/newton/guard-state", "pending t\n")
	before = env.router.snapshot()
	r = run(env, "upgrade", src=src2_path)
	assert r.rc == 1
	lines = r.out.splitlines()
	assert any(l.startswith("WARN upgrade refused") for l in lines)
	assert any("pending" in l for l in lines if l.startswith("WARN upgrade"))
	assert "NOTE state: router unchanged" in lines
	assert lines[-1].startswith("STOPPED upgrade r1")
	assert env.router.snapshot() == before


def test_upgrade_live_helper_lock_refuses(setup_env, tmp_path):
	"""A helper-lock sid present in `ubus call session list` refuses."""
	env = setup_env
	install_ok(env)
	src2_path = src2(tmp_path)
	env.router.write("tmp/owrt-safe-apply.lock/sid", "abc\n")
	env.router.update_state(ubus_sessions="abc")
	before = env.router.snapshot()
	r = run(env, "upgrade", src=src2_path)
	assert r.rc == 1
	lines = r.out.splitlines()
	assert any(l.startswith("WARN upgrade refused: helper-lock") for l in lines)
	assert "NOTE state: router unchanged" in lines
	assert lines[-1].startswith("STOPPED upgrade r1")
	assert env.router.snapshot() == before


def test_upgrade_failed_guard_with_a_new_guard_stops_without_done(setup_env, tmp_path):
	"""A `failed x y` guard is not refused at step 2 and its
	files are not replaced (a failed guard needs the owner's recover
	first), but when this Newton ships a different guard the run must
	not end in DONE: every later change would die demanding an upgrade
	that skips the guard again.  The run stops naming the guard status
	and the recover step; program and helper are upgraded."""
	env = setup_env
	install_ok(env)
	guard_before = env.router.read(GUARD)
	init_before = env.router.read(INIT)
	src2_path = src2(tmp_path)
	src2_prog = (src2_path / PROG_REL).read_text()
	src2_helper = (src2_path / HELPER_REL).read_text()
	env.router.write("etc/newton/guard-state", "failed x y\n")
	r = run(env, "upgrade", src=src2_path)
	assert r.rc == 1, r.out + r.err
	lines = r.out.splitlines()
	assert not any(l.startswith("WARN upgrade refused") for l in lines)
	assert not any(l.startswith("DONE ") for l in lines), r.out
	assert lines[-1] == "STOPPED upgrade r1: the guard was not upgraded"
	warns = [l for l in lines if l.startswith("WARN upgrade guard:")]
	assert warns == [
		"WARN upgrade guard: the guard and its init were not replaced "
		"because the guard status is 'failed x y'; to clear it, as root on "
		"the router run /usr/libexec/newton-guard recover (keeps the live "
		"settings) or /usr/libexec/newton-guard recover restore <txn> "
		"(puts a saved copy back), then run: sudo -u newton "
		"/usr/local/bin/newton-router-setup r1 upgrade"], r.out
	notes = [l for l in lines if l.startswith("NOTE state: ")]
	assert notes == ["NOTE state: program and helper are upgraded; the "
	                 "guard and its init are the old ones"], r.out
	assert env.router.read(PROG) == src2_prog
	assert env.router.read(HELPER) == src2_helper
	assert env.router.read(GUARD) == guard_before
	assert env.router.read(INIT) == init_before
	assert not env.router.path(GUARD + ".new").exists()
	assert not env.router.path(INIT + ".new").exists()


@pytest.mark.parametrize("state", ["cannot-run", "failed"])
def test_upgrade_with_a_guard_it_cannot_replace_names_the_way_back(setup_env, tmp_path, state):
	"""A guard the upgrade cannot replace stops the run: every later
	change would die demanding an upgrade that skips the guard again.

	A guard that reports no status cannot run, so its warning
	says so and names the owner's way back: the full install run for
	that device.  Every other status
	keeps today's message, with the recover step."""
	env = setup_env
	install_ok(env)
	src2_path = src2(tmp_path)
	if state == "cannot-run":
		env.router.path(GUARD).chmod(0o644)
	else:
		env.router.write("etc/newton/guard-state", "failed x y\n")
	r = run(env, "upgrade", src=src2_path)
	assert r.rc == 1, r.out + r.err
	lines = r.out.splitlines()
	assert lines[-1] == "STOPPED upgrade r1: the guard was not upgraded"
	warns = [l for l in lines if l.startswith("WARN upgrade guard:")]
	assert len(warns) == 1, r.out
	if state != "failed":
		assert "reports no status (it looks broken)" in warns[0], warns[0]
		assert "newton-guard recover" not in warns[0], warns[0]
		assert ("sudo -u newton /usr/local/bin/newton-router-setup r1 install"
		        in warns[0]), warns[0]
	else:
		assert "the guard status is 'failed x y'" in warns[0], warns[0]
		assert "/usr/libexec/newton-guard recover" in warns[0], warns[0]
		assert ("sudo -u newton /usr/local/bin/newton-router-setup r1 upgrade"
		        in warns[0]), warns[0]


def test_upgrade_failed_guard_with_the_same_guard_is_done(setup_env, tmp_path):
	"""A failed guard whose files already match this Newton's
	does not stop the upgrade: only the program changed."""
	env = setup_env
	install_ok(env)
	src_p = build_src(tmp_path / "srcp", version="2.0.0")
	env.router.write("etc/newton/guard-state", "failed x y\n")
	r = run(env, "upgrade", src=src_p)
	assert r.rc == 0, r.out + r.err
	assert r.out.splitlines()[-1] == "DONE upgrade r1"
	assert env.router.read(PROG) == (src_p / PROG_REL).read_text()


def test_upgrade_restored_guard_upgrades_the_guard(setup_env, tmp_path):
	"""A `restored t boot` guard has no change in flight (the
	state stays until the next arm), so it is as safe as idle: guard
	and init are uploaded and checked too, and the run ends in DONE."""
	env = setup_env
	install_ok(env)
	src2_path = src2(tmp_path)
	env.router.write("etc/newton/guard-state", "restored t boot\n")
	r = run(env, "upgrade", src=src2_path)
	assert r.rc == 0, r.out + r.err
	assert r.out.splitlines()[-1] == "DONE upgrade r1"
	for rel, remote in ((PROG_REL, PROG), (HELPER_REL, HELPER),
	                    (GUARD_REL, GUARD), (INIT_REL, INIT)):
		assert env.router.read(remote) == (src2_path / rel).read_text(), remote


def test_upgrade_idle_guard_with_a_skipped_line_upgrades_the_guard(setup_env, tmp_path):
	"""A /etc/config entry the guard cannot name adds a second
	`skipped <name>` line to its status; only the first line is the
	status, so the guard is still idle and gets upgraded."""
	env = setup_env
	install_ok(env)
	src2_path = src2(tmp_path)
	env.router.write("etc/newton/guard-skipped", "bad\\x20name\n")
	r = run(env, "upgrade", src=src2_path)
	assert r.rc == 0, r.out + r.err
	assert r.out.splitlines()[-1] == "DONE upgrade r1"
	assert env.router.read(GUARD) == (src2_path / GUARD_REL).read_text()
	assert env.router.read(INIT) == (src2_path / INIT_REL).read_text()


# -- 5. broken new program -----------------------------------------------

def test_upgrade_broken_program_restores_from_prev(setup_env, tmp_path):
	"""After a good upgrade to src2, a broken src3 fails at step 4 and
	install_restore puts the program and helper back to src2's bytes."""
	env = setup_env
	install_ok(env)
	src2_path = src2(tmp_path)
	run(env, "upgrade", src=src2_path)
	src2_prog_after = env.router.read(PROG)
	src2_helper_after = env.router.read(HELPER)
	src3_path = build_src(tmp_path / "src3", program="broken",
	                      version="3.0.0")
	r = run(env, "upgrade", src=src3_path)
	assert r.rc == 1, r.err
	lines = r.out.splitlines()
	assert lines[-1] == "STOPPED upgrade r1: upgrade step 4 failed"
	assert env.router.read(PROG) == src2_prog_after
	assert env.router.read(HELPER) == src2_helper_after
	assert env.router.read(PROG + ".prev") == src2_prog_after
	assert env.router.read(HELPER + ".prev") == src2_helper_after
	notes = [l for l in lines if l.startswith("NOTE state:")]
	assert any("restored from .prev" in n for n in notes)
	assert any("hello after restore: ok" in n for n in notes)


def test_upgrade_failure_note_names_the_new_files_that_stay(setup_env, tmp_path):
	"""The guard and its init keep no .prev, so a failed upgrade
	puts the program and helper back but leaves the new guard on the
	router; the note says so instead of leaving it out."""
	env = setup_env
	install_ok(env)
	src3_path = build_src(tmp_path / "src3", program="broken",
	                      version="3.0.0")
	for rel in (HELPER_REL, GUARD_REL):
		with (src3_path / rel).open("a") as fh:
			fh.write("# v3\n")
	r = run(env, "upgrade", src=src3_path)
	assert r.rc == 1, r.err
	notes = [l for l in r.out.splitlines() if l.startswith("NOTE state:")]
	assert any("restored from .prev" in n for n in notes), notes
	assert any("; kept new (no .prev): /usr/libexec/newton-guard;" in n
	           or n.endswith("; kept new (no .prev): /usr/libexec/newton-guard")
	           for n in notes), notes
	assert env.router.read(GUARD).endswith("# v3\n")


# -- 6. repairing a broken first install ---------------------------------

def test_upgrade_repairs_broken_first_install(setup_env, tmp_path):
	"""Install a broken v1 tree (seed_known_hosts + run install: exit 1),
	then upgrade with the good default tree: exit 0 and the program on
	the router equals the good source."""
	env = setup_env
	seed_known_hosts(env)
	broken_tree = build_src(tmp_path / "broken_install", program="broken",
	                        version="1.0.0")
	r1 = run(env, "install", src=broken_tree)
	assert r1.rc == 1
	assert "# FIXTURE-BROKEN" in env.router.read(PROG)
	r2 = run(env, "upgrade", src=env.src)
	assert r2.rc == 0, r2.err
	assert r2.out.splitlines()[-1] == "DONE upgrade r1"
	assert env.router.read(PROG) == (env.src / PROG_REL).read_text()


# -- 7. restricted-key check ---------------------------------------------

def test_upgrade_with_inventory_key_file_does_step_5(setup_env, tmp_path):
	"""After add-key + key_file in the inventory, upgrade prints PASS
	upgrade step 5 instead of the INFO skip line."""
	env = setup_env
	install_ok(env)
	add_key = run(env, "add-key", "--new-key", "newton-agent", "change")
	assert add_key.rc == 0
	assert add_key.out.splitlines()[-1] == "DONE add-key r1"
	key_file = env.keys_dir / "r1-newton-agent"
	assert key_file.exists()
	with env.inventory.open("a") as fh:
		fh.write('key_file = "%s"\n' % key_file)
	src2_path = src2(tmp_path)
	r = run(env, "upgrade", src=src2_path)
	assert r.rc == 0, r.err
	lines = r.out.splitlines()
	assert "PASS upgrade step 5: restricted key checks pass" in lines
	assert not any("INFO restricted-key check skipped" in l for l in lines)
	assert lines[-1] == "DONE upgrade r1"


def test_upgrade_step_5_fails_when_the_restricted_hello_says_door_root(setup_env, tmp_path):
	"""(planted defect: the restricted check ignored the
	door field).  The hello of the restricted key must say door=ssh; the
	fixture's override makes the forced-command hello say door=root (the
	direct hello says door=root anyway, so step 4 is not disturbed), the
	upgrade fails at step 5 and puts the old files back."""
	env = setup_env
	install_ok(env)
	assert run(env, "add-key", "--new-key", "newton-agent", "change").rc == 0
	key_file = env.keys_dir / "r1-newton-agent"
	with env.inventory.open("a") as fh:
		fh.write('key_file = "%s"\n' % key_file)
	v1_prog = env.router.read(PROG)
	env.router.write("etc/newton/fixture-lie", "door=root\n")
	r = run(env, "upgrade", src=src2(tmp_path))
	assert r.rc == 1
	assert r.out.splitlines()[-1] == "STOPPED upgrade r1: upgrade step 5 failed"
	assert "restored from .prev" in r.out
	assert env.router.read(PROG) == v1_prog


# -- 8. secrets ----------------------------------------------------------

def test_no_secret_leak_after_install_and_upgrade(setup_env, tmp_path):
	"""With GOOD_PW registered, install_ok + a follow-up upgrade has no
	leaks anywhere (call log, last stdout/stderr, every regular file
	under self.tmp)."""
	env = setup_env
	env.register_secrets(GOOD_PW)
	install_ok(env)
	src2_path = src2(tmp_path)
	r = run(env, "upgrade", src=src2_path)
	assert r.rc == 0
	assert r.out.splitlines()[-1] == "DONE upgrade r1"
	assert env.leaks() == []
