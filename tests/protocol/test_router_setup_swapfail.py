"""Behaviour tests of the FAILURE paths of `swap-key` of
scripts/newton-router-setup (, design 8.3
sub-steps 5-7 and 2.5/2.7): the proof-fail restore, the no-program
no-op, the sub-step 6 dead-man restore, the sub-step 7 ghost-blob
detection, the dead-man-start failure, and the --admin password
refusal."""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from router_setup_env import pulsar_env, build_src  # noqa: F401
from test_router_setup_install import seed_known_hosts  # noqa: E402
from test_router_setup_keys import direct_fake_ssh  # noqa: E402


EXTRA = "ssh-ed25519 AAAAEXTRAKEYFORSWAPTESTS0001 agent-laptop"


def install_pulsar(env, program="ok"):
	"""Install on pulsar via the plain-key admin path; a broken program
	returns rc=1 and the router then holds the broken files."""
	seed_known_hosts(env)
	extra_env = None
	if program != "ok":
		broken = build_src(env.tmp / ("src-" + program), program=program)
		extra_env = {"NEWTON_SETUP_SRC": str(broken)}
	return env.run("--plain-key", env.plain_key, "pulsar", "install",
				   typed=("yes",), env=extra_env)


def swap(env, *extra):
	"""swap-key pulsar via the plain-key admin path; no typed input."""
	return env.run("--plain-key", env.plain_key, "pulsar", "swap-key", *extra)


def plain_key_works(env):
	"""The plain key still authenticates against the router."""
	return direct_fake_ssh(env, env.plain_key, "true").returncode == 0


def state_notes(result):
	return [l for l in result.out.splitlines() if l.startswith("NOTE state:")]


def last_line(result):
	lines = result.out.splitlines()
	return lines[-1] if lines else ""


# -- 1. proofs fail before the swap ----------------------------------------

def test_swap_fail_proofs_broken_program(pulsar_env):
	"""A broken program installed: proofs fail, the new line is removed
	again, plain key still works, no dead-man started, inventory
	unchanged."""
	env = pulsar_env
	install_pulsar(env, program="broken")
	env.router.add_authorized_key(EXTRA)
	original = env.router.read("etc/dropbear/authorized_keys")
	inv_before = env.inventory.read_text()
	r = swap(env, "--new-key")
	assert r.rc == 1
	assert last_line(r).startswith("STOPPED swap-key pulsar")
	notes = state_notes(r)
	assert any("router unchanged (the new line was removed again)" in n
			   for n in notes)
	assert env.router.read("etc/dropbear/authorized_keys") == original
	assert plain_key_works(env)
	assert env.router.timers() == []
	assert env.inventory.read_text() == inv_before


def test_swap_fail_proofs_vulnerable(pulsar_env):
	"""Good install but a vulnerable router (forwarding): proofs fail,
	the new line is removed again, plain key still works, no dead-man
	started, inventory unchanged."""
	env = pulsar_env
	install_pulsar(env, program="ok")
	env.router.update_state(vulnerable=["forwarding"])
	env.router.add_authorized_key(EXTRA)
	original = env.router.read("etc/dropbear/authorized_keys")
	inv_before = env.inventory.read_text()
	r = swap(env, "--new-key")
	assert r.rc == 1
	assert last_line(r).startswith("STOPPED swap-key pulsar")
	notes = state_notes(r)
	assert any("router unchanged (the new line was removed again)" in n
			   for n in notes)
	assert env.router.read("etc/dropbear/authorized_keys") == original
	assert plain_key_works(env)
	assert env.router.timers() == []
	assert env.inventory.read_text() == inv_before


# -- 2. no program on the router ------------------------------------------

def test_swap_fail_no_program(pulsar_env):
	"""No install at all: proofs fail because the program is missing,
	the new line is removed again, plain key still works, no dead-man
	started, inventory unchanged."""
	env = pulsar_env
	seed_known_hosts(env)
	env.router.add_authorized_key(EXTRA)
	original = env.router.read("etc/dropbear/authorized_keys")
	inv_before = env.inventory.read_text()
	r = swap(env, "--new-key")
	assert r.rc == 1
	assert last_line(r).startswith("STOPPED swap-key pulsar")
	notes = state_notes(r)
	assert any("router unchanged (the new line was removed again)" in n
			   for n in notes)
	assert env.router.read("etc/dropbear/authorized_keys") == original
	assert plain_key_works(env)
	assert env.router.timers() == []
	assert env.inventory.read_text() == inv_before


def test_swap_fail_step6_dead_man_restores(pulsar_env):
	"""deny_restricted_when_plain_absent: sub-step 6 fails, the dead-man
	timer fires, the plain key works again, the original is restored
	byte for byte (and equals .newton-prev), syslog notes the restore,
	inventory unchanged; then with the knob off, swap succeeds.  The
	knob denies a restricted key only while NO unrestricted key line is
	left, so the router must hold the plain line alone (an unrelated
	unrestricted line would keep the knob quiet)."""
	env = pulsar_env
	install_pulsar(env, program="ok")
	env.router.update_state(deny_restricted_when_plain_absent=True)
	original = env.router.read("etc/dropbear/authorized_keys")
	inv_before = env.inventory.read_text()
	r = swap(env, "--new-key")
	assert r.rc == 1
	notes = state_notes(r)
	assert any("restored by the dead-man switch" in n for n in notes)
	assert last_line(r) == (
		"STOPPED swap-key pulsar: the new key was not proven in time")
	assert plain_key_works(env)
	assert env.router.read("etc/dropbear/authorized_keys") == original
	assert env.router.read(
		"etc/dropbear/authorized_keys.newton-prev") == original
	assert env.router.clock() >= 90
	assert "authorized_keys restored" in env.router.read("tmp/syslog")
	assert env.router.timers() == []
	assert env.inventory.read_text() == inv_before

	env.router.update_state(deny_restricted_when_plain_absent=False)
	r2 = swap(env)
	assert r2.rc == 0
	assert r2.out.splitlines()[-1] == "DONE swap-key pulsar"


# -- 4. sub-step 7 fails (ghost blob) -------------------------------------

def test_swap_fail_step7_ghost_blob(pulsar_env):
	"""The plain key's blob is in ghost_blobs: sub-step 7 fails, the
	new line stays and the plain line is gone, the inventory is not
	updated."""
	env = pulsar_env
	install_pulsar(env, program="ok")
	pub = env.plain_key.with_name("id_ed25519.pub")
	blob = pub.read_text().strip().split()[1]
	env.router.update_state(ghost_blobs=[blob])
	env.router.add_authorized_key(EXTRA)
	inv_before = env.inventory.read_text()
	r = swap(env, "--new-key")
	assert r.rc == 1
	notes = state_notes(r)
	assert any("both keys work; nothing was lost" in n for n in notes)
	assert last_line(r) == (
		"STOPPED swap-key pulsar: the old key still works")
	keys = env.router.authorized_keys()
	assert any("newton-router" in line for line in keys)
	assert not any(blob in line for line in keys)
	assert env.inventory.read_text() == inv_before


def test_swap_fail_dead_man_cannot_start(pulsar_env):
	"""The link drops at the moment the dead-man switch is started (the
	state knob drop_commands: that command is not run, exit 255): the new
	line is removed again, the plain key is never replaced, no timer."""
	env = pulsar_env
	install_pulsar(env, program="ok")
	env.router.add_authorized_key(EXTRA)
	original = env.router.read("etc/dropbear/authorized_keys")
	env.router.update_state(drop_commands=["setsid sh -c"])
	r = swap(env, "--new-key")
	assert r.rc == 1
	notes = state_notes(r)
	assert any("router unchanged (the new line was removed again)" in n
			   for n in notes)
	assert last_line(r) == (
		"STOPPED swap-key pulsar: cannot start the dead-man switch")
	assert env.router.read("etc/dropbear/authorized_keys") == original
	assert plain_key_works(env)
	assert env.router.timers() == []


# -- 5b. the replace call is lost (sub-step 5 fails, 6 and 7 decide) -------

def test_swap_fail_replace_call_dropped(pulsar_env):
	"""The link drops during the key replacement (sub-step 5): the action
	only logs it; sub-step 6 passes (the new line was added in step 2) and
	sub-step 7 finds the old key still working, so it stops with both keys
	valid and the inventory not updated.  The dead-man switch is pending
	and will find its proof line."""
	env = pulsar_env
	install_pulsar(env, program="ok")
	env.router.add_authorized_key(EXTRA)
	inv_before = env.inventory.read_text()
	env.router.update_state(drop_commands=["old=$(awk"])
	r = swap(env, "--new-key")
	assert r.rc == 1
	assert any(l.startswith("INFO swap step 5:") and "failed" in l
			   for l in r.out.splitlines()), r.out
	assert "NOTE state: both keys work; nothing was lost" in r.out
	assert last_line(r) == "STOPPED swap-key pulsar: the old key still works"
	keys = env.router.authorized_keys()
	assert EXTRA in keys
	assert any("newton-router-newton-agent" in l for l in keys)
	assert plain_key_works(env)
	assert len(env.router.timers()) == 1
	assert env.inventory.read_text() == inv_before


# -- 6. --admin password is rejected --------------------------------------

def test_swap_admin_password_rejected(pulsar_env):
	"""--admin password with swap-key: exit 2 with the message on stderr,
	nothing sent to the router.  --admin is a global flag (parsed before
	the device), so it must precede the device on the command line."""
	env = pulsar_env
	r = env.run("--admin", "password",
				 "--plain-key", env.plain_key, "pulsar", "swap-key")
	assert r.rc == 2
	assert "swap-key needs the plain-key admin path" in r.err
	assert r.calls == []


def test_swap_inventory_write_failure_stops_with_recovery_state(pulsar_env):
	env = pulsar_env
	inv_dir = env.tmp / "inventory"
	inv_dir.mkdir()
	env.inventory = env.inventory.rename(inv_dir / "devices.toml")
	install_pulsar(env, program="ok")
	before = env.inventory.read_text()
	os.chmod(inv_dir, 0o555)
	try:
		r = swap(env, "--new-key")
	finally:
		os.chmod(inv_dir, 0o755)
	assert r.rc == 1, r.out + r.err
	assert "error: cannot write %s.new" % env.inventory in r.err
	assert (
		"NOTE state: the swap is done and the new key works (the plain key is refused); "
		"the inventory was NOT updated: add key_file and known_hosts to the device by hand"
	) in r.out.splitlines()
	assert r.out.splitlines()[-1] == (
		"STOPPED swap-key pulsar: cannot update the inventory")
	assert env.inventory.read_text() == before
	assert not plain_key_works(env)
	new_key = env.keys_dir / "pulsar-newton-agent"
	assert direct_fake_ssh(env, new_key, "hello " + "0" * 32).returncode == 0
