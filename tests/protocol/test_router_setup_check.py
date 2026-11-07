"""Tests of the check action of scripts/newton-router-setup (;
design 8.1 row 1): the lab and pulsar happy paths,
the known_hosts rules of 2.4, the failure paths of 3.1, the secret rules
of 2.3 and the seam gate of 1.2."""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from router_setup_env import setup_env, pulsar_env  # noqa: F401
from router_setup_harness import DEFAULT_STATE  # noqa: E402

HOST_KEY_LINE = "%s %s" % ("10.1.2.3", DEFAULT_STATE["host_key"])
GOOD_PW = "root-pw-for-tests"


def run_check(env, typed=(GOOD_PW,), **kw):
	"""A check run with the good typed root password by default."""
	return env.run(env.device, "check", typed=typed, **kw)


def seed_known_hosts(env):
	"""Put the router's current host key in the device known_hosts file,
	as a previous check run would have left it."""
	env.known_hosts.write_text(HOST_KEY_LINE + "\n")


def ssh_calls(result):
	return [c for c in result.calls if c["tool"] == "ssh"]


def assert_stopped(result, device):
	assert result.rc == 1
	assert result.lines("STOPPED check %s:" % device)
	assert "NOTE state: router unchanged" in result.out.splitlines()


# -- 1. happy paths ---------------------------------------------------------

def test_check_lab_happy(setup_env):
	"""Lab-like run (3.1): typed root password, full report, exit 0,
	nothing changed on the router."""
	env = setup_env
	before = env.router.snapshot()
	r = run_check(env, typed=(GOOD_PW, "DECOY"))
	assert r.rc == 0
	assert r.err.count("root password: ") == 1
	assert "DONE check r1" in r.out.splitlines()
	assert "PASS tools 27/27 present" in r.out.splitlines()
	release = [l for l in r.lines("INFO ") if l.startswith("INFO release ")]
	busybox = [l for l in r.lines("INFO ") if l.startswith("INFO busybox ")]
	assert release and release[0].strip() != "INFO release"
	assert busybox and "BusyBox v" in busybox[0]
	assert "PASS password-only login works" in r.out.splitlines()
	assert env.router.snapshot() == before


def test_check_pulsar_happy(pulsar_env):
	"""Pulsar-like run (2.2, 3.1): the report goes over the plain key
	(no askpass), then the typed-password proof uses
	PubkeyAuthentication=no; exit 0."""
	env = pulsar_env
	# the tool finds the default plain key through getent passwd, not
	# $HOME, so the fixture key is named explicitly
	r = env.run("--plain-key", env.plain_key, "pulsar", "check",
			typed=(GOOD_PW, "DECOY"))
	assert r.rc == 0
	assert r.err.count("root password: ") == 1
	assert "DONE check pulsar" in r.out.splitlines()
	calls = ssh_calls(r)
	assert len(calls) == 3
	for call in calls[:2]:
		assert call["lane"] == "key"
		assert str(env.plain_key) in call["argv"]
		assert call["principal"].startswith("key:")
	proof = calls[2]
	assert proof["lane"] == "password"
	assert "PubkeyAuthentication=no" in proof["argv"]
	assert proof["principal"] == "password"


# -- 3. known_hosts ------------------------------------------

def test_known_hosts_first_run_learns(setup_env):
	"""First run: exactly one accept-new call, it is the first call, the
	file then holds the router host key, the NOTE appears once."""
	env = setup_env
	r = run_check(env)
	assert r.rc == 0
	calls = ssh_calls(r)
	learn = [c for c in calls if c["strict"] == "accept-new"]
	assert len(learn) == 1
	assert calls[0] is learn[0]
	assert env.known_hosts.read_text().splitlines() == [HOST_KEY_LINE]
	notes = r.lines("NOTE host key learned:")
	assert len(notes) == 1
	assert "SHA256:" in notes[0]


def test_known_hosts_second_run_all_yes(setup_env):
	"""A second run makes no accept-new call and every ssh call uses
	strict yes with that same file."""
	env = setup_env
	assert run_check(env, typed=(GOOD_PW, "DECOY")).rc == 0
	r = run_check(env, typed=(GOOD_PW, "DECOY"))
	assert r.rc == 0
	assert r.err.count("root password: ") == 1
	calls = ssh_calls(r)
	assert calls
	assert all(c["strict"] == "yes" for c in calls)
	assert all(c["known_hosts"] == str(env.known_hosts) for c in calls)


def test_known_hosts_rotated_stops_lab(setup_env):
	# Fixed (found by the test rig): with a
	# rotated router host_key the report call fails (rc 255, REMOTE HOST
	# IDENTIFICATION HAS CHANGED) but the tool goes on with the password-only
	# proof (a second ssh call) instead of stopping at once (2.2: 255 is a
	# transport failure).
	env = setup_env
	assert run_check(env).rc == 0
	env.router.update_state(host_key="ssh-ed25519 AAAAC3FAKEHOSTKEY0002")
	r = env.run("r1", "check", typed=(GOOD_PW,))
	assert_stopped(r, "r1")
	assert len(ssh_calls(r)) == 1


def test_known_hosts_rotated_stops_pulsar(pulsar_env):
	# Fixed, same defect on the plain-key path: after the failed report no
	# password prompt may be consumed (typed input is empty) and no second
	# ssh call made; the run ends STOPPED (exit 1), not with a prompt error.
	env = pulsar_env
	args = ("--plain-key", env.plain_key, "pulsar", "check")
	assert env.run(*args, typed=(GOOD_PW,)).rc == 0
	env.router.update_state(host_key="ssh-ed25519 AAAAC3FAKEHOSTKEY0002")
	r = env.run(*args, typed=())
	assert_stopped(r, "pulsar")
	assert len(ssh_calls(r)) == 1


def test_known_hosts_trusted_copied(setup_env):
	"""An entry in the trusted known_hosts file is copied and no call
	uses accept-new (2.4b)."""
	env = setup_env
	env.trusted.write_text(HOST_KEY_LINE + "\n")
	r = run_check(env)
	assert r.rc == 0
	assert "DONE check r1" in r.out.splitlines()
	assert env.known_hosts.read_text().splitlines() == [HOST_KEY_LINE]
	assert not r.lines("NOTE host key learned:")
	calls = ssh_calls(r)
	assert calls
	assert all(c["strict"] == "yes" for c in calls)


# -- 4. failures (3.1) ------------------------------------------------------

def test_fail_missing_tool(setup_env):
	"""A missing G0 tool is one FAIL tool NAME line (3.1)."""
	env = setup_env
	(env.router.root / "bin" / "ucode").unlink()
	r = run_check(env)
	assert_stopped(r, "r1")
	assert "FAIL tool ucode" in r.out.splitlines()


def test_iwinfo_missing_alone_warns(setup_env):
	"""Only iwinfo missing: check exits 0, the WARN is printed, the
	FAIL tool iwinfo line is gone, the tools counts still work, no FAIL
	line anywhere."""
	env = setup_env
	(env.router.root / "bin" / "iwinfo").unlink()
	r = run_check(env)
	assert r.rc == 0
	assert "DONE check r1" in r.out.splitlines()
	assert "WARN iwinfo absent: wifi reads unavailable" in r.out.splitlines()
	assert "FAIL tool iwinfo" not in r.out.splitlines()
	assert "PASS tools 26/27 present" in r.out.splitlines()
	assert not [l for l in r.out.splitlines() if l.startswith("FAIL ")]


def test_iwinfo_and_other_tool_missing(setup_env):
	"""iwinfo and ucode both missing: the WARN still mentions iwinfo, the
	other missing tool still FAILs, check stops."""
	env = setup_env
	(env.router.root / "bin" / "iwinfo").unlink()
	(env.router.root / "bin" / "ucode").unlink()
	r = run_check(env)
	assert_stopped(r, "r1")
	assert "WARN iwinfo absent: wifi reads unavailable" in r.out.splitlines()
	assert "FAIL tool iwinfo" not in r.out.splitlines()
	assert "FAIL tool ucode" in r.out.splitlines()


def test_fail_wrong_password_lab(setup_env):
	"""Lab (password lane): a wrong typed root password makes the report
	call fail; the run stops at once after that one ssh call."""
	env = setup_env
	seed_known_hosts(env)
	r = run_check(env, typed=("wrong-password",))
	assert_stopped(r, "r1")
	assert "FAIL router report: ssh failed (exit 255)" in r.out.splitlines()
	status = [line for line in r.out.splitlines()
		if line.startswith(("PASS ", "FAIL ", "INFO ", "WARN "))]
	assert status[0] == "FAIL router report: ssh failed (exit 255)"
	assert len(ssh_calls(r)) == 1


def test_fail_wrong_password_pulsar(pulsar_env):
	"""Pulsar (plain-key report): a wrong typed password FAILs the
	password-only login proof."""
	env = pulsar_env
	seed_known_hosts(env)
	r = env.run("--plain-key", env.plain_key, "pulsar", "check",
			typed=("wrong-password",))
	assert_stopped(r, "pulsar")
	assert "FAIL password-only login failed" in r.out.splitlines()
	assert "PASS tools 27/27 present" in r.out.splitlines()


def test_fail_password_auth_false_lab(setup_env):
	"""password_auth false on the router: the password lane cannot log in,
	the report call fails and the run stops at once."""
	env = setup_env
	seed_known_hosts(env)
	env.router.update_state(password_auth=False)
	r = run_check(env)
	assert_stopped(r, "r1")
	assert "FAIL router report: ssh failed (exit 255)" in r.out.splitlines()
	assert len(ssh_calls(r)) == 1


def test_fail_password_auth_false_pulsar(pulsar_env):
	"""The last resort is gone (password login off): the report passes over
	the plain key, the proof FAILs, exit 1."""
	env = pulsar_env
	seed_known_hosts(env)
	env.router.update_state(password_auth=False)
	r = env.run("--plain-key", env.plain_key, "pulsar", "check", typed=(GOOD_PW,))
	assert_stopped(r, "pulsar")
	assert "FAIL password-only login failed" in r.out.splitlines()


def test_fail_dropbear_passwordauth_off(setup_env):
	"""uci dropbear PasswordAuth = off is a FAIL (3.1)."""
	env = setup_env
	seed_known_hosts(env)
	env.router.update_state(
		uci={
			"dropbear.@dropbear[0]": "dropbear",
			"dropbear.@dropbear[0].PasswordAuth": "off",
		})
	r = run_check(env)
	assert_stopped(r, "r1")
	assert "FAIL dropbear PasswordAuth off" in r.out.splitlines()


def test_fail_guard_pending(setup_env):
	"""A guard-state file saying pending is a FAIL (3.1)."""
	env = setup_env
	seed_known_hosts(env)
	env.router.write("usr/libexec/newton-guard", _guard_fixture_text(),
			mode=0o755)
	env.router.write("etc/newton/guard-state", "pending pending since boot\n")
	r = run_check(env)
	assert_stopped(r, "r1")
	assert any(l.startswith("FAIL guard pending")
		for l in r.lines("FAIL "))


def _guard_fixture_text():
	from router_setup_env import FIXTURES
	return (FIXTURES / "newton-guard").read_text()


def test_fail_helper_lock_live(setup_env):
	"""A helper lock whose sid the fake ubus lists is a FAIL."""
	env = setup_env
	seed_known_hosts(env)
	env.router.write("tmp/owrt-safe-apply.lock/sid", "sess-abc123\n")
	env.router.update_state(ubus_sessions="session sess-abc123 active\n")
	r = run_check(env)
	assert_stopped(r, "r1")
	assert "FAIL helper lock live" in r.out.splitlines()


def test_helper_lock_stale_warns(setup_env):
	"""A helper lock whose sid is not listed is a WARN and exit 0."""
	env = setup_env
	seed_known_hosts(env)
	env.router.write("tmp/owrt-safe-apply.lock/sid", "sess-abc123\n")
	env.router.update_state(ubus_sessions="session sess-other active\n")
	r = run_check(env)
	assert r.rc == 0
	assert "DONE check r1" in r.out.splitlines()
	assert "WARN helper lock stale" in r.out.splitlines()


# -- 5. secrets (2.3, 4.3, 4.4) ---------------------------------------------

def test_no_secret_leaks(setup_env):
	"""After a full lab run the root password leaks nowhere: leaks() is
	empty, no argv holds it (so the askpass directory held only the
	script and the fifo, per the call-log leaks field) and the typed
	file is the only place it was written."""
	env = setup_env
	pw = "unique-root-pw-7f3a91"
	env.router.update_state(root_password=pw)
	env.register_secrets(pw)
	r = run_check(env, typed=(pw,))
	assert r.rc == 0
	assert env.leaks() == []
	for call in env.router.calls():
		for arg in call.get("argv", []):
			assert pw not in arg


# -- 6. seam misuse (1.2) ----------------------------------------------------

def test_seam_misuse_exit2(setup_env):
	"""A NEWTON_SETUP_* variable without the marker: exit 2 before
	anything else."""
	env = setup_env
	r = env.run("r1", "check", env={"NEWTON_SETUP_SEAMS": "0"})
	assert r.rc == 2
	assert "error: NEWTON_SETUP_* variables need NEWTON_SETUP_SEAMS=1" \
		in r.err.splitlines()
	assert "note: test seams active" not in r.err


# -- 7. restricted-key proofs (R5: doctor's F2 router-line check needs the
#      two proof lines; design 7.2 row newton-doctor) -----


def _seed_restricted_setup(env, label="newton-agent", role="change",
		blob_path=None):
	"""Install the four code files on the fake router (so restricted-hello
	says caller=... role=... mode=prod door=ssh), add the matching
	authorized_keys line for label/role, generate the keypair under
	${KEYS_DIR}/${DEVICE}-${label} via the fake ssh-keygen (the one
	set up by env.fakes), set file mode 0600, and append
	key_file = <KEYFILE> to the env's inventory. Returns the keyfile path."""
	from test_router_setup_install import install_ok, PROG
	install_ok(env)
	prog = env.router.read(PROG)
	pub_blob = _private_pub_blob(env, label)
	restricted = (
		"restrict,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,"
		'no-pty,command="/usr/libexec/newton/newton-router '
		'--caller=%s --role=%s" ssh-ed25519 %s '
		"newton-router-%s" % (label, role, pub_blob, label)
	)
	env.router.add_authorized_key(restricted)
	keyfile = env.keys_dir / ("%s-%s" % (env.device, label))
	# ensure the private half exists and is mode 0600
	keyfile.write_text("FAKE-OPENSSH-PRIVATE-KEY\n%s\n" % pub_blob)
	keyfile.chmod(0o600)
	(env.keys_dir / ("%s-%s.pub" % (env.device, label))).write_text(
		"ssh-ed25519 %s newton-router-%s\n" % (pub_blob, label))
	with env.inventory.open("a") as fh:
		fh.write('key_file = "%s"\n' % keyfile)
	return keyfile


def _private_pub_blob(env, label):
	"""Return a deterministic 56-char base64-ish blob (any unique string is
	fine; the fake ssh-keygen only checks shape, not real ed25519)."""
	from router_setup_harness import BLOB_PREFIX
	return BLOB_PREFIX + ("X" * (40 - len(label))) + label


def test_check_prints_both_proofs_when_key_file_exists(setup_env):
	"""R5: with the four code files installed, a restricted-key
	authorized_keys line for newton-agent/change and inventory key_file
	pointing at the matching keypair, `check` prints both whole proof
	lines (PASS proof hello, PASS proof unknown-and-empty) so the
	doctor's F2 router-line check has both lines to grep for; rc=0 and
	DONE check r1."""
	env = setup_env
	keyfile = _seed_restricted_setup(env, label="newton-agent", role="change")
	r = run_check(env, typed=(GOOD_PW,))
	assert r.rc == 0
	assert "DONE check r1" in r.out.splitlines()
	lines = r.out.splitlines()
	assert "PASS proof hello: restricted identity" in lines
	assert "PASS proof unknown-and-empty: rejected" in lines


def test_check_warns_when_inventory_has_no_key_file(setup_env):
	"""R5: with no key_file in the inventory, check prints the WARN
	skip line, prints NO proof lines, exits 0; the doctor stays
	INCONCLUSIVE because the proofs are absent."""
	env = setup_env
	r = run_check(env, typed=(GOOD_PW,))
	assert r.rc == 0
	assert "DONE check r1" in r.out.splitlines()
	lines = r.out.splitlines()
	assert any(l.startswith("WARN restricted-key proofs skipped") for l in lines)
	assert not any(l.startswith("PASS proof hello") for l in lines)
	assert not any(l.startswith("PASS proof unknown-and-empty") for l in lines)
	assert not any(l.startswith("FAIL proof ") for l in lines)


def test_check_warns_when_key_file_does_not_exist(setup_env):
	"""R5: inventory names a key_file that is not installed under
	KEYS_DIR; check prints the WARN skip line (no proof lines, rc=0).
	The doctor stays INCONCLUSIVE; absence of the proofs is not a
	violation."""
	env = setup_env
	with env.inventory.open("a") as fh:
		fh.write('key_file = "%s/r1-never-installed"\n' % env.keys_dir)
	r = run_check(env, typed=(GOOD_PW,))
	assert r.rc == 0
	lines = r.out.splitlines()
	assert any(l.startswith("WARN restricted-key proofs skipped") for l in lines)
	assert not any(l.startswith("PASS proof ") for l in lines)
	assert not any(l.startswith("FAIL proof ") for l in lines)


def test_check_fails_with_proof_hello_when_router_answers_wrong_caller(
		setup_env):
	"""R5: the keypair exists and matches the authorized_keys line on
	the router, but the restricted-key program is rigged to lie about
	caller=<not-newton-agent>; check prints FAIL proof hello: and
	stops with rc=1."""
	env = setup_env
	_seed_restricted_setup(env, label="newton-agent", role="change")
	env.router.write("etc/newton/fixture-lie", "caller=somebody-else\n")
	r = run_check(env, typed=(GOOD_PW,))
	assert r.rc == 1
	assert_stopped(r, "r1")
	assert any(l.startswith("FAIL proof hello:") for l in r.out.splitlines())
	assert r.out.splitlines()[-1] == "STOPPED check r1: check found a problem"


# -- 8. SW2 review: the known_hosts dir parent rule --------------------------

def test_check_refuses_known_hosts_dir_under_group_writable_parent(setup_env):
	"""SW2 review: the router identity pin (known_hosts) is written before
	the check's first ssh call, and the file lands in an operator-settable
	directory (the inventory known_hosts).  ensure_known_hosts therefore
	refuses when that directory's PARENT is group- or world-writable
	without the sticky bit: the host key must not be learned, written or
	pinned under a parent any local user can plant a symlink in.

	Nothing is created and no ssh call happens -- not even the
	accept-new learning call.
	"""
	env = setup_env
	hostile = env.tmp / "hostile-kh-parent"
	hostile.mkdir()
	os.chmod(hostile, 0o777)
	kh_dir = hostile / "kh"
	kh_file = kh_dir / "r1.known_hosts"
	env.inventory.write_text(
		"[devices.r1]\nhost = \"10.1.2.3\"\nprofile = \"lab\"\n"
		"auth = \"password\"\nknown_hosts = \"%s\"\n" % kh_file)

	try:
		r = run_check(env)
	finally:
		os.chmod(hostile, 0o700)

	assert r.rc == 2, r.out + r.err
	assert "group- or world-writable without the sticky bit" in r.err
	assert str(hostile) in r.err
	assert not kh_dir.exists()
	assert not any(c["strict"] == "accept-new" for c in r.calls)
	assert r.calls == []
