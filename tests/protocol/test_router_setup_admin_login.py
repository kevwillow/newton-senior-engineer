"""The admin lane says why the login failed.

Every admin call of scripts/newton-router-setup sits inside a command
substitution, so ssh's stderr (the "Permission denied" of a refused
login) never reached the owner: a refused admin login ended in a bare
STOPPED line with no reason at all.  The lane now records the reason and
the run prints one FAIL line before the STOPPED line.

A login failure is a PROVEN connect or
authentication failure, not a guess from the exit status, every real
failure of the run is recorded (a later successful call never erases
it), and the run prints each recorded line once before it stops.

Stdlib only, no network: the fake ssh of the router-setup harness is the
router.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from router_setup_env import setup_env, pulsar_env  # noqa: E402,F401
from router_setup_harness import DEFAULT_STATE  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
GOOD_PW = DEFAULT_STATE["root_password"]
HOST = "10.1.2.3"
MARKER = "NEWTON-ADMIN-SESSION"
EXTRA = "ssh-ed25519 AAAAEXTRAKEYFORSWAPTESTS0001 agent-laptop"


def seed_known_hosts(env):
	"""The router's current host key in the device known_hosts file, as a
	previous run would have left it."""
	env.known_hosts.write_text("%s %s\n" % (HOST, env.router.state()["host_key"]))


def make_key(env, name="id_ed25519"):
	"""A key pair made with the fake ssh-keygen.  Its public line is not
	added to the router, so the key lane is refused."""
	ssh_dir = env.home / ".ssh"
	ssh_dir.mkdir(parents=True, exist_ok=True)
	key = ssh_dir / name
	proc = subprocess.run(
		[str(env.fakes / "ssh-keygen"), "-q", "-t", "ed25519", "-N", "",
		 "-C", "plain", "-f", str(key)],
		capture_output=True, timeout=30)
	assert proc.returncode == 0, proc.stderr
	return key


def fail_lines(result):
	"""The FAIL lines of the run."""
	return [line for line in result.out.splitlines() if line.startswith("FAIL ")]


def login_fail_line(result):
	"""The one FAIL line that names the admin login."""
	lines = [line for line in fail_lines(result) if "admin login to root@" in line]
	assert len(lines) == 1, result.out
	return lines[0]


def stopped_line(result):
	"""The STOPPED line of the run."""
	lines = [line for line in result.out.splitlines() if line.startswith("STOPPED ")]
	assert len(lines) == 1, result.out
	return lines[0]


def assert_before_stopped(result, line):
	"""The FAIL line comes before the STOPPED line."""
	out = result.out.splitlines()
	assert out.index(line) < out.index(stopped_line(result))


# -- 1. the password lane --------------------------------------------------

def test_upgrade_password_login_failure_names_the_lane_and_the_fix(setup_env):
	"""A refused root password login (ssh exit 255) on the password lane:
	one FAIL line before the STOPPED line, naming the lane and the way
	out (the plain-key lane)."""
	env = setup_env
	seed_known_hosts(env)
	env.router.update_state(password_auth=False)
	r = env.run(env.device, "upgrade", typed=(GOOD_PW,))
	assert r.rc == 1
	line = login_fail_line(r)
	# the wording is pinned: the lane, the way out and ssh's own words
	assert line == (
		"FAIL admin login to root@%s failed (password login). If the router "
		"refuses root passwords, rerun with --admin plain-key --plain-key "
		"<your admin key>. ssh said: root@%s: Permission denied."
		% (HOST, HOST))
	assert_before_stopped(r, line)
	assert stopped_line(r) == "STOPPED upgrade %s: upgrade step 2 failed" % env.device


def test_approval_key_login_failure_does_not_say_run_install_first(setup_env):
	"""approval-key: a refused admin login is not a missing install. The
	FAIL line names the lane, and the error says the login failed, not
	``run install first`` (the owner saw both on an installed
	router)."""
	env = setup_env
	seed_known_hosts(env)
	env.router.update_state(password_auth=False)
	r = env.run(env.device, "approval-key", typed=(GOOD_PW,))
	assert r.rc == 2
	login_fail_line(r)
	assert "run install first" not in r.err
	assert "error: the admin login failed (see the FAIL line above)" in r.err
	assert not env.router.path("etc/newton/approve.key").exists()


def test_install_password_login_failure_names_the_reason(setup_env):
	"""install: the same reason, before the install's STOPPED line."""
	env = setup_env
	seed_known_hosts(env)
	env.router.update_state(password_auth=False)
	r = env.run(env.device, "install", typed=(GOOD_PW, "yes"))
	assert r.rc == 1
	line = login_fail_line(r)
	assert "failed (password login)" in line
	assert_before_stopped(r, line)
	assert stopped_line(r) == "STOPPED install %s: install step 1 failed" % env.device


def test_check_password_login_failure_names_the_reason(setup_env):
	"""check: the report call is the admin call, and the reason is there
	too."""
	env = setup_env
	seed_known_hosts(env)
	env.router.update_state(password_auth=False)
	r = env.run(env.device, "check", typed=(GOOD_PW,))
	assert r.rc == 1
	line = login_fail_line(r)
	assert "failed (password login)" in line
	assert_before_stopped(r, line)


def test_add_key_password_login_failure_names_the_reason(setup_env):
	"""add-key: the reason is there too."""
	env = setup_env
	seed_known_hosts(env)
	env.router.update_state(password_auth=False)
	r = env.run(env.device, "add-key", "--new-key", "newton-agent", "change",
	            typed=(GOOD_PW,))
	assert r.rc == 1
	line = login_fail_line(r)
	assert "failed (password login)" in line
	assert_before_stopped(r, line)


def test_uninstall_password_login_failure_names_the_reason(setup_env):
	"""uninstall: the reason is there too."""
	env = setup_env
	seed_known_hosts(env)
	env.router.update_state(password_auth=False)
	r = env.run(env.device, "uninstall", typed=(GOOD_PW,))
	assert r.rc == 1
	line = login_fail_line(r)
	assert "failed (password login)" in line
	assert_before_stopped(r, line)


def test_the_host_key_learning_call_names_the_reason(setup_env):
	"""The first admin call of a check run learns the host key; when that
	login is refused the reason is printed before the error."""
	env = setup_env
	env.router.update_state(password_auth=False)
	r = env.run(env.device, "check", typed=(GOOD_PW,))
	assert r.rc == 2
	assert "cannot learn the host key" in r.err
	line = login_fail_line(r)
	assert "failed (password login)" in line


# -- 2. the plain-key lane -------------------------------------------------

def test_plain_key_login_failure_names_the_key(setup_env):
	"""The plain-key lane: the FAIL line names the key file and says what
	to check on the router."""
	env = setup_env
	seed_known_hosts(env)
	key = make_key(env)
	r = env.run("--admin", "plain-key", "--plain-key", str(key),
			env.device, "upgrade")
	assert r.rc == 1
	line = login_fail_line(r)
	assert line == (
		"FAIL admin login to root@%s failed (key %s). Check that the key is "
		"in the router's authorized keys. ssh said: root@%s: Permission "
		"denied." % (HOST, key, HOST))
	assert_before_stopped(r, line)


def test_the_plain_key_lane_works_with_an_authorized_key(pulsar_env):
	"""The same lane with a key the router knows: no FAIL line at all."""
	env = pulsar_env
	seed_known_hosts(env)
	r = env.run("--admin", "plain-key", "--plain-key", str(env.plain_key),
			env.device, "check", typed=(GOOD_PW, "DECOY"))
	assert r.rc == 0
	assert not [line for line in fail_lines(r) if "admin login" in line]


# -- 3. what is not a login failure ----------------------------------------

def test_a_failing_remote_command_is_not_a_login_failure(setup_env):
	"""The router command itself failed (exit 1, not 255): no admin-login
	FAIL line, and the run stops as before."""
	env = setup_env
	seed_known_hosts(env)
	env.router.update_state(fail_commands=["ubus call session list"])
	r = env.run(env.device, "upgrade", typed=(GOOD_PW,))
	assert r.rc == 1
	assert not [line for line in fail_lines(r) if "admin login" in line]
	assert stopped_line(r) == "STOPPED upgrade %s: upgrade step 2 failed" % env.device


def test_a_working_login_has_no_fail_line(setup_env):
	"""A run whose admin calls work prints no admin-login FAIL line and
	keeps its exit code."""
	env = setup_env
	seed_known_hosts(env)
	r = env.run(env.device, "check", typed=(GOOD_PW, "DECOY"))
	assert r.rc == 0
	assert not [line for line in fail_lines(r) if "admin login" in line]
	# the report still parses: the router's own lines are untouched
	assert any(line.startswith("INFO release ") for line in r.out.splitlines())
	assert "PASS tools 27/27 present" in r.out.splitlines()


# -- 4. the untrusted text -------------------------------------------------

def test_the_ssh_stderr_is_escaped(setup_env):
	"""ssh's stderr is router text: its control characters are escaped,
	never printed raw."""
	env = setup_env
	seed_known_hosts(env)
	env.router.update_state(password_auth=False,
			deny_stderr="\x1b[31mroot\x1b]0;title\x07")
	r = env.run(env.device, "upgrade", typed=(GOOD_PW,))
	line = login_fail_line(r)
	assert "\x1b" not in line
	assert "\x07" not in line
	assert "\\x1b[31mroot\\x1b]0;title\\x07" in line


def test_the_root_password_is_never_printed(setup_env):
	"""The typed root password never reaches the output, not even in the
	login-failure line."""
	env = setup_env
	seed_known_hosts(env)
	env.router.update_state(password_auth=False)
	env.register_secrets(GOOD_PW)
	r = env.run(env.device, "upgrade", typed=(GOOD_PW,))
	assert GOOD_PW not in r.out
	assert GOOD_PW not in r.err
	assert env.leaks() == []


def escape_text_call(data, max_bytes=None):
	"""The tool's own sanitiser, called the way the isolation tests call
	the installer's."""
	limit = "" if max_bytes is None else f" {max_bytes}"
	result = subprocess.run(
		[
			"bash",
			"-c",
			f'source scripts/newton-router-setup; escape_text "$1"{limit}',
			"escape_text",
			data,
		],
		cwd=str(ROOT),
		capture_output=True,
		timeout=10,
	)
	assert result.returncode == 0, result.stderr
	return result.stdout


def test_escape_text_escapes_terminal_control_bytes():
	out = escape_text_call(b"\x1b[31mred\x1b]0;title\x07\x1bOK\rworld\tend")
	assert out == b"\\x1b[31mred\\x1b]0;title\\x07\\x1bOK\\x0dworld\\x09end\n"


def test_escape_text_escapes_backslash_and_del():
	# the helper of scripts/newton-doctor (the one this script uses) leaves
	# the printable backslash alone and escapes only what is not printable
	assert escape_text_call(b"a\\b") == b"a\\b\n"
	assert escape_text_call(b"\x7f") == b"\\x7f\n"


def test_escape_text_truncates_long_input():
	out = escape_text_call(b"a" * 5000)
	assert out == b"a" * 200 + b"...[truncated]\n"


# -- what counts as a login failure ----------------------------------------------
#
# A login failure is a PROVEN connect or authentication failure.  The
# admin lane prefixes the remote command with a fixed marker written to
# the remote stderr (`echo NEWTON-ADMIN-SESSION >&2;`): the marker
# reaches the client only when the login worked and the remote command
# ran.  So an exit 255 WITH the marker is the remote command's own exit
# status (an init script that failed) and an exit 255 WITHOUT it is a
# connect or authentication failure -- the one case the FAIL line is
# about.
#
# Every real login failure of the run is recorded, in order, and a later
# successful call never erases the record; the run prints each recorded
# line once before it stops.


def swap_install(env):
	"""Install on pulsar through the plain-key admin path."""
	seed_known_hosts(env)
	r = env.run("--plain-key", env.plain_key, "pulsar", "install",
	            typed=("yes",))
	assert r.rc == 0, r.out + r.err
	return r


def swap(env):
	"""swap-key pulsar through the plain-key admin path."""
	return env.run("--plain-key", env.plain_key, "pulsar", "swap-key",
	               "--new-key")


def login_fail_lines(result):
	"""The FAIL lines that name the admin login."""
	return [line for line in fail_lines(result)
		if "admin login to root@" in line]


def test_a_tolerated_remote_failure_leaves_no_stale_login_line(pulsar_env):
	"""Review finding 1 (the stale line): a tolerated exit-255 call left
	the pending "admin login failed" line in the file, and a later
	unrelated stop printed it.

	The swap's replace call (sub-step 5) tolerates a failure: the run
	only logs it.  Here the remote command RAN and the router's shell
	exited 255, so the session marker was written and the login worked:
	the 255 is the remote command's own status, not a login failure.  The
	swap goes on and stops later, at the inventory write, and no admin
	login line may be printed there."""
	env = pulsar_env
	swap_install(env)
	env.router.add_authorized_key(EXTRA)
	env.router.update_state(rc_commands=[["new=$(awk -v blob=", 255]])
	# the inventory write fails, so the swap stops at a later, unrelated
	# step instead of finishing
	inv_dir = env.tmp / "inventory"
	inv_dir.mkdir()
	env.inventory = env.inventory.rename(inv_dir / "devices.toml")
	os.chmod(inv_dir, 0o555)
	try:
		r = swap(env)
	finally:
		os.chmod(inv_dir, 0o755)
	assert r.rc == 1, r.out + r.err
	assert r.out.splitlines()[-1] == (
		"STOPPED swap-key pulsar: cannot update the inventory")
	assert not login_fail_lines(r), r.out
	assert MARKER not in r.out and MARKER not in r.err


def test_a_real_login_failure_during_the_swap_is_reported_once(pulsar_env):
	"""The same swap, but the link drops at the replace call: the remote
	command never ran, so there is no session marker and the failure is a
	real connect failure.  The line is a true fact (the admin call really
	did fail), so it is printed -- once, before the STOPPED line -- even
	though the stop itself is about the old key."""
	env = pulsar_env
	swap_install(env)
	env.router.add_authorized_key(EXTRA)
	env.router.update_state(drop_commands=["old=$(awk"])
	r = swap(env)
	assert r.rc == 1, r.out + r.err
	assert r.out.splitlines()[-1] == (
		"STOPPED swap-key pulsar: the old key still works")
	lines = login_fail_lines(r)
	assert len(lines) == 1, r.out
	assert lines[0].startswith(
		"FAIL admin login to root@%s failed (key " % HOST), lines[0]
	assert_before_stopped(r, lines[0])
	assert MARKER not in r.out and MARKER not in r.err


def test_the_profile_upload_failure_survives_the_cleanup_call(setup_env):
	"""Review finding 2 (the erased line): the profile upload fails and
	the cleanup call that follows it (rm -f of the .new file) truncated
	the record of the failure, so the STOPPED line had no FAIL line at
	all.  The record of a real login failure is never truncated by a
	later successful call."""
	env = setup_env
	seed_known_hosts(env)
	# the upload's link drops: the remote command never ran, so there is
	# no session marker and the failure is a real connect failure
	env.router.update_state(drop_commands=["cat > "])
	r = env.run(env.device, "profile", "lab", typed=(GOOD_PW,))
	assert r.rc == 1, r.out + r.err
	assert stopped_line(r) == (
		"STOPPED profile %s: cannot write the profile file" % env.device)
	line = login_fail_line(r)
	assert_before_stopped(r, line)
	assert MARKER not in r.out and MARKER not in r.err


def test_a_remote_command_exit_255_is_not_a_login_failure(setup_env):
	"""Review finding 3 (the misclassified 255): ssh returns the remote
	command's exit status too, so an authenticated router command that
	fails with 255 must not produce the "fix your key/password" advice.
	The busy check of the upgrade (step 2) is the command: it runs and
	the router's shell exits 255, so the session marker is there and the
	login worked."""
	env = setup_env
	seed_known_hosts(env)
	env.router.update_state(rc_commands=[["guard_status=", 255]])
	r = env.run(env.device, "upgrade", typed=(GOOD_PW,))
	assert r.rc == 1, r.out + r.err
	assert stopped_line(r) == "STOPPED upgrade %s: upgrade step 2 failed" % env.device
	assert not login_fail_lines(r), r.out
	assert MARKER not in r.out and MARKER not in r.err


def test_a_working_run_prints_no_login_line_and_no_marker(setup_env):
	"""A run whose admin calls all work prints no admin-login line, and
	the session marker never reaches the output."""
	env = setup_env
	seed_known_hosts(env)
	r = env.run(env.device, "check", typed=(GOOD_PW, "DECOY"))
	assert r.rc == 0, r.out + r.err
	assert not login_fail_lines(r), r.out
	assert MARKER not in r.out and MARKER not in r.err
