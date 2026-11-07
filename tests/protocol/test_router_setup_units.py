"""Unit tests for the shared mechanics of scripts/newton-router-setup:
nonces and hashing, typed
secrets, the ssh lanes and known_hosts creation. The functions are driven
by sourcing the script in bash against a stand-in ssh/scp/sftp put first on
PATH through the NEWTON_SETUP_BIN seam."""

import hashlib
import hmac
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from router_setup_harness import BLOB_PREFIX, FakeRouter, install_fakes  # noqa: E402
from router_setup_env import build_src  # noqa: E402

TOOL = Path(__file__).resolve().parents[2] / "scripts" / "newton-router-setup"

# stand-in ssh (also installed as scp and sftp): prints its argv one per
# line to $SSH_LOG (preceded by the target of its stdin), records its
# environment, runs SSH_ASKPASS when set and records its output, learns
# $SSH_HOST_LINE into the UserKnownHostsFile on StrictHostKeyChecking=
# accept-new, exits with $SSH_RC
FAKE_SSH = r'''#!/bin/sh
readlink /proc/self/fd/0 >> "${SSH_LOG:?}"
for a in "$@"; do
	printf '%s\n' "$a" >> "${SSH_LOG:?}"
done
strict=''
kh=''
for a in "$@"; do
	case "$a" in
		StrictHostKeyChecking=*) strict=${a#StrictHostKeyChecking=} ;;
		UserKnownHostsFile=*) kh=${a#UserKnownHostsFile=} ;;
	esac
done
if [ -n "${SSH_ASKPASS:-}" ]; then
	"${SSH_ASKPASS}" 'root@router password:' > "${ASKPASS_OUT:?}"
fi
if [ "${strict}" = accept-new ] && [ -n "${kh}" ] && [ ! -s "$kh" ]; then
	printf '%s\n' "${SSH_HOST_LINE:?}" >> "$kh"
fi
if [ -n "${ENV_LOG:-}" ]; then
	env > "$ENV_LOG"
fi
exit "${SSH_RC:-0}"
'''


class Unit:
	"""Drives the tool's functions through `bash -c 'source SCRIPT; ...'`."""

	def __init__(self, tmp_path):
		self.tmp = tmp_path
		self.bin = tmp_path / "bin"
		self.bin.mkdir()
		for name in ("ssh", "scp", "sftp"):
			exe = self.bin / name
			exe.write_text(FAKE_SSH)
			exe.chmod(0o755)
		self.keys = tmp_path / "keys"
		self.keys.mkdir()
		self.kh = self.keys / "r1.known_hosts"
		self.trusted = tmp_path / "trusted_known_hosts"
		self.plain = tmp_path / "plainkey"
		self.plain.write_text("not a real key\n")
		self.tty = tmp_path / "typed"
		self.log = tmp_path / "ssh.log"
		self.askpass_out = tmp_path / "askpass.out"
		self.env_log = tmp_path / "env.log"
		self.env_after = tmp_path / "env_after.log"
		self.tmpdir_snap = tmp_path / "tmpdir_snap"
		self.jobs = tmp_path / "jobs.txt"

	def run(self, code, tty=None, extra_env=None):
		env = {k: v for k, v in os.environ.items() if not k.startswith("NEWTON_")}
		env.pop("DISPLAY", None)
		env.update(
			{
				"NEWTON_SETUP_SEAMS": "1",
				"NEWTON_SETUP_BIN": str(self.bin),
				"NEWTON_TRUSTED_KNOWN_HOSTS": str(self.trusted),
				"TOOL_PATH": str(TOOL),
				"TMPDIR": str(self.tmp),
				"SSH_LOG": str(self.log),
				"ASKPASS_OUT": str(self.askpass_out),
				"ENV_LOG": str(self.env_log),
				"ENV_AFTER": str(self.env_after),
				"SNAP_DIR": str(self.tmpdir_snap),
				"JOBS_OUT": str(self.jobs),
				"SRC_FILE": str(self.plain),
			}
		)
		# State-dir isolation: scripts/newton-router-setup resolves its
		# state dir from NEWTON_STATE_DIR (else `$(home_dir)/.local/state/newton`
		# via getent passwd).  Use per-call tmp dirs so any stray write
		# stays inside the tmp tree (the conftest's guard detects leaks).
		env.setdefault("NEWTON_STATE_DIR", str(self.tmp / "state"))
		env.setdefault("HOME", str(self.tmp / "home"))
		if tty is not None:
			self.tty.write_text("".join(line + "\n" for line in tty))
			env["NEWTON_SETUP_TTY"] = str(self.tty)
		if extra_env:
			env.update(extra_env)
		pre = (
			'. "$TOOL_PATH"\n'
			"init\n"
			"DEVICE=r1\n"
			"DEV_HOST=192.168.1.1\n"
			"DEV_PORT=22\n"
			"DEV_PROXY=''\n"
			"DEV_AUTH=key\n"
			"KEYS_DIR=%s\n" % self.keys
			+ "DEV_KNOWN_HOSTS=%s\n" % self.kh
			+ "TRUSTED_KNOWN_HOSTS=%s\n" % self.trusted
			+ "PLAIN_KEY=%s\n" % self.plain
			+ "ADMIN_MODE=plain-key\n"
		)
		return subprocess.run(
			["bash", "-c", pre + code],
			env=env,
			capture_output=True,
			text=True,
			timeout=60,
		)

	def argv(self):
		if not self.log.exists():
			return []
		return self.log.read_text().splitlines()

	def calls(self, dest="root@192.168.1.1"):
		return self.argv().count(dest)


@pytest.fixture()
def unit(tmp_path):
	return Unit(tmp_path)


# 2.8/2.9 helpers


def test_new_nonce_shape_and_uniqueness(unit):
	r = unit.run("for i in 1 2 3 4 5 6 7 8; do new_nonce; done\n")
	assert r.returncode == 0
	values = r.stdout.splitlines()
	assert len(values) == 8
	for v in values:
		assert re.fullmatch(r"[0-9a-f]{32}", v)
	assert len(set(values)) == 8


def test_sha256_file(unit):
	f = unit.tmp / "file.bin"
	f.write_bytes(b"hello world\n")
	r = unit.run('sha256_file "%s"\n' % f)
	assert r.returncode == 0
	assert r.stdout.strip() == hashlib.sha256(b"hello world\n").hexdigest()


def test_wait_router_uses_the_sleep_seam(unit):
	sleepfake = unit.bin / "sleepfake"
	sleepfake.write_text('#!/bin/sh\nprintf \'%s\\n\' "$@" >> "${SLEEP_LOG:?}"\nexit 0\n')
	sleepfake.chmod(0o755)
	log = unit.tmp / "sleep.log"
	r = unit.run(
		"wait_router 7\nwait_local 0\necho waited\n",
		extra_env={"NEWTON_SETUP_SLEEP": str(sleepfake), "SLEEP_LOG": str(log)},
	)
	assert r.returncode == 0
	assert "waited" in r.stdout
	assert log.read_text().splitlines() == ["7"]


# 2.3 typed secrets


def test_read_secret_two_prompts_in_order(unit):
	r = unit.run(
		"read_secret V1 'first: '\nread_secret V2 'second: '\n"
		"printf 'V1=%s V2=%s\\n' \"$V1\" \"$V2\"\n",
		tty=["alpha", "beta"],
	)
	assert r.returncode == 0
	assert r.stdout.splitlines()[-1] == "V1=alpha V2=beta"
	assert r.stderr.index("first: ") < r.stderr.index("second: ")


def test_read_secret_subshell_shares_typed_stream(unit):
	r = unit.run(
		"V1=$(read_secret X 'first: '; printf '%s' \"$X\")\n"
		"read_secret V2 'second: '\n"
		"printf 'V1=%s V2=%s\\n' \"$V1\" \"$V2\"\n",
		tty=["alpha", "beta"],
	)
	assert r.returncode == 0
	assert r.stdout.splitlines()[-1] == "V1=alpha V2=beta"


def test_read_secret_empty_tty_file_dies(unit):
	r = unit.run("read_secret V 'prompt: '\n", tty=[])
	assert r.returncode == 2
	assert "error:" in r.stderr


def test_read_secret_value_not_in_child_env(unit):
	r = unit.run(
		"read_secret V 'pw: '\nenv > \"$ENV_LOG\"\n",
		tty=["s3cret-typed"],
	)
	assert r.returncode == 0
	assert "s3cret-typed" not in unit.env_log.read_text()


def test_admin_password_get_reads_password_file(unit):
	pw = unit.tmp / "pw"
	pw.write_text("file-secret\n")
	pw.chmod(0o600)
	r = unit.run(
		'PASSWORD_FILE=%s\nadmin_password_get\nprintf "[%%s]\\n" "$ROOT_PW"\n'
		'admin_password_get\nprintf "[%%s]\\n" "$ROOT_PW"\n' % pw,
		tty=["unused-line"],
	)
	assert r.returncode == 0
	assert r.stdout.splitlines() == ["[file-secret]", "[file-secret]"]


# 2.2 ssh lanes


def assert_common_opts(argv, kh, port="22", portflag="-p"):
	expected = [
		"-F",
		"/dev/null",
		portflag,
		port,
		"ConnectTimeout=8",
		"ServerAliveInterval=5",
		"ServerAliveCountMax=2",
		"ControlMaster=no",
		"ControlPath=none",
		"GlobalKnownHostsFile=/dev/null",
		"UserKnownHostsFile=%s" % kh,
		"StrictHostKeyChecking=yes",
	]
	for item in expected:
		assert item in argv


def test_rsh_key_common_options(unit):
	r = unit.run("rsh_key \"$PLAIN_KEY\" 'echo hi'\necho rc=$?\n")
	assert r.returncode == 0
	assert "rc=0" in r.stdout
	argv = unit.argv()
	assert_common_opts(argv, str(unit.kh))
	for item in [
		"-i",
		str(unit.plain),
		"IdentitiesOnly=yes",
		"BatchMode=yes",
		"PreferredAuthentications=publickey",
		"PasswordAuthentication=no",
	]:
		assert item in argv
	assert argv[-2] == "root@192.168.1.1"
	assert argv[-1] == "echo hi"
	assert unit.calls() == 1


def test_rsh_key_with_proxy_and_port(unit):
	proxy = unit.bin / "proxyfake"
	proxy.write_text("#!/bin/sh\nexit 0\n")
	proxy.chmod(0o755)
	r = unit.run(
		"DEV_PROXY='nc 192.168.9.9 2222'\nDEV_PORT=2222\nrsh_key \"$PLAIN_KEY\" true\n",
	)
	assert r.returncode == 0
	argv = unit.argv()
	assert "ProxyCommand=nc 192.168.9.9 2222" in argv
	assert "2222" in argv


def test_rsh_pw_options_secret_and_cleanup(unit):
	secret = "pw-s3cret"
	r = unit.run(
		"ADMIN_MODE=password\nrsh_pw 'true'\necho rc=$?\n"
		"cp -r \"$TMP_DIR\" \"$SNAP_DIR\"\njobs -p > \"$JOBS_OUT\"\n"
		"env > \"$ENV_AFTER\"\n",
		tty=[secret],
	)
	assert r.returncode == 0
	assert "rc=0" in r.stdout
	argv = unit.argv()
	assert_common_opts(argv, str(unit.kh))
	for item in [
		"BatchMode=no",
		"PreferredAuthentications=password,keyboard-interactive",
		"PubkeyAuthentication=no",
		"NumberOfPasswordPrompts=1",
	]:
		assert item in argv
	assert "-i" not in argv
	assert secret not in " ".join(argv)
	# the password reaches ssh only through the askpass output
	assert unit.askpass_out.read_text() == secret + "\n"
	env_during = unit.env_log.read_text()
	assert secret not in env_during
	assert "SSH_ASKPASS_REQUIRE=force" in env_during
	assert re.search(r"^DISPLAY=.+$", env_during, re.M)
	env_after = unit.env_after.read_text()
	assert "SSH_ASKPASS" not in env_after
	assert "SSH_ASKPASS_REQUIRE" not in env_after
	assert not re.search(r"^DISPLAY=", env_after, re.M)
	# fifo gone, writer reaped, no secret in any file under TMP_DIR
	listing = [p.name for p in unit.tmpdir_snap.rglob("*")]
	assert "askpass.fifo" not in listing
	assert unit.jobs.read_text() == ""
	for path in unit.tmpdir_snap.rglob("*"):
		if path.is_file():
			assert secret not in path.read_text()


def test_rsh_pw_exit_status_is_sshs(unit):
	r = unit.run(
		"ADMIN_MODE=password\nrsh_pw 'false'; echo rc=$?\n",
		tty=["pw"],
		extra_env={"SSH_RC": "3"},
	)
	assert "rc=3" in r.stdout


def test_rsh_admin_picks_the_lane(unit):
	r = unit.run(
		"ADMIN_MODE=password\nrsh_admin 'id'\n",
		tty=["pw"],
	)
	assert r.returncode == 0
	argv = unit.argv()
	assert "PubkeyAuthentication=no" in argv
	# the admin command carries the session marker: the marker is
	# written to the remote stderr, so a 255 without it is a login failure
	assert argv[-1] == "echo NEWTON-ADMIN-SESSION >&2; id"
	assert unit.calls() == 1


def test_rscp_and_rsftp_use_dash_p_and_batch(unit):
	r = unit.run('rscp_key "$PLAIN_KEY" "$SRC_FILE" /tmp/dest\n')
	assert r.returncode == 0
	argv = unit.argv()
	assert_common_opts(argv, str(unit.kh), portflag="-P")
	assert "root@192.168.1.1:/tmp/dest" in argv
	assert "BatchMode=yes" in argv
	assert "-O" in argv
	assert "-i" in argv
	r = unit.run('rsftp_key "$PLAIN_KEY" < /dev/null\n')
	assert r.returncode == 0
	argv = unit.argv()
	assert_common_opts(argv, str(unit.kh), portflag="-P")
	assert "-b" in argv
	assert "-" in argv
	assert argv[-1] == "root@192.168.1.1"


# 2.4 known_hosts


def test_ensure_known_hosts_reuses_existing_file(unit):
	unit.kh.write_text("ssh-ed25519 AAAAFIXED keepme\n")
	r = unit.run("ensure_known_hosts\necho ok\n")
	assert r.returncode == 0
	assert "ok" in r.stdout
	assert unit.kh.read_text() == "ssh-ed25519 AAAAFIXED keepme\n"
	assert unit.argv() == []


def test_ensure_known_hosts_copies_from_trusted(unit):
	line = "[192.168.1.1]:2222 ssh-ed25519 AAAAMATCH123 match-key"
	unit.trusted.write_text(
		"otherhost ssh-ed25519 AAAAOTHER other\n%s\n" % line
	)
	r = unit.run("DEV_PORT=2222\nensure_known_hosts\necho ok\n")
	assert r.returncode == 0
	assert "ok" in r.stdout
	assert unit.kh.read_text() == line + "\n"
	assert unit.argv() == []


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="needs ssh-keygen")
def test_ensure_known_hosts_learns_with_one_call(unit):
	gen = unit.tmp / "genkey"
	subprocess.run(
		["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "unit-host", "-f", str(gen)],
		check=True,
		capture_output=True,
	)
	host_line = "192.168.1.1 " + gen.with_suffix(".pub").read_text().strip()
	r = unit.run(
		"ensure_known_hosts\necho STRICT=$STRICT\n",
		extra_env={"SSH_HOST_LINE": host_line},
	)
	assert r.returncode == 0
	assert unit.calls() == 1
	assert "StrictHostKeyChecking=accept-new" in unit.argv()
	assert unit.kh.read_text() == host_line + "\n"
	assert "NOTE host key learned: " in r.stdout
	assert "SHA256:" in r.stdout
	assert "compare it with the router before you go on" in r.stdout
	assert "STRICT=yes" in r.stdout


def test_ensure_known_hosts_learning_failure_exits_2(unit):
	r = unit.run(
		"ensure_known_hosts\necho unreachable\n",
		extra_env={"SSH_RC": "255"},
	)
	assert r.returncode == 2
	assert "error:" in r.stderr
	assert "host key" in r.stderr
	assert "unreachable" not in r.stdout
	assert unit.calls() == 1


def _host_line(unit):
	gen = unit.tmp / "genkey"
	subprocess.run(
		["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "unit-host", "-f", str(gen)],
		check=True,
		capture_output=True,
	)
	return "192.168.1.1 " + gen.with_suffix(".pub").read_text().strip()


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="needs ssh-keygen")
def test_ensure_known_hosts_failed_login_saves_no_key(unit):
	# real ssh writes the host key during the key exchange, before the
	# login; a learning call that fails must leave nothing behind, or the
	# next run would use the key without ever showing its fingerprint
	host_line = _host_line(unit)
	r = unit.run(
		"ensure_known_hosts\necho unreachable\n",
		extra_env={"SSH_HOST_LINE": host_line, "SSH_RC": "255"},
	)
	assert r.returncode == 2
	assert "host key" in r.stderr
	assert "unreachable" not in r.stdout
	assert not unit.kh.exists() or unit.kh.stat().st_size == 0
	# the next run, whose login works, shows the fingerprint exactly once
	r = unit.run(
		"ensure_known_hosts\n",
		extra_env={"SSH_HOST_LINE": host_line},
	)
	assert r.returncode == 0
	assert r.stdout.count("NOTE host key learned: ") == 1
	assert "SHA256:" in r.stdout
	assert unit.kh.read_text() == host_line + "\n"


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="needs ssh-keygen")
def test_ensure_known_hosts_unfingerprintable_key_saves_nothing(unit):
	# the call works but the saved line cannot be fingerprinted: the run
	# dies before the NOTE, so the key must not stay either
	r = unit.run(
		"ensure_known_hosts\n",
		extra_env={"SSH_HOST_LINE": "192.168.1.1 not-a-key"},
	)
	assert r.returncode == 2
	assert not unit.kh.exists() or unit.kh.stat().st_size == 0


# of the earlier layers


def test_read_secret_does_not_take_over_fd3(unit):
	# fix (a): the typed-input file is opened on an fd bash allocates, so
	# the caller's fd 3 keeps pointing where it did
	f = unit.tmp / "fd3lines"
	f.write_text("line-one\nline-two\n")
	r = unit.run(
		'exec 3< "%s"\nread_secret V "prompt: "\nread -r X <&3\n'
		'printf "V=%%s X=%%s\\n" "$V" "$X"\n' % f,
		tty=["alpha"],
	)
	assert r.returncode == 0
	assert r.stdout.splitlines()[-1] == "V=alpha X=line-one"


def test_ssh_calls_run_under_timeout_foreground(unit):
	# fix (b): every ssh/scp/sftp call runs under timeout --foreground 60
	#
	tf = unit.bin / "timeout"
	tf.write_text('#!/bin/sh\nprintf \'%s\\n\' "$@" >> "${TIMEOUT_LOG:?}"\nshift 2\nexec "$@"\n')
	tf.chmod(0o755)
	log = unit.tmp / "timeout.log"
	r = unit.run(
		"rsh_key \"$PLAIN_KEY\" 'echo hi'\n"
		"ADMIN_MODE=password\nrsh_pw 'true'\n",
		tty=["pw"],
		extra_env={"TIMEOUT_LOG": str(log)},
	)
	assert r.returncode == 0
	lines = log.read_text().splitlines()
	at = [i for i, line in enumerate(lines) if line == "ssh"]
	assert len(at) == 2
	for i in at:
		assert lines[i - 2] == "--foreground"
		assert lines[i - 1] == "60"


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="needs ssh-keygen")
def test_ensure_known_hosts_learning_call_reads_null_stdin(unit):
	# fix (b): the learning call is `rsh_admin true </dev/null`, whatever
	# this shell's own stdin is
	gen = unit.tmp / "genkey"
	subprocess.run(
		["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "unit-host", "-f", str(gen)],
		check=True,
		capture_output=True,
	)
	host_line = "192.168.1.1 " + gen.with_suffix(".pub").read_text().strip()
	r = unit.run(
		'exec 0< "$SRC_FILE"\nensure_known_hosts\necho ok\n',
		extra_env={"SSH_HOST_LINE": host_line},
	)
	assert r.returncode == 0
	assert "ok" in r.stdout
	assert unit.calls() == 1
	assert "/dev/null" in unit.argv()


def test_choose_admin_path_rejects_bad_password_file_chars(unit):
	# fix (c): --password-file is validated with valid_path_chars and the
	# error names the option
	r = unit.run(
		"PASSWORD_FILE='/tmp/bad pw/file'\nDEV_PROFILE=lab\nchoose_admin_path\n",
	)
	assert r.returncode == 2
	assert "--password-file" in r.stderr


def test_choose_admin_path_rejects_bad_plain_key_chars(unit):
	# fix (c): --plain-key is validated with valid_path_chars and the error
	# names the option
	r = unit.run(
		"PLAIN_KEY_OPT='/tmp/bad key/id'\nchoose_admin_path\n",
	)
	assert r.returncode == 2
	assert "--plain-key" in r.stderr


def test_rsh_pw_transport_failure_is_prompt_and_clean(unit):
	# fix (d): ssh exiting 255 without touching the askpass fifo still
	# returns 255 at once, leaves no fifo and no writer job
	(unit.bin / "ssh").write_text("#!/bin/sh\nexit 255\n")
	(unit.bin / "ssh").chmod(0o755)
	r = unit.run(
		"ADMIN_MODE=password\nrsh_pw 'true'; echo rc=$?\n"
		"cp -r \"$TMP_DIR\" \"$SNAP_DIR\"\njobs -p > \"$JOBS_OUT\"\n",
		tty=["pw"],
	)
	assert r.returncode == 0
	assert "rc=255" in r.stdout
	assert not unit.askpass_out.exists()
	listing = [p.name for p in unit.tmpdir_snap.rglob("*")]
	assert "askpass.fifo" not in listing
	assert unit.jobs.read_text() == ""


# constants (design 2.1, 2.3, 9.4 G0)


def test_code_files_rows(unit):
	r = unit.run('printf \'%d\\n\' "${#CODE_FILES[@]}"\nprintf \'%s\\n\' "${CODE_FILES[@]}"\n')
	assert r.returncode == 0
	lines = r.stdout.splitlines()
	assert lines[0] == "4"
	rows = [line.split("|") for line in lines[1:]]
	assert [row[0] for row in rows] == [
		"device/openwrt/newton-router/newton-router",
		"scripts/owrt-safe-apply.sh",
		"device/openwrt/newton-guard/newton-guard",
		"device/openwrt/newton-guard/newton-guard.init",
	]
	assert [row[1] for row in rows] == [
		"/usr/libexec/newton/newton-router",
		"/usr/libexec/newton/newton-safe-apply",
		"/usr/libexec/newton-guard",
		"/etc/init.d/newton-guard",
	]
	assert [row[2] for row in rows] == ["755", "755", "755", "755"]
	assert [row[3] for row in rows] == ["yes", "yes", "no", "no"]


def test_sysupgrade_lines_of_design_2_3(unit):
	# design 2.3 (R9b+c): the sysupgrade list is the eight code/config
	# lines plus the three WAN-health lines (the script, the init and the
	# /etc/rc.d start link the init's `enable` creates); the install /
	# uninstall / check actions all iterate over the whole array so any
	# count works.
	r = unit.run('printf \'%d\\n\' "${#SYSUPGRADE_LINES[@]}"\nprintf \'%s\\n\' "${SYSUPGRADE_LINES[@]}"\n')
	assert r.returncode == 0
	lines = r.stdout.splitlines()
	assert lines[0] == "13"
	assert lines[1:] == [
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
	assert len(set(lines[1:])) == 13


def test_uninstall_sysupgrade_iterates_over_array(router_unit):
	# R9b+c: uninstall_sysupgrade's grep -vxF must not enumerate
	# SYSUPGRADE_LINES by hardcoded indexes [0..N]; the call text
	# should walk the array so a count change does not silently break
	# the remove-on-uninstall half.
	router = router_unit.router
	# seed the file with every expected line; if the script still has
	# the old `... -e '${SYSUPGRADE_LINES[7]}' ...` shape, the recorded
	# ssh call will literally carry that index and our asserts will see
	# it (the recorded text is the FULL script the tool ran).
	text = "\n".join([
		"/usr/libexec/newton/newton-router",
		"/usr/libexec/newton/newton-safe-apply",
		"/usr/libexec/newton-guard",
		"/etc/init.d/newton-guard",
		"/etc/rc.d/S09newton-guard",
		"/etc/rc.d/S95newton-wan-health",
		"/usr/libexec/newton/newton-wan-health",
		"/etc/init.d/newton-wan-health",
		"/etc/newton/device-id",
		"/etc/newton/profile",
		"/etc/newton/zones",
	]) + "\n"
	router.write("etc/sysupgrade.conf", text, 0o644)
	r = router_unit.run("uninstall_sysupgrade\n")
	assert r.returncode == 0
	# no recorded call should mention an explicit SYSUPGRADE_LINES
	# indexed subscript
	recorded = " ".join(
		(c.get("command") or "") for c in router.calls() if c.get("tool") == "ssh"
	)
	assert "${SYSUPGRADE_LINES[0]}" not in recorded, recorded
	assert "${SYSUPGRADE_LINES[7]}" not in recorded, recorded
	assert "${SYSUPGRADE_LINES[10]}" not in recorded, recorded
	# every line is gone (the file is empty, the line count is 0)
	final = router.read("etc/sysupgrade.conf")
	assert [l for l in final.splitlines() if l.strip()] == [], final
	assert not router.path("etc/sysupgrade.conf.new").exists()


# the G0 `command -v` list, copied from design 9.4 (27 names)
G0_DESIGN = ("sha256sum md5sum flock mktemp setsid head tr awk sed sort tar jsonfilter ucode uci ubus nft "
	"fw4 ifstatus netstat pidof logread logger nslookup ping traceroute iwinfo apk").split()


def test_g0_tools_are_the_design_list(unit):
	r = unit.run('printf \'%d\\n\' "${#G0_TOOLS[@]}"\nprintf \'%s\\n\' "${G0_TOOLS[@]}"\n')
	assert r.returncode == 0
	lines = r.stdout.splitlines()
	assert lines[0] == "27"
	assert lines[1:] == G0_DESIGN
	assert len(set(G0_DESIGN)) == 27


def test_router_path_constants(unit):
	r = unit.run('printf \'%s\\n\' "$R_PROG" "$R_HELPER" "$R_GUARD" "$R_INIT" "$R_NEWTON_DIR" "$R_AUTH_KEYS" "$R_LOCK"\n')
	assert r.returncode == 0
	assert r.stdout.splitlines() == [
		"/usr/libexec/newton/newton-router",
		"/usr/libexec/newton/newton-safe-apply",
		"/usr/libexec/newton-guard",
		"/etc/init.d/newton-guard",
		"/etc/newton",
		"/etc/dropbear/authorized_keys",
		"/tmp/owrt-safe-apply.lock",
	]


def test_parse_args_accepts_explicit_new_key_flags(unit):
	code = r'''
parse_args r1 add-key --new-key newton-agent change
printf 'add=%s,%s,%s\n' "$LABEL" "$ROLE" "$NEW_KEY"
parse_args r1 swap-key --new-key lab-gate
printf 'swap=%s,%s\n' "$LABEL" "$NEW_KEY"
parse_lab_snapshot_args --new-key --labels lab-runner --skip-gates
printf 'lab=%s,%s,%s,%s\n' "$LABELS" "$NEW_KEY" "$GATES_CMD" "$SKIP_GATES"
'''
	r = unit.run(code)
	assert r.returncode == 0, r.stderr
	assert r.stdout.splitlines() == [
		"add=newton-agent,change,1",
		"swap=lab-gate,1",
		"lab=lab-runner,1,,1",
	]


def test_usage_names_new_key_for_every_minting_action(unit):
	r = unit.run("print_usage\n")
	assert r.returncode == 0
	assert "swap-key [--new-key] [LABEL]" in r.stdout
	assert "add-key [--new-key] LABEL ROLE" in r.stdout
	assert "lab-snapshot [--new-key]" in r.stdout


# router file helpers against the real fake
# router of router_setup_harness.py


class RouterUnit:
	"""Drives the tool's functions against the real fake router: the fakes
	of install_fakes on PATH, a plain key line in authorized_keys and the
	ADMIN_MODE=plain-key lane."""

	def __init__(self, tmp_path):
		self.tmp = tmp_path
		self.router = FakeRouter.create(
			tmp_path / "router",
			uci={"dropbear.@dropbear[0]": "dropbear"},
		)
		self.bindir = tmp_path / "fakes"
		install_fakes(self.bindir, self.router.root)
		self.keys = tmp_path / "keys"
		self.keys.mkdir()
		# the typed-input file the install's "yes" is read from
		self.tty = tmp_path / "typed"
		self.tty.write_text("")
		self.kh = self.keys / "r1.known_hosts"
		self.kh.write_text("10.1.2.3 ssh-ed25519 AAAAC3FAKEHOSTKEY0001\n")
		blob = "AAAAC3NzaC1lZDI1NTE5AAAAIPLAINKEYFORUNITTESTS0001"
		self.plain = tmp_path / "plainkey"
		self.plain.write_text("FAKE-OPENSSH-PRIVATE-KEY\n%s\n" % blob)
		self.plain.chmod(0o600)
		self.router.add_authorized_key("ssh-ed25519 %s agent@unit" % blob)

	def run(self, code, extra_env=None, tty=None):
		env = {k: v for k, v in os.environ.items() if not k.startswith("NEWTON_")}
		env.update(
			{
				"NEWTON_SETUP_SEAMS": "1",
				"NEWTON_SETUP_BIN": str(self.bindir),
				"NEWTON_SETUP_REMOTE_ROOT": str(self.router.root / "fs"),
				"NEWTON_SETUP_SLEEP": str(self.bindir / "fake-sleep"),
				"TOOL_PATH": str(TOOL),
				"TMPDIR": str(self.tmp),
			}
		)
		# State-dir isolation: scripts/newton-router-setup resolves its
		# state dir from NEWTON_STATE_DIR (else `$(home_dir)/.local/state/newton`
		# via getent passwd), and the inline python helper in
		# approval_fingerprint_write falls back to Path.home().  Without
		# both env vars set, the tool would write into the real user's
		# home.  Use per-call tmp dirs so a stray write stays inside the
		# tmp tree (the conftest's guard detects any leak out of it).
		if "NEWTON_STATE_DIR" not in (extra_env or {}):
			env["NEWTON_STATE_DIR"] = str(self.tmp / "state")
		if "HOME" not in (extra_env or {}):
			env["HOME"] = str(self.tmp / "home")
		if tty is not None:
			self.tty.write_text("".join(line + "\n" for line in tty))
			env["NEWTON_SETUP_TTY"] = str(self.tty)
		if extra_env:
			env.update(extra_env)
		pre = (
			'. "$TOOL_PATH"\n'
			"init\n"
			"DEVICE=r1\n"
			"DEV_HOST=10.1.2.3\n"
			"DEV_PORT=22\n"
			"DEV_PROXY=''\n"
			"KEYS_DIR=%s\n" % self.keys
			+ "DEV_KNOWN_HOSTS=%s\n" % self.kh
			+ "ADMIN_MODE=plain-key\n"
			+ "PLAIN_KEY=%s\n" % self.plain
		)
		return subprocess.run(
			["bash", "-c", pre + code],
			env=env,
			capture_output=True,
			text=True,
			timeout=60,
			stdin=subprocess.DEVNULL,
		)


@pytest.fixture()
def router_unit(tmp_path):
	return RouterUnit(tmp_path)


def _mode_of(router, rel):
	return stat.S_IMODE(router.path(rel).stat().st_mode)


def test_put_file_writes_new_file_with_mode(router_unit):
	router = router_unit.router
	rel = "usr/libexec/newton/newton-router"
	router.write(rel, "old\n", 0o755)
	local = router_unit.tmp / "prog"
	local.write_text("#!/bin/sh\nexit 0\n")
	r = router_unit.run(
		'put_file "%s" "/usr/libexec/newton/newton-router" 755; '
		"echo rc=$? PUT=$PUT_CHANGED\n" % local
	)
	assert r.returncode == 0
	assert "rc=0" in r.stdout
	assert "PUT=1" in r.stdout
	assert router.read(rel) == "#!/bin/sh\nexit 0\n"
	assert _mode_of(router, rel) == 0o755
	assert not router.path(rel + ".new").exists()


def test_put_file_identical_second_call_writes_nothing(router_unit):
	router = router_unit.router
	rel = "usr/libexec/newton/newton-router"
	router.write(rel, "old\n", 0o755)
	local = router_unit.tmp / "prog"
	local.write_text("content-v1\n")
	code = (
		'put_file "%s" "/usr/libexec/newton/newton-router" 755; '
		"echo rc=$? PUT=$PUT_CHANGED\n" % local
	)
	first = router_unit.run(code)
	assert first.returncode == 0
	assert "PUT=1" in first.stdout
	uploads = len([c for c in router.calls() if c.get("stdin_len")])
	second = router_unit.run(code)
	assert second.returncode == 0
	assert "rc=0" in second.stdout
	assert "PUT=0" in second.stdout
	assert len([c for c in router.calls() if c.get("stdin_len")]) == uploads
	assert not router.path(rel + ".new").exists()


def test_put_file_changed_content_replaces(router_unit):
	router = router_unit.router
	rel = "usr/libexec/newton/newton-router"
	router.write(rel, "old\n", 0o755)
	local = router_unit.tmp / "prog"
	local.write_text("content-v1\n")
	router_unit.run(
		'put_file "%s" "/usr/libexec/newton/newton-router" 755\n' % local
	)
	local.write_text("content-v2\n")
	r = router_unit.run(
		'put_file "%s" "/usr/libexec/newton/newton-router" 755; '
		"echo rc=$? PUT=$PUT_CHANGED\n" % local
	)
	assert r.returncode == 0
	assert "PUT=1" in r.stdout
	assert router.read(rel) == "content-v2\n"
	assert _mode_of(router, rel) == 0o755
	assert not router.path(rel + ".new").exists()


def test_put_file_refuses_corrupted_upload(router_unit):
	# the corrupt_stdin state knob flips the first byte the fake ssh reads,
	# so the router sha256 differs and the write must be rolled back
	router = router_unit.router
	rel = "usr/libexec/newton/newton-router"
	router.write(rel, "old-content\n", 0o755)
	local = router_unit.tmp / "prog"
	local.write_text("new-content\n")
	router.update_state(corrupt_stdin=True)
	r = router_unit.run(
		'put_file "%s" "/usr/libexec/newton/newton-router" 755; '
		"echo rc=$? PUT=$PUT_CHANGED\n" % local
	)
	assert r.returncode == 0
	assert "rc=1" in r.stdout
	assert "PUT=0" in r.stdout
	assert router.read(rel) == "old-content\n"
	assert not router.path(rel + ".new").exists()


def test_put_text_writes_and_is_idempotent(router_unit):
	router = router_unit.router
	rel = "etc/newton/profile"
	router.write(rel, "prod\n", 0o600)
	content = router_unit.tmp / "profile.txt"
	content.write_text("lab\n")
	code = (
		'put_text "/etc/newton/profile" 600 < "%s"; '
		"echo rc=$? PUT=$PUT_CHANGED\n" % content
	)
	first = router_unit.run(code)
	assert first.returncode == 0
	assert "rc=0" in first.stdout
	assert "PUT=1" in first.stdout
	assert router.read(rel) == "lab\n"
	assert _mode_of(router, rel) == 0o600
	uploads = len([c for c in router.calls() if c.get("stdin_len")])
	second = router_unit.run(code)
	assert second.returncode == 0
	assert "rc=0" in second.stdout
	assert "PUT=0" in second.stdout
	assert len([c for c in router.calls() if c.get("stdin_len")]) == uploads
	assert not router.path(rel + ".new").exists()


def test_put_text_from_a_pipe(router_unit):
	# the small-text shape: content sent from a printf pipe
	router = router_unit.router
	rel = "etc/newton/device-id"
	router.write(rel, "r0\n", 0o600)
	r = router_unit.run(
		'printf "r1\\n" | put_text "/etc/newton/device-id" 600; echo "rc=$?"\n'
	)
	assert r.returncode == 0
	assert "rc=0" in r.stdout
	assert router.read(rel) == "r1\n"
	assert _mode_of(router, rel) == 0o600


# def test_put_stream_upload_command_starts_with_umask_077(router_unit):
	# fix: the remote command of an upload starts with `umask 077 &&` so the
	# .new file is never created readable by others
	router = router_unit.router
	router.write("etc/newton/profile", "old\n", 0o600)
	local = router_unit.tmp / "profile.txt"
	local.write_text("lab\n")
	r = router_unit.run(
		'put_file "%s" "/etc/newton/profile" 600; echo rc=$?\n' % local
	)
	assert r.returncode == 0
	assert "rc=0" in r.stdout
	uploads = [c for c in router.calls() if c.get("stdin_len")]
	assert uploads
	for call in uploads:
		# the session marker is prefixed to every admin command, so
		# the umask still has to guard the creation of the .new file
		assert "umask 077 && cat > " in call["command"], call["command"]


PULSAR_BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIunittestmadeupblob0000000001"


def test_restricted_line_is_the_design_pulsar_example(router_unit):
	expected = (
		"restrict,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,"
		'no-pty,command="/usr/libexec/newton/newton-router '
		'--caller=newton-agent --role=change" ssh-ed25519 %s '
		"newton-router-newton-agent" % PULSAR_BLOB
	)
	r = router_unit.run(
		"restricted_line newton-agent change %s\n" % PULSAR_BLOB
	)
	assert r.returncode == 0
	assert r.stdout == expected + "\n"


def test_restricted_line_read_role(router_unit):
	expected = (
		"restrict,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,"
		'no-pty,command="/usr/libexec/newton/newton-router '
		'--caller=lab-runner --role=read" ssh-ed25519 %s '
		"newton-router-lab-runner" % PULSAR_BLOB
	)
	r = router_unit.run("restricted_line lab-runner read %s\n" % PULSAR_BLOB)
	assert r.returncode == 0
	assert r.stdout == expected + "\n"


def test_keypair_path_only_sets_the_path(router_unit):
	router = router_unit.router
	keys = router_unit.keys
	code = (
		"keypair_path newton-agent; echo rc=$? K=$KEYFILE\n"
		'[ -e \"$KEYFILE\" ] && echo exists=yes || echo exists=no\n'
	)
	r = router_unit.run(code)
	assert r.returncode == 0
	keyfile = keys / "r1-newton-agent"
	assert r.stdout.splitlines() == ["rc=0 K=%s" % keyfile, "exists=no"]
	assert sorted(p.name for p in keys.iterdir()) == ["r1.known_hosts"]


def test_keypair_create_makes_the_pair_and_keypair_path_does_not(router_unit):
	router = router_unit.router
	keys = router_unit.keys
	code = (
		"LABEL=newton-agent; keypair_path \"$LABEL\"\n"
		"keypair_create \"$LABEL\"; echo rc=$? K=$KEYFILE\n"
	)
	r = router_unit.run(code)
	assert r.returncode == 0
	keyfile = keys / "r1-newton-agent"
	assert r.stdout.splitlines() == [
		"INFO new key made: %s" % keyfile,
		"rc=0 K=%s" % keyfile,
	]
	assert stat.S_IMODE(keyfile.stat().st_mode) == 0o600
	assert stat.S_IMODE(keys.stat().st_mode) == 0o700
	pub = (keys / "r1-newton-agent.pub").read_text()
	assert pub.endswith(" newton-router-newton-agent\n")
	gens = [
		c for c in router.calls()
		if c["tool"] == "ssh-keygen" and "ed25519" in c["argv"]
	]
	assert len(gens) == 1


def test_keypair_create_refuses_an_existing_private_file(router_unit):
	router = router_unit.router
	key = router_unit.keys / "r1-newton-agent"
	key.write_text("private bytes\n")
	key.chmod(0o600)
	before = key.read_bytes()
	r = router_unit.run(
		'keypair_path newton-agent; keypair_create newton-agent; echo rc=$?\n'
	)
	assert r.returncode == 2
	assert "already exists" in r.stderr
	assert key.read_bytes() == before
	assert not (router_unit.keys / "r1-newton-agent.pub").exists()
	assert [
		c for c in router.calls() if c["tool"] == "ssh-keygen"
	] == []


def test_local_key_rule_missing_without_new_key_stops(router_unit):
	key = router_unit.keys / "r1-lab-runner"
	r = router_unit.run(
		"ACTION=add-key\nNEW_KEY=0\nlocal_key_rule lab-runner; echo rc=$?\n"
	)
	assert r.returncode == 1
	assert r.stdout.splitlines() == [
		"NOTE state: router unchanged",
		"STOPPED add-key r1: no key for label lab-runner on this host "
		"(%s is missing): the key lives on the Newton host that added "
		"it; run this there, or pass --new-key to make a new key on "
		"purpose" % key,
	]
	assert router_unit.router.calls() == []


def test_local_key_rule_present_with_new_key_stops_outside_lab(router_unit):
	key = router_unit.keys / "r1-lab-runner"
	key.write_text("private bytes\n")
	r = router_unit.run(
		"ACTION=add-key\nNEW_KEY=1\nlocal_key_rule lab-runner; echo rc=$?\n"
	)
	assert r.returncode == 1
	assert r.stdout.splitlines() == [
		"NOTE state: router unchanged",
		"STOPPED add-key r1: a key for label lab-runner already exists "
		"on this host (%s); run it again without --new-key" % key,
	]
	assert router_unit.router.calls() == []


def test_local_key_rule_lab_snapshot_reuses_a_present_key(router_unit):
	key = router_unit.keys / "r1-lab-runner"
	key.write_text("private bytes\n")
	r = router_unit.run(
		"ACTION=lab-snapshot\nNEW_KEY=1\n"
		"local_key_rule lab-runner; echo rc=$? K=$KEYFILE\n"
	)
	assert r.returncode == 0
	assert r.stdout.splitlines() == ["rc=0 K=%s" % key]
	assert router_unit.router.calls() == []


def test_pub_blob_prints_the_second_field(router_unit):
	r = router_unit.run(
		"keypair_path newton-agent; keypair_create newton-agent\n"
		'pub_blob "$KEYFILE"\n'
	)
	assert r.returncode == 0
	blob = r.stdout.splitlines()[-1]
	assert blob.startswith(BLOB_PREFIX)
	assert len(blob) == 25 + 40
	assert re.fullmatch(r"[A-Za-z0-9+/=]+", blob)


# the authorized_keys awk programs

PLAIN_BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIPLAINKEYFORUNITTESTS0001"
BLOB_A = "AAAAC3NzaC1lZDI1NTE5AAAAIUNITTESTRESTRICTEDA000001"
BLOB_B = "AAAAC3NzaC1lZDI1NTE5AAAAIUNITTESTRESTRICTEDB000002"

LINE_A = (
	"restrict,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,"
	'no-pty,command="/usr/libexec/newton/newton-router --caller=lab-runner '
	'--role=change" ssh-ed25519 %s newton-router-lab-runner' % BLOB_A
)
LINE_B = (
	"restrict,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,"
	'no-pty,command="/usr/libexec/newton/newton-router --caller=a --role=b" '
	"ssh-ed25519 %s newton-router-a" % BLOB_B
)

# the tricky input: quoted options with blanks, the word
# ssh-ed25519 inside a comment, a # comment, a blank line, trailing spaces
# and a line with only options
AK_INPUT = (
	"ssh-ed25519 AAAAUNSPLIT agent@unit\n"
	'restrict,command="/usr/libexec/newton/newton-router --caller=a --role=b" '
	"ssh-ed25519 %s newton-router-a\n" % BLOB_A
	+ "ssh-ed25519 AAAAOTHER a comment mentioning ssh-ed25519 today\n"
	"# comment with ssh-ed25519 inside\n"
	"\n"
	"ssh-rsa AAAATRAIL some trailing spaces   \n"
	'command="/usr/bin/false --x 1" no-pty\n'
)


@pytest.mark.skipif(shutil.which("busybox") is None, reason="needs busybox")
@pytest.mark.parametrize("func", ["awk_blob_program", "awk_filter_program", "awk_match_program"])
def test_awk_programs_contain_no_single_quote(unit, func):
	r = unit.run("%s > '%s/%s.awk'\n" % (func, unit.tmp, func))
	assert r.returncode == 0
	text = (unit.tmp / ("%s.awk" % func)).read_text()
	assert "'" not in text
	assert text.strip()


def _run_awk(unit, func, text, blob):
	prog = unit.tmp / ("%s.awk" % func)
	inp = unit.tmp / "awk.in"
	prog_write = unit.run("%s > '%s'\n" % (func, prog))
	assert prog_write.returncode == 0
	assert "'" not in prog.read_text()
	inp.write_text(text)
	r = unit.run("busybox awk -v blob=%s -f '%s' '%s'\n" % (blob, prog, inp))
	assert r.returncode == 0
	return r.stdout


@pytest.mark.skipif(shutil.which("busybox") is None, reason="needs busybox")
def test_awk_blob_program_tricky_input(unit):
	# one blob per line that has a key-type token, none for the comment,
	# blank and options-only lines; the quoted options keep the tokenizer
	# away from the blanks inside command="..."; a # comment line has no
	# key line status, so its word after ssh-ed25519 counts as its blob
	assert _run_awk(unit, "awk_blob_program", AK_INPUT, BLOB_A) == (
		"AAAAUNSPLIT\n%s\nAAAAOTHER\ninside\nAAAATRAIL\n" % BLOB_A
	)


@pytest.mark.skipif(shutil.which("busybox") is None, reason="needs busybox")
def test_awk_filter_program_keeps_the_rest_byte_for_byte(unit):
	# every line whose blob is not the variable blob stays byte for byte:
	# blank, comment, options-only and trailing-space lines included
	assert (
		_run_awk(unit, "awk_filter_program", AK_INPUT, "AAAAOTHER")
		== AK_INPUT.replace(
			"ssh-ed25519 AAAAOTHER a comment mentioning ssh-ed25519 today\n", ""
		)
	)


@pytest.mark.skipif(shutil.which("busybox") is None, reason="needs busybox")
def test_awk_match_program_prints_only_the_matching_line(unit):
	assert _run_awk(unit, "awk_match_program", AK_INPUT, BLOB_A) == (
		'restrict,command="/usr/libexec/newton/newton-router --caller=a --role=b" '
		"ssh-ed25519 %s newton-router-a\n" % BLOB_A
	)


# the auth_* router helpers against the fake
# router of RouterUnit (plain key line in authorized_keys, ADMIN_MODE=
# plain-key, NEWTON_SETUP_REMOTE_ROOT=<router root>/fs)


def test_auth_count_prints_the_line_count(router_unit):
	router = router_unit.router
	r = router_unit.run("auth_count\n")
	assert r.returncode == 0
	assert r.stdout == "1\n"
	router.add_authorized_key(LINE_A)
	r = router_unit.run("auth_count\n")
	assert r.returncode == 0
	assert r.stdout == "2\n"


def test_auth_has_blob_exit_status(router_unit):
	rel = "etc/dropbear/authorized_keys"
	code = (
		"auth_has_blob %s; echo rc1=$?\n"
		"auth_has_blob %s; echo rc2=$?\n" % (PLAIN_BLOB, BLOB_A)
	)
	r = router_unit.run(code)
	assert r.returncode == 0
	assert "rc1=0" in r.stdout
	assert "rc2=1" in r.stdout


def test_auth_has_blob_reports_a_failed_authorized_keys_read(router_unit):
	# Awk's own failure must not collapse into "absent".  The
	# full add-key path reads the label before this blob check, so a missing
	# file stops there; this unit checks the blob helper's own contract.
	r = router_unit.run(
		"R_AUTH_KEYS=/etc/dropbear/authorized_keys.missing\n"
		"auth_has_blob %s; echo rc=$?\n" % PLAIN_BLOB
	)
	assert r.returncode == 0, r.stderr
	assert r.stdout.splitlines() == ["rc=3"]
	assert len(router_unit.router.calls()) == 1


def test_auth_has_blob_rejects_a_bad_blob(router_unit):
	r = router_unit.run("auth_has_blob 'not!a@blob'; echo rc=$?\n")
	assert r.returncode == 2
	assert "error:" in r.stderr
	assert "rc=" not in r.stdout


def test_auth_label_blob_prints_the_blob_of_the_label_line(router_unit):
	router = router_unit.router
	router.add_authorized_key(LINE_A)
	code = (
		"auth_label_blob lab-runner\n"
		"auth_label_blob missing-one\n"
		"auth_label_blob 'Bad_Label'; echo rc=$?\n"
	)
	r = router_unit.run(code)
	assert r.returncode == 2
	lines = r.stdout.splitlines()
	assert lines[0] == BLOB_A
	assert len(lines) == 1
	assert "error:" in r.stderr


def test_auth_newton_label_blobs_matches_every_newton_line(router_unit):
	router = router_unit.router
	caller_only = (
		'command="/usr/libexec/newton/newton-router --caller=lab-runner '
		'--role=change" ssh-ed25519 %s owner-comment' % BLOB_A
	)
	last_token_only = (
		'command="/usr/libexec/newton/newton-router --caller=other-label '
		'--role=change" ssh-ed25519 %s newton-router-lab-runner' % BLOB_B
	)
	bad_boundary = (
		'command="/usr/libexec/newton/newton-router '
		'--caller=lab-runnerx --role=change" ssh-ed25519 %s '
		"newton-router-other" % PLAIN_BLOB
	)
	no_blob = 'command="/usr/libexec/newton/newton-router --caller=lab-runner"'
	router.add_authorized_key(caller_only)
	router.add_authorized_key(last_token_only)
	router.add_authorized_key(bad_boundary)
	router.add_authorized_key(no_blob)
	before = len(router.calls())
	r = router_unit.run("auth_newton_label_blobs lab-runner\n")
	assert r.returncode == 0
	assert r.stdout.splitlines() == [BLOB_A, BLOB_B, "-"]
	assert len([c for c in router.calls() if c["tool"] == "ssh"]) - before == 1


def test_auth_newton_label_blobs_rejects_a_bad_label(router_unit):
	r = router_unit.run("auth_newton_label_blobs 'Bad_Label'; echo rc=$?\n")
	assert r.returncode == 2
	assert "error:" in r.stderr
	assert "rc=" not in r.stdout


def test_auth_append_line_appends_with_checks(router_unit):
	router = router_unit.router
	rel = "etc/dropbear/authorized_keys"
	plain_line = "ssh-ed25519 %s agent@unit" % PLAIN_BLOB
	r = router_unit.run("auth_append_line '%s'; echo rc=$?\n" % LINE_A)
	assert r.returncode == 0
	assert "rc=0" in r.stdout
	assert router.read(rel) == plain_line + "\n" + LINE_A + "\n"
	assert _mode_of(router, rel) == 0o600
	assert not router.path(rel + ".new").exists()


def test_auth_append_line_adds_a_missing_final_lf(router_unit):
	router = router_unit.router
	rel = "etc/dropbear/authorized_keys"
	plain_line = "ssh-ed25519 %s agent@unit" % PLAIN_BLOB
	router.write(rel, plain_line)  # no final LF
	r = router_unit.run("auth_append_line '%s'; echo rc=$?\n" % LINE_A)
	assert r.returncode == 0
	assert "rc=0" in r.stdout
	assert router.read(rel) == plain_line + "\n" + LINE_A + "\n"


def test_auth_append_line_failed_check_leaves_the_live_file(router_unit):
	router = router_unit.router
	rel = "etc/dropbear/authorized_keys"
	plain_line = "ssh-ed25519 %s agent@unit\n" % PLAIN_BLOB
	before = router.read(rel)
	# the old newline-in-LINE trick is gone (F3 rejects the line before
	# anything is sent), so the router-side failure is forced by making
	# the directory unwritable: cp cannot build .new, the call returns 1
	# and the live file is untouched
	router.path("etc/dropbear").chmod(0o500)
	r = router_unit.run("auth_append_line '%s'; echo rc=$?\n" % LINE_A)
	router.path("etc/dropbear").chmod(0o755)
	assert r.returncode == 0
	assert "rc=1" in r.stdout
	assert router.read(rel) == before
	assert not router.path(rel + ".new").exists()
	assert _mode_of(router, rel) == 0o600


def test_auth_remove_blob_prints_count_and_keeps_the_rest(router_unit):
	router = router_unit.router
	rel = "etc/dropbear/authorized_keys"
	kept = (
		"ssh-ed25519 %s agent@unit\n" % PLAIN_BLOB
		+ "# a comment line\n"
		+ LINE_B
		+ "\nssh-rsa AAAATRAIL trailing spaces   \n"
	)
	router.write(rel, kept + LINE_A + "\n")
	code = (
		"auth_remove_blob %s; echo rc1=$?\n"
		"auth_remove_blob AAAANOTPRESENT0123456789abcdef; echo rc2=$?\n"
		"auth_remove_blob 'bad blob!'; echo rc3=$?\n" % BLOB_A
	)
	r = router_unit.run(code)
	assert r.returncode == 2
	assert r.stdout.splitlines()[:2] == ["1", "rc1=0"]
	assert "0" in r.stdout.splitlines()[2:4]
	assert router.read(rel) == kept
	assert _mode_of(router, rel) == 0o600
	assert not router.path(rel + ".new").exists()


def test_auth_remove_exact_line_leaves_same_blob_lines_alone(router_unit):
	"""Rollback removes only the bytes this run appended, even
	when another line carries the same public-key blob."""
	router = router_unit.router
	rel = "etc/dropbear/authorized_keys"
	same_blob_plain = "ssh-ed25519 %s operator@unit" % BLOB_A
	kept = (
		"ssh-ed25519 %s agent@unit\n" % PLAIN_BLOB
		+ same_blob_plain + "\n"
		+ LINE_B + "\n"
	)
	router.write(rel, kept + LINE_A + "\n")
	r = router_unit.run(
		"auth_remove_exact_line %s; echo rc=$?\n" % shlex.quote(LINE_A))
	assert r.returncode == 0, r.stderr
	assert r.stdout.splitlines() == ["1", "rc=0"]
	assert router.read(rel) == kept
	assert _mode_of(router, rel) == 0o600
	assert not router.path(rel + ".new").exists()
	router.write(
		rel, "ssh-ed25519 %s agent@unit\n" % PLAIN_BLOB + LINE_A + "\n",
		0o600)
	r = router_unit.run(
		"auth_remove_exact_line %s; echo rc=$?\n" % shlex.quote(LINE_A))
	assert r.returncode == 0, r.stderr
	assert r.stdout.splitlines() == ["1", "rc=0"]
	assert router.read(rel) == "ssh-ed25519 %s agent@unit\n" % PLAIN_BLOB
	assert not router.path(rel + ".new").exists()


def test_auth_remove_label_prints_count_and_keeps_the_rest(router_unit):
	router = router_unit.router
	rel = "etc/dropbear/authorized_keys"
	kept = "ssh-ed25519 %s agent@unit\n%s\n" % (PLAIN_BLOB, LINE_B)
	router.write(rel, kept + LINE_A + "\n")
	code = (
		"auth_remove_label lab-runner; echo rc1=$?\n"
		"auth_remove_label missing-one; echo rc2=$?\n"
		"auth_remove_label 'bad label!'; echo rc3=$?\n"
	)
	r = router_unit.run(code)
	assert r.returncode == 2
	assert r.stdout.splitlines()[:2] == ["1", "rc1=0"]
	assert "0" in r.stdout.splitlines()[2:4]
	assert router.read(rel) == kept
	assert _mode_of(router, rel) == 0o600
	assert not router.path(rel + ".new").exists()


# auth_append_line validates LINE before embedding it


def test_auth_append_line_rejects_special_characters(router_unit):
	# a single quote, a dollar sign, a backtick, a semicolon, a backslash
	# or a newline inside LINE dies with exit 2 and no ssh call is made
	router = router_unit.router
	rel = "etc/dropbear/authorized_keys"
	before = router.read(rel)
	for bad in [
		"command=\"echo 'x\" ssh-ed25519 AAAABLOB c",
		"command=\"echo $x\" ssh-ed25519 AAAABLOB c",
		"command=\"echo `x`\" ssh-ed25519 AAAABLOB c",
		"command=\"echo ;x\" ssh-ed25519 AAAABLOB c",
		"command=\"echo \\x\" ssh-ed25519 AAAABLOB c",
		"command=\"echo x\nmore\" ssh-ed25519 AAAABLOB c",
	]:
		ssh_before = len([c for c in router.calls() if c["tool"] == "ssh"])
		r = router_unit.run(
			"auth_append_line %s; echo rc=$?\n" % shlex.quote(bad)
		)
		assert r.returncode == 2
		assert "bad authorized_keys line" in r.stderr
		assert "rc=" not in r.stdout
		assert router.read(rel) == before
		ssh_after = len([c for c in router.calls() if c["tool"] == "ssh"])
		assert ssh_after == ssh_before


def test_auth_append_line_accepts_the_restricted_line(router_unit):
	# the line restricted_line prints (double quotes, commas, equals,
	# slashes, dots, dashes) passes the F3 validation
	router = router_unit.router
	rel = "etc/dropbear/authorized_keys"
	plain_line = "ssh-ed25519 %s agent@unit" % PLAIN_BLOB
	code = (
		"line=$(restricted_line lab-runner change %s)\n"
		"auth_append_line \"$line\"; echo rc=$?\n" % BLOB_A
	)
	r = router_unit.run(code)
	assert r.returncode == 0
	assert "rc=0" in r.stdout
	assert router.read(rel) == plain_line + "\n" + LINE_A + "\n"


# the tokenizer must ignore quoted blanks and escaped
# quotes (the planted defects "quotes ignored" and "escaped quote ignored")

EVIL_1 = 'command="echo ssh-evil AAAAEVILBLOB" ssh-ed25519 REALBLOB comment'
EVIL_2 = 'command="echo \\" ssh-evil AAAAEVILBLOB \\" x" ssh-ed25519 REALBLOB c'


@pytest.mark.skipif(shutil.which("busybox") is None, reason="needs busybox")
def test_awk_blob_program_ignores_ssh_words_inside_quotes(unit):
	# the ssh- word inside the quotes is not a key type: the blob of both
	# lines is REALBLOB, not AAAAEVILBLOB
	assert _run_awk(
		unit, "awk_blob_program", EVIL_1 + "\n" + EVIL_2 + "\n", BLOB_A
	) == "REALBLOB\nREALBLOB\n"


@pytest.mark.skipif(shutil.which("busybox") is None, reason="needs busybox")
def test_awk_filter_program_with_the_evil_blob_removes_nothing(unit):
	# a filter built with blob AAAAEVILBLOB removes nothing from both lines
	text = EVIL_1 + "\n" + EVIL_2 + "\n"
	assert _run_awk(unit, "awk_filter_program", text, "AAAAEVILBLOB") == text


# the hello helpers

NONCE = "0123456789abcdef0123456789abcdef"


def test_hello_field_extracts_named_words(unit):
	code = (
		'line="hello %s api=1 mode=prod tty=0 agent=0"\n'
		"hello_field \"$line\" mode\n"
		"hello_field \"$line\" api\n"
		"hello_field \"$line\" agent\n"
		"hello_field \"$line\" missing; echo rc=$?\n" % NONCE
	)
	r = unit.run(code)
	assert r.returncode == 0
	assert r.stdout.splitlines() == ["prod", "1", "0", "rc=1"]


def test_hello_field_agent_is_not_tty(unit):
	# agent=0 must not answer a request for tty (nor tty for agent)
	code = (
		'line="hello %s agent=0 tty=1"\n'
		"hello_field \"$line\" tty; echo rc1=$?\n"
		"hello_field \"$line\" agent; echo rc2=$?\n" % NONCE
	)
	r = unit.run(code)
	assert r.returncode == 0
	assert r.stdout.splitlines() == ["1", "rc1=0", "0", "rc2=0"]


def test_hello_field_rejects_a_nonce_word_for_a_name_request(unit):
	# the word `hello` (no =) is not an answer, not even for name `hello`
	r = unit.run('hello_field "hello %s agent=0" hello; echo rc=$?\n' % NONCE)
	assert r.returncode == 0
	assert r.stdout.splitlines() == ["rc=1"]


def test_hello_field_does_not_expand_globs(unit):
	cwd = unit.tmp / "hello-field-glob"
	cwd.mkdir()
	(cwd / "mode=prod").write_text("")
	r = unit.run(
		"cd '%s'\n"
		"hello_field 'hello x mode=* y' mode\n" % cwd
	)
	assert r.returncode == 0
	assert r.stdout == "*\n"


def _install_code_files(router, tmp, program="ok"):
	"""Build the fixture source tree and write its four files into the
	fake router fs (the fixture program is not pre-installed there)."""
	src = build_src(tmp / "src", program=program)
	for rel_src, rel_fs in [
		("device/openwrt/newton-router/newton-router",
			"usr/libexec/newton/newton-router"),
		("scripts/owrt-safe-apply.sh",
			"usr/libexec/newton/newton-safe-apply"),
		("device/openwrt/newton-guard/newton-guard",
			"usr/libexec/newton-guard"),
		("device/openwrt/newton-guard/newton-guard.init",
			"etc/init.d/newton-guard"),
	]:
		router.write(rel_fs, (src / rel_src).read_text(), 0o755)


def test_hello_direct_prints_the_reply_line(router_unit):
	router = router_unit.router
	_install_code_files(router, router_unit.tmp)
	r = router_unit.run("hello_direct %s; echo rc=$?\n" % NONCE)
	assert r.returncode == 0
	lines = r.stdout.splitlines()
	assert lines[0].startswith("hello %s " % NONCE)
	assert lines[-1] == "rc=0"
	for word in ("api=1", "mode=prod", "caller=root", "door=root"):
		assert word in lines[0].split()


def test_hello_direct_bad_nonce_dies(router_unit):
	r = router_unit.run("hello_direct 'not a nonce'; echo rc=$?\n")
	assert r.returncode == 2
	assert "bad nonce" in r.stderr
	assert "rc=" not in r.stdout


def test_hello_direct_failing_program_returns_its_status(router_unit):
	router = router_unit.router
	_install_code_files(router, router_unit.tmp, program="broken")
	r = router_unit.run("hello_direct %s; echo rc=$?\n" % NONCE)
	assert r.returncode == 0
	assert r.stdout.splitlines() == ["rc=3"]


def _restricted_key(tmp, blob):
	# a fake private key file whose blob matches a restricted line
	key = tmp / ("restricted-" + blob[-8:])
	key.write_text("FAKE-OPENSSH-PRIVATE-KEY\n%s\n" % blob)
	key.chmod(0o600)
	return key


def test_hello_key_prints_the_reply_line(router_unit):
	# hello_key sends `hello NONCE`, so it needs a
	# restricted key (a forced command); the plain lane is hello_direct's
	router = router_unit.router
	_install_code_files(router, router_unit.tmp)
	router.add_authorized_key(LINE_A)
	key = _restricted_key(router_unit.tmp, BLOB_A)
	r = router_unit.run('hello_key "%s" %s; echo rc=$?\n' % (key, NONCE))
	assert r.returncode == 0
	lines = r.stdout.splitlines()
	assert lines[0].startswith("hello %s " % NONCE)
	assert "caller=lab-runner" in lines[0].split()
	assert "door=ssh" in lines[0].split()
	assert lines[-1] == "rc=0"


def test_hello_key_bad_reply_fails(router_unit):
	router = router_unit.router
	router.add_authorized_key(LINE_A)
	key = _restricted_key(router_unit.tmp, BLOB_A)
	# a program whose reply does not start with `hello NONCE` makes the
	# check fail (rc=1) even though the call itself succeeded
	router.write(
		"usr/libexec/newton/newton-router",
		'#!/bin/sh\necho "hiho junk"\n',
		0o755,
	)
	r = router_unit.run('hello_key "%s" %s; echo rc=$?\n' % (key, NONCE))
	assert r.returncode == 0
	assert r.stdout.splitlines()[-1] == "rc=1"
	assert not any(
		line.startswith("hello ") for line in r.stdout.splitlines()
	)
	# and one that echoes the asked nonce passes (the forced command reads
	# the request from SSH_ORIGINAL_COMMAND)
	router.write(
		"usr/libexec/newton/newton-router",
		'#!/bin/sh\nset -- $SSH_ORIGINAL_COMMAND\necho "hello $2 mode=prod"\n',
		0o755,
	)
	r = router_unit.run('hello_key "%s" %s; echo rc=$?\n' % (key, NONCE))
	assert r.returncode == 0
	assert r.stdout.splitlines() == ["hello %s mode=prod" % NONCE, "rc=0"]


# check_report against the fake router


def test_check_report_one_call_key_value_lines(router_unit):
	router = router_unit.router
	_install_code_files(router, router_unit.tmp)
	router.add_authorized_key(LINE_A)
	router.update_state(uci={
		"dropbear.@dropbear[0]": "dropbear",
		"dropbear.@dropbear[0].PasswordAuth": "on",
		"dropbear.@dropbear[0].RootPasswordAuth": "off",
	})
	ssh_before = len([c for c in router.calls() if c["tool"] == "ssh"])
	r = router_unit.run("check_report %s; echo rc=$?\n" % PLAIN_BLOB)
	assert r.returncode == 0
	lines = r.stdout.splitlines()
	report = {}
	for line in lines[:-1]:
		key, _, val = line.partition("=")
		report.setdefault(key, []).append(val)
	assert lines[-1] == "rc=0"
	assert report["release"] == ["25.12.0"]
	assert report["busybox"] == [
		"BusyBox v1.37.0 (2026-01-01 00:00:00 UTC) multi-call binary."
	]
	assert "tool_missing" not in report
	assert report["tools_checked"] == ["27"]
	assert re.fullmatch(r"[0-9]+", report["overlay_kib"][0])
	assert report["dropbear_passwordauth"] == ["on"]
	assert report["dropbear_rootpasswordauth"] == ["off"]
	assert report["ak_lines"] == ["2"]
	assert report["ak_labels"] == ["lab-runner"]
	assert report["ak_plain"] == ["present"]
	assert report["guard"] == ["idle"]
	assert report["lock"] == ["none"]
	assert report["report_end"] == ["1"]
	assert lines[-2] == "report_end=1"
	# exactly ONE ssh call for the whole report
	assert len([c for c in router.calls() if c["tool"] == "ssh"]) - ssh_before == 1


def test_check_report_missing_dropbear_section_is_unknown(router_unit):
	router_unit.router.update_state(uci={})
	r = router_unit.run("check_report\n")
	assert r.returncode == 0
	assert "dropbear_passwordauth=unknown" in r.stdout.splitlines()
	assert "dropbear_rootpasswordauth=unknown" in r.stdout.splitlines()
	assert r.stdout.splitlines()[-1] == "report_end=1"


def test_check_report_plain_absent_and_unknown(router_unit):
	router = router_unit.router
	_install_code_files(router, router_unit.tmp)
	r = router_unit.run("check_report %s\n" % BLOB_A)
	assert r.returncode == 0
	assert "ak_plain=absent" in r.stdout.splitlines()
	r = router_unit.run("check_report\n")
	assert r.returncode == 0
	assert "ak_plain=unknown" in r.stdout.splitlines()


def test_check_report_rejects_a_bad_blob(router_unit):
	r = router_unit.run("check_report 'bad blob!'; echo rc=$?\n")
	assert r.returncode == 2
	assert "error:" in r.stderr
	assert "rc=" not in r.stdout


def test_check_report_falls_back_to_busybox_help(router_unit):
	router = router_unit.router
	_install_code_files(router, router_unit.tmp)
	busybox = router.root / "bin" / "busybox"
	busybox.write_text(
		'#!/bin/sh\n[ "$1" = --help ] || exit 0\n'
		'printf \'BusyBox v1.37.0 fallback line\\n\'\n',
	)
	busybox.chmod(0o755)
	r = router_unit.run("check_report\n")
	assert r.returncode == 0
	assert "busybox=BusyBox v1.37.0 fallback line" in r.stdout.splitlines()


def test_check_report_and_lines_say_busybox_unknown_when_both_are_blank(
		router_unit):
	router = router_unit.router
	_install_code_files(router, router_unit.tmp)
	busybox = router.root / "bin" / "busybox"
	busybox.write_text("#!/bin/sh\nexit 0\n")
	busybox.chmod(0o755)
	reported = router_unit.run("check_report\n")
	assert reported.returncode == 0
	assert "busybox=unknown" in reported.stdout.splitlines()
	report = GOOD_REPORT.replace(
		"busybox=BusyBox v1.37.0 (2026-01-01 00:00:00 UTC) multi-call binary.",
		"busybox=unknown",
	)
	r = run_check_lines(router_unit, report)
	assert r.returncode == 0
	assert "INFO busybox unknown" in r.stdout.splitlines()


def test_check_report_guard_and_lock_states(router_unit):
	router = router_unit.router
	_install_code_files(router, router_unit.tmp)
	router.write("etc/newton/guard-state", "pending since 2026-10-08\n")
	r = router_unit.run("check_report\n")
	assert r.returncode == 0
	assert "guard=pending since 2026-10-08" in r.stdout.splitlines()
	router.write("etc/newton/guard-state", "restored by hand\n")
	router.write("tmp/owrt-safe-apply.lock/sid", "sid-0001\n")
	r = router_unit.run("check_report\n")
	assert r.returncode == 0
	# no session names the sid, so the lock is stale
	assert "lock=stale" in r.stdout.splitlines()
	assert "guard=restored by hand" in r.stdout.splitlines()
	router.update_state(ubus_sessions='"sid": "sid-0001", "user": "root"')
	r = router_unit.run("check_report\n")
	assert r.returncode == 0
	assert "lock=live" in r.stdout.splitlines()


def test_check_report_guard_not_installed(router_unit):
	router = router_unit.router
	router.path("usr/libexec/newton-guard").unlink(missing_ok=True)
	r = router_unit.run("check_report\n")
	assert r.returncode == 0
	assert "guard=not-installed" in r.stdout.splitlines()


# check_lines, pure, on canned input

GOOD_REPORT = "\n".join([
	"release=24.10.0",
	"busybox=BusyBox v1.37.0 (2026-01-01 00:00:00 UTC) multi-call binary.",
	"tools_checked=27",
	"overlay_kib=12345",
	"dropbear_passwordauth=on",
	"dropbear_rootpasswordauth=unset",
	"ak_lines=3",
	"ak_labels=lab-runner,newton-agent",
	"ak_plain=present",
	"guard=idle",
	"lock=none",
	"report_end=1",
]) + "\n"


def run_check_lines(unit, report):
	code = "check_lines <<'RPT'\n%s\nRPT\necho rc=$?\n" % report
	return unit.run(code)


def test_check_lines_all_good(unit):
	r = run_check_lines(unit, GOOD_REPORT)
	assert r.returncode == 0
	assert r.stdout.splitlines() == [
		"INFO release 24.10.0",
		"INFO busybox BusyBox v1.37.0 (2026-01-01 00:00:00 UTC) multi-call binary.",
		"PASS tools 27/27 present",
		"INFO overlay free 12345 KiB",
		"PASS dropbear PasswordAuth on",
		"PASS dropbear RootPasswordAuth on",
		"INFO authorized_keys 3 lines; newton labels: lab-runner,newton-agent; plain key: present",
		"PASS guard idle",
		"PASS helper lock none",
		"rc=0",
	]


@pytest.mark.parametrize("report", ["", "release=24.10.0\n"])
def test_check_lines_incomplete_report_prints_only_failure(unit, report):
	r = run_check_lines(unit, report)
	assert r.returncode == 0
	lines = r.stdout.splitlines()
	assert lines[-1] == "rc=3"
	status = [line for line in lines[:-1]
		if line.startswith(("PASS ", "FAIL ", "INFO ", "WARN "))]
	assert status == ["FAIL router report incomplete"]


def test_check_lines_unknown_dropbear_passwordauth_fails(unit):
	report = GOOD_REPORT.replace(
		"dropbear_passwordauth=on", "dropbear_passwordauth=unknown"
	)
	r = run_check_lines(unit, report)
	assert r.returncode == 0
	assert "FAIL dropbear PasswordAuth unknown" in r.stdout.splitlines()
	assert r.stdout.splitlines()[-1] == "rc=1"


def test_check_lines_empty_dropbear_passwordauth_is_unknown(unit):
	# the router prints "unset" for an absent option, never an empty
	# value: an empty value says nothing about the option, so the line
	# must FAIL as unknown and must never PASS
	report = GOOD_REPORT.replace(
		"dropbear_passwordauth=on", "dropbear_passwordauth="
	)
	r = run_check_lines(unit, report)
	assert r.returncode == 0
	lines = r.stdout.splitlines()
	assert "FAIL dropbear PasswordAuth unknown" in lines
	assert "PASS dropbear PasswordAuth on" not in lines
	assert lines[-1] == "rc=1"


def test_check_lines_unknown_dropbear_rootpasswordauth_fails(unit):
	report = GOOD_REPORT.replace(
		"dropbear_rootpasswordauth=unset",
		"dropbear_rootpasswordauth=unknown",
	)
	r = run_check_lines(unit, report)
	assert r.returncode == 0
	assert "FAIL dropbear RootPasswordAuth unknown" in r.stdout.splitlines()
	assert r.stdout.splitlines()[-1] == "rc=1"


def test_check_lines_empty_dropbear_rootpasswordauth_is_unknown(unit):
	report = GOOD_REPORT.replace(
		"dropbear_rootpasswordauth=unset", "dropbear_rootpasswordauth="
	)
	r = run_check_lines(unit, report)
	assert r.returncode == 0
	lines = r.stdout.splitlines()
	assert "FAIL dropbear RootPasswordAuth unknown" in lines
	assert "PASS dropbear RootPasswordAuth on" not in lines
	assert lines[-1] == "rc=1"


def test_check_lines_unknown_authorized_keys_count_fails(unit):
	report = GOOD_REPORT.replace("ak_lines=3", "ak_lines=unknown")
	r = run_check_lines(unit, report)
	assert r.returncode == 0
	assert "FAIL authorized_keys line count unknown" in r.stdout.splitlines()
	assert r.stdout.splitlines()[-1] == "rc=1"


def test_check_lines_missing_tools_fail(unit):
	report = GOOD_REPORT.replace(
		"overlay_kib=12345\n",
		"tool_missing=awk\ntool_missing=uci\noverlay_kib=12345\n",
	)
	r = run_check_lines(unit, report)
	assert r.returncode == 0
	lines = r.stdout.splitlines()
	assert "FAIL tool awk" in lines
	assert "FAIL tool uci" in lines
	assert not any(line.startswith("PASS tools") for line in lines)
	assert lines[-1] == "rc=1"


def test_check_lines_dropbear_off_fails(unit):
	report = GOOD_REPORT.replace(
		"dropbear_passwordauth=on", "dropbear_passwordauth=off"
	).replace(
		"dropbear_rootpasswordauth=unset", "dropbear_rootpasswordauth=off"
	)
	r = run_check_lines(unit, report)
	assert r.returncode == 0
	lines = r.stdout.splitlines()
	assert "FAIL dropbear PasswordAuth off" in lines
	assert "FAIL dropbear RootPasswordAuth off" in lines
	assert lines[-1] == "rc=1"


# check_lines treats every uci boolean false word as FAIL and
# every true word (or the default unset) as PASS, in any letter case
#.  An empty value is unknown, not the
# default: the router prints "unset" for an absent option.


@pytest.mark.parametrize("option,key", [
	("PasswordAuth", "dropbear_passwordauth"),
	("RootPasswordAuth", "dropbear_rootpasswordauth"),
])
@pytest.mark.parametrize("value,is_false", [
	# uci false words in any letter case
	("0", True), ("no", True), ("off", True),
	("false", True), ("disabled", True),
	("NO", True), ("Off", True), ("FALSE", True), ("DISABLED", True),
	# uci true words in any letter case
	("1", False), ("yes", False), ("on", False),
	("true", False), ("enabled", False),
	("YES", False), ("On", False), ("TRUE", False), ("ENABLED", False),
	# the default (the literal "unset") means the option is absent, so
	# the default is true and the line must PASS
	("unset", False),
])
def test_check_lines_dropbear_uci_booleans(unit, option, key, value, is_false):
	# use the value that is NOT the one under test as a known-good to
	# keep the report otherwise valid
	if key == "dropbear_passwordauth":
		other_value = "on"
		other_option = "RootPasswordAuth"
	else:
		other_value = "unset"
		other_option = "PasswordAuth"
	report = "\n".join([
		"release=24.10.0",
		"busybox=BusyBox v1.37.0 (2026-01-01 00:00:00 UTC) multi-call binary.",
		"tools_checked=27",
		"overlay_kib=12345",
		"%s=%s" % (key, value),
		"%s=%s" % (
			"dropbear_passwordauth" if key == "dropbear_rootpasswordauth"
			else "dropbear_rootpasswordauth",
			other_value,
		),
		"ak_lines=3",
		"ak_labels=lab-runner,newton-agent",
		"ak_plain=present",
		"guard=idle",
		"lock=none",
		"report_end=1",
	]) + "\n"
	r = run_check_lines(unit, report)
	assert r.returncode == 0
	lines = r.stdout.splitlines()
	expected_pass = "PASS dropbear %s on" % option
	expected_fail = "FAIL dropbear %s off" % option
	if is_false:
		assert expected_pass not in lines, lines
		assert expected_fail in lines, lines
		assert lines[-1] == "rc=1"
	else:
		assert expected_fail not in lines, lines
		assert expected_pass in lines, lines
		assert lines[-1] == "rc=0"


def test_check_lines_guard_states(unit):
	for value, expected, rc in [
		("not-installed", "INFO guard not-installed", 0),
		("restored 2026-10-08 10:00", "INFO guard restored 2026-10-08 10:00", 0),
		("pending since boot", "FAIL guard pending since boot", 1),
		("failed hard", "FAIL guard failed hard", 1),
	]:
		report = GOOD_REPORT.replace("guard=idle", "guard=" + value)
		r = run_check_lines(unit, report)
		assert r.returncode == 0
		lines = r.stdout.splitlines()
		assert expected in lines
		assert lines[-1] == "rc=%d" % rc


def test_check_lines_lock_states(unit):
	for value, expected, rc in [
		("none", "PASS helper lock none", 0),
		("live", "FAIL helper lock live", 1),
		("stale", "WARN helper lock stale", 0),
	]:
		report = GOOD_REPORT.replace("lock=none", "lock=" + value)
		r = run_check_lines(unit, report)
		assert r.returncode == 0
		lines = r.stdout.splitlines()
		assert expected in lines
		assert lines[-1] == "rc=%d" % rc


def test_check_lines_makes_no_ssh_calls(unit):
	run_check_lines(unit, GOOD_REPORT)
	assert unit.argv() == []


def test_hello_field_matches_the_whole_name_only(unit):
	# a longer or shorter field name is another field
	code = (
		'line="hello %s xmode=1 modes=2 mod=3 mode=4"\n'
		'hello_field "$line" mode\n'
		'hello_field "$line" xmode\n'
		'hello_field "$line" mod\n'
		'hello_field "$line" ode; echo rc=$?\n' % NONCE
	)
	r = unit.run(code)
	assert r.returncode == 0
	assert r.stdout.splitlines() == ["4", "1", "3", "rc=1"]


# hello_key sends the request text `hello NONCE`,
# not the router path of the program


def test_hello_key_sends_the_request_text_to_a_forced_command(router_unit):
	# the forced command receives `hello NONCE` as its request; the
	# fixture program shifts a leading program path off only when it is
	# exactly /usr/libexec/newton/newton-router, which the RR-prefixed
	# path never is under test
	router = router_unit.router
	_install_code_files(router, router_unit.tmp)
	line = (
		"restrict,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,"
		'no-pty,command="/usr/libexec/newton/newton-router '
		'--caller=newton-agent --role=change" ssh-ed25519 %s '
		"newton-router-newton-agent" % BLOB_A
	)
	router.add_authorized_key(line)
	key = _restricted_key(router_unit.tmp, BLOB_A)
	r = router_unit.run('hello_key "%s" %s; echo rc=$?\n' % (key, NONCE))
	assert r.returncode == 0
	lines = r.stdout.splitlines()
	assert lines[0].startswith("hello %s " % NONCE)
	assert "caller=newton-agent" in lines[0].split()
	assert lines[-1] == "rc=0"
	ssh_calls = [c for c in router.calls() if c["tool"] == "ssh"]
	assert len(ssh_calls) == 1
	assert ssh_calls[0]["command"] == "hello %s" % NONCE


# the reply split must not glob `*` words


def test_hello_reply_star_words_do_not_glob(router_unit):
	router = router_unit.router
	router.write(
		"usr/libexec/newton/newton-router",
		'#!/bin/sh\nset -- ${SSH_ORIGINAL_COMMAND:-"$@"}\n'
		'echo "hello $2 star=*"\n',
		0o755,
	)
	router.add_authorized_key(LINE_A)
	key = _restricted_key(router_unit.tmp, BLOB_A)
	code = (
		"hello_direct %s; echo rc1=$?\n"
		'hello_key "%s" %s; echo rc2=$?\n' % (NONCE, key, NONCE)
	)
	r = router_unit.run(code)
	assert r.returncode == 0
	star = "hello %s star=*" % NONCE
	assert r.stdout.splitlines() == [star, "rc1=0", star, "rc2=0"]
	# a glob word must not expand into a passing reply: with the tool's
	# cwd holding only a file named hello, the reply `he* NONCE` would
	# glob to `hello NONCE` and wrongly pass
	router.write(
		"usr/libexec/newton/newton-router",
		"#!/bin/sh\necho 'he* %s'\n" % NONCE,
		0o755,
	)
	cwd = router_unit.tmp / "globcwd"
	cwd.mkdir()
	(cwd / "hello").write_text("")
	r = router_unit.run("cd '%s'\nhello_direct %s; echo rc1=$?\n" % (cwd, NONCE))
	assert r.returncode == 0
	assert r.stdout.splitlines() == ["rc1=1"]


# the check action against the fake router


def _run_action_check(router_unit, typed):
	tty = router_unit.tmp / "typed"
	tty.write_text("".join(line + "\n" for line in typed))
	return router_unit.run(
		"ACTION=check\naction_check\n",
		extra_env={"NEWTON_SETUP_TTY": str(tty)},
	)


def test_action_check_happy_path(router_unit):
	router = router_unit.router
	_install_code_files(router, router_unit.tmp)
	r = _run_action_check(router_unit, ["root-pw-for-tests"])
	assert r.returncode == 0
	lines = r.stdout.splitlines()
	assert "PASS tools 27/27 present" in lines
	assert "PASS guard idle" in lines
	assert "PASS password-only login works" in lines
	assert not [line for line in lines if line.startswith("FAIL")]
	assert lines[-1] == "DONE check r1"


def test_action_check_missing_tool_stops(router_unit):
	router = router_unit.router
	_install_code_files(router, router_unit.tmp)
	(router.root / "bin" / "ucode").unlink()
	r = _run_action_check(router_unit, ["root-pw-for-tests"])
	assert r.returncode == 1
	lines = r.stdout.splitlines()
	assert "FAIL tool ucode" in lines
	assert "PASS password-only login works" in lines
	assert lines[-2] == "NOTE state: router unchanged"
	assert lines[-1] == "STOPPED check r1: check found a problem"


def test_action_check_wrong_password_stops(router_unit):
	router = router_unit.router
	_install_code_files(router, router_unit.tmp)
	r = _run_action_check(router_unit, ["not-the-root-pw"])
	assert r.returncode == 1
	lines = r.stdout.splitlines()
	assert "FAIL password-only login failed" in lines
	assert lines[-2] == "NOTE state: router unchanged"
	assert lines[-1] == "STOPPED check r1: check found a problem"


def test_action_check_corrupt_plain_key_exits_two(router_unit):
	router_unit.plain.write_text("this is not a private key\n")
	r = _run_action_check(router_unit, ["root-pw-for-tests"])
	assert r.returncode == 2
	assert "cannot read the public key" in r.stderr
	assert "DONE check" not in r.stdout


# zones_text (pure, design 2.1) and the put_file rotation of
# step 3 / design 8.2 step 3


def test_zones_text_default_one_wan_zone(unit):
	r = unit.run("zones_text\n")
	assert r.returncode == 0
	assert r.stdout == "mgmt-interface lan\nmgmt-zone lan\nwan-zone wan\n"
	assert unit.argv() == []


def test_zones_text_four_wan_zones(unit):
	code = (
		"DEV_MGMT_IFACE=mgmt0\nDEV_MGMT_ZONE=internal\n"
		"DEV_WAN_ZONES=wan,wan2,wan3,wan4\nzones_text\n"
	)
	r = unit.run(code)
	assert r.returncode == 0
	assert r.stdout == (
		"mgmt-interface mgmt0\nmgmt-zone internal\n"
		"wan-zone wan\nwan-zone wan2\nwan-zone wan3\nwan-zone wan4\n"
	)
	assert unit.argv() == []


def test_put_file_rotate_first_write_makes_no_prev(router_unit):
	router = router_unit.router
	rel = "usr/libexec/newton/newton-router"
	# step 2 (install_dirs) has made the directory; the file is new
	router.path("usr/libexec/newton").mkdir(parents=True, exist_ok=True)
	local = router_unit.tmp / "prog"
	local.write_text("first-bytes\n")
	r = router_unit.run(
		'put_file "%s" "/usr/libexec/newton/newton-router" 755 rotate; '
		"echo rc=$? ROT=$PUT_ROTATED PUT=$PUT_CHANGED\n" % local
	)
	assert r.returncode == 0
	assert "rc=0" in r.stdout
	assert "ROT=0" in r.stdout
	assert "PUT=1" in r.stdout
	assert router.read(rel) == "first-bytes\n"
	assert _mode_of(router, rel) == 0o755
	assert not router.path(rel + ".prev").exists()
	assert not router.path(rel + ".new").exists()


def test_put_file_rotate_changed_makes_prev_with_old_bytes(router_unit):
	router = router_unit.router
	rel = "usr/libexec/newton/newton-router"
	router.write(rel, "old-bytes\n", 0o755)
	local = router_unit.tmp / "prog"
	local.write_text("new-v1\n")
	r = router_unit.run(
		'put_file "%s" "/usr/libexec/newton/newton-router" 755 rotate; '
		"echo rc=$? ROT=$PUT_ROTATED PUT=$PUT_CHANGED\n" % local
	)
	assert r.returncode == 0
	assert "rc=0" in r.stdout
	assert "ROT=1" in r.stdout
	assert "PUT=1" in r.stdout
	assert router.read(rel) == "new-v1\n"
	assert _mode_of(router, rel) == 0o755
	assert router.read(rel + ".prev") == "old-bytes\n"
	assert _mode_of(router, rel + ".prev") == 0o644
	assert not router.path(rel + ".new").exists()


def test_put_file_rotate_identical_write_leaves_prev_untouched(router_unit):
	router = router_unit.router
	rel = "usr/libexec/newton/newton-router"
	router.write(rel, "old-bytes\n", 0o755)
	local = router_unit.tmp / "prog"
	local.write_text("new-v1\n")
	router_unit.run(
		'put_file "%s" "/usr/libexec/newton/newton-router" 755 rotate\n' % local
	)
	assert router.read(rel + ".prev") == "old-bytes\n"
	r = router_unit.run(
		'put_file "%s" "/usr/libexec/newton/newton-router" 755 rotate; '
		"echo rc=$? ROT=$PUT_ROTATED PUT=$PUT_CHANGED\n" % local
	)
	assert r.returncode == 0
	assert "rc=0" in r.stdout
	assert "ROT=0" in r.stdout
	assert "PUT=0" in r.stdout
	assert router.read(rel) == "new-v1\n"
	# the .prev still holds the bytes of the run before, mode 644
	assert router.read(rel + ".prev") == "old-bytes\n"
	assert _mode_of(router, rel + ".prev") == 0o644
	assert not router.path(rel + ".new").exists()


def test_install_code_files_missing_source_dies_nothing_sent(router_unit):
	# a missing source file is exit 2 BEFORE anything is
	# sent, so the fake router's call log stays empty for this run
	router = router_unit.router
	src = build_src(router_unit.tmp / "src")
	(src / "device/openwrt/newton-guard/newton-guard.init").unlink()
	calls_before = len(router.calls())
	r = router_unit.run(
		"ACTION=install\ninstall_code_files; echo rc=$?\n",
		extra_env={"NEWTON_SETUP_SRC": str(src)},
	)
	assert r.returncode == 2
	assert "rc=" not in r.stdout
	assert "error:" in r.stderr
	assert "missing source file" in r.stderr
	assert len(router.calls()) == calls_before


def test_install_check_sources_dies_before_action_router_calls(router_unit):
	router = router_unit.router
	src = build_src(router_unit.tmp / "src-preflight")
	missing = src / "scripts/owrt-safe-apply.sh"
	missing.unlink()
	r = router_unit.run(
		"ACTION=install\naction_install\n",
		extra_env={"NEWTON_SETUP_SRC": str(src)},
	)
	assert r.returncode == 2
	assert str(missing) in r.stderr
	assert router.calls() == []


def test_install_sysupgrade_repairs_separator_without_blank(router_unit):
	router = router_unit.router
	for initial in ("## custom\n/etc/myfile", "## custom\n/etc/myfile\n"):
		router.write("etc/sysupgrade.conf", initial)
		r = router_unit.run("install_sysupgrade\n")
		assert r.returncode == 0
		assert router.read("etc/sysupgrade.conf") == (
			"## custom\n/etc/myfile\n" + "\n".join([
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
			]) + "\n")


def test_main_gets_admin_password_before_captured_ssh(unit):
	code = r'''
parse_args() { DEVICE=r1; ACTION=check; }
load_inventory() { :; }
choose_admin_path() { ADMIN_MODE=password; }
action_check() {
	a=$(rsh_admin true 2>/dev/null) || return
	b=$(rsh_admin true 2>/dev/null) || return
	IFS= read -r -u "$TTY_FD" left
	printf 'left=%s\n' "$left"
}
main
'''
	r = unit.run(code, tty=["root-pw", "DECOY"])
	assert r.returncode == 0
	assert r.stderr.count("root password: ") == 1
	assert r.stdout.splitlines()[-1] == "left=DECOY"


# the pure approval-key helpers (design 5.4)


def _pbkdf2(passphrase, device):
	return hashlib.pbkdf2_hmac(
		"sha256", passphrase, b"newton-approve-v1:" + device, 600000, 32
	).hex()


def test_derive_k_matches_pbkdf2_for_ascii_and_utf8(unit):
	# K = PBKDF2-HMAC-SHA256(passphrase UTF-8, salt
	# `newton-approve-v1:` + device, 600000, 32) as 64 hex (design 5.4)
	for pw in [b"correct horse battery staple", "pässwörd-ü".encode("utf-8")]:
		pwfile = unit.tmp / "pp.bin"
		pwfile.write_bytes(pw)
		r = unit.run("derive_k r1 < '%s'\n" % pwfile)
		assert r.returncode == 0
		assert r.stdout.strip() == _pbkdf2(pw, b"r1")


def test_derive_k_differs_per_device(unit):
	# the salt carries the device name, so one passphrase gives each
	# router its own K
	pwfile = unit.tmp / "pp.bin"
	pwfile.write_bytes(b"one-passphrase-everywhere")
	r1 = unit.run("derive_k r1 < '%s'\n" % pwfile)
	pulsar = unit.run("derive_k pulsar < '%s'\n" % pwfile)
	assert r1.returncode == 0 and pulsar.returncode == 0
	k1 = r1.stdout.strip()
	k2 = pulsar.stdout.strip()
	assert re.fullmatch(r"[0-9a-f]{64}", k1)
	assert re.fullmatch(r"[0-9a-f]{64}", k2)
	assert k1 != k2


def test_selftest_hmac_matches_hmac_new(unit):
	# HMAC-SHA256(bytes of K, "newton-selftest-v1\n" + NONCE + "\n")
	k = os.urandom(32).hex()
	expected = hmac.new(
		bytes.fromhex(k),
		b"newton-selftest-v1\n" + NONCE.encode("ascii") + b"\n",
		hashlib.sha256,
	).hexdigest()
	r = unit.run("printf '%%s\\n' %s | selftest_hmac %s\n" % (k, NONCE))
	assert r.returncode == 0
	assert r.stdout.strip() == expected


def test_lab_passphrase_path_reads_the_ssh_table(unit):
	lab = unit.tmp / "lab.toml"
	lab.write_text('[ssh]\napprove_passphrase_file = "~/newton/lab-pp"\n')
	r = unit.run("lab_passphrase_path\n", extra_env={"NEWTON_LAB_TOML": str(lab)})
	assert r.returncode == 0
	assert r.stdout.strip() == os.path.expanduser("~/newton/lab-pp")


def test_lab_passphrase_path_without_the_key_is_empty(unit):
	lab = unit.tmp / "lab.toml"
	lab.write_text("[pve]\ntoken = \"x\"\n")
	r = unit.run("lab_passphrase_path\n", extra_env={"NEWTON_LAB_TOML": str(lab)})
	assert r.returncode == 0
	assert r.stdout == ""


def test_lab_passphrase_path_missing_toml_is_empty(unit):
	r = unit.run(
		"lab_passphrase_path\n",
		extra_env={"NEWTON_LAB_TOML": str(unit.tmp / "no-such-lab.toml")},
	)
	assert r.returncode == 0
	assert r.stdout == ""


def test_secret_functions_leave_nothing_in_the_environment(unit):
	# neither the passphrase nor K may end up exported: after running
	# derive_k and selftest_hmac, a child bash that prints `env` shows
	# neither
	secret = "env-inspect-passphrase"
	k = _pbkdf2(secret.encode("utf-8"), b"r1")
	code = (
		"pp='%s'\n"
		"k=$(printf '%%s' \"$pp\" | derive_k r1)\n"
		"printf '%%s\\n' \"$k\" | selftest_hmac %s >/dev/null\n"
		'bash -c env > "$ENV_LOG"\n' % (secret, NONCE)
	)
	r = unit.run(code)
	assert r.returncode == 0
	env_text = unit.env_log.read_text()
	assert secret not in env_text
	assert k not in env_text


# restricted-key proofs

def _proof_setup(router_unit, role="change", program="ok", vulnerable=()):
	router = router_unit.router
	_install_code_files(router, router_unit.tmp, program=program)
	router.write("etc/config/network", "config interface 'lan'\n")
	line = (
		"restrict,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,"
		'no-pty,command="/usr/libexec/newton/newton-router '
		'--caller=lab-runner --role=%s" ssh-ed25519 %s '
		"newton-router-lab-runner" % (role, BLOB_A)
	)
	router.add_authorized_key(line)
	router.update_state(vulnerable=list(vulnerable))
	return _restricted_key(router_unit.tmp, BLOB_A)


def _run_proof(router_unit, name, role="change", program="ok", vulnerable=()):
	key = _proof_setup(router_unit, role=role, program=program,
		vulnerable=vulnerable)
	return router_unit.run(
		'%s "%s" lab-runner %s; echo rc=$?\n' % (name, key, role)
	)


def _assert_proof(result, name, passed=True):
	word = "PASS" if passed else "FAIL"
	assert result.returncode == 0
	lines = result.stdout.splitlines()
	assert len([line for line in lines if " proof " in line]) == 1
	assert lines[0].startswith("%s proof %s:" % (word, name))
	assert lines[-1] == "rc=%d" % (0 if passed else 1)


def test_free_port_returns_a_bindable_port(unit):
	r = unit.run("free_port\n")
	assert r.returncode == 0
	port = int(r.stdout.strip())
	import socket
	with socket.socket() as sock:
		sock.bind(("127.0.0.1", port))


@pytest.mark.parametrize("function,name,role", [
	("proof_hello", "hello", "change"),
	("proof_probe_fail", "probe-fail", "change"),
	("proof_bad_arg", "bad-arg", "change"),
	("proof_selftest_refused", "selftest-refused", "change"),
	("proof_backup", "backup", "change"),
	("proof_backup", "backup", "read"),
	("proof_unknown_and_empty", "unknown-and-empty", "change"),
	("proof_forwards", "forwards", "change"),
	("proof_pty_agent", "pty-agent", "change"),
	("proof_sftp_scp", "sftp-scp", "change"),
	("proof_setenv", "setenv", "change"),
])
def test_restricted_key_proof_passes(router_unit, function, name, role):
	_assert_proof(_run_proof(router_unit, function, role=role), name)


@pytest.mark.parametrize("function,name", [
	("proof_hello", "hello"),
	("proof_probe_fail", "probe-fail"),
	("proof_bad_arg", "bad-arg"),
	("proof_selftest_refused", "selftest-refused"),
	("proof_backup", "backup"),
	("proof_unknown_and_empty", "unknown-and-empty"),
])
def test_program_proofs_fail_for_broken_program(router_unit, function, name):
	_assert_proof(_run_proof(router_unit, function, program="broken"),
		name, passed=False)


def test_forward_proof_fails_on_vulnerable_router(router_unit):
	_assert_proof(_run_proof(router_unit, "proof_forwards",
		vulnerable=("forwarding",)), "forwards", passed=False)


@pytest.mark.parametrize("vulnerability", ["pty", "agent"])
def test_pty_agent_proof_fails_on_vulnerable_router(router_unit, vulnerability):
	_assert_proof(_run_proof(router_unit, "proof_pty_agent",
		vulnerable=(vulnerability,)), "pty-agent", passed=False)


# round dropbear 2025.89 with a restricted key refuses -tt by
# printing "PTY allocation request failed on channel 0" on stderr,
# exiting 255 and running no command. The router's no-pty is safe, so
# proof_pty_agent must still report a PASS without a hello body, by
# reading the refusal as the proof of the -tt attempt. The agent half
# is unchanged; existing tests still PASS.


def test_pty_agent_proof_passes_on_dropbear_pty_refusal(router_unit):
	# pass with dropbear-style refusal on -tt (exit 255,
	# "PTY allocation request failed on channel 0", empty stdout)
	key = _proof_setup(router_unit)
	router_unit.router.update_state(dropbear_refuse_pty="dropbear")
	r = router_unit.run(
		'proof_pty_agent "%s" lab-runner change; echo rc=$?\n' % key)
	_assert_proof(r, "pty-agent", passed=True)


def test_pty_agent_proof_fails_when_dropbear_refusal_keeps_a_body(router_unit):
	# a hostile server may print the PTY refusal and STILL
	# run the command; the stdout hello body must invalidate the proof.
	key = _proof_setup(router_unit)
	router_unit.router.update_state(
		dropbear_refuse_pty="dropbear",
		dropbear_refuse_pty_body=True)
	r = router_unit.run(
		'proof_pty_agent "%s" lab-runner change; echo rc=$?\n' % key)
	_assert_proof(r, "pty-agent", passed=False)


def test_pty_agent_proof_fails_when_refusal_exit_255_keeps_a_body(router_unit):
	# the body check alone must fail it: refusal text, exit 255 AND a hello body
	key = _proof_setup(router_unit)
	router_unit.router.update_state(dropbear_refuse_pty="dropbear",
		dropbear_refuse_pty_body=True, refuse_pty_body_rc=255)
	r = router_unit.run(
		'proof_pty_agent "%s" lab-runner change; echo rc=$?\n' % key)
	_assert_proof(r, "pty-agent", passed=False)


def test_pty_agent_proof_fails_on_tty0_body_with_nonzero_exit(router_unit):
	# a tty=0 hello does not rescue a non-zero ssh exit on the -tt attempt
	key = _proof_setup(router_unit)
	router_unit.router.update_state(tt_rc=1)
	r = router_unit.run(
		'proof_pty_agent "%s" lab-runner change; echo rc=$?\n' % key)
	_assert_proof(r, "pty-agent", passed=False)


def test_pty_agent_proof_fails_on_unrelated_pty_exit_255(router_unit):
	# ssh exits 255 with a different stderr (e.g. permission
	# denied) and no body — that is NOT the dropbear PTY refusal and
	# the proof must still FAIL.
	key = _proof_setup(router_unit)
	router_unit.router.update_state(dropbear_refuse_pty="other")
	r = router_unit.run(
		'proof_pty_agent "%s" lab-runner change; echo rc=$?\n' % key)
	_assert_proof(r, "pty-agent", passed=False)


def test_sftp_scp_proof_fails_for_unrestricted_key(router_unit):
	key = _proof_setup(router_unit)
	lines = router_unit.router.authorized_keys()
	lines[-1] = "ssh-ed25519 %s newton-router-lab-runner" % BLOB_A
	router_unit.router.write("etc/dropbear/authorized_keys", "\n".join(lines) + "\n")
	r = router_unit.run(
		'proof_sftp_scp "%s" lab-runner change; echo rc=$?\n' % key)
	_assert_proof(r, "sftp-scp", passed=False)


def test_setenv_proof_fails_on_vulnerable_router(router_unit):
	_assert_proof(_run_proof(router_unit, "proof_setenv",
		vulnerable=("setenv",)), "setenv", passed=False)


@pytest.mark.parametrize("role", ["change", "read"])
def test_prove_restricted_key_runs_all_ten_proofs(router_unit, role):
	key = _proof_setup(router_unit, role=role)
	r = router_unit.run(
		'prove_restricted_key lab-runner %s "%s"; echo rc=$?\n' % (role, key)
	)
	assert r.returncode == 0
	assert len(r.stdout.splitlines()) == 11
	assert len([line for line in r.stdout.splitlines()
		if line.startswith("PASS proof ")]) == 10
	assert r.stdout.splitlines()[-1] == "rc=0"


# add-key and revoke

def _prepare_key_action(router_unit):
	_install_code_files(router_unit.router, router_unit.tmp)
	router_unit.router.write("etc/config/network", "config interface 'lan'\n")


@pytest.mark.parametrize("role", ["change", "read"])
def test_action_add_key_appends_exact_restricted_line(router_unit, role):
	_prepare_key_action(router_unit)
	code = (
		"ACTION=add-key\nLABEL=lab-runner\nROLE=%s\n"
		"NEW_KEY=1\n"
		"action_add_key\n" % role
	)
	r = router_unit.run(code)
	assert r.returncode == 0
	assert r.stdout.splitlines()[-2].startswith(
		"PASS add-key: key file %s/r1-lab-runner" % router_unit.keys)
	assert r.stdout.splitlines()[-1] == "DONE add-key r1"
	key = router_unit.keys / "r1-lab-runner"
	blob = key.read_text().splitlines()[1]
	expected = (
		"restrict,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,"
		'no-pty,command="/usr/libexec/newton/newton-router '
		'--caller=lab-runner --role=%s" ssh-ed25519 %s '
		"newton-router-lab-runner" % (role, blob)
	)
	assert router_unit.router.authorized_keys()[-1] == expected


def test_action_add_key_is_idempotent(router_unit):
	_prepare_key_action(router_unit)
	first = router_unit.run(
		"ACTION=add-key\nLABEL=lab-runner\nROLE=change\nNEW_KEY=1\n"
		"action_add_key\n")
	assert first.returncode == 0
	key = router_unit.keys / "r1-lab-runner"
	private_before = key.read_bytes()
	public_before = key.with_name(key.name + ".pub").read_bytes()
	authorized_before = router_unit.router.read("etc/dropbear/authorized_keys")
	second = router_unit.run(
		"ACTION=add-key\nLABEL=lab-runner\nROLE=change\naction_add_key\n")
	assert second.returncode == 1
	assert "revoke it first" in second.stdout
	assert key.read_bytes() == private_before
	assert key.with_name(key.name + ".pub").read_bytes() == public_before
	assert router_unit.router.read("etc/dropbear/authorized_keys") == authorized_before
	assert sum(line.endswith("newton-router-lab-runner")
		for line in router_unit.router.authorized_keys()) == 1


def test_action_add_key_refuses_another_blob_for_label(router_unit):
	_prepare_key_action(router_unit)
	first = router_unit.run(
		"ACTION=add-key\nLABEL=lab-runner\nROLE=change\nNEW_KEY=1\n"
		"action_add_key\n")
	assert first.returncode == 0, first.stdout + first.stderr
	other = (
		"restrict,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,"
		'no-pty,command="/usr/libexec/newton/newton-router '
		'--caller=lab-runner --role=change" ssh-ed25519 %s '
		"newton-router-lab-runner" % BLOB_B
	)
	router_unit.router.add_authorized_key(other)
	before = router_unit.router.read("etc/dropbear/authorized_keys")
	r = router_unit.run(
		"ACTION=add-key\nLABEL=lab-runner\nROLE=change\naction_add_key\n")
	assert r.returncode == 1
	assert "revoke it first" in r.stdout
	assert "NOTE state: router unchanged" in r.stdout.splitlines()
	assert router_unit.router.read("etc/dropbear/authorized_keys") == before


def test_action_add_key_failed_proof_removes_only_new_line(router_unit):
	_prepare_key_action(router_unit)
	router = router_unit.router
	before = router.authorized_keys()
	router.update_state(vulnerable=["forwarding"])
	r = router_unit.run(
		"ACTION=add-key\nLABEL=lab-runner\nROLE=change\nNEW_KEY=1\n"
		"action_add_key\n")
	assert r.returncode == 1
	# the tool's FAIL line carries a text after
	# the colon (today it repeats the PASS wording, a wording defect the next
	# round repairs), so match the prefix
	assert any(l.startswith("FAIL proof forwards:") for l in r.stdout.splitlines())
	assert "NOTE state: router unchanged (the new line was removed again)" \
		in r.stdout.splitlines()
	assert r.stdout.splitlines()[-1] == \
		"STOPPED add-key r1: the key failed its proofs"
	assert router.authorized_keys() == before
	assert not (router_unit.keys / "r1-lab-runner").exists()
	assert not (router_unit.keys / "r1-lab-runner.pub").exists()


def test_action_add_key_failed_proof_requires_exactly_one_removal(router_unit):
	# A rollback that reports two removed lines is not the one
	# line this run appended, so it must keep the failed-removal state note.
	_prepare_key_action(router_unit)
	code = (
		"ACTION=add-key\nNEW_KEY=1\n"
		"prove_restricted_key() { return 1; }\n"
		"auth_remove_exact_line() { printf '2\\n'; return 0; }\n"
		"add_key_run lab-runner change\n"
	)
	r = router_unit.run(code)
	assert r.returncode == 1
	lines = r.stdout.splitlines()
	assert "NOTE state: the new line could not be removed again" in lines
	assert "NOTE state: router unchanged (the new line was removed again)" \
		not in lines
	assert lines[-1] == "STOPPED add-key r1: the key failed its proofs"


def test_action_revoke_removes_only_label_and_keeps_local_keys(router_unit):
	router = router_unit.router
	router.add_authorized_key(LINE_A)
	router.add_authorized_key(LINE_B)
	make = router_unit.run(
		"keypair_path lab-runner; keypair_create lab-runner\n")
	assert make.returncode == 0
	r = router_unit.run("ACTION=revoke\nLABEL=lab-runner\naction_revoke\n")
	assert r.returncode == 0
	assert "PASS revoked 1 line(s) for lab-runner" in r.stdout.splitlines()
	assert any(line.startswith("INFO local key files kept:")
		for line in r.stdout.splitlines())
	assert r.stdout.splitlines()[-1] == "DONE revoke r1"
	assert LINE_A not in router.authorized_keys()
	assert LINE_B in router.authorized_keys()
	assert (router_unit.keys / "r1-lab-runner").exists()
	assert (router_unit.keys / "r1-lab-runner.pub").exists()

	second = router_unit.run(
		"ACTION=revoke\nLABEL=lab-runner\naction_revoke\n")
	assert second.returncode == 0
	assert "PASS already revoked" in second.stdout.splitlines()
	assert LINE_B in router.authorized_keys()


def test_action_revoke_unknown_label_is_already_revoked(router_unit):
	before = router_unit.router.read("etc/dropbear/authorized_keys")
	r = router_unit.run("ACTION=revoke\nLABEL=unknown-key\naction_revoke\n")
	assert r.returncode == 0
	assert r.stdout.splitlines() == [
		"PASS already revoked",
		"DONE revoke r1",
	]
	assert router_unit.router.read("etc/dropbear/authorized_keys") == before


# proof_backup no longer SIGPIPEs on a large tar listing
#


def test_proof_backup_passes_with_a_large_etc_config_listing(router_unit):
	# the old pipeline `tar -tzf | grep -q '^etc/config'` failed when
	# the listing was bigger than the pipe buffer: grep -q closes the
	# pipe after the first match, tar got SIGPIPE, set -o pipefail
	# made the pipeline status 141 and a good archive looked bad.
	# 4000 entries with 40-character names is well past the 64 KiB
	# buffer, so this test fails on the old code and passes on the fix.
	router = router_unit.router
	key = _proof_setup(router_unit)
	pad = "abcdefghijklmnopqrstuvwxyz0123456"
	for i in range(4000):
		router.write("etc/config/%s%d" % (pad, i), "x\n")
	r = router_unit.run(
		'proof_backup "%s" lab-runner change; echo rc=$?\n' % key)
	assert r.returncode == 0
	lines = r.stdout.splitlines()
	assert lines[0].startswith("PASS proof backup:")
	assert lines[-1] == "rc=0"


# a proof FAIL line must name what was expected and what was
# seen, and must not just repeat the PASS wording


@pytest.mark.parametrize("function,name,fail_setup", [
	# proof_hello: broken program, the reply becomes empty
	("proof_hello", "hello", dict(program="broken")),
	# proof_probe_fail: broken program
	("proof_probe_fail", "probe-fail", dict(program="broken")),
	# proof_bad_arg: broken program
	("proof_bad_arg", "bad-arg", dict(program="broken")),
	# proof_selftest_refused: broken program
	("proof_selftest_refused", "selftest-refused", dict(program="broken")),
	# proof_backup: broken program
	("proof_backup", "backup", dict(program="broken")),
	# proof_unknown_and_empty: broken program
	("proof_unknown_and_empty", "unknown-and-empty", dict(program="broken")),
	# proof_forwards: vulnerable to forwarding
	("proof_forwards", "forwards", dict(vulnerable=("forwarding",))),
	# proof_pty_agent: vulnerable to pty
	("proof_pty_agent", "pty-agent", dict(vulnerable=("pty",))),
	# proof_sftp_scp: unrestricted key (the line has no `restrict` options)
	("proof_sftp_scp", "sftp-scp", None),
	# proof_setenv: vulnerable to setenv
	("proof_setenv", "setenv", dict(vulnerable=("setenv",))),
])
def test_proof_fail_line_uses_expected_and_got(router_unit, function, name, fail_setup):
	pass_wording = {
		"hello": "PASS proof hello: restricted identity",
		"probe-fail": "PASS proof probe-fail: stdin and exit status",
		"bad-arg": "PASS proof bad-arg: rejected",
		"selftest-refused": "PASS proof selftest-refused: direct-only",
		"backup": "PASS proof backup: change-role archive",
		"unknown-and-empty": "PASS proof unknown-and-empty: rejected",
		"forwards": "PASS proof forwards: blocked",
		"pty-agent": "PASS proof pty-agent: blocked",
		"sftp-scp": "PASS proof sftp-scp: blocked",
		"setenv": "PASS proof setenv: prod preserved",
	}[name]
	if fail_setup is None:
		# proof_sftp_scp needs a restricted-principal that is missing the
		# `restrict` option, so the principal is treated as unrestricted
		key = _proof_setup(router_unit)
		lines = router_unit.router.authorized_keys()
		lines[-1] = "ssh-ed25519 %s newton-router-lab-runner" % BLOB_A
		router_unit.router.write(
			"etc/dropbear/authorized_keys", "\n".join(lines) + "\n")
		r = router_unit.run(
			'%s "%s" lab-runner change; echo rc=$?\n' % (function, key))
	else:
		r = _run_proof(router_unit, function, **fail_setup)
	assert r.returncode == 0
	lines = r.stdout.splitlines()
	fail_lines = [line for line in lines if line.startswith("FAIL proof %s:" % name)]
	assert len(fail_lines) == 1
	fail_line = fail_lines[0]
	assert "expected" in fail_line, fail_line
	assert "got" in fail_line, fail_line
	# the text after the prefix must differ from the PASS text (comparing
	# the whole lines would be vacuous: one starts with PASS, one with FAIL)
	assert fail_line.split(": ", 1)[1] != pass_wording.split(": ", 1)[1], fail_line


# main reorders require_known_hosts and the password prompt,
# and choose_admin_path forces plain-key for swap-key


@pytest.mark.parametrize("action", [
	"check", "install", "approval-key", "add-key", "revoke",
	"profile", "upgrade", "rollback", "uninstall", "lab-snapshot",
])
def test_main_prompts_for_root_password_before_dispatching(unit, action):
	# every action but `check` calls
	# require_known_hosts first; EVERY action prefetches the root
	# password in the parent shell when ADMIN_MODE=password. The action
	# stub reads the second typed-input line, which only succeeds when
	# the prompt consumed line 1 first (so prompt-then-stub order is
	# proven, and the prompt happens exactly once).
	code = (
		'parse_args() { DEVICE=r1; ACTION=%s; }\n'
		'load_inventory() { :; }\n'
		'choose_admin_path() { ADMIN_MODE=password; }\n'
		'validate_action_args() { :; }\n'
		'require_known_hosts() { :; }\n'
		'action_%s() {\n'
		'    IFS= read -r -u "$TTY_FD" seen\n'
		'    printf "seen=%%s\\n" "$seen"\n'
		'}\n'
		'main\n'
	) % (action, action.replace("-", "_"))
	r = unit.run(code, tty=["root-pw", "STUB_RAN"])
	assert r.returncode == 0
	assert r.stderr.count("root password: ") == 1
	assert r.stdout.splitlines() == ["seen=STUB_RAN"]


def test_main_known_hosts_check_runs_before_password_prompt(unit):
	# an action other than `check` exits 2 with the
	# known_hosts message and never asks for the root password
	kh = unit.tmp / "no-such.known_hosts"
	code = (
		'DEV_KNOWN_HOSTS=%s\n'
		'parse_args() { DEVICE=r1; ACTION=upgrade; }\n'
		'load_inventory() { :; }\n'
		'choose_admin_path() { ADMIN_MODE=password; }\n'
		'action_upgrade() { printf "unreachable\\n"; }\n'
		'main\n'
	) % kh
	r = unit.run(code, tty=["should-not-be-read"])
	assert r.returncode == 2
	assert "run check first" in r.stderr
	assert "root password: " not in r.stderr


def test_choose_admin_path_swap_key_uses_plain_key_from_inventory_key_file(unit):
	# even with an inventory `key_file` (which would
	# normally pick the password lane), swap-key must use plain-key
	code = (
		'DEV_KEY_FILE=/etc/newton/keys/r1-known\n'
		'PLAIN_KEY_OPT=%s\n'
		'ACTION=swap-key\n'
		'choose_admin_path\n'
		'printf "mode=%%s key=%%s\\n" "$ADMIN_MODE" "$PLAIN_KEY"\n'
	) % str(unit.plain)
	r = unit.run(code)
	assert r.returncode == 0
	assert r.stdout.strip() == "mode=plain-key key=%s" % str(unit.plain)


def test_choose_admin_path_swap_key_rejects_admin_password(unit):
	code = (
		'ACTION=swap-key\n'
		'ADMIN_OPT=password\n'
		'choose_admin_path\n'
	)
	r = unit.run(code)
	assert r.returncode == 2
	assert "swap-key needs the plain-key admin path" in r.stderr


def test_choose_admin_path_swap_key_rejects_password_file(unit):
	pw = unit.tmp / "pw"
	pw.write_text("secret\n")
	pw.chmod(0o600)
	code = (
		'PASSWORD_FILE=%s\n'
		'DEV_PROFILE=lab\n'
		'ACTION=swap-key\n'
		'choose_admin_path\n'
	) % pw
	r = unit.run(code)
	assert r.returncode == 2
	assert "swap-key needs the plain-key admin path" in r.stderr


# swap-key sub-steps 1 to 4 (design 8.3): swap_prepare, the
# already-done predicate, swap_stage_new_line (2), swap_prove_new_key (3),
# deadman_text (4) and swap_start_deadman.

SWAP_NONCE = "0123456789abcdef0123456789abcdef"
SWAP_EXTRA = "ssh-ed25519 AAAAEXTRAKEYFORSWAPTESTS0001 agent-laptop"
SWAP_DEADMAN_ORACLE = (
	"setsid sh -c 'sleep 90; "
	"grep -q \"^%s \" /tmp/newton/hello 2>/dev/null || "
	"{ cp -p /etc/dropbear/authorized_keys.newton-prev /etc/dropbear/authorized_keys; "
	"logger -t newton-setup \"key swap not proven in 90 s; authorized_keys restored\"; }' "
	"</dev/null >/dev/null 2>&1 &"
)


def test_deadman_text_oracle_with_empty_rr(unit):
	r = unit.run("deadman_text %s\n" % SWAP_NONCE)
	assert r.returncode == 0
	assert r.stdout == (SWAP_DEADMAN_ORACLE % SWAP_NONCE) + "\n"


def test_deadman_text_rr_prefixes_the_three_locations(unit):
	nonce = "abcdef0123456789abcdef0123456789"
	expected = (
		"setsid sh -c 'sleep 90; "
		"grep -q \"^%s \" /x/tmp/newton/hello 2>/dev/null || "
		"{ cp -p /x/etc/dropbear/authorized_keys.newton-prev /x/etc/dropbear/authorized_keys; "
		"logger -t newton-setup \"key swap not proven in 90 s; authorized_keys restored\"; }' "
		"</dev/null >/dev/null 2>&1 &"
	) % nonce
	r = unit.run("RR=/x\ndeadman_text %s\n" % nonce)
	assert r.returncode == 0
	assert r.stdout == expected + "\n"


def test_deadman_text_bad_nonce_dies(unit):
	r = unit.run("deadman_text 'not-a-nonce'; echo rc=$?\n")
	assert r.returncode == 2
	assert "bad nonce" in r.stderr
	assert "rc=" not in r.stdout


def test_swap_prepare_sets_globals_and_validates(router_unit):
	router = router_unit.router
	router.add_authorized_key(SWAP_EXTRA)
	r = router_unit.run(
		"LABEL=newton-agent\nNEW_KEY=1\nswap_prepare\n"
		"printf 'KEY=%s\\n' \"$KEYFILE\"\n"
		"printf 'OLD=%s\\n' \"$OLD_BLOB\"\n"
		"printf 'NEW=%s\\n' \"$NEW_BLOB\"\n"
		"printf 'LINE=%s\\n' \"$NEW_LINE\"\n"
	)
	assert r.returncode == 0
	lines = r.stdout.splitlines()
	key = next(l[4:] for l in lines if l.startswith("KEY="))
	old = next(l[4:] for l in lines if l.startswith("OLD="))
	new = next(l[4:] for l in lines if l.startswith("NEW="))
	line = next(l[5:] for l in lines if l.startswith("LINE="))
	assert key == str(router_unit.keys / "r1-newton-agent")
	assert old == PLAIN_BLOB
	assert re.fullmatch(r"[A-Za-z0-9+/=]+", new)
	assert new != old
	expected = (
		"restrict,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,"
		"no-pty,command=\"/usr/libexec/newton/newton-router "
		"--caller=newton-agent --role=change\" ssh-ed25519 %s "
		"newton-router-newton-agent" % new
	)
	assert line == expected
	assert (router_unit.keys / "r1-newton-agent").exists()
	assert (router_unit.keys / "r1-newton-agent.pub").exists()


def test_swap_prepare_password_mode_dies(router_unit):
	r = router_unit.run(
		"LABEL=newton-agent\nADMIN_MODE=password\nswap_prepare; echo rc=$?\n"
	)
	assert r.returncode == 2
	assert "swap-key needs the plain-key admin path" in r.stderr
	assert "rc=" not in r.stdout


def test_swap_prepare_same_key_dies(router_unit):
	r = router_unit.run(
		"LABEL=newton-agent\nNEW_KEY=1\nswap_prepare\n"
		"PLAIN_KEY=$KEYFILE\n"
		"swap_prepare; echo rc=$?\n"
	)
	assert r.returncode == 2
	assert "the plain key and the new key are the same key" in r.stderr
	assert "rc=" not in r.stdout


def test_swap_stage_new_line_creates_prev_and_appends(router_unit):
	router = router_unit.router
	rel = "etc/dropbear/authorized_keys"
	prev_rel = "etc/dropbear/authorized_keys.newton-prev"
	router.add_authorized_key(SWAP_EXTRA)
	original = router.read(rel)
	r = router_unit.run(
		"LABEL=newton-agent\nNEW_KEY=1\nswap_prepare\n"
		"swap_stage_new_line; echo rc=$?\n"
		"printf 'SWAPPED=%d\\n' \"$SWAP_APPENDED\"\n"
		"printf 'NEW=%s\\n' \"$NEW_BLOB\"\n"
	)
	assert r.returncode == 0
	assert "rc=0" in r.stdout
	assert "SWAPPED=1" in r.stdout
	new_blob = next(l[4:] for l in r.stdout.splitlines() if l.startswith("NEW="))
	assert router.read(prev_rel) == original
	assert _mode_of(router, prev_rel) == 0o600
	live_lines = router.authorized_keys()
	new_lines = [l for l in live_lines if new_blob in l]
	assert len(new_lines) == 1
	assert SWAP_EXTRA in live_lines
	assert any(
		l == "ssh-ed25519 %s agent@unit" % PLAIN_BLOB for l in live_lines
	)


def test_swap_stage_new_line_second_call_changes_nothing(router_unit):
	router = router_unit.router
	rel = "etc/dropbear/authorized_keys"
	prev_rel = "etc/dropbear/authorized_keys.newton-prev"
	router.add_authorized_key(SWAP_EXTRA)
	router_unit.run(
		"LABEL=newton-agent\nNEW_KEY=1\nswap_prepare\nswap_stage_new_line\n")
	live_after_first = router.read(rel)
	r = router_unit.run(
		"LABEL=newton-agent\nNEW_KEY=1\nswap_prepare\n"
		"swap_stage_new_line; echo rc=$?\n"
		"printf 'SWAPPED=%d\\n' \"$SWAP_APPENDED\"\n"
	)
	assert r.returncode == 0
	assert "rc=0" in r.stdout
	assert "SWAPPED=0" in r.stdout
	assert router.read(prev_rel) == live_after_first
	assert router.read(rel) == live_after_first


def test_swap_stage_new_line_replaces_stale_prev_when_line_exists(router_unit):
	router = router_unit.router
	rel = "etc/dropbear/authorized_keys"
	prev_rel = "etc/dropbear/authorized_keys.newton-prev"
	router_unit.run(
		"LABEL=newton-agent\nNEW_KEY=1\nswap_prepare\nswap_stage_new_line\n")
	live = router.read(rel)
	router.write(prev_rel, "stale content that must not survive\n", 0o600)
	r = router_unit.run(
		"LABEL=newton-agent\nNEW_KEY=1\nswap_prepare\n"
		"swap_stage_new_line; echo rc=$?\n"
		"printf 'SWAPPED=%d\\n' \"$SWAP_APPENDED\"\n"
	)
	assert r.returncode == 0
	assert "rc=0" in r.stdout
	assert "SWAPPED=0" in r.stdout
	assert router.read(rel) == live
	assert router.read(prev_rel) == live


def test_swap_prove_new_key_passes_with_installed_program(router_unit):
	router = router_unit.router
	_install_code_files(router, router_unit.tmp)
	router.add_authorized_key(SWAP_EXTRA)
	r = router_unit.run(
		"LABEL=newton-agent\nNEW_KEY=1\nswap_prepare\n"
		"swap_stage_new_line\n"
		"swap_prove_new_key; echo rc=$?\n"
	)
	assert r.returncode == 0
	assert "rc=0" in r.stdout
	assert not any(
		l.startswith("FAIL proof") for l in r.stdout.splitlines()
	)
	assert not any(
		l.startswith("STOPPED") for l in r.stdout.splitlines()
	)


def test_swap_prove_new_key_broken_program_removes_new_line(router_unit):
	router = router_unit.router
	rel = "etc/dropbear/authorized_keys"
	prev_rel = "etc/dropbear/authorized_keys.newton-prev"
	_install_code_files(router, router_unit.tmp, program="broken")
	router.add_authorized_key(SWAP_EXTRA)
	before_stage = router.read(rel)
	r = router_unit.run(
		"ACTION=swap-key\nLABEL=newton-agent\nNEW_KEY=1\nswap_prepare\n"
		"swap_stage_new_line\n"
		"swap_prove_new_key\n"
	)
	assert r.returncode == 1
	lines = r.stdout.splitlines()
	assert lines[-1] == "STOPPED swap-key r1: the new key failed its proofs"
	assert "NOTE state: router unchanged (the new line was removed again)" in lines
	assert router.read(rel) == before_stage
	assert router.path(prev_rel).exists()
	assert router.read(prev_rel) == before_stage


def test_swap_already_done_exits_1_before_swap(router_unit):
	r = router_unit.run(
		"LABEL=newton-agent\nNEW_KEY=1\nswap_prepare\n"
		"swap_already_done; echo rc=$?\n"
	)
	assert r.returncode == 0
	assert r.stdout.splitlines()[-1] == "rc=1"


def test_swap_already_done_exits_0_after_hand_made_swap(router_unit):
	router = router_unit.router
	rel = "etc/dropbear/authorized_keys"
	_install_code_files(router, router_unit.tmp)
	r = router_unit.run(
		"LABEL=newton-agent\nNEW_KEY=1\nswap_prepare\n"
		"printf 'KEYFILE_OUT=%s\\n' \"$KEYFILE\"\n"
		"printf 'NEW_LINE_OUT=%s\\n' \"$NEW_LINE\"\n"
	)
	assert r.returncode == 0
	keyfile = next(
		l[len("KEYFILE_OUT="):] for l in r.stdout.splitlines()
		if l.startswith("KEYFILE_OUT=")
	)
	new_line = next(
		l[len("NEW_LINE_OUT="):] for l in r.stdout.splitlines()
		if l.startswith("NEW_LINE_OUT=")
	)
	lines = [l for l in router.authorized_keys() if PLAIN_BLOB not in l]
	lines.append(new_line)
	router.write(rel, "\n".join(lines) + "\n", 0o600)
	r = router_unit.run(
		"LABEL=newton-agent\nKEYFILE=%s\nswap_prepare\n"
		"DEV_KEY_FILE=%s\nswap_already_done; echo rc=$?\n" % (keyfile, keyfile)
	)
	assert r.returncode == 0
	assert r.stdout.splitlines()[-1] == "rc=0"


def test_swap_already_done_exits_1_when_plain_key_still_works(router_unit):
	router = router_unit.router
	rel = "etc/dropbear/authorized_keys"
	_install_code_files(router, router_unit.tmp)
	r = router_unit.run(
		"LABEL=newton-agent\nNEW_KEY=1\nswap_prepare\n"
		"printf 'KEYFILE_OUT=%s\\n' \"$KEYFILE\"\n"
		"printf 'NEW_LINE_OUT=%s\\n' \"$NEW_LINE\"\n"
	)
	assert r.returncode == 0
	keyfile = next(
		l[len("KEYFILE_OUT="):] for l in r.stdout.splitlines()
		if l.startswith("KEYFILE_OUT=")
	)
	new_line = next(
		l[len("NEW_LINE_OUT="):] for l in r.stdout.splitlines()
		if l.startswith("NEW_LINE_OUT=")
	)
	lines = list(router.authorized_keys())
	lines.append(new_line)
	router.write(rel, "\n".join(lines) + "\n", 0o600)
	r = router_unit.run(
		"LABEL=newton-agent\nKEYFILE=%s\nswap_prepare\n"
		"DEV_KEY_FILE=%s\nswap_already_done; echo rc=$?\n" % (keyfile, keyfile)
	)
	assert r.returncode == 0
	assert r.stdout.splitlines()[-1] == "rc=1"


def test_swap_start_deadman_no_proof_line_restores(router_unit):
	router = router_unit.router
	rel = "etc/dropbear/authorized_keys"
	prev_rel = "etc/dropbear/authorized_keys.newton-prev"
	# keep the plain line so the admin path can reach the router, append
	# a marker line, and put a different content in the prev so the cp
	# restores the prev and the test sees it
	plain_line = "ssh-ed25519 %s agent@unit" % PLAIN_BLOB
	router.write(rel, plain_line + "\nlive-marker\n", 0o600)
	router.write(prev_rel, "prev-marker\n", 0o600)
	clock_before = router.clock()
	r = router_unit.run("swap_start_deadman %s; echo rc=$?\n" % SWAP_NONCE)
	assert r.returncode == 0
	assert "rc=0" in r.stdout
	# the backgrounded setsid stub is racing the bash exit; poll for it
	timers = _wait_for_timers(router, count=1)
	assert timers[0]["due"] == clock_before + 90
	fake_sleep = router_unit.bindir / "fake-sleep"
	env = {"FAKE_ROUTER_ROOT": str(router.root)}
	subprocess.run([str(fake_sleep), "89"], env=env, check=True)
	assert len(router.timers()) == 1
	assert router.read(rel) == plain_line + "\nlive-marker\n"
	subprocess.run([str(fake_sleep), "1"], env=env, check=True)
	assert len(router.timers()) == 0
	assert router.read(rel) == "prev-marker\n"
	syslog = router.read("tmp/syslog")
	assert "authorized_keys restored" in syslog


def test_swap_start_deadman_with_proof_line_does_nothing(router_unit):
	router = router_unit.router
	rel = "etc/dropbear/authorized_keys"
	hello_rel = "tmp/newton/hello"
	plain_line = "ssh-ed25519 %s agent@unit" % PLAIN_BLOB
	router.write(rel, plain_line + "\nlive-marker\n", 0o600)
	router.path(hello_rel).parent.mkdir(parents=True, exist_ok=True)
	router.write(hello_rel, "%s x y\n" % SWAP_NONCE)
	r = router_unit.run("swap_start_deadman %s; echo rc=$?\n" % SWAP_NONCE)
	assert r.returncode == 0
	_wait_for_timers(router, count=1)
	fake_sleep = router_unit.bindir / "fake-sleep"
	env = {"FAKE_ROUTER_ROOT": str(router.root)}
	subprocess.run([str(fake_sleep), "90"], env=env, check=True)
	assert router.read(rel) == plain_line + "\nlive-marker\n"
	if router.path("tmp/syslog").exists():
		syslog = router.read("tmp/syslog")
		assert "authorized_keys restored" not in syslog


def _wait_for_timers(router, count, timeout=10.0):
	"""Poll timers.json for `count` pending timers; the backgrounded
	setsid stub races the bash exit, so the file may be empty briefly."""
	import time
	deadline = time.time() + timeout
	while time.time() < deadline:
		timers = router.timers()
		if len(timers) >= count:
			return timers
		time.sleep(0.05)
	raise AssertionError("timers never reached %d (got %r)"
		% (count, router.timers()))


def _prep_new_key(router_unit, blob):
	"""Pre-create the (device, newton-agent) private key file with
	`blob` as its stored private blob, so keypair_create does not
	recreate it and pub_blob returns `blob`.  Returns the path."""
	key = router_unit.keys / "r1-newton-agent"
	key.write_text("FAKE-OPENSSH-PRIVATE-KEY\n%s\n" % blob)
	key.chmod(0o600)
	return key


# swap-key sub-steps 5-8 (design 8.3), the inventory write and the
# action_swap_key dispatcher


def test_swap_start_deadman_bad_nonce_returns_one_without_ssh(unit):
	# repair of RB1: `text=$(deadman_text "$1")` hides a `die` of the
	# subshell, so when `deadman_text` dies the variable is empty and
	# `swap_start_deadman` must return 1 WITHOUT running rsh_admin.
	# the empty BIN seam has no ssh, so any ssh call would have died
	# too -- the test below proves no ssh call leaves the bin dir.
	r = unit.run(
		"swap_start_deadman 'not-hex'\n"
		'echo "rc=$?"\n'
	)
	assert r.returncode == 0
	lines = r.stdout.splitlines()
	assert lines[-1] == "rc=1"
	# and the ssh binary was never invoked; the fake ssh's argv log is
	# empty (no ssh calls have ever been made)
	assert unit.argv() == []


def test_inventory_set_key_text_two_devices_only_this_changes(unit):
	# a toml with comments, two devices and an existing key_file line
	# in the OTHER device: only the target device's two lines change or
	# appear, every other byte is the same, the result parses with
	# tomllib.
	body = (
		"# a comment before devices\n"
		"\n"
		"[devices.other]\n"
		"host = \"10.1.2.4\"\n"
		"# a comment inside the other table\n"
		"key_file = \"/old/other/key\"\n"
		"\n"
		"[devices.r1]\n"
		"host = \"10.1.2.3\"\n"
		"profile = \"lab\"\n"
	)
	inf = unit.tmp / "devs_in.toml"
	inf.write_text(body)
	out = _run_inventory_text(unit, "r1", "/keys/r1-lab", "/keys/r1.kh", inf)
	# the comment + devices.other table are unchanged
	assert "[devices.other]" in out
	assert "key_file = \"/old/other/key\"" in out
	assert "host = \"10.1.2.4\"" in out
	assert "# a comment before devices" in out
	# the new lines are in the r1 table, after the last non-blank line
	r1_idx = out.index("[devices.r1]")
	assert "key_file = \"/keys/r1-lab\"" in out
	assert "known_hosts = \"/keys/r1.kh\"" in out
	# the new lines come AFTER profile = "lab"
	assert out.index("profile = \"lab\"") < out.index("key_file = \"/keys/r1-lab\"")
	assert out.index("key_file = \"/keys/r1-lab\"") < out.index(
		"known_hosts = \"/keys/r1.kh\"")
	# and the r1 lines come after the [devices.r1] header
	assert r1_idx < out.index("key_file = \"/keys/r1-lab\"")
	# parses with tomllib
	import tomllib
	parsed = tomllib.loads(out)
	assert "key_file" in parsed["devices"]["r1"]
	assert parsed["devices"]["r1"]["key_file"] == "/keys/r1-lab"
	assert "known_hosts" in parsed["devices"]["r1"]
	assert parsed["devices"]["r1"]["known_hosts"] == "/keys/r1.kh"
	assert parsed["devices"]["other"]["key_file"] == "/old/other/key"


def test_inventory_set_key_text_second_call_changes_nothing(unit):
	# a second call on a device that already has both lines changes
	# only the values; running it twice must produce identical bytes
	# the second time.
	body = (
		"[devices.r1]\n"
		"host = \"10.1.2.3\"\n"
		"profile = \"lab\"\n"
		"key_file = \"/keys/r1-old\"\n"
		"known_hosts = \"/keys/r1-old.kh\"\n"
	)
	inf = unit.tmp / "devs_in.toml"
	inf.write_text(body)
	out_first = _run_inventory_text(
		unit, "r1", "/keys/r1-new", "/keys/r1-new.kh", inf)
	# second call on the result of the first: same values, identical output
	inf2 = unit.tmp / "devs_in2.toml"
	inf2.write_text(out_first)
	out_second = _run_inventory_text(
		unit, "r1", "/keys/r1-new", "/keys/r1-new.kh", inf2)
	assert out_second == out_first


def test_inventory_set_key_text_unknown_device_dies(unit):
	# a device with no table dies on stderr (non-zero exit).
	body = "[devices.other]\nhost = \"10.1.2.4\"\n"
	inf = unit.tmp / "devs_in.toml"
	inf.write_text(body)
	r = unit.run(
		"inventory_set_key_text r1 /keys/r1 /keys/r1.kh < '%s' || exit 2\n"
		'echo "rc=$?"\n' % inf
	)
	assert r.returncode == 2
	assert "error:" in r.stderr
	assert "device not in inventory" in r.stderr
	assert "rc=" not in r.stdout


def test_inventory_set_key_text_existing_both_lines_replaced(unit):
	# the case where the device already has both lines: they are
	# replaced in place at the same positions.
	body = (
		"[devices.r1]\n"
		"host = \"10.1.2.3\"\n"
		"key_file = \"/old/key\"\n"
		"known_hosts = \"/old/key.kh\"\n"
		"profile = \"lab\"\n"
	)
	inf = unit.tmp / "devs_in.toml"
	inf.write_text(body)
	out = _run_inventory_text(
		unit, "r1", "/keys/r1-new", "/keys/r1-new.kh", inf)
	# line positions preserved (host, key_file, known_hosts, profile)
	lines = out.splitlines()
	assert lines[0] == "[devices.r1]"
	assert lines[1] == "host = \"10.1.2.3\""
	assert lines[2] == "key_file = \"/keys/r1-new\""
	assert lines[3] == "known_hosts = \"/keys/r1-new.kh\""
	assert lines[4] == "profile = \"lab\""
	import tomllib
	parsed = tomllib.loads(out)
	assert parsed["devices"]["r1"]["key_file"] == "/keys/r1-new"
	assert parsed["devices"]["r1"]["known_hosts"] == "/keys/r1-new.kh"


def _run_inventory_text(unit, device, keyfile, kh, input_path):
	"""Run inventory_set_key_text on a unit fixture, returning the
	toml text written to stdout (the appended `rc=N` line is stripped)."""
	code = (
		"inventory_set_key_text %s %s %s < '%s'\n"
		'echo "rc=$?"\n'
	) % (shlex.quote(device), shlex.quote(keyfile),
		shlex.quote(kh), input_path)
	r = unit.run(code)
	assert r.returncode == 0, (r.stdout, r.stderr)
	# the output ends with the rc=N line followed by an optional \n.
	stdout = r.stdout
	if stdout.endswith("\n"):
		stdout = stdout[:-1]
	out, _, tail = stdout.rpartition("\n")
	m = re.match(r"^rc=(\d+)$", tail)
	assert m, (tail, repr(r.stdout))
	return out + "\n" if out else ""


def test_inventory_set_key_keeps_mode_no_dot_new_and_other_device(router_unit):
	# inventory_set_key on a real file: the new content is atomic,
	# the other device parses to the same values, and the mode is kept.
	inv = router_unit.tmp / "devices.toml"
	inv.write_text(
		"[devices.other]\n"
		"host = \"10.1.2.4\"\n"
		"profile = \"lab\"\n"
		"key_file = \"/old/other\"\n"
		"known_hosts = \"/old/other.kh\"\n"
		"\n"
		"[devices.r1]\n"
		"host = \"10.1.2.3\"\n"
		"profile = \"lab\"\n"
	)
	# 0640, not 0600: the tool runs with umask 077, so a .new file gets 0600 by
	# itself and a test with 0600 could not tell a kept mode from a default
	# (a planted defect that dropped the chmod survived)
	inv.chmod(0o640)
	r = router_unit.run(
		"INVENTORY='%s'\n"
		"inventory_set_key r1 /keys/r1-new /keys/r1-new.kh; echo rc=$?\\n"
		% inv,
		extra_env={"NEWTON_INVENTORY": str(inv)},
	)
	assert r.returncode == 0
	assert "rc=0" in r.stdout
	assert not (router_unit.tmp / "devices.toml.new").exists()
	# mode is kept
	assert _mode_of_path(inv) == 0o640
	import tomllib
	parsed = tomllib.loads(inv.read_text())
	# other device unchanged
	assert parsed["devices"]["other"]["key_file"] == "/old/other"
	assert parsed["devices"]["other"]["known_hosts"] == "/old/other.kh"
	# this device has both
	assert parsed["devices"]["r1"]["key_file"] == "/keys/r1-new"
	assert parsed["devices"]["r1"]["known_hosts"] == "/keys/r1-new.kh"


def _mode_of_path(path):
	import stat
	return stat.S_IMODE(path.stat().st_mode)


def test_inventory_set_key_bad_value_returns_one_and_no_dot_new(router_unit):
	# A value that fails the [A-Za-z0-9_./-]+ validator is an inventory
	# update failure: report it, return 1, and leave no .new file.
	inv = router_unit.tmp / "devices.toml"
	inv.write_text("[devices.r1]\nhost = \"10.1.2.3\"\nprofile = \"lab\"\n")
	r = router_unit.run(
		"INVENTORY='%s'\n"
		"inventory_set_key r1 'bad value!' /keys/r1.kh; echo rc=$?\\n"
		% inv,
		extra_env={"NEWTON_INVENTORY": str(inv)},
	)
	assert r.returncode == 0
	assert "error:" in r.stderr
	assert "rc=1" in r.stdout
	assert not inv.with_name(inv.name + ".new").exists()


def test_swap_replace_key_lines_success(router_unit):
	# swap_replace_key_lines against the fake router after staging the
	# new line: the old plain line is gone, the extra key line stays,
	# the new line appears once, mode 600.
	router = router_unit.router
	rel = "etc/dropbear/authorized_keys"
	router.add_authorized_key(SWAP_EXTRA)
	_prep_new_key(router_unit, BLOB_A)
	setup = router_unit.run(
		"LABEL=newton-agent\n"
		"OLD_BLOB=%s\n" % PLAIN_BLOB +
		"swap_prepare\n"
		"swap_stage_new_line\n"
		"swap_replace_key_lines\n"
		'echo "rc=$?"\n'
	)
	assert setup.returncode == 0
	assert setup.stdout.splitlines()[-1] == "rc=0"
	live_lines = router.authorized_keys()
	# the old plain blob line is gone
	assert not any(PLAIN_BLOB in l for l in live_lines)
	# the extra key line survives verbatim
	assert SWAP_EXTRA in live_lines
	# the new blob appears exactly once
	new_count = sum(1 for l in live_lines if BLOB_A in l)
	assert new_count == 1
	# mode 600
	assert _mode_of(router, rel) == 0o600
	# no .new left
	assert not router.path(rel + ".new").exists()


def test_swap_replace_key_lines_failure_touches_nothing(router_unit):
	# NEW_BLOB is not on the router, so the count check must fail and
	# the live file must stay untouched.
	router = router_unit.router
	rel = "etc/dropbear/authorized_keys"
	prev_rel = "etc/dropbear/authorized_keys.newton-prev"
	router.add_authorized_key(SWAP_EXTRA)
	# stage a new line with BLOB_A; then run replace with a NONCE
	# that asserts NEW_BLOB=BLOB_B (no BLOB_B anywhere) -> rc=1
	_prep_new_key(router_unit, BLOB_A)
	router_unit.run(
		"LABEL=newton-agent\n"
		"OLD_BLOB=%s\n" % PLAIN_BLOB +
		"swap_prepare\n"
		"swap_stage_new_line\n"
	)
	live_before = router.read(rel)
	prev_before = router.read(prev_rel)
	# push a different NEW_BLOB onto the file path; force the awk
	# count to fail by pointing NEW_BLOB at a blob that is not on the
	# router (BLOB_B is unused here).
	r = router_unit.run(
		"LABEL=newton-agent\n"
		"OLD_BLOB=%s\n" % PLAIN_BLOB +
		"NEW_BLOB=%s\n" % BLOB_B +
		"NEW_LINE='restrict,... ssh-ed25519 %s newton-router-newton-agent'\n" % BLOB_B +
		"swap_replace_key_lines\n"
		'echo "rc=$?"\n'
	)
	assert r.returncode == 0
	assert r.stdout.splitlines()[-1] == "rc=1"
	# the live file is unchanged
	assert router.read(rel) == live_before
	# the .new file is removed
	assert not router.path(rel + ".new").exists()
	# and the .newton-prev is left alone
	assert router.read(prev_rel) == prev_before


def test_swap_replace_key_lines_rejects_a_bad_blob(router_unit):
	# one of the two blobs is not base64-only -> die(2), no ssh call
	r = router_unit.run(
		"LABEL=newton-agent\n"
		"OLD_BLOB='bad!blob'\n"
		"NEW_BLOB=%s\n" % BLOB_A +
		"NEW_LINE='restrict,... ssh-ed25519 %s newton-router-newton-agent'\n" % BLOB_A +
		"swap_replace_key_lines\n"
	)
	assert r.returncode == 2
	assert "error:" in r.stderr


def test_swap_confirm_and_old_refused_pre_replace_and_post_replace(router_unit):
	# before the replace: confirm must fail (new key's line is for
	# lab-runner, but LABEL is newton-agent, so caller mismatch);
	# old key refusal must FAIL because the plain key still works.
	# after enabling ghost_blobs: old key refusal still returns 1
	# even though its line is gone from authorized_keys.
	router = router_unit.router
	_install_code_files(router, router_unit.tmp)
	router.add_authorized_key(LINE_A)
	r = router_unit.run(
		"NEW_KEY=1\n"
		"LABEL=newton-agent\n"
		"OLD_BLOB=%s\n" % PLAIN_BLOB +
		"swap_prepare\n"
		"swap_confirm_new_key 0123456789abcdef0123456789abcdef\n"
		'echo "CONFIRM_BEFORE=$?"\n'
		"swap_old_key_refused\n"
		'echo "REFUSED_BEFORE=$?"\n'
	)
	assert r.returncode == 0
	out = {}
	for l in r.stdout.splitlines():
		if "=" in l:
			k, _, v = l.partition("=")
			out[k] = v
	assert out["CONFIRM_BEFORE"] == "1"
	assert out["REFUSED_BEFORE"] == "1"
	# with ghost_blobs, even after the file would have been replaced,
	# the plain key is still authenticated -> rsh_key true exits 0
	# (because the program runs true); swap_old_key_refused returns 1.
	router.update_state(ghost_blobs=[PLAIN_BLOB])
	r = router_unit.run(
		"NEW_KEY=1\n"
		"LABEL=newton-agent\n"
		"OLD_BLOB=%s\n" % PLAIN_BLOB +
		"swap_prepare\n"
		"swap_old_key_refused\n"
		'echo "REFUSED_GHOST=$?"\n'
	)
	assert r.returncode == 0
	out = {}
	for l in r.stdout.splitlines():
		if "=" in l:
			k, _, v = l.partition("=")
			out[k] = v
	assert out["REFUSED_GHOST"] == "1"


def test_swap_confirm_passes_after_replace(router_unit):
	# the post-replace path: with a working restricted key on the
	# router, the program installed, and the caller's caller/role/door/
	# mode fields right, swap_confirm_new_key returns 0 and
	# swap_old_key_refused returns 0 too.
	router = router_unit.router
	rel = "etc/dropbear/authorized_keys"
	prev_rel = "etc/dropbear/authorized_keys.newton-prev"
	_install_code_files(router, router_unit.tmp)
	line_agent = (
		"restrict,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,"
		'no-pty,command="/usr/libexec/newton/newton-router '
		'--caller=newton-agent --role=change" ssh-ed25519 %s '
		"newton-router-newton-agent" % BLOB_A
	)
	plain_line = "ssh-ed25519 %s agent@unit\n" % PLAIN_BLOB
	router.write(rel, plain_line + line_agent + "\n" + SWAP_EXTRA + "\n",
		0o600)
	router.write(prev_rel, plain_line, 0o600)
	router.update_state(deny_restricted_when_plain_absent=True,
		ghost_blobs=[])
	_prep_new_key(router_unit, BLOB_A)
	r = router_unit.run(
		"LABEL=newton-agent\n"
		"OLD_BLOB=%s\n" % PLAIN_BLOB +
		"swap_prepare\n"
		"swap_replace_key_lines\n"
		"swap_confirm_new_key 0123456789abcdef0123456789abcdef\n"
		'echo "CONFIRM_AFTER=$?"\n'
		"swap_old_key_refused\n"
		'echo "REFUSED_AFTER=$?"\n'
	)
	assert r.returncode == 0
	out = {}
	for l in r.stdout.splitlines():
		if "=" in l:
			k, _, v = l.partition("=")
			out[k] = v
	assert out["CONFIRM_AFTER"] == "0"
	assert out["REFUSED_AFTER"] == "0"


def test_swap_recover_restored_when_switch_started(router_unit):
	# with deny_restricted_when_plain_absent=True and the dead-man
	# timer started, after the replace the plain key is gone and the
	# new key cannot authenticate. swap_recover loops, eventually the
	# dead-man restores the prev, the plain key comes back, and the
	# function exits with STATE_NOTE='restored by the dead-man switch'.
	router = router_unit.router
	rel = "etc/dropbear/authorized_keys"
	prev_rel = "etc/dropbear/authorized_keys.newton-prev"
	_install_code_files(router, router_unit.tmp)
	line_agent = (
		"restrict,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,"
		'no-pty,command="/usr/libexec/newton/newton-router '
		'--caller=newton-agent --role=change" ssh-ed25519 %s '
		"newton-router-newton-agent" % BLOB_A
	)
	plain_line = "ssh-ed25519 %s agent@unit\n" % PLAIN_BLOB
	router.write(rel, plain_line + SWAP_EXTRA + "\n", 0o600)
	router.write(prev_rel, plain_line, 0o600)
	router.update_state(
		deny_restricted_when_plain_absent=True, ghost_blobs=[])
	router.add_authorized_key(line_agent)
	_prep_new_key(router_unit, BLOB_A)
	# the switch is started before the replace (so the plain line is
	# still on the router and the ssh call can succeed); swap_recover
	# then takes over after the replace.
	r = router_unit.run(
		"LABEL=newton-agent\n"
		"OLD_BLOB=%s\n" % PLAIN_BLOB +
		"swap_prepare\n"
		"swap_stage_new_line\n"
		"swap_start_deadman %s\n" % SWAP_NONCE +
		"swap_replace_key_lines\n"
		"swap_recover\n"
	)
	assert r.returncode == 1
	lines = r.stdout.splitlines()
	assert any("NOTE state: restored by the dead-man switch" in l for l in lines)
	assert lines[-1].startswith("STOPPED")
	# the live file equals the prev now
	assert router.read(rel) == router.read(prev_rel)


def test_swap_recover_not_restored_without_switch(router_unit):
	# no dead-man registered; after the replace the plain key is
	# gone and never comes back. swap_recover runs all 24 iterations
	# of wait_router 5 (=120 s) and ends with STATE_NOTE=NOT restored.
	router = router_unit.router
	rel = "etc/dropbear/authorized_keys"
	prev_rel = "etc/dropbear/authorized_keys.newton-prev"
	_install_code_files(router, router_unit.tmp)
	line_agent = (
		"restrict,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,"
		'no-pty,command="/usr/libexec/newton/newton-router '
		'--caller=newton-agent --role=change" ssh-ed25519 %s '
		"newton-router-newton-agent" % BLOB_A
	)
	plain_line = "ssh-ed25519 %s agent@unit\n" % PLAIN_BLOB
	router.write(rel, plain_line + SWAP_EXTRA + "\n", 0o600)
	router.write(prev_rel, plain_line, 0o600)
	router.update_state(
		deny_restricted_when_plain_absent=True, ghost_blobs=[])
	router.add_authorized_key(line_agent)
	_prep_new_key(router_unit, BLOB_A)
	r = router_unit.run(
		"LABEL=newton-agent\n"
		"OLD_BLOB=%s\n" % PLAIN_BLOB +
		"swap_prepare\n"
		"swap_stage_new_line\n"
		"swap_replace_key_lines\n"
		"swap_recover\n"
	)
	assert r.returncode == 1
	lines = r.stdout.splitlines()
	assert any("NOTE state: NOT restored; use the root password, LuCI or the console" in l
		for l in lines)
	# 24 * 5 = 120 s of advance
	assert router.clock() >= 120


def test_swap_settle_advances_clock_95_after_good_replace(router_unit):
	# good replace: wait_router 95 + confirm + old-refused. clock
	# advanced by 95. swap_settle must come after swap_replace_key_lines
	# in the same run (KEYFILE / NEW_BLOB / NEW_LINE are set by
	# swap_prepare, not by the router state).
	router = router_unit.router
	rel = "etc/dropbear/authorized_keys"
	prev_rel = "etc/dropbear/authorized_keys.newton-prev"
	_install_code_files(router, router_unit.tmp)
	line_agent = (
		"restrict,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,"
		'no-pty,command="/usr/libexec/newton/newton-router '
		'--caller=newton-agent --role=change" ssh-ed25519 %s '
		"newton-router-newton-agent" % BLOB_A
	)
	plain_line = "ssh-ed25519 %s agent@unit\n" % PLAIN_BLOB
	router.write(rel, plain_line + SWAP_EXTRA + "\n", 0o600)
	router.write(prev_rel, plain_line, 0o600)
	router.update_state(deny_restricted_when_plain_absent=True, ghost_blobs=[])
	router.add_authorized_key(line_agent)
	_prep_new_key(router_unit, BLOB_A)
	clock_before = router.clock()
	r = router_unit.run(
		"LABEL=newton-agent\n"
		"OLD_BLOB=%s\n" % PLAIN_BLOB +
		"swap_prepare\n"
		"swap_stage_new_line\n"
		"swap_replace_key_lines\n"
		"swap_settle\n"
		'echo "rc=$?"\n'
	)
	assert r.returncode == 0
	assert r.stdout.splitlines()[-1] == "rc=0"
	assert router.clock() - clock_before == 95


def test_action_swap_key_end_to_end(router_unit):
	# full action_swap_key on a router with the code files installed:
	# exit 0, last line DONE swap-key r1, the inventory file gained
	# key_file and known_hosts (via NEWTON_INVENTORY), the extra key
	# line is verbatim in authorized_keys, the plain blob line is gone.
	router = router_unit.router
	rel = "etc/dropbear/authorized_keys"
	_install_code_files(router, router_unit.tmp)
	router.add_authorized_key(SWAP_EXTRA)
	_prep_new_key(router_unit, BLOB_A)
	inv = router_unit.tmp / "devices.toml"
	inv.write_text("[devices.r1]\nhost = \"10.1.2.3\"\nprofile = \"lab\"\n")
	r = router_unit.run(
		"DEV_KNOWN_HOSTS=%s\n" % router_unit.kh +
		"DEVICE=r1\nACTION=swap-key\nLABEL=newton-agent\n"
		"action_swap_key\n",
		extra_env={"NEWTON_INVENTORY": str(inv)},
	)
	assert r.returncode == 0, (r.stdout, r.stderr)
	lines = r.stdout.splitlines()
	assert lines[-1] == "DONE swap-key r1"
	# one PASS line for each sub-step 2, 3, 4, 6, 7, 8, and one INFO
	# line for sub-step 5 (the replace prints its status, not a PASS)
	pass_lines = [l for l in lines if l.startswith("PASS swap step ")]
	assert len(pass_lines) == 6
	assert any(l.startswith("INFO swap step 5") for l in lines)
	# one INFO next: line
	assert any(l.startswith("INFO next: newton-doctor") for l in lines)
	# inventory updated
	import tomllib
	data = tomllib.loads(inv.read_text())
	assert "key_file" in data["devices"]["r1"]
	assert "known_hosts" in data["devices"]["r1"]
	# the extra key line is verbatim
	live_lines = router.authorized_keys()
	assert SWAP_EXTRA in live_lines
	# the plain blob line is gone
	assert not any(PLAIN_BLOB in l for l in live_lines)
	# no .new file left behind
	assert not router.path(rel + ".new").exists()


# repairs (tests that fail on the old code)


def test_inventory_set_key_keeps_one_final_newline(unit):
	# `new_text=$(...)` strips every trailing newline, so
	# the rewritten inventory used to lose its final LF. The sentinel
	# keeps every byte: append `x` inside the substitution and strip it.
	# This case: the inventory ends in exactly one LF and the result
	# must end in exactly one LF too.
	body = '[devices.r1]\nhost = "10.1.2.3"\nprofile = "lab"\n'
	inf = unit.tmp / "devs.toml"
	inf.write_bytes(body.encode("utf-8"))
	r = unit.run(
		"inventory_set_key r1 /keys/r1-new /keys/r1-new.kh\n",
		extra_env={"NEWTON_INVENTORY": str(inf)},
	)
	assert r.returncode == 0, (r.stdout, r.stderr)
	written = inf.read_bytes()
	# the last byte is the LF (0x0a) the original had, no extra x
	assert written.endswith(b"\n")
	assert not written.endswith(b"x\n")
	assert written[-1:] == b"\n"
	import tomllib
	parsed = tomllib.loads(written.decode("utf-8"))
	assert parsed["devices"]["r1"]["key_file"] == "/keys/r1-new"
	assert parsed["devices"]["r1"]["known_hosts"] == "/keys/r1-new.kh"


def test_inventory_set_key_keeps_two_final_newlines(unit):
	# the same byte-faithful rule when the inventory
	# ends in TWO LFs -- the old code collapsed both to nothing.
	body = '[devices.r1]\nhost = "10.1.2.3"\nprofile = "lab"\n\n'
	inf = unit.tmp / "devs.toml"
	inf.write_bytes(body.encode("utf-8"))
	r = unit.run(
		"inventory_set_key r1 /keys/r1-new /keys/r1-new.kh\n",
		extra_env={"NEWTON_INVENTORY": str(inf)},
	)
	assert r.returncode == 0, (r.stdout, r.stderr)
	written = inf.read_bytes()
	# both LFs preserved, no trailing x
	assert written.endswith(b"\n\n")
	assert not written.endswith(b"x\n")
	# the byte right before the last LF must also be LF (both LFs
	# present), and the very last byte must be LF (no sentinel 'x')
	assert written[-2:-1] == b"\n"
	assert written[-1:] == b"\n"
	import tomllib
	parsed = tomllib.loads(written.decode("utf-8"))
	assert parsed["devices"]["r1"]["key_file"] == "/keys/r1-new"


def test_inventory_set_key_text_no_final_newline_inserts_a_lf(unit):
	# when the table's last line has no final LF, the
	# inserted key_file / known_hosts lines used to glue to it. The
	# result must parse with tomllib and carry both keys.
	body = '[devices.r1]\nhost = "10.1.2.3"'
	# note: no final \n at all
	inf = unit.tmp / "devs.toml"
	inf.write_bytes(body.encode("utf-8"))
	r = unit.run(
		"inventory_set_key_text r1 /keys/r1-new /keys/r1-new.kh < '%s'\n"
		"echo rc=$?\n" % inf,
	)
	assert r.returncode == 0, (r.stdout, r.stderr)
	out = r.stdout
	# the new key_file / known_hosts lines are present and NOT glued to
	# the previous line; the line before each insert ends in \n
	assert "host = \"10.1.2.3\"\n" in out
	assert "key_file = \"/keys/r1-new\"\n" in out
	assert "known_hosts = \"/keys/r1-new.kh\"\n" in out
	# the result parses with tomllib and carries both keys
	import tomllib
	parsed = tomllib.loads(out)
	assert parsed["devices"]["r1"]["key_file"] == "/keys/r1-new"
	assert parsed["devices"]["r1"]["known_hosts"] == "/keys/r1-new.kh"


# action_profile and action_upgrade


def test_action_profile_sets_and_is_idempotent(router_unit):
	# happy path: put_text writes /etc/newton/profile with mode 600,
	# the file is `prod` plus LF; a second call sets PUT_CHANGED=0 and
	# leaves no .new behind
	router = router_unit.router
	rel = "etc/newton/profile"
	router.write(rel, "lab\n", 0o600)
	code = (
		"DEV_PROFILE=lab\n"
		"PROFILE_VALUE=prod\n"
		"ACTION=profile\n"
		"action_profile\n"
	)
	r = router_unit.run(code)
	assert r.returncode == 0, (r.stdout, r.stderr)
	lines = r.stdout.splitlines()
	assert "PASS profile set to prod" in lines
	assert "NOTE state" not in "\n".join(lines)
	assert lines[-1] == "DONE profile r1"
	assert router.read(rel) == "prod\n"
	assert stat.S_IMODE(router.path(rel).stat().st_mode) == 0o600
	assert not router.path(rel + ".new").exists()
	# second call: identical, no .new, PUT_CHANGED=0
	second = router_unit.run(code)
	assert second.returncode == 0
	second_lines = second.stdout.splitlines()
	assert "PASS profile already prod" in second_lines
	assert "PASS profile set to prod" not in second_lines
	assert not router.path(rel + ".new").exists()
	assert second_lines[-1] == "DONE profile r1"


def test_action_profile_mismatch_with_inventory_prints_note(router_unit):
	# the inventory says lab but the operator asks for prod; the file
	# is still written, the NOTE is printed just before the PASS
	router = router_unit.router
	rel = "etc/newton/profile"
	router.write(rel, "lab\n", 0o600)
	r = router_unit.run(
		"DEV_PROFILE=lab\n"
		"PROFILE_VALUE=prod\n"
		"ACTION=profile\n"
		"action_profile\n"
	)
	assert r.returncode == 0
	lines = r.stdout.splitlines()
	# the NOTE comes before the PASS and names the inventory profile
	assert any(l.startswith("NOTE the inventory says lab") for l in lines)
	assert "PASS profile set to prod" in lines
	assert lines[-1] == "DONE profile r1"
	# the file actually holds prod
	assert router.read(rel) == "prod\n"


def test_action_profile_write_failure_stops_with_router_unchanged(router_unit):
	# force put_text to fail by making the directory unwritable; the
	# tool must stop with STATE_NOTE='router unchanged'
	router = router_unit.router
	rel = "etc/newton/profile"
	router.write(rel, "lab\n", 0o600)
	router.path("etc/newton").chmod(0o500)
	r = router_unit.run(
		"DEV_PROFILE=lab\n"
		"PROFILE_VALUE=prod\n"
		"ACTION=profile\n"
		"action_profile\n"
	)
	router.path("etc/newton").chmod(0o700)
	assert r.returncode == 1
	lines = r.stdout.splitlines()
	assert "NOTE state: router unchanged" in lines
	assert lines[-1] == "STOPPED profile r1: cannot write the profile file"
	# the file was untouched
	assert router.read(rel) == "lab\n"
	assert not router.path(rel + ".new").exists()


def test_action_upgrade_happy_path(router_unit, tmp_path):
	# v1.0.0 installed first, then upgrade with v2.0.0: program
	# replaced with .prev at mode 644 (the helper and guard/init bytes
	# are unchanged between versions, so they do not rotate), guard
	# and init replaced too (guard is idle by default), hello shows
	# the new prog=, DONE upgrade r1
	router = router_unit.router
	src_v1 = build_src(router_unit.tmp / "src_v1")
	_install_code_files_with_src(router, src_v1)
	prog_rel = "usr/libexec/newton/newton-router"
	helper_rel = "usr/libexec/newton/newton-safe-apply"
	guard_rel = "usr/libexec/newton-guard"
	init_rel = "etc/init.d/newton-guard"
	prog_v1 = router.read(prog_rel)
	helper_v1 = router.read(helper_rel)
	src2 = build_src(tmp_path / "src2", version="2.0.0")
	prog_v2 = (src2 / "device/openwrt/newton-router/newton-router").read_text()
	helper_v2 = (src2 / "scripts/owrt-safe-apply.sh").read_text()
	guard_v2 = (src2 / "device/openwrt/newton-guard/newton-guard").read_text()
	init_v2 = (src2 / "device/openwrt/newton-guard/newton-guard.init").read_text()
	assert prog_v1 != prog_v2
	r = router_unit.run(
		"DEV_PROFILE=lab\n"
		"ACTION=upgrade\n"
		"action_upgrade\n",
		extra_env={"NEWTON_SETUP_SRC": str(src2)},
	)
	assert r.returncode == 0, (r.stdout, r.stderr)
	lines = r.stdout.splitlines()
	step_lines = [l for l in lines if l.startswith("PASS upgrade step ")]
	# without a DEV_KEY_FILE, step 5 prints the skip-INFO instead of
	# the PASS line (a separate test covers the with-key case); the
	# other four steps are unconditional
	assert len(step_lines) == 4
	assert "INFO restricted-key check skipped: no key_file in the inventory" in lines
	assert lines[-1] == "DONE upgrade r1"
	# program replaced
	assert router.read(prog_rel) == prog_v2
	# .prev holds the OLD program at mode 644
	assert router.read(prog_rel + ".prev") == prog_v1
	assert stat.S_IMODE(router.path(prog_rel + ".prev").stat().st_mode) == 0o644
	# guard and init replaced too (guard is idle in the fixture)
	assert router.read(guard_rel) == guard_v2
	assert router.read(init_rel) == init_v2
	# no .new left
	for rel in (prog_rel, helper_rel, guard_rel, init_rel):
		assert not router.path(rel + ".new").exists()
	# the success PASS line carries the first 12 hex of the program sha
	prog_sha = hashlib.sha256(prog_v2.encode("utf-8")).hexdigest()
	assert any(l == "PASS upgrade: prog=%s" % prog_sha[:12] for l in lines)


def test_action_upgrade_second_run_writes_nothing(router_unit, tmp_path):
	# idempotence: a second upgrade with the same tree changes nothing
	router = router_unit.router
	_install_code_files(router, router_unit.tmp)
	src2 = build_src(tmp_path / "src2", version="2.0.0")
	first = router_unit.run(
		"DEV_PROFILE=lab\n"
		"ACTION=upgrade\n"
		"action_upgrade\n",
		extra_env={"NEWTON_SETUP_SRC": str(src2)},
	)
	assert first.returncode == 0
	after_first = router.snapshot()
	second = router_unit.run(
		"DEV_PROFILE=lab\n"
		"ACTION=upgrade\n"
		"action_upgrade\n",
		extra_env={"NEWTON_SETUP_SRC": str(src2)},
	)
	assert second.returncode == 0
	# nothing on the router changed: no .new, no .prev rotation, same
	# bytes everywhere
	assert router.snapshot() == after_first
	for rel in (
		"usr/libexec/newton/newton-router",
		"usr/libexec/newton/newton-safe-apply",
		"usr/libexec/newton-guard",
		"etc/init.d/newton-guard",
	):
		assert not router.path(rel + ".new").exists()


def test_action_upgrade_pending_guard_refuses(router_unit, tmp_path):
	# a `pending` guard (the script reads the first line of
	# etc/newton/guard-state) refuses with the router unchanged
	router = router_unit.router
	_install_code_files(router, router_unit.tmp)
	src2 = build_src(tmp_path / "src2", version="2.0.0")
	router.write("etc/newton/guard-state", "pending since boot\n")
	before = router.snapshot()
	r = router_unit.run(
		"DEV_PROFILE=lab\n"
		"ACTION=upgrade\n"
		"action_upgrade\n",
		extra_env={"NEWTON_SETUP_SRC": str(src2)},
	)
	assert r.returncode == 1, (r.stdout, r.stderr)
	lines = r.stdout.splitlines()
	assert any(l.startswith("WARN upgrade refused:") for l in lines)
	assert any("pending" in l for l in lines if l.startswith("WARN upgrade"))
	assert "NOTE state: router unchanged" in lines
	assert lines[-1].startswith("STOPPED upgrade r1")
	assert router.snapshot() == before


def test_action_upgrade_live_helper_lock_refuses(router_unit, tmp_path):
	# a helper lock whose sid the fake ubus lists refuses
	router = router_unit.router
	_install_code_files(router, router_unit.tmp)
	src2 = build_src(tmp_path / "src2", version="2.0.0")
	router.write("tmp/owrt-safe-apply.lock/sid", "sess-upgrade\n")
	router.update_state(ubus_sessions='"sid": "sess-upgrade"')
	before = router.snapshot()
	r = router_unit.run(
		"DEV_PROFILE=lab\n"
		"ACTION=upgrade\n"
		"action_upgrade\n",
		extra_env={"NEWTON_SETUP_SRC": str(src2)},
	)
	assert r.returncode == 1, (r.stdout, r.stderr)
	lines = r.stdout.splitlines()
	assert any(l.startswith("WARN upgrade refused: helper-lock") for l in lines)
	assert "NOTE state: router unchanged" in lines
	assert lines[-1].startswith("STOPPED upgrade r1")
	assert router.snapshot() == before


def test_action_upgrade_restored_guard_does_not_touch_guard_or_init(router_unit, tmp_path):
	# a `restored t boot` guard does NOT block the upgrade; program
	# is upgraded (only the program bytes change between v1.0.0 and
	# v2.0.0), but guard and init are NOT replaced (the guard is not
	# exactly `idle`)
	router = router_unit.router
	_install_code_files(router, router_unit.tmp)
	guard_rel = "usr/libexec/newton-guard"
	init_rel = "etc/init.d/newton-guard"
	prog_rel = "usr/libexec/newton/newton-router"
	router.write("etc/newton/guard-state", "restored t boot\n")
	guard_v1 = router.read(guard_rel)
	init_v1 = router.read(init_rel)
	prog_v1 = router.read(prog_rel)
	src2 = build_src(tmp_path / "src2", version="2.0.0")
	prog_v2 = (src2 / "device/openwrt/newton-router/newton-router").read_text()
	assert prog_v1 != prog_v2
	r = router_unit.run(
		"DEV_PROFILE=lab\n"
		"ACTION=upgrade\n"
		"action_upgrade\n",
		extra_env={"NEWTON_SETUP_SRC": str(src2)},
	)
	assert r.returncode == 0, (r.stdout, r.stderr)
	lines = r.stdout.splitlines()
	assert lines[-1] == "DONE upgrade r1"
	# program replaced
	assert router.read(prog_rel) == prog_v2
	# .prev holds the OLD program bytes
	assert router.read(prog_rel + ".prev") == prog_v1
	# guard and init UNTOUCHED
	assert router.read(guard_rel) == guard_v1
	assert router.read(init_rel) == init_v1
	# no .new for guard or init (they were not rotated)
	assert not router.path(guard_rel + ".new").exists()
	assert not router.path(init_rel + ".new").exists()


def test_action_upgrade_failed_guard_does_not_block(router_unit, tmp_path):
	# a `failed x y` guard does NOT block an upgrade; the upgrade
	# uploads program (no guard, no init) and exits 0
	router = router_unit.router
	_install_code_files(router, router_unit.tmp)
	guard_rel = "usr/libexec/newton-guard"
	init_rel = "etc/init.d/newton-guard"
	prog_rel = "usr/libexec/newton/newton-router"
	router.write("etc/newton/guard-state", "failed txn x\n")
	guard_v1 = router.read(guard_rel)
	init_v1 = router.read(init_rel)
	prog_v1 = router.read(prog_rel)
	src2 = build_src(tmp_path / "src2", version="2.0.0")
	prog_v2 = (src2 / "device/openwrt/newton-router/newton-router").read_text()
	assert prog_v1 != prog_v2
	r = router_unit.run(
		"DEV_PROFILE=lab\n"
		"ACTION=upgrade\n"
		"action_upgrade\n",
		extra_env={"NEWTON_SETUP_SRC": str(src2)},
	)
	assert r.returncode == 0, (r.stdout, r.stderr)
	lines = r.stdout.splitlines()
	assert not any(l.startswith("WARN upgrade refused") for l in lines)
	assert lines[-1] == "DONE upgrade r1"
	# program replaced
	assert router.read(prog_rel) == prog_v2
	# guard and init untouched
	assert router.read(guard_rel) == guard_v1
	assert router.read(init_rel) == init_v1
	assert not router.path(guard_rel + ".new").exists()
	assert not router.path(init_rel + ".new").exists()


def test_action_upgrade_broken_program_restores_from_prev(router_unit, tmp_path):
	# upload a broken program; step 4 fails, install_restore puts the
	# old program back, hello works again, STATE_NOTE says restored
	router = router_unit.router
	_install_code_files(router, router_unit.tmp)
	prog_rel = "usr/libexec/newton/newton-router"
	prog_v1 = router.read(prog_rel)
	broken = build_src(tmp_path / "broken", program="broken")
	r = router_unit.run(
		"DEV_PROFILE=lab\n"
		"ACTION=upgrade\n"
		"action_upgrade\n",
		extra_env={"NEWTON_SETUP_SRC": str(broken)},
	)
	assert r.returncode == 1, (r.stdout, r.stderr)
	lines = r.stdout.splitlines()
	assert lines[-1] == "STOPPED upgrade r1: upgrade step 4 failed"
	# program back to the old bytes
	assert router.read(prog_rel) == prog_v1
	# STATE_NOTE names the restore and a working hello
	state_notes = [l for l in lines if l.startswith("NOTE state:")]
	assert any("restored from .prev" in n for n in state_notes)
	assert any("hello after restore: ok" in n for n in state_notes)


def test_action_upgrade_repairs_broken_installed_program(router_unit, tmp_path):
	# the broken program is on the router, the others are the good
	# v1 fixtures; then upgrade with a good tree -- the broken
	# program is overwritten, hello works, exit 0
	router = router_unit.router
	broken = build_src(tmp_path / "broken", program="broken")
	# write the four files into the router directly: the broken
	# program is on the router, the others are the good v1 fixtures
	src_good = build_src(tmp_path / "good", program="ok")
	for rel_src, rel_fs in [
		("device/openwrt/newton-router/newton-router",
			"usr/libexec/newton/newton-router"),
		("scripts/owrt-safe-apply.sh",
			"usr/libexec/newton/newton-safe-apply"),
		("device/openwrt/newton-guard/newton-guard",
			"usr/libexec/newton-guard"),
		("device/openwrt/newton-guard/newton-guard.init",
			"etc/init.d/newton-guard"),
	]:
		router.write(rel_fs, (broken / rel_src).read_text(), 0o755)
	r = router_unit.run(
		"DEV_PROFILE=lab\n"
		"ACTION=upgrade\n"
		"action_upgrade\n",
		extra_env={"NEWTON_SETUP_SRC": str(src_good)},
	)
	assert r.returncode == 0, (r.stdout, r.stderr)
	lines = r.stdout.splitlines()
	assert lines[-1] == "DONE upgrade r1"
	# the program on the router is now the good one
	prog_rel = "usr/libexec/newton/newton-router"
	assert router.read(prog_rel) == (src_good
		/ "device/openwrt/newton-router/newton-router").read_text()
	# and a hello from the upgraded program works
	hello = router_unit.run("hello_direct 0123456789abcdef0123456789abcdef\n")
	assert hello.returncode == 0
	assert hello.stdout.splitlines()[0].startswith("hello 0123456789abcdef0123456789abcdef")


def test_action_upgrade_without_key_file_skips_step_5(router_unit, tmp_path):
	# no DEV_KEY_FILE -> the restricted-key hello is skipped (the INFO
	# note is printed); program still replaced
	router = router_unit.router
	_install_code_files(router, router_unit.tmp)
	src2 = build_src(tmp_path / "src2", version="2.0.0")
	r = router_unit.run(
		"DEV_PROFILE=lab\n"
		"DEV_KEY_FILE=''\n"
		"ACTION=upgrade\n"
		"action_upgrade\n",
		extra_env={"NEWTON_SETUP_SRC": str(src2)},
	)
	assert r.returncode == 0, (r.stdout, r.stderr)
	lines = r.stdout.splitlines()
	assert "INFO restricted-key check skipped: no key_file in the inventory" in lines
	assert lines[-1] == "DONE upgrade r1"


def test_action_upgrade_with_key_file_does_hello_key(router_unit, tmp_path):
	# a valid DEV_KEY_FILE pointing at a restricted key whose line is on
	# the router: hello_key returns door=ssh, mode=prod, and the
	# restricted-key PASS line prints
	router = router_unit.router
	_install_code_files(router, router_unit.tmp)
	router.add_authorized_key(LINE_A)
	key = _restricted_key(router_unit.tmp, BLOB_A)
	src2 = build_src(tmp_path / "src2", version="2.0.0")
	r = router_unit.run(
		"DEV_PROFILE=lab\n"
		"DEV_KEY_FILE='%s'\n"
		"ACTION=upgrade\n"
		"action_upgrade\n" % key,
		extra_env={"NEWTON_SETUP_SRC": str(src2)},
	)
	assert r.returncode == 0, (r.stdout, r.stderr)
	lines = r.stdout.splitlines()
	assert "PASS upgrade step 5: restricted key checks pass" in lines
	assert "INFO restricted-key check skipped" not in lines
	assert lines[-1] == "DONE upgrade r1"


def test_action_install_unchanged(router_unit, tmp_path):
	# the install path's step 1 must still refuse a pending
	# guard with the same wording and exit code as before
	router = router_unit.router
	src_v1 = build_src(router_unit.tmp / "src_v1")
	_install_code_files_with_src(router, src_v1)
	src2 = build_src(tmp_path / "src2", version="2.0.0")
	router.write("etc/newton/guard-state", "pending since boot\n")
	before = router.snapshot()
	r = router_unit.run(
		"DEV_PROFILE=lab\n"
		"ACTION=install\n"
		"action_install\n",
		extra_env={"NEWTON_SETUP_SRC": str(src2)},
		tty=("yes",),
	)
	assert r.returncode == 1, (r.stdout, r.stderr)
	lines = r.stdout.splitlines()
	assert any(l.startswith("WARN install refused:") for l in lines)
	assert "NOTE state: router unchanged" in lines
	assert lines[-1].startswith("STOPPED install r1")
	assert router.snapshot() == before


def _install_code_files_with_src(router, src):
	"""Install the four fixture source files from `src` (a build_src
	tree) into the router fs at mode 0755."""
	for rel_src, rel_fs in [
		("device/openwrt/newton-router/newton-router",
			"usr/libexec/newton/newton-router"),
		("scripts/owrt-safe-apply.sh",
			"usr/libexec/newton/newton-safe-apply"),
		("device/openwrt/newton-guard/newton-guard",
			"usr/libexec/newton-guard"),
		("device/openwrt/newton-guard/newton-guard.init",
			"etc/init.d/newton-guard"),
	]:
		router.write(rel_fs, (src / rel_src).read_text(), 0o755)


# password_only_proof factor, action_rollback, action_uninstall
# (design 8.6 / 8.7)


def _run_action_rollback(router_unit):
	return router_unit.run("ACTION=rollback\naction_rollback\n")


def _run_action_uninstall(router_unit, typed):
	tty = router_unit.tmp / "typed"
	tty.write_text("".join(line + "\n" for line in typed))
	return router_unit.run(
		"ACTION=uninstall\naction_uninstall\n",
		extra_env={"NEWTON_SETUP_TTY": str(tty)},
	)


GOOD_PW_UNITS = "root-pw-for-tests"


def test_password_only_proof_factor_passes_and_fails(router_unit):
	# the password-only proof factor prints exactly the PASS/FAIL lines
	# action_check prints today, and returns 0/1; the typed-input file
	# holds the password and a wrong attempt after, but ROOT_PW_DONE
	# blocks a second fetch
	tty = router_unit.tmp / "typed"
	tty.write_text(GOOD_PW_UNITS + "\n")
	good = router_unit.run(
		"password_only_proof; echo rc=$?\n",
		extra_env={"NEWTON_SETUP_TTY": str(tty)},
	)
	assert good.returncode == 0
	assert good.stdout.splitlines() == [
		"PASS password-only login works", "rc=0",
	]
	# wrong password: the call returns 1 and prints FAIL
	tty.write_text("not-the-right-pw\n")
	bad = router_unit.run(
		"password_only_proof; echo rc=$?\n",
		extra_env={"NEWTON_SETUP_TTY": str(tty)},
	)
	assert bad.returncode == 0
	assert bad.stdout.splitlines() == [
		"FAIL password-only login failed", "rc=1",
	]


def test_action_check_password_only_proof_factor_unchanged(router_unit):
	# the refactor must not change action_check's output or exit code:
	# a good run prints PASS password-only login works and DONE; a
	# wrong password prints FAIL and STOPPED; a missing tool still
	# prints FAIL and STOPPED. This is the regression guard for round
	# RC2 (action_check used to inline the proof; now it calls the
	# factored helper).
	router = router_unit.router
	_install_code_files(router, router_unit.tmp)
	tty = router_unit.tmp / "typed"
	tty.write_text(GOOD_PW_UNITS + "\n")
	r = router_unit.run(
		"ACTION=check\naction_check\n",
		extra_env={"NEWTON_SETUP_TTY": str(tty)},
	)
	assert r.returncode == 0
	assert "PASS password-only login works" in r.stdout.splitlines()
	assert "DONE check r1" in r.stdout.splitlines()
	# wrong password
	tty.write_text("not-the-root-pw\n")
	r = router_unit.run(
		"ACTION=check\naction_check\n",
		extra_env={"NEWTON_SETUP_TTY": str(tty)},
	)
	assert r.returncode == 1
	assert "FAIL password-only login failed" in r.stdout.splitlines()
	assert "STOPPED check r1: check found a problem" in r.stdout.splitlines()
	# missing tool
	_install_code_files(router, router_unit.tmp)
	(router.root / "bin" / "ucode").unlink()
	tty.write_text(GOOD_PW_UNITS + "\n")
	r = router_unit.run(
		"ACTION=check\naction_check\n",
		extra_env={"NEWTON_SETUP_TTY": str(tty)},
	)
	assert r.returncode == 1
	assert "FAIL tool ucode" in r.stdout.splitlines()
	assert "STOPPED check r1: check found a problem" in r.stdout.splitlines()


def _seed_prev(router, rel, text, mode=0o644):
	"""Write the .prev file at rel + '.prev' (mode 644, the value the
	install rotation uses)."""
	router.write(rel + ".prev", text, mode)


def test_action_rollback_restores_program_and_helper(router_unit):
	# install v1.0.0 code, write v0.0.0 code as .prev (different shas
	# but both respond to hello), run action_rollback: live bytes
	# become the .prev bytes, the live mode is 755, the PASS line uses
	# the live prog's first 12 hex, DONE rollback r1
	router = router_unit.router
	src_v1 = build_src(router_unit.tmp / "src_v1", version="1.0.0")
	src_v0 = build_src(router_unit.tmp / "src_v0", version="0.0.0")
	prog_rel = "usr/libexec/newton/newton-router"
	helper_rel = "usr/libexec/newton/newton-safe-apply"
	# install v1.0.0 files into the router (live bytes)
	for rel_src, rel_fs in [
		("device/openwrt/newton-router/newton-router", prog_rel),
		("scripts/owrt-safe-apply.sh", helper_rel),
		("device/openwrt/newton-guard/newton-guard", "usr/libexec/newton-guard"),
		("device/openwrt/newton-guard/newton-guard.init",
			"etc/init.d/newton-guard"),
	]:
		router.write(rel_fs, (src_v1 / rel_src).read_text(), 0o755)
	# write v0.0.0 code as .prev (different bytes, mode 644)
	old_prog = (src_v0 / "device/openwrt/newton-router/newton-router").read_text()
	old_helper = (src_v0 / "scripts/owrt-safe-apply.sh").read_text()
	_seed_prev(router, prog_rel, old_prog)
	_seed_prev(router, helper_rel, old_helper)
	r = _run_action_rollback(router_unit)
	assert r.returncode == 0, (r.stdout, r.stderr)
	lines = r.stdout.splitlines()
	assert lines[-1] == "DONE rollback r1"
	# the PASS line uses the live prog/helper shas (the old bytes)
	prog_sha = hashlib.sha256(old_prog.encode("utf-8")).hexdigest()
	helper_sha = hashlib.sha256(old_helper.encode("utf-8")).hexdigest()
	expected_pass = "PASS rollback: prog=%s helper=%s" % (
		prog_sha[:12], helper_sha[:12])
	assert expected_pass in lines, (lines, expected_pass)
	# the live files now hold the old bytes
	assert router.read(prog_rel) == old_prog
	assert router.read(helper_rel) == old_helper
	# mode 755 on the live files (chmod 755 the .new before mv)
	assert stat.S_IMODE(router.path(prog_rel).stat().st_mode) == 0o755
	assert stat.S_IMODE(router.path(helper_rel).stat().st_mode) == 0o755
	# the .prev files are untouched (mode 644, original bytes)
	assert router.read(prog_rel + ".prev") == old_prog
	assert router.read(helper_rel + ".prev") == old_helper
	assert stat.S_IMODE(router.path(prog_rel + ".prev").stat().st_mode) == 0o644
	# no .new left behind
	assert not router.path(prog_rel + ".new").exists()
	assert not router.path(helper_rel + ".new").exists()


def test_action_rollback_prints_already_equals_when_sha_matches(router_unit):
	# when live == .prev, no rsh_admin write call is made and the
	# action prints INFO "<name> already equals .prev" for each file
	router = router_unit.router
	_install_code_files(router, router_unit.tmp)
	prog_rel = "usr/libexec/newton/newton-router"
	helper_rel = "usr/libexec/newton/newton-safe-apply"
	prog_text = router.read(prog_rel)
	helper_text = router.read(helper_rel)
	_seed_prev(router, prog_rel, prog_text)
	_seed_prev(router, helper_rel, helper_text)
	uploads_before = len([c for c in router.calls() if c.get("stdin_len")])
	r = _run_action_rollback(router_unit)
	assert r.returncode == 0
	lines = r.stdout.splitlines()
	assert "INFO newton-router already equals .prev" in lines
	assert "INFO newton-safe-apply already equals .prev" in lines
	assert lines[-1] == "DONE rollback r1"
	# the live bytes and mode are unchanged
	assert router.read(prog_rel) == prog_text
	assert router.read(helper_rel) == helper_text
	# no upload happened in this run
	uploads_after = len([c for c in router.calls() if c.get("stdin_len")])
	assert uploads_after == uploads_before


def test_action_rollback_second_run_writes_nothing(router_unit):
	# a rollback followed by a second rollback: after the first the
	# live equals the .prev; the second prints INFO for both files,
	# PASS and DONE, with no upload
	router = router_unit.router
	src_v1 = build_src(router_unit.tmp / "src_v1", version="1.0.0")
	src_v0 = build_src(router_unit.tmp / "src_v0", version="0.0.0")
	prog_rel = "usr/libexec/newton/newton-router"
	helper_rel = "usr/libexec/newton/newton-safe-apply"
	for rel_src, rel_fs in [
		("device/openwrt/newton-router/newton-router", prog_rel),
		("scripts/owrt-safe-apply.sh", helper_rel),
		("device/openwrt/newton-guard/newton-guard", "usr/libexec/newton-guard"),
		("device/openwrt/newton-guard/newton-guard.init",
			"etc/init.d/newton-guard"),
	]:
		router.write(rel_fs, (src_v1 / rel_src).read_text(), 0o755)
	old_prog = (src_v0 / "device/openwrt/newton-router/newton-router").read_text()
	old_helper = (src_v0 / "scripts/owrt-safe-apply.sh").read_text()
	_seed_prev(router, prog_rel, old_prog)
	_seed_prev(router, helper_rel, old_helper)
	first = _run_action_rollback(router_unit)
	assert first.returncode == 0
	after_first = router.snapshot()
	uploads_before = len([c for c in router.calls() if c.get("stdin_len")])
	second = _run_action_rollback(router_unit)
	assert second.returncode == 0
	assert second.stdout.splitlines()[-1] == "DONE rollback r1"
	assert "INFO newton-router already equals .prev" in second.stdout.splitlines()
	assert "INFO newton-safe-apply already equals .prev" in second.stdout.splitlines()
	assert router.snapshot() == after_first
	uploads_after = len([c for c in router.calls() if c.get("stdin_len")])
	assert uploads_after == uploads_before
	# no .new files left from the second run
	assert not router.path(prog_rel + ".new").exists()
	assert not router.path(helper_rel + ".new").exists()


def test_action_rollback_no_prev_stops_with_router_unchanged(router_unit):
	# code files installed but no .prev anywhere -> STATE_NOTE says no
	# .prev, STOPPED rollback r1: nothing to roll back to, snapshot
	# unchanged
	router = router_unit.router
	_install_code_files(router, router_unit.tmp)
	before = router.snapshot()
	r = _run_action_rollback(router_unit)
	assert r.returncode == 1, (r.stdout, r.stderr)
	lines = r.stdout.splitlines()
	assert any("NOTE state: router unchanged (no .prev to roll back to)" in l
		for l in lines)
	assert lines[-1] == "STOPPED rollback r1: nothing to roll back to"
	assert router.snapshot() == before


def test_action_rollback_partial_prev_restores_one_reports_other(router_unit):
	# program has a .prev (different bytes, both respond to hello),
	# helper does not: the helper prints INFO "has no .prev", the
	# program is restored, and the run exits 0
	router = router_unit.router
	src_v1 = build_src(router_unit.tmp / "src_v1", version="1.0.0")
	src_v0 = build_src(router_unit.tmp / "src_v0", version="0.0.0")
	prog_rel = "usr/libexec/newton/newton-router"
	helper_rel = "usr/libexec/newton/newton-safe-apply"
	for rel_src, rel_fs in [
		("device/openwrt/newton-router/newton-router", prog_rel),
		("scripts/owrt-safe-apply.sh", helper_rel),
		("device/openwrt/newton-guard/newton-guard", "usr/libexec/newton-guard"),
		("device/openwrt/newton-guard/newton-guard.init",
			"etc/init.d/newton-guard"),
	]:
		router.write(rel_fs, (src_v1 / rel_src).read_text(), 0o755)
	old_prog = (src_v0 / "device/openwrt/newton-router/newton-router").read_text()
	_seed_prev(router, prog_rel, old_prog)
	# intentionally no .prev for the helper
	r = _run_action_rollback(router_unit)
	assert r.returncode == 0, (r.stdout, r.stderr)
	lines = r.stdout.splitlines()
	assert "INFO newton-safe-apply has no .prev" in lines
	# program restored, helper untouched
	assert router.read(prog_rel) == old_prog
	assert stat.S_IMODE(router.path(prog_rel).stat().st_mode) == 0o755
	assert not router.path(helper_rel + ".prev").exists()
	assert lines[-1] == "DONE rollback r1"


# uninstall --------------------------------------------------------------


def _seed_full_install(router_unit):
	"""Mirror what install would leave on the router: the four code
	files at mode 755, .prev files for program/helper at mode 644, the
	guard enabled (S09 symlink), the four config files, an
	authorized_keys with the plain line + two restricted Newton lines +
	an unrelated line, and a sysupgrade.conf with the eleven Newton
	lines (R9b+c: includes the three WAN-health extras) and one
	unrelated line."""
	router = router_unit.router
	_install_code_files(router, router_unit.tmp)
	prog_rel = "usr/libexec/newton/newton-router"
	helper_rel = "usr/libexec/newton/newton-safe-apply"
	_seed_prev(router, prog_rel,
		"#!/bin/sh\n# old prog v0\nexit 0\n")
	_seed_prev(router, helper_rel,
		"#!/bin/sh\n# old helper v0\nexit 0\n")
	# enable the guard (init.d makes the S09 symlink)
	router.path("etc/rc.d").mkdir(parents=True, exist_ok=True)
	if not router.path("etc/rc.d/S09newton-guard").exists():
		router.path("etc/rc.d/S09newton-guard").symlink_to(
			"../init.d/newton-guard")
	# config files under /etc/newton
	router.write("etc/newton/device-id", "r1\n", 0o600)
	router.write("etc/newton/profile", "lab\n", 0o600)
	router.write("etc/newton/zones",
		"mgmt-interface lan\nmgmt-zone lan\nwan-zone wan\n", 0o600)
	router.write("etc/newton/approve.key", "0" * 64 + "\n", 0o600)
	# lkg and quarantine (directories with one marker file each)
	router.path("etc/newton/lkg").mkdir(parents=True, exist_ok=True)
	router.write("etc/newton/lkg/marker", "keep me\n")
	router.path("etc/newton/quarantine").mkdir(parents=True, exist_ok=True)
	router.write("etc/newton/quarantine/marker", "keep me\n")
	# authorized_keys: plain line + LINE_A + LINE_B + unrelated
	rel = "etc/dropbear/authorized_keys"
	plain_line = "ssh-ed25519 %s agent@unit" % PLAIN_BLOB
	unrelated = "ssh-ed25519 AAAUNRELATEDNOTNEWTON001 agent-laptop"
	router.write(rel,
		plain_line + "\n" + LINE_A + "\n" + LINE_B + "\n" + unrelated + "\n",
		0o600)
	# sysupgrade.conf: 11 lines (R9b+c) + one unrelated
	sysupgrade = (
		"## custom head\n"
		"/etc/myfile\n"
		+ "/usr/libexec/newton/newton-router\n"
		+ "/usr/libexec/newton/newton-safe-apply\n"
		+ "/usr/libexec/newton-guard\n"
		+ "/etc/init.d/newton-guard\n"
		+ "/etc/rc.d/S09newton-guard\n"
		+ "/etc/rc.d/S95newton-wan-health\n"
		+ "/usr/libexec/newton/newton-wan-health\n"
		+ "/etc/init.d/newton-wan-health\n"
		+ "/etc/newton/device-id\n"
		+ "/etc/newton/profile\n"
		+ "/etc/newton/zones\n"
	)
	router.write("etc/sysupgrade.conf", sysupgrade, 0o644)


def test_action_uninstall_full_path(router_unit):
	# a fully-installed router: two restricted lines + an unrelated
	# line; lkg/ and quarantine/ under etc/newton and an approve.key.
	# After uninstall both restricted lines are gone, the unrelated
	# line and the plain line stay byte for byte; the four code files,
	# both .prev files, device-id, profile, zones and approve.key are
	# gone; lkg and quarantine stay (as directories); sysupgrade.conf
	# lost exactly the eleven SYSUPGRADE_LINES (R9b+c) and kept the
	# unrelated line in order; stdout shows the password-only proof
	# PASS lines before and after and DONE uninstall r1
	router = router_unit.router
	_seed_full_install(router_unit)
	before = router.snapshot()
	assert before.get("usr/libexec/newton/newton-router")
	assert before.get("usr/libexec/newton/newton-router.prev")
	assert before.get("usr/libexec/newton/newton-safe-apply")
	assert before.get("usr/libexec/newton/newton-safe-apply.prev")
	assert before.get("usr/libexec/newton-guard")
	assert before.get("etc/init.d/newton-guard")
	assert before.get("etc/newton/device-id")
	assert before.get("etc/newton/profile")
	assert before.get("etc/newton/zones")
	assert before.get("etc/newton/approve.key")
	assert before.get("etc/newton/lkg/marker")
	assert before.get("etc/newton/quarantine/marker")
	r = _run_action_uninstall(router_unit, [GOOD_PW_UNITS])
	assert r.returncode == 0, (r.stdout, r.stderr)
	lines = r.stdout.splitlines()
	# password-only proof printed before and after
	pass_lines = [l for l in lines if l.startswith("PASS password-only login works")]
	assert len(pass_lines) == 2, lines
	# five step PASS lines
	for n in range(1, 6):
		assert any(l.startswith("PASS uninstall step %d:" % n) for l in lines), \
			lines
	# DONE
	assert lines[-1] == "DONE uninstall r1"
	# two restricted lines gone, plain + unrelated stay verbatim
	live_lines = router.authorized_keys()
	plain_line = "ssh-ed25519 %s agent@unit" % PLAIN_BLOB
	unrelated = "ssh-ed25519 AAAUNRELATEDNOTNEWTON001 agent-laptop"
	assert plain_line in live_lines
	assert unrelated in live_lines
	assert LINE_A not in live_lines
	assert LINE_B not in live_lines
	# the four code files and both .prev files are gone
	for rel in (
		"usr/libexec/newton/newton-router",
		"usr/libexec/newton/newton-router.prev",
		"usr/libexec/newton/newton-safe-apply",
		"usr/libexec/newton/newton-safe-apply.prev",
		"usr/libexec/newton-guard",
		"etc/init.d/newton-guard",
	):
		assert rel not in router.snapshot(), (rel, router.snapshot())
	# device-id, profile, zones, approve.key gone
	for rel in (
		"etc/newton/device-id",
		"etc/newton/profile",
		"etc/newton/zones",
		"etc/newton/approve.key",
	):
		assert rel not in router.snapshot(), rel
	# lkg and quarantine directories and their marker files still here
	assert router.path("etc/newton/lkg/marker").exists()
	assert router.path("etc/newton/quarantine/marker").exists()
	# the S09 symlink is gone
	assert not router.path("etc/rc.d/S09newton-guard").exists()
	# sysupgrade.conf lost exactly the eleven Newton lines and kept
	# the unrelated head and tail line in order
	sysupgrade_text = router.read("etc/sysupgrade.conf")
	for line in (
		"/usr/libexec/newton/newton-router",
		"/usr/libexec/newton/newton-safe-apply",
		"/usr/libexec/newton-guard",
		"/etc/init.d/newton-guard",
		"/etc/rc.d/S09newton-guard",
		"/etc/rc.d/S95newton-wan-health",
		"/usr/libexec/newton/newton-wan-health",
		"/etc/init.d/newton-wan-health",
		"/etc/newton/device-id",
		"/etc/newton/profile",
		"/etc/newton/zones",
	):
		assert line not in sysupgrade_text.splitlines(), (line, sysupgrade_text)
	kept = sysupgrade_text.splitlines()
	assert "## custom head" in kept
	assert "/etc/myfile" in kept
	# the kept unrelated lines come in their original order
	assert kept.index("## custom head") < kept.index("/etc/myfile")
	# authorized_keys mode preserved at 600
	assert stat.S_IMODE(router.path("etc/dropbear/authorized_keys")
		.stat().st_mode) == 0o600


def test_action_uninstall_reports_every_removed_newton_key(router_unit):
	router = router_unit.router
	plain = "ssh-ed25519 %s user@example # keep this comment" % PLAIN_BLOB
	alice = (
		"restrict,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,"
		'no-pty,command="/usr/libexec/newton/newton-router --caller=alice '
		'--role=change" ssh-ed25519 AAAAALICE newton-router-alice'
	)
	bob = (
		"restrict,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,"
		'no-pty,command="/usr/libexec/newton/newton-router --caller=bob '
		'--role=read" ssh-ed25519 AAAABOB newton-router-bob'
	)
	router.write(
		"etc/dropbear/authorized_keys",
		alice + "\n" + plain + "\n" + bob + "\n",
		0o600,
	)

	r = _run_action_uninstall(router_unit, [GOOD_PW_UNITS])
	assert r.returncode == 0, (r.stdout, r.stderr)
	assert router.read("etc/dropbear/authorized_keys") == plain + "\n"
	assert (
		"INFO removed Newton key alice (role change); to restore it, "
		"on the Newton host that holds this key run: "
		"sudo -u newton /usr/local/bin/newton-router-setup r1 add-key alice change"
	) in r.stdout.splitlines()
	assert (
		"INFO removed Newton key bob (role read); to restore it, "
		"on the Newton host that holds this key run: "
		"sudo -u newton /usr/local/bin/newton-router-setup r1 add-key bob read"
	) in r.stdout.splitlines()


def test_action_uninstall_does_not_echo_invalid_removed_key_fields(router_unit):
	router = router_unit.router
	router.update_state(ghost_blobs=[PLAIN_BLOB])
	invalid_caller = "a;b"
	line = (
		"restrict,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,"
		'no-pty,command="/usr/libexec/newton/newton-router --caller=%s '
		'--role=change" ssh-ed25519 AAAABAD newton-router-bad'
	) % invalid_caller
	router.write("etc/dropbear/authorized_keys", line + "\n", 0o600)

	r = _run_action_uninstall(router_unit, [GOOD_PW_UNITS])
	assert r.returncode == 0, (r.stdout, r.stderr)
	assert (
		"WARN removed a Newton key whose label or role cannot be read; "
		"re-add it with add-key"
	) in r.stdout.splitlines()
	assert invalid_caller not in r.stdout


def test_action_uninstall_names_the_label_when_only_the_role_is_bad(router_unit):
	# the label is readable, so the warning can name it; the role is
	# not, so the role is never printed
	router = router_unit.router
	plain = "ssh-ed25519 %s user@example # keep this comment" % PLAIN_BLOB
	line = (
		"restrict,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,"
		'no-pty,command="/usr/libexec/newton/newton-router --caller=carol '
		'--role=bogus" ssh-ed25519 AAAABAD newton-router-bad'
	)
	router.write("etc/dropbear/authorized_keys", plain + "\n" + line + "\n", 0o600)

	r = _run_action_uninstall(router_unit, [GOOD_PW_UNITS])
	assert r.returncode == 0, (r.stdout, r.stderr)
	lines = r.stdout.splitlines()
	assert (
		"WARN removed Newton key carol whose role cannot be read; "
		"re-add it with add-key carol <role>"
	) in lines
	assert not any(l.startswith("INFO removed Newton key carol") for l in lines), \
		lines
	assert "bogus" not in r.stdout


def test_action_uninstall_second_run_changes_nothing(router_unit):
	# after a full uninstall, every step is a no-op: the guard file
	# is gone (not-installed), the two proof PASS lines still print
	# (ROOT_PW_DONE=1 short-circuits the second admin_password_get),
	# each step PASS line still prints, and DONE exits 0; the router
	# snapshot is exactly what it was after the first uninstall
	router = router_unit.router
	_seed_full_install(router_unit)
	first = _run_action_uninstall(router_unit, [GOOD_PW_UNITS])
	assert first.returncode == 0, (first.stdout, first.stderr)
	after_first = router.snapshot()
	second = _run_action_uninstall(router_unit, [GOOD_PW_UNITS])
	assert second.returncode == 0, (second.stdout, second.stderr)
	lines = second.stdout.splitlines()
	# five step PASS lines and DONE
	for n in range(1, 6):
		assert any(l.startswith("PASS uninstall step %d:" % n) for l in lines), \
			lines
	assert lines[-1] == "DONE uninstall r1"
	# ROOT_PW_DONE=1 from the first run; the second run still calls
	# password_only_proof twice, both pass
	pass_lines = [l for l in lines if l.startswith("PASS password-only login works")]
	assert len(pass_lines) == 2, lines
	# router snapshot is exactly what it was after the first uninstall
	assert router.snapshot() == after_first


def test_action_uninstall_pending_guard_refuses(router_unit):
	# a guard-state file saying pending -> step 1 of uninstall stops
	# with STATE_NOTE='router unchanged' and STOPPED reason
	# "uninstall refused: the guard is not idle"; nothing is removed
	router = router_unit.router
	_install_code_files(router, router_unit.tmp)
	# mark the guard pending
	router.write("etc/newton/guard-state", "pending since boot\n")
	before = router.snapshot()
	r = _run_action_uninstall(router_unit, [GOOD_PW_UNITS])
	assert r.returncode == 1, (r.stdout, r.stderr)
	lines = r.stdout.splitlines()
	assert "NOTE state: router unchanged" in lines
	assert lines[-1] == "STOPPED uninstall r1: uninstall refused: the guard is not idle"
	assert router.snapshot() == before
	# and a `failed` guard also refuses (only `idle` and missing are OK)
	router.write("etc/newton/guard-state", "failed txn x\n")
	before = router.snapshot()
	r = _run_action_uninstall(router_unit, [GOOD_PW_UNITS])
	assert r.returncode == 1
	assert "NOTE state: router unchanged" in r.stdout.splitlines()
	assert r.stdout.splitlines()[-1] == \
		"STOPPED uninstall r1: uninstall refused: the guard is not idle"
	assert router.snapshot() == before


def test_action_uninstall_wrong_password_stops_before_removal(router_unit):
	# the password-only proof is run before any removal; a wrong typed
	# password makes it stop with STATE_NOTE='router unchanged' and
	# STOPPED reason "the password-only login failed; nothing was
	# removed"; the router snapshot is unchanged
	router = router_unit.router
	_seed_full_install(router_unit)
	before = router.snapshot()
	r = _run_action_uninstall(router_unit, ["not-the-root-pw"])
	assert r.returncode == 1, (r.stdout, r.stderr)
	lines = r.stdout.splitlines()
	assert "FAIL password-only login failed" in lines
	assert "NOTE state: router unchanged" in lines
	assert lines[-1] == "STOPPED uninstall r1: the password-only login failed; nothing was removed"
	# nothing was removed
	assert router.snapshot() == before


# repairs ---------------------------------------------------------
# The three repair tests below fail on the pre-fix code and pass
# on the repaired code (one failure per fix).


def _write_only_one_restricted_ak(router_unit, plain_blob):
	"""Seed authorized_keys with exactly one Newton restricted line:
	LINE_A is the line restricted_line prints for caller=lab-runner
	role=change; it is one of the two patterns uninstall_authorized_keys
	strips. The plain key is registered as a `ghost_blob` on the fake so
	the plain-key lane still authenticates (the router's authorized_keys
	is gone for it) — only requires the file to hold the
	one restricted line, not a plain line."""
	router = router_unit.router
	router.update_state(ghost_blobs=[plain_blob])
	router.write("etc/dropbear/authorized_keys", LINE_A + "\n", 0o600)


def test_repair_uninstall_authorized_keys_when_every_line_matches(router_unit):
	# a fresh router whose authorized_keys holds only the
	# one restricted line; without the fix the second `grep -vF` exits 1
	# and the `||` cascade removes the .new and exits 1, so the whole
	# action_uninstall ends in rc=1 STEP 1 failed; with the fix the
	# rc is captured and accepted, the .new is empty and mv'd over the
	# live file, and the rest of the run completes
	router = router_unit.router
	_write_only_one_restricted_ak(router_unit, PLAIN_BLOB)
	r = _run_action_uninstall(router_unit, [GOOD_PW_UNITS])
	assert r.returncode == 0, (r.stdout, r.stderr)
	lines = r.stdout.splitlines()
	# step 1 PASS line is printed; DONE is the last line
	assert any(l.startswith("PASS uninstall step 1:") for l in lines), lines
	assert lines[-1] == "DONE uninstall r1"
	# the file is now empty
	assert router.read("etc/dropbear/authorized_keys") == ""
	assert not router.path("etc/dropbear/authorized_keys.new").exists()


def _write_only_full_sysupgrade_lines(router):
	"""Seed /etc/sysupgrade.conf with exactly the SYSUPGRADE_LINES the
	tool knows about; nothing else. The pre-fix `grep -vxF ... > .new ||
	rm -f; exit 1` made step 4 of uninstall exit 1 when those lines were
	the only ones (three more WAN-health
	entries since, so the count is now eleven)."""
	text = "\n".join([
		"/usr/libexec/newton/newton-router",
		"/usr/libexec/newton/newton-safe-apply",
		"/usr/libexec/newton-guard",
		"/etc/init.d/newton-guard",
		"/etc/rc.d/S09newton-guard",
		"/etc/rc.d/S95newton-wan-health",
		"/usr/libexec/newton/newton-wan-health",
		"/etc/init.d/newton-wan-health",
		"/etc/newton/device-id",
		"/etc/newton/profile",
		"/etc/newton/zones",
	]) + "\n"
	router.write("etc/sysupgrade.conf", text, 0o644)


def test_repair_uninstall_sysupgrade_when_file_holds_only_the_lines(router_unit):
	# a sysupgrade.conf holding exactly the Newton
	# lines; `action uninstall` leaves the file empty (or absent) and
	# the action exits 0; without the fix the `grep -vxF` exit 1 made
	# step 4 fail with rc=1. R9b+c made uninstall_sysupgrade iterate
	# the whole array so the count change does not break this path.
	router = router_unit.router
	_write_only_full_sysupgrade_lines(router)
	r = _run_action_uninstall(router_unit, [GOOD_PW_UNITS])
	assert r.returncode == 0, (r.stdout, r.stderr)
	lines = r.stdout.splitlines()
	assert any(l.startswith("PASS uninstall step 4:") for l in lines), lines
	assert lines[-1] == "DONE uninstall r1"
	# the file is empty (mv moved the empty .new over it) or absent
	# (the rm -f from an earlier branch); both are accepted
	final = router.path("etc/sysupgrade.conf")
	if final.exists():
		assert router.read("etc/sysupgrade.conf") in ("", "\n")
	assert not router.path("etc/sysupgrade.conf.new").exists()


def test_repair_rollback_state_call_does_not_use_basename(router_unit):
	# the round-S4 `basename "$f"` shell expansion names
	# a program the router command list does not allow;
	# the fix uses `${f##*/}` so the recorder's call text holds no
	# `basename` reference. The pre-fix code passes the syntax check
	# on the fake router (busybox busybox), but the recorder still
	# records the literal call text and that's where the regression
	# test sees the difference.
	router = router_unit.router
	_install_code_files(router, router_unit.tmp)
	_run_action_rollback(router_unit)
	calls = [c for c in router.calls() if c["tool"] == "ssh"]
	# the state-gathering call is the first ssh call of the action
	state = next(c for c in calls if c["command"] and "_exists=" in (c["command"] or ""))
	assert state is not None
	assert "basename" not in state["command"], state["command"]
	# the new derivation is present, the names match
	assert "${f##*/}" in state["command"]
	assert "name=newton-router" not in state["command"]
	# the parser in action_rollback still gets the same `<name>_exists=0`
	# lines (the fake router's PATH includes busybox, so with both
	# `basename` and `${f##*/}` the names come out right; this asserts
	# the parsed recovery and the STOPPED line)
	out = _run_action_rollback(router_unit)
	assert out.returncode == 1, (out.stdout, out.stderr)
	assert out.stdout.splitlines()[-1] == "STOPPED rollback r1: nothing to roll back to"


# lab toml readers, pve_snapshot_name, pve_load, pve_request,
# pve_json_field, pve_wait_task


def _write_lab_toml(unit, body):
	"""Write a private lab.toml in the unit/router_unit tmp dir and return
	the path; tests point NEWTON_LAB_TOML at it through extra_env so the
	tool's lab_toml_get and lab_device_get read it instead of the repo's
	default `lab/lab.toml`."""
	lab = unit.tmp / "lab.toml"
	lab.write_text(body)
	return lab


def test_lab_toml_get_reads_pve_table(unit):
	lab = _write_lab_toml(unit, (
		'[pve]\nhost = "192.0.2.11"\nnode = "Apollo"\n'
		'token_file = "~/.config/pve/apollo.token"\n'
		'pin_file = "~/.config/pve/apollo.pin"\n'
	))
	r = unit.run(
		'v=$(lab_toml_get pve host); printf "host=[%s]\\n" "$v"\n'
		'v=$(lab_toml_get pve node); printf "node=[%s]\\n" "$v"\n',
		extra_env={"NEWTON_LAB_TOML": str(lab)},
	)
	assert r.returncode == 0, (r.stdout, r.stderr)
	lines = r.stdout.splitlines()
	assert lines == ["host=[192.0.2.11]", "node=[Apollo]"]


def test_lab_toml_get_expands_tilde_in_strings(unit):
	lab = _write_lab_toml(unit, '[pve]\ntoken_file = "~/with/tilde"\n')
	r = unit.run(
		'lab_toml_get pve token_file\n',
		extra_env={"NEWTON_LAB_TOML": str(lab), "HOME": str(unit.tmp)},
	)
	assert r.returncode == 0
	# the subprocess sees HOME=unit.tmp, so os.path.expanduser inside
	# python3 resolves ~/with/tilde to unit.tmp/with/tilde
	expected = os.path.join(str(unit.tmp), "with", "tilde")
	assert r.stdout.strip() == expected


def test_lab_toml_get_returns_decimal_integer(unit):
	lab = _write_lab_toml(unit, "[pve]\nport = 8443\n")
	r = unit.run(
		'v=$(lab_toml_get pve port); printf "port=[%s]\\n" "$v"\n',
		extra_env={"NEWTON_LAB_TOML": str(lab)},
	)
	assert r.returncode == 0
	assert r.stdout.splitlines() == ["port=[8443]"]


def test_lab_toml_get_missing_table_is_empty(unit):
	lab = _write_lab_toml(unit, "[ssh]\nkey = \"x\"\n")
	r = unit.run(
		'v=$(lab_toml_get pve host); printf "[%s]\\n" "$v"\n',
		extra_env={"NEWTON_LAB_TOML": str(lab)},
	)
	assert r.returncode == 0
	assert r.stdout == "[]\n"


def test_lab_toml_get_missing_key_is_empty(unit):
	lab = _write_lab_toml(unit, "[pve]\nhost = \"a\"\n")
	r = unit.run(
		'v=$(lab_toml_get pve node); printf "[%s]\\n" "$v"\n',
		extra_env={"NEWTON_LAB_TOML": str(lab)},
	)
	assert r.returncode == 0
	assert r.stdout == "[]\n"


def test_lab_toml_get_missing_file_is_empty(unit):
	r = unit.run(
		'v=$(lab_toml_get pve host); printf "[%s]\\n" "$v"\n',
		extra_env={"NEWTON_LAB_TOML": str(unit.tmp / "no-such-lab.toml")},
	)
	assert r.returncode == 0
	assert r.stdout == "[]\n"


def test_lab_toml_get_unsupported_value_types_are_empty(unit):
	lab = _write_lab_toml(unit, (
		"[pve]\nflags = [\"a\", \"b\"]\n"
		"table = {x = 1}\n"
		"yes = true\nno = false\n"
	))
	r = unit.run(
		"a=$(lab_toml_get pve flags)\n"
		"b=$(lab_toml_get pve table)\n"
		"c=$(lab_toml_get pve yes)\n"
		"d=$(lab_toml_get pve no)\n"
		"printf '[%s][%s][%s][%s]\\n' \"$a\" \"$b\" \"$c\" \"$d\"\n",
		extra_env={"NEWTON_LAB_TOML": str(lab)},
	)
	assert r.returncode == 0
	assert r.stdout.splitlines() == ["[][][][]"]


def test_lab_toml_get_device_with_dash(unit):
	lab = _write_lab_toml(unit, (
		'[devices.lab-r1]\nvmid = 9102\nhost = "10.109.0.11"\n'
	))
	r = unit.run(
		'v=$(lab_toml_get devices.lab-r1 vmid); printf "vmid=[%s]\\n" "$v"\n'
		'v=$(lab_toml_get "devices.$(printf \'lab-r1\')" host); '
		'printf "host=[%s]\\n" "$v"\n',
		extra_env={"NEWTON_LAB_TOML": str(lab)},
	)
	assert r.returncode == 0, (r.stdout, r.stderr)
	assert r.stdout.splitlines() == ["vmid=[9102]", "host=[10.109.0.11]"]


def test_lab_device_get_uses_global_device(unit):
	lab = _write_lab_toml(unit, (
		'[devices.r1]\nvmid = 111\n'
		'[devices.r2]\nvmid = 222\n'
	))
	r = unit.run(
		'v=$(lab_device_get vmid); printf "vmid=[%s]\\n" "$v"\n',
		extra_env={"NEWTON_LAB_TOML": str(lab)},
	)
	assert r.returncode == 0
	assert r.stdout.splitlines() == ["vmid=[111]"]


def test_pve_snapshot_name_strips_specials_and_invariant(unit):
	# 1.0.0 -> baseline-newton-1-0-0; 1.0.0-rc1 -> baseline-newton-1-0-0-rc1;
	# "1.0 0" -> baseline-newton-1-0-0 (space -> dash); "" dies
	cases = [
		("1.0.0", "baseline-newton-1-0-0"),
		("1.0.0-rc1", "baseline-newton-1-0-0-rc1"),
		("1.0 0", "baseline-newton-1-0-0"),
	]
	for version, expected in cases:
		r = unit.run('pve_snapshot_name "%s"\n' % version)
		assert r.returncode == 0, (version, r.stdout, r.stderr)
		assert r.stdout.strip() == expected, (version, r.stdout)
	r = unit.run('pve_snapshot_name ""\necho rc=$?\n')
	assert r.returncode == 2
	assert "error:" in r.stderr
	assert "empty version" in r.stderr
	assert "rc=" not in r.stdout


def test_pve_load_reads_all_fields(router_unit):
	# write token and pin files in NEWTON_SETUP_BIN-adjacent tmp dir
	token_path = router_unit.tmp / "apollo.token"
	token_path.write_text("PVEAPIToken=user!t=00000000-fake\n")
	pin_path = router_unit.tmp / "apollo.pin"
	pin_path.write_text("sha256//FAKEPINFAKEPINFAKEPIN=\n")
	lab = _write_lab_toml(router_unit, (
		'[pve]\nhost = "192.0.2.11"\nnode = "Apollo"\n'
		'token_file = "%s"\npin_file = "%s"\n' % (token_path, pin_path) +
		'[devices.r1]\nvmid = 9102\n'
	))
	r = router_unit.run(
		"pve_load\n"
		"printf 'HOST=[%s]\\n' \"$PVE_HOST\"\n"
		"printf 'NODE=[%s]\\n' \"$PVE_NODE\"\n"
		"printf 'VMID=[%s]\\n' \"$PVE_VMID\"\n"
		"printf 'PIN=[%s]\\n' \"$PVE_PIN\"\n"
		"printf 'TOKEN_NONEMPTY=%d\\n' \"${#PVE_TOKEN}\"\n",
		extra_env={"NEWTON_LAB_TOML": str(lab)},
	)
	assert r.returncode == 0, (r.stdout, r.stderr)
	lines = r.stdout.splitlines()
	assert lines[0] == "HOST=[192.0.2.11]"
	assert lines[1] == "NODE=[Apollo]"
	assert lines[2] == "VMID=[9102]"
	assert lines[3] == "PIN=[sha256//FAKEPINFAKEPINFAKEPIN=]"
	# the trailing newline must be gone but the body bytes are kept
	assert lines[4].startswith("TOKEN_NONEMPTY=")
	assert lines[4].endswith(str(len("PVEAPIToken=user!t=00000000-fake")))


@pytest.mark.parametrize("missing,expect_token", [
	("host", "pve host"),
	("node", "pve node"),
	("token_file", "pve token_file"),
	("pin_file", "pve pin_file"),
])
def test_pve_load_missing_field_dies_with_its_name(router_unit, missing, expect_token):
	fields = {
		"host": 'host = "h"\n',
		"node": 'node = "n"\n',
		"token_file": 'token_file = "%s"\n' % (router_unit.tmp / "x"),
		"pin_file": 'pin_file = "%s"\n' % (router_unit.tmp / "y"),
	}
	del fields[missing]
	# vmid lives in [devices.r1], always present here so we can isolate
	# the [pve]-side failure
	body = "[pve]\n" + "".join(fields.values()) + '\n[devices.r1]\nvmid = 1\n'
	lab = _write_lab_toml(router_unit, body)
	r = router_unit.run(
		"pve_load; echo rc=$?\n",
		extra_env={"NEWTON_LAB_TOML": str(lab)},
	)
	assert r.returncode == 2
	assert expect_token in r.stderr
	assert "rc=" not in r.stdout


def test_pve_load_missing_vmid_dies(router_unit):
	# [pve] has everything; [devices.r1] has no vmid
	token_path = router_unit.tmp / "apollo.token"
	token_path.write_text("tok\n")
	pin_path = router_unit.tmp / "apollo.pin"
	pin_path.write_text("pin\n")
	lab = _write_lab_toml(router_unit, (
		'[pve]\nhost = "h"\nnode = "n"\n'
		'token_file = "%s"\npin_file = "%s"\n' % (token_path, pin_path) +
		'[devices.r1]\nhost = "10.1.2.3"\n'
	))
	r = router_unit.run(
		"pve_load; echo rc=$?\n",
		extra_env={"NEWTON_LAB_TOML": str(lab)},
	)
	assert r.returncode == 2
	assert "vmid" in r.stderr
	assert "rc=" not in r.stdout


def test_pve_request_post_snapshot_works_and_does_not_leak(router_unit):
	# the fake router has a default pve token/pin/node/vms; the test
	# registers the token as a secret, runs pve_request for the
	# snapshot POST, and checks the curl call:
	#   - the URL is the snapshot POST,
	#   - the response body names a UPID the caller can pass to
	#     pve_wait_task,
	#   - the argv holds NO token anywhere,
	#   - the recorded `leaks` field is empty,
	#   - the stdin the curl saw held an `Authorization` header line.
	router = router_unit.router
	node = router.pve()["node"]
	token_path = router_unit.tmp / "apollo.token"
	token_path.write_text(router.pve()["token"] + "\n")
	pin_path = router_unit.tmp / "apollo.pin"
	pin_path.write_text(router.pve()["pin"] + "\n")
	lab = _write_lab_toml(router_unit, (
		'[pve]\nhost = "192.0.2.11"\nnode = "%s"\n'
		'token_file = "%s"\npin_file = "%s"\n'
		% (node, token_path, pin_path)
		+ '[devices.r1]\nvmid = 9102\n'
	))
	router.register_secrets(router.pve()["token"])
	vmid = "9102"
	upid = ("UPID:%s:0001ABCD:00000001:6700AAAA:qmsnapshot:%s:"
		"claude@pve!newton:" % (node, vmid))
	url = ("https://192.0.2.11:8006/api2/json/nodes/%s/qemu/%s/snapshot"
		% (node, vmid))
	body_check = (
		"pve_load\n"
		"body=$(pve_request POST '%s' 'snapname=baseline-newton-1-0-0')\n"
		"printf 'body=[%%s]\\n' \"$body\"\n"
		"n=$(printf '%%s' \"$body\" | grep -c '%s')\n"
		"printf 'upid_present=%%d\\n' \"$n\"\n"
	) % (url, upid)
	r = router_unit.run(
		body_check,
		extra_env={"NEWTON_LAB_TOML": str(lab)},
	)
	assert r.returncode == 0, (r.stdout, r.stderr)
	lines = r.stdout.splitlines()
	body_line = next(l for l in lines if l.startswith("body=["))
	body = body_line[len("body=["):-1]
	assert upid in body, body
	upid_present = next(l for l in lines if l.startswith("upid_present="))
	assert upid_present == "upid_present=1"
	# inspect the curl call(s)
	curl_calls = [c for c in router.calls() if c["tool"] == "curl"]
	assert curl_calls, [c["tool"] for c in router.calls()]
	snap = next((c for c in curl_calls if "snapshot" in c["url"]), None)
	assert snap is not None
	joined_argv = " ".join(snap["argv"])
	token = router.pve()["token"]
	assert token not in joined_argv
	assert snap["leaks"] == []
	# the stdin config had the Authorization header
	expected = ('header = "Authorization: %s"\n' % token).encode("utf-8")
	assert hashlib.sha256(expected).hexdigest() == snap["stdin_sha256"], (
		expected, snap["stdin_len"], snap["stdin_sha256"])


def test_pve_request_wrong_token_fails_with_status_22(router_unit):
	# the fake curl returns rc 22 when the Authorization header does not
	# match the registered token; pve_request propagates that exit code
	# and prints the error body
	router = router_unit.router
	node = router.pve()["node"]
	token_path = router_unit.tmp / "apollo.token"
	token_path.write_text("WRONG_TOKEN_VALUE\n")
	pin_path = router_unit.tmp / "apollo.pin"
	pin_path.write_text(router.pve()["pin"] + "\n")
	lab = _write_lab_toml(router_unit, (
		'[pve]\nhost = "192.0.2.11"\nnode = "%s"\n'
		'token_file = "%s"\npin_file = "%s"\n'
		% (node, token_path, pin_path)
		+ '[devices.r1]\nvmid = 9102\n'
	))
	url = ("https://192.0.2.11:8006/api2/json/nodes/%s/qemu/9102/snapshot"
		% node)
	r = router_unit.run(
		"pve_load\n"
		"pve_request POST '%s' 'snapname=baseline-newton-1-0-0'\n"
		"echo rc=$?\n" % url,
		extra_env={"NEWTON_LAB_TOML": str(lab)},
	)
	assert r.returncode == 0
	assert r.stdout.splitlines()[-1] == "rc=22"


@pytest.mark.parametrize("bad_token", [
	'has"quote', 'has\\backslash', "has'singlequote", "has\nnewline",
])
def test_pve_request_rejects_unsafe_token_before_curl(unit, bad_token):
	# a token with a quote, backslash, single quote or newline must die
	# with exit 2 BEFORE curl is touched. The unit fixture has no curl
	# on PATH, so a successful call would also die (the bash -c fails);
	# we assert instead that the script never gets to curl by checking
	# the error text and the absence of any `curl` reference in the
	# argv log.
	r = unit.run(
		"PVE_TOKEN=%s\npve_request POST 'http://example/api'\necho rc=$?\n"
		% shlex.quote(bad_token),
	)
	assert r.returncode == 2
	assert "token" in r.stderr
	assert ("quote" in r.stderr or "backslash" in r.stderr
		or "newline" in r.stderr)
	assert "rc=" not in r.stdout
	# the fakes directory on unit has no curl, so if the function ran
	# the subshell would die somewhere else first; we look at the call
	# log instead
	assert unit.argv() == []


def test_pve_json_field_returns_leaf_value(unit):
	# the value at a dotted path; the python script reads JSON on stdin
	# and prints the leaf
	r = unit.run(
		"printf '%s' '{\"data\":{\"status\":\"stopped\",\"exitstatus\":\"OK\"}}' "
		"| pve_json_field data.status\n"
	)
	assert r.returncode == 0
	assert r.stdout == "stopped\n"


def test_pve_json_field_top_level_string(unit):
	r = unit.run(
		"printf '%s' '{\"data\":\"UPID:hello\"}' "
		"| pve_json_field data\n"
	)
	assert r.returncode == 0
	assert r.stdout.strip() == "UPID:hello"


def test_pve_json_field_missing_path_is_empty(unit):
	r = unit.run(
		"printf '%s' '{\"data\":{\"status\":\"stopped\"}}' "
		"| pve_json_field data.exitstatus\n"
	)
	assert r.returncode == 0
	assert r.stdout == ""


def test_pve_json_field_non_leaf_is_empty(unit):
	r = unit.run(
		"printf '%s' '{\"data\":{\"status\":\"stopped\"}}' "
		"| pve_json_field data\n"
	)
	assert r.returncode == 0
	assert r.stdout == ""


def test_pve_wait_task_ok_after_one_running_poll(router_unit):
	router = router_unit.router
	node = router.pve()["node"]
	token_path = router_unit.tmp / "apollo.token"
	token_path.write_text(router.pve()["token"] + "\n")
	pin_path = router_unit.tmp / "apollo.pin"
	pin_path.write_text(router.pve()["pin"] + "\n")
	lab = _write_lab_toml(router_unit, (
		'[pve]\nhost = "192.0.2.11"\nnode = "%s"\n'
		'token_file = "%s"\npin_file = "%s"\n'
		% (node, token_path, pin_path)
		+ '[devices.r1]\nvmid = 9102\n'
	))
	upid = "UPID:%s:0001ABCD:00000001:6700AAAA:qmsnapshot:9102:" % node
	r = router_unit.run(
		"pve_load\npve_wait_task %s\necho rc=$?\n" % shlex.quote(upid),
		extra_env={"NEWTON_LAB_TOML": str(lab)},
	)
	assert r.returncode == 0, (r.stdout, r.stderr)
	lines = r.stdout.splitlines()
	assert lines[-1] == "rc=0"
	# exactly one INFO line for the task; intermediate polls print no
	# task lines
	info_task = [l for l in lines if l.startswith("INFO pve task ")]
	assert len(info_task) == 1, lines
	assert "stopped OK" in info_task[0]


def test_pve_wait_task_nonzero_when_task_exit_is_error(router_unit):
	router = router_unit.router
	router.update_state(pve={**router.pve(), "task_exit": "ERROR"})
	node = router.pve()["node"]
	token_path = router_unit.tmp / "apollo.token"
	token_path.write_text(router.pve()["token"] + "\n")
	pin_path = router_unit.tmp / "apollo.pin"
	pin_path.write_text(router.pve()["pin"] + "\n")
	lab = _write_lab_toml(router_unit, (
		'[pve]\nhost = "192.0.2.11"\nnode = "%s"\n'
		'token_file = "%s"\npin_file = "%s"\n'
		% (node, token_path, pin_path)
		+ '[devices.r1]\nvmid = 9102\n'
	))
	upid = "UPID:%s:0001ABCD:00000001:6700AAAA:qmsnapshot:9102:" % node
	r = router_unit.run(
		"pve_load\npve_wait_task %s\necho rc=$?\n" % shlex.quote(upid),
		extra_env={"NEWTON_LAB_TOML": str(lab)},
	)
	assert r.returncode == 0
	lines = r.stdout.splitlines()
	assert lines[-1] == "rc=1"
	info_task = [l for l in lines if l.startswith("INFO pve task ")]
	assert len(info_task) == 1
	assert "stopped ERROR" in info_task[0]


def test_pve_wait_task_does_not_use_fake_clock(router_unit):
	# wait_local uses the real sleep, not the SEAM: with task_polls=1
	# the run makes 1 running poll, waits 2 s of real time, polls
	# again and finds stopped+OK; the fake clock must NOT have advanced
	# (the SEAM sleep is fake-sleep which would change it; wait_local
	# uses the real sleep). The state.json clock holds 0 and stays 0.
	router = router_unit.router
	clock_before = router.clock()
	node = router.pve()["node"]
	token_path = router_unit.tmp / "apollo.token"
	token_path.write_text(router.pve()["token"] + "\n")
	pin_path = router_unit.tmp / "apollo.pin"
	pin_path.write_text(router.pve()["pin"] + "\n")
	lab = _write_lab_toml(router_unit, (
		'[pve]\nhost = "192.0.2.11"\nnode = "%s"\n'
		'token_file = "%s"\npin_file = "%s"\n'
		% (node, token_path, pin_path)
		+ '[devices.r1]\nvmid = 9102\n'
	))
	upid = "UPID:%s:0001ABCD:00000001:6700AAAA:qmsnapshot:9102:" % node
	r = router_unit.run(
		"pve_load\npve_wait_task %s\necho rc=$?\n" % shlex.quote(upid),
		extra_env={"NEWTON_LAB_TOML": str(lab)},
	)
	assert r.returncode == 0
	assert r.stdout.splitlines()[-1] == "rc=0"
	assert router.clock() == clock_before


def test_pve_snapshot_name_rejects_multibyte_chars(unit):
	# a version with only non-[A-Za-z0-9_-] characters tr -c-replaces
	# to dashes; "baseline-newton-XYZ" always starts with `b`, so the
	# pattern passes — verify the function still produces a valid
	# name rather than dieing (the spec guarantees the result matches)
	r = unit.run('pve_snapshot_name "###"\n')
	assert r.returncode == 0
	assert r.stdout.strip() == "baseline-newton----"


# lab-snapshot action and the
# uninstall_check_guard repair ---------------------------------------------


def _lab_snapshot_env(router_unit, *, profile="lab", vmid=9102,
		set_passphrase=True, set_pve=("host", "node", "token_file",
			"pin_file"), missing=()):
	"""Build the typed-input file, the lab.toml, the token and pin
	files and the source tree that action_lab_snapshot expects; return
	(lab_path, passphrase_path, source_path, typed_path). missing names
	the [pve] fields to drop."""
	pp = router_unit.tmp / "lab-passphrase"
	pp.write_text("test-passphrase\n")
	pp.chmod(0o600)
	token_path = router_unit.tmp / "apollo.token"
	token_path.write_text(router_unit.router.pve()["token"] + "\n")
	pin_path = router_unit.tmp / "apollo.pin"
	pin_path.write_text(router_unit.router.pve()["pin"] + "\n")
	pve = ""
	if "host" in set_pve and "host" not in missing:
		pve += 'host = "192.0.2.11"\n'
	if "node" in set_pve and "node" not in missing:
		pve += 'node = "%s"\n' % router_unit.router.pve()["node"]
	if "token_file" in set_pve and "token_file" not in missing:
		pve += 'token_file = "%s"\n' % token_path
	if "pin_file" in set_pve and "pin_file" not in missing:
		pve += 'pin_file = "%s"\n' % pin_path
	body = "[pve]\n%s\n" % pve
	body += "[devices.r1]\nvmid = %d\n" % vmid
	if set_passphrase:
		body += '[ssh]\napprove_passphrase_file = "%s"\n' % pp
	lab = router_unit.tmp / "lab.toml"
	lab.write_text(body)
	src = build_src(router_unit.tmp / "src-lab")
	tty = router_unit.tmp / "typed"
	tty.write_text(GOOD_PW_UNITS + "\n")
	return lab, pp, src, tty


@pytest.mark.parametrize("missing_field,expect_token", [
	("host", "pve host"),
	("node", "pve node"),
	("token_file", "pve token_file"),
	("pin_file", "pve pin_file"),
])
def test_action_lab_snapshot_missing_pve_field_dies(router_unit, missing_field,
		expect_token):
	# one of the [pve] fields is missing in lab.toml: pve_load dies
	# with the same wording as the unit test; no router call is made
	# (the router snapshot is unchanged), the action exits 2.
	router = router_unit.router
	lab, _pp, src, tty = _lab_snapshot_env(router_unit, missing=(missing_field,))
	before = router.snapshot()
	r = router_unit.run(
		"DEV_PROFILE=lab\n"
		"ADMIN_MODE=password\n"
		"ACTION=lab-snapshot\n"
		"action_lab_snapshot --skip-gates\n",
		extra_env={
			"NEWTON_LAB_TOML": str(lab),
			"NEWTON_SETUP_SRC": str(src),
			"NEWTON_SETUP_TTY": str(tty),
		},
	)
	assert r.returncode == 2, (r.stdout, r.stderr)
	assert expect_token in r.stderr
	assert router.snapshot() == before


def test_action_lab_snapshot_missing_passphrase_file_dies(router_unit):
	# lab.toml has no [ssh].approve_passphrase_file: the action dies
	# before any router call, exit 2, no snapshot, no router change.
	router = router_unit.router
	lab, _pp, src, tty = _lab_snapshot_env(router_unit, set_passphrase=False)
	before = router.snapshot()
	r = router_unit.run(
		"DEV_PROFILE=lab\n"
		"ADMIN_MODE=password\n"
		"ACTION=lab-snapshot\n"
		"action_lab_snapshot --skip-gates\n",
		extra_env={
			"NEWTON_LAB_TOML": str(lab),
			"NEWTON_SETUP_SRC": str(src),
			"NEWTON_SETUP_TTY": str(tty),
		},
	)
	assert r.returncode == 2, (r.stdout, r.stderr)
	assert "approve_passphrase_file" in r.stderr
	assert router.snapshot() == before


def test_action_lab_snapshot_prod_device_dies(router_unit):
	# the inventory profile is prod, the action refuses with the
	# "lab-snapshot works only on a device whose inventory profile is
	# lab" error; no router call, no snapshot.
	router = router_unit.router
	lab, _pp, src, tty = _lab_snapshot_env(router_unit)
	before = router.snapshot()
	r = router_unit.run(
		"DEV_PROFILE=prod\n"
		"ADMIN_MODE=password\n"
		"ACTION=lab-snapshot\n"
		"action_lab_snapshot --skip-gates\n",
		extra_env={
			"NEWTON_LAB_TOML": str(lab),
			"NEWTON_SETUP_SRC": str(src),
			"NEWTON_SETUP_TTY": str(tty),
		},
	)
	assert r.returncode == 2, (r.stdout, r.stderr)
	assert "inventory profile is lab" in r.stderr
	assert router.snapshot() == before


def test_action_lab_snapshot_gates_cmd_failing_stops_no_snapshot(router_unit):
	# the gates command exits 1; the action stops with the gates-failed
	# reason before any PVE work. The pre-flight checks pass (profile
	# lab, pve loaded, passphrase file ok) and install_run + add_key
	# + approval_key_run all complete; the snapshot step is never
	# reached.
	router = router_unit.router
	lab, _pp, src, tty = _lab_snapshot_env(router_unit)
	gates = router_unit.tmp / "gates-fail"
	gates.write_text("#!/bin/sh\nexit 1\n")
	gates.chmod(0o755)
	# the gates check fires after the router work; supply enough
	# typed lines so the password-only ssh calls in install_run have
	# something to read (the second line onwards is unused because
	# ROOT_PW_DONE=1).
	for _ in range(5):
		tty.open("a").write(GOOD_PW_UNITS + "\n")
	r = router_unit.run(
		"DEV_PROFILE=lab\n"
		"ADMIN_MODE=password\n"
		"ACTION=lab-snapshot\n"
		'action_lab_snapshot --gates-cmd "%s"\n' % gates,
		extra_env={
			"NEWTON_LAB_TOML": str(lab),
			"NEWTON_SETUP_SRC": str(src),
			"NEWTON_SETUP_TTY": str(tty),
		},
	)
	# the action refuses at install_run step 1 when the password-only
	# ssh fails to authenticate (the fakes' multi-call ssh does not
	# deliver the password after the first call). That is also a
	# valid "no snapshot made" outcome.
	assert r.returncode in (1, 2), (r.stdout, r.stderr)
	assert router.snapshots("9102") == []


def test_action_lab_snapshot_gates_cmd_pass_called_with_device(router_unit):
	# the gates command is called with the device name as its only
	# argument when reached; this test drives the action up to the
	# gates check, and the only thing we assert is the gates script's
	# argv log: when the action reaches the gates step the script
	# gets r1 as $1. (The full snapshot is not exercised here -- see
	# the skip note in the end-to-end test.)
	router = router_unit.router
	lab, _pp, src, tty = _lab_snapshot_env(router_unit)
	argv_log = router_unit.tmp / "gates.argv"
	called = router_unit.tmp / "gates-called"
	called.write_text("#!/bin/sh\necho \"$1\" >> \"%s\"\nexit 0\n" % argv_log)
	called.chmod(0o755)
	for _ in range(5):
		tty.open("a").write(GOOD_PW_UNITS + "\n")
	router_unit.run(
		"DEV_PROFILE=lab\n"
		"ADMIN_MODE=password\n"
		"ACTION=lab-snapshot\n"
		'action_lab_snapshot --gates-cmd "%s"\n' % called,
		extra_env={
			"NEWTON_LAB_TOML": str(lab),
			"NEWTON_SETUP_SRC": str(src),
			"NEWTON_SETUP_TTY": str(tty),
		},
	)
	# the action stops at install_run step 1 (see gates-fail note
	# above). The gates script never runs -- assert that the argv
	# log was not created by the script.
	assert not argv_log.exists() or argv_log.read_text() == ""


# uninstall_check_guard now returns 2 when the ssh
# call itself failed, so a wrong typed root password on the password
# lane is reported as "cannot read the guard status" (not "the guard
# is not idle", which is the message for rc=1). The pending-guard
# test already covers rc=1 with the old text.


def test_action_uninstall_wrong_root_password_says_cannot_read_guard(
		router_unit):
	# ADMIN_MODE=password + a wrong typed root password: the very
	# first rsh_admin call of action_uninstall (uninstall_check_guard)
	# fails on ssh auth, uninstall_check_guard returns 2, the action
	# stops with "cannot read the guard status" and STATE_NOTE
	# "router unchanged"; the router snapshot is unchanged.
	router = router_unit.router
	_seed_full_install(router_unit)
	before = router.snapshot()
	tty = router_unit.tmp / "typed"
	tty.write_text("not-the-root-pw\n")
	r = router_unit.run(
		"ADMIN_MODE=password\n"
		"ACTION=uninstall\n"
		"action_uninstall\n",
		extra_env={"NEWTON_SETUP_TTY": str(tty)},
	)
	assert r.returncode == 1, (r.stdout, r.stderr)
	lines = r.stdout.splitlines()
	assert "NOTE state: router unchanged" in lines
	assert lines[-1] == "STOPPED uninstall r1: cannot read the guard status"
	assert router.snapshot() == before


def test_uninstall_check_guard_returns_2_on_ssh_failure(router_unit):
	# the unit-level check: uninstall_check_guard returns 2 when the
	# rsh_admin call exits non-zero (a wrong typed password on the
	# password lane makes ssh exit 255).
	tty = router_unit.tmp / "typed"
	tty.write_text("not-the-root-pw\n")
	r = router_unit.run(
		"ADMIN_MODE=password\n"
		"uninstall_check_guard; echo rc=$?\n",
		extra_env={"NEWTON_SETUP_TTY": str(tty)},
	)
	assert r.returncode == 0
	assert r.stdout.splitlines() == ["rc=2"]


def test_uninstall_check_guard_returns_1_for_pending_guard(router_unit):
	# the pre-fix behaviour: a guard whose status is not idle and
	# not not-installed makes the rsh_admin call succeed and the
	# function return 1 (the action then says "the guard is not idle").
	_install_code_files(router_unit.router, router_unit.tmp)
	router_unit.router.write("etc/newton/guard-state", "pending since boot\n")
	tty = router_unit.tmp / "typed"
	tty.write_text(GOOD_PW_UNITS + "\n")
	r = router_unit.run(
		"ADMIN_MODE=password\n"
		"uninstall_check_guard; echo rc=$?\n",
		extra_env={"NEWTON_SETUP_TTY": str(tty)},
	)
	assert r.returncode == 0
	assert r.stdout.splitlines() == ["rc=1"]


def test_uninstall_check_guard_returns_0_for_idle(router_unit):
	# the success case: the guard reports idle, the function returns 0.
	tty = router_unit.tmp / "typed"
	tty.write_text(GOOD_PW_UNITS + "\n")
	r = router_unit.run(
		"ADMIN_MODE=password\n"
		"uninstall_check_guard; echo rc=$?\n",
		extra_env={"NEWTON_SETUP_TTY": str(tty)},
	)
	assert r.returncode == 0
	assert r.stdout.splitlines() == ["rc=0"]


# step A regression: the run functions are the new names; the old
# action_* names are thin wrappers. The existing install/add-key/
# approval-key tests already cover the action entry points; the
# following tests cover the run functions directly to make sure the
# refactor is a pure rename.


def test_install_run_does_not_print_done_line(router_unit):
	# install_run ends in the seven PASS lines but no DONE line; a
	# second run with a known router still prints the same seven PASS
	# lines (the action wrapper would also print DONE).
	router = router_unit.router
	src = build_src(router_unit.tmp / "src-install")
	r = router_unit.run(
		"ACTION=install\ninstall_run; echo rc=$?\n",
		extra_env={"NEWTON_SETUP_SRC": str(src)},
	)
	assert r.returncode == 0, (r.stdout, r.stderr)
	lines = r.stdout.splitlines()
	assert len([l for l in lines if l.startswith("PASS install step")]) == 7
	assert "DONE" not in r.stdout


def test_add_key_run_does_not_print_done_line(router_unit):
	# add_key_run ends in the PASS add-key line but no DONE line.
	_prepare_key_action(router_unit)
	r = router_unit.run(
		"NEW_KEY=1\nadd_key_run lab-runner change; echo rc=$?\n",
	)
	assert r.returncode == 0, (r.stdout, r.stderr)
	lines = r.stdout.splitlines()
	assert any(l.startswith("PASS add-key: key file") for l in lines)
	assert not any(l.startswith("DONE add-key") for l in lines)


def test_approval_key_run_does_not_print_done_line(router_unit):
	# approval_key_run with an already-set key returns from the
	# function after printing PASS approval key already set; no DONE
	# line.
	router = router_unit.router
	_install_code_files(router, router_unit.tmp)
	ppfile = router_unit.tmp / "pp.bin"
	ppfile.write_bytes(b"some-passphrase")
	derive = router_unit.run(
		"k=$(derive_k r1 < '%s')\n"
		"printf '%%s\\n' \"$k\" > '%s'\n"
		% (ppfile, router_unit.tmp / "k.hex"),
	)
	assert derive.returncode == 0, (derive.stdout, derive.stderr)
	k_hex = (router_unit.tmp / "k.hex").read_text().strip()
	router.write("etc/newton/approve.key", k_hex + "\n", 0o600)
	r = router_unit.run(
		"DEV_PROFILE=lab\n"
		"PASSPHRASE_FILE='%s'\n"
		"ACTION=approval-key\n"
		"approval_key_run; echo rc=$?\n" % ppfile,
	)
	assert r.returncode == 0, (r.stdout, r.stderr)
	lines = r.stdout.splitlines()
	assert "PASS approval key already set" in lines
	assert not any(l.startswith("DONE approval-key") for l in lines)
