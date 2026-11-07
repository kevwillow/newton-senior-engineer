"""Real-OpenSSH tests for scripts/newton-router-setup:
the REAL /usr/bin/ssh (via `ssh -G`, which only prints the resolved
configuration and contacts no router) and the REAL /usr/bin/ssh-keygen
must accept the exact option sets the tool builds. No fakes from
router_setup_harness.py, no fake ssh on PATH."""

import os
import re
import subprocess
from pathlib import Path

import pytest

TOOL = Path(__file__).resolve().parents[2] / "scripts" / "newton-router-setup"
REAL_SSH = Path("/usr/bin/ssh")
REAL_KEYGEN = Path("/usr/bin/ssh-keygen")

pytestmark = pytest.mark.skipif(
	not (REAL_SSH.is_file() and REAL_KEYGEN.is_file()),
	reason="needs the real /usr/bin/ssh and /usr/bin/ssh-keygen",
)

SOURCE = TOOL.read_text()


def lane_options(must):
	"""The options between "${SSH_OPTS[@]}" and "root@$DEV_HOST" on the ssh
	line of the tool that contains `must` (found by regex so the test
	follows the tool source)."""
	for m in re.finditer(
		r'\bssh "\$\{SSH_OPTS\[@\]\}" ([^\n]+) "root@\$DEV_HOST"', SOURCE
	):
		if must in m.group(1):
			return m.group(1)
	raise AssertionError("no ssh lane line holds %r" % must)


class RealUnit:
	"""Sources the tool in bash -c with a tmp keys dir, a known_hosts path
	and plain environment variables only (no seams, no fakes)."""

	def __init__(self, tmp_path):
		self.tmp = tmp_path
		self.keys = tmp_path / "keys"
		self.keys.mkdir(exist_ok=True)
		self.kh = self.keys / "r1.known_hosts"
		self.trusted = tmp_path / "trusted_known_hosts"

	def run(self, code, port="22", proxy=None, strict=None):
		env = {k: v for k, v in os.environ.items() if not k.startswith("NEWTON_")}
		env.update({"TOOL_PATH": str(TOOL), "TMPDIR": str(self.tmp)})
		# State-dir isolation: scripts/newton-router-setup resolves its
		# state dir from NEWTON_STATE_DIR (else `$(home_dir)/.local/state/newton`
		# via getent passwd).  Use per-call tmp dirs so any stray write
		# stays inside the tmp tree (the conftest's guard detects leaks).
		env.setdefault("NEWTON_STATE_DIR", str(self.tmp / "state"))
		env.setdefault("HOME", str(self.tmp / "home"))
		pre = (
			'. "$TOOL_PATH"\n'
			"init\n"
			"DEVICE=r1\n"
			"DEV_HOST=10.1.2.3\n"
			"DEV_PORT=%s\n" % port
			+ "DEV_PROXY=%s\n" % ("'%s'" % proxy if proxy else "''")
			+ "KEYS_DIR=%s\n" % self.keys
			+ "DEV_KNOWN_HOSTS=%s\n" % self.kh
			+ "TRUSTED_KNOWN_HOSTS=%s\n" % self.trusted
		)
		if strict:
			pre += "STRICT=%s\n" % strict
		return subprocess.run(
			["bash", "-c", pre + code],
			env=env,
			capture_output=True,
			text=True,
			timeout=60,
		)


def make_key(path, comment="realssh-test"):
	subprocess.run(
		[REAL_KEYGEN, "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f", str(path)],
		check=True,
		capture_output=True,
	)


def ssh_g_lines(key, lane_must, port="22", proxy=None, strict=None, tmp_path=None):
	"""Prints SSH_OPTS from the tool, appends the lane options exactly as
	the tool's ssh line holds them, runs the real `ssh -G` and returns the
	resolved output lines."""
	r = RealUnit(tmp_path).run(
		'ssh_base_opts\nprintf \'%s\\n\' "${SSH_OPTS[@]}"\n',
		port=port,
		proxy=proxy,
		strict=strict,
	)
	assert r.returncode == 0, r.stderr
	args = r.stdout.splitlines()
	for token in lane_options(lane_must).split():
		args.append(str(key) if token.strip('"') == "$1" else token.strip('"'))
	args += ["root@10.1.2.3", "hello"]
	p = subprocess.run(
		[REAL_SSH, "-G"] + args, capture_output=True, text=True, timeout=30
	)
	assert p.returncode == 0, p.stderr
	return p.stdout.splitlines()


def test_key_lane_options_resolve_with_real_ssh(tmp_path):
	key = tmp_path / "adminkey"
	make_key(key)
	out = ssh_g_lines(key, "PasswordAuthentication=no", tmp_path=tmp_path)
	for expected in [
		"stricthostkeychecking true",
		"batchmode yes",
		"identitiesonly yes",
		"passwordauthentication no",
		"preferredauthentications publickey",
		"userknownhostsfile %s" % (tmp_path / "keys" / "r1.known_hosts"),
		"globalknownhostsfile /dev/null",
		"port 22",
		"connecttimeout 8",
		"serveraliveinterval 5",
		"serveralivecountmax 2",
		"controlmaster false",
		"hostname 10.1.2.3",
		"user root",
		"identityfile %s" % key,
	]:
		assert expected in out
	# ControlPath=none is accepted but ssh -G (9.6) prints no controlpath
	# line at all when it resolves to none
	assert "controlpath none" in out or not [
		l for l in out if l.startswith("controlpath")
	]
	# a proxy in the inventory becomes a proxycommand
	out = ssh_g_lines(
		key, "PasswordAuthentication=no", proxy="nc 192.168.9.9 2222", tmp_path=tmp_path
	)
	assert "proxycommand nc 192.168.9.9 2222" in out
	# a non-default port wins
	out = ssh_g_lines(key, "PasswordAuthentication=no", port="2222", tmp_path=tmp_path)
	assert "port 2222" in out


def test_password_lane_options_resolve_with_real_ssh(tmp_path):
	key = tmp_path / "adminkey"
	make_key(key)
	out = ssh_g_lines(key, "NumberOfPasswordPrompts=1", tmp_path=tmp_path)
	for expected in [
		"batchmode no",
		"pubkeyauthentication false",
		"numberofpasswordprompts 1",
		"preferredauthentications password,keyboard-interactive",
		"port 22",
		"user root",
	]:
		assert expected in out


def test_strict_accept_new_resolves_with_real_ssh(tmp_path):
	key = tmp_path / "adminkey"
	make_key(key)
	out = ssh_g_lines(
		key, "PasswordAuthentication=no", strict="accept-new", tmp_path=tmp_path
	)
	assert "stricthostkeychecking accept-new" in out


def test_keypair_create_pub_blob_and_restricted_line_with_real_keygen(tmp_path):
	u = RealUnit(tmp_path)
	code = (
		"keypair_path label-x; keypair_create label-x; echo rc=$?\n"
		'echo "K=$KEYFILE"\n'
		'blob=$(pub_blob "$KEYFILE")\n'
		'printf "B=%s\\n" "$blob"\n'
		'restricted_line label-x change "$blob"\n'
	)
	r = u.run(code)
	assert r.returncode == 0, r.stderr
	lines = r.stdout.splitlines()
	assert lines[0] == "INFO new key made: %s" % (
		u.keys / "r1-label-x")
	assert lines[1] == "rc=0"
	keyfile = u.keys / "r1-label-x"
	assert lines[2] == "K=%s" % keyfile
	assert lines[3].startswith("B=")
	blob = lines[3][2:]
	restricted = lines[4]
	assert restricted.startswith("restrict,")
	assert lines[-1].startswith("restrict,")
	assert keyfile.is_file() and keyfile.with_suffix(".pub").is_file()
	# pub_blob equals the second field of the .pub file
	pub_fields = keyfile.with_suffix(".pub").read_text().split()
	assert pub_fields[1] == blob
	# the key is ed25519
	fp = subprocess.run(
		[REAL_KEYGEN, "-l", "-f", str(keyfile)], capture_output=True, text=True
	)
	assert fp.returncode == 0 and "ED25519" in fp.stdout
	# the restricted authorized_keys-style line is valid for ssh-keygen and
	# carries the same fingerprint as the .pub file
	pub_fp = subprocess.run(
		[REAL_KEYGEN, "-l", "-f", str(keyfile) + ".pub"], capture_output=True, text=True
	)
	assert pub_fp.returncode == 0
	ak = tmp_path / "authorized_keys"
	ak.write_text(restricted + "\n")
	ak_fp = subprocess.run(
		[REAL_KEYGEN, "-l", "-f", str(ak)], capture_output=True, text=True
	)
	assert ak_fp.returncode == 0, ak_fp.stderr
	assert ak_fp.stdout.strip() == pub_fp.stdout.strip()


@pytest.mark.parametrize("port,hostform", [("2222", "[10.1.2.3]:2222"), ("22", "10.1.2.3")])
def test_ensure_known_hosts_copy_branch_with_real_keygen(tmp_path, port, hostform):
	u = RealUnit(tmp_path)
	hostkey = tmp_path / "hostkey"
	make_key(hostkey, comment="realssh-host")
	pub = hostkey.with_suffix(".pub").read_text().strip()
	line = "%s %s" % (hostform, pub)
	u.trusted.write_text("otherhost.example %s\n%s\n" % (pub, line))
	r = u.run("ensure_known_hosts\necho rc=$?\n", port=port)
	assert r.returncode == 0, r.stderr
	assert "rc=0" in r.stdout
	assert u.kh.read_text() == line + "\n"
	# the real ssh-keygen finds the copied entry and can fingerprint it
	find = subprocess.run(
		[REAL_KEYGEN, "-F", hostform, "-f", str(u.kh)], capture_output=True, text=True
	)
	assert find.returncode == 0 and line in find.stdout
	lf = subprocess.run(
		[REAL_KEYGEN, "-l", "-f", str(u.kh)], capture_output=True, text=True
	)
	assert lf.returncode == 0 and "ED25519" in lf.stdout
