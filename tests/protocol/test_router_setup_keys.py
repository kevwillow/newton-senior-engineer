"""Tests of the add-key and revoke actions of scripts/newton-router-setup
(design 2.4, 2.7, 5.6, 8.3 sub-steps
1-3): the change and read happy paths, idempotence, the different-blob
refusal, every vulnerable router (forwarding, pty, agent, setenv), the
broken program, the deleted program, the pre-existing-line behavior on a
later failing proof, the unknown-option rule for `from=`, the coexist
labels rule and the secret rule."""

import os
import re
import shlex
import stat
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from router_setup_env import setup_env  # noqa: F401
from router_setup_harness import DEFAULT_STATE  # noqa: E402
from test_router_setup_install import (  # noqa: E402
	install_ok, seed_known_hosts)

GOOD_PW = DEFAULT_STATE["root_password"]

# the 10 proof PASS lines of 3.6 (matched by prefix, the rest is stable)
PROOF_PREFIXES = (
	"PASS proof hello:",
	"PASS proof probe-fail:",
	"PASS proof bad-arg:",
	"PASS proof selftest-refused:",
	"PASS proof backup:",
	"PASS proof unknown-and-empty:",
	"PASS proof forwards:",
	"PASS proof pty-agent:",
	"PASS proof sftp-scp:",
	"PASS proof setenv:",
)


def restricted_line_text(label, role, blob):
	"""The exact authorized_keys line of design 2.4 the tool writes."""
	return (
		"restrict,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,"
		"no-pty,command=\"/usr/libexec/newton/newton-router "
		"--caller=%s --role=%s\" ssh-ed25519 %s newton-router-%s\n"
		% (label, role, blob, label))


def key_blob(env, name):
	"""The blob of a key file created by the fake ssh-keygen."""
	key = env.keys_dir / ("r1-%s" % name)
	pub = key.with_name(key.name + ".pub")
	text = pub.read_text().strip()
	return text.split()[1]


def make_keypair(env, name):
	"""Make one local fake key pair without changing the router."""
	key = env.keys_dir / ("%s-%s" % (env.device, name))
	proc = subprocess.run(
		[str(env.fakes / "ssh-keygen"), "-q", "-t", "ed25519", "-N", "",
		 "-C", "newton-router-%s" % name, "-f", str(key)],
		capture_output=True, timeout=30)
	assert proc.returncode == 0, proc.stderr
	return key


def parse_ssh(argv):
	"""One ssh argv into (vals, flags, oopts, rest)."""
	vals, flags, oopts, rest = {}, set(), {}, []
	i = 0
	while i < len(argv):
		a = argv[i]
		if a in ("-i", "-p", "-P", "-F", "-L", "-D", "-R"):
			vals[a] = argv[i + 1]
			i += 2
		elif a in ("-N", "-T", "-tt", "-t", "-A", "-q", "-v"):
			flags.add(a)
			i += 1
		elif a == "-o":
			k, _, v = argv[i + 1].partition("=")
			oopts[k] = v
			i += 2
		else:
			rest.append(a)
			i += 1
	return vals, flags, oopts, rest


def key_lane_ssh_calls(result, keyfile):
	"""The ssh calls of `result.calls` that used `keyfile` on the key lane."""
	out = []
	for call in result.calls:
		if call["tool"] != "ssh":
			continue
		vals, flags, oopts, _rest = parse_ssh(call["argv"])
		if vals.get("-i") != str(keyfile):
			continue
		if oopts.get("IdentitiesOnly") != "yes":
			continue
		if oopts.get("BatchMode") != "yes":
			continue
		out.append(call)
	return out


def assert_no_ssh_left(tmp_path):
	"""No fake ssh process whose argv mentions `tmp_path` is still alive."""
	proc = subprocess.run(
		["pgrep", "-f", str(tmp_path)],
		capture_output=True, text=True, timeout=10)
	pids = [p for p in proc.stdout.split() if p]
	assert not pids, "leftover fake ssh pids: %s" % pids


def file_mode(path):
	return "0o%o" % stat.S_IMODE(os.stat(path).st_mode)


def direct_fake_ssh(env, keyfile, command):
	"""One fake ssh over the key lane, returns CompletedProcess.

	The fake ssh needs FAKE_ROUTER_ROOT; the rest of the env (NEWTON_*,
	PATH tweak) is irrelevant for this single call."""
	env_vars = {"PATH": str(env.fakes), "FAKE_ROUTER_ROOT": str(env.router.root)}
	return subprocess.run(
		[str(env.fakes / "ssh"),
		 "-F", "/dev/null", "-p", "22",
		 "-o", "ConnectTimeout=8",
		 "-o", "UserKnownHostsFile=" + str(env.known_hosts),
		 "-o", "StrictHostKeyChecking=yes",
		 "-i", str(keyfile),
		 "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
		 "-o", "PreferredAuthentications=publickey",
		 "-o", "PasswordAuthentication=no",
		 "root@10.1.2.3", command],
		capture_output=True, text=True, timeout=30, env=env_vars)


# -- 1. add-key change happy path (design 2.4, 2.7, 3.6) --------------------

def test_add_key_change_writes_one_line(setup_env):
	"""Addendum 3.4 and design 2.4/2.7: add-key newton-agent change
	exits 0, DONE add-key r1, one line in authorized_keys that equals
	restricted_line semantics for the key's blob, the private key file
	mode 0o600 and the keys dir 0o700, every proof of 3.6 printed a
	PASS line and the fake call log shows the proof calls on the key
	lane with -i the new key, IdentitiesOnly=yes, BatchMode=yes and
	the -N -L, -N -D, -N -R calls with a free local port each; every
	key-lane call used strict=yes."""
	env = setup_env
	install_ok(env)
	r = env.run("r1", "add-key", "--new-key", "newton-agent", "change",
	            typed=(GOOD_PW,))
	assert r.rc == 0
	assert "INFO new key made: %s" % (env.keys_dir / "r1-newton-agent") \
		in r.out.splitlines()
	assert r.out.splitlines()[-1] == "DONE add-key r1"
	assert r.err.count("root password: ") == 1
	blob = key_blob(env, "newton-agent")
	expected = restricted_line_text("newton-agent", "change", blob).rstrip("\n")
	ak_lines = env.router.authorized_keys()
	assert ak_lines == [expected]
	assert file_mode(env.keys_dir) == "0o700"
	assert file_mode(env.keys_dir / "r1-newton-agent") == "0o600"
	out_lines = r.out.splitlines()
	for prefix in PROOF_PREFIXES:
		assert any(line.startswith(prefix) for line in out_lines), prefix
	assert_no_ssh_left(env.tmp)

	keyfile = env.keys_dir / "r1-newton-agent"
	key_lane = key_lane_ssh_calls(r, keyfile)
	assert key_lane, "no key-lane ssh calls logged"
	for call in key_lane:
		assert call.get("strict") == "yes", call

	argv_l = next((c["argv"] for c in key_lane
	              if "-L" in c["argv"]), None)
	argv_d = next((c["argv"] for c in key_lane
	              if "-D" in c["argv"]), None)
	argv_r = next((c["argv"] for c in key_lane
	              if "-R" in c["argv"]), None)
	assert argv_l is not None and argv_d is not None and argv_r is not None
	vals_l, _, _o, _ = parse_ssh(argv_l)
	vals_d, _, _o, _ = parse_ssh(argv_d)
	vals_r, _, oopts_r, _ = parse_ssh(argv_r)
	assert re.match(r"^127\.0\.0\.1:\d+:127\.0\.0\.1:22$", vals_l["-L"])
	assert re.match(r"^127\.0\.0\.1:\d+$", vals_d["-D"])
	assert re.match(r"^\d+:127\.0\.0\.1:22$", vals_r["-R"])
	assert oopts_r.get("ExitOnForwardFailure") == "yes"


# -- 2. read role (design 3.5e, 3.6e) --------------------------------------

def test_add_key_read_role(setup_env):
	"""Design 3.6 (e): add-key lab-reader read. The backup proof PASS
	line says the read-role refusal, the backup ssh call (read role)
	got error role / rc 3, and the authorized_keys line says
	--role=read."""
	env = setup_env
	install_ok(env)
	r = env.run("r1", "add-key", "--new-key", "lab-reader", "read",
	            typed=(GOOD_PW,))
	assert r.rc == 0
	assert r.out.splitlines()[-1] == "DONE add-key r1"
	assert any(line.startswith("PASS proof backup: read-role")
	           for line in r.out.splitlines())
	backup = [c for c in r.calls if c["tool"] == "ssh"
	          and "-i" in parse_ssh(c["argv"])[0]
	          and parse_ssh(c["argv"])[0].get("-i") == str(
	              env.keys_dir / "r1-lab-reader")
	          and parse_ssh(c["argv"])[3] and parse_ssh(c["argv"])[3][-1]
	          == "backup"]
	assert backup, "no backup ssh call logged"
	assert backup[0]["rc"] == 3
	blob = key_blob(env, "lab-reader")
	assert env.router.authorized_keys() == [
		restricted_line_text("lab-reader", "read", blob).rstrip("\n")]


# -- 3. idempotence -----------------------------------------------------------

def test_add_key_idempotent(setup_env):
	"""A second add-key never appends or replaces a line.  It
	leaves snapshot() equal and exactly one line for the label, and asks
	the owner to revoke the old line first."""
	env = setup_env
	install_ok(env)
	r1 = env.run("r1", "add-key", "--new-key", "newton-agent", "change",
	             typed=(GOOD_PW,))
	assert r1.rc == 0, r1.out + r1.err
	before = env.router.snapshot()
	r2 = env.run("r1", "add-key", "newton-agent", "change",
	             typed=(GOOD_PW,))
	assert r2.rc == 1
	assert r2.out.splitlines()[-1] == (
		"STOPPED add-key r1: the router already has a Newton key line "
		"for label newton-agent; revoke it first (sudo -u newton "
		"/usr/local/bin/newton-router-setup r1 revoke newton-agent)")
	assert env.router.snapshot() == before
	ak_lines = env.router.authorized_keys()
	assert len(ak_lines) == 1
	assert "newton-router-newton-agent" in ak_lines[0]
	assert_no_ssh_left(env.tmp)


def test_add_key_without_a_local_key_never_mints(setup_env):
	"""The maintainer's hard rule: add-key cannot quietly create the private key that
	belongs to a router line; it stops before the first router call."""
	env = setup_env
	install_ok(env)
	before = env.router.read("etc/dropbear/authorized_keys")
	r = env.run("r1", "add-key", "newton-agent", "change",
	            typed=(GOOD_PW,))
	assert r.rc == 1
	assert r.out.splitlines()[-1] == (
		"STOPPED add-key r1: no key for label newton-agent on this host "
		"(%s is missing): the key lives on the Newton host that added "
		"it; run this there, or pass --new-key to make a new key on "
		"purpose" % (env.keys_dir / "r1-newton-agent"))
	assert "NOTE state: router unchanged" in r.out.splitlines()
	assert env.router.read("etc/dropbear/authorized_keys") == before
	assert r.calls == []
	assert not (env.keys_dir / "r1-newton-agent").exists()
	assert not (env.keys_dir / "r1-newton-agent.pub").exists()


def test_add_key_new_key_is_explicit(setup_env):
	"""--new-key is the only first-time mint path; it names the
	file it made and then writes exactly one restricted line."""
	env = setup_env
	install_ok(env)
	r = env.run("r1", "add-key", "--new-key", "newton-agent", "change",
	            typed=(GOOD_PW,))
	assert r.rc == 0
	assert "INFO new key made: %s" % (env.keys_dir / "r1-newton-agent") \
		in r.out.splitlines()
	assert len(env.router.authorized_keys()) == 1


def test_add_key_new_key_refuses_to_replace_an_existing_file(setup_env):
	"""The maintainer's hard rule: --new-key means make a missing key, never overwrite
	a present one; both bytes and mtime stay the same."""
	env = setup_env
	install_ok(env)
	key = make_keypair(env, "newton-agent")
	assert key.is_file()
	before = key.read_bytes()
	st = key.stat()
	r = env.run("r1", "add-key", "--new-key", "newton-agent", "change",
	            typed=(GOOD_PW,))
	assert r.rc == 1
	assert r.out.splitlines()[-1] == (
		"STOPPED add-key r1: a key for label newton-agent already exists "
		"on this host (%s); run it again without --new-key" % key)
	assert key.read_bytes() == before
	assert key.stat().st_mtime_ns == st.st_mtime_ns
	assert r.calls == []


# -- 4. label exists with a different blob ---------------------------------

def test_add_key_existing_different_blob(setup_env):
	"""Addendum 3.4: a hand-written line whose comment is
	newton-router-LABEL but a different blob stops the run; the line
	is untouched."""
	env = setup_env
	install_ok(env)
	key = make_keypair(env, "newton-agent")
	blob = key_blob(env, "newton-agent")
	env.router.write(
		"etc/dropbear/authorized_keys",
		restricted_line_text("newton-agent", "change", blob))
	hand_blob = "AAAAC3NzaC1lZDI1NTE5AAAAIOLDDdifferentblobffddee"
	hand = (
		"restrict,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,"
		"no-pty,command=\"/usr/libexec/newton/newton-router "
		"--caller=newton-agent --role=change\" ssh-ed25519 %s "
		"newton-router-newton-agent\n" % hand_blob)
	env.router.write("etc/dropbear/authorized_keys", hand)
	before_ak = env.router.authorized_keys()
	r = env.run("r1", "add-key", "newton-agent", "change",
	            typed=(GOOD_PW,))
	assert r.rc == 1
	last = r.out.splitlines()[-1]
	assert last.startswith("STOPPED add-key r1")
	assert "revoke it first" in last
	assert "NOTE state: router unchanged" in r.out.splitlines()
	assert env.router.authorized_keys() == before_ak


def test_add_key_existing_same_blob_refuses_without_replacing(setup_env):
	"""Even the same blob is not an idempotent append path; the
	existing line stays byte for byte and no second line is added."""
	env = setup_env
	install_ok(env)
	key = make_keypair(env, "newton-agent")
	env.router.write(
		"etc/dropbear/authorized_keys",
		restricted_line_text(
			"newton-agent", "change", key_blob(env, "newton-agent")))
	before = env.router.read("etc/dropbear/authorized_keys")
	r = env.run("r1", "add-key", "newton-agent", "change",
	            typed=(GOOD_PW,))
	assert r.rc == 1
	assert r.out.splitlines()[-1] == (
		"STOPPED add-key r1: the router already has a Newton key line "
		"for label newton-agent; revoke it first (sudo -u newton "
		"/usr/local/bin/newton-router-setup r1 revoke newton-agent)")
	assert env.router.read("etc/dropbear/authorized_keys") == before


def test_add_key_blob_on_a_plain_line_refuses_without_touching_it(setup_env):
	"""A blob that already belongs to a plain operator line is
	not appended under a Newton label, and no proof can later remove the
	operator's line."""
	env = setup_env
	install_ok(env)
	key = make_keypair(env, "newton-agent")
	blob = key_blob(env, "newton-agent")
	plain = "ssh-ed25519 %s operator@example\n" % blob
	env.router.write("etc/dropbear/authorized_keys", plain)
	before = env.router.read("etc/dropbear/authorized_keys")
	r = env.run("r1", "add-key", "newton-agent", "change",
	            typed=(GOOD_PW,))
	assert r.rc == 1
	assert r.out.splitlines()[-1] == (
		"STOPPED add-key r1: this key is already on the router in another "
		"line; add-key leaves existing lines alone (remove that line by "
		"hand or use another label)")
	assert "NOTE state: router unchanged" in r.out.splitlines()
	assert env.router.read("etc/dropbear/authorized_keys") == before
	assert key_lane_ssh_calls(r, key) == []
	assert not any(line.startswith(("PASS proof ", "FAIL proof "))
	               for line in r.out.splitlines())


def test_add_key_stops_when_the_blob_check_read_fails(setup_env):
	"""A failed authorized_keys read at add-key's blob check is
	a failure, not 'absent', so nothing is appended and no proof runs.  The
	fake's rc_commands knob fails exactly that admin call: auth_has_blob's
	remote text is the only one that assigns out=$(awk -v blob=."""
	env = setup_env
	install_ok(env)
	key = make_keypair(env, "newton-agent")
	before = env.router.read("etc/dropbear/authorized_keys")
	env.router.update_state(rc_commands=[["out=$(awk -v blob=", 3]])
	r = env.run("r1", "add-key", "newton-agent", "change",
	            typed=(GOOD_PW,))
	assert r.rc == 1
	assert r.out.splitlines()[-1] == (
		"STOPPED add-key r1: cannot check whether the key is on the router")
	assert "NOTE state: router unchanged" in r.out.splitlines()
	assert env.router.read("etc/dropbear/authorized_keys") == before
	assert key_lane_ssh_calls(r, key) == []
	assert not any(line.startswith(("PASS proof ", "FAIL proof "))
	               for line in r.out.splitlines())


# -- 5. vulnerable routers and broken / deleted programs --------------------

@pytest.mark.parametrize("vuln, fail_prefix", [
	(["forwarding"], "FAIL proof forwards:"),
	(["pty"],        "FAIL proof pty-agent:"),
	(["agent"],      "FAIL proof pty-agent:"),
	(["setenv"],     "FAIL proof setenv:"),
])
def test_add_key_vulnerable_router(setup_env, vuln, fail_prefix):
	"""Addendum 3.4 and design 8.3 sub-step 3: each vulnerable router
	makes the matching proof FAIL, the run STOPPED, the added line is
	removed again (authorized_keys equals the original empty bytes)."""
	env = setup_env
	install_ok(env)
	env.router.update_state(vulnerable=vuln)
	original = list(env.router.authorized_keys())
	r = env.run("r1", "add-key", "--new-key", "newton-agent", "change",
	            typed=(GOOD_PW,))
	assert r.rc == 1
	assert r.out.splitlines()[-1].startswith("STOPPED add-key r1")
	assert any(line.startswith(fail_prefix) for line in r.out.splitlines()), \
		"no line starts with %r" % fail_prefix
	assert "router unchanged (the new line was removed again)" in r.out
	assert env.router.authorized_keys() == original
	assert not (env.keys_dir / "r1-newton-agent").exists()
	assert not (env.keys_dir / "r1-newton-agent.pub").exists()
	assert_no_ssh_left(env.tmp)


def test_add_key_broken_program(setup_env, tmp_path):
	"""Design 8.2/3.6: a broken program (build_src(program='broken'))
	installed first, add-key: every proof FAIL, STOPPED, the line is
	removed again (authorized_keys equals the original empty bytes)."""
	env = setup_env
	seed_known_hosts(env)
	broken = build_src_for(env, tmp_path, program="broken")
	inst = env.run("r1", "install", typed=(GOOD_PW, "yes"),
	               env={"NEWTON_SETUP_SRC": str(broken)})
	assert inst.rc == 1
	original = list(env.router.authorized_keys())
	r = env.run("r1", "add-key", "--new-key", "newton-agent", "change",
	            typed=(GOOD_PW,))
	assert r.rc == 1
	assert r.out.splitlines()[-1].startswith("STOPPED add-key r1")
	assert any(line.startswith("FAIL proof hello:")
	           for line in r.out.splitlines())
	assert "router unchanged (the new line was removed again)" in r.out
	assert env.router.authorized_keys() == original
	assert not (env.keys_dir / "r1-newton-agent").exists()
	assert not (env.keys_dir / "r1-newton-agent.pub").exists()
	assert_no_ssh_left(env.tmp)


def test_add_key_deleted_program(setup_env):
	"""Design 8.3 sub-step 3: the program file is missing on the
	router; hello/probe/... all return 127; proofs FAIL; STOPPED;
	authorized_keys equals the original empty bytes."""
	env = setup_env
	install_ok(env)
	env.router.path("usr/libexec/newton/newton-router").unlink()
	original = list(env.router.authorized_keys())
	r = env.run("r1", "add-key", "--new-key", "newton-agent", "change",
	            typed=(GOOD_PW,))
	assert r.rc == 1
	assert r.out.splitlines()[-1].startswith("STOPPED add-key r1")
	assert any(line.startswith("FAIL proof hello:")
	           for line in r.out.splitlines())
	assert any(c["tool"] == "ssh" and c["rc"] == 127 for c in r.calls)
	assert "router unchanged (the new line was removed again)" in r.out
	assert env.router.authorized_keys() == original
	assert not (env.keys_dir / "r1-newton-agent").exists()
	assert not (env.keys_dir / "r1-newton-agent.pub").exists()
	assert_no_ssh_left(env.tmp)


def build_src_for(env, tmp_path, program="ok", version="1.0.0"):
	"""Build the source tree (build_src is defined in router_setup_env)."""
	from router_setup_env import build_src  # noqa: WPS433
	return build_src(tmp_path / "src", program=program, version=version)


# -- 6. failing proof on a pre-existing line --------------------------------

def test_add_key_with_an_existing_line_refuses_before_any_proof(setup_env):
	"""When the router already has a Newton
	line for the label, add-key refuses before any proof and leaves that
	line untouched."""
	env = setup_env
	install_ok(env)
	r1 = env.run("r1", "add-key", "--new-key", "newton-agent", "change",
	             typed=(GOOD_PW,))
	assert r1.rc == 0
	line_after_first = env.router.authorized_keys()[0]
	env.router.update_state(vulnerable=["forwarding"])
	r2 = env.run("r1", "add-key", "newton-agent", "change",
	             typed=(GOOD_PW,))
	assert r2.rc == 1
	assert r2.out.splitlines()[-1].startswith("STOPPED add-key r1")
	assert ("the router already has a Newton key line for label "
	        "newton-agent; revoke it first") in r2.out
	assert not any(line.startswith("FAIL proof ")
	               for line in r2.out.splitlines())
	assert env.router.authorized_keys() == [line_after_first]


# -- 7. revoke ---------------------------------------------------------------

def test_revoke_removes_line_and_revokes_login(setup_env):
	"""Addendum 3.4: revoke newton-agent removes the line, the key
	lane login with the revoked key fails (255), the local key files
	stay, a second revoke prints PASS already revoked and changes
	nothing, revoke of a label that does not exist behaves the same."""
	env = setup_env
	install_ok(env)
	r1 = env.run("r1", "add-key", "--new-key", "newton-agent", "change",
	             typed=(GOOD_PW,))
	assert r1.rc == 0
	ak_before = list(env.router.authorized_keys())
	assert len(ak_before) == 1

	r2 = env.run("r1", "revoke", "newton-agent", typed=(GOOD_PW,))
	assert r2.rc == 0
	assert r2.out.splitlines()[-1] == "DONE revoke r1"
	assert any(line.startswith("PASS revoked ") for line in r2.out.splitlines())
	assert env.router.authorized_keys() == []

	key = env.keys_dir / "r1-newton-agent"
	pub = env.keys_dir / "r1-newton-agent.pub"
	assert key.exists() and pub.exists()
	assert file_mode(key) == "0o600"
	assert "local key files kept" in r2.out

	hello = direct_fake_ssh(env, key, "hello " + ("0" * 32))
	assert hello.returncode == 255
	assert "Permission denied" in hello.stderr

	r3 = env.run("r1", "revoke", "newton-agent", typed=(GOOD_PW,))
	assert r3.rc == 0
	assert r3.out.splitlines()[-1] == "DONE revoke r1"
	assert "PASS already revoked" in r3.out.splitlines()

	r4 = env.run("r1", "revoke", "lab-runner", typed=(GOOD_PW,))
	assert r4.rc == 0
	assert r4.out.splitlines()[-1] == "DONE revoke r1"
	assert "PASS already revoked" in r4.out.splitlines()
	assert env.router.authorized_keys() == []


def test_uninstall_restore_command_fails_safe_off_the_newton_host(setup_env):
	"""The restore advice names add-key without --new-key, so a
	owner who copies it on the wrong host gets a safe refusal instead of a
	brand-new key that does not match the baseline line."""
	env = setup_env
	install_ok(env)
	blob = "AAAAC3NzaC1lZDI1NTE5AAAAIUNINSTALLLABHOSTBLOB0001"
	env.router.write(
		"etc/dropbear/authorized_keys",
		restricted_line_text("workstation", "change", blob))
	removed = env.run("r1", "uninstall", typed=(GOOD_PW,))
	assert removed.rc == 0, removed.out + removed.err
	match = re.search(
		r"run: (sudo -u newton /usr/local/bin/newton-router-setup "
		r"r1 add-key workstation change)",
		removed.out)
	assert match, removed.out
	after_uninstall = env.router.read("etc/dropbear/authorized_keys")
	restore = env.run(*shlex.split(match.group(1))[4:],
	                  typed=(GOOD_PW,))
	assert restore.rc == 1
	assert restore.out.splitlines()[-1] == (
		"STOPPED add-key r1: no key for label workstation on this host "
		"(%s is missing): the key lives on the Newton host that added "
		"it; run this there, or pass --new-key to make a new key on "
		"purpose" % (env.keys_dir / "r1-workstation"))
	assert env.router.read("etc/dropbear/authorized_keys") == after_uninstall
	assert not (env.keys_dir / "r1-workstation").exists()
	assert not (env.keys_dir / "r1-workstation.pub").exists()


# -- 8. two labels coexist (design 5.6) -------------------------------------

def test_two_labels_coexist_revoke_one(setup_env):
	"""Design 5.6: two change labels (newton-agent, lab-runner)
	coexist; revoking one leaves the other working (login with its key
	succeeds)."""
	env = setup_env
	install_ok(env)
	r1 = env.run("r1", "add-key", "--new-key", "newton-agent", "change",
	             typed=(GOOD_PW,))
	assert r1.rc == 0
	r2 = env.run("r1", "add-key", "--new-key", "lab-runner", "change",
	             typed=(GOOD_PW,))
	assert r2.rc == 0
	both = env.router.authorized_keys()
	assert len(both) == 2

	r3 = env.run("r1", "revoke", "newton-agent", typed=(GOOD_PW,))
	assert r3.rc == 0
	assert any(line.startswith("PASS revoked ") for line in r3.out.splitlines())
	after = env.router.authorized_keys()
	assert len(after) == 1
	assert "newton-router-lab-runner" in after[0]

	lab_key = env.keys_dir / "r1-lab-runner"
	hello = direct_fake_ssh(env, lab_key, "hello " + ("0" * 32))
	assert hello.returncode == 0
	assert hello.stdout.split()[0] == "hello"
	assert "caller=lab-runner" in hello.stdout
	assert "role=change" in hello.stdout


# -- 9. unknown-option rule (design 2.4) ------------------------------------

def test_no_from_or_environment_in_line(setup_env):
	"""Design 2.4 last paragraph: dropbear ignores an authorized_keys
	line whose first option is unknown (here `from="..."`); the tool
	writes none, so the new line carries no `from=` and no
	`environment=`."""
	env = setup_env
	install_ok(env)
	from_blob = "AAAAC3NzaC1lZDI1NTE5AAAAIFakefromoptionhandle"
	from_line = (
		"from=\"10.0.0.0/8\" ssh-ed25519 %s some-comment\n" % from_blob)
	env.router.write("etc/dropbear/authorized_keys", from_line)
	reject = direct_fake_ssh(env,
	                          make_plain_key(env, from_blob),
	                          "hello " + ("0" * 32))
	assert reject.returncode == 255
	assert "Permission denied" in reject.stderr

	r = env.run("r1", "add-key", "--new-key", "newton-agent", "change",
	             typed=(GOOD_PW,))
	assert r.rc == 0
	ak = env.router.authorized_keys()
	tool_lines = [l for l in ak
	              if "newton-router-newton-agent" in l]
	assert len(tool_lines) == 1
	assert "from=" not in tool_lines[0]
	assert "environment=" not in tool_lines[0]


def make_plain_key(env, blob):
	"""Write a fake private key file whose blob is `blob`; returns path."""
	key = env.tmp / "known-blob.key"
	key.write_text("FAKE-OPENSSH-PRIVATE-KEY\n%s\n" % blob)
	os.chmod(key, 0o600)
	return key


# -- 10. secrets ---------------------------------------------

def test_add_key_no_secret_leaks(setup_env):
	"""Addendum 1.3 / 2.3: the typed root password never appears in
	output, call argv or any scanned file."""
	env = setup_env
	env.register_secrets(GOOD_PW)
	install_ok(env)
	r = env.run("r1", "add-key", "--new-key", "newton-agent", "change",
	             typed=(GOOD_PW,))
	assert r.rc == 0
	assert env.leaks() == []


# -- 11. every call with the new key is a key-lane call --

def test_add_key_every_call_with_the_key_is_key_lane_only(setup_env):
	"""Addendum 2.2: each ssh, scp and sftp call that names the new key
	carries the whole key-lane option set (found by a planted defect that
	dropped BatchMode=yes from the plain helper and survived because the
	test only looked at the calls that still had it)."""
	env = setup_env
	install_ok(env)
	r = env.run("r1", "add-key", "--new-key", "newton-agent", "change",
	            typed=(GOOD_PW,))
	assert r.rc == 0
	keyfile = str(env.keys_dir / "r1-newton-agent")
	key_calls = [c for c in r.calls
	             if c["tool"] in ("ssh", "scp", "sftp") and keyfile in c["argv"]]
	assert len(key_calls) >= 12, len(key_calls)
	for call in key_calls:
		_vals, _flags, oopts, _rest = parse_ssh(call["argv"])
		assert oopts.get("IdentitiesOnly") == "yes", call["argv"]
		assert oopts.get("BatchMode") == "yes", call["argv"]
		assert oopts.get("PreferredAuthentications") == "publickey", call["argv"]
		assert oopts.get("PasswordAuthentication") == "no", call["argv"]
		assert oopts.get("StrictHostKeyChecking") == "yes", call["argv"]


# -- 12. SW2 review: the keys dir parent rule --------------------------------

def test_add_key_refuses_keys_dir_under_group_writable_parent(setup_env):
	"""SW2 review: NEWTON_KEYS_DIR holds the device private keys, and it is
	operator-settable, so keypair_create refuses to create it when its
	PARENT is group- or world-writable without the sticky bit -- exactly
	the rule the script already applies to its state dir.

	The keys dir itself is created here, so the refusal is the check and
	not a missing directory: no key pair is generated, the authorized_keys
	line is untouched and the run makes no ssh write call.
	"""
	env = setup_env
	install_ok(env)
	hostile = env.tmp / "hostile-keys-parent"
	hostile.mkdir()
	os.chmod(hostile, 0o777)
	keys_dir = hostile / "keys"
	keys_dir.mkdir()
	os.chmod(keys_dir, 0o700)
	# the run must pass require_known_hosts to reach keypair_create
	(keys_dir / "r1.known_hosts").write_text(
		"10.1.2.3 %s\n" % env.router.state()["host_key"])

	try:
		r = env.run("r1", "add-key", "--new-key", "newton-agent", "change",
		            typed=(GOOD_PW,), env={"NEWTON_KEYS_DIR": str(keys_dir)})
	finally:
		os.chmod(hostile, 0o700)

	assert r.rc == 2, r.out + r.err
	assert "group- or world-writable without the sticky bit" in r.err
	assert str(hostile) in r.err
	assert sorted(p.name for p in keys_dir.iterdir()) == ["r1.known_hosts"]
	assert env.router.authorized_keys() == []
	assert len(r.calls) == 1
	assert r.calls[0]["tool"] == "ssh"
