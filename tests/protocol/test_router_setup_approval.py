"""Tests of the approval-key action of scripts/newton-router-setup (;
design 5.4): the lab happy path with K correctness
and a non-ASCII passphrase, the salt includes the device name,
idempotence and a different passphrase, the prod refusal of the lab
passphrase file (with and without a trailing LF) and the missing-file
NOTE, --passphrase-file, the install prerequisite, the selftest-lie
refusal, the typed-input edge cases, the secret rules and the offer of
the authenticator app that follows the passphrase."""

import hashlib
import hmac
import os
import shlex
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from router_setup_env import setup_env, pulsar_env  # noqa: F401
from router_setup_harness import DEFAULT_STATE  # noqa: E402
from test_router_setup_install import (  # noqa: E402
    seed_known_hosts, install_ok)

GOOD_PW = DEFAULT_STATE["root_password"]
NONCE_RE = r"^[0-9a-f]{32}$"
PASS_OK = "PASS approval key verified"
PASS_ALREADY = "PASS approval key already set"


def approve_k(pp, device):
    """The K the tool derives for ``pp`` on ``device`` (test-side check)."""
    return hashlib.pbkdf2_hmac(
        "sha256", pp.encode("utf-8"),
        ("newton-approve-v1:" + device).encode("utf-8"),
        600000, 32).hex()


def approval_fp(k_hex):
    """The fingerprint the tool stores: HMAC-SHA256(K bytes,
    b"newton-approval-fingerprint-v1").hexdigest()."""
    return hmac.new(
        bytes.fromhex(k_hex),
        b"newton-approval-fingerprint-v1",
        hashlib.sha256,
    ).hexdigest()


def has_upload(calls):
    """A put_stream call for approve.key was made (the stored command
    text contains the literal ``approve.key.new``)."""
    return any("approve.key.new" in (c.get("command") or "")
               for c in calls)


def install_pulsar(env):
	"""Seed known_hosts and install for the pulsar env (needs the
	plain-key flag and a known_hosts entry)."""
	seed_known_hosts(env)
	return env.run("--plain-key", env.plain_key, "pulsar", "install",
	              typed=("yes",))


# -- 1. lab happy path -------------------------------------------------------

def test_approval_lab_writes_key(setup_env):
	"""Addendum 3.3 / design 5.4: lab device, passphrase typed twice
	with a non-ASCII character. Exit 0, ``DONE approval-key r1``,
	``/etc/newton/approve.key`` is 64 lowercase hex plus LF, mode 0o600
	and equals ``pbkdf2_hmac('sha256', pp, 'newton-approve-v1:r1',
	600000, 32).hex()``; the PASS line appears and the passphrase or
	the key is never printed; call argv carries neither."""
	env = setup_env
	pp = "seCr3t-é"
	expected_k = approve_k(pp, "r1")
	env.register_secrets(GOOD_PW, pp, expected_k)
	install_ok(env)
	r = env.run("r1", "approval-key", typed=(GOOD_PW, pp, pp))
	assert r.rc == 0
	assert r.out.splitlines()[-1] == "DONE approval-key r1"
	assert PASS_OK in r.out.splitlines()
	snap = env.router.snapshot()
	assert snap["etc/newton/approve.key"]["mode"] == "0o600"
	content = env.router.read("etc/newton/approve.key")
	assert content == expected_k + "\n"
	assert len(content.strip()) == 64
	assert all(c in "0123456789abcdef" for c in content.strip())
	text = r.out + r.err
	assert pp not in text
	assert expected_k not in text
	for call in r.calls:
		for arg in call.get("argv", []):
			assert pp not in arg
			assert expected_k not in arg
		assert not call.get("leaks")
	assert env.leaks() == []


# -- 2. salt includes the device name ----------------------------------------

def test_approval_salt_includes_device_name(setup_env):
	"""The PBKDF2 salt is ``newton-approve-v1:`` + device id, so the
	same passphrase on a second inventory device gives a different K."""
	env = setup_env
	install_ok(env)
	env.inventory.write_text(
		"[devices.r1]\nhost = \"10.1.2.3\"\nprofile = \"lab\"\n"
		"auth = \"password\"\n"
		"[devices.r2]\nhost = \"10.1.2.3\"\nprofile = \"lab\"\n"
		"auth = \"password\"\n")
	shutil.copy(env.known_hosts, env.keys_dir / "r2.known_hosts")
	pp = "shared-pass"
	expected_k_r1 = approve_k(pp, "r1")
	expected_k_r2 = approve_k(pp, "r2")
	assert expected_k_r1 != expected_k_r2
	r1 = env.run("r1", "approval-key", typed=(GOOD_PW, pp, pp))
	assert r1.rc == 0
	assert env.router.read("etc/newton/approve.key").strip() == expected_k_r1
	r2 = env.run("r2", "approval-key", typed=(GOOD_PW, pp, pp))
	assert r2.rc == 0
	assert env.router.read("etc/newton/approve.key").strip() == expected_k_r2


# -- 3. idempotence and a different passphrase ------------------------------

def test_approval_idempotent_same_passphrase(setup_env):
	"""A second run with the same passphrase: ``PASS approval key
	already set``, no upload, snapshot unchanged."""
	env = setup_env
	pp = "stable-pp"
	install_ok(env)
	r1 = env.run("r1", "approval-key", typed=(GOOD_PW, pp, pp))
	assert r1.rc == 0
	before = env.router.snapshot()
	r2 = env.run("r1", "approval-key", typed=(GOOD_PW, pp, pp))
	assert r2.rc == 0
	assert r2.out.splitlines()[-1] == "DONE approval-key r1"
	assert PASS_ALREADY in r2.out.splitlines()
	assert not has_upload(r2.calls)
	assert env.router.snapshot() == before


def test_approval_different_passphrase_changes_key(setup_env):
	"""After a different passphrase the key on the router is replaced
	and the selftest still passes (``PASS approval key verified``)."""
	env = setup_env
	install_ok(env)
	r1 = env.run("r1", "approval-key",
	             typed=(GOOD_PW, "firstpw1", "firstpw1"))
	assert r1.rc == 0
	k1 = env.router.read("etc/newton/approve.key").strip()
	r2 = env.run("r1", "approval-key",
	             typed=(GOOD_PW, "secondpw2", "secondpw2"))
	assert r2.rc == 0
	assert PASS_OK in r2.out.splitlines()
	k2 = env.router.read("etc/newton/approve.key").strip()
	assert k1 != k2
	assert k2 == approve_k("secondpw2", "r1")


# -- 4. prod refuses the lab passphrase file ---------------------------------

def _write_lab_passphrase(env, content):
	"""Put the lab passphrase file in the outside (unscanned) dir and
	point env.lab_toml at it; returns the path."""
	outside = env.typed_file.parent
	lab_pw = outside / "lab.pw"
	lab_pw.write_text(content)
	lab_pw.chmod(0o600)
	env.lab_toml.write_text(
		"[ssh]\napprove_passphrase_file = \"%s\"\n" % lab_pw)
	return lab_pw


def test_approval_pulsar_refuses_lab_passphrase(pulsar_env):
	"""Pulsar with a lab_pw holding ``labpass``: typing ``labpass``
	twice is ``STOPPED approval-key pulsar`` with state ``router
	unchanged``, no upload call, no approve.key on the router."""
	env = pulsar_env
	_write_lab_passphrase(env, "labpass")
	install_pulsar(env)
	r = env.run("--plain-key", env.plain_key, "pulsar", "approval-key",
	            typed=("labpass", "labpass"))
	assert r.rc == 1
	lines = r.out.splitlines()
	assert "NOTE state: router unchanged" in lines
	last = lines[-1]
	assert last.startswith("STOPPED approval-key pulsar")
	assert "the approval passphrase equals the lab passphrase file" in last
	assert not has_upload(r.calls)
	assert not env.router.path("etc/newton/approve.key").exists()


def test_approval_pulsar_refuses_lab_passphrase_trailing_lf(pulsar_env):
	"""A trailing LF in the lab_pw file does not hide the match (one trailing
	LF is dropped)."""
	env = pulsar_env
	_write_lab_passphrase(env, "labpass\n")
	install_pulsar(env)
	r = env.run("--plain-key", env.plain_key, "pulsar", "approval-key",
	            typed=("labpass", "labpass"))
	assert r.rc == 1
	last = r.out.splitlines()[-1]
	assert last.startswith("STOPPED approval-key pulsar")
	assert "the approval passphrase equals the lab passphrase file" in last


def test_approval_pulsar_other_passphrase_works(pulsar_env):
	"""When the typed passphrase differs from the lab_pw, the run writes
	approve.key and DONE."""
	env = pulsar_env
	_write_lab_passphrase(env, "labpass")
	install_pulsar(env)
	pp = "prod-pp-9"
	r = env.run("--plain-key", env.plain_key, "pulsar", "approval-key",
	            typed=(pp, pp))
	assert r.rc == 0
	assert r.out.splitlines()[-1] == "DONE approval-key pulsar"
	assert env.router.read("etc/newton/approve.key") == (
		approve_k(pp, "pulsar") + "\n")


def test_approval_pulsar_lab_file_missing_prints_note(pulsar_env):
	"""lab_toml points at a missing file: the NOTE about the rule is
	printed (before the prompt) and the run still works."""
	env = pulsar_env
	missing = env.tmp / "no-such-lab.pw"
	env.lab_toml.write_text(
		"[ssh]\napprove_passphrase_file = \"%s\"\n" % missing)
	install_pulsar(env)
	pp = "anypw-a"
	r = env.run("--plain-key", env.plain_key, "pulsar", "approval-key",
	            typed=(pp, pp))
	assert r.rc == 0
	assert r.out.splitlines()[-1] == "DONE approval-key pulsar"
	note = "NOTE the approval passphrase must differ from the lab passphrase file"
	assert note in r.out.splitlines()
	# NOTE is printed before ``PASS approval key verified``.
	assert r.out.splitlines().index(note) < r.out.splitlines().index(PASS_OK)
	assert env.router.read("etc/newton/approve.key").strip() == (
		approve_k(pp, "pulsar"))


# -- 5. typed-input edge cases ----------------------------------------------

def test_approval_mismatched_confirmation(setup_env):
	"""Two different typed lines: STOPPED differ, no approve.key."""
	env = setup_env
	install_ok(env)
	r = env.run("r1", "approval-key",
	            typed=(GOOD_PW, "alpha", "beta"))
	assert r.rc == 1
	lines = r.out.splitlines()
	assert "NOTE state: router unchanged" in lines
	last = lines[-1]
	assert last.startswith("STOPPED approval-key r1")
	assert "the approval passphrases differ" in last
	assert not has_upload(r.calls)
	assert not env.router.path("etc/newton/approve.key").exists()


def test_approval_empty_passphrase(setup_env):
	"""Two empty typed lines: STOPPED empty, no approve.key."""
	env = setup_env
	install_ok(env)
	r = env.run("r1", "approval-key", typed=(GOOD_PW, "", ""))
	assert r.rc == 1
	lines = r.out.splitlines()
	assert "NOTE state: router unchanged" in lines
	last = lines[-1]
	assert last.startswith("STOPPED approval-key r1")
	assert "the approval passphrase is empty" in last
	assert not has_upload(r.calls)
	assert not env.router.path("etc/newton/approve.key").exists()


# -- 6. --passphrase-file ----------------------------------------------------

def test_approval_passphrase_file_lab(setup_env):
	"""--passphrase-file FILE on the lab device: reads the file (no
	typed passphrase lines), DONE, K matches."""
	env = setup_env
	install_ok(env)
	outside = env.typed_file.parent
	pp_file = outside / "r1.pp"
	pp = "fromfile-pp"
	pp_file.write_text(pp)
	pp_file.chmod(0o600)
	r = env.run("r1", "approval-key", "--passphrase-file", str(pp_file),
	            typed=(GOOD_PW,))
	assert r.rc == 0
	assert r.out.splitlines()[-1] == "DONE approval-key r1"
	assert PASS_OK in r.out.splitlines()
	assert env.router.read("etc/newton/approve.key") == (
		approve_k(pp, "r1") + "\n")


def test_approval_passphrase_file_prod_refused(pulsar_env):
	"""--passphrase-file on the prod device: exit 2, the profile error
	appears and no approve.key is ever written."""
	env = pulsar_env
	install_pulsar(env)
	outside = env.typed_file.parent
	pp_file = outside / "prod.pp"
	pp_file.write_text("anything")
	pp_file.chmod(0o600)
	r = env.run("--plain-key", env.plain_key, "pulsar", "approval-key",
	            "--passphrase-file", str(pp_file))
	assert r.rc == 2
	assert "--passphrase-file is allowed only when the inventory profile is lab" \
		in r.err
	assert not env.router.path("etc/newton/approve.key").exists()


# -- 7. before install ------------------------------------------------------

def test_approval_no_program_exits_install_first(setup_env):
	"""No program on the router: exit 2, ``run install first`` on
	stderr and no approve.key."""
	env = setup_env
	seed_known_hosts(env)
	r = env.run("r1", "approval-key", typed=(GOOD_PW,))
	assert r.rc == 2
	assert "run install first" in r.err
	assert not env.router.path("etc/newton/approve.key").exists()


# -- 8. selftest lies -------------------------------------------------------

def test_approval_selftest_lie_stopped(setup_env):
	"""``etc/newton/fixture-lie`` with ``selftest=<64 hex>``: the router
	answers a wrong HMAC, both selftests disagree and the run ends
	STOPPED, exit 1."""
	env = setup_env
	install_ok(env)
	lie = "0" * 64
	env.router.write("etc/newton/fixture-lie", "selftest=%s\n" % lie)
	r = env.run("r1", "approval-key", typed=(GOOD_PW, "pp", "pp"))
	assert r.rc == 1
	lines = r.out.splitlines()
	assert any("approve.key was written but the selftest failed" in l
	           for l in lines)
	last = lines[-1]
	assert last.startswith("STOPPED approval-key r1")
	assert "approval selftest mismatch" in last


# -- 9. secrets -------------------------------------------------------------

def test_approval_no_secret_leaks(setup_env):
	"""After install + approval-key with the typed passphrase and the
	lab_pw file present, leaks() is empty (the passphrase, the lab
	passphrase and the derived K never appear in output, call argv, or
	any scanned file)."""
	env = setup_env
	pp = "TopSecret-éx"
	labpass = "labpass-z9"
	expected_k = approve_k(pp, "r1")
	env.register_secrets(GOOD_PW, pp, expected_k, labpass)
	_write_lab_passphrase(env, labpass)
	install_ok(env)
	r = env.run("r1", "approval-key", typed=(GOOD_PW, pp, pp))
	assert r.rc == 0
	for call in env.router.calls():
		for arg in call.get("argv", []):
			assert pp not in arg
			assert expected_k not in arg
			assert labpass not in arg
		assert not call.get("leaks")
	assert env.leaks() == []


# -- host-side approval fingerprint --------------------------------------
#
# approve.py reads STATE_DIR/approval-fp/<device> to catch a wrong approval
# passphrase at approve time. setup records the same fingerprint here, on
# both the fresh-write path (after ``PASS approval key verified``) and the
# already-set path (``PASS approval key already set``); on a failed selftest
# nothing is written.


def test_approval_writes_fingerprint_after_verified(setup_env):
	"""After ``PASS approval key verified`` the host-side fingerprint is
	written under state/approval-fp, mode 0600, holding ``v1 <hex>`` of
	HMAC-SHA256(K bytes, ``newton-approval-fingerprint-v1``). K, the
	passphrase and the HMAC never appear in output, call argv or any
	file the leak scan reads."""
	env = setup_env
	pp = "freshwrite-pp"
	expected_k = approve_k(pp, "r1")
	expected_fp = approval_fp(expected_k)
	env.register_secrets(GOOD_PW, pp, expected_k)
	install_ok(env)
	r = env.run("r1", "approval-key", typed=(GOOD_PW, pp, pp))
	assert r.rc == 0
	fp_path = env.fp_path("r1")
	assert fp_path.exists()
	assert (fp_path.stat().st_mode & 0o777) == 0o600
	content = fp_path.read_text()
	assert content == "v1 %s\n" % expected_fp
	text = r.out + r.err
	assert pp not in text
	assert expected_k not in text
	for call in r.calls:
		for arg in call.get("argv", []):
			assert pp not in arg
			assert expected_k not in arg
			assert expected_fp not in arg
	assert env.leaks() == []
	# the parent dir is created mode 0700 under the host umask 077
	fp_dir = env.state_dir / "approval-fp"
	assert (fp_dir.stat().st_mode & 0o777) == 0o700


def test_approval_writes_fingerprint_on_already_set_path(setup_env):
	"""Second run with the same passphrase: ``PASS approval key already
	set`` AND the host-side fingerprint file is written (the operator
	who runs setup once may have been someone other than the operator
	who runs approve)."""
	env = setup_env
	pp = "stable-pp"
	expected_k = approve_k(pp, "r1")
	expected_fp = approval_fp(expected_k)
	env.register_secrets(GOOD_PW, pp, expected_k)
	install_ok(env)
	r1 = env.run("r1", "approval-key", typed=(GOOD_PW, pp, pp))
	assert r1.rc == 0
	fp_path = env.fp_path("r1")
	assert fp_path.exists()
	assert fp_path.read_text() == "v1 %s\n" % expected_fp
	# second run keeps the existing approve.key on the router but
	# writes the fingerprint again (the contents are identical so any
	# re-write is no observable change).
	r2 = env.run("r1", "approval-key", typed=(GOOD_PW, pp, pp))
	assert r2.rc == 0
	assert PASS_ALREADY in r2.out.splitlines()
	assert fp_path.read_text() == "v1 %s\n" % expected_fp
	assert not has_upload(r2.calls)


def test_approval_no_fingerprint_on_failed_selftest(setup_env):
	"""A selftest lie stops the run before approval_key_run's success
	path: the host-side fingerprint is NOT written. approve.py will
	fall back to the missing-file notice on a later run."""
	env = setup_env
	pp = "lying-pp"
	expected_k = approve_k(pp, "r1")
	env.register_secrets(GOOD_PW, pp, expected_k)
	install_ok(env)
	lie = "0" * 64
	env.router.write("etc/newton/fixture-lie", "selftest=%s\n" % lie)
	r = env.run("r1", "approval-key", typed=(GOOD_PW, pp, pp))
	assert r.rc == 1
	lines = r.out.splitlines()
	assert any("approve.key was written but the selftest failed" in l
	           for l in lines)
	last = lines[-1]
	assert last.startswith("STOPPED approval-key r1")
	assert "approval selftest mismatch" in last
	assert not env.fp_path("r1").exists()
	# K is the same one approve.py would derive; the file just must not
	# exist (a wrong fingerprint would mislead the approve check).
	expected_fp = approval_fp(expected_k)
	assert not (env.state_dir / "approval-fp").joinpath("r1").exists() \
		or env.fp_path("r1").read_text() != "v1 %s\n" % expected_fp


def test_approval_no_fingerprint_on_mismatched_passphrase(setup_env):
	"""A mismatched typed confirmation stops before the key is ever
	confirmed: the host-side fingerprint is NOT written."""
	env = setup_env
	pp = "alpha"
	pp2 = "beta"
	env.register_secrets(GOOD_PW, pp, pp2)
	install_ok(env)
	r = env.run("r1", "approval-key", typed=(GOOD_PW, pp, pp2))
	assert r.rc == 1
	lines = r.out.splitlines()
	assert "NOTE state: router unchanged" in lines
	last = lines[-1]
	assert last.startswith("STOPPED approval-key r1")
	assert "the approval passphrases differ" in last
	assert not has_upload(r.calls)
	assert not env.fp_path("r1").exists()


# -- R8 (a-2): host-side approval fingerprint write failure ------------------
#
# When approval_fingerprint_write fails AFTER the router-side K has been
# verified, the OLD host-side fingerprint must NOT stay behind -- a stale
# fingerprint would cause approve.py to refuse the (correct) new
# passphrase as "wrong" (it would compare the new K's fingerprint against
# the old fingerprint recorded under the previous passphrase).
#
# The fix removes the old fingerprint file BEFORE writing the new one, so
# a failed write leaves it missing (which approve.py treats as the soft
# 'could not check' state, not a refusal).


def _fail_python3_dir(env, real_python):
	"""Build a private bin dir that contains the setup env's existing
	fakes plus a python3 wrapper that fails ONLY when called for the
	fingerprint write (K_FOR_FP set, argv[1] is '-'); the wrapper reads
	the tool's heredoc, injects an os.replace failure AFTER
	``import tempfile``, and runs the modified script so the new
	fingerprint write fails inside the python body (between the unlink
	of the old fp and the replace with the new one).  Every other
	python3 call (derive_k, selftest_hmac, load_inventory, ...) falls
	through to the real interpreter.  Returns the directory path."""
	fail_bin = env.tmp / "fail_python3_bin"
	if fail_bin.exists():
		shutil.rmtree(fail_bin)
	fail_bin.mkdir()
	for f in env.fakes.iterdir():
		shutil.copy(f, fail_bin / f.name)
	wrapper = fail_bin / "python3"
	wrapper.write_text(
		'#!/bin/sh\n'
		'if [ -n "$K_FOR_FP" ] && [ "$1" = "-" ]; then\n'
		'    TOOL_SCRIPT=$(cat)\n'
		'    MODIFIED=$(printf \'%%s\' "$TOOL_SCRIPT" | "%s" -c \'\n'
		'import sys\n'
		'script = sys.stdin.read()\n'
		'inject = """\n'
		'import os as _inj_os\n'
		'_real_replace = _inj_os.replace\n'
		'def _fail_replace(*a, **kw):\n'
		'    raise OSError("injected: replace failed")\n'
		'_inj_os.replace = _fail_replace\n'
		'"""\n'
		'modified = script.replace(\n'
		'    "import tempfile", "import tempfile\\n" + inject, 1)\n'
		'print(modified, end="")\n'
		'\')\n'
		'    printf \'%%s\' "$MODIFIED" | "%s" - "$2"\n'
		'    exit $?\n'
		'fi\n'
		'exec "%s" "$@"\n' % (real_python, real_python, real_python)
	)
	wrapper.chmod(0o755)
	return fail_bin


def test_approval_fingerprint_write_failure_removes_old_fingerprint(
	setup_env,
):
	"""R8 (a-2): the second run hits approval_fingerprint_write with a
	failing python3; the OLD fingerprint (from the first run) must NOT
	stay behind, otherwise approve.py would compare the new passphrase's
	fingerprint against the OLD one and refuse it as wrong.  The fix
	unlinks the old file BEFORE writing the new one, so the second run
	leaves an empty fp dir and prints the existing NOTE."""
	env = setup_env
	pp = "fp-rotate-pp"
	expected_k = approve_k(pp, "r1")
	expected_fp = approval_fp(expected_k)
	env.register_secrets(GOOD_PW, pp, expected_k)
	install_ok(env)
	# First run: fingerprint is written and matches K.
	r1 = env.run("r1", "approval-key", typed=(GOOD_PW, pp, pp))
	assert r1.rc == 0
	fp_path = env.fp_path("r1")
	assert fp_path.exists()
	assert fp_path.read_text() == "v1 %s\n" % expected_fp
	# Inject the failing wrapper before the second run.  The setup
	# tool rebuilds PATH inside init() from FIXED_PATH, optionally with
	# NEWTON_SETUP_BIN prepended -- override NEWTON_SETUP_BIN so the
	# wrapper wins the lookup before FIXED_PATH's /usr/bin/python3.
	real_python = shutil.which("python3")
	fail_bin = _fail_python3_dir(env, real_python)
	# Second run with the SAME passphrase: the selftest still matches
	# (same K), so approval_fingerprint_write is reached and our wrapper
	# makes it fail.  The NOTE is non-fatal so the run still returns 0.
	r2 = env.run("r1", "approval-key", typed=(GOOD_PW, pp, pp),
	             env={"NEWTON_SETUP_BIN": str(fail_bin)})
	assert r2.rc == 0
	assert "could not record the approval fingerprint for r1" in r2.out
	# The OLD fingerprint file is gone (with the OLD code it would
	# still hold expected_fp and that is the bug we are fixing).
	assert not fp_path.exists()
	# No partial fp file in the fp dir either.
	fp_dir = env.state_dir / "approval-fp"
	assert sorted(p.name for p in fp_dir.iterdir()) == []


def test_approval_fingerprint_write_success_keeps_new_fingerprint(setup_env):
	"""R8 (a-2) regression: with the fix in place (unlink-before-write),
	a successful re-write leaves exactly the new fingerprint and nothing
	else in the fp dir.  Same shape as the existing
	test_approval_writes_fingerprint_on_already_set_path but pinned
	here so a future regression that re-introduces a partial file
	breaks loudly."""
	env = setup_env
	pp = "rotate-success-pp"
	expected_k = approve_k(pp, "r1")
	expected_fp = approval_fp(expected_k)
	env.register_secrets(GOOD_PW, pp, expected_k)
	install_ok(env)
	r1 = env.run("r1", "approval-key", typed=(GOOD_PW, pp, pp))
	assert r1.rc == 0
	fp_path = env.fp_path("r1")
	assert fp_path.exists()
	assert fp_path.read_text() == "v1 %s\n" % expected_fp
	# Second run with the same passphrase: idempotent re-write, no
	# wrapper, selftest passes, fp is rewritten and matches.
	r2 = env.run("r1", "approval-key", typed=(GOOD_PW, pp, pp))
	assert r2.rc == 0
	assert PASS_ALREADY in r2.out.splitlines()
	assert fp_path.exists()
	assert fp_path.read_text() == "v1 %s\n" % expected_fp
	fp_dir = env.state_dir / "approval-fp"
	assert sorted(p.name for p in fp_dir.iterdir()) == ["r1"]


def test_approval_refuses_group_writable_state_dir(setup_env):
	"""SW2 item 4: approval-fp is not written when the state dir (its
	PARENT) is group- or world-writable without the sticky bit.

	The fingerprint write is best effort by contract, so the tool keeps
	its PASS lines and adds a NOTE naming the refusal; what matters is
	that nothing is laid down under a parent any local user can write to.
	"""
	env = setup_env
	install_ok(env)
	os.chmod(env.state_dir, 0o777)
	try:
		r = env.run("r1", "approval-key", typed=(GOOD_PW, "groupwrite-pp",
		                                          "groupwrite-pp"))
	finally:
		os.chmod(env.state_dir, 0o700)
	assert PASS_OK in r.out.splitlines(), r.out + r.err
	assert "could not record the approval fingerprint" in r.out + r.err
	assert "group- or world-writable without the sticky bit" in r.err
	assert not (env.state_dir / "approval-fp").exists()


# -- the offer of the authenticator app --------------------------------
#
# The passphrase stays the proof of the owner; the authenticator app is
# OFFERED right after the passphrase was chosen.  The
# offer never changes the passphrase and never runs the enrolment
# without an explicit yes.

OFFER_LINES = (
	"INFO optional: an authenticator app can replace this passphrase in "
	"Newton's approval dialog",
	"INFO it shows a 6-digit code that changes every 30 seconds, so a code "
	"someone sees is useless a minute later",
	"INFO the passphrase stays in use unless you set this up; to do it "
	"later run: sudo -u newton /usr/local/bin/newton-enrol totp r1",
)
ALREADY_LINE = "INFO an authenticator app is already set up for r1"
PROMPT_TEXT = "Set up an authenticator app now? [y/N] "


def write_fake_enrol(env, exit_code=0):
	"""A fake ``$SRC/venv/bin/newton-enrol`` in the source tree (the
	tool looks for the enrolment program there): it records its argv in
	a log file and exits with ``exit_code``.  The tool runs it with an
	argv list, so the log holds the argv and nothing else.  Returns the
	log path."""
	bindir = env.src / "venv" / "bin"
	bindir.mkdir(parents=True, exist_ok=True)
	log = env.tmp / "enrol-argv.log"
	script = bindir / "newton-enrol"
	script.write_text(
		"#!/bin/sh\n"
		"printf '%%s\\n' \"$*\" >> %s\n"
		"exit %d\n" % (shlex.quote(str(log)), exit_code))
	script.chmod(0o755)
	return log


def test_approval_offers_the_authenticator_and_asks(setup_env):
	"""The offer follows the passphrase: the three INFO lines, the
	question on stderr and no enrolment (no answer was typed, so the
	answer is empty and the run must not die).  The run ends in
	``DONE approval-key r1``."""
	env = setup_env
	install_ok(env)
	log = write_fake_enrol(env)
	r = env.run("r1", "approval-key", typed=(GOOD_PW, "offer-pp", "offer-pp"))
	assert r.rc == 0, r.out + r.err
	lines = r.out.splitlines()
	for line in OFFER_LINES:
		assert line in lines, r.out
	assert PROMPT_TEXT in r.err, r.err
	assert not log.exists()
	assert lines[-1] == "DONE approval-key r1"


def test_approval_enrols_the_authenticator_when_accepted(setup_env):
	"""A typed ``y`` runs the enrolment with the argv ``totp r1`` and
	reports ``PASS authenticator set up``; the run ends in DONE."""
	env = setup_env
	install_ok(env)
	log = write_fake_enrol(env, exit_code=0)
	r = env.run("r1", "approval-key",
	            typed=(GOOD_PW, "offer-pp", "offer-pp", "y"))
	assert r.rc == 0, r.out + r.err
	assert log.read_text().splitlines() == ["totp r1"]
	assert "PASS authenticator set up" in r.out.splitlines(), r.out
	assert r.out.splitlines()[-1] == "DONE approval-key r1"


def test_approval_says_so_when_the_enrolment_fails(setup_env):
	"""A failing enrolment keeps the passphrase in use: the NOTE line,
	DONE and exit 0."""
	env = setup_env
	install_ok(env)
	log = write_fake_enrol(env, exit_code=1)
	r = env.run("r1", "approval-key",
	            typed=(GOOD_PW, "offer-pp", "offer-pp", "y"))
	assert r.rc == 0, r.out + r.err
	assert log.read_text().splitlines() == ["totp r1"]
	assert ("NOTE authenticator not set up; the passphrase stays in use"
	        in r.out.splitlines()), r.out
	assert "PASS authenticator set up" not in r.out
	assert r.out.splitlines()[-1] == "DONE approval-key r1"


def test_approval_does_not_enrol_when_the_answer_is_no(setup_env):
	"""A typed ``n`` ends the offer: no enrolment, no PASS, no NOTE."""
	env = setup_env
	install_ok(env)
	log = write_fake_enrol(env)
	r = env.run("r1", "approval-key",
	            typed=(GOOD_PW, "offer-pp", "offer-pp", "n"))
	assert r.rc == 0, r.out + r.err
	assert not log.exists()
	assert "PASS authenticator set up" not in r.out
	assert "NOTE authenticator not set up" not in r.out
	assert r.out.splitlines()[-1] == "DONE approval-key r1"


def test_approval_offers_without_asking_when_the_program_is_missing(setup_env):
	"""No enrolment program in the install tree: the offer is shown, but
	there is nothing to run, so there is no question and no enrolment
	(even when the answer would have been yes)."""
	env = setup_env
	install_ok(env)
	r = env.run("r1", "approval-key",
	            typed=(GOOD_PW, "offer-pp", "offer-pp", "y"))
	assert r.rc == 0, r.out + r.err
	lines = r.out.splitlines()
	for line in OFFER_LINES:
		assert line in lines, r.out
	assert PROMPT_TEXT not in r.err, r.err
	assert lines[-1] == "DONE approval-key r1"


def test_approval_with_a_passphrase_file_offers_nothing(setup_env):
	"""A passphrase from a file is not the owner's own typing: the
	offer is skipped entirely."""
	env = setup_env
	install_ok(env)
	log = write_fake_enrol(env)
	outside = env.typed_file.parent
	pp_file = outside / "r1.pp"
	pp_file.write_text("fromfile-pp")
	pp_file.chmod(0o600)
	r = env.run("r1", "approval-key", "--passphrase-file", str(pp_file),
	            typed=(GOOD_PW,))
	assert r.rc == 0, r.out + r.err
	assert not any(line.startswith("INFO ") for line in r.out.splitlines()), r.out
	assert PROMPT_TEXT not in r.err, r.err
	assert not log.exists()
	assert r.out.splitlines()[-1] == "DONE approval-key r1"


def test_approval_skips_the_offer_when_the_environment_says_so(setup_env):
	"""NEWTON_SKIP_TOTP_OFFER=1 (newton-enrol rotate sets it, because
	the rotation throws the TOTP record away a second later): the offer
	is skipped entirely."""
	env = setup_env
	install_ok(env)
	log = write_fake_enrol(env)
	r = env.run("r1", "approval-key", typed=(GOOD_PW, "offer-pp", "offer-pp"),
	            env={"NEWTON_SKIP_TOTP_OFFER": "1"})
	assert r.rc == 0, r.out + r.err
	assert not any(line.startswith("INFO ") for line in r.out.splitlines()), r.out
	assert PROMPT_TEXT not in r.err, r.err
	assert not log.exists()
	assert r.out.splitlines()[-1] == "DONE approval-key r1"


def test_approval_says_the_authenticator_is_already_set_up(setup_env):
	"""levels/r1 reads ``totp`` and the passphrase did not change (the
	key was already set): the device already asks for a 6-digit code, so
	the offer is one line and there is no question."""
	env = setup_env
	install_ok(env)
	log = write_fake_enrol(env)
	first = env.run("r1", "approval-key", typed=(GOOD_PW, "offer-pp", "offer-pp"))
	assert first.rc == 0, first.out + first.err
	levels = env.state_dir / "levels"
	levels.mkdir(parents=True, exist_ok=True)
	(levels / "r1").write_text("totp\n")
	r = env.run("r1", "approval-key", typed=(GOOD_PW, "offer-pp", "offer-pp"))
	assert r.rc == 0, r.out + r.err
	lines = r.out.splitlines()
	assert ALREADY_LINE in lines, r.out
	for line in OFFER_LINES:
		assert line not in lines, r.out
	assert PROMPT_TEXT not in r.err, r.err
	assert not log.exists()
	assert lines[-1] == "DONE approval-key r1"


def test_approval_offer_keeps_the_passphrase_secret(setup_env):
	"""The passphrase never reaches the enrolment program: the recorded
	argv holds ``totp r1`` only, and the leak scan is empty."""
	env = setup_env
	pp = "offer-secret-pp"
	expected_k = approve_k(pp, "r1")
	env.register_secrets(GOOD_PW, pp, expected_k)
	install_ok(env)
	log = write_fake_enrol(env)
	r = env.run("r1", "approval-key", typed=(GOOD_PW, pp, pp, "y"))
	assert r.rc == 0, r.out + r.err
	recorded = log.read_text()
	assert recorded.strip() == "totp r1"
	assert pp not in recorded
	assert expected_k not in recorded
	assert pp not in r.out + r.err
	assert env.leaks() == []


STALE_LINE = ("INFO the authenticator app for r1 was set up with the old "
              "passphrase and no longer works; set it up again")


def test_approval_new_passphrase_with_an_authenticator_offers_it_again(setup_env):
	"""levels/r1 reads ``totp`` but this run wrote a NEW key: the TOTP
	record still holds the old one, so the run says the app no longer
	works and asks again (a yes runs the enrolment)."""
	env = setup_env
	install_ok(env)
	log = write_fake_enrol(env)
	levels = env.state_dir / "levels"
	levels.mkdir(parents=True, exist_ok=True)
	(levels / "r1").write_text("totp\n")
	r = env.run("r1", "approval-key",
	            typed=(GOOD_PW, "new-pp", "new-pp", "y"))
	assert r.rc == 0, r.out + r.err
	lines = r.out.splitlines()
	assert STALE_LINE in lines, r.out
	assert ALREADY_LINE not in lines, r.out
	assert PROMPT_TEXT in r.err, r.err
	assert log.read_text().splitlines() == ["totp r1"]
	assert lines[-1] == "DONE approval-key r1"
