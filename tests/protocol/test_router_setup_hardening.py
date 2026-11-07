"""Hardening tests for the F3, F4 and F5 repairs in
scripts/newton-router-setup:

  - F3: the key matcher must skip comment lines like the key filter does.
    Tests the swap-key success path with a commented-out copy of the plain
    key blob, the auth_has_blob / auth_remove_blob helpers (against a
    router_unit with the plain-key admin path), and the swap-key step-5
    guard against the mutant that drops the `[ "$old" = 0 ]` check.

  - F4: put_stream must not leave a .new file behind when the upload
    call, the sha or the final mv call failed.  Tests a new harness knob
    `die_after_commands` (the command runs to the end, then the link
    drops), the install and approval-key happy paths and the final-mv
    failure of approval-key.

  - F5: approval-key must not send a K that is not 64 hex.  Tests a
    python3 shim that exits 1 on the PBKDF2 call, with the live
    approve.key on the router unchanged.
"""

import os
import re
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from router_setup_env import setup_env, pulsar_env  # noqa: F401
from test_router_setup_harness import rig, DEST  # noqa: F401
from test_router_setup_install import (  # noqa: E402
	seed_known_hosts, install_ok,
)
from test_router_setup_units import (  # noqa: E402,F401
	router_unit, _install_code_files, PLAIN_BLOB,
)


# -- shared helpers for the F3 swap-key test --------------------------------

# the format of a real key blob (the fake ssh-keygen makes the same shape)
EXTRA = "ssh-ed25519 AAAAEXTRAKEYFORSWAPTESTS0001 agent-laptop"


def install_pulsar(env):
	"""Seed known_hosts and install pulsar via the plain-key admin path."""
	seed_known_hosts(env)
	r = env.run("--plain-key", env.plain_key, "pulsar", "install",
	            typed=("yes",))
	assert r.rc == 0, r.out
	return r


def swap(env, *extra):
	return env.run("--plain-key", env.plain_key, "pulsar", "swap-key", *extra)


def pulsar_blob(env, label="newton-agent"):
	"""The blob of the restricted line the swap-key run wrote."""
	pub = env.keys_dir / ("pulsar-%s.pub" % label)
	return pub.read_text().strip().split()[1]


# ===========================================================================
# the key matcher must skip comment lines like the key filter does
# ===========================================================================


def test_swap_key_succeeds_with_a_commented_copy_of_the_plain_key(pulsar_env):
	"""A commented-out copy of the plain key blob (e.g. ``# ssh-ed25519
	<blob> old-copy-of-plain``) in authorized_keys must not stop
	swap-key: the match program has to ignore the comment line, the
	filter program has to keep it byte for byte, and the swap must
	finish DONE."""
	env = pulsar_env
	install_pulsar(env)
	# the plain key (the unrestricted line Newton will revoke) blob
	plain_pub = env.plain_key.with_suffix(".pub")
	plain_blob = plain_pub.read_text().strip().split()[1]
	# a comment that carries the same blob (the F3 regression) and one
	# unrelated extra key line that must survive verbatim
	comment_line = "# ssh-ed25519 %s old-copy-of-plain" % plain_blob
	env.router.add_authorized_key(comment_line)
	env.router.add_authorized_key(EXTRA)
	r = swap(env, "--new-key")
	assert r.rc == 0, r.out + r.err
	last = r.out.splitlines()[-1]
	assert last == "DONE swap-key pulsar", last
	ak = env.router.authorized_keys()
	# the comment line still in authorized_keys, byte for byte
	assert comment_line in ak
	assert EXTRA in ak
	# NO NON-comment line may hold the plain blob
	for line in ak:
		if line.lstrip().startswith("#"):
			continue
		assert plain_blob not in line, line
	# exactly one restricted line for newton-agent
	new_blob = pulsar_blob(env)
	expected = (
		"restrict,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,"
		"no-pty,command=\"/usr/libexec/newton/newton-router"
		" --caller=newton-agent --role=change\""
		" ssh-ed25519 %s newton-router-newton-agent" % new_blob
	)
	restricted = [l for l in ak if not l.lstrip().startswith("#")
	              and "newton-router-newton-agent" in l and new_blob in l]
	assert len(restricted) == 1, restricted
	assert restricted[0] == expected
	# no leftover .new
	leftovers = list((env.router.root / "fs").rglob("*.new"))
	assert leftovers == [], leftovers


def test_auth_has_blob_and_remove_blob_ignore_comment_lines(router_unit):
	"""The auth_has_blob and auth_remove_blob helpers must not be fooled
	by a commented-out copy of the blob (otherwise
	swap_replace_key_lines would think the old key still works)."""
	router = router_unit.router
	# the router_unit fixture pre-installs the plain key line with
	# PLAIN_BLOB; keep it so the ssh auth lane keeps working, and add a
	# BOGUS blob in a comment, then a real one to remove.
	rel = "etc/dropbear/authorized_keys"
	bogus_blob = "AAAAC3NzaC1lZDI1NTE5AAAAIHARDENINGCOMMENTEDKEY0001"
	real_blob = "AAAAC3NzaC1lZDI1NTE5AAAAIHARDENINGREALKEY00000001"
	plain_line = "ssh-ed25519 %s agent@unit" % PLAIN_BLOB

	# 1. ONLY the plain line and a commented-out copy of bogus_blob --
	# auth_has_blob BOGUS must exit 1 (the comment line is ignored)
	router.write(rel,
		"%s\n# ssh-ed25519 %s note\n" % (plain_line, bogus_blob))
	r = router_unit.run(
		"auth_has_blob %s; echo rc=$?\n" % bogus_blob)
	assert r.returncode == 0, r.stderr
	lines = r.stdout.splitlines()
	assert lines == ["rc=1"], lines

	# 2. add a REAL line with the real blob -- auth_has_blob exits 0
	router.write(rel,
		"%s\n# ssh-ed25519 %s note\n"
		"ssh-ed25519 %s real\n"
		% (plain_line, bogus_blob, real_blob))
	r2 = router_unit.run(
		"auth_has_blob %s; echo rc=$?\n" % real_blob)
	assert r2.returncode == 0, r2.stderr
	assert r2.stdout.splitlines() == ["rc=0"], r2.stdout

	# 3. auth_remove_blob prints 1 (count of removed lines), the comment
	#    line is still there byte for byte, the real line is gone,
	#    the plain line is still there.
	r3 = router_unit.run(
		"auth_remove_blob %s\n" % real_blob)
	assert r3.returncode == 0, r3.stderr
	# auth_remove_blob prints the grep -c count on its own line
	assert r3.stdout.splitlines()[0] == "1", r3.stdout
	after = router.read(rel)
	assert plain_line + "\n" in after
	assert "# ssh-ed25519 %s note\n" % bogus_blob in after
	assert "ssh-ed25519 %s real" % real_blob not in after


def test_swap_step5_fails_when_the_awk_filter_leaves_the_old_key(pulsar_env):
	"""Kills the mutant that deletes the `[ "$old" = 0 ]` clause of
	swap_replace_key_lines: that clause is the only thing that stops the
	replace when the awk filter did not remove the old key.  A wrapper
	`awk` first on the router's PATH makes the filter program copy its
	input unchanged, so the .new file still holds the plain key.  The tool
	must report the failed replace, keep the live file as it was and end in
	STOPPED (the old key still works).  (the rig's
	version ran the mutant inside the test.)"""
	env = pulsar_env
	install_pulsar(env)
	env.router.add_authorized_key(EXTRA)
	wrapper = env.router.root / "bin" / "awk"
	wrapper.write_text(
		"#!/bin/sh\n"
		"# test wrapper: the key FILTER program (its text contains\n"
		"# 'b == \"\" || b != blob') copies its input file unchanged;\n"
		"# every other awk call is the real awk\n"
		"case \"$*\" in\n"
		"\t*'b == \"\" || b != blob'*)\n"
		"\t\tfor last; do :; done\n"
		"\t\tcat \"$last\"\n"
		"\t\texit 0\n"
		"\t\t;;\n"
		"esac\n"
		"exec /usr/bin/busybox awk \"$@\"\n")
	wrapper.chmod(0o755)
	plain_blob = env.plain_key.with_suffix(".pub").read_text().split()[1]
	r = swap(env, "--new-key")
	assert r.rc == 1, r.out + r.err
	lines = r.out.splitlines()
	assert "INFO swap step 5: authorized_keys replace failed" in lines, r.out
	assert "INFO swap step 5: authorized_keys replaced" not in lines, r.out
	assert lines[-1] == "STOPPED swap-key pulsar: the old key still works", r.out
	ak = env.router.read("etc/dropbear/authorized_keys")
	assert plain_blob in ak
	assert EXTRA in ak
	assert list((env.router.root / "fs").rglob("*.new")) == []


# ===========================================================================
# put_stream must not leave a .new file behind
# ===========================================================================


def test_die_after_commands_knob_runs_the_command_then_drops_the_link(rig):
	"""The new state knob ``die_after_commands``: a router command that
	contains one of the listed substrings is RUN to the end (its effects
	are present) and then the fake ssh prints ``Connection closed by
	remote host.`` on stderr and exits 255, marking ``died_after``.
	A command that does not contain the substring behaves normally."""
	# add a plain key for the ssh lane
	key, blob = rig.key("diek")
	rig.router.add_authorized_key("ssh-ed25519 %s agent-laptop" % blob)
	# marker file path -- $FAKE_ROUTER_FS is the on-disk router fs
	marker_subpath = "tmp/died-marker"
	marker_fs = rig.router.path(marker_subpath)
	assert not marker_fs.exists()
	rig.router.update_state(die_after_commands=["touch-marker-text"])
	# a command containing the substring: runs (marker appears) then drops
	proc = rig.ssh(
		rig.key_args(key) +
		[DEST,
		 "echo touch-marker-text && "
		 "touch \"$FAKE_ROUTER_FS/%s\" && "
		 "ls \"$FAKE_ROUTER_FS/%s\"" % (marker_subpath, marker_subpath)])
	assert proc.returncode == 255
	assert b"Connection closed" in proc.stderr
	assert marker_fs.exists()
	call = rig.last_call()
	assert call.get("died_after") is True
	# a command without the substring is normal
	other = rig.router.path("tmp/other-marker")
	proc2 = rig.ssh(
		rig.key_args(key) +
		[DEST,
		 "touch \"$FAKE_ROUTER_FS/tmp/other-marker\""])
	assert proc2.returncode == 0
	assert other.exists()


def test_install_leaves_no_new_file_when_the_upload_call_dies(setup_env):
	"""Install with the upload call sent through the die_after_commands
	``cat > `` path: the tool short-circuits, NO ``*.new`` file is left
	behind under the router fs."""
	env = setup_env
	seed_known_hosts(env)
	env.router.update_state(die_after_commands=["cat > "])
	r = env.run(env.device, "install", typed=(
		env.router.state()["root_password"], "yes"))
	assert r.rc != 0, r.out
	assert r.out.splitlines()[-1].startswith("STOPPED install"), r.out
	leftovers = list((env.router.root / "fs").rglob("*.new"))
	assert leftovers == [], leftovers


def test_approval_key_leaves_no_new_file_when_the_upload_call_dies(setup_env):
	"""approval-key with the die_after_commands knob set to ``cat > ``:
	the upload call dies after the file is created, the cleanup runs
	normally (no ``cat > `` in it), and no ``approve.key.new`` or
	``approve.key`` is left behind."""
	env = setup_env
	install_ok(env)
	env.router.update_state(die_after_commands=["cat > "])
	r = env.run(env.device, "approval-key",
	            typed=(env.router.state()["root_password"],
	                   "its-a-pass", "its-a-pass"))
	assert r.rc != 0, r.out
	lines = r.out.splitlines()
	last = lines[-1]
	assert last.startswith("STOPPED approval-key r1: cannot write "
	                       "approve.key"), last
	# the NOTE state: router unchanged just before STOPPED
	note_idx = next(i for i, l in enumerate(lines)
	                if l.startswith("NOTE state:"))
	assert note_idx == len(lines) - 2
	assert lines[-2] == "NOTE state: router unchanged", lines
	# no .new file and no approve.key
	fs = env.router.root / "fs"
	assert not (fs / "etc/newton/approve.key.new").exists()
	assert not (fs / "etc/newton/approve.key").exists()


def test_failed_final_mv_leaves_no_new_file(setup_env):
	"""Knob ``drop_commands=['mv "']`` (an existing knob): a router
	command containing it is not run; the approval-key run uses that
	mv, so the cleanup ``rm -f ...`` runs normally (it does not contain
	the substring) and no approve.key.new is left."""
	env = setup_env
	install_ok(env)
	env.router.update_state(drop_commands=['mv "'])
	r = env.run(env.device, "approval-key",
	            typed=(env.router.state()["root_password"],
	                   "its-a-pass", "its-a-pass"))
	assert r.rc != 0, r.out
	fs = env.router.root / "fs"
	assert not (fs / "etc/newton/approve.key.new").exists()


# ===========================================================================
# approval-key must not send a K that is not 64 hex
# ===========================================================================


def test_approval_key_keeps_the_old_key_when_k_cannot_be_derived(setup_env):
	"""A python3 shim that exits 1 on the PBKDF2 call: the tool refuses
	to send a bad K, the live approve.key has the same sha256 as before,
	no ssh call of this run contains ``cat > `` or ``approval-selftest``,
	the leak scan is empty, rc=2, stderr mentions the failure."""
	env = setup_env
	install_ok(env)
	# first approval-key run with a clean K: establish the good state
	pp = "another-pass"
	good = env.run(env.device, "approval-key",
	               typed=(env.router.state()["root_password"], pp, pp))
	assert good.rc == 0, good.out
	old_key = env.router.read("etc/newton/approve.key")
	import hashlib as _h
	old_sha = _h.sha256(old_key.encode()).hexdigest()

	# install a python3 shim that fails PBKDF2
	real_py = shutil.which("python3")
	assert real_py is not None, "python3 must be on PATH for this test"
	shim = env.fakes / "python3"
	shim.write_text(
		"#!/bin/sh\n"
		"case \"$*\" in *pbkdf2_hmac*) exit 1 ;; esac\n"
		"exec %s \"$@\"\n" % real_py)
	shim.chmod(0o755)

	# second run with the same passphrase: must refuse, exit 2
	bad = env.run(env.device, "approval-key",
	              typed=(env.router.state()["root_password"], pp, pp))
	assert bad.rc == 2, (bad.out, bad.err)
	assert "cannot derive the approval key" in bad.err, bad.err
	# the live approve.key has the SAME sha256
	new_sha = _h.sha256(
		env.router.read("etc/newton/approve.key").encode()).hexdigest()
	assert new_sha == old_sha, (old_sha, new_sha)
	# no ssh call of this run contains ``cat > `` or ``approval-selftest``
	for call in bad.calls:
		if call.get("tool") != "ssh":
			continue
		assert "cat > " not in (call.get("command") or ""), call
		assert "approval-selftest" not in (call.get("command") or ""), call
	# env.leaks() empty
	assert env.leaks() == [], env.leaks()
