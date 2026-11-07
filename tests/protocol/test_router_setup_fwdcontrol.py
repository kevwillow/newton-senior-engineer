"""Tests of the forwarding proof's positive control and closed-target
behaviour of scripts/newton-router-setup: the harness knob
`closed_targets` (list of "host:port" strings the fake router's own
network cannot connect to) and the tool's new positive-control proof.

The proof runs a real -L and -D through the admin path first; the
control must get an SSH banner, or the proof FAILS, because a blocked
forward cannot be told from a closed target otherwise.
"""

import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from router_setup_env import setup_env, pulsar_env  # noqa: F401
from router_setup_harness import (  # noqa: E402
    DEFAULT_STATE, install_fakes)
from test_router_setup_harness import (  # noqa: E402
    rig, free_port, wait_listener, reap, forward_args)
from test_router_setup_harness import HOST, DEST  # noqa: E402

GOOD_PW = DEFAULT_STATE["root_password"]


def _nc_socks_to(port, dest_host, dest_port, timeout=10):
	"""Like test_router_setup_harness._nc_socks but with a configurable
	SOCKS5 CONNECT destination."""
	return subprocess.run(
		["nc", "-X", "5", "-x", "127.0.0.1:%d" % port,
		 dest_host, str(dest_port)],
		capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL)


def _parse_ssh(argv):
	"""Re-export the test_router_setup_keys parser, used to read the
	tool's ssh argv (vals / flags / oopts / rest)."""
	from test_router_setup_keys import parse_ssh  # noqa: WPS433
	return parse_ssh(argv)


def _first_key_calls_with(result, kind_flag):
	"""The first ssh call in result.calls with -N and `kind_flag`
	(in -L / -D / -R) in argv."""
	for c in result.calls:
		if c.get("tool") != "ssh":
			continue
		argv = c["argv"]
		if "-N" not in argv or kind_flag not in argv:
			continue
		return c
	return None


def _forwarding_calls(result):
	"""All ssh calls of result.calls whose argv contains -N."""
	out = []
	for c in result.calls:
		if c.get("tool") == "ssh" and "-N" in c["argv"]:
			out.append(c)
	return out


def _install_pulsar(env):
	from test_router_setup_swap import install_pulsar  # noqa: WPS433
	install_pulsar(env)


def _swap(env):
	from test_router_setup_swap import swap  # noqa: WPS433
	return swap(env, "--new-key")


# ---------------------------------------------------------------------------
# Harness self-tests (use the `rig` fixture directly; unrestricted key)
# ---------------------------------------------------------------------------

def test_L_to_a_closed_target_gets_no_banner_and_an_open_one_does(rig):
	"""The rig's fake ssh gives the banner when the forward is allowed
	and the target host:port is not in `closed_targets`; when the target
	is named in `closed_targets` the connection is accepted at once and
	closed with no byte."""
	key, blob = rig.key("fwd1")
	rig.router.add_authorized_key("ssh-ed25519 %s plain" % blob)
	rig.router.update_state(closed_targets=["127.0.0.1:22"])

	port = free_port()
	proc = rig.start(forward_args(rig.key_args(key),
								  "-L", "127.0.0.1:%d:127.0.0.1:22" % port))
	try:
		conn = wait_listener(port)
		conn.settimeout(5)
		assert conn.recv(64) == b""
		conn.close()
	finally:
		reap(proc)

	port = free_port()
	proc = rig.start(forward_args(rig.key_args(key),
								  "-L", "127.0.0.1:%d:10.1.2.3:22" % port))
	try:
		conn = wait_listener(port)
		conn.settimeout(5)
		assert conn.recv(64) == b"SSH-2.0-FAKE\r\n"
		conn.close()
	finally:
		reap(proc)


def test_D_to_a_closed_target_gets_no_banner_and_an_open_one_does(rig):
	"""Same for -D: a SOCKS5 CONNECT to a destination in `closed_targets`
	gets SOCKS5 code 5 (connection refused), no banner; an open target
	gets code 0 and the banner."""
	key, blob = rig.key("fwd2")
	rig.router.add_authorized_key("ssh-ed25519 %s plain" % blob)
	rig.router.update_state(closed_targets=["127.0.0.1:22"])

	port = free_port()
	proc = rig.start(forward_args(rig.key_args(key),
								  "-D", "127.0.0.1:%d" % port))
	try:
		wait_listener(port).close()
		out = _nc_socks_to(port, "127.0.0.1", 22).stdout
		assert b"SSH-" not in out
	finally:
		reap(proc)

	port = free_port()
	proc = rig.start(forward_args(rig.key_args(key),
								  "-D", "127.0.0.1:%d" % port))
	try:
		wait_listener(port).close()
		out = _nc_socks_to(port, "10.1.2.3", 22).stdout
		assert b"SSH-2.0-FAKE" in out
	finally:
		reap(proc)


# ---------------------------------------------------------------------------
# End-to-end tests (run the tool)
# ---------------------------------------------------------------------------

def test_the_control_runs_through_the_admin_lane_before_the_restricted_key(pulsar_env):
	"""pulsar / swap-key: among the calls with `-N`, the first -L and -D
	logged calls use the plain key (-i <env.plain_key>); the next calls
	in each set use the new restricted key; both -L specs end with
	`:127.0.0.1:22`; the run ends `DONE swap-key pulsar`."""
	env = pulsar_env
	_install_pulsar(env)
	r = _swap(env)
	assert r.rc == 0, r.out
	assert r.out.splitlines()[-1] == "DONE swap-key pulsar"

	plain_key = str(env.plain_key)
	new_key = str(env.keys_dir / "pulsar-newton-agent")

	l_calls = [c for c in r.calls
			   if c["tool"] == "ssh" and "-N" in c["argv"] and "-L" in c["argv"]]
	d_calls = [c for c in r.calls
			   if c["tool"] == "ssh" and "-N" in c["argv"] and "-D" in c["argv"]]
	assert l_calls, "no -L forward call logged"
	assert d_calls, "no -D forward call logged"

	# first -L: plain-key lane
	first_l = l_calls[0]
	assert "-i" in first_l["argv"]
	vals, _flags, _o, _rest = _parse_ssh(first_l["argv"])
	assert vals["-i"] == plain_key
	assert vals["-L"].endswith(":127.0.0.1:22")

	# second -L: restricted key
	second_l = l_calls[1]
	vals, _flags, _o, _rest = _parse_ssh(second_l["argv"])
	assert vals["-i"] == new_key

	# first -D: plain-key lane
	first_d = d_calls[0]
	vals, _flags, _o, _rest = _parse_ssh(first_d["argv"])
	assert vals["-i"] == plain_key

	# second -D: restricted key
	second_d = d_calls[1]
	vals, _flags, _o, _rest = _parse_ssh(second_d["argv"])
	assert vals["-i"] == new_key

	assert "-R" in r.calls[-1]["argv"] or any(
		"-R" in c["argv"] for c in r.calls
		if c["tool"] == "ssh" and "-N" in c["argv"])


def test_closed_loopback_falls_back_to_the_router_address(pulsar_env):
	"""pulsar / swap-key with closed loopback: the proof must find the
	target by trying 127.0.0.1:22 first, then the inventory host
	(10.1.2.3:22 in the fake router), so the restricted-key -L spec
	ends in `:10.1.2.3:22`; the swap still succeeds."""
	env = pulsar_env
	env.router.update_state(closed_targets=["127.0.0.1:22"])
	_install_pulsar(env)
	r = _swap(env)
	assert r.rc == 0, r.out

	new_key = str(env.keys_dir / "pulsar-newton-agent")
	l_calls = [c for c in r.calls
			   if c["tool"] == "ssh" and "-N" in c["argv"] and "-L" in c["argv"]]
	assert l_calls, "no -L forward call logged"
	# the restricted-key -L spec ends in :10.1.2.3:22 (the inventory host)
	key_l_calls = [c for c in l_calls if _parse_ssh(c["argv"])[0].get("-i") == new_key]
	assert key_l_calls, "no -L call with the restricted key"
	for c in key_l_calls:
		vals, _flags, _o, _rest = _parse_ssh(c["argv"])
		assert vals["-L"].endswith(":10.1.2.3:22"), \
			"expected -L spec to end :10.1.2.3:22, got %r" % vals["-L"]


def test_an_open_forward_is_caught_when_loopback_22_is_closed(setup_env):
	"""setup / add-key with a vulnerable-to-forwarding router whose
	loopback:22 is closed: the unrestricted proof's control is run on
	the router's address (10.1.2.3:22) and gets the banner, then the
	restricted-key -L with vulnerable also allowed carries the banner,
	so the proof FAILS, the run stops, and the appended line is
	removed again. Fails on the OLD tool (it has one -L call and the
	passes)."""
	env = setup_env
	env.router.update_state(
		vulnerable=["forwarding"], closed_targets=["127.0.0.1:22"])
	from test_router_setup_install import install_ok  # noqa: WPS433
	install_ok(env)
	r = env.run("r1", "add-key", "--new-key", "newton-agent", "change",
				typed=(GOOD_PW,))
	assert r.rc == 1, r.out + r.err
	fail_lines = [l for l in r.out.splitlines() if l.startswith("FAIL proof forwards:")]
	assert fail_lines, "no FAIL proof forwards: line"
	assert any("-L carried SSH bytes" in l for l in fail_lines), fail_lines
	assert r.out.splitlines()[-1].startswith(
		"STOPPED add-key r1: the key failed its proofs")
	assert "router unchanged (the new line was removed again)" in r.out
	assert env.router.authorized_keys() == []


def test_no_target_answers_so_the_refusal_cannot_be_proven(setup_env):
	"""setup / add-key with both loopback:22 and the inventory host:22
	closed: the proof's positive control cannot find any target, the
	proof FAILs with the 'admin path to carry an SSH banner through -L'
	reasoning, no -L was tried with the restricted key (the control
	checks closed targets in order, finds none, and stops), the run
	stops, the line is removed, and no -L logged call used the
	restricted key."""
	env = setup_env
	env.router.update_state(
		closed_targets=["127.0.0.1:22", "10.1.2.3:22"])
	from test_router_setup_install import install_ok  # noqa: WPS433
	install_ok(env)
	r = env.run("r1", "add-key", "--new-key", "newton-agent", "change",
				typed=(GOOD_PW,))
	assert r.rc == 1, r.out + r.err
	fail_lines = [l for l in r.out.splitlines() if l.startswith("FAIL proof forwards:")]
	assert fail_lines, "no FAIL proof forwards: line"
	assert any("expected the admin path to carry an SSH banner through -L"
			   in l for l in fail_lines), fail_lines
	# one FAIL line only: the proof stops at the failed -L control and does not
	# go on to the -D control (kills the mutant that does)
	assert len(fail_lines) == 1, fail_lines
	assert r.out.splitlines()[-1].startswith(
		"STOPPED add-key r1: the key failed its proofs")
	assert "router unchanged (the new line was removed again)" in r.out
	assert env.router.authorized_keys() == []
	# no -L logged call used the restricted key
	new_key = str(env.keys_dir / "r1-newton-agent")
	for c in r.calls:
		if c.get("tool") == "ssh" and "-N" in c["argv"] and "-L" in c["argv"]:
			vals, _flags, _o, _rest = _parse_ssh(c["argv"])
			assert vals.get("-i") != new_key, \
				"restricted key should not have been used for -L"


def test_the_same_in_swap_key_leaves_the_router_unchanged(pulsar_env):
	"""pulsar / swap-key with both targets closed: rc 1, the line is
	removed again, the dead-man switch was never started (no `setsid`
	in any logged ssh call of the run), the plain key still works, and
	the authorized_keys equals the original byte for byte. Fails on the
	OLD tool (it runs only one -L call and the proof passes)."""
	env = pulsar_env
	env.router.update_state(
		closed_targets=["127.0.0.1:22", "10.1.2.3:22"])
	from test_router_setup_swap import install_pulsar as _ip  # noqa: WPS433
	_ip(env)
	original = env.router.read("etc/dropbear/authorized_keys")
	r = _swap(env)
	assert r.rc == 1, r.out + r.err
	assert any(l.startswith("FAIL proof forwards:")
			   for l in r.out.splitlines())
	# `NOTE state: router unchanged (the new line was removed again)` immediately
	# before `STOPPED swap-key pulsar: the new key failed its proofs`.
	out_lines = r.out.splitlines()
	state_idx = -1
	for i, l in enumerate(out_lines):
		if l.startswith("NOTE state: router unchanged (the new line was removed again)"):
			state_idx = i
			break
	assert state_idx >= 0
	assert state_idx + 1 < len(out_lines)
	next_l = out_lines[state_idx + 1]
	assert next_l == "STOPPED swap-key pulsar: the new key failed its proofs", next_l

	assert env.router.read("etc/dropbear/authorized_keys") == original
	# no ssh call of the run starts the dead-man switch (the tools check of
	# round FB names setsid in a `command -v` loop, so look for the start text)
	for c in r.calls:
		assert "setsid sh -c" not in (c.get("command") or "")
	# plain key still works
	from test_router_setup_keys import direct_fake_ssh  # noqa: WPS433
	hello = direct_fake_ssh(env, env.plain_key, "true")
	assert hello.returncode == 0


def test_the_password_lane_control_uses_the_password_and_leaks_nothing(setup_env):
	"""setup / add-key (password lane): the first logged -N -L call has
	lane=password and principal=password; the next -L and -D calls are
	key-lane (the restricted key); GOOD_PW registered, env.leaks()
	empty after the run; no leftover askpass.fifo under the run's
	TMPDIR."""
	env = setup_env
	from test_router_setup_install import install_ok  # noqa: WPS433
	env.register_secrets(GOOD_PW)
	install_ok(env)
	r = env.run("r1", "add-key", "--new-key", "newton-agent", "change",
				typed=(GOOD_PW,))
	assert r.rc == 0, r.out + r.err
	# the first -N -L is the control: password lane
	first_l = next((c for c in r.calls
					if c["tool"] == "ssh" and "-N" in c["argv"] and "-L" in c["argv"]),
				   None)
	assert first_l is not None, "no -L ssh call logged"
	assert first_l.get("lane") == "password"
	assert first_l.get("principal") == "password"
	# the restricted-key -L and -D follow (lane=key)
	l_calls = [c for c in r.calls
			   if c["tool"] == "ssh" and "-N" in c["argv"] and "-L" in c["argv"]]
	d_calls = [c for c in r.calls
			   if c["tool"] == "ssh" and "-N" in c["argv"] and "-D" in c["argv"]]
	assert len(l_calls) >= 2
	assert l_calls[1].get("lane") == "key"
	assert l_calls[1].get("principal", "").startswith("key:")
	assert len(d_calls) >= 2
	assert d_calls[1].get("lane") == "key"
	assert d_calls[1].get("principal", "").startswith("key:")
	assert env.leaks() == []
	tmpdir = env.tmpdir
	leftovers = list(tmpdir.rglob("askpass.fifo"))
	assert not leftovers, leftovers


def test_a_nc_without_socks_stops_the_proof_with_a_clear_reason(setup_env):
	"""setup / add-key with an `nc` shim that exits 2 when called with
	-X (no SOCKS5 support): the proof FAILs with 'admin path to carry
	an SSH banner through -D', rc 1."""
	env = setup_env
	real_nc = shutil.which("nc")
	shim_dir = env.fakes  # the NEWTON_SETUP_BIN dir, first on PATH
	shim = shim_dir / "nc"
	shim.write_text(
		"#!/bin/sh\n"
		"case \"$*\" in\n"
		"  *-X*) exit 2 ;;\n"
		"esac\n"
		"exec %s \"$@\"\n" % (real_nc or "/bin/nc"))
	shim.chmod(0o755)
	from test_router_setup_install import install_ok  # noqa: WPS433
	install_ok(env)
	r = env.run("r1", "add-key", "--new-key", "newton-agent", "change",
				typed=(GOOD_PW,))
	assert r.rc == 1, r.out + r.err
	fail_lines = [l for l in r.out.splitlines() if l.startswith("FAIL proof forwards:")]
	assert fail_lines, "no FAIL proof forwards: line"
	assert any("expected the admin path to carry an SSH banner through -D"
			   in l for l in fail_lines), fail_lines


# -- touch-ups after a planted-defect run (each kills a planted defect) --

def _forwards_fail_lines(result):
	return [l for l in result.out.splitlines()
			if l.startswith("FAIL proof forwards:")]


def test_only_d_carrying_bytes_is_caught_at_the_proven_target(setup_env):
	"""Only -D is open on the router (`vulnerable` names forwarding-D) and
	loopback:22 is closed, so the proven target is 10.1.2.3:22.  The
	restricted key's -D must be aimed at that target and so see the
	banner; -L stays blocked.  Kills the mutants that ignore a banner
	through -D or aim the restricted -D at a fixed 127.0.0.1:22."""
	env = setup_env
	env.router.update_state(
		vulnerable=["forwarding-D"], closed_targets=["127.0.0.1:22"])
	from test_router_setup_install import install_ok  # noqa: WPS433
	install_ok(env)
	r = env.run("r1", "add-key", "--new-key", "newton-agent", "change",
				typed=(GOOD_PW,))
	assert r.rc == 1, r.out + r.err
	lines = _forwards_fail_lines(r)
	assert len(lines) == 1, lines
	assert "-D carried SSH bytes" in lines[0], lines
	assert "-L carried SSH bytes" not in lines[0], lines
	assert env.router.authorized_keys() == []


def test_only_l_carrying_bytes_is_caught(setup_env):
	"""The same for -L alone (vulnerable names forwarding-L)."""
	env = setup_env
	env.router.update_state(vulnerable=["forwarding-L"])
	from test_router_setup_install import install_ok  # noqa: WPS433
	install_ok(env)
	r = env.run("r1", "add-key", "--new-key", "newton-agent", "change",
				typed=(GOOD_PW,))
	assert r.rc == 1, r.out + r.err
	lines = _forwards_fail_lines(r)
	assert len(lines) == 1, lines
	assert "-L carried SSH bytes" in lines[0], lines
	assert "-D carried SSH bytes" not in lines[0], lines
	assert env.router.authorized_keys() == []


def test_restricted_forwards_that_cannot_start_fail_the_proof(setup_env):
	"""`deny_restricted_when_plain_absent`: the router closes every
	connection of the restricted key (there is no plain line), so neither
	forward can even be set up.  The admin password-lane control still
	works; the proof must fail and say that -L and -D could not be tried
	(a forward that never started proves nothing)."""
	env = setup_env
	env.router.update_state(deny_restricted_when_plain_absent=True)
	from test_router_setup_install import install_ok  # noqa: WPS433
	install_ok(env)
	r = env.run("r1", "add-key", "--new-key", "newton-agent", "change",
				typed=(GOOD_PW,))
	assert r.rc == 1, r.out + r.err
	lines = _forwards_fail_lines(r)
	assert len(lines) == 1, lines
	assert "-L could not be tried" in lines[0], lines
	assert "-D could not be tried" in lines[0], lines


# ---------------------------------------------------------------------------
# Pure-function unit tests for the IPv6-host fix 
# ---------------------------------------------------------------------------

from test_router_setup_units import unit  # noqa: E401,F401


@pytest.mark.parametrize("candidate,expected", [
	("127.0.0.1:22", "127.0.0.1 22"),
	("r1.lan:2222", "r1.lan 2222"),
	("fd00::1:22", "fd00::1 22"),
	("::1:22", "::1 22"),
	("[fd00::1]:2222", "fd00::1 2222"),
])
def test_forward_target_split(unit, candidate, expected):
	"""`forward_target_split` must print one line `HOST PORT` and split
	HOST/PORT at the LAST colon (so an IPv6 candidate with several colons
	like `fd00::1:22` lands as HOST=`fd00::1` PORT=`22`, not PORT=`:1:22`);
	`[fd00::1]:2222` strips the brackets from HOST."""
	r = unit.run("forward_target_split %s\n" % candidate)
	assert r.returncode == 0
	assert r.stdout.splitlines() == [expected]
	assert len(r.stdout.splitlines()) == 1


@pytest.mark.parametrize("port,thost,tport,expected", [
	("5000", "10.1.2.3", "22", "127.0.0.1:5000:10.1.2.3:22"),
	("5000", "r1.lan", "22", "127.0.0.1:5000:r1.lan:22"),
	("5000", "fd00::1", "22", "127.0.0.1:5000:[fd00::1]:22"),
	("5000", "[fd00::1]", "22", "127.0.0.1:5000:[fd00::1]:22"),
])
def test_forward_l_spec(unit, port, thost, tport, expected):
	"""`forward_l_spec` builds the -L argument `127.0.0.1:PORT:THOST:TPORT`,
	wrapping THOST in [] when it contains `:` and does not already start with
	`[`; an already-wrapped THOST is not wrapped twice."""
	r = unit.run("forward_l_spec %s %s %s\n" % (port, thost, tport))
	assert r.returncode == 0
	assert r.stdout.splitlines() == [expected]


# ---------------------------------------------------------------------------
# Harness self-tests for IPv6 forwarding targets 
# ---------------------------------------------------------------------------

def _recv_exactly(conn, count):
	data = b""
	while len(data) < count:
		chunk = conn.recv(count - len(data))
		if not chunk:
			break
		data += chunk
	return data


def _socks5_ipv6_connect(port):
	conn = socket.create_connection(("127.0.0.1", port), timeout=5)
	conn.settimeout(5)
	conn.sendall(b"\x05\x01\x00")
	assert _recv_exactly(conn, 2) == b"\x05\x00"
	request = (b"\x05\x01\x00\x04"
		+ socket.inet_pton(socket.AF_INET6, "fd00::1")
		+ (22).to_bytes(2, "big"))
	conn.sendall(request)
	reply = _recv_exactly(conn, 10)
	banner = conn.recv(64)
	conn.close()
	return reply, banner


def test_L_to_an_ipv6_target_respects_closed_targets(rig):
	key, blob = rig.key("fwd-ipv6-l")
	rig.router.add_authorized_key("ssh-ed25519 %s plain" % blob)
	spec = "127.0.0.1:%d:[fd00::1]:22"

	rig.router.update_state(closed_targets=["fd00::1:22"])
	port = free_port()
	proc = rig.start(forward_args(rig.key_args(key), "-L", spec % port))
	try:
		conn = wait_listener(port)
		conn.settimeout(5)
		assert conn.recv(64) == b""
		conn.close()
	finally:
		reap(proc)

	rig.router.update_state(closed_targets=[])
	port = free_port()
	proc = rig.start(forward_args(rig.key_args(key), "-L", spec % port))
	try:
		conn = wait_listener(port)
		conn.settimeout(5)
		assert conn.recv(64) == b"SSH-2.0-FAKE\r\n"
		conn.close()
	finally:
		reap(proc)


def test_D_to_an_ipv6_target_respects_closed_targets(rig):
	key, blob = rig.key("fwd-ipv6-d")
	rig.router.add_authorized_key("ssh-ed25519 %s plain" % blob)

	rig.router.update_state(closed_targets=["fd00::1:22"])
	port = free_port()
	proc = rig.start(forward_args(
		rig.key_args(key), "-D", "127.0.0.1:%d" % port))
	try:
		wait_listener(port).close()
		reply, banner = _socks5_ipv6_connect(port)
		assert len(reply) == 10
		assert reply[1] == 5
		assert banner == b""
	finally:
		reap(proc)

	rig.router.update_state(closed_targets=[])
	port = free_port()
	proc = rig.start(forward_args(
		rig.key_args(key), "-D", "127.0.0.1:%d" % port))
	try:
		wait_listener(port).close()
		reply, banner = _socks5_ipv6_connect(port)
		assert len(reply) == 10
		assert reply[1] == 0
		assert banner == b"SSH-2.0-FAKE\r\n"
	finally:
		reap(proc)
