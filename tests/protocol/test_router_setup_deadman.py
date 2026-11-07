"""Tests of the dead-man switch of swap-key in scripts/newton-router-setup (design 8.3 sub-step 4): the prerequisite
tool check (setsid, sleep, grep, cp, logger, ps) and the liveness check
that proves a `sleep 90` process is alive on the router before step 5
replaces authorized_keys.  Self-tests of the harness stubs, end-to-end
through pulsar_env, and unit tests of the new bash functions."""

import os
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from router_setup_env import pulsar_env  # noqa: F401
from test_router_setup_harness import (  # noqa: E402
	DEST, HOST, register_timer, arm_deadman, deadman_text, rig)
from test_router_setup_install import seed_known_hosts  # noqa: E402
from test_router_setup_keys import direct_fake_ssh  # noqa: E402

from router_setup_harness import (  # noqa: E402
	FakeRouter, _write_bin_stubs, advance_clock, install_fakes)


EXTRA = "ssh-ed25519 AAAAEXTRAKEYFORSWAPTESTS0001 agent-laptop"


def install_pulsar(env):
	seed_known_hosts(env)
	# the install asks for the "yes", so the feed carries it
	r = env.run("--plain-key", env.plain_key, "pulsar", "install",
	            typed=("yes",))
	assert r.rc == 0, r.out


def swap(env, *extra):
	return env.run("--plain-key", env.plain_key, "pulsar", "swap-key",
	               *extra)


# -- 1. self-test: the stubs exist on the router, never in hostbin ------------

def test_sleep_and_ps_stubs_exist_on_the_router_but_not_in_hostbin(rig):
	"""The new sleep and ps stubs are written into router/bin, never into
	router/hostbin (hostbin must still never contain sleep, and the new
	ps stub lives only in bin).  `command -v` finds them on the router."""
	key, blob = rig.key("dm1")
	rig.router.add_authorized_key("ssh-ed25519 %s agent-laptop" % blob)
	proc = rig.ssh(rig.key_args(key) + [DEST,
		"command -v sleep && command -v ps"])
	assert proc.returncode == 0, proc.stderr
	out = proc.stdout.decode()
	assert "/sleep" in out
	assert "/ps" in out
	assert not (rig.router.root / "hostbin" / "sleep").exists()
	assert not (rig.router.root / "hostbin" / "ps").exists()


# -- 2. self-test: ps lists the pending timers -------------------------------

def _run_router_ps(rig):
	"""Invoke the router's bin/ps directly (the stub), no ssh, so the
	test is independent of the authorized_keys state."""
	return subprocess.run(
		[str(rig.router.root / "bin" / "ps")],
		capture_output=True, timeout=10,
		env={"FAKE_ROUTER_ROOT": str(rig.router.root), "PATH": "/usr/bin:/bin"})


def test_ps_stub_lists_the_pending_timers(rig):
	"""After a dead-man timer is registered, `ps` prints the header and a
	line with `sleep 90` and the nonce (the command text).  With no
	timer only the header.  After advancing the clock past 90 the line
	is gone (the timer fired and was removed from timers.json)."""
	proc = _run_router_ps(rig)
	assert proc.returncode == 0, proc.stderr
	assert proc.stdout.decode().splitlines() == [
		"  PID USER       VSZ STAT COMMAND"]

	nonce = "dd" * 16
	rig.router.write("/etc/dropbear/authorized_keys.newton-prev",
		"ssh-ed25519 AAA agent-laptop\n", mode=0o600)
	arm_deadman(rig, nonce)

	proc = _run_router_ps(rig)
	assert proc.returncode == 0, proc.stderr
	out = proc.stdout.decode()
	lines = out.splitlines()
	assert lines[0] == "  PID USER       VSZ STAT COMMAND"
	sleep_lines = [l for l in lines if "sleep 90" in l]
	assert len(sleep_lines) >= 1
	assert any(nonce in l for l in lines), out

	advance_clock(rig.router.root, 95)
	proc = _run_router_ps(rig)
	assert proc.returncode == 0, proc.stderr
	assert proc.stdout.decode().splitlines() == [
		"  PID USER       VSZ STAT COMMAND"]


# -- 3. self-test: the setsid_noop knob registers no timer ------------------

def test_setsid_noop_knob_registers_no_timer(rig):
	"""With state knob setsid_noop=True the setsid stub returns 0 for the
	`sh -c 'sleep N; ...'` form WITHOUT adding a timer to timers.json:
	a job that died right after being started."""
	rig.router.update_state(setsid_noop=True)
	proc = arm_deadman(rig, "ee" * 16)
	assert proc.returncode == 0
	assert rig.router.timers() == []


# -- 4. end-to-end: a missing tool refuses the swap --------------------------

@pytest.mark.parametrize("tool", ["setsid", "sleep", "logger", "ps"])
def test_swap_key_refuses_when_a_dead_man_tool_is_missing(pulsar_env, tool):
	"""Deleting router/bin/<tool> makes the dead-man switch unsafe: the
	tool refuses to start a switch on a router that lacks any of the
	six tools it needs.  Nothing is written to the router, no .newton-
	prev is staged, no ssh call of this run mentions .newton-prev, no
	-L forward session is started."""
	env = pulsar_env
	install_pulsar(env)
	env.router.add_authorized_key(EXTRA)
	original = env.router.read("etc/dropbear/authorized_keys")
	(env.router.root / "bin" / tool).unlink()

	r = swap(env, "--new-key")
	assert r.rc == 1
	out_lines = r.out.splitlines()
	assert "STOPPED swap-key pulsar: the router lacks %s, which the dead-man switch needs" % tool in out_lines
	note_idx = out_lines.index(
		"NOTE state: router unchanged")
	stopped_idx = out_lines.index(
		"STOPPED swap-key pulsar: the router lacks %s, which the dead-man switch needs" % tool)
	assert note_idx < stopped_idx

	assert env.router.read("etc/dropbear/authorized_keys") == original
	assert not (env.router.path("etc/dropbear/authorized_keys.newton-prev")).exists()
	for call in r.calls:
		assert ".newton-prev" not in (call.get("command") or ""), call
		assert "-L" not in call.get("argv", []), call


# -- 5. end-to-end: the switch is not alive -> refuse -------------------------

def test_swap_key_stops_when_the_switch_is_not_alive(pulsar_env):
	"""setsid_noop knob: the setsid stub returns 0 but registers no
	timer, so the liveness check finds no `sleep 90` and the tool
	refuses.  The new line is removed, the plain key is never replaced,
	no PASS swap step 4, no swap step 5 line, the plain key still
	works."""
	env = pulsar_env
	install_pulsar(env)
	env.router.add_authorized_key(EXTRA)
	original = env.router.read("etc/dropbear/authorized_keys")
	env.router.update_state(setsid_noop=True)

	r = swap(env, "--new-key")
	assert r.rc == 1, r.out
	assert r.out.splitlines()[-1] == (
		"STOPPED swap-key pulsar: cannot start the dead-man switch")
	assert "NOTE state: router unchanged (the new line was removed again)" in r.out
	assert not any(l.startswith("PASS swap step 4") for l in r.out.splitlines())
	assert not any(l.startswith("INFO swap step 5")
		or l.startswith("PASS swap step 5") for l in r.out.splitlines())
	assert env.router.read("etc/dropbear/authorized_keys") == original
	assert not env.router.path("etc/dropbear/authorized_keys.new").exists()
	assert direct_fake_ssh(env, env.plain_key, "true").returncode == 0


def test_an_unrelated_sleep_90_does_not_prove_the_switch(pulsar_env):
	env = pulsar_env
	install_pulsar(env)
	env.router.add_authorized_key(EXTRA)
	original = env.router.read("etc/dropbear/authorized_keys")
	register_timer(env, "sleep 90; true")
	env.router.update_state(setsid_noop=True)

	r = swap(env, "--new-key")
	assert r.rc == 1, r.out
	assert "STOPPED swap-key pulsar: cannot start the dead-man switch" in r.out
	assert "NOTE state: router unchanged (the new line was removed again)" in r.out
	assert env.router.read("etc/dropbear/authorized_keys") == original


def test_a_stale_sleep_90_does_not_block_a_good_swap(pulsar_env):
	env = pulsar_env
	install_pulsar(env)
	env.router.add_authorized_key(EXTRA)
	register_timer(env, "sleep 90; true")

	r = swap(env, "--new-key")
	assert r.rc == 0, r.out
	assert "DONE swap-key pulsar" in r.out.splitlines()


# -- 6. end-to-end: the liveness check sits between the start and step 5 -----

def test_the_liveness_check_sits_between_the_start_and_the_replace(pulsar_env):
	"""A count before start and a count after it precede key replacement."""
	env = pulsar_env
	install_pulsar(env)
	env.router.add_authorized_key(EXTRA)

	r = swap(env, "--new-key")
	assert r.rc == 0, r.out

	calls = r.calls
	count_ns = []
	start_n = None
	replace_n = None
	for call in calls:
		cmd = call.get("command") or ""
		if "grep -c '[s]leep 90'" in cmd:
			count_ns.append(call["n"])
		if start_n is None and "setsid sh -c 'sleep 90;" in cmd:
			start_n = call["n"]
		if (replace_n is None and 'n="${f}.new"' in cmd
				and "awk -v blob=" in cmd):
			replace_n = call["n"]
	assert len(count_ns) == 2, calls
	assert start_n is not None, calls
	assert replace_n is not None, calls
	assert count_ns[0] < start_n < count_ns[1] < replace_n


# -- 7. end-to-end: second run with one tool missing is the already-swapped path

def test_a_second_swap_key_run_does_not_need_the_tools(pulsar_env):
	"""The tool check sits after the already-swapped branch, so a second
	run on a swap-done router needs none of the six tools."""
	env = pulsar_env
	install_pulsar(env)
	env.router.add_authorized_key(EXTRA)
	assert swap(env, "--new-key").rc == 0

	(env.router.root / "bin" / "ps").unlink()
	r = swap(env)
	assert r.rc == 0
	assert "PASS already swapped" in r.out.splitlines()


# -- 8. unit: swap_deadman_tools -------------------------------------------

class _ToolsUnit:
	"""Drives the new bash functions through `bash -c 'source SCRIPT; ...'`
	against the fake router."""

	TOOL = Path(__file__).resolve().parents[2] / "scripts" / "newton-router-setup"

	# which router dir each dead-man tool lives in
	TOOL_DIR = {
		"setsid": "bin",
		"sleep": "bin",
		"grep": "hostbin",
		"cp": "hostbin",
		"logger": "bin",
		"ps": "bin",
	}

	def __init__(self, tmp_path):
		self.tmp = tmp_path
		self.router = FakeRouter.create(tmp_path / "router")
		self.bindir = tmp_path / "fakes"
		install_fakes(self.bindir, self.router.root)
		self.keys = tmp_path / "keys"
		self.keys.mkdir()
		self.kh = self.keys / "r1.known_hosts"
		self.kh.write_text("10.1.2.3 ssh-ed25519 AAAAC3FAKEHOSTKEY0001\n")
		blob = "AAAAC3NzaC1lZDI1NTE5AAAAIPLAINKEYFORUNITTESTS0001"
		self.plain = tmp_path / "plainkey"
		self.plain.write_text("FAKE-OPENSSH-PRIVATE-KEY\n%s\n" % blob)
		self.plain.chmod(0o600)
		self.router.add_authorized_key("ssh-ed25519 %s agent@unit" % blob)

	def run(self, code, extra_env=None):
		env = {k: v for k, v in os.environ.items() if not k.startswith("NEWTON_")}
		env.update(
			{
				"NEWTON_SETUP_SEAMS": "1",
				"NEWTON_SETUP_BIN": str(self.bindir),
				"NEWTON_SETUP_REMOTE_ROOT": str(self.router.root / "fs"),
				"NEWTON_SETUP_SLEEP": str(self.bindir / "fake-sleep"),
				"TOOL_PATH": str(self.TOOL),
				"TMPDIR": str(self.tmp),
			}
		)
		# State-dir isolation: scripts/newton-router-setup resolves its
		# state dir from NEWTON_STATE_DIR (else `$(home_dir)/.local/state/newton`
		# via getent passwd), and the inline python helper in
		# approval_fingerprint_write falls back to Path.home().  Use
		# per-call tmp dirs so a stray write stays inside the tmp tree.
		if "NEWTON_STATE_DIR" not in (extra_env or {}):
			env["NEWTON_STATE_DIR"] = str(self.tmp / "state")
		if "HOME" not in (extra_env or {}):
			env["HOME"] = str(self.tmp / "home")
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

	def remove_tool(self, tool):
		path = self.router.root / self.TOOL_DIR[tool] / tool
		path.unlink()


@pytest.fixture()
def tools_unit(tmp_path):
	return _ToolsUnit(tmp_path)


def test_swap_deadman_tools_all_present_returns_zero(tools_unit):
	r = tools_unit.run("swap_deadman_tools; echo rc=$?\n")
	assert r.returncode == 0
	assert r.stdout.splitlines() == ["rc=0"]


@pytest.mark.parametrize("tool", ["setsid", "sleep", "grep", "cp", "logger", "ps"])
def test_swap_deadman_tools_one_missing_returns_one(tools_unit, tool):
	tools_unit.remove_tool(tool)
	r = tools_unit.run("swap_deadman_tools; echo rc=$?\n")
	assert r.returncode == 0
	lines = r.stdout.splitlines()
	assert lines[0] == tool
	assert lines[1] == "rc=1"


def test_swap_deadman_tools_two_missing_returns_one(tools_unit):
	tools_unit.remove_tool("setsid")
	tools_unit.remove_tool("sleep")
	r = tools_unit.run("swap_deadman_tools; echo rc=$?\n")
	assert r.returncode == 0
	lines = r.stdout.splitlines()
	assert lines[0] == "setsid sleep"
	assert lines[1] == "rc=1"


def test_swap_deadman_tools_ssh_call_failure_returns_two(tools_unit):
	tools_unit.router.update_state(
		drop_commands=["for t in setsid sleep grep cp logger ps"])
	r = tools_unit.run("swap_deadman_tools; echo rc=$?\n")
	assert r.returncode == 0
	assert r.stdout.splitlines() == ["rc=2"]


# -- 9. unit: swap_deadman_count --------------------------------------------

def test_swap_deadman_count_no_timer_prints_zero(tools_unit):
	r = tools_unit.run("swap_deadman_count; echo rc=$?\n")
	assert r.returncode == 0
	assert r.stdout.splitlines() == ["0", "rc=0"]


def test_swap_deadman_count_with_sleep_90_timer_is_positive(tools_unit):
	nonce = "aabbccddeeff00112233aabbccddeeff"
	inner = deadman_text(nonce, str(tools_unit.router.root / "fs"))
	register_timer(_DummyRig(tools_unit), inner)
	r = tools_unit.run("swap_deadman_count; echo rc=$?\n")
	assert r.returncode == 0
	lines = r.stdout.splitlines()
	assert int(lines[0]) >= 1
	assert lines[1] == "rc=0"


def test_swap_deadman_count_with_only_sleep_30_prints_zero(tools_unit):
	inner = deadman_text("00112233aabbccdd00112233aabbccdd",
		str(tools_unit.router.root / "fs"), seconds=30)
	register_timer(_DummyRig(tools_unit), inner)
	r = tools_unit.run("swap_deadman_count; echo rc=$?\n")
	assert r.returncode == 0
	assert r.stdout.splitlines() == ["0", "rc=0"]


def test_swap_deadman_count_ssh_failure_returns_one_without_output(tools_unit):
	tools_unit.router.update_state(drop_commands=["grep -c '[s]leep 90'"])
	r = tools_unit.run("swap_deadman_count; echo rc=$?\n")
	assert r.returncode == 0
	assert r.stdout.splitlines() == ["rc=1"]


class _DummyRig:
	"""register_timer needs only a `router` attribute; this wraps the unit
	to look like a rig for that one call."""

	def __init__(self, unit):
		self.router = unit.router


# -- 10. unit: swap_start_deadman -------------------------------------------

def test_swap_start_deadman_with_setsid_noop_returns_one_clock_advanced(tools_unit):
	tools_unit.router.update_state(setsid_noop=True)
	r = tools_unit.run(
		"swap_start_deadman 'aabbccddeeff00112233aabbccddeeff'; echo rc=$?\n")
	assert r.returncode == 0
	assert r.stdout.splitlines()[-1] == "rc=1"
	assert tools_unit.router.clock() == 4
	assert tools_unit.router.timers() == []


def test_swap_start_deadman_with_real_stub_returns_zero_no_clock_advance(tools_unit):
	"""The start call registers the one timer itself (no timer is
	registered by the test), the first liveness check finds it, so
	nothing waits: the clock stays at 0.  (the rig's
	version registered a timer by hand first, which made the liveness check
	pass on its own.)"""
	assert tools_unit.router.timers() == []
	r = tools_unit.run(
		"swap_start_deadman '00112233445566778899aabbccddeeff'; echo rc=$?\n")
	assert r.returncode == 0
	assert r.stdout.splitlines()[-1] == "rc=0"
	assert tools_unit.router.clock() == 0
	timers = tools_unit.router.timers()
	assert len(timers) == 1
	assert timers[0]["sleep"] == "90"
	assert "00112233445566778899aabbccddeeff" in timers[0]["command"]


def test_swap_start_deadman_count_failure_does_not_start(tools_unit):
	tools_unit.router.update_state(drop_commands=["grep -c '[s]leep 90'"])
	r = tools_unit.run(
		"swap_start_deadman '11223344556677889900aabbccddeeff'; echo rc=$?\n")
	assert r.returncode == 0
	assert r.stdout.splitlines() == ["rc=1"]
	assert tools_unit.router.timers() == []
	assert not any("setsid sh -c 'sleep 90;" in (call.get("command") or "")
		for call in tools_unit.router.calls())
