"""Behaviour tests of the swap-key success path of scripts/newton-router-setup
(design 2.4, 2.7, 8.3 sub-steps 1-4): the success body,
the order of effects, the already-swapped short-circuit, a custom label and
the secret rule.
"""

import json
import re
import sys
import tomllib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from router_setup_env import pulsar_env  # noqa: F401
from test_router_setup_keys import (  # noqa: E402
	restricted_line_text, parse_ssh, direct_fake_ssh,
	PROOF_PREFIXES, file_mode, make_keypair, key_blob)
from test_router_setup_install import seed_known_hosts  # noqa: E402


EXTRA = "ssh-ed25519 AAAAEXTRAKEYFORSWAPTESTS0001 agent-laptop"
EXTRA_BLOB = "AAAAEXTRAKEYFORSWAPTESTS0001"


def install_pulsar(env):
	seed_known_hosts(env)
	# the install asks for the "yes", so the feed carries it
	r = env.run("--plain-key", env.plain_key, "pulsar", "install",
	            typed=("yes",))
	assert r.rc == 0, r.out


def swap(env, *extra):
	return env.run("--plain-key", env.plain_key, "pulsar", "swap-key", *extra)


def pulsar_blob(env, label="newton-agent"):
	pub = env.keys_dir / ("pulsar-%s.pub" % label)
	return pub.read_text().strip().split()[1]


def first_index(lines, prefix):
	for i, l in enumerate(lines):
		if l.startswith(prefix):
			return i
	return -1


def test_swap_key_without_a_local_key_never_mints(pulsar_env):
	"""swap-key refuses before any router call when this host
	does not hold the private key, instead of making a replacement key."""
	env = pulsar_env
	install_pulsar(env)
	before = env.router.read("etc/dropbear/authorized_keys")
	r = swap(env)
	assert r.rc == 1
	assert r.out.splitlines()[-1] == (
		"STOPPED swap-key pulsar: no key for label newton-agent on this "
		"host (%s is missing): the key lives on the Newton host that "
		"added it; run this there, or pass --new-key to make a new key "
		"on purpose" % (env.keys_dir / "pulsar-newton-agent"))
	assert "NOTE state: router unchanged" in r.out.splitlines()
	assert env.router.read("etc/dropbear/authorized_keys") == before
	assert r.calls == []
	assert not (env.keys_dir / "pulsar-newton-agent").exists()
	assert not (env.keys_dir / "pulsar-newton-agent.pub").exists()


def test_swap_key_new_key_refuses_an_existing_router_line(pulsar_env):
	"""A first-time swap cannot add a second restricted line for
	a label the router already has; it refuses before minting."""
	env = pulsar_env
	install_pulsar(env)
	key = make_keypair(env, "newton-agent")
	env.router.add_authorized_key(restricted_line_text(
		"newton-agent", "change",
		key.with_suffix(".pub").read_text().strip().split()[1]))
	key.with_suffix(".pub").unlink()
	key.unlink()
	before = env.router.read("etc/dropbear/authorized_keys")
	r = swap(env, "--new-key")
	assert r.rc == 1
	assert r.out.splitlines()[-1] == (
		"STOPPED swap-key pulsar: the router already has a Newton key "
		"line for label newton-agent; revoke it first (sudo -u newton "
		"/usr/local/bin/newton-router-setup pulsar revoke newton-agent)")
	assert env.router.read("etc/dropbear/authorized_keys") == before
	assert not key.exists()
	assert not key.with_suffix(".pub").exists()


# -- 1. success --------------------------------------------------------------

def test_swap_key_success(pulsar_env):
	env = pulsar_env
	install_pulsar(env)
	env.router.add_authorized_key(EXTRA)
	original = env.router.read("etc/dropbear/authorized_keys")
	inv_before = env.inventory.read_text()

	r = swap(env, "--new-key")
	assert r.rc == 0, r.out
	out_lines = r.out.splitlines()

	# stdout order: step 2, 10 proofs, step 3, step 4, step 5 INFO, step 6, 7, 8, INFO next, DONE
	idx = {}
	for key, prefix in [
		("step2", "PASS swap step 2:"),
		("proof", "PASS proof "),
		("step3", "PASS swap step 3:"),
		("step4", "PASS swap step 4:"),
		("step5", "INFO swap step 5:"),
		("step6", "PASS swap step 6:"),
		("step7", "PASS swap step 7:"),
		("step8", "PASS swap step 8:"),
		("next", "INFO next:"),
		("done", "DONE swap-key pulsar"),
	]:
		idx[key] = first_index(out_lines, prefix)
	assert all(v >= 0 for v in idx.values()), idx
	order = ["step2", "proof", "step3", "step4", "step5",
		"step6", "step7", "step8", "next", "done"]
	assert all(idx[a] < idx[b] for a, b in zip(order, order[1:])), idx

	# all ten proof lines sit between step 2 and step 3
	proof_idxs = [i for i, l in enumerate(out_lines) if l.startswith("PASS proof ")]
	assert len(proof_idxs) == 10
	for prefix in PROOF_PREFIXES:
		assert any(l.startswith(prefix) for l in out_lines), prefix
	assert all(i > idx["step2"] and i < idx["step3"] for i in proof_idxs)

	# authorized_keys: EXTRA verbatim + exactly one restricted line for newton-agent
	ak = env.router.authorized_keys()
	assert ak.count(EXTRA) == 1
	plain_pub = env.plain_key.with_suffix(".pub")
	plain_blob = plain_pub.read_text().strip().split()[1]
	assert all(plain_blob not in l for l in ak)
	new_blob = pulsar_blob(env)
	expected_line = restricted_line_text("newton-agent", "change", new_blob).rstrip("\n")
	restricted = [l for l in ak if l != EXTRA]
	assert restricted == [expected_line]

	# .newton-prev is the original, mode 0o600
	prev = env.router.read("etc/dropbear/authorized_keys.newton-prev")
	assert prev == original
	assert file_mode(env.router.path("etc/dropbear/authorized_keys.newton-prev")) == "0o600"

	# old plain key no longer works
	old_hello = direct_fake_ssh(env, env.plain_key, "hello " + ("0" * 32))
	assert old_hello.returncode == 255

	# new key login works
	new_key = env.keys_dir / "pulsar-newton-agent"
	new_hello = direct_fake_ssh(env, new_key, "hello " + ("0" * 32))
	assert new_hello.returncode == 0
	for token in ("caller=newton-agent", "role=change", "door=ssh",
	              "mode=prod", "agent=0", "tty=0"):
		assert token in new_hello.stdout, token

	# dead-man fired and found the proof line
	assert env.router.timers() == []
	syslog = env.router.path("tmp/syslog")
	if syslog.exists():
		assert "authorized_keys restored" not in syslog.read_text()

	# the swap slept at least 95 seconds
	assert env.router.clock() >= 95

	# inventory gained exactly two lines, both inside [devices.pulsar], both parse
	inv_after = env.inventory.read_text()
	expected_key_line = 'key_file = "%s"' % (env.keys_dir / "pulsar-newton-agent")
	expected_hosts_line = 'known_hosts = "%s"' % env.known_hosts
	after_lines = inv_after.splitlines()
	before_lines = inv_before.splitlines()
	new_lines = {expected_key_line, expected_hosts_line}
	assert all(nl in after_lines for nl in new_lines)
	after_minus = [l for l in after_lines if l not in new_lines]
	assert after_minus == before_lines
	tomllib.loads(inv_before)
	tomllib.loads(inv_after)


# -- 2. order of effects ----------------------------------------------------

def test_swap_key_order_of_effects(pulsar_env):
	env = pulsar_env
	install_pulsar(env)
	env.router.add_authorized_key(EXTRA)

	r = swap(env, "--new-key")
	assert r.rc == 0, r.out
	calls = r.calls

	# First ssh call with -L in argv
	first_l = next((c for c in calls if c["tool"] == "ssh" and "-L" in c["argv"]), None)
	assert first_l is not None

	# Staging: command contains "authorized_keys.newton-prev" and comes before first -L
	staging = [c for c in calls
	           if "authorized_keys.newton-prev" in (c.get("command") or "")
	           and c["n"] < first_l["n"]]
	assert len(staging) == 1
	staging_n = staging[0]["n"]
	assert staging_n < first_l["n"]

	# Last proof call: last call with SetEnv= in argv
	setenv_calls = [c for c in calls if any(
		a.startswith("SetEnv=") for a in c.get("argv", []))]
	assert setenv_calls
	last_proof = setenv_calls[-1]
	last_proof_n = last_proof["n"]

	# Dead-man: command contains "setsid sh -c 'sleep 90;"
	dead_man = [c for c in calls if "setsid sh -c 'sleep 90;" in (c.get("command") or "")]
	assert len(dead_man) == 1
	dead_man_n = dead_man[0]["n"]
	assert last_proof_n < dead_man_n

	# Replace: command references the .new staging file and runs "awk -v blob="
	replace = [c for c in calls
	           if 'n="${f}.new"' in (c.get("command") or "")
	           and "awk -v blob=" in (c.get("command") or "")]
	assert len(replace) == 1
	replace_n = replace[0]["n"]
	assert dead_man_n < replace_n

	# NONCE from dead-man command (grep -q "^<32 hex>" in the setsid script)
	dead_man_command = dead_man[0]["command"]
	nonce_match = re.search(r'\^([0-9a-f]{32})\s', dead_man_command)
	assert nonce_match, "no NONCE in dead-man command: %s" % dead_man_command
	nonce = nonce_match.group(1)

	# Next call with command "hello NONCE" after replace
	hello = [c for c in calls
	         if c.get("command") == "hello " + nonce and c["n"] > replace_n]
	assert hello, "no hello NONCE call after replace"
	hello_n = hello[0]["n"]

	# Old-key check: ssh with -i plain key and command "true" after hello
	old_check = [c for c in calls
	             if c["n"] > hello_n
	             and c["tool"] == "ssh"
	             and c.get("command") == "true"]
	old_check = [c for c in old_check
	             if parse_ssh(c["argv"])[0].get("-i") == str(env.plain_key)]
	assert old_check, "no old-key check after hello"
	old_check_n = old_check[0]["n"]

	# Last sleep call after old check, argv ["95"]
	sleep_calls = [c for c in calls if c["tool"] == "sleep" and c["n"] > old_check_n]
	assert sleep_calls, "no sleep after old check"
	last_sleep = sleep_calls[-1]
	assert last_sleep["argv"] == ["95"]


# -- 3. already swapped -----------------------------------------------------

def test_swap_key_already_swapped(pulsar_env):
	env = pulsar_env
	install_pulsar(env)
	env.router.add_authorized_key(EXTRA)

	r = swap(env, "--new-key")
	assert r.rc == 0

	snap_before = env.router.snapshot()
	r2 = swap(env)
	assert r2.rc == 0
	assert "PASS already swapped" in r2.out
	assert r2.out.splitlines()[-1] == "DONE swap-key pulsar"
	assert env.router.snapshot() == snap_before
	for call in r2.calls:
		assert "setsid" not in (call.get("command") or ""), call


def test_swap_key_repairs_inventory_after_router_finished(pulsar_env):
	env = pulsar_env
	install_pulsar(env)
	assert swap(env, "--new-key").rc == 0

	without_key = "".join(
		line for line in env.inventory.read_text().splitlines(keepends=True)
		if not line.startswith(("key_file = ", "known_hosts = "))
	)
	env.inventory.write_text(without_key)
	r = swap(env)
	assert r.rc == 0, r.out + r.err
	assert "PASS already swapped; inventory updated" in r.out.splitlines()
	assert r.out.splitlines()[-1] == "DONE swap-key pulsar"
	data = tomllib.loads(env.inventory.read_text())["devices"]["pulsar"]
	assert data["key_file"] == str(env.keys_dir / "pulsar-newton-agent")
	assert data["known_hosts"] == str(env.known_hosts)


# -- 4. custom label --------------------------------------------------------

def test_swap_key_custom_label(pulsar_env):
	env = pulsar_env
	install_pulsar(env)
	env.router.add_authorized_key(EXTRA)

	r = swap(env, "--new-key", "lab-gate")
	assert r.rc == 0, r.out
	assert r.out.splitlines()[-1] == "DONE swap-key pulsar"

	new_key = env.keys_dir / "pulsar-lab-gate"
	assert new_key.exists()

	ak = env.router.authorized_keys()
	assert any("newton-router-lab-gate" in l for l in ak)

	hello = direct_fake_ssh(env, new_key, "hello " + ("0" * 32))
	assert hello.returncode == 0
	assert "caller=lab-gate" in hello.stdout


# -- 5. secrets -------------------------------------------------------------

def test_swap_key_no_secret_leaks(pulsar_env):
	"""The plain-key path takes no password.  The unrelated key line is
	not registered as a secret (the router's own authorized_keys, inside
	the scanned tree, must hold it); instead nothing the tool printed or
	sent may carry its blob, and no private key text is printed."""
	env = pulsar_env
	install_pulsar(env)
	env.router.add_authorized_key(EXTRA)

	r = swap(env, "--new-key")
	assert r.rc == 0
	assert env.leaks() == []
	for text in (r.out, r.err):
		assert "FAKE-OPENSSH-PRIVATE-KEY" not in text
		assert EXTRA_BLOB not in text
	for call in r.calls:
		assert EXTRA_BLOB not in json.dumps(call), call
