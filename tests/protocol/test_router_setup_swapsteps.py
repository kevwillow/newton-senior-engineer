"""Guards for swap-key sub-steps 1 to 4 that the first tests left
open (design 8.3).

Test touch-up after a planted-defect run: an
unreadable key that went on with an empty blob, an already-swapped check that
ignored the inventory key_file or one field of the restricted hello, a prev
file that kept the mode of the live file, a failed proof that removed a line
this run had not added, and a dead-man start that hid a failed router call
all survived the unit tests.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_router_setup_units import (  # noqa: E402,F401
	router_unit, _install_code_files, PLAIN_BLOB, SWAP_NONCE, SWAP_EXTRA)

AK = "etc/dropbear/authorized_keys"
PREV = "etc/dropbear/authorized_keys.newton-prev"


def _hand_swap(router_unit):
	"""Install the code files, prepare the new key and leave the router as
	a finished swap would: the plain line gone, the new line present.
	Returns (keyfile, new_line)."""
	router = router_unit.router
	_install_code_files(router, router_unit.tmp)
	r = router_unit.run(
		"LABEL=newton-agent\nNEW_KEY=1\nswap_prepare\n"
		"printf 'KEYFILE_OUT=%s\\n' \"$KEYFILE\"\n"
		"printf 'NEW_LINE_OUT=%s\\n' \"$NEW_LINE\"\n")
	assert r.returncode == 0, r.stderr
	out = dict(line.split("=", 1) for line in r.stdout.splitlines()
		if "=" in line)
	lines = [l for l in router.authorized_keys() if PLAIN_BLOB not in l]
	lines.append(out["NEW_LINE_OUT"])
	router.write(AK, "\n".join(lines) + "\n", 0o600)
	return out["KEYFILE_OUT"], out["NEW_LINE_OUT"]


def _already(router_unit, keyfile, dev_key_file):
	r = router_unit.run(
		"LABEL=newton-agent\nKEYFILE=%s\nswap_prepare\n"
		"DEV_KEY_FILE=%s\nswap_already_done; echo rc=$?\n"
		% (keyfile, dev_key_file))
	assert r.returncode == 0, r.stderr
	return r.stdout.splitlines()[-1]


# sub-step 1: an unreadable key must stop the action, not go on with an
# empty blob (a die inside $(...) only ends the subshell)

def test_swap_prepare_unreadable_plain_key_dies(router_unit):
	bad = router_unit.tmp / "not-a-key"
	bad.write_text("this is not a private key\n")
	bad.chmod(0o600)
	r = router_unit.run(
		"LABEL=newton-agent\nNEW_KEY=1\nPLAIN_KEY=%s\nswap_prepare; echo rc=$?\n"
		% bad)
	assert r.returncode == 2
	assert "cannot read the public key" in r.stderr
	assert "rc=" not in r.stdout


def test_swap_prepare_unreadable_new_key_dies(router_unit):
	# the key pair for the label exists but its private file is garbage
	router_unit.keys.mkdir(exist_ok=True)
	key = router_unit.keys / "r1-newton-agent"
	key.write_text("this is not a private key\n")
	key.chmod(0o600)
	r = router_unit.run("LABEL=newton-agent\nswap_prepare; echo rc=$?\n")
	assert r.returncode == 2
	assert "cannot read the public key" in r.stderr
	assert "rc=" not in r.stdout


# the already-swapped test needs every part of its evidence

def test_swap_already_done_needs_the_inventory_key_file(router_unit):
	keyfile, _ = _hand_swap(router_unit)
	assert _already(router_unit, keyfile, keyfile) == "rc=0"
	assert _already(router_unit, keyfile, "''") == "rc=1"
	assert _already(router_unit, keyfile, "/some/other/key") == "rc=1"


@pytest.mark.parametrize("lie", [
	"caller=somebody-else", "role=read", "door=root", "mode=test",
])
def test_swap_already_done_checks_every_hello_field(router_unit, lie):
	keyfile, _ = _hand_swap(router_unit)
	router_unit.router.write("etc/newton/fixture-lie", lie + "\n")
	assert _already(router_unit, keyfile, keyfile) == "rc=1"


# sub-step 2: the prev file is private whatever the live file's mode

def test_swap_stage_prev_is_mode_600_even_when_live_is_644(router_unit):
	router = router_unit.router
	router.add_authorized_key(SWAP_EXTRA)
	router.write(AK, router.read(AK), 0o644)
	r = router_unit.run(
		"LABEL=newton-agent\nNEW_KEY=1\nswap_prepare\n"
		"swap_stage_new_line; echo rc=$?\n")
	assert r.returncode == 0, r.stderr
	assert r.stdout.splitlines()[-1] == "rc=0"
	assert (router.path(PREV).stat().st_mode & 0o777) == 0o600


# sub-step 3: a failed proof removes the new line only when this run added it

def test_swap_prove_failure_keeps_a_line_this_run_did_not_add(router_unit):
	router = router_unit.router
	_install_code_files(router, router_unit.tmp, program="broken")
	r = router_unit.run(
		"ACTION=swap-key\nLABEL=newton-agent\nNEW_KEY=1\nswap_prepare\n"
		"swap_stage_new_line\n"
		"SWAP_APPENDED=0\n"            # as in a second run, the line was there
		"swap_prove_new_key\n")
	assert r.returncode == 1
	lines = r.stdout.splitlines()
	assert lines[-1] == "STOPPED swap-key r1: the new key failed its proofs"
	assert ("NOTE state: the new line was already there and was left in place"
		in lines)
	assert any("newton-router-newton-agent" in l
		for l in router.authorized_keys())


# sub-step 4: a failed router call is not hidden

def test_swap_start_deadman_returns_the_router_call_status(router_unit):
	router = router_unit.router
	# the plain key is no longer accepted, so the admin call fails (255)
	lines = [l for l in router.authorized_keys() if PLAIN_BLOB not in l]
	router.write(AK, "\n".join(lines) + ("\n" if lines else ""), 0o600)
	r = router_unit.run("swap_start_deadman %s; echo rc=$?\n" % SWAP_NONCE)
	assert r.returncode == 0
	assert r.stdout.splitlines()[-1] != "rc=0"
	assert router.timers() == []


# sub-steps 6 to 8: the same fields, the same evidence

def _confirm(router_unit, keyfile, code):
	r = router_unit.run(
		"ACTION=swap-key\nLABEL=newton-agent\nKEYFILE=%s\nswap_prepare\n%s"
		% (keyfile, code))
	assert r.returncode == 0, r.stderr
	return r.stdout.splitlines()[-1]


def test_swap_confirm_new_key_passes_on_a_good_swap(router_unit):
	keyfile, _ = _hand_swap(router_unit)
	assert _confirm(router_unit, keyfile,
		"swap_confirm_new_key %s; echo rc=$?\n" % SWAP_NONCE) == "rc=0"


@pytest.mark.parametrize("lie", [
	"caller=somebody-else", "role=read", "door=root", "mode=test",
])
def test_swap_confirm_new_key_checks_every_field(router_unit, lie):
	keyfile, _ = _hand_swap(router_unit)
	router_unit.router.write("etc/newton/fixture-lie", lie + "\n")
	assert _confirm(router_unit, keyfile,
		"swap_confirm_new_key %s; echo rc=$?\n" % SWAP_NONCE) == "rc=1"


def test_swap_settle_checks_the_new_key_again(router_unit):
	keyfile, _ = _hand_swap(router_unit)
	router_unit.router.write("etc/newton/fixture-lie", "caller=somebody-else\n")
	assert _confirm(router_unit, keyfile, "swap_settle; echo rc=$?\n") == "rc=1"


def test_swap_settle_checks_the_old_key_again(router_unit):
	keyfile, _ = _hand_swap(router_unit)
	# the knob keeps the plain key valid although its line is gone
	router_unit.router.update_state(ghost_blobs=[PLAIN_BLOB])
	assert _confirm(router_unit, keyfile, "swap_settle; echo rc=$?\n") == "rc=1"


def test_swap_settle_passes_on_a_good_swap(router_unit):
	keyfile, _ = _hand_swap(router_unit)
	assert _confirm(router_unit, keyfile, "swap_settle; echo rc=$?\n") == "rc=0"


def test_swap_recover_says_so_when_the_file_is_not_the_prev(router_unit):
	router = router_unit.router
	# the plain key works at once, and there is no prev (or a different one)
	router.write(PREV, "something else entirely\n", 0o600)
	r = router_unit.run("ACTION=swap-key\nswap_recover\n")
	assert r.returncode == 1
	lines = r.stdout.splitlines()
	assert any(l.startswith("NOTE state:") and "differs" in l for l in lines), lines
	assert not any("restored by the dead-man switch" in l for l in lines)
	assert lines[-1] == "STOPPED swap-key r1: the new key was not proven in time"
	assert router.clock() >= 120


def test_swap_recover_waits_for_deadman_when_plain_key_already_works(router_unit):
	router = router_unit.router
	live = router.read(AK)
	router.write(PREV, live, 0o600)
	router.add_authorized_key("ssh-ed25519 AAAALIVEONLY live-only")
	r = router_unit.run(
		"ACTION=swap-key\n"
		"swap_start_deadman 0123456789abcdef0123456789abcdef\n"
		"swap_recover\n"
	)
	assert r.returncode == 1
	assert "NOTE state: restored by the dead-man switch; the old key works again" in r.stdout
	assert r.stdout.splitlines()[-1] == (
		"STOPPED swap-key r1: the new key was not proven in time")
	assert 90 <= router.clock() <= 100
	assert router.read(AK) == router.read(PREV)


# sub-step 5: the replaced file is private (the router shell runs with umask 022,
# so only the explicit chmod makes it 0600; touch-up after a planted
# defect that dropped the chmod survived because the fake used the tool's umask)

def test_swap_replace_leaves_the_live_file_mode_600(router_unit):
	router = router_unit.router
	router.add_authorized_key(SWAP_EXTRA)
	router.write(AK, router.read(AK), 0o644)
	r = router_unit.run(
		"LABEL=newton-agent\nNEW_KEY=1\nswap_prepare\nswap_stage_new_line\n"
		"swap_replace_key_lines; echo rc=$?\n")
	assert r.returncode == 0, r.stderr
	assert r.stdout.splitlines()[-1] == "rc=0"
	assert (router.path(AK).stat().st_mode & 0o777) == 0o600
	assert not router.path(AK + ".new").exists()
