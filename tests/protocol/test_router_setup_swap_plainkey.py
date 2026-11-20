"""swap-key says, before it changes anything, that it removes the plain key
from the router, and needs the owner's yes or an explicit flag
(an owner who passed their own admin key as --plain-key
lost root SSH without a word of warning).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from router_setup_env import pulsar_env  # noqa: F401,E402
from test_router_setup_swap import install_pulsar  # noqa: E402


def warning(env):
	return ("swap-key removes the plain key %s from the router: after the "
	        "swap that key no longer logs in as root. If it is your own admin "
	        "key, keep another way in (LuCI or the console) or use a separate "
	        "setup key" % env.plain_key)


def unswapped(env, before):
	assert env.router.read("etc/dropbear/authorized_keys") == before
	assert not env.router.path(
		"etc/dropbear/authorized_keys.newton-prev").exists()


def test_swap_key_asks_before_removing_the_plain_key_and_a_no_stops(pulsar_env):
	env = pulsar_env
	install_pulsar(env)
	before = env.router.read("etc/dropbear/authorized_keys")
	r = env.run("--plain-key", env.plain_key, "pulsar", "swap-key",
	            "--new-key", typed=("n",))
	assert r.rc == 1, r.out
	lines = r.out.splitlines()
	assert "NOTE " + warning(env) in lines
	assert "Remove the plain key %s from the router? (y/N) " % env.plain_key in r.err
	assert lines[-1] == ("STOPPED swap-key pulsar: the plain key was not "
	                     "removed; nothing changed")
	assert "NOTE state: router unchanged" in lines
	assert not any(l.startswith("PASS swap step 2") for l in lines)
	unswapped(env, before)


def test_swap_key_without_a_terminal_needs_the_flag(pulsar_env):
	env = pulsar_env
	install_pulsar(env)
	before = env.router.read("etc/dropbear/authorized_keys")
	r = env.run("--plain-key", env.plain_key, "pulsar", "swap-key",
	            "--new-key", env={"NEWTON_SETUP_TTY": ""})
	assert r.rc == 1, r.out
	lines = r.out.splitlines()
	assert "NOTE " + warning(env) in lines
	assert lines[-1] == (
		"STOPPED swap-key pulsar: no terminal to ask before the plain key "
		"%s is removed; pass --remove-plain-key to swap-key to go ahead"
		% env.plain_key)
	unswapped(env, before)


def test_swap_key_goes_ahead_on_a_yes(pulsar_env):
	env = pulsar_env
	install_pulsar(env)
	r = env.run("--plain-key", env.plain_key, "pulsar", "swap-key",
	            "--new-key", typed=("y",))
	assert r.rc == 0, r.out
	lines = r.out.splitlines()
	assert lines.index("NOTE " + warning(env)) < next(
		i for i, l in enumerate(lines) if l.startswith("PASS swap step 2"))
	assert lines[-1] == "DONE swap-key pulsar"


def test_swap_key_goes_ahead_with_the_flag_and_still_says_it(pulsar_env):
	env = pulsar_env
	install_pulsar(env)
	r = env.run("--plain-key", env.plain_key, "pulsar", "swap-key",
	            "--new-key", "--remove-plain-key", env={"NEWTON_SETUP_TTY": ""})
	assert r.rc == 0, r.out
	assert "NOTE " + warning(env) in r.out.splitlines()
	assert "(y/N)" not in r.err
	assert r.out.splitlines()[-1] == "DONE swap-key pulsar"
