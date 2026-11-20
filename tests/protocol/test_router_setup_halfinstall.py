"""A half-finished install (an interrupted install, or a config file lost
afterwards) is named by check, and no stray `.new` upload is left behind
by uninstall or a re-run of install.

check: when the router program or the guard is on the router but one of
/etc/newton/device-id, profile or zones is missing, check FAILs with
`not fully installed` and names the install command.
uninstall and install: every `.new` a cut-off upload can leave next to a
code file (program, helper, guard, its init, the WAN-health tool and its
init) is removed.
"""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from router_setup_env import setup_env  # noqa: F401
from test_router_setup_install import (  # noqa: E402
	install_ok, run_install, seed_known_hosts, GOOD_PW)

CODE_PATHS = (
	"usr/libexec/newton/newton-router",
	"usr/libexec/newton/newton-safe-apply",
	"usr/libexec/newton-guard",
	"etc/init.d/newton-guard",
	"usr/libexec/newton/newton-wan-health",
	"etc/init.d/newton-wan-health",
)

CONFIG_FILES = ("device-id", "profile", "zones")


def run_check(env):
	return env.run(env.device, "check", typed=(GOOD_PW,))


@pytest.mark.parametrize("name", CONFIG_FILES)
def test_check_fails_when_a_config_file_is_missing(setup_env, name):
	env = setup_env
	install_ok(env)
	os.unlink(env.router.path("etc/newton/%s" % name))
	r = run_check(env)
	assert r.rc == 1, r.out + r.err
	assert ("FAIL not fully installed: /etc/newton/%s is missing; run "
	        "install again (sudo -u newton /usr/local/bin/newton-router-setup "
	        "r1 install)" % name) in r.out.splitlines()
	assert r.out.splitlines()[-1] == "STOPPED check r1: check found a problem"


def test_check_names_every_missing_config_file_with_only_the_program(setup_env):
	"""An install cut off after the program upload: no guard, no config."""
	env = setup_env
	seed_known_hosts(env)
	env.router.write("usr/libexec/newton/newton-router", "#!/bin/sh\n", 0o755)
	r = run_check(env)
	assert r.rc == 1, r.out + r.err
	assert ("FAIL not fully installed: /etc/newton/device-id "
	        "/etc/newton/profile /etc/newton/zones is missing; run install "
	        "again (sudo -u newton /usr/local/bin/newton-router-setup r1 "
	        "install)") in r.out.splitlines()


def test_check_of_a_full_install_is_not_flagged(setup_env):
	env = setup_env
	install_ok(env)
	r = run_check(env)
	assert not [l for l in r.out.splitlines() if "not fully installed" in l]
	assert r.out.splitlines()[-1] == "DONE check r1", r.out


def test_check_of_a_router_without_newton_is_not_flagged(setup_env):
	env = setup_env
	seed_known_hosts(env)
	r = run_check(env)
	assert r.rc == 0, r.out + r.err
	assert not [l for l in r.out.splitlines() if "not fully installed" in l]


@pytest.mark.parametrize("path", CODE_PATHS)
def test_uninstall_removes_a_stray_new_upload(setup_env, path):
	env = setup_env
	install_ok(env)
	env.router.write(path + ".new", "cut-off upload\n", 0o600)
	r = env.run("r1", "uninstall", typed=(GOOD_PW,))
	assert r.rc == 0, r.out + r.err
	assert path + ".new" not in env.router.snapshot()


@pytest.mark.parametrize("path", CODE_PATHS)
def test_install_again_clears_a_stray_new_upload(setup_env, path):
	"""On a re-run every code file is already identical, so no upload
	overwrites the stray .new; the install clears it first."""
	env = setup_env
	install_ok(env)
	env.router.write(path + ".new", "cut-off upload\n", 0o600)
	r = run_install(env)
	assert r.rc == 0, r.out + r.err
	assert path + ".new" not in env.router.snapshot()
