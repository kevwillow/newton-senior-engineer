"""Tests of the key label of scripts/newton-router-setup: the label a router is
enrolled with is newton-agent, and a label the owner types is used as typed."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from router_setup_env import build_src, pulsar_env, setup_env  # noqa: E402,F401
from test_router_setup_keys import direct_fake_ssh  # noqa: E402
from test_router_setup_swap import install_pulsar, swap  # noqa: E402

# The label a router enrolled now carries.
DEFAULT_LABEL = "newton-agent"


def test_swap_key_default_label_is_newton_agent(pulsar_env):
	"""swap-key without a label enrols the router with newton-agent: the
	key file, the restricted line and the hello reply all carry it."""
	env = pulsar_env
	install_pulsar(env)

	r = swap(env, "--new-key")
	assert r.rc == 0, r.out + r.err

	key = env.keys_dir / ("pulsar-%s" % DEFAULT_LABEL)
	assert key.exists()
	ak = env.router.authorized_keys()
	assert len([l for l in ak if "newton-router-%s" % DEFAULT_LABEL in l]) == 1
	hello = direct_fake_ssh(env, key, "hello " + ("0" * 32))
	assert hello.returncode == 0, hello.stderr
	assert "caller=%s" % DEFAULT_LABEL in hello.stdout


def test_swap_key_explicit_label_is_used_as_typed(pulsar_env):
	"""swap-key with an explicit label enrols the router with that label,
	and no newton-agent key appears."""
	env = pulsar_env
	install_pulsar(env)

	r = swap(env, "--new-key", "lab-gate")
	assert r.rc == 0, r.out + r.err

	ak = env.router.authorized_keys()
	assert len([l for l in ak if "newton-router-lab-gate" in l]) == 1
	assert (env.keys_dir / "pulsar-lab-gate").exists()
	assert not (env.keys_dir / ("pulsar-%s" % DEFAULT_LABEL)).exists()
