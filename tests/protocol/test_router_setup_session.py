"""Cross-cutting session tests for scripts/newton-router-setup."""

import hashlib
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from router_setup_env import build_src, pulsar_env, setup_env  # noqa: E402,F401
from test_router_setup_install import GOOD_PW, no_dot_files, seed_known_hosts  # noqa: E402
from test_router_setup_keys import direct_fake_ssh  # noqa: E402


PASSPHRASE = "pp-one-é"
PRIVATE_KEY_MARKER = "FAKE-OPENSSH-PRIVATE-KEY"


def approval_key(device):
	return hashlib.pbkdf2_hmac(
		"sha256", PASSPHRASE.encode(),
		("newton-approve-v1:%s" % device).encode(), 600000, 32).hex()


def run(env, *args, typed=(GOOD_PW,), src=None):
	extra = {"NEWTON_SETUP_SRC": str(src)} if src else None
	return env.run("r1", *args, typed=typed, env=extra)


def src2(tmp):
	src = build_src(Path(tmp) / "src2", version="2.0.0")
	for rel in (
		"scripts/owrt-safe-apply.sh",
		"device/openwrt/newton-guard/newton-guard",
		"device/openwrt/newton-guard/newton-guard.init",
	):
		path = src / rel
		path.write_text(path.read_text() + "# v2\n")
	return src


def assert_tmp_clean(env):
	assert os.listdir(env.tmpdir) == []


def assert_ok(env, result):
	assert result.rc == 0, result.err
	assert_tmp_clean(env)
	return result


def assert_session_secret_hygiene(env, results, secrets):
	all_output = "".join(result.out + result.err for result in results)
	for secret in secrets:
		assert secret not in all_output
	for call in env.router.calls():
		argv = "\0".join(str(value) for value in call.get("argv", ()))
		assert not any(secret in argv for secret in secrets)
		assert call.get("leaks") in (None, [])
	assert env.leaks() == []


def call_kind(call):
	for key in ("kind", "tool", "program", "command"):
		value = call.get(key)
		if isinstance(value, str) and os.path.basename(value) in {"ssh", "scp", "sftp"}:
			return os.path.basename(value)
	argv = call.get("argv") or ()
	if argv and os.path.basename(str(argv[0])) in {"ssh", "scp", "sftp"}:
		return os.path.basename(str(argv[0]))
	return None


def test_lab_whole_session_secrets_and_known_hosts(setup_env):
	env = setup_env
	k = approval_key("r1")
	secrets = (GOOD_PW, PASSPHRASE, k)
	env.register_secrets(*secrets)
	second = src2(env.tmp / "second")
	results = []

	def step(*args, typed=(GOOD_PW,), src=None):
		if args and args[0] == "install":
			typed = typed + ("yes",)
		result = assert_ok(env, run(env, *args, typed=typed, src=src))
		results.append(result)
		return result

	step("check")
	step("install")
	step("approval-key", typed=(GOOD_PW, PASSPHRASE, PASSPHRASE))
	assert env.router.read("etc/newton/approve.key").rstrip("\n") == k
	step("add-key", "--new-key", "newton-agent", "change")
	step("add-key", "--new-key", "lab-runner", "change")
	step("profile", "prod")
	step("profile", "lab")
	step("upgrade", src=second)
	step("rollback")
	step("revoke", "lab-runner")
	step("uninstall")

	env.router.update_state(host_key="ssh-ed25519 AAAAC3NEWHOSTKEY9999")
	before = env.router.snapshot()
	rotated = run(env, "check")
	results.append(rotated)
	assert rotated.rc != 0
	assert env.router.snapshot() == before
	assert_tmp_clean(env)

	transports = [call for call in env.router.calls() if call_kind(call)]
	assert transports
	accept_new = [call for call in transports if call.get("strict") == "accept-new"]
	assert len(accept_new) == 1
	assert call_kind(accept_new[0]) == "ssh"
	assert accept_new[0] in results[0].calls
	for call in transports:
		if call is not accept_new[0]:
			assert call.get("strict") == "yes"
		assert call.get("known_hosts") == str(env.known_hosts)

	assert_session_secret_hygiene(env, results, secrets)


def test_pulsar_whole_session_has_no_secret_or_private_key_output(pulsar_env):
	env = pulsar_env
	k = approval_key("pulsar")
	secrets = (GOOD_PW, PASSPHRASE, k)
	env.register_secrets(*secrets)
	results = []

	result = env.run(
		"--plain-key", str(env.plain_key), "pulsar", "check",
		typed=(GOOD_PW,))
	results.append(assert_ok(env, result))
	for action, typed in (
		(("install",), ("yes",)),
		(("approval-key",), (PASSPHRASE, PASSPHRASE)),
		(("swap-key", "--new-key"), ()),
	):
		results.append(assert_ok(
			env, env.run("--plain-key", str(env.plain_key), "pulsar", *action,
			             typed=typed)))

	new_key = env.keys_dir / "pulsar-newton-agent"
	hello = direct_fake_ssh(
		env, new_key, "hello " + ("0" * 32))
	assert hello.returncode == 0, hello.stderr
	assert_tmp_clean(env)
	all_output = "".join(result.out + result.err for result in results)
	all_output += hello.stdout + hello.stderr
	assert PRIVATE_KEY_MARKER not in all_output
	assert_session_secret_hygiene(env, results, secrets)


def test_every_repeated_action_is_idempotent(setup_env):
	env = setup_env
	seed_known_hosts(env)
	assert_ok(env, run(env, "install", typed=(GOOD_PW, "yes")))
	assert_ok(
		env, run(env, "approval-key",
		         typed=(GOOD_PW, PASSPHRASE, PASSPHRASE)))
	assert_ok(env, run(env, "add-key", "--new-key", "newton-agent", "change"))
	assert_ok(env, run(env, "add-key", "--new-key", "lab-runner", "change"))

	for args, typed, source, stop_text in (
		(("install",), (GOOD_PW, "yes"), None, None),
		(("approval-key",), (GOOD_PW, PASSPHRASE, PASSPHRASE), None, None),
		(("add-key", "newton-agent", "change"), (GOOD_PW,), None,
		 "the router already has a Newton key line for label newton-agent; "
		 "revoke it first"),
		(("profile", "lab"), (GOOD_PW,), None, None),
		(("upgrade",), (GOOD_PW,), env.src, None),
		(("revoke", "missing-label"), (GOOD_PW,), None, None),
	):
		before = env.router.snapshot()
		result = run(env, *args, typed=typed, src=source)
		if stop_text is None:
			assert_ok(env, result)
		else:
			assert result.rc == 1, result.out + result.err
			assert stop_text in result.out
			assert_tmp_clean(env)
		after = env.router.snapshot()
		assert after == before, args
		assert no_dot_files(after) == []


ACTIONS = (
	("install",),
	("approval-key",),
	("add-key", "xy", "change"),
	("revoke", "xy"),
	("profile", "lab"),
	("upgrade",),
	("rollback",),
	("uninstall",),
	("lab-snapshot", "--skip-gates"),
)


def prepare_lab(env):
	"""A complete lab toml, so that lab-snapshot gets past its lab checks
	(they run before the known_hosts gate) and reaches the gate."""
	lab = env.tmp / "lab"
	lab.mkdir()
	files = {"pve.token": "PVEAPIToken=claude@pve!newton=00000000-fake-token",
	         "pve.pin": "sha256//FAKEPINFAKEPINFAKEPIN=", "approve.pw": "labpass"}
	for name, text in files.items():
		(lab / name).write_text(text + "\n")
		(lab / name).chmod(0o600)
	env.lab_toml.write_text(
		'[pve]\nhost = "192.0.2.11"\nnode = "Apollo"\n'
		'token_file = "%s"\npin_file = "%s"\n\n'
		'[ssh]\napprove_passphrase_file = "%s"\n\n'
		'[devices.r1]\nvmid = 9102\nsnapshot = "baseline-pw"\n'
		% (lab / "pve.token", lab / "pve.pin", lab / "approve.pw"))


@pytest.mark.parametrize("action", ACTIONS, ids=lambda action: action[0])
def test_actions_require_known_hosts_and_known_device(setup_env, action):
	env = setup_env
	prepare_lab(env)
	assert not env.known_hosts.exists()
	result = env.run("r1", *action, typed=())
	assert_tmp_clean(env)
	unknown = env.run("unknown-device", *action, typed=())
	assert_tmp_clean(env)
	assert result.rc == 2, action
	assert "run check first" in result.err
	assert result.calls == []
	assert unknown.rc == 2, action
	assert unknown.calls == []
	assert env.router.calls() == []


def shell_function_by_line(lines):
	functions = {}
	current = None
	for number, line in enumerate(lines, 1):
		match = re.match(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{", line)
		if match:
			current = match.group(1)
		functions[number] = current
		if current and re.match(r"^\s*}\s*$", line):
			current = None
	return functions


def uncommented(line):
	return line.split("#", 1)[0]


def test_tool_static_lint():
	tool = Path(os.environ.get("ROUTER_SETUP_TOOL") or "scripts/newton-router-setup")
	parsed = subprocess.run(
		["bash", "-n", str(tool)], capture_output=True, text=True, timeout=30)
	assert parsed.returncode == 0, parsed.stderr
	text = tool.read_text()
	lines = text.splitlines()
	function_at = shell_function_by_line(lines)

	# Prevent construction or execution of shell text through eval.
	assert re.search(r"\beval\b", text) is None

	# Prevent legacy command substitution outside explanatory comments.
	assert all("`" not in uncommented(line) for line in lines)

	# Keep waits injectable and confine literal sleep use to approved text/code.
	sleep_assignments = []
	for number, line in enumerate(lines, 1):
		code = uncommented(line)
		if not re.search(r"\bsleep\b", code):
			continue
		if "SLEEP=" in code:
			sleep_assignments.append(number)
			continue
		assert function_at[number] in {"wait_local", "deadman_text",
			"swap_deadman_tools"}, (number, line)
	assert len(sleep_assignments) == 2

	# Force every network client through a timeout, common options, and a wrapper.
	allowed = {"rsh_key", "rsh_pw", "rscp_key", "rsftp_key", "forward_ssh_start"}
	for number, line in enumerate(lines, 1):
		try:
			lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|(){}")
			lexer.commenters = "#"
			lexer.whitespace_split = True
			tokens = list(lexer)
		except ValueError:
			continue
		segments = [[]]
		for token in tokens:
			if token and all(char in ";&|(){}" for char in token):
				segments.append([])
			else:
				segments[-1].append(token)
		for segment in segments:
			while segment and (segment[0] in {"if", "then", "do", "!", "command"}
			                   or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", segment[0])):
				segment = segment[1:]
			if len(segment) < 2:
				# a lone word `ssh` is data (a quoted toml key in the embedded
				# python), not a call: a real call has options and a target
				continue
			clients = [client for client in ("ssh", "scp", "sftp")
			           if client in segment]
			if segment[0] not in {"timeout", "ssh", "scp", "sftp"} or not clients:
				continue
			client = clients[0]
			assert segment[0] == "timeout", (number, line)
			assert '"${SSH_OPTS[@]}"' in line, (number, line)
			function = function_at[number]
			assert function in allowed or (function or "").startswith("proof_"), (number, line)

	# Never print a root password, API token, or derived approval key to a sink.
	for number, line in enumerate(lines, 1):
		code = uncommented(line)
		if not re.search(r"(^|[;|&]\s*)(echo|printf)\b", code):
			continue
		if not re.search(r"\$(?:\{|)(ROOT_PW|PVE_TOKEN|K)(?:\}|\b)", code):
			continue
		secret_end = max(code.rfind(name) for name in ("ROOT_PW", "PVE_TOKEN", "K"))
		pipe = code.find("|", secret_end)
		assert pipe >= 0 and code[pipe + 1:].strip(), (number, line)
