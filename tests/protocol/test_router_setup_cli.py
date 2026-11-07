"""CLI tests for scripts/newton-router-setup (,
2.1, 2.2 first paragraph, 2.4 prerequisite): argument parsing, the seam gate,
inventory loading, admin path choice, action stubs and temp dir cleanup.
No fake router is used; the tool never reaches a router step here."""

import os
import subprocess
from pathlib import Path

import pytest

from router_setup_env import SetupEnv, setup_env  # noqa: F401

TOOL = Path(__file__).resolve().parents[2] / "scripts" / "newton-router-setup"

LAB_BODY = 'host = "192.168.1.1"\nuser = "root"\nauth = "password"\nprofile = "lab"\n'
PROD_BODY = LAB_BODY.replace('profile = "lab"', 'profile = "prod"')


def write_inventory(tmp_path, body=LAB_BODY, device="r1"):
    inv = tmp_path / "devices.toml"
    inv.write_text("[devices.%s]\n%s" % (device, body))
    # write_text creates 0666 & ~umask, i.e. 0664 under umask 0002, which the
    # inventory-file check in scripts/newton-router-setup refuses; pin it.
    inv.chmod(0o644)
    return inv


def base_env(tmp_path, inventory):
    env = {k: v for k, v in os.environ.items() if not k.startswith("NEWTON_")}
    env["NEWTON_INVENTORY"] = str(inventory)
    env["TMPDIR"] = str(tmp_path)
    # State-dir isolation: scripts/newton-router-setup resolves its
    # state dir from NEWTON_STATE_DIR (else `$(home_dir)/.local/state/newton`
    # via getent passwd), and the inline python helper in
    # approval_fingerprint_write falls back to Path.home().  Point both
    # at per-call tmp dirs so a stray write stays inside the tmp tree.
    env["NEWTON_STATE_DIR"] = str(tmp_path / "state")
    env["HOME"] = str(tmp_path / "home")
    return env


def run_tool(env, *args):
    return subprocess.run(
        [str(TOOL), *args], env=env, capture_output=True, text=True, timeout=60
    )


@pytest.mark.parametrize("flag", ["-h", "--help"])
def test_help_exit_zero(tmp_path, flag):
    env = base_env(tmp_path, tmp_path / "unused.toml")
    r = run_tool(env, flag)
    assert r.returncode == 0
    assert "newton-router-setup" in r.stdout
    assert "ACTION:" in r.stdout
    assert r.stderr == ""


def test_no_args(tmp_path):
    env = base_env(tmp_path, tmp_path / "devices.toml")
    r = run_tool(env)
    assert r.returncode == 2
    assert "newton-router-setup" in r.stderr


def test_unknown_action(tmp_path):
    inv = write_inventory(tmp_path)
    env = base_env(tmp_path, inv)
    r = run_tool(env, "r1", "dance")
    assert r.returncode == 2
    assert "newton-router-setup" in r.stderr


@pytest.mark.parametrize(
    "args",
    [
        ("check", "x"),
        ("install", "x"),
        ("upgrade", "x"),
        ("rollback", "x"),
        ("uninstall", "x"),
        ("approval-key", "x"),
        ("approval-key", "--passphrase-file"),
        ("swap-key", "new", "old"),
        ("add-key", "newton-agent"),
        ("add-key", "newton-agent", "change", "x"),
        ("revoke",),
        ("revoke", "newton-agent", "x"),
        ("profile",),
        ("profile", "lab", "x"),
    ],
)
def test_wrong_argument_counts(tmp_path, args):
    inv = write_inventory(tmp_path)
    env = base_env(tmp_path, inv)
    r = run_tool(env, "r1", *args)
    assert r.returncode == 2
    assert "newton-router-setup" in r.stderr


@pytest.mark.parametrize("device", ["R1", "r_1", "1r", "-r1"])
def test_bad_device(tmp_path, device):
    inv = write_inventory(tmp_path)
    env = base_env(tmp_path, inv)
    r = run_tool(env, device, "check")
    assert r.returncode == 2
    # a leading dash reads as an option, anything else as a bad device name
    assert ("unknown option" if device.startswith("-") else "bad device") in r.stderr


@pytest.mark.parametrize("label", ["1abc", "Newton", "a", "newton_agent"])
def test_bad_label(tmp_path, label):
    inv = write_inventory(tmp_path)
    env = base_env(tmp_path, inv)
    r = run_tool(env, "r1", "add-key", label, "change")
    assert r.returncode == 2
    assert "bad label" in r.stderr


def test_bad_role(tmp_path):
    inv = write_inventory(tmp_path)
    env = base_env(tmp_path, inv)
    r = run_tool(env, "r1", "add-key", "newton-agent", "admin")
    assert r.returncode == 2
    assert "bad role" in r.stderr


def test_seam_without_marker(tmp_path):
    inv = write_inventory(tmp_path)
    env = base_env(tmp_path, inv)
    env["NEWTON_SETUP_BIN"] = str(tmp_path / "bin")
    r = run_tool(env, "r1", "check")
    assert r.returncode == 2
    assert "NEWTON_SETUP_* variables need NEWTON_SETUP_SEAMS=1" in r.stderr


def test_seams_marker_first_stderr_line(tmp_path):
    inv = write_inventory(tmp_path)
    env = base_env(tmp_path, inv)
    env["NEWTON_SETUP_SEAMS"] = "1"
    env["NEWTON_SETUP_BIN"] = str(tmp_path / "bin")
    r = run_tool(env, "r1", "check")
    assert r.stderr.splitlines()[0] == "note: test seams active"


def test_getent_failure_for_default_home_exits_two(tmp_path):
	inv = write_inventory(tmp_path)
	fake_bin = tmp_path / "bin"
	fake_bin.mkdir()
	getent = fake_bin / "getent"
	getent.write_text("#!/bin/sh\nexit 2\n")
	getent.chmod(0o755)
	env = base_env(tmp_path, inv)
	env["NEWTON_SETUP_SEAMS"] = "1"
	env["NEWTON_SETUP_BIN"] = str(fake_bin)
	r = run_tool(env, "r1", "check")
	assert r.returncode == 2
	assert "cannot find the home directory of " in r.stderr


def test_inventory_missing_file(tmp_path):
    env = base_env(tmp_path, tmp_path / "nope.toml")
    r = run_tool(env, "r1", "check")
    assert r.returncode == 2
    assert r.stderr.startswith("error:")


def test_inventory_unknown_device(tmp_path):
    inv = write_inventory(tmp_path, device="r1")
    env = base_env(tmp_path, inv)
    r = run_tool(env, "r2", "check")
    assert r.returncode == 2
    assert r.stderr.startswith("error:")


@pytest.mark.parametrize(
    "body, message",
    [
        ('user = "root"\n', "bad host"),
        ('host = "bad host!"\nuser = "root"\n', "bad host"),
        ('host = "192.168.1.1"\nuser = "labuser"\n', "user must be root"),
        ('host = "192.168.1.1"\nprofile = "dev"\n', "bad profile"),
        ('host = "192.168.1.1"\nauth = "token"\n', "bad auth"),
        ('host = "192.168.1.1"\nport = 70000\n', "bad port"),
        ('host = "192.168.1.1"\nmgmt_zone = "bad zone!"\n', "bad mgmt_zone"),
        ('host = "192.168.1.1"\nwan_zones = []\n', "bad wan_zones"),
        ('host = "192.168.1.1"\nwan_zones = ["a", "b", "c", "d", "e"]\n', "bad wan_zones"),
        ('host = "192.168.1.1"\nkey_file = "/tmp/a b"\n', "bad key_file"),
    ],
)
def test_inventory_bad_values(tmp_path, body, message):
    inv = write_inventory(tmp_path, body)
    env = base_env(tmp_path, inv)
    r = run_tool(env, "r1", "check")
    assert r.returncode == 2
    assert r.stderr.startswith("error:")
    assert message in r.stderr


def test_password_file_on_prod(tmp_path):
    inv = write_inventory(tmp_path, PROD_BODY)
    pw = tmp_path / "pw"
    pw.write_text("secret\n")
    os.chmod(pw, 0o600)
    env = base_env(tmp_path, inv)
    r = run_tool(env, "--password-file", str(pw), "r1", "check")
    assert r.returncode == 2
    assert "--password-file" in r.stderr


def test_password_file_wrong_mode(tmp_path):
    inv = write_inventory(tmp_path, LAB_BODY)
    pw = tmp_path / "pw"
    pw.write_text("secret\n")
    os.chmod(pw, 0o644)
    env = base_env(tmp_path, inv)
    r = run_tool(env, "--password-file", str(pw), "r1", "check")
    assert r.returncode == 2
    assert "0600" in r.stderr


def test_admin_plain_key_missing_file(tmp_path):
    inv = write_inventory(tmp_path, LAB_BODY)
    env = base_env(tmp_path, inv)
    missing = tmp_path / "no-such-key"
    r = run_tool(env, "--admin", "plain-key", "--plain-key", str(missing), "r1", "check")
    assert r.returncode == 2
    assert "--plain-key" in r.stderr


def test_action_without_known_hosts(tmp_path):
    inv = write_inventory(tmp_path, LAB_BODY)
    keys = tmp_path / "keys"
    keys.mkdir()
    env = base_env(tmp_path, inv)
    env["NEWTON_KEYS_DIR"] = str(keys)
    r = run_tool(env, "r1", "upgrade")
    assert r.returncode == 2
    assert "run check first" in r.stderr


@pytest.mark.parametrize("name", ["bad key", "bad'key", "bad$key"])
def test_plain_key_rejects_special_characters(tmp_path, name):
	inv = write_inventory(tmp_path, LAB_BODY)
	env = base_env(tmp_path, inv)
	r = run_tool(
		env, "--admin", "plain-key", "--plain-key", str(tmp_path / name), "r1", "check"
	)
	assert r.returncode == 2
	assert "--plain-key" in r.stderr


@pytest.mark.parametrize("name", ["bad pw", "bad'pw", "bad$pw"])
def test_password_file_rejects_special_characters(tmp_path, name):
	inv = write_inventory(tmp_path, LAB_BODY)
	env = base_env(tmp_path, inv)
	r = run_tool(env, "--password-file", str(tmp_path / name), "r1", "check")
	assert r.returncode == 2
	assert "--password-file" in r.stderr


def test_no_temp_dir_left_behind(tmp_path):
    inv = write_inventory(tmp_path, LAB_BODY)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    env = base_env(tmp_path, inv)
    env["TMPDIR"] = str(scratch)
    before = sorted(os.listdir(scratch))
    run_tool(env, "--help")
    run_tool(env, "r1", "check")
    run_tool(env, "bad_device", "check")
    run_tool(env)
    assert sorted(os.listdir(scratch)) == before


def prepare_lab_snapshot_env(env):
    env.known_hosts.write_text(
        "10.1.2.3 %s\n" % env.router.state()["host_key"])
    passphrase = env.typed_file.parent / "approve-passphrase"
    passphrase.write_text("test-passphrase\n")
    passphrase.chmod(0o600)
    token = env.tmp / "pve.token"
    token.write_text(env.router.pve()["token"] + "\n")
    pin = env.tmp / "pve.pin"
    pin.write_text(env.router.pve()["pin"] + "\n")
    env.lab_toml.write_text(
        '[pve]\n'
        'host = "192.0.2.11"\n'
        'node = "%s"\n'
        'token_file = "%s"\n'
        'pin_file = "%s"\n'
        '\n[devices.r1]\n'
        'vmid = 9102\n'
        '\n[ssh]\n'
        'approve_passphrase_file = "%s"\n'
        % (env.router.pve()["node"], token, pin, passphrase)
    )


def test_action_lab_snapshot_end_to_end_with_skip_gates(setup_env):
    env = setup_env
    prepare_lab_snapshot_env(env)
    r = env.run(
            "r1", "lab-snapshot", "--new-key", "--skip-gates",
        typed=(env.router.state()["root_password"],),
    )

    assert r.rc == 0, (r.out, r.err)
    assert "PASS snapshot baseline-newton-1-0-0 created" in r.out.splitlines()
    assert env.router.snapshots(9102) == ["baseline-newton-1-0-0"]


def test_action_lab_snapshot_sends_gate_output_to_stderr(setup_env):
    env = setup_env
    prepare_lab_snapshot_env(env)
    gates = env.tmp / "snapshot-gates"
    gates.write_text(
        "#!/bin/sh\n"
        "printf 'noise\\n'\n"
        "printf 'noise\\n' >&2\n"
    )
    gates.chmod(0o755)

    r = env.run(
        "r1", "lab-snapshot", "--new-key", "--gates-cmd", str(gates),
        typed=(env.router.state()["root_password"],),
    )

    assert r.rc == 0, (r.out, r.err)
    assert "noise" not in r.out.splitlines()
    assert "noise" in r.err.splitlines()


def test_approval_key_passphrase_file_prod_fails_before_password_prompt(
        tmp_path):
    env = SetupEnv(tmp_path, profile="prod")
    env.known_hosts.write_text(
        "10.1.2.3 %s\n" % env.router.state()["host_key"])
    passphrase = env.typed_file.parent / "approve-passphrase"
    passphrase.write_text("test-passphrase\n")
    passphrase.chmod(0o600)

    r = env.run(
        "r1", "approval-key", "--passphrase-file", str(passphrase),
        typed=(),
    )

    assert r.rc == 2
    assert "--passphrase-file is allowed only when the inventory profile is lab" \
        in r.err
    assert "root password:" not in r.err


def test_lab_snapshot_prod_fails_before_password_prompt(tmp_path):
    env = SetupEnv(tmp_path, profile="prod")
    env.known_hosts.write_text(
        "10.1.2.3 %s\n" % env.router.state()["host_key"])

    r = env.run("r1", "lab-snapshot", "--skip-gates", typed=())

    assert r.rc == 2
    assert "lab-snapshot works only on a device whose inventory profile is lab" \
        in r.err
    assert "root password:" not in r.err
