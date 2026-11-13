"""Tests for newton-lab-test.py.

Each test fails when the behaviour it pins is removed. Test passphrases and
keys are made-up files written into tmp_path by the test itself; nothing is
read from a real secret on disk.
"""
from __future__ import annotations

from conftest import lab_toml_path

import hashlib
import hmac
import json
import os
import re
import subprocess
import time
import tomllib
from pathlib import Path
from unittest import mock

import pytest

import newton_lab_test as nl
from newton_mcp import approve

LAB_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = LAB_DIR.parent
ROUTER_PROG_FILE = REPO_ROOT / "device/openwrt/newton-router/newton-router"
SETUP_TOOL = REPO_ROOT / "scripts/newton-router-setup"
MODULE_PATH = LAB_DIR / "newton-lab-test.py"

LAB_TOML = lab_toml_path()
SCEN_DIR = LAB_DIR / "scenarios"


@pytest.fixture
def lab():
    return nl.load_lab(LAB_TOML)


@pytest.fixture
def scenarios():
    return nl.load_scenarios(SCEN_DIR)


_FULL_LAB_TOML = """
[pve]
host = "pve.test"
node = "lab"
token_file = "~/.config/pve/token"
pin_file = "~/.config/pve/pin"

[ssh]
proxy = "ssh -W %h:%p root@pve.test"
password_file = "~/.config/newton/lab-root.pw"
key = "~/.ssh/key"

[devices.lab-r1]
vmid = 9102
host = "10.109.0.11"
user = "root"
snapshot = "baseline"

[vars]

[checks.reg_ok]
device = "lab-r1"
cmd = "true"
description = "always passes"

[regression]
default = ["reg_ok"]
"""


@pytest.fixture
def full_lab(tmp_path):
    lab_toml = tmp_path / "lab.toml"
    lab_toml.write_text(_FULL_LAB_TOML)
    return lab_toml


def _cp(stdout: str = "", stderr: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(args=[], returncode=returncode,
                                       stdout=stdout, stderr=stderr)


def _read_program_version() -> str:
    """The router program's version literal in its hello line.

    The current program stores it as `version=1.0.0` inside the hello line;
    we extract whatever sits between `version=` and the next space.
    """
    text = ROUTER_PROG_FILE.read_text()
    m = re.search(r"version=([A-Za-z0-9._+-]+)", text)
    assert m, "no version= field in the router program file"
    return m.group(1)


def _make_passphrase_file(tmp_path: Path, *, body: bytes = b"unit-test-pw\n"
                          ) -> Path:
    p = tmp_path / "lab-approve.pw"
    p.write_bytes(body)
    return p


def _make_router_key_file(tmp_path: Path) -> Path:
    p = tmp_path / "router.key"
    p.write_bytes(b"fake-router-key\n")
    p.chmod(0o600)
    return p


def _make_lab_toml(tmp_path: Path, *, router_key: str,
                   approve_passphrase_file: str,
                   known_hosts: str = "",
                   snapshot: str = "baseline-newton-1-0-0",
                   device_name: str = "lab-r1") -> Path:
    lab_toml = tmp_path / "lab.toml"
    lab_toml.write_text(
        f"""
[pve]
host = "pve.test"
node = "lab"
token_file = "~/.config/pve/token"
pin_file = "~/.config/pve/pin"

[ssh]
proxy = "ssh -W %h:%p root@pve.test"
password_file = "~/.config/newton/lab-root.pw"
key = "~/.ssh/key"
router_key = "{router_key}"
approve_passphrase_file = "{approve_passphrase_file}"
{f'known_hosts = "{known_hosts}"' if known_hosts else '# known_hosts not set'}

[devices.{device_name}]
vmid = 9102
host = "10.109.0.11"
user = "root"
snapshot = "{snapshot}"

[vars]
"""
    )
    return lab_toml


# ============================================================================
# Item 1: lab.toml fields + scenario loader
# ============================================================================

def test_load_lab_parses_router_key_and_passphrase_and_known_hosts(tmp_path):
    """[ssh] router_key, approve_passphrase_file, known_hosts all read and
    `~`-expanded like the other ssh paths."""
    rk = _make_router_key_file(tmp_path)
    pp = _make_passphrase_file(tmp_path)
    kh = tmp_path / "router.known_hosts"
    kh.write_text("lab-r1 ssh-ed25519 FAKE\n")
    lab_toml = _make_lab_toml(tmp_path, router_key=str(rk),
                              approve_passphrase_file=str(pp),
                              known_hosts=str(kh))
    lab = nl.load_lab(lab_toml)
    assert lab.router_key == str(rk)
    assert lab.approve_passphrase_file == str(pp)
    assert lab.known_hosts == str(kh)


def test_load_lab_defaults_router_key_and_passphrase_and_known_hosts_to_empty(
    tmp_path,
):
    """When [ssh] omits the new keys, the lab still loads with empty strings
    (so a password-only run can use the same code path)."""
    lab_toml = tmp_path / "lab.toml"
    lab_toml.write_text("""
[pve]
host = "pve.test"
node = "lab"
token_file = "~/.config/pve/token"
pin_file = "~/.config/pve/pin"
[ssh]
proxy = "ssh -W %h:%p root@pve.test"
password_file = "~/.config/newton/lab-root.pw"
key = "~/.ssh/key"
[devices.lab-r1]
vmid = 9102
host = "10.109.0.11"
user = "root"
snapshot = "baseline"
[vars]
""")
    lab = nl.load_lab(lab_toml)
    assert lab.router_key == ""
    assert lab.approve_passphrase_file == ""
    assert lab.known_hosts == ""


def test_lab_toml_snapshot_matches_setup_pve_snapshot_name(tmp_path):
    """lab.toml's lab-r1 snapshot is pve_snapshot_name(<program version>).

    Sources the REAL setup script and asks its pve_snapshot_name for the
    version extracted from the router program. A regression that drops the
    lab-r1 snapshot name, or drifts away from setup's formula, fails this.
    """
    raw = tomllib.loads(LAB_TOML.read_text())
    actual = raw["devices"]["lab-r1"]["snapshot"]
    version = _read_program_version()
    # Source scripts/newton-router-setup and call its pve_snapshot_name.
    rc = subprocess.run(
        ["bash", "-c", f'. "{SETUP_TOOL}"\nprintf "%s\\n" '
                       f'"$(pve_snapshot_name "{version}")"'],
        env={**os.environ, "NEWTON_SETUP_SEAMS": "1"},
        capture_output=True, text=True, timeout=20,
    )
    assert rc.returncode == 0, (rc.stdout, rc.stderr)
    expected = rc.stdout.strip()
    assert actual == expected, (
        f"lab.toml lab-r1 snapshot {actual!r} != "
        f"pve_snapshot_name({version!r}) = {expected!r}")


def test_mgmt_ssh_newton_is_in_regression_default(lab):
    """The new mgmt_ssh_newton check is defined and joined to regression default."""
    assert "mgmt_ssh_newton" in lab.checks
    assert "mgmt_ssh_newton" in lab.regression_default
    # mgmt_ssh and mgmt_ssh_pw stay
    assert "mgmt_ssh" in lab.checks
    assert "mgmt_ssh_pw" in lab.checks


# ============================================================================
# Item 2: build_env per lane
# ============================================================================

def test_build_env_password_lane_does_not_set_key(tmp_path):
    """Password lane: OWRT_SSH_PASSWORD_FILE is set to lab.ssh_password_file;
    OWRT_SSH_KEY is not; OWRT_EXPECT_DEVICE and OWRT_EXPECT_PROFILE are set."""
    pp = _make_passphrase_file(tmp_path)
    lab_toml = _make_lab_toml(tmp_path, router_key=str(_make_router_key_file(tmp_path)),
                              approve_passphrase_file=str(pp))
    lab = nl.load_lab(lab_toml)
    env = nl.build_env(lab, lane="password", device_name="lab-r1")
    assert env["OWRT_SSH_PASSWORD_FILE"] == lab.ssh_password_file
    assert "OWRT_SSH_KEY" not in env
    assert env["OWRT_EXPECT_DEVICE"] == "lab-r1"
    assert env["OWRT_EXPECT_PROFILE"] == "lab"


def test_build_env_scrubs_an_inherited_approval_token_and_window(
    tmp_path, monkeypatch
):
    """The runner never lets the operator's shell supply approval state:
    a stale token, NBF or EXP is dropped before apply_batch sets its own
    (SW2 Item 2)."""
    monkeypatch.setenv("OWRT_APPROVAL_TOKEN", "e" * 64)
    monkeypatch.setenv("OWRT_APPROVAL_NBF", "1790000000")
    monkeypatch.setenv("OWRT_APPROVAL_EXP", "1790001800")
    pp = _make_passphrase_file(tmp_path)
    lab_toml = _make_lab_toml(tmp_path, router_key=str(_make_router_key_file(tmp_path)),
                              approve_passphrase_file=str(pp))
    lab = nl.load_lab(lab_toml)
    env = nl.build_env(lab, lane="password", device_name="lab-r1")
    assert "OWRT_APPROVAL_TOKEN" not in env
    assert "OWRT_APPROVAL_NBF" not in env
    assert "OWRT_APPROVAL_EXP" not in env


def test_build_env_key_lane_sets_key_and_device(tmp_path):
    """Key lane: OWRT_SSH_KEY is set to lab.router_key; password file is not;
    OWRT_EXPECT_DEVICE/OWRT_EXPECT_PROFILE are set; OWRT_APPROVAL_TOKEN is not."""
    rk = _make_router_key_file(tmp_path)
    pp = _make_passphrase_file(tmp_path)
    lab_toml = _make_lab_toml(tmp_path, router_key=str(rk),
                              approve_passphrase_file=str(pp))
    lab = nl.load_lab(lab_toml)
    env = nl.build_env(lab, lane="key", device_name="lab-r1")
    assert env["OWRT_SSH_KEY"] == str(rk)
    assert "OWRT_SSH_PASSWORD_FILE" not in env
    assert env["OWRT_EXPECT_DEVICE"] == "lab-r1"
    assert env["OWRT_EXPECT_PROFILE"] == "lab"
    assert "OWRT_APPROVAL_TOKEN" not in env


def test_build_env_key_lane_with_known_hosts(tmp_path):
    """Key lane + known_hosts: OWRT_KNOWN_HOSTS is set to the lab path."""
    rk = _make_router_key_file(tmp_path)
    pp = _make_passphrase_file(tmp_path)
    kh = tmp_path / "router.known_hosts"
    kh.write_text("lab-r1 ssh-ed25519 FAKE\n")
    lab_toml = _make_lab_toml(tmp_path, router_key=str(rk),
                              approve_passphrase_file=str(pp),
                              known_hosts=str(kh))
    lab = nl.load_lab(lab_toml)
    env = nl.build_env(lab, lane="key", device_name="lab-r1")
    assert env["OWRT_KNOWN_HOSTS"] == str(kh)


def test_main_key_lane_without_router_key_is_usage_error(tmp_path, capsys):
    """`--lane key` with no router_key set is a clear usage error (rc=2)."""
    kh = tmp_path / "lab.known"
    kh.write_text("lab-r1 ssh-ed25519 FAKE\n")
    lab_toml = _make_lab_toml(tmp_path, router_key="",
                              approve_passphrase_file="",
                              known_hosts=str(kh))
    # write a scenario so load_scenarios has something to load
    scens = tmp_path / "scenarios"
    scens.mkdir()
    (scens / "01-x.toml").write_text(
        'name = "01-x"\ntarget = "lab-r1"\nreset = []\n'
        'expect = "none"\ntimeout = 60\nbatch = ""\n')
    with mock.patch.object(nl, "RESULTS_DIR", tmp_path / "results"):
        rc = nl.main(["--lab", str(lab_toml), "--scenarios", str(scens),
                      "--lane", "key", "--no-lab-reset"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "router_key" in err
    assert "lane" in err.lower()


def test_main_key_lane_without_known_hosts_is_usage_error(tmp_path, capsys):
    """`--lane key` with no [ssh] known_hosts is a usage error (rc=2) before
    anything else runs: no scenario is loaded, no reset is attempted."""
    rk = _make_router_key_file(tmp_path)
    pp = _make_passphrase_file(tmp_path)
    lab_toml = _make_lab_toml(tmp_path, router_key=str(rk),
                              approve_passphrase_file=str(pp))
    scens = tmp_path / "scenarios"
    scens.mkdir()
    (scens / "01-x.toml").write_text(
        'name = "01-x"\ntarget = "lab-r1"\nreset = []\n'
        'expect = "none"\ntimeout = 60\nbatch = ""\n')
    with mock.patch.object(nl, "RESULTS_DIR", tmp_path / "results"):
        rc = nl.main(["--lab", str(lab_toml), "--scenarios", str(scens),
                      "--lane", "key", "--no-lab-reset"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "[ssh] known_hosts" in err
    assert "lab-r1" in err
    assert "lab setup" in err


def test_main_password_lane_does_not_require_known_hosts(tmp_path, capsys):
    """The known_hosts gate is specific to --lane key; --lane password runs
    with no [ssh] known_hosts (the password lane does not ssh to lab-r1 with
    StrictHostKeyChecking=yes)."""
    lab_toml = _make_lab_toml(tmp_path, router_key="",
                              approve_passphrase_file="")
    scens = tmp_path / "scenarios"
    scens.mkdir()
    (scens / "01-x.toml").write_text(
        'name = "01-x"\ntarget = "lab-r1"\nreset = []\n'
        'expect = "none"\ntimeout = 60\nbatch = ""\n')
    pve_status = {"status": "stopped", "exitstatus": "OK"}

    def fake_run(args, env=None, **_kw):
        if args[0] == "curl":
            return _cp(stdout=json.dumps({"data": "UPID:abc"}))
        return _cp(stdout="fingerprint\n", returncode=0)

    with mock.patch.object(nl, "_run", side_effect=fake_run), \
         mock.patch.object(nl, "pve_wait_task", return_value=pve_status), \
         mock.patch.object(nl, "RESULTS_DIR", tmp_path / "results"):
        rc = nl.main(["--lab", str(lab_toml), "--scenarios", str(scens),
                      "--lane", "password", "--no-lab-reset"])
    assert rc == 0
    err = capsys.readouterr().err
    assert "[ssh] known_hosts" not in err


# ============================================================================
# Item 3: plan_batch probe file
# ============================================================================

def test_plan_batch_writes_probes_file_0600_and_deletes(tmp_path, lab):
    """plan_batch with probes: 5th arg is the probe file path, body is
    TAB-joined LF-terminated, mode is 0600, and the file is removed after."""
    captured = {}

    def fake_run(args, **_kw):
        captured["args"] = args
        captured["path"] = args[5]
        captured["mode"] = Path(args[5]).stat().st_mode & 0o777
        captured["body"] = Path(args[5]).read_text()
        return _cp(stdout="STAGED session=" + "a" * 32)

    probes = [["conf-has", "dnsmasq", "substr", "present", "MAC"],
              ["nft-rule", "inet", "fw4", "ruleset", "present", "dport 2222"]]
    with mock.patch.object(nl, "_run", side_effect=fake_run):
        rc, out, err = nl.plan_batch(lab, lab.devices["lab-r1"], "set foo=bar",
                                     probes=probes, timeout_s=60,
                                     lane="password")
    assert rc == 0
    assert len(captured["args"]) == 6   # prog plan router changes timeout probes
    assert captured["args"][5] == captured["path"]
    assert captured["args"][5] != captured["args"][3]   # not the changes file
    assert captured["mode"] == 0o600
    # TAB-joined LF-terminated
    assert captured["body"] == (
        "conf-has\tdnsmasq\tsubstr\tpresent\tMAC\n"
        "nft-rule\tinet\tfw4\truleset\tpresent\tdport 2222\n")
    # After plan_batch returns, the probe file is gone (changes file too).
    assert not Path(captured["args"][5]).exists()
    assert not Path(captured["args"][3]).exists()


def test_plan_batch_no_probes_no_fifth_argument(tmp_path, lab):
    """No probes: plan gets 4 args (prog, plan, router, changes, timeout); no
    probe file is created or passed."""
    captured = {}

    def fake_run(args, **_kw):
        captured["args"] = args
        return _cp(stdout="STAGED session=" + "b" * 32)

    with mock.patch.object(nl, "_run", side_effect=fake_run):
        rc, out, err = nl.plan_batch(lab, lab.devices["lab-r1"], "set foo=bar",
                                     probes=None, timeout_s=60,
                                     lane="password")
    assert rc == 0
    assert len(captured["args"]) == 5
    assert captured["args"][4] == "60"


def test_plan_batch_passes_scenario_timeout(tmp_path, lab):
    """plan_batch accepts timeout_s; the value lands on the command line."""
    captured = {}

    def fake_run(args, **_kw):
        captured["args"] = args
        return _cp(stdout="STAGED session=" + "c" * 32)

    with mock.patch.object(nl, "_run", side_effect=fake_run):
        nl.plan_batch(lab, lab.devices["lab-r1"], "set foo=bar",
                      timeout_s=45, lane="password")
    assert captured["args"][4] == "45"


# ============================================================================
# Item 4: apply_batch no check + approval
# ============================================================================

def test_apply_batch_has_no_check_argument_and_timeout_is_t_plus_300(lab):
    """apply_batch: only 5 args (prog, apply, router, sid, timeout); no 6th
    'check' arg; subprocess timeout is timeout_s + 300."""
    sid = "d" * 32
    with mock.patch.object(nl, "_run", return_value=_cp(
            stdout=f"CONFIRMED session={sid}")) as m:
        nl.apply_batch(lab, lab.devices["lab-r1"], sid, 60, lane="password")
    args = m.call_args[0][0]
    assert args[0] == str(nl.OWRT_CHANGE)
    assert args[1] == "apply"
    assert args[2] == "root@10.109.0.11"
    assert args[3] == sid
    assert args[4] == "60"
    assert len(args) == 5
    assert m.call_args.kwargs["timeout"] == 60 + 300


def test_apply_batch_key_lane_includes_expect_device(tmp_path, lab):
    """Key lane: env must include OWRT_SSH_KEY and the device name."""
    sid = "e" * 32
    captured = {}

    def fake_run(args, env=None, **_kw):
        captured["env"] = env
        return _cp(stdout=f"CONFIRMED session={sid}")

    with mock.patch.object(nl, "_run", side_effect=fake_run):
        nl.apply_batch(lab, lab.devices["lab-r1"], sid, 60, lane="key")
    assert captured["env"]["OWRT_SSH_KEY"] == lab.router_key
    assert captured["env"]["OWRT_EXPECT_DEVICE"] == "lab-r1"
    assert captured["env"]["OWRT_EXPECT_PROFILE"] == "lab"


def test_apply_batch_sets_owrt_approval_token(tmp_path, lab):
    """When a token is given, the apply env carries OWRT_APPROVAL_TOKEN
    plus the window the token binds (SW2 Item 2)."""
    sid = "f" * 32
    captured = {}

    def fake_run(args, env=None, **_kw):
        captured["env"] = env
        return _cp(stdout=f"CONFIRMED session={sid}")

    with mock.patch.object(nl, "_run", side_effect=fake_run):
        nl.apply_batch(lab, lab.devices["lab-r1"], sid, 60,
                       lane="password",
                       token="0" * 64,
                       window=(1790000000, 1790001800))
    assert captured["env"]["OWRT_APPROVAL_TOKEN"] == "0" * 64
    assert captured["env"]["OWRT_APPROVAL_NBF"] == "1790000000"
    assert captured["env"]["OWRT_APPROVAL_EXP"] == "1790001800"


def test_apply_batch_sets_a_fresh_window_when_none_is_given(tmp_path, lab):
    """No window given: the runner mints one from the clock, so the two
    env values are 10 decimal digits, ordered, and inside the router's
    3600 s cap."""
    sid = "f" * 32
    captured = {}

    def fake_run(args, env=None, **_kw):
        captured["env"] = env
        return _cp(stdout=f"CONFIRMED session={sid}")

    with mock.patch.object(nl, "_run", side_effect=fake_run):
        nl.apply_batch(lab, lab.devices["lab-r1"], sid, 60, token="0" * 64)
    env = captured["env"]
    assert re.fullmatch(r"[1-9][0-9]{9}", env["OWRT_APPROVAL_NBF"])
    assert re.fullmatch(r"[1-9][0-9]{9}", env["OWRT_APPROVAL_EXP"])
    nbf, exp = int(env["OWRT_APPROVAL_NBF"]), int(env["OWRT_APPROVAL_EXP"])
    assert nbf <= int(time.time()) <= exp
    assert exp - nbf <= 3600


def test_apply_batch_without_a_token_sends_no_window(tmp_path, lab):
    """No token (approval not required): nothing new reaches the env, so
    the wrapper defaults NBF/EXP to 0 0."""
    sid = "f" * 32
    captured = {}

    def fake_run(args, env=None, **_kw):
        captured["env"] = env
        return _cp(stdout=f"CONFIRMED session={sid}")

    with mock.patch.object(nl, "_run", side_effect=fake_run):
        nl.apply_batch(lab, lab.devices["lab-r1"], sid, 60)
    assert "OWRT_APPROVAL_TOKEN" not in captured["env"]
    assert "OWRT_APPROVAL_NBF" not in captured["env"]
    assert "OWRT_APPROVAL_EXP" not in captured["env"]


def test_approval_window_helper_is_now_plus_thirty_minutes():
    nbf, exp = nl.approval_window()
    assert isinstance(nbf, int) and isinstance(exp, int)
    assert re.fullmatch(r"[1-9][0-9]{9}", str(nbf))
    assert exp - nbf == 1800
    assert nbf <= int(time.time()) + 2


def test_approval_token_for_mints_over_a_window():
    """approval_token_for is the one crypto: same value as calling
    approve.approval_token with the same window."""
    k = approve.derive_k(b"unit-test-passphrase", "lab-r1")
    digest = "0a" * 32
    window = (1790000000, 1790001800)
    assert nl.approval_token_for(k, digest, window) == approve.approval_token(
        k, digest, *window
    )


# ============================================================================
# Item 4: derive_k + approval_token via the same module newton-approve uses
# ============================================================================

def test_approval_k_matches_derive_k(tmp_path, lab):
    """The lab's _approval_k derives the same K as approve.derive_k from
    the same passphrase and device (one shared implementation)."""
    passphrase_bytes = b"unit-test-passphrase"
    pp = tmp_path / "lab-approve.pw"
    pp.write_bytes(passphrase_bytes + b"\n")   # trailing LF, stripped by reader
    # re-load the lab to pick up the new passphrase_file
    lab_toml = _make_lab_toml(tmp_path, router_key=str(_make_router_key_file(tmp_path)),
                              approve_passphrase_file=str(pp))
    lab2 = nl.load_lab(lab_toml)
    k_from_lab = nl._approval_k(lab2, "lab-r1", cache=None)
    k_from_module = approve.derive_k(passphrase_bytes, "lab-r1")
    assert k_from_lab == k_from_module


def test_approval_token_matches_hand_computed_value(tmp_path, lab):
    """approval_token == hmac(K bytes, 'newton-approval-v2\\n' + digest +
    '\\n' + NBF + '\\n' + EXP + '\\n') -- SW2 Item 2 binds the window."""
    passphrase = b"unit-test-passphrase"
    device = "lab-r1"
    digest = "0a" * 32
    nbf, exp = 1790000000, 1790001800
    pp = tmp_path / "lab-approve.pw"
    pp.write_bytes(passphrase + b"\n")
    lab_toml = _make_lab_toml(tmp_path, router_key=str(_make_router_key_file(tmp_path)),
                              approve_passphrase_file=str(pp))
    lab2 = nl.load_lab(lab_toml)
    k = nl._approval_k(lab2, device, cache=None)
    token = approve.approval_token(k, digest, nbf, exp)
    # hand-computed using the same recipe
    k_bytes = bytes.fromhex(k)
    expected = hmac.new(
        k_bytes,
        b"newton-approval-v2\n" + digest.encode("ascii") + b"\n"
        + str(nbf).encode("ascii") + b"\n" + str(exp).encode("ascii") + b"\n",
        hashlib.sha256,
    ).hexdigest()
    assert token == expected
    # pinned literal, computed outside the implementation
    assert expected == "3b2db3f986ad3600daf3c0ce5cd8828a63bf83c3a3b67ebf0377a54562b5c626"
    # the v1 domain over the same digest is NOT the token any more
    v1 = hmac.new(
        k_bytes,
        b"newton-approval-v1\n" + digest.encode("ascii") + b"\n",
        hashlib.sha256,
    ).hexdigest()
    assert token != v1
    # and a moved window is a different token (the window binding)
    assert token != approve.approval_token(k, digest, nbf, exp - 1)


def test_wrong_token_changes_only_last_hex_digit():
    """wrong_token: a well-formed token whose last hex digit differs."""
    t = "0123456789abcdef" * 4
    bad = nl.wrong_token(t)
    assert bad != t
    assert bad[:-1] == t[:-1]
    # last char of bad is a hex digit and != t[-1]
    assert re.fullmatch(r"[0-9a-f]", bad[-1])
    assert bad[-1] != t[-1]


def test_g3_self_check_approval_none_sends_no_token(tmp_path):
    """approval = "none" with router-required: the apply env has NO
    OWRT_APPROVAL_TOKEN (the router will refuse it, but the runner still
    records the outcome)."""
    pp = tmp_path / "lab-approve.pw"
    pp.write_bytes(b"unit-test-pp\n")
    rk = tmp_path / "rk"
    rk.write_bytes(b"k\n")
    lab_toml = _make_lab_toml(
        tmp_path, router_key=str(rk), approve_passphrase_file=str(pp),
        snapshot="baseline")
    base = lab_toml.read_text()
    lab_toml.write_text(base + """
[checks.reg_ok]
device = "lab-r1"
cmd = "true"
description = "always passes"

[regression]
default = ["reg_ok"]
""")
    sid = "8" * 32
    (tmp_path / "scenarios").mkdir(exist_ok=True)
    (tmp_path / "scenarios" / "01-x.toml").write_text(
        'name = "01-x"\ndescription = "x"\ntarget = "lab-r1"\n'
        'reset = []\nexpect = "refused"\ntimeout = 60\n'
        'batch = "set foo=bar"\napproval = "none"\n'
        'refuse_match = "needs-approval"\n'
        '[[post]]\ndevice = "lab-r1"\ncmd = "true"\n')
    lab = nl.load_lab(lab_toml)
    scen = nl.load_scenarios(tmp_path / "scenarios")[0]
    assert scen.approval == "none"
    apply_env: dict = {}

    def fake_run(args, env=None, **_kw):
        if args[1] == "plan":
            return _cp(stdout=_ok_plan_output(sid, approval="required"))
        if args[1] == "apply":
            apply_env["env"] = env
            return _cp(returncode=1, stderr=(
                "ERROR: apply refused, nothing applied: needs-approval\n"))
        if args[1] == "abort":
            return _cp(returncode=0)
        return _cp(returncode=0)

    with mock.patch.object(nl, "_run", side_effect=fake_run):
        rec = nl.run_scenario(lab, scen)
    assert rec["outcome"] == "refused"
    assert rec["refuse"]["matched"] is True
    # OWRT_APPROVAL_TOKEN is absent on the apply env
    assert "OWRT_APPROVAL_TOKEN" not in (apply_env.get("env") or {})


def test_g3_self_check_approval_wrong_sends_wrong_token(tmp_path):
    """approval = "wrong": the apply gets a well-formed token whose last hex
    digit differs; the router refuses with bad-approval."""
    pp = tmp_path / "lab-approve.pw"
    pp.write_bytes(b"unit-test-pp\n")
    rk = tmp_path / "rk"
    rk.write_bytes(b"k\n")
    lab_toml = _make_lab_toml(
        tmp_path, router_key=str(rk), approve_passphrase_file=str(pp),
        snapshot="baseline")
    base = lab_toml.read_text()
    lab_toml.write_text(base + """
[checks.reg_ok]
device = "lab-r1"
cmd = "true"
description = "always passes"

[regression]
default = ["reg_ok"]
""")
    sid = "9" * 32
    (tmp_path / "scenarios").mkdir(exist_ok=True)
    (tmp_path / "scenarios" / "01-x.toml").write_text(
        'name = "01-x"\ndescription = "x"\ntarget = "lab-r1"\n'
        'reset = []\nexpect = "refused"\ntimeout = 60\n'
        'batch = "set foo=bar"\napproval = "wrong"\n'
        'refuse_match = "bad-approval"\n'
        '[[post]]\ndevice = "lab-r1"\ncmd = "true"\n')
    lab = nl.load_lab(lab_toml)
    scen = nl.load_scenarios(tmp_path / "scenarios")[0]
    assert scen.approval == "wrong"
    k = nl._approval_k(lab, "lab-r1", cache=None)
    digest = "0a" * 32
    # and the apply env sees the wrong token (NOT the right one)
    apply_env: dict = {}

    def fake_run(args, env=None, **_kw):
        if args[1] == "plan":
            return _cp(stdout=_ok_plan_output(sid, approval="required"))
        if args[1] == "apply":
            apply_env["env"] = env
            return _cp(returncode=1, stderr=(
                "ERROR: apply refused, nothing applied: bad-approval\n"))
        if args[1] == "abort":
            return _cp(returncode=0)
        return _cp(returncode=0)

    with mock.patch.object(nl, "_run", side_effect=fake_run):
        rec = nl.run_scenario(lab, scen)
    assert rec["outcome"] == "refused"
    env = apply_env["env"]
    sent = env["OWRT_APPROVAL_TOKEN"]
    # the window the token was minted over travels with it (SW2 Item 2)
    nbf = int(env["OWRT_APPROVAL_NBF"])
    exp = int(env["OWRT_APPROVAL_EXP"])
    assert exp - nbf == 1800
    assert nbf <= int(time.time()) <= exp
    # the right token over THAT window, and the sent one is only its last
    # hex digit flipped
    right_token = approve.approval_token(k, digest, nbf, exp)
    assert sent != right_token
    assert sent[:-1] == right_token[:-1]
    assert nl.wrong_token(right_token) == sent


def test_approval_k_is_cached_per_device_per_run(tmp_path, lab):
    """Two calls with the same cache dict re-derive only once per device
    (verified by counting file reads of the passphrase)."""
    pp = tmp_path / "lab-approve.pw"
    pp.write_bytes(b"unit-test-passphrase\n")
    lab_toml = _make_lab_toml(tmp_path, router_key=str(_make_router_key_file(tmp_path)),
                              approve_passphrase_file=str(pp))
    lab2 = nl.load_lab(lab_toml)
    cache: dict[str, str] = {}
    with mock.patch.object(nl.approve, "read_passphrase_file",
                           wraps=nl.approve.read_passphrase_file) as spy:
        k1 = nl._approval_k(lab2, "lab-r1", cache)
        k2 = nl._approval_k(lab2, "lab-r1", cache)
        k3 = nl._approval_k(lab2, "lab-r1", cache)
    assert k1 == k2 == k3
    assert spy.call_count == 1   # derived once and cached
    assert cache == {"lab-r1": k1}


# ============================================================================
# Item 4: G3 self-check (router says required, scenario says approved)
# ============================================================================

def _ok_plan_output(sid: str, *, approval: str) -> str:
    """The plan output the runner parses: STAGED session=..., then PLANDIGEST
    and APPROVAL lines that classify_apply / the G3 self-check expect."""
    digest = "0a" * 32
    return (
        f"STAGED session={sid}\n"
        f"PROBES 0 {digest}\n"
        f"PROFILE lab\n"
        f"PLANDIGEST {digest}\n"
        f"APPROVAL {approval}\n"
        f"BASEHASH {'b' * 64}\n"
        "----- diff -----\nset foo=bar\n----------------\n"
    )


def test_g3_self_check_scenario_must_be_approval_when_router_requires(
    tmp_path,
):
    """Plan says APPROVAL required but scenario omits approval: ERROR."""
    sid = "1" * 32
    pp = tmp_path / "lab-approve.pw"
    pp.write_bytes(b"unit-test-pp\n")
    rk = tmp_path / "rk"
    rk.write_bytes(b"k\n")
    lab_toml = _make_lab_toml(
        tmp_path, router_key=str(rk), approve_passphrase_file=str(pp),
        snapshot="baseline")
    base = lab_toml.read_text()
    lab_toml.write_text(base + """
[checks.reg_ok]
device = "lab-r1"
cmd = "true"
description = "always passes"

[regression]
default = ["reg_ok"]
""")
    (tmp_path / "scenarios").mkdir(exist_ok=True)
    (tmp_path / "scenarios" / "01-x.toml").write_text(
        'name = "01-x"\ndescription = "x"\ntarget = "lab-r1"\n'
        'reset = []\nexpect = "confirmed"\ntimeout = 60\n'
        'batch = "set foo=bar"\n'
        '[[post]]\ndevice = "lab-r1"\ncmd = "true"\n')
    lab = nl.load_lab(lab_toml)
    scen = nl.load_scenarios(tmp_path / "scenarios")[0]
    assert scen.approval is None
    with mock.patch.object(nl, "_run", return_value=_cp(
            stdout=_ok_plan_output(sid, approval="required"))):
        rec = nl.run_scenario(lab, scen)
    assert rec["error"] and "needs approval = true" in rec["error"]
    assert "APPROVAL required" in rec["error"]
    assert rec["outcome"] is None


def test_g3_self_check_approval_true_but_router_says_not_required(
    tmp_path,
):
    """Scenario says approval = true but plan says not-required: ERROR."""
    sid = "2" * 32
    pp = tmp_path / "lab-approve.pw"
    pp.write_bytes(b"unit-test-pp\n")
    rk = tmp_path / "rk"
    rk.write_bytes(b"k\n")
    lab_toml = _make_lab_toml(
        tmp_path, router_key=str(rk), approve_passphrase_file=str(pp),
        snapshot="baseline")
    base = lab_toml.read_text()
    lab_toml.write_text(base + """
[checks.reg_ok]
device = "lab-r1"
cmd = "true"
description = "always passes"

[regression]
default = ["reg_ok"]
""")
    (tmp_path / "scenarios").mkdir(exist_ok=True)
    (tmp_path / "scenarios" / "01-x.toml").write_text(
        'name = "01-x"\ndescription = "x"\ntarget = "lab-r1"\n'
        'reset = []\nexpect = "confirmed"\ntimeout = 60\n'
        'batch = "set foo=bar"\napproval = true\n'
        '[[post]]\ndevice = "lab-r1"\ncmd = "true"\n')
    lab = nl.load_lab(lab_toml)
    scen = nl.load_scenarios(tmp_path / "scenarios")[0]
    assert scen.approval is True
    with mock.patch.object(nl, "_run", return_value=_cp(
            stdout=_ok_plan_output(sid, approval="not-required"))):
        rec = nl.run_scenario(lab, scen)
    assert rec["error"] and "not-required" in rec["error"]
    assert rec["outcome"] is None


def test_g3_self_check_consistent_runs_apply_with_token(
    tmp_path,
):
    """approval = true AND router says required: apply gets a 64-hex token."""
    pp = tmp_path / "lab-approve.pw"
    pp.write_bytes(b"unit-test-passphrase\n")
    rk = tmp_path / "router.key"
    rk.write_bytes(b"fake\n")
    lab_toml = _make_lab_toml(
        tmp_path, router_key=str(rk), approve_passphrase_file=str(pp),
        snapshot="baseline")
    # add the [checks]/[regression] sections
    base = lab_toml.read_text()
    lab_toml.write_text(base + """
[checks.reg_ok]
device = "lab-r1"
cmd = "true"
description = "always passes"

[regression]
default = ["reg_ok"]
""")
    sid = "3" * 32
    (tmp_path / "scenarios").mkdir(exist_ok=True)
    (tmp_path / "scenarios" / "01-x.toml").write_text(
        'name = "01-x"\ndescription = "x"\ntarget = "lab-r1"\n'
        'reset = []\nexpect = "confirmed"\ntimeout = 60\n'
        'batch = "set foo=bar"\napproval = true\n'
        '[[post]]\ndevice = "lab-r1"\ncmd = "true"\n')
    lab = nl.load_lab(lab_toml)
    scen = nl.load_scenarios(tmp_path / "scenarios")[0]
    apply_env: dict = {}

    def fake_run(args, env=None, **_kw):
        if args[1] == "plan":
            return _cp(stdout=_ok_plan_output(sid, approval="required"))
        if args[1] == "apply":
            apply_env["args"] = args
            apply_env["env"] = env
            return _cp(
                stdout=f"APPLYBASE {'b' * 64}\nCONFIRMED session={sid}")
        return _cp(returncode=0)

    with mock.patch.object(nl, "_run", side_effect=fake_run):
        rec = nl.run_scenario(lab, scen)
    assert rec["passed"] is True
    assert rec["outcome"] == "confirmed"
    tok = apply_env["env"].get("OWRT_APPROVAL_TOKEN")
    assert tok is not None and re.fullmatch(r"[0-9a-f]{64}", tok)


# ============================================================================
# Item 5: refused outcome end-to-end with fakes
# ============================================================================

def test_refused_outcome_runs_abort_and_records_refuse_match(
    full_lab, tmp_path,
):
    """expect = 'refused' with refuse_match: apply exits with the refused
    message -> outcome 'refused'; runner calls abort; refuse_match is
    checked against apply stdout+stderr; PASS iff refuse_match matched."""
    sid = "4" * 32
    (tmp_path / "scenarios").mkdir(exist_ok=True)
    (tmp_path / "scenarios" / "01-x.toml").write_text(
        'name = "01-x"\ndescription = "x"\ntarget = "lab-r1"\n'
        'reset = []\nexpect = "refused"\ntimeout = 60\n'
        'batch = "set foo=bar"\n'
        'refuse_match = "token bad"\n'
        '[[post]]\ndevice = "lab-r1"\ncmd = "true"\n')
    lab = nl.load_lab(full_lab)
    scen = nl.load_scenarios(tmp_path / "scenarios")[0]
    calls: list[list[str]] = []

    def fake_run(args, env=None, **_kw):
        calls.append(args)
        if args[1] == "plan":
            return _cp(stdout=_ok_plan_output(sid, approval="not-required"))
        if args[1] == "apply":
            return _cp(returncode=1, stderr="ERROR: apply refused, nothing "
                                            "applied: token bad-approval\n")
        if args[1] == "abort":
            return _cp(returncode=0, stdout=f"aborted {sid} discarded\n")
        return _cp()

    with mock.patch.object(nl, "_run", side_effect=fake_run):
        rec = nl.run_scenario(lab, scen)
    assert rec["outcome"] == "refused"
    assert rec["passed"] is True
    # abort was called exactly once, with the SID
    abort_calls = [a for a in calls if a[1] == "abort"]
    assert len(abort_calls) == 1
    assert sid in abort_calls[0]
    # refuse_match was checked
    assert rec["refuse"] is not None and rec["refuse"]["matched"] is True


def test_refused_outcome_with_refuse_match_mismatch_fails(
    full_lab, tmp_path,
):
    """refuse_match is given but apply output does not contain it: outcome
    is 'refused' but rec['passed'] is False; rec['refuse']['matched'] is False."""
    sid = "5" * 32
    (tmp_path / "scenarios").mkdir(exist_ok=True)
    (tmp_path / "scenarios" / "01-x.toml").write_text(
        'name = "01-x"\ndescription = "x"\ntarget = "lab-r1"\n'
        'reset = []\nexpect = "refused"\ntimeout = 60\n'
        'batch = "set foo=bar"\n'
        'refuse_match = "this string never appears"\n'
        '[[post]]\ndevice = "lab-r1"\ncmd = "true"\n')
    lab = nl.load_lab(full_lab)
    scen = nl.load_scenarios(tmp_path / "scenarios")[0]

    def fake_run(args, env=None, **_kw):
        if args[1] == "plan":
            return _cp(stdout=_ok_plan_output(sid, approval="not-required"))
        if args[1] == "apply":
            return _cp(returncode=1, stderr="ERROR: apply refused, nothing "
                                            "applied: token bad-approval\n")
        return _cp()

    with mock.patch.object(nl, "_run", side_effect=fake_run):
        rec = nl.run_scenario(lab, scen)
    assert rec["outcome"] == "refused"
    assert rec["refuse"]["matched"] is False
    assert rec["passed"] is False
    # short_reason mentions the mismatch
    assert "refuse_match" in nl.short_reason(rec)


def test_classify_apply_refused_with_apply_refused_marker():
    sid = "0a" * 16
    assert nl.classify_apply(1, "", "ERROR: apply refused, nothing applied: "
                                    "approval-key-missing\n", sid) == "refused"


def test_probes_refused_classified_as_rejected(full_lab, tmp_path):
    """A plan that dies with 'probes refused:' is outcome 'rejected' and
    reject_match applies if set."""
    sid = "6" * 32
    (tmp_path / "scenarios").mkdir(exist_ok=True)
    (tmp_path / "scenarios" / "01-x.toml").write_text(
        'name = "01-x"\ndescription = "x"\ntarget = "lab-r1"\n'
        'reset = []\nexpect = "rejected"\ntimeout = 60\n'
        'batch = "set foo=bar"\n'
        'reject_match = "uci-equals refuses secret-looking options"\n'
        '[[post]]\ndevice = "lab-r1"\ncmd = "true"\n')
    lab = nl.load_lab(full_lab)
    scen = nl.load_scenarios(tmp_path / "scenarios")[0]
    def fake_run(args, **_kw):
        if args[0].endswith("owrt-change.sh"):
            return _cp(returncode=1, stderr=(
                "ERROR: probes refused: uci-equals refuses secret-looking "
                "options — staged change was discarded\n"))
        # any ssh call (the post)
        return _cp(returncode=0)
    with mock.patch.object(nl, "_run", side_effect=fake_run):
        rec = nl.run_scenario(lab, scen)
    assert rec["outcome"] == "rejected"
    assert rec["reject"]["matched"] is True
    assert rec["passed"] is True


# ============================================================================
# Item 5: lane overrides
# ============================================================================

def test_effective_expect_and_breaks_use_password_overrides_in_password_lane(
    full_lab, tmp_path,
):
    """expect_password replaces expect; breaks_password replaces breaks
    in the password lane; the key lane uses the defaults."""
    (tmp_path / "scenarios").mkdir(exist_ok=True)
    (tmp_path / "scenarios" / "01-x.toml").write_text(
        'name = "01-x"\ndescription = "x"\ntarget = "lab-r1"\n'
        'reset = []\nexpect = "rolled_back"\nexpect_password = "confirmed"\n'
        'timeout = 60\nbatch = "set foo=bar"\n'
        'breaks = ["foo"]\nbreaks_password = ["bar"]\n'
        '[[post]]\ndevice = "lab-r1"\ncmd = "true"\n')
    lab = nl.load_lab(full_lab)
    scen = nl.load_scenarios(tmp_path / "scenarios")[0]
    assert scen.expect == "rolled_back"
    assert scen.expect_password == "confirmed"
    assert scen.breaks == ["foo"]
    assert scen.breaks_password == ["bar"]
    # effective getters per lane
    assert scen.effective_expect("key") == "rolled_back"
    assert scen.effective_expect("password") == "confirmed"
    assert scen.effective_breaks("key") == ["foo"]
    assert scen.effective_breaks("password") == ["bar"]


# ============================================================================
# Item 6: scenario loader refusals
# ============================================================================

def test_loader_refuses_check_key(tmp_path):
    """`check = "..."` in a scenario TOML raises ValueError with the design's
    hint."""
    d = tmp_path / "scenarios"
    d.mkdir()
    (d / "01-x.toml").write_text(
        'name = "01-x"\ntarget = "lab-r1"\nreset = []\n'
        'expect = "rejected"\ntimeout = 60\n'
        'check = "true"\nbatch = "set foo"\n')
    with pytest.raises(ValueError) as excinfo:
        nl.load_scenarios(d)
    assert "check was replaced by probes" in str(excinfo.value)
    assert "design 4.6" in str(excinfo.value)


def test_loader_refuses_probes_not_a_list(tmp_path):
    d = tmp_path / "scenarios"
    d.mkdir()
    (d / "01-x.toml").write_text(
        'name = "01-x"\ntarget = "lab-r1"\nreset = []\n'
        'expect = "confirmed"\ntimeout = 60\n'
        'probes = "not a list"\nbatch = "set foo"\n')
    with pytest.raises(ValueError) as excinfo:
        nl.load_scenarios(d)
    assert "probes" in str(excinfo.value)
    assert "list" in str(excinfo.value)


def test_loader_refuses_probe_field_with_backslash(tmp_path):
    d = tmp_path / "scenarios"
    d.mkdir()
    (d / "01-x.toml").write_text(
        'name = "01-x"\ntarget = "lab-r1"\nreset = []\n'
        'expect = "confirmed"\ntimeout = 60\n'
        'probes = [["conf-has", "dnsmasq", "sub", "present", "A\\\\B"]]\n'
        'batch = "set foo"\n')
    with pytest.raises(ValueError) as excinfo:
        nl.load_scenarios(d)
    assert "backslash" in str(excinfo.value)


def test_loader_refuses_probe_field_with_tab(tmp_path):
    d = tmp_path / "scenarios"
    d.mkdir()
    (d / "01-x.toml").write_text(
        'name = "01-x"\ntarget = "lab-r1"\nreset = []\n'
        'expect = "confirmed"\ntimeout = 60\n'
        'probes = [["conf-has", "dnsmasq", "sub", "present", "A\\tB"]]\n'
        'batch = "set foo"\n')
    with pytest.raises(ValueError) as excinfo:
        nl.load_scenarios(d)
    assert "TAB" in str(excinfo.value) or "tab" in str(excinfo.value)


def test_loader_refuses_too_many_probes(tmp_path):
    d = tmp_path / "scenarios"
    d.mkdir()
    probes = ",\n".join('["noop", "x"]' for _ in range(nl.MAX_PROBES + 1))
    (d / "01-x.toml").write_text(
        f'name = "01-x"\ntarget = "lab-r1"\nreset = []\n'
        f'expect = "confirmed"\ntimeout = 60\n'
        f'probes = [{probes}]\nbatch = "set foo"\n')
    with pytest.raises(ValueError) as excinfo:
        nl.load_scenarios(d)
    assert str(nl.MAX_PROBES) in str(excinfo.value)


def test_loader_refuses_probes_exceeding_4096_bytes(tmp_path):
    d = tmp_path / "scenarios"
    d.mkdir()
    # Each probe: 5 fields of ~110 bytes (within MAX_PROBE_FIELD=128) +
    # 4 TABs + 1 LF -> ~555 bytes on the wire. 32 probes -> ~17,760 bytes,
    # well past MAX_PROBES_BYTES=4096.
    big = "f" * 110
    probe = f'["noop", "{big}", "{big}", "{big}", "{big}"]'
    probes = ",\n".join([probe] * 32)
    (d / "01-x.toml").write_text(
        f'name = "01-x"\ntarget = "lab-r1"\nreset = []\n'
        f'expect = "confirmed"\ntimeout = 60\n'
        f'probes = [{probes}]\nbatch = "set foo"\n')
    with pytest.raises(ValueError) as excinfo:
        nl.load_scenarios(d)
    assert "4096" in str(excinfo.value)


def test_loader_refuses_bad_approval_value(tmp_path):
    d = tmp_path / "scenarios"
    d.mkdir()
    (d / "01-x.toml").write_text(
        'name = "01-x"\ntarget = "lab-r1"\nreset = []\n'
        'expect = "confirmed"\ntimeout = 60\n'
        'approval = "maybe"\nbatch = "set foo"\n')
    with pytest.raises(ValueError) as excinfo:
        nl.load_scenarios(d)
    assert "approval" in str(excinfo.value)


def test_loader_refuses_refuse_match_without_refused_expect(tmp_path, full_lab):
    d = tmp_path / "scenarios"
    d.mkdir()
    (d / "01-x.toml").write_text(
        'name = "01-x"\ntarget = "lab-r1"\nreset = []\n'
        'expect = "confirmed"\ntimeout = 60\n'
        'refuse_match = "anything"\nbatch = "set foo"\n')
    lab = nl.load_lab(full_lab)
    scens = nl.load_scenarios(d)
    errs = nl.validate_scenarios(lab, scens)
    assert any("refuse_match" in e for e in errs)


def test_loader_refuses_refused_without_refuse_match(tmp_path, full_lab):
    d = tmp_path / "scenarios"
    d.mkdir()
    (d / "01-x.toml").write_text(
        'name = "01-x"\ntarget = "lab-r1"\nreset = []\n'
        'expect = "refused"\ntimeout = 60\n'
        'batch = "set foo"\n')
    lab = nl.load_lab(full_lab)
    scens = nl.load_scenarios(d)
    errs = nl.validate_scenarios(lab, scens)
    assert any("refuse_match" in e for e in errs)


def test_post_lanes_filter_against_active_lane():
    """[[post]] with `lanes = [\"key\"]` is skipped in the password lane."""
    only_key = nl.Post(device="lab-r1", cmd="true", lanes=("key",))
    assert only_key.runs_in_lane("key") is True
    assert only_key.runs_in_lane("password") is False


def test_loader_refuses_post_lanes_with_unknown_name(tmp_path):
    d = tmp_path / "scenarios"
    d.mkdir()
    (d / "01-x.toml").write_text(
        'name = "01-x"\ntarget = "lab-r1"\nreset = []\n'
        'expect = "confirmed"\ntimeout = 60\nbatch = "set foo"\n'
        '[[post]]\ndevice = "lab-r1"\ncmd = "true"\nlanes = ["nope"]\n')
    with pytest.raises(ValueError) as excinfo:
        nl.load_scenarios(d)
    assert "lanes" in str(excinfo.value)


def test_probes_placeholders_resolved_like_batch(tmp_path, full_lab):
    """Placeholder names inside probe fields are validated like the batch
    (so used_placeholders pulls them out and resolve_vars runs for them)."""
    (tmp_path / "scenarios").mkdir(exist_ok=True)
    (tmp_path / "scenarios" / "01-x.toml").write_text(
        'name = "01-x"\ndescription = "x"\ntarget = "lab-r1"\n'
        'reset = []\nexpect = "confirmed"\ntimeout = 60\n'
        'probes = [["conf-has", "dnsmasq", "substr", "present", "{client_lab_ip}"]]\n'
        'batch = "set foo"\n'
        '[[post]]\ndevice = "lab-r1"\ncmd = "true"\n')
    lab = nl.load_lab(full_lab)
    scen = nl.load_scenarios(tmp_path / "scenarios")[0]
    used = nl.used_placeholders(scen.batch,
                                  *sum(scen.probes, []),
                                  scen.post[0].cmd)
    assert "client_lab_ip" in used


# ============================================================================
# Item 7: hello preflight
# ============================================================================

def _lab_with_newton_device(tmp_path, *, snapshot="baseline-newton-1-0-0"):
    rk = _make_router_key_file(tmp_path)
    pp = _make_passphrase_file(tmp_path)
    lab_toml = _make_lab_toml(tmp_path, router_key=str(rk),
                              approve_passphrase_file=str(pp),
                              snapshot=snapshot)
    return nl.load_lab(lab_toml)


def _good_hello_line(nonce: str) -> str:
    """A hello line whose sha256 fields match the repo files' and
    guard-state=idle."""
    fields = []
    for comp in ("prog", "helper", "guard", "init"):
        sha = hashlib.sha256(
            (REPO_ROOT / nl.PREFLIGHT_FILES[comp]).read_bytes()).hexdigest()
        fields.append(f"{comp}={sha}")
    return ("hello " + nonce + " " + " ".join(fields)
            + " mode=prod profile=lab approval-key=ok "
              "guard-state=idle busy=- caller=root role=change "
              "door=ssh tty=0 agent=0 from=-")


def _nonce_from_args(args: list[str]) -> str:
    """The hello nonce sits in args[-1] after `hello` (the cmd the preflight
    shells out to is '/usr/libexec/newton/newton-router hello <nonce>')."""
    return args[-1].split()[2]


def _mock_run_with_nonce_reply(extra: str = "") -> "callable":
    """A side_effect factory: extract the nonce from the args, build a hello
    line, return it. `extra` is appended to the line (e.g. guard-state=...)."""
    def side_effect(args, env=None, **_kw):
        nonce = _nonce_from_args(args)
        line = _good_hello_line(nonce)
        if extra:
            # Replace guard-state=idle (or append) with the extra string
            line = line.replace("guard-state=idle", extra)
        return _cp(stdout=line)
    return side_effect


def test_hello_preflight_passes(tmp_path):
    lab = _lab_with_newton_device(tmp_path)
    with mock.patch.object(nl, "_run",
                            side_effect=_mock_run_with_nonce_reply()):
        ok, detail = nl.router_hello_preflight(lab, lab.devices["lab-r1"])
    assert ok is True
    assert detail == ""


def test_hello_preflight_wrong_sha_fails(tmp_path):
    """Wrong prog sha: preflight returns (False, detail naming the comp and
    the first 8 chars of both sides)."""
    lab = _lab_with_newton_device(tmp_path)
    nonce_used = []

    def side_effect(args, env=None, **_kw):
        nonce = _nonce_from_args(args)
        nonce_used.append(nonce)
        bad = "hello " + nonce + " prog=" + ("f" * 64)
        for comp in ("helper", "guard", "init"):
            sha = hashlib.sha256(
                (REPO_ROOT / nl.PREFLIGHT_FILES[comp]).read_bytes()).hexdigest()
            bad += f" {comp}={sha}"
        bad += " mode=prod profile=lab approval-key=ok guard-state=idle busy=-"
        return _cp(stdout=bad)

    with mock.patch.object(nl, "_run", side_effect=side_effect):
        ok, detail = nl.router_hello_preflight(lab, lab.devices["lab-r1"])
    assert ok is False
    assert "prog" in detail and "differs" in detail
    assert nonce_used   # the function did try to talk to the router


def test_hello_preflight_guard_state_not_idle_fails(tmp_path):
    lab = _lab_with_newton_device(tmp_path)

    def side_effect(args, env=None, **_kw):
        nonce = _nonce_from_args(args)
        fields = []
        for comp in ("prog", "helper", "guard", "init"):
            sha = hashlib.sha256(
                (REPO_ROOT / nl.PREFLIGHT_FILES[comp]).read_bytes()).hexdigest()
            fields.append(f"{comp}={sha}")
        return _cp(stdout=("hello " + nonce + " " + " ".join(fields)
                            + " mode=prod profile=lab approval-key=ok "
                              "guard-state=pending busy=01234567"))

    with mock.patch.object(nl, "_run", side_effect=side_effect):
        ok, detail = nl.router_hello_preflight(lab, lab.devices["lab-r1"])
    assert ok is False
    assert "guard-state=pending" in detail
    assert "is not idle" in detail


def test_hello_preflight_no_reply_returns_no_reply(tmp_path):
    """subprocess TimeoutExpired OR non-zero rc OR empty stdout -> no reply."""
    lab = _lab_with_newton_device(tmp_path)
    with mock.patch.object(nl, "_run", side_effect=subprocess.TimeoutExpired(
            cmd=["ssh"], timeout=30)):
        ok, detail = nl.router_hello_preflight(lab, lab.devices["lab-r1"])
    assert ok is False
    assert detail == "no reply"


def _preflight_args_for(tmp_path, *, known_hosts: str = "") -> list[str]:
    """Run router_hello_preflight against a mocked _run and return the args
    it built (the ssh command line up to and including the user@host)."""
    rk = _make_router_key_file(tmp_path)
    pp = _make_passphrase_file(tmp_path)
    lab_toml = _make_lab_toml(tmp_path, router_key=str(rk),
                              approve_passphrase_file=str(pp),
                              known_hosts=known_hosts)
    lab = nl.load_lab(lab_toml)
    captured: dict = {}

    def fake_run(args, env=None, **_kw):
        captured["args"] = args
        return _cp(stdout="")   # the assertions here care about the cmd

    with mock.patch.object(nl, "_run", side_effect=fake_run):
        nl.router_hello_preflight(lab, lab.devices["lab-r1"])
    return captured["args"]


def test_hello_preflight_uses_known_hosts_file_when_set(tmp_path):
    """With [ssh] known_hosts set, the preflight pins lab-r1 against that
    file (StrictHostKeyChecking=yes, UserKnownHostsFile=<path>) instead of
    falling back to the user's real ~/.ssh/known_hosts."""
    rk = _make_router_key_file(tmp_path)
    pp = _make_passphrase_file(tmp_path)
    kh = tmp_path / "lab.known"
    kh.write_text("10.109.0.11 ssh-ed25519 FAKE\n")
    lab_toml = _make_lab_toml(tmp_path, router_key=str(rk),
                              approve_passphrase_file=str(pp),
                              known_hosts=str(kh))
    lab = nl.load_lab(lab_toml)
    captured: dict = {}

    def fake_run(args, env=None, **_kw):
        captured["args"] = args
        return _cp(stdout="")

    with mock.patch.object(nl, "_run", side_effect=fake_run):
        nl.router_hello_preflight(lab, lab.devices["lab-r1"])
    args = captured["args"]
    # the value appears verbatim, with the file path
    assert f"UserKnownHostsFile={kh}" in args
    assert "StrictHostKeyChecking=yes" in args
    assert f"-oUserKnownHostsFile={kh}" not in args   # the runner uses " -o key val " form
    # and the preflight did not silently accept the router's key
    assert not any("accept-new" in str(a) for a in args)
    # the proxy + key are still passed
    assert any(a.startswith("ProxyCommand=") for a in args)
    assert "-i" in args
    i_index = args.index("-i")
    assert args[i_index + 1] == str(rk)


def test_hello_preflight_uses_empty_known_hosts_file_when_unset(tmp_path):
    """Even when [ssh] known_hosts is unset, the preflight still passes
    UserKnownHostsFile= (the lab's known_hosts value, possibly empty) with
    StrictHostKeyChecking=yes: it never falls back to the user's real
    ~/.ssh/known_hosts and never writes to it."""
    args = _preflight_args_for(tmp_path, known_hosts="")
    assert "StrictHostKeyChecking=yes" in args
    assert "UserKnownHostsFile=" in args
    assert not any("accept-new" in str(a) for a in args)
    # and nothing references the user's default known_hosts path
    joined = "\n".join(str(a) for a in args)
    assert "~/.ssh/known_hosts" not in joined
    assert "/root/.ssh/known_hosts" not in joined


def test_hello_preflight_source_never_uses_accept_new():
    """The router_hello_preflight function source contains no `accept-new`.
    A regression that re-adds StrictHostKeyChecking=accept-new to the preflight
    fails this. (ssh_cmd is allowed to keep accept-new for the runner's own
    non-key-lane ssh.)"""
    import ast
    src = MODULE_PATH.read_text()
    tree = ast.parse(src)
    funcs = [n for n in tree.body
             if isinstance(n, ast.FunctionDef)
             and n.name == "router_hello_preflight"]
    assert len(funcs) == 1, "router_hello_preflight must be a single function"
    body_src = ast.get_source_segment(src, funcs[0])
    assert body_src is not None
    assert "accept-new" not in body_src, (
        "router_hello_preflight must not contain 'accept-new' "
        "(it would silently write lab-r1's host key into the user's "
        "real ~/.ssh/known_hosts after every snapshot reset)")


def test_hello_preflight_args_never_contain_accept_new(tmp_path):
    """Behavioural companion to the source-grep test: regardless of
    known_hosts (set, unset, empty path), the actual ssh command the
    preflight shells out to never carries accept-new."""
    for kh in ("", str(tmp_path / "lab.known"), "/nonexistent/.lab.known"):
        args = _preflight_args_for(tmp_path, known_hosts=kh)
        assert not any("accept-new" in str(a) for a in args), (
            f"preflight args contain accept-new with known_hosts={kh!r}: "
            f"{args}")


def test_lab_toml_has_active_known_hosts_entry():
    """lab.toml [ssh] known_hosts is an active (uncommented) entry pointing
    at ~/.config/newton/lab-known-hosts: main()'s key-lane gate and
    router_hello_preflight rely on it being set."""
    raw = LAB_TOML.read_text()
    # parse [ssh] table to confirm known_hosts is set (not just commented)
    parsed = tomllib.loads(raw)["ssh"]
    assert parsed.get("known_hosts", "").strip() == \
        "~/.config/newton/lab-known-hosts", (
        f"lab.toml [ssh] known_hosts = {parsed.get('known_hosts')!r}; "
        "expected the lab-known-hosts path (the file is created once at "
        "lab setup from lab-r1's host key)")
    # and the file's raw text has the assignment on an uncommented line
    has_active = any(
        ln.lstrip().startswith("known_hosts =") and "~/.config/newton/lab-known-hosts" in ln
        for ln in raw.splitlines()
    )
    assert has_active, (
        "lab.toml has no uncommented `known_hosts = \"~/.config/newton/lab-known-hosts\"` "
        "line; the key lane would then refuse to run")


def test_hello_preflight_run_start_resets_and_blocks_when_fails(
    tmp_path, capsys,
):
    """At run-start, a preflight failure prints PREFLIGHT_STOP_TEXT and the
    scenario loop never starts (rc=2)."""
    kh = tmp_path / "lab.known"
    kh.write_text("lab-r1 ssh-ed25519 FAKE\n")
    lab_toml = _make_lab_toml(
        tmp_path, router_key=str(_make_router_key_file(tmp_path)),
        approve_passphrase_file=str(_make_passphrase_file(tmp_path)),
        known_hosts=str(kh),
        snapshot="baseline-newton-1-0-0")
    scens = tmp_path / "scenarios"
    scens.mkdir()
    (scens / "01-x.toml").write_text(
        'name = "01-x"\ntarget = "lab-r1"\nreset = []\n'
        'expect = "none"\ntimeout = 60\nbatch = ""\n')

    def fake_run(args, env=None, **_kw):
        if args[0] == "curl":
            return _cp(stdout=json.dumps({"data": "UPID:abc"}))
        if args[0] == "ssh":
            last = args[-1] if isinstance(args[-1], str) else ""
            if "hello" in last:
                return _cp(stdout="")   # preflight -> no reply
            return _cp(returncode=0)    # ssh_ready
        return _cp(stdout="fingerprint\n", returncode=0)

    pve_status = {"status": "stopped", "exitstatus": "OK"}
    scenario_called = []

    with mock.patch.object(nl, "_run", side_effect=fake_run), \
         mock.patch.object(nl, "pve_wait_task", return_value=pve_status), \
         mock.patch.object(nl, "run_scenario",
                           side_effect=lambda *a, **kw: scenario_called.append(a)), \
         mock.patch.object(nl, "RESULTS_DIR", tmp_path / "results"):
        rc = nl.main(["--lab", str(lab_toml), "--scenarios", str(scens),
                      "--lane", "key"])

    assert rc == 2
    err = capsys.readouterr().err
    assert nl.PREFLIGHT_STOP_TEXT in err
    assert scenario_called == []   # run_scenario was never reached


def test_hello_preflight_absent_in_password_lane(
    tmp_path,
):
    """In the password lane the preflight is NOT called after the run-start
    reset (the runner never builds a ssh cmd containing `hello`)."""
    # snapshot uses Newton prefix so the gate would fire in the key lane.
    lab = _lab_with_newton_device(tmp_path, snapshot="baseline-newton-1-0-0")
    scens = tmp_path / "scenarios"
    scens.mkdir()
    (scens / "01-x.toml").write_text(
        'name = "01-x"\ntarget = "lab-r1"\nreset = []\n'
        'expect = "none"\ntimeout = 60\nbatch = ""\n')
    ssh_cmds: list[list[str]] = []

    def fake_run(args, env=None, **_kw):
        ssh_cmds.extend([args] if args[0] == "ssh" else [])
        if args[0] == "curl":
            return _cp(stdout=json.dumps({"data": "UPID:abc"}))
        return _cp(stdout="fingerprint\n", returncode=0)

    pve_status = {"status": "stopped", "exitstatus": "OK"}
    with mock.patch.object(nl, "_run", side_effect=fake_run), \
         mock.patch.object(nl, "pve_wait_task", return_value=pve_status):
        with mock.patch.object(nl, "RESULTS_DIR", tmp_path / "results"):
            # Need a fake lab_toml with newton prefix so the gate WOULD fire
            # if lane=key.
            nl.main(["--lab", str(_make_lab_toml(
                tmp_path, router_key=str(_make_router_key_file(tmp_path)),
                approve_passphrase_file=str(_make_passphrase_file(tmp_path)))),
                     "--scenarios", str(scens), "--lane", "password",
                     "--no-lab-reset"])
    # The runner did build ssh cmds for the var cmd; none contains `hello`.
    assert not any("hello" in a[-1] for a in ssh_cmds if isinstance(a[-1], str))


# ============================================================================
# Real 9 scenarios: check -> probes, approval flags, real reject/refuse
# ============================================================================

def test_real_scenarios_have_probes_where_design_says_so(scenarios):
    """01, 06, 09 carry probes; 04, 05, 07, 08 do not (true -> none).
    02 and 03 carry approval = true but no probes (their check was 'true')."""
    by_name = {s.name: s for s in scenarios}
    assert set(by_name) == {
        "01-static-lease", "02-mgmt-ip-lockout", "03-mgmt-firewall-drop",
        "04-commit-smuggling", "05-bad-syntax", "06-port-forward-from-isp",
        "07-wan-down-isolation", "08-partial-batch", "09-add-section",
    }
    # 01, 06, 09 -> probes
    for n in ("01-static-lease", "06-port-forward-from-isp", "09-add-section"):
        assert by_name[n].probes, f"{n} should have probes"
    # 04, 05, 07, 08 -> no probes (the design row says "true -> none")
    for n in ("04-commit-smuggling", "05-bad-syntax",
              "07-wan-down-isolation", "08-partial-batch"):
        assert not by_name[n].probes, f"{n} should have no probes"
    # 02, 03 -> approval = true
    for n in ("02-mgmt-ip-lockout", "03-mgmt-firewall-drop",
              "06-port-forward-from-isp"):
        assert by_name[n].approval is True, f"{n} should have approval = true"
    # 01, 04, 05, 07, 08, 09 -> no approval flag
    for n in ("01-static-lease", "04-commit-smuggling", "05-bad-syntax",
              "07-wan-down-isolation", "08-partial-batch", "09-add-section"):
        assert by_name[n].approval is None, f"{n} should not need approval"


# ============================================================================
# Dual-WAN scenarios: validate the new lab/scenarios/dualwan/ dir references
# real checks and steps in lab.toml and probes/expectations are well-formed.
# ============================================================================

DUALWAN_DIR = LAB_DIR / "scenarios" / "dualwan"


@pytest.fixture
def dualwan_scenarios():
    return nl.load_scenarios(DUALWAN_DIR)


def test_dualwan_scenarios_validate_clean(lab, dualwan_scenarios):
    """Every scenario in lab/scenarios/dualwan/ references real checks/steps,
    uses only devices in [devices] or 'local', and matches its expect
    contract (confirmed needs approval for new UCI packages, probes not empty).
    Catches typos in setup/cleanup/breaks/check references."""
    assert dualwan_scenarios, (
        f"no scenarios found in {DUALWAN_DIR} (run --scenarios to confirm)")
    by_name = {s.name: s for s in dualwan_scenarios}
    assert set(by_name) == {
        "dw-01-failover", "dw-02-failback", "dw-03-upstream-dead-no-service",
        "dw-04-no-flap", "dw-05-failover-ifdown",
    }, f"unexpected dualwan scenario set: {sorted(by_name)}"
    errs = nl.validate_scenarios(lab, dualwan_scenarios)
    assert errs == [], (
        f"dualwan scenarios should validate against the real lab; got {errs}")


def test_dualwan_scenarios_reference_real_steps(lab, dualwan_scenarios):
    """Every setup/cleanup step listed by a dualwan scenario exists in
    [steps] and uses a device in [devices] or 'local'."""
    for scen in dualwan_scenarios:
        for s in scen.setup + scen.cleanup:
                assert s in lab.steps, (
                    f"{scen.name}: step {s!r} not defined in [steps]")
                step = lab.steps[s]
                assert step.device == "local" or step.device in lab.devices, (
                    f"{scen.name}: step {s!r} has unknown device "
                    f"{step.device!r}")


def test_dualwan_scenarios_have_uci_probe_or_logread_evidence(lab, dualwan_scenarios):
    """Every dualwan scenario that expects the health tool to be on (all five)
    seals a probe that proves newton_wanhealth.main.enabled = 1 after the
    change. uci-equals is in the probe grammar (design 4.3)."""
    for scen in dualwan_scenarios:
        flat = " ".join(" ".join(p) for p in scen.probes)
        assert "uci-equals" in flat and "newton_wanhealth.main.enabled" in flat, (
            f"{scen.name}: sealed probes must include "
            f"uci-equals newton_wanhealth.main.enabled 1; got {scen.probes}")


def test_dualwan_lib_is_bash_and_loads():
    """lab/dualwan-lib.sh is a sourced bash library (not a #!/bin/sh script);
    the runner's local commands invoke it as `bash -c '. lab/dualwan-lib.sh; ...'`,
    and the file exists alongside the lab.toml."""
    lib = LAB_DIR / "dualwan-lib.sh"
    assert lib.exists(), f"missing {lib}"
    text = lib.read_text()
    assert text.startswith("#!/usr/bin/env bash"), (
        f"{lib} must be a bash library; got first line {text.splitlines()[0]!r}")


# ============================================================================
# RESULTS_DIR and its backups dir: mode 0700, healed, never through a symlink
# ============================================================================
# owrt-change.sh refuses a backup directory whose parent is group- or
# world-writable without the sticky bit, and RESULTS_DIR/backups is what the
# runner hands it as OWRT_BACKUP_DIR. Under umask 0002 (the lab host's) a plain
# mkdir leaves both 0775, so every plan from the runner fails before it starts.


@pytest.fixture
def umask_0002():
    """Run the body under the lab host's umask; restored whatever happens."""
    previous = os.umask(0o002)
    yield 0o002
    os.umask(previous)


def _mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def test_results_dirs_are_0700_under_umask_0002(tmp_path, umask_0002):
    results = tmp_path / "results"
    with mock.patch.object(nl, "RESULTS_DIR", results):
        nl._ensure_results_dirs(results / "results.json")
    assert _mode(results) == 0o700
    assert _mode(results / "backups") == 0o700


def test_existing_group_writable_results_dirs_are_healed_to_0700(tmp_path,
                                                                  umask_0002):
    """A lab/.results an older runner (or an operator) left 0775 is tightened
    instead of refused: the same heal rule owrt-change.sh applies to $STATE,
    so a stale directory does not keep failing every plan."""
    results = tmp_path / "results"
    results.mkdir(mode=0o777)
    (results / "backups").mkdir(mode=0o777)
    assert _mode(results) == 0o775 and _mode(results / "backups") == 0o775
    with mock.patch.object(nl, "RESULTS_DIR", results):
        nl._ensure_results_dirs(results / "results.json")
    assert _mode(results) == 0o700
    assert _mode(results / "backups") == 0o700


def test_symlinked_results_dir_is_refused_and_its_target_untouched(tmp_path):
    target = tmp_path / "elsewhere"
    target.mkdir(mode=0o777)
    assert _mode(target) == 0o775
    link = tmp_path / "results"
    link.symlink_to(target)
    with mock.patch.object(nl, "RESULTS_DIR", link):
        with pytest.raises(nl.DirSetupError) as excinfo:
            nl._ensure_results_dirs(link / "results.json")
    assert "symlink" in str(excinfo.value)
    assert str(link) in str(excinfo.value)
    assert _mode(target) == 0o775          # never chmod through the link
    assert not (target / "backups").exists()


def test_symlinked_backups_dir_is_refused_and_its_target_untouched(tmp_path):
    target = tmp_path / "elsewhere"
    target.mkdir(mode=0o777)
    results = tmp_path / "results"
    results.mkdir()
    (results / "backups").symlink_to(target)
    with mock.patch.object(nl, "RESULTS_DIR", results):
        with pytest.raises(nl.DirSetupError) as excinfo:
            nl._ensure_results_dirs(results / "results.json")
    assert "symlink" in str(excinfo.value)
    assert _mode(target) == 0o775


def test_results_dir_owned_by_another_user_is_refused_untouched(tmp_path,
                                                               monkeypatch):
    """We write full sysupgrade backups (secrets) and every result JSON into
    these directories, so one we do not own is refused, never written to and
    never chmodded. (Simulated: the test host cannot chown.)"""
    results = tmp_path / "results"
    results.mkdir(mode=0o777)
    assert _mode(results) == 0o775
    real_uid = os.geteuid()      # nl.os is the os module, so capture it first
    monkeypatch.setattr(nl.os, "geteuid", lambda: real_uid + 1)
    with mock.patch.object(nl, "RESULTS_DIR", results):
        with pytest.raises(nl.DirSetupError) as excinfo:
            nl._ensure_results_dirs(results / "results.json")
    assert "uid" in str(excinfo.value)
    assert _mode(results) == 0o775


def test_main_creates_results_and_backups_0700(tmp_path, umask_0002, capsys):
    """Through the runner's own path: the directories the run leaves behind
    are 0700 even though the host umask would make them 0775, so the
    owrt-change.sh plan that follows can take them as OWRT_BACKUP_DIR."""
    results = tmp_path / "results"
    lab_toml = _make_lab_toml(tmp_path, router_key="", approve_passphrase_file="")
    scens = tmp_path / "scenarios"
    scens.mkdir()
    (scens / "01-x.toml").write_text(
        'name = "01-x"\ntarget = "lab-r1"\nreset = []\n'
        'expect = "none"\ntimeout = 60\nbatch = ""\n')

    def fake_run(args, env=None, **_kw):
        if args[0] == "curl":
            return _cp(stdout=json.dumps({"data": "UPID:abc"}))
        return _cp(stdout="fingerprint\n", returncode=0)

    pve_status = {"status": "stopped", "exitstatus": "OK"}
    with mock.patch.object(nl, "_run", side_effect=fake_run), \
         mock.patch.object(nl, "pve_wait_task", return_value=pve_status), \
         mock.patch.object(nl, "RESULTS_DIR", results):
        rc = nl.main(["--lab", str(lab_toml), "--scenarios", str(scens),
                      "--lane", "password", "--no-lab-reset"])
    assert rc == 0, capsys.readouterr().err
    assert _mode(results) == 0o700
    assert _mode(results / "backups") == 0o700


def test_main_leaves_a_results_parent_outside_results_dir_alone(tmp_path, umask_0002, capsys):
    """--results in a directory outside RESULTS_DIR (an operator's own dir,
    or /tmp): the runner must not chmod or refuse that directory."""
    results = tmp_path / "results"
    outside = tmp_path / "mine"
    outside.mkdir(mode=0o755)
    os.chmod(outside, 0o755)
    lab_toml = _make_lab_toml(tmp_path, router_key="", approve_passphrase_file="")
    scens = tmp_path / "scenarios"
    scens.mkdir()
    (scens / "01-x.toml").write_text(
        'name = "01-x"\ntarget = "lab-r1"\nreset = []\n'
        'expect = "none"\ntimeout = 60\nbatch = ""\n')

    def fake_run(args, env=None, **_kw):
        if args[0] == "curl":
            return _cp(stdout=json.dumps({"data": "UPID:abc"}))
        return _cp(stdout="fingerprint\n", returncode=0)

    pve_status = {"status": "stopped", "exitstatus": "OK"}
    with mock.patch.object(nl, "_run", side_effect=fake_run), \
         mock.patch.object(nl, "pve_wait_task", return_value=pve_status), \
         mock.patch.object(nl, "RESULTS_DIR", results):
        rc = nl.main(["--lab", str(lab_toml), "--scenarios", str(scens),
                      "--lane", "password", "--no-lab-reset",
                      "--results", str(outside / "r.json")])
    assert rc == 0, capsys.readouterr().err
    assert _mode(outside) == 0o755
    assert (outside / "r.json").exists()
    assert _mode(results) == 0o700


def test_main_refuses_a_symlinked_results_dir(tmp_path, capsys):
    target = tmp_path / "elsewhere"
    target.mkdir(mode=0o777)
    link = tmp_path / "results"
    link.symlink_to(target)
    lab_toml = _make_lab_toml(tmp_path, router_key="", approve_passphrase_file="")
    scens = tmp_path / "scenarios"
    scens.mkdir()
    (scens / "01-x.toml").write_text(
        'name = "01-x"\ntarget = "lab-r1"\nreset = []\n'
        'expect = "none"\ntimeout = 60\nbatch = ""\n')
    with mock.patch.object(nl, "RESULTS_DIR", link):
        rc = nl.main(["--lab", str(lab_toml), "--scenarios", str(scens),
                      "--lane", "password", "--no-lab-reset"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "symlink" in err and str(link) in err
    assert _mode(target) == 0o775
    assert not (target / "backups").exists()