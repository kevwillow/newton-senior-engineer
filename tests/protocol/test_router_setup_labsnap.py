"""Behaviour tests for the lab-snapshot router setup action."""

import hashlib
import shlex
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from router_setup_env import setup_env, build_src  # noqa: E402, F401
from router_setup_harness import DEFAULT_STATE  # noqa: E402
from test_router_setup_install import GOOD_PW, seed_known_hosts  # noqa: E402
from test_router_setup_keys import (  # noqa: E402
    make_keypair, key_blob, restricted_line_text)


CODE_FILES = {
    "device/openwrt/newton-router/newton-router":
        "usr/libexec/newton/newton-router",
    "scripts/owrt-safe-apply.sh": "usr/libexec/newton/newton-safe-apply",
    "device/openwrt/newton-guard/newton-guard": "usr/libexec/newton-guard",
    "device/openwrt/newton-guard/newton-guard.init":
        "etc/init.d/newton-guard",
}
BASELINE = "baseline-newton-1-0-0"


def prepare(env, tmp, with_pass=True):
    lab = env.tmp / "lab"
    lab.mkdir()
    pve = DEFAULT_STATE["pve"]
    token_file = lab / "pve.token"
    pin_file = lab / "pve.pin"
    token_file.write_text(pve["token"])
    pin_file.write_text(pve["pin"])
    token_file.chmod(0o600)
    pin_file.chmod(0o600)

    lines = [
        "[pve]",
        'host = "192.0.2.11"',
        'node = "Apollo"',
        'token_file = "%s"' % token_file,
        'pin_file = "%s"' % pin_file,
        "",
        "[ssh]",
    ]
    if with_pass:
        approve_file = lab / "approve.pw"
        approve_file.write_text("labpass")
        approve_file.chmod(0o600)
        lines.append('approve_passphrase_file = "%s"' % approve_file)
    lines.extend([
        "",
        "[devices.r1]",
        "vmid = 9102",
        'snapshot = "baseline-pw"',
        "",
    ])
    env.lab_toml.write_text("\n".join(lines))
    seed_known_hosts(env)
    return lab


def snap(env, *args, src=None):
    extra = {"NEWTON_SETUP_SRC": str(src)} if src else None
    return env.run("r1", "lab-snapshot", *args,
                   typed=(GOOD_PW,), env=extra)


def assert_router_work_done(env, src=None):
    src = src or env.src
    for source, remote in CODE_FILES.items():
        assert env.router.read(remote) == (src / source).read_text()


def assert_snapshot_failure(result):
    assert result.rc == 1
    assert "NOTE state: router work done; the snapshot was NOT taken" in result.out
    assert "STOPPED lab-snapshot r1:" in result.out


def test_lab_snapshot_installs_keys_profiles_and_snapshots_without_leaks(
        setup_env):
    env = setup_env
    lab = prepare(env, env.tmp)
    token = DEFAULT_STATE["pve"]["token"]
    env.register_secrets(GOOD_PW, "labpass", token)

    result = snap(env, "--new-key", "--skip-gates")

    assert result.rc == 0, result.out + result.err
    assert_router_work_done(env)
    keys = env.router.authorized_keys()
    assert len(keys) == 2
    for identity in ("newton-agent", "lab-runner"):
        matching = [line for line in keys if identity in line]
        assert len(matching) == 1
        assert "change" in matching[0]
    expected_key = hashlib.pbkdf2_hmac(
        "sha256", b"labpass", b"newton-approve-v1:r1", 600000, 32
    ).hex() + "\n"
    assert env.router.read("etc/newton/approve.key") == expected_key
    assert env.router.read("etc/newton/profile") == "lab\n"
    assert BASELINE in env.router.snapshots(9102)

    assert result.lines("PASS install ")
    # ten proofs per key at add-key and again after the approval key was set
    assert len(result.lines("PASS proof ")) == 2 * 2 * 10
    for identity in ("newton-agent", "lab-runner"):
        assert len([line for line in result.lines("PASS add-key: key file ")
                    if identity in line]) == 1
    assert "PASS approval key verified" in result.out
    assert "WARN gates skipped" in result.out
    assert "PASS snapshot %s created" % BASELINE in result.out
    assert ("INFO next: point lab.toml's snapshot for r1 at %s" % BASELINE
            in result.out)
    assert "DONE lab-snapshot r1" in result.out

    curl_calls = [call for call in result.calls if call.get("tool") == "curl"]
    assert curl_calls
    assert all(token not in " ".join(call["argv"]) for call in curl_calls)
    assert all(not call.get("leaks") for call in curl_calls)
    # Input secret files are trusted sources, not emitted artifacts.
    for name in ("pve.token", "pve.pin", "approve.pw"):
        (lab / name).unlink()
    assert env.leaks() == []


def test_gates_command_gets_only_device_and_snapshot_is_made(setup_env):
    env = setup_env
    prepare(env, env.tmp)
    seen = env.tmp / "gate.args"
    gate = env.tmp / "gate-ok"
    gate.write_text(
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> %s\nexit 0\n"
        % ("%s", shlex.quote(str(seen))))
    gate.chmod(0o755)

    result = snap(env, "--new-key", "--gates-cmd", gate)

    assert result.rc == 0, result.out + result.err
    assert seen.read_text().splitlines() == ["r1"]
    assert BASELINE in env.router.snapshots(9102)


def test_failed_gates_leave_router_work_but_take_no_snapshot(setup_env):
    env = setup_env
    prepare(env, env.tmp)
    gate = env.tmp / "gate-fail"
    gate.write_text("#!/bin/sh\nexit 1\n")
    gate.chmod(0o755)

    result = snap(env, "--new-key", "--gates-cmd", gate)

    assert_snapshot_failure(result)
    assert BASELINE not in env.router.snapshots(9102)
    assert_router_work_done(env)


@pytest.mark.parametrize("args", [(), ("--skip-gates", "--gates-cmd", "x")])
def test_gate_choice_is_required_and_exclusive_before_router_calls(
        setup_env, args):
    env = setup_env
    prepare(env, env.tmp)

    result = snap(env, *args)

    assert result.rc == 2
    assert "error:" in result.err
    assert result.calls == []


def test_prod_device_is_rejected_before_router_calls(setup_env):
    env = setup_env
    prepare(env, env.tmp)
    env.inventory.write_text(
        '[devices.r1]\nhost = "10.1.2.3"\nprofile = "prod"\nauth = "password"\n')

    result = snap(env, "--skip-gates")

    assert result.rc == 2
    assert "error:" in result.err
    assert result.calls == []


def test_missing_approval_passphrase_is_rejected_without_router_change(
        setup_env):
    env = setup_env
    prepare(env, env.tmp, with_pass=False)
    before = env.router.snapshot()

    result = snap(env, "--new-key", "--skip-gates")

    assert result.rc == 2
    assert "error:" in result.err
    assert result.calls == []
    assert env.router.snapshot() == before


def test_lab_snapshot_preflight_refuses_a_missing_key_before_router_calls(
        setup_env):
    env = setup_env
    prepare(env, env.tmp)
    before = env.router.snapshot()

    result = snap(env, "--labels", "newton-agent,lab-runner", "--skip-gates")

    assert result.rc == 1
    assert result.out.splitlines()[-1] == (
        "STOPPED lab-snapshot r1: no key for label newton-agent on this "
        "host (%s is missing): the key lives on the Newton host that "
        "added it; run this there, or pass --new-key to make a new key "
        "on purpose" % (env.keys_dir / "r1-newton-agent"))
    assert "NOTE state: router unchanged" in result.out.splitlines()
    assert result.calls == []
    assert env.router.snapshot() == before
    for label in ("newton-agent", "lab-runner"):
        assert not (env.keys_dir / ("r1-" + label)).exists()
        assert not (env.keys_dir / ("r1-" + label + ".pub")).exists()


@pytest.mark.parametrize("failure", [
    "wrong-token", "curl-failure", "task-error", "already-present",
])
def test_proxmox_failure_stops_after_router_work(setup_env, failure):
    env = setup_env
    lab = prepare(env, env.tmp)
    pve = env.router.pve()
    if failure == "wrong-token":
        (lab / "pve.token").write_text("wrong-token")
    elif failure == "curl-failure":
        env.router.update_state(pve={**pve, "fail": "boom"})
    elif failure == "task-error":
        env.router.update_state(pve={**pve, "task_exit": "ERROR"})
    else:
        env.router.update_state(pve={
            **pve, "vms": {"9102": {"snapshots": [BASELINE]}},
        })

    result = snap(env, "--new-key", "--skip-gates")

    assert_snapshot_failure(result)
    assert_router_work_done(env)
    # a refused POST (wrong token, a failing API, a name that exists) gets the
    # hint that a snapshot name is used once; a task that ran and failed does not
    # (a planted defect that ignored the curl status
    # survived because only the STOPPED line was checked)
    hint = [line for line in result.lines("INFO ")
            if "is used once" in line]
    assert bool(hint) == (failure != "task-error"), result.out


def test_sync_runs_before_snapshot_post(setup_env):
    env = setup_env
    prepare(env, env.tmp)
    token = DEFAULT_STATE["pve"]["token"]
    env.register_secrets(GOOD_PW, "labpass", token)

    result = snap(env, "--new-key", "--skip-gates")

    assert result.rc == 0, result.out + result.err
    sync_calls = [c for c in result.calls if c.get("tool") == "ssh"
                  and (c.get("command") or "").endswith(" sync")]
    assert len(sync_calls) == 1, result.out
    sync_n = sync_calls[0]["n"]
    snap_posts = [c for c in result.calls if c.get("tool") == "curl"
                  and c.get("method") == "POST"
                  and c.get("url", "").endswith("/snapshot")]
    assert snap_posts, result.out
    assert sync_n < snap_posts[0]["n"], (
        "sync must run before the snapshot POST: sync n=%d, snap n=%d"
        % (sync_n, snap_posts[0]["n"]))


def test_disk_flush_failure_skips_snapshot(setup_env):
    env = setup_env
    prepare(env, env.tmp)
    env.router.update_state(fail_commands=["sync"])

    result = snap(env, "--new-key", "--skip-gates")

    assert_snapshot_failure(result)
    assert BASELINE not in env.router.snapshots(9102)
    assert_router_work_done(env)
    snap_posts = [c for c in result.calls if c.get("tool") == "curl"
                  and c.get("method") == "POST"
                  and c.get("url", "").endswith("/snapshot")]
    assert snap_posts == [], result.out


def test_prerelease_version_is_normalized_into_snapshot_name(setup_env):
    env = setup_env
    prepare(env, env.tmp)
    src = build_src(env.tmp / "src21", version="2.1.0-rc1")

    result = snap(env, "--new-key", "--skip-gates", src=src)

    assert result.rc == 0, result.out + result.err
    assert "baseline-newton-2-1-0-rc1" in env.router.snapshots(9102)
    assert "PASS snapshot baseline-newton-2-1-0-rc1 created" in result.out


def test_second_identical_run_changes_no_router_work_and_stops_on_name(
        setup_env):
    env = setup_env
    prepare(env, env.tmp)
    first = snap(env, "--new-key", "--skip-gates")
    assert first.rc == 0, first.out + first.err
    after_first = env.router.snapshot()

    second = snap(env, "--skip-gates")

    assert_snapshot_failure(second)
    assert "PASS add-key newton-agent: already on the router" in second.out
    assert "PASS add-key lab-runner: already on the router" in second.out
    assert env.router.snapshot() == after_first
    assert env.router.snapshots(9102).count(BASELINE) == 1


def test_lab_snapshot_new_key_reuses_every_present_local_file(setup_env):
    env = setup_env
    prepare(env, env.tmp)
    keys = {
        label: make_keypair(env, label)
        for label in ("newton-agent", "lab-runner")
    }
    env.router.add_authorized_key(restricted_line_text(
        "newton-agent", "change", key_blob(env, "newton-agent")))
    env.router.add_authorized_key(restricted_line_text(
        "lab-runner", "change", "AAAADIFFERENTLABRUNNERBLOB0000000001"))
    before_ak = env.router.read("etc/dropbear/authorized_keys")
    stats = {
        label: key.stat()
        for label, key in keys.items()
    }

    second = snap(env, "--new-key", "--skip-gates")

    assert second.rc == 1
    assert "PASS add-key newton-agent: already on the router" in second.out
    assert second.out.splitlines()[-1] == (
        "STOPPED lab-snapshot r1: the router already has a Newton key "
        "line for label lab-runner; revoke it first (sudo -u newton "
        "/usr/local/bin/newton-router-setup r1 revoke lab-runner)")
    assert env.router.read("etc/dropbear/authorized_keys") == before_ak
    for label, before_stat in stats.items():
        key = env.keys_dir / ("r1-" + label)
        assert key.stat().st_mtime_ns == before_stat.st_mtime_ns


def test_lab_snapshot_refuses_a_different_router_line(setup_env):
    env = setup_env
    prepare(env, env.tmp)
    for label in ("newton-agent", "lab-runner"):
        make_keypair(env, label)
    other_blob = (
        "AAAAC3NzaC1lZDI1NTE5AAAAIOTHERLOCRALLABSNAPSHOTKEY0001")
    env.router.write(
        "etc/dropbear/authorized_keys",
        restricted_line_text("newton-agent", "change", other_blob))
    before = env.router.read("etc/dropbear/authorized_keys")

    result = snap(env, "--skip-gates")

    assert result.rc == 1
    assert result.out.splitlines()[-1] == (
        "STOPPED lab-snapshot r1: the router already has a Newton key "
        "line for label newton-agent; revoke it first (sudo -u newton "
        "/usr/local/bin/newton-router-setup r1 revoke newton-agent)")
    assert env.router.read("etc/dropbear/authorized_keys") == before
