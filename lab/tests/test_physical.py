"""Physical lab device (kind = "physical") tests for newton-lab-test.py.

A physical device is reset by restoring a `sysupgrade -b` archive over a
direct, pinned, admin-key ssh session, then verified by a state fingerprint.
Everything here runs against a fake router; no network is touched."""
from __future__ import annotations

from conftest import lab_toml_path

import hashlib
import io
import re
import subprocess
import tarfile
from pathlib import Path

import pytest

import newton_lab_test as nl


ARCHIVE_PATH = "/tmp/newton-baseline.tar.gz"


def _cp(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr)


# ---------- fixtures: archive, key files, lab.toml ----------

ARCHIVE_FILES = {
    "etc/config/network": b"config interface 'lan'\n",
    "etc/config/system": b"config system\n",
    "etc/config/firewall": b"config defaults\n",
    "etc/config/dropbear": b"config dropbear\n",
    "etc/dropbear/authorized_keys": b"ssh-ed25519 AAAA fake\n",
    "etc/newton/state": b"n1\n",
    "etc/newton/device-id": b"pulsar\n",
    "etc/newton/profile": b"lab\n",
    "etc/passwd": b"root:x:0:0\n",          # not part of the fingerprint
}


def _make_archive(path: Path, files=None) -> str:
    files = ARCHIVE_FILES if files is None else files
    with tarfile.open(path, "w:gz") as tf:
        for name, data in files.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _expected_fingerprint(files=None) -> str:
    """Independent re-statement of the spec: sha256 over the sorted
    `sha256sum` lines of etc/config/*, etc/newton/*, etc/crontabs/*, plus
    the four named top-level files. /etc/newton/approve.key and
    /etc/newton/guard.lock are excluded (neither is in a sysupgrade backup;
    the approval key is checked for presence instead, the guard lock is
    bookkeeping the guard re-creates); line format `<sha256>  <path>` with no
    leading slash, matching busybox `sha256sum`."""
    files = ARCHIVE_FILES if files is None else files
    lines = []
    for name, data in files.items():
        if name in ("etc/newton/approve.key", "etc/newton/guard.lock"):
            continue  # never in a sysupgrade backup; not device state
        if (name.startswith("etc/config/") or name.startswith("etc/newton/")
                or name.startswith("etc/crontabs/")
                or name in ("etc/dropbear/authorized_keys", "etc/firewall.user",
                            "etc/rc.local", "etc/sysupgrade.conf")):
            lines.append(f"{hashlib.sha256(data).hexdigest()}  {name}\n")
    return hashlib.sha256("".join(sorted(lines)).encode()).hexdigest()


def _physical_toml_block(tmp_path: Path, *, sha: str, extra: str = "",
                         omit: tuple = (), settle_cmd="settle-probe") -> str:
    fields = {
        "kind": 'kind = "physical"',
        "host": 'host = "192.0.2.1"',
        "user": 'user = "root"',
        "lab": "lab = true",
        "board_name": 'board_name = "acme,board-1"',
        "proxy": "proxy = false",
        "known_hosts": f'known_hosts = "{tmp_path}/pk.hosts"',
        "admin_key": f'admin_key = "{tmp_path}/admin.key"',
        "baseline_backup": f'baseline_backup = "{tmp_path}/base.tar.gz"',
        "baseline_sha256": f'baseline_sha256 = "{sha}"',
        "settle_cmd": f'settle_cmd = "{settle_cmd}"',
    }
    body = "\n".join(v for k, v in fields.items() if k not in omit)
    return f"[devices.pulsar]\n{body}\n{extra}\n"


def _write_files(tmp_path: Path) -> str:
    (tmp_path / "admin.key").write_bytes(b"fake-admin-key\n")
    (tmp_path / "pk.hosts").write_text("192.0.2.1 ssh-ed25519 AAAA\n")
    (tmp_path / "change.key").write_bytes(b"fake-change-key\n")
    return _make_archive(tmp_path / "base.tar.gz")


def _toml(tmp_path: Path, device_block: str, vm_block: str = "") -> Path:
    p = tmp_path / "lab.toml"
    p.write_text(f"""
[pve]
host = "pve.test"
node = "lab"
token_file = "t"
pin_file = "p"

[ssh]
proxy = "ssh -W %h:%p root@pve.test"
password_file = "pw"
key = "/global/apollo.key"
router_key = "{tmp_path}/change.key"
known_hosts = "/global/known"

[settle]
quiet_s = 0
timeout_s = 5
poll_s = 1

{vm_block}
{device_block}
""")
    return p


VM_BLOCK = '[devices.vm1]\nvmid = 702\nhost = "10.0.0.2"\nuser = "root"\nsnapshot = "baseline"\n'


@pytest.fixture
def lab(tmp_path):
    sha = _write_files(tmp_path)
    return nl.load_lab(_toml(tmp_path, _physical_toml_block(tmp_path, sha=sha),
                             VM_BLOCK))


@pytest.fixture
def sha(tmp_path):
    return _write_files(tmp_path)


# ---------- loader ----------

def test_physical_load_accepts_full_block_and_vm_device_unchanged(lab, tmp_path):
    p = lab.devices["pulsar"]
    assert p.kind == "physical" and p.is_physical
    assert p.proxy is False
    assert p.admin_key == str(tmp_path / "admin.key")
    assert p.known_hosts == str(tmp_path / "pk.hosts")
    assert p.baseline_backup == str(tmp_path / "base.tar.gz")
    assert p.settle_cmd == "settle-probe"
    v = lab.devices["vm1"]
    assert (v.kind, v.vmid, v.snapshot) == ("vm", 702, "baseline")
    assert not v.is_physical and v.admin_key == ""


def test_physical_load_refuses_missing_field_naming_it(tmp_path, sha):
    for field in ("host", "user", "proxy", "known_hosts", "admin_key",
                  "baseline_backup", "baseline_sha256"):
        block = _physical_toml_block(tmp_path, sha=sha, omit=(field,))
        with pytest.raises(nl.LabConfigError, match=field):
            nl.load_lab(_toml(tmp_path, block))


def test_physical_load_refuses_proxy_true(tmp_path, sha):
    block = _physical_toml_block(tmp_path, sha=sha).replace(
        "proxy = false", "proxy = true")
    with pytest.raises(nl.LabConfigError, match="proxy"):
        nl.load_lab(_toml(tmp_path, block))


def test_physical_load_refuses_mixed_kinds(tmp_path, sha):
    block = _physical_toml_block(tmp_path, sha=sha, extra="vmid = 5")
    with pytest.raises(nl.LabConfigError, match="vmid"):
        nl.load_lab(_toml(tmp_path, block))
    block = _physical_toml_block(tmp_path, sha=sha, extra='snapshot = "b"')
    with pytest.raises(nl.LabConfigError, match="snapshot"):
        nl.load_lab(_toml(tmp_path, block))
    vm = ('[devices.vm1]\nvmid = 702\nhost = "h"\nuser = "root"\n'
          f'snapshot = "b"\nadmin_key = "{tmp_path}/admin.key"\n')
    with pytest.raises(nl.LabConfigError, match="admin_key"):
        nl.load_lab(_toml(tmp_path, "", vm))


def test_physical_load_refuses_unknown_kind(tmp_path, sha):
    block = _physical_toml_block(tmp_path, sha=sha).replace(
        'kind = "physical"', 'kind = "bare"')
    with pytest.raises(nl.LabConfigError, match="kind"):
        nl.load_lab(_toml(tmp_path, block))


def test_physical_load_refuses_relative_and_missing_paths(tmp_path, sha):
    for field in ("known_hosts", "admin_key", "baseline_backup"):
        block = _physical_toml_block(tmp_path, sha=sha)
        block = re.sub(rf'{field} = "[^"]*"', f'{field} = "relative/x"', block)
        with pytest.raises(nl.LabConfigError, match=field):
            nl.load_lab(_toml(tmp_path, block))
        block = _physical_toml_block(tmp_path, sha=sha)
        block = re.sub(rf'{field} = "[^"]*"',
                       f'{field} = "{tmp_path}/nope"', block)
        with pytest.raises(nl.LabConfigError, match=field):
            nl.load_lab(_toml(tmp_path, block))


def test_physical_load_refuses_archive_sha_mismatch(tmp_path, sha):
    block = _physical_toml_block(tmp_path, sha="0" * 64)
    with pytest.raises(nl.LabConfigError, match="baseline_sha256"):
        nl.load_lab(_toml(tmp_path, block))
    block = _physical_toml_block(tmp_path, sha="nothex")
    with pytest.raises(nl.LabConfigError, match="baseline_sha256"):
        nl.load_lab(_toml(tmp_path, block))


def test_physical_load_per_device_router_key_must_exist(tmp_path, sha):
    block = _physical_toml_block(
        tmp_path, sha=sha, extra=f'router_key = "{tmp_path}/nope"')
    with pytest.raises(nl.LabConfigError, match="router_key"):
        nl.load_lab(_toml(tmp_path, block))


def test_shipped_lab_toml_still_loads_and_example_is_not_enabled():
    text = lab_toml_path().read_text()
    assert "# [devices.pulsar]" in text
    assert "\n[devices.pulsar]" not in text
    lab = nl.load_lab(lab_toml_path())
    assert "pulsar" not in lab.devices


# ---------- fake router ----------

class FakeRouter:
    """Answers the fixed remote commands the physical reset issues."""

    def __init__(self, tmp_path, *, files=None,
                 world=None, installed=None):
        self.files = ARCHIVE_FILES if files is None else files
        self.calls: list[list[str]] = []     # every ssh argv
        self.uploads: list[bytes] = []
        self.config_on_router = ["network", "system", "extra", "wireless"]
        self.fingerprint = _expected_fingerprint(self.files)
        self.remote_sha = hashlib.sha256(
            (tmp_path / "base.tar.gz").read_bytes()).hexdigest()
        self.rebooted = False
        self.down_polls_left = 2
        self.fail: dict[str, list] = {}      # cmd prefix -> [results...]
        self.settle_calls = 0
        self.approve_key_present = True
        self.guard_states = []               # popped per status call; then "idle"
        self.newton_on_router = ["state", "approve.key"]
        self.identity = {"device": "pulsar", "profile": "lab",
                         "board": "acme,board-1"}
        self.identity_rc = 0
        # Package state on the router. Sorted lists so the result of PHYSICAL_*
        # probes is deterministic and round-trips through the runner.
        self.world = list(world) if world is not None else [
            "busybox-1.36.1-r28", "dnsmasq-2.93-r1", "dropbear-2024.85-r1",
            "firewall4-2025.05.04-r1", "libmbedtls21-3.6.3-r1",
            "openwrt-keyring-2025.05.21-r1"]
        self.installed = list(installed) if installed is not None else list(
            self.world)
        # apks called. apks_updates / apks_dels record every name the runner
        # sent, including before the extras that got refused (the latter never
        # happens in practice; kept for completeness).
        self.apk_updates: list[str] = []
        self.apk_dels: list[str] = []
        # When set, an `apk del` that matches these names resets `installed`
        # back to the recorded baseline. The next apk del call (or no further
        # change) uses the new value.
        self._del_resets_to_baseline = True
        self._baseline_installed = list(self.installed)
        # Call counters (used by tests to script state transitions across
        # the recording read, the apk del read and the post-reboot read).
        self.pkg_list_calls = 0
        self.world_calls = 0
        # Lists the fake installs onto the router on `reboot`, on top of
        # whatever is already there. Empty by default.
        self.install_post_reboot: list[str] = []
        # Optional callable executed on the `reboot` callback, just before the
        # fake ssh returns. Lets a test rename/delete the on-host state the
        # runner should re-check after the reboot.
        self._post_reboot_hook = None

    def remote(self, argv):
        return argv[-1]

    def cmds(self):
        return [self.remote(a) for a in self.calls]

    def _pkg_lines(self, lines: list[str]) -> str:
        return "\n".join(sorted(lines)) + "\n"

    def ssh(self, argv, *, env=None, timeout=None, input=None):
        self.calls.append(list(argv))
        cmd = argv[-1]
        for prefix, results in self.fail.items():
            if cmd.startswith(prefix) and results:
                r = results.pop(0)
                if r == "timeout":
                    raise subprocess.TimeoutExpired(argv, timeout or 1)
                return r
        if cmd == nl.PHYSICAL_IDENTITY_CMD:
            return _cp("".join(f"{k}={v}\n" for k, v in self.identity.items()),
                       returncode=self.identity_rc)
        if cmd == "true":
            if self.rebooted and self.down_polls_left > 0:
                self.down_polls_left -= 1
                return _cp(returncode=255)
            return _cp()
        if cmd.startswith("sha256sum /tmp/newton-baseline"):
            return _cp(f"{self.remote_sha}  /tmp/newton-baseline.tar.gz\n")
        if cmd == nl.PHYSICAL_PKG_LIST_CMD:
            self.pkg_list_calls += 1
            return _cp(self._pkg_lines(self.installed))
        if cmd == nl.PHYSICAL_WORLD_CMD:
            self.world_calls += 1
            return _cp(self._pkg_lines(self.world))
        if cmd == nl.PHYSICAL_APK_UPDATE_CMD:
            self.apk_updates.append(cmd)
            return _cp()
        if cmd.startswith("apk del "):
            self.apk_dels.append(cmd)
            names = cmd[len("apk del "):].split()
            # apk del matches a world entry by name, pinned (name=ver) or not.
            self.world = [n for n in self.world if n.split("=", 1)[0] not in names]
            if self._del_resets_to_baseline:
                # Simulate the real effect: a package that no longer has any
                # world entry referencing it is removed, and any libraries
                # only it depended on are gone too. Tests that want a
                # residual library left can set installed directly.
                if any(n not in self._baseline_installed for n in names):
                    extras = {x for x in self.installed
                              if x not in self._baseline_installed}
                else:
                    extras = set()
                self.installed = list(self._baseline_installed)
                for n in names:
                    if n in self.installed and n not in extras:
                        self.installed.remove(n)
                # The extra libs are gone: they were only pulled in by the
                # package we just removed. They are NOT re-added, even if
                # some other extra lib was already installed.
            return _cp()
        if cmd.startswith("find /etc/config"):
            return _cp("".join(f"/etc/config/{n}\n"
                               for n in self.config_on_router))
        if cmd == nl.PHYSICAL_GUARD_STATUS_CMD:
            st = self.guard_states.pop(0) if self.guard_states else "idle"
            return _cp(f"{st} since=0\n")
        if cmd == nl.PHYSICAL_LIST_NEWTON_CMD:
            return _cp("".join(f"/etc/newton/{n}\n" for n in self.newton_on_router))
        if cmd.startswith("rm -f") or cmd.startswith("rm -rf"):
            return _cp()
        if cmd.startswith("sysupgrade -r"):
            return _cp()
        if cmd == "reboot":
            self.rebooted = True
            if self.install_post_reboot:
                self.installed = [n for n in self.installed
                                   if n not in set(self.install_post_reboot)]
                self.installed.extend(
                    n for n in self.install_post_reboot
                    if n not in self.installed)
            if self._post_reboot_hook is not None:
                self._post_reboot_hook()
            return _cp(returncode=255)
        if cmd == nl.PHYSICAL_FINGERPRINT_CMD:
            return _cp(self.fingerprint + "\n")
        if cmd == nl.PHYSICAL_APPROVE_KEY_CMD:
            return _cp(returncode=0 if self.approve_key_present else 1)
        if cmd == "settle-probe":
            self.settle_calls += 1
            return _cp("stable\n")
        raise AssertionError(f"unexpected remote command: {cmd!r}")

    def stdin_file(self, argv, path, *, timeout=None):
        self.calls.append(list(argv))
        assert argv[-1] == "cat > /tmp/newton-baseline.tar.gz"
        self.uploads.append(Path(path).read_bytes())
        return _cp()


@pytest.fixture
def router(monkeypatch, tmp_path, lab):
    r = FakeRouter(tmp_path)
    monkeypatch.setattr(nl, "_run", r.ssh)
    monkeypatch.setattr(nl, "_run_stdin_file", r.stdin_file)
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "res")
    r.hellos = []
    r.hello_result = (True, "")
    monkeypatch.setattr(
        nl, "router_hello_preflight",
        lambda l, d: r.hellos.append(d.name) or r.hello_result)
    return r


@pytest.fixture
def pkg_router(monkeypatch, tmp_path, lab):
    """The shared router with a baseline set of packages that matches the
    test file's BASELINE_PKGS_* constants."""
    r = FakeRouter(tmp_path, world=BASELINE_PKGS_WORLD,
                   installed=BASELINE_PKGS_INSTALLED)
    monkeypatch.setattr(nl, "_run", r.ssh)
    monkeypatch.setattr(nl, "_run_stdin_file", r.stdin_file)
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "res")
    r.hellos = []
    r.hello_result = (True, "")
    monkeypatch.setattr(
        nl, "router_hello_preflight",
        lambda l, d: r.hellos.append(d.name) or r.hello_result)
    return r


def _reset(lab, **kw):
    recs: list[dict] = []
    last = nl.physical_reset(lab, "pulsar", recs, **kw)
    return last, recs


# ---------- argv shape ----------

def test_physical_reset_argv_direct_pinned_admin_key_only(lab, router, tmp_path):
    last, _ = _reset(lab)
    assert last["task_ok"] is True
    reset_calls = [a for a in router.calls]
    assert reset_calls
    for a in reset_calls:
        assert a[0] == "ssh"
        assert a[1:3] == ["-F", "/dev/null"]
        joined = " ".join(a)
        assert "ProxyCommand" not in joined and "ssh -W" not in joined
        assert "StrictHostKeyChecking=yes" in a
        assert "StrictHostKeyChecking=accept-new" not in joined
        assert f"UserKnownHostsFile={tmp_path}/pk.hosts" in a
        assert "BatchMode=yes" in a and "IdentitiesOnly=yes" in a
        i = a.index("-i")
        assert a[i + 1] == str(tmp_path / "admin.key")
        assert "/global/apollo.key" not in a
        assert a[-2] == "root@192.0.2.1"


def test_physical_ssh_cmd_uses_admin_key_direct_and_pinned(lab, tmp_path):
    """Like a VM's observer key (lab.ssh_key): checks, steps, vars, posts and
    settle all go through ssh_cmd with the device's unrestricted key."""
    dev = lab.devices["pulsar"]
    a = nl.ssh_cmd(lab, dev, "echo hi")
    assert a[0] == "ssh" and a[1:3] == ["-F", "/dev/null"]
    assert "ProxyCommand" not in " ".join(a)
    assert "StrictHostKeyChecking=yes" in a and "IdentitiesOnly=yes" in a
    assert f"UserKnownHostsFile={tmp_path}/pk.hosts" in a
    assert a[a.index("-i") + 1] == str(tmp_path / "admin.key")
    assert str(tmp_path / "change.key") not in a
    assert a[-2:] == ["root@192.0.2.1", "echo hi"]


def test_physical_checks_steps_and_settle_use_admin_key(lab, router, tmp_path):
    nl.wait_settled(lab, "pulsar")
    nl.ssh_ready(lab, lab.devices["pulsar"], timeout_s=1)
    for a in router.calls:
        assert a[a.index("-i") + 1] == str(tmp_path / "admin.key")


def test_physical_change_lane_never_gets_the_admin_key(lab, tmp_path):
    env = nl.build_env(lab, "key", "pulsar")
    assert str(tmp_path / "admin.key") not in env.values()
    assert env["OWRT_SSH_KEY"] == str(tmp_path / "change.key")
    assert env["OWRT_SSH_PROXY"] == ""
    assert env["OWRT_KNOWN_HOSTS"] == str(tmp_path / "pk.hosts")


def test_physical_per_device_router_key_overrides_global_in_change_lane(
        tmp_path, sha):
    (tmp_path / "own.key").write_bytes(b"k")
    block = _physical_toml_block(
        tmp_path, sha=sha, extra=f'router_key = "{tmp_path}/own.key"')
    lab = nl.load_lab(_toml(tmp_path, block))
    assert nl.build_env(lab, "key", "pulsar")["OWRT_SSH_KEY"] \
        == str(tmp_path / "own.key")
    cmds = []
    import pytest as _p
    mp = _p.MonkeyPatch()
    mp.setattr(nl, "_run", lambda argv, **k: cmds.append(argv) or _cp(""))
    try:
        nl.router_hello_preflight(lab, lab.devices["pulsar"])
    finally:
        mp.undo()
    a = cmds[0]
    assert a[a.index("-i") + 1] == str(tmp_path / "own.key")


def test_physical_hello_preflight_uses_change_key_direct_pinned(
        lab, tmp_path, monkeypatch):
    cmds = []
    monkeypatch.setattr(nl, "_run", lambda argv, **k: cmds.append(argv) or _cp(""))
    nl.router_hello_preflight(lab, lab.devices["pulsar"])
    a = cmds[0]
    assert a[a.index("-i") + 1] == str(tmp_path / "change.key")
    assert str(tmp_path / "admin.key") not in a
    assert "ProxyCommand" not in " ".join(a)
    assert "StrictHostKeyChecking=yes" in a
    assert f"UserKnownHostsFile={tmp_path}/pk.hosts" in a
    assert "hello" in a[-1]


def test_vm_ssh_cmd_unchanged(lab):
    a = nl.ssh_cmd(lab, lab.devices["vm1"], "true")
    assert a == ["ssh", "-i", "/global/apollo.key", "-o", "BatchMode=yes",
                 "-o", "StrictHostKeyChecking=accept-new",
                 "-o", "ConnectTimeout=8", "-o",
                 "ProxyCommand=ssh -W %h:%p root@pve.test", "root@10.0.0.2",
                 "true"]


def test_vm_build_env_unchanged(lab):
    env_vm = nl.build_env(lab, "key", "vm1")
    assert env_vm["OWRT_SSH_PROXY"] == "ssh -W %h:%p root@pve.test"
    assert env_vm["OWRT_KNOWN_HOSTS"] == "/global/known"


# ---------- step order ----------

def test_physical_reset_step_order(lab, router):
    last, recs = _reset(lab)
    cmds = router.cmds()
    def idx(pred):
        return next(i for i, c in enumerate(cmds) if pred(c))
    up = idx(lambda c: c.startswith("cat > "))
    sh = idx(lambda c: c.startswith("sha256sum"))
    ls = idx(lambda c: c.startswith("find /etc/config"))
    rm = idx(lambda c: c.startswith("rm -f"))
    su = idx(lambda c: c.startswith("sysupgrade -r"))
    rb = idx(lambda c: c == "reboot")
    st = idx(lambda c: c == "settle-probe")
    fp = idx(lambda c: c == nl.PHYSICAL_FINGERPRINT_CMD)
    assert up < sh < ls < rm < su < rb < st < fp
    assert router.uploads == [(lab.devices["pulsar"].baseline_backup
                               and Path(lab.devices["pulsar"].baseline_backup)
                               .read_bytes())]
    assert last["verify"] == "ok" and last["upid"] == "physical"
    assert recs == [last]


def test_physical_reset_waits_for_ssh_down_then_up(lab, router):
    _reset(lab)
    cmds = router.cmds()
    rb = cmds.index("reboot")
    after = cmds[rb + 1:]
    # two failed polls (router rebooting) are consumed before settle runs
    assert after.count("true") >= 3
    assert after.index("settle-probe") > max(
        i for i, c in enumerate(after) if c == "true") - 1


# ---------- extra config deletion ----------

def test_physical_reset_deletes_only_configs_missing_from_archive(lab, router):
    _reset(lab)
    rm = [c for c in router.cmds() if c.startswith("rm -f /etc/config")]
    assert rm == ["rm -f /etc/config/extra /etc/config/wireless"]


def test_physical_reset_no_rm_when_nothing_extra(lab, router):
    router.config_on_router = ["network", "system"]
    _reset(lab)
    assert not [c for c in router.cmds() if c.startswith("rm")
                and ARCHIVE_PATH not in c]


@pytest.mark.parametrize("bad", ["a b", "x;reboot", "$(id)", "a/b",
                                 "..", ".", "na`me", "ünï", "a\tb"])
def test_physical_reset_refuses_unsafe_config_names(lab, router, bad):
    router.config_on_router = ["network", bad]
    last, _ = _reset(lab)
    assert last["task_ok"] is False
    assert "unsafe" in last["exitstatus"] and repr(bad) in last["exitstatus"]
    cmds = router.cmds()
    assert not [c for c in cmds if c.startswith("rm")
                and ARCHIVE_PATH not in c]
    assert not [c for c in cmds if c.startswith("sysupgrade")]
    assert "reboot" not in cmds


# ---------- verify ----------

def test_physical_reset_verify_mismatch_fails_aborts_and_is_not_retried(
        lab, router):
    router.fingerprint = "0" * 64
    last, recs = _reset(lab)
    assert last["task_ok"] is False
    assert last["verify"] == "mismatch" and last["abort_run"] is True
    assert "fingerprint" in last["exitstatus"]
    assert router.cmds().count("reboot") == 1
    assert sum(c == nl.PHYSICAL_FINGERPRINT_CMD for c in router.cmds()) == 1
    assert len(recs) == 1


def test_physical_reset_verify_uses_archive_contents_not_bundled_constant(
        tmp_path, monkeypatch):
    other = dict(ARCHIVE_FILES)
    other["etc/config/system"] = b"config system\n\toption hostname 'zz'\n"
    (tmp_path / "admin.key").write_bytes(b"k")
    (tmp_path / "pk.hosts").write_text("x")
    (tmp_path / "change.key").write_bytes(b"k")
    sha = _make_archive(tmp_path / "base.tar.gz", other)
    lab = nl.load_lab(_toml(tmp_path, _physical_toml_block(tmp_path, sha=sha)))
    assert nl.archive_fingerprint(lab.devices["pulsar"].baseline_backup) \
        == _expected_fingerprint(other)
    assert _expected_fingerprint(other) != _expected_fingerprint()


def test_archive_fingerprint_leaves_nothing_on_disk(lab):
    before = set(Path("/tmp").glob("newton-fp-*"))
    nl.archive_fingerprint(lab.devices["pulsar"].baseline_backup)
    assert set(Path("/tmp").glob("newton-fp-*")) == before


def test_physical_reset_remote_sha_mismatch_fails_before_any_change(lab, router):
    router.remote_sha = "f" * 64
    last, _ = _reset(lab)
    assert last["task_ok"] is False and "sha256" in last["exitstatus"]
    cmds = router.cmds()
    assert not [c for c in cmds if c.startswith(("rm", "sysupgrade"))
                and ARCHIVE_PATH not in c]
    assert "reboot" not in cmds
    assert "abort_run" not in last or not last["abort_run"]


# ---------- retries ----------

def test_physical_reset_retries_transient_ssh_failure_then_succeeds(lab, router):
    router.fail["find /etc/config"] = [_cp(returncode=255), "timeout"]
    last, recs = _reset(lab, attempts=4, retry_sleep_s=0)
    assert last["task_ok"] is True and last["attempt"] == 3
    assert router.cmds().count("reboot") == 1
    assert len(router.uploads) == 3


def test_physical_reset_gives_up_after_bounded_attempts(lab, router):
    router.fail["cat > "] = []
    router.fail["find /etc/config"] = [_cp(returncode=255)] * 10
    last, recs = _reset(lab, attempts=3, retry_sleep_s=0)
    assert last["task_ok"] is False and last["attempt"] == 3
    assert "reboot" not in router.cmds()


def test_physical_reset_does_not_retry_a_nonssh_failure(lab, router):
    router.fail["sysupgrade -r"] = [_cp(stderr="bad archive", returncode=1)]
    last, _ = _reset(lab, attempts=4, retry_sleep_s=0)
    assert last["task_ok"] is False and last["attempt"] == 1
    assert "reboot" not in router.cmds()


def test_physical_reset_ssh_never_returns_fails_without_retry(lab, router, monkeypatch):
    ticks = iter(range(10 ** 6))
    monkeypatch.setattr(nl.time, "monotonic", lambda: float(next(ticks)))
    router.down_polls_left = 10 ** 6
    last, _ = _reset(lab, attempts=4, retry_sleep_s=0)
    assert last["task_ok"] is False
    assert router.cmds().count("reboot") == 1


# ---------- dispatch into the runner ----------

def test_reset_device_dispatches_by_kind(lab, router, monkeypatch):
    called = []
    monkeypatch.setattr(nl, "pve_reset",
                        lambda l, d, r, **k: called.append(d) or
                        {"task_ok": True, "upid": "u", "exitstatus": "OK",
                         "attempt": 1})
    nl.reset_device(lab, "vm1", [])
    assert called == ["vm1"] and not router.calls
    nl.reset_device(lab, "pulsar", [])
    assert called == ["vm1"] and router.calls


def test_run_start_reset_physical_ok_skips_pve_and_records(
        lab, router, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(nl, "pve_reset", lambda *a, **k: pytest.fail("pve"))
    del lab.devices["vm1"]
    out = tmp_path / "lr.json"
    assert nl._reset_lab_at_run_start(lab, out, lane="key") is True
    assert "lab-reset pulsar ok" in capsys.readouterr().out
    assert out.exists()


def test_run_start_reset_verify_mismatch_stops_run(
        lab, router, tmp_path, capsys):
    del lab.devices["vm1"]
    router.fingerprint = "1" * 64
    out = tmp_path / "lr.json"
    assert nl._reset_lab_at_run_start(lab, out, lane="key") is False
    err = capsys.readouterr().err
    assert "pulsar" in err and "fingerprint" in err


def test_scenario_level_verify_mismatch_marks_run_abort(lab, router):
    router.fingerprint = "2" * 64
    scen = nl.Scenario(name="s", description="", target="pulsar",
                       reset=["pulsar"], expect="none", timeout=1, batch="",
                       post=[], path=Path("s.toml"))
    rec = nl.run_scenario(lab, scen, lane="key")
    assert rec["abort_run"] is True and rec["error"]
    assert rec["passed"] is False


def test_reset_after_fingerprint_mismatch_fails_the_scenario(lab, router,
                                                           monkeypatch):
    """`reset_after` on a physical device: the start-of-scenario restore
    verifies clean, then the after restore does not, so the scenario record is
    still written with the error and the run is aborted."""
    orig = router.ssh
    verifies = []

    def ssh(argv, **kw):
        proc = orig(argv, **kw)
        cmd = argv[-1]
        if cmd == "reboot":
            # every restore reboots: give the fake its "router is down" polls
            # back, or the second reset waits out PHYSICAL_WAIT_SSH_DOWN_S
            router.down_polls_left = 2
        elif cmd == nl.PHYSICAL_FINGERPRINT_CMD:
            verifies.append(proc.stdout.strip())
            if len(verifies) == 1:
                router.fingerprint = "3" * 64   # the after restore diverges
        return proc

    monkeypatch.setattr(nl, "_run", ssh)
    scen = nl.Scenario(name="s", description="", target="pulsar",
                       reset=["pulsar"], reset_after=["pulsar"],
                       expect="none", timeout=1, batch="",
                       post=[], path=Path("s.toml"))
    rec = nl.run_scenario(lab, scen, lane="key")
    assert len(verifies) >= 2
    assert rec["reset"] and rec["reset"][0]["task_ok"] is True
    assert rec["reset_after"][-1]["task_ok"] is False
    assert rec["reset_after"][-1]["verify"] == "mismatch"
    assert rec["reset_after"][-1]["abort_run"] is True
    assert rec["abort_run"] is True
    assert "reset_after" in rec["error"] and "pulsar" in rec["error"]
    assert rec["passed"] is False
    assert nl.status_letter(rec) == "ERROR"


def test_vm_scenario_reset_has_no_abort_flag(lab, monkeypatch):
    monkeypatch.setattr(nl, "pve_reset", lambda *a, **k: {
        "task_ok": False, "upid": "u", "exitstatus": "boom", "attempt": 1})
    scen = nl.Scenario(name="s", description="", target="vm1",
                       reset=["vm1"], expect="none", timeout=1, batch="",
                       post=[], path=Path("s.toml"))
    rec = nl.run_scenario(lab, scen, lane="key")
    assert rec["error"] and not rec.get("abort_run")


# ---------- hello preflight after a physical reset ----------

def test_run_start_physical_key_lane_runs_hello_after_reset(
        lab, router, tmp_path):
    del lab.devices["vm1"]
    assert nl._reset_lab_at_run_start(lab, tmp_path / "r.json", lane="key")
    assert router.hellos == ["pulsar"]
    assert nl.PHYSICAL_FINGERPRINT_CMD in router.cmds()


def test_run_start_physical_password_lane_skips_hello(lab, router, tmp_path):
    del lab.devices["vm1"]
    assert nl._reset_lab_at_run_start(lab, tmp_path / "r.json",
                                      lane="password")
    assert router.hellos == []


def test_run_start_physical_hello_failure_stops_run_with_physical_wording(
        lab, router, tmp_path, capsys):
    del lab.devices["vm1"]
    router.hello_result = (False, "guard-state=busy is not idle")
    assert nl._reset_lab_at_run_start(lab, tmp_path / "r.json",
                                      lane="key") is False
    err = capsys.readouterr().err
    assert "hello preflight failed" in err and "guard-state=busy" in err
    assert "newton-router-setup pulsar install/check" in err
    assert "retake the baseline backup" in err
    assert "rebuild the snapshot" not in err


def test_scenario_level_physical_hello_failure_stops_run(lab, router):
    router.hello_result = (False, "prog abc... differs")
    scen = nl.Scenario(name="s", description="", target="pulsar",
                       reset=["pulsar"], expect="none", timeout=1, batch="",
                       post=[], path=Path("s.toml"))
    rec = nl.run_scenario(lab, scen, lane="key")
    assert rec["abort_run"] is True
    assert "retake the baseline backup" in rec["error"]


# ---------- reboot_device on a physical device ----------

def test_reboot_device_physical_uses_admin_reboot_never_proxmox(
        lab, router, monkeypatch, tmp_path):
    monkeypatch.setattr(nl, "pve_guest_reboot",
                        lambda *a, **k: pytest.fail("proxmox call"))
    monkeypatch.setattr(nl, "_curl_pve",
                        lambda *a, **k: pytest.fail("proxmox call"))
    boots = iter(["boot-a", "boot-b"])
    orig = router.ssh

    def ssh(argv, **kw):
        if argv[-1] == "cat /proc/sys/kernel/random/boot_id":
            router.calls.append(list(argv))
            return _cp(next(boots) + "\n")
        return orig(argv, **kw)
    monkeypatch.setattr(nl, "_run", ssh)
    recs: list = []
    rec = nl.reboot_device(lab, lab.devices["pulsar"], recs, "key")
    assert rec["ok"] is True and rec["rebooted"] and rec["fallback"] is None
    cmds = router.cmds()
    assert "reboot" in cmds
    rb = cmds.index("reboot")
    assert "true" in cmds[rb + 1:] and "settle-probe" in cmds[rb + 1:]
    assert cmds.index("settle-probe") > rb
    for a in router.calls:
        assert a[a.index("-i") + 1] == str(tmp_path / "admin.key")
    assert router.hellos == ["pulsar"]


def test_reboot_device_physical_ssh_never_returns_fails_without_proxmox(
        lab, router, monkeypatch):
    monkeypatch.setattr(nl, "pve_guest_reboot",
                        lambda *a, **k: pytest.fail("proxmox call"))
    ticks = iter(range(10 ** 6))
    monkeypatch.setattr(nl.time, "monotonic", lambda: float(next(ticks)))
    router.rebooted = True
    router.down_polls_left = 10 ** 6
    orig = router.ssh
    monkeypatch.setattr(nl, "_run", lambda argv, **kw: (
        _cp("boot-a\n") if argv[-1].startswith("cat /proc") else orig(argv, **kw)))
    rec = nl.reboot_device(lab, lab.devices["pulsar"], [], "key")
    assert rec["ok"] is False and "ssh not ready" in rec["reason"]
    assert rec["fallback"] is None


# ---------- approval key (kept out of sysupgrade backups) ----------

def test_archive_fingerprint_ignores_approve_key(tmp_path):
    with_key = dict(ARCHIVE_FILES)
    with_key["etc/newton/approve.key"] = b"secret\n"
    a = tmp_path / "a.tar.gz"
    b = tmp_path / "b.tar.gz"
    _make_archive(a)
    _make_archive(b, with_key)
    assert nl.archive_fingerprint(str(a)) == nl.archive_fingerprint(str(b))
    assert "approve.key" in nl.PHYSICAL_FINGERPRINT_CMD


def test_physical_reset_fails_when_approve_key_missing(lab, router):
    router.approve_key_present = False
    last, _ = _reset(lab)
    assert last["task_ok"] is False
    assert "approve.key" in last["exitstatus"]
    assert last.get("abort_run") is True


# ---------- guard state left by scenarios (/etc/newton) ----------

def test_physical_reset_waits_for_idle_guard_before_touching_anything(
        lab, router, monkeypatch):
    monkeypatch.setattr(nl.time, "sleep", lambda s: None)
    router.guard_states = ["pending", "pending", "idle"]
    last, _ = _reset(lab)
    assert last["task_ok"] is True
    cmds = router.cmds()
    statuses = [i for i, c in enumerate(cmds) if c == nl.PHYSICAL_GUARD_STATUS_CMD]
    assert len(statuses) == 3
    assert router.uploads and statuses[-1] < len(cmds)
    first_write = min(i for i, c in enumerate(router.calls)
                      if c[-1].startswith(("cat >", "rm ", "sysupgrade")))
    assert statuses[-1] < first_write


def test_physical_reset_stops_when_guard_never_idle(lab, router, monkeypatch):
    monkeypatch.setattr(nl.time, "sleep", lambda s: None)
    monkeypatch.setattr(nl, "PHYSICAL_GUARD_IDLE_TIMEOUT_S", 0)
    router.guard_states = ["pending"] * 50
    last, _ = _reset(lab)
    assert last["task_ok"] is False
    assert last["abort_run"] is True
    assert "guard" in last["exitstatus"]
    assert router.uploads == []
    assert not any(c.startswith(("rm ", "sysupgrade")) for c in router.cmds())


def test_physical_reset_clears_guard_leftovers_but_keeps_approve_key(lab, router):
    router.newton_on_router = ["state", "approve.key", "guard.log",
                               "last_revert", "lkg"]
    last, _ = _reset(lab)
    assert last["task_ok"] is True
    rm = [c for c in router.cmds() if c.startswith("rm -rf /etc/newton/")]
    assert rm == ["rm -rf /etc/newton/guard.log /etc/newton/last_revert "
                  "/etc/newton/lkg"]
    assert "approve.key" not in rm[0] and "/etc/newton/state" not in rm[0]


def test_physical_reset_keeps_the_guard_lock(lab, router):
    """etc/newton/guard.lock is the guard's own lock, held open while it runs,
    and the guard re-creates it after a restore. The reset deletes what the
    archive lacks, and a file the guard is holding open is not ours to
    delete."""
    router.newton_on_router = ["state", "approve.key", "guard.lock",
                               "guard.log", "lkg"]
    last, _ = _reset(lab)
    assert last["task_ok"] is True
    rm = [c for c in router.cmds() if c.startswith("rm -rf /etc/newton/")]
    assert rm == ["rm -rf /etc/newton/guard.log /etc/newton/lkg"]
    assert "guard.lock" not in " ".join(rm)


def test_physical_reset_refuses_unsafe_newton_name(lab, router):
    router.newton_on_router = ["state", "approve.key", "bad name;x"]
    last, _ = _reset(lab)
    assert last["task_ok"] is False
    assert not any(c.startswith("rm -rf") for c in router.cmds())


def test_physical_reset_accepts_restored_guard(lab, router):
    router.guard_states = ["restored"]
    last, _ = _reset(lab)
    assert last["task_ok"] is True


def test_physical_reset_stops_at_once_on_failed_guard(lab, router, monkeypatch):
    monkeypatch.setattr(nl.time, "sleep", lambda s: pytest.fail("must not wait"))
    router.guard_states = ["failed"]
    last, _ = _reset(lab)
    assert last["task_ok"] is False and last["abort_run"] is True
    assert router.uploads == []


# ---------- lab marker and identity guard before anything destructive ----------

DESTRUCTIVE = ("cat >", "rm ", "sysupgrade", "reboot")


def _destructive(router):
    return [c for c in router.cmds() if c.startswith(DESTRUCTIVE)]


def test_physical_load_requires_lab_true(tmp_path, sha):
    block = _physical_toml_block(tmp_path, sha=sha, omit=("lab",))
    with pytest.raises(nl.LabConfigError, match="lab"):
        nl.load_lab(_toml(tmp_path, block))
    for bad in ("false", '"true"', "1"):
        block = _physical_toml_block(tmp_path, sha=sha).replace(
            "lab = true", f"lab = {bad}")
        with pytest.raises(nl.LabConfigError, match="lab"):
            nl.load_lab(_toml(tmp_path, block))


def test_vm_device_may_not_set_lab_or_board_name(tmp_path, sha):
    for f in ('lab = true', 'board_name = "x"'):
        vm = ('[devices.vm1]\nvmid = 702\nhost = "h"\nuser = "root"\n'
              f'snapshot = "b"\n{f}\n')
        with pytest.raises(nl.LabConfigError, match=f.split()[0]):
            nl.load_lab(_toml(tmp_path, "", vm))


def test_physical_board_name_is_required_and_loaded(tmp_path, sha):
    block = _physical_toml_block(tmp_path, sha=sha)
    assert nl.load_lab(_toml(tmp_path, block)).devices["pulsar"].board_name \
        == "acme,board-1"
    block = _physical_toml_block(tmp_path, sha=sha, omit=("board_name",))
    with pytest.raises(nl.LabConfigError, match="board_name"):
        nl.load_lab(_toml(tmp_path, block))
    for bad in ('board_name = ""', 'board_name = " x"', 'board_name = 3'):
        block = _physical_toml_block(tmp_path, sha=sha, omit=("board_name",),
                                     extra=bad)
        with pytest.raises(nl.LabConfigError, match="board_name"):
            nl.load_lab(_toml(tmp_path, block))


def test_identity_probe_is_first_and_read_only_admin_key_pinned(
        lab, router, tmp_path):
    last, _ = _reset(lab)
    assert last["task_ok"] is True
    assert router.cmds()[0] == nl.PHYSICAL_IDENTITY_CMD
    a = router.calls[0]
    assert a[a.index("-i") + 1] == str(tmp_path / "admin.key")
    assert "StrictHostKeyChecking=yes" in a
    probe = nl.PHYSICAL_IDENTITY_CMD.replace("2>/dev/null", "")
    for verb in ("rm ", "sysupgrade", "reboot", "tee", ">", "mv ", "uci "):
        assert verb not in probe
    for f in ("/etc/newton/device-id", "/etc/newton/profile",
              "/tmp/sysinfo/board_name"):
        assert f in nl.PHYSICAL_IDENTITY_CMD


@pytest.mark.parametrize("ident", [
    {"device": "pulsar", "profile": "prod", "board": "acme,board-1"},
    {"device": "quasar", "profile": "lab", "board": "acme,board-1"},
    {"device": "quasar", "profile": "prod", "board": "acme,board-1"},
    {"device": "pulsar", "profile": "", "board": "acme,board-1"},
    {"device": "", "profile": "lab", "board": "acme,board-1"},
    {"device": "pulsar", "profile": "lab ", "board": "acme,board-1"},
    {"device": "pulsar2", "profile": "lab", "board": "acme,board-1"},
])
def test_wrong_identity_aborts_before_any_destructive_command(
        lab, router, ident):
    router.identity = ident
    last, _ = _reset(lab)
    assert last["task_ok"] is False and last["abort_run"] is True
    assert "identity" in last["exitstatus"]
    assert router.cmds() == [nl.PHYSICAL_IDENTITY_CMD]
    assert _destructive(router) == [] and router.uploads == []


def test_board_name_mismatch_aborts(lab, router):
    router.identity["board"] = "other,board"
    last, _ = _reset(lab)
    assert last["task_ok"] is False and last["abort_run"] is True
    assert "board" in last["exitstatus"]
    assert router.cmds() == [nl.PHYSICAL_IDENTITY_CMD]


def test_unreadable_identity_aborts_before_any_destructive_command(
        lab, router):
    router.identity_rc = 1
    last, _ = _reset(lab)
    assert last["task_ok"] is False and last["abort_run"] is True
    assert _destructive(router) == []
    router.calls.clear()
    router.identity_rc = 0
    router.fail[nl.PHYSICAL_IDENTITY_CMD] = [_cp("garbage\n")]
    last, _ = _reset(lab)
    assert last["task_ok"] is False and last["abort_run"] is True
    assert _destructive(router) == []


def test_identity_ssh_failure_is_retried_but_never_goes_destructive(
        lab, router, monkeypatch):
    monkeypatch.setattr(nl.time, "sleep", lambda s: None)
    router.fail[nl.PHYSICAL_IDENTITY_CMD] = [_cp(returncode=255, stderr="x")]
    last, recs = _reset(lab, retry_sleep_s=0)
    assert last["task_ok"] is True and len(recs) == 2
    assert router.cmds().count(nl.PHYSICAL_IDENTITY_CMD) == 2


def test_wrong_identity_stops_every_lane_before_any_reset_step(
        lab, router, tmp_path):
    del lab.devices["vm1"]
    router.identity["profile"] = "prod"
    for lane in ("key", "password"):
        assert nl._reset_lab_at_run_start(
            lab, tmp_path / "r.json", lane=lane) is False
    assert _destructive(router) == []
    assert router.hellos == []


def test_reboot_device_physical_checks_identity_before_reboot(
        lab, router, monkeypatch):
    router.identity["device"] = "quasar"
    orig = router.ssh
    monkeypatch.setattr(nl, "_run", lambda argv, **kw: (
        _cp("boot-a\n") if argv[-1].startswith("cat /proc") else orig(argv, **kw)))
    rec = nl.reboot_device(lab, lab.devices["pulsar"], [], "key")
    assert rec["ok"] is False and "identity" in rec["reason"]
    assert "reboot" not in router.cmds()


def test_main_proves_identity_before_steps_even_with_no_lab_reset(
        lab, router, tmp_path, monkeypatch):
    lab_toml = tmp_path / "lab.toml"
    scens = tmp_path / "scens"
    scens.mkdir()
    (scens / "s.toml").write_text(
        'name = "s"\ndescription = "d"\ntarget = "pulsar"\nreset = []\n'
        'expect = "none"\nsetup = []\ncleanup = []\n')
    router.identity["profile"] = "prod"
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "res")
    rc = nl.main(["--lab", str(lab_toml), "--scenarios", str(scens),
                  "--lane", "password", "--no-lab-reset"])
    assert rc == 2
    assert router.cmds() == [nl.PHYSICAL_IDENTITY_CMD]


# ---------- validate the baseline archive before any deletion ----------

def _tar_with(path: Path, members: list) -> str:
    """members: (name, kind, data_or_linkname)"""
    with tarfile.open(path, "w:gz") as tf:
        for name, kind, extra in members:
            ti = tarfile.TarInfo(name)
            if kind == "file":
                ti.size = len(extra)
                tf.addfile(ti, io.BytesIO(extra))
            elif kind == "sym":
                ti.type = tarfile.SYMTYPE
                ti.linkname = extra
                tf.addfile(ti)
            elif kind == "hard":
                ti.type = tarfile.LNKTYPE
                ti.linkname = extra
                tf.addfile(ti)
            elif kind == "dir":
                ti.type = tarfile.DIRTYPE
                tf.addfile(ti)
            elif kind == "fifo":
                ti.type = tarfile.FIFOTYPE
                tf.addfile(ti)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _good_members():
    return [(n, "file", d) for n, d in ARCHIVE_FILES.items()]


def _load_with(tmp_path, members=None, raw: bytes | None = None):
    (tmp_path / "admin.key").write_bytes(b"k")
    (tmp_path / "pk.hosts").write_text("x")
    (tmp_path / "change.key").write_bytes(b"k")
    if raw is not None:
        (tmp_path / "base.tar.gz").write_bytes(raw)
        sha = hashlib.sha256(raw).hexdigest()
    else:
        sha = _tar_with(tmp_path / "base.tar.gz", members)
    return nl.load_lab(_toml(tmp_path, _physical_toml_block(tmp_path, sha=sha)))


def test_archive_with_only_f_is_refused_at_load(tmp_path):
    with pytest.raises(nl.LabConfigError, match="baseline_backup"):
        _load_with(tmp_path, [("f", "file", b"x")])


@pytest.mark.parametrize("bad", [
    ("../etc/config/evil", "file", b"x"),
    ("etc/../../x", "file", b"x"),
    ("/etc/config/abs", "file", b"x"),
    ("etc/config/ln", "sym", "/etc/shadow"),
    ("etc/config/ln", "sym", "../../../etc/passwd"),
    ("etc/config/ln", "hard", "../x"),
    ("etc/config/ln", "hard", "etc/config/network"),   # fingerprint cannot see it
    ("etc/config/ln", "hard", "/etc/passwd"),
    ("etc/config/fifo", "fifo", b""),
])
def test_archive_with_unsafe_members_is_refused_at_load(tmp_path, bad):
    with pytest.raises(nl.LabConfigError, match="baseline_backup"):
        _load_with(tmp_path, _good_members() + [bad])


def test_archive_that_is_not_a_readable_targz_is_refused_at_load(tmp_path):
    with pytest.raises(nl.LabConfigError, match="baseline_backup"):
        _load_with(tmp_path, raw=b"synthetic archive")


@pytest.mark.parametrize("missing", [
    "etc/config/network", "etc/config/firewall", "etc/config/system",
    "etc/config/dropbear", "etc/dropbear/authorized_keys"])
def test_archive_missing_a_required_file_is_refused_naming_it(tmp_path, missing):
    members = [m for m in _good_members() if m[0] != missing]
    with pytest.raises(nl.LabConfigError, match=re.escape(missing)):
        _load_with(tmp_path, members)


@pytest.mark.parametrize("name,good,bad", [
    ("etc/newton/device-id", b"pulsar\n", b"quasar\n"),
    ("etc/newton/profile", b"lab\n", b"prod\n"),
])
def test_archive_identity_files_are_required_and_checked(
        tmp_path, name, good, bad):
    others = [m for m in _good_members() if m[0] != name]
    with pytest.raises(nl.LabConfigError, match=re.escape(name)):
        _load_with(tmp_path, others)
    for data in (bad, b"", good + good, b" " + good, good.rstrip() + b"\r\n"):
        with pytest.raises(nl.LabConfigError, match=re.escape(name)):
            _load_with(tmp_path, others + [(name, "file", data)])
    for data in (good, good.rstrip()):          # one trailing newline optional
        _load_with(tmp_path, others + [(name, "file", data)])


def test_archive_without_newton_state_is_refused_empty_keep_set(tmp_path):
    members = [m for m in _good_members() if not m[0].startswith("etc/newton/")]
    with pytest.raises(nl.LabConfigError, match="etc/newton"):
        _load_with(tmp_path, members)


def test_valid_archive_with_dot_prefix_and_safe_links_and_dirs_loads(tmp_path):
    members = [("./" + n, "file", d) for n, d in ARCHIVE_FILES.items()]
    members += [("etc", "dir", None), ("etc/config/ok", "sym", "network")]
    lab = _load_with(tmp_path, members)
    assert lab.devices["pulsar"].is_physical


def test_archive_swapped_after_load_is_refused_before_any_ssh(lab, router,
                                                              tmp_path):
    _tar_with(tmp_path / "base.tar.gz", [("f", "file", b"x")])
    last, _ = _reset(lab)
    assert last["task_ok"] is False and last["abort_run"] is True
    assert "archive" in last["exitstatus"]
    assert router.calls == []


def test_archive_changed_but_valid_is_refused_by_local_sha_before_ssh(
        lab, router, tmp_path):
    files = dict(ARCHIVE_FILES)
    files["etc/config/extra2"] = b"x"
    _make_archive(tmp_path / "base.tar.gz", files)
    last, _ = _reset(lab)
    assert last["task_ok"] is False and last["abort_run"] is True
    assert "sha256" in last["exitstatus"]
    assert router.calls == []


# ---------- host keys ----------

def test_physical_ssh_ignores_global_known_hosts(lab, router, tmp_path):
    _reset(lab)
    for a in router.calls:
        assert "GlobalKnownHostsFile=/dev/null" in a
        assert "StrictHostKeyChecking=yes" in a
        assert f"UserKnownHostsFile={tmp_path}/pk.hosts" in a
    a = nl._physical_ssh(lab.devices["pulsar"], "k", "true")
    assert "GlobalKnownHostsFile=/dev/null" in a


def test_host_key_failure_is_not_retried_and_aborts_run(lab, router,
                                                        monkeypatch):
    monkeypatch.setattr(nl.time, "sleep", lambda s: pytest.fail("no retry wait"))
    router.fail[nl.PHYSICAL_IDENTITY_CMD] = [_cp(
        returncode=255, stderr="Host key verification failed.\n")] * 5
    last, recs = _reset(lab, attempts=3, retry_sleep_s=0)
    assert last["task_ok"] is False and last["abort_run"] is True
    assert "host key" in last["exitstatus"].lower()
    assert len(recs) == 1
    assert router.cmds() == [nl.PHYSICAL_IDENTITY_CMD]


def test_ssh_ready_gives_up_at_once_on_host_key_failure(lab, monkeypatch):
    calls = []
    monkeypatch.setattr(nl, "_run", lambda argv, **k: calls.append(argv) or _cp(
        returncode=255, stderr="Host key verification failed.\n"))
    monkeypatch.setattr(nl.time, "sleep", lambda s: pytest.fail("no wait"))
    assert nl.ssh_ready(lab, lab.devices["pulsar"], timeout_s=120) is False
    assert len(calls) == 1


# ---------- the uploaded archive is removed on every exit path ----------

def _archive_rms(router):
    return [c for c in router.cmds() if c == f"rm -f {ARCHIVE_PATH}"]


def test_uploaded_archive_removed_after_success_before_reboot(lab, router):
    last, _ = _reset(lab)
    assert last["task_ok"] is True
    cmds = router.cmds()
    assert cmds.count(f"rm -f {ARCHIVE_PATH}") == 1
    assert cmds.index(f"rm -f {ARCHIVE_PATH}") < cmds.index("reboot")
    assert cmds.index(f"rm -f {ARCHIVE_PATH}") > next(
        i for i, c in enumerate(cmds) if c.startswith("sysupgrade -r"))


def test_uploaded_archive_removed_on_remote_sha_mismatch(lab, router):
    router.remote_sha = "0" * 64
    last, _ = _reset(lab)
    assert last["task_ok"] is False
    assert _archive_rms(router)


def test_uploaded_archive_removed_when_sysupgrade_fails(lab, router):
    router.fail["sysupgrade -r"] = [_cp(returncode=1)]
    last, _ = _reset(lab)
    assert last["task_ok"] is False
    assert _archive_rms(router)
    assert "reboot" not in router.cmds()


def test_uploaded_archive_removed_when_config_delete_fails(lab, router):
    router.fail["rm -f /etc/config"] = [_cp(returncode=1)]
    last, _ = _reset(lab)
    assert last["task_ok"] is False
    assert _archive_rms(router)


def test_archive_cleanup_is_best_effort(lab, router):
    router.fail[f"rm -f {ARCHIVE_PATH}"] = ["timeout"]
    last, _ = _reset(lab)
    assert last["task_ok"] is True


def test_no_archive_cleanup_when_nothing_was_uploaded(lab, router):
    router.identity["profile"] = "prod"
    _reset(lab)
    assert _archive_rms(router) == []


# ---------- package state on a physical device ----------

# Sample package state a Pulsar baseline snapshot fits in. Names are
# realistic apk names ("<name>-<version>" for installed, plain names for
# /etc/apk/world), not literal baselines.
BASELINE_PKGS_INSTALLED = [
    "apk-mbedtls-3.0.5-r3", "busybox-1.36.1-r28", "dnsmasq-2.93-r1",
    "dropbear-2024.85-r1", "firewall4-2025.05.04-r1",
    "libmbedtls21-3.6.3-r1", "openwrt-keyring-2025.05.21-r1",
]
BASELINE_PKGS_WORLD = [
    "busybox", "dnsmasq", "dropbear", "firewall4", "libmbedtls21",
    "openwrt-keyring",
]


def _pkg_rec_paths(dev_name, tmp_path):
    d = tmp_path / "res" / "packages"
    return d / f"{dev_name}.installed", d / f"{dev_name}.world"


def test_physical_reset_first_run_records_packages_0600_in_0700_dir(lab,
                                                                   pkg_router,
                                                                   tmp_path):
    last, recs = _reset(lab)
    assert last["task_ok"] is True
    # No package commands beyond the recording reads.
    assert pkg_router.apk_updates == [] and pkg_router.apk_dels == []
    ipath, wpath = _pkg_rec_paths("pulsar", tmp_path)
    assert ipath.exists() and wpath.exists()
    d = ipath.parent
    assert d.is_dir() and oct(d.stat().st_mode & 0o777) == "0o700"
    assert oct(ipath.stat().st_mode & 0o777) == "0o600"
    assert oct(wpath.stat().st_mode & 0o777) == "0o600"
    assert ipath.read_text().splitlines() == sorted(
        BASELINE_PKGS_INSTALLED)
    assert wpath.read_text().splitlines() == sorted(BASELINE_PKGS_WORLD)
    assert recs[-1]["packages"] == {
        "recorded": True,
        "installed": len(BASELINE_PKGS_INSTALLED),
        "world": len(BASELINE_PKGS_WORLD),
    }
    # The record is the package state the reset restores to, so it has to be
    # the state as it was BEFORE the first change. Both reads, in that order,
    # before the archive is uploaded and before anything on the router is
    # touched: an `rm`, an apk change or a sysupgrade -r first would record the
    # reset's own result as the baseline and the next run would have nothing
    # to restore.
    cmds = pkg_router.cmds()
    list_i = cmds.index(nl.PHYSICAL_PKG_LIST_CMD)
    world_i = cmds.index(nl.PHYSICAL_WORLD_CMD)
    upload_i = cmds.index(f"cat > {nl.PHYSICAL_REMOTE_ARCHIVE}")
    assert list_i < world_i < upload_i
    changes = [i for i, c in enumerate(cmds)
               if c.startswith(("rm -f", "rm -rf", "sysupgrade -r",
                                "apk del ", "apk update"))]
    # Not vacuous: the reset does delete the extra /etc/config files and then
    # restores with sysupgrade -r, both after the record.
    assert changes
    assert min(changes) > world_i


def test_physical_reset_tightens_a_loose_record_dir_to_0700(lab, pkg_router,
                                                            tmp_path):
    # A pre-existing record directory with looser bits (e.g. 0755 from a
    # earlier older runner or an operator hand-creation): the first reset
    # that needs to write the record tightens it back to 0700.
    d = tmp_path / "res" / nl.PHYSICAL_PKG_RECORD_DIR
    d.mkdir(parents=True)
    d.chmod(0o755)
    assert oct(d.stat().st_mode & 0o777) == "0o755"
    last, _ = _reset(lab)
    assert last["task_ok"] is True
    assert oct(d.stat().st_mode & 0o777) == "0o700"
    # Files remain 0600.
    ipath, wpath = _pkg_rec_paths("pulsar", tmp_path)
    assert oct(ipath.stat().st_mode & 0o777) == "0o600"
    assert oct(wpath.stat().st_mode & 0o777) == "0o600"


def test_physical_reset_uses_record_when_present(lab, pkg_router, tmp_path):
    ipath, wpath = _pkg_rec_paths("pulsar", tmp_path)
    ipath.parent.mkdir(parents=True, exist_ok=True)
    ipath.write_text("\n".join(BASELINE_PKGS_INSTALLED) + "\n")
    wpath.write_text("\n".join(BASELINE_PKGS_WORLD) + "\n")
    last, recs = _reset(lab)
    assert last["task_ok"] is True
    assert pkg_router.apk_updates == [] and pkg_router.apk_dels == []
    assert "packages" not in recs[-1]   # did not record: already present
    # The record files are unchanged.
    assert ipath.read_text().splitlines() == sorted(BASELINE_PKGS_INSTALLED)
    assert wpath.read_text().splitlines() == sorted(BASELINE_PKGS_WORLD)


def test_physical_reset_runs_apk_update_then_apk_del_for_extra_world(
        lab, pkg_router, tmp_path):
    ipath, wpath = _pkg_rec_paths("pulsar", tmp_path)
    ipath.parent.mkdir(parents=True, exist_ok=True)
    ipath.write_text("\n".join(BASELINE_PKGS_INSTALLED) + "\n")
    wpath.write_text("\n".join(BASELINE_PKGS_WORLD) + "\n")
    extra_name = "dnsmasq-full"
    pkg_router.world = list(BASELINE_PKGS_WORLD) + [extra_name]
    pkg_router.installed = list(BASELINE_PKGS_INSTALLED) + [
        extra_name + "-2.93-r1"]
    # After apk del the world entry and its lib (not in baseline) are both
    # gone, so the re-read matches the record.
    pkg_router._baseline_installed = list(BASELINE_PKGS_INSTALLED)
    pkg_router._del_resets_to_baseline = True
    last, recs = _reset(lab)
    assert last["task_ok"] is True
    assert pkg_router.apk_updates == [nl.PHYSICAL_APK_UPDATE_CMD]
    assert pkg_router.apk_dels == [f"apk del {extra_name}"]
    cmds = pkg_router.cmds()
    apk_del_idx = cmds.index(f"apk del {extra_name}")
    find_etc_idx = next(i for i, c in enumerate(cmds)
                        if c.startswith("find /etc/config"))
    sysupg_idx = next(i for i, c in enumerate(cmds)
                      if c.startswith("sysupgrade -r"))
    assert apk_del_idx < find_etc_idx < sysupg_idx
    assert recs[-1]["packages_removed"] == [extra_name]


def test_physical_reset_runs_apk_del_without_update_when_nothing_extra(
        lab, pkg_router, tmp_path):
    ipath, wpath = _pkg_rec_paths("pulsar", tmp_path)
    ipath.parent.mkdir(parents=True, exist_ok=True)
    ipath.write_text("\n".join(BASELINE_PKGS_INSTALLED) + "\n")
    wpath.write_text("\n".join(BASELINE_PKGS_WORLD) + "\n")
    last, recs = _reset(lab)
    assert last["task_ok"] is True
    assert pkg_router.apk_updates == [] and pkg_router.apk_dels == []
    assert recs[-1]["packages_removed"] == []


def test_physical_reset_aborts_when_apk_del_returns_nonzero(
        lab, pkg_router, tmp_path):
    ipath, wpath = _pkg_rec_paths("pulsar", tmp_path)
    ipath.parent.mkdir(parents=True, exist_ok=True)
    ipath.write_text("\n".join(BASELINE_PKGS_INSTALLED) + "\n")
    wpath.write_text("\n".join(BASELINE_PKGS_WORLD) + "\n")
    extra_name = "dnsmasq-full"
    pkg_router.world = list(BASELINE_PKGS_WORLD) + [extra_name]
    pkg_router.installed = list(BASELINE_PKGS_INSTALLED) + [
        extra_name + "-2.93-r1"]
    pkg_router._baseline_installed = list(BASELINE_PKGS_INSTALLED)
    pkg_router._del_resets_to_baseline = True
    # Make the apk del fail with rc=1 and a tail on stderr that the stop
    # message should quote.
    pkg_router.fail["apk del "] = [_cp(
        returncode=1, stderr="ERROR: unable to remove "
        f"{extra_name}: not found in database (final 200 chars)\n" * 5)]
    last, _ = _reset(lab)
    assert last["task_ok"] is False and last["abort_run"] is True
    msg = last["exitstatus"]
    assert "apk del" in msg
    assert extra_name in msg
    assert "rc=1" in msg
    assert "NOT at its baseline package state" in msg
    cmds = pkg_router.cmds()
    # sysupgrade -r is never reached when apk del fails: the device is NOT
    # at its baseline package state.
    assert not [c for c in cmds if c.startswith("sysupgrade -r")]
    assert "reboot" not in cmds


def test_physical_reset_stops_when_recorded_world_entry_missing(lab,
                                                                pkg_router,
                                                                tmp_path):
    ipath, wpath = _pkg_rec_paths("pulsar", tmp_path)
    ipath.parent.mkdir(parents=True, exist_ok=True)
    ipath.write_text("\n".join(BASELINE_PKGS_INSTALLED) + "\n")
    wpath.write_text("\n".join(BASELINE_PKGS_WORLD) + "\n")
    pkg_router.world = [n for n in BASELINE_PKGS_WORLD if n != "dnsmasq"]
    last, _ = _reset(lab)
    assert last["task_ok"] is False and last["abort_run"] is True
    assert pkg_router.apk_updates == [] and pkg_router.apk_dels == []
    cmds = pkg_router.cmds()
    assert not [c for c in cmds if c.startswith("find /etc/config")]
    assert not [c for c in cmds if c.startswith("sysupgrade -r")]
    assert "reboot" not in cmds
    assert "dnsmasq" in last["exitstatus"]
    assert "delete both files" in last["exitstatus"]


def test_physical_reset_stops_when_apk_del_leaves_extra_or_missing_installed(
        lab, pkg_router, tmp_path):
    ipath, wpath = _pkg_rec_paths("pulsar", tmp_path)
    ipath.parent.mkdir(parents=True, exist_ok=True)
    # A library left after apk del: `installed` still has an extra name.
    rec_installed = list(BASELINE_PKGS_INSTALLED)
    extra_lib = "libstale-1.0-r1"
    ipath.write_text("\n".join(rec_installed) + "\n")
    wpath.write_text("\n".join(BASELINE_PKGS_WORLD) + "\n")
    pkg_router.world = list(BASELINE_PKGS_WORLD) + ["extra-pkg"]
    pkg_router.installed = list(rec_installed) + [extra_lib, "extra-pkg-1.0-r1"]
    pkg_router._baseline_installed = rec_installed  # default reset keeps extras
    # Make apk del a no-op for installed (the world entry's library is
    # gone, but a different lib stays): simulate by NOT marking the world
    # entry as already known.
    pkg_router._del_resets_to_baseline = False
    last, _ = _reset(lab)
    assert last["task_ok"] is False and last["abort_run"] is True
    assert "apk del extra-pkg" in pkg_router.apk_dels
    assert "installed packages differ from the record" in last["exitstatus"]
    cmds = pkg_router.cmds()
    assert not [c for c in cmds if c.startswith("sysupgrade -r")]
    assert "reboot" not in cmds


def test_physical_reset_aborts_after_reboot_when_installed_differs(
        lab, pkg_router, tmp_path, caplog):
    ipath, wpath = _pkg_rec_paths("pulsar", tmp_path)
    ipath.parent.mkdir(parents=True, exist_ok=True)
    ipath.write_text("\n".join(BASELINE_PKGS_INSTALLED) + "\n")
    wpath.write_text("\n".join(BASELINE_PKGS_WORLD) + "\n")
    # Router has one extra package on entry. apk del removes it; the
    # re-check inside the same restore finds nothing extra and proceeds.
    # Reboot then installs a new package (e.g. something brought back by
    # a scenario a previous run left behind). The post-restore check
    # catches that as a mismatch and the device is NOT verified.
    pkg_router.world = list(BASELINE_PKGS_WORLD) + ["extra-x"]
    pkg_router.installed = list(BASELINE_PKGS_INSTALLED) + [
        "extra-x-1.0-r1"]
    pkg_router._baseline_installed = list(BASELINE_PKGS_INSTALLED)
    pkg_router._del_resets_to_baseline = True
    pkg_router.install_post_reboot = ["surprise-pkg-2.0-r1"]
    last, _ = _reset(lab)
    if last.get("abort_run") is not True:
        caplog.set_level("DEBUG")
        for c in caplog.records:
            print("LOG:", c.message)
        print("FAIL:")
        print("installed at end:", pkg_router.installed)
        print("recorded installed:", list(ipath.read_text().splitlines()))
        print("recorded world:", list(wpath.read_text().splitlines()))
        print("calls:", [c[-1] for c in pkg_router.calls])
    assert last["task_ok"] is False
    assert last["abort_run"] is True
    assert last["verify"] == "mismatch"
    assert "installed packages differ from the record" in last["exitstatus"]
    assert "the device is NOT verified" in last["exitstatus"]


def test_physical_reset_stops_with_mismatch_when_pkg_record_vanished(
        lab, pkg_router, tmp_path):
    ipath, wpath = _pkg_rec_paths("pulsar", tmp_path)
    ipath.parent.mkdir(parents=True, exist_ok=True)
    ipath.write_text("\n".join(BASELINE_PKGS_INSTALLED) + "\n")
    wpath.write_text("\n".join(BASELINE_PKGS_WORLD) + "\n")
    # Simulate the on-host record being deleted during the reset (e.g. a
    # disk-full recovery clears /var/lib/results). The post-reboot installed
    # check then reads nothing and must stop the run.
    pkg_router._post_reboot_hook = lambda: ipath.unlink() or wpath.unlink()
    last, _ = _reset(lab)
    assert last["task_ok"] is False
    assert last["abort_run"] is True
    assert last["verify"] == "mismatch"
    msg = last["exitstatus"]
    assert "package record" in msg
    assert "NOT verified" in msg or "gone" in msg or "vanished" in msg


def test_physical_reset_refuses_unsafe_name_in_world(lab, pkg_router,
                                                     tmp_path, monkeypatch):
    monkeypatch.setattr(nl.time, "sleep", lambda s: pytest.fail("no retry"))
    ipath, wpath = _pkg_rec_paths("pulsar", tmp_path)
    ipath.parent.mkdir(parents=True, exist_ok=True)
    ipath.write_text("\n".join(BASELINE_PKGS_INSTALLED) + "\n")
    wpath.write_text("\n".join(BASELINE_PKGS_WORLD) + "\n")
    # Three unsafe cases the test covers individually: shell metachar, !
    # syntax the safe regex bans, version pin.
    cases = ("foo;rm", "!dnsmasq", "foo>=1")
    for bad in cases:
        r = FakeRouter(tmp_path, world=list(BASELINE_PKGS_WORLD),
                       installed=list(BASELINE_PKGS_INSTALLED))
        r.world = list(BASELINE_PKGS_WORLD) + [bad]
        r.installed = list(BASELINE_PKGS_INSTALLED) + [f"{bad}-1"]
        # Re-bind helpers for this router instance.
        run_mp = pytest.MonkeyPatch()
        run_mp.setattr(nl, "_run", r.ssh)
        run_mp.setattr(nl, "_run_stdin_file", r.stdin_file)
        run_mp.setattr(nl, "RESULTS_DIR", tmp_path / "res")
        try:
            recs = []
            nl.physical_reset(lab, "pulsar", recs, attempts=1)
        finally:
            run_mp.undo()
        assert recs[-1]["task_ok"] is False
        assert recs[-1]["abort_run"] is True
        assert "unsafe" in recs[-1]["exitstatus"]
        assert r.apk_updates == [] and r.apk_dels == []
        # The function refuses before any reset step; the file records
        # remain unchanged.
        assert wpath.read_text().splitlines() == sorted(BASELINE_PKGS_WORLD)


def test_physical_reset_stops_when_only_one_record_file_present(lab,
                                                                pkg_router,
                                                                tmp_path,
                                                                capsys):
    ipath, wpath = _pkg_rec_paths("pulsar", tmp_path)
    ipath.parent.mkdir(parents=True, exist_ok=True)
    ipath.write_text("\n".join(BASELINE_PKGS_INSTALLED) + "\n")
    # The .world is missing on purpose.
    last, _ = _reset(lab)
    assert last["task_ok"] is False and last["abort_run"] is True
    msg = last["exitstatus"]
    assert "pulsar.world" in msg and "pulsar.installed" in msg
    assert "delete both files" in msg
    assert "apk update" not in pkg_router.cmds()
    assert not [c for c in pkg_router.cmds() if c.startswith("apk del")]


def test_vm_reset_never_invokes_the_apk_commands(lab, monkeypatch, tmp_path):
    monkeypatch.setattr(nl, "pve_reset", lambda *a, **k: {
        "task_ok": True, "upid": "u", "exitstatus": "OK", "attempt": 1})
    last = nl.reset_device(lab, "vm1", [])
    assert last["task_ok"] is True



def test_physical_reset_records_apk_versions_with_a_tilde(lab, tmp_path,
                                                          monkeypatch):
    # apk-tools 3 on Pulsar prints base-files-1711~f5dae5ece4: a `~` is part
    # of a real version, so the installed list accepts it; world names do not.
    r = FakeRouter(tmp_path, world=BASELINE_PKGS_WORLD,
                   installed=BASELINE_PKGS_INSTALLED + ["base-files-1711~f5dae5ece4"])
    monkeypatch.setattr(nl, "_run", r.ssh)
    monkeypatch.setattr(nl, "_run_stdin_file", r.stdin_file)
    monkeypatch.setattr(nl, "router_hello_preflight", lambda l, d: (True, ""))
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "res")
    last, _ = _reset(lab)
    assert last["task_ok"] is True, last["exitstatus"]
    ipath, _ = _pkg_rec_paths("pulsar", tmp_path)
    assert "base-files-1711~f5dae5ece4" in ipath.read_text().splitlines()
    r2 = FakeRouter(tmp_path, world=BASELINE_PKGS_WORLD + ["foo~1"],
                    installed=BASELINE_PKGS_INSTALLED)
    monkeypatch.setattr(nl, "_run", r2.ssh)
    monkeypatch.setattr(nl, "_run_stdin_file", r2.stdin_file)
    last, _ = _reset(lab, attempts=1)
    assert last["abort_run"] is True and "'foo~1'" in last["exitstatus"]
    assert r2.apk_dels == []


def test_physical_reset_accepts_pinned_world_entries_and_dels_by_name(
        lab, tmp_path, monkeypatch):
    # Pulsar's /etc/apk/world pins base-files, kernel and libc as name=version.
    pinned = ["base-files=1711~f5dae5ece4", "libc=1.2.5-r5"]
    r = FakeRouter(tmp_path, world=BASELINE_PKGS_WORLD + pinned,
                   installed=BASELINE_PKGS_INSTALLED)
    monkeypatch.setattr(nl, "_run", r.ssh)
    monkeypatch.setattr(nl, "_run_stdin_file", r.stdin_file)
    monkeypatch.setattr(nl, "router_hello_preflight", lambda l, d: (True, ""))
    monkeypatch.setattr(nl, "RESULTS_DIR", tmp_path / "res")
    last, _ = _reset(lab)
    assert last["task_ok"] is True, last["exitstatus"]
    _, wpath = _pkg_rec_paths("pulsar", tmp_path)
    assert set(pinned) <= set(wpath.read_text().splitlines())
    # A pinned entry added since the record is removed by its name only.
    r3 = FakeRouter(tmp_path, world=BASELINE_PKGS_WORLD + pinned
                    + ["miniupnpd-nftables=2.3.9-r1"],
                    installed=BASELINE_PKGS_INSTALLED)
    monkeypatch.setattr(nl, "_run", r3.ssh)
    monkeypatch.setattr(nl, "_run_stdin_file", r3.stdin_file)
    last, _ = _reset(lab)
    assert last["task_ok"] is True, last["exitstatus"]
    assert r3.apk_dels == ["apk del miniupnpd-nftables"]
    for bad in ("foo>=1", "foo=", "foo=1;rm", "!foo"):
        r2 = FakeRouter(tmp_path, world=BASELINE_PKGS_WORLD + pinned + [bad],
                        installed=BASELINE_PKGS_INSTALLED)
        monkeypatch.setattr(nl, "_run", r2.ssh)
        monkeypatch.setattr(nl, "_run_stdin_file", r2.stdin_file)
        last, _ = _reset(lab, attempts=1)
        assert last["abort_run"] is True and repr(bad) in last["exitstatus"]
        assert r2.apk_dels == []
