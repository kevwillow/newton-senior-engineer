"""SetupEnv, the pytest fixtures and the fixture source-tree builder for
scripts/newton-router-setup tests.

The environment with every test seam, built on top of the
harness (router_setup_harness).  Stdlib only, no network.
"""

import contextlib
import json
import os
import signal
import subprocess
import sys
from pathlib import Path

import pytest

MODULE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(MODULE_DIR))

from router_setup_harness import install_fakes  # noqa: E402

FIXTURES = MODULE_DIR / "router_setup_fixtures"
# ROUTER_SETUP_TOOL lets a test run use a snapshot of the tool while the
# tool itself is being edited ; unset = the repo script
DEFAULT_TOOL = Path(os.environ.get("ROUTER_SETUP_TOOL")
                    or MODULE_DIR.parent.parent / "scripts/newton-router-setup")
HOST = "10.1.2.3"

# fixture name -> repo-relative source path (and WAN-health extras)
SRC_LAYOUT = {
    "newton-router": "device/openwrt/newton-router/newton-router",
    "newton-safe-apply": "scripts/owrt-safe-apply.sh",
    "newton-guard": "device/openwrt/newton-guard/newton-guard",
    "newton-guard.init": "device/openwrt/newton-guard/newton-guard.init",
    "newton-wan-health.sh": "scripts/newton-wan-health.sh",
    "newton-wan-health.init": "scripts/newton-wan-health.init",
}

# files under the tmp tree leaks() never reports
LEAK_SKIP = {
    "router/fs/etc/newton/approve.key",  # K may sit only here
    "router/secrets.json",               # only the registered secrets list
    "router/state.json",                 # the fake router's config holds root_password
    "state/approval-fp",                 # the host-side approval fingerprint
    "state/plans",                       # plan records held on the host
    "state/approvals",                   # approval records held on the host
    "state/redact.key",                  # the redaction HMAC key
}


def build_src(dest, program="ok", version="1.0.0"):
    """Write the repo-shaped source tree the tool reads through
    NEWTON_SETUP_SRC, from the fixture files, appending the version and
    broken markers to the program as needed; every file executable."""
    dest = Path(dest)
    for name, rel in SRC_LAYOUT.items():
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        text = (FIXTURES / name).read_text()
        if name == "newton-router":
            if not text.endswith("\n"):
                text += "\n"
            if version != "1.0.0":
                text += "# FIXTURE-VERSION %s\n" % version
            if program == "broken":
                text += "# FIXTURE-BROKEN\n"
        target.write_text(text)
        target.chmod(0o755)
    return dest


class Result:
    """What one SetupEnv.run() produced."""

    def __init__(self, rc, out, err, calls):
        self.rc = rc
        self.out = out
        self.err = err
        self.calls = calls

    def lines(self, prefix):
        """The stdout lines that start with prefix."""
        return [line for line in self.out.splitlines()
                if line.startswith(prefix)]


class SetupEnv:
    """A whole test environment: fake router, source tree, inventory,
    keys dir, home, typed-input file and every seam"""

    def __init__(self, tmp, device="r1", profile="lab", auth="password",
                 tool=DEFAULT_TOOL):
        tmp = Path(tmp).resolve()
        self.tmp = tmp
        self.device = device
        self.profile = profile
        self.auth = auth
        self.tool = Path(tool)
        self.plain_key = None
        self.last_result = None
        self._watermark = 0

        # the typed-input file lives outside the tree leaks() scans
        outside = tmp.parent / (tmp.name + "-outside")
        outside.mkdir(parents=True, exist_ok=True)
        self.typed_file = outside / "typed"
        self.typed_file.write_text("")
        self.trusted = outside / "trusted_known_hosts"
        self.trusted.write_text("")

        self.home = tmp / "home"
        self.home.mkdir(parents=True)
        self.tmpdir = tmp / "tmpdir"
        self.tmpdir.mkdir()
        os.chmod(self.tmpdir, 0o700)
        # host-side state dir for the setup tool and approve.py; the
        # tool's approval_fingerprint_write and approve.py's state_dir()
        # both resolve through NEWTON_STATE_DIR, so a single tmp directory
        # makes the protocol tests inspect the same file that approve.py
        # would read on a later run.
        self.state_dir = tmp / "state"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.state_dir, 0o700)

        from router_setup_harness import FakeRouter
        self.router = FakeRouter.create(
            tmp / "router",
            host=HOST,
            uci={"dropbear.@dropbear[0]": "dropbear"},
        )
        self.src = build_src(tmp / "src")
        self.keys_dir = tmp / "keys"
        self.keys_dir.mkdir()
        os.chmod(self.keys_dir, 0o700)
        self.inventory = tmp / "devices.toml"
        self.inventory.write_text(
            "[devices.%s]\nhost = \"%s\"\nprofile = \"%s\"\nauth = \"%s\"\n"
            % (device, HOST, profile, auth))
        # write_text creates 0666 & ~umask, i.e. 0664 under umask 0002, which
        # the inventory-file check in scripts/newton-router-setup refuses.
        self.inventory.chmod(0o644)
        self.lab_toml = tmp / "lab.toml"
        self.lab_toml.write_text("")
        self.known_hosts = self.keys_dir / ("%s.known_hosts" % device)
        self.fakes = tmp / "bin"
        install_fakes(self.fakes, self.router.root)

    # -- environment ---------------------------------------------------------

    def base_env(self, extra=None):
        """The environment of 1.2 with every seam, plus `extra`."""
        env = dict(os.environ)
        for key in list(env):
            if key.startswith("NEWTON_") or key in (
                    "SSH_AUTH_SOCK", "SSH_CLIENT", "FAKE_ROUTER_ROOT",
                    "FAKE_ROUTER_FS"):
                del env[key]
        env.update({
            "NEWTON_SETUP_SEAMS": "1",
            "NEWTON_SETUP_BIN": str(self.fakes),
            "NEWTON_SETUP_TTY": str(self.typed_file),
            "NEWTON_SETUP_SLEEP": str(self.fakes / "fake-sleep"),
            "NEWTON_SETUP_SRC": str(self.src),
            "NEWTON_SETUP_REMOTE_ROOT": str(self.router.root / "fs"),
            "NEWTON_INVENTORY": str(self.inventory),
            "NEWTON_KEYS_DIR": str(self.keys_dir),
            "NEWTON_LAB_TOML": str(self.lab_toml),
            "NEWTON_TRUSTED_KNOWN_HOSTS": str(self.trusted),
            "NEWTON_STATE_DIR": str(self.state_dir),
            "HOME": str(self.home),
            "TMPDIR": str(self.tmpdir),
            "PATH": "%s:%s" % (self.fakes, env.get("PATH", "")),
        })
        if extra:
            env.update(extra)
        return env

    # -- running the tool ----------------------------------------------------

    def run(self, *args, typed=(), env=None, timeout=120):
        """Run the tool with every seam set, the typed lines in the
        private file, stdin from /dev/null; fail the test on timeout or
        when a fake call logged unsupported/syntax_error/unexpanded_rr."""
        self.typed_file.write_text("".join(line + "\n" for line in typed))
        before = max((call["n"] for call in self.router.calls()), default=0)
        argv = [str(self.tool)] + [str(a) for a in args]
        proc = subprocess.Popen(argv, env=self.base_env(env),
                                stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                start_new_session=True)
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(OSError):
                os.killpg(proc.pid, signal.SIGKILL)
            proc.communicate()
            pytest.fail("tool %r timed out after %ss" % (argv, timeout))
        calls = [call for call in self.router.calls() if call["n"] > before]
        result = Result(proc.returncode, out.decode("utf-8", "replace"),
                        err.decode("utf-8", "replace"), calls)
        self.last_result = result
        bad = [call for call in calls if call.get("unsupported")
               or call.get("syntax_error") or call.get("unexpanded_rr")]
        if bad:
            pytest.fail("fake logged a bad call: %s" % json.dumps(bad))
        return result

    def calls_since(self, n=None):
        """Calls after n; with no argument, calls since the last
        no-argument call (a watermark)."""
        calls = self.router.calls()
        if n is None:
            n = self._watermark
        self._watermark = max([call["n"] for call in calls]
                              + [self._watermark])
        return [call for call in calls if call["n"] > n]

    # -- secrets and leaks ---------------------------------------------------

    def register_secrets(self, *values):
        """Values the leak scan looks for."""
        self.router.register_secrets(*values)

    def fp_path(self, device=None):
        """The host-side fingerprint file the tool writes for `device`
        (default: this env's inventory device)."""
        device = device or self.device
        return self.state_dir / "approval-fp" / device

    def leaks(self):
        """Where registered secrets must not appear: the
        call-log entries that carry `leaks`, the tool output and every
        regular file under the tmp tree but approve.key, the typed file
        and the secrets registry."""
        secrets = [s for s in json.loads(
            (self.router.root / "secrets.json").read_text()) if s]
        found = []
        for call in self.router.calls():
            for tag in call.get("leaks") or []:
                found.append("call:%s:%s" % (call["n"], tag))
        if self.last_result is not None:
            text = self.last_result.out + self.last_result.err
            if any(secret in text for secret in secrets):
                found.append("output")
        for dirpath, _dirnames, filenames in os.walk(self.tmp):
            for name in filenames:
                real = Path(dirpath) / name
                rel = real.relative_to(self.tmp).as_posix()
                if rel in LEAK_SKIP or real.is_symlink() or not real.is_file():
                    continue
                try:
                    data = real.read_bytes()
                except OSError:
                    continue
                if any(secret.encode() in data for secret in secrets):
                    found.append("file:%s" % rel)
        return sorted(set(found))


@pytest.fixture
def setup_env(tmp_path):
    """Lab-like SetupEnv: inventory r1, profile lab, password auth."""
    return SetupEnv(tmp_path)


@pytest.fixture
def pulsar_env(tmp_path):
    """Pulsar-like SetupEnv: inventory pulsar, profile prod, key auth,
    a plain key pair made with the fake ssh-keygen and its unrestricted
    line on the router; the key path in .plain_key."""
    env = SetupEnv(tmp_path, device="pulsar", profile="prod", auth="key")
    ssh_dir = env.home / ".ssh"
    ssh_dir.mkdir(parents=True, exist_ok=True)
    key = ssh_dir / "id_ed25519"
    proc = subprocess.run(
        [str(env.fakes / "ssh-keygen"), "-q", "-t", "ed25519", "-N", "",
         "-C", "plain", "-f", str(key)],
        capture_output=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    env.plain_key = key
    env.router.add_authorized_key(
        key.with_name(key.name + ".pub").read_text().strip())
    return env
