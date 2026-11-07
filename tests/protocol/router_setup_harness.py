"""Fake router and fake ssh/scp/sftp/ssh-keygen/curl/sleep for
scripts/newton-router-setup tests.

Implements the setup design (4.1 shape including the virtual clock and
timers, 4.2 fake ssh with forwarding sessions, scp, sftp, 4.3 call log,
4.4 snapshot) except SetupEnv and curl, which come in later rounds.
Stdlib only, no network.
"""

import base64
import contextlib
import getopt
import hashlib
import json
import os
import re
import selectors
import secrets as _pysecrets
import shlex
import shutil
import signal
import socket
import stat
import string
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

from _host_busybox import HOST_BUSYBOX

MODULE_DIR = Path(__file__).resolve().parent

BUSYBOX_VERSION = "BusyBox v1.37.0 (2026-01-01 00:00:00 UTC) multi-call binary."
BLOB_PREFIX = "AAAAC3NzaC1lZDI1NTE5AAAAI"

# hostbin applets: symlinks to the host busybox (4.1); missing names are skipped
HOSTBIN_APPLETS = (
    "awk sed grep cp mv cat sha256sum md5sum wc tail head tr cut ls mkdir rm ln chmod "
    "touch tar gzip date df mktemp sort printf id uname netstat pidof nslookup ping "
    "traceroute logread "
    "basename dirname readlink stat xargs cmp diff expr seq uniq od hexdump"
).split()

# bin stubs that just exit 0
NOOP_STUBS = "jsonfilter ucode nft fw4 ifstatus iwinfo apk sleep sync".split()

DEFAULT_STATE = {
    "root_password": "root-pw-for-tests",
    "password_auth": True,
    "host": "10.1.2.3",
    "host_key": "ssh-ed25519 AAAAC3FAKEHOSTKEY0001",
    "vulnerable": [],
    "deny_restricted_when_plain_absent": False,
    "ghost_blobs": [],
    # extra stderr text the fake ssh prints when it refuses a login (the
    # untrusted ssh text the setup tool has to sanitise)
    "deny_stderr": "",
    # substrings of a router command: a command that contains one is not run;
    # the fake ssh closes the connection (exit 255), as when the link drops
    "drop_commands": [],
    # [needle, rc] pairs: a command that contains the needle RUNS and the
    # router's shell exits with rc, as when the remote command itself fails
    # (ssh returns the remote command's exit status)
    "rc_commands": [],
    "uci": {},
    # the uci section model of the fake router: pkg -> section ->
    # {"type": str, "options": {name: value}, "lists": {name: [values]}}
    "uci_sections": {},
    # the rpcd sessions of the fake router: [{"id": ..., "username": ...}]
    "rpcd_sessions": [],
    "ubus_sessions": "",
    # substrings of the ubus argument list: an ubus call whose arguments
    # hold one FAILS (exit 1), as when the router's session service is
    # broken; the rest of the remote command still runs
    "ubus_fail": [],
    # [needle, rc] pairs: a uci call whose argument list holds the
    # needle FAILS with that status, as when the router's uci is broken
    # for one call; the rest of the remote command still runs
    "uci_fail": [],
    # substrings of a uci argument list: a uci call that holds one
    # SUCCEEDS but changes nothing, as when the router takes the
    # command and forgets it
    "uci_ignore": [],
    "overlay_free_kib": 20000,
    "pve": {
        "token": "PVEAPIToken=claude@pve!newton=00000000-fake-token",
        "pin": "sha256//FAKEPINFAKEPINFAKEPIN=",
        "node": "Apollo",
        "vms": {"9102": {"snapshots": []}},
        "task_polls": 1,
        "task_exit": "OK",
        "fail": None,
    },
}


def is_vulnerable(state, name):
    """True when the state's `vulnerable` knob (list or dict) names `name`."""
    vuln = state.get("vulnerable", [])
    if isinstance(vuln, dict):
        return bool(vuln.get(name))
    return name in vuln


# ---------------------------------------------------------------------------
# FakeRouter: the on-disk router every fake process shares
# ---------------------------------------------------------------------------

class FakeRouter:
    """Router state on disk: fs/, state.json, clock, timers.json, calls.jsonl."""

    def __init__(self, root):
        self.root = Path(root)

    @classmethod
    def create(cls, root, **state_overrides):
        """Lay out root/fs, root/bin, root/hostbin and the state files."""
        root = Path(root).resolve()
        router = cls(root)
        fs = root / "fs"
        for d in ("etc/dropbear", "etc/config", "etc/init.d", "etc/rc.d",
                  "usr/libexec", "tmp", "overlay", "root", "var/run"):
            (fs / d).mkdir(parents=True, exist_ok=True)
        ak = fs / "etc/dropbear/authorized_keys"
        ak.write_text("")
        ak.chmod(0o600)
        (fs / "etc/openwrt_release").write_text(
            "DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='25.12.0'\n")
        state = dict(DEFAULT_STATE)
        state.update(state_overrides)
        (root / "state.json").write_text(json.dumps(state, indent=2) + "\n")
        (root / "clock").write_text("0")
        (root / "timers.json").write_text("[]")
        (root / "calls.jsonl").write_text("")
        (root / "secrets.json").write_text("[]")
        _write_bin_stubs(root)
        _write_hostbin(root / "hostbin")
        return router

    # -- state ---------------------------------------------------------------

    def state(self):
        """The parsed state.json."""
        return json.loads((self.root / "state.json").read_text())

    def update_state(self, **kw):
        """Merge kw into state.json and return the new state."""
        state = self.state()
        state.update(kw)
        (self.root / "state.json").write_text(json.dumps(state, indent=2) + "\n")
        return state

    def register_secrets(self, *values):
        """Add values the leak scan (4.3) looks for."""
        path = self.root / "secrets.json"
        known = json.loads(path.read_text())
        known.extend(values)
        path.write_text(json.dumps(known) + "\n")

    def clock(self):
        """The virtual clock in seconds."""
        return _read_clock(self.root)

    def timers(self):
        """The pending timers of timers.json."""
        return _read_timers(self.root)

    def pve(self):
        """The pve knob of state.json."""
        return self.state().get("pve", {})

    def snapshots(self, vmid):
        """The recorded snapshot names of one PVE VM."""
        vm = self.pve().get("vms", {}).get(str(vmid), {})
        return list(vm.get("snapshots", []))

    # -- files ---------------------------------------------------------------

    def path(self, p):
        """Map a router path to the real path under fs/."""
        return self.root / "fs" / str(p).lstrip("/")

    def write(self, path, text, mode=None):
        """Write text into the router fs, optionally chmod."""
        real = self.path(path)
        real.parent.mkdir(parents=True, exist_ok=True)
        real.write_text(text)
        if mode is not None:
            real.chmod(mode)

    def read(self, path):
        """Read a file from the router fs."""
        return self.path(path).read_text()

    def authorized_keys(self):
        """The live authorized_keys lines."""
        return self.path("etc/dropbear/authorized_keys").read_text().splitlines()

    def add_authorized_key(self, line):
        """Append one line to the live authorized_keys."""
        real = self.path("etc/dropbear/authorized_keys")
        with open(real, "a") as fh:
            fh.write(line.rstrip("\n") + "\n")

    def snapshot(self):
        """path -> mode + sha256 (or link target), without tmp/."""
        out = {}
        fs = self.root / "fs"
        for dirpath, dirnames, filenames in os.walk(fs):
            rel_dir = os.path.relpath(dirpath, fs)
            if rel_dir == "tmp":
                dirnames[:] = []
                continue
            dirnames[:] = [d for d in dirnames
                           if os.path.relpath(os.path.join(dirpath, d), fs) != "tmp"]
            for name in filenames:
                real = Path(dirpath) / name
                rel = os.path.relpath(real, fs)
                st = real.lstat()
                mode = "0o%o" % stat.S_IMODE(st.st_mode)
                if stat.S_ISLNK(st.st_mode):
                    out[rel] = {"mode": mode, "link": os.readlink(real)}
                else:
                    digest = hashlib.sha256(real.read_bytes()).hexdigest()
                    out[rel] = {"mode": mode, "sha256": digest}
        return out

    # -- call log ------------------------------------------------------------

    def calls(self):
        """The parsed calls.jsonl entries."""
        text = (self.root / "calls.jsonl").read_text()
        return [json.loads(line) for line in text.splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# router bin stubs and hostbin
# ---------------------------------------------------------------------------

def _write_executable(path, body):
    """Write a script with mode 0755."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)
    path.chmod(0o755)


def _stub_body(name, root):
    """A stub script that calls back into this module."""
    return (
        "#!%s\n"
        "import sys\n"
        "sys.path.insert(0, %r)\n"
        "import router_setup_harness as _h\n"
        "sys.exit(_h.router_stub_main(%r, sys.argv[1:], %r))\n"
    ) % (sys.executable, str(MODULE_DIR), name, str(root))


def _write_bin_stubs(root):
    """Write root/bin: busybox, logger, ubus, uci, setsid, ps and the no-op
    stubs (4.1).  The ps stub prints a BusyBox-style header and, for every
    pending timer, two lines: a sh wrapping the sleep, then the sleep."""
    bin_dir = root / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    for name in ("busybox", "logger", "ubus", "uci", "setsid", "ps") + tuple(NOOP_STUBS):
        _write_executable(bin_dir / name, _stub_body(name, root))


def _write_hostbin(hostbin):
    """Symlink host busybox applets, /bin/sh and host flock into hostbin;
    skip names the host lacks; never a sleep."""
    hostbin.mkdir(parents=True, exist_ok=True)
    busybox = HOST_BUSYBOX
    if not os.path.exists(busybox):
        return
    listed = subprocess.run([busybox, "--list"], capture_output=True,
                            text=True, timeout=10).stdout.split()
    for name in HOSTBIN_APPLETS:
        if name == "sleep":
            continue
        if name in listed:
            target = hostbin / name
            if not target.exists():
                target.symlink_to(busybox)
    sh_link = hostbin / "sh"
    if not sh_link.exists():
        sh_link.symlink_to("/bin/sh")
    flock = shutil.which("flock")
    if flock and not (hostbin / "flock").exists():
        (hostbin / "flock").symlink_to(flock)


def router_stub_main(name, argv, root):
    """Entry point of the root/bin stubs."""
    router = FakeRouter(root)
    if name == "setsid":
        return setsid_main(router, argv)
    if name == "ps":
        return ps_main(router, argv)
    if name == "busybox":
        if not argv:
            print(BUSYBOX_VERSION)
            return 0
        return os.execv(HOST_BUSYBOX, ["busybox"] + list(argv))
    if name == "logger":
        log = router.path("tmp/syslog")
        log.parent.mkdir(parents=True, exist_ok=True)
        with open(log, "a") as fh:
            fh.write(" ".join(argv) + "\n")
        return 0
    if name == "ubus":
        joined = " ".join(argv)
        for needle in router.state().get("ubus_fail") or []:
            if needle and needle in joined:
                print("ubus: call failed: %s" % needle, file=sys.stderr)
                return 1
        if "session" in argv:
            if "list" in argv:
                sys.stdout.write(render_sessions(router))
                return 0
            if "destroy" in argv:
                return destroy_session(router, argv)
        return 0
    if name == "uci":
        return uci_main(router, argv)
    if name in NOOP_STUBS:
        return 0
    return 0


# ---------------------------------------------------------------------------
# the fake uci: a section model over state.json (the no-install mode needs
# get, set, add_list, delete, commit and show)
# ---------------------------------------------------------------------------

def _uci_configs(router):
    """The uci section model of the fake router."""
    configs = router.state().get("uci_sections")
    return configs if isinstance(configs, dict) else {}


def _uci_save(router, configs):
    """Write the uci section model back to state.json."""
    router.update_state(uci_sections=configs)


def _uci_split(path):
    """'pkg[.section[.option]]' -> (pkg, section, option)."""
    parts = str(path).split(".")
    pkg = parts[0]
    section = parts[1] if len(parts) > 1 else None
    option = parts[2] if len(parts) > 2 else None
    return pkg, section, option


def _uci_lookup(configs, path):
    """The value of a path in the section model, or None."""
    pkg, section, option = _uci_split(path)
    if section is None:
        return None
    entry = (configs.get(pkg) or {}).get(section)
    if entry is None:
        return None
    if option is None:
        return entry.get("type", "")
    options = entry.get("options") or {}
    if option in options:
        return options[option]
    lists = entry.get("lists") or {}
    if option in lists:
        return " ".join(lists[option])
    return None


def uci_main(router, argv):
    """The fake uci: get, set, add_list, delete, commit and show."""
    joined = " ".join(argv)
    for needle in router.state().get("uci_ignore") or []:
        if needle and needle in joined:
            # the router takes the command and does nothing with it
            return 0
    for pair in router.state().get("uci_fail") or []:
        try:
            needle = pair[0]
            want_rc = int(pair[1])
        except (IndexError, TypeError, ValueError):
            continue
        if needle and needle in joined:
            print("uci: %s failed" % needle, file=sys.stderr)
            return want_rc
    args = [a for a in argv if a != "-q"]
    if not args:
        return 1
    cmd, rest = args[0], args[1:]
    configs = _uci_configs(router)
    if cmd == "get":
        if not rest:
            return 1
        value = _uci_lookup(configs, rest[0])
        if value is None:
            value = router.state().get("uci", {}).get(rest[0])
        if value is None:
            return 1
        print(value)
        return 0
    if cmd == "set":
        if not rest or "=" not in rest[0]:
            return 1
        path, value = rest[0].split("=", 1)
        pkg, section, option = _uci_split(path)
        if section is None:
            return 1
        sections = configs.setdefault(pkg, {})
        entry = sections.setdefault(section,
                                    {"type": "", "options": {}, "lists": {}})
        if option is None:
            entry["type"] = value
        else:
            entry.setdefault("options", {})[option] = value
        _uci_save(router, configs)
        return 0
    if cmd == "add_list":
        if not rest or "=" not in rest[0]:
            return 1
        path, value = rest[0].split("=", 1)
        pkg, section, option = _uci_split(path)
        entry = (configs.get(pkg) or {}).get(section)
        if entry is None or option is None:
            return 1
        entry.setdefault("lists", {}).setdefault(option, []).append(value)
        _uci_save(router, configs)
        return 0
    if cmd == "delete":
        if not rest:
            return 1
        pkg, section, option = _uci_split(rest[0])
        sections = configs.get(pkg) or {}
        entry = sections.get(section)
        if entry is None:
            return 1
        if option is None:
            del sections[section]
        else:
            entry.get("options", {}).pop(option, None)
            entry.get("lists", {}).pop(option, None)
        _uci_save(router, configs)
        return 0
    if cmd == "commit":
        if not rest:
            return 0
        pkg = rest[0]
        sections = configs.get(pkg) or {}
        text = []
        for name, entry in sections.items():
            text.append("config %s '%s'\n" % (entry.get("type", ""), name))
            for key, value in (entry.get("options") or {}).items():
                text.append("\toption %s '%s'\n" % (key, value))
            for key, values in (entry.get("lists") or {}).items():
                for value in values:
                    text.append("\tlist %s '%s'\n" % (key, value))
        router.write("etc/config/" + pkg, "".join(text))
        return 0
    if cmd == "show":
        if not rest:
            return 0
        pkg = rest[0]
        sections = configs.get(pkg) or {}
        for name, entry in sections.items():
            print("%s.%s=%s" % (pkg, name, entry.get("type", "")))
            for key, value in (entry.get("options") or {}).items():
                print("%s.%s.%s='%s'" % (pkg, name, key, value))
            for key, values in (entry.get("lists") or {}).items():
                for value in values:
                    print("%s.%s.%s='%s'" % (pkg, name, key, value))
        return 0
    return 0


# ---------------------------------------------------------------------------
# the fake rpcd sessions (the no-install uninstall destroys them)
# ---------------------------------------------------------------------------

DEFAULT_SESSION_ID = "0" * 32


def _session_object(sid, username):
    """One session as `ubus call session list` prints it (measured on
    Pulsar, OpenWrt 25.12, 2026-11-02): a top-level object, the login
    name nested in "data".  A username of None is rpcd's own
    unauthenticated session, whose "data" holds a blank line."""
    head = ['\t"ubus_rpc_session": "%s",' % sid,
            '\t"timeout": 300,',
            '\t"expires": 299,',
            '\t"acls": {',
            '\t\t"ubus": {',
            '\t\t\t"session": [',
            '\t\t\t\t"access",',
            '\t\t\t\t"login"',
            '\t\t\t]',
            '\t\t}',
            '\t},']
    if username is None:
        data = ['\t"data": {', '\t\t', '\t}']
    else:
        data = ['\t"data": {', '\t\t"username": "%s"' % username, '\t}']
    return head, data


def render_sessions(router):
    """The `ubus call session list` output of the fake router.

    The shape is the measured one: one top-level object per session,
    rpcd's own unauthenticated session first.  A session dictionary
    whose first key is "username" prints its "data" member before its id
    (the order of the members of a JSON object is not semantic, and the
    uninstall must not depend on it).  The state key ubus_sessions,
    when set, replaces the whole answer once the session list is empty.
    """
    state = router.state()
    sessions = state.get("rpcd_sessions") or []
    if not sessions and state.get("ubus_sessions"):
        return state["ubus_sessions"] + "\n"
    lines = []
    for session in [{"id": DEFAULT_SESSION_ID}] + sessions:
        head, data = _session_object(session.get("id", ""),
                                     session.get("username"))
        lines.append("{")
        if next(iter(session)) == "username":
            lines += data[:-1] + ["\t},"] + head[:-1] + ["\t}"]
        else:
            lines += head + data
        lines.append("}")
    # a session marked expires_after_list times out right after this
    # listing (rpcd's own session timeout), before any destroy reaches it
    kept = [s for s in sessions if not s.get("expires_after_list")]
    if len(kept) != len(sessions):
        router.update_state(rpcd_sessions=kept)
    return "\n".join(lines) + "\n"


def destroy_session(router, argv):
    """`ubus call session destroy '{"ubus_rpc_session":"<id>"}'`."""
    payload = None
    for arg in argv:
        if arg.startswith("{"):
            payload = arg
    if payload is None:
        return 1
    try:
        data = json.loads(payload)
    except ValueError:
        return 1
    sid = data.get("ubus_rpc_session")
    if not isinstance(sid, str):
        return 1
    sessions = router.state().get("rpcd_sessions") or []
    kept = [s for s in sessions if s.get("id") != sid]
    if len(kept) == len(sessions):
        # measured on Pulsar (2026-11-02): "Command failed: ... (Not
        # found)" on stderr and exit status 252
        print("Command failed: ubus call session destroy %s (Not found)"
              % payload, file=sys.stderr)
        return 252
    router.update_state(rpcd_sessions=kept)
    return 0


# ---------------------------------------------------------------------------
# virtual clock and timers
# ---------------------------------------------------------------------------

def _write_clock(root, value):
    """Write the virtual clock; integral values stay integers on disk."""
    value = float(value)
    text = str(int(value)) if value.is_integer() else repr(value)
    (root / "clock").write_text(text)


def _read_timers(root):
    """The pending timers list of timers.json."""
    try:
        return json.loads((root / "timers.json").read_text())
    except (OSError, ValueError):
        return []


def _write_timers(root, timers):
    """Replace timers.json."""
    (root / "timers.json").write_text(json.dumps(timers) + "\n")


def _base_router_env(router):
    """The environment every router shell, program and timer runs with."""
    return {
        "PATH": "%s:%s" % (router.root / "bin", router.root / "hostbin"),
        "FAKE_ROUTER_FS": str(router.root / "fs"),
        # the repository the fake router may run a script of, so a
        # fixture can exercise the real code and not a copy of it
        "FAKE_NEWTON_REPO": str(MODULE_DIR.parent.parent),
        "SSH_CLIENT": "127.0.0.1 40000 22",
    }


def setsid_main(router, argv):
    """The setsid stub: `sh -c 'sleep N; REST'` registers a timer and
    returns at once; any other form runs its command in the foreground.
    State knob `setsid_noop`: when true, the `sh -c 'sleep N; ...'` form
    returns 0 WITHOUT registering a timer (a job that died right after
    being started), so swap_deadman_alive can prove the switch is not
    really running."""
    env = _base_router_env(router)
    if len(argv) >= 3 and argv[0] == "sh" and argv[1] == "-c":
        match = re.match(r"^sleep (\d+(?:\.\d+)?);\s*(.*)$", argv[2], re.S)
        if match:
            if router.state().get("setsid_noop"):
                return 0
            timers = _read_timers(router.root)
            timers.append({
                "due": _read_clock(router.root) + float(match.group(1)),
                "sleep": match.group(1),
                "command": match.group(2),
                "env": env,
            })
            _write_timers(router.root, timers)
            return 0
        try:
            return subprocess.run(["/bin/sh", "-c", argv[2]], env=env,
                                  stdin=subprocess.DEVNULL,
                                  timeout=60).returncode
        except subprocess.TimeoutExpired:
            return 124
    if not argv:
        return 0
    try:
        return subprocess.run(list(argv), env=env,
                              stdin=subprocess.DEVNULL,
                              timeout=60).returncode
    except subprocess.TimeoutExpired:
        return 124


def ps_main(router, argv):
    """The ps stub: prints a BusyBox header and, for every pending timer
    of timers.json, two lines (a sh wrapping the sleep, then the sleep).
    Timer records without a `sleep` key fall back to the integer part of
    `due - clock` (for tests that pre-populate timers by hand).  No
    arguments beyond what the call needs; the timer content is the
    original text the setsid stub saw, not the parsed number."""
    header = "  PID USER       VSZ STAT COMMAND"
    print(header)
    timers = _read_timers(router.root)
    clock = _read_clock(router.root)
    for index, timer in enumerate(timers):
        if "sleep" in timer:
            seconds_text = timer["sleep"]
        else:
            seconds_text = str(int(timer["due"] - clock))
        pid_sh = 1000 + 2 * index
        pid_sleep = pid_sh + 1
        print(" %4d root      1316 S    sh -c sleep %s; %s"
              % (pid_sh, seconds_text, timer["command"]))
        print(" %4d root      1304 S    sleep %s"
              % (pid_sleep, seconds_text))
    return 0


def advance_clock(root, seconds):
    """Run due timers in due order, then set the clock to the target (4.1)."""
    root = root.root if isinstance(root, FakeRouter) else Path(root)
    target = _read_clock(root) + float(seconds)
    while True:
        timers = _read_timers(root)
        index = min((i for i, t in enumerate(timers) if t["due"] <= target),
                    key=lambda i: timers[i]["due"], default=None)
        if index is None:
            break
        timer = timers.pop(index)
        _write_timers(root, timers)
        _write_clock(root, timer["due"])
        subprocess.run(["/bin/sh", "-c", timer["command"]],
                       env=timer.get("env") or _base_router_env(
                           FakeRouter(root)),
                       stdin=subprocess.DEVNULL, timeout=60)
    _write_clock(root, target)


def fake_sleep_main(argv):
    """The NEWTON_SETUP_SLEEP seam: advance the virtual clock (2.9, 4.2)."""
    root = Path(os.environ["FAKE_ROUTER_ROOT"]).resolve()
    if not argv:
        return 2
    try:
        seconds = float(argv[0])
    except ValueError:
        print("fake-sleep: bad seconds: %s" % argv[0], file=sys.stderr)
        return 2
    advance_clock(root, seconds)
    _append_call(root, {"n": _next_n(root), "tool": "sleep",
                        "argv": list(argv), "rc": 0,
                        "clock": _read_clock(root)})
    return 0


# ---------------------------------------------------------------------------
# fake ssh-keygen
# ---------------------------------------------------------------------------

def _random_blob():
    """A fake ed25519 blob: fixed prefix plus 40 base64-safe characters."""
    alphabet = string.ascii_letters + string.digits
    return BLOB_PREFIX + "".join(_pysecrets.choice(alphabet) for _ in range(40))


def _private_blob(path):
    """The blob stored in a fake private key file, or None."""
    try:
        lines = Path(path).read_text().splitlines()
    except OSError:
        return None
    if len(lines) >= 2 and lines[0] == "FAKE-OPENSSH-PRIVATE-KEY":
        return lines[1].strip()
    return None


def keygen_main(argv):
    """The fake ssh-keygen; every call is logged."""
    root = Path(os.environ["FAKE_ROUTER_ROOT"])
    rc = _keygen_run(list(argv))
    _append_call(root, {"n": _next_n(root), "tool": "ssh-keygen",
                        "argv": list(argv), "rc": rc, "clock": _read_clock(root)})
    return rc


def _keygen_run(argv):
    # getopt understands combined short flags the way ssh-keygen prints
    # them: -lf FILE, -yf FILE, -qt ed25519
    try:
        opts, _rest = getopt.getopt(argv, "qylf:t:N:C:F:")
    except getopt.GetoptError as exc:
        print("ssh-keygen: %s" % exc, file=sys.stderr)
        return 2
    vals = dict(opts)
    flags = {key for key, _value in opts}
    if "-y" in flags:
        blob = _private_blob(Path(vals.get("-f", "")))
        if blob is None:
            print("ssh-keygen: error: cannot load key", file=sys.stderr)
            return 255
        print("ssh-ed25519 %s" % blob)
        return 0
    if "-l" in flags:
        try:
            lines = Path(vals.get("-f", "")).read_text().splitlines()
        except OSError:
            print("ssh-keygen: error: cannot open file", file=sys.stderr)
            return 255
        line = next((l for l in lines if l.strip() and not l.startswith("#")), "")
        fields = line.split()
        if fields and fields[0].startswith("@"):
            fields = fields[1:]
        if fields and not fields[0].startswith("ssh-"):
            name = fields[0]
        else:
            name = fields[2] if len(fields) > 2 else "no comment"
        digest = base64.b64encode(
            hashlib.sha256(line.encode()).digest()).decode().rstrip("=")
        print("256 SHA256:%s %s (ED25519)" % (digest, name))
        return 0
    if "-F" in vals:
        host = vals["-F"]
        path = Path(vals.get("-f", ""))
        lines = path.read_text().splitlines() if path.exists() else []
        found = [(n, l) for n, l in enumerate(lines, 1)
                 if len(l.split()) >= 3 and host in l.split()[0].split(",")]
        if not found:
            return 1
        for n, l in found:
            print("# Host %s found: line %d" % (host, n))
            print(l)
        return 0
    # key generation: -q -t ed25519 -N '' -C COMMENT -f FILE
    target = Path(vals.get("-f", ""))
    if not str(target):
        print("ssh-keygen: missing -f", file=sys.stderr)
        return 2
    blob = _random_blob()
    comment = vals.get("-C", "")
    target.write_text("FAKE-OPENSSH-PRIVATE-KEY\n%s\n" % blob)
    os.chmod(target, 0o600)
    target.with_name(target.name + ".pub").write_text(
        "ssh-ed25519 %s %s\n" % (blob, comment))
    return 0


# ---------------------------------------------------------------------------
# fake ssh / scp / sftp
# ---------------------------------------------------------------------------

SSH_VALUE_OPTS = ("-i", "-p", "-P", "-F", "-L", "-D", "-R")
SSH_FLAG_OPTS = ("-N", "-T", "-tt", "-t", "-A", "-q", "-v")
ALLOWED_SSH_O = {
    "ConnectTimeout", "ServerAliveInterval", "ServerAliveCountMax",
    "ControlMaster", "ControlPath", "GlobalKnownHostsFile",
    "UserKnownHostsFile", "StrictHostKeyChecking", "ProxyCommand",
    "IdentitiesOnly", "BatchMode", "PreferredAuthentications",
    "PasswordAuthentication", "PubkeyAuthentication",
    "NumberOfPasswordPrompts", "ExitOnForwardFailure", "SetEnv",
}
ALLOWED_AK_OPTIONS = {
    "restrict", "command", "no-pty", "no-port-forwarding",
    "no-agent-forwarding", "no-X11-forwarding", "no-user-rc", "pty",
    "port-forwarding", "agent-forwarding", "X11-forwarding", "user-rc",
    "permitopen",
}


def _parse_ssh_argv(argv):
    """Split argv into value options, -o options, flags and the rest."""
    parsed = {"vals": {}, "o": {}, "flags": set(), "rest": []}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in SSH_VALUE_OPTS:
            if i + 1 >= len(argv):
                return None, a
            parsed["vals"][a] = argv[i + 1]
            i += 2
        elif a in SSH_FLAG_OPTS:
            parsed["flags"].add(a)
            i += 1
        elif a == "-o":
            if i + 1 >= len(argv):
                return None, a
            key, _, value = argv[i + 1].partition("=")
            if key not in ALLOWED_SSH_O:
                return None, "-o %s" % key
            parsed["o"][key] = value
            i += 2
        elif a.startswith("-"):
            return None, a
        else:
            parsed["rest"].append(a)
            i += 1
    return parsed, None


def _split_commas_outside_quotes(text):
    """Split an authorized_keys option list on commas, keeping quotes intact."""
    parts = []
    current = []
    in_quotes = False
    for ch in text:
        if ch == '"':
            in_quotes = not in_quotes
            current.append(ch)
        elif ch == "," and not in_quotes:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return [p for p in parts if p]


def _parse_ak_line(line):
    """One authorized_keys line -> options/blob/comment/command, or None.

    None means the line is ignored whole (unknown option or malformed),
    like dropbear does.
    """
    line = line.strip()
    if not line or line.startswith("#") or line.startswith("@"):
        return None
    opt_text = ""
    rest = line
    if not line.startswith("ssh-"):
        in_quotes = False
        i = 0
        while i < len(line):
            ch = line[i]
            if ch == '"':
                in_quotes = not in_quotes
            elif ch in " \t" and not in_quotes:
                break
            i += 1
        opt_text, rest = line[:i], line[i:].strip()
    options = []
    command = None
    for part in _split_commas_outside_quotes(opt_text):
        name = part.split("=", 1)[0].strip().strip('"')
        if name not in ALLOWED_AK_OPTIONS:
            return None
        options.append(name)
        if name == "command":
            command = part[len("command="):].strip()
            if command.startswith('"') and command.endswith('"') and len(command) >= 2:
                command = command[1:-1]
    fields = rest.split()
    if len(fields) < 2 or not fields[0].startswith("ssh-"):
        return None
    return {"options": options, "blob": fields[1],
            "comment": " ".join(fields[2:]), "command": command}


def _read_clock(root):
    """The virtual clock in seconds (an int whenever it is integral)."""
    try:
        value = float((root / "clock").read_text().strip() or 0)
    except (OSError, ValueError):
        return 0
    return int(value) if value.is_integer() else value


def _next_n(root):
    """The next call-log sequence number."""
    path = root / "calls.jsonl"
    if not path.exists():
        return 1
    return sum(1 for _ in path.open()) + 1


def _append_call(root, entry):
    """Append one JSON line to calls.jsonl."""
    with open(root / "calls.jsonl", "a") as fh:
        fh.write(json.dumps(entry) + "\n")


def _scan_leaks(root, argv):
    """Look for registered secrets in argv, environment values and the
    regular files (never a FIFO) of the SSH_ASKPASS directory."""
    path = root / "secrets.json"
    known = json.loads(path.read_text()) if path.exists() else []
    leaks = []
    for secret in known:
        if not secret:
            continue
        if any(secret in a for a in argv):
            leaks.append("argv")
        for key, value in os.environ.items():
            if value and secret in value:
                leaks.append("env:%s" % key)
        askpass = os.environ.get("SSH_ASKPASS")
        if askpass:
            directory = Path(askpass).parent
            if directory.is_dir():
                for child in sorted(directory.iterdir()):
                    try:
                        st = os.stat(child)
                    except OSError:
                        continue
                    if not stat.S_ISREG(st.st_mode):
                        continue
                    try:
                        data = child.read_bytes()
                    except OSError:
                        continue
                    if secret.encode() in data:
                        leaks.append("askpass-file:%s" % child.name)
    return list(dict.fromkeys(leaks))


def _host_key_policy(state, host, port, strict, kh_file):
    """Addendum 4.2 item 1; returns an ssh exit code or None to continue."""
    if not kh_file or kh_file == "/dev/null":
        return None
    entry = host if str(port) == "22" else "[%s]:%s" % (host, port)
    wanted = "%s %s" % (entry, state["host_key"])
    path = Path(kh_file)
    lines = path.read_text().splitlines() if path.exists() else []
    for line in lines:
        fields = line.split()
        if len(fields) >= 3 and entry in fields[0].split(","):
            if line == wanted:
                return None
            print("REMOTE HOST IDENTIFICATION HAS CHANGED!", file=sys.stderr)
            return 255
    if strict == "accept-new":
        with open(path, "a") as fh:
            fh.write(wanted + "\n")
        return None
    print("Host key verification failed.", file=sys.stderr)
    return 255


def _run_askpass(prompt):
    """Run SSH_ASKPASS and return its stdout (one trailing newline dropped)."""
    program = os.environ.get("SSH_ASKPASS")
    if not program:
        return None
    try:
        proc = subprocess.run([program, prompt], capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.decode("utf-8", "replace").rstrip("\n")


def _syntax_bad(text):
    """busybox sh -n on the command text."""
    try:
        proc = subprocess.run([HOST_BUSYBOX, "sh", "-n", "-c", text],
                              capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode != 0


def _router_env(router, state, matched, parsed, original_command):
    """The environment every router command and program runs with (4.1, 4.2)."""
    env = dict(_base_router_env(router))
    options = matched["options"] if matched else []
    pty_allowed = (matched is None or is_vulnerable(state, "pty")
                   or not ("restrict" in options or "no-pty" in options))
    if ("-tt" in parsed["flags"] or "-t" in parsed["flags"]) and pty_allowed:
        env["FAKE_TTY"] = "1"
    if "-A" in parsed["flags"]:
        agent_allowed = (matched is None or is_vulnerable(state, "agent")
                         or not ("restrict" in options
                                 or "no-agent-forwarding" in options))
        sock = os.environ.get("SSH_AUTH_SOCK")
        if agent_allowed and sock:
            env["SSH_AUTH_SOCK"] = sock
    if original_command is not None:
        env["SSH_ORIGINAL_COMMAND"] = original_command
    setenv = parsed["o"].get("SetEnv")
    if setenv and is_vulnerable(state, "setenv"):
        key, _, value = setenv.partition("=")
        if key:
            env[key] = value
    return env


def ssh_main(argv, tool="ssh"):
    """The fake ssh (and, until their round, scp and sftp)."""
    root = Path(os.environ["FAKE_ROUTER_ROOT"]).resolve()
    rc, fields = _ssh_dispatch(FakeRouter(root), list(argv), tool)
    entry = {"n": _next_n(root), "tool": tool, "argv": list(argv)}
    entry.update(fields)
    entry["rc"] = rc
    entry["clock"] = _read_clock(root)
    entry["leaks"] = _scan_leaks(root, list(argv))
    _append_call(root, entry)
    return rc


def _ssh_dispatch(router, argv, tool):
    """Everything ssh does, minus the logging; returns (rc, log fields)."""
    if tool in ("scp", "sftp"):
        return _scp_sftp_dispatch(router, argv, tool)
    parsed, bad = _parse_ssh_argv(argv)
    if bad is not None:
        return 254, {"unsupported": bad}

    state = router.state()
    o = parsed["o"]
    strict = o.get("StrictHostKeyChecking")
    kh_file = o.get("UserKnownHostsFile")
    fields = {"strict": strict, "known_hosts": kh_file}
    rest = parsed["rest"]
    if not rest or "@" not in rest[0]:
        return 254, dict(fields, unsupported="destination")
    user, host = rest[0].split("@", 1)
    command = " ".join(rest[1:]) or None
    fields["command"] = command
    port = parsed["vals"].get("-p") or parsed["vals"].get("-P") or "22"

    rc = _host_key_policy(state, host, port, strict, kh_file)
    if rc is not None:
        fields["principal"] = "none"
        return rc, fields

    def denied(fields):
        print("%s@%s: Permission denied." % (user, host), file=sys.stderr)
        extra = state.get("deny_stderr") or ""
        if extra:
            print(extra, file=sys.stderr)
        return 255, fields

    if parsed["vals"].get("-i"):
        fields["lane"] = "key"
        blob = _private_blob(Path(parsed["vals"]["-i"]))
        matched = None
        if blob is not None:
            for line in router.authorized_keys():
                ak = _parse_ak_line(line)
                if ak and ak["blob"] == blob:
                    matched = ak
                    break
            if matched is None and blob in state.get("ghost_blobs", []):
                matched = {"options": [], "blob": blob, "comment": "ghost",
                           "command": None}
        if matched is None:
            fields["principal"] = "none"
            return denied(fields)
        fields["principal"] = "key:%s" % (matched["comment"] or "no-comment")
        if matched["command"] is not None \
                and state.get("deny_restricted_when_plain_absent"):
            plain = any(a and a["command"] is None
                        for a in (_parse_ak_line(l)
                                  for l in router.authorized_keys()))
            if not plain:
                print("Connection closed by remote host.", file=sys.stderr)
                return 255, fields
    elif os.environ.get("SSH_ASKPASS"):
        fields["lane"] = "password"
        if not state.get("password_auth"):
            fields["principal"] = "none"
            return denied(fields)
        password = _run_askpass("root@%s's password: " % host)
        if password is None or password != state.get("root_password"):
            fields["principal"] = "none"
            return denied(fields)
        fields["principal"] = "password"
        matched = None
    else:
        fields["principal"] = "none"
        return denied(fields)

    if "-N" in parsed["flags"] or any(parsed["vals"].get(flag)
                                      for flag in ("-L", "-D", "-R")):
        return _forward_session(router, state, parsed, matched), fields

    options = matched["options"] if matched else []
    pty_allowed = (matched is None or is_vulnerable(state, "pty")
                   or not ("restrict" in options or "no-pty" in options))
    pty_refusal = state.get("dropbear_refuse_pty") or ""
    if pty_refusal and ("-tt" in parsed["flags"] or "-t" in parsed["flags"]) \
            and not pty_allowed:
        if pty_refusal == "dropbear":
            print("PTY allocation request failed on channel 0",
                  file=sys.stderr)
        else:
            print("%s@%s: Permission denied (publickey)."
                  % (user, host), file=sys.stderr)
        fields["pty_refused"] = pty_refusal
        if not state.get("dropbear_refuse_pty_body"):
            return 255, fields

    forced = matched["command"] if matched else None
    if forced is None and command is None:
        return 254, fields
    text = forced if forced is not None else command
    # "$RR" only as the whole name: a random crypt hash such as
    # "$6$salt$RRClsq..." holds "$RR" inside a longer word
    if re.search(r"\$RR(?![A-Za-z0-9_])", text) or "${RR}" in text:
        # the tool expands RR on the host when it builds a command
        fields["unexpanded_rr"] = True
        return 254, fields
    if _syntax_bad(text):
        fields["syntax_error"] = True
        return 254, fields
    for needle in state.get("drop_commands") or []:
        if needle and needle in text:
            fields["dropped"] = True
            print("Connection closed by remote host.", file=sys.stderr)
            return 255, fields
    for needle in state.get("fail_commands") or []:
        if needle and needle in text:
            fields["failed"] = True
            print("fake-router: command failed: %s" % needle, file=sys.stderr)
            return 1, fields
    # rc_commands: the remote command RUNS (so the session marker the
    # tool writes reaches the stderr) and the router's shell exits with
    # the given status, as when the remote command itself fails; a list
    # of [needle, rc] pairs
    override_rc = None
    for pair in state.get("rc_commands") or []:
        try:
            needle = pair[0]
            want_rc = int(pair[1])
        except (IndexError, TypeError, ValueError):
            continue
        if needle and needle in text:
            override_rc = want_rc
            break

    stdin_data = sys.stdin.buffer.read()
    if stdin_data and state.get("corrupt_stdin"):
        # test knob: flip the first stdin byte so the
        # host-side sha256 comparison of an upload fails
        stdin_data = bytes([stdin_data[0] ^ 0xFF]) + stdin_data[1:]
    fields["stdin_len"] = len(stdin_data)
    fields["stdin_sha256"] = hashlib.sha256(stdin_data).hexdigest()
    script_lines = state.get("owner_script_lines")
    if command == "sh -s" and isinstance(script_lines, list):
        # The fake router is not root and has no uci staging, so it
        # cannot run the owner script for real.  A test may tell it what
        # the script printed; the script's own bytes still travel over
        # the lane (their digest is the one above).
        for line in script_lines:
            print(line)
        return 0, fields
    env = _router_env(router, state, matched, parsed,
                      command if forced is not None else None)
    if forced is not None:
        parts = shlex.split(forced)
        exe = router.path(parts[0]) if parts[0].startswith("/") else Path(parts[0])
        if not exe.exists():
            return 127, fields
        exec_argv = [str(exe)] + parts[1:]
    else:
        exec_argv = ["/bin/sh", "-c", command]
    # The router shell may leave a background job behind (the dead-man
    # switch: `setsid sh -c 'sleep 90; ...' &`).  The fake setsid stub is a
    # python program that registers its timer a moment after the shell has
    # exited, so the call must not return before that process group is empty,
    # or a later fake-sleep can run before the timer exists .
    # a router root shell runs with umask 022 (OpenWrt), not with the umask
    # of the tool that called ssh (077): a router command that relies on the
    # tool's umask instead of an explicit chmod must show up in the tests
    proc = subprocess.Popen(exec_argv, stdin=subprocess.PIPE, env=env,
                            start_new_session=True,
                            preexec_fn=lambda: os.umask(0o022))
    try:
        proc.communicate(input=stdin_data, timeout=60)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(OSError):
            os.killpg(proc.pid, signal.SIGKILL)
        proc.communicate()
        return 255, fields
    _wait_process_group_gone(proc.pid)
    # post-call hook (WAN-health verify test): the call number is the next
    # available n (the entry is logged only after _ssh_dispatch returns).
    # When `corrupt_after_call_n` matches that n, overwrite the listed
    # router path so a later sha256sum (the install_wan_health_verify
    # step) sees different bytes than what put_file just wrote.
    upcoming_n = _next_n(router.root)
    for trigger_n, trigger_path in (state.get("corrupt_after_call_n") or []):
        if trigger_n == upcoming_n:
            try:
                Path(trigger_path).write_bytes(b"corrupted-after-put\n")
            except OSError:
                pass
    for needle in state.get("die_after_commands") or []:
        if needle and needle in text:
            fields["died_after"] = True
            print("Connection closed by remote host.", file=sys.stderr)
            return 255, fields
    if state.get("tt_rc") and ("-tt" in parsed["flags"] or "-t" in parsed["flags"]):
        return state["tt_rc"], fields  # body ran, ssh still exits non-zero
    if fields.get("pty_refused") and state.get("refuse_pty_body_rc"):
        return state["refuse_pty_body_rc"], fields  # refusal text, body ran, rc 255
    if override_rc is not None:
        fields["remote_rc"] = override_rc
        return override_rc, fields  # the remote command's own exit status
    return proc.returncode, fields


def _wait_process_group_gone(pgid, limit=10.0):
    """Wait until no process of the group `pgid` is left (a background job of
    the router shell), at most `limit` seconds."""
    deadline = time.monotonic() + limit
    while time.monotonic() < deadline:
        try:
            os.killpg(pgid, 0)
        except OSError:
            return
        time.sleep(0.005)


# ---------------------------------------------------------------------------
# forwarding sessions: -N -L/-D/-R
# ---------------------------------------------------------------------------

FORWARD_BANNER = b"SSH-2.0-FAKE\r\n"


def _router_syslog(router, message):
    """Append one line to the router's syslog (the logger stub's file)."""
    log = router.path("tmp/syslog")
    log.parent.mkdir(parents=True, exist_ok=True)
    with open(log, "a") as fh:
        fh.write(message + "\n")


def _recv_exact(conn, count):
    """Read exactly count bytes, or fewer when the peer closes first."""
    data = b""
    while len(data) < count:
        chunk = conn.recv(count - len(data))
        if not chunk:
            break
        data += chunk
    return data


def _socks_reply(conn, code):
    """One SOCKS5 reply: the code, address 0.0.0.0, port 0."""
    conn.sendall(b"\x05" + bytes([code]) +
                 b"\x00\x01\x00\x00\x00\x00\x00\x00")


def _parse_socks_destination(conn):
    """One SOCKS5 CONNECT request; returns (host, port) or None on bad ATYP."""
    header = _recv_exact(conn, 2)
    if len(header) < 2 or header[0] != 5:
        return None
    _recv_exact(conn, header[1])
    conn.sendall(b"\x05\x00")
    request = _recv_exact(conn, 4)
    if len(request) < 4 or request[1] != 1:
        return None
    atyp = request[3]
    if atyp == 1:
        addr = _recv_exact(conn, 4)
        if len(addr) < 4:
            return None
        host = ".".join(str(b) for b in addr)
    elif atyp == 3:
        length = _recv_exact(conn, 1)
        data = _recv_exact(conn, length[0] if length else 0)
        host = data.decode("utf-8", "replace")
    elif atyp == 4:
        data = _recv_exact(conn, 16)
        if len(data) < 16:
            return None
        host = socket.inet_ntop(socket.AF_INET6, data)
    else:
        return None
    port_bytes = _recv_exact(conn, 2)
    if len(port_bytes) < 2:
        return None
    port = (port_bytes[0] << 8) | port_bytes[1]
    return host, port


def _serve_socks(conn, allowed, closed_targets=()):
    """Just enough SOCKS5: no-auth greeting, one CONNECT of ATYP 1, 3 or 4."""
    try:
        conn.settimeout(5)
        dest = _parse_socks_destination(conn)
        if dest is None:
            _socks_reply(conn, 2)
            return
        host, port = dest
        closed = "%s:%d" % (host, port) in closed_targets
        if not allowed:
            _socks_reply(conn, 2)
            return
        if closed:
            _socks_reply(conn, 5)
            return
        _socks_reply(conn, 0)
        conn.sendall(FORWARD_BANNER)
    except OSError:
        pass
    finally:
        for how in (socket.SHUT_WR, socket.SHUT_RDWR):
            try:
                conn.shutdown(how)
            except OSError:
                pass
        try:
            conn.close()
        except OSError:
            pass


def _handle_forward_conn(conn, kind, allowed, closed_targets=()):
    """Serve one accepted local forwarding connection."""
    try:
        conn.settimeout(5)
        if kind == "-L":
            if allowed:
                conn.sendall(FORWARD_BANNER)
            # shut down the write side: the client sees EOF and stops at once,
            # then wait for the client to close (so `nc -w 3` does not wait
            # the full 3 s).
            conn.shutdown(socket.SHUT_WR)
            try:
                conn.recv(1024)
            except OSError:
                pass
            conn.close()
        else:
            _serve_socks(conn, allowed, closed_targets=closed_targets)
    except OSError:
        try:
            conn.close()
        except OSError:
            pass


def _make_listener(bind, port, kind, allowed, thost, tport):
    """One listening socket for -L or -D.

    thost/tport are the -L target (empty for -D; -D targets are parsed
    from the SOCKS5 CONNECT inside _handle_forward_conn)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind, int(port)))
    sock.listen(8)
    return sock, kind, allowed, thost, tport


def _run_forward_loop(listeners, closed_targets=()):
    """Serve the listeners until SIGTERM or SIGINT; always exits 255.

    `closed_targets` is a list of "host:port" strings; the -D handler
    uses it to send SOCKS5 code 5 (connection refused) for CONNECT
    requests whose destination is in the list."""
    stop_read, stop_write = socket.socketpair()

    def _stopped(_signum, _frame):
        try:
            stop_write.send(b"x")
        except OSError:
            pass

    previous = {sig: signal.signal(sig, _stopped)
                for sig in (signal.SIGTERM, signal.SIGINT)}
    selector = selectors.DefaultSelector()
    for sock, kind, allowed, thost, tport in listeners:
        sock.setblocking(False)
        selector.register(sock, selectors.EVENT_READ,
                          (sock, kind, allowed, thost, tport))
    selector.register(stop_read, selectors.EVENT_READ, None)
    try:
        while True:
            for key, _events in selector.select(timeout=1.0):
                if key.data is None:
                    return 255
                _sock, kind, allowed, thost, tport = key.data
                try:
                    conn, _addr = key.fileobj.accept()
                except OSError:
                    continue
                _handle_forward_conn(conn, kind, allowed,
                                     closed_targets=closed_targets)
    finally:
        selector.close()
        stop_read.close()
        stop_write.close()
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def _forward_session(router, state, parsed, matched):
    """The -N forwarding session; returns an ssh rc.

    When the state's `closed_targets` knob names a target of an -L spec
    (or the SOCKS5 CONNECT destination of a -D), the local end accepts
    the connection then closes it at once with no byte (-L: EOF; -D:
    SOCKS5 code 5); this lets the proof's positive control prove the
    local nc and the path instead of getting the banner for a closed
    target."""
    options = matched["options"] if matched else []
    allowed = (matched is None or is_vulnerable(state, "forwarding")
               or not ("restrict" in options
                       or "no-port-forwarding" in options))
    closed_targets = state.get("closed_targets") or []
    exit_on_fail = parsed["o"].get("ExitOnForwardFailure") == "yes"
    listeners = []
    try:
        for flag in ("-L", "-D"):
            spec = parsed["vals"].get(flag)
            if not spec:
                continue
            try:
                if flag == "-L":
                    bind, port, target = spec.split(":", 2)
                    bind = bind or "127.0.0.1"
                    if target.startswith("["):
                        closing = target.find("]:")
                        if closing < 0:
                            raise ValueError("bad bracketed -L target")
                        thost = target[1:closing]
                        tport = target[closing + 2:]
                    else:
                        thost, tport = target.rsplit(":", 1)
                    target_closed = ("%s:%s" % (thost, tport)
                                     in closed_targets)
                else:
                    bind, _, port = spec.rpartition(":")
                    bind = bind or "127.0.0.1"
                    thost = ''
                    tport = 0
                    target_closed = False
                # `vulnerable` may also name "forwarding-L" or "forwarding-D":
                # only that one kind of forward carries bytes
                kind_open = allowed or is_vulnerable(
                    state, "forwarding-" + flag[1:])
                listener_allowed = kind_open and not target_closed
                listeners.append(_make_listener(
                    bind, port, flag, listener_allowed, thost, tport))
            except (OSError, ValueError):
                print("bind: %s" % spec, file=sys.stderr)
                if exit_on_fail:
                    return 255
        remote = parsed["vals"].get("-R")
        if remote and not allowed:
            rport = remote.split(":")[0]
            _router_syslog(router, "sshd: error: remote port forwarding "
                                   "failed for listen port %s" % rport)
            if exit_on_fail:
                print("Error: remote port forwarding failed for listen "
                      "port %s" % rport, file=sys.stderr)
                return 255
            print("Warning: remote port forwarding failed for listen "
                  "port %s" % rport, file=sys.stderr)
        return _run_forward_loop(listeners, closed_targets=closed_targets)
    finally:
        for sock, _kind, _allowed, _t1, _t2 in listeners:
            try:
                sock.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# fake scp and sftp
# ---------------------------------------------------------------------------

SCP_VALUE_LETTERS = set("PiFobSl")
SCP_FLAG_LETTERS = set("qvrpBCON1234")


def _parse_scp_argv(argv):
    """Split a scp/sftp argv (combined short flags included) into the same
    shape _parse_ssh_argv returns; the second item is the bad option."""
    parsed = {"vals": {}, "o": {}, "flags": set(), "rest": []}
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--":
            parsed["rest"].extend(argv[i + 1:])
            break
        if arg.startswith("-") and len(arg) > 1:
            j = 1
            while j < len(arg):
                letter = arg[j]
                if letter in SCP_VALUE_LETTERS:
                    if j + 1 < len(arg):
                        value, j = arg[j + 1:], len(arg)
                    elif i + 1 < len(argv):
                        value, j, i = argv[i + 1], len(arg), i + 1
                    else:
                        return None, arg
                    if letter == "o":
                        key, _, option_value = value.partition("=")
                        if key not in ALLOWED_SSH_O:
                            return None, "-o %s" % key
                        parsed["o"][key] = option_value
                    else:
                        parsed["vals"]["-" + letter] = value
                elif letter in SCP_FLAG_LETTERS:
                    parsed["flags"].add("-" + letter)
                    j += 1
                else:
                    return None, "-%s" % letter
            i += 1
        else:
            parsed["rest"].append(arg)
            i += 1
    return parsed, None


def _scp_sftp_dispatch(router, argv, tool):
    """scp and sftp: restricted principals always fail, others succeed
    with no effect."""
    parsed, bad = _parse_scp_argv(argv)
    if bad is not None:
        return 254, {"unsupported": bad}
    state = router.state()
    o = parsed["o"]
    strict = o.get("StrictHostKeyChecking")
    kh_file = o.get("UserKnownHostsFile")
    fields = {"strict": strict, "known_hosts": kh_file, "command": None}
    dest = next((a for a in parsed["rest"] if "@" in a), None)
    if dest is None:
        return 254, dict(fields, unsupported="destination")
    user, host = dest.split("@", 1)
    host = host.split(":", 1)[0]
    port = parsed["vals"].get("-P") or "22"

    rc = _host_key_policy(state, host, port, strict, kh_file)
    if rc is not None:
        fields["principal"] = "none"
        return rc, fields

    def denied(fields):
        print("%s@%s: Permission denied." % (user, host), file=sys.stderr)
        extra = state.get("deny_stderr") or ""
        if extra:
            print(extra, file=sys.stderr)
        return 255, fields

    matched = None
    if parsed["vals"].get("-i"):
        fields["lane"] = "key"
        blob = _private_blob(Path(parsed["vals"]["-i"]))
        if blob is not None:
            for line in router.authorized_keys():
                ak = _parse_ak_line(line)
                if ak and ak["blob"] == blob:
                    matched = ak
                    break
        if matched is None:
            fields["principal"] = "none"
            return denied(fields)
        fields["principal"] = "key:%s" % (matched["comment"] or "no-comment")
    elif os.environ.get("SSH_ASKPASS"):
        fields["lane"] = "password"
        if not state.get("password_auth"):
            fields["principal"] = "none"
            return denied(fields)
        password = _run_askpass("root@%s's password: " % host)
        if password is None or password != state.get("root_password"):
            fields["principal"] = "none"
            return denied(fields)
        fields["principal"] = "password"
    else:
        fields["principal"] = "none"
        return denied(fields)

    stdin_data = sys.stdin.buffer.read()
    fields["stdin_len"] = len(stdin_data)
    fields["stdin_sha256"] = hashlib.sha256(stdin_data).hexdigest()
    if matched is not None and matched["command"] is not None:
        message = ("scp: Connection closed" if tool == "scp"
                   else "Connection closed")
        print(message, file=sys.stderr)
        return 255, fields
    return 0, fields


# ---------------------------------------------------------------------------
# fake curl: the Proxmox API (pve_rollback mirrors)
# ---------------------------------------------------------------------------

CURL_SHORT_FLAGS = set("sSk")
CURL_SHORT_VALUE = set("XdKH")
SNAP_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]+$")
CURL_FAIL_MSG = "curl: (22) The requested URL returned error: %s"


def _parse_curl_argv(argv):
    """Split a curl argv (combined short flags like -sk included) into
    flags, value options, form fields, headers and the one URL; the second
    item is the bad option."""
    parsed = {"flags": set(), "pin": None, "config": None,
              "method": "GET", "form": [], "headers": [], "url": None}
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg.startswith("--"):
            name, eq, value = arg.partition("=")
            if name == "--fail":
                parsed["flags"].add(name)
                i += 1
            elif name in ("--max-time", "--pinnedpubkey", "--data-urlencode"):
                if eq:
                    i += 1
                elif i + 1 < len(argv):
                    value, i = argv[i + 1], i + 2
                else:
                    return None, arg
                if name == "--pinnedpubkey":
                    parsed["pin"] = value
                else:
                    parsed["form"].append(value)
            else:
                return None, arg
        elif arg.startswith("-") and len(arg) > 1:
            j = 1
            while j < len(arg):
                letter = arg[j]
                if letter in CURL_SHORT_FLAGS:
                    parsed["flags"].add("-" + letter)
                    j += 1
                elif letter in CURL_SHORT_VALUE:
                    if j + 1 < len(arg):
                        value, j = arg[j + 1:], len(arg)
                    elif i + 1 < len(argv):
                        value, j, i = argv[i + 1], len(arg), i + 1
                    else:
                        return None, arg
                    if letter == "X":
                        parsed["method"] = value
                    elif letter == "d":
                        parsed["form"].append(value)
                    elif letter == "H":
                        parsed["headers"].append(value)
                    else:
                        parsed["config"] = value
                else:
                    return None, "-%s" % letter
            i += 1
        else:
            if parsed["url"] is not None:
                return None, arg
            parsed["url"] = arg
            i += 1
    if parsed["url"] is None:
        return None, "url"
    if parsed["config"] is not None and parsed["config"] != "-":
        return None, "-K %s" % parsed["config"]
    return parsed, None


def _parse_curl_config(text):
    """The `header = "NAME: VALUE"` lines of a curl -K - config."""
    headers = []
    for line in text.splitlines():
        match = re.match(r'^\s*header\s*=\s*"(.*)"\s*$', line)
        if match:
            headers.append(match.group(1))
    return headers


def _curl_error(code):
    """Print an error body and the --fail style stderr line; rc 22."""
    print('{"data":null}')
    print(CURL_FAIL_MSG % code, file=sys.stderr)
    return 22


def _curl_dispatch(router, argv, stdin_data):
    """Everything curl does, minus the logging; returns (rc, log fields)."""
    parsed, bad = _parse_curl_argv(argv)
    if bad is not None:
        return 254, {"unsupported": bad}
    headers = list(parsed["headers"])
    if parsed["config"] == "-":
        headers.extend(_parse_curl_config(
            stdin_data.decode("utf-8", "replace")))
    fields = {"url": parsed["url"], "method": parsed["method"]}

    state = router.state()
    pve = state.get("pve", {})
    if pve.get("fail"):
        print(pve["fail"], file=sys.stderr)
        return 22, fields
    auth = next((h.split(":", 1)[1].strip() for h in headers
                 if h.split(":", 1)[0].strip().lower() == "authorization"
                 and ":" in h), None)
    if auth != pve.get("token") or parsed["pin"] != pve.get("pin"):
        print("curl: (22) PVE token or pin mismatch", file=sys.stderr)
        return 22, fields

    form = {}
    for item in parsed["form"]:
        key, _, value = item.partition("=")
        form[key] = value
    parts = [p for p in urllib.parse.urlsplit(parsed["url"]).path.split("/")
             if p]

    # POST .../nodes/NODE/qemu/VMID/snapshot with snapname
    if len(parts) == 7 and parts[:2] == ["api2", "json"] \
            and parts[2] == "nodes" and parts[4] == "qemu" \
            and parts[6] == "snapshot" and parsed["method"] == "POST":
        node, vmid = parts[3], parts[5]
        vms = pve.get("vms", {})
        if node != pve.get("node") or vmid not in vms:
            return _curl_error(500), fields
        name = form.get("snapname")
        if name is None or not SNAP_NAME_RE.match(name):
            return _curl_error(400), fields
        snaps = vms[vmid].setdefault("snapshots", [])
        if name in snaps:
            return _curl_error(500), fields
        snaps.append(name)
        router.update_state(pve=pve)
        upid = ("UPID:%s:0001ABCD:00000001:6700AAAA:qmsnapshot:%s:"
                "claude@pve!newton:" % (node, vmid))
        print('{"data":"%s"}' % upid)
        return 0, fields

    # GET .../nodes/NODE/tasks/UPID/status: running then stopped (3.8)
    if len(parts) == 7 and parts[:2] == ["api2", "json"] \
            and parts[2] == "nodes" and parts[4] == "tasks" \
            and parts[6] == "status" and parsed["method"] == "GET":
        polls = pve.get("polls", 0) + 1
        pve["polls"] = polls
        router.update_state(pve=pve)
        if polls <= pve.get("task_polls", 1):
            print('{"data":{"status":"running"}}')
        else:
            print('{"data":{"status":"stopped","exitstatus":"%s"}}'
                  % pve.get("task_exit", "OK"))
        return 0, fields

    return _curl_error(404), fields


def curl_main(argv):
    """The fake curl: Proxmox API only, every call logged."""
    root = Path(os.environ["FAKE_ROUTER_ROOT"]).resolve()
    stdin_data = sys.stdin.buffer.read()
    rc, fields = _curl_dispatch(FakeRouter(root), list(argv), stdin_data)
    entry = {"n": _next_n(root), "tool": "curl", "argv": list(argv),
             "stdin_len": len(stdin_data),
             "stdin_sha256": hashlib.sha256(stdin_data).hexdigest()}
    entry.update(fields)
    entry["rc"] = rc
    entry["clock"] = _read_clock(root)
    entry["leaks"] = _scan_leaks(root, list(argv))
    _append_call(root, entry)
    return rc


# ---------------------------------------------------------------------------
# install_fakes: the wrappers the tool's NEWTON_SETUP_BIN seam puts on PATH
# ---------------------------------------------------------------------------

def install_fakes(bindir, root):
    """Write executable wrappers ssh, scp, sftp, ssh-keygen, curl and
    fake-sleep into bindir (never a program named sleep)."""
    bindir = Path(bindir)
    bindir.mkdir(parents=True, exist_ok=True)
    root = str(Path(root).resolve())
    preamble = (
        "#!%s\n"
        "import os\n"
        "import sys\n"
        "sys.path.insert(0, %r)\n"
        "os.environ['FAKE_ROUTER_ROOT'] = %r\n"
        "from router_setup_harness import ssh_main, keygen_main, "
        "curl_main, fake_sleep_main\n"
    ) % (sys.executable, str(MODULE_DIR), root)
    tools = [
        ("ssh", "sys.exit(ssh_main(sys.argv[1:], tool='ssh'))\n"),
        ("scp", "sys.exit(ssh_main(sys.argv[1:], tool='scp'))\n"),
        ("sftp", "sys.exit(ssh_main(sys.argv[1:], tool='sftp'))\n"),
        ("ssh-keygen", "sys.exit(keygen_main(sys.argv[1:]))\n"),
        ("curl", "sys.exit(curl_main(sys.argv[1:]))\n"),
        ("fake-sleep", "sys.exit(fake_sleep_main(sys.argv[1:]))\n"),
    ]
    for name, tail in tools:
        _write_executable(bindir / name, preamble + tail)
