"""end-to-end host test for scripts/owrt-change.sh.

Design 7.4 "the one end-to-end host test": a fake ssh runs the REAL
router program (device/openwrt/newton-router/newton-router) in test mode
against a fake router root, so ``plan`` and ``apply`` go through hello,
stage, seal, diff, apply, verify and confirm FOR REAL with no canned
replies.

The host's hashes of ``diff`` and ``base`` are pinned against the
router's (design 3.5b steps 3-4); canned replies cannot do that, because
a canned reply can repeat the host's own mistake (e.g. a diff hashed
without its final LF).

Helpers the router harness lacks (md5sum that actually computes md5 for
the helper's confighash) live in this file. The router harness's Router
class is reused by importing its conftest by file path.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
import types
from pathlib import Path

import pytest


HERE = Path(__file__).resolve()
REPO = HERE.parents[2]
SCRIPT = REPO / "scripts" / "owrt-change.sh"
PROG_PATH = "/usr/libexec/newton/newton-router"
BUSYBOX = "/usr/bin/busybox"
SID = "0123456789abcdef0123456789abcdef"
DIFF_TEXT = b"dhcp.cfg01.domain=lan\n"
POST_DHCP = b"config dnsmasq\n\toption domainneeded '0'\n"
ORIGINAL_DHCP = b"config dnsmasq\n\toption domainneeded '1'\n"


# ----- fake-ssh -----------------------------------------------------------
#
# The fake ssh takes its first argument that contains "@" as the
# destination, joins everything after it into the remote command string,
# forwards its stdin, runs the real program against the fake router root
# (NEWTON_ROUTER_ROOT set, --caller=<label> --role=change), and returns
# the program's rc/stdout/stderr unchanged. The one documented exception:
# the hello reply's ``mode=test`` is rewritten to ``mode=prod`` because
# the host only talks to prod routers (the test-mode program says test).

FAKE_SSH_BODY = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    import os
    import subprocess
    import sys
    from pathlib import Path

    PROGRAM = Path(os.environ["FAKE_SSH_PROGRAM"])
    ROUTER_ROOT = Path(os.environ["FAKE_SSH_ROUTER_ROOT"])
    BUSYBOX = os.environ["FAKE_SSH_BUSYBOX"]
    CONNECT_FLAG = Path(os.environ.get("FAKE_SSH_CONNECT_FLAG", "/nonexistent"))

    try:
        dest_idx = next(i for i, a in enumerate(sys.argv[1:], 1) if "@" in a)
    except StopIteration:
        sys.stderr.write("fake ssh: destination not found\\n")
        sys.exit(127)
    cmd = " ".join(sys.argv[dest_idx + 1:])

    stdin_bytes = sys.stdin.buffer.read()

    if CONNECT_FLAG.exists():
        sys.stderr.write("ssh: connect to host 192.0.2.1 port 22: Connection timed out\\n")
        sys.exit(255)

    env = {
        "PATH": "/usr/bin:/bin",
        "NEWTON_ROUTER_ROOT": str(ROUTER_ROOT),
        "LC_ALL": "C",
        "SSH_ORIGINAL_COMMAND": cmd,
    }
    argv = [BUSYBOX, "sh", str(PROGRAM), "--caller=host-e2e", "--role=change"]

    try:
        proc = subprocess.run(
            argv, input=stdin_bytes,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, timeout=60,
        )
    except subprocess.TimeoutExpired:
        sys.stderr.write("fake ssh: program timeout\\n")
        sys.exit(124)

    out_bytes = proc.stdout
    err_bytes = proc.stderr
    if cmd.startswith("/usr/libexec/newton/newton-router hello "):
        out_text = out_bytes.decode("utf-8", "replace")
        out_text = out_text.replace(" mode=test ", " mode=prod ")
        out_bytes = out_text.encode("utf-8")

    sys.stdout.buffer.write(out_bytes)
    sys.stderr.buffer.write(err_bytes)
    sys.exit(proc.returncode)
    """
)


# md5sum: the helper's confighash runs md5sum over each /etc/config file.
# The router harness's fake root has no md5sum binary; the generic fake
# is not appropriate here because md5sum's stdout is the helper's input.

MD5SUM_FAKE = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    import hashlib
    import os
    import sys
    from pathlib import Path

    ROOT = Path(os.environ.get("NEWTON_ROUTER_ROOT", ""))
    log = ROOT / "control" / "calls.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a") as f:
        f.write("md5sum " + " ".join(sys.argv[1:]) + "\\n")

    if len(sys.argv) > 1 and sys.argv[1] != "-":
        rc = 0
        for path_str in sys.argv[1:]:
            try:
                data = Path(path_str).read_bytes()
                sys.stdout.write(hashlib.md5(data).hexdigest() + "  " + path_str + "\\n")
            except OSError as exc:
                sys.stderr.write("md5sum: " + path_str + ": " + str(exc) + "\\n")
                rc = 1
        sys.exit(rc)
    data = sys.stdin.buffer.read()
    sys.stdout.write(hashlib.md5(data).hexdigest() + "  -\\n")
    """
)


# uci: the helper's stage needs ``uci -P <dir> batch``, ``uci -P <dir>
# changes`` and ``uci -q get <path>``. The router harness's bin/uci is
# symlinked to the generic fake which logs and exits 0 with empty
# stdout — that prevents the helper from doing anything. This fake
# maintains its own per-session state file (control/uci-<sid>.json) so
# batch writes are visible to a later ``changes`` call in the same
# session, and treats un-prefixed calls as live (the /etc/config
# directory).

UCI_FAKE = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    import json
    import os
    import re
    import sys
    from pathlib import Path

    ROOT = Path(os.environ.get("NEWTON_ROUTER_ROOT", ""))
    CONFIG = ROOT / "etc/config"
    CONTROL = ROOT / "control"
    CONTROL.mkdir(parents=True, exist_ok=True)
    log = CONTROL / "calls.log"

    args = sys.argv[1:]
    with log.open("a") as f:
        f.write("uci " + " ".join(args) + "\\n")

    # parse flags
    staged = False
    quiet = False
    staged_dir = ""
    while args and args[0] in ("-P", "-q"):
        if args[0] == "-P":
            staged = True
            staged_dir = args[1]
            args = args[2:]
        elif args[0] == "-q":
            quiet = True
            args = args[1:]
        else:
            break

    if not args:
        sys.exit(1)

    def session_state_path():
        m = re.search(r"rpcd/uci-([0-9a-f]+)", staged_dir)
        if not m:
            return None
        sid = m.group(1)
        return CONTROL / ("uci-" + sid + ".json"), sid

    def live_state_path():
        return CONTROL / "uci-live.json", None

    cmd = args[0]
    target = args[1] if len(args) > 1 else ""

    if cmd == "changes":
        if staged:
            sp, sid = session_state_path()
            if sp is not None and sp.exists():
                with sp.open() as f:
                    data = json.load(f)
                for line in data.get("changes", []):
                    print(line)
        sys.exit(0)

    if cmd == "batch":
        # batch input on stdin; lines that don't start with a recognized
        # verb go to stderr (the helper checks stderr for rejection).
        state_path, sid = session_state_path()
        if state_path is None:
            sys.exit(1)
        if state_path.exists():
            data = json.loads(state_path.read_text())
        else:
            data = {"changes": [], "values": {}}
        batch_lines = sys.stdin.read().splitlines()
        bad = []
        changes = []
        for line in batch_lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            kind = stripped.split(None, 1)[0]
            if kind not in ("set", "add", "add_list", "del_list", "delete",
                            "rename", "reorder"):
                bad.append(line)
                continue
            # parse ``set path=value`` -> store value, record an effective
            # diff line in the form ``path='value'`` (the form the awk
            # parser in seal/leash_classify accepts).
            m = re.match(r"set\\s+([A-Za-z0-9_.@\\-\\[\\]]+)=(.*)", stripped)
            if m:
                path, value = m.group(1), m.group(2)
                data["values"][path] = value
                changes.append(path + "=" + value)
        data["changes"] = changes
        state_path.write_text(json.dumps(data))
        if bad:
            sys.stderr.write("uci: unknown verb: " + bad[0] + "\\n")
            sys.exit(1)
        sys.exit(0)

    if cmd == "get":
        state_path, sid = session_state_path() if staged else live_state_path()
        if state_path.exists():
            data = json.loads(state_path.read_text())
        else:
            data = {"values": {}}
        if target in data["values"]:
            print(data["values"][target])
            sys.exit(0)
        if not quiet:
            sys.stderr.write("uci: Entry not found\\n")
        sys.exit(1)

    sys.exit(0)
    """
)


# ubus wrapper: the helper's stage calls ``ubus call session create``
# and ``ubus call session grant``. The router harness's fake ubus logs
# the call and exits 0 with empty stdout, which makes jsonfilter fail
# to extract the SID. This wrapper handles the session verbs and
# delegates everything else to the harness's existing fake ubus.

UBUS_FAKE = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    import json
    import os
    import sys
    from pathlib import Path

    ROOT = Path(os.environ.get("NEWTON_ROUTER_ROOT", ""))
    FALLBACK = ROOT / "control" / "fakes-ubus.py"
    args = sys.argv[1:]

    # session create: return the fixed SID in the JSON the helper expects
    if (len(args) >= 4 and args[0] == "call"
            and args[1] == "session" and args[2] == "create"):
        import re
        timeout = 300
        m = re.search(r'"timeout"\\s*:\\s*(\\d+)', args[3])
        if m:
            timeout = int(m.group(1))
        sid = os.environ.get("FAKE_SSH_SID", "0123456789abcdef0123456789abcdef")
        sys.stdout.write(json.dumps({"ubus_rpc_session": sid,
                                      "timeout": timeout}) + "\\n")
        sys.stdout.flush()
        # add to sessions file
        sessions = ROOT / "control" / "sessions"
        existing = sessions.read_text() if sessions.exists() else ""
        if sid not in existing.split():
            with sessions.open("a") as f:
                f.write(sid + "\\n")
        sys.exit(0)

    # session grant: success
    if (len(args) >= 4 and args[0] == "call"
            and args[1] == "session" and args[2] == "grant"):
        sys.stdout.write(json.dumps({"timeout": 300}) + "\\n")
        sys.exit(0)

    # otherwise hand off to the harness's existing fake ubus
    os.execv(sys.executable, [sys.executable, str(FALLBACK)] + args)
    """
)


# BASH_ENV file: virtual sleep override so the failure-branch waits cost
# no time. The host script's sleeps become instant; SECONDS still ticks.
BASH_ENV_BODY = (
    "sleep() { local s=${1%%.*}; [[ $s =~ ^[0-9]+$ ]] || s=0;"
    " SECONDS=$((SECONDS + s)); export NEWTON_VIRTUAL_SECONDS=$SECONDS;"
    " command sleep 0.01; }\n"
)


# ucode fake for the helper's health-snapshot / health-check JSON parse.
# Same body used by test_flow.py.

FAKE_UCODE_BODY = (
    "#!/usr/bin/python3\n"
    "import json, sys\n"
    "script = ''\n"
    "i = 1\n"
    "while i < len(sys.argv):\n"
    "    if sys.argv[i] == '-e' and i + 1 < len(sys.argv):\n"
    "        script = sys.argv[i + 1]\n"
    "        i += 2\n"
    "    else:\n"
    "        i += 1\n"
    "three_field = ('\\\\t%s' in script)\n"
    "try:\n"
    "    obj = json.loads(sys.stdin.read())\n"
    "except Exception:\n"
    "    sys.exit(1)\n"
    "if not isinstance(obj, dict):\n"
    "    sys.exit(1)\n"
    "for service, body in obj.items():\n"
    "    if not isinstance(body, dict):\n"
    "        continue\n"
    "    instances = body.get('instances', {})\n"
    "    if not isinstance(instances, dict):\n"
    "        continue\n"
    "    for instance, state in instances.items():\n"
    "        if not isinstance(state, dict):\n"
    "            continue\n"
    "        if three_field:\n"
    "            running = 'true' if state.get('running') is True else 'false'\n"
    "            pid = state.get('pid') if state.get('pid') is not None else ''\n"
    "            sys.stdout.write(f'{service}/{instance}\\t{running}\\t{pid}\\n')\n"
    "        elif state.get('running') is True:\n"
    "            sys.stdout.write(f'{service}/{instance}\\n')\n"
    "sys.exit(0)\n"
)


SERVICE_LIST = (
    '{"dnsmasq":{"instances":{"main":{"running":true,"pid":411}}}}\n'
)

DF_OUT = (
    "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
    "/dev/sda1 1000000 1000 999000 1% /etc\n"
)


# ----- helpers (local, do not edit the router conftest) -------------------


def _load_router_conftest():
    """Import device/openwrt/newton-router/tests/conftest.py by file path."""
    path = (REPO / "device/openwrt/newton-router/tests/conftest.py").resolve()
    spec = importlib.util.spec_from_file_location("router_conftest_e2e", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def install_init_fakes(router):
    """init.d/firewall and init.d/dnsmasq both succeed (verify, fwrestart)."""
    initd = router.root / "etc/init.d"
    initd.mkdir(parents=True, exist_ok=True)
    router.write("etc/init.d/firewall", "#!/bin/sh\nexit 0\n", mode=0o755)
    router.write(
        "etc/init.d/dnsmasq",
        "#!/bin/sh\n"
        'case "$1" in running) exit 0 ;; restart) exit 0 ;; *) exit 0 ;; esac\n',
        mode=0o755,
    )


def install_ucode(router):
    """Drop a ucode fake next to the other fakes."""
    ucode = router.root / "bin" / "ucode"
    if ucode.exists() or ucode.is_symlink():
        ucode.unlink()
    router.write("bin/ucode", FAKE_UCODE_BODY, mode=0o755)


def install_md5sum(router):
    """Drop a md5sum fake that actually computes md5 (the helper's
    confighash pipes bytes from md5sum into its output)."""
    md5 = router.root / "bin" / "md5sum"
    if md5.exists() or md5.is_symlink():
        md5.unlink()
    router.write("bin/md5sum", MD5SUM_FAKE, mode=0o755)


def ready_for_arm(router):
    router.set_fake("df", out=DF_OUT)


def ready_for_health(router):
    install_ucode(router)
    router.set_fake("ubus", out=SERVICE_LIST)


def staged_dhcp(router):
    router.write("control/staged/dhcp", POST_DHCP)


def confighash_text(router):
    """The md5 lines the helper would print for the fake root's
    /etc/config (matching the program's confighash_text rule and the
    harness's VALID_NAME regex)."""
    import re as _re
    valid = _re.compile(r"[A-Za-z0-9_-]+")
    out_lines = []
    for path in sorted((router.root / "etc/config").iterdir(), key=lambda p: p.name):
        if path.is_file() and not path.is_symlink() and valid.fullmatch(path.name):
            digest = hashlib.md5(path.read_bytes()).hexdigest()
            out_lines.append(f"{digest} {path.name}\n")
    return "".join(out_lines)


def snap_cfg(router):
    cfg = router.root / "etc/config"
    return {p.name: p.read_bytes() for p in sorted(cfg.iterdir())
            if p.is_file() and not p.is_symlink()}


# ----- e2e fixture ---------------------------------------------------------


def _unshare_ssh_or_skip():
    """The script resolves ssh via /usr/bin/ssh (or /bin/ssh); the fake ssh
    in tmp_path/"bin"/ssh must be bind-mounted there for the test to see
    it.  Skip the test module when ``unshare -Urm`` is unavailable."""
    unshare = shutil.which("unshare")
    if unshare is None:
        pytest.skip("unshare is unavailable; cannot bind-mount a fake ssh over /usr/bin/ssh")
    probe = subprocess.run(
        [unshare, "-Urm", "true"], text=True, capture_output=True, timeout=10
    )
    if probe.returncode != 0:
        reason = probe.stderr.strip() or f"unshare exited {probe.returncode}"
        pytest.skip(f"unshare -Urm is unavailable: {reason}")


@pytest.fixture
def e2e(tmp_path):
    _unshare_ssh_or_skip()
    """A fake router root + a fake ssh that runs the REAL router program
    against it (test mode), and an env dict ready for ``scripts/owrt-change.sh``.

    State persists on disk between ssh calls (the fake root is the router's
    filesystem). The one rewrite: hello's ``mode=test`` -> ``mode=prod``.
    """
    rc = _load_router_conftest()
    router = rc.Router(tmp_path / "router")
    install_init_fakes(router)
    install_ucode(router)
    install_md5sum(router)

    # Replace the harness's bin/uci and bin/ubus symlinks with our own
    # so the REAL helper's stage can call uci -P batch and ubus call
    # session create. Keep a copy of the harness's fake ubus under
    # control/ for our ubus wrapper to delegate non-session calls.
    harness_ubus = REPO / "device/openwrt/newton-router/tests/fakes/ubus"
    if harness_ubus.exists():
        (router.root / "control" / "fakes-ubus.py").write_text(
            harness_ubus.read_text())
    for name in ("uci", "ubus"):
        link = router.root / "bin" / name
        if link.is_symlink() or link.exists():
            link.unlink()
    router.write("bin/uci", UCI_FAKE, mode=0o755)
    router.write("bin/ubus", UBUS_FAKE, mode=0o755)

    # Seed the live uci state from the fake root's /etc/config so the
    # helper's stage can verify it does not change the live config and
    # diff against the staged snapshot. Also seed a hostname value so
    # the backup step's hostname subcommand succeeds.
    live_state = {"system.@system[0].hostname": "lab-r1"}
    for p in sorted((router.root / "etc/config").iterdir(), key=lambda p: p.name):
        if p.is_file() and not p.is_symlink():
            for line in p.read_bytes().decode("utf-8", "replace").splitlines():
                m = re.match(
                    r"\s*option\s+([A-Za-z0-9_]+)\s+'([^']*)'", line)
                if m:
                    live_state[f"{p.name}.cfg01.{m.group(1)}"] = m.group(2)
    (router.root / "control" / "uci-live.json").write_text(
        json.dumps({"changes": [], "values": live_state}))

    # The handshake compares sha256 of the controller's copy of every
    # router code file with the router's. The harness installs them with
    # their first line replaced (BusyBox sh); the source keeps the real
    # shebang. Replace the installed copies with byte-identical copies of
    # the sources so the shas match. The init script is the exception:
    # the source uses ``/etc/rc.common`` (OpenWrt procd), which the fake
    # root has no equivalent for, so we install the harness's
    # test-friendly stub at both the fake-root path and the source
    # root's relative path so the shas still match.
    init_stub_path = REPO / "device/openwrt/newton-router/tests/conftest.py"
    init_stub_text = None
    for line in init_stub_path.read_text().splitlines():
        if 'etc/init.d/newton-guard' in line and "exit 0" in line:
            init_stub_text = line.split("'", 1)[1].rsplit("'", 1)[0]
            break
    init_stub_text = init_stub_text or ""

    pairs = [
        (REPO / "device/openwrt/newton-router/newton-router",
         router.root / "usr/libexec/newton/newton-router"),
        (REPO / "scripts/owrt-safe-apply.sh",
         router.root / "usr/libexec/newton/newton-safe-apply"),
        (REPO / "device/openwrt/newton-guard/newton-guard",
         router.root / "usr/libexec/newton-guard"),
    ]
    for src, dst in pairs:
        if src.exists():
            dst.write_bytes(src.read_bytes())
            dst.chmod(0o755)

    # init.d/newton-guard: the source won't run on the fake root, so
    # write the harness's test stub at the fake-root path. Then also
    # write the SAME bytes at a side dir and point OWRT_SRC_ROOT there
    # so the handshake sha matches.
    init_dst = router.root / "etc/init.d/newton-guard"
    init_dst.write_text(init_stub_text)
    init_dst.chmod(0o755)
    init_sha = hashlib.sha256(init_stub_text.encode()).hexdigest()

    src_root_alt = tmp_path / "src_root"
    for src_rel in (
        "scripts/owrt-change.sh",
        "scripts/owrt-safe-apply.sh",
        "scripts/newton-doctor",
        "scripts/newton-install",
        "scripts/newton-router-setup",
        "scripts/newton-lab-isolation",
        "device/openwrt/newton-router/newton-router",
        "device/openwrt/newton-router/grammar.tsv",
        "device/openwrt/newton-guard/newton-guard",
        "device/openwrt/newton-guard/newton-guard.init",
        "mcp/newton_mcp/redact.py",
        "mcp/newton_mcp/secret_names.txt",
        "mcp/newton_mcp/probes.py",
        "mcp/newton_mcp/plan.py",
        "mcp/newton_mcp/policy.py",
        "mcp/newton_mcp/approve.py",
        "mcp/newton_mcp/envelope.py",
        "mcp/newton_mcp/server.py",
        "mcp/newton_mcp/__init__.py",
    ):
        src = REPO / src_rel
        if not src.exists():
            continue
        dst = src_root_alt / src_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src_rel == "device/openwrt/newton-guard/newton-guard.init":
            dst.write_text(init_stub_text)
        else:
            try:
                dst.symlink_to(src)
            except OSError:
                dst.write_bytes(src.read_bytes())

    bindir = tmp_path / "bin"
    bindir.mkdir()
    ssh = bindir / "ssh"
    ssh.write_text(
        FAKE_SSH_BODY
        .replace("BUSYBOX = os.environ[\"FAKE_SSH_BUSYBOX\"]", "BUSYBOX = " + repr(BUSYBOX))
    )
    ssh.chmod(0o755)

    # sleep override (used by both the host script via BASH_ENV and any
    # children that call sleep directly).
    sleep = bindir / "sleep"
    sleep.write_text("#!/bin/sh\nexec /bin/sleep 0.05\n")
    sleep.chmod(0o755)

    bash_env = tmp_path / "bash-env"
    bash_env.write_text(BASH_ENV_BODY)

    # A never-read ssh key file (key mode; ssh is fake so it is unused).
    (tmp_path / "fake-key").write_text("")

    env = os.environ.copy()
    env.update({
        "HOME": str(tmp_path),
        "XDG_STATE_HOME": str(tmp_path / "state"),
        "OWRT_AUDIT_LOG": str(tmp_path / "audit.log"),
        "OWRT_BACKUP_DIR": str(tmp_path / "backups"),
        "OWRT_SRC_ROOT": str(src_root_alt),
        "OWRT_SSH_KEY": str(tmp_path / "fake-key"),
        "OWRT_EXPECT_DEVICE": "lab-r1",
        "OWRT_EXPECT_PROFILE": "lab",
        "BASH_ENV": str(bash_env),
        "PATH": str(bindir) + os.pathsep + env["PATH"],
        "FAKE_SSH_PROGRAM": str(rc.PROGRAM),
        "FAKE_SSH_ROUTER_ROOT": str(router.root),
        "FAKE_SSH_BUSYBOX": BUSYBOX,
        "FAKE_SSH_CONNECT_FLAG": str(tmp_path / "connect-fail"),
        "FAKE_SSH_SID": SID,
    })
    # NB: the fixture does NOT pre-create the XDG_STATE_HOME / OWRT_BACKUP_DIR
    # parents; the script will lay them down and chmod 0700 itself, and any
    # tests that pre-create them must keep them at 0700 to satisfy the new
    # parent-sticky check.
    for var in (
        "OWRT_SSH_PASSWORD_FILE", "OWRT_KNOWN_HOSTS", "OWRT_APPROVAL_TOKEN",
        "OWRT_OPERATOR", "OWRT_LOCAL_CHECK", "OWRT_SSH_PROXY", "OWRT_EXPECT_BASE",
    ):
        env.pop(var, None)

    def _wrap_with_unshare(args, run_env, timeout):
        """Run *args* in a private user+mount namespace where bindir/ssh is
        bind-mounted at /usr/bin/ssh (the script's resolved ssh path)."""
        fake_ssh = str(bindir / "ssh")
        unshare_cmd = [
            "unshare", "-Urm", "--", "bash", "-c",
            'mount --bind "$1" /usr/bin/ssh && shift && exec "$@"',
            "noop", fake_ssh, *args,
        ]
        return subprocess.run(
            unshare_cmd, env=run_env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=timeout, stdin=subprocess.DEVNULL,
        )

    def run_plan(*, changes, timeout=90, probes=None, extra_env=None):
        args = [str(SCRIPT), "plan", "root@lab-r1", str(changes), str(timeout)]
        if probes is not None:
            args.append(str(probes))
        run_env = env.copy()
        if extra_env:
            run_env.update(extra_env)
        return _wrap_with_unshare(args, run_env, 300)

    def run_apply(sid, *, timeout=60, extra_env=None):
        args = [str(SCRIPT), "apply", "root@lab-r1", sid, str(timeout)]
        run_env = env.copy()
        if extra_env:
            run_env.update(extra_env)
        return _wrap_with_unshare(args, run_env, 600)

    def run_status(sid):
        args = [str(SCRIPT), "status", "root@lab-r1", sid]
        return _wrap_with_unshare(args, env, 120)

    def run_abort(sid):
        args = [str(SCRIPT), "abort", "root@lab-r1", sid]
        return _wrap_with_unshare(args, env, 120)

    return types.SimpleNamespace(
        router=router,
        rc=rc,
        env=env,
        root=tmp_path,
        audit=tmp_path / "audit.log",
        state_plans=tmp_path / "state" / "network-agent" / "plans",
        run_plan=run_plan,
        run_apply=run_apply,
        run_status=run_status,
        run_abort=run_abort,
        install_md5sum=lambda: install_md5sum(router),
        install_init_fakes=lambda: install_init_fakes(router),
        install_ucode=lambda: install_ucode(router),
        ready_for_arm=lambda: ready_for_arm(router),
        ready_for_health=lambda: ready_for_health(router),
        staged_dhcp=lambda: staged_dhcp(router),
        confighash_text=lambda: confighash_text(router),
        snap_cfg=lambda: snap_cfg(router),
    )


# ----- plan output shape (used by tests a, b, c, d) -----------------------


_PLAN_OUTPUT_KEYS = (
    "BASEHASH", "PROBES", "PROFILE", "APPROVAL", "PLANDIGEST",
)


def _parse_plan_stdout(stdout):
    """Walk the plan's stdout lines, return (meta dict, raw bytes of the
    diff section). Skips the masked diff section between '----- diff -----'
    and '----------------'."""
    meta = {}
    diff_lines = []
    in_diff = False
    for line in stdout.splitlines():
        if line.startswith("----- diff -----"):
            in_diff = True
            continue
        if line.startswith("----------------"):
            in_diff = False
            continue
        if in_diff:
            diff_lines.append(line)
            continue
        if line.startswith("STAGED "):
            meta["STAGED"] = line[len("STAGED "):]
            continue
        for key in _PLAN_OUTPUT_KEYS:
            if line.startswith(key + " "):
                meta[key] = line[len(key) + 1:]
                break
    return meta, diff_lines


def _audit_lines(e2e):
    return e2e.audit.read_text().splitlines() if e2e.audit.exists() else []


def _sid_from_staged(meta_or_audit_line):
    """Extract SID from a line like 'STAGED session=0123...'."""
    m = re.search(r"session=([0-9a-f]{32})", meta_or_audit_line)
    return m.group(1) if m else None


# =========================================================================
# TESTS
# =========================================================================


def _prep_plannable(e2e):
    """Set up the fake root so the next plan() call goes through hello,
    stage, seal, diff for real. The plan also runs backup (which calls
    hostname + backup), so wire those up too."""
    e2e.router.write("control/staged/dhcp", POST_DHCP)
    e2e.router.set_fake("uci", out="lab-r1\n")
    # health-snapshot needs a valid service list + ucode fake
    e2e.ready_for_health()


def test_a_plan_no_probes_pins_full_plan_output(e2e):
    """Plan with no probes: STAGED, BASEHASH, PROBES 0 <sha of empty>,
    PROFILE, APPROVAL not-required, PLANDIGEST, the masked diff. Exit 0.
    The staged session exists in the fake root."""
    _prep_plannable(e2e)

    changes = e2e.root / "changes.uci"
    changes.write_text("set dhcp.cfg01.domain=lan\n")

    res = e2e.run_plan(changes=changes, timeout=90)
    assert res.returncode == 0, (res.returncode, res.stdout)
    meta, diff_lines = _parse_plan_stdout(res.stdout)

    assert "STAGED" in meta, res.stdout
    sid = _sid_from_staged(meta["STAGED"])
    assert sid is not None and len(sid) == 32, (sid, res.stdout)

    # BASEHASH: 64 hex (the router's sealed base)
    assert re.fullmatch(r"[0-9a-f]{64}", meta["BASEHASH"]), meta
    # PROBES: "<n> <sha>" with n == 0 and sha256 of empty bytes
    n, psha = meta["PROBES"].split(" ", 1)
    assert n == "0", meta
    assert psha == hashlib.sha256(b"").hexdigest(), (psha, meta)

    assert meta["PROFILE"] == "lab", meta
    assert meta["APPROVAL"] == "not-required", meta
    assert re.fullmatch(r"[0-9a-f]{64}", meta["PLANDIGEST"]), meta

    # The masked diff is the same byte-for-byte as DIFF_TEXT (the stub's
    # control/diff.txt), because seal hashes control/diff.txt content.
    assert b"".join((line + "\n").encode() for line in diff_lines).rstrip(b"\n") == DIFF_TEXT.rstrip(b"\n"), diff_lines

    # The staged session exists in the fake root
    sid_dir = e2e.router.root / "tmp/owrt-safe-apply.lock" / f"{sid}.txn"
    assert sid_dir.exists()
    assert (sid_dir / "owner").read_text().strip() == "host-e2e"
    assert (sid_dir / "sealed").exists()

    # The plans file was written
    plans = e2e.state_plans
    assert (plans / f"{sid}.sha256").exists()
    assert (plans / f"{sid}.base").exists()
    assert (plans / f"{sid}.probes").read_text().strip() == "0"


def test_b_plan_with_two_probes_byte_for_byte(e2e):
    """Plan with a probes file (two probes): the probe bytes reach ``seal``
    byte for byte (compare the router's sealed ``probes`` file with the
    host's file), PROBES 2 <sha256 of exactly those bytes>."""
    _prep_plannable(e2e)
    probes = e2e.root / "probes.txt"
    body = b"ping\t127.0.0.1\t1\nfail\n"
    probes.write_bytes(body)

    changes = e2e.root / "changes.uci"
    changes.write_text("set dhcp.cfg01.domain=lan\n")

    res = e2e.run_plan(changes=changes, timeout=90, probes=probes)
    assert res.returncode == 0, (res.returncode, res.stdout)
    meta, _ = _parse_plan_stdout(res.stdout)
    sid = _sid_from_staged(meta["STAGED"])

    n, psha = meta["PROBES"].split(" ", 1)
    assert n == "2", meta
    assert psha == hashlib.sha256(body).hexdigest(), (psha, meta)

    # The sealed probes file is exactly the bytes the host sent
    sealed_probes = e2e.router.root / "tmp/owrt-safe-apply.lock" / f"{sid}.txn" / "probes"
    assert sealed_probes.read_bytes() == body, sealed_probes.read_bytes()
    # And the sealed probes-sha matches the host's reported sha
    assert (e2e.router.root / "tmp/owrt-safe-apply.lock" / f"{sid}.txn" / "probes-sha").read_text().strip() == psha


def _program_diff_sha(e2e, sid):
    """Run the real program's `diff SID` subcommand against the fake
    router root and sha256 its stdout (the bytes the host will hash at
    apply time)."""
    env = e2e.env.copy()
    env["NEWTON_ROUTER_ROOT"] = str(e2e.router.root)
    env["PATH"] = "/usr/bin:/bin"
    env["SSH_ORIGINAL_COMMAND"] = f"/usr/libexec/newton/newton-router diff {sid}"
    proc = subprocess.run(
        [BUSYBOX, "sh", str(e2e.rc.PROGRAM), "--caller=host-e2e", "--role=change"],
        input=b"", env=env, capture_output=True, timeout=15,
    )
    assert proc.returncode == 0, (proc.returncode, proc.stderr.decode())
    return hashlib.sha256(proc.stdout).hexdigest()


def test_c_hash_pins_after_plan_and_mutation_refuses_apply(e2e):
    """HASH PINS: after plan, the host's recorded diff hash equals sha256
    of the router's real `diff` output AND equals the `diff` line of the
    router's seal AND the router's sealed `diff` file. BASEHASH equals
    the router's sealed `base` AND equals sha256 of the router's
    confighash text computed independently in Python from the fake
    root's /etc/config files.

    Then change what the host hashes (run the host script copy with
    `printf '%s\\n'` replaced by `printf '%s'` in the diff hash line, in
    a tmp copy of scripts/ and mcp/ and device/ layout) and show the
    apply is refused with ``staged diff changed since plan``, proving
    the pin is real.
    """
    _prep_plannable(e2e)
    changes = e2e.root / "changes.uci"
    changes.write_text("set dhcp.cfg01.domain=lan\n")

    res = e2e.run_plan(changes=changes, timeout=90)
    assert res.returncode == 0, (res.returncode, res.stdout)
    meta, _ = _parse_plan_stdout(res.stdout)
    sid = _sid_from_staged(meta["STAGED"])

    plans = e2e.state_plans
    host_diff_sha = (plans / f"{sid}.sha256").read_text().strip()
    host_base_sha = (plans / f"{sid}.base").read_text().strip()

    # 1) program-side diff hash (run the real `diff` subcommand)
    prog_diff_sha = _program_diff_sha(e2e, sid)
    assert prog_diff_sha == host_diff_sha, (prog_diff_sha, host_diff_sha)

    # 2) the router's seal `diff <sha>` line equals host_diff_sha
    sealed_diff_line = (e2e.router.root / "tmp/owrt-safe-apply.lock"
                        / f"{sid}.txn" / "diff").read_text().strip()
    assert sealed_diff_line == host_diff_sha, (sealed_diff_line, host_diff_sha)

    # 3) BASEHASH == sealed base file == sha256 of confighash text
    sealed_base_line = (e2e.router.root / "tmp/owrt-safe-apply.lock"
                        / f"{sid}.txn" / "base").read_text().strip()
    assert sealed_base_line == host_base_sha, (sealed_base_line, host_base_sha)
    # the printed BASEHASH line is what the MCP records as base_hash 
    assert meta["BASEHASH"] == sealed_base_line, (meta["BASEHASH"], sealed_base_line)
    sealed_digest = (e2e.router.root / "tmp/owrt-safe-apply.lock"
                     / f"{sid}.txn" / "digest").read_text().strip()
    assert meta["PLANDIGEST"] == sealed_digest, (meta["PLANDIGEST"], sealed_digest)
    cfg_text = e2e.confighash_text()
    py_base_sha = hashlib.sha256(cfg_text.encode()).hexdigest()
    assert py_base_sha == host_base_sha, (py_base_sha, host_base_sha)

    # Now: build a tmp copy of the repo layout and mutate the diff hash
    # line in scripts/owrt-change.sh. The handshake reads the controller's
    # copy of the program/helper/guard/init from $OWRT_SRC_ROOT/<rel>, so
    # symlink the rest of the tree; the script alone is mutated so the
    # host's printed diff hash no longer matches the router's.
    tmp_copy = e2e.root / "mut"
    e2e_src_root = Path(e2e.env["OWRT_SRC_ROOT"])
    for src_rel in (
        "scripts/owrt-change.sh",
        "scripts/owrt-safe-apply.sh",
        "scripts/newton-doctor",
        "scripts/newton-install",
        "scripts/newton-router-setup",
        "scripts/newton-lab-isolation",
        "device/openwrt/newton-router/newton-router",
        "device/openwrt/newton-router/grammar.tsv",
        "device/openwrt/newton-guard/newton-guard",
        "device/openwrt/newton-guard/newton-guard.init",
        "mcp/newton_mcp/redact.py",
        "mcp/newton_mcp/secret_names.txt",
        "mcp/newton_mcp/probes.py",
        "mcp/newton_mcp/plan.py",
        "mcp/newton_mcp/policy.py",
        "mcp/newton_mcp/approve.py",
        "mcp/newton_mcp/envelope.py",
        "mcp/newton_mcp/server.py",
        "mcp/newton_mcp/__init__.py",
    ):
        src = e2e_src_root / src_rel
        if not src.exists():
            continue
        dst = tmp_copy / src_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src_rel == "scripts/owrt-change.sh":
            dst.write_text(src.read_text())
        else:
            try:
                dst.symlink_to(src)
            except OSError:
                dst.write_bytes(src.read_bytes())
    # Make the diff hash include an extra leading character so it no longer
    # matches the plan record (which was hashed from the unmodified diff
    # bytes). The apply runs the mutated script; the host's printed
    # "staged diff changed since plan" appears when its hash of the real
    # diff bytes no longer equals the plan record.
    mutated = (tmp_copy / "scripts/owrt-change.sh").read_text()
    target = "DIFF_SHA=$(printf '%s\\n' \"$DIFF_RAW\" | sha256sum | cut -d' ' -f1)"
    replacement = ("DIFF_SHA=$(printf 'X%s\\n' \"$DIFF_RAW\""
                   " | sha256sum | cut -d' ' -f1)")
    assert target in mutated, "diff hash line not found in script"
    mutated = mutated.replace(target, replacement, 1)
    (tmp_copy / "scripts/owrt-change.sh").write_text(mutated)
    (tmp_copy / "scripts/owrt-change.sh").chmod(0o755)

    mut_env = e2e.env.copy()
    mut_env["OWRT_SRC_ROOT"] = str(tmp_copy)
    fake_ssh = str(e2e.root / "bin" / "ssh")
    unshare_cmd = [
        "unshare", "-Urm", "--", "bash", "-c",
        'mount --bind "$1" /usr/bin/ssh && shift && exec "$@"',
        "noop", fake_ssh,
        str(tmp_copy / "scripts/owrt-change.sh"), "apply",
        "root@lab-r1", sid, "90",
    ]
    res_apply = subprocess.run(
        unshare_cmd,
        env=mut_env, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=300, stdin=subprocess.DEVNULL,
    )
    assert res_apply.returncode != 0, res_apply.stdout
    assert "staged diff changed since plan" in res_apply.stdout, res_apply.stdout
    # Nothing applied: session still staged
    assert (e2e.router.root / "tmp/owrt-safe-apply.lock" / f"{sid}.txn" / "sealed").exists()


def test_d_full_happy_flow_plan_apply_confirms(e2e):
    """Plan, then apply (T=60): the audit log has STAGED, OPERATOR, DIFF
    lines (masked), APPLIED, CONFIRMED with the probe count; the final
    fake-root config bytes equal the staged result; the guard is idle;
    ``status`` prints ``confirmed ...``."""
    _prep_plannable(e2e)
    # Make the guard's arm check happy (free space) and confirm works
    e2e.ready_for_arm()
    # Make logd-pid return a real pid (the apply checks logd before/after)
    e2e.router.set_fake("pidof", out="411\n")

    changes = e2e.root / "changes.uci"
    changes.write_text("set dhcp.cfg01.domain=lan\n")

    res_plan = e2e.run_plan(changes=changes, timeout=60)
    assert res_plan.returncode == 0, (res_plan.returncode, res_plan.stdout)
    meta, _ = _parse_plan_stdout(res_plan.stdout)
    sid = _sid_from_staged(meta["STAGED"])

    res_apply = e2e.run_apply(sid, timeout=60)
    assert res_apply.returncode == 0, (res_apply.returncode, res_apply.stdout, "---AUDIT---\n" + e2e.audit.read_text())
    # ``status`` prints ``confirmed``
    res_status = e2e.run_status(sid)
    assert res_status.returncode == 0, (res_status.returncode, res_status.stdout)
    # the status reply is one line; ``oneline`` strips control chars but
    # the handshake line precedes it. Look for the ``confirmed `` token.
    assert "confirmed " in res_status.stdout, res_status.stdout
    status_first_word = res_status.stdout.splitlines()[-1].split()[0]
    assert status_first_word == "confirmed", (status_first_word, res_status.stdout)

    # Audit log lines
    audit = _audit_lines(e2e)
    audit_join = "\n".join(audit)
    assert "STAGED" in audit_join, audit_join
    assert "OPERATOR" in audit_join, audit_join
    assert "DIFF session=" in audit_join, audit_join
    assert "APPLIED" in audit_join, audit_join
    assert "CONFIRMED" in audit_join and "0 probes" in audit_join, audit_join

    # The final fake-root config bytes are the staged POST bytes
    snap = e2e.snap_cfg()
    assert snap["dhcp"] == POST_DHCP, snap

    # The guard is idle (the program and helper cleaned up after confirm)
    guard_status = subprocess.run(
        [BUSYBOX, "sh", str(e2e.router.root / "usr/libexec/newton-guard"),
         "status"],
        env={"PATH": "/usr/bin:/bin",
             "NEWTON_GUARD_ROOT": str(e2e.router.root),
             "NEWTON_ROUTER_ROOT": str(e2e.router.root),
             "LC_ALL": "C"},
        capture_output=True, timeout=10, text=True,
    )
    assert guard_status.stdout.strip().startswith("idle"), guard_status.stdout


def test_e_failing_probe_rolls_back(e2e):
    """A sealed passing probe and a sealed failing probe (fail): the
    failing one prevents confirm, the router (rpcd tick / guard) rolls
    back, the host ends with ``ROLLBACK WINDOW PASSED ... rolled back
    by ...``; config bytes equal the original; the guard is idle after
    the host's abort."""
    _prep_plannable(e2e)
    e2e.ready_for_arm()
    e2e.router.set_fake("pidof", out="411\n")

    probes = e2e.root / "probes.txt"
    # ping 127.0.0.1 1: the fake ping from /etc/config check (no override)
    # exits 0; fail always fails.
    probes.write_bytes(b"ping\t127.0.0.1\t1\nfail\n")

    changes = e2e.root / "changes.uci"
    changes.write_text("set dhcp.cfg01.domain=lan\n")

    res_plan = e2e.run_plan(changes=changes, timeout=60, probes=probes)
    assert res_plan.returncode == 0, (res_plan.returncode, res_plan.stdout)
    meta, _ = _parse_plan_stdout(res_plan.stdout)
    sid = _sid_from_staged(meta["STAGED"])

    res_apply = e2e.run_apply(sid, timeout=60)
    # apply exits 1 (the host script dies with the ROLLBACK line and exit 1)
    assert res_apply.returncode != 0, res_apply.stdout
    assert "ROLLBACK WINDOW PASSED" in res_apply.stdout, res_apply.stdout
    assert "rolled back by" in res_apply.stdout, res_apply.stdout
    status_first_word = res_apply.stdout.splitlines()[-1].split()[-1]
    # The last audit line has 'rolled back by rpcd' or 'rolled back by the guard'
    assert any("rolled back by" in line for line in res_apply.stdout.splitlines()), res_apply.stdout

    # Final config bytes equal the ORIGINAL
    snap = e2e.snap_cfg()
    assert snap["dhcp"] == ORIGINAL_DHCP, snap

    # Guard is restored <sid> abort after the host's failure branch
    # (design 6.7 row 2: the guard restored and the host's `abort` does
    # the no-op copy/reload). Either the guard stays restored or, if the
    # guard had already reverted before the abort, the guard becomes
    # idle. Both are valid outcomes of the failure branch.
    guard_status = subprocess.run(
        [BUSYBOX, "sh", str(e2e.router.root / "usr/libexec/newton-guard"),
         "status"],
        env={"PATH": "/usr/bin:/bin",
             "NEWTON_GUARD_ROOT": str(e2e.router.root),
             "NEWTON_ROUTER_ROOT": str(e2e.router.root),
             "LC_ALL": "C"},
        capture_output=True, timeout=10, text=True,
    )
    guard_line = guard_status.stdout.strip()
    assert guard_line.startswith("idle") or guard_line.startswith(
        f"restored {sid}"), guard_line


def test_f_approval_positive_and_negative(e2e):
    """APPROVAL positive: a leash batch (e.g. a dropbear option) planned on
    a lab profile router says ``APPROVAL required`` and a PLANDIGEST; the
    router's approve.key is written in the fake root as the 64-hex K
    from approve.derive_k(<made-up passphrase bytes>, <device name>);
    the token is minted by the HOST function approve.approval_token(K,
    digest, NBF, EXP) (import it from mcp/newton_mcp/approve.py; NO
    second implementation in the test); OWRT_APPROVAL_TOKEN=<token>
    with OWRT_APPROVAL_NBF/OWRT_APPROVAL_EXP = the window it was minted
    over (SW2 Item 2); apply confirms.

    NEGATIVE: the same plan with the token for a different digest, with
    a flipped last hex digit, with the token over a MOVED window (what an
    edited expires_at looks like at the device) and with the token
    ``none`` is refused by the REAL program: the host script dies with
    ``apply refused, nothing applied:`` and the program's reason
    (bad-approval / needs-approval), the session stays staged, nothing
    applied, config bytes unchanged, then ``abort`` cleans up.
    """
    import importlib as _il
    sys.path.insert(0, str(REPO / "mcp"))
    import newton_mcp  # noqa: F401  - register the package
    mcp_approve = _il.import_module("newton_mcp.approve")

    # Use a made-up passphrase and derive K; write K into the fake root
    # as the router's approve.key. The router reads that key in
    # ``approval_key_value`` and signs the token in ``check_approval``.
    passphrase = b"e2e-test-passphrase-bytes-do-not-reuse"
    device = "lab-r1"
    k_hex = mcp_approve.derive_k(passphrase, device)
    e2e.router.write("etc/newton/approve.key", k_hex + "\n")
    # SW2 Item 2: the token binds the approval window, and the router
    # checks it against the fake clock ($R/control/date.out), so the
    # window is built around that clock, not the host's.
    nbf, exp = e2e.router.window()

    # A dropbear option triggers a leash code (dropbear is a leash
    # code per design 5.2); the seal marks the plan APPROVAL required.
    _prep_plannable(e2e)
    e2e.ready_for_arm()
    e2e.router.set_fake("pidof", out="411\n")

    changes = e2e.root / "changes.uci"
    # dropbear.@dropbear[0].PasswordAuth='on' is a leash code
    changes.write_text(
        "set dropbear.@dropbear[0].PasswordAuth='on'\n")

    res_plan = e2e.run_plan(changes=changes, timeout=60)
    assert res_plan.returncode == 0, (res_plan.returncode, res_plan.stdout)
    meta, _ = _parse_plan_stdout(res_plan.stdout)
    sid = _sid_from_staged(meta["STAGED"])
    assert meta["APPROVAL"] == "required", (meta["APPROVAL"], res_plan.stdout)
    digest = meta["PLANDIGEST"]
    assert re.fullmatch(r"[0-9a-f]{64}", digest), digest

    # Mint the token using the imported host function — no second impl.
    token = mcp_approve.approval_token(k_hex, digest, nbf, exp)
    assert re.fullmatch(r"[0-9a-f]{64}", token), token

    # 1) POSITIVE: the correct token confirms the change.
    pos_env = e2e.env.copy()
    pos_env["OWRT_APPROVAL_TOKEN"] = token
    pos_env["OWRT_APPROVAL_NBF"] = str(nbf)
    pos_env["OWRT_APPROVAL_EXP"] = str(exp)
    res_apply = e2e.run_apply(sid, timeout=60, extra_env=pos_env)
    assert res_apply.returncode == 0, (res_apply.returncode, res_apply.stdout)
    res_status = e2e.run_status(sid)
    assert "confirmed " in res_status.stdout, res_status.stdout

    # Helper: plan a fresh approval-required change for the negative
    # cases; the previous confirm removed the txn.
    def _plan_again():
        res = e2e.run_plan(changes=changes, timeout=60)
        assert res.returncode == 0, (res.returncode, res.stdout)
        m2, _ = _parse_plan_stdout(res.stdout)
        sid2 = _sid_from_staged(m2["STAGED"])
        assert m2["APPROVAL"] == "required", m2
        return sid2, m2["PLANDIGEST"]

    # 2) NEGATIVE: token for a different digest.
    sid_n, digest_n = _plan_again()
    wrong_digest = "0" * 64
    wrong_token_for_digest = mcp_approve.approval_token(
        k_hex, wrong_digest, nbf, exp
    )
    bad_env = e2e.env.copy()
    bad_env["OWRT_APPROVAL_TOKEN"] = wrong_token_for_digest
    bad_env["OWRT_APPROVAL_NBF"] = str(nbf)
    bad_env["OWRT_APPROVAL_EXP"] = str(exp)
    res_neg = e2e.run_apply(sid_n, timeout=60, extra_env=bad_env)
    assert res_neg.returncode != 0, res_neg.stdout
    assert "apply refused, nothing applied:" in res_neg.stdout, res_neg.stdout
    assert "bad-approval" in res_neg.stdout, res_neg.stdout
    # Session still staged, config unchanged
    txn = e2e.router.root / "tmp/owrt-safe-apply.lock" / f"{sid_n}.txn"
    assert (txn / "sealed").exists()
    # Dropbear may not exist in the fake root; record the snapshot once
    # and re-check on subsequent negative cases.
    pre_neg_snap = e2e.snap_cfg()
    # Abort cleans up
    res_abort = e2e.run_abort(sid_n)
    assert res_abort.returncode == 0, res_abort.stdout

    # 3) NEGATIVE: same token with a flipped last hex digit.
    sid_f, _ = _plan_again()
    flipped = token[:-1] + ("0" if token[-1] != "0" else "1")
    assert flipped != token
    flip_env = e2e.env.copy()
    flip_env["OWRT_APPROVAL_TOKEN"] = flipped
    flip_env["OWRT_APPROVAL_NBF"] = str(nbf)
    flip_env["OWRT_APPROVAL_EXP"] = str(exp)
    res_flip = e2e.run_apply(sid_f, timeout=60, extra_env=flip_env)
    assert res_flip.returncode != 0, res_flip.stdout
    assert "apply refused, nothing applied:" in res_flip.stdout, res_flip.stdout
    assert "bad-approval" in res_flip.stdout, res_flip.stdout
    e2e.run_abort(sid_f)

    # 3b) NEGATIVE: the same token with a MOVED
    # window.  This is what an edited expires_at in the approval file
    # looks like once the host passes the edited value on: the router
    # recomputes the HMAC over what it was told and the token no longer
    # matches.  The window is SHORTENED here (still inside the router's
    # own rules, so it reaches the HMAC compare; a window stretched past
    # an hour is refused earlier as approval-window instead).
    sid_w, _ = _plan_again()
    moved_exp = exp - 300
    win_env = e2e.env.copy()
    win_env["OWRT_APPROVAL_TOKEN"] = token
    win_env["OWRT_APPROVAL_NBF"] = str(nbf)
    win_env["OWRT_APPROVAL_EXP"] = str(moved_exp)
    res_win = e2e.run_apply(sid_w, timeout=60, extra_env=win_env)
    assert res_win.returncode != 0, res_win.stdout
    assert "apply refused, nothing applied:" in res_win.stdout, res_win.stdout
    assert "bad-approval" in res_win.stdout, res_win.stdout
    e2e.run_abort(sid_w)

    # 4) NEGATIVE: token ``none``.
    sid_t, _ = _plan_again()
    none_env = e2e.env.copy()
    none_env["OWRT_APPROVAL_TOKEN"] = "none"
    res_t = e2e.run_apply(sid_t, timeout=60, extra_env=none_env)
    assert res_t.returncode != 0, res_t.stdout
    assert "apply refused, nothing applied:" in res_t.stdout, res_t.stdout
    assert "needs-approval" in res_t.stdout, res_t.stdout
    e2e.run_abort(sid_t)


def test_g_host_refusals_in_front_of_real_program(e2e):
    """Host refusals in front of a real program: a hello with the wrong
    prog sha (replace the fake root's program copy by a modified one),
    a wrong device-id, a wrong profile, ``mode=test`` NOT rewritten, a
    busy router (another caller's open transaction) at plan: each dies
    with the one-line text and nothing is staged / applied."""
    changes = e2e.root / "changes.uci"
    changes.write_text("set dhcp.cfg01.domain=lan\n")

    # 1. WRONG PROG SHA: replace the installed program with a modified copy
    fake_root = e2e.router.root
    src_prog = fake_root / "usr/libexec/newton/newton-router"
    backup_prog = e2e.root / "prog.bak"
    backup_prog.write_bytes(src_prog.read_bytes())
    src_prog.write_bytes(src_prog.read_bytes() + b"\n# modified\n")
    src_prog.chmod(0o755)
    res = e2e.run_plan(changes=changes, timeout=60)
    assert res.returncode != 0, res.stdout
    assert "differs from this controller's" in res.stdout, res.stdout
    assert not (fake_root / "tmp/owrt-safe-apply.lock" / f"{SID}.txn").exists()
    # restore
    src_prog.write_bytes(backup_prog.read_bytes())
    src_prog.chmod(0o755)

    # 2. WRONG DEVICE-ID: OWRT_EXPECT_DEVICE points at a name the
    # hello reply does not have.
    _prep_plannable(e2e)
    wrong_dev_env = e2e.env.copy()
    wrong_dev_env["OWRT_EXPECT_DEVICE"] = "other-router"
    res = e2e.run_plan(changes=changes, timeout=60, extra_env=wrong_dev_env)
    assert res.returncode != 0, res.stdout
    assert "is not the expected other-router" in res.stdout, res.stdout
    assert not (fake_root / "tmp/owrt-safe-apply.lock" / f"{SID}.txn").exists()

    # 3. WRONG PROFILE: OWRT_EXPECT_PROFILE=prod but the router says lab
    wrong_prof_env = e2e.env.copy()
    wrong_prof_env["OWRT_EXPECT_PROFILE"] = "prod"
    res = e2e.run_plan(changes=changes, timeout=60, extra_env=wrong_prof_env)
    assert res.returncode != 0, res.stdout
    assert "is not the expected prod" in res.stdout, res.stdout
    assert not (fake_root / "tmp/owrt-safe-apply.lock" / f"{SID}.txn").exists()

    # 4. mode=test NOT rewritten: the fake ssh ignores the
    # mode=test -> mode=prod rewrite. The host script's handshake dies
    # with the exact text it logs for any non-prod router.
    no_rewrite_env = e2e.env.copy()
    no_rewrite_env["FAKE_SSH_CONNECT_FLAG"] = "/nonexistent-marker"
    # flip a switch: rewrite the fake ssh body to skip the rewrite.
    ssh = Path(e2e.env["PATH"].split(os.pathsep)[0]) / "ssh"
    real_body = ssh.read_text()
    ssh.write_text(real_body.replace(
        'if cmd.startswith("/usr/libexec/newton/newton-router hello "):',
        'if False and cmd.startswith("/usr/libexec/newton/newton-router hello "):',
    ))
    try:
        res = e2e.run_plan(changes=changes, timeout=60, extra_env=no_rewrite_env)
    finally:
        ssh.write_text(real_body)
    assert res.returncode != 0, res.stdout
    assert "mode=test" in res.stdout or "runs in mode=test" in res.stdout, res.stdout
    assert not (fake_root / "tmp/owrt-safe-apply.lock" / f"{SID}.txn").exists()

    # 5. BUSY ROUTER (another caller's open transaction) at plan.
    # Stage a transaction with a DIFFERENT caller so the plan's busy
    # gate refuses with ``error busy ...``.
    other_caller = "other-caller"
    other_sid = "fedcba9876543210fedcba9876543210"
    other_sessions = fake_root / "control/sessions"
    other_sessions.write_text(other_sid + "\n")
    txn = fake_root / "tmp/owrt-safe-apply.lock" / f"{other_sid}.txn"
    txn.mkdir(parents=True, exist_ok=True)
    (txn / "owner").write_text(other_caller + "\n")
    (txn / "stage-up").write_text("100\n")
    (txn / "boot").write_text("boot-one\n")
    (fake_root / "tmp/owrt-safe-apply.lock" / "sid").write_text(other_sid + "\n")

    _prep_plannable(e2e)
    res = e2e.run_plan(changes=changes, timeout=60)
    assert res.returncode != 0, res.stdout
    assert "router busy with another change" in res.stdout, res.stdout
    assert not (fake_root / "tmp/owrt-safe-apply.lock" / f"{SID}.txn").exists()


def test_h_seal_refusal_for_real_bad_probe_name(e2e):
    """Seal refusal for real: a probes file the program refuses (unknown
    probe name) makes plan die with ``probes refused: ... bad-probe 1
    unknown-probe`` and the stage is aborted (no transaction left in
    the fake root)."""
    _prep_plannable(e2e)
    probes = e2e.root / "probes.txt"
    probes.write_bytes(b"unknown-probe\n")

    changes = e2e.root / "changes.uci"
    changes.write_text("set dhcp.cfg01.domain=lan\n")

    res = e2e.run_plan(changes=changes, timeout=60, probes=probes)
    assert res.returncode != 0, res.stdout
    assert "probes refused:" in res.stdout, res.stdout
    assert "bad-probe 1 unknown-probe" in res.stdout, res.stdout
    # The seal failure aborts the stage: no live txn
    assert not (e2e.router.root / "tmp/owrt-safe-apply.lock" / f"{SID}.txn").exists()


def test_i_failure_branch_for_real_confirm_too_late(e2e):
    """The failure branch for real: confirm refused too late (set the
    fake clock past the rpcd deadline with the harness's uptime helper)
    -> the host enters the failure branch, retries status, aborts
    first, ends with the ``ROLLBACK WINDOW PASSED`` line naming the
    cause."""
    _prep_plannable(e2e)
    e2e.ready_for_arm()
    e2e.router.set_fake("pidof", out="411\n")

    changes = e2e.root / "changes.uci"
    changes.write_text("set dhcp.cfg01.domain=lan\n")

    res_plan = e2e.run_plan(changes=changes, timeout=60)
    assert res_plan.returncode == 0, (res_plan.returncode, res_plan.stdout)
    meta, _ = _parse_plan_stdout(res_plan.stdout)
    sid = _sid_from_staged(meta["STAGED"])

    # Move the fake clock past the rpcd deadline (T=60 -> deadline=160)
    # and make ping fail so verify fails (so the host waits the whole
    # window).
    e2e.router.set_uptime(200)
    e2e.router.set_fake("ping", rc=1)
    res_apply = e2e.run_apply(sid, timeout=60)
    assert res_apply.returncode != 0, res_apply.stdout
    assert "ROLLBACK WINDOW PASSED" in res_apply.stdout, res_apply.stdout
    # the cause is named on the last line
    last_audit = [
        line for line in res_apply.stdout.splitlines()
        if "ROLLED BACK" in line or "rolled back by" in line
        or "ROLLBACK WINDOW" in line
    ]
    assert last_audit, res_apply.stdout
    # The host entered the failure branch: it issued a status, an abort,
    # then a confighash/health-check round (one of the named causes).
    assert "rolled back by" in res_apply.stdout, res_apply.stdout

# ----- the agent's expect claims are sealed probes -----------------------------
#
# The claims go through the same sealed probe file as Newton's own probes (the
# last lines of it); the REAL router program verifies them from a fresh
# session.  The host's failed_claim() reads the real relayed verify line.

def _ex4_plan_apply(e2e, probe_lines: bytes):
    _prep_plannable(e2e)
    e2e.ready_for_arm()
    e2e.router.set_fake("pidof", out="411\n")
    probes = e2e.root / "probes.txt"
    probes.write_bytes(probe_lines)
    changes = e2e.root / "changes.uci"
    changes.write_text("set dhcp.cfg01.domain=lan\n")
    res_plan = e2e.run_plan(changes=changes, timeout=60, probes=probes)
    assert res_plan.returncode == 0, (res_plan.returncode, res_plan.stdout)
    meta, _ = _parse_plan_stdout(res_plan.stdout)
    sid = _sid_from_staged(meta["STAGED"])
    return sid, e2e.run_apply(sid, timeout=60)


def test_a_true_claim_probe_confirms(e2e):
    sid, res = _ex4_plan_apply(e2e, b"ping\t127.0.0.1\t1\nuci-equals\tdhcp.cfg01.domainneeded\t1\n")
    assert res.returncode == 0, (res.returncode, res.stdout)
    assert "CONFIRMED" in res.stdout and "2 probes" in res.stdout, res.stdout


def test_a_false_claim_probe_rolls_back_and_the_host_names_the_claim(e2e):
    sid, res = _ex4_plan_apply(e2e, b"ping\t127.0.0.1\t1\nuci-equals\tdhcp.cfg01.domainneeded\t0\n")
    assert res.returncode != 0, res.stdout
    assert "CONFIRMED" not in res.stdout
    assert "ROLLBACK WINDOW PASSED" in res.stdout, res.stdout
    assert e2e.snap_cfg()["dhcp"] == ORIGINAL_DHCP
    import importlib as _il

    ex = _il.import_module("newton_mcp.explanation")
    expect = [{"kind": "uci_equals", "path": "dhcp.cfg01.domainneeded", "equals": "0"}]
    probes = [["ping", "127.0.0.1", "1"], ["uci-equals", "dhcp.cfg01.domainneeded", "0"]]
    found = ex.failed_claim(res.stdout, sid, probes, expect)
    assert found == {
        "claim": 1,
        "text": "expect claim 1 failed: uci dhcp.cfg01.domainneeded != 0 (mismatch)",
    }, res.stdout


def test_a_failing_newton_probe_before_a_true_claim_names_no_claim(e2e):
    sid, res = _ex4_plan_apply(e2e, b"fail\nuci-equals\tdhcp.cfg01.domainneeded\t1\n")
    assert res.returncode != 0 and "ROLLBACK WINDOW PASSED" in res.stdout, res.stdout
    import importlib as _il

    ex = _il.import_module("newton_mcp.explanation")
    expect = [{"kind": "uci_equals", "path": "dhcp.cfg01.domainneeded", "equals": "1"}]
    probes = [["fail"], ["uci-equals", "dhcp.cfg01.domainneeded", "1"]]
    assert ex.failed_claim(res.stdout, sid, probes, expect) is None


# the reason word of a failing claim, as the REAL router program prints it
# (count=N, unset, present are not "mismatch"); the host must still name the claim.
@pytest.mark.parametrize(
    "line, claim, reason, words",
    [
        (
            b"uci-equals\tdhcp.cfg01.nosuchoption\t1\n",
            {"kind": "uci_equals", "path": "dhcp.cfg01.nosuchoption", "equals": "1"},
            "unset",
            "is unset",
        ),
        (
            b"uci-unset\tdhcp.cfg01.domainneeded\n",
            {"kind": "probe", "probe": ["uci-unset", "dhcp.cfg01.domainneeded"]},
            "present",
            "found present",
        ),
        (
            b"listen\ttcp\twildcard\t22\tdropbear\tpresent\n",
            {"kind": "probe", "probe": ["listen", "tcp", "wildcard", "22", "dropbear", "present"]},
            "count=0",
            "matched 0 times",
        ),
    ],
    ids=["unset", "present", "count"],
)
def test_each_failure_reason_the_router_prints_names_the_claim(e2e, line, claim, reason, words):
    sid, res = _ex4_plan_apply(e2e, b"ping\t127.0.0.1\t1\n" + line)
    assert res.returncode != 0 and "ROLLBACK WINDOW PASSED" in res.stdout, res.stdout
    assert f"failed: {line.split(b'\t')[0].decode()} {reason}" in res.stdout, res.stdout
    import importlib as _il

    ex = _il.import_module("newton_mcp.explanation")
    probes = [["ping", "127.0.0.1", "1"], [x.decode() for x in line.rstrip(b"\n").split(b"\t")]]
    found = ex.failed_claim(res.stdout, sid, probes, [claim])
    assert found is not None and found["claim"] == 1, res.stdout
    assert words in found["text"] and f"({reason})" in found["text"], found
