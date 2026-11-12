import hashlib
import hmac
import os
import re
import shutil
import subprocess
import types
from collections import namedtuple
from pathlib import Path

import pytest


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
PROGRAM = Path(
    os.environ.get("NEWTON_ROUTER_PROGRAM")
    or REPO / "device/openwrt/newton-router/newton-router"
)
HELPER = REPO / "scripts/owrt-safe-apply.sh"
GUARD = REPO / "device/openwrt/newton-guard/newton-guard"
BUSYBOX = "/usr/bin/busybox"
SID = "0123456789abcdef0123456789abcdef"
INSTALL_PATH = "/usr/libexec/newton/newton-router"
VALID_NAME = re.compile(r"[A-Za-z0-9_-]+")

CONFIG = {
    "system": (b"config system\n\toption hostname 'newton-test'\n", 0o644),
    "network": (b"config interface 'lan'\n\toption proto 'static'\n", 0o600),
    "firewall": (b"config defaults\n\toption input 'REJECT'\n", 0o600),
    "dhcp": (b"config dnsmasq\n\toption domainneeded '1'\n", 0o644),
    "wireless": (b"config wifi-device 'radio0'\n\toption channel 'auto'\n", 0o600),
}

FAKE_TOOLS = (
    "uci ubus jsonfilter nft fw4 ifstatus netstat pidof ping nslookup "
    "traceroute logread logger iwinfo ip apk wifi df free uptime uname "
    "date tar flock sleep utpl"
).split()

# Calls the tool-allowlist trace test runs under `busybox sh -x` (design 9.2
# group 1). Later rounds extend this list as more subcommands are built.
# Each entry: (mode, argv-or-request, role).
TRACE_CALLS = [
    ("direct", ("hello", "0123456789abcdef"), "read"),
    ("direct", ("hostname",), "read"),
    ("direct", ("fw-loaded",), "read"),
    ("direct", ("logd-pid",), "read"),
    ("direct", ("backup",), "change"),
    ("forced", "hostname 'x", "change"),  # refused: bad-character
    ("forced", "hello nothex", "read"),  # refused: bad-arg
    ("direct", ("fwrestart", "7"), "change"),  # refused: bad-arg
]

Result = namedtuple("Result", "rc out err outb errb")

SYSLOG_PREFIX = "logger -t newton-router -p daemon.info "


def _executable(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0o755)


def _install_code(source, dest):
    """Copy a code file with its first line replaced for direct BusyBox exec."""
    body = Path(source).read_text().split("\n", 1)[1]
    _executable(dest, "#!/usr/bin/busybox sh\n" + body)


class Router:
    """The fake router root plus helpers to run the program against it."""

    def __init__(self, root):
        self.root = Path(root)
        self.canary = self.root / "canary"
        self.program = PROGRAM
        self._build()

    # ---- fake root -----------------------------------------------------
    def _build(self):
        root = self.root
        cfg = root / "etc/config"
        cfg.mkdir(parents=True)
        for name, (data, mode) in CONFIG.items():
            path = cfg / name
            path.write_bytes(data)
            path.chmod(mode)
        (root / "proc/sys/kernel/random").mkdir(parents=True)
        (root / "proc/uptime").write_text("100.00 90.00\n")
        (root / "proc/sys/kernel/random/boot_id").write_text("boot-one\n")
        (root / "tmp").mkdir()
        (root / "control").mkdir()
        (root / "control/avail").write_text("999999\n")
        # Preserve the old generic ubus fake's default that the fixture SID
        # is live; tests can empty sessions or set ubus.rc to make it gone.
        (root / "control/sessions").write_text(SID + "\n")
        newton = root / "etc/newton"
        newton.mkdir(parents=True)
        (newton / "device-id").write_text("lab-r1\n")
        (newton / "profile").write_text("lab\n")
        (newton / "approve.key").write_text("0123456789abcdef" * 4 + "\n")
        _install_code(PROGRAM, root / INSTALL_PATH.lstrip("/"))
        _install_code(HELPER, root / "usr/libexec/newton/newton-safe-apply")
        _install_code(GUARD, root / "usr/libexec/newton-guard")
        _executable(
            root / "etc/init.d/newton-guard",
            '#!/bin/sh\necho "$*" >> "$NEWTON_GUARD_ROOT/control/init.calls"\n'
            'if [ "$1" = enabled ] && [ -f "$NEWTON_GUARD_ROOT/control/disabled" ];'
            " then exit 1; fi\n"
            'if [ "${1:-} ${2:-}" = "running timer" ] &&'
            ' [ -f "$NEWTON_GUARD_ROOT/control/not-running" ]; then exit 1; fi\n'
            "exit 0\n",
        )
        _executable(
            root / "sbin/reload_config",
            '#!/bin/sh\necho reload >> "$NEWTON_GUARD_ROOT/control/reload.calls"\n'
            '[ ! -f "$NEWTON_GUARD_ROOT/control/reload-fails" ]\n',
        )
        _executable(
            root / "usr/bin/logger",
            '#!/bin/sh\necho "$*" >> "$NEWTON_GUARD_ROOT/control/logger.calls"\n',
        )
        binroot = root / "bin"
        binroot.mkdir(parents=True)
        for name in FAKE_TOOLS:
            if name in ("jsonfilter", "ubus", "utpl"):
                (binroot / name).symlink_to(HERE / f"fakes/{name}")
            elif name == "tar":
                (binroot / name).symlink_to(HERE / "fakes/tar")
            elif name in ("flock", "sleep"):
                (binroot / name).symlink_to(f"/usr/bin/{name}")
            else:
                (binroot / name).symlink_to(HERE / "fakes/generic")
        # Default `now` for tests that need a valid approval window.
        # The fake `date` reads this file when called as `date +%s`.
        (root / "control/date.out").write_text("1700000000\n")
        # The guard on the main branch calls these through $R/bin; the
        # guard this branch is based on does not use them.
        for name in ("cp", "mv", "sync", "rm", "mktemp"):
            (binroot / name).symlink_to(f"/usr/bin/{name}")

    # ---- running the program -------------------------------------------
    def _base_env(self):
        return {
            "PATH": "/usr/bin:/bin",
            "NEWTON_ROUTER_ROOT": str(self.root),
            "LC_ALL": "C",
        }

    def _run(self, argv, stdin, env, timeout, cwd, xtrace):
        full = dict(self._base_env())
        for key, value in (env or {}).items():
            if value is None:
                full.pop(key, None)
            else:
                full[key] = value
        sh_argv = [BUSYBOX, "sh"]
        if xtrace:
            sh_argv.append("-x")
        proc = subprocess.run(
            sh_argv + [str(self.program)] + [str(a) for a in argv],
            input=stdin or b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=full,
            timeout=timeout,
            start_new_session=True,
            cwd=str(cwd) if cwd else None,
        )
        return Result(
            proc.returncode,
            proc.stdout.decode("utf-8", "replace"),
            proc.stderr.decode("utf-8", "replace"),
            proc.stdout,
            proc.stderr,
        )

    def forced(
        self,
        request,
        *,
        role="change",
        caller="agent-one",
        stdin=b"",
        env=None,
        timeout=30,
        xtrace=False,
        cwd=None,
    ):
        extra = dict(env or {})
        extra["SSH_ORIGINAL_COMMAND"] = request
        return self._run(
            [f"--caller={caller}", f"--role={role}"],
            stdin,
            extra,
            timeout,
            cwd,
            xtrace,
        )

    def direct(self, *argv, stdin=b"", env=None, timeout=30, cwd=None, xtrace=False):
        return self._run(list(argv), stdin, env, timeout, cwd, xtrace)

    def probe(self, *fields, role="change", stdin=None, cwd=None, timeout=30):
        """One probe line (fields joined by TAB, LF at the end) to the probe
        subcommand in forced mode (design 3.5d)."""
        if stdin is None:
            stdin = ("\t".join(str(f) for f in fields) + "\n").encode()
        return self.forced("probe", role=role, stdin=stdin, cwd=cwd, timeout=timeout)

    def use_stub_helper(self):
        """Wrap the real helper, stubbing only stage and diff."""
        helper = self.root / "usr/libexec/newton/newton-safe-apply"
        real = helper.with_name("newton-safe-apply.real")
        if not real.exists():
            helper.replace(real)
        _executable(
            helper,
            "#!/usr/bin/busybox sh\n"
            'root="$NEWTON_ROUTER_ROOT"\n'
            'echo "helper $*" >> "$root/control/calls.log"\n'
            'case "${1:-}" in\n'
            "stage)\n"
            '  cat > "$root/control/stage-stdin"\n'
            '  if [ -f "$root/control/stage.rc" ]; then\n'
            '    [ ! -f "$root/control/stage.err" ] || cat "$root/control/stage.err" >&2\n'
            '    read -r rc < "$root/control/stage.rc"; exit "$rc"\n'
            "  fi\n"
            '  mkdir -p "$NEWTON_LOCK"\n'
            '  read -r sid < "$root/control/next-sid"\n'
            '  printf "%s\\n" "$sid" > "$NEWTON_LOCK/sid"\n'
            '  printf "%s\\n" "$sid" >> "$root/control/sessions"\n'
            # the helper records the folder rpcd keeps the session's changes
            # in (rpcd d99f703); the stub records the old one
            '  printf "/var/run/rpcd/uci-%s\\n" "$sid" > "$NEWTON_LOCK/$sid.dir"\n'
            '  [ ! -f "$root/control/stage-extra-line" ] || cat "$root/control/stage-extra-line"\n'
            '  printf "%s\\n" "$sid"\n'
            '  [ ! -f "$root/control/stage-trailing-line" ] || cat "$root/control/stage-trailing-line"\n'
            "  ;;\n"
            "diff)\n"
            '  if [ -f "$root/control/diff.rc" ]; then\n'
            '    read -r rc < "$root/control/diff.rc"; exit "$rc"\n'
            "  fi\n"
            '  cat "$root/control/diff.txt"\n'
            "  ;;\n"
            "*)\n"
            f'  exec {BUSYBOX} sh "{real}" "$@"\n'
            "  ;;\n"
            "esac\n",
        )

    def stage(self, batch=b"set dhcp.cfg01.domain=lan\n", caller="agent-one", sid=SID,
              role="change"):
        self.write("control/next-sid", sid + "\n")
        return self.forced("stage", caller=caller, role=role, stdin=batch, timeout=40)

    def seal(self, sid, t, probes=b"", caller="agent-one", role="change"):
        return self.forced(
            f"seal {sid} {t}", caller=caller, role=role, stdin=probes, timeout=40
        )

    def txn(self, sid=SID):
        return self.root / "tmp/owrt-safe-apply.lock" / f"{sid}.txn"

    def confighash_text(self):
        # The program's rule: only names the guard's valid_name accepts
        # (^[A-Za-z0-9_-]+$) are hashed; every other name is skipped.
        lines = []
        for path in sorted((self.root / "etc/config").iterdir(), key=lambda p: p.name):
            if (
                path.is_file()
                and not path.is_symlink()
                and VALID_NAME.fullmatch(path.name)
            ):
                digest = hashlib.md5(path.read_bytes()).hexdigest()
                lines.append(f"{digest} {path.name}\n")
        return "".join(lines)

    def forced_open_stdin_start(
        self, request, *, role="change", caller="agent-one", prefix=b""
    ):
        """Start a forced run whose stdin pipe never closes; returns
        (proc, finish) where finish(timeout) waits and returns the Result."""
        read_fd, write_fd = os.pipe()
        proc = subprocess.Popen(
            [BUSYBOX, "sh", str(self.program), f"--caller={caller}", f"--role={role}"],
            stdin=read_fd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._merged_env({"SSH_ORIGINAL_COMMAND": request}),
            start_new_session=True,
        )
        os.close(read_fd)
        sent = 0
        while sent < len(prefix):
            sent += os.write(write_fd, prefix[sent:])

        def finish(timeout=40):
            try:
                out, err = proc.communicate(timeout=timeout)
            finally:
                os.close(write_fd)
            return Result(
                proc.returncode,
                out.decode("utf-8", "replace"),
                err.decode("utf-8", "replace"),
                out,
                err,
            )

        return proc, finish

    def _merged_env(self, env):
        full = dict(self._base_env())
        for key, value in (env or {}).items():
            if value is None:
                full.pop(key, None)
            else:
                full[key] = value
        return full

    def direct_pty(self, *argv, env=None, timeout=15):
        """Direct run whose stdin is a pty (so `[ -t 0 ]` is true)."""
        import pty

        master, slave = pty.openpty()
        proc = subprocess.Popen(
            [BUSYBOX, "sh", str(self.program)] + [str(a) for a in argv],
            stdin=slave,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._merged_env(env),
            start_new_session=True,
        )
        os.close(slave)
        try:
            out, err = proc.communicate(timeout=timeout)
        finally:
            os.close(master)
        return Result(
            proc.returncode,
            out.decode("utf-8", "replace"),
            err.decode("utf-8", "replace"),
            out,
            err,
        )

    def direct_open_stdin(self, *argv, env=None, timeout=10):
        """Direct run whose stdin is a pipe whose write end never closes."""
        read_fd, write_fd = os.pipe()
        proc = subprocess.Popen(
            [BUSYBOX, "sh", str(self.program)] + [str(a) for a in argv],
            stdin=read_fd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._merged_env(env),
            start_new_session=True,
        )
        os.close(read_fd)
        try:
            out, err = proc.communicate(timeout=timeout)
        finally:
            os.close(write_fd)
        return Result(
            proc.returncode,
            out.decode("utf-8", "replace"),
            err.decode("utf-8", "replace"),
            out,
            err,
        )

    # ---- observation and control ---------------------------------------
    def calls(self, exclude=("logger",)):
        path = self.root / "control/calls.log"
        if not path.exists():
            return []
        return [
            line
            for line in path.read_text().splitlines()
            if line.split(" ", 1)[0] not in exclude
        ]

    def syslog(self):
        return [
            line[len(SYSLOG_PREFIX):]
            for line in self.calls(exclude=())
            if line.startswith(SYSLOG_PREFIX)
        ]

    def set_fake(self, name, out=None, err=None, rc=None, sleep=None):
        if out is not None:
            self.write(f"control/{name}.out", out)
        if err is not None:
            self.write(f"control/{name}.err", err)
        if rc is not None:
            self.write(f"control/{name}.rc", f"{rc}\n")
        if sleep is not None:
            self.write(f"control/{name}.sleep", f"{sleep}\n")

    def write(self, rel, data, mode=0o644):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(data, str):
            data = data.encode()
        path.write_bytes(data)
        path.chmod(mode)

    def set_uptime(self, seconds):
        self.write("proc/uptime", f"{seconds:.2f} 90.00\n")

    def set_boot_id(self, text):
        self.write("proc/sys/kernel/random/boot_id", text + "\n")

    # ---- harness transaction helpers --------------------
    def fresh_plan(self, t=90, probes=b"", profile="lab", caller="agent-one", sid=SID):
        """Build a sealed plan the harness can act on: stub helper, diff,
        profile, a staged etc/config/dhcp that differs from the live one,
        stage, the health snapshot, seal. Asserts seal rc=0 and returns
        the digest/base/diff/probes-sha it just sealed."""
        self.use_stub_helper()
        if not (self.root / "control/diff.txt").exists():
            self.write("control/diff.txt", b"dhcp.cfg01.domain='lan'\n")
        self.write("etc/newton/profile", profile + "\n")
        live_dhcp = (self.root / "etc/config/dhcp").read_bytes()
        staged_dhcp = b"config dnsmasq\n\toption domainneeded '0'\n"
        self.write("control/staged/dhcp", staged_dhcp)
        assert staged_dhcp != live_dhcp
        self.stage(sid=sid, caller=caller)
        health = self.root / "tmp/owrt-safe-apply.lock" / f"{sid}.health"
        health.mkdir(parents=True, exist_ok=True)
        (health / "newton-fw4-loaded").write_text("0\n")
        result = self.seal(sid, t, probes, caller=caller)
        assert result.rc == 0, (result.rc, result.out, result.err)
        digest = base = diff = psha = None
        for line in result.out.splitlines():
            if line.startswith("digest "):
                digest = line[len("digest "):]
            elif line.startswith("base "):
                base = line[len("base "):]
            elif line.startswith("diff "):
                diff = line[len("diff "):]
            elif line.startswith("probes "):
                psha = line.split(" ", 2)[2]
        return types.SimpleNamespace(
            sid=sid, digest=digest, base=base, diff=diff, psha=psha,
            t=t, txn=self.txn(sid),
        )

    def token(self, digest, nbf, exp, key_hex=None):
        """The v2 approval token the program checks: hmac-sha256(key,
        'newton-approval-v2\\n<digest>\\n<nbf>\\n<exp>\\n'). The router's
        check_approval binds NBF and EXP into the HMAC, so passing the same
        (nbf, exp) at apply time is what makes the token valid."""
        if key_hex is None:
            key_hex = (self.root / "etc/newton/approve.key").read_text().split("\n", 1)[0]
        msg = f"newton-approval-v2\n{digest}\n{nbf}\n{exp}\n".encode()
        return hmac.new(bytes.fromhex(key_hex), msg, "sha256").hexdigest()

    def window(self, now=None, span=3600):
        """A (nbf, exp) approval window that contains `now`. By default,
        `now` is read from $R/control/date.out (the fake `date` source);
        if the file is missing or not a number, fall back to 1700000000."""
        if now is None:
            date_out = self.root / "control/date.out"
            if date_out.exists():
                txt = date_out.read_text().strip()
                try:
                    now = int(txt)
                except ValueError:
                    now = 1700000000
            else:
                now = 1700000000
        return now, now + span

    def apply(self, sid, t, token="none", nbf=0, exp=0, caller="agent-one", role="change"):
        return self.forced(
            f"apply {sid} {t} {token} {nbf} {exp}",
            caller=caller, role=role, timeout=60,
        )

    def guard(self, *args):
        """Invoke the real guard copy in this root. Returns a Result."""
        proc = subprocess.run(
            [BUSYBOX, "sh", str(self.root / "usr/libexec/newton-guard")] + [str(a) for a in args],
            input=b"",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                "PATH": "/usr/bin:/bin",
                "NEWTON_GUARD_ROOT": str(self.root),
                "NEWTON_ROUTER_ROOT": str(self.root),
                "LC_ALL": "C",
            },
            timeout=30,
            start_new_session=True,
        )
        return Result(
            proc.returncode,
            proc.stdout.decode("utf-8", "replace"),
            proc.stderr.decode("utf-8", "replace"),
            proc.stdout,
            proc.stderr,
        )

    def guard_status(self):
        """The first line of `newton-guard status`."""
        out = self.guard("status").out
        return out.split("\n", 1)[0] if out else ""

    def rpcd_tick(self):
        """Drive the fake ubus' --tick path (no log line)."""
        proc = subprocess.run(
            [str(self.root / "bin/ubus"), "--tick"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"NEWTON_ROUTER_ROOT": str(self.root), "PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            timeout=10,
        )
        return proc.returncode

    def use_program(self, path):
        """Run this path instead of the global PROGRAM for later _run calls."""
        self.program = Path(path)

    def scratch_program(self, tmp_path, old, new):
        """Copy the program text to tmp_path/newton-router with one occurrence
        of `old` replaced by `new` (asserts exactly one), make it executable,
        set it as the program for this router, return the path."""
        text = PROGRAM.read_text()
        count = text.count(old)
        assert count == 1, f"expected exactly one occurrence of {old!r}, found {count}"
        path = Path(tmp_path) / "newton-router"
        path.write_text(text.replace(old, new, 1))
        path.chmod(0o755)
        self.use_program(path)
        return path

    def calls_matching(self, prefix):
        path = self.root / "control/calls.log"
        if not path.exists():
            return []
        return [line for line in path.read_text().splitlines() if line.startswith(prefix)]

    # ---- leash scenario helpers --------
    def use_leash_uci(self):
        """Replace the symlink at <root>/bin/uci with the leash fake and reset its store."""
        uci = self.root / "bin/uci"
        if uci.is_symlink() or uci.exists():
            uci.unlink()
        uci.symlink_to(HERE / "fakes/uci")
        self.write("control/uci.json", b"{}")

    def use_rpcd(self, mode="new"):
        """The rpcd model: the uci fake is the session-folder fake.

        control/rpcd-mode says which rpcd is in force: "old" names the
        session's folder after the session id, "new" gives it a 32-hex
        name of its own (the rpcd change d99f703)."""
        uci = self.root / "bin/uci"
        if uci.is_symlink() or uci.exists():
            uci.unlink()
        uci.symlink_to(HERE / "fakes/uci")
        self.write("control/rpcd-mode", mode + "\n")
        self.write("control/uci.json", b"{}")

    def set_zones(self, mgmt_interface="lan", mgmt_zone="lan", wan=("wan",)):
        """Write etc/newton/zones with one mgmt-interface, one mgmt-zone, one wan-zone per entry."""
        lines = [f"mgmt-interface {mgmt_interface}\n", f"mgmt-zone {mgmt_zone}\n"]
        lines.extend(f"wan-zone {w}\n" for w in wan)
        self.write("etc/newton/zones", "".join(lines))

    def sealed_scenario(self, scn, sid=SID):
        """Build the open transaction directly and run seal; returns the seal Result.

        Writes control/uci.json from scn.build(), etc/newton/profile from scn.profile,
        etc/newton/zones from scn.zones, then creates the txn directory and the owner
        / stage-up / boot files plus the lock sid file and a control/sessions entry."""
        import json as _json

        built = scn.build()
        self.write("control/uci.json", _json.dumps(dict(
            changes=built["changes"], staged=built["staged"],
            committed=built["committed"], full_firewall=built["full_firewall"],
        )))
        self.write("etc/newton/profile", scn.profile + "\n")
        zones = scn.zones
        zl = (
            f"mgmt-interface {zones['mgmt-interface']}\n"
            f"mgmt-zone {zones['mgmt-zone']}\n"
            + "".join(f"wan-zone {w}\n" for w in zones["wan-zone"])
        )
        self.write("etc/newton/zones", zl)
        # helper diff (seal hashes this too; we mirror the staged changes line-for-line
        # so the program can build the diff sha the same way the helper would)
        diff = ("\n".join(built["changes"]) + ("\n" if built["changes"] else "")).encode()
        self.write("control/diff.txt", diff)
        lock = self.root / "tmp/owrt-safe-apply.lock"
        txn = lock / f"{sid}.txn"
        if txn.exists():
            import shutil as _shutil
            _shutil.rmtree(txn)
        txn.mkdir(parents=True)
        (txn / "owner").write_text("agent-one\n")
        (txn / "stage-up").write_text("100\n")
        (txn / "boot").write_text("boot-one\n")
        (lock / "sid").write_text(sid + "\n")
        # the helper records the folder rpcd keeps the session's changes in
        (lock / f"{sid}.dir").write_text(f"/var/run/rpcd/uci-{sid}\n")
        sessions = self.root / "control/sessions"
        existing = sessions.read_text() if sessions.exists() else ""
        if sid not in existing.split():
            sessions.write_text(existing + sid + "\n")
        return self.seal(sid, 90)


@pytest.fixture
def router(tmp_path):
    return Router(tmp_path / "router")


def pytest_configure(config):
    config.addinivalue_line("markers", "slow: takes more than about 20 s (a real 25 s or 30 s bound is waited out)")
