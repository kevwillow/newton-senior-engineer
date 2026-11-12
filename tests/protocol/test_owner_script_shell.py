"""A3 Part 2: the owner script, run for real under sh and busybox ash.

The owner approves the exact bytes of the script, so the bytes have to
work on a router.  This file runs the golden scripts
(``mcp/tests/fixtures/owner/*.sh``) for real: a fake ``/usr/bin`` that
holds stub ``uci``, ``ubus``, ``jsonfilter``, ``id`` and ``mktemp``, a
private ``/var``, and the script fed on stdin the way
``newton-router-setup`` sends it.

What is proved here:

  * the script runs to the apply under the host's ``sh`` and under
    ``busybox ash`` (the shell OpenWrt runs);
  * every accepted value reaches the router byte-exact, and the
    stdin-swallow canary never fires (no command of the script reads
    the script's own stdin);
  * the order is the preconditions, then the stage, then exactly one
    ``uci apply`` whose argv carries the 32-hex session id and the
    integer window;
  * the apply never happens when the script must stop: not root, dirty
    ``uci changes``, a pending window, a failing precondition, a stage
    line that writes to stderr, an empty stage;
  * the private directory ``$W`` is 0700, has a random name, and is
    gone after the script ends, after a stop and after an interrupt
    before the apply.

The sandbox needs a user namespace: the script sets its own PATH to
``/usr/sbin:/usr/bin:/sbin:/bin``, so the stubs have to be *in*
``/usr/bin``, and it stages under ``/var/run/rpcd``.  ``unshare -Urm``
gives both without root on the host; the test is skipped where that is
not allowed.

Under ``busybox ash`` the names ``id`` and ``mktemp`` are busybox
applets, and busybox runs its own applets before it looks at PATH.
That is what a router does too, so the ash run uses the real applets
and the dash run uses the stubs.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "mcp"))

from newton_mcp import owner_script  # noqa: E402
from newton_mcp.owner_script import ScriptPlan  # noqa: E402

GOLDEN = REPO / "mcp" / "tests" / "fixtures" / "owner"
HOST_BUSYBOX = "/usr/bin/busybox"

#: The session the stub ubus hands out: 32 hex characters, like a real one.
SESSION_ID = "0123456789abcdef0123456789abcdef"

#: The private directory the template creates.
WORK_PREFIX = "/tmp/newton-owner."

#: The rpcd versions the stub ubus models: "old" names the session's
#: folder after the session id, "new" gives it a 32-hex name of its own
#: (the rpcd change d99f703).
RPCD_MODES = ["old", "new"]


def staging_dir(mode, sid=SESSION_ID):
    """The folder rpcd keeps the session's changes in, per mode."""
    if mode == "old":
        return "/var/run/rpcd/uci-" + sid
    digest = hashlib.md5(sid.encode()).hexdigest()
    return "/var/run/rpcd/uci-" + digest[:32]


def _busybox() -> str | None:
    """The host busybox, when the host has one."""
    return HOST_BUSYBOX if os.path.exists(HOST_BUSYBOX) else None


def _namespaces_work() -> bool:
    """True when an unprivileged user namespace is allowed here."""
    try:
        done = subprocess.run(
            ["unshare", "-Urm", "true"], capture_output=True, timeout=30
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return done.returncode == 0


pytestmark = pytest.mark.skipif(
    not _namespaces_work(),
    reason="the owner script test needs a user namespace (unshare -Urm)",
)

#: The shells the script is run under.  ``sh`` is the host's shell
#: (dash on Debian); ``ash`` is busybox ash, the shell of the router.
SHELLS = ["sh"] + (["ash"] if _busybox() else [])


# ---- the stubs -------------------------------------------------------------

_UCI_STUB = r'''#!/bin/sh
# The stub uci of the owner-script shell tests.
_line='uci'
for a in "$@"; do _line="$_line@TAB@$a"; done
printf '%s\n' "$_line" >> "$NEWTON_STUB_LOG"

# What stdin did this call get?  The template closes stdin on every
# command, so this must be /dev/null and never the pipe the script
# itself arrived on.
printf 'uci@TAB@%s\n' "$(readlink /proc/self/fd/0 2>/dev/null || echo '')" >> "$NEWTON_STDIN_LOG"

# The stdin-swallow canary: a command that kept the script's stdin
# could read the rest of the script.
if [ -n "${NEWTON_STDIN_CANARY:-}" ] && [ -f "${NEWTON_SCRIPT_PIPE_FILE:-}" ]; then
  if [ "$(readlink /proc/self/fd/0 2>/dev/null || echo '')" = "$(cat "$NEWTON_SCRIPT_PIPE_FILE")" ]; then
    : > "$NEWTON_STDIN_CANARY"
  fi
fi

# Where does this call's stderr point?  The stage helper redirects it
# into the private directory, and that is how the test learns the name
# and the mode of that directory.
if [ -n "${NEWTON_META_LOG:-}" ]; then
  err=$(readlink /proc/self/fd/2 2>/dev/null || echo '')
  mode=''
  case "$err" in
    /tmp/newton-owner.*/*) mode=$(/usr/bin/busybox stat -c %a "${err%/*}" 2>/dev/null || echo '') ;;
  esac
  printf 'uci\t%s\t%s\n' "$err" "$mode" >> "$NEWTON_META_LOG"
fi

# An interrupt before the apply: the script must die with it.
if [ -n "${NEWTON_INTERRUPT:-}" ] && [ "$1" = "-P" ]; then
  kill -INT $PPID
  sleep 5
fi

case "$1" in
  changes)
    # the router's own uncommitted changes
    if [ -n "${NEWTON_UCI_DIRTY:-}" ]; then
      printf '%s\n' 'firewall.cfg0a1b2c=dest_port'
    fi
    exit 0 ;;
esac

if [ "$1" = "-P" ]; then
  dir=$2
  verb=$3
  key=$4
  case "$verb" in
    changes)
      # what the staging directory holds
      if [ -n "${NEWTON_UCI_EMPTY_STAGE:-}" ]; then exit 0; fi
      if [ -f "$dir/changes" ]; then cat "$dir/changes"; fi
      exit 0 ;;
    set|add_list|del_list|delete|reorder)
      if [ -n "${NEWTON_UCI_STAGE_ERR:-}" ]; then
        printf 'uci: cannot write %s\n' "$key" >&2
        exit 0
      fi
      printf '%s %s\n' "$verb" "$key" >> "$dir/changes"
      exit 0 ;;
  esac
  exit 0
fi

if [ "$1" = "-q" ] && [ "$2" = "get" ]; then
  key=$3
  if [ -f "$NEWTON_UCI_STATE" ]; then
    line=$(grep -m1 "^$key=" "$NEWTON_UCI_STATE" 2>/dev/null) || line=''
    if [ -n "$line" ]; then
      printf '%s\n' "${line#*=}"
      exit 0
    fi
  fi
  exit 1
fi

exit 0
'''

_UBUS_STUB = r'''#!/bin/sh
# The stub ubus of the owner-script shell tests.
_line='ubus'
for a in "$@"; do _line="$_line@TAB@$a"; done
printf '%s\n' "$_line" >> "$NEWTON_STUB_LOG"
printf 'ubus@TAB@%s\n' "$(readlink /proc/self/fd/0 2>/dev/null || echo '')" >> "$NEWTON_STDIN_LOG"

# rpcd_dir_for SID: the folder rpcd keeps the session's changes in.
# NEWTON_RPCD_MODE says which rpcd is in force: "old" names the folder
# after the session id, "new" gives it a 32-hex name of its own (the
# rpcd change d99f703). NEWTON_RPCD_BAD_NAME makes a folder whose name is
# not one of rpcd's own.
rpcd_dir_for() {
  if [ "${NEWTON_RPCD_MODE:-new}" = old ]; then
    printf '/var/run/rpcd/uci-%s' "$1"
    return 0
  fi
  sum=$(printf '%s' "$1" | /usr/bin/busybox md5sum)
  sum=${sum%% *}
  printf '/var/run/rpcd/uci-%s' "$(printf '%s' "$sum" | sed 's/\(.\{32\}\).*/\1/')"
}

rpcd_sid() {
  printf '%s' "$1" | sed -n 's/.*"ubus_rpc_session"[[:space:]]*:[[:space:]]*"\([0-9a-f]\{32\}\)".*/\1/p'
}

# rpcd_probe_section SID: the name of the section the marker probe gets.
# Libuci names an anonymous section from the index it got in the package
# plus a hash of the type, so two sessions that add at the same index get
# the SAME name: the name is never derived from the session id.
rpcd_probe_section() {
  count_file="$NEWTON_RPCD_STATE/adds-$1"
  n=0
  if [ -f "$count_file" ]; then n=$(cat "$count_file"); fi
  printf '%s' "$(( n + 1 ))" > "$count_file"
  sum=$(printf '%s' newton_probe | /usr/bin/busybox md5sum)
  sum=${sum%% *}
  printf 'cfg%02x%s' "$n" "$(printf '%s' "$sum" | sed 's/\(.\{4\}\).*/\1/')"
}

case "$2" in
  session)
    case "$3" in
      create) printf '{"ubus_rpc_session":"%s"}\n' "$NEWTON_SESSION_ID"; exit 0 ;;
      grant)
        if [ -n "${NEWTON_GRANT_FAIL:-}" ]; then exit 1; fi
        printf '{}\n'; exit 0 ;;
      destroy)
        # rpcd removes the session's folder when the session is destroyed
        sid=$(rpcd_sid "$4")
        [ -n "$sid" ] || exit 1
        rm -rf "$(rpcd_dir_for "$sid")"
        : > "$NEWTON_RPCD_STATE/destroyed-$sid"
        exit 0 ;;
    esac ;;
  uci)
    case "$3" in
      apply)
        if [ -n "${NEWTON_APPLY_FAIL:-}" ]; then exit 1; fi
        printf '{}\n'; exit 0 ;;
      add)
        # the marker probe that names the session's folder
        sid=$(rpcd_sid "$4")
        [ -n "$sid" ] || exit 1
        section=$(rpcd_probe_section "$sid")
        dir=$(rpcd_dir_for "$sid")
        [ -z "${NEWTON_RPCD_BAD_NAME:-}" ] || dir=/var/run/rpcd/uci-not-a-hash
        mkdir -p "$dir" || exit 1
        printf "+system.%s='newton_probe'\n" "$section" > "$dir/system"
        # a stale session that still holds a probe of the same name: the
        # marker is in two folders and the lookup has to refuse
        stale="${NEWTON_RPCD_STALE:-}"
        if [ -n "$stale" ] && [ "$stale" != "$sid" ] &&
           [ ! -f "$NEWTON_RPCD_STATE/destroyed-$stale" ]; then
          sdir=$(rpcd_dir_for "$stale")
          mkdir -p "$sdir" || exit 1
          printf "+system.%s='newton_probe'\n" "$section" > "$sdir/system"
        fi
        printf '{\n\t"section": "%s"\n}\n' "$section"
        exit 0 ;;
      revert)
        # the probe is taken back out of the folder
        sid=$(rpcd_sid "$4")
        [ -n "$sid" ] || exit 1
        dir=$(rpcd_dir_for "$sid")
        [ -z "${NEWTON_RPCD_BAD_NAME:-}" ] || dir=/var/run/rpcd/uci-not-a-hash
        [ -f "$dir/system" ] && : > "$dir/system"
        exit 0 ;;
    esac ;;
esac
exit 0
'''

_JSONFILTER_STUB = r'''#!/bin/sh
# The stub jsonfilter of the owner-script shell tests.
_line='jsonfilter'
for a in "$@"; do _line="$_line@TAB@$a"; done
printf '%s\n' "$_line" >> "$NEWTON_STUB_LOG"
printf 'jsonfilter@TAB@%s\n' "$(readlink /proc/self/fd/0 2>/dev/null || echo '')" >> "$NEWTON_STDIN_LOG"
case "$*" in
  *'@.section'*)
    # the name of the section the marker probe got
    sed -n 's/.*"section"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' ;;
  *)
    sed -n 's/.*"ubus_rpc_session"[[:space:]]*:[[:space:]]*"\([0-9a-f]\{32\}\)".*/\1/p' ;;
esac
'''

_ID_STUB = r'''#!/bin/sh
# The stub id of the owner-script shell tests.
_line='id'
for a in "$@"; do _line="$_line@TAB@$a"; done
printf '%s\n' "$_line" >> "$NEWTON_STUB_LOG"
printf 'id@TAB@%s\n' "$(readlink /proc/self/fd/0 2>/dev/null || echo '')" >> "$NEWTON_STDIN_LOG"
if [ "$1" = '-u' ]; then
  printf '%s\n' "${NEWTON_ID_UID:-0}"
else
  printf 'uid=%s\n' "${NEWTON_ID_UID:-0}"
fi
'''

_MKTEMP_STUB = r'''#!/bin/sh
# The stub mktemp of the owner-script shell tests.  It makes the
# directory with busybox mktemp, so the mode is the mode a router's
# mktemp gives it.
_line='mktemp'
for a in "$@"; do _line="$_line@TAB@$a"; done
printf '%s\n' "$_line" >> "$NEWTON_STUB_LOG"
printf 'mktemp@TAB@%s\n' "$(readlink /proc/self/fd/0 2>/dev/null || echo '')" >> "$NEWTON_STDIN_LOG"
out=$(/usr/bin/busybox mktemp "$@") || exit 1
mode=$(/usr/bin/busybox stat -c %a "$out" 2>/dev/null) || mode='?'
printf '%s@TAB@%s\n' "$out" "$mode" >> "$NEWTON_MKTEMP_LOG"
printf '%s\n' "$out"
'''

STUBS = {
    "uci": _UCI_STUB,
    "ubus": _UBUS_STUB,
    "jsonfilter": _JSONFILTER_STUB,
    "id": _ID_STUB,
    "mktemp": _MKTEMP_STUB,
}


# ---- the sandbox -----------------------------------------------------------


class Run:
    """What one run of the script did."""

    def __init__(self, done, calls, meta):
        self.rc = done.returncode
        self.out = done.stdout
        self.err = done.stderr
        self.calls = calls
        self.meta = meta

    def named(self, name):
        """The argv of every call of one stub."""
        return [call for call in self.calls if call[0] == name]

    def applies(self):
        """The argv of every uci apply call."""
        return [
            call
            for call in self.calls
            if call[0] == "ubus" and call[1:3] == ("call", "uci")
            and call[3] == "apply"
        ]


class Sandbox:
    """A fake router: a fake /usr/bin, a private /var, a fake router state."""

    def __init__(self, root: Path):
        self.root = root
        self.fake = root / "usrbin"
        self.log = root / "calls.log"
        self.meta_log = root / "meta.log"
        self.mktemp_log = root / "mktemp.log"
        self.stdin_log = root / "stdin.log"
        self.pipe_file = root / "script-pipe"
        self.state = root / "uci-state.txt"
        self.canary = root / "canary"
        self.script = root / "script.sh"
        # the state the stub rpcd keeps outside /var (which is a fresh
        # tmpfs for every run): the add counter of every session and the
        # sessions that were destroyed
        self.rpcd_state = root / "rpcd-state"
        self._build()

    def _build(self):
        self.fake.mkdir(parents=True, exist_ok=True)
        self.rpcd_state.mkdir(parents=True, exist_ok=True)
        shutil.copy2("/usr/bin/dash", self.fake / "sh")
        shutil.copy2(HOST_BUSYBOX, self.fake / "busybox")
        for applet in (
            "grep", "mkdir", "rm", "sed", "stat", "cat", "readlink", "ls",
            "date", "touch",
        ):
            (self.fake / applet).symlink_to("busybox")
        for name, body in STUBS.items():
            path = self.fake / name
            path.write_text(body.replace("@TAB@", "\t"))
            path.chmod(0o755)

    def set_state(self, values):
        """The values the router holds: a mapping of uci path to value."""
        self.state.write_text(
            "".join("{0}={1}\n".format(key, value) for key, value in values.items())
        )

    def _read_calls(self):
        calls = []
        if self.log.exists():
            for line in self.log.read_text().splitlines():
                calls.append(tuple(line.split("\t")))
        return calls

    def _read_meta(self):
        meta = []
        if self.meta_log.exists():
            for line in self.meta_log.read_text().splitlines():
                parts = line.split("\t")
                meta.append((parts[0], parts[1] if len(parts) > 1 else "",
                             parts[2] if len(parts) > 2 else ""))
        return meta

    def run(self, script, *, shell="sh", env=None, setup="", namespace=True):
        """Run the script under the sandbox and return what it did."""
        if isinstance(script, (bytes, bytearray)):
            self.script.write_bytes(bytes(script))
        else:
            self.script.write_text(script, encoding="utf-8")
        environment = dict(os.environ)
        environment.update(
            {
                "NEWTON_STUB_LOG": str(self.log),
                "NEWTON_META_LOG": str(self.meta_log),
                "NEWTON_MKTEMP_LOG": str(self.mktemp_log),
                "NEWTON_UCI_STATE": str(self.state),
                "NEWTON_STDIN_CANARY": str(self.canary),
                "NEWTON_STDIN_LOG": str(self.stdin_log),
                "NEWTON_SCRIPT_PIPE_FILE": str(self.pipe_file),
                "NEWTON_SESSION_ID": SESSION_ID,
                "NEWTON_RPCD_STATE": str(self.rpcd_state),
            }
        )
        if env:
            environment.update(env)
        parts = []
        if namespace:
            parts.append("mount -t tmpfs tmpfs /var")
            parts.append("mount --bind {0} /usr/bin".format(self.fake))
        if setup:
            parts.append(setup)
        command = "/usr/bin/sh -s" if shell == "sh" else "/usr/bin/busybox ash -s"
        # The script arrives on a pipe, the way the ssh lane sends it: a
        # shell that can seek back over a file would hide a command that
        # reads its stdin, and the router's shell cannot.
        parts.append(
            "cat {0} | {{ readlink /proc/self/fd/0 > {1}; exec {2}; }}".format(
                self.script, self.pipe_file, command
            )
        )
        inner = self.root / "inner.sh"
        inner.write_text("set -e\n" + ";\n".join(parts) + "\n")
        argv = ["sh"]
        if namespace:
            argv = ["unshare", "-Urm", "--propagation", "private"] + argv
        done = subprocess.run(
            argv + [str(inner)],
            env=environment,
            capture_output=True,
            text=True,
            timeout=120,
        )
        return Run(done, self._read_calls(), self._read_meta())

    def stdins(self):
        """The stdin every stub call was given."""
        found = []
        if self.stdin_log.exists():
            for line in self.stdin_log.read_text().splitlines():
                parts = line.split("\t")
                found.append((parts[0], parts[1] if len(parts) > 1 else ""))
        return found

    def script_pipe(self):
        """The pipe the script itself arrived on."""
        if self.pipe_file.exists():
            return self.pipe_file.read_text().strip()
        return ""

    def work_dirs(self):
        """The private directories the script made, from the stub log."""
        found = []
        if self.mktemp_log.exists():
            for line in self.mktemp_log.read_text().splitlines():
                found.append(tuple(line.split("\t")))
        return found

    def private_dirs(self):
        """The private directories the stage helper wrote into."""
        found = []
        for _name, err, mode in self._read_meta():
            if err.startswith(WORK_PREFIX):
                found.append((err.rsplit("/", 1)[0], mode))
        return found


@pytest.fixture
def sandbox(tmp_path):
    """A fake router."""
    box = Sandbox(tmp_path / "sandbox")
    box.set_state({"firewall.cfg0a1b2c.dest_port": "22"})
    yield box
    for path, _mode in box.work_dirs():
        shutil.rmtree(path, ignore_errors=True)
    for path, _mode in box.private_dirs():
        shutil.rmtree(path, ignore_errors=True)


# ---- the happy path --------------------------------------------------------


@pytest.mark.parametrize("shell", SHELLS)
def test_the_golden_apply_script_runs_to_the_apply(sandbox, shell):
    """The apply script ends with the apply, under both shells."""
    run = sandbox.run((GOLDEN / "apply.sh").read_bytes(), shell=shell)
    assert run.rc == 0, run.err
    assert "NEWTON-APPLYING plan=3f9a1c0be2d44b17a1c3d5e7f9012345" in run.out
    assert "NEWTON-CHECKED plan=3f9a1c0be2d44b17a1c3d5e7f9012345" in run.out
    assert "NEWTON-STAGED plan=3f9a1c0be2d44b17a1c3d5e7f9012345" in run.out
    assert (
        "NEWTON-APPLIED plan=3f9a1c0be2d44b17a1c3d5e7f9012345 window=180 "
        f"session={SESSION_ID}"
    ) in run.out
    assert "NEWTON-STOP" not in run.out


def test_the_script_grants_its_own_session_the_right_to_confirm(sandbox):
    """The session the script opens may confirm, and nothing else.

    A fresh limited session cannot confirm a root script's apply
    (measured, a3m-01), so the script gives its own session the one
    right it needs.  The grant is the fixed JSON of the measurement.
    """
    run = sandbox.run((GOLDEN / "apply.sh").read_bytes())
    grants = [
        call
        for call in run.calls
        if call[0] == "ubus" and call[1:4] == ("call", "session", "grant")
    ]
    assert len(grants) == 2, run.calls
    payload = json.loads(grants[1][4])
    assert payload == {
        "ubus_rpc_session": SESSION_ID,
        "scope": "ubus",
        "objects": [["uci", "confirm"]],
    }


@pytest.mark.parametrize("shell", SHELLS)
def test_there_is_exactly_one_apply_and_it_carries_the_session_and_the_window(
    sandbox, shell
):
    """One apply, with the 32-hex session id and the integer window."""
    run = sandbox.run((GOLDEN / "apply.sh").read_bytes(), shell=shell)
    applies = run.applies()
    assert len(applies) == 1, run.calls
    argv = applies[0]
    assert argv[1] == "call" and argv[2] == "uci" and argv[3] == "apply"
    payload = json.loads(argv[4])
    assert payload["ubus_rpc_session"] == SESSION_ID
    assert len(payload["ubus_rpc_session"]) == 32
    assert payload["rollback"] is True
    assert payload["timeout"] == 180
    assert isinstance(payload["timeout"], int)


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("mode", RPCD_MODES)
def test_the_order_is_the_preconditions_then_the_stage_then_the_apply(
    sandbox, shell, mode
):
    """The script checks, stages, and only then applies."""
    run = sandbox.run(
        (GOLDEN / "apply.sh").read_bytes(), shell=shell,
        env={"NEWTON_RPCD_MODE": mode},
    )
    order = []
    for call in run.calls:
        if call[0] == "uci" and call[1] == "-q" and call[2] == "get":
            order.append("precondition")
        elif call[0] == "uci" and call[1] == "-P" and call[3] == "changes":
            order.append("staged")
        elif call[0] == "ubus" and call[3] == "apply":
            order.append("apply")
    assert order == ["precondition", "staged", "apply"]
    # the precondition is the value the plan recorded
    gets = [call for call in run.calls if call[1:3] == ("-q", "get")]
    assert gets == [
        ("uci", "-q", "get", "firewall.cfg0a1b2c.dest_port")
    ]
    # the stage writes the new value into the staging directory, and that
    # directory is the one rpcd keeps the session's changes in
    sets = [call for call in run.calls if call[1] == "-P" and call[3] == "set"]
    assert sets == [
        (
            "uci",
            "-P",
            staging_dir(mode),
            "set",
            "firewall.cfg0a1b2c.dest_port=2222",
        )
    ]


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("mode", RPCD_MODES)
def test_the_script_finds_the_session_folder_of_both_rpcd_versions(
    sandbox, shell, mode
):
    """The script finds the folder rpcd keeps the session's changes in
    under both rpcd versions: the marker probe names it."""
    run = sandbox.run(
        (GOLDEN / "apply.sh").read_bytes(), shell=shell,
        env={"NEWTON_RPCD_MODE": mode},
    )
    assert run.rc == 0, run.err
    assert "NEWTON-APPLIED" in run.out
    adds = [
        call for call in run.calls
        if call[0] == "ubus" and call[1:4] == ("call", "uci", "add")
    ]
    assert len(adds) == 1, run.calls
    payload = json.loads(adds[0][4])
    assert payload["config"] == "system"
    assert payload["type"] == "newton_probe"
    assert payload["ubus_rpc_session"] == SESSION_ID
    # the probe is taken back out again before anything is staged
    reverts = [
        call for call in run.calls
        if call[0] == "ubus" and call[1:4] == ("call", "uci", "revert")
    ]
    assert len(reverts) == 1, run.calls


def test_the_script_stops_when_the_folder_name_is_not_one_of_rpcd_own(sandbox):
    """A folder whose name is not one of rpcd's own is refused."""
    run = sandbox.run(
        (GOLDEN / "apply.sh").read_bytes(),
        env={"NEWTON_RPCD_BAD_NAME": "1"},
    )
    assert run.rc == 1
    assert "NEWTON-STOP: could not locate the rpcd session folder" in run.out
    _no_apply(run)


def test_the_script_destroys_its_session_when_the_lookup_fails(sandbox):
    """A lookup that fails takes the session with it.

    Nothing has been applied at that point, so the session is not needed;
    leaving it behind would hold a grant on the router for nothing.
    """
    run = sandbox.run(
        (GOLDEN / "apply.sh").read_bytes(),
        env={"NEWTON_RPCD_BAD_NAME": "1"},
    )
    assert run.rc == 1
    destroys = [
        call
        for call in run.calls
        if call[0] == "ubus" and call[1:4] == ("call", "session", "destroy")
    ]
    assert len(destroys) == 1, run.calls
    payload = json.loads(destroys[0][4])
    assert payload == {"ubus_rpc_session": SESSION_ID}
    _no_apply(run)


def test_the_script_destroys_its_session_when_the_grant_fails(sandbox):
    """A session the router will not grant is destroyed as well."""
    run = sandbox.run(
        (GOLDEN / "apply.sh").read_bytes(),
        env={"NEWTON_GRANT_FAIL": "1"},
    )
    assert run.rc == 1
    assert "NEWTON-STOP: could not open a session" in run.out
    destroys = [
        call
        for call in run.calls
        if call[0] == "ubus" and call[1:4] == ("call", "session", "destroy")
    ]
    assert len(destroys) == 1, run.calls
    _no_apply(run)


#: A session that is still alive and holds a probe of its own.
STALE_SESSION = "aaaabbbbccccddddeeeeffff00001111"


def test_a_stale_session_with_the_same_probe_makes_the_lookup_refuse(sandbox):
    """Two sessions can hold the same probe name.

    Libuci names an anonymous section from the index it got plus a hash of
    the type, so the name is the same in every session that adds at the
    same index.  The marker is then in two folders and the lookup refuses.
    """
    run = sandbox.run(
        (GOLDEN / "apply.sh").read_bytes(),
        env={"NEWTON_RPCD_STALE": STALE_SESSION},
    )
    assert run.rc == 1
    assert "NEWTON-STOP: could not locate the rpcd session folder" in run.out
    _no_apply(run)


def test_the_lookup_works_again_once_the_stale_session_is_gone(sandbox):
    """The stale session is destroyed: rpcd takes its folder with it, and
    the next lookup finds the folder of the new session."""
    run = sandbox.run(
        (GOLDEN / "apply.sh").read_bytes(),
        env={"NEWTON_RPCD_STALE": STALE_SESSION},
    )
    assert run.rc == 1

    # the stale session is destroyed
    sandbox.run(
        '/usr/bin/ubus call session destroy \'{"ubus_rpc_session":"%s"}\'\n'
        % STALE_SESSION
    )

    run = sandbox.run(
        (GOLDEN / "apply.sh").read_bytes(),
        env={"NEWTON_RPCD_STALE": STALE_SESSION},
    )
    assert run.rc == 0, run.err
    assert "NEWTON-APPLIED" in run.out
    assert len(run.applies()) == 1, run.calls


#: What the router holds before each golden script runs.
GOLDEN_STATE = {
    "apply.sh": {"firewall.cfg0a1b2c.dest_port": "22"},
    "restore.sh": {"firewall.cfg0a1b2c.dest_port": "2222"},
    "apply-lists.sh": {"firewall.cfg03dc81.network": "wan wan6 wan2"},
    "restore-lists.sh": {
        "firewall.cfg03dc81.network": "wan wan2 wan3",
        "firewall.labz": "zone",
    },
}


@pytest.mark.parametrize("name", ["restore.sh", "apply-lists.sh", "restore-lists.sh"])
def test_every_golden_script_runs_to_one_apply(sandbox, name):
    """The restore script and the list scripts run the same way."""
    sandbox.set_state(GOLDEN_STATE[name])
    run = sandbox.run((GOLDEN / name).read_bytes())
    assert run.rc == 0, run.err
    assert len(run.applies()) == 1
    assert "NEWTON-APPLIED" in run.out


def test_the_restore_script_restores_the_old_value(sandbox):
    """The restore script writes the old value back."""
    sandbox.set_state(GOLDEN_STATE["restore.sh"])
    run = sandbox.run((GOLDEN / "restore.sh").read_bytes())
    assert run.rc == 0, run.err
    sets = [call for call in run.calls if call[1] == "-P" and call[3] == "set"]
    assert sets[0][-1] == "firewall.cfg0a1b2c.dest_port=22"


def test_the_list_script_stages_the_list_verbs(sandbox):
    """The list script carries the list verbs in the order of the plan."""
    sandbox.set_state(GOLDEN_STATE["apply-lists.sh"])
    run = sandbox.run((GOLDEN / "apply-lists.sh").read_bytes())
    assert run.rc == 0, run.err
    stages = [call[-1] for call in run.calls if call[1] == "-P" and call[3] != "changes"]
    assert stages == [
        "firewall.cfg03dc81.network=wan6",
        "firewall.cfg03dc81.network=wan3",
        "firewall.labz",
        "system.hostname=newton-lab",
    ]


# ---- the values ------------------------------------------------------------

#: The values the grammar accepts and a router may really hold.  They
#: are the shell metacharacters the grammar does not refuse.
HOSTILE_VALUES = (
    "*",
    "?",
    "~",
    "#",
    "!",
    "%",
    "^",
    "a b",
    "a=b",
    "a:b",
    "a/b",
    "a-b_c",
    "a,b",
    "a+b",
    "a[b]",
    "user@example",
    "0123456789",
    "New",
    "-",
    "..",
    "/",
)


def _value_plan():
    """A plan whose ops carry every accepted hostile value."""
    ops = []
    preconditions = []
    for index, value in enumerate(HOSTILE_VALUES):
        option = "value{0}".format(index)
        preconditions.append(("firewall.cfg0a1b2c." + option, "old"))
        ops.append(("set", "firewall.cfg0a1b2c." + option, value))
    return ScriptPlan(
        sid="3f9a1c0be2d44b17a1c3d5e7f9012345",
        kind="apply",
        device="lab-r1",
        window=180,
        restore_sid="9e8d7c6b5a4938271605f4e3d2c1b0a9",
        preconditions=tuple(preconditions),
        ops=tuple(ops),
    )


def test_the_accepted_hostile_values_reach_the_router_byte_exact(sandbox):
    """Every accepted value arrives at the router exactly as it was written."""
    plan = _value_plan()
    sandbox.set_state(
        {
            "firewall.cfg0a1b2c.value{0}".format(index): "old"
            for index in range(len(HOSTILE_VALUES))
        }
    )
    run = sandbox.run(owner_script.render_script(plan))
    assert run.rc == 0, run.err
    stages = [call[-1] for call in run.calls if call[1] == "-P" and call[3] == "set"]
    expected = [
        "firewall.cfg0a1b2c.value{0}={1}".format(index, value)
        for index, value in enumerate(HOSTILE_VALUES)
    ]
    assert stages == expected
    for index, value in enumerate(HOSTILE_VALUES):
        assert value.encode("ascii") in stages[index].encode("ascii")


def test_every_command_of_the_script_closes_its_stdin(sandbox):
    """No command of the script can read the script itself."""
    run = sandbox.run((GOLDEN / "apply.sh").read_bytes())
    assert run.rc == 0, run.err
    pipe = sandbox.script_pipe()
    assert pipe, "the script must arrive on a pipe"
    for name, stdin in sandbox.stdins():
        if name == "jsonfilter":
            # it reads the answer of the ubus call, not the script
            assert stdin != pipe, (name, stdin)
            continue
        assert stdin == "/dev/null", (name, stdin)
    assert not sandbox.canary.exists()


def test_the_stdin_canary_fires_when_a_command_reads_stdin(sandbox):
    """The canary is real: a command without </dev/null keeps the script.

    The shell of this host reads the whole script before it runs it, so
    the script still ends here; on a shell that streams the script, the
    rest of it would be eaten.  The canary sees the difference: the
    command kept the pipe the script arrived on.
    """
    broken = (GOLDEN / "apply.sh").read_bytes().replace(
        b'[ -z "$(uci changes </dev/null)" ]', b'[ -z "$(uci changes)" ]'
    )
    assert broken != (GOLDEN / "apply.sh").read_bytes()
    sandbox.run(broken)
    assert sandbox.canary.exists()
    assert ("uci", sandbox.script_pipe()) in sandbox.stdins()


# ---- the refusals ----------------------------------------------------------


def _no_apply(run):
    assert run.applies() == [], run.calls


def test_the_apply_is_not_called_when_the_user_is_not_root(sandbox):
    """Not root: the script stops before it touches the router."""
    run = sandbox.run(
        (GOLDEN / "apply.sh").read_bytes(), env={"NEWTON_ID_UID": "1000"}
    )
    assert run.rc == 1
    assert "NEWTON-STOP: this must run as root" in run.out
    _no_apply(run)


def test_the_apply_is_not_called_when_the_router_has_uncommitted_changes(sandbox):
    """A dirty uci changes stops the script."""
    run = sandbox.run(
        (GOLDEN / "apply.sh").read_bytes(), env={"NEWTON_UCI_DIRTY": "1"}
    )
    assert run.rc == 1
    assert "NEWTON-STOP: the router has uncommitted changes" in run.out
    _no_apply(run)


def test_the_apply_is_not_called_when_another_change_is_waiting(sandbox):
    """A pending window stops the script.

    A real window holds one file per changed config (measured, a3m-04).
    """
    run = sandbox.run(
        (GOLDEN / "apply.sh").read_bytes(),
        setup="mkdir -p /var/run/rpcd/snapshot-files"
        " && : > /var/run/rpcd/snapshot-files/dhcp",
    )
    assert run.rc == 1
    assert (
        "NEWTON-STOP: another change is waiting for confirmation (LuCI or Newton)"
        in run.out
    )
    _no_apply(run)


@pytest.mark.parametrize("shell", SHELLS)
def test_the_apply_stops_on_a_leftover_undo_file_and_says_the_way_out(
    sandbox, shell
):
    """An undo file the router forgot about says how to clear it.

    A restart of the router's web service forgets the window but leaves
    the undo file behind for good (measured, a4m-02).  The script still
    refuses to apply, and it tells the owner what to do about it.
    """
    old = int(time.time()) - 7200
    run = sandbox.run(
        (GOLDEN / "apply.sh").read_bytes(),
        shell=shell,
        setup="mkdir -p /var/run/rpcd/snapshot-files"
        " && : > /var/run/rpcd/snapshot-files/dhcp"
        f" && touch -d @{old} /var/run/rpcd/snapshot-files/dhcp",
    )
    assert run.rc == 1
    assert (
        "NEWTON-STOP: the router has a leftover undo file from 2 hours ago"
        in run.out
    ), run.out
    assert "rm -rf /var/run/rpcd/snapshot-files" in run.out
    _no_apply(run)


def test_an_empty_snapshot_directory_does_not_stop_the_script(sandbox):
    """An empty leftover directory is not a window (measured, a3m-04).

    A refused apply leaves the directory behind, empty, and it stays
    that way: it must not block Newton forever.  The script says so in
    one NOTE line, and it removes nothing.
    """
    run = sandbox.run(
        (GOLDEN / "apply.sh").read_bytes(),
        setup="mkdir -p /var/run/rpcd/snapshot-files",
    )
    assert run.rc == 0, run.err
    assert len(run.applies()) == 1
    assert (
        "NEWTON-NOTE: the router has an empty leftover from a refused "
        "change (/var/run/rpcd/snapshot-files); it does not block Newton"
        in run.out
    )


def test_the_apply_is_not_called_when_a_precondition_fails(sandbox):
    """A router that changed since the plan stops the script."""
    sandbox.set_state({"firewall.cfg0a1b2c.dest_port": "23"})
    run = sandbox.run((GOLDEN / "apply.sh").read_bytes())
    assert run.rc == 1
    assert (
        "NEWTON-STOP: the router changed since the plan: "
        "firewall.cfg0a1b2c.dest_port" in run.out
    )
    _no_apply(run)


def test_the_apply_is_not_called_when_a_stage_line_writes_to_stderr(sandbox):
    """A stage line the router refuses stops the script."""
    run = sandbox.run(
        (GOLDEN / "apply.sh").read_bytes(), env={"NEWTON_UCI_STAGE_ERR": "1"}
    )
    assert run.rc == 1
    assert (
        "NEWTON-STOP: the router refused a change; nothing was applied" in run.out
    )
    _no_apply(run)


def test_the_apply_is_not_called_when_the_stage_is_empty(sandbox):
    """An empty stage stops the script."""
    run = sandbox.run(
        (GOLDEN / "apply.sh").read_bytes(), env={"NEWTON_UCI_EMPTY_STAGE": "1"}
    )
    assert run.rc == 1
    assert "NEWTON-STOP: nothing to apply" in run.out
    _no_apply(run)


def test_the_apply_is_not_called_when_the_router_refuses_the_apply(sandbox):
    """A refused apply stops the script, and the change is not confirmed."""
    run = sandbox.run(
        (GOLDEN / "apply.sh").read_bytes(), env={"NEWTON_APPLY_FAIL": "1"}
    )
    assert run.rc == 1
    assert "NEWTON-STOP: the router refused the apply; nothing changed" in run.out
    assert "NEWTON-APPLIED" not in run.out


# ---- the private directory ------------------------------------------------


def test_the_private_directory_is_private_and_has_a_random_name(sandbox):
    """$W is 0700 and its name is not fixed."""
    run = sandbox.run((GOLDEN / "apply.sh").read_bytes())
    assert run.rc == 0, run.err
    dirs = sandbox.work_dirs()
    assert dirs, run.calls
    path, mode = dirs[0]
    assert path.startswith(WORK_PREFIX)
    assert path != WORK_PREFIX
    assert len(path.rsplit(".", 1)[-1]) >= 4
    assert mode == "700"
    # a second run makes a different directory
    sandbox.run((GOLDEN / "apply.sh").read_bytes())
    assert sandbox.work_dirs()[1][0] != path


def test_the_private_directory_is_gone_after_the_script_ends(sandbox):
    """The script leaves nothing of its own behind."""
    run = sandbox.run((GOLDEN / "apply.sh").read_bytes())
    assert run.rc == 0, run.err
    for path, _mode in sandbox.work_dirs():
        assert not os.path.exists(path)


def test_the_private_directory_is_gone_after_a_stop(sandbox):
    """A refused script leaves nothing behind either."""
    run = sandbox.run(
        (GOLDEN / "apply.sh").read_bytes(), env={"NEWTON_UCI_DIRTY": "1"}
    )
    assert run.rc == 1
    for path, _mode in sandbox.work_dirs():
        assert not os.path.exists(path)


def test_the_private_directory_is_gone_after_an_interrupt_before_the_apply(sandbox):
    """An interrupt before the apply leaves nothing behind."""
    run = sandbox.run(
        (GOLDEN / "apply.sh").read_bytes(), env={"NEWTON_INTERRUPT": "1"}
    )
    assert run.rc != 0
    assert "NEWTON-APPLIED" not in run.out
    _no_apply(run)
    for path, _mode in sandbox.work_dirs():
        assert not os.path.exists(path)


def test_the_staging_directory_is_the_only_thing_the_script_writes(sandbox):
    """Nothing outside the private directory and the staging directory."""
    run = sandbox.run((GOLDEN / "apply.sh").read_bytes())
    assert run.rc == 0, run.err
    allowed = (WORK_PREFIX, "/var/run/rpcd/uci-")
    for call in run.calls:
        for argument in call[1:]:
            if argument.startswith("/"):
                assert argument.startswith(allowed), argument
