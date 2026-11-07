import os
import stat
import subprocess
from pathlib import Path

import pytest


HERE = Path(__file__).resolve().parents[1]
GUARD = HERE / "newton-guard"
INIT = HERE / "newton-guard.init"
BUSYBOX = "/usr/bin/busybox"


CONFIG = {
    "network": (b"config interface 'lan'\n\toption proto 'static'\n", 0o600),
    "wireless": (b"config wifi-device 'radio0'\n\toption channel 'auto'\n", 0o600),
    "firewall": (b"config defaults\n\toption input 'REJECT'\n", 0o600),
    "dhcp": (b"config dnsmasq\n\toption domainneeded '1'\n", 0o644),
    "system": (b"config system\n\toption hostname 'newton-test'\n", 0o644),
}

# Guard runs call the system-wide sync, so under machine load they need headroom.
GUARD_TIMEOUT = 60


def executable(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0o755)


def install_io_wrapper(root: Path, tool: str) -> None:
    if tool == "mv":
        tail = """
# mv-append / mv-append-once: after a successful move, append one line to the target.
for mode in append-once append; do
    control="$NEWTON_GUARD_ROOT/control/mv-$mode"
    if [ -f "$control" ] && matches "$control" "$@"; then
        /usr/bin/mv "$@" || exit $?
        target=
        for argument do target=$argument; done
        echo extra >> "$target"
        [ "$mode" != append-once ] || rm -f "$control"
        exit 0
    fi
done
# mv-truncate / mv-truncate-once: after a successful move, empty the target.
truncate_control=
for mode in truncate-once truncate; do
    control="$NEWTON_GUARD_ROOT/control/mv-$mode"
    if [ -f "$control" ] && matches "$control" "$@"; then
        truncate_control=$control
        [ "$mode" != truncate-once ] || rm -f "$control"
        break
    fi
done
if [ -z "$truncate_control" ]; then exec /usr/bin/mv "$@"; fi
/usr/bin/mv "$@" || exit $?
target=
for argument do target=$argument; done
: > "$target"
"""
    elif tool == "cp":
        tail = """
# cp-partial / cp-partial-once: copy only the first 4 bytes of the source to the
# destination, then exit 1 (like ENOSPC mid-copy).
for mode in partial-once partial; do
    control="$NEWTON_GUARD_ROOT/control/cp-$mode"
    if [ -f "$control" ] && matches "$control" "$@"; then
        [ "$mode" != partial-once ] || rm -f "$control"
        src=
        dest=
        for argument do
            case "$argument" in -*) continue ;; esac
            if [ -z "$src" ]; then src=$argument; else dest=$argument; fi
        done
        head -c 4 "$src" > "$dest"
        exit 1
    fi
done
# cp-hook / cp-hook-once: after a successful real copy whose arguments match
# the pattern on line 1, run the shell command on line 2 (NEWTON_GUARD_ROOT is
# in the environment). cp-hook-once removes its control file first.
for mode in hook-once hook; do
    control="$NEWTON_GUARD_ROOT/control/cp-$mode"
    if [ -f "$control" ] && matches "$control" "$@"; then
        hook_command=$(sed -n '2p' "$control")
        [ "$mode" != hook-once ] || rm -f "$control"
        /usr/bin/cp "$@" || exit $?
        sh -c "$hook_command"
        exit $?
    fi
done
exec /usr/bin/cp "$@"
"""
    elif tool == "sync":
        tail = """
# sync-fail-if-exists(-once): the control's first line is a path relative to
# the fake root; the sync fails only while that path exists.
for mode in fail-if-exists-once fail-if-exists; do
    control="$NEWTON_GUARD_ROOT/control/sync-$mode"
    if [ -f "$control" ]; then
        IFS= read -r marker < "$control" || marker=
        if [ -n "$marker" ] && [ -e "$NEWTON_GUARD_ROOT/$marker" ]; then
            [ "$mode" != fail-if-exists-once ] || rm -f "$control"
            exit 1
        fi
    fi
done
exec /usr/bin/sync "$@"
"""
    elif tool == "sleep":
        tail = """
# Skip long sleeps (two or more leading digits, e.g. 15) so tests never wait for the retry gap.
case "${1:-}" in
    [0-9][0-9]*) exit 0 ;;
esac
exec /usr/bin/sleep "$@"
"""
    else:
        tail = f'exec /usr/bin/{tool} "$@"\n'
    executable(
        root / f"bin/{tool}",
        f"""#!/bin/sh
# A control file selects always/once failure and may contain an argument substring.
# Every call is logged as one line to control/{tool}.calls so tests can count calls.
echo "$*" >> "$NEWTON_GUARD_ROOT/control/{tool}.calls"
matches() {{
    control=$1
    pattern=
    IFS= read -r pattern < "$control" || :
    [ -z "$pattern" ] && return 0
    shift
    for argument do
        # Match against the path inside the fake root, so a pattern cannot hit the pytest tmp dir name.
        case "${{argument#"$NEWTON_GUARD_ROOT"}}" in *"$pattern"*) return 0 ;; esac
    done
    return 1
}}
for mode in fail-once fail; do
    control="$NEWTON_GUARD_ROOT/control/{tool}-$mode"
    if [ -f "$control" ] && matches "$control" "$@"; then
        [ "$mode" != fail-once ] || rm -f "$control"
        exit 1
    fi
done
{tail}""",
    )


@pytest.fixture
def router(tmp_path):
    root = tmp_path / "router"
    cfg = root / "etc/config"
    cfg.mkdir(parents=True)
    for name, (data, mode) in CONFIG.items():
        path = cfg / name
        path.write_bytes(data)
        path.chmod(mode)
    (root / "proc/sys/kernel/random").mkdir(parents=True)
    (root / "proc/uptime").write_text("100.00 90.00\n")
    (root / "proc/sys/kernel/random/boot_id").write_text("boot-one\n")
    (root / "dev").mkdir()
    (root / "dev/kmsg").write_text("")
    (root / "tmp").mkdir()
    (root / "control").mkdir()
    (root / "control/avail").write_text("999999\n")
    executable(
        root / "etc/init.d/newton-guard",
        """#!/bin/sh
echo "$*" >> "$NEWTON_GUARD_ROOT/control/init.calls"
if [ "$1" = enabled ] && [ -f "$NEWTON_GUARD_ROOT/control/disabled" ]; then exit 1; fi
if [ "${1:-} ${2:-}" = "running timer" ] && [ -f "$NEWTON_GUARD_ROOT/control/not-running" ]; then exit 1; fi
exit 0
""",
    )
    executable(
        root / "sbin/reload_config",
        """#!/bin/sh
echo reload >> "$NEWTON_GUARD_ROOT/control/reload.calls"
[ ! -f "$NEWTON_GUARD_ROOT/control/reload-fails" ]
""",
    )
    executable(
        root / "usr/bin/logger",
        """#!/bin/sh
echo "$*" >> "$NEWTON_GUARD_ROOT/control/logger.calls"
""",
    )
    executable(
        root / "bin/df",
        """#!/bin/sh
if [ -f "$NEWTON_GUARD_ROOT/control/df-block" ]; then
    touch "$NEWTON_GUARD_ROOT/control/df-ready"
    while [ -f "$NEWTON_GUARD_ROOT/control/df-block" ]; do sleep 0.05; done
fi
avail=$(cat "$NEWTON_GUARD_ROOT/control/avail")
echo 'Filesystem 1024-blocks Used Available Capacity Mounted on'
echo "fake 1000000 1 $avail 1% /"
""",
    )
    for tool in ("cp", "mv", "sync", "rm", "mktemp", "sleep"):
        install_io_wrapper(root, tool)
    return root


def run_guard(root: Path, *args, crash=None, timeout=GUARD_TIMEOUT):
    env = os.environ.copy()
    env["NEWTON_GUARD_ROOT"] = str(root)
    if crash is not None:
        env["NEWTON_GUARD_CRASH_AT"] = str(crash)
    else:
        env.pop("NEWTON_GUARD_CRASH_AT", None)
    return subprocess.run(
        [BUSYBOX, "sh", str(GUARD), *map(str, args)],
        env=env,
        text=True,
        capture_output=True,
        timeout=timeout,
        start_new_session=True,
    )


def snapshot(root: Path):
    result = {}
    for path in (root / "etc/config").iterdir():
        if not path.name.startswith("."):
            result[path.name] = (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
    return result


def arm(root: Path, txn="txn-0001", timeout=60):
    result = run_guard(root, "arm", txn, timeout)
    assert result.returncode == 0, (result.stdout, result.stderr)
    return result
