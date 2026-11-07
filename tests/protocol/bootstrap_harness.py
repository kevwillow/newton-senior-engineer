"""Harness for exercising newton-bootstrap inside a user+mount namespace.

The harness writes a copy of the pivot recipe into a per-test directory and
then runs commands under `unshare -Urm bash pivot.sh ...` so the inner command
sees a freshly built rootfs owned by uid 0, even though the host filesystem
belongs to the test runner. The recipe is the same shell script newton-bootstrap
itself relies on, with one extra positional argument for the /usr/local/sbin
mode so tests can exercise different permission combinations.
"""
from __future__ import annotations

import os
import pty
import shutil
import subprocess
from pathlib import Path

PIVOT = r"""#!/bin/bash
# runs inside unshare -Urm. $1 = new root dir (empty dir), $2 = stage dir,
# $3 = mode for /usr/local/sbin, rest = command
set -e
NR=$1; STAGE=$2; SBIN_MODE=$3; shift 3
mount --make-rprivate /
mount -t tmpfs -o mode=755 tmpfs "$NR"
mkdir -p "$NR"/{usr,proc,dev,tmp,var/tmp,root,etc,run,old}
mount -t tmpfs -o mode=755 tmpfs "$NR/usr"
for d in bin sbin lib lib64 libexec share; do
	[ -d "/usr/$d" ] || continue
	mkdir "$NR/usr/$d"; mount --rbind "/usr/$d" "$NR/usr/$d"
done
mkdir -p "$NR/usr/local/sbin"
mount --rbind /proc "$NR/proc"; mount --rbind /dev "$NR/dev"; mount --rbind /etc "$NR/etc"
for l in bin sbin lib lib64; do ln -s usr/$l "$NR/$l"; done
chmod 1777 "$NR/tmp" "$NR/var/tmp"; chmod 700 "$NR/root"
tar -C "$STAGE" -cf - . | tar -C "$NR" -xf - --no-overwrite-dir --no-same-owner
chmod 755 "$NR/usr/local"; chmod "$SBIN_MODE" "$NR/usr/local/sbin"
cd "$NR"; pivot_root . old; umount -l /old; rmdir /old
exec "$@"
"""

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "newton-bootstrap"

_USERNS_OK: bool | None = None


def userns_ok() -> bool:
    """Return True iff `unshare -Urm true` succeeds here.

    The probe runs once and the result is cached: subsequent calls return the
    same answer. Tests should guard with
    `@pytest.mark.skipif(not userns_ok(), reason="user ns unavailable")`.
    """
    global _USERNS_OK
    if _USERNS_OK is not None:
        return _USERNS_OK
    try:
        r = subprocess.run(
            ["unshare", "-Urm", "true"],
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        _USERNS_OK = r.returncode == 0
    except FileNotFoundError:
        _USERNS_OK = False
    except Exception:
        _USERNS_OK = False
    return _USERNS_OK


_OUTER_ENV = {
    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME": "/root",
    "LANG": "C.UTF-8",
}


def _build_inner(argv, env):
    """Build the argv that runs INSIDE the namespace.

    The harness always prefixes the inner command with `env` so the test's env
    dict is applied inside the namespace; keys whose value is None are dropped
    via `-u KEY` (passed as two separate argv entries). If env is None or
    empty, no `env` prefix is added and inner equals argv verbatim.
    """
    if not env:
        return list(argv)
    pieces = ["env"]
    for k, v in env.items():
        if v is None:
            pieces.append("-u")
            pieces.append(k)
        else:
            pieces.append(f"{k}={v}")
    pieces.extend(argv)
    return pieces


def _run_proc(cmd, timeout):
    """Run cmd with DEVNULL stdin, capturing stdout/stderr, return (rc, out, err)."""
    proc = subprocess.Popen(
        cmd,
        env=_OUTER_ENV,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        raise
    return (
        proc.returncode,
        stdout.decode("utf-8", "replace"),
        stderr.decode("utf-8", "replace"),
    )


def _run_proc_pty(cmd, tty_input, timeout):
    """Run cmd with a pty as stdin; pre-write tty_input to the master end.

    A line written to the pty master before the child reads it is delivered
    to the child's read because the kernel buffers the slave end. The parent
    closes its copy of the slave fd right after Popen so EOF propagates once
    the child is done. The master is closed after the child exits.
    """
    master_fd, slave_fd = pty.openpty()
    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            env=_OUTER_ENV,
            stdin=slave_fd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    finally:
        # Parent no longer needs the slave end; closing it here means the
        # child sees EOF after consuming whatever we wrote to the master.
        os.close(slave_fd)
    try:
        os.write(master_fd, tty_input.encode())
    except OSError:
        pass
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        stdout, stderr = proc.communicate()
        raise
    finally:
        try:
            os.close(master_fd)
        except OSError:
            pass
    return (
        proc.returncode,
        stdout.decode("utf-8", "replace"),
        stderr.decode("utf-8", "replace"),
    )


class FakeRoot:
    """A tmp_path-based scratch area to drive a single new-root namespace run.

    The constructor writes the pivot recipe into tmp_path/pivot.sh (mode 0755)
    and creates the stage and newroot directories underneath tmp_path. The
    helper methods exec commands inside `unshare -Urm bash pivot.sh ...` so
    the inner command sees a tmpfs-rooted filesystem owned by uid 0.

    Inside the namespace tmpfs is gone the moment the namespace exits, so
    there is no way to inspect /root afterwards from the host. To learn
    what /root contains after a command, prefix the argv with
    `FakeRoot.RUN_THEN_LIST` (a bash helper that runs the test's command and
    then `ls -A /root` to stdout before exiting).
    """

    RUN_THEN_LIST = ["bash", "-c", '"$@"; rc=$?; ls -A /root; exit $rc', "x"]

    def __init__(self, tmp_path: Path):
        self.base = Path(tmp_path)
        self.stage = Path(tmp_path) / "stage"
        self.newroot = Path(tmp_path) / "newroot"
        self.stage.mkdir(parents=True, exist_ok=True)
        self.newroot.mkdir(parents=True, exist_ok=True)
        self._pivot = Path(tmp_path) / "pivot.sh"
        self._pivot.write_text(PIVOT)
        self._pivot.chmod(0o755)

    def install_bootstrap(
        self,
        source: Path = SCRIPT,
        mode: int = 0o755,
        name: str = "newton-bootstrap",
        subdir: str = "usr/local/sbin",
    ) -> str:
        """Stage `source` as stage/<subdir>/<name>, chmod to `mode`.

        Returns the in-root path (`/<subdir>/<name>`) so callers can pass it
        to run() commands without re-deriving it.
        """
        dest_dir = self.stage / subdir
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / name
        shutil.copyfile(source, dest)
        dest.chmod(mode)
        return f"/{subdir}/{name}"

    def run(self, argv, env=None, tty_input=None, sbin_mode="755", timeout=60):
        """Run argv inside a fresh user+mount namespace with a new root.

        The OUTER environment is fixed (PATH, HOME, LANG only) so the test
        cannot accidentally inherit host variables. The optional `env` dict
        is applied INSIDE the namespace by prefixing `env KEY=VAL ...`.
        Keys whose value is None are dropped via `-u KEY`. If `tty_input` is
        given, the child is connected to a pty whose master has that text
        pre-written to it (callers should ensure it ends with a newline so
        the child bash's `read` returns a complete line).
        """
        inner = _build_inner(argv, env)
        cmd = [
            "unshare", "-Urm", "bash", str(self._pivot),
            str(self.newroot), str(self.stage), sbin_mode, *inner,
        ]
        if tty_input is None:
            return _run_proc(cmd, timeout)
        return _run_proc_pty(cmd, tty_input, timeout)

    def run_plain(self, argv, env=None, timeout=60):
        """Run argv under `unshare -Ur` WITHOUT pivoting into a new root.

        The host filesystem is left in place; only the uid mapping changes.
        Files that belong to uids not in the mapping (typically the real
        root) appear as uid 65534 (nobody/overflow) inside the namespace.
        """
        inner = _build_inner(argv, env)
        cmd = ["unshare", "-Ur", "--", *inner]
        return _run_proc(cmd, timeout)

    def run_nonroot(self, argv, env=None, timeout=60):
        """Run argv with no namespace, same outer env (PATH/HOME/LANG only)."""
        inner = _build_inner(argv, env)
        return _run_proc(inner, timeout)