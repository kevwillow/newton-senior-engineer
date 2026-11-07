"""DEV-01: /tmp/newton must be a real directory owned by the program user.

A local non-root daemon (dnsmasq, logd, ntpd) can create /tmp/newton after
boot. `mkdir -p` plus `chmod 700` accepts that: chmod never changes the
owner, so the planted directory stays readable by the user that made it and
every scratch file written after the check is exposed. The program refuses
with `error internal tmp-owner` unless the path is a real directory whose
owner is the user running it, and the checks run in the design order
(design 3, v2 change 1): not a symlink, mkdir without -p, not a symlink
again, a directory, the owner from `ls -ldn`, and only then the mode.
"""

import os
import stat

from conftest import PROGRAM

NONCE = "0123456789abcdef"


def hello(router, timeout=20):
    """One direct hello call: it exercises the top-level code and nothing else."""
    return router.direct("hello", NONCE, timeout=timeout)


def mode_of(path):
    return stat.S_IMODE(os.lstat(str(path)).st_mode)


def names_in(path):
    return sorted(p.name for p in path.iterdir())


def plant_dir(router, mode):
    path = router.root / "tmp/newton"
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(str(path), mode)
    return path


# ---- 1. a symlink is refused and its target is never touched --------------


def test_symlinked_tmp_newton_is_refused_and_the_target_is_untouched(router):
    target = router.root / "tmp/elsewhere"
    target.mkdir()
    os.chmod(str(target), 0o755)
    (router.root / "tmp/newton").symlink_to(target)

    res = hello(router)

    assert res.rc == 1, (res.rc, res.out, res.err)
    assert res.err == "error internal tmp-owner\n"
    assert mode_of(target) == 0o755, "the symlink target was chmodded"
    assert names_in(target) == [], "a scratch file was written through the symlink"


# ---- 2. a regular file at the path is refused -----------------------------


def test_tmp_newton_that_is_a_regular_file_is_refused(router):
    path = router.root / "tmp/newton"
    path.write_text("planted\n")
    os.chmod(str(path), 0o644)

    res = hello(router)

    assert res.rc == 1, (res.rc, res.out, res.err)
    assert res.err == "error internal tmp-owner\n"
    assert path.read_text() == "planted\n"
    assert mode_of(path) == 0o644, "the planted file was chmodded"


# ---- 3. a directory owned by another uid is refused ------------------------


def test_tmp_newton_owned_by_another_uid_is_refused(router, tmp_path):
    """The uid of the running program is the only place the owner is learned,
    so a scratch program that reports a different uid stands in for a
    directory another local user created after boot (a test cannot chown)."""
    router.scratch_program(tmp_path, "id -u", "printf %s 4242")
    path = plant_dir(router, 0o755)

    res = hello(router)

    assert res.rc == 1, (res.rc, res.out, res.err)
    assert res.err == "error internal tmp-owner\n"
    assert mode_of(path) == 0o755, "the mode was tightened before the owner check"
    assert names_in(path) == [], "a scratch file was written into a foreign directory"


# ---- 4. our own directory is accepted and tightened ------------------------


def test_existing_tmp_newton_with_mode_0755_is_tightened(router):
    path = plant_dir(router, 0o755)

    res = hello(router)

    assert res.rc == 0, (res.rc, res.out, res.err)
    assert res.out.startswith(f"hello {NONCE} "), res.out
    assert mode_of(path) == 0o700


# ---- 5. a fresh path is created mode 0700 ----------------------------------


def test_fresh_tmp_newton_is_created_mode_0700(router):
    path = router.root / "tmp/newton"
    assert not path.exists()

    res = hello(router)

    assert res.rc == 0, (res.rc, res.out, res.err)
    assert path.is_dir()
    assert not path.is_symlink()
    assert mode_of(path) == 0o700


# ---- 6. the checks are in the design order --------------------------------


def test_the_owner_checks_run_in_the_design_order():
    text = PROGRAM.read_text()
    symlink_first = text.index('[ -h "$R/tmp/newton" ]')
    create = text.index('mkdir -m 700 "$R/tmp/newton"')
    symlink_second = text.index('[ -h "$R/tmp/newton" ]', create)
    directory = text.index('[ ! -d "$R/tmp/newton" ]', symlink_second)
    owner = text.index('ls -ldn "$R/tmp/newton"', directory)
    tighten = text.index('chmod 700 "$R/tmp/newton"', owner)
    assert symlink_first < create < symlink_second < directory < owner < tighten
    assert 'mkdir -p "$R/tmp/newton"' not in text
    assert "stat -c" not in text  # stock OpenWrt BusyBox has no stat applet


def test_the_owner_check_compares_against_the_program_uid():
    text = PROGRAM.read_text()
    assert 'id -u' in text, "the owner check does not read the running uid"
    assert '"$R/tmp/newton"' in text