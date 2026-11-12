"""The rpcd session folder (the rpcd change d99f703).

rpcd stopped naming a session's staged changes folder after the session
id: the folder is now ``uci-<32 hex>`` and no ubus call returns it. The
helper finds the folder with a marker (one probe section, added to the
session and taken back out again), records it in ``$LOCK/<SID>.dir`` and
reads it from there for every later step.

These tests run the REAL helper against the fakes, which model both rpcd
behaviours:

  * "old": the folder is ``uci-<SID>``;
  * "new": the folder is ``uci-<32 hex>``, made on the first ``uci add``,
    and only that folder holds the staged changes.

What is proved here:

  * stage, diff, apply and confirm work under both rpcd versions, and
    the change is kept by the confirm;
  * an apply whose confirm is withheld reverts (hard rule 6);
  * the lookup refuses (and stages nothing) when the marker is in no
    folder, in two folders, in a folder whose name is not one of rpcd's
    own, when the section name is malformed, or when the revert left the
    marker behind;
  * a stale session that holds the same probe name makes the lookup
    refuse, and the lookup works again once that session is gone;
  * the abort removes the recorded folder and the record, and a
    transaction without a record (staged by an older Newton) still falls
    back to the folder named after the session id;
  * a record that holds a path outside the pattern is refused before any
    ``uci -P`` or ``rm -rf`` uses it: the WHOLE path must be
    ``/var/run/rpcd/uci-`` and 32 hex characters;
  * the record of the folder must be written and read back, or the stage
    fails and nothing is staged;
  * the helper drops NEWTON_RPCD_ROOT on its production path, so only
    the test harness can set it.
"""

import json
import os
import re
import subprocess
from pathlib import Path

import pytest

from conftest import SID

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
HELPER = REPO / "scripts" / "owrt-safe-apply.sh"
BUSYBOX = "/usr/bin/busybox"
BATCH = b"set dhcp.cfg01.domain=lan\n"
RECORD_RE = re.compile(r"^/var/run/rpcd/uci-[0-9a-f]{32}$")
STAGED_LINE = "option domain 'lan'"

#: A session that is still alive and holds a probe of its own.
STALE = "aaaabbbbccccddddeeeeffff00001111"

#: Records that are not one of rpcd's own folders.  The whole path must
#: be /var/run/rpcd/uci- and exactly 32 hex characters: no "..", no extra
#: component, no trailing slash, no name that is too short or too long.
BAD_RECORDS = (
    "/var/run/rpcd/uci-x/../../../tmp/uci-" + "a" * 32,
    "/var/run/rpcd/../../tmp/uci-" + "a" * 32,
    "/var/run/rpcd/uci-" + "a" * 32 + "/",
    "/var/run/rpcd/uci-" + "a" * 32 + "/system",
    "/var/run/rpcd/uci-" + "a" * 31,
    "/var/run/rpcd/uci-" + "a" * 33,
    "/var/run/rpcd/uci-" + "g" * 32,
    "/var/run/rpcd/uci-" + "a" * 31 + "/../uci-" + "b" * 32,
)


# ---- the harness ---------------------------------------------------------


def rpcd(router, mode="new"):
    """The rpcd model, the fakes of it, and the tools the helper needs."""
    router.use_rpcd(mode)
    router.write("control/next-sid", SID + "\n")
    # md5sum: the helper hashes the config before and after staging
    router.write(
        "bin/md5sum",
        '#!/usr/bin/busybox sh\nexec /usr/bin/busybox md5sum "$@"\n',
        mode=0o755,
    )


def helper(router, *args, stdin=b"", timeout=60):
    """Run the real helper against the fake router."""
    env = {
        "PATH": str(router.root / "bin") + ":/usr/bin:/bin",
        "NEWTON_ROUTER_ROOT": str(router.root),
        "NEWTON_LOCK": str(router.root / "tmp/owrt-safe-apply.lock"),
        "NEWTON_RPCD_ROOT": str(router.root),
        "NEWTON_CONFIG_DIR": str(router.root / "etc/config"),
        "LC_ALL": "C",
    }
    return subprocess.run(
        [BUSYBOX, "sh", str(HELPER)] + [str(a) for a in args],
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        timeout=timeout,
    )


def record_path(router, sid=SID):
    return router.root / "tmp/owrt-safe-apply.lock" / f"{sid}.dir"


def recorded(router, sid=SID):
    """The folder the transaction recorded, as the router sees it."""
    text = record_path(router, sid).read_text().strip()
    assert RECORD_RE.match(text), text
    return router.root / text.lstrip("/")


def stage(router, mode="new"):
    """Stage the batch; returns the session id."""
    rpcd(router, mode)
    res = helper(router, "stage", stdin=BATCH)
    assert res.returncode == 0, (res.stdout, res.stderr)
    sid = res.stdout.decode().strip()
    assert sid == SID, res.stdout
    return sid


def dhcp(router):
    return (router.root / "etc/config/dhcp").read_text()


def _files(base):
    """The text of every file under a directory (empty when it is not there)."""
    if not base.is_dir():
        return []
    return [path.read_text() for path in base.rglob("*") if path.is_file()]


# ---- the happy path -----------------------------------------------------


@pytest.mark.parametrize("mode", ["new", "old"])
def test_stage_diff_apply_confirm(router, mode):
    """Stage, diff, apply and confirm: the change is visible, the apply
    succeeds and the confirm keeps it."""
    sid = stage(router, mode)

    # the folder is recorded, and it is one of rpcd's own
    folder = recorded(router, sid)
    assert folder.is_dir(), folder
    if mode == "new":
        # rpcd d99f703: the folder is not named after the session id
        assert folder.name != f"uci-{sid}"
    else:
        assert folder.name == f"uci-{sid}"

    # the diff shows the staged change
    res = helper(router, "diff", sid)
    assert res.returncode == 0, res.stderr
    assert "dhcp.cfg01.domain" in res.stdout.decode(), res.stdout

    # the apply succeeds and the change reaches /etc/config
    res = helper(router, "apply", sid, "60")
    assert res.returncode == 0, (res.stdout, res.stderr)
    assert STAGED_LINE in dhcp(router), dhcp(router)

    # the confirm keeps the change and cleans up
    res = helper(router, "confirm", sid)
    assert res.returncode == 0, (res.stdout, res.stderr)
    assert STAGED_LINE in dhcp(router), dhcp(router)
    assert not folder.exists(), folder
    assert not record_path(router, sid).exists()


@pytest.mark.parametrize("mode", ["new", "old"])
def test_apply_without_confirm_reverts(router, mode):
    """The apply is armed with a rollback and the confirm is withheld:
    the change is taken back (hard rule 6)."""
    sid = stage(router, mode)
    res = helper(router, "apply", sid, "60")
    assert res.returncode == 0, (res.stdout, res.stderr)
    assert STAGED_LINE in dhcp(router), dhcp(router)

    # the rollback timer runs out: the fake rpcd puts the config back
    router.set_uptime(200)
    assert router.rpcd_tick() == 0
    assert STAGED_LINE not in dhcp(router), dhcp(router)


# ---- the lookup refuses -------------------------------------------------


@pytest.mark.parametrize(
    "fault",
    [
        "rpcd-no-folder",       # the marker is in no folder
        "rpcd-extra-folder",    # the marker is in two folders
        "rpcd-bad-folder",      # the folder name is not one of rpcd's own
        "rpcd-revert-keeps",    # the revert left the marker behind
    ],
    ids=["no-folder", "two-folders", "bad-folder-name", "marker-left-behind"],
)
def test_the_lookup_refuses_and_stages_nothing(router, fault):
    """Every fault of the lookup refuses the stage: the session is
    destroyed, nothing is staged and /etc/config is untouched."""
    rpcd(router, "new")
    router.write(f"control/{fault}", "")
    res = helper(router, "stage", stdin=BATCH)
    assert res.returncode != 0, res.stdout
    assert b"could not locate the rpcd session folder" in res.stderr, res.stderr
    # nothing is staged and no record is left behind
    assert not record_path(router).exists()
    assert not any("dhcp.cfg01.domain" in text
                   for text in _files(router.root / "var/run/rpcd"))
    # the session is destroyed
    sessions = (router.root / "control/sessions").read_text().split()
    assert SID not in sessions, sessions
    # /etc/config is untouched
    assert STAGED_LINE not in dhcp(router), dhcp(router)


def test_the_lookup_refuses_a_malformed_section_name(router):
    """A section name that is not a section name is refused."""
    rpcd(router, "new")
    router.write("control/rpcd-add.section", "bad name!")
    res = helper(router, "stage", stdin=BATCH)
    assert res.returncode != 0, res.stdout
    assert b"could not locate the rpcd session folder" in res.stderr, res.stderr
    assert not record_path(router).exists()
    assert STAGED_LINE not in dhcp(router), dhcp(router)


def test_the_lookup_refuses_a_section_name_that_is_too_long(router):
    """A section name of more than 64 characters is refused."""
    rpcd(router, "new")
    router.write("control/rpcd-add.section", "a" * 65)
    res = helper(router, "stage", stdin=BATCH)
    assert res.returncode != 0, res.stdout
    assert b"could not locate the rpcd session folder" in res.stderr, res.stderr
    assert not record_path(router).exists()


# ---- a stale session with the same probe name ----------------------------


def destroy_session(router, sid):
    """Destroy a session the way rpcd does: the session and its folder go."""
    subprocess.run(
        [
            str(router.root / "bin/ubus"),
            "call",
            "session",
            "destroy",
            '{"ubus_rpc_session":"%s"}' % sid,
        ],
        env={
            "NEWTON_ROUTER_ROOT": str(router.root),
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
        },
        capture_output=True,
        timeout=30,
        check=True,
    )


def stale_session(router):
    """A session that is still alive and holds a probe of its own."""
    router.write("control/rpcd-stale-session", STALE + "\n")
    sessions = (router.root / "control/sessions").read_text()
    (router.root / "control/sessions").write_text(sessions + STALE + "\n")


def test_a_stale_session_with_the_same_probe_makes_the_lookup_refuse(router):
    """Libuci names an anonymous section from the index it got plus a hash
    of the type, so two sessions can hold the same probe name.  The
    marker is then in two folders and the lookup refuses."""
    rpcd(router, "new")
    stale_session(router)
    res = helper(router, "stage", stdin=BATCH)
    assert res.returncode != 0, res.stdout
    assert b"could not locate the rpcd session folder" in res.stderr, res.stderr
    # nothing is staged and no record is left behind
    assert not record_path(router).exists()
    assert not any("dhcp.cfg01.domain" in text
                   for text in _files(router.root / "var/run/rpcd"))


def test_the_lookup_works_again_once_the_stale_session_is_gone(router):
    """The stale session is destroyed: rpcd takes its folder with it, and
    the next lookup finds the folder of the new session."""
    rpcd(router, "new")
    stale_session(router)
    res = helper(router, "stage", stdin=BATCH)
    assert res.returncode != 0, res.stdout

    destroy_session(router, STALE)

    res = helper(router, "stage", stdin=BATCH)
    assert res.returncode == 0, (res.stdout, res.stderr)
    sid = res.stdout.decode().strip()
    assert sid == SID, res.stdout
    assert recorded(router, sid).is_dir()


# ---- the record ---------------------------------------------------------


def test_the_abort_removes_the_recorded_folder_and_the_record(router):
    """The abort removes the folder the transaction recorded and the
    record itself."""
    sid = stage(router, "new")
    folder = recorded(router, sid)
    res = helper(router, "abort", sid)
    assert res.returncode == 0, (res.stdout, res.stderr)
    assert not folder.exists(), folder
    assert not record_path(router, sid).exists()


def test_the_abort_of_a_transaction_without_a_record_falls_back(router):
    """A transaction staged by an older Newton has no record: the abort
    still cleans the folder it used."""
    sid = stage(router, "old")
    old_folder = router.root / "var/run/rpcd" / f"uci-{sid}"
    assert old_folder.is_dir(), old_folder
    record_path(router, sid).unlink()
    res = helper(router, "abort", sid)
    assert res.returncode == 0, (res.stdout, res.stderr)
    assert not old_folder.exists(), old_folder


def test_a_record_outside_the_pattern_is_refused(router):
    """A record that holds a path outside the pattern is refused before
    any ``uci -P`` or ``rm -rf`` uses it."""
    sid = stage(router, "new")
    record_path(router, sid).write_text("/etc\n")

    # the diff refuses and never hands the path to uci
    res = helper(router, "diff", sid)
    assert res.returncode != 0, res.stdout
    assert b"could not locate the rpcd session folder" in res.stderr, res.stderr
    assert not any("-P /etc" in c for c in router.calls()), router.calls()

    # the abort refuses too, and /etc is still there
    before = dhcp(router)
    res = helper(router, "abort", sid)
    assert res.returncode == 0, (res.stdout, res.stderr)
    assert dhcp(router) == before
    assert (router.root / "etc/config").is_dir()
    assert not any("-P /etc" in c for c in router.calls()), router.calls()


def test_a_record_outside_the_pattern_is_refused_by_the_program(router):
    """The program reads the record too, and refuses a path that is not
    one of rpcd's own."""
    router.use_stub_helper()
    router.use_leash_uci()
    router.write("control/diff.txt", b"firewall.cfg0a1b2c=rule\n")
    router.write(
        "control/uci.json",
        json.dumps({"changes": ["firewall.cfg0a1b2c=rule"], "staged": {},
                    "committed": {}}),
    )
    lock = router.root / "tmp/owrt-safe-apply.lock"
    txn = lock / f"{SID}.txn"
    txn.mkdir(parents=True, exist_ok=True)
    (txn / "owner").write_text("agent-one\n")
    (txn / "stage-up").write_text("100\n")
    (txn / "boot").write_text("boot-one\n")
    (lock / "sid").write_text(SID + "\n")
    (lock / f"{SID}.dir").write_text("/etc\n")
    router.write("control/sessions", SID + "\n")

    res = router.seal(SID, 90)
    assert res.rc != 0, (res.rc, res.out, res.err)
    assert "rpcd-dir" in res.err, res.err
    assert not any("-P /etc" in c for c in router.calls()), router.calls()


@pytest.mark.parametrize("record", BAD_RECORDS)
def test_a_record_with_more_than_the_pattern_is_refused(router, record):
    """The whole path must be /var/run/rpcd/uci- and 32 hex characters.

    A record that holds more than that (a "..", another component, a
    trailing slash, a name that is too short or too long) is refused
    before any ``uci -P`` or ``rm -rf`` uses it.
    """
    sid = stage(router, "new")
    # the path the record points at, as this host sees it
    target = router.root / os.path.normpath(record).lstrip("/")
    target.mkdir(parents=True, exist_ok=True)
    (target / "keep").write_text("keep\n")
    record_path(router, sid).write_text(record + "\n")

    # the diff refuses and never hands the path to uci
    res = helper(router, "diff", sid)
    assert res.returncode != 0, res.stdout
    assert b"could not locate the rpcd session folder" in res.stderr, res.stderr
    assert not any(record in c for c in router.calls()), router.calls()

    # the abort refuses too: the path outside the pattern is not removed
    res = helper(router, "abort", sid)
    assert res.returncode == 0, (res.stdout, res.stderr)
    assert (target / "keep").exists(), target


@pytest.mark.parametrize("record", BAD_RECORDS)
def test_the_program_refuses_a_record_with_more_than_the_pattern(router, record):
    """The program reads the record too: a path that is not one of rpcd's
    own folders is refused before it is used."""
    router.use_stub_helper()
    router.use_leash_uci()
    router.write("control/diff.txt", b"firewall.cfg0a1b2c=rule\n")
    router.write(
        "control/uci.json",
        json.dumps({"changes": ["firewall.cfg0a1b2c=rule"], "staged": {},
                    "committed": {}}),
    )
    lock = router.root / "tmp/owrt-safe-apply.lock"
    txn = lock / f"{SID}.txn"
    txn.mkdir(parents=True, exist_ok=True)
    (txn / "owner").write_text("agent-one\n")
    (txn / "stage-up").write_text("100\n")
    (txn / "boot").write_text("boot-one\n")
    (lock / "sid").write_text(SID + "\n")
    (lock / f"{SID}.dir").write_text(record + "\n")
    router.write("control/sessions", SID + "\n")

    res = router.seal(SID, 90)
    assert res.rc != 0, (res.rc, res.out, res.err)
    assert "rpcd-dir" in res.err, res.err
    assert not any(record in c for c in router.calls()), router.calls()


@pytest.mark.parametrize(
    "fault",
    ["rpcd-record-block", "rpcd-record-lies"],
    ids=["the-write-fails", "the-read-back-differs"],
)
def test_the_stage_fails_when_the_record_cannot_be_written(router, fault):
    """The record of the folder must be written and read back equal.

    When it is not (the write fails, or the read back says something
    else), the stage fails, the session is destroyed and nothing is
    staged.
    """
    rpcd(router, "new")
    router.write("control/%s" % fault, "")
    res = helper(router, "stage", stdin=BATCH)
    assert res.returncode != 0, res.stdout
    assert b"could not record the rpcd session folder" in res.stderr, res.stderr
    # the session is destroyed
    sessions = (router.root / "control/sessions").read_text().split()
    assert SID not in sessions, sessions
    # nothing is staged and no record is left behind
    assert not record_path(router).exists()
    assert not any("dhcp.cfg01.domain" in text
                   for text in _files(router.root / "var/run/rpcd"))
    assert STAGED_LINE not in dhcp(router), dhcp(router)


# ---- the production path --------------------------------------------------


def test_the_helper_drops_the_test_root_on_the_production_path(tmp_path):
    """The helper is installed as /usr/libexec/newton/newton-safe-apply.

    On that path it drops NEWTON_RPCD_ROOT, the way newton-router drops
    it in production, so only the test harness can set it.  The test runs
    the helper there: a chroot (a user namespace and a tmpfs) with the
    helper, busybox and a fake ubus that says which environment it was
    given.
    """
    probe = subprocess.run(
        ["unshare", "-rm", "true"], capture_output=True, text=True
    )
    if probe.returncode != 0:
        pytest.skip("no user namespaces")
    mnt = tmp_path / "mnt"
    mnt.mkdir()
    script = f"""
set -e
mount -t tmpfs tmpfs {mnt}
cd {mnt}
mkdir -p usr/libexec/newton bin etc/config tmp dev
cp /usr/bin/busybox bin/busybox
chmod 755 bin/busybox
/usr/bin/busybox chroot {mnt} /bin/busybox --install -s /bin
touch dev/null
mount --bind /dev/null dev/null || true
cp {HELPER} usr/libexec/newton/newton-safe-apply
cp {HELPER} tmp/helper.sh
chmod 755 usr/libexec/newton/newton-safe-apply tmp/helper.sh
printf 'config system\\n' > etc/config/system
cat > bin/ubus <<'EOF'
#!/bin/sh
printf 'RPCD_ROOT=%s\\n' "${{NEWTON_RPCD_ROOT-unset}}" >> /tmp/ubus.calls
exit 1
EOF
cat > bin/uci <<'EOF'
#!/bin/sh
exit 0
EOF
cat > bin/jsonfilter <<'EOF'
#!/bin/sh
cat >/dev/null
exit 1
EOF
chmod 755 bin/ubus bin/uci bin/jsonfilter
for path in /usr/libexec/newton/newton-safe-apply /tmp/helper.sh; do
  NEWTON_RPCD_ROOT=/tmp/rootfake NEWTON_LOCK=/tmp/lock PATH=/bin \\
    /usr/bin/busybox chroot {mnt} /bin/busybox sh "$path" stage </dev/null \\
    || echo "stage rc=$?"
done
cat {mnt}/tmp/ubus.calls
"""
    res = subprocess.run(
        ["unshare", "-rm", "/bin/sh", "-c", script],
        capture_output=True, text=True, timeout=120,
    )
    assert res.returncode == 0, res.stderr
    seen = [line for line in res.stdout.splitlines()
            if line.startswith("RPCD_ROOT=")]
    assert seen == ["RPCD_ROOT=unset", "RPCD_ROOT=/tmp/rootfake"], res.stdout


# ---- the program --------------------------------------------------------


def test_the_program_reads_the_recorded_folder(router):
    """The leash reads the folder the helper recorded, not one named after
    the session id."""
    router.use_leash_uci()
    other = "a" * 32
    router.write(
        "control/uci.json",
        json.dumps({"changes": ["firewall.cfg0a1b2c=rule"], "staged": {},
                    "committed": {}}),
    )
    lock = router.root / "tmp/owrt-safe-apply.lock"
    txn = lock / f"{SID}.txn"
    txn.mkdir(parents=True, exist_ok=True)
    (txn / "owner").write_text("agent-one\n")
    (txn / "stage-up").write_text("100\n")
    (txn / "boot").write_text("boot-one\n")
    (lock / "sid").write_text(SID + "\n")
    (lock / f"{SID}.dir").write_text(f"/var/run/rpcd/uci-{other}\n")
    router.write("control/sessions", SID + "\n")

    res = router.seal(SID, 90)
    assert res.rc == 0, (res.rc, res.out, res.err)
    calls = router.calls()
    assert any(f"uci -P {router.root}/var/run/rpcd/uci-{other} changes" in c
               for c in calls), calls
    assert not any(f"uci -P {router.root}/var/run/rpcd/uci-{SID} changes" in c
                   for c in calls), calls
