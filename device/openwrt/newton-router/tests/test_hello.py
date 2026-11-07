"""Design 2.6: the hello line (fields, digests, environment, dead-man file)."""

import hashlib
import subprocess
from pathlib import Path

import pytest

from conftest import BUSYBOX, SID

NONCE = "0123456789abcdef"
KEYS = (
    "api version mode prog helper guard init device profile approval-key "
    "guard-state busy caller role door tty agent from"
).split()

CODE_FILES = {
    "prog": "usr/libexec/newton/newton-router",
    "helper": "usr/libexec/newton/newton-safe-apply",
    "guard": "usr/libexec/newton-guard",
    "init": "etc/init.d/newton-guard",
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def parse(res):
    lines = res.out.splitlines()
    assert len(lines) == 1, res.out
    tokens = lines[0].split()
    assert tokens[0] == "hello" and tokens[1] == NONCE
    pairs = [t.split("=", 1) for t in tokens[2:]]
    assert all(len(p) == 2 for p in pairs)
    return dict(pairs), [p[0] for p in pairs]


def hello(router, **kw):
    return router.forced(f"hello {NONCE}", role="read", **kw)


# ---- the whole line, exact field names and order ----------------------------


def test_all_fields_in_order_with_exact_values(router):
    res = hello(router, timeout=15)
    assert res.rc == 0
    fields, keys = parse(res)
    assert keys == KEYS
    assert fields["api"] == "1"
    assert fields["version"] == "1.3.0"
    assert fields["mode"] == "test"
    for name, rel in CODE_FILES.items():
        assert fields[name] == sha(router.root / rel), name
    assert fields["device"] == "lab-r1"
    assert fields["profile"] == "lab"
    assert fields["approval-key"] == "present"
    assert fields["guard-state"] == "idle"
    assert fields["busy"] == "-"
    assert fields["caller"] == "agent-one"
    assert fields["role"] == "read"
    assert fields["door"] == "ssh"
    assert fields["tty"] == "0"
    assert fields["agent"] == "0"
    assert fields["from"] == "-"


@pytest.mark.parametrize("name", list(CODE_FILES), ids=list(CODE_FILES))
def test_missing_code_file(router, name):
    path = router.root / CODE_FILES[name]
    path.unlink()
    res = hello(router, timeout=15)
    assert res.rc == 1
    fields, _ = parse(res)
    assert fields[name] == "missing"
    for other, rel in CODE_FILES.items():
        if other != name:
            assert fields[other] == sha(router.root / rel)


# ---- device and profile ------------------------------------------------------


@pytest.mark.parametrize(
    "content,expected",
    [(None, "-"), ("router#1\n", "router#1")],
    ids=["device-missing", "device-junk"],
)
def test_device_field(router, content, expected):
    path = router.root / "etc/newton/device-id"
    if content is None:
        path.unlink()
    else:
        path.write_text(content)
    fields, _ = parse(hello(router, timeout=15))
    assert fields["device"] == expected


# etc/newton/device-id is operator-written and may lack a trailing newline;
# BusyBox `read` returns rc=1 in that case but has set the variable, and the
# old `|| device=-` then cleared it. The hello line must report the value.
def test_device_field_no_trailing_newline(router):
    router.write("etc/newton/device-id", b"router#1")
    fields, _ = parse(hello(router, timeout=15))
    assert fields["device"] == "router#1"


def test_device_unreadable(router):
    if subprocess.run(["id", "-u"], capture_output=True, text=True).stdout.strip() == "0":
        pytest.skip("running as real root: unreadable file is still readable")
    (router.root / "etc/newton/device-id").chmod(0o000)
    fields, _ = parse(hello(router, timeout=15))
    assert fields["device"] == "-"


@pytest.mark.parametrize(
    "content,expected",
    [(None, "prod"), ("garbage\n", "prod"), ("lab\n", "lab"), ("prod\n", "prod")],
    ids=["profile-missing", "profile-junk", "profile-lab", "profile-prod"],
)
def test_profile_field(router, content, expected):
    path = router.root / "etc/newton/profile"
    if content is None:
        path.unlink()
    else:
        path.write_text(content)
    fields, _ = parse(hello(router, timeout=15))
    assert fields["profile"] == expected


# ---- approval-key ------------------------------------------------------------


@pytest.mark.parametrize(
    "content,expected",
    [
        ("0123456789abcdef" * 4 + "\n", "present"),
        ("0123456789abcdef" * 4 + "0123456789abcde"[:15] + "\n", "missing"),
        ("0123456789ABCDEF" * 4 + "\n", "missing"),
        (None, "missing"),
    ],
    ids=["key-64hex", "key-63hex", "key-upper", "key-missing"],
)
def test_approval_key_field(router, content, expected):
    path = router.root / "etc/newton/approve.key"
    if content is None:
        path.unlink()
    else:
        path.write_text(content)
    fields, _ = parse(hello(router, timeout=15))
    assert fields["approval-key"] == expected


# ---- guard-state (the real copied guard) -------------------------------------


def arm_guard(router, txn="txn-pending-1", timeout="60"):
    router.set_fake(
        "df",
        out=(
            "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
            "/dev/sda1 1000000 1000 999000 1% /etc\n"
        ),
    )
    res = subprocess.run(
        [BUSYBOX, "sh", str(router.root / "usr/libexec/newton-guard"),
         "arm", txn, timeout],
        capture_output=True,
        env={
            "PATH": "/usr/bin:/bin",
            "NEWTON_GUARD_ROOT": str(router.root),
            "NEWTON_ROUTER_ROOT": str(router.root),
        },
        timeout=30,
    )
    assert res.returncode == 0 and res.stdout.startswith(b"armed"), res.stderr


def test_guard_state_idle(router):
    fields, _ = parse(hello(router, timeout=15))
    assert fields["guard-state"] == "idle"


def test_guard_state_pending_after_real_arm(router):
    arm_guard(router)
    fields, _ = parse(hello(router, timeout=15))
    assert fields["guard-state"] == "pending"


def test_guard_state_failed(router):
    router.write("etc/newton/pending", "txn-x 9999 boot-one\n")
    router.write("etc/newton/failed", "txn-x rollback-failed\n")
    fields, _ = parse(hello(router, timeout=15))
    assert fields["guard-state"] == "failed"


# ---- busy ---------------------------------------------------------------------


def make_live_txn(router, owner="agent-one"):
    lock = router.root / "tmp/owrt-safe-apply.lock"
    txn = lock / f"{SID}.txn"
    txn.mkdir(parents=True)
    (lock / "sid").write_text(SID + "\n")
    if owner is not None:
        (txn / "owner").write_text(owner + "\n")


def test_busy_owner_label_of_live_txn(router):
    make_live_txn(router)
    fields, _ = parse(hello(router, timeout=15))
    assert fields["busy"] == "agent-one"


def test_busy_question_mark_without_owner_file(router):
    make_live_txn(router, owner=None)
    fields, _ = parse(hello(router, timeout=15))
    assert fields["busy"] == "?"


def test_busy_dash_when_session_not_live(router):
    make_live_txn(router)
    router.set_fake("ubus", rc=1)
    fields, _ = parse(hello(router, timeout=15))
    assert fields["busy"] == "-"


# ---- caller/role/door, tty, agent, from ---------------------------------------


def test_direct_mode_fields(router):
    fields, _ = parse(router.direct("hello", NONCE, timeout=15))
    assert fields["caller"] == "root"
    assert fields["role"] == "change"
    assert fields["door"] == "root"


def test_forced_mode_fields(router):
    res = router.forced(f"hello {NONCE}", role="read", caller="agent-two", timeout=15)
    fields, _ = parse(res)
    assert (fields["caller"], fields["role"], fields["door"]) == (
        "agent-two", "read", "ssh")


def test_tty_one_with_pty_stdin(router):
    fields, _ = parse(router.direct_pty("hello", NONCE))
    assert fields["tty"] == "1"


def test_agent_field(router):
    fields, _ = parse(hello(router, env={"SSH_AUTH_SOCK": "/run/agent.sock"}, timeout=15))
    assert fields["agent"] == "1"
    fields, _ = parse(hello(router, env={"SSH_AUTH_SOCK": ""}, timeout=15))
    assert fields["agent"] == "0"
    fields, _ = parse(hello(router, env={"SSH_AUTH_SOCK": None}, timeout=15))
    assert fields["agent"] == "0"


def test_from_field(router):
    fields, _ = parse(
        hello(router, env={"SSH_CLIENT": "2001:db8::1 51234 22"}, timeout=15))
    assert fields["from"] == "2001:db8::1"
    fields, _ = parse(hello(router, env={"SSH_CLIENT": "not-addr 1 2"}, timeout=15))
    assert fields["from"] == "-"


# ---- the dead-man file (forced mode only) -------------------------------------


def hello_file(router):
    return router.root / "tmp/newton/hello"


def test_forced_hello_appends_nonce_caller_uptime(router):
    res = hello(router, timeout=15)
    assert res.rc == 0
    assert hello_file(router).read_text() == f"{NONCE} agent-one 100\n"


def test_direct_hello_writes_nothing(router):
    res = router.direct("hello", NONCE, timeout=15)
    assert res.rc == 0
    assert not hello_file(router).exists()


def test_later_hello_keeps_earlier_line(router):
    router.forced("hello aaaaaaaaaaaaaaaa", caller="agent-two", timeout=15)
    router.forced("hello bbbbbbbbbbbbbbbb", caller="agent-three", timeout=15)
    lines = hello_file(router).read_text().splitlines()
    assert lines == ["aaaaaaaaaaaaaaaa agent-two 100", "bbbbbbbbbbbbbbbb agent-three 100"]


def test_hello_file_keeps_last_64_lines(router):
    f = hello_file(router)
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("".join(f"old-{i:02d} c{i:02d} {i}\n" for i in range(1, 71)))
    res = hello(router, timeout=15)
    assert res.rc == 0
    lines = f.read_text().splitlines()
    assert len(lines) == 64
    assert lines[0] == "old-08 c08 8"
    assert lines[-1] == f"{NONCE} agent-one 100"
