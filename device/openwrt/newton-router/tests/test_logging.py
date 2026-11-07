"""Design 9.2 group 12 (3.11): one syslog line per call, nothing secret."""

import re

from conftest import SID, SYSLOG_PREFIX

SECRET = "S3cretMark"

LINE_RE = re.compile(
    r"^caller=\S+ door=(ssh|root) cmd=\S+ sid=\S+ rc=\d+ from=\S+$"
)
REJECTED_RE = re.compile(
    r"^caller=\S+ door=(ssh|root) cmd=- rejected=[a-z-]+ len=\d+ from=\S+$"
)


def one_syslog_line(router):
    raw = [
        line
        for line in router.calls(exclude=())
        if line.startswith("logger ")
    ]
    assert len(raw) == 1, raw
    assert raw[0].startswith(SYSLOG_PREFIX)
    return raw[0][len(SYSLOG_PREFIX):]


def test_success_line_shape(router):
    res = router.forced("hello 0123456789abcdef", role="read", timeout=15)
    assert res.rc == 0
    line = one_syslog_line(router)
    assert line == "caller=agent-one door=ssh cmd=hello sid=- rc=0 from=-"
    assert LINE_RE.match(line)


def test_success_direct_door(router):
    res = router.direct("hello", "0123456789abcdef", timeout=15)
    assert res.rc == 0
    assert one_syslog_line(router) == (
        "caller=root door=root cmd=hello sid=- rc=0 from=-"
    )


# ---- grammar-stage refusals: the rejected= form (design 3.11) ---------------


def test_rejected_bad_character(router):
    request = "hostname 'x"
    res = router.forced(request, timeout=15)
    assert res.rc == 2
    assert one_syslog_line(router) == (
        f"caller=agent-one door=ssh cmd=- rejected=bad-character "
        f"len={len(request)} from=-"
    )


def test_rejected_arg_count(router):
    request = "hostname x"
    res = router.forced(request, role="read", timeout=15)
    assert res.rc == 2
    line = one_syslog_line(router)
    assert line == (
        f"caller=agent-one door=ssh cmd=- rejected=arg-count "
        f"len={len(request)} from=-"
    )
    assert REJECTED_RE.match(line)


def test_rejected_bad_arg(router):
    request = "hello nothex"
    res = router.forced(request, role="read", timeout=15)
    assert res.rc == 2
    assert one_syslog_line(router) == (
        f"caller=agent-one door=ssh cmd=- rejected=bad-arg "
        f"len={len(request)} from=-"
    )


# ---- state refusals: the cmd=/sid=/rc= form (design 3.11) -------------------


def test_role_refusal_logged_without_request(router):
    res = router.forced("backup", role="read", timeout=15)
    assert res.rc == 3
    assert one_syslog_line(router) == (
        "caller=agent-one door=ssh cmd=backup sid=- rc=3 from=-"
    )


def test_no_such_txn_shows_only_first_8_hex(router):
    res = router.forced(f"seal {SID} 60", timeout=15)
    assert res.rc == 3
    line = one_syslog_line(router)
    assert line == (
        f"caller=agent-one door=ssh cmd=seal sid={SID[:8]} rc=3 from=-"
    )
    assert SID not in line
    assert SID[8:] not in line


# ---- secrets never reach the log (M42) --------------------------------------


def test_rejected_request_text_never_logged(router):
    request = f"hostname '{SECRET}-x"
    res = router.forced(request, timeout=15)
    assert res.rc == 2
    line = one_syslog_line(router)
    assert SECRET not in line
    assert SECRET not in res.out and SECRET not in res.err
    assert "hostname" not in line


def test_stdin_never_logged(router):
    res = router.forced("stage", stdin=f"uci batch {SECRET}\n".encode(), timeout=15)
    line = one_syslog_line(router)
    assert re.fullmatch(
        r"caller=agent-one door=ssh cmd=stage sid=- rc=\d+ from=-", line
    )
    assert SECRET not in line


def test_read_arguments_never_logged(router):
    res = router.forced("read uci show", role="read", timeout=15)
    line = one_syslog_line(router)
    assert re.fullmatch(
        r"caller=agent-one door=ssh cmd=read sid=- rc=\d+ from=-", line
    )
    assert "uci" not in line


# ---- from= follows SSH_CLIENT (design 2.6) ----------------------------------


def test_from_valid_address(router):
    res = router.forced(
        "hello 0123456789abcdef", role="read",
        env={"SSH_CLIENT": "192.0.2.9 51234 22"}, timeout=15,
    )
    assert res.rc == 0
    assert one_syslog_line(router).endswith("from=192.0.2.9")


def test_from_junk_is_dash(router):
    res = router.forced(
        "hello 0123456789abcdef", role="read",
        env={"SSH_CLIENT": "!!!junk 1 2"}, timeout=15,
    )
    assert res.rc == 0
    assert one_syslog_line(router).endswith("from=-")
