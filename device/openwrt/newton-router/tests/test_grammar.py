"""Design 9.2 group 2: the grammar table (grammar.tsv) against the program."""

import re
from pathlib import Path

import pytest

from conftest import SID

GRAMMAR = Path(__file__).resolve().parents[1] / "grammar.tsv"

BUILT = {"hello", "hostname", "backup", "fw-loaded", "logd-pid"}

# Independent class regexes, copied from design 3.3 (never read from the program).
CLASS_RE = {
    "sid": re.compile(r"[0-9a-f]{32}"),
    "t": re.compile(r"[1-9][0-9]{1,2}"),
    "dhcp": re.compile(r"[012]"),
    "fw": re.compile(r"[01]"),
    "hcmode": re.compile(r"after-rollback"),
    "nonce": re.compile(r"[0-9a-f]{16,64}"),
    "token": re.compile(r"none|[0-9a-f]{64}"),
    "epoch": re.compile(r"0|[1-9][0-9]{9}"),
    "cfg": re.compile(r"[a-z0-9_-]{1,32}"),
    "section": re.compile(
        r"([A-Za-z0-9_]{1,64}|@[A-Za-z0-9_-]{1,32}\[-?[0-9]{1,3}\])"
    ),
    "option": re.compile(r"[A-Za-z0-9_]{1,64}"),
    "iface": re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}"),
    "host": re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,252}"),
    "obj": re.compile(r"[a-z][a-z0-9_.-]{0,63}"),
    "nftfam": re.compile(r"inet|ip|ip6|arp|bridge|netdev"),
    "nftname": re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}"),
    "apkname": re.compile(r"[a-z0-9][a-z0-9_.+-]{0,63}"),
    "logpat": re.compile(r"[A-Za-z0-9_.:][A-Za-z0-9_.:-]{0,63}"),
    "lines": re.compile(r"[1-9][0-9]{0,4}"),
    "count": re.compile(r"[1-5]"),
    "table": re.compile(
        r"main|local|default|all|[0-9]{1,10}|[A-Za-z0-9_.@][A-Za-z0-9_.@-]{0,63}"
    ),
}

GRAMMAR_CODES = (
    "empty-request",
    "request-too-long",
    "bad-character",
    "bad-spacing",
    "too-many-tokens",
    "unknown-subcommand",
    "arg-count",
    "bad-arg",
)

CORPUS = [
    "0123456789ABCDEF",
    "a" * 15,
    "a" * 31,
    "a" * 33,
    "0" + "a" * 31,
    "-1",
    "+1",
    "0x10",
    ".",
    "..",
    "a/b",
    "@x",
    "[",
    "]",
    "-x",
    "--",
    "none",
    "NONE",
    "060",
    "0600",
    "99",
    "100",
    "0",
    "00",
    "a" * 300,
]


def load_rows():
    lines = GRAMMAR.read_text().splitlines()
    header = lines[0].split("\t")
    rows = []
    for line in lines[1:]:
        fields = line.split("\t")
        assert len(fields) == len(header), line
        row = dict(zip(header, fields))
        row["sub"] = row.pop("subcommand")
        row["argmin"] = int(row["argmin"])
        row["argmax"] = int(row["argmax"])
        row["args"] = row["sample"].split()[1:]
        rows.append(row)
    return rows


ROWS = load_rows()
BY_SUB = {row["sub"]: row for row in ROWS}


def class_ok(cls, token):
    matched = CLASS_RE[cls].fullmatch(token) is not None
    if cls == "t":
        return matched and 60 <= int(token) <= 600
    return matched


def role_for(row):
    return row["role"] if row["role"] in ("read", "change") else "read"


def expect_answer(row, mode):
    """(rc, stderr) a correct program gives a grammatical sample this round.

    None means the sample only has to get PAST the grammar stage: its first
    stderr line must not be a grammar-level refusal. Later rounds build the
    remaining subcommands one by one and their real answers replace the
    not-built placeholder, so exact answers are pinned only where they are
    already final.
    """
    if row["owner"] == "yes":
        return 3, "error no-such-txn\n"
    if row["sub"] == "approval-selftest":
        if mode == "forced":
            return 3, "error direct-only\n"
        return None
    if row["sub"] in BUILT:
        return 0, ""
    return None


# Grammar-level error codes (design 3.2/3.7): a grammatical sample must never
# produce one of these, whatever later rounds make the subcommand answer.
GRAMMAR_LEVEL_CODES = frozenset(
    {
        "empty-request",
        "request-too-long",
        "bad-character",
        "bad-spacing",
        "too-many-tokens",
        "unknown-subcommand",
        "arg-count",
        "bad-arg",
        "bad-key-line",
        "door-not-built",
        "bad-root",
        "role",
    }
)


def assert_not_grammar_level(res):
    """The request passed the grammar stage: no grammar-level refusal."""
    first = res.err.splitlines()[0] if res.err else ""
    m = re.match(r"error ([a-z-]+)", first)
    assert not (m and m.group(1) in GRAMMAR_LEVEL_CODES), (res.rc, res.err)


def adversarial_cases():
    cases = []
    for row in ROWS:
        if row["classes"] in ("-", "*"):
            continue
        classes = row["classes"].split()
        assert len(classes) == len(row["args"]), row["sub"]
        for pos, cls in enumerate(classes, 1):
            for token in CORPUS:
                if class_ok(cls, token):
                    continue
                label = token if len(token) <= 12 else f"{token[:3]}..x{len(token)}"
                cases.append((row["sub"], pos, token, f"{row['sub']}-{pos}-{label}"))
    return cases


ADVERSARIAL = adversarial_cases()


def test_table_shape():
    assert len(ROWS) == 25
    assert len(BY_SUB) == 25
    for row in ROWS:
        assert row["role"] in ("read", "change", "direct")
        assert row["owner"] in ("yes", "no", "special")
        assert 0 <= row["argmin"] <= row["argmax"] <= 15
        assert row["stdin"] in ("none", "uci-batch", "probe-lines", "probe-line")
        n = len(row["args"])
        assert row["argmin"] <= n <= row["argmax"], row["sub"]
        if row["classes"] in ("-", "*"):
            continue
        for pos, cls in enumerate(row["classes"].split(), 1):
            assert class_ok(cls, row["args"][pos - 1]), (row["sub"], pos)


@pytest.mark.parametrize("row", ROWS, ids=[r["sub"] for r in ROWS])
def test_sample_passes_grammar(router, row):
    expected = expect_answer(row, "forced")
    res = router.forced(row["sample"], role=role_for(row), timeout=15)
    if expected is None:
        assert_not_grammar_level(res)
    else:
        assert (res.rc, res.err) == expected, res.out
    expected = expect_answer(row, "direct")
    res = router.direct(*row["sample"].split(), timeout=15)
    if expected is None:
        assert_not_grammar_level(res)
    else:
        assert (res.rc, res.err) == expected, res.out
    if row["sub"] == "hello":
        assert res.out.startswith("hello 0123456789abcdef api=1 ")
    if row["sub"] == "fw-loaded":
        assert res.out in ("0\n", "1\n")


@pytest.mark.parametrize(
    "row", [r for r in ROWS if r["role"] == "change"], ids=[r["sub"] for r in ROWS if r["role"] == "change"]
)
def test_read_credential_refused_for_change_rows(router, row):
    res = router.forced(row["sample"], role="read", timeout=15)
    # fwrestart maps every refusal of its own to exit 2: the host reads 3 as
    # "firewall not loaded, left alone" (design 3.4, 3.5, 3.7)
    want_rc = 2 if row["sub"] == "fwrestart" else 3
    assert (res.rc, res.err, res.out) == (want_rc, "error role\n", "")
    res = router.direct(*row["sample"].split(), timeout=15)
    assert res.err != "error role\n"
    assert not re.match(r"error (arg-count|bad-arg|unknown-subcommand)", res.err)


@pytest.mark.parametrize(
    "row", [r for r in ROWS if r["classes"] not in ("-", "*")],
    ids=[r["sub"] for r in ROWS if r["classes"] not in ("-", "*")],
)
def test_one_argument_more_fails_arg_count(router, row):
    request = row["sample"] + " 0"
    res = router.forced(request, role=role_for(row), timeout=15)
    assert (res.rc, res.err, res.out) == (2, "error arg-count\n", "")
    res = router.direct(*(request.split()), timeout=15)
    assert (res.rc, res.err, res.out) == (2, "error arg-count\n", "")


@pytest.mark.parametrize(
    "row", [r for r in ROWS if len(r["args"]) - 1 < r["argmin"] and r["classes"] not in ("-", "*")],
    ids=[r["sub"] for r in ROWS if len(r["args"]) - 1 < r["argmin"] and r["classes"] not in ("-", "*")],
)
def test_one_argument_less_fails_arg_count(router, row):
    request = " ".join([row["sub"]] + row["args"][:-1])
    res = router.forced(request, role=role_for(row), timeout=15)
    assert (res.rc, res.err, res.out) == (2, "error arg-count\n", "")


@pytest.mark.parametrize("name", ["HELLO", "hell", "hello2"])
def test_unknown_subcommand(router, name):
    res = router.forced(name, role="change", timeout=15)
    assert (res.rc, res.err, res.out) == (2, "error unknown-subcommand\n", "")
    res = router.direct(name, timeout=15)
    assert (res.rc, res.err, res.out) == (2, "error unknown-subcommand\n", "")


@pytest.mark.parametrize("sub,pos,token,label", ADVERSARIAL, ids=[c[3] for c in ADVERSARIAL])
def test_adversarial_token_rejected_identically(router, sub, pos, token, label):
    row = BY_SUB[sub]
    args = list(row["args"])
    args[pos - 1] = token
    request = " ".join([sub] + args)
    forced = router.forced(request, role=role_for(row), timeout=15)
    expected = (2, f"error bad-arg {pos}\n", "")
    assert (forced.rc, forced.err, forced.out) == expected
    direct = router.direct(*request.split(), timeout=15)
    if len(token) > 255:
        # a 300-byte token is past the direct-mode per-token limit (design 3.2)
        assert (direct.rc, direct.err, direct.out) == (
            2,
            "error request-too-long\n",
            "",
        )
    else:
        assert (direct.rc, direct.err, direct.out) == expected
    assert direct.out == forced.out == ""


# ---- class boundaries (design 3.3) ---------------------------------------


@pytest.mark.parametrize("t", ["59", "060", "0600", "601", "99", "60", "600", "100"])
def test_t_boundaries(router, t):
    good = class_ok("t", t)
    res = router.forced(f"seal {SID} {t}", timeout=15)
    if good:
        assert (res.rc, res.err, res.out) == (3, "error no-such-txn\n", "")
    else:
        assert (res.rc, res.err, res.out) == (2, "error bad-arg 2\n", "")


@pytest.mark.parametrize(
    "sid,good",
    [
        ("0123456789abcdef0123456789abcde", False),
        ("0123456789abcdef0123456789abcdef", True),
        ("0123456789abcdef0123456789abcdef0", False),
        ("0123456789ABCDEF0123456789abcdef", False),
    ],
    ids=["sid31", "sid32", "sid33", "sid-upper"],
)
def test_sid_boundaries(router, sid, good):
    res = router.forced(f"status {sid}", role="read", timeout=15)
    if good:
        assert_not_grammar_level(res)
    else:
        assert (res.rc, res.err, res.out) == (2, "error bad-arg 1\n", "")


@pytest.mark.parametrize("fw", ["0", "1", "2", "01", "-1", "+"], ids=lambda v: f"fw{v}")
def test_fw_boundaries(router, fw):
    res = router.forced(f"fwrestart {fw}", timeout=15)
    if fw in ("0", "1"):
        assert_not_grammar_level(res)
    else:
        assert (res.rc, res.err, res.out) == (2, "error bad-arg 1\n", "")


@pytest.mark.parametrize("dhcp", ["0", "1", "2", "3", "01"], ids=lambda v: f"dhcp{v}")
def test_dhcp_boundaries(router, dhcp):
    res = router.forced(f"dns-dhcp-check {dhcp}", role="read", timeout=15)
    if dhcp in ("0", "1", "2"):
        assert_not_grammar_level(res)
    else:
        assert (res.rc, res.err, res.out) == (2, "error bad-arg 1\n", "")
    res = router.forced(f"verify {SID} {dhcp}", timeout=15)
    if dhcp in ("0", "1", "2"):
        assert (res.rc, res.err, res.out) == (3, "error no-such-txn\n", "")
    else:
        assert (res.rc, res.err, res.out) == (2, "error bad-arg 2\n", "")


@pytest.mark.parametrize(
    "nonce,good",
    [
        ("0123456789abcde", False),
        ("0123456789abcdef", True),
        ("0123456789abcdef" * 4, True),
        ("0123456789abcdef" * 4 + "0", False),
        ("0123456789ABCDEF", False),
    ],
    ids=["n15", "n16", "n64", "n65", "n-upper"],
)
def test_nonce_boundaries(router, nonce, good):
    res = router.forced(f"hello {nonce}", role="read", timeout=15)
    if good:
        assert res.rc == 0 and res.err == ""
        assert res.out.startswith(f"hello {nonce} ")
    else:
        assert (res.rc, res.err, res.out) == (2, "error bad-arg 1\n", "")


@pytest.mark.parametrize(
    "token,good",
    [
        ("none", True),
        ("NONE", False),
        ("0123456789abcdef" * 3 + "0123456789abcde", False),
        ("0123456789abcdef" * 4, True),
        ("0123456789abcdef" * 4 + "0", False),
    ],
    ids=["tk-none", "tk-NONE", "tk63", "tk64", "tk65"],
)
def test_token_boundaries(router, token, good):
    res = router.forced(f"apply {SID} 60 {token} 0 0", timeout=15)
    if good:
        # The token class accepts `none` or 64-hex; passing them with 0 0
        # triggers the v2 shape check (none->0 0 ok), the SID owner rule
        # (no txn), and the apply refuses with no-such-txn.
        assert (res.rc, res.err, res.out) == (3, "error no-such-txn\n", "")
    else:
        assert (res.rc, res.err, res.out) == (2, "error bad-arg 3\n", "")


@pytest.mark.parametrize(
    "epoch,good",
    [
        ("0", True),
        ("00", False),
        ("0000000000", False),
        ("01700000000", False),
        ("1700000000", True),
        ("1", False),
        ("170000000", False),
        ("17000000000", False),
        ("+1700000000", False),
        ("-1700000000", False),
    ],
    ids=[
        "ep-zero", "ep-double-zero", "ep-ten-zeros", "ep-leading-zero",
        "ep-ten-1-9", "ep-1digit", "ep-9digits", "ep-11digits",
        "ep-plus", "ep-minus",
    ],
)
def test_epoch_boundaries(router, epoch, good):
    """The `epoch` class accepts `0` or exactly 10 decimal digits starting with 1-9.
    Use a 64-hex token so NBF/EXP can be non-zero; the shape check is
    lazy for non-zero epochs because the grammar class is checked before
    cmd_apply reads state. With a valid epoch, the apply reaches no-such-txn
    (no txn for SID); with an invalid epoch, the grammar refuses bad-arg 4
    or bad-arg 5."""
    token = "0" * 64
    request = f"apply {SID} 60 {token} {epoch} {epoch}"
    res = router.forced(request, timeout=15)
    if good:
        # The grammar class accepts the epoch, so handle() proceeds past
        # bad-arg; with no txn for SID the apply reaches no-such-txn.
        assert res.err != "error bad-arg 4\n"
        assert res.err != "error bad-arg 5\n"
        # The 5-arg form passes grammar; downstream code refuses with no-such-txn.
        assert (res.rc, res.err) == (3, "error no-such-txn\n"), (
            res.rc, res.err, res.out
        )
    else:
        # The first invalid epoch is at position 4 (NBF), so bad-arg 4.
        assert (res.rc, res.err, res.out) == (2, "error bad-arg 4\n", "")


def test_apply_5_word_sample_passes_grammar(router):
    """The grammar.tsv apply row sample is now 5 words; it must pass the
    grammar stage (reach no-such-txn, which fires after the SID owner rule)."""
    request = "apply 0123456789abcdef0123456789abcdef 60 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 0 0"
    res = router.forced(request, timeout=15)
    assert (res.rc, res.err, res.out) == (3, "error no-such-txn\n", ""), (
        res.rc, res.err, res.out
    )


# ---- refusal precedence (design 3.2 order) --------------------------------


def test_arg_count_before_bad_arg(router):
    res = router.forced(f"seal notasid", timeout=15)
    assert (res.rc, res.err, res.out) == (2, "error arg-count\n", "")
    res = router.forced(f"apply {SID} 60", timeout=15)
    assert (res.rc, res.err, res.out) == (2, "error arg-count\n", "")
    # The apply argv grew from 3 to 5 user words; one more user word
    # (3 user words after `apply`) still falls below argmin=5 user words.
    res = router.forced(f"apply {SID} 60 none 0", timeout=15)
    assert (res.rc, res.err, res.out) == (2, "error arg-count\n", "")


def test_bad_arg_before_role(router):
    res = router.forced(f"seal notasid 60", role="read", timeout=15)
    assert (res.rc, res.err, res.out) == (2, "error bad-arg 1\n", "")
    res = router.forced(f"seal {SID} 59", role="read", timeout=15)
    assert (res.rc, res.err, res.out) == (2, "error bad-arg 2\n", "")


def test_role_before_owner(router):
    res = router.forced(f"seal {SID} 60", role="read", timeout=15)
    assert (res.rc, res.err, res.out) == (3, "error role\n", "")
    res = router.forced(f"confirm {SID}", role="read", timeout=15)
    assert (res.rc, res.err, res.out) == (3, "error role\n", "")


# ---- tool-missing: read_run exits 127, so the read row must declare 127 -----


def test_read_row_declares_127_for_tool_missing(router):
    """read_run exits 127 when the underlying tool is not on PATH (design
    3.5e); the `read` row's exit column must include 127 so the contract
    is honest. Both halves are pinned: the grammar row lists 127, and the
    program actually does exit 127 for a tool missing under the fake
    $R/bin. If the row ever drops 127 while read_run still exits 127, this
    test fails."""
    row = BY_SUB["read"]
    allowed = {int(x) for x in row["exit"].split(",")}
    assert 127 in allowed, (row["exit"], sorted(allowed))

    target = router.root / "bin" / "iwinfo"
    assert target.exists() or target.is_symlink()
    target.unlink()
    res = router.forced("read iwinfo", role="read", timeout=15)
    assert res.rc == 127, (res.rc, res.err)
    assert res.err == "error tool-missing iwinfo\n", (res.err, res.out)
    assert res.out == ""
    assert "/" not in res.err, res.err
