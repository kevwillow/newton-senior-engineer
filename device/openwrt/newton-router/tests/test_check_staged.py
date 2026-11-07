"""The `check-staged SID` verb and its helper.

The verb checks the STAGED firewall config without applying it: the helper renders the
ruleset with fw4's own template over the session's staged delta (a ucode wrapper that
points `uci.cursor` at the rpcd session dir) and asks `nft -c` about it. The program
prints exactly ONE line, which is all the host reads:

    fw4 pass | fw4 fail <detail> | fw4 running-fails <detail>
    | fw4 skipped-untouched | fw4 not-checked <reason>

Tests CS-01..CS-18. The fakes: `fw4`, `nft` replay canned rc/err (generic fake); `utpl`
renders a ruleset that carries every line of the savedir's `batch` file, which the fake
`uci -P DIR batch` writes, so a wrapper that ignores the session dir is detectable.
"""

import json
import re

import pytest

from conftest import SID

CS = f"check-staged {SID}"

FW_GOOD = [
    "firewall.cfg0a1b2c=rule",
    "firewall.cfg0a1b2c.name='allow-8443'",
    "firewall.cfg0a1b2c.dest_port='8443'",
]
NET_CHANGE = ["network.lan.ipaddr='192.168.9.1'"]
DHCP_CHANGE = ["dhcp.cfg01411c.domain='lan'"]
NFT_BAD_ERR = (
    "/dev/stdin:150:24-35: Error: Could not resolve protocol name\n"
    "\t\tmeta l4proto nosuchproto accept comment \"!fw4: bad\"\n"
    "\t\t             ^^^^^^^^^^^\n"
    "/dev/stdin:151: a fourth line that must not be shown\n"
)


def setup(router, changes, *, owner="agent-one", live=True):
    """Stub helper only for stage; check-staged falls through to the real helper."""
    router.use_leash_uci()
    router.write("control/uci.json", json.dumps({"changes": changes, "staged": {}, "committed": {}}))
    lock = router.root / "tmp/owrt-safe-apply.lock"
    txn = lock / f"{SID}.txn"
    txn.mkdir(parents=True, exist_ok=True)
    (txn / "owner").write_text(owner + "\n")
    (txn / "stage-up").write_text("100\n")
    (txn / "boot").write_text("boot-one\n")
    (lock / "sid").write_text(SID + "\n")
    router.write("control/sessions", (SID + "\n") if live else "")
    router.write("control/utpl.out", "table inet fw4 {\n}\n")


def run(router, **kw):
    return router.forced(CS, role="change", timeout=30, **kw)


def calls(router, name):
    return [c for c in router.calls() if c.split(" ", 1)[0] == name]


def one_line(res):
    assert res.rc == 0, (res.rc, res.out, res.err)
    assert res.out.endswith("\n") and res.out.count("\n") == 1, repr(res.out)
    return res.out.rstrip("\n")


def test_cs01_good_staged_firewall_passes(router):
    setup(router, FW_GOOD)
    assert one_line(run(router)) == "fw4 pass"
    # the staged ruleset went through nft -c, never a real load
    nft = calls(router, "nft")
    assert nft and all(c.startswith("nft -c -f ") for c in nft), nft
    assert len(calls(router, "utpl")) == 2  # the staged render and the canary render
    assert nft[0].endswith("/staged.nft"), nft  # what nft reads is the staged render, not the canary
    assert "canary" not in nft[0]


def test_cs02_bad_staged_firewall_fails_with_three_lines_joined(router):
    setup(router, FW_GOOD)
    router.set_fake("nft", err=NFT_BAD_ERR, rc=1)
    line = one_line(run(router))
    assert line.startswith("fw4 fail "), line
    assert "Could not resolve protocol name" in line
    assert "nosuchproto" in line and "^^^^" in line
    assert "fourth line" not in line  # first three lines only
    assert len(line) <= len("fw4 fail ") + 300


def test_cs03_running_config_already_fails(router):
    setup(router, FW_GOOD)
    router.set_fake("fw4", err="Section @rule[3] (x) is disabled, ignoring section\nreal problem here\n", rc=1)
    line = one_line(run(router))
    assert line == "fw4 running-fails real problem here", line
    assert not calls(router, "utpl"), "nothing is rendered when the running config fails"


def test_cs04_running_fails_even_when_firewall_untouched(router):
    setup(router, DHCP_CHANGE)
    router.set_fake("fw4", err="boom\n", rc=1)
    assert one_line(run(router)) == "fw4 running-fails boom"


def test_cs05_firewall_untouched_is_skipped(router):
    setup(router, DHCP_CHANGE)
    assert one_line(run(router)) == "fw4 skipped-untouched"
    assert not calls(router, "utpl") and not calls(router, "nft")


def test_cs06_network_only_is_not_checked_never_pass(router):
    setup(router, NET_CHANGE)
    assert one_line(run(router)) == "fw4 not-checked network-live-state"
    assert not calls(router, "utpl")


def test_cs07_network_plus_good_firewall_is_not_a_pass(router):
    setup(router, FW_GOOD + NET_CHANGE)
    assert one_line(run(router)) == "fw4 not-checked network-live-state"


def test_cs08_network_plus_bad_firewall_still_fails(router):
    setup(router, FW_GOOD + NET_CHANGE)
    router.set_fake("nft", err="Error: bad\n", rc=1)
    assert one_line(run(router)).startswith("fw4 fail Error: bad")


def test_cs09_session_gone_is_not_checked(router):
    setup(router, FW_GOOD, live=False)
    assert one_line(run(router)) == "fw4 not-checked session-gone"
    assert not calls(router, "nft")


def test_cs10_empty_delta_is_session_gone_never_pass(router):
    setup(router, [])
    assert one_line(run(router)) == "fw4 not-checked session-gone"


def test_cs11_wrapper_failure_is_not_checked(router):
    setup(router, FW_GOOD)
    router.set_fake("utpl", err="ucode: exception\n", rc=1)
    assert one_line(run(router)) == "fw4 not-checked wrapper-failed"
    assert not calls(router, "nft")


def test_cs12_wrapper_that_ignores_the_session_dir_is_never_a_pass(router):
    setup(router, FW_GOOD)
    router.write("control/utpl.ignore-savedir", "")
    assert one_line(run(router)) == "fw4 not-checked wrapper-unverified"
    assert not calls(router, "nft")


def test_cs13_no_fw4_binary(router):
    setup(router, FW_GOOD)
    (router.root / "bin/fw4").unlink()
    assert one_line(run(router)) == "fw4 not-checked no-fw4"


def test_cs14_nothing_is_applied_or_committed(router):
    setup(router, FW_GOOD)
    before = {p.name: p.read_bytes() for p in (router.root / "etc/config").iterdir()}
    run(router)
    after = {p.name: p.read_bytes() for p in (router.root / "etc/config").iterdir()}
    assert before == after
    for c in router.calls():
        assert not re.match(r"uci (-P \S+ )?(commit|import|revert)\b", c), c
        assert not re.match(r"ubus call uci (apply|confirm|rollback)", c), c
        assert not c.startswith(("fw4 reload", "fw4 start", "fw4 restart", "fw4 stop")), c
        assert not (c.startswith("nft") and not c.startswith("nft -c -f ")), c
    # the only fw4 call is the running check
    assert [c for c in calls(router, "fw4")] == ["fw4 check"]


def test_cs15_wrapper_points_at_the_session_dir_only(router):
    setup(router, FW_GOOD)
    run(router)
    wrappers = sorted((router.root / "control").glob("utpl.wrapper.*"))
    assert len(wrappers) == 2, wrappers
    first = wrappers[1].read_text()  # [0] is the canary render
    assert f'"/var/run/rpcd/uci-{SID}"' in first
    assert 'include("/usr/share/firewall4/main.uc")' in first
    assert "uci.cursor = function" in first
    assert all(c.startswith("utpl -S ") for c in calls(router, "utpl"))
    # no wrapper or temp dir is left behind
    assert not list((router.root / "tmp").glob("newton-chk.*"))


def test_cs16_temp_dir_removed_on_failure_paths(router):
    setup(router, FW_GOOD)
    router.set_fake("nft", err="Error: bad\n", rc=1)
    run(router)
    router.set_fake("utpl", rc=1)
    run(router)
    assert not list((router.root / "tmp").glob("newton-chk.*"))


def test_cs17_not_owner_is_refused(router):
    setup(router, FW_GOOD)
    res = router.forced(CS, role="change", caller="agent-two", timeout=30)
    assert res.rc == 3 and res.err.startswith("error not-owner"), (res.rc, res.err)


def test_cs18_read_role_is_refused(router):
    setup(router, FW_GOOD)
    res = router.forced(CS, role="read", timeout=30)
    assert res.rc != 0 and res.out == ""


# ---- the program is the boundary: one validated line, whatever the helper says ----


def stub_helper_answer(router, text, rc=0):
    helper = router.root / "usr/libexec/newton/newton-safe-apply"
    real = helper.with_name("newton-safe-apply.real")
    if not real.exists():
        helper.replace(real)
    router.write("control/check.answer", text)
    router.write(
        "usr/libexec/newton/newton-safe-apply",
        "#!/usr/bin/busybox sh\n"
        f'if [ "$1" = check-staged ]; then cat "$NEWTON_ROUTER_ROOT/control/check.answer"; exit {rc}; fi\n'
        f'exec /usr/bin/busybox sh "{real}" "$@"\n',
        mode=0o755,
    )


@pytest.mark.parametrize(
    "answer,expected",
    [
        ("fw4 pass\nfw4 fail extra\nmore\n", "fw4 not-checked bad-helper-output"),
        ("fw4 pass\n\n\n", "fw4 pass"),
        ("fw4 skipped-untouched\n", "fw4 skipped-untouched"),
        ("fw4 not-checked network-live-state\n", "fw4 not-checked network-live-state"),
        ("fw4 fail Error: x\nsecond line\n", "fw4 not-checked bad-helper-output"),
        ("fw4 running-fails y\n", "fw4 running-fails y"),
        ("fw4 fail a\x1b[31mb\x07c\n", "fw4 fail a[31mbc"),
        ("fw4 PASS\n", "fw4 not-checked bad-helper-output"),
        ("pass\n", "fw4 not-checked bad-helper-output"),
        ("fw4 pass extra\n", "fw4 not-checked bad-helper-output"),
        ("fw4 not-checked Bad_Reason\n", "fw4 not-checked bad-helper-output"),
        ("fw4 not-checked \n", "fw4 not-checked bad-helper-output"),
        ("fw4 not-checked " + "a" * 41 + "\n", "fw4 not-checked bad-helper-output"),
        ("fw4 fail \n", "fw4 not-checked bad-helper-output"),
        ("", "fw4 not-checked no-answer"),
        ("\n", "fw4 not-checked no-answer"),
    ],
)
def test_cs19_program_prints_one_validated_line(router, answer, expected):
    setup(router, FW_GOOD)
    stub_helper_answer(router, answer)
    assert one_line(run(router)) == expected


def test_cs20_overlong_detail_is_cut(router):
    setup(router, FW_GOOD)
    stub_helper_answer(router, "fw4 fail " + "x" * 5000 + "\n")
    line = one_line(run(router))
    assert line == "fw4 fail " + "x" * 300


def test_cs21_helper_failure_exit_is_not_checked(router):
    setup(router, FW_GOOD)
    stub_helper_answer(router, "", rc=1)
    assert one_line(run(router)) == "fw4 not-checked no-answer"


def test_cs22_helper_stderr_does_not_leak_to_stdout(router):
    setup(router, FW_GOOD)
    router.set_fake("fw4", err="secret-looking text\n", rc=0)
    res = run(router)
    assert "secret-looking" not in res.out


def test_cs23_empty_staged_render_is_never_a_pass(router):
    setup(router, FW_GOOD)
    router.write("control/utpl.empty-staged", "")
    assert one_line(run(router)) == "fw4 not-checked wrapper-failed"
    assert not calls(router, "nft")


def test_cs24_wireless_change_is_not_a_pass(router):
    setup(router, FW_GOOD + ["wireless.radio0.disabled='0'"])
    assert one_line(run(router)) == "fw4 not-checked network-live-state"


def test_cs25_extra_argument_is_refused(router):
    setup(router, FW_GOOD)
    res = router.forced(CS + " junk", role="change", timeout=30)
    assert res.rc != 0 and res.out == ""


def test_cs26_fail_detail_does_not_name_the_temp_dir(router):
    setup(router, FW_GOOD)
    router.set_fake("nft", err="/tmp/newton-chk.AbC123/staged.nft:112:16-26: Error: Could not resolve protocol name\n", rc=1)
    line = one_line(run(router))
    assert line.startswith("fw4 fail staged.nft:112:16-26: Error: Could not resolve"), line
    assert "newton-chk" not in line


@pytest.mark.parametrize("answer", ["fw4 pass\n", "fw4 skipped-untouched\n", "fw4 fail Error: x\n"])
def test_cs27_a_failed_helper_is_never_trusted(router, answer):
    """The helper's exit status counts, not only its first line."""
    setup(router, FW_GOOD)
    stub_helper_answer(router, answer, rc=1)
    assert one_line(run(router)) == "fw4 not-checked bad-helper-output"
