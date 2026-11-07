"""getter rows carry `why` and `expect`; every ok run reports a shape."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import newton_mcp.server as server
from newton_mcp.adapters import registry
from newton_mcp.adapters.getters import GetterError, load_getters
from newton_mcp.adapters.ssh_cli import MISMATCH_CAVEAT, shape_of

from test_getters import base_row, load_one

VENDORS = Path(__file__).parent / "fixtures" / "vendors"
PLATFORMS = ("iosxe", "fortios", "junos", "eos", "vyos", "routeros")
GOOD_WHY = "Shows the running software version."
GOOD_EXPECT = ["Version: VyOS"]

FAKE_SSH = r'''#!/usr/bin/env python3
import os
from pathlib import Path

payload = Path(os.environ["NEWTON_RECORDED_FIXTURE"]).read_bytes()
_marker, separator, body = payload.partition(b"\n")
if not separator:
    raise SystemExit("fixture has no marker line")
os.write(int(os.environ.get("NEWTON_RECORDED_FD", "1")), body)
raise SystemExit(int(os.environ.get("NEWTON_RECORDED_EXIT", "0")))
'''


def body_of(path: Path) -> str:
    """Return a fixture without its first marker line."""
    return path.read_text(encoding="utf-8").split("\n", 1)[1]


def row(**changes: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {"why": GOOD_WHY, "expect": list(GOOD_EXPECT)}
    fields.update(changes)
    return base_row(**fields)


def test_valid_row_exposes_why_and_token_expect(tmp_path: Path) -> None:
    """why and expect load; entries keep their source and alternatives."""
    getter = load_one(tmp_path, row(expect=["Version: VyOS", "up* || down*"]))["version"]
    assert getter.why == GOOD_WHY
    assert [e.source for e in getter.expect] == ["Version: VyOS", "up* || down*"]
    assert getter.expect[0].alternatives == (("Version:", "VyOS"),)
    assert getter.expect[1].alternatives == (("up*",), ("down*",))


BAD_ROWS = [
    ("why-missing", {"why": None}),
    ("expect-missing", {"expect": None}),
    ("why-type", {"why": 5}),
    ("why-empty", {"why": ""}),
    ("why-long", {"why": "a" * 161}),
    ("why-newline", {"why": "two\nlines"}),
    ("why-escape", {"why": "bad \x1b[0m"}),
    ("why-tab", {"why": "bad\ttab"}),
    ("expect-type", {"expect": "Version: VyOS"}),
    ("expect-empty-list", {"expect": []}),
    ("expect-five", {"expect": ["aa", "bb", "cc", "dd", "ee"]}),
    ("expect-item-type", {"expect": [1]}),
    ("expect-empty-item", {"expect": [""]}),
    ("expect-blank-item", {"expect": ["  "]}),
    ("expect-long", {"expect": ["a" * 201]}),
    ("expect-13-tokens", {"expect": ["a1 b1 c1 d1 e1 f1 g1 h1 i1 j1 k1 l1 m1"]}),
    ("expect-double-space", {"expect": ["Version:  VyOS"]}),
    ("expect-leading-space", {"expect": [" Version: VyOS"]}),
    ("expect-trailing-space", {"expect": ["Version: VyOS "]}),
    ("expect-tab", {"expect": ["Version:\tVyOS"]}),
    ("expect-newline", {"expect": ["Version:\nVyOS"]}),
    ("expect-control-char", {"expect": ["Version\x00"]}),
    ("expect-non-ascii", {"expect": ["Versi\u00f6n:"]}),
    ("expect-always-true-star", {"expect": ["*"]}),
    ("expect-always-true-stars", {"expect": ["* *"]}),
    ("expect-always-true-one-char-prefix", {"expect": ["a* *"]}),
    ("expect-always-true-one-char-literal", {"expect": ["a * *"]}),
    ("expect-alt-always-true", {"expect": ["Version: || *"]}),
    ("expect-star-prefix", {"expect": ["*x Version:"]}),
    ("expect-double-star", {"expect": ["Version:**"]}),
    ("expect-star-middle", {"expect": ["Ver*sion:"]}),
    ("expect-single-pipe", {"expect": ["Version: | VyOS"]}),
    ("expect-pipe-in-token", {"expect": ["Ver|sion:"]}),
    ("expect-triple-pipe", {"expect": ["Version: ||| VyOS"]}),
    ("expect-leading-alt", {"expect": ["|| Version:"]}),
    ("expect-trailing-alt", {"expect": ["Version: ||"]}),
    ("expect-empty-alt", {"expect": ["Version: || || Other:"]}),
    ("expect-glued-alt", {"expect": ["Version:||Other:"]}),
    ("success-marker-gone", {"success_marker": "x"}),
]


@pytest.mark.parametrize("label,changes", BAD_ROWS, ids=[b[0] for b in BAD_ROWS])
def test_loader_refuses_bad_why_and_expect(
    tmp_path: Path, label: str, changes: dict[str, Any]
) -> None:
    """missing, oversized, unsafe or malformed why/expect fail closed."""
    r = row()
    for key, value in changes.items():
        if value is None:
            del r[key]
        else:
            r[key] = value
    with pytest.raises(GetterError):
        load_one(tmp_path, r)


ACCEPTED = [
    "Version:",
    "Version: VyOS",
    "ge-* up",
    "Codes: * - *",
    "# * * by RouterOS",
    "chain=* || * chain=* || * * chain=*",
    ";;; || * ;;;",
    "ab* *",
    "x1 x2 x3 x4 x5 x6 x7 x8 x9 xa xb xc",
    "a" * 200,
]


@pytest.mark.parametrize("source", ACCEPTED)
def test_token_grammar_accepts(tmp_path: Path, source: str) -> None:
    """literals, `*`, `prefix*` and ` || ` alternatives load."""
    getter = load_one(tmp_path, row(expect=[source]))["version"]
    assert getter.expect[0].source == source


def test_matching_semantics(tmp_path: Path) -> None:
    """leading tokens, position by position, per line, any line."""
    def shape(expect: list[str], text: str) -> str:
        getter = load_one(tmp_path, row(expect=expect))["version"]
        return shape_of(getter, "ok", text)

    assert shape(["Version: VyOS"], "x\n  Version:\t  VyOS 1.4\ny") == "matched"
    assert shape(["Version: VyOS"], "Version: VyOS") == "matched"
    assert shape(["Version: VyOS"], "Version:") == "mismatch"          # too few tokens
    assert shape(["Version: VyOS"], "x Version: VyOS") == "mismatch"   # not leading
    assert shape(["Version: VyOS"], "Version: vyos") == "mismatch"     # case exact
    assert shape(["Version: VyOS"], "Version:\nVyOS") == "mismatch"    # per line
    assert shape(["Version: VyOS"], "Version: VyOSX") == "mismatch"    # exact token
    assert shape(["a1 *"], "a1 z") == "matched"
    assert shape(["a1 *"], "a1") == "mismatch"
    assert shape(["ab* z1"], "abcd z1") == "matched"
    assert shape(["ab* z1"], "ab z1") == "matched"
    assert shape(["ab* z1"], "a z1") == "mismatch"
    assert shape(["ab* z1"], "xab z1") == "mismatch"
    assert shape(["ab* z1 || cd* z2"], "cdx z2") == "matched"
    assert shape(["ab* z1 || cd* z2"], "cdx z1") == "mismatch"
    assert shape(["ab* z1 || cd* z2"], "abx z2") == "mismatch"
    # regex metacharacters are plain literal characters, never an engine
    assert shape(["^Version:"], "Version: x") == "mismatch"
    assert shape(["^Version:"], "^Version: x") == "matched"
    assert shape(["a.c1"], "abc1") == "mismatch"
    assert shape(["a.c1"], "a.c1") == "matched"
    # every entry must match some line, not necessarily the same line
    assert shape(["aa1", "bb2"], "bb2\naa1") == "matched"
    assert shape(["aa1", "bb2"], "aa1\naa1") == "mismatch"
    assert shape(["aa1", "bb2"], "bb2") == "mismatch"


def test_every_row_of_every_vendor_has_why_and_expect() -> None:
    """all six shipped files, enabled or not, document their rows."""
    for platform in PLATFORMS:
        getters = load_getters(platform)
        assert getters, platform
        for getter_id, getter in getters.items():
            assert 1 <= len(getter.why) <= 160, (platform, getter_id)
            assert getter.why.isprintable(), (platform, getter_id)
            assert 1 <= len(getter.expect) <= 4, (platform, getter_id)


def test_every_enabled_row_has_a_synthetic_fixture_that_matches() -> None:
    """each enabled row's synthetic fixture satisfies every expect."""
    checked = 0
    for platform in PLATFORMS:
        for getter_id, getter in load_getters(platform).items():
            path = VENDORS / platform / f"{getter_id}.txt"
            if not path.exists():
                assert not getter.enabled, (platform, getter_id)
                continue
            body = body_of(path)
            assert shape_of(getter, "ok", body) == "matched", (platform, getter_id)
            for entry in getter.expect:
                assert shape_of(replace(getter, expect=(entry,)), "ok", body) == "matched", (
                    platform,
                    getter_id,
                    entry.source,
                )
            checked += 1
    assert checked == 28


def test_every_recorded_capture_matches_its_expect() -> None:
    """lab captures (RouterOS CHR, VyOS) satisfy every expect line."""
    checked = 0
    for platform in ("routeros", "vyos"):
        getters = load_getters(platform)
        for path in sorted((VENDORS / platform / "recorded").glob("*.txt")):
            getter = getters.get(path.stem)
            if getter is None:
                continue  # error and paging captures are not getter bodies
            body = body_of(path)
            if body.strip() == "":
                continue  # an empty body is status empty, never shape-checked
            assert shape_of(getter, "ok", body) == "matched", (platform, path.stem)
            checked += 1
    assert checked >= 12


def test_junk_matches_no_enabled_row() -> None:
    """wrong-shaped text fails at least one expect on every row."""
    junk = "Hello world\nnothing documented here\n"
    for platform in PLATFORMS:
        for getter_id, getter in load_getters(platform).items():
            assert shape_of(getter, "ok", junk) == "mismatch", (platform, getter_id)


def test_shape_of_rules() -> None:
    """matched strips controls; non-ok statuses are not checked."""
    getter = load_getters("vyos")["version"]
    good = "Version:          VyOS 1.4\n"
    assert shape_of(getter, "ok", good) == "matched"
    assert shape_of(getter, "ok", "\x1b[1mVersion:\x1b[0m          VyOS 1.4\n") == "matched"
    assert shape_of(getter, "ok", "Invalid command: show\n") == "mismatch"
    for status in ("empty", "device_error", "timed_out", "unreachable", "auth_failed"):
        assert shape_of(getter, status, "junk") == "not_checked", status


@pytest.fixture
def run_fake(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Callable[..., dict[str, Any]]:
    fake_ssh = tmp_path / "fake-ssh"
    fake_ssh.write_text(FAKE_SSH, encoding="utf-8")
    fake_ssh.chmod(0o755)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(
        "192.0.2.31 ssh-ed25519 "
        "AAAAC3NzaC1lZDI1NTE5AAAAIFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n",
        encoding="utf-8",
    )
    device = server.Device(
        name="lab-vyos", platform="vyos", host="192.0.2.31", user="newton",
        experimental_readonly=True, lab=True, known_hosts=known_hosts,
    )
    monkeypatch.setenv("NEWTON_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(server, "SSH_BINARY", str(fake_ssh))
    monkeypatch.setattr(server, "_RUNNERS", {})
    monkeypatch.setattr(server, "_SEEN_IFACES", {})
    monkeypatch.setattr(server, "load_inventory", lambda: {device.name: device})

    def run(getter_id: str, body: str, exit_code: int = 0, fd: int = 1) -> dict[str, Any]:
        fixture = tmp_path / "body.txt"
        fixture.write_text("# synthetic\n" + body, encoding="utf-8")
        monkeypatch.setenv("NEWTON_RECORDED_FIXTURE", str(fixture))
        monkeypatch.setenv("NEWTON_RECORDED_EXIT", str(exit_code))
        monkeypatch.setenv("NEWTON_RECORDED_FD", str(fd))
        server._RUNNERS.clear()
        return server.newton_get_state(device=device.name, getter=getter_id)

    return run


def test_matched_shape_through_get_state(
    run_fake: Callable[..., dict[str, Any]],
) -> None:
    """a recorded VyOS body is ok, shape matched, no mismatch caveat."""
    body = body_of(VENDORS / "vyos" / "recorded" / "version.txt")
    result = run_fake("version", body)
    assert result["status"] == "ok"
    assert result["shape"] == "matched"
    assert MISMATCH_CAVEAT not in result["caveat"]


def test_wrong_shape_keeps_ok_and_adds_caveat(
    run_fake: Callable[..., dict[str, Any]],
) -> None:
    """right status, wrong shape: status stays ok, shape mismatch, caveat."""
    result = run_fake("version", "this box says hello\nand nothing else\n")
    assert result["status"] == "ok"
    assert result["shape"] == "mismatch"
    assert result["caveat"].endswith(MISMATCH_CAVEAT)
    assert result["caveat"].startswith(server.EXPERIMENTAL_CAVEAT)
    assert MISMATCH_CAVEAT == (
        "output did not match the documented shape; treat as unreliable"
    )


def test_error_and_empty_results_are_not_checked(
    run_fake: Callable[..., dict[str, Any]],
) -> None:
    """device_error and empty carry shape not_checked and no new caveat."""
    err = run_fake("version", "  Invalid command: show [bogus]\n", exit_code=1, fd=2)
    assert err["status"] == "device_error"
    assert err["shape"] == "not_checked"
    assert MISMATCH_CAVEAT not in err["caveat"]
    empty = run_fake("version", "")
    assert empty["status"] == "empty"
    assert empty["shape"] == "not_checked"


def test_expect_never_changes_status(
    run_fake: Callable[..., dict[str, Any]],
) -> None:
    """the old success-marker device_error path is gone; mismatch is still ok."""
    result = run_fake("interfaces", "completely unrelated output\n")
    assert result["status"] == "ok"
    assert result["shape"] == "mismatch"


def test_registry_platforms_cover_the_six_vendors() -> None:
    """the six vendor files tested here are all the non-openwrt platforms."""
    assert set(registry.PLATFORMS) - {"openwrt"} == set(PLATFORMS)


@pytest.mark.parametrize(
    ("getter_id", "text"),
    [
        ("nat", "NAT is not configured\n"),
        ("vpn", "IPsec not initialized\n"),
        ("firewall_policy", "Rulesets Information\n"),
    ],
)
def test_vyos_lab_empty_sentences_match(getter_id: str, text: str) -> None:
    """the empty-table sentences lab-vyos printed are a documented shape."""
    getter = load_getters("vyos")[getter_id]
    assert shape_of(getter, "ok", text) == "matched"


def test_vyos_guessed_shapes_do_not_match() -> None:
    """pre-lab guesses the real box never printed are a mismatch."""
    getters = load_getters("vyos")
    assert shape_of(getters["nat"], "ok", "Ruleset Information\n") == "mismatch"
    assert shape_of(
        getters["ntp"], "ok", "Remote           NTP server   RefID\n"
    ) == "mismatch"


STAGED = Path(
    "/tmp/newton-junos-staged"
)


@pytest.mark.skipif(not STAGED.is_dir(), reason="staged Junos captures not present")
def test_staged_real_junos_captures_match() -> None:
    """real Junos 26.2 captures satisfy the junos expects; errors do not."""
    getters = load_getters("junos")
    for name in ("version", "interfaces", "routes"):
        body = body_of(STAGED / f"{name}.txt")
        assert shape_of(getters[name], "ok", body) == "matched", name
    err = body_of(STAGED / "error-bad-command.txt")
    for getter_id, getter in getters.items():
        assert shape_of(getter, "ok", err) == "mismatch", getter_id


def test_junk_probes_do_not_match_tightened_routeros_rows() -> None:
    """the breadth probes a review named are mismatches now."""
    getters = load_getters("routeros")
    for getter_id in ("routes", "vpn", "running_config", "version"):
        for junk in ("1 foo\n", "# comment\n", "/ foo\n", "version: 1\n", "Flags: x\n"):
            assert shape_of(getters[getter_id], "ok", junk) == "mismatch", (
                getter_id,
                junk,
            )


def _adversarial() -> list[str]:
    n = 256 * 1024
    return [
        "\n" * n + "x",
        " " * n + "x",
        "a " * (n // 2),
        " \n" * (n // 2) + "x",
        "\t" * n + "x",
        "x" * n,
        "a" * 100 + " " * n + "b",
        ("a " * 12 + "\n") * (n // 25),
        "\x1b]" * (n // 2),
        "\x1b[0" * (n // 3),
    ]


def test_shape_of_is_linear_on_adversarial_256k_inputs() -> None:
    """every shipped row finishes each hostile 256 KiB body quickly.

    CPU time, not wall clock: a loaded machine stretched the wall-clock version.
    A quadratic matcher took over 120 s, so these bounds still catch it.
    """
    inputs = _adversarial()
    worst = 0.0
    total = 0.0
    for platform in PLATFORMS:
        for getter_id, getter in load_getters(platform).items():
            for text in inputs:
                start = time.process_time()
                shape_of(getter, "ok", text)
                spent = time.process_time() - start
                # fail on the first slow call, not after the whole (slow) loop
                assert spent < 1.0, (platform, getter_id, spent)
                worst = max(worst, spent)
                total += spent
                assert total < 20, (platform, getter_id, total)
    print(f"worst single call {worst:.3f}s, total {total:.2f}s")
    assert worst < 1.0, worst
    assert total < 20, total
