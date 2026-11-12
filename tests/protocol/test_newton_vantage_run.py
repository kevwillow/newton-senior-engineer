"""VC-01, VC-02, VC-03, VC-14 and VC-18 protocol tests for newton-vantage-run."""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import time
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts" / "newton-vantage-run"
SID = "0123456789abcdef0123456789abcdef"
OTHER_SID = "fedcba9876543210fedcba9876543210"


def _vantage(tmp_path: Path, *, proxy_command=None):
    key_file = tmp_path / "keys" / "inside-check"
    known_hosts = tmp_path / "known_hosts"
    key_file.parent.mkdir(exist_ok=True)
    key_file.write_text("private fixture\n")
    key_file.chmod(0o600)
    known_hosts.write_text("vantage.example.test ssh-ed25519 AAAATESTHOST\n")
    known_hosts.chmod(0o600)
    return {
        "name": "inside-vantage",
        "destination": "scanner@vantage.example.test",
        "key_file": str(key_file),
        "known_hosts": str(known_hosts),
        "proxy_command": proxy_command,
    }


def _group(tmp_path: Path, checks, *, zone="guest", proxy_command=None):
    return {
        "zone": zone,
        "vantage": _vantage(tmp_path, proxy_command=proxy_command),
        "checks": checks,
    }


def _write_spec(
    tmp_path: Path,
    groups,
    *,
    sid=SID,
    version=1,
    check_timeout_s=None,
    extra=None,
    mode=0o600,
):
    spec_dir = tmp_path / "specs"
    spec_dir.mkdir(exist_ok=True)
    spec_dir.chmod(0o700)
    spec = {"version": version, "sid": sid, "groups": groups}
    if check_timeout_s is not None:
        spec["check_timeout_s"] = check_timeout_s
    if extra:
        spec.update(extra)
    spec_path = spec_dir / f"{SID}.json"
    spec_path.write_text(json.dumps(spec) + "\n")
    spec_path.chmod(mode)
    return spec_dir, spec_path


def _make_ssh(tmp_path: Path, rows, *, sleep_s=None):
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir(exist_ok=True)
    table_path = tmp_path / "ssh-table"
    table_path.write_text("".join(row + "\n" for row in rows))
    log_path = tmp_path / "ssh-argv.log"
    if log_path.exists():
        log_path.unlink()
    ssh_path = fake_bin / "ssh"
    ssh_path.write_text(
        "#!/bin/sh\n"
        "set -u\n"
        # The call is written in one write(), so that calls running at the
        # same time never interleave their lines in the log.
        "block=\"ARG $0\n\"\n"
        "for arg in \"$@\"; do block=\"${block}ARG $arg\n\"; done\n"
        "block=\"${block}END\n\"\n"
        "printf '%s' \"$block\" >>\"$NEWTON_FAKE_SSH_LOG\"\n"
        "if [ -n \"${NEWTON_FAKE_SSH_SLEEP:-}\" ]; then sleep \"$NEWTON_FAKE_SSH_SLEEP\"; fi\n"
        "while [ \"$#\" -gt 0 ]; do\n"
        "  if [ \"$1\" = check ]; then break; fi\n"
        "  shift\n"
        "done\n"
        "command=$*\n"
        "while IFS='|' read -r key kind status word rc nap; do\n"
        "  [ \"$key\" = \"$command\" ] || continue\n"
        "  if [ -n \"$nap\" ]; then sleep \"$nap\"; fi\n"
        "  case \"$kind\" in\n"
        "    reply) printf 'RESULT %s %s\\n' \"$status\" \"$word\" ;;\n"
        "    raw) printf '%s\\n' \"$status\" ;;\n"
        "    err) printf '%s\\n' \"$status\" >&2 ;;\n"
        "    two) printf 'RESULT PASS reached\\nRESULT PASS reached\\n' ;;\n"
        "    empty) : ;;\n"
        "    hang) exec sleep 60 ;;\n"
        "  esac\n"
        "  exit \"${rc:-0}\"\n"
        "done <\"$NEWTON_FAKE_SSH_TABLE\"\n"
        "exit 255\n"
    )
    ssh_path.chmod(0o755)
    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}{os.pathsep}{env['PATH']}"
    env["NEWTON_FAKE_SSH_TABLE"] = str(table_path)
    env["NEWTON_FAKE_SSH_LOG"] = str(log_path)
    if sleep_s is not None:
        env["NEWTON_FAKE_SSH_SLEEP"] = str(sleep_s)
    env.pop("NEWTON_VANTAGE_SPEC_DIR", None)
    return env, log_path


def _run(tmp_path: Path, rows, groups, *, sid=SID, version=1, check_timeout_s=None,
         extra=None, mode=0o600, unset_spec_dir=False, sleep_s=None):
    env, log_path = _make_ssh(tmp_path, rows, sleep_s=sleep_s)
    spec_dir, _spec_path = _write_spec(
        tmp_path,
        groups,
        sid=sid,
        version=version,
        check_timeout_s=check_timeout_s,
        extra=extra,
        mode=mode,
    )
    if not unset_spec_dir:
        env["NEWTON_VANTAGE_SPEC_DIR"] = str(spec_dir)
    result = subprocess.run(
        [str(RUNNER), sid],
        text=True,
        capture_output=True,
        env=env,
        timeout=30,
    )
    calls = _calls(log_path)
    return result, calls


def _calls(log_path: Path):
    if not log_path.exists():
        return []
    calls = []
    current = []
    for line in log_path.read_text().splitlines():
        if line == "END":
            calls.append(current)
            current = []
        elif line.startswith("ARG "):
            current.append(line[4:])
    return calls


def _claim_lines(result):
    return [
        line
        for line in result.stderr.splitlines()
        if line.startswith("vantage-check: claim ")
    ]


def test_runner_is_executable_and_uses_only_python_stdlib():
    mode = RUNNER.stat().st_mode
    assert mode & stat.S_IXUSR
    text = RUNNER.read_text()
    assert text.startswith("#!/usr/bin/env python3\n")
    assert "newton_mcp" not in text
    assert "shell=True" not in text
    assert "os.system" not in text


def test_vc01_unreachable_vantage_is_not_tested_and_blocks_confirm(tmp_path):
    result, calls = _run(
        tmp_path,
        ["check guest canary|exit|||255"],
        [_group(tmp_path, [{"claim": 2, "kind": "client_dns"}])],
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert _claim_lines(result) == [
        "vantage-check: claim 2 NOT-TESTED ssh-failed"
    ]
    assert len(calls) == 1


def test_vc01_failed_canary_makes_every_check_not_tested(tmp_path):
    result, calls = _run(
        tmp_path,
        ["check guest canary|reply|FAIL|unreachable|0"],
        [
            _group(
                tmp_path,
                [
                    {"claim": 2, "kind": "client_dns"},
                    {"claim": 3, "kind": "client_dhcp"},
                ],
            )
        ],
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert _claim_lines(result) == [
        "vantage-check: claim 2 NOT-TESTED canary-failed",
        "vantage-check: claim 3 NOT-TESTED canary-failed",
    ]
    assert len(calls) == 1


def test_vc01_wrong_zone_canary_word_passes_through(tmp_path):
    result, calls = _run(
        tmp_path,
        ["check guest canary|reply|NOTTESTED|wrong-zone|0"],
        [_group(tmp_path, [{"claim": 2, "kind": "client_dns"}])],
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert _claim_lines(result) == [
        "vantage-check: claim 2 NOT-TESTED wrong-zone"
    ]
    assert len(calls) == 1


@pytest.mark.parametrize(
    ("kind", "status"),
    [
        ("raw", "garbage"),
        ("two", ""),
        ("empty", ""),
    ],
)
def test_vc01_unparsable_reply_is_bad_reply(tmp_path, kind, status):
    result, calls = _run(
        tmp_path,
        [
            "check guest canary|reply|PASS|reached|0",
            f"check guest dns|{kind}|{status}||0",
        ],
        [_group(tmp_path, [{"claim": 2, "kind": "client_dns"}])],
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert _claim_lines(result) == [
        "vantage-check: claim 2 NOT-TESTED bad-reply"
    ]
    assert len(calls) == 2


def test_vc01_hanging_ssh_times_out_as_ssh_failed(tmp_path):
    result, calls = _run(
        tmp_path,
        [
            "check guest canary|reply|PASS|reached|0",
            "check guest dns|hang|||0",
        ],
        [_group(tmp_path, [{"claim": 2, "kind": "client_dns"}])],
        check_timeout_s=1,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert _claim_lines(result) == [
        "vantage-check: claim 2 NOT-TESTED ssh-failed"
    ]
    assert len(calls) == 2


def test_vc02_blocked_target_that_opens_fails_the_claim(tmp_path):
    result, calls = _run(
        tmp_path,
        [
            "check guest canary|reply|PASS|reached|0",
            "check guest blocked 192.0.2.10 22|reply|FAIL|open|0",
        ],
        [
            _group(
                tmp_path,
                [
                    {
                        "claim": 4,
                        "kind": "client_blocked",
                        "to": "router",
                        "targets": ["192.0.2.10:22"],
                    }
                ],
            )
        ],
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert _claim_lines(result) == ["vantage-check: claim 4 FAIL open"]
    assert calls[-1][-5:] == [
        "check",
        "guest",
        "blocked",
        "192.0.2.10",
        "22",
    ]


def test_vc02_pass_refused_with_passing_canary_passes(tmp_path):
    result, calls = _run(
        tmp_path,
        [
            "check guest canary|reply|PASS|reached|0",
            "check guest blocked 192.0.2.10 22|reply|PASS|refused|0",
        ],
        [
            _group(
                tmp_path,
                [
                    {
                        "claim": 4,
                        "kind": "client_blocked",
                        "to": "router",
                        "targets": ["192.0.2.10:22"],
                    }
                ],
            )
        ],
    )

    assert result.returncode == 0
    assert result.stdout == ""
    assert _claim_lines(result) == ["vantage-check: claim 4 PASS refused"]
    assert len(calls) == 2


def test_vc02_pass_refused_with_failed_canary_is_not_tested(tmp_path):
    result, calls = _run(
        tmp_path,
        [
            "check guest canary|reply|FAIL|unreachable|0",
            "check guest blocked 192.0.2.10 22|reply|PASS|refused|0",
        ],
        [
            _group(
                tmp_path,
                [
                    {
                        "claim": 4,
                        "kind": "client_blocked",
                        "to": "router",
                        "targets": ["192.0.2.10:22"],
                    }
                ],
            )
        ],
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert _claim_lines(result) == [
        "vantage-check: claim 4 NOT-TESTED canary-failed"
    ]
    assert len(calls) == 1


def test_vc02_one_open_target_fails_the_claim_and_every_target_is_probed(tmp_path):
    result, calls = _run(
        tmp_path,
        [
            "check guest canary|reply|PASS|reached|0",
            "check guest blocked 192.0.2.10 22|reply|PASS|refused|0",
            "check guest blocked 192.0.2.11 80|reply|FAIL|open|0",
            "check guest blocked 192.0.2.12 443|reply|PASS|refused|0",
        ],
        [
            _group(
                tmp_path,
                [
                    {
                        "claim": 4,
                        "kind": "client_blocked",
                        "to": "router",
                        "targets": [
                            "192.0.2.10:22",
                            "192.0.2.11:80",
                            "192.0.2.12:443",
                        ],
                    }
                ],
            )
        ],
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert _claim_lines(result) == ["vantage-check: claim 4 FAIL open"]
    # VC-18: the targets of a blocked claim run at the same time now, so
    # every target is probed (the canary is the only call that is alone).
    assert len(calls) == 4
    probed = sorted(call[-2:] for call in calls if call[-3] == "blocked")
    assert probed == [
        ["192.0.2.10", "22"],
        ["192.0.2.11", "80"],
        ["192.0.2.12", "443"],
    ]


def test_vc03_host_maps_wrong_zone_to_not_tested(tmp_path):
    result, calls = _run(
        tmp_path,
        ["check guest canary|reply|NOTTESTED|wrong-zone|0"],
        [
            _group(
                tmp_path,
                [
                    {"claim": 2, "kind": "client_dns"},
                    {"claim": 3, "kind": "client_internet"},
                ],
            )
        ],
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert _claim_lines(result) == [
        "vantage-check: claim 2 NOT-TESTED wrong-zone",
        "vantage-check: claim 3 NOT-TESTED wrong-zone",
    ]
    assert len(calls) == 1


@pytest.mark.parametrize(
    "mutation",
    [
        "unknown-top-key",
        "unknown-group-key",
        "unknown-vantage-key",
        "unknown-check-key",
        "bad-zone",
        "bad-kind",
        "bad-target",
        "bad-version",
        "bad-timeout",
        "sid-mismatch",
    ],
)
def test_vc03_invalid_specs_are_refused_without_ssh(tmp_path, mutation):
    groups = [_group(tmp_path, [{"claim": 2, "kind": "client_dns"}])]
    extra = None
    version = 1
    check_timeout_s = None
    sid = SID

    if mutation == "unknown-top-key":
        extra = {"extra": True}
    elif mutation == "unknown-group-key":
        groups[0]["extra"] = True
    elif mutation == "unknown-vantage-key":
        groups[0]["vantage"]["extra"] = True
    elif mutation == "unknown-check-key":
        groups[0]["checks"][0]["extra"] = True
    elif mutation == "bad-zone":
        groups[0]["zone"] = "Guest"
    elif mutation == "bad-kind":
        groups[0]["checks"][0]["kind"] = "client_scan"
    elif mutation == "bad-target":
        groups[0]["checks"][0] = {
            "claim": 2,
            "kind": "client_blocked",
            "to": "router",
            "targets": ["192.0.2.1:not-a-port"],
        }
    elif mutation == "bad-version":
        version = 2
    elif mutation == "bad-timeout":
        check_timeout_s = 41
    elif mutation == "sid-mismatch":
        sid = OTHER_SID

    result, calls = _run(
        tmp_path,
        [],
        groups,
        sid=sid,
        version=version,
        check_timeout_s=check_timeout_s,
        extra=extra,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert re.fullmatch(r"vantage-check: error [a-z-]+\n", result.stderr)
    assert calls == []


def test_vc03_bad_command_sid_is_refused(tmp_path):
    result, calls = _run(
        tmp_path,
        [],
        [_group(tmp_path, [{"claim": 2, "kind": "client_dns"}])],
        sid="not-a-sid",
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert re.fullmatch(r"vantage-check: error [a-z-]+\n", result.stderr)
    assert calls == []


def test_vc03_unset_spec_dir_is_refused(tmp_path):
    result, calls = _run(
        tmp_path,
        [],
        [_group(tmp_path, [{"claim": 2, "kind": "client_dns"}])],
        unset_spec_dir=True,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert re.fullmatch(r"vantage-check: error [a-z-]+\n", result.stderr)
    assert calls == []


def test_vc03_missing_spec_is_refused(tmp_path):
    env, log_path = _make_ssh(tmp_path, [])
    spec_dir = tmp_path / "specs"
    spec_dir.mkdir()
    env["NEWTON_VANTAGE_SPEC_DIR"] = str(spec_dir)

    result = subprocess.run(
        [str(RUNNER), SID], text=True, capture_output=True, env=env, timeout=10
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert re.fullmatch(r"vantage-check: error [a-z-]+\n", result.stderr)
    assert _calls(log_path) == []


def test_vc03_symlink_spec_is_refused(tmp_path):
    env, log_path = _make_ssh(tmp_path, [])
    spec_dir = tmp_path / "specs"
    spec_dir.mkdir()
    target = tmp_path / "real-spec.json"
    target.write_text(
        json.dumps(
            {
                "version": 1,
                "sid": SID,
                "groups": [_group(tmp_path, [{"claim": 2, "kind": "client_dns"}])],
            }
        )
    )
    target.chmod(0o600)
    (spec_dir / f"{SID}.json").symlink_to(target)
    env["NEWTON_VANTAGE_SPEC_DIR"] = str(spec_dir)

    result = subprocess.run(
        [str(RUNNER), SID], text=True, capture_output=True, env=env, timeout=10
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert re.fullmatch(r"vantage-check: error [a-z-]+\n", result.stderr)
    assert _calls(log_path) == []


def test_vc03_group_or_world_accessible_spec_is_refused(tmp_path):
    result, calls = _run(
        tmp_path,
        [],
        [_group(tmp_path, [{"claim": 2, "kind": "client_dns"}])],
        mode=0o644,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert re.fullmatch(r"vantage-check: error [a-z-]+\n", result.stderr)
    assert calls == []


def test_vc03_spec_not_owned_by_running_uid_is_refused_when_test_can_set_owner(tmp_path):
    spec_dir, spec_path = _write_spec(
        tmp_path, [_group(tmp_path, [{"claim": 2, "kind": "client_dns"}])]
    )
    try:
        os.chown(spec_path, os.getuid() + 1, os.getgid())
    except PermissionError:
        pytest.skip("the test user cannot change file ownership")
    env, log_path = _make_ssh(tmp_path, [])
    env["NEWTON_VANTAGE_SPEC_DIR"] = str(spec_dir)

    result = subprocess.run(
        [str(RUNNER), SID], text=True, capture_output=True, env=env, timeout=10
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert re.fullmatch(r"vantage-check: error [a-z-]+\n", result.stderr)
    assert _calls(log_path) == []


def test_vc14_pass_only_run_exits_zero_with_three_claim_lines(tmp_path):
    groups = [
        _group(
            tmp_path,
            [
                {"claim": 2, "kind": "client_dns"},
                {"claim": 3, "kind": "client_dhcp"},
                {"claim": 4, "kind": "client_internet"},
            ],
        )
    ]
    result, calls = _run(
        tmp_path,
        [
            "check guest canary|reply|PASS|reached|0",
            "check guest dns|reply|PASS|resolved|0",
            "check guest dhcp|reply|PASS|offer|0",
            "check guest internet|reply|PASS|online|0",
        ],
        groups,
    )

    assert result.returncode == 0
    assert result.stdout == ""
    assert _claim_lines(result) == [
        "vantage-check: claim 2 PASS ok",
        "vantage-check: claim 3 PASS ok",
        "vantage-check: claim 4 PASS ok",
    ]
    assert len(calls) == 4


def test_vc14_canary_runs_exactly_once_per_group(tmp_path):
    result, calls = _run(
        tmp_path,
        [
            "check guest canary|reply|PASS|reached|0",
            "check guest dns|reply|PASS|resolved|0",
            "check guest dhcp|reply|PASS|offer|0",
            "check guest internet|reply|PASS|online|0",
        ],
        [
            _group(
                tmp_path,
                [
                    {"claim": 2, "kind": "client_dns"},
                    {"claim": 3, "kind": "client_dhcp"},
                    {"claim": 4, "kind": "client_internet"},
                ],
            )
        ],
    )

    assert result.returncode == 0
    canary_calls = [call for call in calls if call[-3:] == ["check", "guest", "canary"]]
    assert len(canary_calls) == 1


def test_ssh_argv_is_exact_and_proxy_is_present_only_when_set(tmp_path):
    proxy_group = _group(
        tmp_path,
        [{"claim": 2, "kind": "client_dns"}],
        proxy_command="proxy-helper --fixed",
    )
    result, calls = _run(
        tmp_path,
        [
            "check guest canary|reply|PASS|reached|0",
            "check guest dns|reply|PASS|resolved|0",
        ],
        [proxy_group],
    )
    assert result.returncode == 0
    vantage = proxy_group["vantage"]
    expected = [
        calls[0][0],
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPath=none",
        "-o",
        "ConnectTimeout=8",
        "-o",
        "BatchMode=yes",
        "-o",
        "ProxyCommand=proxy-helper --fixed",
        "-i",
        vantage["key_file"],
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={vantage['known_hosts']}",
        "--",
        vantage["destination"],
        "check",
        "guest",
        "canary",
    ]
    assert calls[0] == expected

    plain_group = _group(tmp_path, [{"claim": 2, "kind": "client_dns"}])
    result, calls = _run(
        tmp_path,
        [
            "check guest canary|reply|PASS|reached|0",
            "check guest dns|reply|PASS|resolved|0",
        ],
        [plain_group],
    )
    assert result.returncode == 0
    assert not any(arg.startswith("ProxyCommand=") for arg in calls[0])


# ---- VC-18: further review fixes ------------------------------------------


def _blocked_check(claim, targets):
    return {
        "claim": claim,
        "kind": "client_blocked",
        "to": "router",
        "targets": list(targets),
    }


def test_vc18_01_eleven_calls_do_not_cost_eleven_round_trips(tmp_path):
    """VC-18: the calls of a group run at the same time.

    The apply gives every round a fixed budget and needs three passing
    rounds in a row, so a vantage whose firewall DROPs the probes (six
    seconds a target) and a DHCP probe that waits twelve seconds would
    blow the budget when every call waited for the one before it.  The
    canary stays first and alone; the checks of the group and the
    targets of a blocked claim run together.
    """
    targets = [f"192.0.2.{index}:22" for index in range(10, 17)]
    rows = [
        "check guest canary|reply|PASS|reached|0",
        "check guest dns|reply|PASS|resolved|0",
        "check guest dhcp|reply|PASS|offer|0",
        "check guest internet|reply|PASS|online|0",
    ]
    rows += [
        f"check guest blocked {target.split(':')[0]} 22|reply|PASS|refused|0"
        for target in targets
    ]
    groups = [
        _group(
            tmp_path,
            [
                {"claim": 2, "kind": "client_dns"},
                {"claim": 3, "kind": "client_dhcp"},
                {"claim": 4, "kind": "client_internet"},
                _blocked_check(5, targets),
            ],
        )
    ]

    started = time.monotonic()
    result, calls = _run(tmp_path, rows, groups, sleep_s=1)
    elapsed = time.monotonic() - started

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert _claim_lines(result) == [
        "vantage-check: claim 2 PASS ok",
        "vantage-check: claim 3 PASS ok",
        "vantage-check: claim 4 PASS ok",
        "vantage-check: claim 5 PASS refused",
    ]
    assert len(calls) == 11
    # eleven calls of a second each: the canary alone, then two rounds of
    # six workers.  One after the other it would be eleven seconds.
    assert elapsed < 7, f"the run took {elapsed:.1f}s"


def test_vc18_02_the_first_failing_target_in_target_order_is_named(tmp_path):
    """The word of the claim does not depend on the order the replies came
    back in: the first FAIL in target order wins."""
    result, _calls = _run(
        tmp_path,
        [
            "check guest canary|reply|PASS|reached|0",
            # the first target answers slowly and fails with its own word
            "check guest blocked 192.0.2.10 22|reply|FAIL|open|0|2",
            # the second answers first and fails with another word
            "check guest blocked 192.0.2.11 80|reply|FAIL|wide-open|0",
        ],
        [_group(tmp_path, [_blocked_check(4, ["192.0.2.10:22", "192.0.2.11:80"])])],
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert _claim_lines(result) == ["vantage-check: claim 4 FAIL open"]


def test_vc18_03_a_failed_target_wins_over_a_target_that_could_not_be_tested(tmp_path):
    result, _calls = _run(
        tmp_path,
        [
            "check guest canary|reply|PASS|reached|0",
            "check guest blocked 192.0.2.10 22|reply|NOTTESTED|unreachable|0|2",
            "check guest blocked 192.0.2.11 80|reply|FAIL|open|0",
        ],
        [_group(tmp_path, [_blocked_check(4, ["192.0.2.10:22", "192.0.2.11:80"])])],
    )

    assert result.returncode == 1
    assert _claim_lines(result) == ["vantage-check: claim 4 FAIL open"]


def test_vc18_04_the_first_target_that_could_not_be_tested_is_named(tmp_path):
    result, _calls = _run(
        tmp_path,
        [
            "check guest canary|reply|PASS|reached|0",
            "check guest blocked 192.0.2.10 22|reply|NOTTESTED|unreachable|0|2",
            "check guest blocked 192.0.2.11 80|reply|NOTTESTED|not-allowed|0",
        ],
        [_group(tmp_path, [_blocked_check(4, ["192.0.2.10:22", "192.0.2.11:80"])])],
    )

    assert result.returncode == 1
    assert _claim_lines(result) == ["vantage-check: claim 4 NOT-TESTED unreachable"]


def test_vc18_05_every_target_is_probed_even_when_the_first_one_fails(tmp_path):
    result, calls = _run(
        tmp_path,
        [
            "check guest canary|reply|PASS|reached|0",
            "check guest blocked 192.0.2.10 22|reply|FAIL|open|0",
            "check guest blocked 192.0.2.11 80|reply|PASS|refused|0",
        ],
        [_group(tmp_path, [_blocked_check(4, ["192.0.2.10:22", "192.0.2.11:80"])])],
    )

    assert result.returncode == 1
    assert len(calls) == 3
    probed = sorted(call[-2:] for call in calls if call[-3] == "blocked")
    assert probed == [["192.0.2.10", "22"], ["192.0.2.11", "80"]]


def test_vc18_06_the_canary_runs_once_and_before_the_checks(tmp_path):
    result, calls = _run(
        tmp_path,
        [
            "check guest canary|reply|PASS|reached|0",
            "check guest dns|reply|PASS|resolved|0",
            "check guest dhcp|reply|PASS|offer|0",
            "check guest internet|reply|PASS|online|0",
        ],
        [
            _group(
                tmp_path,
                [
                    {"claim": 2, "kind": "client_dns"},
                    {"claim": 3, "kind": "client_dhcp"},
                    {"claim": 4, "kind": "client_internet"},
                ],
            )
        ],
    )

    assert result.returncode == 0
    canary_calls = [call for call in calls if call[-3:] == ["check", "guest", "canary"]]
    assert len(canary_calls) == 1
    # the canary is the first call of the group and it is alone: the
    # checks only start after it has answered.
    assert calls[0][-3:] == ["check", "guest", "canary"]


def test_vc18_07_the_claim_lines_come_in_claim_order(tmp_path):
    result, _calls = _run(
        tmp_path,
        [
            "check guest canary|reply|PASS|reached|0",
            "check guest internet|reply|PASS|online|0",
            "check guest dns|reply|PASS|resolved|0",
            "check guest dhcp|reply|PASS|offer|0",
        ],
        [
            _group(
                tmp_path,
                [
                    {"claim": 2, "kind": "client_dns"},
                    {"claim": 3, "kind": "client_dhcp"},
                    {"claim": 4, "kind": "client_internet"},
                ],
            )
        ],
    )

    assert result.returncode == 0
    assert _claim_lines(result) == [
        "vantage-check: claim 2 PASS ok",
        "vantage-check: claim 3 PASS ok",
        "vantage-check: claim 4 PASS ok",
    ]


# ---- VC-19: client_reaches and the old forced command --------------------------


def _reaches_check(claim, targets):
    return {
        "claim": claim,
        "kind": "client_reaches",
        "to": targets[0],
        "targets": list(targets),
    }


def test_vc19_01_reach_passes_when_the_target_answers(tmp_path):
    result, calls = _run(
        tmp_path,
        [
            "check guest canary|reply|PASS|reached|0",
            "check guest reach 192.0.2.10 631|reply|PASS|reached|0",
        ],
        [_group(tmp_path, [_reaches_check(2, ["192.0.2.10:631"])])],
    )

    assert result.returncode == 0
    assert result.stdout == ""
    assert _claim_lines(result) == ["vantage-check: claim 2 PASS reached"]
    assert calls[-1][-5:] == ["check", "guest", "reach", "192.0.2.10", "631"]


def test_vc19_02_reach_refused_or_timeout_fails_the_claim(tmp_path):
    for word in ("refused", "timeout"):
        result, _calls = _run(
            tmp_path,
            [
                "check guest canary|reply|PASS|reached|0",
                f"check guest reach 192.0.2.10 631|reply|FAIL|{word}|0",
            ],
            [_group(tmp_path, [_reaches_check(2, ["192.0.2.10:631"])])],
        )
        assert result.returncode == 1, word
        assert _claim_lines(result) == [f"vantage-check: claim 2 FAIL {word}"]


def test_vc19_03_reach_not_allowed_is_not_tested(tmp_path):
    result, _calls = _run(
        tmp_path,
        [
            "check guest canary|reply|PASS|reached|0",
            "check guest reach 192.0.2.10 631|reply|NOTTESTED|not-allowed|0",
        ],
        [_group(tmp_path, [_reaches_check(2, ["192.0.2.10:631"])])],
    )

    assert result.returncode == 1
    assert _claim_lines(result) == ["vantage-check: claim 2 NOT-TESTED not-allowed"]


def test_vc19_04_the_old_forced_command_is_detected_for_reach(tmp_path):
    """A vantage that still runs the OLD forced command does not know the
    reach verb and answers with its fixed refusal line.  The runner maps
    exactly that answer (rc 2, one stderr line) to old-forced-command."""
    result, _calls = _run(
        tmp_path,
        [
            "check guest canary|reply|PASS|reached|0",
            "check guest reach 192.0.2.10 631|err|newton-vantage-check: refused||2",
        ],
        [_group(tmp_path, [_reaches_check(2, ["192.0.2.10:631"])])],
    )

    assert result.returncode == 1
    assert _claim_lines(result) == [
        "vantage-check: claim 2 NOT-TESTED old-forced-command"
    ]


def test_vc19_05_the_old_forced_command_needs_the_exact_answer(tmp_path):
    for stderr, rc in (
        ("newton-vantage-check: refused extra", 2),
        ("newton-vantage-check: refused", 255),
        ("ssh: connect refused", 2),
        ("", 2),
    ):
        result, _calls = _run(
            tmp_path,
            [
                "check guest canary|reply|PASS|reached|0",
                f"check guest reach 192.0.2.10 631|err|{stderr}||{rc}",
            ],
            [_group(tmp_path, [_reaches_check(2, ["192.0.2.10:631"])])],
        )
        assert result.returncode == 1, (stderr, rc)
        assert _claim_lines(result) == [
            "vantage-check: claim 2 NOT-TESTED ssh-failed"
        ], (stderr, rc)


def test_vc19_06_the_old_forced_command_is_not_mapped_for_blocked(tmp_path):
    # Only `reach` is a new verb; a blocked call that fails is the ssh
    # failure it always was.
    result, _calls = _run(
        tmp_path,
        [
            "check guest canary|reply|PASS|reached|0",
            "check guest blocked 192.0.2.10 22|err|newton-vantage-check: refused||2",
        ],
        [
            _group(
                tmp_path,
                [
                    {
                        "claim": 4,
                        "kind": "client_blocked",
                        "to": "router",
                        "targets": ["192.0.2.10:22"],
                    }
                ],
            )
        ],
    )

    assert result.returncode == 1
    assert _claim_lines(result) == ["vantage-check: claim 4 NOT-TESTED ssh-failed"]


def test_vc19_07_the_targets_of_a_reaches_claim_run_at_the_same_time(tmp_path):
    targets = [f"192.0.2.{index}:631" for index in (10, 11, 12)]
    rows = ["check guest canary|reply|PASS|reached|0"]
    rows += [
        f"check guest reach {target.split(':')[0]} 631|reply|PASS|reached|0"
        for target in targets
    ]
    result, calls = _run(
        tmp_path,
        rows,
        [_group(tmp_path, [_reaches_check(5, targets)])],
    )

    assert result.returncode == 0
    assert _claim_lines(result) == ["vantage-check: claim 5 PASS reached"]
    probed = sorted(call[-2:] for call in calls if call[-3] == "reach")
    assert probed == [["192.0.2.10", "631"], ["192.0.2.11", "631"], ["192.0.2.12", "631"]]


def test_vc19_08_one_target_that_cannot_be_reached_fails_the_claim(tmp_path):
    result, _calls = _run(
        tmp_path,
        [
            "check guest canary|reply|PASS|reached|0",
            "check guest reach 192.0.2.10 631|reply|PASS|reached|0",
            "check guest reach 192.0.2.11 631|reply|FAIL|refused|0",
        ],
        [_group(tmp_path, [_reaches_check(5, ["192.0.2.10:631", "192.0.2.11:631"])])],
    )

    assert result.returncode == 1
    assert _claim_lines(result) == ["vantage-check: claim 5 FAIL refused"]


def test_vc19_09_a_target_that_cannot_be_tested_is_not_a_pass(tmp_path):
    result, _calls = _run(
        tmp_path,
        [
            "check guest canary|reply|PASS|reached|0",
            "check guest reach 192.0.2.10 631|reply|PASS|reached|0",
            "check guest reach 192.0.2.11 631|reply|NOTTESTED|unreachable|0",
        ],
        [_group(tmp_path, [_reaches_check(5, ["192.0.2.10:631", "192.0.2.11:631"])])],
    )

    assert result.returncode == 1
    assert _claim_lines(result) == ["vantage-check: claim 5 NOT-TESTED unreachable"]


def test_vc19_10_a_reaches_check_without_targets_is_refused(tmp_path):
    groups = [
        _group(tmp_path, [{"claim": 2, "kind": "client_reaches", "to": "192.0.2.10:631"}])
    ]
    result, calls = _run(tmp_path, [], groups)

    assert result.returncode == 1
    assert re.fullmatch(r"vantage-check: error [a-z-]+\n", result.stderr)
    assert calls == []


def test_vc19_11_a_reaches_check_with_a_bad_to_or_target_is_refused(tmp_path):
    for check in (
        {"claim": 2, "kind": "client_reaches", "to": "router", "targets": ["192.0.2.10:631"]},
        {"claim": 2, "kind": "client_reaches", "to": "192.0.2.10:631", "targets": ["192.0.2.10:not-a-port"]},
        {"claim": 2, "kind": "client_reaches", "to": "192.0.2.10:631", "targets": []},
    ):
        result, calls = _run(tmp_path, [], [_group(tmp_path, [check])])
        assert result.returncode == 1, check
        assert re.fullmatch(r"vantage-check: error [a-z-]+\n", result.stderr)
        assert calls == []


def test_vc19_12_a_blocked_check_with_an_owner_target_is_accepted(tmp_path):
    result, calls = _run(
        tmp_path,
        [
            "check guest canary|reply|PASS|reached|0",
            "check guest blocked 192.0.2.10 631|reply|PASS|refused|0",
        ],
        [
            _group(
                tmp_path,
                [
                    {
                        "claim": 4,
                        "kind": "client_blocked",
                        "to": "192.0.2.10:631",
                        "targets": ["192.0.2.10:631"],
                    }
                ],
            )
        ],
    )

    assert result.returncode == 0
    assert _claim_lines(result) == ["vantage-check: claim 4 PASS refused"]
    assert calls[-1][-2:] == ["192.0.2.10", "631"]


def test_vc19_13_a_blocked_check_with_a_bad_owner_to_is_refused(tmp_path):
    groups = [
        _group(
            tmp_path,
            [
                {
                    "claim": 4,
                    "kind": "client_blocked",
                    "to": "lan",
                    "targets": ["192.0.2.10:631"],
                }
            ],
        )
    ]
    result, calls = _run(tmp_path, [], groups)

    assert result.returncode == 1
    assert re.fullmatch(r"vantage-check: error [a-z-]+\n", result.stderr)
    assert calls == []
