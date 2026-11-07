import os
import subprocess
import hashlib
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
LIB = REPO / "lab" / "teardown-lib.sh"


def run_bash(code, *, stdin="", env=None, strict=False):
    run_env = dict(os.environ)
    run_env["LIB"] = str(LIB)
    if env:
        run_env.update({key: str(value) for key, value in env.items()})
    strict_prelude = "set -euo pipefail\n" if strict else ""
    return subprocess.run(
        ["bash", "-c", 'source "$LIB"\n' + strict_prelude + code],
        input=stdin,
        text=True,
        capture_output=True,
        env=run_env,
        timeout=10,
    )


def newton_line(label, role):
    return (
        "restrict,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,"
        'no-pty,command="/usr/libexec/newton/newton-router --caller=%s '
        '--role=%s" ssh-ed25519 AAAA%s newton-router-%s\n'
    ) % (label, role, label.upper(), label)


def test_newton_key_labels_extracts_sorted_unique_and_ignores_plain_key():
    text = (
        newton_line("bob", "read")
        + "ssh-ed25519 AAAAPLAIN user@example # unchanged\n"
        + newton_line("alice", "change")
        + newton_line("bob", "read")
    )
    result = run_bash("newton_key_labels\n", stdin=text)
    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert result.stdout.splitlines() == ["alice change", "bob read"]


def test_newton_key_labels_warns_and_skips_invalid_label_without_echoing_it():
    invalid = "a;b"
    result = run_bash("newton_key_labels\n", stdin=newton_line(invalid, "change"))
    assert result.returncode == 0
    assert result.stdout == ""
    assert "warning" in result.stderr.lower()
    assert invalid not in result.stderr


def test_newton_key_labels_skips_a_bad_or_missing_role_without_echoing_it():
    # only the roles Newton knows are re-added, so a key whose role is
    # not one of them is skipped; the warning never echoes the value
    bad_role = "x;id"
    no_role = (
        "restrict,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,"
        'no-pty,command="/usr/libexec/newton/newton-router --caller=carol" '
        "ssh-ed25519 AAAACAROL newton-router-carol\n"
    )
    text = newton_line("bob", bad_role) + no_role + newton_line("alice", "change")
    result = run_bash("newton_key_labels\n", stdin=text)
    assert result.returncode == 0
    assert result.stdout.splitlines() == ["alice change"]
    assert bad_role not in result.stdout
    assert "bob" not in result.stdout
    assert "carol" not in result.stdout
    assert "warning" in result.stderr.lower()
    assert bad_role not in result.stderr


def test_capture_newton_keys_uses_rsh_output(tmp_path):
    outfile = tmp_path / "labels"
    text = newton_line("bob", "read") + newton_line("alice", "change")
    result = run_bash(
        'rsh() { [ "$1" = "cat /etc/dropbear/authorized_keys" ] || return 9; '
        'printf "%s" "$AK_TEXT"; }\n'
        'capture_newton_keys "$OUTFILE"\n',
        strict=True,
        env={"AK_TEXT": text, "OUTFILE": outfile},
    )
    assert result.returncode == 0, result.stderr
    assert outfile.read_text().splitlines() == ["alice change", "bob read"]


def test_capture_newton_keys_fails_when_rsh_fails(tmp_path):
    outfile = tmp_path / "labels"
    result = run_bash(
        'rsh() { return 23; }\n'
        'capture_newton_keys "$OUTFILE" || echo "rc=$?"\n'
        'echo still-here\n',
        strict=True,
        env={"OUTFILE": outfile},
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == "rc=23\nstill-here\n"


def stub_readd_code():
    return r'''
setup() {
	printf '%s\n' "$*" >> "$CALLS"
	[ "$2" = alice ] || return 7
	printf '%s\n' "$ALICE_LINE" >> "$LIVE"
}
rsh() {
	[ -z "${RSH_CALLS:-}" ] || printf '%s\n' "$1" >> "$RSH_CALLS"
	local script
	case "$1" in
		'cat /etc/dropbear/authorized_keys')
			if [[ -n "${AK_TEXT+x}" ]]; then
				printf '%s' "$AK_TEXT"
			else
				cat "$LIVE"
			fi
			return $?
			;;
		*'read -r label'*)
			[ -z "${WRITES:-}" ] || printf '%s\n' append >> "$WRITES"
			script=${1//\/etc\/dropbear\/authorized_keys/$LIVE}
			sh -c "$script"
			return $?
			;;
	esac
	return 9
}
readd_newton_keys "$BASELINE" "$KEYS_DIR" "$DEVICE"
'''


def remote_readd_script(router_file):
    source = LIB.read_text()
    marker = " | rsh '\n"
    start = source.index(marker) + len(marker)
    end = source.index("\n\t\t\t'; then", start)
    script = source[start:end]
    return script.replace(
        "/etc/dropbear/authorized_keys", str(router_file))


def run_remote_readd(router_file, *, stdin, tmpdir, prelude=""):
    return run_bash(
        prelude + "\n" + remote_readd_script(router_file),
        stdin=stdin,
        # The router's shell runs this script without set -e.
        strict=False,
        env={"TMPDIR": tmpdir},
    )


def test_readd_newton_keys_prefers_add_key_and_appends_the_missing_exact_bytes(
        tmp_path):
    baseline = tmp_path / "baseline.authorized_keys"
    live = tmp_path / "authorized_keys"
    keys = tmp_path / "keys"
    calls = tmp_path / "calls"
    rsh_calls = tmp_path / "rsh-calls"
    tmpdir = tmp_path / "tmp"
    keys.mkdir()
    tmpdir.mkdir()
    plain = "ssh-ed25519 AAAAPLAIN user@example\n"
    alice = newton_line("alice", "change").rstrip("\n")
    workstation = newton_line("workstation", "change").rstrip("\n")
    baseline.write_text(plain + workstation + "\n" + alice + "\n")
    live.write_text(plain)
    (keys / "lab-r1-alice").write_text("alice private\n")
    result = run_bash(
        stub_readd_code(),
        strict=True,
        env={
            "BASELINE": baseline,
            "KEYS_DIR": keys,
            "DEVICE": "lab-r1",
            "LIVE": live,
            "CALLS": calls,
            "RSH_CALLS": rsh_calls,
            "ALICE_LINE": alice,
            "TMPDIR": tmp_path / "tmp",
        },
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert calls.read_text().splitlines() == ["add-key alice change"]
    assert rsh_calls.exists()
    assert all("workstation" not in line for line in rsh_calls.read_text().splitlines())
    assert result.stdout.splitlines() == [
        "== re-add workstation byte-exact rc=0",
        "== re-add alice via add-key rc=0",
    ]
    assert live.read_bytes() == baseline.read_bytes()
    assert list(tmpdir.iterdir()) == []


def test_readd_newton_keys_keeps_an_unchanged_router(tmp_path):
    baseline = tmp_path / "baseline.authorized_keys"
    live = tmp_path / "authorized_keys"
    keys = tmp_path / "keys"
    calls = tmp_path / "calls"
    rsh_calls = tmp_path / "rsh-calls"
    writes = tmp_path / "writes"
    tmpdir = tmp_path / "tmp"
    keys.mkdir()
    tmpdir.mkdir()
    plain = "ssh-ed25519 AAAAPLAIN user@example\n"
    workstation = newton_line("workstation", "change")
    alice = newton_line("alice", "read")
    baseline.write_text(plain + workstation + alice)
    live.write_bytes(baseline.read_bytes())
    (keys / "lab-r1-alice").write_text("alice private\n")
    calls.write_text("")
    rsh_calls.write_text("")
    writes.write_text("")
    result = run_bash(stub_readd_code(), strict=True, env={
        "BASELINE": baseline,
        "KEYS_DIR": keys,
        "DEVICE": "lab-r1",
        "LIVE": live,
        "CALLS": calls,
        "RSH_CALLS": rsh_calls,
        "WRITES": writes,
        "ALICE_LINE": alice.rstrip("\n"),
        "TMPDIR": tmpdir,
    })
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines() == [
        "== keep workstation already on the router",
        "== keep alice already on the router",
    ]
    assert calls.read_text().splitlines() == []
    assert writes.read_text().splitlines() == []
    assert all(
        "read -r label" not in line
        for line in rsh_calls.read_text().splitlines()
    )
    assert live.read_bytes() == baseline.read_bytes()
    assert list(tmpdir.iterdir()) == []


def test_readd_newton_keys_adds_one_missing_local_key_and_keeps_the_other(
        tmp_path):
    baseline = tmp_path / "baseline.authorized_keys"
    live = tmp_path / "authorized_keys"
    keys = tmp_path / "keys"
    calls = tmp_path / "calls"
    rsh_calls = tmp_path / "rsh-calls"
    writes = tmp_path / "writes"
    tmpdir = tmp_path / "tmp"
    keys.mkdir()
    tmpdir.mkdir()
    plain = "ssh-ed25519 AAAAPLAIN user@example\n"
    workstation = newton_line("workstation", "change")
    alice = newton_line("alice", "read")
    baseline.write_text(plain + workstation + alice)
    live.write_text(plain + workstation)
    (keys / "lab-r1-alice").write_text("alice private\n")
    calls.write_text("")
    rsh_calls.write_text("")
    writes.write_text("")
    result = run_bash(stub_readd_code(), strict=True, env={
        "BASELINE": baseline,
        "KEYS_DIR": keys,
        "DEVICE": "lab-r1",
        "LIVE": live,
        "CALLS": calls,
        "RSH_CALLS": rsh_calls,
        "WRITES": writes,
        "ALICE_LINE": alice.rstrip("\n"),
        "TMPDIR": tmpdir,
    })
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines() == [
        "== keep workstation already on the router",
        "== re-add alice via add-key rc=0",
    ]
    assert calls.read_text().splitlines() == ["add-key alice read"]
    assert writes.read_text().splitlines() == []
    assert live.read_bytes() == baseline.read_bytes()
    assert list(tmpdir.iterdir()) == []


def test_readd_newton_keys_appends_one_missing_key_without_a_local_file(
        tmp_path):
    baseline = tmp_path / "baseline.authorized_keys"
    live = tmp_path / "authorized_keys"
    keys = tmp_path / "keys"
    calls = tmp_path / "calls"
    rsh_calls = tmp_path / "rsh-calls"
    writes = tmp_path / "writes"
    tmpdir = tmp_path / "tmp"
    keys.mkdir()
    tmpdir.mkdir()
    plain = "ssh-ed25519 AAAAPLAIN user@example\n"
    alice = newton_line("alice", "read")
    workstation = newton_line("workstation", "change")
    baseline.write_text(plain + alice + workstation)
    live.write_text(plain + alice)
    calls.write_text("")
    rsh_calls.write_text("")
    writes.write_text("")
    result = run_bash(stub_readd_code(), strict=True, env={
        "BASELINE": baseline,
        "KEYS_DIR": keys,
        "DEVICE": "lab-r1",
        "LIVE": live,
        "CALLS": calls,
        "RSH_CALLS": rsh_calls,
        "WRITES": writes,
        "ALICE_LINE": alice.rstrip("\n"),
        "TMPDIR": tmpdir,
    })
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines() == [
        "== keep alice already on the router",
        "== re-add workstation byte-exact rc=0",
    ]
    assert calls.read_text().splitlines() == []
    assert len(writes.read_text().splitlines()) == 1
    assert live.read_bytes() == baseline.read_bytes()
    assert list(tmpdir.iterdir()) == []


def test_readd_newton_keys_stops_before_a_write_for_a_skipped_baseline_line(
        tmp_path):
    baseline = tmp_path / "baseline.authorized_keys"
    live = tmp_path / "authorized_keys"
    keys = tmp_path / "keys"
    calls = tmp_path / "calls"
    rsh_calls = tmp_path / "rsh-calls"
    writes = tmp_path / "writes"
    tmpdir = tmp_path / "tmp"
    keys.mkdir()
    tmpdir.mkdir()
    plain = "ssh-ed25519 AAAAPLAIN user@example\n"
    alice = newton_line("alice", "read")
    admin_role = newton_line("bob", "admin")
    baseline.write_text(plain + alice + admin_role)
    live.write_text(plain)
    (keys / "lab-r1-alice").write_text("alice private\n")
    before = live.read_bytes()
    calls.write_text("")
    rsh_calls.write_text("")
    writes.write_text("")
    result = run_bash(stub_readd_code(), strict=True, env={
        "BASELINE": baseline,
        "KEYS_DIR": keys,
        "DEVICE": "lab-r1",
        "LIVE": live,
        "CALLS": calls,
        "RSH_CALLS": rsh_calls,
        "WRITES": writes,
        "ALICE_LINE": alice.rstrip("\n"),
        "TMPDIR": tmpdir,
    })
    assert result.returncode == 1
    assert result.stdout.splitlines() == [
        "STOP the baseline cannot be restored by appending "
        "the missing key lines; nothing changed"
    ]
    assert calls.read_text().splitlines() == []
    assert writes.read_text().splitlines() == []
    assert live.read_bytes() == before
    assert list(tmpdir.iterdir()) == []


def test_readd_newton_keys_stops_before_a_write_for_an_extra_router_key(
        tmp_path):
    baseline = tmp_path / "baseline.authorized_keys"
    live = tmp_path / "authorized_keys"
    keys = tmp_path / "keys"
    calls = tmp_path / "calls"
    rsh_calls = tmp_path / "rsh-calls"
    writes = tmp_path / "writes"
    tmpdir = tmp_path / "tmp"
    keys.mkdir()
    tmpdir.mkdir()
    plain = "ssh-ed25519 AAAAPLAIN user@example\n"
    alice = newton_line("alice", "read")
    bob = newton_line("bob", "read")
    baseline.write_text(plain + alice)
    live.write_text(plain + bob)
    (keys / "lab-r1-alice").write_text("alice private\n")
    before = live.read_bytes()
    calls.write_text("")
    rsh_calls.write_text("")
    writes.write_text("")
    result = run_bash(stub_readd_code(), strict=True, env={
        "BASELINE": baseline,
        "KEYS_DIR": keys,
        "DEVICE": "lab-r1",
        "LIVE": live,
        "CALLS": calls,
        "RSH_CALLS": rsh_calls,
        "WRITES": writes,
        "ALICE_LINE": alice.rstrip("\n"),
        "TMPDIR": tmpdir,
    })
    assert result.returncode == 1
    assert result.stdout.splitlines() == [
        "STOP the baseline cannot be restored by appending "
        "the missing key lines; nothing changed"
    ]
    assert calls.read_text().splitlines() == []
    assert writes.read_text().splitlines() == []
    assert live.read_bytes() == before
    assert list(tmpdir.iterdir()) == []


def test_readd_newton_keys_stops_before_a_write_for_a_missing_line_before_kept(
        tmp_path):
    baseline = tmp_path / "baseline.authorized_keys"
    live = tmp_path / "authorized_keys"
    keys = tmp_path / "keys"
    calls = tmp_path / "calls"
    rsh_calls = tmp_path / "rsh-calls"
    writes = tmp_path / "writes"
    tmpdir = tmp_path / "tmp"
    keys.mkdir()
    tmpdir.mkdir()
    plain = "ssh-ed25519 AAAAPLAIN user@example\n"
    alice = newton_line("alice", "read")
    bob = newton_line("bob", "read")
    baseline.write_text(plain + alice + bob)
    live.write_text(plain + bob)
    (keys / "lab-r1-alice").write_text("alice private\n")
    before = live.read_bytes()
    calls.write_text("")
    rsh_calls.write_text("")
    writes.write_text("")
    result = run_bash(stub_readd_code(), strict=True, env={
        "BASELINE": baseline,
        "KEYS_DIR": keys,
        "DEVICE": "lab-r1",
        "LIVE": live,
        "CALLS": calls,
        "RSH_CALLS": rsh_calls,
        "WRITES": writes,
        "ALICE_LINE": alice.rstrip("\n"),
        "TMPDIR": tmpdir,
    })
    assert result.returncode == 1
    assert result.stdout.splitlines() == [
        "== keep bob already on the router",
        "STOP the baseline cannot be restored by appending "
        "the missing key lines; nothing changed"
    ]
    assert calls.read_text().splitlines() == []
    assert writes.read_text().splitlines() == []
    assert live.read_bytes() == before
    assert list(tmpdir.iterdir()) == []


def test_readd_newton_keys_stops_on_a_different_line_for_a_label(tmp_path):
    baseline = tmp_path / "baseline.authorized_keys"
    live = tmp_path / "authorized_keys"
    keys = tmp_path / "keys"
    calls = tmp_path / "calls"
    rsh_calls = tmp_path / "rsh-calls"
    writes = tmp_path / "writes"
    tmpdir = tmp_path / "tmp"
    keys.mkdir()
    tmpdir.mkdir()
    plain = "ssh-ed25519 AAAAPLAIN user@example\n"
    alice = newton_line("alice", "change")
    changed_alice = alice.replace("AAAAALICE", "AAAACHANGED")
    bob = newton_line("bob", "read")
    baseline.write_text(plain + alice + bob)
    live.write_text(plain + changed_alice)
    (keys / "lab-r1-alice").write_text("alice private\n")
    (keys / "lab-r1-bob").write_text("bob private\n")
    before = live.read_bytes()
    calls.write_text("")
    rsh_calls.write_text("")
    writes.write_text("")
    result = run_bash(stub_readd_code(), strict=True, env={
        "BASELINE": baseline,
        "KEYS_DIR": keys,
        "DEVICE": "lab-r1",
        "LIVE": live,
        "CALLS": calls,
        "RSH_CALLS": rsh_calls,
        "WRITES": writes,
        "ALICE_LINE": alice.rstrip("\n"),
        "TMPDIR": tmpdir,
    })
    assert result.returncode == 1
    assert result.stdout.splitlines() == [
        "STOP a different Newton key line for alice is on the router; "
        "not replaced"
    ]
    assert calls.read_text().splitlines() == []
    assert writes.read_text().splitlines() == []
    assert live.read_bytes() == before
    assert list(tmpdir.iterdir()) == []


def test_readd_newton_keys_stops_before_a_write_for_a_later_conflict(
        tmp_path):
    baseline = tmp_path / "baseline.authorized_keys"
    live = tmp_path / "authorized_keys"
    keys = tmp_path / "keys"
    calls = tmp_path / "calls"
    rsh_calls = tmp_path / "rsh-calls"
    writes = tmp_path / "writes"
    tmpdir = tmp_path / "tmp"
    keys.mkdir()
    tmpdir.mkdir()
    plain = "ssh-ed25519 AAAAPLAIN user@example\n"
    alice = newton_line("alice", "read")
    bob = newton_line("bob", "change")
    changed_bob = bob.replace("AAAABOB", "AAAACHANGED")
    baseline.write_text(plain + alice + bob)
    live.write_text(plain + changed_bob)
    (keys / "lab-r1-alice").write_text("alice private\n")
    before = live.read_bytes()
    calls.write_text("")
    rsh_calls.write_text("")
    writes.write_text("")
    result = run_bash(stub_readd_code(), strict=True, env={
        "BASELINE": baseline,
        "KEYS_DIR": keys,
        "DEVICE": "lab-r1",
        "LIVE": live,
        "CALLS": calls,
        "RSH_CALLS": rsh_calls,
        "WRITES": writes,
        "ALICE_LINE": alice.rstrip("\n"),
        "TMPDIR": tmpdir,
    })
    assert result.returncode == 1
    assert result.stdout.splitlines() == [
        "STOP a different Newton key line for bob is on the router; "
        "not replaced"
    ]
    assert calls.read_text().splitlines() == []
    assert writes.read_text().splitlines() == []
    assert live.read_bytes() == before
    assert list(tmpdir.iterdir()) == []


def test_readd_newton_keys_counts_a_bad_role_router_line_as_a_conflict(
        tmp_path):
    baseline = tmp_path / "baseline.authorized_keys"
    live = tmp_path / "authorized_keys"
    keys = tmp_path / "keys"
    calls = tmp_path / "calls"
    rsh_calls = tmp_path / "rsh-calls"
    writes = tmp_path / "writes"
    tmpdir = tmp_path / "tmp"
    keys.mkdir()
    tmpdir.mkdir()
    plain = "ssh-ed25519 AAAAPLAIN user@example\n"
    alice = newton_line("alice", "read")
    bad_role = (
        "restrict,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,"
        'no-pty,command="/usr/libexec/newton/newton-router --caller=alice '
        '--role=admin" ssh-ed25519 AAAAROUTER newton-router-alice\n'
    )
    baseline.write_text(plain + alice)
    live.write_text(plain + bad_role)
    (keys / "lab-r1-alice").write_text("alice private\n")
    before = live.read_bytes()
    calls.write_text("")
    rsh_calls.write_text("")
    writes.write_text("")
    result = run_bash(stub_readd_code(), strict=True, env={
        "BASELINE": baseline,
        "KEYS_DIR": keys,
        "DEVICE": "lab-r1",
        "LIVE": live,
        "CALLS": calls,
        "RSH_CALLS": rsh_calls,
        "WRITES": writes,
        "ALICE_LINE": alice.rstrip("\n"),
        "TMPDIR": tmpdir,
    })
    assert result.returncode == 1
    assert result.stdout.splitlines() == [
        "STOP a different Newton key line for alice is on the router; "
        "not replaced"
    ]
    assert calls.read_text().splitlines() == []
    assert writes.read_text().splitlines() == []
    assert live.read_bytes() == before
    assert list(tmpdir.iterdir()) == []


def test_readd_newton_keys_stops_when_the_baseline_has_a_label_twice(
        tmp_path):
    baseline = tmp_path / "baseline.authorized_keys"
    live = tmp_path / "authorized_keys"
    keys = tmp_path / "keys"
    calls = tmp_path / "calls"
    rsh_calls = tmp_path / "rsh-calls"
    writes = tmp_path / "writes"
    tmpdir = tmp_path / "tmp"
    keys.mkdir()
    tmpdir.mkdir()
    plain = "ssh-ed25519 AAAAPLAIN user@example\n"
    alice_change = newton_line("alice", "change")
    alice_read = newton_line("alice", "read")
    baseline.write_text(plain + alice_change + alice_read)
    live.write_text(plain)
    (keys / "lab-r1-alice").write_text("alice private\n")
    before = live.read_bytes()
    calls.write_text("")
    rsh_calls.write_text("")
    writes.write_text("")
    result = run_bash(stub_readd_code(), strict=True, env={
        "BASELINE": baseline,
        "KEYS_DIR": keys,
        "DEVICE": "lab-r1",
        "LIVE": live,
        "CALLS": calls,
        "RSH_CALLS": rsh_calls,
        "WRITES": writes,
        "ALICE_LINE": alice_change.rstrip("\n"),
        "TMPDIR": tmpdir,
    })
    assert result.returncode == 1
    assert result.stdout.splitlines() == [
        "STOP the baseline has two Newton key lines for alice"]
    assert calls.read_text().splitlines() == []
    assert writes.read_text().splitlines() == []
    assert live.read_bytes() == before
    assert list(tmpdir.iterdir()) == []


def test_readd_newton_keys_stops_when_the_router_has_a_label_twice(tmp_path):
    baseline = tmp_path / "baseline.authorized_keys"
    live = tmp_path / "authorized_keys"
    keys = tmp_path / "keys"
    calls = tmp_path / "calls"
    rsh_calls = tmp_path / "rsh-calls"
    writes = tmp_path / "writes"
    tmpdir = tmp_path / "tmp"
    keys.mkdir()
    tmpdir.mkdir()
    plain = "ssh-ed25519 AAAAPLAIN user@example\n"
    alice = newton_line("alice", "read")
    extra_alice = newton_line("alice", "change")
    bob = newton_line("bob", "read")
    baseline.write_text(plain + alice + bob)
    live.write_text(plain + alice + extra_alice)
    (keys / "lab-r1-bob").write_text("bob private\n")
    before = live.read_bytes()
    calls.write_text("")
    rsh_calls.write_text("")
    writes.write_text("")
    result = run_bash(stub_readd_code(), strict=True, env={
        "BASELINE": baseline,
        "KEYS_DIR": keys,
        "DEVICE": "lab-r1",
        "LIVE": live,
        "CALLS": calls,
        "RSH_CALLS": rsh_calls,
        "WRITES": writes,
        "ALICE_LINE": alice.rstrip("\n"),
        "TMPDIR": tmpdir,
    })
    assert result.returncode == 1
    assert result.stdout.splitlines() == [
        "STOP alice has 2 key lines on the router; not replaced"]
    assert calls.read_text().splitlines() == []
    assert writes.read_text().splitlines() == []
    assert live.read_bytes() == before
    assert list(tmpdir.iterdir()) == []


def test_readd_newton_keys_stops_on_a_router_line_ending_at_the_label(
        tmp_path):
    baseline = tmp_path / "baseline.authorized_keys"
    live = tmp_path / "authorized_keys"
    keys = tmp_path / "keys"
    calls = tmp_path / "calls"
    rsh_calls = tmp_path / "rsh-calls"
    writes = tmp_path / "writes"
    tmpdir = tmp_path / "tmp"
    keys.mkdir()
    tmpdir.mkdir()
    plain = "ssh-ed25519 AAAAPLAIN user@example\n"
    alice = newton_line("alice", "read")
    label_at_eol = (
        "restrict,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,"
        'no-pty,command="/usr/libexec/newton/newton-router --caller=alice\n'
    )
    baseline.write_text(plain + alice)
    live.write_text(plain + label_at_eol)
    (keys / "lab-r1-alice").write_text("alice private\n")
    before = live.read_bytes()
    calls.write_text("")
    rsh_calls.write_text("")
    writes.write_text("")
    result = run_bash(stub_readd_code(), strict=True, env={
        "BASELINE": baseline,
        "KEYS_DIR": keys,
        "DEVICE": "lab-r1",
        "LIVE": live,
        "CALLS": calls,
        "RSH_CALLS": rsh_calls,
        "WRITES": writes,
        "ALICE_LINE": alice.rstrip("\n"),
        "TMPDIR": tmpdir,
    })
    assert result.returncode == 1
    assert result.stdout.splitlines() == [
        "STOP a different Newton key line for alice is on the router; "
        "not replaced"
    ]
    assert calls.read_text().splitlines() == []
    assert writes.read_text().splitlines() == []
    assert live.read_bytes() == before
    assert list(tmpdir.iterdir()) == []


def test_readd_newton_keys_counts_a_skipped_baseline_line_for_its_label(
        tmp_path):
    baseline = tmp_path / "baseline.authorized_keys"
    live = tmp_path / "authorized_keys"
    keys = tmp_path / "keys"
    calls = tmp_path / "calls"
    rsh_calls = tmp_path / "rsh-calls"
    writes = tmp_path / "writes"
    tmpdir = tmp_path / "tmp"
    keys.mkdir()
    tmpdir.mkdir()
    plain = "ssh-ed25519 AAAAPLAIN user@example\n"
    alice = newton_line("alice", "read")
    admin_role = (
        "restrict,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,"
        'no-pty,command="/usr/libexec/newton/newton-router --caller=alice '
        '--role=admin" ssh-ed25519 AAAAADMIN newton-router-alice\n'
    )
    baseline.write_text(plain + alice + admin_role)
    live.write_text(plain)
    (keys / "lab-r1-alice").write_text("alice private\n")
    before = live.read_bytes()
    calls.write_text("")
    rsh_calls.write_text("")
    writes.write_text("")
    result = run_bash(stub_readd_code(), strict=True, env={
        "BASELINE": baseline,
        "KEYS_DIR": keys,
        "DEVICE": "lab-r1",
        "LIVE": live,
        "CALLS": calls,
        "RSH_CALLS": rsh_calls,
        "WRITES": writes,
        "ALICE_LINE": alice.rstrip("\n"),
        "TMPDIR": tmpdir,
    })
    assert result.returncode == 1
    assert result.stdout.splitlines() == [
        "STOP the baseline has two Newton key lines for alice"]
    assert calls.read_text().splitlines() == []
    assert writes.read_text().splitlines() == []
    assert live.read_bytes() == before
    assert list(tmpdir.iterdir()) == []


def test_readd_newton_keys_does_not_treat_a_prefix_label_as_present(
        tmp_path):
    baseline = tmp_path / "baseline.authorized_keys"
    live = tmp_path / "authorized_keys"
    keys = tmp_path / "keys"
    calls = tmp_path / "calls"
    rsh_calls = tmp_path / "rsh-calls"
    writes = tmp_path / "writes"
    tmpdir = tmp_path / "tmp"
    keys.mkdir()
    tmpdir.mkdir()
    plain = "ssh-ed25519 AAAAPLAIN user@example\n"
    alice = newton_line("alice", "read")
    alic = newton_line("alic", "read")
    baseline.write_text(plain + alice + alic)
    live.write_text(plain + alice)
    calls.write_text("")
    rsh_calls.write_text("")
    writes.write_text("")
    result = run_bash(stub_readd_code(), strict=True, env={
        "BASELINE": baseline,
        "KEYS_DIR": keys,
        "DEVICE": "lab-r1",
        "LIVE": live,
        "CALLS": calls,
        "RSH_CALLS": rsh_calls,
        "WRITES": writes,
        "ALICE_LINE": alice.rstrip("\n"),
        "TMPDIR": tmpdir,
    })
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines() == [
        "== keep alice already on the router",
        "== re-add alic byte-exact rc=0",
    ]
    assert calls.read_text().splitlines() == []
    assert len(writes.read_text().splitlines()) == 1
    assert live.read_bytes() == baseline.read_bytes()
    assert list(tmpdir.iterdir()) == []


def test_remote_readd_refuses_a_stdin_record_without_a_line(tmp_path):
    router_file = tmp_path / "authorized_keys"
    tmpdir = tmp_path / "tmp"
    tmpdir.mkdir()
    router_file.write_text("ssh-ed25519 AAAAPLAIN user@example\n")
    before = router_file.read_bytes()
    result = run_remote_readd(
        router_file,
        stdin="alice\n",
        tmpdir=tmpdir,
    )
    assert result.returncode != 0
    assert router_file.read_bytes() == before
    assert list(tmpdir.iterdir()) == []


def test_remote_readd_refuses_a_quote_bounded_existing_label(tmp_path):
    router_file = tmp_path / "authorized_keys"
    tmpdir = tmp_path / "tmp"
    tmpdir.mkdir()
    plain = "ssh-ed25519 AAAAPLAIN user@example\n"
    alice = newton_line("alice", "read")
    conflict = alice.replace(" --role=read", "")
    router_file.write_text(plain + conflict)
    before = router_file.read_bytes()
    result = run_remote_readd(
        router_file,
        stdin="alice\n" + alice,
        tmpdir=tmpdir,
    )
    assert result.returncode != 0
    assert router_file.read_bytes() == before
    assert list(tmpdir.iterdir()) == []


def test_readd_newton_keys_stops_when_the_final_hash_differs(tmp_path):
    baseline = tmp_path / "baseline.authorized_keys"
    live = tmp_path / "authorized_keys"
    keys = tmp_path / "keys"
    calls = tmp_path / "calls"
    tmpdir = tmp_path / "tmp"
    keys.mkdir()
    tmpdir.mkdir()
    plain = "ssh-ed25519 AAAAPLAIN user@example\n"
    workstation = newton_line("workstation", "change")
    baseline.write_text(plain + workstation)
    live.write_text(plain)
    code = stub_readd_code().replace(
        'sh -c "$script"\n\t\t\treturn $?',
        'sh -c "$script"\n'
        '\t\t\tprintf \'%s\\n\' wrong-bytes >> "$LIVE"\n'
        '\t\t\treturn $?',
    )
    result = run_bash(code, strict=True, env={
        "BASELINE": baseline,
        "KEYS_DIR": keys,
        "DEVICE": "lab-r1",
        "LIVE": live,
        "CALLS": calls,
        "ALICE_LINE": "",
        "TMPDIR": tmpdir,
    })
    assert result.returncode == 1
    assert result.stdout.splitlines()[-1] == (
        "STOP authorized_keys differs from the baseline")
    assert list(tmpdir.iterdir()) == []


def test_readd_newton_keys_stops_when_the_initial_read_fails(tmp_path):
    baseline = tmp_path / "baseline.authorized_keys"
    baseline.write_text("")
    tmpdir = tmp_path / "tmp"
    tmpdir.mkdir()
    result = run_bash(
        'rsh() { return 7; }\n'
        'readd_newton_keys "$BASELINE" "$KEYS_DIR" "$DEVICE"\n',
        strict=True,
        env={
            "BASELINE": baseline,
            "KEYS_DIR": tmp_path,
            "DEVICE": "lab-r1",
            "TMPDIR": tmpdir,
        },
    )
    assert result.returncode == 7
    assert "STOP cannot read authorized_keys" in result.stdout.splitlines()
    assert list(tmpdir.iterdir()) == []


def test_readd_newton_keys_stops_when_the_final_read_fails(tmp_path):
    baseline = tmp_path / "baseline.authorized_keys"
    state = tmp_path / "rsh-state"
    tmpdir = tmp_path / "tmp"
    baseline.write_text("")
    tmpdir.mkdir()
    result = run_bash(
        'rsh() {\n'
        '\tcase "$1" in\n'
        "\t\t'cat /etc/dropbear/authorized_keys')\n"
        '\t\t\t[[ -e "$STATE" ]] && return 7\n'
        '\t\t\t: >"$STATE"\n'
        '\t\t\treturn 0\n'
        '\t\t\t;;\n'
        '\tesac\n'
        '\treturn 9\n'
        '}\n'
        'readd_newton_keys "$BASELINE" "$KEYS_DIR" "$DEVICE"\n',
        strict=True,
        env={
            "BASELINE": baseline,
            "KEYS_DIR": tmp_path,
            "DEVICE": "lab-r1",
            "STATE": state,
            "TMPDIR": tmpdir,
        },
    )
    assert result.returncode == 7
    assert "STOP cannot read authorized_keys" in result.stdout.splitlines()
    assert state.exists()
    assert list(tmpdir.iterdir()) == []


def test_readd_newton_keys_fails_quietly_when_the_baseline_hash_fails(tmp_path):
    # the baseline hash read has the same set -e hazard as the final read:
    # a failure must return non-zero without the misleading
    # "authorized_keys differs" STOP line or a leaked temp file
    baseline = tmp_path / "baseline.authorized_keys"  # never created
    tmpdir = tmp_path / "tmp"
    tmpdir.mkdir()
    result = run_bash(
        'rsh() { return 0; }\n'
        'readd_newton_keys "$BASELINE" "$KEYS_DIR" "$DEVICE"\n',
        strict=True,
        env={
            "BASELINE": baseline,
            "KEYS_DIR": tmp_path,
            "DEVICE": "lab-r1",
            "TMPDIR": tmpdir,
        },
    )
    assert result.returncode == 1
    assert result.stdout == ""
    assert list(tmpdir.iterdir()) == []


def test_readd_newton_keys_remote_guard_stops_a_duplicate_label(tmp_path):
    baseline = tmp_path / "baseline.authorized_keys"
    live = tmp_path / "authorized_keys"
    keys = tmp_path / "keys"
    calls = tmp_path / "calls"
    tmpdir = tmp_path / "tmp"
    keys.mkdir()
    tmpdir.mkdir()
    workstation = newton_line("workstation", "change")
    baseline.write_text(workstation)
    live.write_text(workstation)
    before = live.read_bytes()
    result = run_bash(stub_readd_code(), strict=True, env={
        "BASELINE": baseline,
        "KEYS_DIR": keys,
        "DEVICE": "lab-r1",
        "LIVE": live,
        "CALLS": calls,
        "AK_TEXT": "",
        "ALICE_LINE": "",
        "TMPDIR": tmpdir,
    })
    assert result.returncode == 1
    assert result.stdout.splitlines() == [
        "== re-add workstation byte-exact rc=1"]
    assert live.read_bytes() == before
    assert list(tmpdir.iterdir()) == []


def test_readd_newton_keys_remote_guard_stops_without_a_final_newline(
        tmp_path):
    baseline = tmp_path / "baseline.authorized_keys"
    live = tmp_path / "authorized_keys"
    keys = tmp_path / "keys"
    calls = tmp_path / "calls"
    tmpdir = tmp_path / "tmp"
    keys.mkdir()
    tmpdir.mkdir()
    plain = "ssh-ed25519 AAAAPLAIN user@example"
    workstation = newton_line("workstation", "change")
    baseline.write_text(plain + "\n" + workstation)
    live.write_text(plain)
    before = live.read_bytes()
    result = run_bash(stub_readd_code(), strict=True, env={
        "BASELINE": baseline,
        "KEYS_DIR": keys,
        "DEVICE": "lab-r1",
        "LIVE": live,
        "CALLS": calls,
        "AK_TEXT": plain + "\n",
        "ALICE_LINE": "",
        "TMPDIR": tmpdir,
    })
    assert result.returncode == 1
    assert result.stdout.splitlines() == [
        "== re-add workstation byte-exact rc=1"]
    assert live.read_bytes() == before
    assert list(tmpdir.iterdir()) == []


def test_readd_newton_keys_remote_guard_fails_closed_when_grep_errors(
        tmp_path):
    live = tmp_path / "authorized_keys"
    tmpdir = tmp_path / "tmp"
    tmpdir.mkdir()
    workstation = newton_line("workstation", "change").rstrip("\n")
    live.write_text("ssh-ed25519 AAAPLAIN user@example\n")
    before = live.read_bytes()
    result = run_remote_readd(
        live,
        stdin="workstation\n" + workstation + "\n",
        tmpdir=tmpdir,
        prelude="grep() { return 2; }",
    )
    assert result.returncode != 0
    assert live.read_bytes() == before


def test_readd_newton_keys_remote_guard_fails_closed_when_tail_errors(
        tmp_path):
    live = tmp_path / "authorized_keys"
    tmpdir = tmp_path / "tmp"
    tmpdir.mkdir()
    workstation = newton_line("workstation", "change").rstrip("\n")
    live.write_text("ssh-ed25519 AAAPLAIN user@example\n")
    before = live.read_bytes()
    result = run_remote_readd(
        live,
        stdin="workstation\n" + workstation + "\n",
        tmpdir=tmpdir,
        prelude="tail() { return 1; }",
    )
    assert result.returncode != 0
    assert live.read_bytes() == before


def test_readd_newton_keys_stops_on_the_first_add_key_failure(tmp_path):
    baseline = tmp_path / "baseline.authorized_keys"
    live = tmp_path / "authorized_keys"
    keys = tmp_path / "keys"
    calls = tmp_path / "calls"
    tmpdir = tmp_path / "tmp"
    keys.mkdir()
    tmpdir.mkdir()
    alice = newton_line("alice", "change")
    workstation = newton_line("workstation", "change")
    baseline.write_text(alice + workstation)
    live.write_text("")
    (keys / "lab-r1-alice").write_text("alice private\n")
    failing_setup = stub_readd_code().replace(
        '[ "$2" = alice ] || return 7', 'return 7')
    result = run_bash(failing_setup, strict=True, env={
        "BASELINE": baseline,
        "KEYS_DIR": keys,
        "DEVICE": "lab-r1",
        "LIVE": live,
        "CALLS": calls,
        "ALICE_LINE": "",
        "TMPDIR": tmpdir,
    })
    assert result.returncode == 7
    assert calls.read_text().splitlines() == ["add-key alice change"]
    assert result.stdout.splitlines() == ["== re-add alice via add-key rc=7"]
    assert live.read_text() == ""
    assert list(tmpdir.iterdir()) == []


def test_baseline_diff_stops_when_authorized_keys_changed(tmp_path):
    before = tmp_path / "before"
    after = tmp_path / "after"
    before.write_text("aaa  etc/dropbear/authorized_keys\n")
    after.write_text("bbb  etc/dropbear/authorized_keys\n")
    result = run_bash(
        'baseline_diff_or_stop "$BEFORE" "$AFTER"\n',
        env={"BEFORE": before, "AFTER": after},
    )
    assert result.returncode == 1
    assert "  changed: etc/dropbear/authorized_keys" in result.stdout.splitlines()
    assert result.stdout.splitlines()[-1] == (
        "STOP authorized_keys differs from the baseline: a key was removed or not restored"
    )


def test_baseline_diff_stops_when_a_leading_slash_spelling_of_keys_changed(
        tmp_path):
    before = tmp_path / "before"
    after = tmp_path / "after"
    before.write_text("aaa  /etc/dropbear/authorized_keys\n")
    after.write_text("bbb  /etc/dropbear/authorized_keys\n")
    result = run_bash(
        'baseline_diff_or_stop "$BEFORE" "$AFTER"\n',
        env={"BEFORE": before, "AFTER": after},
    )
    assert result.returncode == 1
    assert "  changed: etc/dropbear/authorized_keys" \
        in result.stdout.splitlines()
    assert result.stdout.splitlines()[-1] == (
        "STOP authorized_keys differs from the baseline: "
        "a key was removed or not restored"
    )


def test_baseline_diff_returns_zero_for_identical_fingerprints(tmp_path):
    before = tmp_path / "before"
    after = tmp_path / "after"
    content = "aaa  etc/dropbear/authorized_keys\nbbb  etc/config/network\n"
    before.write_text(content)
    after.write_text(content)
    result = run_bash(
        'baseline_diff_or_stop "$BEFORE" "$AFTER"\n',
        env={"BEFORE": before, "AFTER": after},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout == ""


def test_baseline_diff_ignores_only_lkg_and_the_exact_guard_log(tmp_path):
    before = tmp_path / "before"
    after = tmp_path / "after"
    before.write_text(
        "aaa  etc/newton/lkg/anything/deep\n"
        "bbb  etc/newton/guard.log\n"
        "ccc  etc/config/network\n"
    )
    after.write_text(
        "zzz  etc/newton/lkg/anything/deep\n"
        "zzz  /etc/newton/guard.log\n"
        "ccc  etc/config/network\n"
    )
    result = run_bash(
        'baseline_diff_or_stop "$BEFORE" "$AFTER"\n',
        env={"BEFORE": before, "AFTER": after},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout == ""


def test_baseline_diff_stops_for_guard_log_rotation(tmp_path):
    before = tmp_path / "before"
    after = tmp_path / "after"
    before.write_text("aaa  etc/newton/guard.log\n")
    after.write_text("aaa  etc/newton/guard.log.1\n")
    result = run_bash(
        'baseline_diff_or_stop "$BEFORE" "$AFTER"\n',
        env={"BEFORE": before, "AFTER": after},
    )
    assert result.returncode == 1
    assert result.stdout.splitlines()[-1] == "STOP files differ from the baseline"


def test_baseline_diff_stops_when_any_other_file_changes(tmp_path):
    before = tmp_path / "before"
    after = tmp_path / "after"
    before.write_text(
        "aaa  etc/newton/lkg/keep\nbbb  etc/config/network\n"
    )
    after.write_text(
        "aaa  etc/newton/lkg/keep\nzzz  etc/config/network\n"
    )
    result = run_bash(
        'baseline_diff_or_stop "$BEFORE" "$AFTER"\n',
        env={"BEFORE": before, "AFTER": after},
    )
    assert result.returncode == 1
    assert "  changed: etc/config/network" in result.stdout.splitlines()
    assert result.stdout.splitlines()[-1] == "STOP files differ from the baseline"


def test_baseline_diff_stops_when_a_non_key_file_vanished(tmp_path):
    before = tmp_path / "before"
    after = tmp_path / "after"
    before.write_text("aaa  etc/dropbear/authorized_keys\nbbb  etc/config/network\n")
    after.write_text("aaa  etc/dropbear/authorized_keys\n")
    result = run_bash(
        'baseline_diff_or_stop "$BEFORE" "$AFTER"\n',
        env={"BEFORE": before, "AFTER": after},
    )
    assert result.returncode == 1
    assert "  files: etc/config/network" in result.stdout.splitlines()
    assert result.stdout.splitlines()[-1] == "STOP files differ from the baseline"
