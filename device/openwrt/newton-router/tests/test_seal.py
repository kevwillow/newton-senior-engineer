"""Design 3.5b, 3.6 and 5.4: sealing and transaction plan files."""

import fcntl
import hashlib
import os
import subprocess
import time

import pytest

from conftest import SID


SID2 = "fedcba9876543210fedcba9876543210"
DIFF = b"dhcp.cfg01.domain='lan'\n"
EMPTY_SHA = hashlib.sha256(b"").hexdigest()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def lock_is_free(router):
    result = subprocess.run(
        ["/usr/bin/flock", "-n", str(router.root / "tmp/newton/flock"), "/bin/true"],
        capture_output=True,
        timeout=5,
    )
    return result.returncode == 0


def staged(router, sid=SID, batch=b"set dhcp.cfg01.domain=lan\n", diff=DIFF):
    router.use_stub_helper()
    router.write("control/diff.txt", diff)
    result = router.stage(batch=batch, sid=sid)
    assert (result.rc, result.out, result.err) == (0, sid + "\n", "")
    return router.txn(sid)


def digest_bytes(device, sid, base, diff, probes_sha, timeout):
    return (
        f"newton-plan-v1\n{device}\n{sid}\n{base}\n{diff}\n"
        f"{probes_sha}\n{timeout}\n"
    ).encode()


def expected_values(router, sid, timeout, probes, diff=DIFF, device="lab-r1"):
    base = sha(router.confighash_text().encode())
    diff_sha = sha(diff)
    probes_sha = sha(probes)
    digest = sha(digest_bytes(device, sid, base, diff_sha, probes_sha, timeout))
    return base, diff_sha, probes_sha, digest


def assert_success(router, result, sid, timeout, probes, profile, approval, diff=DIFF,
                   device="lab-r1"):
    base, diff_sha, probes_sha, digest = expected_values(
        router, sid, timeout, probes, diff, device
    )
    lines = result.out.splitlines()
    assert result.rc == 0 and result.err == ""
    assert lines[:5] == [
        f"base {base}",
        f"diff {diff_sha}",
        f"probes {len(probes.splitlines())} {probes_sha}",
        f"t {timeout}",
        f"profile {profile}",
    ]
    assert lines[-2:] == [f"approval {approval}", f"digest {digest}"]
    assert all(line.startswith(("section ", "leash ")) for line in lines[5:-2])
    txn = router.txn(sid)
    expected_files = {
        "t": f"{timeout}\n".encode(),
        "base": f"{base}\n".encode(),
        "diff": f"{diff_sha}\n".encode(),
        "probes": probes,
        "probes-sha": f"{probes_sha}\n".encode(),
        "profile": f"{profile}\n".encode(),
        "leash": ("\n".join(lines[5:-2]) + ("\n" if lines[5:-2] else "")).encode(),
        "digest": f"{digest}\n".encode(),
        "sealed": b"",
    }
    for name, content in expected_files.items():
        assert (txn / name).read_bytes() == content, name
    assert lock_is_free(router)
    return base, diff_sha, probes_sha, digest


@pytest.mark.parametrize(
    "probes",
    [b"", b"ping\t192.0.2.1\nfail\n"],
    ids=["without-probes", "with-probes"],
)
def test_seal_happy_path_output_digest_and_files(router, probes):
    staged(router)
    result = router.seal(SID, 90, probes)
    assert_success(router, result, SID, 90, probes, "lab", "not-required")
    logs = router.syslog()
    assert any(f"cmd=seal sid={SID[:8]} rc=0" in line for line in logs)
    assert all(SID not in line for line in logs)


@pytest.mark.parametrize(
    "content,profile,approval",
    [("lab\n", "lab", "not-required"), ("prod\n", "prod", "required"),
     (None, "prod", "required"), ("junk\n", "prod", "required")],
    ids=["lab", "prod", "missing", "junk"],
)
def test_seal_profile_rule(router, content, profile, approval):
    path = router.root / "etc/newton/profile"
    if content is None:
        path.unlink()
    else:
        path.write_text(content)
    staged(router)
    result = router.seal(SID, 90)
    assert_success(router, result, SID, 90, b"", profile, approval)


def test_seal_unreadable_profile_fails_closed_to_prod(router):
    if os.geteuid() == 0:
        pytest.skip("root can read mode-000 files")
    profile = router.root / "etc/newton/profile"
    profile.chmod(0)
    staged(router)
    result = router.seal(SID, 90)
    assert_success(router, result, SID, 90, b"", "prod", "required")


@pytest.mark.parametrize("ingredient", ["device", "sid", "base", "diff", "probes", "t"])
def test_plan_digest_changes_with_every_ingredient(router, ingredient):
    baseline_base, baseline_diff, baseline_psha, baseline_digest = expected_values(
        router, SID, 90, b""
    )
    actual_sid, actual_t, actual_probes, actual_diff, device = SID, 90, b"", DIFF, "lab-r1"
    if ingredient == "device":
        device = "lab-r2"
        router.write("etc/newton/device-id", device + "\n")
    elif ingredient == "sid":
        actual_sid = SID2
    elif ingredient == "base":
        router.write("etc/config/dhcp", b"config dnsmasq\n\toption domainneeded '0'\n")
    elif ingredient == "diff":
        actual_diff = b"dhcp.cfg01.domain='example'\n"
    elif ingredient == "probes":
        actual_probes = b"fail\n"
    else:
        actual_t = 91
    staged(router, sid=actual_sid, diff=actual_diff)
    result = router.seal(actual_sid, actual_t, actual_probes)
    values = assert_success(
        router, result, actual_sid, actual_t, actual_probes, "lab", "not-required",
        actual_diff, device,
    )
    assert values[3] != baseline_digest
    changed = [device != "lab-r1", actual_sid != SID, values[0] != baseline_base,
               values[1] != baseline_diff, values[2] != baseline_psha, actual_t != 90]
    assert sum(changed) == 1


# etc/newton/device-id is operator-written and may lack a trailing newline;
# BusyBox `read` returns rc=1 in that case but has set the variable, and the
# old `|| dev=-` then cleared it. plan_digest must include the actual value.
def test_plan_digest_device_id_no_trailing_newline(router):
    device = "lab-r2"
    router.write("etc/newton/device-id", device.encode())
    staged(router)
    result = router.seal(SID, 90)
    assert_success(
        router, result, SID, 90, b"", "lab", "not-required",
        DIFF, device,
    )


def assert_nothing_sealed(txn, allowed=()):
    for name in ("sealed", "t", "base", "diff", "probes", "probes-sha", "profile", "leash", "digest"):
        if name not in allowed:
            assert not (txn / name).exists(), name


def test_seal_no_such_transaction(router):
    router.use_stub_helper()
    result = router.seal(SID, 90)
    assert (result.rc, result.out, result.err) == (3, "", "error no-such-txn\n")
    assert lock_is_free(router)


def test_seal_other_caller_is_not_owner(router):
    txn = staged(router)
    result = router.seal(SID, 90, caller="agent-two")
    assert (result.rc, result.out, result.err) == (3, "", "error not-owner\n")
    assert_nothing_sealed(txn)
    assert lock_is_free(router)


def test_seal_read_role_is_refused(router):
    txn = staged(router)
    result = router.seal(SID, 90, role="read")
    assert (result.rc, result.out, result.err) == (3, "", "error role\n")
    assert_nothing_sealed(txn)
    assert lock_is_free(router)


def test_seal_session_gone(router):
    txn = staged(router)
    router.write("control/sessions", b"")
    result = router.seal(SID, 90)
    assert (result.rc, result.out, result.err) == (3, "", "error session-gone\n")
    assert_nothing_sealed(txn)
    assert lock_is_free(router)


def test_seal_already_sealed(router):
    txn = staged(router)
    (txn / "sealed").touch()
    result = router.seal(SID, 90)
    assert (result.rc, result.out, result.err) == (3, "", "error already-sealed\n")
    assert_nothing_sealed(txn, allowed={"sealed"})
    assert lock_is_free(router)


@pytest.mark.parametrize("marker", ["applying", "applied"])
def test_seal_already_applied(router, marker):
    txn = staged(router)
    (txn / marker).write_text("marker\n")
    result = router.seal(SID, 90)
    assert (result.rc, result.out, result.err) == (1, "", "error already-applied\n")
    assert_nothing_sealed(txn)
    assert lock_is_free(router)


def line_of_length(length):
    prefix = b"nft-rule\tinet\tfw4\truleset\tpresent\t"
    fields = [b"x" * 128, b"x" * 128, b"x" * 128]
    final = length - len(prefix) - sum(map(len, fields)) - 3
    data = prefix + b"\t".join(fields + [b"x" * final])
    assert len(data) == length and 1 <= final <= 128
    return data


def probes_4096():
    prefix = b"uci-equals\tnetwork.lan.proto\t"
    line = prefix + b"x" * (127 - len(prefix)) + b"\n"
    assert len(line) == 128
    return line * 32


@pytest.mark.parametrize(
    "data,accepted,error",
    [
        (b"", True, None),
        (b"fail\n" * 32, True, None),
        (b"fail\n" * 33, False, "error bad-probe 33 too-many\n"),
        (probes_4096(), True, None),
        (probes_4096() + b"x", False, "error bad-probe 33 too-long\n"),
        (line_of_length(512) + b"\n", True, None),
        (line_of_length(513) + b"\n", False, "error bad-probe 1 too-long\n"),
    ],
    ids=["empty", "32-lines", "33-lines", "4096-bytes", "4097-bytes", "512-line", "513-line"],
)
def test_seal_probe_limits(router, data, accepted, error):
    txn = staged(router)
    result = router.seal(SID, 90, data)
    if accepted:
        assert_success(router, result, SID, 90, data, "lab", "not-required")
    else:
        assert (result.rc, result.out, result.err) == (2, "", error)
        assert_nothing_sealed(txn)
        assert lock_is_free(router)


@pytest.mark.parametrize(
    "data,line,reason",
    [
        (b"fail\nping\t192.0.2.1", 2, "syntax"),
        (b"fail\n\n", 2, "syntax"),
        (b"fail\nno-such-probe\n", 2, "unknown-probe"),
        (b"fail\nping\n", 2, "arg-count"),
        (b"fail\nping\t-bad\n", 2, "bad-arg-1"),
        (b"fail\nlisten\ttcp\tany\t0\tany\tpresent\n", 2, "bad-arg-3"),
        (b"fail\nping\tbad\\host\n", 2, "syntax"),
    ],
    ids=["unterminated", "blank", "unknown", "arg-count", "bad-arg-1", "bad-arg-3", "backslash"],
)
def test_seal_bad_probe_reason_and_line(router, data, line, reason):
    txn = staged(router)
    result = router.seal(SID, 90, data)
    assert (result.rc, result.out, result.err) == (
        2, "", f"error bad-probe {line} {reason}\n"
    )
    assert_nothing_sealed(txn)
    assert lock_is_free(router)


def test_seal_confighash_rejects_symlink(router):
    txn = staged(router)
    (router.root / "etc/config/linked").symlink_to("dhcp")
    result = router.seal(SID, 90)
    assert (result.rc, result.out, result.err) == (
        1, "", "ERROR: confighash config entry the guard cannot copy: linked\n"
    )
    assert_nothing_sealed(txn)
    assert lock_is_free(router)


def test_seal_confighash_skips_guard_invalid_name(router):
    """A config file whose name fails the guard's valid_name rule is
    SKIPPED, not refused: seal succeeds and the base hash is the same as
    with that file absent (the guard protects, copies and restores
    nothing of it, so its edits never change the base or post hash)."""
    txn = staged(router)
    router.write("etc/config/bad name", "config test\n")
    result = router.seal(SID, 90)
    assert result.rc == 0
    assert result.err == ""
    base_with = next(
        line.split()[1] for line in result.out.splitlines()
        if line.startswith("base ")
    )
    assert base_with == sha(router.confighash_text().encode())
    (router.root / "etc/config/bad name").unlink()
    assert base_with == sha(router.confighash_text().encode())
    assert txn.joinpath("sealed").exists()
    assert lock_is_free(router)


def test_seal_confighash_skips_invalid_named_symlink_and_dir(router):
    """The `config entry the guard cannot copy` refusal applies only to
    entries whose name is valid_name; an invalid-named symlink or
    directory is skipped like the guard's skipped_line treats it."""
    txn = staged(router)
    (router.root / "etc/config/bad.link").symlink_to("dhcp")
    (router.root / "etc/config/bad.dir").mkdir()
    result = router.seal(SID, 90)
    assert result.rc == 0
    assert result.err == ""
    base = next(
        line.split()[1] for line in result.out.splitlines()
        if line.startswith("base ")
    )
    assert base == sha(router.confighash_text().encode())
    assert txn.joinpath("sealed").exists()
    assert lock_is_free(router)


def test_seal_diff_failure_stores_nothing(router):
    txn = staged(router)
    router.write("control/diff.rc", "1\n")
    result = router.seal(SID, 90)
    assert (result.rc, result.out, result.err) == (1, "", "")
    assert_nothing_sealed(txn)
    assert lock_is_free(router)


@pytest.mark.slow
def test_seal_open_stdin_times_out_without_holding_program_lock(router):
    # Slow by design: this waits for the real 30-second stdin watchdog.
    txn = staged(router)
    started = time.monotonic()
    proc, finish = router.forced_open_stdin_start(f"seal {SID} 90")
    lock_path = router.root / "tmp/newton/flock"
    with lock_path.open("a+b") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = finish(timeout=38)
        fcntl.flock(lock_file, fcntl.LOCK_UN)
    elapsed = time.monotonic() - started
    assert proc.returncode == 2
    assert (result.out, result.err) == ("", "error stdin-timeout\n")
    assert 29 <= elapsed < 38
    assert_nothing_sealed(txn)
    assert lock_is_free(router)


def test_seal_hashes_are_repeatable_across_fresh_transactions(router):
    probes = b"ping\t192.0.2.1\n"
    staged(router, sid=SID)
    first = router.seal(SID, 90, probes)
    first_values = assert_success(router, first, SID, 90, probes, "lab", "not-required")
    router.write("control/sessions", b"")
    staged(router, sid=SID2)
    second = router.seal(SID2, 90, probes)
    second_values = assert_success(router, second, SID2, 90, probes, "lab", "not-required")
    assert second_values[:3] == first_values[:3]


def test_empty_probe_hash_is_sha256_of_empty_bytes(router):
    staged(router)
    result = router.seal(SID, 90)
    _, _, probes_sha, _ = assert_success(
        router, result, SID, 90, b"", "lab", "not-required"
    )
    assert probes_sha == EMPTY_SHA
