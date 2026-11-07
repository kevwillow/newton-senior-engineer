"""R2 ap2: the doctor's two new F2 checks (design 7.2 row newton-doctor):

- restricted-key-unreadable: every regular file under the newton keys
  directory must be unreadable by the agent (a missing directory is a
  PASS with a note);
- router-line-restricted[NAME]: `sudo -u newton /usr/local/bin/
  newton-router-setup NAME check` exiting non-zero is INCONCLUSIVE; a
  report line starting with `FAIL proof ` is a FAIL naming it; both
  proof lines as whole lines is a PASS; anything else (including a
  report with no proof lines at all, which is what today's check action
  prints) is INCONCLUSIVE -- absence of a proof is not evidence of a
  violation.

Uses the NEWTON_DOCTOR_* seams only (the shared doctor_env fixture fakes
sudo/ssh and the filesystem root); nothing touches the real system.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_newton_isolation import DOCTOR, doctor_env, run  # noqa: E402


def write_setup_report(tmp_path, lines):
    report = tmp_path / "setup-check-report"
    report.write_text("".join(line + "\n" for line in lines))
    return str(report)


GOOD_REPORT = [
    "INFO release 24.10",
    "PASS tools 29/29 present",
    "PASS proof hello: restricted identity",
    "PASS proof unknown-and-empty: rejected",
    "DONE check r1",
]


# ---- restricted-key-unreadable ----


def test_doctor_restricted_key_pass_when_all_keys_unreadable(doctor_env, tmp_path):
    keys = doctor_env["root"] / "var/lib/newton/keys"
    keys.mkdir()
    key = keys / "r1-newton-mcp"
    key.write_text("made-up key bytes created by the test\n")
    key.chmod(0o000)

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS restricted-key-unreadable" in result.stdout
    assert "FAIL restricted-key-unreadable" not in result.stdout
    # the key content never reaches the output
    assert "made-up key bytes" not in result.stdout


def test_doctor_restricted_key_fails_when_a_key_is_readable(doctor_env, tmp_path):
    keys = doctor_env["root"] / "var/lib/newton/keys"
    keys.mkdir()
    key = keys / "r1-newton-mcp"
    key.write_text("made-up key bytes created by the test\n")
    key.chmod(0o644)

    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 1, result.stdout + result.stderr
    assert (
        "FAIL restricted-key-unreadable: agent can read %s" % key in result.stdout
    )
    # the key content never reaches the output
    assert "made-up key bytes" not in result.stdout


def test_doctor_restricted_key_passes_with_note_when_no_keys_directory(doctor_env):
    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS restricted-key-unreadable: no keys directory this account can see" in result.stdout


# ---- router-line-restricted[NAME] ----


def test_doctor_router_line_pass_on_both_proofs(doctor_env, tmp_path):
    env = doctor_env["env"].copy()
    args_log = tmp_path / "setup-args.txt"
    env["DOCTOR_STUB_SETUP_ARGS"] = str(args_log)
    env["DOCTOR_STUB_SETUP_REPORT"] = write_setup_report(tmp_path, GOOD_REPORT)

    result = run(DOCTOR, "--router", "root@192.0.2.1", "--device", "r1", env=env)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS router-line-restricted[r1]" in result.stdout
    # the sudo call: -u newton, the absolute launcher, NAME check; no -n
    # (the rule has no NOPASSWD, the maintainer types their password on the tty)
    args = args_log.read_text().splitlines()
    assert args == [
        "-u", "newton", "/usr/local/bin/newton-router-setup", "r1", "check",
    ]
    assert "-n" not in args


def test_doctor_router_line_setup_prompt_reaches_the_terminal(doctor_env, tmp_path):
    # after swap-key the setup tool's check asks "root password: " on
    # stderr and reads the answer from the terminal; the doctor must not
    # swallow that prompt, or the owner waits on a silent screen
    env = doctor_env["env"].copy()
    env["DOCTOR_STUB_SETUP_REPORT"] = write_setup_report(tmp_path, GOOD_REPORT)
    env["DOCTOR_STUB_SETUP_PROMPT"] = "root password: "

    result = run(DOCTOR, "--router", "root@192.0.2.1", "--device", "r1", env=env)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "root password: " in result.stderr
    assert "root password" not in result.stdout
    assert "PASS router-line-restricted[r1]" in result.stdout


def test_doctor_router_line_fail_on_first_fail_proof_line(doctor_env, tmp_path):
    # (b) the setup tool's own failing proof line is a FAIL naming the
    # first such line; it wins even when the other proof passed
    env = doctor_env["env"].copy()
    env["DOCTOR_STUB_SETUP_REPORT"] = write_setup_report(
        tmp_path,
        [
            "INFO release 24.10",
            "PASS proof hello: restricted identity",
            "FAIL proof unknown-and-empty: expected exit 2 for both 'id' and no-command; got exit 0 / 0",
            "DONE check r1",
        ],
    )

    result = run(DOCTOR, "--router", "root@192.0.2.1", "--device", "r1", env=env)

    assert result.returncode == 1, result.stdout + result.stderr
    assert (
        "FAIL router-line-restricted[r1]: FAIL proof unknown-and-empty: "
        "expected exit 2 for both 'id' and no-command; got exit 0 / 0"
        in result.stdout
    )
    assert "PASS router-line-restricted" not in result.stdout


def test_doctor_router_line_fail_names_first_fail_proof_line(doctor_env, tmp_path):
    # two failing proof lines: the FIRST one is named
    env = doctor_env["env"].copy()
    env["DOCTOR_STUB_SETUP_REPORT"] = write_setup_report(
        tmp_path,
        [
            "FAIL proof hello: expected caller=r1-newton-mcp; got 'other'",
            "FAIL proof unknown-and-empty: expected exit 2; got exit 0",
        ],
    )

    result = run(DOCTOR, "--router", "root@192.0.2.1", "--device", "r1", env=env)

    assert result.returncode == 1, result.stdout + result.stderr
    assert "FAIL router-line-restricted[r1]: FAIL proof hello:" in result.stdout
    assert "FAIL proof unknown-and-empty" not in result.stdout


def test_doctor_router_line_fail_proof_line_cut_at_200(doctor_env, tmp_path):
    env = doctor_env["env"].copy()
    long_line = "FAIL proof hello: got '" + "x" * 400 + "'"
    env["DOCTOR_STUB_SETUP_REPORT"] = write_setup_report(tmp_path, [long_line])

    result = run(DOCTOR, "--router", "root@192.0.2.1", "--device", "r1", env=env)

    assert result.returncode == 1, result.stdout + result.stderr
    fail_lines = [
        line
        for line in result.stdout.splitlines()
        if line.startswith("FAIL router-line-restricted[r1]:")
    ]
    assert len(fail_lines) == 1
    assert fail_lines[0].endswith("...[truncated]")
    assert len(fail_lines[0]) <= len("FAIL router-line-restricted[r1]: ") + 200 + len("...[truncated]")


def test_doctor_router_line_pass_needs_both_proofs_as_whole_lines(
    doctor_env, tmp_path
):
    # each whole-line proof alone is not enough
    for keep in ("proof hello", "proof unknown-and-empty"):
        env = doctor_env["env"].copy()
        env["DOCTOR_STUB_SETUP_REPORT"] = write_setup_report(
            tmp_path,
            [line for line in GOOD_REPORT if keep not in line],
        )

        result = run(DOCTOR, "--router", "root@192.0.2.1", "--device", "r1", env=env)

        assert result.returncode == 3, (keep, result.stdout + result.stderr)
        assert (
            "INCONCLUSIVE router-line-restricted[r1]: the setup report carries "
            "no restricted-line proof" in result.stdout
        )
        assert "PASS router-line-restricted" not in result.stdout
        assert "FAIL router-line-restricted" not in result.stdout


def test_doctor_router_line_pass_substring_inside_another_line_does_not_count(
    doctor_env, tmp_path
):
    env = doctor_env["env"].copy()
    env["DOCTOR_STUB_SETUP_REPORT"] = write_setup_report(
        tmp_path,
        [
            "INFO check ran; note PASS proof hello: restricted identity is expected here",
            "INFO also PASS proof unknown-and-empty: rejected may appear elsewhere",
        ],
    )

    result = run(DOCTOR, "--router", "root@192.0.2.1", "--device", "r1", env=env)

    assert result.returncode == 3, result.stdout + result.stderr
    assert (
        "INCONCLUSIVE router-line-restricted[r1]: the setup report carries "
        "no restricted-line proof (the setup tool's check action does not "
        "print the proofs; run its restricted-key proofs another way or "
        "upgrade the tool)" in result.stdout
    )
    assert "PASS router-line-restricted" not in result.stdout
    assert "FAIL router-line-restricted" not in result.stdout


def test_doctor_router_line_inconclusive_without_any_proof(doctor_env, tmp_path):
    # (d) today's real setup check report: no proof lines at all; absence
    # of a proof is not evidence of a violation
    env = doctor_env["env"].copy()
    env["DOCTOR_STUB_SETUP_REPORT"] = write_setup_report(
        tmp_path,
        ["INFO release 24.10", "PASS tools 29/29 present", "DONE check r1"],
    )

    result = run(DOCTOR, "--router", "root@192.0.2.1", "--device", "r1", env=env)

    assert result.returncode == 3, result.stdout + result.stderr
    assert (
        "INCONCLUSIVE router-line-restricted[r1]: the setup report carries "
        "no restricted-line proof (the setup tool's check action does not "
        "print the proofs; run its restricted-key proofs another way or "
        "upgrade the tool)" in result.stdout
    )
    assert "PASS router-line-restricted" not in result.stdout
    assert "FAIL router-line-restricted" not in result.stdout


def test_doctor_router_line_inconclusive_when_setup_exits_nonzero(
    doctor_env, tmp_path
):
    env = doctor_env["env"].copy()
    env["DOCTOR_STUB_SETUP_FAIL"] = "sudo: no password was provided"
    env["DOCTOR_STUB_SETUP_RC_FAIL"] = "1"

    result = run(DOCTOR, "--router", "root@192.0.2.1", "--device", "r1", env=env)

    assert result.returncode == 3, result.stdout + result.stderr
    assert (
        "INCONCLUSIVE router-line-restricted[r1]: newton-router-setup exited 1 "
        "(sudo or the setup tool failed; never a PASS)" in result.stdout
    )
    assert "PASS router-line-restricted" not in result.stdout
    assert "FAIL router-line-restricted" not in result.stdout


def test_doctor_router_line_inconclusive_even_with_both_proofs_but_rc_nonzero(
    doctor_env, tmp_path
):
    # a lying report that prints both proofs but exits non-zero must never
    # be a PASS
    env = doctor_env["env"].copy()
    env["DOCTOR_STUB_SETUP_REPORT"] = write_setup_report(tmp_path, GOOD_REPORT)
    env["DOCTOR_STUB_SETUP_RC"] = "1"

    result = run(DOCTOR, "--router", "root@192.0.2.1", "--device", "r1", env=env)

    assert result.returncode == 3, result.stdout + result.stderr
    assert "INCONCLUSIVE router-line-restricted[r1]" in result.stdout
    assert "PASS router-line-restricted" not in result.stdout


def test_doctor_router_line_skipped_with_info_without_device(doctor_env):
    result = run(DOCTOR, "--router", "root@192.0.2.1", env=doctor_env["env"])

    assert result.returncode == 0, result.stdout + result.stderr
    assert (
        "INFO router-line check skipped (no --device given; pass --device "
        "NAME to prove the restricted router line)" in result.stdout
    )
    assert "router-line-restricted" not in result.stdout


def test_doctor_rejects_invalid_device_name(doctor_env):
    for bad in ("R1", "1x", "ro uter", "x" * 33, "a_b"):
        result = run(
            DOCTOR, "--router", "root@192.0.2.1", "--device", bad,
            env=doctor_env["env"],
        )
        assert result.returncode == 2, bad
        assert "ERROR: invalid device name" in result.stderr


def test_doctor_device_still_requires_a_router(doctor_env):
    result = run(DOCTOR, "--device", "r1", env=doctor_env["env"])

    assert result.returncode == 2
    assert "at least one --router" in result.stderr


# ---- doctor F2 router-line check on REAL setup check output ----------

def _run_real_check(tmp_path):
    """Run the real newton-router-setup `check` against a fake router that
    has a restricted key and an inventory key_file; return its stdout text.

    The setup tool reads NEWTON_INVENTORY / NEWTON_KEYS_DIR / etc.; the env
    is built from the setup_env fixture so the real tool sees the fake
    router. We import setup_env inside the function so this test stays in
    the doctor test file."""
    from router_setup_env import SetupEnv
    from router_setup_harness import BLOB_PREFIX
    env = SetupEnv(tmp_path / "real", device="r1", profile="lab",
            auth="password")
    # Install code files so the restricted-key hello has a real program.
    from test_router_setup_install import install_ok, PROG
    install_ok(env)
    # Set up the restricted keypair and matching authorized_keys line.
    label = "newton-agent"
    role = "change"
    pub_blob = BLOB_PREFIX + ("X" * (40 - len(label))) + label
    env.router.add_authorized_key(
        "restrict,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,"
        'no-pty,command="/usr/libexec/newton/newton-router '
        '--caller=%s --role=%s" ssh-ed25519 %s '
        "newton-router-%s" % (label, role, pub_blob, label))
    keyfile = env.keys_dir / ("%s-%s" % (env.device, label))
    keyfile.write_text("FAKE-OPENSSH-PRIVATE-KEY\n%s\n" % pub_blob)
    keyfile.chmod(0o600)
    (env.keys_dir / ("%s-%s.pub" % (env.device, label))).write_text(
        "ssh-ed25519 %s newton-router-%s\n" % (pub_blob, label))
    with env.inventory.open("a") as fh:
        fh.write('key_file = "%s"\n' % keyfile)
    # Run the real `check` and capture its stdout.
    r = env.run("r1", "check", typed=("root-pw-for-tests",))
    assert r.rc == 0, (r.out, r.err)
    return r.out


def test_doctor_router_line_pass_on_real_check_output(doctor_env, tmp_path):
    """R5: run the real newton-router-setup `check` (against a fake router
    with a restricted keypair), feed its REAL stdout to the doctor's
    sudo stub as DOCTOR_STUB_SETUP_REPORT, and expect
    PASS router-line-restricted[r1] (the doctor's F2 check must no
    longer fall back to INCONCLUSIVE with 'the setup tool's check
    action does not print the proofs')."""
    real_report = _run_real_check(tmp_path / "real")
    # Sanity check: the real check output must carry both proof lines.
    assert "PASS proof hello: restricted identity" in real_report.splitlines(), real_report
    assert "PASS proof unknown-and-empty: rejected" in real_report.splitlines(), real_report
    report = tmp_path / "real_setup_check.out"
    report.write_text(real_report)
    env = doctor_env["env"].copy()
    env["DOCTOR_STUB_SETUP_REPORT"] = str(report)
    result = run(DOCTOR, "--router", "root@192.0.2.1", "--device", "r1",
            env=env)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS router-line-restricted[r1]" in result.stdout, result.stdout
    # The doctor must NOT fall back to the old INCONCLUSIVE wording.
    assert "the setup tool's check action does not print" not in result.stdout
    assert "INCONCLUSIVE router-line-restricted[r1]" not in result.stdout


def test_doctor_router_line_fail_on_real_check_output_fail_proof(
        doctor_env, tmp_path):
    """R5: a real check where the restricted-key program lies about its
    caller produces a FAIL proof hello: line; feeding that output to the
    doctor (via DOCTOR_STUB_SETUP_REPORT) makes the F2 router-line check
    FAIL, naming the FAIL proof line."""
    from router_setup_env import SetupEnv
    from router_setup_harness import BLOB_PREFIX
    env = SetupEnv(tmp_path / "real-fail", device="r1", profile="lab",
            auth="password")
    from test_router_setup_install import install_ok
    install_ok(env)
    label = "newton-agent"
    role = "change"
    pub_blob = BLOB_PREFIX + ("X" * (40 - len(label))) + label
    env.router.add_authorized_key(
        "restrict,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,"
        'no-pty,command="/usr/libexec/newton/newton-router '
        '--caller=%s --role=%s" ssh-ed25519 %s '
        "newton-router-%s" % (label, role, pub_blob, label))
    keyfile = env.keys_dir / ("%s-%s" % (env.device, label))
    keyfile.write_text("FAKE-OPENSSH-PRIVATE-KEY\n%s\n" % pub_blob)
    keyfile.chmod(0o600)
    (env.keys_dir / ("%s-%s.pub" % (env.device, label))).write_text(
        "ssh-ed25519 %s newton-router-%s\n" % (pub_blob, label))
    with env.inventory.open("a") as fh:
        fh.write('key_file = "%s"\n' % keyfile)
    # Rig the router to lie about its caller.
    env.router.write("etc/newton/fixture-lie", "caller=somebody-else\n")
    r = env.run("r1", "check", typed=("root-pw-for-tests",))
    assert r.rc == 1
    assert any(l.startswith("FAIL proof hello:")
            for l in r.out.splitlines()), r.out
    report = tmp_path / "real_setup_check_fail.out"
    report.write_text(r.out)
    doc_env = doctor_env["env"].copy()
    doc_env["DOCTOR_STUB_SETUP_REPORT"] = str(report)
    result = run(DOCTOR, "--router", "root@192.0.2.1", "--device", "r1",
            env=doc_env)
    assert result.returncode == 1, result.stdout + result.stderr
    assert ("FAIL router-line-restricted[r1]: FAIL proof hello:"
            in result.stdout), result.stdout
