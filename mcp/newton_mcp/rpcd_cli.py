"""``newton-rpcd``: the setup CLI for the no-install mode.

The CLI is what the setup uses to talk to the router's own web API
before Newton manages anything:

  * ``groups`` prints the group lists Newton asks for, and the groups
    it never asks for, so the setup can build the login section;
  * ``pin CERTFILE`` prints the SPKI pin of a certificate read over the
    admin lane (the router's own certificate is DER, not PEM);
  * ``verify`` logs in and checks that the router granted exactly the
    groups Newton asked for;
  * ``verify-refused`` proves that the login is refused, which is how
    an uninstall is shown to have worked.

The password is read from a file with the same rules the inventory uses
for a password file.  Neither the password nor a session id ever
reaches the screen.

Exit codes: 0 the check passed, 1 the check was refused or failed, 2
the command line was wrong.
"""

from __future__ import annotations

import argparse
import hmac
import re
import shutil
import sys
import time
from pathlib import Path
from typing import Any

from . import approval_proof
from . import approve
from . import change_receipt
from . import credential_file
from . import noinstall_read
from . import owner_backup
from . import owner_records
from . import owner_script
from . import owner_verify
from . import server
from .adapters import openwrt_rpcd as rpcd
from .plan import compute_plan_hash

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2

#: The login timeout the CLI asks for: long enough to run the checks,
#: short enough that a forgotten session dies on its own.
LOGIN_TIMEOUT_S = 30

PROGRAM = "newton-rpcd"

#: The shape of the session the script printed.  It is 32 lowercase hex
#: characters, like every session id rpcd hands out.
TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description="Talk to the router's own web API (rpcd) over pinned HTTPS.",
    )
    commands = parser.add_subparsers(dest="command")

    commands.add_parser(
        "groups",
        help="print the read, write and never-granted ACL group lists",
    )

    pin = commands.add_parser("pin", help="print the SPKI pin of a certificate")
    pin.add_argument("certfile", help="the certificate file (DER or PEM)")

    owner_check = commands.add_parser(
        "owner-check",
        help="check an owner script and its approval, and start the run",
    )
    owner_check.add_argument("device", help="the device name")
    owner_check.add_argument("session_id", help="the plan id")

    owner_finish = commands.add_parser(
        "owner-finish",
        help="read the change back, and confirm it when every check passes",
    )
    owner_finish.add_argument("device", help="the device name")
    owner_finish.add_argument("session_id", help="the plan id")
    owner_finish.add_argument(
        "--reached",
        required=True,
        choices=("yes", "no"),
        help="whether the script reached the router",
    )

    owner_print = commands.add_parser(
        "owner-print",
        help="print the script of an owner plan and the hash of its bytes",
    )
    owner_print.add_argument("device", help="the device name")
    owner_print.add_argument("session_id", help="the plan id")

    owner_cleanup = commands.add_parser(
        "owner-cleanup",
        help="remove the owner scripts, backups and plan records of a device",
    )
    owner_cleanup.add_argument("device", help="the device name")

    for name, help_text in (
        ("verify", "log in and check that the groups are the ones Newton asked for"),
        ("verify-refused", "prove that the login is refused"),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--host", required=True, help="the router's host")
        command.add_argument("--port", required=True, type=int, help="the HTTPS port")
        command.add_argument("--pin", required=True, help="the SPKI pin, base64")
        command.add_argument(
            "--password-file",
            required=True,
            help="the file holding the rpcd password (mode 0600)",
        )
    return parser


def _groups() -> int:
    for group in rpcd.READ_GROUPS:
        print(f"read {group}")
    for group in rpcd.WRITE_GROUPS:
        print(f"write {group}")
    for group in rpcd.NEVER_GROUPS:
        print(f"never {group}")
    return EXIT_OK


def _pin(certfile: str) -> int:
    try:
        data = Path(certfile).read_bytes()
    except OSError as exc:
        print(f"FAIL the certificate cannot be read: {exc}")
        return EXIT_FAILED
    try:
        pin = rpcd.spki_pin(data)
    except rpcd.RpcdError as exc:
        print(f"FAIL {exc}")
        return EXIT_FAILED
    print(pin)
    return EXIT_OK


def _read_password(path: Path) -> str:
    data = path.read_bytes()
    return data.decode("utf-8").rstrip("\r\n")


def _hide(text: str, password: str) -> str:
    """The text with the password taken out of it.

    The router's own words reach the screen (a group it granted, the
    reason it refused).  A router that reflects the password back must
    not put it on the screen, so it never does.
    """
    if not password:
        return text
    return text.replace(password, "<hidden>")


def _verify(args: argparse.Namespace, expect_refused: bool) -> int:
    password_path = Path(args.password_file)
    problem = credential_file.check(password_path)
    if problem is not None:
        print(f"FAIL {problem}")
        return EXIT_FAILED
    try:
        password = _read_password(password_path)
    except (OSError, UnicodeDecodeError) as exc:
        print(f"FAIL the password file cannot be read: {exc}")
        return EXIT_FAILED
    if not password:
        print("FAIL the password file is empty")
        return EXIT_FAILED

    def say(line: str) -> None:
        print(_hide(line, password))

    try:
        client = rpcd.RpcdClient(args.host, args.port, args.pin)
    except rpcd.RpcdError as exc:
        say(f"FAIL {exc}")
        return EXIT_FAILED
    try:
        session = client.login(rpcd.RPCD_USER, password, LOGIN_TIMEOUT_S)
    except rpcd.RpcdCallFailed as exc:
        if exc.code == 6:
            if expect_refused:
                say("PASS the login is refused")
                return EXIT_OK
            say("FAIL the login was refused")
            return EXIT_FAILED
        say(f"FAIL the login failed: {exc}")
        return EXIT_FAILED
    except rpcd.RpcdError as exc:
        say(f"FAIL {exc}")
        return EXIT_FAILED
    if expect_refused:
        say("FAIL the login still works")
        return EXIT_FAILED
    differences = rpcd.check_acls(session.acls)
    if differences:
        for difference in differences:
            say(f"FAIL {difference}")
        return EXIT_FAILED
    say("PASS login and groups")
    return EXIT_OK


# ---- the owner script ------------------------------------------------------


def _service() -> Any:
    """Newton's own service: the inventory and the state directory."""
    return server.NewtonService()


def _owner_device(service: Any, name: str) -> Any:
    """The device of an owner script, or None."""
    return service.devices.get(name)


def _owner_record(service: Any, sid: str) -> dict[str, Any]:
    """The plan record of an owner script, or a refusal."""
    if approve.PLAN_ID_RE.fullmatch(sid) is None:
        raise owner_records.RecordError(
            "the plan id must be 32 lowercase hexadecimal characters"
        )
    return owner_records.load_record(service.state, sid)


def _check_record(service: Any, device: Any, sid: str) -> dict[str, Any]:
    """Every check the owner-check makes before anything is sent."""
    record = _owner_record(service, sid)
    if record.get("device") != device.name:
        raise owner_records.RecordError("the plan record is for another device")
    if record.get("host") != device.host:
        raise owner_records.RecordError(
            "the host of the device changed since the plan was made"
        )
    if record.get("router_leash") not in owner_records.OWNER_LEASHES:
        raise owner_records.RecordError("this plan is not an owner script")
    try:
        digest = compute_plan_hash(record)
    except ValueError as exc:
        raise owner_records.RecordError(str(exc)) from None
    bound = record.get("plan_hash")
    if not isinstance(bound, str) or not hmac.compare_digest(digest, bound):
        raise owner_records.RecordError(
            "the plan record does not match the hash it carries"
        )
    owner_records.check_scripts(service.state, record)
    try:
        parsed = owner_script.parse_script(
            owner_records.read_script(service.state, sid)
        )
    except owner_script.ScriptError as exc:
        raise owner_records.RecordError(
            f"the script of this plan cannot be read: {exc}"
        ) from None
    if [list(op) for op in parsed.ops] != record.get("ops"):
        raise owner_records.RecordError(
            "the script of this plan does not do what the plan says"
        )
    owner_backup.load(service.state, sid)
    return record


def _owner_approval(
    service: Any, device: Any, sid: str, record: dict[str, Any]
) -> tuple[bool, str]:
    """The approval of an owner script, asked for in this one command.

    An approval that is already on disk is used as it is.  Otherwise the
    owner is asked here, the way ``newton-approve`` asks: the plan is
    shown, the confirmation line is read, and the proof is read at the
    device's level.  The proof never reaches the argv, the environment,
    a log or the run record.
    """
    state = service.state
    approval = state / "approvals" / f"{sid}.json"
    if not approval.exists():
        if not sys.stdin.isatty():
            return False, (
                "this plan needs an approval and stdin is not an interactive "
                f"terminal; run `sudo -u newton /usr/local/bin/newton-approve "
                f"{sid}` in your own terminal"
            )
        level = approval_proof.get_level(device.name)
        if level == approval_proof.LEVEL_TOTP:
            proof_prompt = (
                f"Newton 6-digit code for {device.name} "
                "(not the router's admin password): "
            )
        else:
            proof_prompt = (
                f"Newton approval passphrase for {device.name} "
                "(not the router's admin password): "
            )
        ok, refusal = approve.approve_plan(
            sid,
            record,
            program=PROGRAM,
            level=level,
            proof_prompt=proof_prompt,
            lockout=True,
        )
        if not ok:
            return False, refusal
    try:
        service.consume_approval(device.name, sid, record)
    except Exception as exc:
        return False, str(exc)
    return True, ""


def _read_confirm_token() -> str | None:
    """The session the script opened, read from stdin.

    The session is a confirm-only right: it comes in on stdin, it is
    never logged, and it is never written down.  A terminal has no
    token: the owner-run lane is the only place one comes from, and it
    is the only place that has one.

    Anything that is not 32 lowercase hex characters is not a session
    and is refused.
    """
    stream = sys.stdin
    if stream is None:
        return None
    try:
        if stream.isatty():
            return None
        line = stream.readline()
    except (OSError, ValueError):
        return None
    token = line.strip()
    if TOKEN_RE.fullmatch(token) is None:
        return None
    return token


def _owner_check(args: argparse.Namespace) -> int:
    """Check the plan, the script, the backup and the approval of a run."""
    service = _service()
    device = _owner_device(service, args.device)
    if device is None:
        print(f"FAIL unknown device: {args.device}")
        return EXIT_FAILED
    if device.access != "no-install":
        print("FAIL this device does not use no-install access")
        return EXIT_FAILED
    try:
        record = _check_record(service, device, args.session_id)
    except owner_records.RecordError as exc:
        print(f"FAIL {exc}")
        return EXIT_FAILED
    except owner_backup.BackupError as exc:
        print(f"FAIL {exc}")
        return EXIT_FAILED
    ok, refusal = _owner_approval(service, device, args.session_id, record)
    if not ok:
        print(f"FAIL {refusal}")
        return EXIT_FAILED
    # The run starts now, before anything is sent to the router: the
    # deadline of the window is counted from here.
    run = owner_records.read_run(service.state, args.session_id)
    # A new run starts from nothing.  The verdict of an earlier run of
    # this plan belongs to that run: the owner may run the same plan
    # again after a lane that died, and the earlier verdict must never
    # decide this one.
    run.pop("verdict", None)
    run.pop("owner_keep", None)
    run["started_at"] = time.time()
    owner_records.write_run(service.state, args.session_id, run)
    apply_sha = str(record.get("script_sha256", ""))
    print(f"[1/5] script bytes match the approved sha256 {apply_sha[:12]}")
    return EXIT_OK


#: The states a run ends in.  Only these are cached: an UNKNOWN run is
#: re-checked against the router on the next owner-finish.
FINAL_STATES: tuple[str, ...] = (
    owner_verify.CONFIRMED,
    owner_verify.ROLLED_BACK,
    owner_verify.NOT_APPLIED,
    owner_verify.KEPT,
)


def _stored_verdict(stored: Any) -> owner_verify.Verdict | None:
    """The verdict of an earlier run, or None when there is none."""
    if not isinstance(stored, dict):
        return None
    state = stored.get("state")
    if not isinstance(state, str):
        return None
    deadline = stored.get("deadline")
    owner_keep = stored.get("owner_keep")
    return owner_verify.Verdict(
        state=state,
        checks=tuple(str(item) for item in stored.get("checks", []) or []),
        deadline=(
            float(deadline)
            if isinstance(deadline, (int, float)) and not isinstance(deadline, bool)
            else 0.0
        ),
        notes=tuple(str(item) for item in stored.get("notes", []) or []),
        not_verified=tuple(str(item) for item in stored.get("not_verified", []) or []),
        owner_keep=owner_keep if isinstance(owner_keep, bool) else None,
    )


def _print_verdict(verdict: owner_verify.Verdict) -> None:
    """The fifth line of the run, the notes and what Newton could not check.

    The line ends with the state word, so the owner can read the state
    without reading the sentence: CONFIRMED, ROLLED BACK, NOT APPLIED,
    KEPT or UNKNOWN.
    """
    print(f"[5/5] {verdict.sentence()} {verdict.state}")
    for note in verdict.notes:
        print(f"note: {note}")
    for item in verdict.not_verified:
        print(f"not verified: {item}")


def _owner_finish(args: argparse.Namespace) -> int:
    """Read the change back, confirm it when everything passes, and report."""
    service = _service()
    device = _owner_device(service, args.device)
    if device is None:
        print(f"FAIL unknown device: {args.device}")
        return EXIT_FAILED
    state = service.state
    run = owner_records.read_run(state, args.session_id)
    stored = _stored_verdict(run.get("verdict"))
    if stored is not None and stored.state in FINAL_STATES:
        # a second run only reads and reports: the change is not
        # confirmed twice
        _print_verdict(stored)
        return EXIT_OK
    try:
        record = _owner_record(service, args.session_id)
    except owner_records.RecordError as exc:
        print(f"FAIL {exc}")
        return EXIT_FAILED
    if record.get("device") != device.name:
        print("FAIL the plan record is for another device")
        return EXIT_FAILED
    if args.reached == "no":
        # The change never reached the router.  The approval is settled
        # as apply() settles it -- the token did not reach the router,
        # so the owner may run the plan again -- and the run stops here:
        # there is nothing to read back, and no verdict to cache.
        service.settle_approval(args.session_id, reached_router=False)
        # The script was never sent, so the run never started: the
        # start of the run is cleared and the plan may be aborted.
        if "started_at" in run:
            run.pop("started_at", None)
            owner_records.write_run(state, args.session_id, run)
        return EXIT_OK
    # The approval is settled as apply() settles it: the token reached
    # the router, or it did not.
    service.settle_approval(args.session_id, reached_router=True)
    # The session the script opened comes in on stdin.  It is the only
    # session that may confirm the change, and it is used once.
    confirm_token = _read_confirm_token()
    try:
        backup = owner_backup.load(state, args.session_id)
    except owner_backup.BackupError as exc:
        print(f"FAIL {exc}")
        return EXIT_FAILED
    if stored is not None and stored.state == owner_verify.UNKNOWN:
        # A run that ended in UNKNOWN is re-checked against the router:
        # the window is closed by now, and the state is decided there.
        # This never confirms: a second run only reads.
        try:
            verdict = owner_verify.settle(
                device,
                record,
                backup,
                run,
                noinstall_read.default_client_factory,
                previous=stored,
            )
        except owner_verify.VerifyError as exc:
            print(f"FAIL {exc}")
            return EXIT_FAILED
    else:
        try:
            verdict = owner_verify.finish(
                device,
                record,
                backup,
                run,
                noinstall_read.default_client_factory,
                confirm_token=confirm_token,
                state=state,
            )
        except owner_verify.VerifyError as exc:
            print(f"FAIL {exc}")
            return EXIT_FAILED
        if verdict.state == owner_verify.UNKNOWN:
            # The change may still be waiting on the router: wait for the
            # window to close, then read the router and say what it did.
            wait = verdict.deadline + 30 - time.time()
            if wait > 0:
                time.sleep(wait)
            verdict = owner_verify.settle(
                device,
                record,
                backup,
                run,
                noinstall_read.default_client_factory,
                previous=verdict,
            )
    run["owner_keep"] = verdict.owner_keep
    run["verdict"] = {
        "state": verdict.state,
        "checks": list(verdict.checks),
        "notes": list(verdict.notes),
        "not_verified": list(verdict.not_verified),
        "owner_keep": verdict.owner_keep,
        "deadline": verdict.deadline,
        "sentence": verdict.sentence(),
    }
    owner_records.write_run(state, args.session_id, run)
    outcome = {
        owner_verify.CONFIRMED: "confirmed",
        owner_verify.ROLLED_BACK: "rolled_back",
    }.get(verdict.state, "unknown")
    if verdict.state != owner_verify.NOT_APPLIED:
        # A change the router never took leaves no receipt: nothing is
        # live on the router, so there is nothing to undo, and a
        # receipt would claim otherwise.
        receipt_record = dict(record)
        receipt_record["backup_path"] = str(
            owner_backup.backup_dir(state, args.session_id)
        )
        change_receipt.write_receipt(state, receipt_record, outcome, "")
    _print_verdict(verdict)
    if verdict.state == owner_verify.UNKNOWN:
        # The owner must not touch the router while Newton cannot tell
        # what it did with the change.
        print(
            owner_verify.unknown_advice(
                device.name, args.session_id, verdict.deadline
            )
        )
    return EXIT_OK


def _owner_print(args: argparse.Namespace) -> int:
    """Print the script of an owner plan, and the hash of its bytes.

    Nothing is sent to the router, no approval is claimed and nothing
    is changed: this is what the owner reads before the run.
    """
    service = _service()
    device = _owner_device(service, args.device)
    if device is None:
        print(f"FAIL unknown device: {args.device}")
        return EXIT_FAILED
    if device.access != "no-install":
        print("FAIL this device does not use no-install access")
        return EXIT_FAILED
    try:
        record = _owner_record(service, args.session_id)
        if record.get("device") != device.name:
            raise owner_records.RecordError("the plan record is for another device")
        apply_sha, _restore_sha = owner_records.check_scripts(
            service.state, record
        )
        script = owner_records.read_script(service.state, args.session_id)
    except owner_records.RecordError as exc:
        print(f"FAIL {exc}")
        return EXIT_FAILED
    try:
        text = script.decode("utf-8")
    except UnicodeDecodeError:
        print("FAIL the script of this plan is not text")
        return EXIT_FAILED
    print(text, end="" if text.endswith("\n") else "\n")
    print(f"sha256 {apply_sha}")
    return EXIT_OK


def _owner_cleanup(args: argparse.Namespace) -> int:
    """Remove the owner scripts, backups and plan records of a device.

    Only the plans that name THIS device are removed, and every one of
    them is removed whole: the script, the backup and the run record
    live in one directory.

    The cleanup needs the state directory and the device name, and
    nothing else: it does not read the inventory, so one entry of
    another device that cannot be read never blocks the uninstall of
    this device.
    """
    device_name = args.device
    if not isinstance(device_name, str) or not server.DEVICE_NAME_RE.fullmatch(
        device_name
    ):
        print(f"FAIL unknown device: {device_name}")
        return EXIT_FAILED
    state = server.state_dir()
    plans = state / "plans"
    try:
        names = sorted(path.name for path in plans.glob("*.json"))
    except OSError:
        names = []
    doomed: list[str] = []
    for name in names:
        if not name.endswith(".json"):
            continue
        sid = name[: -len(".json")]
        try:
            record = owner_records.load_record(state, sid)
        except owner_records.RecordError:
            continue
        if record.get("device") != device_name:
            continue
        # an owner script and an auto plan are both the device's: the
        # uninstall removes them both, with their run directories.
        if not (
            owner_records.is_owner_record(record)
            or record.get("mode") == "auto"
        ):
            continue
        doomed.append(sid)
    for sid in doomed:
        directory = state / owner_records.OWNER_DIR / sid
        if directory.exists():
            shutil.rmtree(directory, ignore_errors=True)
        record_path = owner_records.plan_path(state, sid)
        try:
            record_path.unlink()
        except OSError:
            pass
        print(f"removed the owner script {sid}")
    if not doomed:
        print(f"no owner scripts for {device_name}")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        # argparse already printed the usage error
        code = exc.code
        if code is None:
            return EXIT_OK
        return int(code) if isinstance(code, int) else EXIT_USAGE
    if args.command == "groups":
        return _groups()
    if args.command == "pin":
        return _pin(args.certfile)
    if args.command == "verify":
        return _verify(args, expect_refused=False)
    if args.command == "verify-refused":
        return _verify(args, expect_refused=True)
    if args.command == "owner-check":
        return _owner_check(args)
    if args.command == "owner-finish":
        return _owner_finish(args)
    if args.command == "owner-print":
        return _owner_print(args)
    if args.command == "owner-cleanup":
        return _owner_cleanup(args)
    parser.print_usage(sys.stderr)
    return EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
