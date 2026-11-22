"""newton-enrol: enrol the owner in a TOTP authenticator, rotate the
approval passphrase, or end an easy grant.

Four commands for the owner:

* ``newton-enrol totp <device>`` -- enrol an authenticator app for
  ``device``.  The owner types the approval passphrase, the ``otpauth://``
  URI and the base32 seed are shown, the owner types the code the
  authenticator shows and only then is the seed written down.  A wrong
  code leaves the device exactly as it was.
* ``newton-enrol level <device> passphrase|totp`` -- choose which proof
  the device asks for.  ``passphrase`` keeps the TOTP record, so the
  owner can switch back without enrolling again.
* ``newton-enrol rotate <device>`` -- throw the TOTP record, the lockout
  counter and the acknowledgement away and let the owner type a new
  approval passphrase on the router (the ``approval-key`` action of
  newton-router-setup).
* ``newton-enrol grant-off <device>`` -- end the easy grant on a device.
  It needs no terminal because it neither asks for nor shows a secret.

WHY enrolment and rotation are commands and not MCP tools: the seed is a
secret the agent must never see, and the approval passphrase is a secret
the agent must never hold.  Both are typed in the owner's own terminal, so
neither ever reaches the agent.

The passphrase is never printed, logged or written here: it is checked
against the fingerprint ``newton-router-setup`` left behind, and the key
derived from it goes straight into the TOTP record.  The seed is shown to
the owner (they have to type it into their app) and nowhere else.
"""

from __future__ import annotations

import hmac
import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

from . import approval_proof as _proof
from . import approve
from . import grants
from .ad.write.inventory import AD_PLATFORMS


USAGE = (
    "usage: newton-enrol totp <device> | newton-enrol rotate <device> | "
    "newton-enrol level <device> passphrase|totp | "
    "newton-enrol grant-off <device>"
)

# Where Newton lives on the host; the router key change is run from there.
DEFAULT_NEWTON_HOME = "/opt/newton"


def _read_line() -> str:
    """The next line the owner typed, without its newline."""
    return sys.stdin.readline().rstrip("\r\n")


def _code_matches(seed: bytes, code: str) -> bool:
    """True when *code* is the TOTP code of *seed* right now.

    The counter of this moment and its two neighbours are all tried, so an
    authenticator whose clock is a little off still works.  Every window
    is compared even after one of them matched: how long this call takes
    must not tell an attacker which window matched.
    """
    candidate = code.strip()
    if not _proof.CODE_RE.fullmatch(candidate):
        return False
    current = _proof.totp_counter()
    matched = False
    for offset in (-1, 0, 1):
        counter = current + offset
        if counter < 0:
            continue
        if hmac.compare_digest(_proof.totp_code(seed, counter), candidate):
            matched = True
    return matched


def _print_qr(uri: str) -> None:
    """Show the enrolment URI as a QR code, when qrencode is installed.

    The QR goes straight to the terminal (the code is captured nowhere)
    and the command is run with an argv list, never through a shell.
    """
    if shutil.which("qrencode") is None:
        print("qrencode not installed: type the seed into your authenticator app")
        return
    try:
        subprocess.run(["qrencode", "-t", "ANSIUTF8", uri], check=False)
    except OSError:
        print("qrencode could not be run: type the seed into your authenticator app")


def _enrol_totp(device: str) -> int:
    """Enrol an authenticator app for *device*.

    The seed is only written down after the owner has proved that the
    authenticator holds it, by typing the code the app shows.  Until then
    the device keeps whatever proof it had.
    """
    try:
        passphrase = approve._getpass(f"approval passphrase for {device}: ")
    except (EOFError, KeyboardInterrupt, OSError):
        print(
            "newton-enrol: the approval passphrase could not be read; "
            "nothing was enrolled",
            file=sys.stderr,
        )
        return 1
    if not passphrase:
        print(
            "newton-enrol: the approval passphrase must not be empty; "
            "nothing was enrolled",
            file=sys.stderr,
        )
        return 1
    status, k_hex = _proof.verify_passphrase(device, passphrase)
    del passphrase
    if status != _proof.PASS_OK:
        if status == _proof.PASS_NO_FINGERPRINT:
            print(
                f"newton-enrol: no approval fingerprint on record for {device}; "
                f"run {approve._launcher('newton-router-setup')} {device} approval-key first; "
                "nothing was enrolled",
                file=sys.stderr,
            )
        elif status == _proof.PASS_DAMAGED:
            print(
                f"newton-enrol: the approval fingerprint file for {device} is damaged; "
                f"run sudo -u newton /usr/local/bin/newton-router-setup {device} approval-key again; "
                "nothing was enrolled",
                file=sys.stderr,
            )
        else:
            print(
                f"newton-enrol: wrong approval passphrase for {device}; "
                "nothing was enrolled",
                file=sys.stderr,
            )
        return 1
    seed = _proof.generate_seed()
    uri = _proof.otpauth_uri(seed, device)
    print(f"otpauth URI: {uri}")
    print(f"Seed (base32): {_proof.seed_to_base32(seed)}")
    _print_qr(uri)
    print(
        "Type the 6-digit code your authenticator app shows: ",
        end="",
        flush=True,
    )
    typed_code = _read_line()
    if not _code_matches(seed, typed_code):
        print(
            "newton-enrol: that code does not match the seed; "
            "nothing was enrolled",
            file=sys.stderr,
        )
        return 1
    _proof.store_totp(device, seed, k_hex)
    del k_hex
    # The code just typed proved the app holds the seed; burn it so it
    # cannot also serve as the first approval.
    _proof.verify_totp(device, typed_code)
    _proof.set_level(device, _proof.LEVEL_TOTP)
    print(f"Approval level for {device}: {_proof.LEVEL_TOTP}")
    print("newton-approve still works as the fallback")
    return 0


def _set_level(device: str, level: str) -> int:
    """Record which proof *device* asks for.

    Switching back to the passphrase keeps the TOTP record, so the owner
    can enrol again without a second authenticator.
    """
    if level == _proof.LEVEL_TOTP and _proof.load_totp(device) is None:
        print(
            f"newton-enrol: {device} has no TOTP record; enrol one with "
            f"{approve._launcher('newton-enrol')} totp {device}",
            file=sys.stderr,
        )
        return 1
    _proof.set_level(device, level)
    print(f"Approval level for {device}: {level}")
    if level == _proof.LEVEL_PASSPHRASE:
        print("the TOTP record is kept; newton-enrol level switches back")
    return 0


def _rotate(device: str) -> int:
    """Throw the old secrets away and let the owner type a new passphrase.

    The TOTP record, the lockout counter and the acknowledgement all
    belong to the proof that is being replaced, so they go with it.  The
    lockout counter in particular must not outlive the passphrase it
    counted: a stale counter would lock the owner out of the device they
    just re-proved.

    The setup run is told not to offer the authenticator app
    (``NEWTON_SKIP_TOTP_OFFER``): the offer would be made and undone
    within the same second.
    """
    expected = f"rotate {device}"
    print(
        f"Type {expected!r} to rotate the approval key of {device}: ",
        end="",
        flush=True,
    )
    if _read_line().strip() != expected:
        print(
            "newton-enrol: confirmation did not match; nothing was changed",
            file=sys.stderr,
        )
        return 1
    setup = _setup_tool()
    if not os.path.isfile(setup):
        # The path just found missing is never offered as the command to
        # run: the owner is told how to point newton-enrol at the tool.
        print(
            f"newton-enrol: {setup} is missing; set NEWTON_HOME to the "
            "folder that holds scripts/newton-router-setup (the Newton "
            "install or a Newton checkout) and run "
            f"{approve._launcher('newton-enrol')} rotate {device} again",
            file=sys.stderr,
        )
        print(
            f"newton-enrol: the approval passphrase of {device} was not changed "
            "and nothing on this host was changed"
        )
        return 1
    try:
        # The setup tool must not OFFER the authenticator app here: this
        # rotation throws the TOTP record away a second later, so an
        # accepted offer would be undone right after it was made.
        result = subprocess.run(
            [setup, device, "approval-key"],
            check=False,
            env={**os.environ, "NEWTON_SKIP_TOTP_OFFER": "1"},
        )
    except OSError as exc:
        print(
            f"newton-enrol: could not run {setup}: {exc}; "
            "run it yourself to change the approval passphrase",
            file=sys.stderr,
        )
        return 1
    if result.returncode != 0:
        # The setup tool writes the router's approve.key before its
        # selftest, so a failure can leave the router on the new key
        # while this host still holds the old proofs.
        print(
            f"newton-enrol: the approval key change failed (exit {result.returncode}); "
            f"the router {device} may already hold the new key (see the "
            "setup tool's messages above), and the old TOTP record, lockout "
            "and acknowledgement are kept; run "
            f"{approve._launcher('newton-enrol')} rotate {device} again",
            file=sys.stderr,
        )
        return result.returncode
    # Only now, with the new passphrase on the router, do the old proofs go.
    _proof.delete_totp(device)
    _proof.record_success(device)
    try:
        _proof.ack_path(device).unlink()
    except FileNotFoundError:
        pass
    _proof.set_level(device, _proof.LEVEL_PASSPHRASE)
    print(
        "newton-enrol: enrol the authenticator again with "
        f"{approve._launcher('newton-enrol')} totp {device}"
    )
    return 0


def _setup_tool() -> str:
    """The newton-router-setup a rotation runs.

    NEWTON_HOME names it when set (the installed launchers set it).
    Without it the installed copy under the default home is used, and
    when there is none, the copy of the source tree this module runs
    from: a source checkout has no /opt/newton.
    """
    home = os.environ.get("NEWTON_HOME")
    if home:
        return f"{home}/scripts/newton-router-setup"
    installed = f"{DEFAULT_NEWTON_HOME}/scripts/newton-router-setup"
    if os.path.isfile(installed):
        return installed
    source = Path(__file__).resolve().parents[2] / "scripts" / "newton-router-setup"
    if source.is_file():
        return str(source)
    return installed


def _ad_refusal(command: str, device: str) -> int:
    """Refuse a router-only command on an Active Directory entry.

    An AD approval (newton-approve ad-change) asks for the passphrase
    only, and its key lives on the DCs, not on a router: rotate would run
    newton-router-setup against a DC, and an authenticator would never be
    asked for.
    """
    if command == "rotate":
        print(
            f"newton-enrol: {device} is an Active Directory entry, and rotate "
            "changes a router's approval key. To replace the AD approval "
            "passphrase, remove the approval key file on every DC of the "
            "domain, run the DC write setup again on each with the new "
            "passphrase, then run "
            f"{approve._launcher('newton-ad-setup')} approval-key {device} "
            "for the domain on the Newton host; nothing was changed",
            file=sys.stderr,
        )
    else:
        print(
            f"newton-enrol: {device} is an Active Directory entry: AD "
            "approvals ask for the approval passphrase only, so an "
            "authenticator app is never asked for there; nothing was changed",
            file=sys.stderr,
        )
    return 2


def _known_devices() -> tuple[dict[str, str] | None, str]:
    """The device names of the inventory with their platforms, or None
    and why it cannot be read.

    Only the names and platforms are read: a typo in the device name must
    not end in "No easy grant" while the real grant stays open.
    """
    path = Path(
        os.environ.get("NEWTON_INVENTORY", "~/.config/newton/devices.toml")
    ).expanduser()
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return None, f"the inventory {path} cannot be read"
    devices = data.get("devices", {})
    if not isinstance(devices, dict):
        return None, f"the inventory {path} has no [devices] table"
    return {
        name: str(entry.get("platform", "")) if isinstance(entry, dict) else ""
        for name, entry in devices.items()
        if isinstance(name, str)
    }, ""


def _unknown(device: str, known: dict[str, str]) -> int:
    names = ", ".join(sorted(known)) or "none"
    print(
        f"newton-enrol: unknown device {device}: the inventory names {names}",
        file=sys.stderr,
    )
    return 2


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) < 2:
        print(USAGE, file=sys.stderr)
        return 2
    command = args[0]
    device = args[1]
    if command == "level":
        if len(args) != 3:
            print(USAGE, file=sys.stderr)
            return 2
        if args[2] not in _proof.LEVELS:
            print(
                "newton-enrol: level must be 'passphrase' or 'totp'",
                file=sys.stderr,
            )
            return 2
    elif command in ("totp", "rotate", "grant-off"):
        if len(args) != 2:
            print(USAGE, file=sys.stderr)
            return 2
    else:
        print(USAGE, file=sys.stderr)
        return 2
    if not approve.DEVICE_NAME_RE.fullmatch(device):
        print(
            "newton-enrol: device must be 1-32 characters of [a-z][a-z0-9-]",
            file=sys.stderr,
        )
        return 2
    known, problem = _known_devices()
    if command == "grant-off":
        # Ending a grant is always safe, so a grant is ended even when
        # its device is no longer in the inventory; only "there was
        # none" needs the name checked.
        if grants.revoke_grant(device):
            print(f"Easy grant for {device} ended.")
            return 0
        if known is None:
            print(
                f"newton-enrol: no easy grant for {device}, and {problem} "
                "to check the name",
                file=sys.stderr,
            )
            return 1
        if device not in known:
            return _unknown(device, known)
        print(f"No easy grant for {device}.")
        return 0
    if known is None:
        print(f"newton-enrol: {problem}", file=sys.stderr)
        return 1
    if device not in known:
        return _unknown(device, known)
    if known[device] in AD_PLATFORMS and (
        command in ("totp", "rotate")
        or (command == "level" and args[2] == _proof.LEVEL_TOTP)
    ):
        return _ad_refusal(command, device)
    # The owner types the passphrase and reads the seed, so those commands
    # only run in a terminal; grant-off asks for and shows no secret.
    if not sys.stdin.isatty():
        print(
            "newton-enrol: stdin must be an interactive terminal",
            file=sys.stderr,
        )
        return 1
    if command == "totp":
        return _enrol_totp(device)
    if command == "rotate":
        return _rotate(device)
    return _set_level(device, args[2])


if __name__ == "__main__":
    raise SystemExit(main())
