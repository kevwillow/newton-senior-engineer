"""The Active Directory write request contract (SPEC-1.4-REQUEST).

This module holds the request rules as pure functions: no file is read,
no device is contacted, no clock is read.  The helpers in the other
languages mirror it, so every rule here is written once and in one place.

The rules come from three sections of the contract:

- section 2: the fields, their types and their patterns.  A request that
  does not fit is refused with the code ``schema``;
- section 3: the verbs, the shape of their target and of their before-
  and after-images.  The shape is a schema rule; the rule of the table
  (the bit arithmetic, the direction of a membership) is a ``denied``;
- section 4: the canonical bytes, the digest and the token.

The token is never reimplemented here: ``newton_mcp.approve.approval_token``
is the one function of the repository that mints it, and this module calls
it.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping


#: The biggest request the helper reads (SPEC-1.4-REQUEST section 1).
MAX_REQUEST_BYTES = 64 * 1024

#: The modes of the contract.
MODES: tuple[str, ...] = ("apply", "confirm", "abort", "status", "read")

#: The verbs of section 3.
VERBS: tuple[str, ...] = (
    "uac-clear",
    "disable",
    "enable",
    "enc-types",
    "unlock",
    "member-add",
    "member-remove",
    "maq",
    "user-create",
    "move",
)

#: The codes the contract knows (section 6).
CODES: tuple[str, ...] = (
    "ok",
    "schema",
    "bad_token",
    "expired",
    "replay",
    "not_found",
    "conflict",
    "privileged",
    "denied",
    "unavailable",
    "not_pdc",
    "risk_mismatch",
    "error",
)

#: The userAccountControl bits a uac-clear may clear (section 3).
UAC_CLEAR_BITS: tuple[int, ...] = (4194304, 32, 128, 524288, 65536)

#: The ACCOUNTDISABLE bit.
ACCOUNTDISABLE = 2

#: The bits of msDS-SupportedEncryptionTypes below 64 (section 3).
ENC_TYPE_LOW_MASK = 63

#: The DES bits of msDS-SupportedEncryptionTypes (section 3).
ENC_TYPE_DES_MASK = 3

#: The delegated identity used by both write helpers.
WRITE_ACCOUNT_SAM = "newton-ops"

#: The built-in Kerberos service account and the per-RODC account prefix.
KRBTGT_SAM = "krbtgt"
RODC_KRBTGT_PREFIX = "krbtgt_"


DEVICE_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
TXID_RE = re.compile(r"^[0-9a-f]{32}$")
TOKEN_RE = re.compile(r"^[0-9a-f]{64}$")
#: The risk levels of section 4: the level the owner approves.
RISK_RE = re.compile(r"^(LOW|MED|HIGH)$")
GUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
SID_RE = re.compile(r"^S-1-5-21-[0-9]{1,10}-[0-9]{1,10}-[0-9]{1,10}-[0-9]{1,10}$")
SAM_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,19}$")
COMPUTER_SAM_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,19}\$$")
#: The int form of the contract: no sign, no fraction, no exponent.
INT_RE = re.compile(r"^(0|[1-9][0-9]*)$")
#: The approval window is ten digits of UNIX seconds.
EPOCH_RE = re.compile(r"^[0-9]{10}$")

#: The approval window is at most this wide (section 2).
APPROVAL_WINDOW_S = 1800

#: The undo window of an apply (section 2).
WINDOW_MIN_S = 120
WINDOW_MAX_S = 1800

#: The window of an unlock: no undo is armed, so it is the unused floor.
UNLOCK_WINDOW_S = 120

#: The secret of a user-create: 16..128 printable ASCII (0x21..0x7e).
SECRET_MIN = 16
SECRET_MAX = 128


#: The fields every request carries.
_COMMON_FIELDS = frozenset({"v", "mode", "device"})

#: The fields of each mode (section 2).
_MODE_FIELDS: dict[str, frozenset[str]] = {
    "apply": _COMMON_FIELDS
    | frozenset(
        {
            "txid",
            "verb",
            "target",
            "before",
            "after",
            "window",
            "risk",
            "nbf",
            "exp",
            "token",
            "secret",
        }
    ),
    "confirm": _COMMON_FIELDS | frozenset({"txid"}),
    "abort": _COMMON_FIELDS | frozenset({"txid"}),
    "status": _COMMON_FIELDS | frozenset({"txid"}),
    "read": _COMMON_FIELDS | frozenset({"verb", "target"}),
}

#: The target keys of each verb and the kind of every value.
_TARGET_KEYS: dict[str, dict[str, str]] = {
    "uac-clear": {"guid": "guid", "sid": "sid", "sam": "sam", "bit": "int"},
    "disable": {"guid": "guid", "sid": "sid", "sam": "sam"},
    "enable": {"guid": "guid", "sid": "sid", "sam": "sam"},
    "enc-types": {"guid": "guid", "sid": "sid", "sam": "sam"},
    "unlock": {"guid": "guid", "sid": "sid", "sam": "sam"},
    "member-add": {
        "group_guid": "guid",
        "group_sid": "sid",
        "group_sam": "sam",
        "member_guid": "guid",
        "member_sid": "sid",
        "member_sam": "sam",
    },
    "member-remove": {
        "group_guid": "guid",
        "group_sid": "sid",
        "group_sam": "sam",
        "member_guid": "guid",
        "member_sid": "sid",
        "member_sam": "sam",
    },
    "maq": {"guid": "guid"},
    "user-create": {"parent_guid": "guid", "sam": "sam"},
    "move": {"guid": "guid", "sid": "sid", "sam": "sam"},
}

#: The target a read may use when it only knows the name (section 6).
_READ_TARGET_KEYS: dict[str, dict[str, str]] = {
    "uac-clear": {"sam": "sam"},
    "disable": {"sam": "sam"},
    "enable": {"sam": "sam"},
    "enc-types": {"sam": "sam"},
    "unlock": {"sam": "sam"},
    "member-add": {"group_sam": "sam", "member_sam": "sam"},
    "member-remove": {"group_sam": "sam", "member_sam": "sam"},
    "maq": {"guid": "guid"},
    "user-create": {"parent_guid": "guid", "sam": "sam"},
    "move": {"sam": "sam"},
}

#: The before- and after-image keys of each verb and the kind of every value.
_VALUE_KEYS: dict[str, dict[str, str]] = {
    "uac-clear": {"uac": "int"},
    "disable": {"uac": "int"},
    "enable": {"uac": "int"},
    "enc-types": {"etypes": "int_or_absent"},
    "unlock": {"lockout": "int"},
    "member-add": {"member": "present_absent"},
    "member-remove": {"member": "present_absent"},
    "maq": {"maq": "int"},
    "user-create": {"object": "present_absent"},
    "move": {"parent": "guid"},
}


class RequestRefused(Exception):
    """The request is refused with one of the codes of the contract.

    The code is the word the helper answers with; the message is for the
    log and never carries the value that was refused.
    """

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code
        self.message = message or code


def _refuse(code: str, message: str) -> RequestRefused:
    return RequestRefused(code, message)


def _is_int(value: Any) -> bool:
    """True for an int that is not a bool."""
    return isinstance(value, int) and not isinstance(value, bool)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """The object hook: one key once, and never two keys that differ only in case."""
    seen: dict[str, Any] = {}
    lowered: set[str] = set()
    for key, value in pairs:
        if not isinstance(key, str):
            raise _refuse("schema", "an object key is not text")
        if key in seen:
            raise _refuse("schema", "the request holds a duplicate key")
        if key.lower() in lowered:
            raise _refuse("schema", "the request holds two keys that differ only in case")
        seen[key] = value
        lowered.add(key.lower())
    return seen


def _parse_int(text: str) -> int:
    """The int hook: the raw text of the number must have the int form."""
    if INT_RE.fullmatch(text) is None:
        raise _refuse("schema", "an integer is not written in the required form")
    return int(text)


def _parse_float(text: str) -> Any:
    """A number with a fraction or an exponent is never an int."""
    raise _refuse("schema", "a number with a fraction or an exponent is not allowed")


def _parse_constant(name: str) -> Any:
    """NaN and Infinity are not numbers of the contract."""
    raise _refuse("schema", "a constant is not allowed")


def _check_sam(value: Any) -> None:
    """A sam is a user's or a computer's."""
    if not isinstance(value, str):
        raise _refuse("schema", "a sam is not text")
    if SAM_RE.fullmatch(value) is None and COMPUTER_SAM_RE.fullmatch(value) is None:
        raise _refuse("schema", "a sam is outside its pattern")


def _check_value(kind: str, value: Any) -> None:
    """Check one value against the kind its key carries."""
    if kind == "int":
        if not _is_int(value):
            raise _refuse("schema", "an integer is not an integer")
    elif kind == "int_or_absent":
        if value != "absent" and not _is_int(value):
            raise _refuse("schema", "a value is neither an integer nor absent")
    elif kind == "present_absent":
        if value not in ("present", "absent"):
            raise _refuse("schema", "a value is neither present nor absent")
    elif kind == "guid":
        if not isinstance(value, str) or GUID_RE.fullmatch(value) is None:
            raise _refuse("schema", "a guid is outside its pattern")
    elif kind == "sid":
        if not isinstance(value, str) or SID_RE.fullmatch(value) is None:
            raise _refuse("schema", "a sid is outside its pattern")
    elif kind == "sam":
        _check_sam(value)
    else:  # pragma: no cover - a kind this module does not know
        raise _refuse("schema", "an unknown kind of value")


def _check_keys(values: Mapping[str, Any], kinds: Mapping[str, str]) -> None:
    """Check the keys of an object and every value in it."""
    if set(values) != set(kinds):
        raise _refuse("schema", "the object does not hold exactly the keys of its verb")
    for key, value in values.items():
        _check_value(kinds[key], value)


def _check_target(verb: str, target: Any, *, reading: bool) -> None:
    """Check the target of an apply or of a read."""
    if not isinstance(target, dict):
        raise _refuse("schema", "a target is not an object")
    if reading and set(target) == set(_READ_TARGET_KEYS[verb]):
        _check_keys(target, _READ_TARGET_KEYS[verb])
        return
    _check_keys(target, _TARGET_KEYS[verb])


def _check_common(request: Mapping[str, Any]) -> None:
    """The fields every request carries."""
    if not _is_int(request.get("v")) or request["v"] != 1:
        raise _refuse("schema", "the version is not 1")
    mode = request.get("mode")
    if not isinstance(mode, str) or mode not in _MODE_FIELDS:
        raise _refuse("schema", "the mode is not one of the modes")
    device = request.get("device")
    if not isinstance(device, str) or DEVICE_RE.fullmatch(device) is None:
        raise _refuse("schema", "the device is outside its pattern")


def _check_txid(request: Mapping[str, Any]) -> None:
    """The transaction id."""
    txid = request.get("txid")
    if not isinstance(txid, str) or TXID_RE.fullmatch(txid) is None:
        raise _refuse("schema", "the txid is outside its pattern")


def _check_window(request: Mapping[str, Any], verb: str) -> None:
    """The undo window."""
    window = request.get("window")
    if not _is_int(window):
        raise _refuse("schema", "the window is not an integer")
    if not WINDOW_MIN_S <= window <= WINDOW_MAX_S:
        raise _refuse("schema", "the window is outside its range")
    if verb == "unlock" and window != UNLOCK_WINDOW_S:
        raise _refuse("schema", "the window of an unlock is 120")


def _check_approval_window(request: Mapping[str, Any]) -> None:
    """The approval window: ten digits, moving forward, at most 1800 seconds."""
    nbf = request.get("nbf")
    exp = request.get("exp")
    for name, value in (("nbf", nbf), ("exp", exp)):
        if not _is_int(value):
            raise _refuse("schema", f"the approval {name} is not an integer")
        if EPOCH_RE.fullmatch(str(value)) is None:
            raise _refuse("schema", f"the approval {name} is not ten digits")
    assert _is_int(nbf) and _is_int(exp)
    if nbf >= exp:
        raise _refuse("schema", "the approval window does not move forward")
    if exp - nbf > APPROVAL_WINDOW_S:
        raise _refuse("schema", "the approval window is wider than 1800 seconds")


def _check_secret(request: Mapping[str, Any], verb: str) -> None:
    """The secret of a user-create."""
    if "secret" not in request:
        return
    if verb != "user-create":
        raise _refuse("schema", "only a user-create carries a secret")
    secret = request.get("secret")
    if not isinstance(secret, str):
        raise _refuse("schema", "the secret is not text")
    if not SECRET_MIN <= len(secret) <= SECRET_MAX:
        raise _refuse("schema", "the secret is outside its length")
    if any(not 0x21 <= ord(character) <= 0x7E for character in secret):
        raise _refuse("schema", "the secret holds a character outside 0x21..0x7e")


def _check_risk(request: Mapping[str, Any]) -> None:
    """The risk level the owner approved (section 4)."""
    risk = request.get("risk")
    if not isinstance(risk, str) or RISK_RE.fullmatch(risk) is None:
        raise _refuse("schema", "the risk is not one of LOW, MED or HIGH")


def parse_request(raw: bytes) -> dict[str, Any]:
    """Parse one request and check every schema rule of the contract.

    The raw text is checked for a duplicate key, for two keys that differ
    only in case and for the int form of every number; then every field,
    every type and every pattern of the mode is checked.

    Raises ``RequestRefused`` with the code ``schema`` when the request
    does not fit the contract.
    """
    if not isinstance(raw, (bytes, bytearray)):
        raise _refuse("schema", "the request is not bytes")
    if len(raw) > MAX_REQUEST_BYTES:
        raise _refuse("schema", "the request is bigger than 64 KiB")
    try:
        text = bytes(raw).decode("utf-8")
    except UnicodeDecodeError:
        raise _refuse("schema", "the request is not UTF-8") from None
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_parse_int,
            parse_float=_parse_float,
            parse_constant=_parse_constant,
        )
    except RequestRefused:
        raise
    except (json.JSONDecodeError, ValueError):
        raise _refuse("schema", "the request is not one JSON object") from None
    if not isinstance(value, dict):
        raise _refuse("schema", "the request is not a JSON object")

    _check_common(value)
    mode = value["mode"]
    allowed = _MODE_FIELDS[mode]
    for key in value:
        if key not in allowed:
            raise _refuse("schema", "the request holds a field the mode does not have")
    for key in allowed:
        if key in ("secret",):
            continue
        if key not in value:
            raise _refuse("schema", "the request is missing a field of its mode")

    if mode in ("apply", "read"):
        verb = value.get("verb")
        if not isinstance(verb, str) or verb not in _TARGET_KEYS:
            raise _refuse("schema", "the verb is not one of the verbs")
        _check_target(verb, value.get("target"), reading=(mode == "read"))
    if mode == "apply":
        _check_txid(value)
        _check_window(value, value["verb"])
        _check_approval_window(value)
        _check_risk(value)
        token = value.get("token")
        if not isinstance(token, str) or TOKEN_RE.fullmatch(token) is None:
            raise _refuse("schema", "the token is outside its pattern")
        _check_keys(value["before"], _VALUE_KEYS[value["verb"]])
        _check_keys(value["after"], _VALUE_KEYS[value["verb"]])
        _check_secret(value, value["verb"])
    elif mode in ("confirm", "abort", "status"):
        _check_txid(value)
    return value


def check_verb_rules(req: Mapping[str, Any]) -> None:
    """Apply the per-verb rules of section 3 to one request.

    Only the rules the request itself can answer are checked here: the
    rules that need the live object (a DC account, a privileged group, the
    location of a parent) are the helper's, because it reads the object
    at the moment of the write.

    Raises ``RequestRefused`` with the code ``denied`` when a rule of the
    table is broken.
    """
    verb = req.get("verb")
    if not isinstance(verb, str) or verb not in _TARGET_KEYS:
        raise _refuse("denied", "the verb is not one of the verbs")
    target = req.get("target")
    before = req.get("before")
    after = req.get("after")
    if not isinstance(target, dict) or not isinstance(before, dict) or not isinstance(after, dict):
        raise _refuse("denied", "the request does not hold the images of its verb")

    for key in ("sam", "group_sam", "member_sam"):
        value = target.get(key)
        if isinstance(value, str) and value.casefold() == WRITE_ACCOUNT_SAM.casefold():
            raise _refuse("denied", "the write account is never a target or member")
        if isinstance(value, str):
            lowered = value.casefold()
            if lowered == KRBTGT_SAM or lowered.startswith(RODC_KRBTGT_PREFIX):
                raise _refuse("denied", "krbtgt accounts are never a target or member")

    if verb == "uac-clear":
        bit = target.get("bit")
        if not _is_int(bit) or bit not in UAC_CLEAR_BITS:
            raise _refuse("denied", "the bit is not one of the bits of the table")
        if not _is_int(before.get("uac")) or not _is_int(after.get("uac")):
            raise _refuse("denied", "the images do not hold the userAccountControl")
        if before["uac"] & bit == 0:
            raise _refuse("denied", "the bit is not set in the before-image")
        if after["uac"] != before["uac"] & ~bit:
            raise _refuse("denied", "the after-image is not the before-image without the bit")
    elif verb == "disable":
        if not _is_int(before.get("uac")) or not _is_int(after.get("uac")):
            raise _refuse("denied", "the images do not hold the userAccountControl")
        if before["uac"] & ACCOUNTDISABLE != 0:
            raise _refuse("denied", "the account is already disabled")
        if after["uac"] != before["uac"] | ACCOUNTDISABLE:
            raise _refuse("denied", "the after-image is not the before-image with the bit")
        if _rid_of(target.get("sid")) == 500:
            raise _refuse("denied", "the administrator is never disabled")
    elif verb == "enable":
        if not _is_int(before.get("uac")) or not _is_int(after.get("uac")):
            raise _refuse("denied", "the images do not hold the userAccountControl")
        if before["uac"] & ACCOUNTDISABLE == 0:
            raise _refuse("denied", "the account is not disabled")
        if after["uac"] != before["uac"] & ~ACCOUNTDISABLE:
            raise _refuse("denied", "the after-image is not the before-image without the bit")
    elif verb == "enc-types":
        before_types = _as_int(before.get("etypes"))
        after_types = _as_int(after.get("etypes"))
        if after_types & ENC_TYPE_DES_MASK != 0:
            raise _refuse("denied", "DES is never enabled")
        if (after_types & ~ENC_TYPE_LOW_MASK) != (before_types & ~ENC_TYPE_LOW_MASK):
            raise _refuse("denied", "the bits above 63 may not change")
        if after_types == before_types:
            raise _refuse("denied", "the encryption types do not change")
    elif verb == "unlock":
        if not _is_int(before.get("lockout")) or not _is_int(after.get("lockout")):
            raise _refuse("denied", "the images do not hold the lockout time")
        if before["lockout"] <= 0:
            raise _refuse("denied", "the account is not locked out")
        if after["lockout"] != 0:
            raise _refuse("denied", "the after-image of an unlock is zero")
    elif verb == "member-add":
        if before.get("member") != "absent" or after.get("member") != "present":
            raise _refuse("denied", "a member-add goes from absent to present")
    elif verb == "member-remove":
        if before.get("member") != "present" or after.get("member") != "absent":
            raise _refuse("denied", "a member-remove goes from present to absent")
    elif verb == "maq":
        if not _is_int(after.get("maq")):
            raise _refuse("denied", "the quota is not an integer")
        if not 0 <= after["maq"] <= 1000:
            raise _refuse("denied", "the quota is outside 0..1000")
    elif verb == "user-create":
        if before.get("object") != "absent" or after.get("object") != "present":
            raise _refuse("denied", "a user-create goes from absent to present")
    elif verb == "move":
        # The shape of the parent is a schema rule; where the parent sits
        # is the helper's, because it reads the object at the moment of
        # the write.
        pass


def _as_int(value: Any) -> int:
    """The value of an image field that may be absent (which counts as 0)."""
    if value == "absent":
        return 0
    if _is_int(value):
        return value
    raise _refuse("denied", "the image does not hold the value of its verb")


def _rid_of(sid: Any) -> int | None:
    """The RID of a SID, or None when the SID does not carry one."""
    if not isinstance(sid, str):
        return None
    tail = sid.rsplit("-", 1)[-1]
    if not tail.isdigit():
        return None
    return int(tail)


def _canonical_value(value: Any) -> str:
    """The canonical text of one value."""
    if isinstance(value, bool):
        raise _refuse("schema", "a boolean has no canonical form")
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return value
    raise _refuse("schema", "a value has no canonical form")


def _canonical_pairs(values: Any) -> str:
    """The canonical text of an object: the pairs, sorted, joined with commas."""
    if values is None:
        return ""
    if not isinstance(values, dict):
        raise _refuse("schema", "an object has no canonical form")
    parts = []
    for key in sorted(values):
        if not isinstance(key, str):
            raise _refuse("schema", "an object key is not text")
        parts.append(f"{key}={_canonical_value(values[key])}")
    return ",".join(parts)


def canonical_bytes(req: Mapping[str, Any]) -> bytes:
    """The canonical bytes of one request (SPEC-1.4-REQUEST section 4).

    The eleven lines of the spec, each ending in a newline, in ASCII
    only.  The secret never appears: its line holds the sha256 of its
    ASCII bytes, or a dash when there is no secret.  The risk is in the
    bytes, so the owner approves the level they were shown.
    """
    for field in ("device", "txid", "verb"):
        value = req.get(field)
        if not isinstance(value, str):
            raise _refuse("schema", "the request does not hold the fields of a request")
    risk = req.get("risk")
    if not isinstance(risk, str) or RISK_RE.fullmatch(risk) is None:
        raise _refuse("schema", "the request does not hold a risk level")
    secret = req.get("secret")
    if secret is None:
        secret_line = "-"
    else:
        if not isinstance(secret, str):
            raise _refuse("schema", "the secret is not text")
        secret_line = hashlib.sha256(secret.encode("ascii")).hexdigest()
    window = req.get("window")
    window_line = "" if window is None else _canonical_value(window)
    lines = [
        "newton-ad-request-v1",
        f"device={req['device']}",
        f"txid={req['txid']}",
        f"verb={req['verb']}",
        f"target={_canonical_pairs(req.get('target'))}",
        f"before={_canonical_pairs(req.get('before'))}",
        f"after={_canonical_pairs(req.get('after'))}",
        f"window={window_line}",
        f"risk={risk}",
        f"secret={secret_line}",
        "helper=1",
    ]
    return ("\n".join(lines) + "\n").encode("ascii")


def digest(req: Mapping[str, Any]) -> str:
    """The digest of one request: the sha256 of its canonical bytes."""
    return hashlib.sha256(canonical_bytes(req)).hexdigest()


def token(k_hex: str, digest_hex: str, nbf: int, exp: int) -> str:
    """The approval token of one request.

    The token is the one of the router flow: ``approval_token`` of
    ``newton_mcp.approve`` is the only implementation of it in the
    repository and this function calls it.
    """
    from ...approve import approval_token

    return approval_token(k_hex, digest_hex, nbf, exp)
