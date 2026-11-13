"""The parity of the Windows write helper with the rules of CORE.

The Windows helper (``mcp/newton_mcp/ad/collector/write.ps1``) has its own
JSON scanner, its own canonical bytes and its own digest.  They must be the
same as the ones of ``newton_mcp.ad.write.request``, the Python rules of the
contract, or the two helpers disagree about what the owner approved.

One pwsh process answers every case: the harness dot-sources the helper and
walks the cases of one JSON file.

The tests are skipped, with a reason, when PowerShell 7.4 is not installed.
"""

from __future__ import annotations

import base64
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from newton_mcp.ad.write import request
from pwsh_path import PWSH


AD_DIR = Path(__file__).resolve().parent
HARNESS = AD_DIR / "win_write_harness.ps1"
HELPER = AD_DIR.parents[1] / "newton_mcp" / "ad" / "collector" / "write.ps1"
FIXTURES = AD_DIR / "fixtures"

#: The key of the test vector (SPEC section 4).
KEY_HEX = "11" * 32

#: The ids of the contract.
DEVICE = "lab-win"
TXID = "0123456789abcdef0123456789abcdef"
NBF = 1800000000
EXP = 1800000600
TOKEN = "0" * 64

#: The ids of the objects of the cases.
GUID = "6f9619ff-8b86-d011-b42d-00c04fc964ff"
SID = "S-1-5-21-1-2-3-1105"
SAM = "seed-asrep"
GROUP_GUID = "8f9619ff-8b86-d011-b42d-00c04fc964ff"
GROUP_SID = "S-1-5-21-1-2-3-1106"
GROUP_SAM = "seed-group"
MEMBER_GUID = "9f9619ff-8b86-d011-b42d-00c04fc964ff"
MEMBER_SID = "S-1-5-21-1-2-3-1107"
MEMBER_SAM = "other-user"
PARENT_GUID = "af9619ff-8b86-d011-b42d-00c04fc964ff"
OTHER_GUID = "bf9619ff-8b86-d011-b42d-00c04fc964ff"

#: The target, the before-image and the after-image of every verb.
IMAGES: dict[str, tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = {
    "uac-clear": (
        {"guid": GUID, "sid": SID, "sam": SAM, "bit": 4194304},
        {"uac": 4260352},
        {"uac": 66048},
    ),
    "disable": (
        {"guid": GUID, "sid": SID, "sam": SAM},
        {"uac": 512},
        {"uac": 514},
    ),
    "enable": (
        {"guid": GUID, "sid": SID, "sam": SAM},
        {"uac": 514},
        {"uac": 512},
    ),
    "enc-types": (
        {"guid": GUID, "sid": SID, "sam": SAM},
        {"etypes": 0},
        {"etypes": 16},
    ),
    "unlock": (
        {"guid": GUID, "sid": SID, "sam": SAM},
        {"lockout": 1000},
        {"lockout": 0},
    ),
    "member-add": (
        {
            "group_guid": GROUP_GUID,
            "group_sid": GROUP_SID,
            "group_sam": GROUP_SAM,
            "member_guid": MEMBER_GUID,
            "member_sid": MEMBER_SID,
            "member_sam": MEMBER_SAM,
        },
        {"member": "absent"},
        {"member": "present"},
    ),
    "member-remove": (
        {
            "group_guid": GROUP_GUID,
            "group_sid": GROUP_SID,
            "group_sam": GROUP_SAM,
            "member_guid": MEMBER_GUID,
            "member_sid": MEMBER_SID,
            "member_sam": MEMBER_SAM,
        },
        {"member": "present"},
        {"member": "absent"},
    ),
    "maq": (
        {"guid": GUID},
        {"maq": 10},
        {"maq": 20},
    ),
    "user-create": (
        {"parent_guid": PARENT_GUID, "sam": "new.user"},
        {"object": "absent"},
        {"object": "present"},
    ),
    "move": (
        {"guid": GUID, "sid": SID, "sam": SAM},
        {"parent": PARENT_GUID},
        {"parent": OTHER_GUID},
    ),
}

#: The target a read may use when it knows only the name (SPEC section 6).
READ_TARGETS: dict[str, dict[str, Any]] = {
    "uac-clear": {"sam": SAM},
    "disable": {"sam": SAM},
    "enable": {"sam": SAM},
    "enc-types": {"sam": SAM},
    "unlock": {"sam": SAM},
    "member-add": {"group_sam": GROUP_SAM, "member_sam": MEMBER_SAM},
    "member-remove": {"group_sam": GROUP_SAM, "member_sam": MEMBER_SAM},
    "maq": {"guid": GUID},
    "user-create": {"parent_guid": PARENT_GUID, "sam": "new.user"},
    "move": {"sam": SAM},
}


def _apply(verb: str = "uac-clear", **changes: Any) -> dict[str, Any]:
    """A request of the contract, with the changes of the case."""
    target, before, after = IMAGES[verb]
    payload: dict[str, Any] = {
        "v": 1,
        "mode": "apply",
        "device": DEVICE,
        "txid": TXID,
        "verb": verb,
        "target": dict(target),
        "before": dict(before),
        "after": dict(after),
        "window": 120 if verb == "unlock" else 600,
        "risk": "MED",
        "nbf": NBF,
        "exp": EXP,
        "token": TOKEN,
    }
    for name, value in changes.items():
        if value is None:
            payload.pop(name, None)
        else:
            payload[name] = value
    return payload


def _read(verb: str = "uac-clear", **changes: Any) -> dict[str, Any]:
    """A read request of the contract."""
    payload: dict[str, Any] = {
        "v": 1,
        "mode": "read",
        "device": DEVICE,
        "verb": verb,
        "target": dict(READ_TARGETS[verb]),
    }
    for name, value in changes.items():
        if value is None:
            payload.pop(name, None)
        else:
            payload[name] = value
    return payload


def _without(payload: dict[str, Any], name: str) -> dict[str, Any]:
    """The request without one field."""
    copy = dict(payload)
    copy.pop(name, None)
    return copy


def _text(payload: dict[str, Any]) -> str:
    """The raw text of a request."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _cases() -> list[dict[str, Any]]:
    """Every case of the parity: the valid requests and the broken ones."""
    cases: list[dict[str, Any]] = []

    def add(name: str, raw: str) -> None:
        cases.append({"id": name, "stage": "parse", "raw": raw})

    # every verb, as an apply and as a read
    for verb in IMAGES:
        add(f"apply-{verb}", _text(_apply(verb)))
        add(f"read-{verb}", _text(_read(verb)))

    # the secret of a user-create
    add(
        "user-create-with-secret",
        _text(_apply("user-create", secret="a-very-secret-password")),
    )
    add(
        "user-create-without-secret",
        _text(_apply("user-create")),
    )

    # the modes that are not an apply
    for mode in ("confirm", "abort", "status"):
        add(
            f"mode-{mode}",
            _text({"v": 1, "mode": mode, "device": DEVICE, "txid": TXID}),
        )

    # the version
    add("version-two", _text(_apply(v=2)))
    add("version-zero", _text(_apply(v=0)))
    add("version-text", _text(_apply(v="1")))
    add("version-true", _text(_apply(v=True)))

    # the mode
    add("mode-unknown", _text(_apply(mode="write")))
    add("mode-empty", _text(_apply(mode="")))
    add("mode-number", _text(_apply(mode=7)))

    # the device
    add("device-upper", _text(_apply(device="Lab-Win")))
    add("device-digit-first", _text(_apply(device="1ab")))
    add("device-too-long", _text(_apply(device="a" * 33)))
    add("device-empty", _text(_apply(device="")))
    add("device-dash", _text(_apply(device="lab-win-2")))
    add("device-trailing-newline", _text(_apply(device=DEVICE + "\n")))

    # a field outside the mode
    add("field-unknown", _text(_apply(extra=1)))
    add("field-unknown-read", _text(_read(extra=1)))
    add("field-secret-on-uac", _text(_apply(secret="a-very-secret-password")))
    add("field-before-on-read", _text(_read(before={"uac": 1})))

    # a missing field
    add("field-missing-txid", _text(_apply(txid=None)))
    add("field-missing-token", _text(_apply(token=None)))
    add("field-missing-risk", _text(_apply(risk=None)))
    add("field-missing-window", _text(_apply(window=None)))
    add("field-missing-target", _text(_apply(target=None)))
    add("field-missing-before", _text(_apply(before=None)))
    add("field-missing-after", _text(_apply(after=None)))
    add("field-missing-verb", _text(_without(_apply(), "verb")))
    add("field-missing-nbf", _text(_apply(nbf=None)))
    add("field-missing-exp", _text(_apply(exp=None)))
    add("field-missing-mode", _text(_without(_apply(), "mode")))
    add("field-missing-device", _text(_without(_apply(), "device")))

    # the txid
    add("txid-upper", _text(_apply(txid="0123456789ABCDEF0123456789abcdef")))
    add("txid-short", _text(_apply(txid="0123")))
    add("txid-long", _text(_apply(txid="0" * 33)))
    add("txid-path", _text(_apply(txid="../../etc/passwd")))
    add("txid-trailing-newline", _text(_apply(txid=TXID + "\n")))

    # the token
    add("token-upper", _text(_apply(token="A" * 64)))
    add("token-short", _text(_apply(token="a" * 63)))
    add("token-number", _text(_apply(token=1)))

    # the risk
    add("risk-low", _text(_apply(risk="LOW")))
    add("risk-high", _text(_apply(risk="HIGH")))
    add("risk-lower", _text(_apply(risk="low")))
    add("risk-empty", _text(_apply(risk="")))

    # the window
    add("window-min", _text(_apply(window=120)))
    add("window-max", _text(_apply(window=1800)))
    add("window-low", _text(_apply(window=119)))
    add("window-high", _text(_apply(window=1801)))
    add("window-unlock-120", _text(_apply("unlock", window=120)))
    add("window-unlock-600", _text(_apply("unlock", window=600)))
    add("window-text", _text(_apply(window="600")))

    # the approval window
    add("nbf-nine-digits", _text(_apply(nbf=180000000, exp=180000600)))
    add("exp-nine-digits", _text(_apply(exp=180000600)))
    add("nbf-after-exp", _text(_apply(nbf=1800000600, exp=1800000000)))
    add("nbf-equal-exp", _text(_apply(nbf=1800000000, exp=1800000000)))
    add("approval-too-wide", _text(_apply(nbf=1800000000, exp=1800001801)))
    add("approval-wide-enough", _text(_apply(nbf=1800000000, exp=1800001800)))

    # the int form of the contract
    add("int-float", _text(_apply(window=600.0)).replace('"window":600.0', '"window":1.0'))
    add("int-exponent", _text(_apply(window=600)).replace('"window":600', '"window":1e3'))
    add("int-negative", _text(_apply(window=600)).replace('"window":600', '"window":-1'))
    add("int-leading-zero", _text(_apply(window=600)).replace('"window":600', '"window":01'))
    add("int-true", _text(_apply(window=600)).replace('"window":600', '"window":true'))
    add("int-true-bit", _text(_apply()).replace('"bit":4194304', '"bit":true'))
    add("int-null", _text(_apply(window=600)).replace('"window":600', '"window":null'))
    add("int-float-uac", _text(_apply()).replace('"uac":4260352', '"uac":4260352.0'))
    add("int-exponent-uac", _text(_apply()).replace('"uac":4260352', '"uac":4.26e6'))
    add("int-negative-uac", _text(_apply()).replace('"uac":4260352', '"uac":-4260352'))
    add("int-huge-uac", _text(_apply()).replace('"uac":4260352', '"uac":123456789012345678901234567890'))
    add("int-true-before", _text(_apply()).replace('"uac":4260352', '"uac":true'))

    # a duplicate key and two keys that differ only in case
    add(
        "duplicate-key",
        '{"v":1,"v":1,"mode":"apply","device":"lab-win","txid":"'
        + TXID
        + '","verb":"uac-clear","target":{"guid":"'
        + GUID
        + '","sid":"'
        + SID
        + '","sam":"'
        + SAM
        + '","bit":4194304},"before":{"uac":4260352},"after":{"uac":66048},'
        '"window":600,"risk":"MED","nbf":1800000000,"exp":1800000600,'
        '"token":"' + TOKEN + '"}',
    )
    add(
        "case-variant-key",
        '{"v":1,"V":1,"mode":"apply","device":"lab-win","txid":"'
        + TXID
        + '","verb":"uac-clear","target":{"guid":"'
        + GUID
        + '","sid":"'
        + SID
        + '","sam":"'
        + SAM
        + '","bit":4194304},"before":{"uac":4260352},"after":{"uac":66048},'
        '"window":600,"risk":"MED","nbf":1800000000,"exp":1800000600,'
        '"token":"' + TOKEN + '"}',
    )
    add(
        "duplicate-key-in-target",
        '{"v":1,"mode":"apply","device":"lab-win","txid":"'
        + TXID
        + '","verb":"uac-clear","target":{"guid":"'
        + GUID
        + '","guid":"'
        + GUID
        + '","sid":"'
        + SID
        + '","sam":"'
        + SAM
        + '","bit":4194304},"before":{"uac":4260352},"after":{"uac":66048},'
        '"window":600,"risk":"MED","nbf":1800000000,"exp":1800000600,'
        '"token":"' + TOKEN + '"}',
    )
    add(
        "case-variant-key-in-target",
        '{"v":1,"mode":"apply","device":"lab-win","txid":"'
        + TXID
        + '","verb":"uac-clear","target":{"guid":"'
        + GUID
        + '","SID":"'
        + SID
        + '","sam":"'
        + SAM
        + '","bit":4194304},"before":{"uac":4260352},"after":{"uac":66048},'
        '"window":600,"risk":"MED","nbf":1800000000,"exp":1800000600,'
        '"token":"' + TOKEN + '"}',
    )

    # the text of the request itself
    add("empty-request", "")
    add("not-json", "this is not json")
    add("json-array", "[1,2,3]")
    add("json-number", "42")
    add("json-string", '"hello"')
    add("trailing-junk", _text(_apply()) + " trailing")
    add("two-objects", _text(_apply()) + _text(_apply()))

    # the shape of the target of every verb
    for verb in IMAGES:
        target = dict(IMAGES[verb][0])
        broken = dict(target)
        broken["extra"] = "x"
        add(f"target-extra-{verb}", _text(_apply(verb, target=broken)))
        missing = dict(target)
        missing.pop(sorted(missing)[0])
        add(f"target-missing-{verb}", _text(_apply(verb, target=missing)))
        add(f"target-not-object-{verb}", _text(_apply(verb, target="CN=x")))

    # the shape of the images of every verb
    for verb in IMAGES:
        before = dict(IMAGES[verb][1])
        after = dict(IMAGES[verb][2])
        broken_before = dict(before)
        broken_before["extra"] = 1
        add(f"before-extra-{verb}", _text(_apply(verb, before=broken_before)))
        broken_after = dict(after)
        broken_after["extra"] = 1
        add(f"after-extra-{verb}", _text(_apply(verb, after=broken_after)))

    # the values of the images
    add("before-wrong-kind", _text(_apply(before={"uac": "4260352"})))
    add("after-wrong-kind", _text(_apply(after={"uac": True})))
    add("enc-types-absent-before", _text(_apply("enc-types", before={"etypes": "absent"})))
    add("enc-types-absent-after", _text(_apply("enc-types", after={"etypes": "absent"})))
    add("enc-types-text", _text(_apply("enc-types", before={"etypes": "0"})))
    add("member-present", _text(_apply("member-add", before={"member": "present"})))
    add("member-unknown", _text(_apply("member-add", before={"member": "maybe"})))
    add("object-unknown", _text(_apply("user-create", before={"object": "maybe"})))
    add("parent-not-a-guid", _text(_apply("move", after={"parent": "not-a-guid"})))

    # the patterns of the values of the target
    add("guid-upper", _text(_apply(target={**IMAGES["uac-clear"][0], "guid": GUID.upper()})))
    add("guid-braces", _text(_apply(target={**IMAGES["uac-clear"][0], "guid": "{" + GUID + "}"})))
    add("guid-trailing-newline", _text(_apply(target={**IMAGES["uac-clear"][0], "guid": GUID + "\n"})))
    add("sid-short", _text(_apply(target={**IMAGES["uac-clear"][0], "sid": "S-1-5-21-1-2-3"})))
    add("sam-upper", _text(_apply(target={**IMAGES["uac-clear"][0], "sam": "Seed"})))
    add("sam-trailing-newline", _text(_apply(target={**IMAGES["uac-clear"][0], "sam": SAM + "\n"})))
    add("sam-too-long", _text(_apply(target={**IMAGES["uac-clear"][0], "sam": "a" * 21})))
    add("sam-computer", _text(_apply(target={**IMAGES["uac-clear"][0], "sam": "pc-1$"})))
    add("bit-not-in-table", _text(_apply(target={**IMAGES["uac-clear"][0], "bit": 2})))
    add("bit-text", _text(_apply(target={**IMAGES["uac-clear"][0], "bit": "4194304"})))
    add("read-target-extra", _text(_read(target={"sam": SAM, "sid": SID})))
    add("read-target-guid", _text(_read(target={"guid": GUID})))

    # the secret
    add("secret-short", _text(_apply("user-create", secret="short")))
    add("secret-long", _text(_apply("user-create", secret="a" * 129)))
    add("secret-space", _text(_apply("user-create", secret="a secret with spaces")))
    add("secret-control", _text(_apply("user-create", secret="a" * 15 + "\t")))
    add("secret-number", _text(_apply("user-create", secret=1234567890123456)))

    # the size of the request
    add(
        "oversize",
        _text(_apply(pad="x" * 70000)),
    )
    add(
        "oversize-read",
        _text(_read(pad="x" * 70000)),
    )
    add(
        "oversize-just-over",
        _text(_apply(pad="x" * 65500)),
    )

    # the risk the owner approves, for every verb
    for verb in IMAGES:
        add(f"risk-low-{verb}", _text(_apply(verb, risk="LOW")))
        add(f"risk-high-{verb}", _text(_apply(verb, risk="HIGH")))

    # a read with the whole target, for every verb
    for verb in IMAGES:
        add(f"read-full-{verb}", _text(_read(verb, target=dict(IMAGES[verb][0]))))

    # a value of the wrong type, for every value of every verb
    for verb in IMAGES:
        target = IMAGES[verb][0]
        for name, value in target.items():
            wrong = "not-an-int" if isinstance(value, int) else 42
            broken = dict(target)
            broken[name] = wrong
            add(f"target-type-{verb}-{name}", _text(_apply(verb, target=broken)))
        for name, value in IMAGES[verb][1].items():
            wrong = "not-an-int" if isinstance(value, int) else 42
            broken = dict(IMAGES[verb][1])
            broken[name] = wrong
            add(f"before-type-{verb}-{name}", _text(_apply(verb, before=broken)))
            broken = dict(IMAGES[verb][2])
            broken[name] = wrong
            add(f"after-type-{verb}-{name}", _text(_apply(verb, after=broken)))

    # the int form of every number of the request
    for field in ("window", "nbf", "exp"):
        for form in ("1.0", "1e3", "-1", "01", "true"):
            add(
                f"int-form-{field}-{form}",
                _text(_apply(**{field: "INTFORM"})).replace('"INTFORM"', form),
            )

    # the int form of the numbers of the target and of the images
    for verb in IMAGES:
        for name, value in IMAGES[verb][0].items():
            if not isinstance(value, int):
                continue
            for form in ("1.0", "1e3", "-1", "true"):
                broken = dict(IMAGES[verb][0])
                broken[name] = "INTFORM"
                add(
                    f"target-int-form-{verb}-{name}-{form}",
                    _text(_apply(verb, target=broken)).replace('"INTFORM"', form),
                )
        for image in ("before", "after"):
            for name, value in IMAGES[verb][1 if image == "before" else 2].items():
                if not isinstance(value, int):
                    continue
                for form in ("1.0", "1e3", "-1", "true"):
                    broken = dict(IMAGES[verb][1 if image == "before" else 2])
                    broken[name] = "INTFORM"
                    add(
                        f"{image}-int-form-{verb}-{name}-{form}",
                        _text(_apply(verb, **{image: broken})).replace('"INTFORM"', form),
                    )

    # the device names
    for index, name in enumerate((
        "a",
        "z9",
        "lab-win",
        "lab-win-2",
        "a" * 32,
        "Lab",
        "9lab",
        "-lab",
        "lab_win",
        "lab.win",
        "lab win",
        "",
    )):
        add(f"device-name-{index}-{name or 'empty'}", _text(_apply(device=name)))

    # the transaction ids
    for index, name in enumerate((
        "0" * 32,
        "f" * 32,
        "0123456789abcdef" * 2,
        "0123456789ABCDEF0123456789abcdef",
        "0123456789abcdef0123456789abcde",
        "0123456789abcdef0123456789abcdefa",
        "0123456789abcdef0123456789abcdeg",
        "",
    )):
        add(f"txid-{index}-{name or 'empty'}", _text(_apply(txid=name)))

    # the tokens
    for index, name in enumerate((
        "0" * 64,
        "f" * 64,
        "a" * 63,
        "a" * 65,
        "A" * 64,
        "g" * 64,
        "",
    )):
        add(f"token-{index}-{len(name)}", _text(_apply(token=name)))

    # the windows and the approval windows
    for value in (0, 1, 119, 120, 121, 1799, 1800, 1801, 3600):
        add(f"window-{value}", _text(_apply(window=value)))
    for nbf, exp in (
        (999999999, 1000000000),
        (1000000000, 1000000001),
        (1000000000, 1000001800),
        (1000000000, 1000001801),
        (1800000000, 1800000000),
        (1800000600, 1800000000),
        (9999999999, 9999999999),
        (99999999999, 99999999999),
    ):
        add(f"approval-{nbf}-{exp}", _text(_apply(nbf=nbf, exp=exp)))

    # the secrets
    for index, name in enumerate((
        "a" * 16,
        "a" * 128,
        "a" * 15,
        "a" * 129,
        "a b c d e f g h i j k l",
        "a!b@c#d$e%f^g&h*i(j",
        "secret-with-a-quote\"",
    )):
        add(f"secret-{index}-{len(name)}", _text(_apply("user-create", secret=name)))

    # the targets of a read
    for verb in IMAGES:
        broken = dict(READ_TARGETS[verb])
        broken["extra"] = "x"
        add(f"read-target-extra-{verb}", _text(_read(verb, target=broken)))
        missing = dict(READ_TARGETS[verb])
        missing.pop(sorted(missing)[0])
        add(f"read-target-missing-{verb}", _text(_read(verb, target=missing)))

    return cases


def _pwsh() -> str:
    """The shell of the tests, or a skip."""
    if not PWSH.is_file():
        pytest.skip(
            f"PowerShell 7.4 is not installed at {PWSH}: the Windows write "
            "helper cannot be exercised"
        )
    return str(PWSH)


def _run(cases: list[dict[str, Any]], tmp_path: Path) -> dict[str, dict[str, Any]]:
    """One pwsh process answers every case."""
    cases_path = tmp_path / "cases.json"
    cases_path.write_text(json.dumps({"cases": cases}), encoding="utf-8")
    finished = subprocess.run(
        [
            _pwsh(),
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(HARNESS),
            str(cases_path),
        ],
        capture_output=True,
        text=True,
        timeout=900,
        check=False,
    )
    if finished.returncode != 0:
        pytest.fail(
            "the harness of the Windows write helper failed: "
            f"{finished.returncode}: {finished.stderr.strip()[:2000]}"
        )
    document = json.loads(finished.stdout)
    return {str(case["id"]): case for case in document["cases"]}


@pytest.fixture(scope="module")
def answers(tmp_path_factory: pytest.TempPathFactory) -> dict[str, dict[str, Any]]:
    """The answers of the harness to every case."""
    _pwsh()
    cases = _cases()
    directory = tmp_path_factory.mktemp("win-write-parity")
    return _run(cases, directory)


def _core(raw: str) -> tuple[str, dict[str, Any] | None]:
    """What CORE makes of one request."""
    try:
        parsed = request.parse_request(raw.encode("utf-8"))
    except request.RequestRefused as exc:
        return exc.code, None
    return "ok", parsed


def test_the_cases_cover_every_verb_and_the_rules() -> None:
    """The case set is big enough and holds every verb."""
    cases = _cases()
    ids = {case["id"] for case in cases}
    assert len(cases) >= 300
    for verb in IMAGES:
        assert f"apply-{verb}" in ids
        assert f"read-{verb}" in ids
    for name in (
        "duplicate-key",
        "case-variant-key",
        "int-float",
        "int-exponent",
        "int-negative",
        "int-leading-zero",
        "int-true",
        "oversize",
    ):
        assert name in ids


def test_every_case_answers_the_same_code_as_core(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The helper refuses exactly what CORE refuses."""
    for case in _cases():
        raw = case["raw"]
        code, _ = _core(raw)
        answer = answers[case["id"]]
        assert answer["code"] == code, case["id"]


def test_every_accepted_case_has_the_same_canonical_bytes(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The canonical bytes of the helper are the ones of CORE."""
    checked = 0
    for case in _cases():
        raw = case["raw"]
        code, parsed = _core(raw)
        if parsed is None:
            continue
        answer = answers[case["id"]]
        if code != "ok":
            continue
        if "risk" not in parsed:
            continue
        expected = base64.b64encode(request.canonical_bytes(parsed)).decode("ascii")
        assert answer["canonical_b64"] == expected, case["id"]
        checked += 1
    assert checked >= 60


def test_every_accepted_case_has_the_same_digest_and_token(
    answers: dict[str, dict[str, Any]],
) -> None:
    """The digest and the token of the helper are the ones of CORE."""
    checked = 0
    for case in _cases():
        raw = case["raw"]
        code, parsed = _core(raw)
        if parsed is None or "nbf" not in parsed:
            continue
        answer = answers[case["id"]]
        digest = request.digest(parsed)
        assert answer["digest"] == digest, case["id"]
        assert answer["token"] == request.token(
            KEY_HEX, digest, parsed["nbf"], parsed["exp"]
        ), case["id"]
        checked += 1
    assert checked >= 40


def test_the_vector_is_reproduced_byte_for_byte(
    tmp_path: Path,
) -> None:
    """The vector of the contract: the bytes, the digest and the token."""
    vector = json.loads((FIXTURES / "write-request-v1.json").read_text(encoding="utf-8"))
    expected = json.loads(
        (FIXTURES / "write-request-v1.expected.json").read_text(encoding="utf-8")
    )
    cases = [
        {
            "id": "vector",
            "stage": "parse",
            "raw": json.dumps(vector, sort_keys=True, separators=(",", ":")),
        }
    ]
    answer = _run(cases, tmp_path)["vector"]
    assert answer["code"] == "ok"
    assert answer["canonical_b64"] == expected["canonical_b64"]
    assert answer["digest"] == expected["digest"]
    assert answer["token"] == expected["token"]
    assert answer["token"] == vector["token"]


def test_the_helper_is_where_the_tests_expect_it() -> None:
    """The helper the tests drive is the one the package ships."""
    assert HELPER.is_file()
    assert HARNESS.is_file()
