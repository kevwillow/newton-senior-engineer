"""The AD change plan (DESIGN-1.4 section 1, SPEC-1.4-REQUEST).

A plan is built from two reads of the domain controller: the first one
resolves the names to ids, the second one takes the before-image.  The
plan holds the verb, the target by id, the before- and after-images, the
risk and the window, and it is written under the state directory with
mode 0600.

The plan never carries a filter, a DN or free text: everything in it is
an id, an int or one of the words of the contract.

For a ``user-create`` the plan holds the password Newton generated.  It
is written in the plan file and nowhere else: it never reaches a tool
result, a receipt or a log.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Sequence

from . import inventory, request, store, transport
from .errors import WriteError


#: The function that sends one request to one helper.
Send = Callable[[Any, Mapping[str, Any]], dict[str, Any]]

#: The undo window of a plan, in seconds (SPEC-1.4-REQUEST section 2).
DEFAULT_WINDOW_S = 600

#: The length of the password of a user-create.
PASSWORD_LENGTH = 24

#: The printable set of section 2: 0x21..0x7e, without the backslash.
#: The terminal prints a literal backslash as two, so a password holding
#: one would reach the owner as another password.
PASSWORD_ALPHABET = "".join(
    chr(code) for code in range(0x21, 0x7F) if chr(code) != "\\"
)

#: The verbs that take one name.
ONE_NAME = (
    "uac-clear",
    "disable",
    "enable",
    "enc-types",
    "unlock",
    "user-create",
    "move",
)

#: The verbs that take two names.
TWO_NAMES = ("member-add", "member-remove")

#: The verbs that take no name.
NO_NAMES = ("maq",)


def load_devices(devices: Mapping[str, Any] | None) -> Mapping[str, Any]:
    """The inventory, or the one the caller passes."""
    if devices is not None:
        return devices
    from ...server import load_inventory

    return load_inventory()


def _names(target_names: Any) -> list[str]:
    """The names of the target, as a list of text."""
    if target_names is None:
        return []
    if isinstance(target_names, str) or not isinstance(target_names, Sequence):
        raise WriteError("the names of the target must be a list")
    names: list[str] = []
    for name in target_names:
        if not isinstance(name, str):
            raise WriteError("a name of the target is not text")
        names.append(name)
    return names


def _check_names(verb: str, names: list[str]) -> None:
    """The names of the target: the right count, and every one a sam."""
    if verb in TWO_NAMES:
        expected = 2
    elif verb in NO_NAMES:
        expected = 0
    else:
        expected = 1
    if len(names) != expected:
        raise WriteError(
            f"the verb {verb} takes {expected} name(s) of the target"
        )
    for name in names:
        if (
            request.SAM_RE.fullmatch(name) is None
            and request.COMPUTER_SAM_RE.fullmatch(name) is None
        ):
            raise WriteError("a name of the target is outside the sam pattern")


#: TRUSTED_FOR_DELEGATION: the directory lets only a holder of
#: SeEnableDelegationPrivilege change it (measured 2026-11-13, LDAP error 50).
TRUSTED_FOR_DELEGATION = 524288

TRUST_BIT_REFUSAL = (
    "Newton does not clear bit 524288 (TRUSTED_FOR_DELEGATION): the "
    "directory lets only a holder of SeEnableDelegationPrivilege change it, "
    "and the write account does not hold that privilege by design. Clear it "
    "with the Active Directory admin tools."
)


def _check_value(verb: str, value: Any) -> None:
    """The value of the change: an int or a guid, where the verb needs one."""
    if verb == "uac-clear":
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value not in request.UAC_CLEAR_BITS
        ):
            raise WriteError("the bit is not one of the bits of the table")
        if value == TRUSTED_FOR_DELEGATION:
            raise WriteError(TRUST_BIT_REFUSAL)
    elif verb == "enc-types":
        if not isinstance(value, int) or isinstance(value, bool):
            raise WriteError("the encryption types must be an integer")
    elif verb == "maq":
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not 0 <= value <= 1000
        ):
            raise WriteError("the quota must be an integer from 0 to 1000")
    elif verb in ("move", "user-create"):
        if not isinstance(value, str) or request.GUID_RE.fullmatch(value) is None:
            raise WriteError("the value must be a guid")
    elif value is not None:
        raise WriteError("this verb takes no value")


def _read_target(
    verb: str,
    names: list[str],
    value: Any,
    devices: Mapping[str, Any],
    domain: str,
) -> dict[str, Any]:
    """The target of the first read: the names, or the guid the verb needs."""
    if verb in TWO_NAMES:
        return {"group_sam": names[0], "member_sam": names[1]}
    if verb == "maq":
        return {"guid": inventory.domain_guid(devices, domain)}
    if verb == "user-create":
        return {"parent_guid": value, "sam": names[0]}
    return {"sam": names[0]}


def _pdc_of(dcs: list[Any], answers: Mapping[str, Any]) -> Any | None:
    """The domain controller of the domain, by the read facts."""
    for device in dcs:
        facts = answers.get(device.name, {}).get("facts") or {}
        if not isinstance(facts, dict):
            continue
        for one in facts.values():
            if isinstance(one, dict) and one.get("pdc") is True:
                return device
    return None


def _full_target(verb: str, ids: Mapping[str, Any], value: Any) -> dict[str, Any]:
    """The target of the request: the ids of the object, and what the verb adds."""
    target = dict(ids)
    if verb == "uac-clear":
        target["bit"] = value
    return target


def _after(verb: str, before: Mapping[str, Any], value: Any) -> dict[str, Any]:
    """The after-image of the change."""
    if verb == "uac-clear":
        return {"uac": int(before["uac"]) & ~int(value)}
    if verb == "disable":
        return {"uac": int(before["uac"]) | request.ACCOUNTDISABLE}
    if verb == "enable":
        return {"uac": int(before["uac"]) & ~request.ACCOUNTDISABLE}
    if verb == "enc-types":
        return {"etypes": value}
    if verb == "unlock":
        return {"lockout": 0}
    if verb == "member-add":
        if before.get("member") != "absent":
            raise WriteError("the member is already in the group")
        return {"member": "present"}
    if verb == "member-remove":
        if before.get("member") != "present":
            raise WriteError("the member is not in the group")
        return {"member": "absent"}
    if verb == "maq":
        return {"maq": value}
    if verb == "user-create":
        if before.get("object") != "absent":
            raise WriteError("an object with that name is already there")
        return {"object": "present"}
    if verb == "move":
        return {"parent": value}
    raise WriteError("the verb is not one of the verbs of the contract")


def _check_facts(
    verb: str,
    target: Mapping[str, Any],
    facts: Mapping[str, Any],
) -> None:
    """The rules of the table and of section 5 that the facts answer."""
    for one in facts.values():
        if not isinstance(one, dict):
            continue
        privileged = one.get("privileged") is True
        dc_account = one.get("dc_account") is True
        classes = [str(item) for item in one.get("object_class") or []]
        if privileged and verb not in ("uac-clear", "enc-types", "unlock"):
            raise WriteError(
                "the target is privileged; only uac-clear, enc-types and "
                "unlock are allowed on it"
            )
        if dc_account:
            if verb in ("disable", "move"):
                raise WriteError(
                    "a domain controller account is never disabled or moved"
                )
            if verb == "uac-clear" and target.get("bit") == 524288:
                raise WriteError(
                    "the trust bit is never cleared on a domain controller account"
                )
        if verb in ("disable", "enable") and not (
            {"user", "computer"} & set(classes)
        ):
            raise WriteError("only a user or a computer may be disabled or enabled")
        if verb == "maq" and "domainDNS" not in classes:
            raise WriteError("the target of a maq is the domain head")


def _risk(verb: str, facts: Mapping[str, Any]) -> str:
    """The risk of the change (SPEC-1.4-REQUEST section 5)."""
    for one in facts.values():
        if not isinstance(one, dict):
            continue
        if one.get("privileged") is True:
            return "HIGH"
        if one.get("admin_count") == 1:
            return "HIGH"
        if one.get("dc_account") is True:
            return "HIGH"
    if verb == "unlock":
        return "LOW"
    return "MED"


def _password() -> str:
    """A password of 24 characters of the printable set of section 2."""
    return "".join(
        secrets.choice(PASSWORD_ALPHABET) for _ in range(PASSWORD_LENGTH)
    )


def _window(verb: str) -> int:
    """The undo window of the plan."""
    if verb == "unlock":
        return request.UNLOCK_WINDOW_S
    return DEFAULT_WINDOW_S


#: The plain line every plan carries: Newton reads back only the DCs it knows.
UNLISTED_DC_WARNING = (
    "Newton verifies the change only on the DCs listed in dcs: the DCs of "
    "the domain with a write entry in the inventory. A DC of the domain "
    "without a write entry is never read before the confirm, so set up "
    "every DC of the domain (SKILL.md, the AD write setup) before you "
    "approve."
)


def plan_change(
    domain: str,
    verb: str,
    target_names: Any,
    value: Any = None,
    *,
    send: Send | None = None,
    devices: Mapping[str, Any] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build the plan of one change in one domain.

    The domain is the name of the device that stands for it.  The verb is
    one of the verbs of the contract, the names are the sams of the
    target and the value is the int or the guid the verb needs.

    The plan is written under ``<state_dir>/ad-plans/`` with mode 0600
    and a fresh transaction id.  The result never holds the password of a
    user-create.
    """
    if not isinstance(domain, str) or not domain:
        raise WriteError("the domain is not a name")
    if not isinstance(verb, str) or verb not in request.VERBS:
        raise WriteError("the verb is not one of the verbs of the contract")
    names = _names(target_names)
    _check_names(verb, names)
    _check_value(verb, value)

    inventory_devices = load_devices(devices)
    dcs = inventory.domain_dcs(inventory_devices, domain)
    if not dcs:
        raise WriteError("the domain has no write entry")
    sender = send if send is not None else transport.send

    read_target = _read_target(verb, names, value, inventory_devices, domain)
    answers: dict[str, Any] = {}
    for device in dcs:
        answer = sender(
            device,
            {
                "v": 1,
                "mode": "read",
                "device": domain,
                "verb": verb,
                "target": read_target,
            },
        )
        if answer.get("code") != "ok":
            raise WriteError("a domain controller of the domain did not answer the read")
        answers[device.name] = answer
    pdc = _pdc_of(dcs, answers)
    if pdc is None:
        raise WriteError("the domain has no domain controller")

    ids = answers[pdc.name].get("ids")
    if not isinstance(ids, dict):
        raise WriteError("the domain controller did not resolve the target")
    target = _full_target(verb, ids, value)
    # The rules the first read's facts already answer come first: a BUILTIN
    # group's SID (S-1-5-32-...) fails the request pattern of the full
    # target, so its read answers schema, never the privileged refusal.
    first_facts = answers[pdc.name].get("facts")
    if isinstance(first_facts, dict):
        _check_facts(verb, target, first_facts)
    before_answer = sender(
        pdc,
        {
            "v": 1,
            "mode": "read",
            "device": domain,
            "verb": verb,
            "target": target,
        },
    )
    if before_answer.get("code") != "ok":
        raise WriteError("the domain controller did not answer the read")
    live = before_answer.get("live")
    if not isinstance(live, dict):
        raise WriteError("the domain controller did not answer the read")
    before = dict(live)
    facts = before_answer.get("facts")
    if not isinstance(facts, dict):
        facts = {}
    after = _after(verb, before, value)
    _check_facts(verb, target, facts)

    planned = {
        "v": 1,
        "mode": "apply",
        "device": domain,
        "verb": verb,
        "target": target,
        "before": before,
        "after": after,
        "window": _window(verb),
    }
    try:
        request.check_verb_rules(planned)
    except request.RequestRefused as exc:
        raise WriteError(f"the change does not fit the rules of the verb: {exc}") from None

    risk = _risk(verb, facts)
    plan_id = secrets.token_hex(16)
    txid = secrets.token_hex(16)
    created = datetime.now(timezone.utc) if now is None else now
    plan: dict[str, Any] = {
        "v": 1,
        "plan_id": plan_id,
        "txid": txid,
        "device": domain,
        "domain": domain,
        "pdc": pdc.name,
        "verb": verb,
        "target": target,
        "before": before,
        "after": after,
        "window": planned["window"],
        "risk": risk,
        "facts": facts,
        "created_at": created.isoformat(),
    }
    if verb == "user-create":
        plan["secret"] = _password()
    plan["digest"] = request.digest(plan)
    store.write_json(store.plan_path(plan_id), plan)

    return {
        "result": "ok",
        "plan_id": plan_id,
        "txid": txid,
        "device": domain,
        "verb": verb,
        "risk": risk,
        "window": plan["window"],
        "target": dict(target),
        "before": dict(before),
        "after": dict(after),
        "dcs": sorted(device.name for device in dcs),
        "warning": UNLISTED_DC_WARNING,
    }
