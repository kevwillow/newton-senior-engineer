"""The agent's explanation of a change (design Part 2).

``newton_plan_change`` and ``newton_plan_tier`` take an ``explanation`` object
written by the agent: ``intent`` (one line), ``steps`` (one short reason per
change line), ``expect`` (1-8 structured claims) and ``risk`` (one or two
lines).  Newton checks the shape and the text, masks secrets, and puts the
result inside the plan hash.  The explanation is the agent's CLAIM, shown to
the owner at approval under its own heading; nothing here makes it true.

An ``expect`` claim is never free-form and never a command.  It is one of:

* ``uci_equals``: ``{"kind": "uci_equals", "path": "cfg.section.option",
  "equals": "text"}``, which is the existing ``uci-equals`` probe;
* ``probe``: ``{"kind": "probe", "probe": [name, field, ...]}``, any existing
  probe from ``probes.PROBE_TABLE`` (checked with ``validate_probes``);
* ``config_has``: ``{"kind": "config_has", "line": "set ..."}``, a vendor
  statement the device's running configuration must hold;
* ``ping``: ``{"kind": "ping", "host": "192.0.2.1"}``, a host the device must
  answer.
* ``client_dns``, ``client_dhcp``, ``client_internet`` and ``client_blocked``
  name what a CLIENT sees, not what the router reports.  A client claim
  names a kind and a zone only; the addresses it is checked against are
  derived by Newton, never supplied by the agent.

Which kinds a claim may use depends on the platform the change is for: an
OpenWrt device carries the two router kinds (``uci_equals`` and ``probe``) and the four client kinds,
a VyOS device the two vendor kinds (``config_has`` and ``ping``), a Junos
device the same two (its display-set output is read statement by statement,
so a configuration line can be compared with it) and a RouterOS device the
ping only: the export of a CHR normalises its lines, so a configuration
line cannot be compared with it reliably.  A claim of the wrong kind for
the platform is refused, so a vendor claim can never reach an OpenWrt
router's probe list and an OpenWrt claim can never reach a vendor's.

The line of a ``config_has`` claim is read with the tokenizer of the
platform the claim is for, so what the owner approves, what the sealed
probe carries and what the device is checked against are the same text.

``claim_to_probe`` turns a ROUTER claim into the probe line the post-apply check will run
after apply.  Planning only validates and records the claims; it does not run
them.  A client claim has no router probe: it is checked from a registered
inside vantage (see ``client_checks``), and any FAIL or NOT-TESTED of a
claimed check stops the confirm.

Text rules (rule 1): printable characters only.  Control, format, separator
and other non-printing characters are REFUSED, not silently stripped, so what
the owner reads is exactly what was hashed.  The one exception is a single
newline inside ``risk`` (two lines).  Free text then goes through the
redactor, so a secret the agent pasted is stored and shown masked.

Error messages never echo the agent's text; they name the field and the rule.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Annotated, Any, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from . import redact as _redact
from .adapters import vendor_write
from .client_checks import CLIENT_KINDS, MAX_TARGETS, is_client_claim
from .probes import PROBE_NAMES, validate_probes
from .scans import ZONE_RE

MAX_INTENT = 160
MAX_STEP = 160
MAX_RISK = 300
MAX_STEPS = 64
MIN_CLAIMS = 1
MAX_CLAIMS = 8
# masking can lengthen a field by a placeholder; the stored text may use this much
MASKED_SLACK = 2

# the vendor claims.  A vendor statement is bounded by the vendor's own
# lint (400 characters); Newton's own bound is tighter, so a claim line stays
# a line the owner can read on one screen.
MAX_VENDOR_LINE = 300
# How much of a claim's own text a failure message may carry.
MAX_FAILED_TEXT = 80
# The one vendor platform with a claim grammar today.
VENDOR_PLATFORM = "vyos"
# The CHR platform.  Its export normalises the lines it writes, so a
# configuration line cannot be compared with it reliably: the ping is the
# only claim kind a CHR carries.
ROUTEROS_PLATFORM = "routeros"
# The Junos platform.  Its display-set output is read statement by
# statement, so a configuration line can be compared with it: the Junos
# carries the two vendor claims.
JUNOS_PLATFORM = "junos"

# The platforms whose claims are read with a tokenizer of their own.  A
# claim line of one of them is read with that tokenizer, so what the
# owner approves, what the sealed probe carries and what the device is
# checked against are the same text.
VENDOR_CLAIM_PLATFORMS = (VENDOR_PLATFORM, JUNOS_PLATFORM)

CLAIM_KINDS = ("uci_equals", "probe", "config_has", "ping", *CLIENT_KINDS)
# The claim kinds each platform may carry.  OpenWrt keeps the router's own
# probes; vyos carries the vendor claims, because it is the one platform
# with a tokenizer today.  A platform with no tokenizer of its own
# carries no claim kinds at all: a claim it cannot check with its own
# grammar is a claim it cannot keep.
OPENWRT_CLAIM_KINDS = ("uci_equals", "probe", *CLIENT_KINDS)
VENDOR_CLAIM_KINDS = ("config_has", "ping")
ROUTEROS_CLAIM_KINDS = ("ping",)
JUNOS_CLAIM_KINDS = ("config_has", "ping")
CLAIM_KINDS_BY_PLATFORM = {
    "openwrt": OPENWRT_CLAIM_KINDS,
    "vyos": VENDOR_CLAIM_KINDS,
    "routeros": ROUTEROS_CLAIM_KINDS,
    "junos": JUNOS_CLAIM_KINDS,
}

# The refusal of a claim kind a platform cannot carry, when the platform
# says which kind to use instead.
CLAIM_REFUSAL_BY_PLATFORM: dict[str, dict[str, str]] = {
    ROUTEROS_PLATFORM: {
        "config_has": "config_has is not supported on RouterOS; use ping",
    },
}


class ExplanationError(ValueError):
    """The explanation was refused.  The message is safe to show the agent."""


DROPPED_PLACEHOLDER_PREFIX = "# dropped placeholder:"


def change_lines(uci_batch: str) -> int:
    """How many change lines a batch has: non-blank lines that are not comments.

    This is the unit "one step per change line" counts, and the same rule
    ``policy.classify`` uses to decide whether a batch writes anything.

    Always count the RESOLVED batch (the stored ``uci_batch``): plan, apply and
    newton-approve all use this one function on that one representation.  A
    ``set path=<redacted:fp>`` line the planner dropped is kept as a
    ``# dropped placeholder:`` comment and still counts, because the agent
    wrote a line for it and gives it a step.
    """
    return sum(
        1
        for line in uci_batch.splitlines()
        if line.strip()
        and (not line.strip().startswith("#") or line.strip().startswith(DROPPED_PLACEHOLDER_PREFIX))
    )


# Printable but blank-looking characters.  ``str.isprintable``
# already refuses the categories Cc, Cf, Cs, Co, Cn, Zl, Zp and every Zs but
# U+0020; these are letters or symbols that still render as nothing.
#
# the same set has to be consulted at approve-time, where the agent's
# text is rendered on the operator's terminal via approve._sanitize_terminal_value.
# It is the SAME set on both sides (one definition, two callers); when one side
# gains a codepoint the other side gets it for free.
BLANK_LOOKING = frozenset(
    "\u115f\u1160\u3164\uffa0\u2800"
    "\u17b4\u17b5\u034f\ufffc"  # Khmer inherent vowels, combining grapheme joiner, object replacement
    "\u180b\u180c\u180d\u180f"  # Mongolian free variation selectors
    "\U0001d159\U00016fe4\U00013441\U00013442"  # null notehead, Khitan filler, Egyptian blank glyphs
) | frozenset(map(chr, range(0xFE00, 0xFE10))) | frozenset(map(chr, range(0xE0100, 0xE01F0)))


def _printable_or_raise(value: str, *, allow_newline: bool = False) -> None:
    for char in value:
        if char == "\n" and allow_newline:
            continue
        if not char.isprintable() or char in BLANK_LOOKING:
            raise ValueError("must be printable text (no control or non-printing characters)")


def _clean_text(value: Any, *, maximum: int, allow_newline: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError("must be a string")
    text = value.strip()
    if not text:
        raise ValueError("must not be empty")
    if len(text) > maximum:
        raise ValueError(f"must be at most {maximum} characters")
    _printable_or_raise(text, allow_newline=allow_newline)
    if allow_newline and "\n" in text:
        lines = text.split("\n")
        if len(lines) > 2 or not all(line.strip() for line in lines):
            raise ValueError("must be one or two non-empty lines")
    masked = _redact.redact_text(text)
    if len(masked) > maximum * MASKED_SLACK:
        raise ValueError(f"must be at most {maximum} characters")
    return masked


_UCI_CLAIM_PATH_RE = re.compile(r"^[a-z0-9_-]{1,32}\.[A-Za-z0-9_@\[\]-]{1,64}\.[A-Za-z0-9_]{1,64}$")


def _looks_secret(*fields: str) -> bool:
    """True when the redactor would rewrite these claim fields."""
    probe = " ".join(fields)
    return _redact.redact_text(probe) != probe or _redact.redact_text("\n".join(fields)) != "\n".join(fields)


class UciEqualsClaim(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    kind: Literal["uci_equals"]
    path: str
    equals: str

    def to_probe(self) -> list[str]:
        return ["uci-equals", self.path, self.equals]

    @field_validator("path", "equals")
    @classmethod
    def _text(cls, value: str) -> str:
        _printable_or_raise(value)
        return value

    @field_validator("path")
    @classmethod
    def _path(cls, value: str) -> str:
        if not _UCI_CLAIM_PATH_RE.fullmatch(value):
            raise ValueError("must be a uci path config.section.option")
        return value

    @model_validator(mode="after")
    def _probe(self) -> "UciEqualsClaim":
        _check_probe_line(self.to_probe())
        return self


class ProbeClaim(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    kind: Literal["probe"]
    probe: list[str]

    def to_probe(self) -> list[str]:
        return list(self.probe)

    @model_validator(mode="after")
    def _probe(self) -> "ProbeClaim":
        if not self.probe:
            raise ValueError("must name a probe")
        if self.probe[0] == "fail":
            raise ValueError("the 'fail' probe can never be true")
        if self.probe[0] not in PROBE_NAMES:
            raise ValueError("must be one of the existing probes")
        _check_probe_line(self.probe)
        return self


# ---- the client claims -------------------------------------------------------
#
# A client claim says what a CLIENT sees, not what the router reports.  It
# carries no free text and no address: a kind and the zone the client is in.
# The addresses a blocked claim is checked against are derived by Newton
# (client_checks.fill_targets), and the agent may not supply them.

_TARGET_RE = re.compile(r"^([0-9]{1,3}(?:\.[0-9]{1,3}){3}):([1-9][0-9]{0,4})$")


def _zone_ok(value: str) -> str:
    if not ZONE_RE.fullmatch(value):
        raise ValueError("must be a zone name of [a-z][a-z0-9-]{0,31}")
    return value


def _target_ok(value: str) -> str:
    """One target: an IPv4 address and a port."""
    match = _TARGET_RE.fullmatch(value)
    if match is None:
        raise ValueError("must be an address and a port (a.b.c.d:port)")
    address, port = match.groups()
    try:
        ipaddress.IPv4Address(address)
    except ValueError:
        raise ValueError("must be an address and a port (a.b.c.d:port)") from None
    if int(port) > 65535:
        raise ValueError("must be an address and a port (a.b.c.d:port)")
    return value


class ClientDnsClaim(BaseModel):
    """A client in the zone resolves a name through the zone's router."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    kind: Literal["client_dns"]
    zone: str

    @field_validator("zone")
    @classmethod
    def _zone(cls, value: str) -> str:
        return _zone_ok(value)


class ClientDhcpClaim(BaseModel):
    """A client in the zone gets a DHCP offer from the zone's router."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    kind: Literal["client_dhcp"]
    zone: str

    @field_validator("zone")
    @classmethod
    def _zone(cls, value: str) -> str:
        return _zone_ok(value)


class ClientInternetClaim(BaseModel):
    """A client in the zone reaches the internet and resolves a name."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    kind: Literal["client_internet"]
    zone: str

    @field_validator("zone")
    @classmethod
    def _zone(cls, value: str) -> str:
        return _zone_ok(value)


class ClientBlockedClaim(BaseModel):
    """A client in the zone cannot reach a set of addresses.

    ``to`` is what the claim is about: the router's own addresses or the
    internet.  ``targets`` is filled by Newton at plan time and carried by the
    stored explanation; the agent may not supply it.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    kind: Literal["client_blocked"]
    zone: str
    to: Literal["router", "internet"]
    targets: Annotated[list[str], Field(min_length=1, max_length=MAX_TARGETS)] | None = None

    @field_validator("zone")
    @classmethod
    def _zone(cls, value: str) -> str:
        return _zone_ok(value)

    @field_validator("targets")
    @classmethod
    def _targets(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        return [_target_ok(item) for item in value]


def _check_probe_line(line: list[str]) -> None:
    """The real probe table decides; its refusal text carries only a reason code."""
    from .server import NewtonError

    try:
        validate_probes([line])
    except NewtonError as exc:
        reason = str(exc).split(": ", 1)[-1]
        raise ValueError(f"is not a valid probe ({reason})") from None
    if _looks_secret(*line[1:]):
        raise ValueError("looks like it carries a secret; name a non-secret value")


# ---- the vendor claims -------------------------------------------------------


def _claim_platform(platform: str) -> str:
    """The platform whose grammar reads a claim line.

    Only the platforms with a claim grammar of their own have one.  A
    platform without one carries no vendor claim, so the default grammar
    is never used for a claim that matters.
    """
    return platform if platform in VENDOR_CLAIM_PLATFORMS else VENDOR_PLATFORM


def _vendor_statement(text: str, platform: str = VENDOR_PLATFORM) -> list[str] | None:
    """The one vendor statement in ``text``, or None when there is not exactly one.

    The vendor's own tokenizer decides: the text is split into statements and
    anything the vendor refuses (a metacharacter, a control character, a
    non-ascii character, a reserved verb, a refused path) is not a statement.
    The lint's own message quotes the agent's text, so it is dropped here and
    the caller names a rule instead.

    The platform is the one the claim is for: a Junos line is read with the
    Junos tokenizer and a VyOS line with the VyOS one.
    """
    try:
        statements = vendor_write.parse_lines(_claim_platform(platform), text)
    except vendor_write.LintError:
        return None
    if len(statements) != 1:
        return None
    return list(statements[0])


def _render_vendor_line(text: str, platform: str = VENDOR_PLATFORM) -> str:
    """The canonical text of a claim's vendor line.

    The line is parsed and re-rendered from its tokens, never copied: what
    the probe carries is what the vendor tokenizer accepts again.
    """
    statement = _vendor_statement(text, platform)
    if statement is None:
        raise ValueError("not a vendor statement")
    return vendor_write.render_line(_claim_platform(platform), statement)


def canonical_claim_line(line: str, platform: str = VENDOR_PLATFORM) -> str:
    """The canonical text of a vendor claim line: what is sealed and checked.

    The line is read with the vendor's own tokenizer and re-rendered from
    its tokens, never copied.  What the owner approves, what the sealed
    probe carries and what the device's configuration is checked against
    are then the same text.  Only the platforms with a claim grammar of
    their own read a claim line, so the tokenizer of the platform the
    claim is for is the one that reads the line.
    """
    return _render_vendor_line(line, platform)


class ConfigHasClaim(BaseModel):
    """The claim that the device's running configuration holds this line.

    The line is DATA: the vendor's own tokenizer reads it and the probe
    carries the re-rendered tokens, so a claim can never become script text.
    """

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    kind: Literal["config_has"]
    line: str

    def to_probe(self, platform: str = VENDOR_PLATFORM) -> list[str]:
        return ["config_has", _render_vendor_line(self.line, platform)]

    @field_validator("line")
    @classmethod
    def _line(cls, value: str) -> str:
        text = value.strip()
        if not text:
            raise ValueError("must not be empty")
        if len(text) > MAX_VENDOR_LINE:
            raise ValueError(f"must be at most {MAX_VENDOR_LINE} characters")
        if not text.isascii() or not text.isprintable():
            raise ValueError("must be printable ASCII text")
        if '"' in text:
            raise ValueError("must not contain a double quote")
        statement = _vendor_statement(text)
        if statement is None:
            raise ValueError("must be one vendor statement")
        if statement[0] != "set":
            raise ValueError("must be a vendor set statement")
        if _looks_secret(text):
            raise ValueError("looks like it carries a secret; name a non-secret value")
        return text


def _is_vacuous_ping_host(host: str) -> bool:
    """True for a host the device answers itself, whatever the change is.

    A ping to 127.0.0.0/8 or to the unspecified address 0.0.0.0 comes
    back from the device's own stack, so the claim cannot fail and says
    nothing about the change: it is refused.  The device's own address is
    not refused here, because parse_explanation does not know which device
    the change is for; only the loopback and the unspecified address are
    refused at parse time.
    """
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_loopback or address.is_unspecified


class PingClaim(BaseModel):
    """The claim that the device answers a ping to this host."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    kind: Literal["ping"]
    host: str

    def to_probe(self) -> list[str]:
        return ["ping", self.host]

    @field_validator("host")
    @classmethod
    def _host(cls, value: str) -> str:
        if not vendor_write.HOST_RE.fullmatch(value):
            raise ValueError("must be a host name or address")
        if _is_vacuous_ping_host(value):
            raise ValueError("must not be a loopback or unspecified address")
        return value


Claim = Annotated[
    Union[
        UciEqualsClaim,
        ProbeClaim,
        ConfigHasClaim,
        PingClaim,
        ClientDnsClaim,
        ClientDhcpClaim,
        ClientInternetClaim,
        ClientBlockedClaim,
    ],
    Field(discriminator="kind"),
]


class Explanation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    intent: str
    steps: Annotated[list[str], Field(min_length=1, max_length=MAX_STEPS)]
    expect: Annotated[list[Claim], Field(min_length=MIN_CLAIMS, max_length=MAX_CLAIMS)]
    risk: str

    @field_validator("intent")
    @classmethod
    def _intent(cls, value: str) -> str:
        return _clean_text(value, maximum=MAX_INTENT)

    @field_validator("risk")
    @classmethod
    def _risk(cls, value: str) -> str:
        return _clean_text(value, maximum=MAX_RISK, allow_newline=True)

    @field_validator("steps")
    @classmethod
    def _steps(cls, value: list[str]) -> list[str]:
        cleaned = []
        for index, step in enumerate(value):
            try:
                cleaned.append(_clean_text(step, maximum=MAX_STEP))
            except ValueError as exc:
                raise ValueError(f"step {index + 1} {exc}") from None
        return cleaned


def _safe_name(part: Any) -> str:
    text = str(part)
    return text if re.fullmatch(r"[A-Za-z0-9_]{1,32}", text) else "?"


def _describe(error: ValidationError) -> str:
    """Field and rule only.  Pydantic's ``input`` (the agent's text) is dropped."""
    seen: list[str] = []
    for item in error.errors(include_input=False, include_url=False, include_context=False):
        where = ".".join(_safe_name(p) for p in item["loc"])
        message = item["msg"]
        if message.startswith("Value error, "):
            message = message[len("Value error, "):]
        # a rule text can only be one of ours or pydantic's fixed wording
        line = f"explanation.{where}: {message}" if where else f"explanation: {message}"
        if line not in seen:
            seen.append(line)
        if len(seen) >= 4:
            break
    return "; ".join(seen)


def _allowed_claim_kinds(platform: str) -> tuple[str, ...]:
    """The claim kinds a platform may carry.

    The allow-list is explicit: a platform with a tokenizer of its own
    carries that platform's claim kinds, and a platform without one
    carries none.
    """
    return CLAIM_KINDS_BY_PLATFORM.get(platform, ())


def _safe_platform(platform: str) -> str:
    """A platform name safe to put in an error message."""
    return platform if re.fullmatch(r"[a-z0-9_-]{1,32}", platform) else "unknown"


def _platform_claim_refusal(raw: dict[str, Any], platform: str) -> ExplanationError | None:
    """Refuse a claim kind the platform does not carry, before anything else.

    The kind is checked first: a claim the platform cannot run is refused for
    that reason, whatever its own text says.
    """
    if not isinstance(platform, str) or not platform:
        return ExplanationError("platform must be a non-empty string")
    allowed = _allowed_claim_kinds(platform)
    expect = raw.get("expect")
    if not isinstance(expect, list):
        return None
    for index, claim in enumerate(expect):
        if not isinstance(claim, dict):
            continue
        kind = claim.get("kind")
        if isinstance(kind, str) and kind in CLAIM_KINDS and kind not in allowed:
            refusal = CLAIM_REFUSAL_BY_PLATFORM.get(platform, {}).get(kind)
            if refusal is not None:
                # the platform says what to use instead
                return ExplanationError(
                    f"explanation.expect[{index}]: {refusal}"
                )
            if allowed:
                message = (
                    f"a {kind} claim is not available on platform "
                    f"{_safe_platform(platform)}; use {' or '.join(allowed)}"
                )
            else:
                message = (
                    f"a {kind} claim is not available on platform "
                    f"{_safe_platform(platform)}: it has no claim grammar"
                )
            return ExplanationError(f"explanation.expect[{index}]: {message}")
    return None


def _platform_claim_lines(stored: dict[str, Any], platform: str) -> None:
    """A claim line must be a statement of the platform's own grammar.

    The line of a ``config_has`` claim is read with the tokenizer of the
    platform the change is for: a Junos line is a Junos statement and a
    line the vendor's own lint refuses cannot be a claim the vendor can
    check.  The check runs after the model, so the message names the
    claim and not the field.
    """
    if platform not in VENDOR_CLAIM_PLATFORMS:
        return
    expect = stored.get("expect")
    if not isinstance(expect, list):
        return
    for index, claim in enumerate(expect):
        if not isinstance(claim, dict) or claim.get("kind") != "config_has":
            continue
        line = claim.get("line")
        if not isinstance(line, str):
            continue
        if _vendor_statement(line, platform) is None:
            raise ExplanationError(
                f"explanation.expect[{index}]: the line is not a "
                f"{_safe_platform(platform)} statement"
            )


def parse_explanation(
    raw: Any, *, change_lines: int, platform: str = "openwrt", allow_targets: bool = False
) -> dict[str, Any]:
    """Validate ``raw`` and return the plain-JSON stored form.

    ``change_lines`` is how many change lines the batch has; ``steps`` must
    have exactly that many entries.  ``platform`` says which claim kinds the
    change may carry: ``openwrt`` (the default) takes ``uci_equals``,
    ``probe`` and the client kinds, any other platform takes its vendor
    kinds (``config_has`` and ``ping``).  Raises ``ExplanationError``.

    ``allow_targets`` is for the STORED form (apply and the receipt re-parse
    what the plan wrote): a stored ``client_blocked`` claim carries the
    targets Newton derived, and they must be there.  The agent's own form may
    not carry them at all -- Newton fills them at plan time, so a claim that
    names its own addresses is refused.
    """
    if not isinstance(raw, dict):
        raise ExplanationError(
            "explanation must be an object with intent, steps, expect and risk"
        )
    refusal = _platform_claim_refusal(raw, platform)
    if refusal is not None:
        raise refusal
    if not allow_targets:
        expect = raw.get("expect")
        for index, claim in enumerate(expect if isinstance(expect, list) else []):
            if (
                isinstance(claim, dict)
                and "targets" in claim
                and claim.get("kind") in CLIENT_KINDS
            ):
                raise ExplanationError(
                    f"explanation.expect.{index}: targets are derived by Newton"
                )
    try:
        model = Explanation.model_validate(raw)
    except ValidationError as exc:
        raise ExplanationError(_describe(exc)) from None
    if len(model.steps) != change_lines:
        raise ExplanationError(
            f"explanation.steps has {len(model.steps)} entries but the batch has "
            f"{change_lines} change lines; give exactly one short reason per change line"
        )
    stored = model.model_dump(mode="json", exclude_none=True)
    _platform_claim_lines(stored, platform)
    if allow_targets:
        for index, claim in enumerate(stored["expect"]):
            if not isinstance(claim, dict) or claim.get("kind") != "client_blocked":
                continue
            if not claim.get("targets"):
                raise ExplanationError(
                    f"explanation.expect.{index}: a stored client_blocked claim must "
                    "carry the targets Newton derived"
                )
    return stored


def claim_to_probe(claim: dict[str, Any],
                   platform: str = VENDOR_PLATFORM) -> list[str]:
    """The probe line for one stored ROUTER claim.

    A vendor claim line is read with the tokenizer of the platform the
    claim is for, so the probe carries the text the device is checked
    against.  A client claim has no router probe: it is checked from a
    client vantage, so asking for one is refused.
    """
    if is_client_claim(claim):
        raise ExplanationError(
            "a client claim is checked by a client vantage, not by a router probe"
        )
    kind = claim["kind"]
    if kind == "uci_equals":
        return ["uci-equals", claim["path"], claim["equals"]]
    if kind == "config_has":
        return ["config_has", _render_vendor_line(claim["line"], platform)]
    if kind == "ping":
        return ["ping", claim["host"]]
    return list(claim["probe"])


# ---- the claims join the sealed probe list -------------------------------------


def claim_probes(explanation: dict[str, Any],
                 platform: str = VENDOR_PLATFORM) -> list[list[str]]:
    """The probe lines for every ROUTER claim, in claim order.

    They are sealed AFTER Newton's own and the caller's probes (the router
    verifies one list, from a fresh session), so a claim only ever adds a line.
    Claim ``k`` (1-based) is always line ``len(probes) - len(router claims) + k``.
    Nothing is deduplicated: a claim equal to another probe still gets its own
    line, so a failure always names the right claim.

    A CLIENT claim is not in this list: it is not a router probe, and it is
    checked from a vantage.  The claim NUMBER of every claim is still
    its 1-based place in ``expect``, router claims and client claims share
    one numbering.
    """
    return [
        claim_to_probe(claim, platform)
        for claim in explanation["expect"]
        if not is_client_claim(claim)
    ]


def _short_text(text: str) -> str:
    """The first ``MAX_FAILED_TEXT`` characters of the agent's own text."""
    return str(text)[:MAX_FAILED_TEXT]


def _describe_client_claim(claim: dict[str, Any]) -> str:
    zone = claim.get("zone", "")
    kind = claim.get("kind")
    if kind == "client_dns":
        return f"client in zone {zone} resolves names through the zone router"
    if kind == "client_dhcp":
        return f"client in zone {zone} gets a DHCP offer from the zone router"
    if kind == "client_internet":
        return f"client in zone {zone} reaches the internet"
    targets = claim.get("targets")
    count = len(targets) if isinstance(targets, list) else 0
    where = "router addresses" if claim.get("to") == "router" else "the internet"
    return f"client in zone {zone} cannot reach {where} ({count} targets)"


def describe_claim(claim: dict[str, Any]) -> str:
    """One claim in plain words, as the agent claimed it."""
    kind = claim.get("kind")
    if kind == "uci_equals":
        return f"uci {claim['path']} == {claim['equals']}"
    if kind == "config_has":
        return f"config has {_short_text(claim['line'])}"
    if kind == "ping":
        return f"ping {claim['host']}"
    if kind in CLIENT_KINDS:
        return _describe_client_claim(claim)
    return "probe " + " ".join(claim["probe"])


def describe_failed_claim(claim: dict[str, Any], reason: str) -> str:
    """A claim that failed verify, in words that fit why (``reason`` is on the router grammar).

    The two vendor claims have one failure each, so their reason does not
    change the words: a ping that did not answer and a line that is not in
    the running configuration.
    """
    kind = claim["kind"]
    if kind == "ping":
        # the vendor driver knows one way for a ping to fail: no answer
        return f"ping {claim['host']}: no answer"
    if kind == "config_has":
        # the line is either in the running configuration or it is not
        return f"config line not present: {_short_text(claim['line'])}"
    uci = kind == "uci_equals"
    subject = f"uci {claim['path']}" if uci else "probe " + " ".join(claim["probe"])
    if reason == "timeout":
        return f"{describe_claim(claim)} could not be checked: timed out" if uci else f"{subject}: timed out"
    if reason == "error":
        return f"{describe_claim(claim)} could not be checked: error" if uci else f"{subject}: could not be checked, error"
    if reason == "budget":
        return f"{subject}: not checked, the verify time budget ran out"
    if uci and reason == "mismatch":
        return f"uci {claim['path']} != {claim['equals']}"
    if uci and reason == "unset":
        return f"uci {claim['path']} is unset (claimed {claim['equals']})"
    count = re.fullmatch(r"count=([0-9]+)", reason)
    if count:
        times = int(count[1])
        return f"{subject}: matched {times} {'time' if times == 1 else 'times'}, not as claimed"
    if reason in ("absent", "present"):
        return f"{subject}: found {reason}, not as claimed"
    return f"{subject}: did not hold"


def claims_match_probes(probes: Any, explanation: dict[str, Any],
                        platform: str = VENDOR_PLATFORM) -> bool:
    """True when the last ``len(expect)`` probes are exactly the claims' probes."""
    wanted = claim_probes(explanation, platform)
    if not isinstance(probes, list) or len(probes) < len(wanted):
        return False
    return probes[len(probes) - len(wanted):] == wanted if wanted else True


# Every reason the router's probe code can set in PB_REASON (newton-router): a fixed
# vocabulary, never free device text.  ``count=N`` is a match count (nft-rule, conf-has,
# the proc and log probes, listen), ``class=X`` the root-password class, ``bad-arg-N`` the
# Nth field refused by a re-check.  A reason outside this grammar names no claim.
_REASON = (
    r"(?:absent|arg-count|budget|error|fail|mismatch|no-process|not-near|order|planted|present"
    r"|syntax|timeout|too-long|unknown-probe|unset"
    r"|count=[0-9]{1,6}|class=(?:EMPTY|LOCKED|HASH|NOROOT|MULTIROOT)|bad-arg-[0-9]{1,2})"
)
_VERIFY_LINE = re.compile(
    r"^verify: probe (?P<n>[0-9]{1,2}) failed: (?P<name>[a-z0-9-]{1,32}) (?P<reason>" + _REASON + r")$"
)

# The line the vantage runner prints for every claim it checked:
# "vantage-check: claim N PASS|FAIL|NOT-TESTED <word>".  Nothing else counts:
# a line outside this shape is ignored, so a claim is named only by a line
# that says which claim it is about.
_LOCAL_CLAIM_LINE = re.compile(
    r"^vantage-check: claim (?P<n>[1-9][0-9]?) (?P<status>PASS|FAIL|NOT-TESTED) (?P<word>[a-z-]{1,24})$"
)


def _local_check_failure(
    lines: list[str], expect: list[dict[str, Any]]
) -> dict[str, Any] | None:
    """The first client claim the vantage runner reports as failed, if any."""
    for text in lines:
        match = _LOCAL_CLAIM_LINE.match(text)
        if match is None:
            continue
        status = match["status"]
        if status == "PASS":
            continue
        number = int(match["n"])
        if not 1 <= number <= len(expect):
            continue
        claim = expect[number - 1]
        if not is_client_claim(claim):
            continue
        word = match["word"]
        if status == "FAIL":
            return {
                "claim": number,
                "text": f"expect claim {number} failed: {describe_claim(claim)} ({word})",
            }
        return {
            "claim": number,
            "text": f"expect claim {number} could not be tested: {word}",
        }
    return None


def failed_claim(
    log: str, session_id: str, probes: list[list[str]], expect: list[dict[str, Any]]
) -> dict[str, Any] | None:
    """Which agent claim failed verify, read from the apply log; None if none did.

    The router's verify stops at its first failing probe: its last act is to print
    ``verify: probe N failed: <name> <reason>`` on stderr and exit.  The host script
    relays the last failed round's stderr after a ``VERIFY DETAIL session=<sid>
    round=R exit=N stage=router-verify`` header (owrt-change.sh labels the stage:
    ``router-verify``, ``local-check`` or ``logd``) as ``VERIFY STDERR session=<sid>:``
    lines.  Only the LAST stderr line of a router-verify block, for this session, in
    that exact shape, counts: earlier stderr text (ssh banners, anything a device
    prints first), the firewall-restart excerpt, local-check and logd failures
    (script-labelled other stages, whose text an operator command can shape), and
    stdout are all ignored.  The probe number must lie in the
    claims' tail of ``probes`` and the name must be that probe's name; the reason must
    fit the router's grammar.  Residual: the router is the source of that last line,
    so a compromised router can name a claim wrongly (it can equally fake a pass or a
    different failure); no safety decision rests on it.  Split on LF only.

    A CLIENT claim has no router probe, so it is named by the vantage
    runner instead: the ``stage=local-check`` block of the same log, where
    ``vantage-check: claim N FAIL|NOT-TESTED <word>`` says which claim failed
    and why.  The claim number is its place in ``expect``, the same numbering
    the router claims use.  A router claim is never named by that block, and a
    client claim is never named by the router's verify line.
    """
    sid = re.escape(session_id)
    header = re.compile(rf"^VERIFY DETAIL session={sid} round=[0-9]{{1,6}} exit=[0-9]{{1,3}} stage=router-verify \(last failed round;")
    local_header = re.compile(rf"^VERIFY DETAIL session={sid} round=[0-9]{{1,6}} exit=[0-9]{{1,3}} stage=local-check \(last failed round;")
    stderr = re.compile(rf"^VERIFY STDERR session={sid}: (?P<text>.*)$")
    block: list[str] | None = None
    last_block: list[str] = []
    local_block: list[str] | None = None
    last_local: list[str] = []
    for raw in str(log).split("\n"):
        line = raw.removesuffix("\r")
        if header.match(line):
            block = []
            last_block = block
            local_block = None
            continue
        if local_header.match(line):
            local_block = []
            last_local = local_block
            block = None
            continue
        if block is not None:
            hit = stderr.match(line)
            if hit:
                block.append(hit["text"])
            else:
                block = None  # the stderr half ends at the first other line
        elif local_block is not None:
            hit = stderr.match(line)
            if hit:
                local_block.append(hit["text"])
            else:
                local_block = None  # the stderr half ends at the first other line
    failed = _local_check_failure(last_local, expect)
    if failed is not None:
        return failed
    if not last_block:
        return None
    match = _VERIFY_LINE.match(last_block[-1])
    if not match:
        return None
    # The sealed tail of ``probes`` holds the ROUTER claims only, so the probe
    # number is mapped through the router claims' own places in ``expect``.
    router_claims = [
        index for index, claim in enumerate(expect) if not is_client_claim(claim)
    ]
    first_claim = len(probes) - len(router_claims)
    number = int(match["n"])
    if not first_claim < number <= len(probes) or probes[number - 1][0] != match["name"]:
        return None
    index = router_claims[number - first_claim - 1]
    text = describe_failed_claim(expect[index], match["reason"])
    return {"claim": index + 1, "text": f"expect claim {index + 1} failed: {text} ({match['reason']})"}


# ---- the mechanical disagreement flag (newton-approve) ---------------------------

_REF_RE = re.compile(
    r"(?<![A-Za-z0-9_.@\[\]-])([a-z0-9_-]{1,32})\.(@[A-Za-z0-9_-]{1,32}\[-?[0-9]{1,3}\]|[A-Za-z0-9_-]{1,64})"
    r"(?:\.([A-Za-z0-9_]{1,64}))?(?![A-Za-z0-9_@\[\]-])"
)
_ANON_RE = re.compile(r"^@([A-Za-z0-9_-]{1,32})\[-?[0-9]{1,3}\]$")


def _touched(diff: str, sections: list[str]) -> dict[tuple[str, str], set[str]]:
    """Newton's own list: (config, section) -> the names a step may use for it."""
    from .policy import parse_diff_line, parse_section_fact_line

    touched: dict[tuple[str, str], set[str]] = {}
    for line in diff.splitlines():
        change = parse_diff_line(line)
        if change is None or not change.parsed:
            continue
        touched.setdefault((change.config, change.section), {change.section})
    facts: dict[tuple[str, str], tuple[str | None, str | None]] = {}
    for line in sections:
        parsed = parse_section_fact_line(line)
        if parsed is not None:
            facts[parsed[0]] = parsed[1]
            touched.setdefault(parsed[0], {parsed[0][1]})
    for key, names in touched.items():
        section_type, section_name = facts.get(key, (None, None))
        if section_name:
            names.add(section_name)
        anon = _ANON_RE.match(key[1])
        if anon:
            names.add(f"@{anon.group(1)}[")
        elif section_type and not section_name and key[1].startswith("cfg"):
            names.add(section_type)
    return touched


@dataclass(frozen=True)
class MechanicalCheck:
    """What the mechanical check found.

    ``disagreements``: a step names a section Newton did not touch, or a
    named touched section is named by no step.  ``also_touches``: touched
    ANONYMOUS sections no step names (an honest step may describe them in
    words, so this is information, not a disagreement).  ``unparsed``: diff
    lines the check could not read; it says nothing about them.
    """

    disagreements: list[str]
    also_touches: list[str]
    unparsed: int


def mechanical_check(steps: list[str], diff: str, sections: list[str]) -> MechanicalCheck:
    """Compare the steps with Newton's own touched list.  Never proves anything."""
    from .policy import KNOWN_PACKAGES, parse_diff_line

    unparsed = 0
    for line in diff.splitlines():
        change = parse_diff_line(line)
        if change is not None and not change.parsed:
            unparsed += 1
    touched = _touched(diff, sections)
    configs = {config for config, _ in touched}
    known = set(KNOWN_PACKAGES) | configs
    out: list[str] = []
    mentioned: set[tuple[str, str]] = set()
    for number, step in enumerate(steps, start=1):
        for match in _REF_RE.finditer(step):
            config, section = match.group(1), match.group(2)
            if config not in known:
                continue
            anon = _ANON_RE.match(section)
            hits = [
                key for key, names in touched.items()
                if key[0] == config and (
                    section in names
                    # an index below zero cannot be resolved by a reader: match the type
                    or (anon is not None and section.endswith("[-1]") and (
                        _ANON_RE.match(key[1]) is not None
                        and _ANON_RE.match(key[1]).group(1) == anon.group(1)
                    ))
                )
            ]
            if hits:
                mentioned.update(hits)
            else:
                out.append(
                    f"step {number} names {config}.{section}, which is not in Newton's touched list"
                )
    text = "\n".join(steps)
    also: list[str] = []
    for key, names in sorted(touched.items()):
        if key in mentioned:
            continue
        found = False
        for name in names:
            if name.endswith("["):
                continue
            if re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])", text):
                found = True
                break
        if found:
            continue
        if _ANON_RE.match(key[1]) or key[1].startswith("cfg"):
            also.append(f"{key[0]}.{key[1]}")
        else:
            out.append(f"Newton touched {key[0]}.{key[1]}, but no step mentions it")
    return MechanicalCheck(out, also, unparsed)


def disagreements(steps: list[str], diff: str, sections: list[str]) -> list[str]:
    """Just the disagreement lines of ``mechanical_check``.

    An empty list means no obvious disagreement; it does not mean the
    explanation is right, and it says nothing about unparsed diff lines.
    """
    return mechanical_check(steps, diff, sections).disagreements
