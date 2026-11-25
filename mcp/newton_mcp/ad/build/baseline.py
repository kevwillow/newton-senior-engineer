"""The baseline of an AD build (DESIGN-1.5 "Baseline", PLAN-1.5 task 6).

``baseline-<version>.toml`` beside this module holds one table per
setting: its value (or its options), why, its source and its
compatibility risk.  A source is a ``learn.microsoft.com`` page or a CIS
Benchmark item cited by its number only: no text of a CIS document is
ever copied into the file.

``load_baseline(version)`` reads and checks one file and answers a
``Baseline``.  The helper on the server holds the same values compiled
into ``helper/build.ps1`` (DESIGN-1.5 "The property": the helper runs
only what it holds, with the parameters of the signed plan), and
``Baseline.helper_values`` is the table the helper must hold, so a test
keeps the two equal.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: The baseline versions Newton holds.
VERSIONS: tuple[str, ...] = ("2026.11",)

#: The directory of the baseline files.
_HERE = Path(__file__).resolve().parent

#: A setting's name.
_SETTING_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

#: A CIS Benchmark item, by its number only.
CIS_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){1,5}$")

#: A source page.
SOURCE_RE = re.compile(r"^https://learn\.microsoft\.com/en-us/[A-Za-z0-9/._-]+$")

#: The value of an option and of a setting.
_VALUE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")

#: A registry key of a GPO setting: HKLM, then key names.
_KEY_RE = re.compile(r"^HKLM(?:\\[A-Za-z0-9_]+)+$")

#: A registry value name of a GPO setting.
_NAME_RE = re.compile(r"^[A-Za-z0-9_]{1,64}$")

#: The longest a why or a risk may be: a sentence or two of Newton's
#: own, never a pasted paragraph.
TEXT_MAX = 200

#: Text that is the shape of a CIS recommendation title or profile: a
#: file holding it has copied CIS text.
COPIED_RE = re.compile(r"Ensure '|\(L[12]\)|is set to '|\(DC only\)|\(MS only\)")

#: The targets of stage 5 and the helper value each field names.
STAGE5_FIELDS: dict[str, tuple[str, ...]] = {
    "password-policy": (
        "PasswordMinLength",
        "PasswordHistory",
        "PasswordMaxAgeDays",
        "PasswordMinAgeDays",
        "PasswordComplexity",
        "PasswordReversible",
        "LockoutThreshold",
        "LockoutMinutes",
        "LockoutWindowMinutes",
    ),
    "admin-pso": ("PsoName", "PsoPrecedence", "PsoMinLength"),
    "protected-users": ("ProtectedUsers",),
    "builtin-administrator": ("AdministratorOption",),
}

#: The GPO links of stage 6.
GPO_LINKS: tuple[str, ...] = ("domain", "dc")

_COMMON = {"stage", "target", "why", "source", "cis", "risk"}
_STAGE5_KEYS = _COMMON | {"field", "value", "options"}
_STAGE6_KEYS = _COMMON | {"key", "name", "value", "security_template"}


class BaselineRefused(ValueError):
    """A baseline file or a request for one that is refused."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


@dataclass(frozen=True)
class Setting:
    """One setting of the baseline."""

    id: str
    stage: int
    target: str
    value: str
    options: tuple[str, ...]
    why: str
    source: str
    cis: str
    risk: str
    field: str = ""
    key: str = ""
    name: str = ""
    security_template: bool = True


@dataclass(frozen=True)
class Gpo:
    """One baseline GPO: its name and where it is linked."""

    id: str
    name: str
    link: str


@dataclass(frozen=True)
class Baseline:
    """A checked baseline file."""

    version: str
    settings: tuple[Setting, ...]
    gpos: tuple[Gpo, ...]

    def options(self) -> dict[str, tuple[str, ...]]:
        """The settings that have options, and the options of each."""
        return {s.id: s.options for s in self.settings if s.options}

    def gpo_settings(self, gpo: str) -> list[str]:
        """The settings of one GPO as the helper renders them:
        ``key|name|value``."""
        return [
            f"{s.key}|{s.name}|{s.value}"
            for s in self.settings
            if s.target == f"gpo:{gpo}"
        ]

    def security_gpo_settings(self) -> list[str]:
        """The settings of the security template as the helper renders
        them: ``key|name|value``.

        The export of the security policy (the area secedit exports) holds
        the values of the security template only.  A baseline value
        outside it (the Windows LAPS policy) is proved by the read of the
        registry, not by that export.
        """
        return [
            f"{s.key}|{s.name}|{s.value}"
            for s in self.settings
            if s.target.startswith("gpo:") and s.security_template
        ]

    def helper_values(self) -> dict[str, Any]:
        """The values the helper holds compiled in for this version."""
        values: dict[str, Any] = {"BaselineVersion": self.version}
        for setting in self.settings:
            if setting.stage == 5 and not setting.options:
                values[setting.field] = setting.value
        gpos = {g.id: g for g in self.gpos}
        values["DomainGpoName"] = gpos["domain"].name
        values["DomainGpoLink"] = gpos["domain"].link
        values["DomainGpoSettings"] = self.gpo_settings("domain")
        values["DcGpoName"] = gpos["dc"].name
        values["DcGpoLink"] = gpos["dc"].link
        values["DcGpoSettings"] = self.gpo_settings("dc")
        values["GpoNames"] = [gpos["domain"].name, gpos["dc"].name]
        values["GpoSettings"] = self.gpo_settings("domain") + self.gpo_settings("dc")
        values["SecurityGpoSettings"] = self.security_gpo_settings()
        return values


def _text(raw: Any, where: str) -> str:
    if not isinstance(raw, str) or raw == "":
        raise BaselineRefused("bad_entry", f"{where} is not a text")
    return raw


def _prose(raw: Any, where: str) -> str:
    text = _text(raw, where)
    if len(text) > TEXT_MAX or "\n" in text:
        raise BaselineRefused("bad_entry", f"{where} is longer than a sentence or two")
    if COPIED_RE.search(text) is not None:
        raise BaselineRefused("copied_text", f"{where} holds the shape of a CIS title")
    return text


def _setting(key: str, raw: Any) -> Setting:
    if _SETTING_RE.fullmatch(key) is None:
        raise BaselineRefused("bad_entry", "a setting name is outside its grammar")
    if not isinstance(raw, dict):
        raise BaselineRefused("bad_entry", f"setting {key} is not a table")
    stage = raw.get("stage")
    if stage not in (5, 6):
        raise BaselineRefused("bad_entry", f"setting {key} is not of stage 5 or 6")
    allowed = _STAGE5_KEYS if stage == 5 else _STAGE6_KEYS
    unknown = set(raw) - allowed
    if unknown:
        raise BaselineRefused("bad_entry", f"setting {key} holds an unknown field")

    source = raw.get("source", "")
    cis = raw.get("cis", "")
    if source and (not isinstance(source, str) or SOURCE_RE.fullmatch(source) is None):
        raise BaselineRefused("no_source", f"setting {key} has a source off learn.microsoft.com")
    if cis and (not isinstance(cis, str) or CIS_RE.fullmatch(cis) is None):
        raise BaselineRefused("no_source", f"setting {key} has a CIS item that is not a number")
    if not source and not cis:
        raise BaselineRefused("no_source", f"setting {key} has no source")

    target = _text(raw.get("target"), f"the target of {key}")
    why = _prose(raw.get("why"), f"the why of {key}")
    risk = _prose(raw.get("risk"), f"the risk of {key}")

    options: tuple[str, ...] = ()
    raw_options = raw.get("options")
    if raw_options is not None:
        if (
            not isinstance(raw_options, list)
            or len(raw_options) < 2
            or any(not isinstance(o, str) or _VALUE_RE.fullmatch(o) is None for o in raw_options)
            or len(set(raw_options)) != len(raw_options)
        ):
            raise BaselineRefused("bad_entry", f"the options of {key} are not options")
        options = tuple(raw_options)
        if "value" in raw:
            raise BaselineRefused("bad_entry", f"setting {key} has options and a value")
        value = ""
    else:
        value = _text(raw.get("value"), f"the value of {key}")
        if _VALUE_RE.fullmatch(value) is None:
            raise BaselineRefused("bad_entry", f"the value of {key} is outside its grammar")

    if stage == 5:
        fields = STAGE5_FIELDS.get(target)
        field = _text(raw.get("field"), f"the field of {key}")
        if fields is None or field not in fields:
            raise BaselineRefused("bad_entry", f"setting {key} has an unknown target or field")
        if (field == "AdministratorOption") != bool(options):
            raise BaselineRefused("bad_entry", f"setting {key}: only the built-in Administrator has options")
        return Setting(key, 5, target, value, options, why, source, cis, risk, field=field)

    if options:
        raise BaselineRefused("bad_entry", f"setting {key}: a GPO setting has no options")
    if target not in {f"gpo:{link}" for link in GPO_LINKS}:
        raise BaselineRefused("bad_entry", f"setting {key} has an unknown GPO")
    reg_key = _text(raw.get("key"), f"the key of {key}")
    name = _text(raw.get("name"), f"the name of {key}")
    if _KEY_RE.fullmatch(reg_key) is None or _NAME_RE.fullmatch(name) is None:
        raise BaselineRefused("bad_entry", f"the registry value of {key} is outside its grammar")
    if not value.isdigit() or int(value) > 0x7FFFFFFF:
        raise BaselineRefused("bad_entry", f"the value of {key} is not a DWORD the helper sets")
    # A value of the security template is in the export of the security
    # policy (the area secedit exports); a value outside it is proved by
    # the read of the registry alone.
    security_template = raw.get("security_template", True)
    if not isinstance(security_template, bool):
        raise BaselineRefused("bad_entry", f"the security template of {key} is not a yes or a no")
    return Setting(key, 6, target, value, (), why, source, cis, risk, key=reg_key, name=name,
                   security_template=security_template)


def parse_baseline(text: str, version: str) -> Baseline:
    """A baseline from the text of its file, checked."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise BaselineRefused("bad_entry", "the baseline file is not TOML") from error
    if set(data) != {"version", "gpos", "settings"}:
        raise BaselineRefused("bad_entry", "the baseline file holds an unknown table")
    if data["version"] != version:
        raise BaselineRefused("unknown_version", "the file is not of this version")

    gpos_raw = data["gpos"]
    if not isinstance(gpos_raw, dict) or set(gpos_raw) != set(GPO_LINKS):
        raise BaselineRefused("bad_entry", "the baseline GPOs are not the two of the design")
    gpos: list[Gpo] = []
    for gpo_id in GPO_LINKS:
        raw = gpos_raw[gpo_id]
        if not isinstance(raw, dict) or set(raw) != {"name", "link"} or raw["link"] != gpo_id:
            raise BaselineRefused("bad_entry", f"the GPO {gpo_id} is not a name and its link")
        name = _text(raw["name"], f"the name of GPO {gpo_id}")
        if _VALUE_RE.fullmatch(name) is None:
            raise BaselineRefused("bad_entry", f"the name of GPO {gpo_id} is outside its grammar")
        gpos.append(Gpo(gpo_id, name, gpo_id))

    settings_raw = data["settings"]
    if not isinstance(settings_raw, dict):
        raise BaselineRefused("bad_entry", "the settings are not a table")
    settings = tuple(_setting(key, raw) for key, raw in settings_raw.items())

    fields = [s.field for s in settings if s.stage == 5]
    every = [f for group in STAGE5_FIELDS.values() for f in group]
    if sorted(fields) != sorted(every):
        raise BaselineRefused("bad_entry", "the stage 5 settings are not each field once")
    for link in GPO_LINKS:
        names = [(s.key.lower(), s.name.lower()) for s in settings if s.target == f"gpo:{link}"]
        if not names or len(set(names)) != len(names):
            raise BaselineRefused("bad_entry", f"the GPO {link} has no settings or one twice")
    return Baseline(version, settings, tuple(gpos))


def load_baseline(version: str) -> Baseline:
    """The baseline of one version, read from its file and checked."""
    if version not in VERSIONS:
        raise BaselineRefused("unknown_version", "Newton holds no baseline of that version")
    path = _HERE / f"baseline-{version}.toml"
    return parse_baseline(path.read_text(encoding="utf-8"), version)
