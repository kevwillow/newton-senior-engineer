"""One recipe format: a reviewed TOML file that plans a common router job.

A recipe is ``<recipes dir>/<id>.toml``.  The recipes dir sits next to the
manifest (``Path(probes.manifest_path()).parent / "recipes"``), so the
``NEWTON_MANIFEST`` override moves it in the tests and an installed server
finds it under ``NEWTON_HOME/profiles/openwrt/recipes``.

The module is pure: it reads one file, checks it, and resolves it.  It does
not ssh, it does not touch device state, and it holds no lab name, host or
path of its own.

Every value a recipe takes is checked by its kind BEFORE anything else
happens, and a refusal names the PARAM, never the value: a passphrase is
never echoed back to the model.  A default is checked by the kind of its
param when the file loads, so it can never reach the batch unchecked.  The
substitution is one pass, so a value can never inject another placeholder.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import re
import tomllib
from pathlib import Path
from typing import Any, Callable

from . import probes


class RecipeError(ValueError):
    """A recipe file, or a value for one of its params, is refused.

    The message names the param (or the key of the file) and never the
    value: a rejected value is not echoed.
    """


# ---- the shapes ------------------------------------------------------------

#: The id of a recipe: the file stem and the ``id`` key are the same.
RECIPE_ID_RE = re.compile(r"[a-z][a-z0-9-]{0,31}")
#: The name of a param.
PARAM_NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,31}")
#: The name of an apk package.
PACKAGE_RE = re.compile(r"[a-z0-9][a-z0-9._+-]{0,63}")
#: A placeholder in a template: ``{name}``.
PLACEHOLDER_RE = re.compile(r"\{([a-z][a-z0-9_]{0,31})\}")

#: The keys of the header of a recipe file.
HEADER_KEYS = frozenset({
    "id", "title", "summary", "platform", "version", "risk",
    "packages", "requires_set", "owner_command", "suggest_rule",
    "params", "steps", "checks",
})
#: The keys the header needs.
HEADER_REQUIRED = ("id", "title", "summary", "platform", "version", "risk", "steps")
#: The keys of a param.
PARAM_KEYS = frozenset({"kind", "help", "default", "min", "max", "values"})
#: The keys of a step.
STEP_KEYS = frozenset({"kind", "when", "text"})
#: The keys of a check.
CHECK_KEYS = frozenset({"when", "probe"})

#: The only platform of 1.6.1.
PLATFORMS = ("openwrt",)
#: The only step kind of 1.6.1.
STEP_KINDS = ("uci",)

MAX_TITLE = 80
MAX_SUMMARY = 200
MAX_RISK = 200
MAX_HELP = 200
MAX_TEXT = 500
#: The cap of the text of one step: a step holds a whole job (a guest
#: network is about twenty UCI lines), and the plan path and the router's
#: own limits are the real ones.
MAX_STEP_TEXT = 16384


# ---- the kinds -------------------------------------------------------------


_MAC_RE = re.compile(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}")
_HOSTNAME_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,31}")
_IFACE_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}")
_INT_RE = re.compile(r"(?:0|[1-9][0-9]*)")
_CIDR4_RE = re.compile(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})/([0-9]{1,2})")


def _ipv4(value: str) -> str | None:
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        return None
    return value


def _cidr4(value: str) -> str | None:
    match = _CIDR4_RE.fullmatch(value)
    if match is None:
        return None
    if _ipv4(match.group(1)) is None:
        return None
    if not 8 <= int(match.group(2)) <= 30:
        return None
    return value


def _mac(value: str) -> str | None:
    if not _MAC_RE.fullmatch(value):
        return None
    return value.lower()


def _hostname(value: str) -> str | None:
    if not value or len(value) > 253:
        return None
    for label in value.split("."):
        if not _HOSTNAME_LABEL_RE.fullmatch(label):
            return None
    return value


def _name(value: str) -> str | None:
    if not _NAME_RE.fullmatch(value):
        return None
    return value


def _iface(value: str) -> str | None:
    if not _IFACE_RE.fullmatch(value):
        return None
    return value


def _printable(value: str, low: int, high: int) -> str | None:
    """Printable ASCII 0x20..0x7e, no quote and no backslash, of a size
    between ``low`` and ``high`` bytes."""
    if not low <= len(value) <= high:
        return None
    for character in value:
        if not 0x20 <= ord(character) <= 0x7E:
            return None
    if "'" in value or "\\" in value:
        return None
    return value


def _wg_pubkey(value: str) -> str | None:
    if len(value) != 44:
        return None
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) != 32:
        return None
    return value


#: The kind of a param, the value it takes, and the reason a refusal
#: gives (the reason never carries the value).
KINDS: dict[str, tuple[Callable[[str], str | None], str]] = {
    "ipv4": (_ipv4, "not a dotted IPv4 address"),
    "cidr4": (_cidr4, "not an IPv4 address with a prefix of 8 to 30"),
    "mac": (_mac, "not six hex pairs separated by colons"),
    "hostname": (_hostname, "not a hostname of lower-case labels"),
    "name": (_name, "not a UCI section name"),
    "iface": (_iface, "not an interface name"),
    "wifi_ssid": (
        lambda value: _printable(value, 1, 32),
        "not a Wi-Fi name of 1 to 32 printable characters",
    ),
    "wifi_key": (
        lambda value: _printable(value, 8, 63),
        "not a passphrase of 8 to 63 printable characters",
    ),
    "wg_pubkey": (_wg_pubkey, "not a 44-character base64 key of 32 bytes"),
}

#: The kinds whose value is checked against the param's own list.
CHOICE = "choice"
#: The kind whose value is checked against the param's own range.
INTEGER = "int"
#: Every kind of a param.
ALL_KINDS = frozenset(KINDS) | {CHOICE, INTEGER}


# ---- the file --------------------------------------------------------------


def recipes_dir() -> Path:
    """The directory the recipe files live in: next to the manifest."""
    return Path(probes.manifest_path()).parent / "recipes"


def _text(value: Any, limit: int, what: str, recipe_id: str) -> str:
    """One line of printable text (no line break of its own)."""
    if not isinstance(value, str):
        raise RecipeError(f"recipe {recipe_id}: the {what} must be text")
    if len(value) > limit:
        raise RecipeError(
            f"recipe {recipe_id}: the {what} is longer than {limit} characters"
        )
    if not value.isprintable():
        raise RecipeError(f"recipe {recipe_id}: the {what} is not printable")
    return value


def _block(value: Any, limit: int, what: str, recipe_id: str) -> str:
    """Text that may hold line breaks (a step template), but no other
    control character."""
    if not isinstance(value, str):
        raise RecipeError(f"recipe {recipe_id}: the {what} must be text")
    if len(value) > limit:
        raise RecipeError(
            f"recipe {recipe_id}: the {what} is longer than {limit} characters"
        )
    for character in value:
        if character in "\n\t":
            continue
        if not character.isprintable():
            raise RecipeError(f"recipe {recipe_id}: the {what} is not printable")
    return value


def _unknown_keys(
    keys: Any, allowed: frozenset[str], what: str, recipe_id: str
) -> None:
    unknown = sorted(set(keys) - allowed)
    if unknown:
        raise RecipeError(
            f"recipe {recipe_id}: unknown key(s) in {what}: {', '.join(unknown)}"
        )


def _placeholders(text: str) -> set[str]:
    return {match.group(1) for match in PLACEHOLDER_RE.finditer(text)}


def _check_param(
    recipe_id: str, name: str, spec: Any
) -> dict[str, Any]:
    if not PARAM_NAME_RE.fullmatch(name):
        raise RecipeError(
            f"recipe {recipe_id}: the param name {name!r} must match "
            "[a-z][a-z0-9_]{0,31}"
        )
    if not isinstance(spec, dict):
        raise RecipeError(f"recipe {recipe_id}: the param {name!r} must be a table")
    _unknown_keys(spec, PARAM_KEYS, f"the param {name!r}", recipe_id)
    kind = spec.get("kind")
    if not isinstance(kind, str) or kind not in ALL_KINDS:
        raise RecipeError(
            f"recipe {recipe_id}: the param {name!r} has the unknown kind "
            f"{kind!r}"
        )
    help_text = spec.get("help")
    if not isinstance(help_text, str) or not help_text:
        raise RecipeError(
            f"recipe {recipe_id}: the param {name!r} needs a help text"
        )
    _text(help_text, MAX_HELP, f"help of the param {name!r}", recipe_id)
    checked: dict[str, Any] = {"kind": kind, "help": help_text}
    if kind == INTEGER:
        minimum = spec.get("min")
        maximum = spec.get("max")
        if (
            isinstance(minimum, bool) or not isinstance(minimum, int)
            or isinstance(maximum, bool) or not isinstance(maximum, int)
        ):
            raise RecipeError(
                f"recipe {recipe_id}: the param {name!r} of kind int needs both "
                "min and max"
            )
        if minimum > maximum:
            raise RecipeError(
                f"recipe {recipe_id}: the param {name!r} of kind int has a min "
                "above its max"
            )
        checked["min"] = minimum
        checked["max"] = maximum
    elif "min" in spec or "max" in spec:
        raise RecipeError(
            f"recipe {recipe_id}: the param {name!r} of kind {kind} must not "
            "carry min or max"
        )
    if kind == CHOICE:
        values = spec.get("values")
        if (
            not isinstance(values, list) or not values
            or not all(isinstance(value, str) for value in values)
        ):
            raise RecipeError(
                f"recipe {recipe_id}: the param {name!r} of kind choice needs "
                "a list of values"
            )
        if len(set(values)) != len(values):
            raise RecipeError(
                f"recipe {recipe_id}: the param {name!r} of kind choice names "
                "the same value twice"
            )
        checked["values"] = list(values)
    elif "values" in spec:
        raise RecipeError(
            f"recipe {recipe_id}: the param {name!r} of kind {kind} must not "
            "carry values"
        )
    if "default" in spec:
        default = spec["default"]
        if not isinstance(default, str):
            raise RecipeError(
                f"recipe {recipe_id}: the default of the param {name!r} must be text"
            )
        if default != "":
            # A default is a value of its kind: it is checked by the
            # same check a given value passes, so it can never reach
            # the batch unchecked.  The empty default stays "not given".
            try:
                default = _check_value(name, checked, default)
            except RecipeError as exc:
                raise RecipeError(
                    f"recipe {recipe_id}: the default of the param {name} is not "
                    "a value of its kind"
                ) from exc
        checked["default"] = default
    return checked


def _check_step(recipe_id: str, step: Any, index: int) -> dict[str, Any]:
    if not isinstance(step, dict):
        raise RecipeError(f"recipe {recipe_id}: a step must be a table")
    _unknown_keys(step, STEP_KEYS, f"step {index}", recipe_id)
    kind = step.get("kind")
    if kind not in STEP_KINDS:
        raise RecipeError(
            f"recipe {recipe_id}: the step {index} has the unknown kind "
            f"{kind!r} (1.6.1 knows {', '.join(STEP_KINDS)})"
        )
    text = step.get("text")
    if not isinstance(text, str) or not text.strip():
        raise RecipeError(f"recipe {recipe_id}: the step {index} needs a text")
    _block(text, MAX_STEP_TEXT, f"text of step {index}", recipe_id)
    checked: dict[str, Any] = {"kind": kind, "text": text}
    if "when" in step:
        when = step["when"]
        if not isinstance(when, str) or not when:
            raise RecipeError(
                f"recipe {recipe_id}: the when of step {index} must name a param"
            )
        checked["when"] = when
    return checked


def _check_check(recipe_id: str, check: Any, index: int) -> dict[str, Any]:
    if not isinstance(check, dict):
        raise RecipeError(f"recipe {recipe_id}: a check must be a table")
    _unknown_keys(check, CHECK_KEYS, f"check {index}", recipe_id)
    probe = check.get("probe")
    if (
        not isinstance(probe, list) or not probe
        or not all(isinstance(field, str) for field in probe)
    ):
        raise RecipeError(
            f"recipe {recipe_id}: the check {index} needs a probe (a list of "
            "fields)"
        )
    checked: dict[str, Any] = {"probe": list(probe)}
    if "when" in check:
        when = check["when"]
        if not isinstance(when, str) or not when:
            raise RecipeError(
                f"recipe {recipe_id}: the when of check {index} must name a param"
            )
        checked["when"] = when
    return checked


def _check(recipe_id: str, data: Any) -> dict[str, Any]:
    """Check a parsed recipe file and return the recipe it describes."""
    if not isinstance(data, dict):
        raise RecipeError(f"recipe {recipe_id}: the file is not a table")
    _unknown_keys(data, HEADER_KEYS, "the header", recipe_id)
    for key in HEADER_REQUIRED:
        if key not in data:
            raise RecipeError(f"recipe {recipe_id}: the header needs {key}")

    file_id = data["id"]
    if not isinstance(file_id, str) or not RECIPE_ID_RE.fullmatch(file_id):
        raise RecipeError(
            f"recipe {recipe_id}: the id must match [a-z][a-z0-9-]{{0,31}}"
        )
    if file_id != recipe_id:
        raise RecipeError(
            f"recipe {recipe_id}: the id of the file is {file_id!r}, which is "
            "not the name of the file"
        )
    title = _text(data["title"], MAX_TITLE, "title", recipe_id)
    summary = _text(data["summary"], MAX_SUMMARY, "summary", recipe_id)
    risk = _text(data["risk"], MAX_RISK, "risk", recipe_id)
    platform = data["platform"]
    if platform not in PLATFORMS:
        raise RecipeError(
            f"recipe {recipe_id}: the platform {platform!r} is not known in "
            f"1.6.1 ({', '.join(PLATFORMS)})"
        )
    version = data["version"]
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise RecipeError(
            f"recipe {recipe_id}: the version must be an integer of 1 or more"
        )

    packages = data.get("packages", [])
    if not isinstance(packages, list) or not all(
        isinstance(package, str) for package in packages
    ):
        raise RecipeError(f"recipe {recipe_id}: the packages must be a list of names")
    for package in packages:
        if not PACKAGE_RE.fullmatch(package):
            raise RecipeError(
                f"recipe {recipe_id}: the package {package!r} is not an apk "
                "package name"
            )

    requires_set = data.get("requires_set", [])
    if not isinstance(requires_set, list) or not all(
        isinstance(path, str) and path for path in requires_set
    ):
        raise RecipeError(
            f"recipe {recipe_id}: the requires_set must be a list of UCI paths"
        )
    for path in requires_set:
        _text(path, MAX_TEXT, "a requires_set path", recipe_id)

    owner_command = _text(
        data.get("owner_command", ""), MAX_TEXT, "owner_command", recipe_id
    )
    suggest_rule = _text(
        data.get("suggest_rule", ""), MAX_TEXT, "suggest_rule", recipe_id
    )

    raw_params = data.get("params", {})
    if not isinstance(raw_params, dict):
        raise RecipeError(f"recipe {recipe_id}: the params must be a table")
    params: dict[str, dict[str, Any]] = {}
    for name, spec in raw_params.items():
        params[name] = _check_param(recipe_id, name, spec)

    raw_steps = data["steps"]
    if not isinstance(raw_steps, list) or not raw_steps:
        raise RecipeError(f"recipe {recipe_id}: the recipe needs a step")
    steps = [
        _check_step(recipe_id, step, index)
        for index, step in enumerate(raw_steps, start=1)
    ]

    raw_checks = data.get("checks", [])
    if not isinstance(raw_checks, list):
        raise RecipeError(f"recipe {recipe_id}: the checks must be a list")
    checks = [
        _check_check(recipe_id, check, index)
        for index, check in enumerate(raw_checks, start=1)
    ]

    # Every placeholder names a declared param, every when names a
    # declared param, and every declared param is used somewhere.
    used: set[str] = set()
    for step in steps:
        used |= _placeholders(step["text"])
        if "when" in step:
            used.add(step["when"])
    for check in checks:
        for field in check["probe"]:
            used |= _placeholders(field)
        if "when" in check:
            used.add(check["when"])
    for path in requires_set:
        used |= _placeholders(path)
    used |= _placeholders(owner_command)
    used |= _placeholders(suggest_rule)

    undeclared = sorted(used - set(params))
    if undeclared:
        raise RecipeError(
            f"recipe {recipe_id}: the placeholder(s) {', '.join(undeclared)} "
            "are not declared params"
        )
    unused = sorted(set(params) - used)
    if unused:
        raise RecipeError(
            f"recipe {recipe_id}: the param(s) {', '.join(unused)} are never used"
        )

    return {
        "id": file_id,
        "title": title,
        "summary": summary,
        "platform": platform,
        "version": version,
        "risk": risk,
        "packages": list(packages),
        "requires_set": list(requires_set),
        "owner_command": owner_command,
        "suggest_rule": suggest_rule,
        "params": params,
        "steps": steps,
        "checks": checks,
    }


def _parse(recipe_id: str, raw: bytes) -> dict[str, Any]:
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise RecipeError(f"recipe {recipe_id}: the file is not valid TOML ({exc})") from exc
    recipe = _check(recipe_id, data)
    recipe["sha256"] = hashlib.sha256(raw).hexdigest()
    return recipe


def load_recipe(recipe_id: str) -> dict[str, Any]:
    """Load and check one recipe file.

    The id is checked against the recipe id shape BEFORE any path is
    built, so a name that walks out of the recipes dir never reaches the
    disk.  The file is then read, parsed and checked; the recipe carries
    the ``sha256`` of its bytes, so a plan says which file it came from.
    """
    if not isinstance(recipe_id, str) or not RECIPE_ID_RE.fullmatch(recipe_id):
        raise RecipeError(
            "the recipe id must match [a-z][a-z0-9-]{0,31}: "
            f"{recipe_id!r}"
        )
    path = recipes_dir() / f"{recipe_id}.toml"
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise RecipeError(f"recipe {recipe_id}: the file cannot be read") from exc
    return _parse(recipe_id, raw)


def list_recipes(platform: str) -> list[dict[str, Any]]:
    """Every recipe of one platform, sorted by id.

    A file that does not load is listed as ``{"id": <stem>, "error":
    <message>}``: it is never skipped silently, so the owner sees that a
    recipe file is broken.
    """
    listed: list[dict[str, Any]] = []
    directory = recipes_dir()
    if not directory.is_dir():
        return listed
    for path in sorted(directory.glob("*.toml")):
        stem = path.stem
        try:
            recipe = load_recipe(stem)
        except RecipeError as exc:
            listed.append({"id": stem, "error": str(exc)})
            continue
        if recipe["platform"] != platform:
            continue
        listed.append(recipe)
    return listed


# ---- the values ------------------------------------------------------------


def _substitute(text: str, values: dict[str, str]) -> str:
    """Substitute every ``{name}`` in one pass.

    The replacement is a function, so the text a value carries is never
    scanned again: a value can never inject another placeholder.
    """
    return PLACEHOLDER_RE.sub(
        lambda match: values.get(match.group(1), match.group(0)), text
    )


def _check_value(name: str, spec: dict[str, Any], value: str) -> str:
    """Check one value by the kind of its param and return it (the MAC
    kind is normalised to lower case)."""
    kind = spec["kind"]
    if kind == INTEGER:
        if not _INT_RE.fullmatch(value):
            raise RecipeError(f"param {name}: the value is not a decimal number")
        number = int(value)
        if not spec["min"] <= number <= spec["max"]:
            raise RecipeError(
                f"param {name}: the value is not between the min and the max "
                "the recipe gives"
            )
        return value
    if kind == CHOICE:
        if value not in spec["values"]:
            raise RecipeError(
                f"param {name}: the value is not one of the values the recipe "
                "allows"
            )
        return value
    checked = KINDS[kind][0](value)
    if checked is None:
        raise RecipeError(f"param {name}: the value is {KINDS[kind][1]}")
    return checked


def resolve(recipe: dict[str, Any], values: dict[str, str] | None) -> dict[str, Any]:
    """Resolve a recipe against the values the caller named.

    Returns ``{"uci_batch", "probes", "requires_set", "owner_command",
    "suggest_rule"}``, all of them with the values substituted.  A value
    that its kind refuses is refused by the name of its param, and the
    value itself is never echoed.
    """
    params: dict[str, dict[str, Any]] = recipe["params"]
    given = values if values is not None else {}
    if not isinstance(given, dict):
        raise RecipeError("the values must be a dict or None")
    for name in given:
        if not isinstance(name, str):
            raise RecipeError("the value names must be text")
    extra = sorted(name for name in given if name not in params)
    if extra:
        raise RecipeError(
            f"value name(s) not in this recipe: {', '.join(extra)}"
        )
    missing = sorted(name for name in params if name not in given and "default" not in params[name])
    if missing:
        raise RecipeError(
            f"missing value for param(s): {', '.join(missing)}"
        )

    effective: dict[str, str] = {}
    for name, spec in params.items():
        if name not in given:
            effective[name] = spec["default"]
            continue
        value = given[name]
        if not isinstance(value, str):
            raise RecipeError(f"param {name}: the value must be text")
        if value == "" and "default" in spec:
            # an empty value takes the default of its param: an empty
            # default stays "not given" (the optional param is left out
            # and the steps that need it are dropped by their ``when``),
            # and a default that holds a value is used.
            effective[name] = spec["default"]
            continue
        effective[name] = _check_value(name, spec, value)

    def is_given(name: str) -> bool:
        """A param with an empty default is not given: a step that uses it
        needs a ``when`` to say it is optional."""
        return effective.get(name, "") != ""

    steps = [
        step for step in recipe["steps"]
        if "when" not in step or is_given(step["when"])
    ]
    checks = [
        check for check in recipe["checks"]
        if "when" not in check or is_given(check["when"])
    ]

    def needs_given(names: set[str], where: str) -> None:
        for name in sorted(names):
            if not is_given(name):
                raise RecipeError(
                    f"param {name} is not given and the recipe uses it in {where}"
                )

    parts: list[str] = []
    for step in steps:
        needs_given(_placeholders(step["text"]), "a step")
        body = _substitute(step["text"], effective).strip("\n")
        if body:
            parts.append(body)
    uci_batch = "\n".join(parts) + "\n" if parts else ""

    probe_list: list[list[str]] = []
    for check in checks:
        fields: list[str] = []
        for field in check["probe"]:
            needs_given(_placeholders(field), "a check")
            fields.append(_substitute(field, effective))
        probe_list.append(fields)
    # The probe grammar is the router's own: ``validate_probes`` raises
    # the server's NewtonError, which is imported here (not at the top of
    # the module) because the server imports this one.
    from .server import NewtonError

    try:
        probes.validate_probes(probe_list)
    except NewtonError as exc:  # the router's own refusal, as a recipe error
        raise RecipeError(
            f"recipe {recipe['id']}: a check does not pass the router's probe "
            f"grammar: {exc}"
        ) from exc

    requires_set: list[str] = []
    for path in recipe["requires_set"]:
        needs_given(_placeholders(path), "requires_set")
        requires_set.append(_substitute(path, effective))
    needs_given(_placeholders(recipe["owner_command"]), "owner_command")
    needs_given(_placeholders(recipe["suggest_rule"]), "suggest_rule")

    return {
        "uci_batch": uci_batch,
        "probes": probe_list,
        "requires_set": requires_set,
        "owner_command": _substitute(recipe["owner_command"], effective),
        "suggest_rule": _substitute(recipe["suggest_rule"], effective),
    }
