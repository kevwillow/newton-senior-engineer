"""Catalog-first, linear-time secret redaction for OpenWrt output (K7).

Secret-looking option names are recognized case-insensitively in UCI dotted,
UCI file, name/value, colon, and JSON forms.  The catalog includes common
password, PIN, token, UUID, credential, community, and key names; suffixes such
as ``_password``, ``_pass``, ``_pin``, and ``_community`` fail closed.  The
broader legacy contains rule remains for assignment forms, while colon labels
use only the exact catalog and suffixes so ordinary device text is untouched.

Pattern rules also cover private-key blocks, shadow hashes (including legacy
DES), URL userinfo passwords, and WireGuard-style base64 keys.  Replacements
are stable ``<redacted:8hex>`` HMAC fingerprints.  Existing placeholders are
left intact, and every pass is designed to be idempotent and linear in input
size.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets as _secrets
import stat
import tempfile
from pathlib import Path
from typing import Any

from . import receipts as _receipts


# ---- catalog ---------------------------------------------------------------
#
# The catalog lives in secret_names.txt next to this file (triage #4): ONE
# list shared with scripts/owrt-change.sh mask_secrets.  It is loaded once at
# import; a missing, unreadable, empty or malformed catalog raises at import
# (fail closed, loud) -- there is never a smaller built-in fallback.

SECRET_NAMES_FILE = "secret_names.txt"
_CATALOG_PATH = Path(__file__).with_name(SECRET_NAMES_FILE)
_CATALOG_LINE_RE = re.compile(r"^(exact|suffix|contains|allow) ([a-z0-9_]+)$")


def _load_secret_catalog(
    path: Path,
) -> tuple[frozenset[str], frozenset[str], frozenset[str], frozenset[str]]:
    """Parse the catalog file into (exact, suffix_words, contains_words, allow_names).

    Raises RuntimeError on any problem so both import-time loading and tests
    fail closed instead of silently masking less.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(f"secret-name catalog unreadable: {path}") from exc
    exact: set[str] = set()
    suffix: set[str] = set()
    contains: set[str] = set()
    allow: set[str] = set()
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _CATALOG_LINE_RE.match(line)
        if not m:
            raise RuntimeError(
                f"secret-name catalog {path}:{lineno}: not 'exact|suffix|contains <lowercase word>': {line!r}"
            )
        {
            "exact": exact,
            "suffix": suffix,
            "contains": contains,
            "allow": allow,
        }[m.group(1)].add(m.group(2))
    if not exact or not suffix or not contains:
        raise RuntimeError(f"secret-name catalog {path}: empty (needs exact, suffix and contains rules)")
    return frozenset(exact), frozenset(suffix), frozenset(contains), frozenset(allow)


_CATALOG_EXACT, _CATALOG_SUFFIX, _CATALOG_CONTAINS, _CATALOG_ALLOW = _load_secret_catalog(
    _CATALOG_PATH
)

KNOWN_SECRET_OPTIONS = _CATALOG_EXACT
_KNOWN_SECRET_OPTIONS_LOWER = frozenset(n.lower() for n in KNOWN_SECRET_OPTIONS)
_KNOWN_ALLOW_OPTIONS_LOWER = frozenset(n.lower() for n in _CATALOG_ALLOW)
_HEADER_ONLY_SECRET_NAMES = frozenset({"sid"})

SECRET_NAME_SUFFIX_RE = re.compile(
    "_(?:" + "|".join(sorted(re.escape(w) for w in _CATALOG_SUFFIX)) + ")$",
    re.IGNORECASE,
)
SECRET_NAME_CONTAINS_RE = re.compile(
    "(?:" + "|".join(sorted(re.escape(w) for w in _CATALOG_CONTAINS)) + ")",
    re.IGNORECASE,
)


def _normalized_secret_name(name: str) -> str:
    """Normalize free-text and JSON spellings to the UCI name vocabulary."""
    return name.lower().replace("-", "_")


def _is_header_only_secret_name(name: str) -> bool:
    """Recognize header-only names that must not affect assignment forms."""
    return _normalized_secret_name(name) in _HEADER_ONLY_SECRET_NAMES


def _is_catalog_secret_name(name: str) -> bool:
    """Strict secret-name predicate used where false positives are dangerous."""
    if not name:
        return False
    lower = _normalized_secret_name(name)
    if lower in _KNOWN_ALLOW_OPTIONS_LOWER:
        return False
    return lower in _KNOWN_SECRET_OPTIONS_LOWER or bool(SECRET_NAME_SUFFIX_RE.search(lower))


def _looks_like_secret_option(name: str) -> bool:
    if not name:
        return False
    if _normalized_secret_name(name) in _KNOWN_ALLOW_OPTIONS_LOWER:
        return False
    return _is_catalog_secret_name(name) or bool(
        SECRET_NAME_CONTAINS_RE.search(_normalized_secret_name(name))
    )


def _uci_unescape(value: str) -> str:
    return value.replace(r"'\''", "'")


# ---- placeholder shape and key --------------------------------------------

PLACEHOLDER_RE = re.compile(r"<redacted:([0-9a-f]{8})>")
_KEY_FILENAME = "redact.key"
_cached_key: bytes | None = None


def _placeholder(placeholder_fmt: str, fp: str) -> str:
    return placeholder_fmt.format(fp=fp)


def _state_dir_path() -> Path:
    from .server import state_dir
    return state_dir()


def _read_key(path: Path) -> bytes:
    try:
        st = path.stat()
    except OSError as exc:
        raise RuntimeError(f"redact key unreadable: {path}") from exc
    if stat.S_IMODE(st.st_mode) != 0o600:
        raise RuntimeError(f"redact key must be mode 0600: {path}")
    try:
        key = path.read_bytes()
    except OSError as exc:
        raise RuntimeError(f"redact key unreadable: {path}") from exc
    if len(key) != 32:
        raise RuntimeError(f"redact key must be exactly 32 bytes: {path}")
    return key


def _load_or_create_key(state_dir: Path) -> bytes:
    path = state_dir / _KEY_FILENAME
    # refuse before the mkdir below when the state dir is unsafe or the parent
    # it would be created in is group- or world-writable without the sticky bit
    refusal = _receipts.check_state_write_path(state_dir, state_dir)
    if refusal is not None:
        raise RuntimeError(refusal)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return _read_key(path)

    new_key = _secrets.token_bytes(32)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{_KEY_FILENAME}.", dir=path.parent)
    tmp_path = Path(tmp_name)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(new_key)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise RuntimeError(f"redact key write failed: {path}")
            view = view[written:]
        os.close(fd)
        fd = -1
        try:
            os.link(tmp_path, path)
        except FileExistsError:
            pass
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass
    # Always read the linked file: in a race this is the winner's key.
    return _read_key(path)


def get_key() -> bytes:
    global _cached_key
    if _cached_key is None:
        _cached_key = _load_or_create_key(_state_dir_path())
    return _cached_key


def reset_key_cache() -> None:
    global _cached_key
    _cached_key = None


def fingerprint(path: str, value: str, key: bytes | None = None) -> str:
    if key is None:
        key = get_key()
    msg = path.encode("utf-8") + b"\0" + value.encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()[:8]


# ---- form recognition ------------------------------------------------------

# Public regex names are retained because tests and callers inspect them.
# Line-start rules are LINEAR in the line length: the prefix is parsed with a
# bounded regex and the rest of the line is taken as the value by the callers
# (no lazy .*? plus a trailing \s*$ re-scan, which backtracked quadratically
# over long whitespace runs).  UCI_DOTTED_RE is kept as a compatibility alias
# for the prefix form, like the ANYWHERE aliases below.
UCI_DOTTED_PREFIX_RE = re.compile(
    r"^(?P<op>[-+]?)(?P<path>[A-Za-z][A-Za-z0-9_.@\[\]-]*[A-Za-z0-9_])"
    r"(?P<space1>[ \t]*)(?P<assign_op>[+\-^]?=)(?P<space2>[ \t]*)"
)
UCI_DOTTED_RE = UCI_DOTTED_PREFIX_RE
SECTION_HEADER_RE = re.compile(
    r"^\s*(?:config|cfg)\s+(?P<q1>['\"]?)(?P<type>[A-Za-z0-9_.-]+)(?P=q1)"
    r"(?:\s+(?P<q2>['\"]?)(?P<name>[^'\"\s]+)(?P=q2))?\s*$"
)
OPTION_LINE_RE = re.compile(
    r"^(?P<indent>\s*)(?P<directive>option)\s+(?P<option>[A-Za-z0-9_]+)\s+(?P<value>.*)$"
)
LIST_LINE_RE = re.compile(
    r"^(?P<indent>\s*)(?P<directive>list)\s+(?P<option>[A-Za-z0-9_]+)\s+(?P<value>.*)$"
)
KV_LINE_RE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<name>[A-Za-z](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?)"
    r"(?P<space1>[ \t]*)(?P<assign_op>[+\-^]?=)(?P<space2>[ \t]*)(?P<value>.*)$"
)
COLON_LINE_RE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<name>[A-Za-z][A-Za-z0-9_-]*)"
    r"(?P<separator>[ \t]*:[ \t]*)(?P<value>.*)$"
)

UCI_DOTTED_PREFIX_ANYWHERE_RE = re.compile(
    r"(?<![A-Za-z0-9_.@\[\]-])(?P<op>[-+]?)"
    r"(?P<path>[A-Za-z][A-Za-z0-9_.@\[\]-]*[A-Za-z0-9_])"
    r"[ \t]*(?P<assign_op>[+\-^]?=)[ \t]*"
)
KV_PREFIX_ANYWHERE_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?P<name>[A-Za-z](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?)"
    r"[ \t]*(?P<assign_op>[+\-^]?=)[ \t]*"
)
COLON_PREFIX_ANYWHERE_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?P<name>[A-Za-z][A-Za-z0-9_-]*)[ \t]*:[ \t]*"
)

# Compatibility aliases: these now deliberately match only the prefix.
UCI_DOTTED_ANYWHERE_RE = UCI_DOTTED_PREFIX_ANYWHERE_RE
KV_ANYWHERE_RE = KV_PREFIX_ANYWHERE_RE

SHADOW_HASH_RE = re.compile(
    r"(?<![A-Za-z0-9_/])\$(?P<id>sha512|sha256|sha1|apr1|md5|2a|2b|2x|2y|1|2|3|5|6|7|gy|y)\$[^\s:]*"
)
DES_SHADOW_RE = re.compile(
    r"(?m)^(?P<user>[^:\r\n]+):(?P<value>[./A-Za-z0-9]{13})(?=:[0-9]*:[0-9]*:)"
)
WG_B64_RE = re.compile(r"([A-Za-z0-9+/]{43}=)")
WG_LINE_KEYWORDS_RE = re.compile(
    r"\b(?:private_key|preshared_key|auth_secret|sae_password|wpa_psk|"
    r"wg[0-9a-z_-]*psk|wg[0-9a-z_-]*key|psk|key)\b", re.IGNORECASE
)
URL_USERINFO_RE = re.compile(
    r"(?<![A-Za-z0-9+.-])(?P<prefix>[A-Za-z][A-Za-z0-9+.-]*://[^/\s'\":@]+:)"
    r"(?P<password>[^@/\s'\"]+)(?=@)"
)
JSON_PREFIX_RE = re.compile(r'"(?P<name>[A-Za-z0-9_-]+)"\s*:\s*')


def _line_end(text: str, start: int) -> tuple[int, str]:
    pos = text.find("\n", start)
    if pos < 0:
        return len(text), ""
    body_end = pos - 1 if pos > start and text[pos - 1] == "\r" else pos
    return body_end, text[body_end:pos + 1]


def _find_quote_close(text: str, start: int, quote: str, limit: int) -> int | None:
    i = start
    if quote == "'":
        while i < limit:
            if text.startswith(r"'\''", i):
                i += 4
            elif text[i] == "'":
                return i
            else:
                i += 1
    else:
        while i < limit:
            if text[i] == "\\":
                i += 2
            elif text[i] == '"':
                return i
            else:
                i += 1
    return None


def _dotted_path_parts(path: str) -> tuple[str, str, str] | None:
    """Split a greedily captured dotted path without regex backtracking."""
    if "." not in path:
        return None
    package, tail = path.split(".", 1)
    if "." not in tail:
        return None
    section, option = tail.rsplit(".", 1)
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", package):
        return None
    if not re.fullmatch(r"@?[A-Za-z0-9_.\[\]-]+", section):
        return None
    if not re.fullmatch(r"[A-Za-z0-9_]+", option):
        return None
    return package, section, option


def _redact_dotted(text: str, key: bytes, placeholder_fmt: str) -> str:
    out: list[str] = []
    pos = 0
    while pos < len(text):
        end, ending = _line_end(text, pos)
        line = text[pos:end]
        if "=" not in line:
            out.append(line + ending)
            pos = end + len(ending)
            continue
        m = UCI_DOTTED_PREFIX_RE.match(line)
        parts = _dotted_path_parts(m.group("path")) if m else None
        if not m or not parts or not _looks_like_secret_option(parts[2]):
            out.append(line + ending)
            pos = end + len(ending)
            continue
        prefix = line[:m.end()]
        package, section, option = parts
        path = f"{package}.{section}.{option}"
        value_start = pos + m.end()
        if value_start < len(text) and text[value_start] in "'\"":
            quote = text[value_start]
            close = _find_quote_close(text, value_start + 1, quote, len(text))
            if close is None:
                raw = text[value_start + 1:]
                if PLACEHOLDER_RE.fullmatch(raw):
                    out.append(text[pos:])
                else:
                    fp = fingerprint(path, _uci_unescape(raw), key)
                    out.append(prefix + quote + _placeholder(placeholder_fmt, fp))
                break
            raw = text[value_start + 1:close]
            close_line_end, close_ending = _line_end(text, close)
            if PLACEHOLDER_RE.fullmatch(raw) and close + 1 == close_line_end:
                out.append(text[pos:close_line_end] + close_ending)
            else:
                fp = fingerprint(path, _uci_unescape(raw), key)
                out.append(prefix + quote + _placeholder(placeholder_fmt, fp) + quote + close_ending)
            pos = close_line_end + len(close_ending)
        else:
            raw = line[m.end():]
            if PLACEHOLDER_RE.fullmatch(raw):
                out.append(line + ending)
            else:
                fp = fingerprint(path, _uci_unescape(raw), key)
                out.append(prefix + _placeholder(placeholder_fmt, fp) + ending)
            pos = end + len(ending)
    return "".join(out)


def _redact_file_form(text: str, key: bytes, placeholder_fmt: str) -> str:
    out: list[str] = []
    pos = 0
    current_type: str | None = None
    current_name: str | None = None
    while pos < len(text):
        end, ending = _line_end(text, pos)
        line = text[pos:end]
        section = SECTION_HEADER_RE.match(line)
        if section:
            current_type = section.group("type")
            current_name = section.group("name") or current_type
            out.append(line + ending)
            pos = end + len(ending)
            continue
        match = OPTION_LINE_RE.match(line) or LIST_LINE_RE.match(line)
        if not match or not _looks_like_secret_option(match.group("option")):
            out.append(line + ending)
            pos = end + len(ending)
            continue
        option = match.group("option")
        value_start = pos + match.start("value")
        finish = end
        finish_ending = ending
        raw = text[value_start:end]
        if value_start < len(text) and text[value_start] in "'\"":
            quote = text[value_start]
            close = _find_quote_close(text, value_start + 1, quote, len(text))
            if close is None:
                raw = text[value_start + 1:]
                finish = len(text)
                finish_ending = ""
            else:
                raw = text[value_start + 1:close]
                finish, finish_ending = _line_end(text, close)
        else:
            quote = ""
        if PLACEHOLDER_RE.fullmatch(raw) and (
            not quote or (finish == end and text[value_start + len(raw) + 1:value_start + len(raw) + 2] == quote)
        ):
            out.append(text[pos:finish] + finish_ending)
        else:
            path = f"@{current_type or 'unknown'}.{current_name or 'unknown'}.{option}"
            fp = fingerprint(path, _uci_unescape(raw), key)
            out.append(
                f"{match.group('indent')}{match.group('directive')} {option} "
                f"'{_placeholder(placeholder_fmt, fp)}'{finish_ending}"
            )
        pos = finish + len(finish_ending)
    return "".join(out)


def _redact_kv_lines(text: str, key: bytes, placeholder_fmt: str) -> str:
    out: list[str] = []
    for physical in text.splitlines(keepends=True):
        ending = "\r\n" if physical.endswith("\r\n") else ("\n" if physical.endswith("\n") else "")
        line = physical[:-len(ending)] if ending else physical
        m = KV_LINE_RE.match(line)
        if not m or not _looks_like_secret_option(m.group("name")):
            out.append(physical)
            continue
        raw = m.group("value")
        if PLACEHOLDER_RE.fullmatch(raw):
            out.append(physical)
            continue
        fp = fingerprint(f"kv:{m.group('name')}", _uci_unescape(raw), key)
        prefix = line[:m.start("value")]
        out.append(prefix + _placeholder(placeholder_fmt, fp) + ending)
    return "".join(out)


def _redact_colon_lines(text: str, key: bytes, placeholder_fmt: str) -> str:
    out: list[str] = []
    for physical in text.splitlines(keepends=True):
        ending = "\r\n" if physical.endswith("\r\n") else ("\n" if physical.endswith("\n") else "")
        line = physical[:-len(ending)] if ending else physical
        m = COLON_LINE_RE.match(line)
        if not m or not (
            _is_catalog_secret_name(m.group("name"))
            or _is_header_only_secret_name(m.group("name"))
        ):
            out.append(physical)
            continue
        raw = m.group("value")
        if PLACEHOLDER_RE.fullmatch(raw):
            out.append(physical)
            continue
        fp = fingerprint(f"kv:{m.group('name')}", _uci_unescape(raw), key)
        out.append(line[:m.start("value")] + _placeholder(placeholder_fmt, fp) + ending)
    return "".join(out)


def _parse_midline_value(text: str, pos: int, line_end: int, *, query: bool = False) -> tuple[int, str, str, str]:
    """Return end, opening quote, fingerprint value, and output closing quote."""
    if pos >= line_end:
        return pos, "", "", ""
    if text.startswith('\\"', pos) or text.startswith("\\'", pos):
        token = text[pos:pos + 2]
        close = text.find(token, pos + 2, line_end)
        if close < 0:
            return line_end, token, text[pos + 2:line_end], ""
        return close + 2, token, text[pos + 2:close], token
    quote = text[pos] if text[pos] in "'\"" else ""
    if not quote:
        existing = PLACEHOLDER_RE.match(text, pos)
        if existing and existing.end() < line_end and text[existing.end()] in "&#":
            # A placeholder followed by another query component is already a
            # complete value.  Preserve it and let scanning resume at the
            # separator; placeholder-plus-arbitrary-text is still redacted.
            return existing.end(), "", existing.group(0), ""
        if not query:
            # A non-query assignment has no delimiter that can safely end a
            # secret. Consume the complete logical line, excluding whitespace
            # that belongs to the line ending, and let the caller emit that
            # trailing whitespace unchanged.
            end = line_end
            while end > pos and text[end - 1] in " \t\r":
                end -= 1
            return end, "", text[pos:end], ""
        end = pos
        while end < line_end and not text[end].isspace() and text[end] not in "'\"":
            if query and text[end] in "&#":
                break
            end += 1
        return end, "", text[pos:end], ""

    close = _find_quote_close(text, pos + 1, quote, line_end)
    if close is None:
        return line_end, quote, text[pos + 1:line_end], ""
    end = close + 1
    raw = text[pos + 1:close]
    if end < line_end and not text[end].isspace() and text[end] not in "'\",;&)]}>":
        cont_start = end
        while end < line_end and not text[end].isspace() and text[end] not in "'\"":
            end += 1
        raw += text[cont_start:end]
    return end, quote, raw, quote


def _scan_assignments(
    text: str,
    regex: re.Pattern[str],
    key: bytes,
    placeholder_fmt: str,
    *,
    dotted: bool,
) -> str:
    if "=" not in text:
        return text
    out: list[str] = []
    cursor = 0
    search_at = 0
    line_end = -1
    while True:
        m = regex.search(text, search_at)
        if not m:
            out.append(text[cursor:])
            break
        parts = _dotted_path_parts(m.group("path")) if dotted else None
        name = parts[2] if parts else (m.group("name") if not dotted else "")
        if not _looks_like_secret_option(name):
            # Emit only through the prefix; its value remains ordinary input and
            # can contain another assignment found by the next search.
            out.append(text[cursor:m.end()])
            cursor = m.end()
            search_at = m.end()
            continue
        if m.end() > line_end:
            line_end = text.find("\n", m.end())
            if line_end < 0:
                line_end = len(text)
        end, opening, raw, closing = _parse_midline_value(
            text, m.end(), line_end,
            query=(m.start() > 0 and text[m.start() - 1] in "?&"),
        )
        out.append(text[cursor:m.end()])
        if PLACEHOLDER_RE.fullmatch(raw):
            out.append(text[m.end():end])
        else:
            if dotted:
                assert parts is not None
                path = f"{parts[0]}.{parts[1]}.{name}"
            else:
                path = f"kv:{name}"
            fp = fingerprint(path, _uci_unescape(raw), key)
            out.append(opening + _placeholder(placeholder_fmt, fp) + closing)
        cursor = end
        search_at = end if end > m.end() else m.end()
    return "".join(out)


def _redact_dotted_anywhere(text: str, key: bytes, placeholder_fmt: str) -> str:
    return _scan_assignments(
        text, UCI_DOTTED_PREFIX_ANYWHERE_RE, key, placeholder_fmt, dotted=True
    )


def _redact_kv_anywhere(text: str, key: bytes, placeholder_fmt: str) -> str:
    return _scan_assignments(text, KV_PREFIX_ANYWHERE_RE, key, placeholder_fmt, dotted=False)


def _redact_colon_anywhere(text: str, key: bytes, placeholder_fmt: str) -> str:
    out: list[str] = []
    cursor = 0
    search_at = 0
    line_end = -1
    while True:
        m = COLON_PREFIX_ANYWHERE_RE.search(text, search_at)
        if not m:
            out.append(text[cursor:])
            break
        name = m.group("name")
        if not (_is_catalog_secret_name(name) or _is_header_only_secret_name(name)):
            out.append(text[cursor:m.end()])
            cursor = m.end()
            search_at = m.end()
            continue
        if m.end() > line_end:
            line_end = text.find("\n", m.end())
            if line_end < 0:
                line_end = len(text)
        end, opening, raw, closing = _parse_midline_value(text, m.end(), line_end)
        out.append(text[cursor:m.end()])
        if PLACEHOLDER_RE.fullmatch(raw):
            out.append(text[m.end():end])
        else:
            fp = fingerprint(f"kv:{name}", _uci_unescape(raw), key)
            out.append(opening + _placeholder(placeholder_fmt, fp) + closing)
        cursor = end
        search_at = end if end > m.end() else m.end()
    return "".join(out)


def _scan_json_string(text: str, pos: int) -> tuple[int, str, bool]:
    i = pos + 1
    while i < len(text):
        if text[i] == "\\":
            i += 2
        elif text[i] == '"':
            return i + 1, text[pos + 1:i], True
        else:
            i += 1
    return len(text), text[pos + 1:], False


_JSON_SCALAR_RE = re.compile(r"[^\s,}\]]+")


def _scan_json_container(text: str, pos: int) -> int:
    """text[pos] is '[' or '{'. Return the index just past its matching close, or len(text) when it is never closed (fail closed)."""
    depth = 0
    i = pos
    n = len(text)
    while i < n:
        c = text[i]
        if c == '"':
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                elif text[i] == '"':
                    break
                else:
                    i += 1
            i += 1
            continue
        if c == "[" or c == "{":
            depth += 1
        elif c == "]" or c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def _redact_json(text: str, key: bytes, placeholder_fmt: str) -> str:
    out: list[str] = []
    cursor = 0
    search_at = 0
    while True:
        m = JSON_PREFIX_RE.search(text, search_at)
        if not m:
            out.append(text[cursor:])
            break
        name = m.group("name")
        if not (_looks_like_secret_option(name) or _is_header_only_secret_name(name)):
            search_at = m.end()
            continue
        pos = m.end()
        end: int | None = None
        raw = ""
        if pos < len(text) and text[pos] == '"':
            end, raw, closed = _scan_json_string(text, pos)
            if PLACEHOLDER_RE.fullmatch(raw) and closed:
                search_at = end
                continue
        elif pos < len(text) and text[pos] in "[{":
            end = _scan_json_container(text, pos)
            raw = text[pos:end]
        else:
            # Secret members fail closed for any bare scalar token.  This
            # includes the promised numeric form and protects malformed or
            # partially emitted JSON before a parser can validate it.
            scalar = _JSON_SCALAR_RE.match(text, pos)
            if scalar:
                end = scalar.end()
                raw = scalar.group(0)
        if end is None:
            search_at = m.end()
            continue
        fp = fingerprint(f"json:{name}", raw, key)
        out.append(text[cursor:m.start()] + f'"{name}": "{_placeholder(placeholder_fmt, fp)}"')
        cursor = end
        search_at = end
    return "".join(out)


def _redact_url_userinfo(text: str, key: bytes, placeholder_fmt: str) -> str:
    def sub(m: re.Match[str]) -> str:
        password = m.group("password")
        if PLACEHOLDER_RE.fullmatch(password):
            return m.group(0)
        fp = fingerprint("url:userinfo", password, key)
        return m.group("prefix") + _placeholder(placeholder_fmt, fp)
    return URL_USERINFO_RE.sub(sub, text)


_PEM_BEGIN_RE = re.compile(
    r"-----BEGIN (?P<label>(?:[A-Z0-9 ]*PRIVATE KEY|PGP PRIVATE KEY BLOCK|OpenVPN Static key V1))-----"
)


def _redact_pem(text: str, key: bytes, placeholder_fmt: str) -> str:
    out: list[str] = []
    cursor = 0
    while True:
        m = _PEM_BEGIN_RE.search(text, cursor)
        if not m:
            out.append(text[cursor:])
            break
        out.append(text[cursor:m.start()])
        end_marker = f"-----END {m.group('label')}-----"
        end = text.find(end_marker, m.end())
        end = len(text) if end < 0 else end + len(end_marker)
        block = text[m.start():end]
        first_line = block.splitlines()[0]
        fp = fingerprint(f"pem:{first_line}", block, key)
        out.append(_placeholder(placeholder_fmt, fp))
        cursor = end
    return "".join(out)


def _redact_shadow_hash(text: str, key: bytes, placeholder_fmt: str) -> str:
    def hash_sub(m: re.Match[str]) -> str:
        return _placeholder(placeholder_fmt, fingerprint(f"shadow:{m.group('id')}", m.group(0), key))

    def des_sub(m: re.Match[str]) -> str:
        ph = _placeholder(placeholder_fmt, fingerprint("shadow:des", m.group("value"), key))
        return f"{m.group('user')}:{ph}"

    return DES_SHADOW_RE.sub(des_sub, SHADOW_HASH_RE.sub(hash_sub, text))


def _redact_wireguard(text: str, key: bytes, placeholder_fmt: str) -> str:
    def line_redact(line: str) -> str:
        if not WG_LINE_KEYWORDS_RE.search(line):
            return line
        def sub(m: re.Match[str]) -> str:
            value = m.group(1)
            return _placeholder(placeholder_fmt, fingerprint(f"wireguard:{line[:48]}", value, key))
        return WG_B64_RE.sub(sub, line)
    return "\n".join(line_redact(line) for line in text.split("\n"))


# ---- main entry points -----------------------------------------------------

def redact_text(text: str, key: bytes | None = None, *, placeholder_fmt: str = "<redacted:{fp}>") -> str:
    """Redact secrets in OpenWrt-style text without exposing intermediate data."""
    if key is None:
        key = get_key()
    text = _redact_pem(text, key, placeholder_fmt)
    text = _redact_dotted(text, key, placeholder_fmt)
    text = _redact_file_form(text, key, placeholder_fmt)
    text = _redact_kv_lines(text, key, placeholder_fmt)
    text = _redact_colon_lines(text, key, placeholder_fmt)
    text = _redact_json(text, key, placeholder_fmt)
    text = _redact_dotted_anywhere(text, key, placeholder_fmt)
    text = _redact_kv_anywhere(text, key, placeholder_fmt)
    text = _redact_colon_anywhere(text, key, placeholder_fmt)
    text = _redact_url_userinfo(text, key, placeholder_fmt)
    text = _redact_shadow_hash(text, key, placeholder_fmt)
    text = _redact_wireguard(text, key, placeholder_fmt)
    return text


def redact_value(value: Any, key: bytes | None = None, *, placeholder_fmt: str = "<redacted:{fp}>") -> Any:
    """Recursively redact every string in a JSON-like result structure."""
    if key is None:
        key = get_key()
    if isinstance(value, str):
        return redact_text(value, key, placeholder_fmt=placeholder_fmt)
    if isinstance(value, dict):
        return {k: redact_value(v, key, placeholder_fmt=placeholder_fmt) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(item, key, placeholder_fmt=placeholder_fmt) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_value(item, key, placeholder_fmt=placeholder_fmt) for item in value)
    return value
