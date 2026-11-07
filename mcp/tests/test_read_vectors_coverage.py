"""Coverage pin for the shared read vectors: the accepted commands in
device/openwrt/newton-router/tests/read_cases.json must exercise EVERY form
in server.READ_FORMS, every alternative of every enumerated word class in
server._ARG_CLASS_PATTERN / ARG_CLASSES (a plain alternation of literal
words, optionally behind a literal '-' prefix, or a flag-bundle char class),
and the whole ip object/option/selector vocabulary.  Deleting a vector that
is the only cover of a form or a word turns one of these tests red with a
message naming the uncovered form or word."""

import json
import re
import shlex
from pathlib import Path

import newton_mcp.server as server

CASES = json.loads(
    (Path(__file__).resolve().parents[2]
     / "device/openwrt/newton-router/tests/read_cases.json").read_text()
)

# The wifiscan verb lives in its own section of the shared file (the
# router's own test drives the program with those vectors).  The host
# knows the verb, so its vectors count as cover here too.
ACCEPTED_COMMANDS = list(CASES["accepted"]) + list(
    CASES.get("wifiscan", {}).get("accepted", [])
)
ACCEPTED_TOKENS = [shlex.split(command) for command in ACCEPTED_COMMANDS]
ALL_TOKENS = {token for tokens in ACCEPTED_TOKENS for token in tokens}


def test_every_read_form_is_matched_by_an_accepted_vector():
    missing = []
    for verb, forms in server.READ_FORMS.items():
        for form in forms:
            covered = any(
                tokens[0] == verb and server._form_matches(tokens[1:], form)
                for tokens in ACCEPTED_TOKENS
                if tokens
            )
            if not covered:
                missing.append(f"{verb} {' '.join(form)}")
    assert not missing, "no accepted vector matches the form(s): " + "; ".join(missing)


def _plain_alternation(pattern: str):
    """['-I', '-u', '-a'] for '-(?:I|u|a)', ['inet', 'ip', ...] for
    '(?:inet|ip|...)'; None when the pattern is not a plain alternation."""
    match = re.fullmatch(r"(-?)\(\?:([A-Za-z0-9_]+(?:\|[A-Za-z0-9_]+)+)\)", pattern)
    if match is None:
        return None
    prefix = match.group(1)
    return [prefix + word for word in match.group(2).split("|")]


def _flag_bundle(pattern: str):
    """'alnptuwxr' for '-[alnptuwxr]{1,8}'; None otherwise."""
    match = re.fullmatch(r"-\[([A-Za-z]+)\]\{1,\d+\}", pattern)
    return match.group(1) if match else None


def test_every_enumerated_alternative_is_a_token():
    missing = []
    for name, matcher in server.ARG_CLASSES.items():
        alternatives = _plain_alternation(matcher.pattern)
        if alternatives is None:
            continue
        for word in alternatives:
            if word not in ALL_TOKENS:
                missing.append(f"{name} alternative {word!r}")
    assert not missing, "no accepted vector contains the word(s): " + "; ".join(missing)


def test_every_flag_bundle_letter_is_used():
    missing = []
    for name, matcher in server.ARG_CLASSES.items():
        letters = _flag_bundle(matcher.pattern)
        if letters is None:
            continue
        bundle_tokens = [t for t in ALL_TOKENS if matcher.fullmatch(t)]
        for letter in letters:
            if not any(letter in token for token in bundle_tokens):
                missing.append(f"{name} letter {letter!r}")
    assert not missing, "no accepted vector uses the flag letter(s): " + "; ".join(missing)


def test_ip_vectors_cover_objects_options_and_selectors():
    ip_tokens = {token for tokens in ACCEPTED_TOKENS
                 if tokens and tokens[0] == "ip" for token in tokens}
    missing = []
    for word in sorted(server.IP_OBJECTS):
        if word not in ip_tokens:
            missing.append(f"ip object {word!r}")
    for option in sorted(server.IP_OPTIONS):
        if option not in ip_tokens:
            missing.append(f"ip option {option!r}")
    for selector in ("dev", "table"):
        if selector not in ip_tokens:
            missing.append(f"ip selector {selector!r}")
    assert not missing, "no accepted ip vector uses: " + "; ".join(missing)
