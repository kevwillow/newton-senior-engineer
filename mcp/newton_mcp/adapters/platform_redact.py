"""Platform-specific redaction run before the shared OpenWrt redactor."""

from __future__ import annotations

import re


_ROUTEROS_CONTINUATION_RE = re.compile(r"\\\r?\n[ \t]*")

# The secret-looking parameters of a RouterOS export.  The export writes
# them as ``name=value``, so the label is the name of the parameter.  A
# compound name is listed whole: the rule does not match the tail of a
# longer name, so "authentication-password" needs its own entry.
_ROUTEROS_SECRET_WORDS = (
    "authentication-password",
    "encryption-password",
    "wpa2-pre-shared-key",
    "wpa-pre-shared-key",
    "pre-shared-key",
    "preshared-key",
    "shared-secret",
    "shared-key",
    "authentication-key",
    "auth-key",
    "tcp-md5-key",
    "private-key",
    "scep-secret",
    "password",
    "passphrase",
    "secret",
    "community",
    "psk",
    "key",
)

# The label is a whole parameter name: a lookbehind keeps the rule from
# matching the tail of a longer name ("pre-shared-key" is not "key"), and
# the label carries its own "=" so "key-id=" is not "key=".
_ROUTEROS_SECRET_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?P<label>(?:"
    + "|".join(_ROUTEROS_SECRET_WORDS)
    + r")=)"
    r"(?P<value>\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s\r\n]*)",
    re.IGNORECASE,
)

_VYOS_SECRET_WORDS = (
    "encrypted-password",
    "plaintext-password",
    "authentication-key",
    "pre-shared-secret",
    "preshared-key",
    "shared-secret",
    "private-key",
    "passphrase",
    "community",
    "password",
    "md5-key",
    "secret",
    "key",
)

_VYOS_SECRET_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?P<label>(?:" + "|".join(_VYOS_SECRET_WORDS) + r")"
    r"[ \t]+)"
    r"(?P<value>"
    r"'[^'\r\n]*'"
    r"|\"[^\"\r\n]*\""
    r"|'[^'\r\n]*(?=$|\r|\n)"
    r"|\"[^\"\r\n]*(?=$|\r|\n)"
    r"|[^ \t\r\n'\"]+"
    r")",
    re.IGNORECASE,
)
_PLACEHOLDER_RE = re.compile(r"<redacted(?::[0-9a-f]{8})?>")


def _placeholder_inner(value: str) -> str:
    """Strip surrounding quotes so PLACEHOLDER matches against the inner value."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
        return value[1:-1]
    return value


def _redact_routeros(text: str) -> str:
    """Redact a RouterOS export: join the wraps, then hide the secrets.

    The export writes a secret as ``name=value`` (or ``name="value"``), so
    the rule matches the name of the parameter and replaces its value.
    A placeholder is terminal: a value that is already ``<redacted>`` (or
    ``<redacted:fp>``) is kept as it is, so the rule is idempotent.
    """
    joined = _ROUTEROS_CONTINUATION_RE.sub("", text)

    def replace(match: re.Match[str]) -> str:
        value = match.group("value")
        if _PLACEHOLDER_RE.fullmatch(_placeholder_inner(value)):
            return match.group(0)
        return match.group("label") + "<redacted>"

    return _ROUTEROS_SECRET_RE.sub(replace, joined)


def _redact_vyos(text: str) -> str:
    """Redact VyOS's space-separated secret values, preserving placeholders."""

    def replace(match: re.Match[str]) -> str:
        value = match.group("value")
        if _PLACEHOLDER_RE.fullmatch(value):
            return match.group(0)
        return match.group("label") + "<redacted>"

    return _VYOS_SECRET_RE.sub(replace, text)


_JUNOS_SECRET_DATA_LINE_RE = re.compile(
    r"(?m)^(?P<line>[^\n]*## SECRET-DATA)"
)
_JUNOS_QUOTED_RE = re.compile(r'"[^"\r\n]*"')
_JUNOS_D9_QUOTED_RE = re.compile(r'"\$9\$[^"\r\n]*"')
_JUNOS_D9_BARE_RE = re.compile(r"(?<![\w-])\$9\$[^\s\"';]+")
_JUNOS_D8_QUOTED_RE = re.compile(r'"\$8\$[^"\r\n]*"')
_JUNOS_D8_BARE_RE = re.compile(r"(?<![\w-])\$8\$[^\s\"';]+")
_JUNOS_D6_QUOTED_RE = re.compile(r'"\$6\$[^"\r\n]*"')
_JUNOS_D6_BARE_RE = re.compile(r"(?<![\w-])\$6\$[^\s\"';]+")
_JUNOS_COMMUNITY_RE = re.compile(
    r"(?<![A-Za-z0-9_-])community(?P<space>[ \t]+)(?P<value>"
    r'"[^"\r\n]*"'
    r"|'[^'\r\n]*'"
    r"|[^{}\s\"';]+"
    r")"
)

# The labels of a secret value in a display-set configuration: the name
# of the parameter and the value that follows it.  A compound name is
# listed whole, because the rule does not match the tail of a longer
# name: "privacy-secret" needs its own entry, and "psksecret" (which
# carries an encrypted value) is not a secret at all.
_JUNOS_SECRET_WORDS = (
    "encrypted-password",
    "plaintext-password",
    "plain-text-password",
    "authentication-key",
    "password",
    "privacy-secret",
    "pre-shared-key",
    "preshared-key",
    "secret",
    "simple-password",
)

# The labels whose value may be an index and not a secret.  Only these
# keep the exemption for a value that is only digits ("ntp
# authentication-key 1 sha1 ..."): under every other label a value that
# is only digits is a secret like any other.
_JUNOS_INDEX_LABELS = frozenset({"authentication-key"})


def _is_index_label(label: str) -> bool:
    """True when the label of a value may carry an index and not a secret."""
    return label.strip().lower() in _JUNOS_INDEX_LABELS

_JUNOS_SECRET_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?P<label>(?:"
    + "|".join(_JUNOS_SECRET_WORDS)
    + r")[ \t]+)"
    # The value is never an assignment: a display-set configuration does
    # not carry one, and swallowing the "=" of a "name = value" line
    # would leave the value behind it in the clear.  The shared redactor
    # owns that form.
    r"(?P<value>\"[^\"\r\n]*\"|'[^'\r\n]*'|(?!=[ \t])[^\s\r\n]+)",
    re.IGNORECASE,
)

# The body of an ssh key: the type of the key and the base64 that
# follows it.  The type alone is not a secret, so only the body is
# hidden.
_JUNOS_SSH_KEY_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?P<type>ssh-(?:ed25519|rsa|dss|ecdsa(?:-sha2-nistp\d+)?))"
    r"(?P<space>[ \t]+)(?P<value>[A-Za-z0-9+/=]+)"
)


def _redact_junos(text: str) -> str:
    """Redact the secrets of a Junos display-set configuration.

    The pass hides the hashes of the device (``$9$``, ``$8$`` and
    ``$6$``), the values of the parameters that carry a secret (the
    encrypted password, the password, the authentication key, the
    pre-shared key, the secret), the body of an ssh key, the ``##
    SECRET-DATA`` lines and the ``community`` names.  A placeholder is
    terminal, so the pass is idempotent.

    A value that is only digits is the index of a parameter ("ntp
    authentication-key 1 sha1 ...") and not a secret, but only under
    the label that may carry an index: under a secret label a value of
    digits is a secret like any other.
    """

    def secret_data_replace(match: re.Match[str]) -> str:
        def quote_replace(qm: re.Match[str]) -> str:
            inner = qm.group(0)[1:-1]
            if _PLACEHOLDER_RE.fullmatch(inner):
                return qm.group(0)
            return '"<redacted>"'
        return _JUNOS_QUOTED_RE.sub(quote_replace, match.group("line"))

    text = _JUNOS_SECRET_DATA_LINE_RE.sub(secret_data_replace, text)

    text = _JUNOS_D9_QUOTED_RE.sub("<redacted>", text)
    text = _JUNOS_D9_BARE_RE.sub("<redacted>", text)
    text = _JUNOS_D8_QUOTED_RE.sub("<redacted>", text)
    text = _JUNOS_D8_BARE_RE.sub("<redacted>", text)
    text = _JUNOS_D6_QUOTED_RE.sub("<redacted>", text)
    text = _JUNOS_D6_BARE_RE.sub("<redacted>", text)

    def label_replace(match: re.Match[str]) -> str:
        value = match.group("value")
        inner = _placeholder_inner(value)
        if _PLACEHOLDER_RE.fullmatch(inner):
            return match.group(0)
        if inner.isdigit() and _is_index_label(match.group("label")):
            # a value that is only digits is the index of a parameter
            # ("ntp authentication-key 1 sha1 ..."), not a secret
            return match.group(0)
        return match.group("label") + "<redacted>"

    text = _JUNOS_SECRET_RE.sub(label_replace, text)

    def key_replace(match: re.Match[str]) -> str:
        value = match.group("value")
        if _PLACEHOLDER_RE.fullmatch(value):
            return match.group(0)
        return match.group("type") + match.group("space") + "<redacted>"

    text = _JUNOS_SSH_KEY_RE.sub(key_replace, text)

    def community_replace(match: re.Match[str]) -> str:
        value = match.group("value")
        if _PLACEHOLDER_RE.fullmatch(_placeholder_inner(value)):
            return match.group(0)
        return "community" + match.group("space") + "<redacted>"

    text = _JUNOS_COMMUNITY_RE.sub(community_replace, text)
    return text


_EOS_SECRET_WORDS = (
    "pre-shared-key",
    "shared-key",
    "authentication-key",
    "key-string",
    "secret",
    "password",
    "md5",
    "key",
)

_EOS_SECRET_RE = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"(?P<keyword>" + "|".join(_EOS_SECRET_WORDS) + r")"
    r"[ \t]+"
    r"(?:(?P<algkw>" + "|".join(_EOS_SECRET_WORDS) + r")[ \t]+)?"
    r"(?:(?P<type>0|5|7|8a|sha512)[ \t]+)?"
    r"(?P<value>\S+)",
    re.IGNORECASE,
)

# MACsec CAK/CKN pairs: ``key <ckn> <0|7> <value>`` redacts both ckn and value.
# The negative lookahead excludes the algorithm keywords (``md5`` etc.) so
# ``key md5 7 X`` falls through to the generic rule and only redacts ``X``.
_EOS_MACSEC_RE = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"key[ \t]+"
    r"(?P<ckn>(?!" + "|".join(_EOS_SECRET_WORDS) + r")[^\s]+)"
    r"[ \t]+"
    r"(?P<type>0|7)"
    r"[ \t]+"
    r"(?P<value>\S+)",
    re.IGNORECASE,
)

_EOS_SNMP_RE = re.compile(
    r"(?<![A-Za-z0-9_-])snmp-server[ \t]+community[ \t]+(?P<value>\S+)",
    re.IGNORECASE,
)

# SNMPv3 user line scoping keeps ``auth`` / ``priv`` elsewhere untouched.
_EOS_SNMP_USER_LINE_RE = re.compile(r"(?mi)^[^\n]*snmp-server[ \t]+user[^\n]*")

# VRRP authentication text (with optional 0|7 type token). The value is the secret.
_EOS_VRRP_AUTH_TEXT_RE = re.compile(
    r"(?<![\w-])authentication[ \t]+text[ \t]+(?:(?:0|7)[ \t]+)?(?P<value>\S+)",
    re.IGNORECASE,
)

# SNMP trap/inform host lines (scoped by line, like the v3 user rule). Within
# those lines, redacts the community value after version 1|2c. version 3
# users are kept byte-identical (the v3 user is not a secret).
_EOS_SNMP_HOST_LINE_RE = re.compile(r"(?mi)^[^\n]*snmp-server[ \t]+host[^\n]*")
_EOS_SNMP_HOST_VERSION_RE = re.compile(
    r"(?<![A-Za-z0-9_-])version[ \t]+(?:1|2c)[ \t]+(?P<value>\S+)",
    re.IGNORECASE,
)
# Arista EOS defaults to SNMPv1, so ``snmp-server host`` lines with no
# ``version`` keyword still carry an SNMPv1 community (the trailing token
# before any optional ``udp-port``/VRF tokens).  Scoped to the host line,
# case insensitive, and the negative lookahead excludes ``version|vrf|
# traps|informs|udp-port`` so backtracking over the optional groups never
# redacts a keyword (e.g. ``traps version 2c X`` keeps ``version 2c X`` for
# the version rule and only that value lands as ``<redacted>``).
_EOS_SNMP_HOST_BARE_RE = re.compile(
    r"(?<![\w-])snmp-server[ \t]+host[ \t]+\S+"
    r"(?:[ \t]+vrf[ \t]+\S+)?"
    r"(?:[ \t]+(?:traps|informs))?[ \t]+"
    r"(?!(?:version|vrf|traps|informs|udp-port)(?![^ \t\r\n]))"
    r"(?P<value>\S+)",
    re.IGNORECASE,
)
_EOS_SNMP_AUTH_RE = re.compile(
    r"(?<![A-Za-z0-9_-])auth[ \t]+(?P<alg>\S+)"
    r"(?:[ \t]+(?P<type>0|5|7|8a))?[ \t]+(?P<value>\S+)",
    re.IGNORECASE,
)
_EOS_SNMP_PRIV_RE = re.compile(
    r"(?<![A-Za-z0-9_-])priv[ \t]+(?P<alg>\S+)"
    r"(?:[ \t]+(?P<type>0|5|7|8a))?[ \t]+(?P<value>\S+)",
    re.IGNORECASE,
)


def _redact_eos(text: str) -> str:
    """Redact EOS secret-bearing keywords, optional type tokens, MACsec pairs, and SNMP forms."""

    def macsec_replace(match: re.Match[str]) -> str:
        ckn = match.group("ckn")
        value = match.group("value")
        prefix_end = match.start("value")
        prefix = text[match.start():prefix_end]
        if _PLACEHOLDER_RE.fullmatch(value) and _PLACEHOLDER_RE.fullmatch(ckn):
            return match.group(0)
        return prefix + "<redacted>"

    text = _EOS_MACSEC_RE.sub(macsec_replace, text)

    def replace(match: re.Match[str]) -> str:
        value = match.group("value")
        if _PLACEHOLDER_RE.fullmatch(value):
            return match.group(0)
        prefix_end = match.start("value")
        prefix = text[match.start():prefix_end]
        return prefix + "<redacted>"

    text = _EOS_SECRET_RE.sub(replace, text)

    def snmp_replace(match: re.Match[str]) -> str:
        value = match.group("value")
        if _PLACEHOLDER_RE.fullmatch(value):
            return match.group(0)
        prefix = text[match.start():match.start("value")]
        return prefix + "<redacted>"

    text = _EOS_SNMP_RE.sub(snmp_replace, text)

    def snmp_user_line_replace(match: re.Match[str]) -> str:
        line = match.group(0)

        def value_sub(m: re.Match[str]) -> str:
            value = m.group("value")
            if _PLACEHOLDER_RE.fullmatch(value):
                return m.group(0)
            prefix_end = m.start("value")
            prefix = line[m.start():prefix_end]
            return prefix + "<redacted>"

        line = _EOS_SNMP_AUTH_RE.sub(value_sub, line)
        line = _EOS_SNMP_PRIV_RE.sub(value_sub, line)
        return line

    text = _EOS_SNMP_USER_LINE_RE.sub(snmp_user_line_replace, text)

    def vrrp_auth_text_replace(match: re.Match[str]) -> str:
        value = match.group("value")
        if _PLACEHOLDER_RE.fullmatch(value):
            return match.group(0)
        prefix_end = match.start("value")
        prefix = text[match.start():prefix_end]
        return prefix + "<redacted>"

    text = _EOS_VRRP_AUTH_TEXT_RE.sub(vrrp_auth_text_replace, text)

    def snmp_host_line_replace(match: re.Match[str]) -> str:
        line = match.group(0)

        def value_sub(m: re.Match[str]) -> str:
            value = m.group("value")
            if _PLACEHOLDER_RE.fullmatch(value):
                return m.group(0)
            prefix_end = m.start("value")
            prefix = line[m.start():prefix_end]
            return prefix + "<redacted>"

        line = _EOS_SNMP_HOST_VERSION_RE.sub(value_sub, line)
        line = _EOS_SNMP_HOST_BARE_RE.sub(value_sub, line)
        return line

    text = _EOS_SNMP_HOST_LINE_RE.sub(snmp_host_line_replace, text)
    return text



_IOSXE_SECRET_WORDS = (
    "authentication-key",
    "domain-password",
    "area-password",
    "key-string",
    "password",
    "secret",
    "md5",
    "key",
)

# Rule 1: a secret word (longest first), optional second secret word (EOS
# ``algkw`` pattern), optional whole-word type token ``0|5|6|7|8|9``, then a
# non-whitespace value.  The negative lookahead on bare ``key`` skips the
# whole words ``chain`` and ``config-key`` so ``key chain KC`` and
# ``key config-key password-encrypt`` stay byte-identical; ``key chainSynth``
# and ``key config-keyX`` still redact because the next token is not the
# whole word followed by whitespace.
_IOSXE_SECRET_RE = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"(?:"
    # ``authentication-key`` carries an NTP-shape exclusion: rule 11
    # owns ``ntp authentication-key <id> <alg> [0|7] X`` with the id
    # kept.  Without the exclusion rule 1 would redact ``<id>`` after
    # the r6 rule has redacted the secret.  The exclusion only fires
    # when rule 11 has already redacted the secret, so an NTP-shaped
    # line rule 11 missed still gets rule 1 (over-redaction, never a leak).
    # Any other ``authentication-key`` form (``ip ospf authentication-key
    # 7 X``) is still redacted by rule 1.
    r"authentication-key(?![ \t]+\d+[ \t]+(?:md5|sha1|sha2|cmac-aes-128)(?:[ \t]+[06789])?[ \t]+<redacted)"
    r"|"
    r"(?:domain-password|area-password|key-string|secret|md5)"
    r"|"
    # ``password`` skips ``peer <addr>`` / ``fallback`` only when the
    # MSDP or LDP r6 rule already redacted the value, so any other
    # ``password peer ...`` line still gets rule 1 (never a leak).
    r"password(?![ \t]+(?:peer[ \t]+\S+|fallback|option[ \t]+\d+[ \t]+for[ \t]+\S+)[ \t]+(?:[06789][ \t]+)?<redacted)"
    r"|"
    r"key(?![ \t]+(?:chain|config-key)[ \t])"
    r")"
    r"[ \t]+"
    r"(?:level[ \t]+[0-9]+[ \t]+)?"
    r"(?:(?P<algkw>" + "|".join(_IOSXE_SECRET_WORDS) + r")[ \t]+)?"
    r"(?:(?P<type>0|5|6|7|8|9)[ \t]+)?"
    r"(?P<value>\S+)",
    re.IGNORECASE,
)

# Rule 2: ``pre-shared-key`` then optional ``local|remote``, optional type
# ``0|6|7``, then value.  ``pre-shared-key address 192.0.2.1 key X`` ends up
# over-redacting ``address``; the ``key`` rule catches ``X``.
_IOSXE_PRE_SHARED_KEY_RE = re.compile(
    r"(?<![A-Za-z0-9_-])pre-shared-key"
    r"[ \t]+"
    r"(?:(?:local|remote)[ \t]+)?"
    r"(?:(?:0|6|7)[ \t]+)?"
    r"(?P<value>\S+)",
    re.IGNORECASE,
)

# Rule 2 cont: ``wpa-psk ascii|hex [0|7|8] X``.  Type ``8`` is a
# salted SHA-1 hash used by some APs; it sits in the same secret slot
# as ``0`` (plaintext) and ``7`` (Cisco type-7 obfuscation) so the regex
# widens to accept it.
_IOSXE_WPA_PSK_RE = re.compile(
    r"(?<![A-Za-z0-9_-])wpa-psk[ \t]+(?:ascii|hex)[ \t]+(?:[06789][ \t]+)?(?P<value>\S+)",
    re.IGNORECASE,
)

# Rule 3: ``snmp-server community X [view V] [RO|RW] [acl]``.
_IOSXE_SNMP_COMMUNITY_RE = re.compile(
    r"(?<![A-Za-z0-9_-])snmp-server[ \t]+community[ \t]+(?P<value>\S+)",
    re.IGNORECASE,
)

# Rule 4: SNMPv3 user line scoping keeps ``auth``/``priv`` elsewhere untouched.
_IOSXE_SNMP_USER_LINE_RE = re.compile(r"(?mi)^[^\n]*snmp-server[ \t]+user[^\n]*")
_IOSXE_SNMP_AUTH_RE = re.compile(
    r"(?<![A-Za-z0-9_-])auth[ \t]+(?P<alg>\S+)"
    r"(?:[ \t]+(?:128|192|256))?[ \t]+(?P<value>\S+)",
    re.IGNORECASE,
)
# Greedy fallback for ``auth <alg> X Y`` (e.g. ``priv aes 128x PrivSynth``).
# ``128x`` is not a whole-word key size so the simple rule treats it as the
# value; the greedy rule then sweeps the trailing token as well so no secret
# survives on the line.
_IOSXE_SNMP_AUTH_GREEDY_RE = re.compile(
    # Bounded wildcard between ``alg`` and ``value``: ``[^\n]*`` is
    # collapsed to an optional (?:[^\n]*[ \t])? group which keeps the
    # same set of lines (alg is greedy so the previous ``[^\n]*``
    # always started on whitespace or was empty) and turns the run
    # linear on a long line of ``auth`` followed by non-whitespace.
    r"(?<![A-Za-z0-9_-])auth[ \t]+(?P<alg>\S+)[ \t](?:[^\n]*[ \t])?(?P<value>\S+)",
    re.IGNORECASE,
)
_IOSXE_SNMP_PRIV_RE = re.compile(
    r"(?<![A-Za-z0-9_-])priv[ \t]+(?P<alg>\S+)"
    r"(?:[ \t]+(?:128|192|256))?[ \t]+(?P<value>\S+)",
    re.IGNORECASE,
)
_IOSXE_SNMP_PRIV_GREEDY_RE = re.compile(
    r"(?<![A-Za-z0-9_-])priv[ \t]+(?P<alg>\S+)[ \t](?:[^\n]*[ \t])?(?P<value>\S+)",
    re.IGNORECASE,
)

# Rule 5: SNMP host lines (scoped by line, like the v3 user rule).  Within
# those lines, redacts the community value after ``version 1|2c`` and the
# v1/v2c community after ``host <ip> [vrf V] [traps|informs]`` when there is no
# ``version`` keyword (Arista-EOS-style default; IOS XE behaves the same).
# version 3 user names stay byte-identical.
_IOSXE_SNMP_HOST_LINE_RE = re.compile(r"(?mi)^[^\n]*snmp-server[ \t]+host[^\n]*")
_IOSXE_SNMP_HOST_VERSION_RE = re.compile(
    r"(?<![A-Za-z0-9_-])version[ \t]+(?:1|2c)[ \t]+(?P<value>\S+)",
    re.IGNORECASE,
)
_IOSXE_SNMP_HOST_BARE_RE = re.compile(
    r"(?<![\w-])snmp-server[ \t]+host[ \t]+\S+"
    r"(?:[ \t]+vrf[ \t]+\S+)?"
    r"(?:[ \t]+(?:traps|informs))?[ \t]+"
    r"(?!(?:version|vrf|traps|informs|udp-port)(?![^ \t\r\n]))"
    r"(?P<value>\S+)",
    re.IGNORECASE,
)

# Rule 6: HSRP/VRRP plain authentication.  ``standby <n> authentication [text]
# [0|7] X`` (X must not be the whole word ``md5``; ``standby 1 authentication
# md5 key-string 7 X`` is handled by rule 1).  ``vrrp <n> authentication text
# [0|7] X`` requires the literal ``text`` keyword.
_IOSXE_STANDBY_AUTH_TEXT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])standby[ \t]+\S+[ \t]+authentication[ \t]+"
    r"(?:text[ \t]+)?(?:(?:0|7)[ \t]+)?(?!md5(?![^ \t\r\n]))(?P<value>\S+)",
    re.IGNORECASE,
)
_IOSXE_NHRP_AUTH_RE = re.compile(
    r"(?<![A-Za-z0-9_-])nhrp[ \t]+authentication[ \t]+(?P<value>\S+)", re.IGNORECASE
)
_IOSXE_VRRP_AUTH_TEXT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])vrrp[ \t]+\S+[ \t]+authentication[ \t]+text[ \t]+"
    r"(?:(?:0|7)[ \t]+)?(?P<value>\S+)",
    re.IGNORECASE,
)

# Rule 7: GLBP plain authentication ``glbp <group> authentication text [0|7] X``.
# The md5 form ``glbp 1 authentication md5 key-string 7 X`` is caught by rule 1
# (``md5 key-string 7 X`` matches the generic secret word rule); this rule only
# handles the ``text`` form, mirroring the VRRP rule.
_IOSXE_GLBP_AUTH_TEXT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])glbp[ \t]+\S+[ \t]+authentication[ \t]+text[ \t]+"
    r"(?:(?:0|7)[ \t]+)?(?P<value>\S+)",
    re.IGNORECASE,
)

# Rule 7: Catalyst 9800 WLAN PSK ``security wpa psk set-key ascii|hex [0|8] X``.
# The ``-`` before ``key`` blocks rule 1's ``(?<![A-Za-z0-9_-])key`` lookbehind,
# so a dedicated rule is needed.  Type token is ``0`` (plain) or ``8`` (hash);
# ``7`` (Cisco IOS XE type 7 obfuscation) is intentionally NOT a type token here
# because the Catalyst CLI does not use it for ``set-key``.
_IOSXE_SET_KEY_RE = re.compile(
    r"(?<![A-Za-z0-9_-])set-key[ \t]+(?:ascii|hex)[ \t]+(?:(?:0|8)[ \t]+)?(?P<value>\S+)",
    re.IGNORECASE,
)

# Rule 7: Cisco TrustSec ``cts manual`` SAP PMK.  Syntax under ``cts
# manual``: ``sap pmk <hex-key> [mode-list <modes...>]``.  The whole-word
# guards keep ``sapx pmk`` / ``sap pmkfoo`` byte-identical; a leading
# letter/digit/underscore/hyphen before ``sap`` (e.g.
# ``description sap pmkfoo bar``) already fails the lookbehind because
# ``sap`` follows a space.  Linear-time: ``\S+`` is the value, then the
# optional mode-list keyword is whatever follows.
_IOSXE_SAP_PMK_RE = re.compile(
    r"(?<![A-Za-z0-9_-])sap[ \t]+pmk[ \t]+(?P<value>\S+)",
    re.IGNORECASE,
)

# Rule 7: OSPFv3 / IPv6 OSPF IPsec.  Scoped to lines containing whole-word
# ``ipsec`` then whole-word ``spi`` so ``sha1`` and ``md5`` elsewhere on the
# device (e.g. ``crypto isakmp policy 10 hash sha1``) stay byte-identical.
# Within those lines two separate values are redacted:
#   - ``esp {des|3des|aes-cbc {128|192|256}|null} [0|7] <key>`` (cipher key)
#   - ``{md5|sha1} [0|7] <key>`` (authentication hash key)
# ``null``, the cipher, the size, the type token, ``spi`` and its number,
# ``md5``/``sha1`` themselves, ``esp`` and ``ipsec`` are all kept.
# One unbounded run before ``spi`` keeps the line match linear (two runs
# around ``ipsec`` and ``spi`` were quadratic on a long line of ``ipsec``);
# the callback then requires a whole-word ``ipsec`` on the line.
_IOSXE_IPSEC_LINE_RE = re.compile(
    r"(?mi)^[^\n]*(?<![A-Za-z0-9_-])spi(?![A-Za-z0-9_-])[^\n]*"
)
_IOSXE_IPSEC_WORD_RE = re.compile(r"(?<![A-Za-z0-9_-])ipsec(?![A-Za-z0-9_-])", re.IGNORECASE)
_IOSXE_IPSEC_ESP_RE = re.compile(
    r"(?<![A-Za-z0-9_-])esp[ \t]+"
    r"(?:"
    # ``null`` cipher carries no encryption key (the next tokens are the
    # authentication hash keyword and value, which the hash rule handles).
    r"null(?![A-Za-z0-9_-])"
    r"|"
    r"(?:"
    r"des(?![A-Za-z0-9_-])"
    r"|3des(?![A-Za-z0-9_-])"
    r"|aes-cbc[ \t]+(?:128|192|256)(?![A-Za-z0-9_-])"
    r")"
    r"[ \t]+"
    r"(?:(?:0|7)[ \t]+)?"
    r"(?P<value>\S+)"
    r")",
    re.IGNORECASE,
)
_IOSXE_IPSEC_HASH_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:md5|sha1)(?![A-Za-z0-9_-])[ \t]+"
    r"(?:(?:0|7)[ \t]+)?"
    r"(?P<value>\S+)",
    re.IGNORECASE,
)



# Rule 8: RADIUS dynamic-author ``server-key``.  The ``-key`` suffix
# blocks rule 1's ``(?<![A-Za-z0-9_-])key`` lookbehind so the form
# ``aaa server radius dynamic-author ... server-key [0|6|7] X``
# survives the generic rule and leaks the shared secret (typically
# Cisco type-7).  The whole-word lookbehind keeps ``xserver-key``,
# ``server-keyfoo`` and ``server-key chain`` byte-identical.  Linear-
# time: bounded ``type`` alternative, single ``\S+`` value.
_IOSXE_SERVER_KEY_RE = re.compile(
    r"(?<![A-Za-z0-9_-])server-key[ \t]+(?:[06789][ \t]+)?(?P<value>\S+)",
    re.IGNORECASE,
)

# Rule 9: EIGRP named-mode HMAC-SHA-256 keys under
# ``af-interface default ... authentication mode hmac-sha-256 [0|7] X``.
# ``authentication`` alone is not a secret-word alternative in rule 1,
# so the multi-keyword phrase needs its own rule.  Near-miss pins
# ``authentication mode md5`` and ``authentication key-chain EIGRP-KEYS``
# byte-identical (they have no value); they stay that way because the
# rule requires ``hmac-sha-256`` after ``authentication mode``.
_IOSXE_EIGRP_HMAC_SHA_256_RE = re.compile(
    r"(?<![A-Za-z0-9_-])authentication[ \t]+mode[ \t]+hmac-sha-256[ \t]+"
    r"(?:[06789][ \t]+)?(?P<value>\S+)",
    re.IGNORECASE,
)

# Rule 10: MSDP ``[ip] msdp [vrf V] password peer <addr> [0|6|7] X``.
# Matches only the MSDP-shaped address clause so it does not collide
# with the (uncommon) ``password peer`` form elsewhere.  The rule
# fires before rule 1; with rule 1's ``password`` alternative also
# carrying a ``(?![ \t]+peer(?![^ \t\r\n]))`` guard, neither rule
# redacts the whole-word ``peer`` token.  Type ``0`` / ``6`` / ``7``
# matches the IOS XE crypto type tokens used after ``peer`` in this
# configuration.  Linear-time: optional ``vrf`` group has one ``\S+``
# alternation; the address is one ``\S+``; both are bounded.
_IOSXE_MSDP_RE = re.compile(
    r"(?<![A-Za-z0-9_-])msdp[ \t]+"
    r"(?:vrf[ \t]+\S+[ \t]+)?"
    r"password[ \t]+peer[ \t]+\S+[ \t]+"
    r"(?:[06789][ \t]+)?(?P<value>\S+)",
    re.IGNORECASE,
)

# Rule 11: NTP ``ntp authentication-key <id> <alg> [0|7] X``.  The
# generic rule 1 fires on ``ntp authentication-key <id>`` today, which
# over-redacts the key id (``1``) and leaves the secret on the line.
# This rule keeps the id and the algorithm token and only redacts the
# trailing secret.  Algorithm tokens are limited to the known IOS XE
# forms (``md5``, ``sha1``, ``sha2``, ``cmac-aes-128``); an unknown
# algorithm token (``trusted``) falls through and lets rule 1 handle it
# (which still over-redacts the id, the behaviour pinned by
# ``test_mv1_9_64``).  Linear-time: ``\d+`` and ``\S+`` are bounded by
# whitespace on either side.
_IOSXE_NTP_AUTH_KEY_RE = re.compile(
    r"(?<![A-Za-z0-9_-])ntp[ \t]+authentication-key[ \t]+\d+[ \t]+"
    r"(?:md5|sha1|sha2|cmac-aes-128)"
    r"(?:[ \t]+[06789])?[ \t]+"
    r"(?P<value>\S+)",
    re.IGNORECASE,
)

# Rule 12: ``mpls ldp [vrf V] password fallback [type] X`` and
# ``... password option <n> for <acl> [type] X`` (key-chain names a chain, not a key).  The shared keyword
# ``password`` matches rule 1 with value ``fallback`` (then the secret
# remains on the line).  This rule keeps the ``fallback`` neighbour
# and redacts the secret.  Linear-time: one optional ``\d``-style
# type alternative.
_IOSXE_LDP_RE = re.compile(
    r"(?<![A-Za-z0-9_-])mpls[ \t]+ldp[ \t]+(?:vrf[ \t]+\S+[ \t]+)?password[ \t]+"
    r"(?:fallback|option[ \t]+\d+[ \t]+for[ \t]+\S+)[ \t]+"
    r"(?!key-chain(?![^ \t\r\n]))(?:[06789][ \t]+)?(?P<value>\S+)",
    re.IGNORECASE,
)

# Rule 13: ``vrrp|glbp <n> authentication [0|7] X`` (old no-keyword
# form).  Rule 6 / GLBP-text rule require the literal ``text`` keyword
# after ``authentication``; this new rule covers the older configurations
# where the keyword is omitted.  The negative lookahead
# ``(?!text|md5|key-chain)`` excludes those three neighbours so this
# rule never fires when rule 6 or rule 1 owns the line:
#   * ``vrrp 1 authentication text 7 X``  -> rule 6 redacts X
#   * ``vrrp 1 authentication md5 key-chain VRRP-KC`` -> rule 1 redacts
#     ``key-chain`` (HEAD output is pinned in test_mv1_9_55)
#   * ``vrrp 1 authentication key-chain X`` -> unchanged on HEAD
# Linear-time: optional ``0|7`` alternative plus a single bounded value.
_IOSXE_VRRP_GLBP_AUTH_OLD_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:vrrp|glbp)[ \t]+\S+[ \t]+authentication[ \t]+"
    r"(?:(?:0|7)[ \t]+)?"
    r"(?!text(?![^ \t\r\n])|md5(?![^ \t\r\n])|key-chain(?![^ \t\r\n]))"
    r"(?P<value>\S+)",
    re.IGNORECASE,
)


def _redact_iosxe(text: str) -> str:
    """Redact Cisco IOS XE secret-bearing keywords, optional type tokens,
    pre-shared-key / wpa-psk forms, SNMP community / user / host, and the
    HSRP / VRRP plain authentication forms.  Other platforms' output must
    stay byte-identical (this function is only invoked from ``redact`` when
    ``platform == "iosxe"``)."""

    # Rule 4 -- line-scoped so ``auth`` / ``priv`` elsewhere on the device are
    # untouched.  Simple rule first, then a greedy sweep that catches the
    # trailing token when the simple rule treated a non-size token as the
    # value (e.g. ``priv aes 128x PrivSynth``).
    def snmp_user_line_replace(match: re.Match[str]) -> str:
        line = match.group(0)

        def auth_value_sub(m: re.Match[str]) -> str:
            value = m.group("value")
            if _PLACEHOLDER_RE.fullmatch(value):
                return m.group(0)
            prefix_end = m.start("value")
            prefix = line[m.start():prefix_end]
            return prefix + "<redacted>"

        new_line = _IOSXE_SNMP_AUTH_RE.sub(auth_value_sub, line)
        line = new_line
        new_line = _IOSXE_SNMP_AUTH_GREEDY_RE.sub(auth_value_sub, line)
        line = new_line

        def priv_value_sub(m: re.Match[str]) -> str:
            value = m.group("value")
            if _PLACEHOLDER_RE.fullmatch(value):
                return m.group(0)
            prefix_end = m.start("value")
            prefix = line[m.start():prefix_end]
            return prefix + "<redacted>"

        new_line = _IOSXE_SNMP_PRIV_RE.sub(priv_value_sub, line)
        line = new_line
        new_line = _IOSXE_SNMP_PRIV_GREEDY_RE.sub(priv_value_sub, line)
        return new_line

    text = _IOSXE_SNMP_USER_LINE_RE.sub(snmp_user_line_replace, text)

    # Rule 5 -- line-scoped for the same reason.  version 1/2c community is
    # matched first; the bare rule picks up unversioned (v1 default) hosts
    # without redacting ``version``/``vrf``/``traps``/``informs``/``udp-port``
    # tokens that are followed by another non-whitespace char.
    def snmp_host_line_replace(match: re.Match[str]) -> str:
        line = match.group(0)

        def value_sub(m: re.Match[str]) -> str:
            value = m.group("value")
            if _PLACEHOLDER_RE.fullmatch(value):
                return m.group(0)
            prefix_end = m.start("value")
            prefix = line[m.start():prefix_end]
            return prefix + "<redacted>"

        new_line = _IOSXE_SNMP_HOST_VERSION_RE.sub(value_sub, line)
        line = new_line
        new_line = _IOSXE_SNMP_HOST_BARE_RE.sub(value_sub, line)
        return new_line

    text = _IOSXE_SNMP_HOST_LINE_RE.sub(snmp_host_line_replace, text)

    # Rules 8-13 (r6) -- ``server-key``, EIGRP HMAC-SHA-256, MSDP,
    # NTP authentication-key, ``mpls ldp password fallback`` and the
    # ``vrrp|glbp <n> authentication`` old form.  The MSDP, NTP and LDP
    # rules must fire before rule 1 (otherwise rule 1 over-redacts the
    # neighbouring tokens and leaves the secret on the line).  The
    # server-key / hmac-sha-256 rules must fire before rule 1 because
    # the ``-key`` suffix and the multi-keyword phrase are not owned by
    # any rule 1 alternative.  The vrrp/glbp old-form rule must fire
    # before rule 1 because rule 6 / GLBP-text require ``text``.
    def r6_sub(match: re.Match[str]) -> str:
        value = match.group("value")
        if _PLACEHOLDER_RE.fullmatch(value):
            return match.group(0)
        prefix_end = match.start("value")
        prefix = text[match.start():prefix_end]
        return prefix + "<redacted>"

    text = _IOSXE_SERVER_KEY_RE.sub(r6_sub, text)
    text = _IOSXE_EIGRP_HMAC_SHA_256_RE.sub(r6_sub, text)
    text = _IOSXE_MSDP_RE.sub(r6_sub, text)
    text = _IOSXE_NTP_AUTH_KEY_RE.sub(r6_sub, text)
    text = _IOSXE_LDP_RE.sub(r6_sub, text)
    # The VRRP / GLBP old-auth-form rule is applied LATER, after rule 6
    # / GLBP-text rule, so the existing rule 6 owns ``vrrp|glbp <n>
    # authentication text X`` first.

    # Rule 1 -- generic secret word + optional second secret word + optional
    # type token + value.  Run before rule 2 so the latter's ``key`` exception
    # is unaffected; run after the SNMP line-scoped rules so ``key 7`` inside
    # a host line can still be matched.  The r6 rules above run before this
    # one so the ``password peer`` / ``ntp authentication-key <id>`` /
    # ``mpls ldp password fallback`` neighbour shapes are owned first.
    def rule1_sub(match: re.Match[str]) -> str:
        value = match.group("value")
        if _PLACEHOLDER_RE.fullmatch(value):
            return match.group(0)
        prefix_end = match.start("value")
        prefix = text[match.start():prefix_end]
        return prefix + "<redacted>"

    text = _IOSXE_SECRET_RE.sub(rule1_sub, text)

    # Rule 2 -- ``pre-shared-key`` and ``wpa-psk`` forms.
    def rule2_sub(match: re.Match[str]) -> str:
        value = match.group("value")
        if _PLACEHOLDER_RE.fullmatch(value):
            return match.group(0)
        prefix_end = match.start("value")
        prefix = text[match.start():prefix_end]
        return prefix + "<redacted>"

    text = _IOSXE_PRE_SHARED_KEY_RE.sub(rule2_sub, text)
    text = _IOSXE_WPA_PSK_RE.sub(rule2_sub, text)

    # Rule 3 -- ``snmp-server community X``.
    def rule3_sub(match: re.Match[str]) -> str:
        value = match.group("value")
        if _PLACEHOLDER_RE.fullmatch(value):
            return match.group(0)
        prefix_end = match.start("value")
        prefix = text[match.start():prefix_end]
        return prefix + "<redacted>"

    text = _IOSXE_SNMP_COMMUNITY_RE.sub(rule3_sub, text)

    # Rule 6 -- HSRP / VRRP plain authentication (rule 1 catches
    # ``standby 1 authentication md5 key-string 7 X`` already).
    def rule6_sub(match: re.Match[str]) -> str:
        value = match.group("value")
        if _PLACEHOLDER_RE.fullmatch(value):
            return match.group(0)
        prefix_end = match.start("value")
        prefix = text[match.start():prefix_end]
        return prefix + "<redacted>"

    text = _IOSXE_STANDBY_AUTH_TEXT_RE.sub(rule6_sub, text)
    text = _IOSXE_VRRP_AUTH_TEXT_RE.sub(rule6_sub, text)
    text = _IOSXE_NHRP_AUTH_RE.sub(rule6_sub, text)

    # Rule 7 -- GLBP plain authentication (matches the VRRP rule shape).
    text = _IOSXE_GLBP_AUTH_TEXT_RE.sub(rule6_sub, text)

    # Rule 13 (r6) -- ``vrrp|glbp <n> authentication [0|7] X`` (old
    # no-keyword form).  Runs AFTER rule 6 / GLBP-text so the existing
    # rule 6 owns ``text X`` first; the new rule excludes ``text``,
    # ``md5`` and ``key-chain`` from its value position so none of those
    # neighbour shapes are ever over-redacted.  Pin HEAD behaviour for
    # ``vrrp 1 authentication md5 key-chain VRRP-KC`` (rule 1 redacts
    # ``key-chain``) in ``test_mv1_9_55``.
    text = _IOSXE_VRRP_GLBP_AUTH_OLD_RE.sub(r6_sub, text)

    # Rule 7 -- Catalyst 9800 WLAN PSK ``set-key ascii|hex [0|8] X``.  The
    # ``-`` before ``key`` blocks rule 1's whole-word lookbehind.
    text = _IOSXE_SET_KEY_RE.sub(rule6_sub, text)

    # Rule 7 -- Cisco TrustSec ``cts manual`` ``sap pmk``.  The lookbehind
    # keeps ``sapx pmk`` / ``sap pmkfoo`` byte-identical; a placeholder
    # ``<redacted>`` or ``<redacted:xxxxxxxx>`` value survives via the
    # shared ``rule6_sub`` placeholder check.
    text = _IOSXE_SAP_PMK_RE.sub(rule6_sub, text)

    # Rule 7 -- OSPFv3 / IPv6 OSPF IPsec.  Line-scoped to ``ipsec ... spi ...``
    # so ``sha1`` / ``md5`` in unrelated config (e.g. ``crypto isakmp policy
    # 10 hash sha1``, ``authentication sha1 SomeName``) stays byte-identical.
    def ipsec_line_replace(match: re.Match[str]) -> str:
        line = match.group(0)
        if not _IOSXE_IPSEC_WORD_RE.search(line):
            return line

        def esp_value_sub(m: re.Match[str]) -> str:
            value = m.group("value")
            if value is None:
                return m.group(0)
            if _PLACEHOLDER_RE.fullmatch(value):
                return m.group(0)
            prefix_end = m.start("value")
            prefix = line[m.start():prefix_end]
            return prefix + "<redacted>"

        def hash_value_sub(m: re.Match[str]) -> str:
            value = m.group("value")
            if _PLACEHOLDER_RE.fullmatch(value):
                return m.group(0)
            prefix_end = m.start("value")
            prefix = line[m.start():prefix_end]
            return prefix + "<redacted>"

        new_line = _IOSXE_IPSEC_ESP_RE.sub(esp_value_sub, line)
        line = new_line
        new_line = _IOSXE_IPSEC_HASH_RE.sub(hash_value_sub, line)
        return new_line

    text = _IOSXE_IPSEC_LINE_RE.sub(ipsec_line_replace, text)

    return text






# ---- FortiOS (Fortinet FortiGate) ---------------------------------------
#
# Catalog rule 1: any whole-word ``ENC`` not preceded by a letter, digit,
# underscore or hyphen, then whitespace, then a bare value or a single-line
# double-quoted value, replaces the value with ``<redacted>`` and keeps
# ``ENC``.
#
# Catalog rule 2: ``set`` + whitespace + a secret word (whole word) +
# whitespace + optional whole-word ``ENC`` + whitespace, then the value:
# a double-quoted string (which may span lines until its closing quote; an
# unclosed quote runs to the end of the text), or a bare run of
# non-whitespace, replaces the value with ``<redacted>`` and keeps the
# ``set`` label and ``ENC`` keyword.
#
# Catalog rule 3: inside a ``config system snmp community`` block (from
# that line to its matching ``end``, counting nested ``config`` ... ``end``
# pairs; indentation varies, match on stripped line text,
# case-insensitive), ``set name <value>`` (quoted or bare) replaces the
# value with ``<redacted>``.  ``set name`` outside the block stays.
#
# Linear-time: each regex has bounded groups and single quantifiers; the
# community block is a single line-by-line scan with a depth counter.

_FORTIOS_SECRET_WORDS = (
    # Longest first so alternation picks the right word (e.g. psksecret-remote
    # before psksecret; pre-shared-key before key).
    "psksecret-remote",
    "pre-shared-key",
    "auth-password",
    "ldap-password",
    "sso-password",
    "private-key",
    "ppk-secret",
    "key-string",
    "psksecret",
    "passphrase",
    "auth-pwd",
    "priv-pwd",
    "password",
    "md5-key",
    "passwd",
    "secret",
    "key",
)

_FORTIOS_ENC_RE = re.compile(
    r"(?<![A-Za-z0-9_-])ENC(?![A-Za-z0-9_-])[ \t]+"
    r"(?P<value>"
    r"\"[^\"\r\n]*\""
    r"|[^\s\r\n\"]+"
    r")",
    re.IGNORECASE,
)

_FORTIOS_SET_SECRET_RE = re.compile(
    r"(?m)^[ \t]*set[ \t]+"
    r"(?:md5-keys?[ \t]+[0-9]+|" + "|".join(_FORTIOS_SECRET_WORDS) + r")(?![A-Za-z0-9_-])"
    r"[ \t]+"
    r"(?:ENC(?![A-Za-z0-9_-])[ \t]+)?"
    r"(?P<value>"
    r"\"[^\"]*?\""
    r"|\"[^\"]*\Z"
    r"|[^\s\r\n\"]+"
    r")",
    re.IGNORECASE,
)

_FORTIOS_CONFIG_RE = re.compile(r"(?im)^[ \t]*config(?![A-Za-z0-9_-])[ \t]+")
_FORTIOS_END_RE = re.compile(r"(?im)^[ \t]*end[ \t]*$")
_FORTIOS_SNMP_COMMUNITY_RE = re.compile(
    r"(?im)^[ \t]*config[ \t]+system[ \t]+snmp[ \t]+community(?![A-Za-z0-9_-])[ \t]*$"
)
_FORTIOS_SET_NAME_RE = re.compile(
    r"(?im)^[ \t]*set[ \t]+name(?![A-Za-z0-9_-])[ \t]+"
)


def _redact_fortios_set_name_value(line: str, match_end: int) -> str:
    """Given a line matched by FORTIOS_SET_NAME_RE, redact the value after match_end."""
    pos = match_end
    n = len(line)
    while pos < n and line[pos] in " \t":
        pos += 1
    if pos < n and line[pos] == '"':
        end = line.find('"', pos + 1)
        if end < 0:
            end = n
        else:
            end += 1
    else:
        end = pos
        while end < n and line[end] not in " \t\r\n":
            end += 1
    value = line[pos:end]
    if _PLACEHOLDER_RE.fullmatch(_placeholder_inner(value)):
        return line
    return line[:pos] + "<redacted>"


def _redact_fortios_snmp_community(text: str) -> str:
    """Redact ``set name <value>`` inside ``config system snmp community`` blocks."""
    lines = text.split("\n")
    out_lines: list[str] = []
    depth = 0
    snmp_depth: int | None = None

    for line in lines:
        set_name_match = _FORTIOS_SET_NAME_RE.match(line)
        if (
            set_name_match is not None
            and snmp_depth is not None
            and depth >= snmp_depth
        ):
            out_lines.append(
                _redact_fortios_set_name_value(line, set_name_match.end())
            )
        else:
            out_lines.append(line)

        if _FORTIOS_CONFIG_RE.match(line):
            depth += 1
            if snmp_depth is None and _FORTIOS_SNMP_COMMUNITY_RE.match(line):
                snmp_depth = depth
        elif _FORTIOS_END_RE.match(line):
            depth -= 1
            if snmp_depth is not None and depth < snmp_depth:
                snmp_depth = None

    return "\n".join(out_lines)


def _redact_fortios(text: str) -> str:
    """Redact FortiOS secrets per the catalog (ENC, secret words, snmp community names)."""

    def enc_replace(match: re.Match[str]) -> str:
        value = match.group("value")
        if _PLACEHOLDER_RE.fullmatch(_placeholder_inner(value)):
            return match.group(0)
        prefix_len = match.start("value") - match.start()
        return match.group(0)[:prefix_len] + "<redacted>"

    text = _FORTIOS_ENC_RE.sub(enc_replace, text)

    def secret_replace(match: re.Match[str]) -> str:
        value = match.group("value")
        if _PLACEHOLDER_RE.fullmatch(_placeholder_inner(value)):
            return match.group(0)
        prefix_len = match.start("value") - match.start()
        return match.group(0)[:prefix_len] + "<redacted>"

    text = _FORTIOS_SET_SECRET_RE.sub(secret_replace, text)

    text = _redact_fortios_snmp_community(text)

    return text



def redact(platform: str, text: str) -> str:
    """Apply only the platform forms the shared redactor cannot represent.

    OpenWrt output is deliberately untouched: its shell-side masking and shared
    redactor are pinned independently, and this pass must not change those bytes.
    """

    normalized = platform.lower()
    if normalized == "routeros":
        return _redact_routeros(text)
    if normalized == "vyos":
        return _redact_vyos(text)
    if normalized == "junos":
        return _redact_junos(text)
    if normalized == "eos":
        return _redact_eos(text)
    if normalized == "iosxe":
        return _redact_iosxe(text)
    if normalized == "fortios":
        return _redact_fortios(text)
    return text
