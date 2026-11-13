"""The attributes the audit never requests and never returns.

The list is normative (SPEC-1.3 section 4) and the first red-team review added six
names to it (``clearTextPassword``, ``pekList``, ``sambaNTPassword``,
``sambaLMPassword``, ``sambaPasswordHistory`` and
``msDS-ExecuteScriptPassword``): each of them holds a password or a
password history on one platform or another, and none of them is in the
query set.  It is a deliberate superset of ActiveDirectoryMCP's
``SENSITIVE_FILTER_ATTRIBUTES``: some names are legacy or unreal, which
is harmless, and the three deltas the spec names (``nTSecurityDescriptor``,
``securityIdentifier``, ``sIDHistory`` and
``msDS-AllowedToActOnBehalfOfOtherIdentity``) are not forbidden, because
they hold SIDs and owner+DACL descriptors and the checks need them.

This module is the single source.  ``setupgen.py`` writes ``forbidden.json``
beside each installed collector, and both collectors refuse to run when a
requested attribute, or a non-presence filter attribute, is on this list.

Portions adapted from ActiveDirectoryMCP, Copyright (c) 2024 Alperen Adalar,
MIT License.
"""

from __future__ import annotations

import json


# The normative list, lowercased.  The names keep their original spelling
# in the comments so a reader can match them against the schema.
FORBIDDEN_ATTRIBUTES: frozenset[str] = frozenset(
    {
        # Password hashes and history.
        "unicodepwd",
        "dbcspwd",
        "ntpwdhistory",
        "lmpwdhistory",
        "pwdhistory",
        "supplementalcredentials",
        # Password-bearing attributes.
        "userpassword",
        "unixuserpassword",
        "mssfu30password",
        # LAPS.
        "ms-mcs-admpwd",
        "mslaps-password",
        "mslaps-encryptedpassword",
        "mslaps-encryptedpasswordhistory",
        "mslaps-encrypteddsrmpassword",
        "mslaps-encrypteddsrmpasswordhistory",
        # BitLocker.
        "msfve-recoverypassword",
        "msfve-keypackage",
        "msfve-recoveryguid",
        "msfve-volumeguid",
        # gMSA.
        "msds-managedpassword",
        "msds-managedpasswordid",
        "msds-managedpasswordpreviousid",
        # KDS root keys.
        "mskds-rootkeydata",
        # Domain backup keys and trust secrets.
        "currentvalue",
        "priorvalue",
        "trustauthincoming",
        "trustauthoutgoing",
        "initialauthincoming",
        "initialauthoutgoing",
        # Credential roaming.
        "mspki-dpapimasterkeys",
        "mspki-credentialroamingtokens",
        "mspkiaccountcredentials",
        "mspkiroamingtimestamp",
        # Key credentials.
        "msds-keycredentiallink",
        # The first red-team review: the password names the spec does not name.
        # They hold a password or a password history on one platform or
        # another, so they are refused like the ones above.
        "cleartextpassword",
        "peklist",
        "sambantpassword",
        "sambalmpassword",
        "sambapasswordhistory",
        "msds-executescriptpassword",
    }
)


def is_forbidden(name: object) -> bool:
    """True when the attribute name is on the forbidden list.

    The comparison ignores case and the options a collector may add to an
    attribute name (``;binary``, ``;range=0-1500``): the base name decides.
    """
    if not isinstance(name, str):
        return False
    base = name.split(";", 1)[0].strip().lower()
    if not base:
        return False
    return base in FORBIDDEN_ATTRIBUTES


def dump_json() -> bytes:
    """The bytes of ``forbidden.json``, the file the collectors load.

    The list is sorted, so the file is the same on every collector and a
    hash of it means the same thing everywhere.
    """
    text = json.dumps(sorted(FORBIDDEN_ATTRIBUTES), indent=2) + "\n"
    return text.encode("utf-8")
