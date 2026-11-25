"""``newton-doctor ad``: a read-only consistency check of the AD inventory.

The check reads local files only (the inventory, the key files, the
known_hosts files and the approval fingerprints in the state directory).
It contacts no host, writes nothing and runs no command.  It asks
``server.load_inventory`` whether the inventory Newton itself uses loads,
and it parses the inventory as well: the loader stops at the first bad
entry, and the doctor's job is to name every finding with the step that
fixes it.

Output, like the rest of the doctor: ``PASS``, ``FAIL`` and
``INCONCLUSIVE`` lines, plus ``INFO`` notes that never change the exit
code.  Exit codes: 0 clean, 1 at least one FAIL, 3 no FAIL but something
could not be judged, 2 the arguments or the account are wrong.

An inventory Newton itself refuses to load is a finding: the loader
refuses the whole inventory for it, so Newton loads no device from it.
The doctor says so in the loader's own words, and it names every entry
it finds wrong itself, because the loader stops at the first one.  The
refusal keeps its ``FAIL``; its next step says to fix the findings this
run names for that entry first, and otherwise the one fixed line that
edits it.  An inventory that does not load is also why the doctor cannot
judge a pairing: it says so until the inventory loads, and it never
claims that a domain has audit entries only, or that a write entry has
no audit entry.  A loader error it did not expect is no verdict at all:
the doctor then says the inventory could not be judged, never that it
does not load.

A DC's audit entry and its write entry pair by domain and host.  The
host text is compared normalised: lowercase, one trailing dot removed.
When one entry gives an IP address and the other a name, no name is
resolved (the doctor contacts no host), so the pairing cannot be
confirmed: the doctor says so as an ``INCONCLUSIVE`` note (the run then
exits 3) instead of calling the write entry missing, and it never names
one write entry as the partner of the read entry.  The IP-versus-name
test looks at every write entry of the domain, paired or not: a write
entry that gives a name may be this DC's even when another audit entry
pairs with it.  Only the write entries whose address is of the other
kind (IP versus name) are named there; a write entry that is unpaired
for another reason keeps its own note.  A DC is called missing its
write entry only when every write entry of its domain gives an address
of the same kind as its audit entry.  The setup command of such a
finding never names a device that is already an entry of the file: that
command would replace that entry, so the next step is the one fixed
line that edits it.

Every value of the inventory is untrusted text.  A value reaches a
printed command only when it passes the grammar the inventory loader
uses for that field and cannot look like an option; the command quotes
it with ``shlex.quote``.  A value that fails its grammar gets no command
at all: the next step is the one fixed line that edits the entry.  The
whole next step escapes the bytes outside 0x20-0x7e and is never cut
short, because a truncated command is dangerous.
"""

from __future__ import annotations

import argparse
import base64
import errno
import hashlib
import hmac
import ipaddress
import os
import pwd
import re
import shlex
import stat
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NamedTuple

from newton_mcp import server
from newton_mcp.ad.setupgen import DOMAIN_RE
from newton_mcp.adapters import registry
from newton_mcp.adapters.ssh_cli import HOST_RE, USER_RE, user_grammar
from newton_mcp.server import DEVICE_NAME_RE, INVENTORY_PATH_RE, NewtonError

#: The platforms of the inventory this check reads.  They are the
#: registry's own sets, so a platform Newton adds is picked up here.
READ_PLATFORMS = frozenset(registry.AD_PLATFORMS)
WRITE_PLATFORMS = frozenset(registry.AD_WRITE_PLATFORMS)
AD_PLATFORMS = READ_PLATFORMS | WRITE_PLATFORMS

#: The exact placeholder lines newton-ad-setup prints in an entry.  A test
#: pins each one against the text of the setup generators.
PLACEHOLDERS = (
    "<the private key of the audit key, on the Newton host>",
    "<the pinned known_hosts of the collector host>",
    "<the private key of the write key, on the Newton host>",
    "<the pinned known_hosts of the controller>",
)

#: What the doctor says about an inventory Newton does not load.
NO_DEVICE = "Newton loads no device from this inventory"

#: Why the doctor cannot judge a pairing while the inventory does not load.
NOT_JUDGED = "it cannot be judged until the inventory loads"

#: Why the doctor cannot judge a pairing when the loader refused the
#: inventory: the inventory does not load, and that is what it knows.
REFUSED_REASON = "the inventory does not load"

#: Why the doctor cannot judge a pairing when the loader's verdict was an
#: error it did not expect: the inventory could not be judged, and that is
#: all the doctor knows about it.
UNJUDGED_REASON = "the inventory could not be judged"

_FP_RE = re.compile(r"v1 ([0-9a-f]{64})")
_LIMIT = 600
_SSH_DIR = "/var/lib/newton/.ssh"
_FAMILIES = (
    "ad-domain-link", "ad-domain-device", "ad-read-coverage",
    "ad-key-file", "ad-known-hosts", "ad-approval-fingerprint",
)

#: The shapes of the loader's refusal that name the entry it refuses.
#: The doctor reads the name only to fold the refusal into the finding it
#: made for that entry itself; a name it cannot read leaves the refusal
#: on a line of its own.
_REFUSAL_NAMES = (
    re.compile(r"^device ([^:]+): "),
    re.compile(r"^invalid device entry: (.+)$"),
    re.compile(r"^invalid device name in inventory: (.*?): "),
)


def _escape_bytes(text: str) -> str:
    """Every byte outside 0x20-0x7e prints as \\xNN.  Nothing is cut."""
    return "".join(
        c if 32 <= ord(c) <= 126 else "".join(f"\\x{b:02x}" for b in c.encode("utf-8"))
        for c in text
    )


def _escape(text: str) -> str:
    """Inventory text is untrusted: bytes outside 0x20-0x7e print as \\xNN."""
    clipped = text[:_LIMIT]
    return _escape_bytes(clipped) + ("...[truncated]" if len(text) > _LIMIT else "")


def _safe(value: object, grammar: re.Pattern[str]) -> str | None:
    """The value if it may be pasted into a command, else None.

    A value of the inventory reaches a command only when it passes the
    grammar the inventory loader uses for that field, and when it cannot
    look like an option of the command it lands in.
    """
    if not isinstance(value, str) or not value:
        return None
    if value.startswith("-"):
        return None
    if grammar.fullmatch(value) is None:
        return None
    return value


@dataclass
class Report:
    lines: list[str] = field(default_factory=list)
    summary: str = ""
    exit_code: int = 0


class _Checker:
    def __init__(self, inventory: Path, state_dir: Path, setup_command: str, owner_uid: int) -> None:
        self.inventory = inventory
        self.state_dir = state_dir
        self.setup = setup_command
        self.owner_uid = owner_uid
        self.out: list[tuple[str, str, str]] = []  # level, family, text
        self.fails = 0
        self.inconclusive = 0
        self.notes = 0

    def emit(self, level: str, family: str, who: str, message: str, next_step: str = "") -> None:
        label = f"{family}[{_escape(who)}]" if who else family
        text = f"{level} {label}: {_escape(message)}"
        if next_step:
            # The next step is a command the owner runs: it is escaped
            # like the message, and never cut short.
            text += f" Next: {_escape_bytes(next_step)}"
        self.out.append((level, family, text))
        if level == "FAIL":
            self.fails += 1
        elif level == "INCONCLUSIVE":
            self.inconclusive += 1
        elif level == "INFO":
            self.notes += 1

    def fail(self, family: str, who: str, message: str, next_step: str) -> None:
        self.emit("FAIL", family, who, message, next_step)

    # ---- helpers for the commands the owner runs --------------------------

    def inventory_path(self) -> str | None:
        """The path of the inventory, when it may be pasted into a command."""
        return _safe(str(self.inventory), INVENTORY_PATH_RE)

    def fix_entry(self) -> str:
        """The one next step for an entry whose text may not be pasted."""
        path = self.inventory_path()
        if path is None:
            return "fix that entry with sudoedit -u newton <the inventory path>"
        return f"fix that entry with sudoedit -u newton {shlex.quote(path)}"

    def fix_inventory(self) -> str:
        """The next step for an inventory the doctor cannot read."""
        path = self.inventory_path()
        if path is None:
            return "fix it with sudoedit -u newton <the inventory path>"
        return f"fix it with sudoedit -u newton {shlex.quote(path)}"

    def edit(self, name: str, what: str) -> str:
        """The sudoedit line that fixes one field of one entry.

        ``what`` is the doctor's own text; it names no value of the
        inventory, so only the entry name and the inventory path can be
        untrusted here.
        """
        path = self.inventory_path()
        safe_name = _safe(name, DEVICE_NAME_RE)
        if path is None or safe_name is None:
            return self.fix_entry()
        return (f"sudoedit -u newton {shlex.quote(path)} "
                f"({what} in [devices.{shlex.quote(safe_name)}])")

    def edit_other(self, name: str, other: str, what: str) -> str:
        """The sudoedit line that names another entry of the inventory."""
        safe_other = _safe(other, DEVICE_NAME_RE)
        if safe_other is None:
            return self.edit(name, what)
        return self.edit(name, f"{what} {shlex.quote(safe_other)}")

    def setup_line(self, entry_platform: str, write: bool, domain: str, name: str,
                   host: str, domain_device: str | None) -> str:
        """The setup command that adds one entry or reads one DC."""
        word = "samba" if "samba" in entry_platform else "windows"
        setup = _safe(self.setup, INVENTORY_PATH_RE)
        safe_domain = _safe(domain, DOMAIN_RE)
        safe_name = _safe(name, DEVICE_NAME_RE)
        safe_host = _safe(host, HOST_RE)
        safe_device = None if domain_device is None else _safe(domain_device, DEVICE_NAME_RE)
        if (setup is None or safe_domain is None or safe_name is None or safe_host is None
                or (domain_device is not None and safe_device is None)):
            return self.fix_entry()
        if write:
            line = (
                f"{shlex.quote(setup)} write {word} --domain {shlex.quote(safe_domain)} "
                f"--pubkey {shlex.quote(safe_name)}.pub --device {shlex.quote(safe_name)} "
                f"--host {shlex.quote(safe_host)} --ou '<DN of a location to change>'"
            )
            if safe_device is not None:
                line += f" --domain-device {shlex.quote(safe_device)}"
            return line
        return (f"{shlex.quote(setup)} {word} --domain {shlex.quote(safe_domain)} "
                f"--pubkey {shlex.quote(safe_name)}.pub --device {shlex.quote(safe_name)} "
                f"--host {shlex.quote(safe_host)}")

    def keygen(self, name: str, key_name: str) -> str:
        """The ssh-keygen line that makes the key of one entry."""
        safe_key = _safe(f"{_SSH_DIR}/{key_name}", INVENTORY_PATH_RE)
        if safe_key is None:
            return self.fix_entry()
        return (f"sudo -u newton ssh-keygen -t ed25519 -N '' -f {shlex.quote(safe_key)}, "
                f"then {self.edit(name, 'set key_file to that path')}")

    def scan(self, name: str, host: str) -> str:
        """The ssh-keyscan line that pins the host key of one entry."""
        safe_host = _safe(host, HOST_RE)
        safe_file = _safe(f"{_SSH_DIR}/{_stem(name)}.known_hosts", INVENTORY_PATH_RE)
        if safe_host is None or safe_file is None:
            return self.fix_entry()
        return (f"ssh-keyscan -t ed25519 {shlex.quote(safe_host)} | sudo -u newton tee "
                f"{shlex.quote(safe_file)} >/dev/null, "
                "compare the fingerprint it shows with the DC's own (docs/INSTALL.md 10d), "
                f"then {self.edit(name, 'set known_hosts to that path')}")

    def chown(self, value: str) -> str:
        """The chown line that gives one file to the account of Newton."""
        safe = _safe(value, INVENTORY_PATH_RE)
        if safe is None:
            return self.fix_entry()
        return f"sudo chown newton {shlex.quote(safe)}"

    def chmod(self, value: str, mode: str) -> str:
        """The chmod line that sets the mode of one file."""
        safe = _safe(value, INVENTORY_PATH_RE)
        if safe is None:
            return self.fix_entry()
        return f"sudo -u newton chmod {mode} {shlex.quote(safe)}"

    def approval_key(self, name: str) -> str:
        """The setup line that prints the approval key of one domain device."""
        safe_name = _safe(name, DEVICE_NAME_RE)
        if safe_name is None:
            return self.fix_entry()
        return f"sudo -u newton /usr/local/bin/newton-ad-setup approval-key {shlex.quote(safe_name)}"

    def sudo_user(self, user: str) -> str:
        """The line that runs the doctor as the account that owns the keys."""
        safe = _safe(user, USER_RE)
        if safe is None:
            return "run the doctor as the account that owns the keys and the inventory"
        return f"sudo -u {shlex.quote(safe)} /usr/local/bin/newton-doctor ad"

    def pair_step(self, domain: str, names: list[str]) -> str:
        """The next step of a DC whose two entries could not be paired.

        It names the write entries of the domain that may be this DC's
        and says what the owner has to do; it never tells the owner to
        copy the host of one entry into another one.
        """
        safe_domain = _safe(domain, DOMAIN_RE)
        safe_names = [_safe(n, DEVICE_NAME_RE) for n in names]
        if safe_domain is None or not safe_names or any(n is None for n in safe_names):
            return self.fix_entry()
        return (f"the write entries of {safe_domain} that may be this DC's are {', '.join(safe_names)}; "
                "the owner must use the same host text in both entries of a DC")


def _str(entry: dict[str, Any], key: str) -> str:
    value = entry.get(key)
    return value if isinstance(value, str) else ""


def _port(entry: dict[str, Any]) -> int:
    port = entry.get("port", 22)
    return port if isinstance(port, int) and not isinstance(port, bool) else 22


def _stem(name: str) -> str:
    return name[:-4] if name.endswith("-ops") else name


def _norm_host(host: str) -> str:
    """The text that pairs two entries: lowercase, one trailing dot removed."""
    lowered = host.lower()
    return lowered[:-1] if lowered.endswith(".") else lowered


def _is_ip_literal(host: str) -> bool:
    """True when the host text is an IP address rather than a name."""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _known_hosts_has(path: Path, host: str, port: int) -> bool:
    target = host if port == 22 else f"[{host}]:{port}"
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("@"):
            continue
        fields = line.split()
        if len(fields) < 3:
            continue
        for pattern in fields[0].split(","):
            if pattern.startswith("|1|"):
                parts = pattern.split("|")
                if len(parts) != 4:
                    continue
                try:
                    salt = base64.b64decode(parts[2], validate=True)
                    want = base64.b64decode(parts[3], validate=True)
                except ValueError:
                    continue
                got = hmac.new(salt, target.encode(), hashlib.sha1).digest()
                if hmac.compare_digest(got, want):
                    return True
            elif pattern.lower() == target.lower():
                return True
    return False


def _entry_problem(name: str, entry: Any) -> str | None:
    """What is wrong with this entry, or None.

    The grammars are the loader's own (``server.load_inventory``): a
    device name, a platform, a host, a user, a port and the two file
    paths.  The doctor keeps its own scan because the loader stops at
    the first bad entry and the doctor names every one of them; the
    loader's own verdict is what the doctor asks about the inventory as
    a whole (see ``_ask_the_loader``).
    """
    if not isinstance(name, str) or DEVICE_NAME_RE.fullmatch(name) is None:
        return ("the device name is not lowercase letters, digits and hyphens that start with a letter")
    if not isinstance(entry, dict):
        return "the entry is not a table"
    platform = entry.get("platform")
    if not isinstance(platform, str) or platform not in registry.PLATFORMS:
        return f"the platform {platform!r} is not one Newton supports"
    if platform in AD_PLATFORMS:
        host = entry.get("host")
        if not isinstance(host, str) or not host:
            return "the host is missing"
        if HOST_RE.fullmatch(host) is None:
            return ("the host fails the hostname grammar (letters, digits, '.', ':' and '-', starting with "
                    "a letter or digit)")
        user = entry.get("user")
        if not isinstance(user, str) or not user:
            return "the user is missing"
        if user_grammar(platform).fullmatch(user) is None:
            return "the user fails the username grammar"
        port = entry.get("port", 22)
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            return "the port must be 1..65535"
        for field in ("key_file", "known_hosts"):
            value = entry.get(field)
            if value is None or value == "":
                continue
            if isinstance(value, str) and (value in PLACEHOLDERS
                                           or (value.startswith("<") and value.endswith(">"))):
                # the doctor names the placeholder itself, with the
                # command that replaces it
                continue
            if not isinstance(value, str) or INVENTORY_PATH_RE.fullmatch(value) is None:
                return f"the {field} must be a path of [A-Za-z0-9_./-]"
    return None


def load_inventory(path: Path) -> dict[str, Any]:
    """The loader Newton itself uses, asked about one inventory.

    This is the doctor's only way to judge the inventory: it never
    decides on its own whether Newton loads the file, it asks the
    loader that Newton uses.  The name is a seam of its own, so the
    call can be replaced in a test.
    """
    return server.load_inventory(path=path)


def _ask_the_loader(inventory: Path) -> tuple[str, str]:
    """What the loader Newton itself uses says about this inventory.

    "loaded" when the loader accepts the inventory, "refused" with the
    loader's own message when it refuses it (Newton then loads no
    device from it), and "unexpected" with the text of an error the
    loader did not expect: such an error is no verdict at all.
    """
    try:
        load_inventory(inventory)
    except NewtonError as exc:
        return "refused", str(exc)
    except Exception as exc:  # an error the loader did not expect is no verdict
        return "unexpected", f"{type(exc).__name__}: {exc}"
    return "loaded", ""


def _refused_entries(message: str) -> list[str]:
    """The entry the loader's refusal names, when it names exactly one.

    The loader stops at the first entry it refuses, so its message
    names that entry.  The doctor reads the name only to fold the
    refusal into the finding it made for the entry itself, so that one
    refusal is not printed twice; a name it cannot read leaves the
    refusal on a line of its own.
    """
    for pattern in _REFUSAL_NAMES:
        found = pattern.match(message)
        if found is not None:
            return [found.group(1)]
    return []


class _Entries(NamedTuple):
    """What the doctor reads of the inventory's own table."""

    entries: dict[str, dict[str, Any]]   # the AD entries it can read
    problems: dict[str, str]             # the entries it found wrong
    raw: dict[str, Any]                  # every entry of the file
    broken: bool                         # the [devices] table itself is wrong


def _load_entries(c: _Checker, data: dict[str, Any]) -> _Entries:
    """The AD entries the doctor can read, the entries it refuses, and the file's own table."""
    raw = data.get("devices")
    if raw is None:
        if "device" in data:
            c.fail("ad-inventory", "",
                   "the inventory has a top-level [device] table; Newton reads the entries of [devices].",
                   c.fix_inventory())
            return _Entries({}, {}, {}, True)
        return _Entries({}, {}, {}, False)
    if not isinstance(raw, dict):
        c.fail("ad-inventory", "",
               "the [devices] table of the inventory is not a table; Newton loads no device until it is fixed.",
               c.fix_inventory())
        return _Entries({}, {}, {}, True)
    entries: dict[str, dict[str, Any]] = {}
    problems: dict[str, str] = {}
    for name, entry in raw.items():
        problem = _entry_problem(name, entry)
        if problem is not None:
            problems[name] = problem
            continue
        if entry["platform"] in AD_PLATFORMS:
            entries[name] = entry
    return _Entries(entries, problems, raw, False)


def _check_key_file(c: _Checker, name: str, entry: dict[str, Any], key_name: str) -> None:
    family = "ad-key-file"
    value = entry.get("key_file")
    keygen = c.keygen(name, key_name)
    if not isinstance(value, str) or not value:
        c.fail(family, name, "key_file is not set.", keygen)
        return
    if value in PLACEHOLDERS or (value.startswith("<") and value.endswith(">")):
        c.fail(family, name, "key_file is still the placeholder the setup printed.", keygen)
        return
    path = Path(value)
    try:
        info = path.lstat()
    except FileNotFoundError:
        c.fail(family, name, f"key_file {value} not found.", keygen)
        return
    except OSError as exc:
        c.emit("INCONCLUSIVE", family, name, f"key_file {value} cannot be inspected: {exc.strerror}.")
        return
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        c.fail(family, name, f"key_file {value} must be a regular file, not a symlink.", keygen)
        return
    if info.st_uid != c.owner_uid:
        c.fail(family, name, f"key_file {value} is owned by uid {info.st_uid}, not by the account that runs Newton (uid {c.owner_uid}).",
               c.chown(value))
        return
    if stat.S_IMODE(info.st_mode) != 0o600:
        c.fail(family, name, f"key_file {value} has mode {stat.S_IMODE(info.st_mode):04o}; it must be 0600.",
               c.chmod(value, "600"))


def _check_known_hosts(c: _Checker, name: str, entry: dict[str, Any]) -> None:
    family = "ad-known-hosts"
    value = entry.get("known_hosts")
    host = _str(entry, "host")
    scan = c.scan(name, host)
    if not isinstance(value, str) or not value:
        c.fail(family, name, "known_hosts is not set.", scan)
        return
    if value in PLACEHOLDERS or (value.startswith("<") and value.endswith(">")):
        c.fail(family, name, "known_hosts is still the placeholder the setup printed.", scan)
        return
    path = Path(value)
    try:
        info = path.lstat()
    except FileNotFoundError:
        c.fail(family, name, f"known_hosts {value} not found.", scan)
        return
    except OSError as exc:
        c.emit("INCONCLUSIVE", family, name, f"known_hosts {value} cannot be inspected: {exc.strerror}.")
        return
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        c.fail(family, name, f"known_hosts {value} must be a regular file, not a symlink.", scan)
        return
    if info.st_uid != c.owner_uid:
        c.fail(family, name, f"known_hosts {value} is owned by uid {info.st_uid}, not by the account that runs Newton (uid {c.owner_uid}).",
               c.chown(value))
        return
    if info.st_mode & 0o022:
        c.fail(family, name, f"known_hosts {value} is writable by group or others, so a pinned host key could be swapped.",
               c.chmod(value, "go-w"))
        return
    try:
        found = _known_hosts_has(path, host, _port(entry))
    except OSError as exc:
        c.emit("INCONCLUSIVE", family, name, f"known_hosts {value} cannot be read: {exc.strerror}.")
        return
    if not found:
        c.fail(family, name, f"known_hosts {value} holds no key for the host {host}.", scan)


def _check_links(c: _Checker, entries: dict[str, dict[str, Any]], raw: dict[str, Any],
                 problems: dict[str, str]) -> dict[str, dict[str, Any]]:
    """Check 1 and the one-domain-device rule.  Returns the domain devices.

    ``raw`` holds every entry of the file and ``problems`` the ones the
    doctor found wrong, so that an ``ad_domain`` naming an entry of the
    file that Newton does not load is not called an entry the inventory
    does not hold.
    """
    family = "ad-domain-link"
    for name, entry in entries.items():
        if entry.get("platform") not in WRITE_PLATFORMS:
            continue
        target_name = entry.get("ad_domain")
        fix = c.edit(name, "set ad_domain to the name of the write entry that stands for the domain, the PDC emulator's")
        if not isinstance(target_name, str) or not target_name:
            c.fail(family, name, "ad_domain is not set.", fix)
            continue
        target = entries.get(target_name)
        if target is None:
            if target_name in problems:
                c.fail(family, name,
                       f"ad_domain names {target_name}, which is in the inventory but which Newton does not load.",
                       fix)
            elif target_name in raw:
                c.fail(family, name, f"ad_domain names {target_name}, which is not an AD write entry.", fix)
            else:
                c.fail(family, name, f"ad_domain names {target_name}, which the inventory does not hold.", fix)
            continue
        if target.get("platform") not in WRITE_PLATFORMS:
            c.fail(family, name, f"ad_domain names {target_name}, which is not an AD write entry.", fix)
            continue
        if target.get("ad_domain") != target_name:
            c.fail(family, name,
                   f"ad_domain names {target_name}, which is itself a write entry of {target.get('ad_domain')!s}; "
                   "the entry that stands for a domain names itself.", fix)
            continue
        mine, theirs = _str(entry, "domain").lower(), _str(target, "domain").lower()
        if mine and theirs and mine != theirs:
            c.fail(family, name, f"domain {_str(entry, 'domain')} is not the domain of {target_name} ({_str(target, 'domain')}).",
                   c.edit(name, "set domain and ad_domain to one domain's values"))
    heads = {
        n: e for n, e in entries.items()
        if e.get("platform") in WRITE_PLATFORMS and e.get("ad_domain") == n
    }
    seen: dict[str, list[str]] = {}
    for name, entry in heads.items():
        dns = _str(entry, "domain").lower()
        if not dns:
            continue
        for other in seen.setdefault(dns, []):
            ga, gb = _str(heads[other], "ad_domain_guid"), _str(entry, "ad_domain_guid")
            if ga and gb and ga != gb:
                continue  # two one-DC domains of two forests
            c.fail("ad-domain-device", dns,
                   f"{other} and {name} both stand for the domain {_str(entry, 'domain')}; a domain has exactly one domain device.",
                   "re-run the setup of the second DC naming the first: "
                   + c.setup_line(_str(entry, "platform"), True, _str(entry, "domain"), name,
                                  _str(entry, "host"), other)
                   + f", then {c.edit_other(name, other, 'set ad_domain to')}")
        seen[dns].append(name)
    return heads


def _check_coverage(c: _Checker, entries: dict[str, dict[str, Any]], *,
                    can_tell: bool, reason: str, file_names: frozenset[str]) -> None:
    """Check the pairing of every DC's audit entry and its write entry.

    ``can_tell`` is false when the inventory does not load: that entry
    could be the write entry of a DC, so the doctor cannot say that a
    DC has none, nor that a write entry has no audit entry.  It says
    instead that the pairing cannot be judged until the inventory loads.
    ``reason`` says why: the inventory does not load, or the loader's
    verdict was an error it did not expect, so the inventory could not
    be judged.

    ``file_names`` holds every entry of the file, so a setup command
    that would replace one of them is never printed.
    """
    family = "ad-read-coverage"
    reads = {n: e for n, e in entries.items() if e.get("platform") in READ_PLATFORMS}
    writes = {n: e for n, e in entries.items() if e.get("platform") in WRITE_PLATFORMS}

    def key(entry: dict[str, Any]) -> tuple[str, str]:
        return _str(entry, "domain").lower(), _norm_host(_str(entry, "host"))

    write_keys = {key(e) for e in writes.values()}
    read_keys = {key(e) for e in reads.values()}
    audit_only: set[str] = set()
    claimed: set[str] = set()
    for name, entry in reads.items():
        dns = _str(entry, "domain")
        domain_writes = [(n, w) for n, w in writes.items()
                         if _str(w, "domain").lower() == dns.lower()]
        if not domain_writes:
            if dns.lower() not in audit_only:
                audit_only.add(dns.lower())
                if can_tell:
                    c.emit("INFO", family, dns, "the domain has audit entries only, so changes are off for it (audit only).")
                else:
                    c.emit("INCONCLUSIVE", family, dns,
                           f"the domain {dns} has audit entries, but {reason}, so the doctor "
                           f"cannot tell whether it has a write entry; {NOT_JUDGED}.")
            continue
        if key(entry) in write_keys:
            continue
        if not can_tell:
            # the inventory does not load: the doctor makes no claim
            # about a pairing at all, not even an IP-versus-name one
            c.emit("INCONCLUSIVE", family, name,
                   f"this DC of {dns} has an audit entry but no write entry; {reason}, so the "
                   f"doctor cannot tell whether the write entry of this DC is in it; {NOT_JUDGED}.")
            continue
        host = _str(entry, "host")
        # the IP-versus-name test looks at every write entry of the
        # domain, paired or not: a write entry of the other kind may be
        # this DC's, even when another audit entry pairs with it.
        candidates = [(n, w) for n, w in domain_writes
                      if _is_ip_literal(key(entry)[1]) != _is_ip_literal(key(w)[1])]
        if candidates:
            claimed.update(n for n, _ in candidates)
            names = ", ".join(n for n, _ in candidates)
            c.emit("INCONCLUSIVE", family, name,
                   f"the audit entry {name} ({host}) and the write entries {names} of {dns} may be the same DC of "
                   f"{dns}, but one gives an IP address and the other a name, so the pairing could not be confirmed "
                   "here (no name is resolved).",
                   c.pair_step(dns, [n for n, _ in candidates]))
            continue
        new_device = f"{name}-ops"
        if new_device in file_names:
            # the setup command would replace that entry of the file
            step = c.fix_entry()
        else:
            head = next((_str(w, "ad_domain") for _, w in domain_writes if _str(w, "ad_domain")), None)
            step = c.setup_line(_str(entry, "platform"), True, dns, new_device, host, head)
            step += (", run the script on the DC, then add the printed entry to "
                     f"{c.inventory_path() or 'the inventory'}")
        c.fail(family, name,
               f"this DC of {dns} has an audit entry but no write entry, so it is never read back after a change "
               "(a change can be confirmed while it differs there).",
               step)
    for name, entry in writes.items():
        if key(entry) in read_keys:
            continue
        if name in claimed:
            # an audit entry of this domain could be this entry: the
            # doctor does not claim that the write entry has no audit entry
            continue
        host = _str(entry, "host")
        if not can_tell:
            c.emit("INCONCLUSIVE", family, name,
                   f"{host} has a write entry, but {reason}, so the doctor cannot tell whether "
                   f"it has an audit entry; {NOT_JUDGED}.")
            continue
        c.emit("INFO", family, name,
               f"{host} has a write entry but no audit entry, so the audit cannot read this DC (changes do not need one).",
               c.setup_line(_str(entry, "platform").removesuffix("-write"), False,
                            _str(entry, "domain"), f"{_stem(name)}-audit", host, None))


def _check_fingerprints(c: _Checker, entries: dict[str, dict[str, Any]], heads: dict[str, dict[str, Any]]) -> None:
    family = "ad-approval-fingerprint"
    for name in heads:
        path = c.state_dir / "approval-fp" / name
        command = c.approval_key(name)
        try:
            text = path.read_text(encoding="ascii")
        except FileNotFoundError:
            c.fail(family, name, "no approval-key fingerprint is recorded on this host for the domain device.", command)
            continue
        except (OSError, UnicodeDecodeError) as exc:
            c.emit("INCONCLUSIVE", family, name, f"{path} cannot be read: {getattr(exc, 'strerror', None) or 'not ascii'}.")
            continue
        match = _FP_RE.fullmatch(text.strip())
        if match is None:
            c.fail(family, name, f"{path} is not a recorded fingerprint (v1 and 64 hex characters).", command)
            continue
        others = [n for n, e in entries.items()
                  if e.get("platform") in WRITE_PLATFORMS and e.get("ad_domain") == name]
        c.emit("INFO", family, name,
               f"the host records the fingerprint {match.group(1)}. Nothing records what each DC printed, so compare it "
               f"yourself: the setup of each DC ({', '.join(others)}) ended with 'The approval key is installed. "
               "Its fingerprint is ...'; every one must equal this value.")


def check(*, inventory: Path, state_dir: Path, setup_command: str,
          owner_uid: int, expect_user: str | None) -> Report:
    report = Report()
    c = _Checker(inventory, state_dir, setup_command, owner_uid)
    if expect_user is not None:
        try:
            who = pwd.getpwuid(os.geteuid()).pw_name
        except KeyError:
            who = str(os.geteuid())
        if who != expect_user:
            report.exit_code = 2
            report.lines.append(
                f"ERROR ad: run as the account that owns the keys and the inventory ({_escape(expect_user)}), "
                f"not {_escape(who)}. Next: {_escape_bytes(c.sudo_user(expect_user))}"
            )
            return report
    try:
        data = tomllib.loads(inventory.read_text(encoding="utf-8"))
    except FileNotFoundError:
        c.fail("ad-inventory", "", f"the inventory {inventory} does not exist.",
               "docs/INSTALL.md step 7 adds the first device")
        data = None
    except (OSError, ValueError) as exc:
        c.fail("ad-inventory", "", f"the inventory {inventory} cannot be read: {exc}",
               c.fix_inventory())
        data = None
    entries: dict[str, dict[str, Any]] = {}
    problems: dict[str, str] = {}
    raw: dict[str, Any] = {}
    broken = False
    if data is not None:
        found = _load_entries(c, data)
        entries, problems, raw, broken = found
    # what Newton itself makes of this inventory: the loader is the
    # authority, the doctor's own scan only adds findings
    verdict, message = "unreadable", ""
    if data is not None:
        verdict, message = _ask_the_loader(inventory)
    loaded = verdict == "loaded"
    # why the doctor cannot judge a pairing: the inventory does not load,
    # or the loader's verdict was an error it did not expect, so the
    # inventory could not be judged.  The doctor never says the second
    # when it means the first.
    reason = REFUSED_REASON if verdict == "refused" else UNJUDGED_REASON
    refusal: dict[str, str] = {}
    refusal_step: dict[str, str] = {}
    if verdict == "refused":
        named = _refused_entries(message)
        covered = [n for n in named if n in problems]
        if named and len(covered) == len(named):
            # the loader refused an entry the doctor found wrong too:
            # one refusal, one finding
            for name in covered:
                refusal[name] = f"{NO_DEVICE}: {message}"
                # the owner fixes what this run names for that entry
                # first, then the one fixed line that edits it
                safe_name = _safe(name, DEVICE_NAME_RE)
                if safe_name is None:
                    refusal_step[name] = c.fix_entry()
                else:
                    refusal_step[name] = (f"fix the findings this run names for {safe_name} first, "
                                          f"then {c.fix_entry()}")
        else:
            c.fail("ad-inventory", "", f"{NO_DEVICE}: {message}", c.fix_inventory())
    elif verdict == "unexpected":
        c.emit("INCONCLUSIVE", "ad-inventory", "",
               f"the inventory could not be judged: {message}; the doctor cannot say whether Newton loads it.")
    for name, defect in problems.items():
        text = f"{defect}; Newton loads no device until this entry is fixed"
        if name in refusal:
            text += f". {refusal[name]}"
        c.fail("ad-inventory", name, text, refusal_step.get(name, c.fix_entry()))
    # the doctor can name a pairing only when the inventory loads: an
    # entry Newton does not load could be the write entry of a DC
    can_tell = loaded and not problems
    if data is not None and not entries and not problems and not broken and loaded:
        c.emit("INFO", "ad", "", "the inventory holds no Active Directory entries; nothing to check.")
    if entries:
        heads = _check_links(c, entries, raw, problems)
        _check_coverage(c, entries, can_tell=can_tell, reason=reason, file_names=frozenset(raw))
        for name, entry in entries.items():
            write = entry.get("platform") in WRITE_PLATFORMS
            _check_key_file(c, name, entry, name if write else f"{_stem(name)}-audit")
            _check_known_hosts(c, name, entry)
        _check_fingerprints(c, entries, heads)
        if loaded:
            # an inventory Newton does not load is not judged: the
            # checks above ran on the entries the doctor could read, so
            # no family is a PASS
            for family in _FAMILIES:
                if not any(f == family and lvl in ("FAIL", "INCONCLUSIVE") for lvl, f, _ in c.out):
                    c.out.append(("PASS", family, f"PASS {family}"))
    report.lines = [text for _, _, text in c.out]
    report.summary = (
        f"ad: {c.fails} finding(s), {c.inconclusive} inconclusive, {c.notes} note(s)"
    )
    report.exit_code = 1 if c.fails else 3 if c.inconclusive else 0
    return report


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="newton-doctor ad", add_help=False)
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--setup-command", required=True)
    parser.add_argument("--expect-user")
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        print("usage: newton-doctor ad", file=sys.stderr)
        return 2
    report = check(
        inventory=Path(args.inventory), state_dir=Path(args.state_dir),
        setup_command=args.setup_command, owner_uid=os.geteuid(),
        expect_user=args.expect_user,
    )
    for line in report.lines:
        print(line)
    if report.summary:
        print(report.summary)
    return report.exit_code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
