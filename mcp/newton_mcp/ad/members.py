"""Recursive, cycle-safe membership from the directory data.

Privilege is computed by SID and RID, never by name: a renamed or
localized group is still the same group, and a group Newton cannot read
the name of is still privileged.

The resolver walks the ``member`` values of the groups and the
``primaryGroupID`` of the principals.  The primary group is a real
membership that no ``member`` traversal shows, and it is how an account
can be a Domain Admin without being in the member list of the group.

The walk is cycle-safe: a group that is a member of itself, directly or
through other groups, is visited once.  A cycle in a directory is a real
thing (AD-A-03), not a broken directory.

A member value that names no object of the document is a hidden member:
the group holds a principal the audit cannot see.  The walk records those
values (``unresolved_members``), so a check that reads such a group knows
that it cannot prove anything.  A foreign security principal is a row of
the document, so a member that names one is resolved.

The privileged set is the one of section 8: the domain RIDs 512, 516,
518, 519, 520, 521, 498, 526 and 527, the BUILTIN groups S-1-5-32-544,
548, 549, 550 and 551, and everything nested in any of them.
"""

from __future__ import annotations

from dataclasses import dataclass

from .values import dn_key, rid_in_domain, sid_from_base64
from .wire import Document, Row


KIND_USER = "user"
KIND_COMPUTER = "computer"
KIND_GROUP = "group"
KIND_FSP = "fsp"

# The privileged groups of a domain, by RID.
DOMAIN_PRIVILEGED_RIDS: tuple[int, ...] = (512, 516, 518, 519, 520, 521, 498, 526, 527)

# The privileged groups of BUILTIN.
BUILTIN_PRIVILEGED_SIDS: tuple[str, ...] = (
    "S-1-5-32-544",
    "S-1-5-32-548",
    "S-1-5-32-549",
    "S-1-5-32-550",
    "S-1-5-32-551",
)


@dataclass(frozen=True)
class Principal:
    """One object of the directory, by SID."""

    sid: str
    dn: str
    name: str | None
    kind: str
    primary_group_id: int | None
    members: tuple[str, ...]


class Directory:
    """The principals of one collector document, indexed by DN and SID."""

    def __init__(self, document: Document) -> None:
        self.domain_sid = _domain_sid(document)
        self.principals: dict[str, Principal] = {}
        self.by_dn: dict[str, Principal] = {}
        self.groups: dict[str, Principal] = {}
        self._primary_members: dict[str, list[str]] = {}
        self._direct_groups: dict[str, set[str]] = {}
        self._walks: dict[str, tuple[frozenset[str], tuple[str, ...]]] = {}
        self._load(document)

    # ---- building ---------------------------------------------------------

    def _load(self, document: Document) -> None:
        for query_id, kind in (
            ("users", KIND_USER),
            ("computers", KIND_COMPUTER),
            ("groups", KIND_GROUP),
            ("fsps", KIND_FSP),
        ):
            result = document.queries.get(query_id)
            if result is None:
                continue
            for row in result.rows:
                principal = _principal(row, kind)
                if principal is None:
                    continue
                self.principals[principal.sid] = principal
                self.by_dn.setdefault(dn_key(principal.dn), principal)
                if principal.kind == KIND_GROUP:
                    self.groups[principal.sid] = principal

        # The groups that hold a principal directly, and the principals
        # whose primary group is a group of this domain.
        for group in self.groups.values():
            for member_dn in group.members:
                member = self.by_dn.get(dn_key(member_dn))
                if member is None:
                    continue
                self._direct_groups.setdefault(member.sid, set()).add(group.sid)

        for principal in self.principals.values():
            if principal.primary_group_id is None:
                continue
            if rid_in_domain(principal.sid, self.domain_sid) is None:
                # The primary group of a principal of another domain is
                # a group of that domain: it is not a group of this one.
                continue
            primary_sid = f"{self.domain_sid}-{principal.primary_group_id}"
            self._primary_members.setdefault(primary_sid, []).append(principal.sid)
            self._direct_groups.setdefault(principal.sid, set()).add(primary_sid)

    # ---- reading ----------------------------------------------------------

    def principal(self, sid: str) -> Principal | None:
        """The principal with that SID, when the document holds one."""
        return self.principals.get(sid)

    def privileged_group_sids(self) -> set[str]:
        """The privileged groups themselves: the domain RIDs and BUILTIN."""
        sids = {
            f"{self.domain_sid}-{rid}" for rid in DOMAIN_PRIVILEGED_RIDS
        }
        sids.update(BUILTIN_PRIVILEGED_SIDS)
        return sids

    def _walk(self, group_sid: str) -> tuple[frozenset[str], tuple[str, ...]]:
        """The members of the group and the member values that named nothing.

        The walk visits every group once, so a cycle ends the walk.  A
        member value that names no object of the document is a hidden
        member: the group holds a principal the audit cannot see.  The
        second part of the result holds the distinguished names of those
        values; a report counts them and never shows them.
        """
        cached = self._walks.get(group_sid)
        if cached is not None:
            return cached
        found: set[str] = set()
        unresolved: list[str] = []
        visited: set[str] = set()
        stack: list[str] = [group_sid]
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            group = self.groups.get(current)
            if group is not None:
                for member_dn in group.members:
                    member = self.by_dn.get(dn_key(member_dn))
                    if member is None:
                        unresolved.append(member_dn)
                        continue
                    if member.sid not in found:
                        found.add(member.sid)
                        if member.kind == KIND_GROUP:
                            stack.append(member.sid)
            for sid in self._primary_members.get(current, ()):
                if sid not in found:
                    found.add(sid)
        result = (frozenset(found), tuple(dict.fromkeys(unresolved)))
        self._walks[group_sid] = result
        return result

    def members_recursive(self, group_sid: str) -> set[str]:
        """Every SID that is a member of the group, directly or not.

        The group itself is not in the result.  A group nested in the
        group is in the result, and so is everything nested in that one.
        The walk visits every group once, so a cycle ends the walk.  A
        member value that names no object of the document is not a
        member: ``unresolved_members`` counts those.
        """
        found, _ = self._walk(group_sid)
        return set(found)

    def unresolved_members(self, group_sid: str) -> tuple[str, ...]:
        """The member values of the group that named no object.

        The values are the distinguished names of the members the audit
        cannot see.  A privileged group that holds one of them hides a
        principal, so a check that reads such a group cannot prove
        anything and says so.  The names are for the resolver; a report
        counts them and never shows them.
        """
        _, unresolved = self._walk(group_sid)
        return unresolved

    def groups_of(self, sid: str) -> set[str]:
        """Every group the SID belongs to, directly or through a group.

        The primary group is one of them: it is a membership no
        ``member`` value shows.
        """
        found: set[str] = set(self._direct_groups.get(sid, ()))
        visited: set[str] = set()
        stack = list(found)
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            for parent in self._direct_groups.get(current, ()):
                if parent not in found:
                    found.add(parent)
                    stack.append(parent)
        return found

    def privileged_set(self) -> set[str]:
        """The privileged groups and everything nested in them."""
        result: set[str] = set()
        for group_sid in self.privileged_group_sids():
            result.add(group_sid)
            result |= self.members_recursive(group_sid)
        return result

    def is_privileged(self, sid: str) -> bool:
        """True when the SID is in the privileged set."""
        return sid in self.privileged_set()


def _domain_sid(document: Document) -> str:
    """The SID of the domain the document is about."""
    sid = document.domain.domain_sid
    return sid if isinstance(sid, str) else ""


def _principal(row: Row, kind: str) -> Principal | None:
    """The principal of one row, when the row carries a usable SID."""
    attributes = row.a
    dn = row.dn
    if not isinstance(attributes, dict) or not isinstance(dn, str):
        return None
    sid_values = attributes.get("objectSid")
    if not sid_values:
        return None
    try:
        sid = sid_from_base64(sid_values[0])
    except ValueError:
        return None
    name_values = attributes.get("sAMAccountName")
    name = name_values[0] if name_values else None
    primary_group_id: int | None = None
    primary_values = attributes.get("primaryGroupID")
    if primary_values:
        try:
            primary_group_id = int(primary_values[0])
        except ValueError:
            primary_group_id = None
    members = tuple(attributes.get("member", ()))
    return Principal(
        sid=sid,
        dn=dn,
        name=name,
        kind=kind,
        primary_group_id=primary_group_id,
        members=members,
    )
