"""The membership resolver: recursion, cycles, primary groups and FSPs."""

from __future__ import annotations

from newton_mcp.ad import members

import docs


ADMIN_SID = docs.ADMIN_SID
DOMAIN_ADMINS_SID = docs.DOMAIN_ADMINS_SID
USER_SID = f"{docs.DOMAIN_SID}-1107"
NESTED_SID = f"{docs.DOMAIN_SID}-1200"
OPERATORS_SID = f"{docs.DOMAIN_SID}-1201"
FSP_SID = "S-1-5-21-1111111111-2222222222-3333333333-1000"

ADMIN_DN = f"CN=Administrator,OU=People,{docs.DOMAIN_DN}"
USER_DN = f"CN=User,OU=People,{docs.DOMAIN_DN}"
NESTED_DN = f"CN=Nested,OU=Groups,{docs.DOMAIN_DN}"
OPERATORS_DN = f"CN=Operators,OU=Groups,{docs.DOMAIN_DN}"
FSP_DN = f"CN={FSP_SID},CN=ForeignSecurityPrincipals,{docs.DOMAIN_DN}"


def user_row(dn: str, sid: str, **attrs: object) -> dict:
    """One user row."""
    values: dict[str, object] = {"objectSid": sid_blob(sid)}
    values.update(attrs)
    return docs.row(dn, **values)


def group_row(dn: str, sid: str, member: list[str] | None = None) -> dict:
    """One group row."""
    values: dict[str, object] = {"objectSid": sid_blob(sid)}
    if member is not None:
        values["member"] = member
    return docs.row(dn, **values)


def sid_blob(sid: str) -> str:
    """The base64 of the binary SID."""
    return docs.sid_blob(sid)


def test_a_direct_member_is_found() -> None:
    """A member of the group is in the group."""
    directory = members.Directory(
        docs.parsed(
            groups=[group_row(OPERATORS_DN, OPERATORS_SID, [USER_DN])],
            users=[user_row(USER_DN, USER_SID)],
        )
    )

    assert directory.members_recursive(OPERATORS_SID) == {USER_SID}


def test_a_nested_member_is_found() -> None:
    """The walk goes through the groups that are nested in the group."""
    directory = members.Directory(
        docs.parsed(
            groups=[
                group_row(OPERATORS_DN, OPERATORS_SID, [NESTED_DN]),
                group_row(NESTED_DN, NESTED_SID, [USER_DN]),
            ],
            users=[user_row(USER_DN, USER_SID)],
        )
    )

    assert directory.members_recursive(OPERATORS_SID) == {NESTED_SID, USER_SID}


def test_a_cycle_ends_the_walk() -> None:
    """Two groups that hold each other do not hang the resolver."""
    directory = members.Directory(
        docs.parsed(
            groups=[
                group_row(OPERATORS_DN, OPERATORS_SID, [NESTED_DN]),
                group_row(NESTED_DN, NESTED_SID, [OPERATORS_DN, USER_DN]),
            ],
            users=[user_row(USER_DN, USER_SID)],
        )
    )

    # The two groups hold each other, so each one is a member of the
    # other and the walk still ends.
    assert directory.members_recursive(OPERATORS_SID) == {
        NESTED_SID,
        USER_SID,
        OPERATORS_SID,
    }


def test_a_group_that_is_its_own_member_ends_the_walk() -> None:
    """A group that holds itself does not hang the resolver."""
    directory = members.Directory(
        docs.parsed(
            groups=[group_row(OPERATORS_DN, OPERATORS_SID, [OPERATORS_DN])],
        )
    )

    assert directory.members_recursive(OPERATORS_SID) == {OPERATORS_SID}


def test_a_primary_group_is_a_membership() -> None:
    """The primary group shows up even though no member value does."""
    directory = members.Directory(
        docs.parsed(
            groups=[group_row(OPERATORS_DN, OPERATORS_SID, [])],
            users=[
                user_row(
                    USER_DN,
                    USER_SID,
                    primaryGroupID=str(int(OPERATORS_SID.rsplit("-", 1)[1])),
                )
            ],
        )
    )

    assert directory.members_recursive(OPERATORS_SID) == {USER_SID}


def test_the_groups_of_a_principal_are_the_direct_and_the_nested_ones() -> None:
    """A group of a group is a group of the principal."""
    directory = members.Directory(
        docs.parsed(
            groups=[
                group_row(OPERATORS_DN, OPERATORS_SID, [NESTED_DN]),
                group_row(NESTED_DN, NESTED_SID, [USER_DN]),
            ],
            users=[user_row(USER_DN, USER_SID)],
        )
    )

    assert directory.groups_of(USER_SID) == {NESTED_SID, OPERATORS_SID}


def test_the_groups_of_a_principal_include_the_primary_group() -> None:
    """The primary group is one of the groups of the principal."""
    directory = members.Directory(
        docs.parsed(
            groups=[group_row(OPERATORS_DN, OPERATORS_SID, [])],
            users=[
                user_row(
                    USER_DN,
                    USER_SID,
                    primaryGroupID=str(int(OPERATORS_SID.rsplit("-", 1)[1])),
                )
            ],
        )
    )

    assert directory.groups_of(USER_SID) == {OPERATORS_SID}


def test_a_foreign_security_principal_is_indexed_by_its_sid() -> None:
    """An FSP is a principal with a foreign SID."""
    directory = members.Directory(
        docs.parsed(fsps=[docs.row(FSP_DN, objectSid=sid_blob(FSP_SID))])
    )

    principal = directory.principal(FSP_SID)
    assert principal is not None
    assert principal.kind == members.KIND_FSP


def test_the_privileged_set_holds_the_members_of_the_admin_groups() -> None:
    """A member of the Domain Admins group is in the privileged set."""
    directory = members.Directory(
        docs.parsed(
            groups=[group_row(OPERATORS_DN, DOMAIN_ADMINS_SID, [USER_DN])],
            users=[user_row(USER_DN, USER_SID)],
        )
    )

    assert USER_SID in directory.privileged_set()


def test_the_privileged_set_holds_the_nested_members() -> None:
    """A group inside the Domain Admins group brings its members."""
    directory = members.Directory(
        docs.parsed(
            groups=[
                group_row(OPERATORS_DN, DOMAIN_ADMINS_SID, [NESTED_DN]),
                group_row(NESTED_DN, NESTED_SID, [USER_DN]),
            ],
            users=[user_row(USER_DN, USER_SID)],
        )
    )

    assert USER_SID in directory.privileged_set()


def test_the_privileged_set_holds_a_primary_group_member() -> None:
    """An account whose primary group is Domain Admins is privileged."""
    directory = members.Directory(
        docs.parsed(
            groups=[group_row(OPERATORS_DN, DOMAIN_ADMINS_SID, [])],
            users=[user_row(USER_DN, USER_SID, primaryGroupID="512")],
        )
    )

    assert USER_SID in directory.privileged_set()


def test_the_privileged_set_does_not_hold_an_ordinary_user() -> None:
    """An ordinary account is not in the privileged set."""
    directory = members.Directory(
        docs.parsed(users=[user_row(USER_DN, USER_SID, primaryGroupID="513")])
    )

    assert USER_SID not in directory.privileged_set()


def test_the_privileged_groups_are_the_documented_ones() -> None:
    """The privileged groups are the RIDs of the spec and the BUILTIN ones."""
    directory = members.Directory(docs.parsed())

    groups = directory.privileged_group_sids()

    for rid in (512, 516, 518, 519, 520, 521, 498, 526, 527):
        assert f"{docs.DOMAIN_SID}-{rid}" in groups
    for sid in (
        "S-1-5-32-544",
        "S-1-5-32-548",
        "S-1-5-32-549",
        "S-1-5-32-550",
        "S-1-5-32-551",
    ):
        assert sid in groups


def test_the_privileged_set_holds_the_privileged_groups_themselves() -> None:
    """The set holds the groups and everything nested in them."""
    directory = members.Directory(docs.parsed())

    assert DOMAIN_ADMINS_SID in directory.privileged_set()
    assert "S-1-5-32-544" in directory.privileged_set()


def test_a_member_that_does_not_resolve_is_ignored() -> None:
    """A member value that names nothing is not a member."""
    directory = members.Directory(
        docs.parsed(
            groups=[
                group_row(OPERATORS_DN, OPERATORS_SID, [f"CN=Gone,{docs.DOMAIN_DN}"])
            ]
        )
    )

    assert directory.members_recursive(OPERATORS_SID) == set()


def test_a_member_that_does_not_resolve_is_an_unresolved_member() -> None:
    """A member value that names nothing is a hidden member."""
    gone = f"CN=Gone,{docs.DOMAIN_DN}"
    directory = members.Directory(
        docs.parsed(
            groups=[group_row(OPERATORS_DN, OPERATORS_SID, [gone])],
            users=[user_row(USER_DN, USER_SID)],
        )
    )

    assert directory.unresolved_members(OPERATORS_SID) == (gone,)
    assert directory.members_recursive(OPERATORS_SID) == set()


def test_a_nested_group_that_does_not_resolve_is_an_unresolved_member() -> None:
    """The walk counts the member values of the nested groups too."""
    gone = f"CN=Gone,{docs.DOMAIN_DN}"
    directory = members.Directory(
        docs.parsed(
            groups=[
                group_row(OPERATORS_DN, OPERATORS_SID, [NESTED_DN]),
                group_row(NESTED_DN, NESTED_SID, [gone]),
            ],
        )
    )

    assert directory.unresolved_members(OPERATORS_SID) == (gone,)


def test_a_foreign_security_principal_member_is_resolved() -> None:
    """A member value that names a foreign security principal resolves."""
    directory = members.Directory(
        docs.parsed(
            groups=[group_row(OPERATORS_DN, OPERATORS_SID, [FSP_DN])],
            fsps=[docs.row(FSP_DN, objectSid=sid_blob(FSP_SID))],
        )
    )

    assert directory.unresolved_members(OPERATORS_SID) == ()
    assert directory.members_recursive(OPERATORS_SID) == {FSP_SID}


def test_a_member_name_is_matched_without_regard_to_case() -> None:
    """A distinguished name is case-insensitive."""
    directory = members.Directory(
        docs.parsed(
            groups=[group_row(OPERATORS_DN, OPERATORS_SID, [USER_DN.upper()])],
            users=[user_row(USER_DN, USER_SID)],
        )
    )

    assert directory.members_recursive(OPERATORS_SID) == {USER_SID}


def test_a_row_without_a_sid_is_not_a_principal() -> None:
    """A row Newton cannot name is not a principal."""
    directory = members.Directory(
        docs.parsed(
            fsps=[
                docs.row(f"CN=Ghost,CN=ForeignSecurityPrincipals,{docs.DOMAIN_DN}")
            ]
        )
    )

    assert directory.principals == {}


def test_a_member_that_is_written_differently_is_the_same_member() -> None:
    """A distinguished name is one name, whatever it is written like."""
    directory = members.Directory(
        docs.parsed(
            groups=[
                group_row(
                    OPERATORS_DN,
                    OPERATORS_SID,
                    [f"CN=User, OU=People, {docs.DOMAIN_DN}"],
                )
            ],
            users=[user_row(USER_DN, USER_SID)],
        )
    )

    assert directory.members_recursive(OPERATORS_SID) == {USER_SID}
