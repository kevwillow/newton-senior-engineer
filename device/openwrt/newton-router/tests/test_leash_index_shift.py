"""fail-safe: the leash must not trust `@TYPE[N]`
selector lines when the same batch also holds a structural line of that
type (delete, add, rename or reorder), because the selector index may
then refer to a different section in the staged view than in the
committed view. The program fires `leash section-unidentified` per
(config, type) when at least one selector line and one structural line
of the same type coexist in the same batch.

Tests build by hand with the `Raw` helper (the same shape the leash uci
fake serves). `seal_lines` returns the set of leash lines and the
approval line so individual tests can check the exact (code, where)
set the program produces.
"""
from types import SimpleNamespace


class Raw:
    """A minimal `Scenario`-shaped object for `router.sealed_scenario`."""

    def __init__(self, changes, staged, committed, full_firewall=(), profile="lab", zones=None):
        self.profile = profile
        self.zones = zones or {"mgmt-interface": "lan", "mgmt-zone": "lan", "wan-zone": ["wan"]}
        built = dict(changes=changes, staged=staged, committed=committed, full_firewall=list(full_firewall))
        self._built = built

    def build(self):
        return self._built


def seal_lines(router, scn):
    """Run seal on `scn` and return (codes_set, codes_with_where, approval_line)."""
    router.use_leash_uci()
    res = router.sealed_scenario(scn)
    assert (res.rc, res.err) == (0, ""), (res.rc, res.err, res.out)
    leash = [l[len("leash "):] for l in res.out.splitlines() if l.startswith("leash ")]
    pairs = set()
    for entry in leash:
        code, where = entry.split(" ", 1)
        pairs.add((code, where))
    codes = {c for c, _ in pairs}
    approval = [l for l in res.out.splitlines() if l.startswith("approval ")]
    return pairs, codes, approval


def test_delete_then_set_same_selector_is_section_unidentified(router):
    changes = [
        "-firewall.@zone[0]",
        "firewall.@zone[0].output='DROP'",
    ]
    staged = {"firewall.@zone[0]": [
        "firewall.cfglan=zone",
        "firewall.cfglan.name='lan'",
        "firewall.cfglan.output='DROP'",
    ]}
    committed = {"firewall.@zone[0]": [
        "firewall.cfgguest=zone",
        "firewall.cfgguest.name='guest'",
        "firewall.cfgguest.input='REJECT'",
    ]}
    pairs, codes, approval = seal_lines(router, Raw(changes, staged, committed))
    assert ("section-unidentified", "firewall.cfgguest") in pairs, pairs
    assert approval == ["approval required"]


def test_selector_set_plus_delete_by_name_of_same_type_is_section_unidentified(router):
    changes = [
        "firewall.@zone[1].input='ACCEPT'",
        "-firewall.cfgguest",
    ]
    committed_cfgguest = [
        "firewall.cfgguest=zone",
        "firewall.cfgguest.name='guest'",
    ]
    committed = {
        "firewall.cfgguest": committed_cfgguest,
        "firewall.@zone[1]": [
            "firewall.cfglan=zone",
            "firewall.cfglan.name='lan'",
            "firewall.cfglan.input='ACCEPT'",
        ],
    }
    pairs, codes, approval = seal_lines(router, Raw(changes, {}, committed))
    assert any(c == "section-unidentified" for c in codes), pairs
    assert approval == ["approval required"]


def test_selector_set_plus_add_of_same_type_is_section_unidentified(router):
    changes = [
        "firewall.cfgnew=zone",
        "firewall.@zone[1].input='ACCEPT'",
    ]
    staged = {
        "firewall.cfgnew": [
            "firewall.cfgnew=zone",
            "firewall.cfgnew.name='new'",
        ],
        "firewall.@zone[1]": [
            "firewall.cfglan=zone",
            "firewall.cfglan.name='lan'",
            "firewall.cfglan.input='ACCEPT'",
        ],
    }
    pairs, codes, approval = seal_lines(router, Raw(changes, staged, {}))
    assert any(c == "section-unidentified" for c in codes), pairs
    assert approval == ["approval required"]


def test_lone_delete_by_selector_does_not_fire(router):
    changes = ["-firewall.@rule[3]"]
    committed = {"firewall.@rule[3]": [
        "firewall.cfgrule3=rule",
        "firewall.cfgrule3.name='r'",
        "firewall.cfgrule3.src='wan'",
        "firewall.cfgrule3.proto='tcp'",
        "firewall.cfgrule3.dest_port='23'",
        "firewall.cfgrule3.target='REJECT'",
    ]}
    pairs, codes, _ = seal_lines(router, Raw(changes, {}, committed))
    assert not any(c == "section-unidentified" for c in codes), pairs


def test_selector_sets_only_do_not_fire(router):
    changes = [
        "firewall.@rule[0].enabled='0'",
        "firewall.@rule[3].name='x'",
    ]
    committed = {
        "firewall.@rule[0]": [
            "firewall.cfgrule0=rule",
            "firewall.cfgrule0.enabled='0'",
        ],
        "firewall.@rule[3]": [
            "firewall.cfgrule3=rule",
            "firewall.cfgrule3.name='x'",
        ],
    }
    pairs, codes, _ = seal_lines(router, Raw(changes, {}, committed))
    assert not any(c == "section-unidentified" for c in codes), pairs


def test_other_type_structural_line_does_not_fire(router):
    changes = [
        "firewall.@zone[1].output='DROP'",
        "-firewall.cfgrule7",
    ]
    committed = {
        "firewall.@zone[1]": [
            "firewall.cfglan=zone",
            "firewall.cfglan.name='lan'",
            "firewall.cfglan.output='DROP'",
        ],
        "firewall.cfgrule7": [
            "firewall.cfgrule7=rule",
            "firewall.cfgrule7.name='r7'",
        ],
    }
    pairs, codes, _ = seal_lines(router, Raw(changes, {}, committed))
    assert not any(c == "section-unidentified" for c in codes), pairs


def test_control_direct_change_by_name_still_gives_mgmt_zone(router):
    changes = ["firewall.cfglan.output='DROP'"]
    cfglan_view = [
        "firewall.cfglan=zone",
        "firewall.cfglan.name='lan'",
        "firewall.cfglan.output='DROP'",
    ]
    staged = {"firewall.cfglan": cfglan_view}
    committed = {"firewall.cfglan": cfglan_view}
    pairs, codes, approval = seal_lines(router, Raw(changes, staged, committed))
    assert ("mgmt-zone", "firewall.cfglan") in pairs, pairs
    assert not any(c == "section-unidentified" for c in codes), pairs
    assert approval == ["approval required"]


def test_prod_profile_still_adds_profile_prod(router):
    changes = [
        "-firewall.@zone[0]",
        "firewall.@zone[0].output='DROP'",
    ]
    staged = {"firewall.@zone[0]": [
        "firewall.cfglan=zone",
        "firewall.cfglan.name='lan'",
        "firewall.cfglan.output='DROP'",
    ]}
    committed = {"firewall.@zone[0]": [
        "firewall.cfgguest=zone",
        "firewall.cfgguest.name='guest'",
        "firewall.cfgguest.input='REJECT'",
    ]}
    pairs, codes, approval = seal_lines(router, Raw(changes, staged, committed, profile="prod"))
    assert ("section-unidentified", "firewall.cfgguest") in pairs, pairs
    assert ("profile-prod", "-") in pairs, pairs
    assert approval == ["approval required"]
