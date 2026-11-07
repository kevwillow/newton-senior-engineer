"""Extra leash scenarios the corpus lacks.

Each scenario is a (name, committed_config, ops, expect, profile, zones) tuple replayed
through `seal` in two naming modes (`index`, `id`). The test asserts the program's leash
code set EQUALS `expect` (exact), matches the model's `scn.expected()` (so the model and
the program stay aligned), and the `approval required` / `approval not-required` line
follows the rule of design 5.3.
"""
import copy

import pytest

from leash_corpus import base_config
from leash_model import Scenario, Sec


def _codes(res):
    return {l.split()[1] for l in res.out.splitlines() if l.startswith("leash ")}


def _approval(res):
    return [l for l in res.out.splitlines() if l.startswith("approval ")]


def _commit(extra_per_cfg=None):
    cfg = copy.deepcopy(base_config())
    if extra_per_cfg:
        for cfg_name, mutate in extra_per_cfg.items():
            mutate(cfg)
    return cfg


def _add_address_list(value):
    def mut(cfg):
        cfg["dhcp"][0].opts["address"] = [value]
    return mut


def _drop_target_for_block_x(cfg):
    for s in cfg["firewall"]:
        if s.type == "rule" and s.name == "Block-X":
            s.opts.pop("target", None)


EXTRA = [
    (
        "fw include delsec",
        lambda: _commit(),
        [("delsec", "firewall", "@include[0]")],
        {"exec-include", "path-option"},
        "lab",
        None,
    ),
    (
        "dnsmasq domainneeded next to address list",
        lambda: _commit({"dhcp": _add_address_list("/x.lan/1.2.3.4")}),
        [("set", "dhcp", "@dnsmasq[0]", "domainneeded", "0")],
        set(),
        "lab",
        None,
    ),
    (
        "dnsmasq address dellist",
        lambda: _commit({"dhcp": _add_address_list("/x.lan/1.2.3.4")}),
        [("dellist", "dhcp", "@dnsmasq[0]", "address", "/x.lan/1.2.3.4")],
        {"path-option"},
        "lab",
        None,
    ),
    (
        "dnsmasq address delopt",
        lambda: _commit({"dhcp": _add_address_list("/x.lan/1.2.3.4")}),
        [("delopt", "dhcp", "@dnsmasq[0]", "address")],
        {"path-option"},
        "lab",
        None,
    ),
    (
        "dnsmasq foo prefix exempt",
        lambda: _commit(),
        [("set", "dhcp", "@dnsmasq[0]", "foo", "192.168.1.0/24")],
        set(),
        "lab",
        None,
    ),
    (
        "dnsmasq foo https exempt",
        lambda: _commit(),
        [("set", "dhcp", "@dnsmasq[0]", "foo", "https://example.org/x")],
        set(),
        "lab",
        None,
    ),
    (
        "dnsmasq foo rate exempt",
        lambda: _commit(),
        [("set", "dhcp", "@dnsmasq[0]", "foo", "10/second")],
        set(),
        "lab",
        None,
    ),
    (
        "dnsmasq foo file url fires",
        lambda: _commit(),
        [("set", "dhcp", "@dnsmasq[0]", "foo", "file:///etc/x")],
        {"path-option"},
        "lab",
        None,
    ),
    (
        "dnsmasq foo relative path fires",
        lambda: _commit(),
        [("set", "dhcp", "@dnsmasq[0]", "foo", "foo/bar")],
        {"path-option"},
        "lab",
        None,
    ),
    (
        "network delsec guest default zones",
        lambda: _commit(),
        [("delsec", "network", "guest")],
        set(),
        "lab",
        None,
    ),
    (
        "network delsec guest mgmt-interface",
        lambda: _commit(),
        [("delsec", "network", "guest")],
        {"mgmt-interface"},
        "lab",
        {"mgmt-interface": "guest", "mgmt-zone": "lan", "wan-zone": ["wan"]},
    ),
    (
        "dnsmasq renameopt foo to leasetrigger",
        lambda: _commit(),
        [("renameopt", "dhcp", "@dnsmasq[0]", "foo", "leasetrigger")],
        {"exec-option"},
        "lab",
        None,
    ),
    (
        "dnsmasq renamesec then renameopt under new name",
        lambda: _commit(),
        [
            ("renamesec", "dhcp", "@dnsmasq[0]", "dnsmain"),
            ("renameopt", "dhcp", "@dnsmasq[0]", "foo", "dhcpscript", "new"),
        ],
        {"exec-option"},
        "lab",
        None,
    ),
    (
        "wan rule REJECT deleted",
        lambda: _commit(),
        [("delsec", "firewall", "@rule[2]")],
        {"wan-rule"},
        "lab",
        None,
    ),
    (
        "wan rule no-target deleted",
        lambda: _commit({"firewall": _drop_target_for_block_x}),
        [("delsec", "firewall", "@rule[2]")],
        {"wan-rule"},
        "lab",
        None,
    ),
]


@pytest.mark.parametrize(
    "name, commit_fn, ops, expect, profile, zones",
    EXTRA,
    ids=[e[0] for e in EXTRA],
)
@pytest.mark.parametrize("mode", ["index", "id"])
def test_extra_codes(router, name, commit_fn, ops, expect, profile, zones, mode):
    router.use_leash_uci()
    scn = Scenario(commit_fn(), ops, profile=profile, zones=zones, mode=mode)
    model = scn.expected()
    assert model == expect, (
        f"{name} [{mode}]: model disagrees with hand expectation; "
        f"hand={sorted(expect)} model={sorted(model)}"
    )
    res = router.sealed_scenario(scn)
    assert (res.rc, res.err) == (0, ""), f"{name} [{mode}]: rc={res.rc} err={res.err}"
    got = _codes(res)
    assert got == expect, (
        f"{name} [{mode}]: got={sorted(got)} expect={sorted(expect)}"
    )
    want_approval = "approval required" if (expect or profile == "prod") else "approval not-required"
    assert _approval(res) == [want_approval], (
        f"{name} [{mode}]: approval={_approval(res)} want=[{want_approval}]"
    )
