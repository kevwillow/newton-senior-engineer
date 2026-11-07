"""Tests for the host policy's fail-open on a section-type line that the
diff masker could only render as a placeholder.

``scripts/owrt-change.sh mask_secrets`` masks secret-looking ``name=value``
pairs into the form ``name='<masked>'``; ``mcp.newton_mcp.redact`` masks values
into ``<redacted:8hex>``.  A new-section line such as
``network.br_auth='device'`` becomes ``network.br_auth='<masked>'`` once a
``contains auth`` secret rule matches the section name.  The raw diff fires
``bridge-member`` (the new section is a ``device`` / bridge-vlan section,
and the option line touches bridge membership); the masked diff used to give
the host policy an unknown type ``<masked>`` that did not match any leash
check, so the host gave no reason and ``requires_approval`` was ``False``.
The router-side leash still fired ``bridge-member`` on raw data, so this was
fail-open on the host, not on the device.

The fix: in ``_groups``, a section-type value that is one of the mask
placeholders the maskers produce is treated as unknown (``section_type``
stays ``None``); the network branch's ``section_type is None`` dispatch then
takes the existing unknown-type path, which fires ``section-unidentified``
when a router fact names the section or a new-section line was present.
A non-masked unknown type (``network.foo=bar``) keeps today's behaviour
(the section is identified as some type we do not leash on, so it stays
free on the lab profile).
"""

from __future__ import annotations

import pytest

from newton_mcp.policy import classify
from newton_mcp.server import Device


def dev(profile="lab", mgmt_interface="lan", mgmt_zone="lan", wan_zones=("wan",)):
    return Device("quasar", "openwrt", "192.0.2.1", "root",
                  profile=profile, mgmt_interface=mgmt_interface, mgmt_zone=mgmt_zone,
                  wan_zones=wan_zones)


def decide(diff, batch="", device=None, section_facts=None):
    return classify(device if device is not None else dev(), batch, diff,
                    section_facts=section_facts)


def free(diff, batch="", device=None, section_facts=None):
    return decide(diff, batch, device, section_facts) == {"requires_approval": False, "risk": "low", "reasons": []}


def fires(diff, code, device=None, section_facts=None):
    result = decide(diff, device=device, section_facts=section_facts)
    assert result["requires_approval"] is True, result
    assert result["risk"] == "critical", result
    assert any(reason.startswith(code + ":") for reason in result["reasons"]), result["reasons"]
    return result


# the diff shape from a reproduction: a new bridge
# section the masker turned into '<masked>', plus one option line that does
# not match a secret name so the masker left it intact
MASKED_BRIDGE_DIFF = (
    "network.br_auth='<masked>'\n"
    "network.br_auth.ports='lan1'"
)


def test_masked_section_type_with_no_facts_requires_approval_as_section_unidentified():
    # the raw diff (type='device') fires bridge-member (critical); the masked
    # diff must also require approval -- the network.@device[N] branch and
    # the new-section check both need a real type to fire, so the masked
    # value must dispatch through the unknown-type path that fails safe
    result = decide(MASKED_BRIDGE_DIFF)
    assert result["requires_approval"] is True, result
    assert result["risk"] == "critical", result
    assert any(reason.startswith("section-unidentified") for reason in result["reasons"]), result["reasons"]


def test_masked_section_type_with_facts_naming_device_fires_bridge_member():
    # when the router-side seal reported the section's type is 'device'
    # (an anonymous "<sid>.section network br_auth device -" line), the
    # resolved type is taken from the fact and the masked section-type
    # value no longer matters -- the bridge-member reason fires just like
    # the raw diff
    facts = {("network", "br_auth"): ("device", None)}
    raw_diff = "network.br_auth='device'\nnetwork.br_auth.ports='lan1'"
    raw_result = fires(raw_diff, "bridge-member")
    facts_result = decide(MASKED_BRIDGE_DIFF, section_facts=facts)
    assert facts_result["requires_approval"] is True, facts_result
    assert facts_result["risk"] == "critical", facts_result
    # the masked-with-facts result resolves to the same bridge-member code
    # the raw diff fires; the reason snippet quotes the diff line and that
    # line differs between masked and raw (the whole point of the masking),
    # but the code and the section-type the reason reports must match
    assert any(reason.startswith("bridge-member") for reason in facts_result["reasons"]), facts_result["reasons"]
    raw_bridge_reasons = [reason for reason in raw_result["reasons"] if reason.startswith("bridge-member")]
    masked_bridge_reasons = [reason for reason in facts_result["reasons"] if reason.startswith("bridge-member")]
    assert raw_bridge_reasons and masked_bridge_reasons
    # both reasons name the section the same way and report the same
    # resolved section type
    assert "network.br_auth" in raw_bridge_reasons[0]
    assert "network.br_auth" in masked_bridge_reasons[0]
    assert "'device'" in raw_bridge_reasons[0]
    assert "'device'" in masked_bridge_reasons[0]


@pytest.mark.parametrize("masked_value", [
    "<masked>",
    "<masked: too many assignments>",
    "<redacted:deadbeef>",
])
def test_every_mask_placeholder_form_is_treated_as_an_unknown_type(masked_value):
    diff = (
        f"network.br_auth='{masked_value}'\n"
        "network.br_auth.ports='lan1'"
    )
    result = decide(diff)
    assert result["requires_approval"] is True, (masked_value, result)
    assert any(reason.startswith("section-unidentified") for reason in result["reasons"]), (masked_value, result)


@pytest.mark.parametrize("unknown_type", [
    "bar",
    "frob",
    "mycustom",
])
def test_non_masked_unknown_type_keeps_todays_free_behaviour(unknown_type):
    # a new section whose type is a real string we do not recognise must
    # not silently get more approval than today; today the section_type
    # falls through every elif, so a lab-profile change stays free.  The
    # fix for masked values must not lower-or-raise this case.
    diff = (
        f"network.foo='{unknown_type}'\n"
        "network.foo.ports='lan1'"
    )
    assert free(diff)


def test_existing_named_section_without_a_fact_stays_free_when_section_type_is_unmasked_unknown():
    # an *existing* named section (no new-section line in the diff, no
    # router fact) was free before, and must stay free -- the masked fix
    # only raises the NewSectionWithMaskedValue case, not every unknown
    # type
    assert free("network.foo.x='y'")


def test_masked_section_type_on_an_existing_firewall_section_fires_section_unidentified_too():
    # the firewall branch already fired section-unidentified for an
    # unknown type; this pins that a masked type on a firewall section
    # takes the same path (the fix is in _groups, not in the network
    # branch alone)
    diff = (
        "firewall.z_auth='<masked>'\n"
        "firewall.z_auth.input='REJECT'"
    )
    result = decide(diff)
    assert result["requires_approval"] is True, result
    assert any(reason.startswith("section-unidentified") for reason in result["reasons"]), result["reasons"]


def test_mask_placeholder_not_followed_by_a_type_assignment_does_not_affect_other_diffs():
    # a diff that mentions '<masked>' only as an OPTION value (not as a
    # new-section type) was already ignored by the policy; the fix must
    # not change that
    diff = "dropbear.@dropbear[0].PasswordAuth='<masked>'"
    result = decide(diff)
    # PasswordAuth is on the management access service, so the mgmt-config
    # reason still fires; the policy did not change mgmt-config
    assert result["requires_approval"] is True
    assert any(reason.startswith("mgmt-config") for reason in result["reasons"]), result["reasons"]
