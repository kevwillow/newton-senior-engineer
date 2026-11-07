"""Design 9.2 group 8, 5.2: the intended-differences table between the router-side
leash (run by `seal`) and the host policy (run by `newton_mcp.policy.classify`,
fed the seal's own section facts).

Round p shrank this table to the scenarios where the two STILL disagree.
Every remaining row is a committed-view fact the host's inputs (the staged
diff, the batch, the device settings and the section facts) cannot supply:

* ``router-wider``: the router identifies the management zone by the
  section's COMMITTED ``network`` holding the mgmt interface (or by the
  committed name); the diff does not touch ``network`` or ``name``, so the
  host cannot see the binding. Firing fail-safe on every unknown committed
  network would flag every ordinary zone change the router allows, so the
  design keeps this difference on the router's side.

* ``router-narrower``: the host fails safe where a rule needs a committed
  value the diff cannot show (a rule's committed ``src`` and ``target``, a
  forwarding's committed ``src``/``dest``, a redirect's committed ``src``,
  the option values a deleted section held). The router reads the committed
  view, names the section and stays quiet.

Rows not in this table default to ``same``. Every non-same row MUST carry a
reason; the test fails with "relation without a reason" otherwise.
"""

from __future__ import annotations


RELATIONS = {
    # ---- router-wider: mgmt-zone by a committed view the host cannot see ----
    "custom zones: lan zone is ordinary": (
        "router-wider",
        "mgmt-zone identity by the committed network (the zone holds the mgmt interface 'lan'); the diff touches only masq, so the host cannot see the binding",
    ),

    # ---- router-narrower: the host fails safe on committed values the diff cannot show ----
    "guest delete": (
        "router-narrower",
        "path-option fails safe: a deleted section's committed option values are not in the diff, and one may hold a path",
    ),
    "forwarding guest existing set": (
        "router-narrower",
        "forwarding-mgmt/wan-forwarding fail safe: the committed src/dest of an existing forwarding are not in the diff (they are guest/wan, not mgmt/wan-src)",
    ),
    "redirect existing set": (
        "router-narrower",
        "wan-redirect fails safe: the committed src of an existing redirect is not in the diff (it is lan, not wan)",
    ),
    "rule wan REJECT other set": (
        "router-narrower",
        "wan-rule fails safe: the committed src/target of an existing rule are not in the diff (target is REJECT, so the router stays quiet)",
    ),
    "rule out reorder": (
        "router-narrower",
        "wan-rule fails safe on reorder of an existing rule whose committed src (none, an output rule) is not in the diff",
    ),
    "rule lan deleted": (
        "router-narrower",
        "wan-rule fails safe on delete of an existing rule whose committed src (lan) is not in the diff",
    ),
}
