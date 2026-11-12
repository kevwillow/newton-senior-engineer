"""Render the golden owner scripts (mcp/tests/fixtures/owner/*.sh).

The fixtures are rendered, never hand-edited: the bytes of a golden file
are the bytes ``render_script`` makes of the plan in
``mcp/tests/test_owner_script.py``.  Run it after every template change:

    mcp/.venv/bin/python mcp/tests/render_owner_fixtures.py

It writes the four files and prints what it wrote.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))

from newton_mcp import owner_script  # noqa: E402
from newton_mcp.owner_script import ScriptPlan  # noqa: E402

FIXTURES = HERE / "fixtures" / "owner"

APPLY_ID = "3f9a1c0be2d44b17a1c3d5e7f9012345"
RESTORE_ID = "9e8d7c6b5a4938271605f4e3d2c1b0a9"

GOLDENS = {
    "apply.sh": ScriptPlan(
        sid=APPLY_ID,
        kind="apply",
        device="lab-r1",
        window=180,
        restore_sid=RESTORE_ID,
        preconditions=(("firewall.cfg0a1b2c.dest_port", "22"),),
        ops=(("set", "firewall.cfg0a1b2c.dest_port", "2222"),),
    ),
    "restore.sh": ScriptPlan(
        sid=RESTORE_ID,
        kind="restore",
        device="lab-r1",
        window=180,
        restore_of=APPLY_ID,
        preconditions=(("firewall.cfg0a1b2c.dest_port", "2222"),),
        ops=(("set", "firewall.cfg0a1b2c.dest_port", "22"),),
    ),
    "apply-lists.sh": ScriptPlan(
        sid="00112233445566778899aabbccddeeff",
        kind="apply",
        device="lab-r1",
        window=300,
        restore_sid="ffeeddccbbaa99887766554433221100",
        preconditions=(
            ("firewall.cfg03dc81.network", "wan wan6 wan2"),
            ("firewall.labz.ntp", None),
        ),
        ops=(
            ("del_list", "firewall.cfg03dc81.network", "wan6"),
            ("add_list", "firewall.cfg03dc81.network", "wan3"),
            ("delete", "firewall.labz", None),
            ("set", "system.hostname", "newton-lab"),
        ),
    ),
    "restore-lists.sh": ScriptPlan(
        sid="ffeeddccbbaa99887766554433221100",
        kind="restore",
        device="lab-r1",
        window=300,
        restore_of="00112233445566778899aabbccddeeff",
        preconditions=(
            ("firewall.cfg03dc81.network", "wan wan2 wan3"),
            ("firewall.labz", "zone"),
        ),
        ops=(
            ("delete", "firewall.cfg03dc81.network", None),
            ("add_list", "firewall.cfg03dc81.network", "wan"),
            ("add_list", "firewall.cfg03dc81.network", "wan6"),
            ("add_list", "firewall.cfg03dc81.network", "wan2"),
            ("set", "firewall.newton_r_00112233_13.name", "lab"),
            ("reorder", "firewall.newton_r_00112233_13", "13"),
            ("set", "system.hostname", "OpenWrt"),
        ),
    ),
}


def main() -> int:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    for name, plan in sorted(GOLDENS.items()):
        data = owner_script.render_script(plan)
        path = FIXTURES / name
        path.write_bytes(data)
        path.chmod(0o644)
        print("wrote {0} ({1} bytes)".format(path, len(data)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
