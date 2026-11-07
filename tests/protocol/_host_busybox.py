"""Single source of truth for the host busybox path used to emulate the
OpenWrt router shell (busybox ash).

The OpenWrt target runs busybox ash; the host /bin/sh on Debian/Ubuntu is
dash.  They differ in arithmetic parsing (e.g. ``$(( 08 + 1 ))`` is a fatal
syntax error in ash), so tests that only ever passed under dash would mask
the router's actual behaviour.  Reuse this lookup instead of inventing a
second one; the path matches the lookup inside
``tests/protocol/router_setup_harness.py``'s ``_write_hostbin``.
"""

import os

HOST_BUSYBOX = "/usr/bin/busybox"


def host_busybox():
    """Return the absolute path to the host busybox, or None if missing."""
    return HOST_BUSYBOX if os.path.exists(HOST_BUSYBOX) else None
