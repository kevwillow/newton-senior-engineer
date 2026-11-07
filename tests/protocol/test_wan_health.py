"""WH-01/WH-INIT-01: router-resident dual-WAN health-check contract.

The real POSIX shell daemon runs against stdlib-only stubs on PATH.  All
mutable router state is in ``tmp_path``; these tests never touch a network.
"""

import json
import os
import shlex
import shutil
import signal
import subprocess
import textwrap
import time
from pathlib import Path

import pytest

from _host_busybox import host_busybox


# The router runs busybox ash; the host /bin/sh on Debian/Ubuntu is dash.
# They differ in arithmetic parsing (e.g. ``$(( 08 + 1 ))`` is fatal in ash
# but silently misparsed by dash), so tests that only ever passed under
# dash would mask the router's actual behaviour.  When host busybox is
# missing we skip with this message rather than silently fall back.
ROUTER_SHELL_MISSING = "host busybox not found: the router shell (ash) cannot be emulated"


def host_busybox_or_skip():
    """Return the host busybox path or ``pytest.skip`` the calling test.

    Never silently falls back to host dash.
    """
    busybox = host_busybox()
    if busybox is None:
        pytest.skip(ROUTER_SHELL_MISSING)
    return busybox


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "newton-wan-health.sh"
INIT = ROOT / "scripts" / "newton-wan-health.init"

DEFAULT_CONFIG = {
    "newton_wanhealth.main.enabled": "1",
    "newton_wanhealth.main.interval": "5",
    "newton_wanhealth.main.timeout": "2",
    "newton_wanhealth.main.down_after": "3",
    "newton_wanhealth.main.up_after": "3",
    "newton_wanhealth.main.target": ["192.0.2.1", "198.51.100.1"],
    "newton_wanhealth.main.iface": ["wan", "wan2"],
}

DEFAULT_INTERFACES = {
    "wan": {
        "up": True,
        "l3_device": "eth1",
        "metric": 10,
        "route": [{"target": "0.0.0.0", "mask": 0, "nexthop": "10.100.0.1"}],
    },
    "wan2": {
        "up": True,
        "l3_device": "eth2",
        "metric": 20,
        "route": [{"target": "0.0.0.0", "mask": 0, "nexthop": "10.101.0.1"}],
    },
}

# Realistic netifd-owned table exactly as BusyBox `ip route list` prints it:
# netifd default routes carry `src`, and the interface prefix route is present.
DEFAULT_ROUTES = [
    {"prefix": "10.100.0.0/24", "device": "eth1", "scope": "link", "metric": 10},
    {"gateway": "10.100.0.1", "device": "eth1", "src": "10.100.0.108", "metric": 10},
    {"gateway": "10.101.0.1", "device": "eth2", "src": "10.101.0.110", "metric": 20},
]


def _stub_overrides(bin_dir):
    """Return ash function definitions that re-route each stubbed name
    in ``bin_dir`` to the stub binary, so PATH-installed stubs win over
    busybox's built-in applets inside ``busybox sh``.

    Host busybox is built with ``FEATURE_SH_STANDALONE`` (the Ubuntu
    1.36.1 build uses it), so when running under ``busybox sh`` every
    applet name (``ip``, ``ping``, ``logger``, ``sleep``, ...) is
    expanded to busybox's own implementation before the PATH lookup.
    On the OpenWrt router the busybox build does not set that flag, so
    PATH lookup still applies and the same scripts run against the
    installed tools.  To bridge that, define a shell function for every
    stub in the lab's bin directory; ash function lookup precedes the
    applet table, so the stubs reach the script with their original
    argv (and Popen/signal behaviour stays that of the wrapper shell).

    Names are read from ``bin_dir`` rather than hard-coded so the helper
    cannot drift if the lab starts or stops stubbing a particular tool.
    Paths are ``shlex.quote``d so a tmp dir containing spaces (the lab
    uses ``"runtime state"``) cannot break function definitions.
    """
    lines = []
    for entry in sorted(bin_dir.iterdir()):
        # Only follow symlinks so the lab's dispatcher file (which is a
        # regular file under a hyphenated name that ash would refuse as a
        # function name) is excluded; the symlinked stubs are the names
        # the script actually invokes.
        if not entry.is_symlink():
            continue
        # Invoke via the symlink path (not the dispatcher's resolved
        # target) so the dispatched Python script sees ``sys.argv[0]``
        # as the stubbed name and records the correct tool in calls.log.
        name = entry.name
        if name.startswith("."):
            continue
        quoted = shlex.quote(str(entry))
        lines.append(f'{name}() {{ {quoted} "$@"; }}')
    return "\n".join(lines) + ("\n" if lines else "")


STUB = r'''#!/usr/bin/env python3
import json
import os
import sys
import time
from pathlib import Path

root = Path(os.environ["WAN_HEALTH_TEST_ROOT"])
name = Path(sys.argv[0]).name
argv = sys.argv[1:]

with (root / "calls.jsonl").open("a") as handle:
    handle.write(json.dumps({"tool": name, "argv": argv}) + "\n")

def load(filename):
    return json.loads((root / filename).read_text())

def save(filename, value):
    target = root / filename
    temporary = target.with_name(f"{target.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(json.dumps(value, sort_keys=True) + "\n")
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)

if name == "uci":
    config = load("config.json")
    rest = [arg for arg in argv if arg != "-q"]
    if len(rest) == 2 and rest[0] == "get" and rest[1] in config:
        value = config[rest[1]]
        print(" ".join(value) if isinstance(value, list) else value)
        raise SystemExit(0)
    raise SystemExit(1)

if name == "ubus":
    if len(argv) == 3 and argv[0] == "call" and argv[2] == "status":
        prefix = "network.interface."
        if argv[1].startswith(prefix):
            iface = argv[1][len(prefix):]
            value = load("interfaces.json").get(iface)
            if value is not None:
                print(json.dumps(value))
                raise SystemExit(0)
    raise SystemExit(1)

if name == "jsonfilter":
    try:
        value = json.load(sys.stdin)
    except (ValueError, OSError):
        raise SystemExit(1)
    expression = argv[argv.index("-e") + 1] if "-e" in argv else ""
    if expression == "@.up":
        print("true" if value.get("up") is True else "false")
    elif expression == "@.l3_device":
        print(value.get("l3_device", ""))
    elif expression == "@.metric":
        print(value.get("metric", ""))
    elif expression == '@.route[@.target="0.0.0.0"].nexthop':
        for route in value.get("route", []):
            if route.get("target") == "0.0.0.0" and route.get("mask") == 0:
                print(route.get("nexthop", ""))
    else:
        raise SystemExit(1)
    raise SystemExit(0)

if name == "ping":
    probes = load("probes.json")
    try:
        device = argv[argv.index("-I") + 1]
        target = argv[-1]
    except (ValueError, IndexError):
        raise SystemExit(2)
    answer = probes.get(device, False)
    if isinstance(answer, dict):
        answer = answer.get(target, False)
    raise SystemExit(0 if answer else 1)

if name == "ip":
    if not argv or argv[0] != "route":
        raise SystemExit(2)
    routes = load("routes.json")
    action = argv[1] if len(argv) > 1 else ""

    def route_matches(item, gateway, device, metric):
        return (
            item.get("gateway") == gateway
            and item.get("device") == device
            and item.get("metric") == metric
        )

    if action in ("list", "show"):
        # Real BusyBox output: double spaces between fields, one trailing
        # space; netifd-owned routes carry `src`, script-added ones do not.
        for route in routes:
            parts = []
            if "prefix" in route:
                parts.append(route["prefix"])
            else:
                parts.append("default")
                parts.append("via " + route["gateway"])
            parts.append("dev " + route["device"])
            if route.get("scope"):
                parts.append("scope " + route["scope"])
            if route.get("src"):
                parts.append("src " + route["src"])
            parts.append("metric " + str(route["metric"]))
            print("  ".join(parts) + " ")
        raise SystemExit(0)
    if action in ("add", "del"):
        try:
            route = {
                "gateway": argv[argv.index("via") + 1],
                "device": argv[argv.index("dev") + 1],
                "metric": int(argv[argv.index("metric") + 1]),
            }
        except (ValueError, IndexError):
            raise SystemExit(2)
        if action == "add" and (root / "ip_route_add_fail").exists():
            raise SystemExit(1)
        present = any(route_matches(item, **route) for item in routes)
        if action == "add":
            if present:
                print("RTNETLINK answers: File exists", file=sys.stderr)
                raise SystemExit(2)
            routes.append(route)
        else:
            if not present:
                raise SystemExit(2)
            routes[:] = [
                item for item in routes if not route_matches(item, **route)
            ]
        save("routes.json", routes)
        raise SystemExit(0)
    raise SystemExit(2)

if name == "logger":
    with (root / "messages.log").open("a") as handle:
        handle.write((argv[-1] if argv else "") + "\n")
    raise SystemExit(0)

if name == "sleep":
    if os.environ.get("WAN_HEALTH_REAL_SLEEP") == "1":
        time.sleep(0.03)
    raise SystemExit(0)

raise SystemExit(127)
'''


class WanHealthLab:
    def __init__(self, tmp_path, busybox):
        # busybox is the host path used to emulate the router shell (ash);
        # tests pass the same path to every run/popen so we never silently
        # fall back to host dash (see host_busybox_or_skip above).
        self.busybox = busybox
        self.root = tmp_path
        self.bin = tmp_path / "bin"
        self.state = tmp_path / "runtime state"
        self.bin.mkdir()
        dispatcher = self.bin / "wan-health-stub"
        dispatcher.write_text(STUB)
        dispatcher.chmod(0o755)
        for name in ("ping", "ip", "ubus", "jsonfilter", "uci", "logger", "sleep"):
            (self.bin / name).symlink_to(dispatcher)
        self.write("config.json", DEFAULT_CONFIG)
        self.write("interfaces.json", DEFAULT_INTERFACES)
        self.write("routes.json", DEFAULT_ROUTES)
        self.write("probes.json", {"eth1": True, "eth2": True})
        (self.root / "calls.jsonl").write_text("")
        (self.root / "messages.log").write_text("")

    def write(self, filename, value):
        (self.root / filename).write_text(json.dumps(value) + "\n")

    def read(self, filename):
        return json.loads((self.root / filename).read_text())

    def configure(self, **options):
        config = self.read("config.json")
        for key, value in options.items():
            config[f"newton_wanhealth.main.{key}"] = value
        self.write("config.json", config)

    def set_probes(self, **values):
        self.write("probes.json", values)

    def env(self, *, real_sleep=False):
        env = os.environ.copy()
        env["PATH"] = f"{self.bin}:{env['PATH']}"
        env["WAN_HEALTH_TEST_ROOT"] = str(self.root)
        env["NEWTON_WAN_HEALTH_STATE"] = str(self.state)
        if real_sleep:
            env["WAN_HEALTH_REAL_SLEEP"] = "1"
        return env

    def _shell_prefix(self):
        """Wrapper-shell prelude: redefine every stubbed command as an
        ash function so PATH-installed stubs win over busybox applets.

        The script is then sourced into the wrapper so its ``$1``/``$@``
        match what ``busybox sh SCRIPT ...`` would deliver, the
        wrapper's ``$$`` stays the parent of the script (so SIGTERM
        tests see the same PID), and any ``exit`` in the script exits
        the wrapper rather than an unrelated subshell.
        """
        prefix = _stub_overrides(self.bin)
        return prefix + '. "$0" "$@"' + '\n'

    def argv(self, mode, script=None):
        # The one argv run() and popen() share, so the runner proof covers both.
        return [self.busybox, "sh", "-c", self._shell_prefix(), str(script or SCRIPT), mode]

    def run(self, mode="once", *, timeout=10, script=None):
        # Run the script under busybox sh, not host /bin/sh (dash), so we
        # exercise the same arithmetic / quoting rules as the router.
        # See ``_stub_overrides`` for why the wrapper redefines the
        # stubbed applets as functions before sourcing the script.
        # ``script`` is an opt-in override used by tests that want to
        # run a tiny probe through the EXACT same argv construction
        # (busybox -> sh -c <prefix> -> script -> mode) without copying
        # the argv list; production callers leave it None and get
        # ``SCRIPT`` as before.
        return subprocess.run(
            self.argv(mode, script),
            env=self.env(),
            text=True,
            capture_output=True,
            timeout=timeout,
        )

    def popen(self):
        # Same router-shell emulation as run(); the daemon is also ash.
        return subprocess.Popen(
            self.argv("run"),
            env=self.env(real_sleep=True),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def calls(self, tool=None):
        calls = [
            json.loads(line)
            for line in (self.root / "calls.jsonl").read_text().splitlines()
            if line
        ]
        return [call for call in calls if tool is None or call["tool"] == tool]

    def messages(self):
        return (self.root / "messages.log").read_text().splitlines()

    def routes(self):
        return self.read("routes.json")

    def clear_calls(self):
        (self.root / "calls.jsonl").write_text("")

    def clear_messages(self):
        (self.root / "messages.log").write_text("")

    def assert_no_uci_writes(self):
        writes = {"set", "add", "add_list", "del_list", "delete", "commit", "revert"}
        for call in self.calls("uci"):
            assert writes.isdisjoint(call["argv"]), call


@pytest.fixture
def lab(tmp_path):
    return WanHealthLab(tmp_path, host_busybox_or_skip())


def run_ok(lab):
    result = lab.run()
    assert result.returncode == 0, result.stdout + result.stderr
    lab.assert_no_uci_writes()
    return result


def route_entries(lab, gateway, device, metric):
    return [
        item
        for item in lab.routes()
        if item.get("gateway") == gateway
        and item.get("device") == device
        and item.get("metric") == metric
    ]


def default_routes_on(lab, device):
    return [item for item in lab.routes() if item.get("device") == device and "gateway" in item]


def test_healthy_steady_state_changes_no_route_and_pins_ping_argv(lab):
    before = lab.routes()

    run_ok(lab)

    assert lab.routes() == before
    assert [call["argv"] for call in lab.calls("ping")] == [
        ["-I", "eth1", "-c", "1", "-W", "2", "192.0.2.1"],
        ["-I", "eth2", "-c", "1", "-W", "2", "192.0.2.1"],
    ]
    assert lab.messages() == ["started"]


def test_down_after_exactly_n_rounds_demotes_route_and_keeps_probing(lab):
    lab.configure(down_after="3")
    lab.set_probes(eth1=False, eth2=True)

    run_ok(lab)
    run_ok(lab)
    assert lab.routes() == DEFAULT_ROUTES
    assert "wan down (eth1) after 3 failed rounds" not in lab.messages()

    run_ok(lab)
    assert not route_entries(lab, "10.100.0.1", "eth1", 10)
    assert route_entries(lab, "10.100.0.1", "eth1", 1010)
    assert min(item["metric"] for item in lab.routes() if "gateway" in item) == 20
    assert lab.messages() == [
        "started",
        "started",
        "started",
        "wan down (eth1) after 3 failed rounds",
    ]

    lab.clear_calls()
    lab.clear_messages()
    run_ok(lab)
    assert [call["argv"][1] for call in lab.calls("ping")] == ["eth1", "eth1", "eth2"]
    assert lab.messages() == ["started"]


def test_recovery_after_exactly_m_rounds_restores_original_metric(lab):
    lab.configure(down_after="1", up_after="2")
    lab.set_probes(eth1=False, eth2=True)
    run_ok(lab)
    assert route_entries(lab, "10.100.0.1", "eth1", 1010)

    lab.clear_messages()
    lab.set_probes(eth1=True, eth2=True)
    run_ok(lab)
    assert route_entries(lab, "10.100.0.1", "eth1", 1010)
    assert "wan up (eth1) after 2 good rounds" not in lab.messages()

    run_ok(lab)
    assert route_entries(lab, "10.100.0.1", "eth1", 10)
    assert not route_entries(lab, "10.100.0.1", "eth1", 1010)
    assert lab.messages() == ["started", "started", "wan up (eth1) after 2 good rounds"]


def test_three_wan_down_then_up_leaves_exactly_one_default_route_per_wan(lab):
    lab.configure(down_after="1", up_after="1")
    config = lab.read("config.json")
    config["newton_wanhealth.main.iface"] = ["wan", "wan2", "wan3"]
    lab.write("config.json", config)
    interfaces = lab.read("interfaces.json")
    interfaces["wan3"] = {
        "up": True,
        "l3_device": "eth3",
        "metric": 30,
        "route": [{"target": "0.0.0.0", "mask": 0, "nexthop": "10.102.0.1"}],
    }
    lab.write("interfaces.json", interfaces)
    routes = lab.routes()
    routes.append(
        {"gateway": "10.102.0.1", "device": "eth3", "src": "10.102.0.112", "metric": 30}
    )
    lab.write("routes.json", routes)
    lab.set_probes(eth1=False, eth2=True, eth3=True)

    run_ok(lab)

    assert len(route_entries(lab, "10.100.0.1", "eth1", 1010)) == 1
    assert not route_entries(lab, "10.100.0.1", "eth1", 10)
    assert len(default_routes_on(lab, "eth1")) == 1
    assert len(route_entries(lab, "10.101.0.1", "eth2", 20)) == 1
    assert len(route_entries(lab, "10.102.0.1", "eth3", 30)) == 1

    lab.set_probes(eth1=True, eth2=True, eth3=True)
    run_ok(lab)

    assert len(route_entries(lab, "10.100.0.1", "eth1", 10)) == 1
    assert not route_entries(lab, "10.100.0.1", "eth1", 1010)
    assert len(default_routes_on(lab, "eth1")) == 1
    assert len(route_entries(lab, "10.101.0.1", "eth2", 20)) == 1
    assert len(route_entries(lab, "10.102.0.1", "eth3", 30)) == 1


def test_good_round_resets_failures_and_failed_round_resets_recovery(lab):
    lab.configure(down_after="2", up_after="2")
    lab.set_probes(eth1=False, eth2=True)
    run_ok(lab)
    lab.set_probes(eth1=True, eth2=True)
    run_ok(lab)
    lab.set_probes(eth1=False, eth2=True)
    run_ok(lab)
    assert route_entries(lab, "10.100.0.1", "eth1", 10)
    run_ok(lab)
    assert route_entries(lab, "10.100.0.1", "eth1", 1010)

    lab.set_probes(eth1=True, eth2=True)
    run_ok(lab)
    lab.set_probes(eth1=False, eth2=True)
    run_ok(lab)
    lab.set_probes(eth1=True, eth2=True)
    run_ok(lab)
    assert route_entries(lab, "10.100.0.1", "eth1", 1010)
    run_ok(lab)
    assert route_entries(lab, "10.100.0.1", "eth1", 10)


def test_any_target_answer_makes_round_healthy(lab):
    lab.configure(down_after="1")
    lab.write(
        "probes.json",
        {
            "eth1": {"192.0.2.1": False, "198.51.100.1": True},
            "eth2": True,
        },
    )

    run_ok(lab)

    eth1 = [call["argv"] for call in lab.calls("ping") if call["argv"][1] == "eth1"]
    assert eth1 == [
        ["-I", "eth1", "-c", "1", "-W", "2", "192.0.2.1"],
        ["-I", "eth1", "-c", "1", "-W", "2", "198.51.100.1"],
    ]
    assert lab.routes() == DEFAULT_ROUTES


def test_down_state_reasserts_after_netifd_readds_original_route(lab):
    lab.configure(down_after="1")
    lab.set_probes(eth1=False, eth2=True)
    run_ok(lab)
    routes = lab.routes()
    routes.append(
        {"gateway": "10.100.0.1", "device": "eth1", "src": "10.100.0.108", "metric": 10}
    )
    lab.write("routes.json", routes)
    lab.clear_calls()
    lab.clear_messages()

    run_ok(lab)

    assert not route_entries(lab, "10.100.0.1", "eth1", 10)
    assert route_entries(lab, "10.100.0.1", "eth1", 1010)
    assert [call["argv"] for call in lab.calls("ip") if "del" in call["argv"]] == [
        ["route", "del", "default", "via", "10.100.0.1", "dev", "eth1", "metric", "10"]
    ]
    assert lab.messages() == ["started"]


def test_all_down_changes_no_route_and_logs_once(lab):
    lab.configure(down_after="1")
    lab.set_probes(eth1=False, eth2=False)
    before = lab.routes()

    run_ok(lab)
    assert lab.routes() == before
    assert lab.messages() == [
        "started",
        "wan down (eth1) after 1 failed rounds",
        "wan2 down (eth2) after 1 failed rounds",
        "all configured WAN interfaces are down; leaving routes unchanged",
    ]

    lab.clear_messages()
    run_ok(lab)
    assert lab.routes() == before
    assert lab.messages() == ["started"]


def test_netifd_down_iface_is_skipped_without_forgetting_state(lab):
    lab.configure(down_after="1", up_after="1")
    lab.set_probes(eth1=False, eth2=True)
    run_ok(lab)
    interfaces = lab.read("interfaces.json")
    interfaces["wan"]["up"] = False
    lab.write("interfaces.json", interfaces)
    lab.set_probes(eth1=True, eth2=True)
    lab.clear_calls()

    run_ok(lab)
    assert all(call["argv"][1] != "eth1" for call in lab.calls("ping"))

    interfaces["wan"]["up"] = True
    lab.write("interfaces.json", interfaces)
    run_ok(lab)
    assert route_entries(lab, "10.100.0.1", "eth1", 10)


def test_sigterm_restores_demoted_routes_and_exits_zero(lab):
    lab.configure(down_after="1")
    lab.set_probes(eth1=False, eth2=True)
    process = lab.popen()
    deadline = time.monotonic() + 5
    while not route_entries(lab, "10.100.0.1", "eth1", 1010):
        assert process.poll() is None
        assert time.monotonic() < deadline
        time.sleep(0.02)

    process.send_signal(signal.SIGTERM)
    stdout, stderr = process.communicate(timeout=5)

    assert process.returncode == 0, stdout + stderr
    assert route_entries(lab, "10.100.0.1", "eth1", 10)
    assert not route_entries(lab, "10.100.0.1", "eth1", 1010)


def test_stub_route_save_replaces_the_target_atomically(lab):
    routes = lab.root / "routes.json"
    inode_before = routes.stat().st_ino

    result = subprocess.run(
        [
            str(lab.bin / "ip"),
            "route",
            "add",
            "default",
            "via",
            "10.100.0.1",
            "dev",
            "eth1",
            "metric",
            "1010",
        ],
        env=lab.env(),
        text=True,
        capture_output=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert routes.stat().st_ino != inode_before
    assert route_entries(lab, "10.100.0.1", "eth1", 1010)
    assert not list(lab.root.glob("routes.json.*tmp"))


def test_restore_mode_restores_and_clears_runtime_state(lab):
    lab.configure(down_after="1")
    lab.set_probes(eth1=False, eth2=True)
    run_ok(lab)
    assert list(lab.state.glob("*.state"))

    result = lab.run("restore")

    assert result.returncode == 0, result.stdout + result.stderr
    restored = sorted(
        (item.get("gateway"), item.get("device"), item["metric"])
        for item in lab.routes()
        if "gateway" in item
    )
    expected = sorted(
        (item["gateway"], item["device"], item["metric"])
        for item in DEFAULT_ROUTES
        if "gateway" in item
    )
    assert restored == expected
    assert not list(lab.state.glob("*.state"))


def test_demote_keeps_original_route_when_replacement_add_fails(lab):
    lab.configure(down_after="1")
    lab.set_probes(eth1=False, eth2=True)
    (lab.root / "ip_route_add_fail").write_text("")
    before = lab.routes()

    run_ok(lab)

    assert route_entries(lab, "10.100.0.1", "eth1", 10)
    assert not route_entries(lab, "10.100.0.1", "eth1", 1010)
    assert lab.routes() == before


def test_restore_keeps_demoted_route_when_original_add_fails(lab):
    lab.configure(down_after="1", up_after="1")
    lab.set_probes(eth1=False, eth2=True)
    run_ok(lab)
    assert route_entries(lab, "10.100.0.1", "eth1", 1010)

    lab.set_probes(eth1=True, eth2=True)
    (lab.root / "ip_route_add_fail").write_text("")

    run_ok(lab)

    assert not route_entries(lab, "10.100.0.1", "eth1", 10)
    assert route_entries(lab, "10.100.0.1", "eth1", 1010)
    assert len(default_routes_on(lab, "eth1")) == 1


def test_all_down_guard_ignores_inactive_wan_stale_up_mark(lab):
    lab.configure(down_after="1")
    lab.set_probes(eth1=False, eth2=True)
    run_ok(lab)
    interfaces = lab.read("interfaces.json")
    interfaces["wan2"]["up"] = False
    lab.write("interfaces.json", interfaces)
    before = lab.routes()

    lab.clear_messages()
    run_ok(lab)
    assert lab.routes() == before
    assert lab.messages() == [
        "started",
        "all configured WAN interfaces are down; leaving routes unchanged",
    ]

    lab.clear_messages()
    run_ok(lab)
    assert lab.routes() == before
    assert lab.messages() == ["started"]


def test_inactive_stale_down_mark_alone_is_not_all_down(lab):
    lab.configure(down_after="1")
    lab.set_probes(eth1=False, eth2=False)
    run_ok(lab)
    interfaces = lab.read("interfaces.json")
    interfaces["wan"]["up"] = False
    interfaces["wan2"]["up"] = False
    lab.write("interfaces.json", interfaces)
    before = lab.routes()
    (lab.state / "all_down.flag").unlink(missing_ok=True)

    lab.clear_messages()
    run_ok(lab)

    assert lab.routes() == before
    assert "all configured WAN interfaces are down" not in "\n".join(lab.messages())


def test_runner_uses_busybox_ash_not_host_dash(lab):
    """The router runs busybox ash; host /bin/sh on Debian/Ubuntu is dash.

    They diverge on arithmetic parsing (e.g. ``$(( 08 + 1 ))`` is fatal in
    ash but only warned about in dash), so a test that only ever passed
    under dash would silently mask the router's real behaviour.  We prove
    the harness actually executes scripts through busybox (and not the
    host shebang ``#!/bin/sh``) by running a tiny probe through the same
    code path the production daemon uses (``WanHealthLab.run``): the
    wrapper sources the script under ``busybox sh -c <prefix>``, so the
    running shell is busybox even when the probe itself has a dash
    shebang.  The probe prints the executable the kernel exec'd for the
    wrapper (``readlink /proc/$$/exe``); if the harness ever reverted to
    running the script directly, the running shell would be host dash
    and this test would fail.
    """
    probe = lab.root / "busybox-probe.sh"
    probe.write_text('#!/bin/sh\nreadlink "/proc/$$/exe"\n')
    probe.chmod(0o755)

    result = lab.run(script=probe)

    assert result.returncode == 0, result.stdout + result.stderr
    binary = Path(result.stdout.strip()).name.lower()
    assert "busybox" in binary, (
        "router shell runner fell back to non-busybox shell: "
        f"expected a busybox binary, got {result.stdout!r}"
    )


def test_popen_runner_uses_shared_busybox_argv(lab, monkeypatch):
    """The daemon path must not silently fall back to host dash."""
    real_popen = subprocess.Popen
    captured_argv = []

    def capture_popen(*args, **kwargs):
        assert len(args) == 1
        captured_argv.append(args[0])
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", capture_popen)
    process = lab.popen()
    try:
        expected_argv = lab.argv("run")
        assert captured_argv == [expected_argv]
        assert expected_argv[:3] == [lab.busybox, "sh", "-c"]
    finally:
        deadline = time.monotonic() + 5
        while not list(lab.state.glob("*.state")):
            assert process.poll() is None
            assert time.monotonic() < deadline
            time.sleep(0.02)
        process.terminate()
        stdout, stderr = process.communicate(timeout=5)

    assert process.returncode == 0, stdout + stderr


def test_leading_zero_metric_from_ubus_is_rejected_without_route_change(lab):
    # under busybox ash, the pre-fix code (valid_metric accepting "08")
    # would have reached ``dm_high=$(( $3 + 1000 ))`` and exited 2 with
    # ``sh: arithmetic syntax error`` because ``08`` is not a valid POSIX
    # arithmetic literal.  dash also rejects it, but with a different
    # message and at a slightly different stage, so the test had to be
    # explicit about the ash-visible behaviour to actually exercise the
    # router shell that the device runs.
    lab.configure(down_after="1")
    lab.set_probes(eth1=False, eth2=True)
    interfaces = lab.read("interfaces.json")
    interfaces["wan"]["metric"] = "08"
    lab.write("interfaces.json", interfaces)
    before = lab.routes()

    result = lab.run()

    assert result.returncode == 0, result.stdout + result.stderr
    # The router shell must not die with a shell-level arithmetic error;
    # the pre-fix code did exactly that under ash.
    assert "arithmetic" not in result.stderr.lower()
    assert "syntax error" not in result.stderr.lower()
    assert lab.routes() == before
    assert "invalid ubus metric; skipping interface" in lab.messages()


def test_leading_zero_metric_in_state_file_is_never_used_for_restore(lab):
    lab.state.mkdir(parents=True, exist_ok=True)
    (lab.state / "wan.state").write_text(
        "s_dev=eth1\ns_gw=10.100.0.1\ns_metric=08\n"
        "s_fail=0\ns_good=0\ns_mark=down\ns_active=1\n"
    )
    before = lab.routes()

    result = lab.run("restore")

    assert result.returncode == 0, result.stdout + result.stderr
    assert lab.routes() == before
    assert not [item for item in lab.routes() if item.get("metric") in (8, 1008)]


def test_sigterm_while_idling_with_missing_config_still_restores(lab):
    config = lab.read("config.json")
    config.pop("newton_wanhealth.main.target")
    lab.write("config.json", config)
    lab.state.mkdir(parents=True, exist_ok=True)
    (lab.state / "wan.state").write_text(
        "s_dev=eth1\ns_gw=10.100.0.1\ns_metric=10\n"
        "s_fail=0\ns_good=0\ns_mark=down\ns_active=1\n"
    )
    lab.write(
        "routes.json",
        [
            route
            for route in DEFAULT_ROUTES
            if not (route.get("device") == "eth1" and "gateway" in route)
        ],
    )

    process = lab.popen()
    deadline = time.monotonic() + 5
    while not lab.calls("sleep"):
        assert process.poll() is None
        assert time.monotonic() < deadline
        time.sleep(0.02)

    process.send_signal(signal.SIGTERM)
    stdout, stderr = process.communicate(timeout=5)

    assert process.returncode == 0, stdout + stderr
    assert route_entries(lab, "10.100.0.1", "eth1", 10)
    assert not list(lab.state.glob("*.state"))


def test_invalid_numeric_settings_fall_back_to_defaults(lab):
    lab.configure(
        interval="0",
        timeout="11",
        down_after="bad",
        up_after="21",
    )

    run_ok(lab)

    assert lab.calls("ping")[0]["argv"] == [
        "-I", "eth1", "-c", "1", "-W", "2", "192.0.2.1"
    ]
    assert lab.messages() == [
        "invalid interval; using default 5",
        "invalid timeout; using default 2",
        "invalid down_after; using default 3",
        "invalid up_after; using default 3",
        "started",
    ]


@pytest.mark.parametrize("missing", ["target", "iface"])
def test_missing_required_lists_logs_and_idles(lab, missing):
    config = lab.read("config.json")
    config.pop(f"newton_wanhealth.main.{missing}")
    lab.write("config.json", config)

    run_ok(lab)

    assert not lab.calls("ping")
    assert lab.calls("sleep") == [{"tool": "sleep", "argv": ["5"]}]
    expected = "no valid targets configured; idling" if missing == "target" else "no valid interfaces configured; idling"
    assert lab.messages() == ["started", expected]


@pytest.mark.parametrize(
    "field,payload",
    [
        ("iface", "bad;touch"),
        ("iface", "$(touch_bad)"),
        ("iface", "`touch_bad`"),
        ("iface", "bad n;me"),
        ("iface", "bad'quote"),
        ("iface", "bad\nn;me"),
        ("iface", "-x"),
        ("target", "192.0.2.1;touch"),
        ("target", "$(touch_bad)"),
        ("target", "`touch_bad`"),
        ("target", "192.0.2.1 bad"),
        ("target", "-x"),
    ],
)
def test_hostile_uci_values_never_reach_operational_argv(lab, field, payload):
    config = lab.read("config.json")
    config[f"newton_wanhealth.main.{field}"] = [payload]
    lab.write("config.json", config)

    run_ok(lab)

    operational = {"ping", "ip", "ubus", "jsonfilter", "logger", "sleep"}
    assert all(payload not in arg for call in lab.calls() if call["tool"] in operational for arg in call["argv"])
    assert payload not in "\n".join(lab.messages())
    assert ("invalid iface; skipping" if field == "iface" else "invalid target; skipping") in lab.messages()


@pytest.mark.parametrize(
    "field,payload,message",
    [
        ("l3_device", "eth1;touch", "invalid ubus device; skipping interface"),
        ("l3_device", "$(touch_bad)", "invalid ubus device; skipping interface"),
        ("l3_device", "bad name", "invalid ubus device; skipping interface"),
        ("l3_device", "-x", "invalid ubus device; skipping interface"),
        ("gateway", "10.100.0.1;touch", "invalid ubus gateway; skipping interface"),
        ("gateway", "$(touch_bad)", "invalid ubus gateway; skipping interface"),
        ("gateway", "bad\nvalue", "invalid ubus gateway; skipping interface"),
    ],
)
def test_hostile_ubus_values_never_reach_operational_argv(lab, field, payload, message):
    interfaces = lab.read("interfaces.json")
    if field == "gateway":
        interfaces["wan"]["route"][0]["nexthop"] = payload
    else:
        interfaces["wan"][field] = payload
    lab.write("interfaces.json", interfaces)

    run_ok(lab)

    assert all(payload not in arg for call in lab.calls() for arg in call["argv"])
    assert payload not in "\n".join(lab.messages())
    assert message in lab.messages()


@pytest.mark.parametrize("field", ["gateway", "l3_device"])
def test_hostile_ubus_value_is_never_executed_from_state_file(lab, tmp_path, field):
    marker = tmp_path / "pwned"
    payload = f"1.2.3.4;touch {marker}"
    interfaces = lab.read("interfaces.json")
    if field == "gateway":
        interfaces["wan"]["route"][0]["nexthop"] = payload
    else:
        interfaces["wan"][field] = payload
    lab.write("interfaces.json", interfaces)

    run_ok(lab)
    run_ok(lab)

    assert not marker.exists()


def test_ipv4_validation_rejects_out_of_range_octets(lab):
    lab.configure(target=["256.1.1.1", "1.2.3", "01.2.3.4"])

    run_ok(lab)

    assert not lab.calls("ping")
    assert lab.messages().count("invalid target; skipping") == 3


def test_script_has_no_shell_code_construction_or_uci_writes():
    text = SCRIPT.read_text()
    assert "eval" not in text
    assert "sh -c" not in text
    assert "uci set" not in text
    assert "uci commit" not in text
    assert not any("/etc/" in line and not line.startswith("#!") for line in text.splitlines())


def _run_init(enabled, busybox):
    shell = r'''
CALLS=$1
ENABLED=$2
INIT=$3
uci() {
    [ "$ENABLED" = unset ] && return 1
    printf '%s\n' "$ENABLED"
}
record() { printf '%s\n' "$*" >> "$CALLS"; }
procd_open_instance() { record open; }
procd_set_param() { record set "$@"; }
procd_close_instance() { record close; }
procd_add_reload_trigger() { record trigger "$@"; }
. "$INIT"
start_service
service_triggers
'''
    calls = INIT.parent / ".wan-health-init-calls"
    try:
        calls.write_text("")
        # Run the snippet (and the . "$INIT" it sources) under the router
        # shell so procd_open_instance et al. see the same parser as on the
        # device; never silently fall back to host /bin/sh (dash).
        result = subprocess.run(
            [busybox, "sh", "-c", shell,
             "wan-health-init-test", str(calls), enabled, str(INIT)],
            text=True,
            capture_output=True,
            timeout=10,
        )
        return result, calls.read_text().splitlines()
    finally:
        calls.unlink(missing_ok=True)


@pytest.mark.parametrize("enabled", ["0", "unset", "yes", "01"])
def test_init_does_not_open_procd_unless_enabled_is_exactly_one(enabled):
    result, calls = _run_init(enabled, host_busybox_or_skip())
    assert result.returncode == 0, result.stdout + result.stderr
    assert calls == ["trigger newton_wanhealth"]


def test_init_opens_expected_procd_instance_when_enabled():
    result, calls = _run_init("1", host_busybox_or_skip())
    assert result.returncode == 0, result.stdout + result.stderr
    assert calls == [
        "open",
        "set command /usr/libexec/newton/newton-wan-health run",
        "set respawn",
        "set stdout 1",
        "set stderr 1",
        "close",
        "trigger newton_wanhealth",
    ]
    text = INIT.read_text()
    assert text.startswith("#!/bin/sh /etc/rc.common\n")
    assert "USE_PROCD=1" in text
    assert "START=95" in text
    assert "/usr/libexec/newton/newton-wan-health restore" in text


@pytest.mark.parametrize(
    "command",
    [
        ["bash", "-n"],
        ["busybox", "sh", "-n"],
        ["shellcheck", "-S", "warning"],
    ],
)
def test_shell_syntax_and_lint(command):
    if shutil.which(command[0]) is None:
        pytest.skip(f"{command[0]} is not installed")
    result = subprocess.run(
        [*command, str(SCRIPT), str(INIT)],
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
