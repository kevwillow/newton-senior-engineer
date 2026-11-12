"""VC-03, VC-04, VC-06, VC-07, VC-18: the vantage forced command for client checks.

scripts/newton-vantage-check is the only thing the second (check) key may
run on a vantage.  The original command is DATA: it is parsed into a fixed
grammar and one of a fixed set of argv lists is executed.  Every test here
drives the script through a fake PATH, so no real network, DNS or DHCP is
touched.

Test IDs
  VC-03  wrong-zone: the zone's src address is not configured where the
         check runs, so the vantage answers NOTTESTED wrong-zone.
  VC-04  the grammar is closed: every malformation is refused with rc 2 and
         no tool ever runs.
  VC-06  the five checks answer with the one RESULT line the host expects.
  VC-07  the allow-list is parsed strictly, an unknown zone and a missing
         allow-list are named, and the CIDR allow-list has sharp edges.
  VC-18  the zone is proved twice: the source address is configured where
         the check runs, and the route to the target leaves through it.
  VC-19  reach (the inverse of blocked) and the wider port rule: any port
         1..65535 for a host inside check_targets, the fixed port list for
         the public resolvers, and never the public resolvers for reach.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
CHECK = ROOT / "scripts" / "newton-vantage-check"

ALLOW_PLAIN = (
    "zone guest src 192.0.2.50 canary 192.0.2.1 53 iface eth0.30\n"
    "target 10.0.0.0/8\n"
    "target 172.16.0.0/12\n"
    "target 192.168.0.0/16\n"
)
ALLOW_NETNS = (
    "zone guest src 192.0.2.50 canary 192.0.2.1 53 iface eth0.30 netns guest\n"
    "target 10.0.0.0/8\n"
)
ADDR_LINE = "inet 192.0.2.50/24 brd 192.0.2.255 scope global eth0.30"
ZONE_SRC = "192.0.2.50"


def _write_exec(path, body):
    path.write_text(body)
    path.chmod(0o755)


def make_fake_path(tmp_path, *, tools=("timeout", "bash", "host", "ip", "sudo", "python3")):
    """A PATH of fake executables.  Nothing here touches the network."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    calls = tmp_path / "calls"

    def log(name):
        return (
            "{ printf 'CALL %s\\n'; printf 'ARG %%s\\n' \"$@\"; printf 'END\\n'; }"
            " >>\"$NEWTON_CHECK_CALLS\"\n" % name
        )

    if "timeout" in tools:
        # timeout <secs> <cmd...>: runs the command unless the target is
        # listed in FAKE_TIMEOUT_TARGETS, in which case it behaves like a
        # real timeout that killed the command (rc 124).
        _write_exec(
            fake_bin / "timeout",
            "#!/bin/sh\n"
            "set -eu\n"
            + log("timeout")
            + "secs=$1\n"
            "shift\n"
            "last=\n"
            "prev=\n"
            "for a in \"$@\"; do prev=$last; last=$a; done\n"
            "case \",${FAKE_TIMEOUT_TARGETS:-},\" in\n"
            "  *\",$prev:$last,\"*) exit 124 ;;\n"
            "esac\n"
            "exec \"$@\"\n",
        )
    if "bash" in tools:
        # bash -c <code> bash <ip> <port>: stands in for the /dev/tcp
        # connect.  The target lists decide the outcome.
        _write_exec(
            fake_bin / "bash",
            "#!/bin/sh\n"
            "set -eu\n"
            + log("bash")
            + "last=\n"
            "prev=\n"
            "for a in \"$@\"; do prev=$last; last=$a; done\n"
            "case \",${FAKE_OPEN_TARGETS:-},\" in\n"
            "  *\",$prev:$last,\"*) exit 0 ;;\n"
            "esac\n"
            "case \",${FAKE_UNREACHABLE_TARGETS:-},\" in\n"
            "  *\",$prev:$last,\"*) printf 'bash: connect: Network is unreachable\\n' >&2; exit 1 ;;\n"
            "esac\n"
            "printf 'bash: connect: Connection refused\\n' >&2\n"
            "exit 1\n",
        )
    if "host" in tools:
        _write_exec(
            fake_bin / "host",
            "#!/bin/sh\n"
            "set -eu\n"
            + log("host")
            + "if [ \"${FAKE_HOST_ANSWER:-1}\" = 1 ]; then\n"
            "  printf 'openwrt.org has address 198.51.100.9\\n'\n"
            "else\n"
            "  printf 'openwrt.org has no address\\n'\n"
            "fi\n",
        )
    if "ip" in tools:
        # `ip netns exec <ns> <cmd...>` runs the command in the namespace:
        # the stub hands the rest of the command over and remembers the
        # namespace, so a later address lookup answers for that namespace.
        # `ip -4 route get <ip>` answers from the route table of the test:
        # FAKE_ROUTE_TABLE holds "<target>=<src>" pairs, FAKE_ROUTE_SRC is
        # the source address of every other target and FAKE_ROUTE_FAIL
        # makes the route lookup fail.
        _write_exec(
            fake_bin / "ip",
            "#!/bin/sh\n"
            "set -eu\n"
            + log("ip")
            + "if [ \"${1-}\" = netns ] && [ \"${2-}\" = exec ]; then\n"
            "  ns=$3\n"
            "  shift 3\n"
            "  NEWTON_FAKE_NETNS=$ns\n"
            "  export NEWTON_FAKE_NETNS\n"
            "  exec \"$@\"\n"
            "fi\n"
            + "if [ \"${1-}\" = -4 ] && [ \"${2-}\" = route ] && [ \"${3-}\" = get ]; then\n"
            "  target=${4-}\n"
            "  if [ -n \"${FAKE_ROUTE_FAIL:-}\" ]; then\n"
            "    printf 'ip: route get: %s: Network is unreachable\\n' \"$target\" >&2\n"
            "    exit 1\n"
            "  fi\n"
            "  src=\n"
            "  for pair in ${FAKE_ROUTE_TABLE:-}; do\n"
            "    case $pair in\n"
            "      \"$target\"=*) src=${pair#*=} ;;\n"
            "    esac\n"
            "  done\n"
            "  if [ -z \"$src\" ]; then src=${FAKE_ROUTE_SRC:-}; fi\n"
            "  if [ -z \"$src\" ]; then\n"
            "    printf 'ip: route get: %s: Network is unreachable\\n' \"$target\" >&2\n"
            "    exit 1\n"
            "  fi\n"
            "  printf '%s dev eth0 src %s uid 0\\n' \"$target\" \"$src\"\n"
            "  exit 0\n"
            "fi\n"
            + "if [ -n \"${NEWTON_FAKE_NETNS:-}\" ]; then\n"
            "  printf '%s\\n' \"${FAKE_ADDRS_NS:-${FAKE_ADDRS:-}}\"\n"
            "else\n"
            "  printf '%s\\n' \"${FAKE_ADDRS:-}\"\n"
            "fi\n",
        )
    if "sudo" in tools:
        _write_exec(
            fake_bin / "sudo",
            "#!/bin/sh\n"
            "set -eu\n"
            + log("sudo")
            + "if [ \"${1-}\" = -n ]; then shift; fi\n"
            "exec \"$@\"\n",
        )
    if "python3" in tools:
        _write_exec(
            fake_bin / "python3",
            "#!/bin/sh\n"
            "set -eu\n"
            + log("python3")
            # The probe program arrives on stdin; read it with the shell
            # builtin so the fake PATH needs no coreutils.
            + "while IFS= read -r line; do :; done\n"
            + "if [ \"${FAKE_DHCP_ANSWER:-1}\" = 1 ]; then\n"
            "  printf 'newton-dhcp-offer: DHCPOFFER from %s yiaddr=192.0.2.60 after 0.1s (no REQUEST sent)\\n' \"${3-}\"\n"
            "else\n"
            "  printf 'newton-dhcp-offer: no DHCPOFFER from %s on %s within 12s\\n' \"${3-}\" \"${2-}\"\n"
            "fi\n",
        )

    env = os.environ.copy()
    env["PATH"] = str(fake_bin)
    env["NEWTON_CHECK_CALLS"] = str(calls)
    env["FAKE_ADDRS"] = ADDR_LINE
    # the route to a target leaves through the zone's own address unless
    # the test says otherwise
    env["FAKE_ROUTE_SRC"] = ZONE_SRC
    return env, calls


def run_check(tmp_path, command, *, allow=ALLOW_PLAIN, unset=False, tools=None, **overrides):
    """Run the forced command from a copy in its own directory, so that
    ${0%/*} is the directory that holds the allow-list."""
    env, calls = make_fake_path(tmp_path, tools=tools or ("timeout", "bash", "host", "ip", "sudo", "python3"))
    vantage = tmp_path / "vantage"
    vantage.mkdir(exist_ok=True)
    script = vantage / "newton-vantage-check"
    shutil.copy(CHECK, script)
    if allow is not None:
        (vantage / "newton-vantage-check.allow").write_text(allow)
    if unset:
        env.pop("SSH_ORIGINAL_COMMAND", None)
    else:
        env["SSH_ORIGINAL_COMMAND"] = command
    env.update(overrides)
    result = subprocess.run(
        ["/bin/sh", str(script)],
        text=True,
        capture_output=True,
        env=env,
        timeout=30,
    )
    text = calls.read_text() if calls.exists() else ""
    return result, call_names(text), text


def call_names(text):
    names = []
    for block in text.split("CALL ")[1:]:
        names.append(block.splitlines()[0])
    return names


# ---- VC-04: the grammar is closed ------------------------------------------


REFUSED = [
    pytest.param("", id="empty"),
    pytest.param("ignored", id="unset"),
    pytest.param("scan guest canary", id="wrong-verb"),
    pytest.param("check guest", id="no-verb"),
    pytest.param("check guest canary extra", id="extra-token"),
    pytest.param("check guest CANARY", id="uppercase-verb"),
    pytest.param("check GUEST canary", id="uppercase-zone"),
    pytest.param("check guest dns extra", id="extra-token-dns"),
    pytest.param("check guest blocked 192.0.2.1", id="blocked-without-port"),
    pytest.param("check guest blocked 192.0.2.1 22 extra", id="blocked-extra-token"),
    pytest.param("check guest blocked 192.0.2.1 0", id="blocked-port-zero"),
    pytest.param("check guest blocked 192.0.2.1 65536", id="blocked-port-too-big"),
    pytest.param("check guest blocked 192.0.2.1 http", id="blocked-port-not-a-number"),
    pytest.param("check guest blocked 192.0.2.1 053", id="blocked-leading-zero-port"),
    pytest.param("check guest blocked 192.0.2.1 0443", id="blocked-leading-zero-https-port"),
    pytest.param("check guest blocked 192.0.2.256 22", id="blocked-large-octet"),
    pytest.param("check guest blocked 192.0.2 22", id="blocked-short-ip"),
    pytest.param("check guest blocked 192.0.2.1.5 22", id="blocked-long-ip"),
    pytest.param("check guest blocked 192.0.2.1:22", id="blocked-colon-port"),
    pytest.param("check guest blocked 192.0.2.1 22;id", id="semicolon"),
    pytest.param("check guest blocked $(id) 22", id="dollar-command"),
    pytest.param("check guest blocked 192.0.2.1 22\nid", id="newline"),
    pytest.param("check guest blocked 2001:db8::1 22", id="ipv6"),
    pytest.param("check guest reach 192.0.2.1", id="reach-without-port"),
    pytest.param("check guest reach 192.0.2.1 22 extra", id="reach-extra-token"),
    pytest.param("check guest reach 192.0.2.1 0", id="reach-port-zero"),
    pytest.param("check guest reach 192.0.2.1 65536", id="reach-port-too-big"),
    pytest.param("check guest reach 192.0.2.256 22", id="reach-large-octet"),
    pytest.param("check guest reach 192.0.2.1:22", id="reach-colon-port"),
    pytest.param("check guest reach 192.0.2.1 053", id="reach-leading-zero-port"),
    pytest.param("check guest reach $(id) 22", id="reach-dollar-command"),
    pytest.param("check guest reach 192.0.2.1 22;id", id="reach-semicolon"),
    pytest.param("check guest reach 192.0.2.1 22 ", id="reach-trailing-space"),
    pytest.param(" check guest canary", id="leading-space"),
    pytest.param("check  guest canary", id="double-space"),
    pytest.param("check guest canary ", id="trailing-space"),
    pytest.param("check guest blocked 192.0.2.1 22 ", id="blocked-trailing-space"),
    pytest.param("check guest blocked 192.0.2.1 22 --script", id="flag-like-token"),
]


@pytest.mark.parametrize("command", REFUSED)
def test_vc04_refused_grammar_never_runs_a_tool(tmp_path, command):
    result, names, _text = run_check(tmp_path, command)

    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr == "newton-vantage-check: refused\n"
    assert names == []


def test_vc04_unset_original_command_is_refused(tmp_path):
    result, names, _text = run_check(tmp_path, "", unset=True)

    assert result.returncode == 2
    assert result.stderr == "newton-vantage-check: refused\n"
    assert names == []


def test_vc04_script_is_a_posix_shell_without_a_shell_string_seam():
    text = CHECK.read_text()
    assert text.startswith("#!/bin/sh\n")
    assert "set -eu" in text
    assert "eval" not in text
    assert "sh -c" not in text.replace("bash -c", "")
    # No NEWTON_* environment seam: the forced command reads nothing but
    # SSH_ORIGINAL_COMMAND and the allow-list next to itself.
    assert "NEWTON_" not in text
    # the checkout mode follows the umask (0775 under umask 002); git records 0755
    assert CHECK.stat().st_mode & 0o111 == 0o111


def test_vc04_busybox_and_shellcheck_accept_script():
    busybox = shutil.which("busybox")
    shellcheck = shutil.which("shellcheck")
    if busybox is None and shellcheck is None:
        pytest.skip("neither busybox nor shellcheck is installed")

    if busybox is not None:
        syntax = subprocess.run(
            [busybox, "sh", "-n", str(CHECK)], text=True, capture_output=True, timeout=10
        )
        assert syntax.returncode == 0, syntax.stderr

    if shellcheck is not None:
        checked = subprocess.run(
            [shellcheck, "-S", "warning", str(CHECK)],
            text=True,
            capture_output=True,
            timeout=20,
        )
        assert checked.returncode == 0, checked.stdout + checked.stderr


# ---- VC-06: the checks answer with one RESULT line -------------------------


def test_vc06_canary_reached_passes(tmp_path):
    result, names, _text = run_check(
        tmp_path, "check guest canary", FAKE_OPEN_TARGETS="192.0.2.1:53"
    )

    assert result.returncode == 0
    assert result.stdout == "RESULT PASS reached\n"
    assert result.stderr == ""
    # the address of the zone, then the route to the canary, then the probe
    assert names == ["ip", "ip", "timeout", "bash"]


def test_vc06_canary_refused_is_not_tested(tmp_path):
    result, _names, _text = run_check(
        tmp_path, "check guest canary", FAKE_REFUSED_TARGETS="192.0.2.1:53"
    )

    assert result.returncode == 0
    assert result.stdout == "RESULT NOTTESTED unreachable\n"


def test_vc06_canary_timeout_is_not_tested(tmp_path):
    result, _names, _text = run_check(
        tmp_path, "check guest canary", FAKE_TIMEOUT_TARGETS="192.0.2.1:53"
    )

    assert result.returncode == 0
    assert result.stdout == "RESULT NOTTESTED unreachable\n"


def test_vc06_dns_resolved_passes(tmp_path):
    result, names, _text = run_check(tmp_path, "check guest dns")

    assert result.returncode == 0
    assert result.stdout == "RESULT PASS resolved\n"
    assert "host" in names


def test_vc06_dns_without_an_answer_fails(tmp_path):
    result, _names, _text = run_check(
        tmp_path, "check guest dns", FAKE_HOST_ANSWER="0"
    )

    assert result.returncode == 0
    assert result.stdout == "RESULT FAIL no-answer\n"


def test_vc06_dns_without_the_host_tool_is_not_tested(tmp_path):
    result, _names, _text = run_check(
        tmp_path, "check guest dns", tools=("timeout", "bash", "ip", "sudo")
    )

    assert result.returncode == 0
    assert result.stdout == "RESULT NOTTESTED no-tool\n"


def test_vc06_internet_online_passes(tmp_path):
    result, names, _text = run_check(
        tmp_path, "check guest internet", FAKE_OPEN_TARGETS="1.1.1.1:443"
    )

    assert result.returncode == 0
    assert result.stdout == "RESULT PASS online\n"
    assert "host" in names


def test_vc06_internet_with_the_second_resolver_passes(tmp_path):
    result, _names, _text = run_check(
        tmp_path, "check guest internet", FAKE_OPEN_TARGETS="9.9.9.9:443"
    )

    assert result.returncode == 0
    assert result.stdout == "RESULT PASS online\n"


def test_vc06_internet_without_a_route_fails(tmp_path):
    result, _names, _text = run_check(tmp_path, "check guest internet")

    assert result.returncode == 0
    assert result.stdout == "RESULT FAIL no-internet\n"


def test_vc06_internet_without_dns_fails(tmp_path):
    result, _names, _text = run_check(
        tmp_path,
        "check guest internet",
        FAKE_OPEN_TARGETS="1.1.1.1:443",
        FAKE_HOST_ANSWER="0",
    )

    assert result.returncode == 0
    assert result.stdout == "RESULT FAIL no-internet\n"


def test_vc06_dhcp_offer_passes(tmp_path):
    result, names, _text = run_check(tmp_path, "check guest dhcp")

    assert result.returncode == 0
    assert result.stdout == "RESULT PASS offer\n"
    assert "python3" in names
    assert "sudo" in names


def test_vc06_dhcp_without_an_offer_fails(tmp_path):
    result, _names, _text = run_check(
        tmp_path, "check guest dhcp", FAKE_DHCP_ANSWER="0"
    )

    assert result.returncode == 0
    assert result.stdout == "RESULT FAIL no-offer\n"


def test_vc06_dhcp_without_an_interface_is_not_tested(tmp_path):
    allow = "zone guest src 192.0.2.50 canary 192.0.2.1 53\n"
    result, _names, _text = run_check(tmp_path, "check guest dhcp", allow=allow)

    assert result.returncode == 0
    assert result.stdout == "RESULT NOTTESTED no-iface\n"


def test_vc06_dhcp_without_python_is_not_tested(tmp_path):
    result, _names, _text = run_check(
        tmp_path, "check guest dhcp", tools=("timeout", "bash", "host", "ip", "sudo")
    )

    assert result.returncode == 0
    assert result.stdout == "RESULT NOTTESTED no-tool\n"


def test_vc06_blocked_refused_passes(tmp_path):
    result, _names, _text = run_check(tmp_path, "check guest blocked 192.168.1.1 22")

    assert result.returncode == 0
    assert result.stdout == "RESULT PASS refused\n"


def test_vc06_blocked_open_fails(tmp_path):
    result, _names, _text = run_check(
        tmp_path,
        "check guest blocked 192.168.1.1 22",
        FAKE_OPEN_TARGETS="192.168.1.1:22",
    )

    assert result.returncode == 0
    assert result.stdout == "RESULT FAIL open\n"


def test_vc06_blocked_timeout_passes(tmp_path):
    result, _names, _text = run_check(
        tmp_path,
        "check guest blocked 192.168.1.1 22",
        FAKE_TIMEOUT_TARGETS="192.168.1.1:22",
    )

    assert result.returncode == 0
    assert result.stdout == "RESULT PASS timeout\n"


def test_vc06_blocked_unreachable_is_not_tested(tmp_path):
    result, _names, _text = run_check(
        tmp_path,
        "check guest blocked 192.168.1.1 22",
        FAKE_UNREACHABLE_TARGETS="192.168.1.1:22",
    )

    assert result.returncode == 0
    assert result.stdout == "RESULT NOTTESTED unreachable\n"


def test_vc06_blocked_port_outside_the_policy_is_not_allowed(tmp_path):
    # The public resolvers keep their fixed port list (22|53|80|443); a
    # host inside the allow-list may be probed on any port (VC-19).
    result, _names, _text = run_check(
        tmp_path, "check guest blocked 1.1.1.1 8080"
    )

    assert result.returncode == 0
    assert result.stdout == "RESULT NOTTESTED not-allowed\n"


def test_vc06_zone_with_a_netns_runs_inside_it(tmp_path):
    result, names, _text = run_check(
        tmp_path, "check guest canary", allow=ALLOW_NETNS, FAKE_OPEN_TARGETS="192.0.2.1:53"
    )

    assert result.returncode == 0
    assert result.stdout == "RESULT PASS reached\n"
    # Every probe went through the netns: sudo -n ip netns exec <ns> ...
    assert names == [
        "sudo", "ip", "ip",      # the address of the zone
        "sudo", "ip", "ip",      # the route to the canary
        "sudo", "ip", "timeout", "bash",
    ]


# ---- VC-03: wrong-zone ----------------------------------------------------


def test_vc03_zone_without_its_address_is_not_tested(tmp_path):
    result, names, _text = run_check(
        tmp_path,
        "check guest canary",
        FAKE_ADDRS="inet 198.51.100.7/24 brd 198.51.100.255 scope global eth0",
        FAKE_OPEN_TARGETS="192.0.2.1:53",
    )

    assert result.returncode == 0
    assert result.stdout == "RESULT NOTTESTED wrong-zone\n"
    # The check itself never ran: no probe was made.
    assert names == ["ip"]


def test_vc03_netns_without_the_zone_address_is_not_tested(tmp_path):
    result, names, _text = run_check(
        tmp_path,
        "check guest canary",
        allow=ALLOW_NETNS,
        FAKE_ADDRS_NS="inet 198.51.100.7/24 brd 198.51.100.255 scope global eth0",
        FAKE_OPEN_TARGETS="192.0.2.1:53",
    )

    assert result.returncode == 0
    assert result.stdout == "RESULT NOTTESTED wrong-zone\n"
    assert names == ["sudo", "ip", "ip"]


# ---- VC-07: the allow-list ----------------------------------------------


def test_vc07_missing_allow_list_is_not_tested(tmp_path):
    result, names, _text = run_check(tmp_path, "check guest canary", allow=None)

    assert result.returncode == 0
    assert result.stdout == "RESULT NOTTESTED no-config\n"
    assert names == []


def test_vc07_unknown_zone_is_not_tested(tmp_path):
    result, _names, _text = run_check(tmp_path, "check lan canary")

    assert result.returncode == 0
    assert result.stdout == "RESULT NOTTESTED unknown-zone\n"


@pytest.mark.parametrize(
    "allow",
    [
        pytest.param("zone guest src 192.0.2.50 canary 192.0.2.1\n", id="short-zone-line"),
        pytest.param("zone guest src 192.0.2.50 canary 192.0.2.1 53 extra\n", id="extra-word"),
        pytest.param("zone guest src 192.0.2.50 canary 192.0.2.1 53 iface eth0.30 netns guest extra\n", id="extra-after-netns"),
        pytest.param("zone guest src 192.0.2.500 canary 192.0.2.1 53\n", id="bad-src"),
        pytest.param("zone guest src 192.0.2.50 canary 192.0.2.1 0\n", id="bad-canary-port"),
        pytest.param("zone guest src 192.0.2.50 canary 192.0.2.1 53 iface eth0.30 netns guest\ntarget 10.0.0.0/7\n", id="bad-prefix"),
        pytest.param("zone guest src 192.0.2.50 canary 192.0.2.1 53 iface eth0.30 netns guest\ntarget 10.0.0.0\n", id="target-without-prefix"),
        pytest.param("zone guest src 192.0.2.50 canary 192.0.2.1 53 iface eth0.30 netns guest\nzone guest src 192.0.2.51 canary 192.0.2.1 53\n", id="duplicate-zone"),
        pytest.param("zones guest src 192.0.2.50 canary 192.0.2.1 53\n", id="misspelled-key"),
        pytest.param("zone guest src 192.0.2.50 canary 192.0.2.1 53 netns guest iface eth0.30\n", id="netns-before-iface"),
    ],
)
def test_vc07_malformed_allow_list_is_not_tested(tmp_path, allow):
    result, names, _text = run_check(tmp_path, "check guest canary", allow=allow)

    assert result.returncode == 0
    assert result.stdout == "RESULT NOTTESTED bad-config\n"
    assert names == []


def test_vc07_comments_and_blank_lines_are_ignored(tmp_path):
    allow = (
        "# a comment\n"
        "\n"
        "zone guest src 192.0.2.50 canary 192.0.2.1 53 iface eth0.30\n"
        "# another comment\n"
        "target 10.0.0.0/8\n"
        "\n"
    )
    result, _names, _text = run_check(
        tmp_path, "check guest canary", allow=allow, FAKE_OPEN_TARGETS="192.0.2.1:53"
    )

    assert result.returncode == 0
    assert result.stdout == "RESULT PASS reached\n"


def test_vc17_whitespace_only_allow_list_lines_are_skipped(tmp_path):
    allow = "   \n\t\nzone guest src 192.0.2.50 canary 192.0.2.1 53\n"
    result, names, _text = run_check(
        tmp_path, "check guest canary", allow=allow, FAKE_OPEN_TARGETS="192.0.2.1:53"
    )

    assert result.returncode == 0
    assert result.stdout == "RESULT PASS reached\n"
    assert names == ["ip", "ip", "timeout", "bash"]


@pytest.mark.parametrize(
    "allow",
    [
        pytest.param(
            "zone guest  src 192.0.2.50 canary 192.0.2.1 53\n",
            id="double-space",
        ),
        pytest.param(
            "zone guest\tsrc 192.0.2.50 canary 192.0.2.1 53\n",
            id="tab",
        ),
    ],
)
def test_vc17_allow_list_fields_must_be_single_space_separated(tmp_path, allow):
    result, names, _text = run_check(
        tmp_path, "check guest canary", allow=allow, FAKE_OPEN_TARGETS="192.0.2.1:53"
    )

    assert result.returncode == 0
    assert result.stdout == "RESULT NOTTESTED bad-config\n"
    assert names == []


@pytest.mark.parametrize(
    "allow",
    [
        pytest.param(
            "zone guest src 192.0.2.50 canary 192.0.2.1 53\ntarget 10.0.0.0/08\n",
            id="leading-zero-prefix",
        ),
        pytest.param(
            "zone guest src 192.0.2.50 canary 192.0.2.1 53\ntarget 0.0.0.0/0\n",
            id="zero-prefix",
        ),
        pytest.param(
            "zone guest src 192.0.2.50 canary 192.0.2.1 53\ntarget 010.0.0.0/8\n",
            id="leading-zero-octet",
        ),
        pytest.param(
            "zone guest src 192.0.2.50 canary 192.0.2.1 053\n",
            id="leading-zero-canary-port",
        ),
    ],
)
def test_vc17_noncanonical_config_numbers_are_bad_config(tmp_path, allow):
    result, names, _text = run_check(tmp_path, "check guest canary", allow=allow)

    assert result.returncode == 0
    assert result.stdout == "RESULT NOTTESTED bad-config\n"
    assert names == []


def test_vc17_duplicate_check_target_is_bad_config(tmp_path):
    allow = (
        "zone guest src 192.0.2.50 canary 192.0.2.1 53\n"
        "target 10.0.0.0/8\n"
        "target 10.0.0.0/8\n"
    )
    result, names, _text = run_check(tmp_path, "check guest canary", allow=allow)

    assert result.returncode == 0
    assert result.stdout == "RESULT NOTTESTED bad-config\n"
    assert names == []


def test_vc17_more_than_thirty_two_check_targets_is_bad_config(tmp_path):
    targets = "".join("target 10.0.%d.0/24\n" % index for index in range(33))
    allow = "zone guest src 192.0.2.50 canary 192.0.2.1 53\n" + targets
    result, names, _text = run_check(tmp_path, "check guest canary", allow=allow)

    assert result.returncode == 0
    assert result.stdout == "RESULT NOTTESTED bad-config\n"
    assert names == []


def test_vc17_a_32_character_zone_name_is_accepted(tmp_path):
    zone_name = "z" * 32
    allow = f"zone {zone_name} src 192.0.2.50 canary 192.0.2.1 53\n"
    result, _names, _text = run_check(
        tmp_path,
        f"check {zone_name} canary",
        allow=allow,
        FAKE_OPEN_TARGETS="192.0.2.1:53",
    )

    assert result.returncode == 0
    assert result.stdout == "RESULT PASS reached\n"


def test_vc17_allow_list_without_a_trailing_newline_parses(tmp_path):
    allow = "zone guest src 192.0.2.50 canary 192.0.2.1 53\ntarget 10.0.0.0/8"
    result, _names, _text = run_check(
        tmp_path, "check guest canary", allow=allow, FAKE_OPEN_TARGETS="192.0.2.1:53"
    )

    assert result.returncode == 0
    assert result.stdout == "RESULT PASS reached\n"


def test_vc07_zone_without_an_optional_interface_is_accepted(tmp_path):
    allow = "zone guest src 192.0.2.50 canary 192.0.2.1 53\n"
    result, _names, _text = run_check(
        tmp_path, "check guest canary", allow=allow, FAKE_OPEN_TARGETS="192.0.2.1:53"
    )

    assert result.returncode == 0
    assert result.stdout == "RESULT PASS reached\n"


@pytest.mark.parametrize(
    ("target", "probe", "allowed"),
    [
        ("10.0.0.0/8", "10.1.2.3", True),
        ("10.0.0.0/8", "10.255.255.255", True),
        ("10.0.0.0/8", "11.0.0.0", False),
        ("192.168.1.0/24", "192.168.1.0", True),
        ("192.168.1.0/24", "192.168.1.255", True),
        ("192.168.1.0/24", "192.168.2.1", False),
        ("192.168.1.0/24", "192.168.0.255", False),
        ("203.0.113.7/32", "203.0.113.7", True),
        ("203.0.113.7/32", "203.0.113.8", False),
        ("172.16.0.0/12", "172.31.255.255", True),
        ("172.16.0.0/12", "172.32.0.0", False),
        ("172.16.0.0/12", "172.16.0.0", True),
        ("172.16.0.0/12", "172.15.255.255", False),
        ("10.0.0.0/10", "10.63.255.255", True),
        ("10.0.0.0/10", "10.64.0.0", False),
        ("192.0.2.0/23", "192.0.3.255", True),
        ("192.0.2.0/23", "192.0.4.0", False),
    ],
)
def test_vc07_cidr_edges_are_exact(tmp_path, target, probe, allowed):
    allow = "zone guest src 192.0.2.50 canary 192.0.2.1 53\ntarget %s\n" % target
    result, _names, _text = run_check(
        tmp_path, "check guest blocked %s 22" % probe, allow=allow
    )

    if allowed:
        assert result.stdout == "RESULT PASS refused\n", result.stdout
    else:
        assert result.stdout == "RESULT NOTTESTED not-allowed\n", result.stdout


def test_vc07_public_resolvers_are_allowed_without_a_target(tmp_path):
    allow = "zone guest src 192.0.2.50 canary 192.0.2.1 53\n"
    result, _names, _text = run_check(tmp_path, "check guest blocked 1.1.1.1 443", allow=allow)

    assert result.stdout == "RESULT PASS refused\n"


def test_vc07_the_key_is_not_a_scan_oracle(tmp_path):
    allow = "zone guest src 192.0.2.50 canary 192.0.2.1 53\ntarget 10.0.0.0/8\n"
    result, names, _text = run_check(tmp_path, "check guest blocked 198.51.100.9 443", allow=allow)

    assert result.stdout == "RESULT NOTTESTED not-allowed\n"
    # No probe was made at all for a target outside the allow-list.
    assert "bash" not in names


# ---- VC-18: further review fixes ------------------------------------------


def test_vc18_01_a_zone_that_does_not_hold_the_source_address_is_wrong_zone(tmp_path):
    """VC-18: the address field is matched exactly.

    ``ip -4 -o addr show`` answers "inet 110.0.0.1/24"; a zone whose
    source address is 10.0.0.1 is not in that zone.
    """
    allow = "zone guest src 10.0.0.1 canary 192.0.2.1 53\n"
    result, names, _text = run_check(
        tmp_path,
        "check guest canary",
        allow=allow,
        FAKE_ADDRS="inet 110.0.0.1/24 brd 110.0.0.255 scope global eth0",
        FAKE_ROUTE_SRC="10.0.0.1",
        FAKE_OPEN_TARGETS="192.0.2.1:53",
    )

    assert result.returncode == 0
    assert result.stdout == "RESULT NOTTESTED wrong-zone\n"
    # No probe was made: the vantage is not in the zone.
    assert "bash" not in names


@pytest.mark.parametrize(
    "command",
    [
        "check guest canary",
        "check guest internet",
        "check guest blocked 192.168.1.1 22",
    ],
)
def test_vc18_02_a_probe_from_another_source_address_is_wrong_zone(tmp_path, command):
    """VC-18: the probe must leave through the zone's own address.

    A zone without a netns probes from the routing default otherwise, so
    the answer would be about the wrong address.
    """
    result, names, _text = run_check(
        tmp_path,
        command,
        FAKE_ROUTE_SRC="198.51.100.7",
        FAKE_OPEN_TARGETS="192.0.2.1:53",
    )

    assert result.returncode == 0
    assert result.stdout == "RESULT NOTTESTED wrong-zone\n"
    # No probe was made at all.
    assert "bash" not in names


def test_vc18_03_a_route_that_cannot_be_read_is_wrong_zone(tmp_path):
    result, names, _text = run_check(
        tmp_path,
        "check guest canary",
        FAKE_ROUTE_FAIL="1",
        FAKE_OPEN_TARGETS="192.0.2.1:53",
    )

    assert result.returncode == 0
    assert result.stdout == "RESULT NOTTESTED wrong-zone\n"
    assert "bash" not in names


def test_vc18_04_a_route_with_the_zone_source_address_probes_as_before(tmp_path):
    result, names, _text = run_check(
        tmp_path,
        "check guest canary",
        FAKE_ROUTE_TABLE="192.0.2.1=192.0.2.50",
        FAKE_OPEN_TARGETS="192.0.2.1:53",
    )

    assert result.returncode == 0
    assert result.stdout == "RESULT PASS reached\n"
    assert "bash" in names


def test_vc18_05_the_name_lookup_is_not_a_tcp_probe(tmp_path):
    """The dns check asks the zone's router, not a port: it needs no route."""
    result, names, _text = run_check(
        tmp_path,
        "check guest dns",
        FAKE_ROUTE_SRC="198.51.100.7",
    )

    assert result.returncode == 0
    assert result.stdout == "RESULT PASS resolved\n"
    assert "host" in names


def test_vc18_06_the_script_runs_with_the_c_locale(tmp_path):
    """VC-18: bash says "Connection refused" in English only under LC_ALL=C."""
    text = CHECK.read_text()
    assert "LC_ALL=C" in text
    assert "export LC_ALL" in text


# ---- VC-19: reach and the wider blocked ports ---------------------------------
#
# `reach <ip> <port>` is the inverse of `blocked`: PASS when a TCP
# connect succeeds, FAIL when it is refused or times out.  The target
# must be inside the root-owned allow-list `check_targets`; the public
# resolvers are never a reach target.  For `reach`, and for `blocked`
# against a host inside `check_targets`, any port 1..65535 is allowed;
# `blocked` against 1.1.1.1/9.9.9.9 keeps its current port list.


def test_vc19_reach_open_passes(tmp_path):
    result, names, _text = run_check(
        tmp_path,
        "check guest reach 192.168.1.50 631",
        FAKE_OPEN_TARGETS="192.168.1.50:631",
    )

    assert result.returncode == 0
    assert result.stdout == "RESULT PASS reached\n"
    assert "bash" in names


def test_vc19_reach_refused_fails(tmp_path):
    result, _names, _text = run_check(tmp_path, "check guest reach 192.168.1.50 631")

    assert result.returncode == 0
    assert result.stdout == "RESULT FAIL refused\n"


def test_vc19_reach_timeout_fails(tmp_path):
    result, _names, _text = run_check(
        tmp_path,
        "check guest reach 192.168.1.50 631",
        FAKE_TIMEOUT_TARGETS="192.168.1.50:631",
    )

    assert result.returncode == 0
    assert result.stdout == "RESULT FAIL timeout\n"


def test_vc19_reach_unreachable_is_not_tested(tmp_path):
    result, _names, _text = run_check(
        tmp_path,
        "check guest reach 192.168.1.50 631",
        FAKE_UNREACHABLE_TARGETS="192.168.1.50:631",
    )

    assert result.returncode == 0
    assert result.stdout == "RESULT NOTTESTED unreachable\n"


def test_vc19_reach_outside_the_allow_list_is_not_a_scan_oracle(tmp_path):
    allow = "zone guest src 192.0.2.50 canary 192.0.2.1 53\ntarget 10.0.0.0/8\n"
    result, names, _text = run_check(
        tmp_path, "check guest reach 198.51.100.9 443", allow=allow
    )

    assert result.stdout == "RESULT NOTTESTED not-allowed\n"
    # No probe was made at all for a target outside the allow-list.
    assert "bash" not in names


def test_vc19_reach_never_allows_the_public_resolvers(tmp_path):
    # `blocked` may probe 1.1.1.1 without a target line; `reach` may not:
    # the public resolvers are not inside check_targets.
    allow = "zone guest src 192.0.2.50 canary 192.0.2.1 53\n"
    result, names, _text = run_check(
        tmp_path, "check guest reach 1.1.1.1 443", allow=allow
    )

    assert result.stdout == "RESULT NOTTESTED not-allowed\n"
    assert "bash" not in names


def test_vc19_reach_from_the_wrong_zone_is_not_tested(tmp_path):
    result, names, _text = run_check(
        tmp_path,
        "check guest reach 192.168.1.50 631",
        FAKE_ROUTE_SRC="198.51.100.7",
        FAKE_OPEN_TARGETS="192.168.1.50:631",
    )

    assert result.returncode == 0
    assert result.stdout == "RESULT NOTTESTED wrong-zone\n"
    assert "bash" not in names


@pytest.mark.parametrize("port", [1, 53, 631, 65535])
def test_vc19_reach_accepts_the_ports_of_the_whole_range(tmp_path, port):
    result, _names, _text = run_check(
        tmp_path,
        "check guest reach 192.168.1.50 %d" % port,
        FAKE_OPEN_TARGETS="192.168.1.50:%d" % port,
    )
    assert result.returncode == 0
    assert result.stdout == "RESULT PASS reached\n"


@pytest.mark.parametrize("port", [22, 8080, 65535])
def test_vc19_blocked_inside_the_allow_list_accepts_any_port(tmp_path, port):
    # 192.168.1.1 is inside the 192.168.0.0/16 target of ALLOW_PLAIN; the
    # old port list (22|53|80|443) no longer applies to it.
    result, names, _text = run_check(
        tmp_path, "check guest blocked 192.168.1.1 %d" % port
    )
    assert result.returncode == 0
    assert result.stdout == "RESULT PASS refused\n"
    assert "bash" in names


def test_vc19_blocked_port_one_inside_the_allow_list_probes(tmp_path):
    result, _names, _text = run_check(tmp_path, "check guest blocked 10.1.2.3 1")

    assert result.stdout == "RESULT PASS refused\n"


@pytest.mark.parametrize("port", [22, 53, 80, 443])
def test_vc19_blocked_public_resolver_keeps_its_port_list(tmp_path, port):
    result, _names, _text = run_check(
        tmp_path, "check guest blocked 1.1.1.1 %d" % port
    )
    assert result.returncode == 0
    assert result.stdout == "RESULT PASS refused\n"


def test_vc19_blocked_public_resolver_outside_its_port_list_is_not_allowed(tmp_path):
    result, names, _text = run_check(
        tmp_path, "check guest blocked 9.9.9.9 8080"
    )

    assert result.stdout == "RESULT NOTTESTED not-allowed\n"
    assert "bash" not in names


def test_vc19_blocked_public_resolver_inside_the_targets_uses_any_port(tmp_path):
    # The allow-list wins over the fixed port list: an owner who lists
    # 1.1.1.1/32 in check_targets may probe every port of it.
    allow = (
        "zone guest src 192.0.2.50 canary 192.0.2.1 53\n"
        "target 1.1.1.1/32\n"
    )
    result, names, _text = run_check(
        tmp_path, "check guest blocked 1.1.1.1 8080", allow=allow
    )

    assert result.stdout == "RESULT PASS refused\n"
    assert "bash" in names
