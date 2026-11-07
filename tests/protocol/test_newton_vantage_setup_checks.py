"""The vantage setup utility can install and check the client-check identity.

scripts/newton-vantage-setup gains two actions next to the existing
install/check pair:

  install-client-checks  writes the newton-vantage-check forced command and
                         its allow-list on the vantage, and gives the second
                         (check) key a restricted authorized_keys line.
  check-client-checks    proves the check key is still confined, and that
                         the canary check of the first zone is reachable.

Every test drives the script through a fake ssh that runs the remote side
in a sandbox, so nothing lands outside the tmp tree.
"""

import base64
import hashlib
import os
import re
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
SETUP = ROOT / "scripts" / "newton-vantage-setup"
CHECK_SRC = ROOT / "scripts" / "newton-vantage-check"

ALLOW_EXPECTED = (
    "zone guest src 192.0.2.50 canary 192.0.2.1 53 iface eth0.30 netns guest\n"
    "target 10.0.0.0/8\n"
    "target 172.16.0.0/12\n"
    "target 192.168.0.0/16\n"
    "target 100.64.0.0/10\n"
)


DEFAULT = object()

STANDARD_ZONE = (
    '{ name = "guest", src = "192.0.2.50", canary = "192.0.2.1:53",'
    ' iface = "eth0.30", netns = "guest" }'
)


def _toml_basic(value):
    return value.replace("\\", "\\\\").replace('"', '\\"')


def write_inventory(tmp_path, *, zones=DEFAULT, check_targets=None, extra=""):
    key_file = tmp_path / "keys" / "edge"
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("vantage.example.test ssh-ed25519 AAAATESTHOST\n")
    admin = tmp_path / "admin_key"
    admin.write_text("ADMIN-SECRET\n")
    admin.chmod(0o600)
    if zones is DEFAULT:
        zones = STANDARD_ZONE
    body = (
        "[vantages.edge]\n"
        'host = "vantage.example.test"\n'
        'user = "scanner"\n'
        f'key_file = "{key_file}"\n'
        f'known_hosts = "{known_hosts}"\n'
        'role = "inside"\n'
        'devices = ["router-a"]\n'
        f'admin_key = "{admin}"\n'
    )
    if zones is not None:
        body += f"zones = [ {zones} ]\n"
    if check_targets is not None:
        targets = ", ".join('"%s"' % t for t in check_targets)
        body += f"check_targets = [ {targets} ]\n"
    body += extra
    inventory = tmp_path / "devices.toml"
    inventory.write_text(body)
    inventory.chmod(0o644)
    return inventory, key_file, known_hosts, admin


def fake_tools(tmp_path, *, mode="remote"):
    """A fake ssh (and the few other host tools) the setup script uses.

    mode="remote" runs the remote command string inside a sandbox HOME,
    mode="check" answers like a vantage that has the forced command
    installed.
    """
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    log = tmp_path / "calls"

    fake_bin.joinpath("ssh-keygen").write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        "out=\n"
        "while [ \"$#\" -gt 0 ]; do\n"
        "  if [ \"$1\" = -f ]; then out=$2; shift 2; else shift; fi\n"
        "done\n"
        "[ -n \"$out\" ]\n"
        "mkdir -p \"$(dirname \"$out\")\"\n"
        "printf 'private fixture\\n' >\"$out\"\n"
        "printf 'ssh-ed25519 AAAACHECKKEY newton-vantage-edge\\n' >\"$out.pub\"\n"
    )
    fake_bin.joinpath("ssh-keygen").chmod(0o755)

    if mode == "remote":
        body = (
            "#!/bin/sh\n"
            "set -e\n"
            "{ printf 'CALL ssh\\n'; printf 'ARG %s\\n' \"$@\"; printf 'END\\n'; } >>\"$FAKE_LOG\"\n"
            "remote=\n"
            "for a in \"$@\"; do remote=$a; done\n"
            "{ printf 'REMOTE-CMD-BEGIN\\n'; printf '%s\\n' \"$remote\"; printf 'REMOTE-CMD-END\\n'; } >>\"$FAKE_LOG\"\n"
            "mkdir -p \"$FAKE_VANTAGE_ROOT\"\n"
            "STDIN_FILE=\"$FAKE_VANTAGE_ROOT/.stdin-snapshot\"\n"
            "cat >\"$STDIN_FILE\"\n"
            "if [ -n \"${FAKE_STDIN_TRANSFORM:-}\" ]; then\n"
            "  case \"$FAKE_STDIN_TRANSFORM\" in\n"
            "    truncate:*)\n"
            "      N=${FAKE_STDIN_TRANSFORM#truncate:}\n"
            "      /usr/bin/head -c \"$N\" \"$STDIN_FILE\" >\"$STDIN_FILE.tmp\"\n"
            "      /usr/bin/mv \"$STDIN_FILE.tmp\" \"$STDIN_FILE\"\n"
            "      ;;\n"
            "    bad_key_header)\n"
            "      /usr/bin/awk 'NR==1{print \"ssh-rsa BADKEY\"; next}{print}' \"$STDIN_FILE\" >\"$STDIN_FILE.tmp\"\n"
            "      /usr/bin/mv \"$STDIN_FILE.tmp\" \"$STDIN_FILE\"\n"
            "      ;;\n"
            "    bad_script_digest)\n"
            "      /usr/bin/awk 'NR==3{print \"abc12\"; next}{print}' \"$STDIN_FILE\" >\"$STDIN_FILE.tmp\"\n"
            "      /usr/bin/mv \"$STDIN_FILE.tmp\" \"$STDIN_FILE\"\n"
            "      ;;\n"
            "    bad_allow_digest)\n"
            "      /usr/bin/awk 'NR==5{print \"abc12\"; next}{print}' \"$STDIN_FILE\" >\"$STDIN_FILE.tmp\"\n"
            "      /usr/bin/mv \"$STDIN_FILE.tmp\" \"$STDIN_FILE\"\n"
            "      ;;\n"
            "    corrupt_script)\n"
            "      /usr/bin/awk 'NR==7{print \"#!/bin/sh\"; print \"# corrupted\"; next}{print}' \"$STDIN_FILE\" >\"$STDIN_FILE.tmp\"\n"
            "      /usr/bin/mv \"$STDIN_FILE.tmp\" \"$STDIN_FILE\"\n"
            "      ;;\n"
            "  esac\n"
            "fi\n"
            "{ printf 'STDIN-BEGIN\\n'; cat \"$STDIN_FILE\"; printf 'STDIN-END\\n'; } >>\"$FAKE_LOG\"\n"
            "exec 0<\"$STDIN_FILE\"\n"
            "HOME=${FAKE_HOME:-$FAKE_VANTAGE_ROOT/home}\n"
            "export HOME\n"
            "FAKE_BIN=\"$FAKE_VANTAGE_ROOT/fake-bin\"\n"
            "mkdir -p \"$FAKE_BIN\"\n"
            "export FAKE_BIN\n"
            "export FAKE_UID\n"
            "PATH=/usr/bin:/bin\n"
            "export PATH\n"
            "for tool in mkdir cp chmod mv rm rmdir touch ls grep tee mktemp tail cat head; do\n"
            "  printf '#!/bin/sh\\nexec /usr/bin/%s \"$@\"\\n' \"$tool\" >\"$FAKE_BIN/$tool\"\n"
            "  chmod 0755 \"$FAKE_BIN/$tool\"\n"
            "done\n"
            "ln -sf /usr/bin/awk \"$FAKE_BIN/awk\"\n"
            "cat >\"$FAKE_BIN/id\" <<'IDEOF'\n"
            "#!/bin/sh\n"
            "if [ \"$1\" = -u ]; then printf '%s\\n' \"$FAKE_UID\"; else /usr/bin/id \"$@\"; fi\n"
            "IDEOF\n"
            "chmod 0755 \"$FAKE_BIN/id\"\n"
            "cat >\"$FAKE_BIN/command\" <<'CMD'\n"
            "#!/bin/sh\n"
            "if [ \"$1\" = -v ]; then\n"
            "  shift\n"
            "  rc=0\n"
            "  for tool in \"$@\"; do\n"
            "    if [ -x \"$FAKE_BIN/$tool\" ]; then\n"
            "      printf '%s/%s\\n' \"$FAKE_BIN\" \"$tool\"\n"
            "    else\n"
            "      printf '%s: command not found\\n' \"$tool\" >&2\n"
            "      rc=1\n"
            "    fi\n"
            "  done\n"
            "  exit $rc\n"
            "fi\n"
            "exit 0\n"
            "CMD\n"
            "chmod 0755 \"$FAKE_BIN/command\"\n"
            "printf '#!/bin/sh\\nexit 0\\n' >\"$FAKE_BIN/timeout\"\n"
            "chmod 0755 \"$FAKE_BIN/timeout\"\n"
            "printf '#!/bin/sh\\nexit 0\\n' >\"$FAKE_BIN/bash\"\n"
            "chmod 0755 \"$FAKE_BIN/bash\"\n"
            "printf '#!/bin/sh\\nexec /usr/bin/sha256sum \"$@\"\\n' >\"$FAKE_BIN/sha256sum\"\n"
            "chmod 0755 \"$FAKE_BIN/sha256sum\"\n"
            "printf '#!/bin/sh\\nexec /usr/bin/base64 \"$@\"\\n' >\"$FAKE_BIN/base64\"\n"
            "chmod 0755 \"$FAKE_BIN/base64\"\n"
            "for tool in ${FAKE_MISSING_TOOLS:-}; do rm -f \"$FAKE_BIN/$tool\"; done\n"
            "export PATH=\"$FAKE_BIN\"\n"
            "/usr/bin/sh -c \"$remote\"\n"
        )
    else:
        body = (
            "#!/bin/sh\n"
            "set -e\n"
            "{ printf 'CALL ssh\\n'; printf 'ARG %s\\n' \"$@\"; printf 'END\\n'; } >>\"$FAKE_LOG\"\n"
            "remote=\n"
            "for a in \"$@\"; do remote=$a; done\n"
            "case \" $* \" in\n"
            "  *' -tt '*) printf 'PTY allocation request failed on channel 0\\n' >&2; exit 2 ;;\n"
            "  *' -R '*) printf 'remote port forwarding failed\\n' >&2; exit 255 ;;\n"
            "esac\n"
            "case $remote in\n"
            "  'check '*' canary')\n"
            "    if [ \"${FAKE_CANARY:-1}\" = 1 ]; then\n"
            "      printf 'RESULT PASS reached\\n'\n"
            "    else\n"
            "      printf 'RESULT NOTTESTED unreachable\\n'\n"
            "    fi\n"
            "    exit 0\n"
            "    ;;\n"
            "esac\n"
            "printf '%s\\n' \"${FAKE_REFUSAL_TEXT:-newton-scan: refused}\" >&2\n"
            "exit 2\n"
        )
    fake_bin.joinpath("ssh").write_text(body)
    fake_bin.joinpath("ssh").chmod(0o755)

    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    env["FAKE_LOG"] = str(log)
    env["FAKE_VANTAGE_ROOT"] = str(tmp_path / "vantage")
    env["FAKE_HOME"] = str(tmp_path / "vantage" / "home")
    env["FAKE_UID"] = "1000"
    env["NEWTON_INVENTORY"] = str(tmp_path / "devices.toml")
    env["NEWTON_VANTAGE_CHECK_SOURCE"] = str(CHECK_SRC)
    return env, log


def run_setup(env, action="install-client-checks", vantage="edge"):
    return subprocess.run(
        [str(SETUP), vantage, action],
        text=True,
        capture_output=True,
        env=env,
        timeout=30,
    )


def call_blocks(log):
    text = log.read_text()
    return re.findall(r"CALL ([^\n]+)\n(.*?)END\n", text, re.DOTALL)


def args_for(block):
    return re.findall(r"^ARG (.*)$", block, re.MULTILINE)


def vantage_home(tmp_path):
    return tmp_path / "vantage" / "home"


# ---- install-client-checks -------------------------------------------------


def test_install_client_checks_writes_script_allow_list_and_restricted_line(tmp_path):
    inventory, key_file, _known_hosts, _admin = write_inventory(tmp_path)
    env, log = fake_tools(tmp_path)

    result = run_setup(env)

    assert result.returncode == 0, result.stdout + result.stderr
    home = vantage_home(tmp_path)
    script = home / ".local" / "libexec" / "newton-vantage-check"
    allow = home / ".local" / "libexec" / "newton-vantage-check.allow"
    assert script.read_bytes() == CHECK_SRC.read_bytes()
    assert oct(script.stat().st_mode & 0o777) == "0o755"
    assert allow.read_text() == ALLOW_EXPECTED
    assert oct(allow.stat().st_mode & 0o777) == "0o644"
    authorized = (home / ".ssh" / "authorized_keys").read_text()
    assert (
        f'restrict,command="{home}/.local/libexec/newton-vantage-check" '
        "ssh-ed25519 AAAACHECKKEY newton-vantage-check-edge\n"
    ) in authorized
    # The check key is a second key, not the scan key.
    assert (key_file.parent / (key_file.name + "-check")).is_file()
    assert result.stdout == "DONE install-client-checks edge\n"


def test_install_client_checks_sends_the_digests_and_the_payload(tmp_path):
    write_inventory(tmp_path)
    env, log = fake_tools(tmp_path)

    result = run_setup(env)

    assert result.returncode == 0, result.stdout + result.stderr
    stdin_text = "\n".join(
        re.findall(r"STDIN-BEGIN\n(.*?)\nSTDIN-END\n", log.read_text(), re.DOTALL)
    )
    assert "ssh-ed25519 AAAACHECKKEY" in stdin_text
    assert hashlib.sha256(CHECK_SRC.read_bytes()).hexdigest() in stdin_text
    encoded = base64.b64encode(ALLOW_EXPECTED.encode()).decode()
    assert encoded in stdin_text
    assert hashlib.sha256(ALLOW_EXPECTED.encode()).hexdigest() in stdin_text
    assert CHECK_SRC.read_text().rstrip("\n") in stdin_text


def test_install_client_checks_is_idempotent(tmp_path):
    write_inventory(tmp_path)
    env, log = fake_tools(tmp_path)

    first = run_setup(env)
    assert first.returncode == 0, first.stdout + first.stderr
    second = run_setup(env)
    assert second.returncode == 0, second.stdout + second.stderr

    authorized = (vantage_home(tmp_path) / ".ssh" / "authorized_keys").read_text()
    lines = [line for line in authorized.splitlines() if "newton-vantage-check" in line]
    assert len(lines) == 1


def test_install_client_checks_refuses_a_bad_key_header_before_any_change(tmp_path):
    write_inventory(tmp_path)
    env, log = fake_tools(tmp_path)
    env["FAKE_STDIN_TRANSFORM"] = "bad_key_header"

    result = run_setup(env)

    assert result.returncode == 2
    assert "key header" in result.stderr
    home = vantage_home(tmp_path)
    assert not (home / ".local" / "libexec" / "newton-vantage-check").exists()
    assert not (home / ".local" / "libexec" / "newton-vantage-check.allow").exists()
    assert not (home / ".ssh" / "authorized_keys").exists()


def test_install_client_checks_refuses_a_bad_script_digest_before_any_change(tmp_path):
    write_inventory(tmp_path)
    env, log = fake_tools(tmp_path)
    env["FAKE_STDIN_TRANSFORM"] = "bad_script_digest"

    result = run_setup(env)

    assert result.returncode == 2
    assert "64 lowercase hex" in result.stderr
    home = vantage_home(tmp_path)
    assert not (home / ".local" / "libexec" / "newton-vantage-check").exists()


def test_install_client_checks_refuses_a_bad_allow_list_digest_before_any_change(tmp_path):
    write_inventory(tmp_path)
    env, log = fake_tools(tmp_path)
    env["FAKE_STDIN_TRANSFORM"] = "bad_allow_digest"

    result = run_setup(env)

    assert result.returncode == 2
    assert "64 lowercase hex" in result.stderr
    home = vantage_home(tmp_path)
    assert not (home / ".local" / "libexec" / "newton-vantage-check.allow").exists()


def test_install_client_checks_refuses_a_corrupted_payload_before_any_change(tmp_path):
    write_inventory(tmp_path)
    env, log = fake_tools(tmp_path)
    env["FAKE_STDIN_TRANSFORM"] = "corrupt_script"

    result = run_setup(env)

    assert result.returncode == 2
    assert "sha256" in result.stderr and "mismatch" in result.stderr
    home = vantage_home(tmp_path)
    assert not (home / ".local" / "libexec" / "newton-vantage-check").exists()
    assert not (home / ".local" / "libexec" / "newton-vantage-check.allow").exists()
    assert not (home / ".ssh" / "authorized_keys").exists()


def test_install_client_checks_names_a_missing_tool(tmp_path):
    write_inventory(tmp_path)
    env, log = fake_tools(tmp_path)
    # base64 is not installed on this vantage.
    env["FAKE_MISSING_TOOLS"] = "base64"

    result = run_setup(env)

    assert result.returncode == 2
    assert "base64" in result.stderr
    home = vantage_home(tmp_path)
    assert not (home / ".local" / "libexec" / "newton-vantage-check").exists()


def test_install_client_checks_uses_the_default_check_targets(tmp_path):
    write_inventory(tmp_path, check_targets=None)
    env, log = fake_tools(tmp_path)

    result = run_setup(env)

    assert result.returncode == 0, result.stdout + result.stderr
    allow = (
        vantage_home(tmp_path)
        / ".local"
        / "libexec"
        / "newton-vantage-check.allow"
    )
    text = allow.read_text()
    assert "target 10.0.0.0/8\n" in text
    assert "target 172.16.0.0/12\n" in text
    assert "target 192.168.0.0/16\n" in text
    # VC-18: a router with a CGNAT address is a target too, so the range
    # has to be in the default allow-list.
    assert "target 100.64.0.0/10\n" in text


def test_install_client_checks_uses_the_inventory_check_targets(tmp_path):
    write_inventory(tmp_path, check_targets=["10.9.0.0/16"])
    env, log = fake_tools(tmp_path)

    result = run_setup(env)

    assert result.returncode == 0, result.stdout + result.stderr
    allow = (
        vantage_home(tmp_path)
        / ".local"
        / "libexec"
        / "newton-vantage-check.allow"
    )
    text = allow.read_text()
    assert "target 10.9.0.0/16\n" in text
    assert "target 10.0.0.0/8\n" not in text


def test_install_client_checks_refuses_a_vantage_without_zones(tmp_path):
    write_inventory(tmp_path, zones=None)
    env, log = fake_tools(tmp_path)

    result = run_setup(env)

    assert result.returncode == 2
    assert "zones" in result.stderr
    assert not log.exists()


@pytest.mark.parametrize(
    ("zones", "message"),
    [
        ('{ name = "guest", src = "192.0.2.500", canary = "192.0.2.1:53" }', "bad zones"),
        ('{ name = "guest", src = "192.0.2.50", canary = "192.0.2.1" }', "bad zones"),
        ('{ name = "guest", src = "192.0.2.50", canary = "192.0.2.1:0" }', "bad zones"),
        ('{ name = "guest", src = "192.0.2.50", canary = "192.0.2.1:053" }', "bad zones"),
        ('{ name = "guest", src = "192.0.2.50", canary = "192.0.2.1:53", colour = "red" }', "bad zones"),
        ('{ name = "Guest", src = "192.0.2.50", canary = "192.0.2.1:53" }', "bad zones"),
        (
            '{ name = "guest", src = "192.0.2.50", canary = "192.0.2.1:53" },'
            ' { name = "guest", src = "192.0.2.51", canary = "192.0.2.1:53" }',
            "bad zones",
        ),
    ],
)
def test_inventory_refuses_bad_zones_before_any_external_call(tmp_path, zones, message):
    write_inventory(tmp_path, zones=zones)
    env, log = fake_tools(tmp_path)

    result = run_setup(env)

    assert result.returncode == 2
    assert message in result.stderr
    assert not log.exists()


@pytest.mark.parametrize(
    "targets",
    [
        ["10.0.0.0/7"],
        ["10.0.0.0"],
        ["10.0.0.0/33"],
        ["not-a-cidr"],
        ["10.0.0.0/8", "10.0.0.0/8"],
        ["0.0.0.0/0"],
        ["10.0.0.0/08"],
        ["010.0.0.0/8"],
        ["10.0.%d.0/24" % index for index in range(33)],
    ],
)
def test_inventory_refuses_bad_check_targets_before_any_external_call(tmp_path, targets):
    write_inventory(tmp_path, check_targets=targets)
    env, log = fake_tools(tmp_path)

    result = run_setup(env)

    assert result.returncode == 2
    assert "bad check_targets" in result.stderr
    assert not log.exists()


def test_inventory_refuses_too_many_zones(tmp_path):
    zones = ", ".join(
        '{ name = "zone%d", src = "192.0.2.%d", canary = "192.0.2.1:53" }' % (n, n + 10)
        for n in range(17)
    )
    write_inventory(tmp_path, zones=zones)
    env, log = fake_tools(tmp_path)

    result = run_setup(env)

    assert result.returncode == 2
    assert "bad zones" in result.stderr
    assert not log.exists()


# ---- check-client-checks ---------------------------------------------------


def test_check_client_checks_proves_the_key_is_confined_and_the_canary_answers(tmp_path):
    write_inventory(tmp_path)
    env, log = fake_tools(tmp_path, mode="check")
    env["FAKE_REFUSAL_TEXT"] = "newton-vantage-check: refused"
    key_file = tmp_path / "keys" / "edge"
    key_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.write_text("existing private fixture\n")
    (key_file.parent / (key_file.name + "-check")).write_text("check private fixture\n")

    result = run_setup(env, action="check-client-checks")

    assert result.returncode == 0, result.stdout + result.stderr
    blocks = call_blocks(log)
    assert [name for name, _ in blocks] == ["ssh", "ssh", "ssh", "ssh"]
    for _name, block in blocks:
        args = args_for(block)
        assert str(key_file.parent / (key_file.name + "-check")) in args
        assert "-o\nIdentitiesOnly=yes" in "\n".join(args)
        assert "-o\nStrictHostKeyChecking=yes" in "\n".join(args)
    assert args_for(blocks[3][1])[-1] == "check guest canary"
    assert result.stdout == (
        "PASS empty command refused\n"
        "PASS forwarding blocked\n"
        "PASS pty blocked\n"
        "PASS canary\n"
        "DONE check-client-checks edge\n"
    )


def test_check_client_checks_fails_when_the_canary_is_not_reached(tmp_path):
    write_inventory(tmp_path)
    env, log = fake_tools(tmp_path, mode="check")
    env["FAKE_REFUSAL_TEXT"] = "newton-vantage-check: refused"
    key_file = tmp_path / "keys" / "edge"
    key_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.write_text("existing private fixture\n")
    (key_file.parent / (key_file.name + "-check")).write_text("check private fixture\n")
    env["FAKE_CANARY"] = "0"

    result = run_setup(env, action="check-client-checks")

    assert result.returncode == 1
    assert "FAIL canary" in result.stderr
    assert "PASS canary" not in result.stdout


def test_check_client_checks_uses_the_first_zone(tmp_path):
    zones = (
        '{ name = "guest", src = "192.0.2.50", canary = "192.0.2.1:53" },'
        ' { name = "lab", src = "192.0.2.60", canary = "192.0.2.1:53" }'
    )
    write_inventory(tmp_path, zones=zones)
    env, log = fake_tools(tmp_path, mode="check")
    env["FAKE_REFUSAL_TEXT"] = "newton-vantage-check: refused"
    key_file = tmp_path / "keys" / "edge"
    key_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.write_text("existing private fixture\n")
    (key_file.parent / (key_file.name + "-check")).write_text("check private fixture\n")

    result = run_setup(env, action="check-client-checks")

    assert result.returncode == 0, result.stdout + result.stderr
    blocks = call_blocks(log)
    assert args_for(blocks[3][1])[-1] == "check guest canary"


def test_the_existing_actions_are_unchanged(tmp_path):
    """install and check keep their behaviour: the new actions do not
    change the old ones."""
    write_inventory(tmp_path)
    env, log = fake_tools(tmp_path, mode="check")
    key_file = tmp_path / "keys" / "edge"
    key_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.write_text("existing private fixture\n")

    result = run_setup(env, action="check")

    assert result.returncode == 0, result.stdout + result.stderr
    blocks = call_blocks(log)
    assert [name for name, _ in blocks] == ["ssh", "ssh", "ssh"]
    assert result.stdout == (
        "PASS empty command refused\n"
        "PASS forwarding blocked\n"
        "PASS pty blocked\n"
        "DONE check edge\n"
    )


def test_usage_refuses_an_unknown_action(tmp_path):
    write_inventory(tmp_path)
    env, log = fake_tools(tmp_path)

    result = run_setup(env, action="install-client-check")

    assert result.returncode == 2
    assert "usage" in result.stderr
