"""Protocol tests for the small, owner-run vantage setup utility."""

import ast
import hashlib
import os
import re
import subprocess
from pathlib import Path

import pytest

from test_newton_isolation import INSTALL, install_test_env, launcher_text, make_executable, run


ROOT = Path(__file__).resolve().parents[2]
SETUP = ROOT / "scripts" / "newton-vantage-setup"
ROUTER_SETUP = ROOT / "scripts" / "newton-router-setup"
SCAN = ROOT / "scripts" / "newton-scan"


def _toml_basic(value):
    """Escape a string for a TOML basic string."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def write_inventory(tmp_path, *, extra="", auth="admin_key", proxy="proxy-helper --fixed"):
    key_file = tmp_path / "keys" / "edge"
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("vantage.example.test ssh-ed25519 AAAATESTHOST\n")
    admin = tmp_path / ("admin_key" if auth == "admin_key" else "admin_password")
    admin.write_text("ADMIN-SECRET\n")
    admin.chmod(0o600)
    inventory = tmp_path / "devices.toml"
    role_line = "" if 'role = ' in extra else 'role = "outside"\n'
    devices_line = "" if 'devices = ' in extra else 'devices = ["router-a", "router-b"]\n'
    proxy_line = "" if 'proxy_command = ' in extra else f'proxy_command = "{_toml_basic(proxy)}"\n'
    inventory.write_text(
        "[vantages.edge]\n"
        'host = "vantage.example.test"\n'
        'user = "scanner"\n'
        f'key_file = "{key_file}"\n'
        f'known_hosts = "{known_hosts}"\n'
        f"{proxy_line}"
        f"{role_line}"
        f"{devices_line}"
        f'{auth} = "{admin}"\n'
        f"{extra}"
    )
    # write_text creates 0666 & ~umask, which is 0664 under umask 0002 and is
    # refused by the inventory-file check.  Pin the fixture to 0644.
    inventory.chmod(0o644)
    return inventory, key_file, known_hosts, admin


def fake_tools(tmp_path, check_mode=False, *, run_remote=False):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    log = tmp_path / "calls"

    make_executable(
        fake_bin / "ssh-keygen",
        "#!/bin/sh\n"
        "set -eu\n"
        "{ printf 'CALL ssh-keygen\\n'; printf 'ARG %s\\n' \"$@\"; printf 'END\\n'; } >>\"$FAKE_LOG\"\n"
        "out=\n"
        "while [ \"$#\" -gt 0 ]; do\n"
        "  if [ \"$1\" = -f ]; then out=$2; shift 2; else shift; fi\n"
        "done\n"
        "[ -n \"$out\" ]\n"
        "mkdir -p \"$(dirname \"$out\")\"\n"
        "printf 'private fixture\\n' >\"$out\"\n"
        "printf 'ssh-ed25519 AAAAVANTAGE newton-vantage-edge\\n' >\"$out.pub\"\n",
    )
    make_executable(
        fake_bin / "scp",
        "#!/bin/sh\n"
        "set -eu\n"
        "{ printf 'CALL scp\\n'; printf 'ARG %s\\n' \"$@\"; printf 'END\\n'; } >>\"$FAKE_LOG\"\n"
        "# The install flow always copies scripts/newton-scan to\n"
        "# /tmp/newton-scan.newton-setup on the remote; write a placeholder\n"
        "# under the sandbox so the remote script's `cp` and `mv` succeed.\n"
        "for arg in \"$@\"; do\n"
        "  case $arg in\n"
        "    *:/tmp/newton-scan.newton-setup)\n"
        "      if [ -n \"${FAKE_VANTAGE_ROOT:-}\" ]; then\n"
        "        mkdir -p \"$FAKE_VANTAGE_ROOT/tmp\"\n"
        "        printf '#!/bin/sh\\nexit 0\\n' >\"$FAKE_VANTAGE_ROOT/tmp/newton-scan.newton-setup\"\n"
        "        chmod 0755 \"$FAKE_VANTAGE_ROOT/tmp/newton-scan.newton-setup\"\n"
        "      fi\n"
        "      ;;\n"
        "  esac\n"
        "done\n",
    )
    ssh_body = (
        "#!/bin/sh\n"
        "set -e\n"
        "{ printf 'CALL ssh\\n'; printf 'ARG %s\\n' \"$@\"; printf 'END\\n'; } >>\"$FAKE_LOG\"\n"
    )
    if check_mode:
        ssh_body += (
            "case \" $* \" in\n"
            "  *' -tt '*) printf 'PTY allocation request failed on channel 0\\n' >&2; exit 2 ;;\n"
            "  *' -R '*) printf 'remote port forwarding failed\\n' >&2; exit 255 ;;\n"
            "esac\n"
            "printf 'newton-scan: refused\\n' >&2\n"
            "exit 2\n"
        )
    elif run_remote:
        # Fake ssh that actually executes the remote command string in a
        # controlled vantage env (FAKE_UID, FAKE_HOME, FAKE_VANTAGE_ROOT,
        # PATH that includes or excludes nmap and timeout stubs).  Used
        # by the install-path tests so the real remote shell code runs.
        ssh_body += (
            "remote=\n"
            "for a in \"$@\"; do remote=$a; done\n"
            "{ printf 'REMOTE-CMD-BEGIN\\n'; printf '%s\\n' \"$remote\"; printf 'REMOTE-CMD-END\\n'; } >>\"$FAKE_LOG\"\n"
            "if [ -n \"${FAKE_VANTAGE_ROOT:-}\" ]; then\n"
            "  mkdir -p \"$FAKE_VANTAGE_ROOT\"\n"
            "  STDIN_FILE=\"$FAKE_VANTAGE_ROOT/.stdin-snapshot\"\n"
            "  cat >\"$STDIN_FILE\"\n"
            # tests can ask the fake ssh to mutate the stdin snapshot
            # AFTER the host sent the bytes but BEFORE the remote command
            # sees them.  Used to simulate (i) truncated bytes on the
            # ssh channel with a correct digest header, and (ii) the
            # third header line arriving non-lowercase / wrong length.
            "  if [ -n \"${FAKE_STDIN_TRANSFORM:-}\" ]; then\n"
            "    case \"$FAKE_STDIN_TRANSFORM\" in\n"
            "      truncate:*)\n"
            "        N=${FAKE_STDIN_TRANSFORM#truncate:}\n"
            "        /usr/bin/head -c \"$N\" \"$STDIN_FILE\" >\"$STDIN_FILE.tmp\"\n"
            "        /usr/bin/mv \"$STDIN_FILE.tmp\" \"$STDIN_FILE\"\n"
            "        ;;\n"
            "      bad_digest:*)\n"
            "        BAD=${FAKE_STDIN_TRANSFORM#bad_digest:}\n"
            "        /usr/bin/awk -v bad=\"$BAD\" 'NR==3{print bad; next}{print}' \"$STDIN_FILE\" >\"$STDIN_FILE.tmp\"\n"
            "        /usr/bin/mv \"$STDIN_FILE.tmp\" \"$STDIN_FILE\"\n"
            "        ;;\n"
            "      uppercase_digest)\n"
            "        /usr/bin/awk 'NR==3{print toupper($0); next}{print}' \"$STDIN_FILE\" >\"$STDIN_FILE.tmp\"\n"
            "        /usr/bin/mv \"$STDIN_FILE.tmp\" \"$STDIN_FILE\"\n"
            "        ;;\n"
            "    esac\n"
            "  fi\n"
            "  { printf 'STDIN-BEGIN\\n'; sed -n '1,20p' \"$STDIN_FILE\"; printf 'STDIN-END\\n'; } >>\"$FAKE_LOG\"\n"
            "  exec 0<\"$STDIN_FILE\"\n"
            "  HOME_DEFAULT=\"$FAKE_VANTAGE_ROOT/root-home\"\n"
            "else\n"
            "  HOME_DEFAULT=\"$HOME\"\n"
            "fi\n"
            "HOME=${FAKE_HOME-$HOME_DEFAULT}\n"
            "export HOME\n"
            # The fake ssh's own operations (cat, sed, mkdir) need the
            # system /usr/bin.  The REMOTE command's PATH is set later
            # so the F4 probe only sees the test-controlled stubs.
            "PATH=/usr/bin:/bin\n"
            "export PATH\n"
            "# Stub 'id -u' and the scan-time tools so the test controls them.\n"
            "# Path-prefix wrappers rewrite absolute paths under /usr/local\n"
            "# into the sandbox so the real mkdir/cp/chmod/mv never touch\n"
            # the host filesystem outside the sandbox.\n"
            "FAKE_BIN=\"$FAKE_VANTAGE_ROOT/fake-bin\"\n"
            "mkdir -p \"$FAKE_BIN\"\n"
            "VROOT=\"$FAKE_VANTAGE_ROOT\"\n"
            "export VROOT FAKE_BIN\n"
            "cat >\"$FAKE_BIN/_rewrite.sh\" <<RWE\n"
            "#!/bin/sh\n"
            "VROOT_INNER=\"$VROOT\"\n"
            "for arg in \"\\$@\"; do\n"
            "  case \\$arg in\n"
            "    /usr/local/*|/usr/local) printf '%s%s\\n' \"\\$VROOT_INNER\" \"\\$arg\" ;;\n"
            "    /etc/dropbear|/etc/dropbear*) printf '%s%s\\n' \"\\$VROOT_INNER\" \"\\$arg\" ;;\n"
            "    *) printf '%s\\n' \"\\$arg\" ;;\n"
            "  esac\n"
            "done\n"
            "RWE\n"
            "chmod 0755 \"$FAKE_BIN/_rewrite.sh\"\n"
            "REWRITE=\"$FAKE_BIN/_rewrite.sh\"\n"
            "for tool in mkdir cp chmod mv rm rmdir touch ls grep tee mktemp tail cat head; do\n"
            "  printf '#!/bin/sh\\nexec /usr/bin/%s $(%s \"$@\")\\n' \"$tool\" \"$REWRITE\" >\"$FAKE_BIN/$tool\"\n"
            "  chmod 0755 \"$FAKE_BIN/$tool\"\n"
            "done\n"
            # the install path parses sha256sum output with awk.
            # awk does not deal with /usr/local paths in the remote
            # script, so a path-rewrite wrapper would also be wrong:
            # the wrapper expands `$(REWRITE "$@")` and loses the
            # quoting around the `{print $1}` program.  Symlink to the
            # real awk on the host system instead.\n"
            "ln -sf /usr/bin/awk \"$FAKE_BIN/awk\"\n"
            "if [ -n \"${FAKE_UID:-}\" ]; then\n"
            "  cat >\"$FAKE_BIN/id\" <<'IDEOF'\n"
            "#!/bin/sh\n"
            "if [ \"$1\" = -u ]; then printf '%s\\n' \"$FAKE_UID\"; else /usr/bin/id \"$@\"; fi\n"
            "IDEOF\n"
            "  chmod 0755 \"$FAKE_BIN/id\"\n"
            "fi\n"
            "if [ \"${FAKE_HAS_nmap:-0}\" = 1 ]; then\n"
            "  printf '#!/bin/sh\\nexit 0\\n' >\"$FAKE_BIN/nmap\"\n"
            "  chmod 0755 \"$FAKE_BIN/nmap\"\n"
            "fi\n"
            "if [ \"${FAKE_HAS_timeout:-0}\" = 1 ]; then\n"
            "  printf '#!/bin/sh\\nexit 0\\n' >\"$FAKE_BIN/timeout\"\n"
            "  chmod 0755 \"$FAKE_BIN/timeout\"\n"
            "fi\n"
            # the install path probes for sha256sum alongside
            # nmap/timeout.  Default off so existing tests are explicit.
            "if [ \"${FAKE_HAS_sha256sum:-0}\" = 1 ]; then\n"
            "  printf '#!/bin/sh\\nexec /usr/bin/sha256sum $(%s \"$@\")\\n' \"$REWRITE\" >\"$FAKE_BIN/sha256sum\"\n"
            "  chmod 0755 \"$FAKE_BIN/sha256sum\"\n"
            "fi\n"
            # Write the `command -v` wrapper while the system PATH is
            # still available (so `cat` works).  It is placed first in
            # PATH for the remote so the F4 probe's `command -v` looks
            # only at the test-controlled stubs.\n"
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
            # Now restrict the REMOTE's PATH so the F4 probe's only\n"
            # `command -v` source is the stub the test installed.\n"
            "export PATH=\"$FAKE_BIN\"\n"
            "/usr/bin/sh -c \"$remote\"\n"
        )
    else:
        ssh_body += (
            "{ printf 'STDIN-BEGIN\\n'; sed -n '1,20p'; printf 'STDIN-END\\n'; } >>\"$FAKE_LOG\"\n"
        )
    make_executable(fake_bin / "ssh", ssh_body)

    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    env["FAKE_LOG"] = str(log)
    return env, log


def setup_env(env, inventory, tmp_path):
    env.update(
        NEWTON_INVENTORY=str(inventory),
        NEWTON_KEYS_DIR=str(tmp_path / "keys"),
        NEWTON_SCAN_SOURCE=str(SCAN),
    )
    return env


def call_blocks(log):
    text = log.read_text()
    return re.findall(r"CALL ([^\n]+)\n(.*?)END\n", text, re.DOTALL)


def args_for(block):
    return re.findall(r"^ARG (.*)$", block, re.MULTILINE)


def assert_pinned_options(args, known_hosts):
    joined = "\n".join(args)
    assert "-F\n/dev/null" in joined
    assert "-o\nIdentitiesOnly=yes" in joined
    assert "-o\nGlobalKnownHostsFile=/dev/null" in joined
    assert f"-o\nUserKnownHostsFile={known_hosts}" in joined
    assert "-o\nStrictHostKeyChecking=yes" in joined
    assert "-o\nProxyCommand=proxy-helper --fixed" in joined


def test_install_generates_key_copies_scan_and_adds_exact_restricted_line(tmp_path):
    inventory, key_file, known_hosts, admin_key = write_inventory(tmp_path)
    env, log = fake_tools(tmp_path)
    setup_env(env, inventory, tmp_path)

    result = subprocess.run(
        [str(SETUP), "edge", "install"], text=True, capture_output=True, env=env, timeout=10
    )

    assert result.returncode == 0, result.stdout + result.stderr
    blocks = call_blocks(log)
    # F4 added an nmap/timeout probe ssh call between the keygen and the
    # install: keygen, ssh (probe), ssh (install).  R8 removed the scp
    # staging step; the install ssh carries both the key+vantage header
    # lines and the scan bytes on its stdin.
    assert [name for name, _ in blocks] == ["ssh-keygen", "ssh", "ssh"]
    keygen = args_for(blocks[0][1])
    assert keygen == [
        "-q", "-t", "ed25519", "-N", "", "-C", "newton-vantage-edge",
        "-f", str(key_file),
    ]
    ssh = args_for(blocks[2][1])
    assert_pinned_options(ssh, known_hosts)
    assert str(admin_key) in ssh
    assert "-o\nBatchMode=yes" in "\n".join(ssh)
    # The host no longer names SCAN on any command line; the bytes travel
    # over stdin so a refusal cannot leave the staged file on the vantage.
    joined_args = "\n".join(ssh)
    assert str(SCAN) not in joined_args
    assert "/tmp/newton-scan.newton-setup" not in joined_args
    text = log.read_text()
    # the host no longer composes the restricted line; the remote
    # does.  Without run_remote=True, the fake ssh only logs the
    # STDIN-BEGIN/STDIN-END capture, so the assertion becomes "the line
    # is NOT in the log on the host side".
    assert (
        'restrict,command="/usr/local/libexec/newton-scan" ssh-ed25519 '
        "AAAAVANTAGE newton-vantage-edge"
    ) not in text
    assert "ADMIN-SECRET" not in text
    assert result.stdout == "DONE install edge\n"


def test_install_password_path_keeps_secret_out_of_argv_output_and_environment(tmp_path):
    inventory, _key_file, _known_hosts, password_file = write_inventory(
        tmp_path, auth="admin_password_file"
    )
    env, log = fake_tools(tmp_path)
    setup_env(env, inventory, tmp_path)

    result = subprocess.run(
        [str(SETUP), "edge", "install"], text=True, capture_output=True, env=env, timeout=10
    )

    assert result.returncode == 0, result.stdout + result.stderr
    all_args = "\n".join(arg for _name, block in call_blocks(log) for arg in args_for(block))
    assert "ADMIN-SECRET" not in all_args + result.stdout + result.stderr
    assert str(password_file) not in all_args
    assert "SSH_ASKPASS=" not in all_args
    assert "-o\nBatchMode=no" in all_args
    assert "-o\nPubkeyAuthentication=no" in all_args


def test_check_proves_empty_command_forwarding_and_pty_are_blocked(tmp_path):
    inventory, key_file, known_hosts, _admin_key = write_inventory(tmp_path)
    key_file.parent.mkdir()
    key_file.write_text("existing private fixture\n")
    env, log = fake_tools(tmp_path, check_mode=True)
    setup_env(env, inventory, tmp_path)

    result = subprocess.run(
        [str(SETUP), "edge", "check"], text=True, capture_output=True, env=env, timeout=10
    )

    assert result.returncode == 0, result.stdout + result.stderr
    blocks = call_blocks(log)
    assert [name for name, _ in blocks] == ["ssh", "ssh", "ssh"]
    for _name, block in blocks:
        args = args_for(block)
        assert_pinned_options(args, known_hosts)
        assert str(key_file) in args
        assert "-o\nBatchMode=yes" in "\n".join(args)
        assert "-o\nPasswordAuthentication=no" in "\n".join(args)
    assert not args_for(blocks[0][1])[-1].startswith("scan ")
    assert "-R" in args_for(blocks[1][1])
    assert "-tt" in args_for(blocks[2][1])
    # pass -T to the empty-command and forwarding calls so the real
    # OpenSSH "Pseudo-terminal will not be allocated because stdin is
    # not a terminal" noise on stderr never mixes with the forced
    # command's output.  The pty call (-tt) must NOT also carry -T.
    assert "-T" in args_for(blocks[0][1])
    assert "-T" in args_for(blocks[1][1])
    assert "-T" not in args_for(blocks[2][1])
    assert result.stdout == (
        "PASS empty command refused\n"
        "PASS forwarding blocked\n"
        "PASS pty blocked\n"
        "DONE check edge\n"
    )


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        ('unknown = "x"\n', "unknown keys"),
        ('role = "sideways"\n', "bad role"),
        ('devices = ["Bad Device"]\n', "bad devices"),
        ('admin_password_file = "/tmp/also"\n', "exactly one"),
    ],
)
def test_inventory_refuses_unknown_or_bad_values_before_any_external_call(
    tmp_path, extra, message
):
    inventory, _key_file, _known_hosts, _admin = write_inventory(tmp_path, extra=extra)
    env, log = fake_tools(tmp_path)
    setup_env(env, inventory, tmp_path)

    result = subprocess.run(
        [str(SETUP), "edge", "install"], text=True, capture_output=True, env=env, timeout=10
    )

    assert result.returncode == 2
    assert message in result.stderr
    assert not log.exists()


def test_vantage_launcher_is_clean_owner_authenticated_and_listed(tmp_path):
    text = launcher_text("vantage_setup_launcher_tmp")
    assert "newton-vantage-setup: must run as user newton" in text
    assert "valid non-root SUDO_USER" in text
    assert "cd /\nexec /usr/bin/env -i" in text
    assert "NEWTON_INVENTORY=/var/lib/newton/devices.toml" in text
    assert "NEWTON_KEYS_DIR=/var/lib/newton/keys" in text
    assert "/opt/newton/scripts/newton-vantage-setup \"$@\"" in text

    env = install_test_env(tmp_path)
    preview = run(INSTALL, "--check", env=env)
    assert preview.returncode == 0, preview.stderr
    assert (
        "Would install launcher: /usr/local/bin/newton-vantage-setup "
        "(root:root 0755; clean environment; newton user only; arguments passed through "
        "to newton-vantage-setup)"
    ) in preview.stdout
    assert "agent ALL=(newton) /usr/local/bin/newton-vantage-setup" in preview.stdout
    assert (
        "Defaults!/usr/local/bin/newton-vantage-setup timestamp_timeout=0"
        in preview.stdout
    )
    assert not any(
        "NOPASSWD" in line and "newton-vantage-setup" in line
        for line in preview.stdout.splitlines()
    )


# ---- F2/F3/F4: install lays the scan tool, the restricted key, and verifies
#                 nmap + timeout over the admin path ---------------------------


def _remote_ssh_blocks(log):
    """Return the (remote_cmd, stdin_log) of each ssh call.  For the install
    path the fake ssh records the remote command between REMOTE-CMD-BEGIN
    and REMOTE-CMD-END."""
    text = log.read_text()
    return re.findall(
        r"REMOTE-CMD-BEGIN\n(.*?)\nREMOTE-CMD-END\n", text, re.DOTALL
    )


def _admin_path_calls(env, tmp_path):
    """Create the fake ssh / scp / ssh-keygen binaries that actually run the
    remote command (run_remote=True) so the real install-path code runs."""
    inventory, key_file, _known_hosts, _admin_key = write_inventory(tmp_path)
    fenv, log = fake_tools(tmp_path, run_remote=True)
    setup_env(fenv, inventory, tmp_path)
    # the install path requires sha256sum on the vantage; the probe
    # names it.  Tests that want the probe to refuse must override this.
    fenv["FAKE_HAS_sha256sum"] = "1"
    return fenv, log, inventory, key_file


def test_install_root_uses_usr_local_libexec_and_writes_only_key_blob_on_stdin(
    tmp_path,
):
    fenv, log, _inventory, _key_file = _admin_path_calls(None, tmp_path)
    fenv["FAKE_UID"] = "0"
    fenv["FAKE_VANTAGE_ROOT"] = str(tmp_path / "vantage")
    fenv["FAKE_HAS_nmap"] = "1"
    fenv["FAKE_HAS_timeout"] = "1"

    result = subprocess.run(
        [str(SETUP), "edge", "install"], text=True, capture_output=True, env=fenv, timeout=10
    )

    assert result.returncode == 0, result.stdout + result.stderr
    blocks = call_blocks(log)
    # probe (ssh) runs after key generation, then the install (ssh)
    # carries the scan bytes plus the key+vantage lines on stdin.  R8
    # dropped the staging scp so the sequence is ssh-keygen, ssh, ssh.
    names = [name for name, _ in blocks]
    assert names == ["ssh-keygen", "ssh", "ssh"], names
    remote_cmds = _remote_ssh_blocks(log)
    assert len(remote_cmds) == 2
    probe, install_cmd = remote_cmds
    assert "command -v" in probe
    assert "nmap" in probe
    assert "timeout" in probe
    # remote side composes the line from stdin (NOT the host).
    assert "newton-vantage-edge" not in install_cmd
    assert (
        'restrict,command="/usr/local/libexec/newton-scan" '
        "ssh-ed25519 AAAAVANTAGE newton-vantage-edge"
        not in install_cmd
    )
    # stdin carries the validated key_type, key_blob, the vantage
    # name, and (R9) the sha256 digest of $SCAN_SOURCE -- the restricted
    # line is composed on the REMOTE side.
    stdin_lines = re.findall(r"STDIN-BEGIN\n(.*?)\nSTDIN-END\n", log.read_text(), re.DOTALL)
    assert any("ssh-ed25519" in s and "AAAAVANTAGE" in s and "edge" in s for s in stdin_lines)
    # the third header line is a 64-character lowercase hex digest
    # of the local $SCAN_SOURCE bytes.
    expected_digest = hashlib.sha256(SCAN.read_bytes()).hexdigest()
    assert any(re.search(r"(?:^|\n)" + expected_digest + r"(?:\n|$)", s) for s in stdin_lines), (
        stdin_lines
    )
    # install must not use the busybox-missing 'install' applet.
    assert "install -d" not in install_cmd
    assert "install -m" not in install_cmd
    assert "mkdir -p" in install_cmd
    assert "chmod 0755" in install_cmd
    # the file ends up at /usr/local/libexec/newton-scan on a root vantage.
    vantage = tmp_path / "vantage"
    script = vantage / "usr" / "local" / "libexec" / "newton-scan"
    assert script.is_file()
    assert oct(script.stat().st_mode & 0o777) == "0o755"
    authorized = vantage / "root-home" / ".ssh" / "authorized_keys"
    text = authorized.read_text()
    # The restricted line is the LITERAL path the vantage's sshd will use
    # to find the forced command.  The wrapper layer only sandboxed the
    # real mkdir/cp/mv so the test does not need root on the host.
    assert (
        'restrict,command="/usr/local/libexec/newton-scan" '
        "ssh-ed25519 AAAAVANTAGE newton-vantage-edge\n"
    ) in text
    assert result.stdout == "DONE install edge\n"


def test_install_non_root_uses_home_local_libexec(tmp_path):
    fenv, log, _inventory, _key_file = _admin_path_calls(None, tmp_path)
    fenv["FAKE_UID"] = "1000"
    fenv["FAKE_HOME"] = str(tmp_path / "alice")
    fenv["FAKE_VANTAGE_ROOT"] = str(tmp_path / "vantage")
    fenv["FAKE_HAS_nmap"] = "1"
    fenv["FAKE_HAS_timeout"] = "1"

    result = subprocess.run(
        [str(SETUP), "edge", "install"], text=True, capture_output=True, env=fenv, timeout=10
    )

    assert result.returncode == 0, result.stdout + result.stderr
    home = tmp_path / "alice"
    script = home / ".local" / "libexec" / "newton-scan"
    assert script.is_file()
    assert oct(script.stat().st_mode & 0o777) == "0o755"
    # the host must not have tried to put anything under /usr/local.
    assert not (tmp_path / "vantage" / "root-home" / "usr" / "local" / "libexec").exists() \
        or not (tmp_path / "vantage" / "root-home" / "usr" / "local" / "libexec" / "newton-scan").exists()
    authorized = home / ".ssh" / "authorized_keys"
    text = authorized.read_text()
    assert (
        'restrict,command="/home/dummy/.local/libexec/newton-scan" '
        "ssh-ed25519 AAAAVANTAGE newton-vantage-edge"
    ) not in text
    assert (
        f'restrict,command="{home}/.local/libexec/newton-scan" '
        "ssh-ed25519 AAAAVANTAGE newton-vantage-edge\n"
    ) in text


def test_install_refuses_when_nmap_or_timeout_missing_with_clear_message(tmp_path):
    fenv, log, _inventory, _key_file = _admin_path_calls(None, tmp_path)
    fenv["FAKE_UID"] = "0"
    fenv["FAKE_VANTAGE_ROOT"] = str(tmp_path / "vantage")
    fenv["FAKE_HAS_nmap"] = "0"
    fenv["FAKE_HAS_timeout"] = "0"

    result = subprocess.run(
        [str(SETUP), "edge", "install"], text=True, capture_output=True, env=fenv, timeout=10
    )

    assert result.returncode == 2, result.stdout + result.stderr
    assert "nmap" in result.stderr and "timeout" in result.stderr
    # The message must name a fix path; OpenWrt / Debian both shown is fine
    # so long as the missing tools are listed.
    assert "apk add" in result.stderr or "apt install" in result.stderr
    # the probe ssh ran (and reported both tools missing), then the
    # install died before scp or the install ssh ever ran.
    blocks = call_blocks(log)
    names = [name for name, _ in blocks]
    assert names == ["ssh-keygen", "ssh"], names


def test_install_refuses_when_only_timeout_missing(tmp_path):
    fenv, _log, _inventory, _key_file = _admin_path_calls(None, tmp_path)
    fenv["FAKE_UID"] = "0"
    fenv["FAKE_VANTAGE_ROOT"] = str(tmp_path / "vantage")
    fenv["FAKE_HAS_nmap"] = "1"
    fenv["FAKE_HAS_timeout"] = "0"

    result = subprocess.run(
        [str(SETUP), "edge", "install"], text=True, capture_output=True, env=fenv, timeout=10
    )

    assert result.returncode == 2, result.stdout + result.stderr
    # The missing-tools portion of the error names only timeout, not nmap
    # (the OpenWrt fix may still list nmap as part of the suggested apt
    # add argument, so we check the dedicated phrase).
    assert "vantage is missing the scan tool(s): timeout" in result.stderr
    assert "vantage is missing the scan tool(s): timeout nmap" not in result.stderr


def test_check_pty_blocked_accepts_rc_2_with_pty_text_on_stderr(tmp_path):
    """F5: real sshd/dropbear with restrict (no-pty) prints 'PTY allocation
    request failed on channel 0' and the forced command still runs, so the
    exit status is the forced command's (2 with 'newton-scan: refused'),
    not 255."""
    inventory, key_file, known_hosts, _admin_key = write_inventory(tmp_path)
    key_file.parent.mkdir()
    key_file.write_text("existing private fixture\n")
    env, log = fake_tools(tmp_path, check_mode=True)
    setup_env(env, inventory, tmp_path)

    result = subprocess.run(
        [str(SETUP), "edge", "check"], text=True, capture_output=True, env=env, timeout=10
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS pty blocked" in result.stdout
    assert "PASS empty command refused" in result.stdout
    assert "PASS forwarding blocked" in result.stdout


def test_check_pty_granted_with_wrong_output_fails(tmp_path):
    """A pty that IS granted with rc 0 or other output still fails the
    check, because the point of the check is to confirm the key denies
    the pty."""
    inventory, key_file, _known_hosts, _admin = write_inventory(tmp_path)
    key_file.parent.mkdir()
    key_file.write_text("existing private fixture\n")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    log = tmp_path / "calls"
    make_executable(
        fake_bin / "ssh",
        "#!/bin/sh\n"
        "set -eu\n"
        "{ printf 'CALL ssh\\n'; printf 'ARG %s\\n' \"$@\"; printf 'END\\n'; } >>\"$FAKE_LOG\"\n"
        "case \" $* \" in\n"
        "  *' -tt '*) printf 'PTY granted\\n'; exit 0 ;;\n"
        "  *' -R '*) printf 'remote port forwarding failed\\n' >&2; exit 255 ;;\n"
        "esac\n"
        "printf 'newton-scan: refused\\n' >&2\n"
        "exit 2\n",
    )
    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    env["FAKE_LOG"] = str(log)
    setup_env(env, inventory, tmp_path)

    result = subprocess.run(
        [str(SETUP), "edge", "check"], text=True, capture_output=True, env=env, timeout=10
    )

    assert result.returncode == 1
    assert "FAIL pty" in result.stderr
    assert "PASS pty blocked" not in result.stdout


# ---- OpenWrt root vantage reads root keys from /etc/dropbear/authorized_keys
#         (dropbear ignores $HOME/.ssh/authorized_keys), not from ~/.ssh.


def test_install_root_writes_dropbear_authorized_keys_when_dir_exists(tmp_path):
    fenv, log, _inventory, _key_file = _admin_path_calls(None, tmp_path)
    fenv["FAKE_UID"] = "0"
    fenv["FAKE_VANTAGE_ROOT"] = str(tmp_path / "vantage")
    # OpenWrt ships dropbear, which reads root's authorized_keys from
    # /etc/dropbear/authorized_keys and never looks at $HOME/.ssh.
    # Model that by pre-creating the directory in the sandbox; the
    # remote script's `ls -d /etc/dropbear` check (after the rewriter
    # maps it under FAKE_VANTAGE_ROOT) then sees the dir and routes the
    # restricted line there.
    (tmp_path / "vantage" / "etc" / "dropbear").mkdir(parents=True)
    fenv["FAKE_HAS_nmap"] = "1"
    fenv["FAKE_HAS_timeout"] = "1"

    result = subprocess.run(
        [str(SETUP), "edge", "install"], text=True, capture_output=True, env=fenv, timeout=10
    )

    assert result.returncode == 0, result.stdout + result.stderr
    dropbear_keys = tmp_path / "vantage" / "etc" / "dropbear" / "authorized_keys"
    ssh_keys = tmp_path / "vantage" / "root-home" / ".ssh" / "authorized_keys"
    text = dropbear_keys.read_text()
    assert (
        'restrict,command="/usr/local/libexec/newton-scan" '
        "ssh-ed25519 AAAAVANTAGE newton-vantage-edge\n"
    ) in text
    assert oct(dropbear_keys.stat().st_mode & 0o777) == "0o600"
    # And: nothing landed under the OpenWrt-irrelevant ~/.ssh path.
    assert not ssh_keys.exists()


def test_install_root_falls_back_to_home_ssh_when_dropbear_missing(tmp_path):
    fenv, log, _inventory, _key_file = _admin_path_calls(None, tmp_path)
    fenv["FAKE_UID"] = "0"
    fenv["FAKE_VANTAGE_ROOT"] = str(tmp_path / "vantage")
    # No /etc/dropbear directory under the sandbox: a Debian vantage
    # (sshd, not dropbear) must keep using $HOME/.ssh/authorized_keys.
    assert not (tmp_path / "vantage" / "etc" / "dropbear").exists()
    fenv["FAKE_HAS_nmap"] = "1"
    fenv["FAKE_HAS_timeout"] = "1"

    result = subprocess.run(
        [str(SETUP), "edge", "install"], text=True, capture_output=True, env=fenv, timeout=10
    )

    assert result.returncode == 0, result.stdout + result.stderr
    authorized = tmp_path / "vantage" / "root-home" / ".ssh" / "authorized_keys"
    text = authorized.read_text()
    assert (
        'restrict,command="/usr/local/libexec/newton-scan" '
        "ssh-ed25519 AAAAVANTAGE newton-vantage-edge\n"
    ) in text
    # And: the dropbear path was NOT created out of thin air.
    assert not (tmp_path / "vantage" / "etc" / "dropbear").exists()


# ---- when the empty-command check fails, name the OpenWrt dropbear cause.


def test_check_empty_command_failure_prints_dropbear_hint(tmp_path):
    inventory, key_file, _known_hosts, _admin = write_inventory(tmp_path)
    key_file.parent.mkdir()
    key_file.write_text("existing private fixture\n")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    log = tmp_path / "calls"
    # The vantage lets the empty command through with rc 0 -- the key is
    # not forced to newton-scan.  The hint must point at the most likely
    # cause: an OpenWrt dropbear with no root password lets any login
    # in (no key-based forced execution).
    make_executable(
        fake_bin / "ssh",
        "#!/bin/sh\n"
        "set -eu\n"
        "{ printf 'CALL ssh\\n'; printf 'ARG %s\\n' \"$@\"; printf 'END\\n'; } >>\"$FAKE_LOG\"\n"
        "exit 0\n",
    )
    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    env["FAKE_LOG"] = str(log)
    setup_env(env, inventory, tmp_path)

    result = subprocess.run(
        [str(SETUP), "edge", "check"], text=True, capture_output=True, env=env, timeout=10
    )

    assert result.returncode == 1
    assert "FAIL empty command was not refused" in result.stderr
    assert "rc=" in result.stderr
    assert "dropbear" in result.stderr
    assert "root password" in result.stderr


# ---- scripts/newton-vantage-setup REMOTE install path.
# Two blockers (B1, B2) and three nits (N1, N2, N3).  Each test is red on the
# pre-fix REMOTE install path and green after the corresponding fix.


def test_install_root_tightens_pre_existing_0777_bin_dir_to_0755(tmp_path):
    """B1: a pre-existing /usr/local/libexec with mode 0777 (left by another
    local user, or by a botched package) must not let another local user
    replace newton-scan.  Root tightens it to 0755; the install succeeds;
    the binary is mode 0755 inside it."""
    fenv, _log, _inventory, _key_file = _admin_path_calls(None, tmp_path)
    fenv["FAKE_UID"] = "0"
    fenv["FAKE_VANTAGE_ROOT"] = str(tmp_path / "vantage")
    fenv["FAKE_HAS_nmap"] = "1"
    fenv["FAKE_HAS_timeout"] = "1"
    bin_dir = tmp_path / "vantage" / "usr" / "local" / "libexec"
    bin_dir.mkdir(parents=True)
    bin_dir.chmod(0o777)
    assert oct(bin_dir.stat().st_mode & 0o777) == "0o777"

    result = subprocess.run(
        [str(SETUP), "edge", "install"], text=True, capture_output=True, env=fenv, timeout=10
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert oct(bin_dir.stat().st_mode & 0o777) == "0o755"
    script = bin_dir / "newton-scan"
    assert script.is_file()
    assert oct(script.stat().st_mode & 0o777) == "0o755"


def test_install_non_root_tightens_pre_existing_0777_bin_dir_to_0700(tmp_path):
    """B1: same as the root case, but a non-root vantage must tighten the
    bin dir to 0700 so other local users on the host can neither list nor
    replace newton-scan."""
    fenv, _log, _inventory, _key_file = _admin_path_calls(None, tmp_path)
    fenv["FAKE_UID"] = "1000"
    fenv["FAKE_HOME"] = str(tmp_path / "alice")
    fenv["FAKE_VANTAGE_ROOT"] = str(tmp_path / "vantage")
    fenv["FAKE_HAS_nmap"] = "1"
    fenv["FAKE_HAS_timeout"] = "1"
    home = tmp_path / "alice"
    bin_dir = home / ".local" / "libexec"
    bin_dir.mkdir(parents=True)
    bin_dir.chmod(0o777)
    assert oct(bin_dir.stat().st_mode & 0o777) == "0o777"

    result = subprocess.run(
        [str(SETUP), "edge", "install"], text=True, capture_output=True, env=fenv, timeout=10
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert oct(bin_dir.stat().st_mode & 0o777) == "0o700"
    script = bin_dir / "newton-scan"
    assert script.is_file()
    assert oct(script.stat().st_mode & 0o777) == "0o755"


def test_install_authorized_keys_no_trailing_newline_keeps_old_line_intact(tmp_path):
    """B2: tee -a onto an authorized_keys whose last line has no trailing
    newline glues the new line onto the old key, producing an unparseable
    line like 'ssh-ed25519 AAAAOLD old-keyrestrict,...'.  The installer
    must prepend a newline before the append so the old and new lines are
    each on their own line."""
    fenv, _log, _inventory, _key_file = _admin_path_calls(None, tmp_path)
    fenv["FAKE_UID"] = "0"
    fenv["FAKE_VANTAGE_ROOT"] = str(tmp_path / "vantage")
    fenv["FAKE_HAS_nmap"] = "1"
    fenv["FAKE_HAS_timeout"] = "1"
    # Pre-create /etc/dropbear + authorized_keys WITHOUT a trailing newline.
    dropbear_keys = tmp_path / "vantage" / "etc" / "dropbear" / "authorized_keys"
    dropbear_keys.parent.mkdir(parents=True)
    dropbear_keys.write_bytes(b"ssh-ed25519 AAAAOLD old-key")

    result = subprocess.run(
        [str(SETUP), "edge", "install"], text=True, capture_output=True, env=fenv, timeout=10
    )

    assert result.returncode == 0, result.stdout + result.stderr
    text = dropbear_keys.read_text()
    # The old line remains its own line.
    assert text.splitlines()[0] == "ssh-ed25519 AAAAOLD old-key"
    # The restricted line was appended as its own line, not glued onto old-key.
    assert "old-keyrestrict" not in text
    assert (
        'restrict,command="/usr/local/libexec/newton-scan" '
        "ssh-ed25519 AAAAVANTAGE newton-vantage-edge"
    ) in text
    # The file ends with the restricted line followed by the trailing newline.
    assert text.endswith("\n")


def test_install_root_no_dropbear_with_unset_home_refuses_before_copy(tmp_path):
    """N1: a root vantage without /etc/dropbear must consult $HOME to find
    the authorized_keys fallback path.  When HOME is empty the previous
    code first copied the binary into /usr/local/libexec and only then
    aborted on the auth_keys branch with set -u's opaque 'parameter not
    set' (rc 1).  The fix must refuse with a clear HOME message BEFORE
    any change so the binary never lands on the vantage."""
    fenv, _log, _inventory, _key_file = _admin_path_calls(None, tmp_path)
    fenv["FAKE_UID"] = "0"
    fenv["FAKE_VANTAGE_ROOT"] = str(tmp_path / "vantage")
    fenv["FAKE_HAS_nmap"] = "1"
    fenv["FAKE_HAS_timeout"] = "1"
    # Empty HOME so the auth_keys branch is forced into the $HOME/.ssh fallback.
    fenv["FAKE_HOME"] = ""
    assert not (tmp_path / "vantage" / "etc" / "dropbear").exists()

    vantage = tmp_path / "vantage"
    result = subprocess.run(
        [str(SETUP), "edge", "install"], text=True, capture_output=True, env=fenv, timeout=10
    )

    assert result.returncode == 2, result.stdout + result.stderr
    assert "HOME" in result.stderr
    # No copy happened: the forced command binary never landed on the vantage.
    assert not (vantage / "usr" / "local" / "libexec" / "newton-scan").exists()


def test_check_pty_with_whitespace_in_refused_text_fails(tmp_path):
    """N3: the previous pty check stripped all whitespace from stdout and
    compared against 'newton-scan:refused', so 'newton- scan: refused'
    (a single inserted space, the kind of mutation a side channel might
    add) silently passed the check.  The fix compares exactly: stdout
    must be empty or exactly 'newton-scan: refused' (with at most a
    trailing CR/LF)."""
    inventory, key_file, _known_hosts, _admin = write_inventory(tmp_path)
    key_file.parent.mkdir()
    key_file.write_text("existing private fixture\n")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    log = tmp_path / "calls"
    make_executable(
        fake_bin / "ssh",
        "#!/bin/sh\n"
        "set -eu\n"
        "{ printf 'CALL ssh\\n'; printf 'ARG %s\\n' \"$@\"; printf 'END\\n'; } >>\"$FAKE_LOG\"\n"
        # For the pty check: print a refusal WITH an inserted space on
        # stdout (the kind of mutation the buggy whitespace-stripping
        # predicate would silently accept).  Other checks behave normally.
        "case \" $* \" in\n"
        "  *' -tt '*) printf 'PTY allocation request failed on channel 0\\n' >&2\n"
        "              printf 'newton- scan: refused\\n'\n"
        "              exit 2 ;;\n"
        "  *' -R '*) printf 'remote port forwarding failed\\n' >&2; exit 255 ;;\n"
        "esac\n"
        "printf 'newton-scan: refused\\n' >&2\n"
        "exit 2\n",
    )
    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    env["FAKE_LOG"] = str(log)
    setup_env(env, inventory, tmp_path)

    result = subprocess.run(
        [str(SETUP), "edge", "check"], text=True, capture_output=True, env=env, timeout=10
    )

    assert result.returncode == 1
    assert "FAIL pty" in result.stderr
    assert "PASS pty blocked" not in result.stdout




def test_check_pty_with_extra_trailing_newlines_fails(tmp_path):
    """Review r2: stripping every trailing LF accepted extra output; at most one CR/LF is allowed."""
    inventory, key_file, _known_hosts, _admin = write_inventory(tmp_path)
    key_file.parent.mkdir()
    key_file.write_text("existing private fixture\n")
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    log = tmp_path / "calls"
    make_executable(
        fake_bin / "ssh",
        "#!/bin/sh\n"
        "set -eu\n"
        "{ printf 'CALL ssh\\n'; printf 'ARG %s\\n' \"$@\"; printf 'END\\n'; } >>\"$FAKE_LOG\"\n"
        # For the pty check: print a refusal WITH an inserted space on
        # stdout (the kind of mutation the buggy whitespace-stripping
        # predicate would silently accept).  Other checks behave normally.
        "case \" $* \" in\n"
        "  *' -tt '*) printf 'PTY allocation request failed on channel 0\\n' >&2\n"
        "              printf 'newton-scan: refused\\n\\n\\n'\n"
        "              exit 2 ;;\n"
        "  *' -R '*) printf 'remote port forwarding failed\\n' >&2; exit 255 ;;\n"
        "esac\n"
        "printf 'newton-scan: refused\\n' >&2\n"
        "exit 2\n",
    )
    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    env["FAKE_LOG"] = str(log)
    setup_env(env, inventory, tmp_path)

    result = subprocess.run(
        [str(SETUP), "edge", "check"], text=True, capture_output=True, env=env, timeout=10
    )

    assert result.returncode == 1
    assert "FAIL pty" in result.stderr


def test_install_refuses_bad_home_before_creating_ssh_dir(tmp_path):
    """Review r2: $HOME/.ssh was created before the authorized_keys path was validated."""
    fenv, _log, _inventory, _key_file = _admin_path_calls(None, tmp_path)
    fenv["FAKE_UID"] = "0"
    fenv["FAKE_VANTAGE_ROOT"] = str(tmp_path / "vantage")
    fenv["FAKE_HAS_nmap"] = "1"
    fenv["FAKE_HAS_timeout"] = "1"
    fenv["FAKE_HOME"] = "/home/bad:home"

    result = subprocess.run(
        [str(SETUP), "edge", "install"], text=True, capture_output=True, env=fenv, timeout=10
    )

    assert result.returncode == 2, result.stdout + result.stderr
    assert "forbidden characters" in result.stderr
    assert not list((tmp_path / "vantage").rglob(".ssh"))
    assert not (tmp_path / "vantage" / "usr" / "local" / "libexec" / "newton-scan").exists()


# ---- install stops staging through scp + /tmp on the vantage, because a
# refusal (or a hostile local user pre-planting /tmp/newton-scan.newton-setup
# as a symlink) would either leak the staged file or redirect the root scp
# write.  Everything now travels over the install -> admin_ssh stdin.


def test_install_r8_never_invokes_scp(tmp_path):
    """R8: the install flow no longer uses scp at all.  Only ssh-keygen,
    the nmap/timeout probe (ssh), and the install (ssh) call exist."""
    fenv, log, _inventory, _key_file = _admin_path_calls(None, tmp_path)
    fenv["FAKE_UID"] = "0"
    fenv["FAKE_VANTAGE_ROOT"] = str(tmp_path / "vantage")
    fenv["FAKE_HAS_nmap"] = "1"
    fenv["FAKE_HAS_timeout"] = "1"

    result = subprocess.run(
        [str(SETUP), "edge", "install"], text=True, capture_output=True, env=fenv, timeout=10
    )

    assert result.returncode == 0, result.stdout + result.stderr
    text = log.read_text()
    assert "CALL scp" not in text, text
    blocks = call_blocks(log)
    assert [name for name, _ in blocks] == ["ssh-keygen", "ssh", "ssh"], blocks


def test_install_r8_writes_nothing_under_vantage_tmp(tmp_path):
    """R8: nothing in the install (success OR failure) creates or modifies
    a file under the vantage's /tmp.  Pre-plant a hostile symlink there to
    prove the install never resolves the world-writable name."""
    fenv, log, _inventory, _key_file = _admin_path_calls(None, tmp_path)
    fenv["FAKE_UID"] = "0"
    fenv["FAKE_VANTAGE_ROOT"] = str(tmp_path / "vantage")
    fenv["FAKE_HAS_nmap"] = "1"
    fenv["FAKE_HAS_timeout"] = "1"
    # Pre-plant a hostile symlink at /tmp/newton-scan.newton-setup on
    # the vantage: on the old flow, a root scp would follow the symlink
    # and overwrite its target (the very attack R8 closes).  The test
    # then runs install and proves the symlink was never read, opened,
    # or replaced.
    tmp = tmp_path / "vantage" / "tmp"
    tmp.mkdir(parents=True)
    hostile_target = tmp_path / "hostile_target"
    hostile_target.write_text("hostile\n")
    (tmp / "newton-scan.newton-setup").symlink_to(hostile_target)
    preexisting_symlink = (tmp / "newton-scan.newton-setup").readlink()

    result = subprocess.run(
        [str(SETUP), "edge", "install"], text=True, capture_output=True, env=fenv, timeout=10
    )

    assert result.returncode == 0, result.stdout + result.stderr
    # The symlink is still the same one we planted: nothing wrote through
    # or removed it, so the host-side root scp that would have followed
    # it never ran.
    current = tmp / "newton-scan.newton-setup"
    assert current.is_symlink()
    assert current.readlink() == preexisting_symlink
    # And the hostile target's content was never replaced.
    assert hostile_target.read_text() == "hostile\n"


def test_install_r8_bad_home_refusal_leaves_vantage_completely_unchanged(tmp_path):
    """R8: a refusal (here a HOME with a forbidden character) leaves the
    vantage with no .ssh dir, no bin_dir file, no bin_dir temp file, and
    no /tmp staging file.  Nothing the install touched landed on the
    vantage."""
    fenv, log, _inventory, _key_file = _admin_path_calls(None, tmp_path)
    fenv["FAKE_UID"] = "0"
    fenv["FAKE_VANTAGE_ROOT"] = str(tmp_path / "vantage")
    fenv["FAKE_HAS_nmap"] = "1"
    fenv["FAKE_HAS_timeout"] = "1"
    fenv["FAKE_HOME"] = "/home/bad:home"

    result = subprocess.run(
        [str(SETUP), "edge", "install"], text=True, capture_output=True, env=fenv, timeout=10
    )

    vantage = tmp_path / "vantage"
    assert result.returncode == 2, result.stdout + result.stderr
    assert "forbidden characters" in result.stderr
    # No .ssh anywhere under the vantage.
    assert not list(vantage.rglob(".ssh"))
    # No bin_dir file, and no leftover mktemp temp file in it.  (bin_dir
    # itself may exist if the refusal ran past that point; only the
    # content is forbidden.)
    bin_dir = vantage / "usr" / "local" / "libexec"
    assert not (bin_dir / "newton-scan").exists()
    assert not list(bin_dir.glob(".newton-scan.*"))
    # And: nothing under the vantage's /tmp (this is the R8 guarantee:
    # the old flow staged the scan binary under /tmp via scp before
    # validation, so a refusal left a world-writable file behind).
    tmp = vantage / "tmp"
    if tmp.exists():
        assert not list(tmp.iterdir()), list(tmp.iterdir())


def test_install_r8_empty_payload_refused_with_no_temp_file_left(tmp_path):
    """R8: if the bytes following the two header lines on stdin are empty
    (the host's $SCAN_SOURCE is empty), the remote refuses and removes the
    temp file it created, leaving the bin_dir untouched."""
    fenv, log, inventory, _key_file = _admin_path_calls(None, tmp_path)
    fenv["FAKE_UID"] = "0"
    fenv["FAKE_VANTAGE_ROOT"] = str(tmp_path / "vantage")
    fenv["FAKE_HAS_nmap"] = "1"
    fenv["FAKE_HAS_timeout"] = "1"
    # Point the install at an empty file as the scan source.  The remote
    # will still receive the two header lines, but the bytes after them
    # will be zero.
    empty_scan = tmp_path / "empty-scan"
    empty_scan.write_text("")
    fenv["NEWTON_SCAN_SOURCE"] = str(empty_scan)

    result = subprocess.run(
        [str(SETUP), "edge", "install"], text=True, capture_output=True, env=fenv, timeout=10
    )

    vantage = tmp_path / "vantage"
    assert result.returncode == 2, result.stdout + result.stderr
    # The remote refused because the payload was empty.
    assert "empty" in result.stderr or "refus" in result.stderr.lower()
    # No newton-scan and no leftover temp file in bin_dir.
    bin_dir = vantage / "usr" / "local" / "libexec"
    assert not (bin_dir / "newton-scan").exists()
    assert not list(bin_dir.glob(".newton-scan.*"))
    # And: no /tmp staging file on the vantage.
    tmp = vantage / "tmp"
    if tmp.exists():
        assert not list(tmp.iterdir()), list(tmp.iterdir())


def test_install_r8_non_sh_payload_refused_with_no_temp_file_left(tmp_path):
    """R8: a payload that is not a POSIX shell script (does not start with
    '#!/bin/sh') is refused, and the temp file the remote created is
    removed.  This stops a vantage that somehow receives a wrong blob
    from running an arbitrary binary on every signed-out scan."""
    fenv, log, inventory, _key_file = _admin_path_calls(None, tmp_path)
    fenv["FAKE_UID"] = "0"
    fenv["FAKE_VANTAGE_ROOT"] = str(tmp_path / "vantage")
    fenv["FAKE_HAS_nmap"] = "1"
    fenv["FAKE_HAS_timeout"] = "1"
    bogus_scan = tmp_path / "bogus-scan"
    bogus_scan.write_bytes(b"this is not a shell script\n")
    fenv["NEWTON_SCAN_SOURCE"] = str(bogus_scan)

    result = subprocess.run(
        [str(SETUP), "edge", "install"], text=True, capture_output=True, env=fenv, timeout=10
    )

    vantage = tmp_path / "vantage"
    assert result.returncode == 2, result.stdout + result.stderr
    assert "#!/bin/sh" in result.stderr
    bin_dir = vantage / "usr" / "local" / "libexec"
    assert not (bin_dir / "newton-scan").exists()
    assert not list(bin_dir.glob(".newton-scan.*"))


def test_install_r8_installed_scan_is_byte_identical_to_source(tmp_path):
    """R8: the newton-scan the install leaves on the vantage is byte-for-
    byte identical to scripts/newton-scan.  No trailing-byte munging, no
    CRLF insertion from the ssh channel, nothing dropped."""
    fenv, log, _inventory, _key_file = _admin_path_calls(None, tmp_path)
    fenv["FAKE_UID"] = "0"
    fenv["FAKE_VANTAGE_ROOT"] = str(tmp_path / "vantage")
    fenv["FAKE_HAS_nmap"] = "1"
    fenv["FAKE_HAS_timeout"] = "1"

    result = subprocess.run(
        [str(SETUP), "edge", "install"], text=True, capture_output=True, env=fenv, timeout=10
    )

    assert result.returncode == 0, result.stdout + result.stderr
    expected = SCAN.read_bytes()
    installed = (tmp_path / "vantage" / "usr" / "local" / "libexec" / "newton-scan").read_bytes()
    assert installed == expected
    # And: the file on the vantage starts with #!/bin/sh (the same guard
    # the remote uses to refuse a bad payload).
    assert installed.startswith(b"#!/bin/sh\n")


# ---- install pairs the 3rd stdin header line with the SHA-256 of the
# $SCAN_SOURCE bytes, so a truncated / corrupted payload on the ssh channel
# is detected by the remote BEFORE any filesystem change.  The remote reads
# the three header lines with IFS= read -r, refuses if the digest is not
# exactly 64 lowercase hex, then cat >"$tmp_file" and sha256sums the temp
# file.  If the digest of the received bytes does not match the header,
# the temp file is removed and the install refuses BEFORE the mv and
# BEFORE authorized_keys is touched.  The #!/bin/sh check stays.  If
# sha256sum is missing on the vantage, the existing nmap/timeout tool
# probe is extended to name it in the refusal.


def test_install_r9_refuses_truncated_payload_with_correct_digest_header(
    tmp_path,
):
    """R9: the host computes the digest correctly, but the bytes the remote
    receives via ssh are truncated.  The `#!/bin/sh\\nprintf
    'unterminated` payload starts with `#!/bin/sh` so the existing guard
    would also let it through.  The remote sha256sum of the temp file does
    not match the digest header, so the install refuses; nothing has been
    changed (the previously installed binary is untouched, authorized_keys
    is untouched, no temp file is left behind)."""
    fenv, log, _inventory, _key_file = _admin_path_calls(None, tmp_path)
    fenv["FAKE_UID"] = "0"
    fenv["FAKE_VANTAGE_ROOT"] = str(tmp_path / "vantage")
    fenv["FAKE_HAS_nmap"] = "1"
    fenv["FAKE_HAS_timeout"] = "1"

    # Pre-create a working `newton-scan` and a populated authorized_keys
    # file so we can prove the refused install does not touch them.
    vantage = tmp_path / "vantage"
    bin_dir = vantage / "usr" / "local" / "libexec"
    bin_dir.mkdir(parents=True)
    preexisting = b"#!/bin/sh\\nprintf 'preexisting\\n'"
    (bin_dir / "newton-scan").write_bytes(preexisting)
    (bin_dir / "newton-scan").chmod(0o755)
    dropbear_keys = vantage / "etc" / "dropbear" / "authorized_keys"
    dropbear_keys.parent.mkdir(parents=True)
    preexisting_keyline = "ssh-ed25519 AAAAOLD old-key"
    dropbear_keys.write_text(preexisting_keyline + "\n")
    dropbear_keys.chmod(0o600)

    # Truncate the stdin bytes AFTER the host sent the full headers
    # and payload.  All three header lines survive (the
    # payload starts with `#!/bin/sh` and is otherwise the R8 guard
    # alone would not catch it), but the payload itself is shortened.
    # 200 keeps the key header (~30 bytes) + name (5) + digest (65)
    # intact and crops the payload.  The remote reads the three
    # headers cleanly, then `cat >tmp_file` gets a partial payload,
    # then sha256sum of the temp file does not match the header.
    fenv["FAKE_STDIN_TRANSFORM"] = "truncate:200"

    result = subprocess.run(
        [str(SETUP), "edge", "install"], text=True, capture_output=True, env=fenv, timeout=10
    )

    assert result.returncode == 2, result.stdout + result.stderr
    assert "sha256" in result.stderr and "mismatch" in result.stderr, result.stderr
    # The previously installed binary is byte-identical to what we wrote
    # before the refused install ran.
    assert (bin_dir / "newton-scan").read_bytes() == preexisting
    # authorized_keys still has only the old key line, on its own line.
    text = dropbear_keys.read_text()
    assert text == preexisting_keyline + "\n"
    # No temp file leaked into the bin dir.
    assert not list(bin_dir.glob(".newton-scan.*"))


def test_install_r9_refuses_wrong_length_digest_before_any_change(tmp_path):
    """R9: a digest header that is not 64 lowercase hex chars is refused
    by the remote BEFORE any filesystem change.  Test with a digest that
    is too short, so the case-pattern check rejects it."""
    fenv, log, _inventory, _key_file = _admin_path_calls(None, tmp_path)
    fenv["FAKE_UID"] = "0"
    fenv["FAKE_VANTAGE_ROOT"] = str(tmp_path / "vantage")
    fenv["FAKE_HAS_nmap"] = "1"
    fenv["FAKE_HAS_timeout"] = "1"

    vantage = tmp_path / "vantage"
    bin_dir = vantage / "usr" / "local" / "libexec"
    bin_dir.mkdir(parents=True)
    preexisting = b"#!/bin/sh\\nprintf 'good\\n'"
    (bin_dir / "newton-scan").write_bytes(preexisting)
    (bin_dir / "newton-scan").chmod(0o755)
    dropbear_keys = vantage / "etc" / "dropbear" / "authorized_keys"
    dropbear_keys.parent.mkdir(parents=True)
    preexisting_keyline = "ssh-ed25519 AAAAOLD old-key"
    dropbear_keys.write_text(preexisting_keyline + "\n")

    # Replace the third header line (the digest) with a 5-char lowercase
    # hex string.  The case-pattern check fails before any filesystem
    # change.
    fenv["FAKE_STDIN_TRANSFORM"] = "bad_digest:abc12"

    result = subprocess.run(
        [str(SETUP), "edge", "install"], text=True, capture_output=True, env=fenv, timeout=10
    )

    assert result.returncode == 2, result.stdout + result.stderr
    assert "64 lowercase hex" in result.stderr, result.stderr
    assert (bin_dir / "newton-scan").read_bytes() == preexisting
    text = dropbear_keys.read_text()
    assert text == preexisting_keyline + "\n"
    assert not list(bin_dir.glob(".newton-scan.*"))


def test_install_r9_refuses_uppercase_digest_before_any_change(tmp_path):
    """R9: a 64-char but uppercase hex digest is refused.  Use the real
    (lowercase) digest and ask the harness to uppercase it; the case
    pattern rejects it."""
    fenv, log, _inventory, _key_file = _admin_path_calls(None, tmp_path)
    fenv["FAKE_UID"] = "0"
    fenv["FAKE_VANTAGE_ROOT"] = str(tmp_path / "vantage")
    fenv["FAKE_HAS_nmap"] = "1"
    fenv["FAKE_HAS_timeout"] = "1"

    vantage = tmp_path / "vantage"
    bin_dir = vantage / "usr" / "local" / "libexec"
    bin_dir.mkdir(parents=True)
    preexisting = b"#!/bin/sh\\nprintf 'good\\n'"
    (bin_dir / "newton-scan").write_bytes(preexisting)
    (bin_dir / "newton-scan").chmod(0o755)
    dropbear_keys = vantage / "etc" / "dropbear" / "authorized_keys"
    dropbear_keys.parent.mkdir(parents=True)
    preexisting_keyline = "ssh-ed25519 AAAAOLD old-key"
    dropbear_keys.write_text(preexisting_keyline + "\n")

    fenv["FAKE_STDIN_TRANSFORM"] = "uppercase_digest"

    result = subprocess.run(
        [str(SETUP), "edge", "install"], text=True, capture_output=True, env=fenv, timeout=10
    )

    assert result.returncode == 2, result.stdout + result.stderr
    assert "64 lowercase hex" in result.stderr, result.stderr
    assert (bin_dir / "newton-scan").read_bytes() == preexisting
    text = dropbear_keys.read_text()
    assert text == preexisting_keyline + "\n"
    assert not list(bin_dir.glob(".newton-scan.*"))


def test_install_r9_refuses_when_sha256sum_missing_on_vantage(tmp_path):
    """R9: the probe extended to include sha256sum refuses (and names
    `sha256sum` in the message) when the vantage does not have it.  The
    install ssh never runs."""
    fenv, log, _inventory, _key_file = _admin_path_calls(None, tmp_path)
    fenv["FAKE_UID"] = "0"
    fenv["FAKE_VANTAGE_ROOT"] = str(tmp_path / "vantage")
    fenv["FAKE_HAS_nmap"] = "1"
    fenv["FAKE_HAS_timeout"] = "1"
    # Default for _admin_path_calls is FAKE_HAS_sha256sum=1; flip it off
    # to make the probe refuse.
    fenv["FAKE_HAS_sha256sum"] = "0"

    result = subprocess.run(
        [str(SETUP), "edge", "install"], text=True, capture_output=True, env=fenv, timeout=10
    )

    assert result.returncode == 2, result.stdout + result.stderr
    assert "sha256sum" in result.stderr, result.stderr
    # The message names the fix path (apk add nmap ... + sha256sum, or
    # apt install nmap + sha256sum).
    assert "apk add" in result.stderr or "apt install" in result.stderr, result.stderr
    # And: the probe ssh was the last ssh call (no install ssh).
    blocks = call_blocks(log)
    names = [name for name, _ in blocks]
    assert names == ["ssh-keygen", "ssh"], names
    # And: the vantage has no newton-scan binary or temp file.
    vantage = tmp_path / "vantage"
    bin_dir = vantage / "usr" / "local" / "libexec"
    assert not (bin_dir / "newton-scan").exists()
    assert not list(bin_dir.glob(".newton-scan.*")) if bin_dir.exists() else True


def test_install_r9_probe_includes_sha256sum(tmp_path):
    """R9: the probe ssh call probes for sha256sum alongside nmap and
    timeout.  The remote script text contains the tool name."""
    fenv, log, _inventory, _key_file = _admin_path_calls(None, tmp_path)
    fenv["FAKE_UID"] = "0"
    fenv["FAKE_VANTAGE_ROOT"] = str(tmp_path / "vantage")
    fenv["FAKE_HAS_nmap"] = "1"
    fenv["FAKE_HAS_timeout"] = "1"

    result = subprocess.run(
        [str(SETUP), "edge", "install"], text=True, capture_output=True, env=fenv, timeout=10
    )

    assert result.returncode == 0, result.stdout + result.stderr
    remote_cmds = _remote_ssh_blocks(log)
    assert len(remote_cmds) == 2
    probe = remote_cmds[0]
    assert "command -v" in probe
    assert "nmap" in probe
    assert "timeout" in probe
    assert "sha256sum" in probe


# ---- the vantage setup loader must apply the same inventory-file checks
# and the same proxy_command allowlist as the MCP server.


def _inventory_file_refusal_messages():
    """The static refusal messages mcp/newton_mcp/inventory_file.py returns,
    read from its source so this drift test cannot drift from it."""
    tree = ast.parse((ROOT / "mcp" / "newton_mcp" / "inventory_file.py").read_text())
    messages = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Return) or node.value is None:
            continue
        value = node.value
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            prefix = value.value
        elif isinstance(value, ast.JoinedStr):
            first = value.values[0]
            if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
                continue
            prefix = first.value
        else:
            continue
        # The lstat OSError branch interpolates a strerror, so its text is a
        # template rather than a fixed string; it is covered by its own
        # refusal tests, not by this verbatim comparison.
        if prefix.startswith("inventory file cannot be inspected"):
            continue
        messages.append(prefix)
    return tuple(messages)


INVENTORY_REFUSAL_MESSAGES = _inventory_file_refusal_messages()


def test_inventory_file_messages_match_vantage_setup():
    """The three static refusal messages must appear verbatim in the script's
    embedded loader, so an operator sees the same wording on both paths."""
    assert len(INVENTORY_REFUSAL_MESSAGES) == 3, INVENTORY_REFUSAL_MESSAGES
    text = SETUP.read_text()
    for message in INVENTORY_REFUSAL_MESSAGES:
        assert message in text, message


def test_router_setup_messages_match():
    """Same drift guard for the router setup script, which now applies the same
    inventory-file check (SF1)."""
    text = ROUTER_SETUP.read_text()
    for message in INVENTORY_REFUSAL_MESSAGES:
        assert message in text, message


def test_inventory_symlink_is_refused(tmp_path):
    """A symlinked inventory is refused without ever being opened: lstat sees
    a link, and the loader says so instead of following it."""
    inventory, _key_file, _known_hosts, _admin = write_inventory(tmp_path)
    real = tmp_path / "devices-real.toml"
    inventory.rename(real)
    inventory.symlink_to(real)
    env, log = fake_tools(tmp_path)
    setup_env(env, inventory, tmp_path)

    result = subprocess.run(
        [str(SETUP), "edge", "install"], text=True, capture_output=True, env=env, timeout=10
    )

    assert result.returncode == 2, result.stdout + result.stderr
    assert "inventory file must be a regular file, not a symlink" in result.stderr
    assert not log.exists()


def test_inventory_group_or_world_writable_is_refused(tmp_path):
    """A 0664 inventory can be rewritten by another local user between the
    check and the read, so the loader refuses and names the fix."""
    inventory, _key_file, _known_hosts, _admin = write_inventory(tmp_path)
    inventory.chmod(0o664)
    env, log = fake_tools(tmp_path)
    setup_env(env, inventory, tmp_path)

    result = subprocess.run(
        [str(SETUP), "edge", "install"], text=True, capture_output=True, env=env, timeout=10
    )

    assert result.returncode == 2, result.stdout + result.stderr
    assert "inventory file must not be group- or world-writable" in result.stderr
    assert f"chmod go-w {inventory}" in result.stderr
    assert not log.exists()


def test_inventory_owned_by_another_user_is_refused(tmp_path):
    """An inventory owned by a different uid than the one running the script
    is refused.  Needs root to chown, so it is skipped otherwise."""
    if os.geteuid() != 0:
        pytest.skip("chown to a foreign uid needs root")
    inventory, _key_file, _known_hosts, _admin = write_inventory(tmp_path)
    foreign_uid = 65534 if os.geteuid() != 65534 else 65533
    os.chown(inventory, foreign_uid, -1)
    env, log = fake_tools(tmp_path)
    setup_env(env, inventory, tmp_path)

    result = subprocess.run(
        [str(SETUP), "edge", "install"], text=True, capture_output=True, env=env, timeout=10
    )

    assert result.returncode == 2, result.stdout + result.stderr
    assert "inventory file must be owned by the user running the MCP server" in result.stderr
    assert not log.exists()

def _pretend_other_euid(monkeypatch, tmp_path):
    """Make the script's python think it runs as another user (no root needed)."""
    hook = tmp_path / "euidhook"
    hook.mkdir()
    (hook / "sitecustomize.py").write_text("import os\nos.geteuid = lambda: os.stat(os.environ['NEWTON_INVENTORY']).st_uid + 1\n")
    monkeypatch.setenv("PYTHONPATH", str(hook))


def test_inventory_owner_mismatch_is_refused_without_root(tmp_path, monkeypatch):
    inventory, _key_file, _known_hosts, _admin = write_inventory(tmp_path)
    env, log = fake_tools(tmp_path)
    setup_env(env, inventory, tmp_path)
    _pretend_other_euid(monkeypatch, tmp_path)
    env["PYTHONPATH"] = os.environ["PYTHONPATH"]

    result = subprocess.run(
        [str(SETUP), "edge", "install"], text=True, capture_output=True, env=env, timeout=10
    )

    assert result.returncode == 2, result.stdout + result.stderr
    assert "inventory file must be owned by the user running the MCP server" in result.stderr
    assert not log.exists()


def test_missing_inventory_keeps_its_current_message(tmp_path):
    """A missing inventory is not one of the refusals above: the read error
    the operator already knows stays as it was."""
    env, log = fake_tools(tmp_path)
    setup_env(env, tmp_path / "absent.toml", tmp_path)

    result = subprocess.run(
        [str(SETUP), "edge", "install"], text=True, capture_output=True, env=env, timeout=10
    )

    assert result.returncode == 2, result.stdout + result.stderr
    assert "cannot read inventory" in result.stderr
    assert "regular file" not in result.stderr
    assert not log.exists()


@pytest.mark.parametrize(
    "char", [";", "|", "&", "$", "`", "(", ")", "<", ">", "'", '"', "\\"]
)
def test_proxy_command_with_shell_metacharacter_is_refused(tmp_path, char):
    """proxy_command reaches ssh -o ProxyCommand=<value>; any shell
    metacharacter in it is refused, exactly as the MCP server refuses it."""
    inventory, _key_file, _known_hosts, _admin = write_inventory(
        tmp_path, proxy=f"ssh -W %h:%p root@jump{char}id"
    )
    env, log = fake_tools(tmp_path)
    setup_env(env, inventory, tmp_path)

    result = subprocess.run(
        [str(SETUP), "edge", "install"], text=True, capture_output=True, env=env, timeout=10
    )

    assert result.returncode == 2, result.stdout + result.stderr
    assert "bad proxy_command for edge" in result.stderr
    assert not log.exists()


def test_proxy_command_without_metacharacter_is_accepted(tmp_path):
    """The real-world ProxyCommand form stays accepted and reaches ssh."""
    proxy = "ssh -i ~/.ssh/key -o BatchMode=yes -W %h:%p root@jump"
    inventory, _key_file, _known_hosts, _admin = write_inventory(tmp_path, proxy=proxy)
    env, log = fake_tools(tmp_path)
    setup_env(env, inventory, tmp_path)

    result = subprocess.run(
        [str(SETUP), "edge", "install"], text=True, capture_output=True, env=env, timeout=10
    )

    assert result.returncode == 0, result.stdout + result.stderr
    logged = [arg for _name, block in call_blocks(log) for arg in args_for(block)]
    assert f"ProxyCommand={proxy}" in logged


def test_install_refuses_keys_dir_under_group_writable_parent(tmp_path):
	"""SW2 item 4: the vantage keys dir is not created when its PARENT is
	group- or world-writable without the sticky bit, and nothing is sent to
	the vantage."""
	inventory, key_file, known_hosts, admin_key = write_inventory(tmp_path)
	env, log = fake_tools(tmp_path)
	setup_env(env, inventory, tmp_path)
	hostile = tmp_path / "hostile"
	hostile.mkdir()
	os.chmod(hostile, 0o777)
	hostile_key = hostile / "keys" / "edge"
	inventory.write_text(inventory.read_text().replace(
		'key_file = "%s"' % key_file, 'key_file = "%s"' % hostile_key))
	inventory.chmod(0o644)

	result = subprocess.run(
		[str(SETUP), "edge", "install"], text=True, capture_output=True, env=env, timeout=10
	)

	assert result.returncode != 0, result.stdout + result.stderr
	assert "group- or world-writable without the sticky bit" in result.stderr
	assert list(hostile.iterdir()) == []
	assert not log.exists()
