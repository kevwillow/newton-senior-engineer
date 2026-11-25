"""``newton-doctor ad`` is wired into the doctor script.

The check itself is tested in mcp/tests/test_ad_doctor.py; here the script
dispatches to it, needs no --router, and keeps the doctor's exit codes.
The repo copy runs against a fake root (NEWTON_DOCTOR_ROOT); the installed
copy is only checked as text, because it ignores every seam.
"""

import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_newton_isolation import DOCTOR, ROOT, run  # noqa: E402

PUBKEY = "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l8GmJE"


def make_root(tmp_path, key_file=None):
    home = tmp_path / "root/var/lib/newton"
    (home / "state/approval-fp").mkdir(parents=True)
    key = home / "dc1-ops.key"
    key.write_text("key\n")
    key.chmod(0o600)
    known = home / "dc1.known_hosts"
    known.write_text(f"192.0.2.21 ssh-ed25519 {PUBKEY}\n")
    known.chmod(0o600)
    (home / "state/approval-fp/dc1-ops").write_text("v1 " + "cd" * 32 + "\n")
    inventory = home / "devices.toml"
    inventory.write_text(
        "[devices.dc1-ops]\n"
        'platform = "ad-samba-write"\nad_domain = "dc1-ops"\nhost = "192.0.2.21"\n'
        'user = "newton-ops"\ndomain = "ad.example.com"\n'
        f'key_file = "{key_file or key}"\nknown_hosts = "{known}"\n'
    )
    # the mode the installer gives the inventory (docs/INSTALL.md step 7):
    # Newton refuses to load a group- or world-writable one
    inventory.chmod(0o600)
    return tmp_path / "root"


def ad(tmp_path, *args, root):
    env = dict(os.environ, NEWTON_DOCTOR_ROOT=str(root))
    return subprocess.run(
        [str(DOCTOR), "ad", *args], text=True, capture_output=True, env=env, timeout=30
    )


def test_ad_needs_no_router_and_a_clean_inventory_exits_0(tmp_path):
    result = ad(tmp_path, root=make_root(tmp_path))
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS ad-key-file" in result.stdout
    assert result.stdout.splitlines()[-1].startswith("ad: 0 finding(s)")


def test_ad_finding_exits_1_with_the_next_step(tmp_path):
    root = make_root(tmp_path, key_file="<the private key of the write key, on the Newton host>")
    result = ad(tmp_path, root=root)
    assert result.returncode == 1, result.stdout + result.stderr
    assert any(
        x.startswith("FAIL ad-key-file[dc1-ops]") and "Next: sudo -u newton ssh-keygen" in x
        for x in result.stdout.splitlines()
    ), result.stdout


def test_ad_takes_no_arguments(tmp_path):
    result = ad(tmp_path, "--router", "root@192.0.2.1", root=make_root(tmp_path))
    assert result.returncode == 2
    assert "usage: newton-doctor ad" in result.stderr


def test_without_ad_the_router_is_still_required():
    result = run(DOCTOR, env=dict(os.environ))
    assert result.returncode == 2


def test_the_installed_copy_runs_as_newton_from_the_installed_code():
    text = DOCTOR.read_text()
    assert "/opt/newton/venv/bin/python -I -m newton_mcp.ad.doctor" in text
    assert "--expect-user newton" in text
    assert "/var/lib/newton/state" in text
