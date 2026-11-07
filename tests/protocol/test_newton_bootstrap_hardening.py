"""Hardening regressions found by planted defects."""
import pytest
from bootstrap_harness import FakeRoot, userns_ok

pytestmark = pytest.mark.skipif(not userns_ok(), reason="unshare -Urm unavailable")
ENV = {"SUDO_USER": "ci-test"}


def test_symlink_in_a_writable_directory_is_refused(tmp_path):
    # the target is fine (installed root-owned path); the PATH IT WAS STARTED AS lives in a 0777 directory
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    rc, out, err = fr.run(
        ["bash", "-c", f"mkdir -p /home/u && chmod 777 /home/u && ln -s {boot} /home/u/nb && exec /home/u/nb version"],
        env=ENV,
    )
    assert rc == 1, (rc, out, err)
    assert "group/other-writable" in err and "/home/u" in err, err
    assert "sha256" not in out


def test_symlink_to_a_script_in_a_writable_directory_is_refused(tmp_path):
    # the REAL file is in a 0777 directory, reached via a symlink at /usr/local/sbin/nb2 (a fine path).
    fr = FakeRoot(tmp_path)
    fr.install_bootstrap(subdir="home/u", name="newton-bootstrap")
    rc, out, err = fr.run(
        ["bash", "-c", "chmod 777 /home/u && ln -s /home/u/newton-bootstrap /usr/local/sbin/nb2 && exec /usr/local/sbin/nb2 version"],
        env=ENV,
    )
    assert rc == 1, (rc, out, err)
    assert "group/other-writable" in err and "/home/u" in err, err
    assert "sha256" not in out


def test_login_shell_environment_is_accepted(tmp_path):
    # A real `sudo -i` shell carries these; the re-exec must drop them rather than refuse.
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    env = {
        "SUDO_USER": "alice",
        "SUDO_UID": "1000",
        "SUDO_GID": "1000",
        "SUDO_COMMAND": "/bin/bash",
        "TERM": "xterm-256color",
        "LS_COLORS": "rs=0:di=01;34",
        "USER": "root",
        "LOGNAME": "root",
        "MAIL": "/var/mail/root",
        "SHELL": "/bin/bash",
        "LANGUAGE": "en_US:en",
        "LC_ALL": "en_US.UTF-8",
        "LC_CTYPE": "en_US.UTF-8",
        "XDG_RUNTIME_DIR": "/run/user/0",
        "OLDPWD": "/home/alice",
        "HOME": "/root",
    }
    rc, out, err = fr.run([boot, "version"], env=env)
    assert rc == 0, (rc, out, err)
    assert out.startswith("sha256 "), (rc, out, err)


@pytest.mark.parametrize("sub", ["install", "self-update"])
def test_refusal_text_never_contains_raw_control_bytes(tmp_path, sub):
    # When refusing, the error text must escape control bytes (ESC, BEL) rather than emit them raw.
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    rc, out, err = fr.run(
        [boot, sub, "/no\x1b[31mpe\x07x", "a" * 40],
        tty_input="x\n",
        env=ENV,
    )
    assert rc == 1, (rc, out, err)
    assert "\x1b" not in err, err
    assert "\x07" not in err, err
    assert "\\x1b" in err, err
    assert "nothing installed" in err, err