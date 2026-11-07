"""Bootstrap dirty-environment refusals."""
import pytest
from bootstrap_harness import FakeRoot, userns_ok

pytestmark = pytest.mark.skipif(not userns_ok(), reason="unshare -Urm unavailable")
BASE = {"SUDO_USER": "ci-test"}

DIRTY = [
    ("LD_PRELOAD", "/x", "environment variable not allowed"),
    ("LD_LIBRARY_PATH", "/x", "environment variable not allowed"),
    ("PATH", "/tmp/evil:/usr/bin", "PATH contains"),
    ("PATH", "/usr/bin::/bin", "PATH contains"),
    ("PATH", "/usr/bin:.", "PATH contains"),
    ("IFS", "x", "environment variable not allowed"),
    ("ENV", "/x", "environment variable not allowed"),
    ("PYTHONPATH", "/x", "environment variable not allowed"),
    ("GIT_DIR", "/x", "environment variable not allowed"),
    ("SHELLOPTS", "xtrace", "environment variable not allowed"),
    ("BASHOPTS", "x", "environment variable not allowed"),
    ("PS4", "x", "environment variable not allowed"),
    ("PROMPT_COMMAND", "x", "environment variable not allowed"),
    ("CDPATH", "/x", "environment variable not allowed"),
    ("GLOBIGNORE", "x", "environment variable not allowed"),
    ("SUDO_USER", "root", "SUDO_USER"),
    ("SUDO_USER", "a b", "SUDO_USER"),
]


@pytest.mark.parametrize("name,value,text", DIRTY)
def test_dirty_env_is_refused(tmp_path, name, value, text):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    rc, out, err = fr.run([boot, "version"], env={**BASE, name: value})
    assert rc == 1, (rc, out, err)
    assert text in err, err
    assert "sha256" not in out


def test_bash_env_file_is_never_executed(tmp_path):
    fr = FakeRoot(tmp_path)
    marker = fr.stage / "marker-src.sh"
    marker.write_text("touch /bash_env_ran\n")
    boot = fr.install_bootstrap()
    rc, out, err = fr.run(
        ["bash", "-c",
         f"env BASH_ENV=/marker-src.sh SUDO_USER=ci-test {boot} version; echo rc=$?; ls /bash_env_ran 2>&1"]
    )
    assert "rc=1" in out, out
    assert "environment variable not allowed (BASH_ENV)" in err, err
    assert "No such file" in out, out


def test_marker_variable_cannot_skip_the_checks(tmp_path):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()

    rc, out, err = fr.run(
        [boot, "version"],
        env={**BASE, "_NEWTON_BOOTSTRAP_CLEAN": "1", "LC_ALL": "C"},
    )
    assert rc == 1, (rc, out, err)
    assert "environment after re-exec still has" in err, err

    rc, out, err = fr.run(
        [boot, "version"],
        env={**BASE, "_NEWTON_BOOTSTRAP_CLEAN": "1", "LD_PRELOAD": "/x"},
    )
    assert rc == 1, (rc, out, err)
    assert "environment variable not allowed" in err, err


def test_harmless_env_is_accepted_and_scrubbed(tmp_path):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    rc, out, err = fr.run(
        [boot, "version"],
        env={"HOME": "/home/x", "LANG": "en_US.UTF-8", "SUDO_USER": "alice"},
    )
    assert rc == 0, (rc, out, err)
    assert out.startswith("sha256 "), out


def test_works_without_sudo_user(tmp_path):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    rc, out, err = fr.run([boot, "version"], env={})
    assert rc == 0, (rc, out, err)
    assert out.startswith("sha256 "), out

def test_exported_shell_function_is_never_imported(tmp_path):
    # bash -p (the shebang) does not import functions from the environment; `version` calls sha256sum.
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    rc, out, err = fr.run(
        ["bash", "-c", f"env 'BASH_FUNC_sha256sum%%=() {{ touch /pwned; }}' SUDO_USER=ci-test {boot} version; echo rc=$?; ls /pwned 2>&1"]
    )
    assert "rc=0" in out and "sha256 " in out, (out, err)
    assert "No such file" in out, out
