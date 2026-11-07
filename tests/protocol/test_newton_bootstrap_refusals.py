"""Bootstrap refusal tests: every rule shown refusing inside a fake root-owned namespace."""
from pathlib import Path
import pytest
from bootstrap_harness import FakeRoot, SCRIPT, userns_ok

pytestmark = pytest.mark.skipif(not userns_ok(), reason="unshare -Urm unavailable")


# Added on top of the harness's own clean outer env (PATH HOME LANG); never taken from os.environ.
CLEAN_ENV = {"SUDO_USER": "ci-test"}


def refused(res, text, rc=1):
    code, out, err = res
    assert code == rc, (code, out, err)
    assert text in err, err
    assert "Commit:" not in out


def test_non_root_is_refused(tmp_path):
    fr = FakeRoot(tmp_path)
    refused(fr.run_nonroot([str(SCRIPT), "version"], env=CLEAN_ENV), "must run as root")


def test_chain_not_root_owned(tmp_path):
    # /usr/bin is the host's directory, so it shows up as owned by "nobody" (mode 755, not writable): bind the
    # script over /usr/bin/true and the ONLY thing wrong with its path is the owner of that parent.
    fr = FakeRoot(tmp_path)
    fr.install_bootstrap()
    refused(
        fr.run(["bash", "-c", "mount --bind /usr/local/sbin/newton-bootstrap /usr/bin/true && exec /usr/bin/true version"],
               env=CLEAN_ENV),
        "not owned by root",
    )


@pytest.mark.parametrize("mode", ["777", "775", "757"])
def test_writable_parent_refused(tmp_path, mode):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    refused(fr.run([boot, "version"], env=CLEAN_ENV, sbin_mode=mode), "group/other-writable")


def test_writable_parent_sticky_not_exempt(tmp_path):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    refused(fr.run([boot, "version"], env=CLEAN_ENV, sbin_mode="1777"), "group/other-writable")


def test_writable_file_refused(tmp_path):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap(mode=0o775)
    code, out, err = fr.run([boot, "version"], env=CLEAN_ENV)
    assert code != 0, (code, out, err)
    assert "group/other-writable" in err, err
    assert "newton-bootstrap" in err, err
    assert "Commit:" not in out, out


def test_running_copy_checked_not_installed(tmp_path):
    fr = FakeRoot(tmp_path)
    boot = fr.install_bootstrap()
    code, out, err = fr.run([
        "bash", "-c",
        "mkdir -p /home/u && cp /usr/local/sbin/newton-bootstrap /home/u/newton-bootstrap && "
        "chmod 755 /home/u/newton-bootstrap && chmod 777 /home/u && exec /home/u/newton-bootstrap version"
    ], env=CLEAN_ENV)
    assert code != 0, (code, out, err)
    assert "group/other-writable" in err, err
    assert "/usr/local/sbin" not in err, err
    assert "Commit:" not in out, out