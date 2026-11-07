"""Design 3.5 simple subcommands: hostname, fw-loaded, logd-pid, backup."""

import io
import tarfile

from conftest import BUSYBOX

# ---- hostname (moved snippet I3, design 3.5) ---------------------------------


def test_hostname_output_and_exit_pass_through(router):
    router.set_fake("uci", out="newton-test\n")
    res = router.forced("hostname", role="read", timeout=15)
    assert (res.rc, res.out, res.err) == (0, "newton-test\n", "")
    assert router.calls() == ["uci -q get system.@system[0].hostname"]


def test_hostname_failure_passes_through(router):
    router.set_fake("uci", rc=1, err="uci: entry not found\n")
    res = router.forced("hostname", role="read", timeout=15)
    assert (res.rc, res.out, res.err) == (1, "", "uci: entry not found\n")


def test_hostname_does_not_read_stdin(router):
    router.set_fake("uci", out="newton-test\n")
    res = router.direct_open_stdin("hostname", timeout=10)
    assert (res.rc, res.out) == (0, "newton-test\n")


# ---- fw-loaded (moved snippet I5; M40: never nft's own output) ----------------


def test_fw_loaded_one(router):
    router.set_fake("nft", out="table inet fw4 { NFTSECRET-DUMP }\n")
    res = router.forced("fw-loaded", role="read", timeout=15)
    assert (res.rc, res.out) == (0, "1\n")
    assert "NFTSECRET" not in res.out and "NFTSECRET" not in res.err


def test_fw_loaded_zero(router):
    router.set_fake("nft", rc=1, out="Error: no such table\n")
    res = router.forced("fw-loaded", role="read", timeout=15)
    assert (res.rc, res.out) == (0, "0\n")
    assert res.out in ("0\n", "1\n")
    assert "Error" not in res.out and "Error" not in res.err


# ---- logd-pid (moved snippet I6; the ~5 s wait is by design) ------------------


def test_logd_pid_prints_pid(router):
    router.set_fake("pidof", out="411\n")
    res = router.forced("logd-pid", role="read", timeout=15)
    assert (res.rc, res.out) == (0, "411\n")
    assert router.calls() == ["pidof logd"]


def test_logd_pid_found_on_second_try(router):
    # a custom pidof that fails once, then reports a pid
    pidof = router.root / "bin/pidof"
    pidof.unlink()
    pidof.write_text(
        "#!/usr/bin/busybox sh\n"
        'root="$NEWTON_ROUTER_ROOT"\n'
        'echo "pidof $*" >> "$root/control/calls.log"\n'
        'n=$(cat "$root/control/pidof.tries" 2>/dev/null || echo 0)\n'
        'n=$((n + 1)); echo "$n" > "$root/control/pidof.tries"\n'
        'if [ "$n" -ge 2 ]; then echo 411; exit 0; fi\n'
        "exit 1\n"
    )
    pidof.chmod(0o755)
    res = router.forced("logd-pid", role="read", timeout=15)
    assert (res.rc, res.out) == (0, "411\n")
    assert router.calls() == ["pidof logd", "pidof logd"]


def test_logd_pid_never_found(router):
    # takes about 5 s: the snippet retries once a second, five times
    router.set_fake("pidof", rc=1)
    res = router.forced("logd-pid", role="read", timeout=20)
    assert (res.rc, res.out, res.err) == (0, "", "")
    assert router.calls() == ["pidof logd"] * 6


# ---- backup (design 3.5; M44: only etc/config in the archive) -----------------


SECRET_FILES = (
    "etc/shadow",
    "etc/newton/approve.key",
    "etc/dropbear/dropbear_ed25519_host_key",
)


def add_secret_files(router):
    for rel in SECRET_FILES:
        router.write(rel, "SECRET-" + rel + "\n")


def test_backup_archive_holds_only_etc_config(router):
    add_secret_files(router)
    res = router.direct("backup", timeout=30)
    assert res.rc == 0
    assert res.err == ""
    with tarfile.open(fileobj=io.BytesIO(res.outb), mode="r:gz") as tar:
        names = tar.getnames()
    assert names, "empty archive"
    for name in names:
        assert name == "etc/config" or name.startswith("etc/config/"), name
    for rel in SECRET_FILES:
        assert rel not in names
    # the config files the fake root ships are all in
    for cfg in ("system", "network", "firewall", "dhcp", "wireless"):
        assert f"etc/config/{cfg}" in names


def test_backup_exit_status_is_tars(router):
    tar = router.root / "bin/tar"
    tar.unlink()
    tar.write_text("#!/usr/bin/busybox sh\nexit 4\n")
    tar.chmod(0o755)
    res = router.direct("backup", timeout=15)
    assert res.rc == 4
    assert res.out == ""
