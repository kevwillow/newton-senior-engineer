"""The backup/restore drill `p-drill-01-backup-restore` and the
`p_drill_restored` check that runs after its own `reset_after`.

Every Pulsar reset is the same drill: a `sysupgrade -r` of the baseline archive
followed by a fingerprint check. This scenario is the one that names the drill
and shows that a confirmed multi-config change does not survive it.

Everything here is offline: files in the repo, the runner's own loader and
validator, and the check's own shell text run for real under `sh -c` against
generated stub `uci` and `nft` scripts. No router, no VM, no network.
"""
from __future__ import annotations

import hashlib
import io
import os
import re
import subprocess
import tarfile
import tomllib
from pathlib import Path

import pytest

import newton_lab_test as nl

LAB_DIR = Path(__file__).resolve().parent.parent
EXAMPLE = LAB_DIR / "pulsar.example.toml"
SCEN_DIR = LAB_DIR / "scenarios-pulsar"
SCEN = SCEN_DIR / "p-drill-01-backup-restore.toml"
README = SCEN_DIR / "README.md"

NAME = "p-drill-01-backup-restore"
CHECK = "p_drill_restored"

# The state the baseline archive holds, i.e. what the restore must put back.
#
# ARCHIVE_HOSTNAME is the value of `system.@system[0].hostname` inside the
# archive lab/pulsar.example.toml points at as `baseline_backup`: a `sysupgrade
# -b` tar.gz whose `etc/config/system` was taken with Newton installed on
# Pulsar. It is NOT read out of lab/pulsar.example.toml or any other file in
# this repo (the example holds no router state, and
# test_the_archive_facts_are_not_read_from_a_repo_file says so), so it is
# spelled here as a fact about the archive rather than derived from a file that
# could drift away from it.
ARCHIVE_HOSTNAME = "Pulsar"
# The archive has no drilltest section in either config, so both must read back
# empty once the restore has run.
ARCHIVE_SECTIONS_GONE = ("dhcp.drilltest", "firewall.drilltest")
# The port the scenario's REJECT rule blocks; the archive's ruleset has no rule
# carrying it.
ARCHIVE_RULE_PORT = "65123"

# What the scenario puts in, all of it gone again after the reset.
DRILL_HOSTNAME = "pulsar-drill"
DRILL_MAC = "02:00:00:00:00:88"
DRILL_IP = "192.168.1.88"
DRILL_LEASE = "drilltest"
DRILL_RULE = "Drill-Test"
DRILL_SECTIONS = ("dhcp.drilltest", "firewall.drilltest")


@pytest.fixture(scope="module")
def example_text() -> str:
    assert EXAMPLE.is_file(), f"{EXAMPLE} is missing"
    return EXAMPLE.read_text()


@pytest.fixture(scope="module")
def example(example_text: str) -> dict:
    return tomllib.loads(example_text)


@pytest.fixture(scope="module")
def scenario_text() -> str:
    assert SCEN.is_file(), f"{SCEN} is missing"
    return SCEN.read_text()


@pytest.fixture(scope="module")
def scenario(scenario_text: str) -> dict:
    return tomllib.loads(scenario_text)


@pytest.fixture(scope="module")
def pulsar_scenarios() -> dict:
    return {p.stem: tomllib.loads(p.read_text())
            for p in sorted(SCEN_DIR.glob("*.toml"))}


@pytest.fixture(scope="module")
def synthetic_archive() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name in ("etc/config/network", "etc/config/firewall",
                     "etc/config/system", "etc/config/dropbear",
                     "etc/dropbear/authorized_keys", "etc/newton/device-id",
                     "etc/newton/profile"):
            data = {"etc/newton/device-id": b"pulsar\n",
                    "etc/newton/profile": b"lab\n"}.get(name, b"synthetic\n")
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


@pytest.fixture
def example_lab(tmp_path, example_text, synthetic_archive, monkeypatch):
    """The example as the runner loads it: a synthetic HOME with the
    placeholder files, and the archive's sha256 filled in."""
    monkeypatch.setenv("HOME", str(tmp_path))
    home = tmp_path / ".config" / "newton" / "pulsar"
    home.mkdir(parents=True)
    for name in ("known-hosts", "admin-key", "change-key", "wifi-psk"):
        (home / name).write_text("x\n")
    (home / "baseline.tar.gz").write_bytes(synthetic_archive)
    path = tmp_path / "lab.toml"
    path.write_text(example_text.replace(
        "<sha256 of baseline.tar.gz>",
        hashlib.sha256(synthetic_archive).hexdigest()))
    return nl.load_lab(path)


# ---------- the scenario file itself ----------

def test_the_drill_scenario_is_named_after_its_scenario(scenario):
    assert SCEN.stem == NAME
    assert scenario["name"] == NAME


def test_the_drill_scenario_loads_through_the_runner(scenario_text, example_lab):
    """The runner's own loader, not just tomllib: the scenario is loadable."""
    loaded = nl.load_scenarios(SCEN_DIR)
    by_name = {s.name: s for s in loaded}
    assert NAME in by_name, sorted(by_name)
    assert by_name[NAME].path == SCEN


def test_the_drill_scenario_has_the_drill_fields(scenario):
    assert scenario["target"] == "pulsar"
    assert scenario["reset"] == ["pulsar"]
    assert scenario["reset_after"] == ["pulsar"]
    assert scenario["after_reset"] == [CHECK]
    assert "approval" not in scenario  # the router rates this batch not-required (measured live)
    assert scenario["expect"] == "confirmed"
    assert scenario["timeout"] == 240
    assert scenario["regression"] == "default"


def test_the_drill_scenario_validates_against_the_example(example_lab,
                                                          pulsar_scenarios):
    """Every step, check, var and device it names is defined in the example,
    and the runner's validator is silent about it."""
    assert nl.validate_scenarios(example_lab,
                                 nl.load_scenarios(SCEN_DIR)) == []


def test_every_name_the_drill_scenario_uses_is_defined_in_the_example(
        scenario, example, example_lab):
    data = scenario
    steps = set(data.get("setup", [])) | set(data.get("cleanup", []))
    checks = set(data.get("after_reset", []))
    assert steps <= set(example_lab.steps), steps - set(example_lab.steps)
    assert checks <= set(example_lab.checks), checks - set(example_lab.checks)
    texts = [data["batch"]]
    for post in data.get("post", []):
        texts.append(post["cmd"])
    for effect in data.get("effect", []):
        texts.append(effect["cmd"])
    texts.append(example["checks"][CHECK]["cmd"])
    for name in sorted(steps):
        texts.append(example_lab.steps[name].cmd)
    used = nl.used_placeholders(*texts)
    assert used <= set(example_lab.var_defs), used - set(example_lab.var_defs)
    devices = {data["target"], *data["reset"], *data["reset_after"]}
    for post in data.get("post", []) + data.get("effect", []):
        devices.add(post["device"])
    devices.add(example["checks"][CHECK]["device"])
    devices.discard("local")
    assert devices <= set(example_lab.devices), devices - set(example_lab.devices)


def test_no_pulsar_scenario_names_after_reset_without_a_reset_after(
        pulsar_scenarios):
    """The rule `after_reset` lives by: a check that runs after the restore is
    meaningless without a restore to run after, and the runner refuses the
    whole run (exit 2) before any device contact."""
    bad = {name: data.get("after_reset") for name, data in
           pulsar_scenarios.items()
           if data.get("after_reset") and not data.get("reset_after")}
    assert not bad, bad


def test_the_drill_batch_is_set_lines_only(scenario):
    """A uci batch of `set` lines: no delete, no del_list, no add_list. uci
    batch writes to stderr for a delete of something that is not there, and
    scripts/owrt-safe-apply.sh rejects a batch whose uci wrote to stderr."""
    lines = [ln.strip() for ln in scenario["batch"].splitlines()
             if ln.strip()]
    assert lines
    for line in lines:
        assert line.startswith("set "), line
        assert "=" in line, line
        verb = line.split(" ", 1)[0]
        assert verb == "set", verb


def test_the_drill_batch_is_the_documented_one(scenario):
    batch = scenario["batch"]
    assert "set system.@system[0].hostname='pulsar-drill'" in batch
    assert "set dhcp.drilltest=host" in batch
    assert "set dhcp.drilltest.name='drilltest'" in batch
    assert "set dhcp.drilltest.mac='02:00:00:00:00:88'" in batch
    assert "set dhcp.drilltest.ip='192.168.1.88'" in batch
    assert "set firewall.drilltest=rule" in batch
    assert "set firewall.drilltest.name='Drill-Test'" in batch
    assert "set firewall.drilltest.src='lan'" in batch
    assert "set firewall.drilltest.dest='wan'" in batch
    assert "set firewall.drilltest.proto='tcp'" in batch
    assert "set firewall.drilltest.dest_port='65123'" in batch
    assert "set firewall.drilltest.target='REJECT'" in batch
    assert len([ln for ln in batch.splitlines() if ln.strip()]) == 12


def test_the_drill_batch_carries_no_secret_var(scenario, example_lab):
    """A secret var is only ever substituted into the batch; this one has no
    var at all, and the runner refuses a scenario that names one outside it."""
    secrets = nl.secret_var_names(example_lab)
    assert secrets, "the example defines the Wi-Fi secret var"
    everywhere = [scenario["batch"]]
    for post in scenario.get("post", []):
        everywhere.append(post["cmd"])
    for effect in scenario.get("effect", []):
        everywhere.append(effect["cmd"])
    for probe in scenario.get("probes", []):
        everywhere.extend(probe)
    bad = [text for text in everywhere
           if nl.used_placeholders(text) & secrets]
    assert not bad, bad
    assert nl.used_placeholders(*everywhere) == set()


def test_the_drill_probes_are_the_existing_grammar(scenario):
    """conf-has and nft-rule as p-01 and p-ev-07 use them; nothing invented."""
    probes = scenario.get("probes", [])
    assert ["conf-has", "dnsmasq", "substr", "present", DRILL_MAC] in probes
    assert ["nft-rule", "inet", "fw4", "ruleset", "present",
            f"dport {ARCHIVE_RULE_PORT}"] in probes
    for probe in probes:
        assert probe[0] in ("conf-has", "nft-rule"), probe


# ---------- the posts: the change is live before the reset ----------

def test_the_drill_posts_run_on_pulsar_and_expect_a_fixed_string(scenario):
    posts = scenario.get("post", [])
    assert posts
    for post in posts:
        assert post["device"] == "pulsar", post
        assert post.get("expect_rc", 0) == 0, post
        assert post["expect_stdout"], post
        re.compile(post["expect_stdout"])


def _post_with(scenario, needle):
    hits = [p for p in scenario["post"] if needle in p["cmd"]]
    assert len(hits) == 1, (needle, [p["cmd"] for p in scenario["post"]])
    return hits[0]


@pytest.mark.parametrize("cmd,expected", [
    ("uci get system.@system[0].hostname", [DRILL_HOSTNAME]),
    ("uci get dhcp.drilltest.name", [DRILL_LEASE]),
    ("uci get dhcp.drilltest.mac", [DRILL_MAC]),
    ("uci get dhcp.drilltest.ip", [DRILL_IP]),
    ("uci get firewall.drilltest.name", [DRILL_RULE]),
    ("uci get firewall.drilltest.dest_port", [ARCHIVE_RULE_PORT]),
    ("uci get firewall.drilltest.target", ["REJECT"]),
])
def test_every_value_the_batch_sets_is_read_back(scenario, cmd, expected):
    """`uci get` of each value the batch set, and the regex matches exactly
    that value and nothing else."""
    post = _post_with(scenario, cmd)
    pattern = post["expect_stdout"]
    for value in expected:
        assert re.search(pattern, value), (pattern, value)
        assert not re.search(pattern, value + "x"), pattern
        assert not re.search(pattern, "drilltest-other\n" + value), pattern


def test_the_drill_post_reads_the_live_hostname(scenario):
    post = _post_with(scenario, "/proc/sys/kernel/hostname")
    assert post["cmd"].strip() == "cat /proc/sys/kernel/hostname"
    assert re.search(post["expect_stdout"], DRILL_HOSTNAME)
    assert not re.search(post["expect_stdout"], ARCHIVE_HOSTNAME), \
        "the live hostname post must not pass for the archive's value"


def test_the_drill_post_proves_the_lease_reached_dnsmasq(scenario):
    """The static lease is not just in uci: it is in the generated dnsmasq
    config. The directory is not measured, so either is accepted."""
    post = _post_with(scenario, "grep -rl " + DRILL_MAC)
    assert "/var/etc/" in post["cmd"] and "/tmp/etc/" in post["cmd"]
    assert re.search(post["expect_stdout"], "/tmp/etc/dnsmasq.conf")
    assert re.search(post["expect_stdout"], "/var/etc/dnsmasq.conf")
    assert not re.search(post["expect_stdout"], "/etc/config/dhcp")
    assert not re.search(post["expect_stdout"], "drilltest lease")


def test_the_drill_post_proves_the_rule_is_in_the_loaded_ruleset(scenario):
    post = _post_with(scenario, "nft list ruleset")
    assert f"grep -c {ARCHIVE_RULE_PORT}" in post["cmd"]
    assert re.search(post["expect_stdout"], "1")
    assert re.search(post["expect_stdout"], "4")
    assert not re.search(post["expect_stdout"], "0"), "a count of 0 proves nothing"


def test_the_drill_posts_are_one_per_set_value_plus_the_three_live_facts(scenario):
    """One `uci get` per value the batch sets (the two section-typing lines
    carry no value of their own), plus the three facts that are not in uci: the
    live hostname, the generated dnsmasq config and the loaded ruleset. The
    README says how many posts that is, and this is what keeps the two
    together."""
    values = [ln for ln in scenario["batch"].splitlines()
              if ln.strip() and ln.count(".") >= 2]
    assert len(values) == 10, values
    posts = scenario["post"]
    assert len(posts) == len(values) + 3 == 13
    for line in values:
        # the option the line sets is what the post reads back, verbatim
        option = re.sub(r"=.*$", "", line.strip())[len("set "):]
        assert option == "system.@system[0].hostname" or option.count(".") == 2
        assert any(p["cmd"].strip() == f"uci get {option}" for p in posts), line


# ---------- the description ----------

def test_the_drill_description_says_every_pulsar_reset_is_this_drill(scenario):
    desc = scenario["description"]
    assert "sysupgrade -r" in desc
    assert "baseline archive" in desc
    assert "fingerprint" in desc
    # the one before each scenario and every reset_after
    assert "reset_after" in desc
    assert "every" in desc and "scenario" in desc
    # what the scenario is for
    assert "does not survive" in desc
    assert CHECK in desc
    assert "approval" in desc


def test_the_drill_description_is_not_a_stub(scenario):
    assert len(scenario["description"]) > 400, len(scenario["description"])


# ---------- the check, run for real against stub uci and nft ----------

UCI_STUB = """#!/bin/sh
case "$*" in
  *'system.@system[0].hostname'*) v=${STUB_UCI_HOSTNAME-} ;;
  *'dhcp.drilltest'*) v=${STUB_UCI_DHCP_DRILLTEST-} ;;
  *'firewall.drilltest'*) v=${STUB_UCI_FW_DRILLTEST-} ;;
  *) exit 0 ;;
esac
[ -n "$v" ] || exit 1
printf '%s\\n' "$v"
"""

NFT_STUB = """#!/bin/sh
[ "$1" = list ] && [ "$2" = ruleset ] || exit 0
[ -n "${STUB_NFT_RULESET-}" ] || exit 0
printf '%s\\n' "$STUB_NFT_RULESET"
"""

CLEAN_RULESET = """table inet fw4 {
\tchain forward_lan {
\t\t\tmeta l4proto { tcp, udp } jump accept_to_wan comment "Allow forward to wan"
\t}
\tchain forward_wan {
\t\t\tjump reject_to_wan comment "Reject forward to wan"
\t}
}"""

SURVIVING_RULESET = CLEAN_RULESET.replace(
    '\tchain forward_wan {',
    '\tchain forward_lan {\n'
    '\t\t\ttcp dport 65123 reject comment "Drill-Test"\n'
    '\t}\n'
    '\tchain forward_wan {')


def _run_check(example, tmp_path, *, uci_hostname=ARCHIVE_HOSTNAME,
               uci_dhcp="", uci_firewall="", ruleset=CLEAN_RULESET,
               live_hostname=ARCHIVE_HOSTNAME):
    """The check's own shell text, run for real under `sh -c` in tmp_path with
    a PATH whose `uci` and `nft` answer from the environment. The live
    hostname file is a plain file the check reads through its
    NEWTON_HOSTNAME_FILE override, so the /proc read is the only thing stubbed
    out of the check's own text."""
    fake = tmp_path / "bin"
    fake.mkdir()
    (fake / "uci").write_text(UCI_STUB)
    (fake / "nft").write_text(NFT_STUB)
    for path in fake.iterdir():
        path.chmod(0o755)
    hostname_file = tmp_path / "kernel-hostname"
    hostname_file.write_text(live_hostname + "\n")
    env = dict(os.environ,
               PATH=f"{fake}{os.pathsep}{os.environ.get('PATH', '')}",
               STUB_UCI_HOSTNAME=uci_hostname,
               STUB_UCI_DHCP_DRILLTEST=uci_dhcp,
               STUB_UCI_FW_DRILLTEST=uci_firewall,
               STUB_NFT_RULESET=ruleset,
               NEWTON_HOSTNAME_FILE=str(hostname_file))
    return subprocess.run(["sh", "-c", example["checks"][CHECK]["cmd"]],
                          capture_output=True, text=True, env=env,
                          cwd=tmp_path, timeout=20)


def test_p_drill_restored_is_a_pulsar_check(example):
    check = example["checks"][CHECK]
    assert check["device"] == "pulsar"
    assert check.get("timeout", 60) >= 30
    assert check["expect_stdout"] == "^p_drill_restored: "
    assert check.get("description")
    assert "fingerprint" in check["description"]


def test_p_drill_restored_prints_one_line_and_fails_through_fail(example):
    cmd = example["checks"][CHECK]
    echoes = [ln for ln in cmd["cmd"].splitlines()
              if ln.strip().startswith("echo ")]
    assert len(echoes) == 1, echoes
    assert echoes[0].strip() == (
        f'echo "p_drill_restored: hostname={ARCHIVE_HOSTNAME}, drilltest '
        'lease and rule gone"')
    assert 'fail() { echo "p_drill_restored: $1" >&2; exit 1; }' in cmd["cmd"]
    assert cmd["cmd"].count(">&2; exit 1; }") == 1


def test_p_drill_restored_reads_the_hostname_through_the_env_override(example):
    """The shape the stub test depends on: one `h=$(cat ...)` line whose path
    falls back to /proc/sys/kernel/hostname on the router."""
    cmd = example["checks"][CHECK]["cmd"]
    assert ("h=$(cat ${NEWTON_HOSTNAME_FILE:-/proc/sys/kernel/hostname})"
            in cmd)
    assert cmd.count("/proc/sys/kernel/hostname") == 1, \
        "one read of the live hostname, through the override"


def test_p_drill_restored_passes_on_the_archive_state(example, tmp_path):
    proc = _run_check(example, tmp_path)
    assert proc.returncode == 0, (proc.returncode, proc.stdout, proc.stderr)
    assert re.search(example["checks"][CHECK]["expect_stdout"], proc.stdout)
    assert proc.stderr == ""


def _survivor(stub):
    """One value that outlived the restore, and the text stderr must name."""
    return {
        "hostname": (dict(uci_hostname=DRILL_HOSTNAME), "hostname"),
        "live-hostname": (dict(live_hostname=DRILL_HOSTNAME), "hostname"),
        "lease": (dict(uci_dhcp=f"dhcp.{DRILL_LEASE}=host"), DRILL_LEASE),
        "rule": (dict(uci_firewall="firewall.drilltest=rule"),
                 "firewall.drilltest"),
        "nft": (dict(ruleset=SURVIVING_RULESET), ARCHIVE_RULE_PORT),
    }[stub]


@pytest.mark.parametrize("stub", ["hostname", "live-hostname", "lease",
                                  "rule", "nft"])
def test_p_drill_restored_fails_when_a_value_survived_the_restore(
        example, tmp_path, stub):
    """The plant: a survivor has to make the check red, one value at a time,
    with rc 1 and that value named on stderr."""
    overrides, named = _survivor(stub)
    proc = _run_check(example, tmp_path, **overrides)
    assert proc.returncode == 1, (stub, proc.returncode, proc.stdout)
    assert not re.search(example["checks"][CHECK]["expect_stdout"],
                         proc.stdout), (stub, proc.stdout)
    assert proc.stderr.startswith("p_drill_restored: "), (stub, proc.stderr)
    assert named in proc.stderr, (stub, proc.stderr)
    assert proc.stderr.count("\n") == 1, (stub, proc.stderr)


def test_p_drill_restored_names_only_the_first_failing_value(example,
                                                             tmp_path):
    """Every value survived: stderr names the first one that fails, not all of
    them."""
    proc = _run_check(example, tmp_path, uci_hostname=DRILL_HOSTNAME,
                      uci_dhcp=f"dhcp.{DRILL_LEASE}=host",
                      uci_firewall="firewall.drilltest=rule",
                      ruleset=SURVIVING_RULESET,
                      live_hostname=DRILL_HOSTNAME)
    assert proc.returncode == 1
    assert proc.stderr.count("\n") == 1, proc.stderr
    assert DRILL_LEASE not in proc.stderr, proc.stderr
    assert ARCHIVE_RULE_PORT not in proc.stderr, proc.stderr
    assert DRILL_HOSTNAME in proc.stderr, proc.stderr


def test_p_drill_restored_reads_the_five_archive_facts(example):
    """Every fact the drill's after_reset check proves, in the order the check
    reads them: the uci hostname, the two sections gone, the live hostname and
    the ruleset."""
    cmd = example["checks"][CHECK]["cmd"]
    order = [cmd.index("uci -q get system.@system[0].hostname"),
             cmd.index("uci -q get dhcp.drilltest"),
             cmd.index("uci -q get firewall.drilltest"),
             cmd.index("h=$(cat "),
             cmd.index("nft list ruleset")]
    assert order == sorted(order)
    for section in ARCHIVE_SECTIONS_GONE:
        assert f"uci -q get {section}" in cmd
    assert f'!= "{ARCHIVE_HOSTNAME}"' in cmd or \
        f'= {ARCHIVE_HOSTNAME} ]' in cmd


# ---------- the archive facts are facts about the archive ----------

def test_the_archive_facts_are_not_read_from_a_repo_file(example,
                                                        example_lab):
    """`Pulsar` is the baseline archive's own system.@system[0].hostname (the
    `sysupgrade -b` tar.gz lab/pulsar.example.toml points at as
    baseline_backup). It is asserted here as a fact about the archive: it is
    spelled out in the check itself, and no [vars] cmd in the example carries
    it, because the example holds no router state and nothing in this repo can
    drift the expected value away from the archive it names."""
    cmd = example["checks"][CHECK]["cmd"]
    assert ARCHIVE_HOSTNAME == "Pulsar"
    assert f'= {ARCHIVE_HOSTNAME} ]' in cmd
    for name, spec in example_lab.var_defs.items():
        assert ARCHIVE_HOSTNAME not in spec["cmd"], name
    # the archive has neither section and no rule on the drill port
    assert ARCHIVE_SECTIONS_GONE == DRILL_SECTIONS
    assert ARCHIVE_RULE_PORT == "65123"


def test_the_drill_sections_are_named_the_same_on_both_sides(scenario):
    """The scenario's own batch and the check's expectations are one set of
    names, so the check cannot pass for the wrong reason."""
    batch = scenario["batch"]
    for section in DRILL_SECTIONS:
        assert f"set {section}=" in batch
    assert f"dest_port='{ARCHIVE_RULE_PORT}'" in batch


# ---------- the README ----------

def test_the_readme_lists_the_drill_and_its_check():
    text = README.read_text()
    assert NAME in text, NAME
    assert CHECK in text, CHECK
    assert "sysupgrade -r" in text
    # the post count in the README is this test's count
    assert "Thirteen posts" in text
