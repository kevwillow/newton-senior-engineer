#!/usr/bin/env python3
"""Newton lab scenario runner.

Reads `lab/lab.toml` and every `lab/scenarios/*.toml`, optionally resets lab VMs
to their Proxmox snapshot baseline, then drives `scripts/owrt-change.sh` to
apply each scenario's UCI batch with verification + automatic rollback, and
finally checks the post-conditions on the lab devices.

Python >= 3.11, stdlib only.

Scenarios may declare optional tables in `lab.toml`:
  [checks.<name>]   reusable probes (device, cmd, expect_rc, expect_stdout,
                    timeout=60, description)
  [steps.<name>]    reusable setup/cleanup actions (device, cmd, timeout=120,
                    description); must exit 0
  [regression]
  default = [...]   what `regression = "default"` in a scenario expands to

A scenario TOML may additionally declare:
  access     = "installed" | "no-install"   the access mode the scenario
                              exercises (ADR-021 point 1); default
                              "installed".  The mode is what the run
                              measured, not what it says: the runner
                              records the installed transport itself
                              when it drives owrt-change.sh, and the
                              no-install transport writes a receipt
                              line into the file the runner hands it
                              (NEWTON_LAB_RECEIPT).  A scenario whose
                              receipts say another mode than it
                              declared is refused, and so is a scenario
                              that used both transports, and a run that
                              mixes the modes.  The runner refuses a
                              scenario that declares one mode against
                              a device whose inventory says the other
                              before anything is touched.
  setup      = [step names]   run after reset + var resolution; first rc!=0
                              stops the scenario
  cleanup    = [step names]   run after the rest, in a try/finally once setup
                              has started
  regression = "default" | [check names]   default = lab.toml [regression].default
  breaks     = [check names]  checks expected to PASS before apply and FAIL
                              after a confirmed apply
  expect     = confirmed | rolled_back | rebooted_restored | rejected | refused | noop | none
                              rebooted_restored = the router rebooted inside the window and the
                              guard restored the config at boot (owrt-change.sh ends with an
                              ALERT, no ROLLBACK WINDOW PASSED); post checks run like rolled_back
                              refused = apply was rejected by the router
                              (token/role/etc); noop = plan ran but staged
                              nothing; none = audit scenario with no batch
  batch      = "..."          OPTIONAL; missing/empty implies expect = "none"
  reset_after = ["device", ...]  devices to reset again once the posts and
                              the cleanup have run, whatever the scenario
                              outcome was; same rules as `reset` (a defined
                              device, never `local`)
  after_reset = ["check", ...]  checks run, in order, right after the
                              `reset_after` resets finish OK; every entry
                              must name a [checks] check, and the scenario
                              must carry a `reset_after` to run them after
  probes     = [[fields, ...], ...]  sealed probe file the plan reads
                                     (TAB-joined; see design 4.3/4.6)
  approval   = true | "none" | "wrong"   plan-and-apply token: true = mint a
                                         real token from the lab passphrase;
                                         "none" = send no token; "wrong" =
                                         mint a real token then flip the last
                                         hex digit (router refuses it).
                                         "none" and "wrong" are for
                                         expect = "refused" scenarios.
  plan_match = "regex"        optional: the plan stdout+stderr must contain it
                              (scenarios that stage; not with expect = "rejected")
  reject_match = "regex"      REQUIRED when expect = "rejected" (forbidden
                              otherwise); re.search (MULTILINE) over plan
                              stdout+stderr pins WHY the plan was refused
  refuse_match = "regex"      REQUIRED when expect = "refused" (forbidden
                              otherwise); re.search (MULTILINE) over apply
                              stdout+stderr pins WHY the router refused the
                              apply; the runner calls owrt-change abort to
                              clean the session up.
  expect_password / breaks_password = same as expect / breaks but only in
                              the password lane (RD8: scenarios that change
                              shape between key and password auth).
  [[post]] / [[effect]]  each may carry `lanes = ["key"] | ["password"] |
                       ["key","password"]`; an entry whose lanes exclude the
                       active lane is skipped (not run, not counted).

Per-scenario run order:
  1. reset (Proxmox rollback; retried at most RESET_MAX_ATTEMPTS times,
      RESET_RETRY_SLEEP_S seconds apart, only when the rollback task's
      exitstatus contains PVE_LOCK_TEXT — the previous VM's `qm cleanup`
      holds the VM config lock for ~35 s — then ssh readiness; every
      attempt is a rec["reset"] record
      {device, upid, task_ok, exitstatus, attempt})
  2. resolve every {var} placeholder used in batch, probes, posts, effects,
     and the cmds of every check and step the scenario references
  3. setup steps in order; first rc!=0 -> ERROR, stop, run cleanup
  4. BEFORE probes:
        role "regression" / "breaks" / "effect" with want "pass"/"pass"/"fail"
        any failure -> ERROR; skip plan/apply/after/post; run cleanup
  5. plan/apply when a batch is present:
        plan rc != 0 and "no changes staged" in plan stdout+stderr -> noop
        plan rc != 0 and "staging rejected" (or a refused probe, or a staged firewall
                            that fails fw4 check) in plan stdout+stderr -> rejected
                            (then reject_match must match plan stdout+stderr)
        plan rc != 0 otherwise -> ERROR plan failed (rc=N): <tail>
        else apply + classify_apply (confirmed | rolled_back | rebooted_restored | unknown)
        no batch -> outcome "none"
  6. AFTER probes (depending on outcome):
        confirmed: regression NOT in breaks want pass;
                        breaks want fail; effects want pass
        other: regression and breaks want pass; effects want fail
  7. post checks
  8. cleanup (try/finally once step 3 has begun; failure here only sets
     rec["error"] if no earlier error exists)
  9. reset_after: the same reset_device() the scenario got at the start,
     per named device, in order (records land in rec["reset_after"]). It
     runs even when the scenario failed or errored after changes were
     applied; a failing reset_after fails the scenario (rec["passed"]
     False and rec["error"] set) without hiding an earlier error, and a
     physical post-restore fingerprint mismatch marks abort_run as it
     does at the start. A scenario that was refused before it contacted
     anything resets nothing.
 10. after_reset: the named checks, in order, once the resets in step 9
     have all finished OK (records land in rec["after_reset"], shaped
     like the regression records: role/name/device/cmd/rc/stdout/stderr/
     passed/want/ok/reason). None runs when a reset failed -- that already
     fails the scenario and a check would read a device that is not the
     baseline -- or when nothing was reset. A check that fails (rc or
     expect_stdout mismatch) fails the scenario: rec["passed"] False and
     rec["error"] set, never hiding an earlier error. This is the only
     place a check sees the state the reset_after left behind.

A [vars.NAME] table in lab.toml may set `secret = true`. The value is read
like any other var and substituted into the scenario `batch` only, which
travels to the wrapper in a 0600 temp file and then to the router over ssh
stdin (see plan_batch). It never reaches a record, a log line, the runner's
stdout or the results file: rec["vars"] carries the "<secret>" placeholder,
every other string in the record is masked once the scenario is done,
print_summary masks what it prints, and the serialized payload is masked
again before it is written. A scenario whose step, cleanup, post, effect or
check cmd names a secret var is refused before any device contact, because
those cmds travel in ssh argv. A var with `secret = false`, or with no
`secret` key, changes nothing.

A probe or post that times out is a normal failed result (rc None, reason
"timed out after Ns"); a step, plan or apply that times out is an ERROR.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import posixpath
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import urllib.parse
import zlib
from pathlib import Path
from typing import Any

if sys.version_info < (3, 11):
    sys.exit(f"{__file__}: requires Python 3.11+")

HERE = Path(__file__).resolve().parent
OWRT_CHANGE = HERE.parent / "scripts" / "owrt-change.sh"
DEFAULT_LAB = HERE / "lab.toml"
SCEN_DIR = HERE / "scenarios"
RESULTS_DIR = HERE / ".results"

MCP_DIR = HERE.parent / "mcp"
if str(MCP_DIR) not in sys.path:
    sys.path.insert(0, str(MCP_DIR))
from newton_mcp import approve  # noqa: E402
from newton_mcp import client_checks  # noqa: E402
from newton_mcp import explanation  # noqa: E402
from newton_mcp import probes as newton_probes  # noqa: E402
from newton_mcp import scans  # noqa: E402
from newton_mcp import tiers as newton_tiers  # noqa: E402
from newton_mcp import touched as newton_touched  # noqa: E402

PLACEHOLDER_RE = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")
SID_RE = re.compile(r"STAGED session=([0-9a-f]{32})")
APPROVAL_RE = re.compile(r"^APPROVAL (required|not-required)$", re.MULTILINE)
PLANDIGEST_RE = re.compile(r"^PLANDIGEST ([0-9a-f]{64})$", re.MULTILINE)
BASEHASH_RE = re.compile(r"^BASEHASH ([0-9a-f]{64})$", re.MULTILINE)
APPLYBASE_RE = re.compile(r"^APPLYBASE ([0-9a-f]{64})$", re.MULTILINE)
DIFF_BLOCK_RE = re.compile(
    r"^----- diff -----\n(.*?)^----------------\s*$",
    re.MULTILINE | re.DOTALL,
)
_SECTION_LINE_RE = re.compile(r"^SECTION (.+)$", re.MULTILINE)

MAX_LOG = 4000
MAX_POST = 2000

# md5 of empty input -- the helper rejects this digest so a router that
# returned an empty `uci export` cannot make the rollback check pass
# vacuously.
_EMPTY_MD5_DIGEST = "d41d8cd98f00b204e9800998ecf8427e"
_MD5_HEX_RE = re.compile(r"^[0-9a-f]{32}$")

PVE_LOCK_TEXT = "can't lock file"   # exitstatus of a rollback task that lost the VM config lock
RESET_MAX_ATTEMPTS = 4              # rollback attempts per device, in total
RESET_RETRY_SLEEP_S = 12            # pause between two attempts

# Proxmox curl retry: a 0.1 s PVE API outage made curl exit 7 once (the
# request was never sent), which took 15 scenarios down with it. Retry ONLY
# when curl exits 7, up to PVE_CURL_MAX_ATTEMPTS (4) tries, pausing
# PVE_CURL_RETRY_SLEEPS_S = [2, 5, 10] seconds between them. Any other non-zero
# exit (e.g. rc=28 timeout) raises at once. Each retry logs to stderr so an
# operator chasing a slow run sees it. The sleep is patchable via the module's
# `time.sleep`, which the test conftest already neutralises.
PVE_CURL_MAX_ATTEMPTS = 4            # 1 initial + 3 retries
PVE_CURL_RETRY_SLEEPS_S = (2, 5, 10) # pauses between consecutive attempts

VALID_EXPECT = {"confirmed", "rolled_back", "rebooted_restored", "rejected",
                "refused", "noop", "none"}
VALID_APPROVAL = (True, "none", "wrong")
LANES = ("key", "password")
# The two access modes of an OpenWrt router (ADR-021 point 1): the
# installed mode, where Newton's program and guard live on the router,
# and the no-install mode, where Newton uses the router's own web API.
ACCESS_MODES = ("installed", "no-install")

# The receipt of a run: the file the no-install transport writes its
# own lines into (one per rpcd call over HTTPS that got an answer).
# The runner exports the variable to every scenario command and reads
# the file after every scenario, so the mode of a run comes from what
# the scenarios exercised and not from what a scenario declared.
RECEIPT_ENV = "NEWTON_LAB_RECEIPT"
RPCD_RECEIPT_PREFIX = "rpcd "

# a lab device whose snapshot follows this naming rule is a Newton
# router installed by `newton-router-setup lab-snapshot`; only those get
# the hello preflight (lab-isp and lab-client do not speak the grammar).
NEWTON_SNAPSHOT_PREFIX = "baseline-newton-"
PREFLIGHT_STOP_TEXT = ("rebuild the snapshot: "
                       "newton-router-setup lab-r1 lab-snapshot")
ROUTER_PROG = "/usr/libexec/newton/newton-router"
PREFLIGHT_FILES = {
    "prog": "device/openwrt/newton-router/newton-router",
    "helper": "scripts/owrt-safe-apply.sh",
    "guard": "device/openwrt/newton-guard/newton-guard",
    "init": "device/openwrt/newton-guard/newton-guard.init",
}
PREFLIGHT_SHA_CACHE: dict[str, str] = {}

# Probe limits: the router's own (design 4.3).
MAX_PROBES = 32
MAX_PROBE_FIELD = 128
MAX_PROBES_BYTES = 4096

# subprocess wrapper used by every external call. Mocked in tests.
def _run(args: list[str], *, env=None, timeout: float | None = None,
         input: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(args, env=env, capture_output=True, text=True,
                          timeout=timeout, input=input)


def _run_stdin_file(args: list[str], path: str, *,
                    timeout: float | None = None) -> subprocess.CompletedProcess:
    """Like `_run`, but stdin is the (binary) file at `path`. Mocked in tests."""
    with open(path, "rb") as fh:
        return subprocess.run(args, stdin=fh, capture_output=True,
                              timeout=timeout)


def _local_env(lab: "Lab") -> dict[str, str]:
    """Env for local subprocesses; carries the SSH key/proxy so a local cmd
    can shell out to a router the same way `ssh_cmd` does."""
    env = os.environ.copy()
    env["LAB_SSH_KEY"] = lab.ssh_key
    env["LAB_SSH_PROXY"] = lab.ssh_proxy
    env["NEWTON_REPO"] = str(HERE.parent)
    env["OWRT_AUDIT_LOG"] = str(RESULTS_DIR / "audit.log")
    # The lab-client's user name.  A local cmd that ssh's the lab-client (the
    # dualwan helper) takes it from here, so no user name is written down in
    # the tree that ships; the lab file carries it.
    client = lab.devices.get("lab-client")
    env["LAB_CLIENT_USER"] = client.user if client is not None else ""
    return env


# ---------- runner directories on the lab host ----------

class DirSetupError(RuntimeError):
    """A directory the runner has to use cannot be created or is not ours to
    use. Raised before any result, record or backup is written there."""


def _ensure_private_dir(path: Path, what: str) -> None:
    """Create `path` with mode 0700, or heal an existing real directory we own
    to 0700. Every missing component along the way is laid down 0700 too, so a
    `parents=True` never leaves a 0775 behind.

    The runner hands RESULTS_DIR/backups to scripts/owrt-change.sh as
    OWRT_BACKUP_DIR, and owrt-change.sh refuses a backup directory whose parent
    is group- or world-writable without the sticky bit. The lab host runs with
    umask 0002, so a bare `mkdir(parents=True, exist_ok=True)` leaves both
    RESULTS_DIR and its backups dir 0775 and every plan from the runner fails
    before it starts. An existing directory is therefore tightened rather than
    refused -- the same heal rule owrt-change.sh applies to $STATE -- and a
    lab/.results an older runner left 0775 heals on the next run.

    A symlink is refused outright: we never chmod through one, and every result
    and every full `sysupgrade -b` backup (secrets) would follow it somewhere
    else. So is a directory another user owns, which we would be writing those
    secrets into. Both raise DirSetupError with a message an operator can act
    on."""
    missing: list[Path] = []
    probe = path
    while True:
        if probe.is_symlink():
            raise DirSetupError(
                f"{what} {probe} is a symlink; refusing to use it (a symlinked "
                f"results or backups directory would move every result and "
                f"every backup, and a chmod would land on the target): remove "
                f"it or point the runner somewhere else")
        if probe.is_dir():
            break
        missing.append(probe)
        parent = probe.parent
        if parent == probe:
            raise DirSetupError(
                f"{what} {path} cannot be created: no parent directory")
        probe = parent
    for d in reversed(missing):
        try:
            d.mkdir(mode=0o700)
        except OSError as e:
            raise DirSetupError(f"{what} {d} cannot be created: {e}") from None
    for d in [*missing, path]:
        st = d.stat()
        if st.st_uid != os.geteuid():
            raise DirSetupError(
                f"{what} {d} is owned by uid {st.st_uid} and this run is uid "
                f"{os.geteuid()}; refusing to write results or backups there "
                f"(point the runner at a directory of your own)")
        if st.st_mode & 0o777 != 0o700:
            os.chmod(d, 0o700)


def _ensure_results_dirs(results_path: Path) -> None:
    """RESULTS_DIR, its backups dir and the parent of `results_path` (the
    `--results` path, which defaults to a file inside RESULTS_DIR), each 0700.
    Idempotent, so the run-start call and the pre-write call do the same work
    twice and nothing else."""
    _ensure_private_dir(RESULTS_DIR, "RESULTS_DIR")
    _ensure_private_dir(RESULTS_DIR / "backups", "RESULTS_DIR/backups")
    _ensure_output_parent(results_path, "the results directory")


def _ensure_output_parent(path: Path, what: str) -> None:
    """The parent of an output file: 0700 rules only inside RESULTS_DIR. A
    --results path elsewhere (the operator's own dir, /tmp) is created if
    missing but never chmodded or refused."""
    parent = path.parent
    if parent == RESULTS_DIR or RESULTS_DIR in parent.parents:
        _ensure_private_dir(parent, f"{what} for {path}")
    else:
        parent.mkdir(parents=True, exist_ok=True)


# ---------- Data classes ----------

class LabConfigError(ValueError):
    """lab.toml is invalid; the message names the offending field."""


class Device:
    __slots__ = ("name", "vmid", "host", "user", "snapshot", "settle_cmd",
                 "kind", "proxy", "known_hosts", "admin_key",
                 "baseline_backup", "baseline_sha256", "router_key",
                 "lab", "board_name", "platform", "vendor_write")

    def __init__(self, name: str, vmid: int, host: str, user: str,
                 snapshot: str, settle_cmd: str = "", *,
                 kind: str = "vm", proxy: bool = True,
                 known_hosts: str = "", admin_key: str = "",
                 baseline_backup: str = "", baseline_sha256: str = "",
                 router_key: str = "", lab: bool = False,
                 board_name: str = "", platform: str = "",
                 vendor_write: bool = False) -> None:
        self.name = name
        self.vmid = vmid
        self.host = host
        self.user = user
        self.snapshot = snapshot
        self.settle_cmd = settle_cmd
        self.kind = kind
        self.proxy = proxy
        self.known_hosts = known_hosts
        self.admin_key = admin_key
        self.baseline_backup = baseline_backup
        self.baseline_sha256 = baseline_sha256
        self.router_key = router_key
        self.lab = lab
        self.board_name = board_name
        self.platform = platform
        self.vendor_write = vendor_write

    @property
    def is_physical(self) -> bool:
        return self.kind == "physical"

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "vmid": self.vmid, "host": self.host,
                "user": self.user, "snapshot": self.snapshot,
                "settle_cmd": self.settle_cmd}


class Lab:
    __slots__ = ("pve_host", "pve_node", "pve_token_file", "pve_pin_file",
                 "ssh_proxy", "ssh_password_file", "ssh_key",
                 "router_key", "approve_passphrase_file", "known_hosts",
                 "settle_quiet_s", "settle_timeout_s", "settle_poll_s",
                 "devices", "var_defs",
                 "checks", "steps", "regression_default")

    def __init__(self, *, pve_host: str, pve_node: str,
                 pve_token_file: str, pve_pin_file: str,
                 ssh_proxy: str, ssh_password_file: str, ssh_key: str,
                 devices: dict[str, Device],
                 var_defs: dict[str, dict[str, Any]],
                 settle_quiet_s: float = 10,
                 settle_timeout_s: float = 120,
                 settle_poll_s: float = 1,
                 checks: dict[str, "Check"] | None = None,
                 steps: dict[str, "Step"] | None = None,
                 regression_default: list[str] | None = None,
                 router_key: str = "",
                 approve_passphrase_file: str = "",
                 known_hosts: str = "") -> None:
        self.pve_host = pve_host
        self.pve_node = pve_node
        self.pve_token_file = pve_token_file
        self.pve_pin_file = pve_pin_file
        self.ssh_proxy = ssh_proxy
        self.ssh_password_file = ssh_password_file
        self.ssh_key = ssh_key
        self.router_key = router_key
        self.approve_passphrase_file = approve_passphrase_file
        self.known_hosts = known_hosts
        self.settle_quiet_s = settle_quiet_s
        self.settle_timeout_s = settle_timeout_s
        self.settle_poll_s = settle_poll_s
        self.devices = devices
        self.var_defs = var_defs
        self.checks = checks if checks is not None else {}
        self.steps = steps if steps is not None else {}
        self.regression_default = (
            list(regression_default) if regression_default is not None else [])


class Check:
    """Reusable probe declared in `[checks.<name>]` of lab.toml."""
    __slots__ = ("name", "device", "cmd", "expect_rc", "expect_stdout",
                 "timeout", "description")

    def __init__(self, *, name: str, device: str, cmd: str,
                 expect_rc: int = 0, expect_stdout: str | None = None,
                 timeout: int = 60, description: str = "") -> None:
        self.name = name
        self.device = device
        self.cmd = cmd
        self.expect_rc = expect_rc
        self.expect_stdout = expect_stdout
        self.timeout = timeout
        self.description = description


class Step:
    """Reusable setup/cleanup action declared in `[steps.<name>]` of lab.toml."""
    __slots__ = ("name", "device", "cmd", "timeout", "description")

    def __init__(self, *, name: str, device: str, cmd: str,
                 timeout: int = 120, description: str = "") -> None:
        self.name = name
        self.device = device
        self.cmd = cmd
        self.timeout = timeout
        self.description = description


class Post:
    __slots__ = ("device", "cmd", "expect_rc", "expect_stdout", "timeout",
                 "lanes")

    def __init__(self, device: str, cmd: str, expect_rc: int = 0,
                 expect_stdout: str | None = None, timeout: int = 60,
                 lanes: "tuple[str, ...] | None" = None) -> None:
        self.device = device
        self.cmd = cmd
        self.expect_rc = expect_rc
        self.expect_stdout = expect_stdout
        self.timeout = timeout
        self.lanes = tuple(LANES) if lanes is None else tuple(lanes)

    def runs_in_lane(self, lane: str) -> bool:
        return lane in self.lanes


class RunReceipts:
    """The receipt file of a run: the lines the no-install transport wrote.

    The runner hands the path to every scenario command (RECEIPT_ENV)
    and the transport appends one line per rpcd call over HTTPS that
    got an answer.  The runner reads the file after every scenario, so
    a scenario sees only the lines its own commands wrote.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.offset = 0

    def take(self) -> list[str]:
        """The lines written since the last call."""
        try:
            data = self.path.read_bytes()
        except OSError:
            return []
        chunk = data[self.offset:]
        cut = chunk.rfind(b"\n")
        if cut < 0:
            # a half-written line is not a receipt yet
            return []
        self.offset += cut + 1
        return [line.decode("utf-8", "replace").strip()
                for line in chunk[:cut + 1].splitlines() if line.strip()]


class AccessEvidence:
    """Which transport one scenario used.

    The runner drives the installed SSH change path itself, so it
    records that receipt itself; the no-install transport writes its
    own lines into the receipt file.  The mode of the scenario is what
    the two of them say.
    """

    def __init__(self) -> None:
        self.installed = False
        self.rpcd = False


# The evidence of the scenario that is running.  The runner runs one
# scenario at a time, so one slot is enough.
_EVIDENCE: "AccessEvidence | None" = None


def _note_installed_transport() -> None:
    """The installed transport ran: the runner drove owrt-change.sh."""
    if _EVIDENCE is not None:
        _EVIDENCE.installed = True


def derive_access_mode(installed: bool, rpcd: bool) -> tuple[str | None,
                                                             str | None]:
    """The mode a scenario's receipts describe, and the reason it has none.

    The installed transport alone means the installed mode, the rpcd
    transport alone the no-install mode, both of them are a mixed run
    that is refused, and neither of them means the scenario carries no
    access fact at all.
    """
    if installed and rpcd:
        return None, ("the scenario used both transports (the installed "
                      "SSH path and the rpcd web API); a scenario has one")
    if installed:
        return "installed", None
    if rpcd:
        return "no-install", None
    return None, None


class Scenario:
    __slots__ = ("name", "description", "target", "reset", "reset_after",
                 "after_reset", "expect",
                 "timeout", "probes", "approval", "batch", "post", "path",
                 "setup", "cleanup", "regression", "breaks", "effects",
                 "reject_match", "refuse_match", "plan_match", "expect_password",
                 "breaks_password",
                 "tier", "tier_values", "tier_batch_lines",
                 "tier_fail_probe", "tier_reboot", "client_checks",
                 "expect_failed_claim", "access")

    def __init__(self, *, name: str, description: str, target: str,
                 reset: list[str], expect: str, timeout: int,
                 batch: str, post: list[Post], path: Path,
                 reset_after: list[str] | None = None,
                 after_reset: list[str] | None = None,
                 setup: list[str] | None = None,
                 cleanup: list[str] | None = None,
                 regression: "str | list[str] | None" = None,
                 breaks: list[str] | None = None,
                 effects: list[Post] | None = None,
                 reject_match: str | None = None,
                 probes: "list[list[str]] | None" = None,
                 approval: "bool | str | None" = None,
                 refuse_match: str | None = None,
                 plan_match: str | None = None,
                 expect_password: str | None = None,
                 breaks_password: "list[str] | None" = None,
                 tier: "str | None" = None,
                 tier_values: "dict[str, str] | None" = None,
                 tier_batch_lines: "int | None" = None,
                 tier_fail_probe: "list[str] | None" = None,
                 tier_reboot: bool = True,
                 client_checks: "list[dict] | None" = None,
                 expect_failed_claim: str | None = None,
                 access: str = "installed") -> None:
        self.name = name
        self.description = description
        self.target = target
        self.access = access
        self.reset = reset
        self.reset_after = list(reset_after) if reset_after else []
        self.after_reset = list(after_reset) if after_reset else []
        self.expect = expect
        self.timeout = timeout
        self.probes = list(probes) if probes else []
        self.approval = approval
        self.batch = batch
        self.post = post
        self.path = path
        self.setup = list(setup) if setup else []
        self.cleanup = list(cleanup) if cleanup else []
        self.regression = regression
        self.breaks = list(breaks) if breaks else []
        self.effects = list(effects) if effects else []
        self.reject_match = reject_match
        self.refuse_match = refuse_match
        self.plan_match = plan_match
        self.expect_password = expect_password
        self.breaks_password = (list(breaks_password)
                                if breaks_password else None)
        self.tier = tier
        self.tier_values = (dict(tier_values)
                            if tier_values is not None else None)
        self.tier_batch_lines = tier_batch_lines
        self.tier_fail_probe = (list(tier_fail_probe)
                                if tier_fail_probe is not None else None)
        self.tier_reboot = bool(tier_reboot)
        self.client_checks = list(client_checks) if client_checks else []
        self.expect_failed_claim = expect_failed_claim

    def effective_expect(self, lane: str) -> str:
        if lane == "password" and self.expect_password is not None:
            return self.expect_password
        return self.expect

    def effective_breaks(self, lane: str) -> list[str]:
        if lane == "password" and self.breaks_password is not None:
            return list(self.breaks_password)
        return list(self.breaks)


# ---------- Loading ----------

def _expand(p: str) -> str:
    # os.path.expanduser only honours a leading "~". For ssh ProxyCommand strings
    # like `ssh -i ~/.ssh/key`, expand each whitespace-separated token instead.
    if "~" not in p:
        return p
    return " ".join(os.path.expanduser(t) for t in p.split())


PHYSICAL_ONLY_FIELDS = ("proxy", "known_hosts", "admin_key",
                        "baseline_backup", "baseline_sha256", "router_key",
                        "lab", "board_name")
PHYSICAL_REQUIRED = ("host", "user", "proxy", "lab", "board_name",
                     "known_hosts", "admin_key", "baseline_backup", "baseline_sha256")
# A vendor device (a VM that speaks a vendor platform) may name its own
# known_hosts file and its own admin key: it is not an OpenWrt router, so
# the lab's [ssh] router_key is not its key.  The files are not required to
# exist here: the vendor driver checks them and says which one is missing.
VENDOR_DEVICE_FIELDS = ("known_hosts", "admin_key")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _vendor_path(name: str, dev: dict, field: str) -> str:
    """A vendor device's own path: a string, expanded, absolute.

    The file itself is not required to exist: the run that needs it (the
    vendor driver) checks it and refuses with a message that names it.
    """
    raw = dev.get(field, "")
    if raw is None:
        raw = ""
    if not isinstance(raw, str):
        raise LabConfigError(f"devices.{name}.{field}: must be a string")
    path = os.path.expanduser(raw)
    if not path:
        return ""
    if not os.path.isabs(path):
        raise LabConfigError(
            f"devices.{name}.{field}: must be an absolute path, got {raw!r}")
    return path


def _physical_path(name: str, dev: dict, field: str) -> str:
    raw = str(dev[field])
    path = os.path.expanduser(raw)
    if not os.path.isabs(path):
        raise LabConfigError(
            f"devices.{name}.{field}: must be an absolute path, got {raw!r}")
    if not os.path.isfile(path):
        raise LabConfigError(
            f"devices.{name}.{field}: no such file: {path}")
    return path


def _vendor_fields(name: str, dev: dict) -> tuple[str, bool]:
    """The optional vendor fields of a device table.

    A VM that is a vendor device says which platform it speaks and that
    it may write.  Both are optional: an OpenWrt device leaves them out
    and keeps the behaviour it had.
    """
    platform = dev.get("platform", "")
    if platform is None:
        platform = ""
    if not isinstance(platform, str):
        raise LabConfigError(f"devices.{name}.platform: must be a string")
    vendor_write = dev.get("vendor_write", False)
    if not isinstance(vendor_write, bool):
        raise LabConfigError(
            f"devices.{name}.vendor_write: must be true or false")
    return platform, vendor_write


def _load_device_with_kind(name: str, dev: dict) -> Device:
    """A device table that sets `kind`: "vm" (the Proxmox snapshot kind) or
    "physical" (restored from a sysupgrade archive)."""
    kind = dev.get("kind")
    if kind not in ("vm", "physical"):
        raise LabConfigError(
            f"devices.{name}.kind: must be \"vm\" or \"physical\", "
            f"got {kind!r}")
    if kind == "vm":
        platform, vendor_write = _vendor_fields(name, dev)
        for f in PHYSICAL_ONLY_FIELDS:
            if f not in dev:
                continue
            if f in VENDOR_DEVICE_FIELDS and platform:
                # a vendor device may name its own known_hosts file and its
                # own admin key
                continue
            raise LabConfigError(
                f"devices.{name}.{f}: only valid for kind = \"physical\"")
        for f in ("vmid", "host", "user", "snapshot"):
            if f not in dev:
                raise LabConfigError(f"devices.{name}.{f}: missing")
        return Device(name=name, vmid=int(dev["vmid"]), host=str(dev["host"]),
                      user=str(dev["user"]), snapshot=str(dev["snapshot"]),
                      settle_cmd=str(dev.get("settle_cmd", "")),
                      platform=platform, vendor_write=vendor_write,
                      known_hosts=_vendor_path(name, dev, "known_hosts"),
                      admin_key=_vendor_path(name, dev, "admin_key"))
    for f in ("vmid", "snapshot"):
        if f in dev:
            raise LabConfigError(
                f"devices.{name}.{f}: not valid for kind = \"physical\" "
                f"(a device is either a VM or physical, never both)")
    for f in ("platform", "vendor_write"):
        if f in dev:
            raise LabConfigError(
                f"devices.{name}.{f}: not valid for kind = \"physical\" "
                f"(a physical device is an OpenWrt router)")
    for f in PHYSICAL_REQUIRED:
        if f not in dev:
            raise LabConfigError(f"devices.{name}.{f}: missing")
    if dev["proxy"] is not False:
        raise LabConfigError(
            f"devices.{name}.proxy: must be false (a physical device is "
            f"reached directly)")
    if dev["lab"] is not True:
        raise LabConfigError(
            f"devices.{name}.lab: must be true (the operator's statement "
            f"that this physical device is a lab router; the runner wipes "
            f"and restores it)")
    board_name = dev["board_name"]
    if (not isinstance(board_name, str) or not board_name
            or board_name != board_name.strip() or "\n" in board_name):
        raise LabConfigError(
            f"devices.{name}.board_name: must be a non-empty one-line "
            f"string (the router's /tmp/sysinfo/board_name)")
    sha = str(dev["baseline_sha256"]).lower()
    if not _SHA256_RE.match(sha):
        raise LabConfigError(
            f"devices.{name}.baseline_sha256: not a 64-hex sha256")
    known_hosts = _physical_path(name, dev, "known_hosts")
    admin_key = _physical_path(name, dev, "admin_key")
    backup = _physical_path(name, dev, "baseline_backup")
    router_key = (_physical_path(name, dev, "router_key")
                  if "router_key" in dev else "")
    actual = hashlib.sha256(Path(backup).read_bytes()).hexdigest()
    if actual != sha:
        raise LabConfigError(
            f"devices.{name}.baseline_sha256: {backup} hashes to "
            f"{actual}, not the configured value")
    try:
        validate_baseline_archive(backup, name)
    except ArchiveError as e:
        raise LabConfigError(f"devices.{name}.baseline_backup: {e}") from None
    return Device(name=name, vmid=0, host=str(dev["host"]),
                  user=str(dev["user"]), snapshot="",
                  settle_cmd=str(dev.get("settle_cmd", "")), kind="physical",
                  proxy=False, known_hosts=known_hosts, admin_key=admin_key,
                  baseline_backup=backup, baseline_sha256=sha,
                  router_key=router_key, lab=True, board_name=board_name)


def load_lab(path: Path) -> Lab:
    data = tomllib.loads(path.read_text())
    pve = data["pve"]
    ssh = data["ssh"]
    settle = data.get("settle", {})
    devs: dict[str, Device] = {}
    for name, dev in data.get("devices", {}).items():
        if "kind" in dev:
            devs[name] = _load_device_with_kind(name, dev)
            continue
        platform, vendor_write = _vendor_fields(name, dev)
        for f in PHYSICAL_ONLY_FIELDS:
            if f not in dev:
                continue
            if f in VENDOR_DEVICE_FIELDS and platform:
                # a vendor device may name its own known_hosts file and its
                # own admin key
                continue
            raise LabConfigError(
                f"devices.{name}.{f}: only valid for kind = \"physical\"")
        devs[name] = Device(
            name=name,
            vmid=int(dev["vmid"]),
            host=str(dev["host"]),
            user=str(dev["user"]),
            snapshot=str(dev["snapshot"]),
            settle_cmd=str(dev.get("settle_cmd", "")),
            platform=platform,
            vendor_write=vendor_write,
            known_hosts=_vendor_path(name, dev, "known_hosts"),
            admin_key=_vendor_path(name, dev, "admin_key"),
        )
    checks: dict[str, Check] = {}
    for name, c in data.get("checks", {}).items():
        checks[name] = Check(
            name=name,
            device=str(c["device"]),
            cmd=str(c["cmd"]),
            expect_rc=int(c.get("expect_rc", 0)),
            expect_stdout=c.get("expect_stdout"),
            timeout=int(c.get("timeout", 60)),
            description=str(c.get("description", "")),
        )
    steps: dict[str, Step] = {}
    for name, s in data.get("steps", {}).items():
        steps[name] = Step(
            name=name,
            device=str(s["device"]),
            cmd=str(s["cmd"]),
            timeout=int(s.get("timeout", 120)),
            description=str(s.get("description", "")),
        )
    reg_default: list[str] = list(
        data.get("regression", {}).get("default", []))
    var_defs: dict[str, dict[str, Any]] = {}
    for vname, v in data.get("vars", {}).items():
        secret = v.get("secret", False)
        if not isinstance(secret, bool):
            raise LabConfigError(
                f"vars.{vname}.secret: must be true or false, got {secret!r}")
        var_defs[vname] = {"device": str(v["device"]), "cmd": str(v["cmd"]),
                           "secret": secret}
    return Lab(
        pve_host=str(pve["host"]),
        pve_node=str(pve["node"]),
        pve_token_file=_expand(str(pve["token_file"])),
        pve_pin_file=_expand(str(pve["pin_file"])),
        ssh_proxy=_expand(str(ssh["proxy"])),
        ssh_password_file=_expand(str(ssh["password_file"])),
        ssh_key=_expand(str(ssh["key"])),
        router_key=_expand(str(ssh.get("router_key", ""))),
        approve_passphrase_file=_expand(str(ssh.get("approve_passphrase_file", ""))),
        known_hosts=_expand(str(ssh.get("known_hosts", ""))),
        devices=devs,
        var_defs=var_defs,
        settle_quiet_s=float(settle.get("quiet_s", 10)),
        settle_timeout_s=float(settle.get("timeout_s", 120)),
        settle_poll_s=float(settle.get("poll_s", 1)),
        checks=checks,
        steps=steps,
        regression_default=reg_default,
    )


def _parse_lanes(path: Path, table: dict, what: str) -> tuple[str, ...]:
    lanes = table.get("lanes")
    if lanes is None:
        return tuple(LANES)
    if (not isinstance(lanes, list) or not lanes
            or any(l not in LANES for l in lanes)):
        raise ValueError(
            f"{path.name}: {what} lanes must be a non-empty list drawn "
            f"from {list(LANES)}")
    return tuple(lanes)


def _parse_probes(path: Path, raw: Any) -> list[list[str]]:
    where = f"{path.name}: probes"
    if not isinstance(raw, list):
        raise ValueError(f"{where} must be a list of probe lists")
    if len(raw) > MAX_PROBES:
        raise ValueError(
            f"{where} has {len(raw)} probe lists, at most {MAX_PROBES} allowed")
    out: list[list[str]] = []
    size = 0
    for i, probe in enumerate(raw):
        if not isinstance(probe, list) or not probe:
            raise ValueError(
                f"{where}[{i}] must be a non-empty list of strings")
        fields: list[str] = []
        for field in probe:
            if not isinstance(field, str):
                raise ValueError(
                    f"{where}[{i}] fields must be strings, got "
                    f"{type(field).__name__}")
            b = field.encode("ascii", errors="strict") if field.isascii() else None
            if (b is None or not (1 <= len(b) <= MAX_PROBE_FIELD)
                    or any(not (0x20 <= c <= 0x7E) or c in (0x5C, 0x09)
                           for c in b)):
                raise ValueError(
                    f"{where}[{i}] has a field that is not 1..{MAX_PROBE_FIELD} "
                    f"printable ASCII bytes without backslash or TAB: "
                    f"{field!r}")
            fields.append(field)
        out.append(fields)
        size += sum(len(f.encode("ascii")) for f in fields) + len(fields) - 1 + 1
    if size > MAX_PROBES_BYTES:
        raise ValueError(
            f"{where} would be {size} bytes on the wire, at most "
            f"{MAX_PROBES_BYTES} allowed")
    return out


def _parse_approval(path: Path, raw: Any) -> "bool | str | None":
    if raw is None:
        return None
    if raw is True or raw in ("none", "wrong"):
        return raw
    raise ValueError(
        f"{path.name}: approval must be true, \"none\" or \"wrong\", "
        f"got {raw!r}")


def _parse_check_names(path: Path, raw: Any, what: str) -> list[str]:
    """A list of [checks] names. A bare string is refused rather than read as
    one name: `regression` may be "default", `after_reset` never is."""
    if not isinstance(raw, list):
        raise ValueError(
            f"{path.name}: {what} must be a list of check names, got "
            f"{type(raw).__name__}")
    out: list[str] = []
    for i, name in enumerate(raw):
        if not isinstance(name, str):
            raise ValueError(
                f"{path.name}: {what}[{i}] must be a string, got "
                f"{type(name).__name__}")
        out.append(name)
    return out


def _parse_tier_values(path: Path, raw: Any) -> dict[str, str]:
    """A table str -> str; both keys and values must be strings."""
    if not isinstance(raw, dict):
        raise ValueError(
            f"{path.name}: tier_values must be a table of str -> str")
    out: dict[str, str] = {}
    for k, v in raw.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise ValueError(
                f"{path.name}: tier_values entries must be str -> str")
        out[k] = v
    return out


def _parse_tier_fail_probe(path: Path, raw: Any) -> list[str]:
    """A single probe: a non-empty list of strings (one probe line)."""
    if not isinstance(raw, list) or not raw:
        raise ValueError(
            f"{path.name}: tier_fail_probe must be a non-empty list of"
            f" strings")
    for i, field in enumerate(raw):
        if not isinstance(field, str):
            raise ValueError(
                f"{path.name}: tier_fail_probe[{i}] must be a string")
    return [str(f) for f in raw]


def _parse_client_checks(path: Path, raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        raise ValueError(f"{path.name}: client_checks must be an array of tables")
    out: list[dict[str, Any]] = []
    for index, entry in enumerate(raw):
        if not isinstance(entry, dict):
            raise ValueError(
                f"{path.name}: client_checks[{index}] must be a table")
        out.append(dict(entry))
    return out


def load_scenarios(directory: Path) -> list[Scenario]:
    out: list[Scenario] = []
    for path in sorted(directory.glob("*.toml")):
        data = tomllib.loads(path.read_text())
        if "check" in data:
            raise ValueError(
                f"{path.name}: check was replaced by probes; see design 4.6")
        posts: list[Post] = []
        for p in data.get("post", []):
            posts.append(Post(
                device=str(p["device"]),
                cmd=str(p["cmd"]),
                expect_rc=int(p.get("expect_rc", 0)),
                expect_stdout=p.get("expect_stdout"),
                timeout=int(p.get("timeout", 60)),
                lanes=_parse_lanes(path, p, "[[post]]"),
            ))
        effects: list[Post] = []
        for e in data.get("effect", []):
            effects.append(Post(
                device=str(e["device"]),
                cmd=str(e["cmd"]),
                expect_rc=int(e.get("expect_rc", 0)),
                expect_stdout=e.get("expect_stdout"),
                timeout=int(e.get("timeout", 60)),
                lanes=_parse_lanes(path, e, "[[effect]]"),
            ))
        reg_raw = data.get("regression")
        if reg_raw is None:
            regression: "str | list[str] | None" = None
        elif isinstance(reg_raw, str):
            regression = reg_raw
        else:
            regression = [str(x) for x in reg_raw]
        out.append(Scenario(
            name=str(data["name"]),
            description=str(data.get("description", "")),
            target=str(data.get("target", "")),
            reset=list(data.get("reset", [])),
            reset_after=[str(x) for x in data.get("reset_after", [])],
            after_reset=(_parse_check_names(path, data["after_reset"],
                                            "after_reset")
                         if "after_reset" in data else []),
            expect=str(data["expect"]),
            timeout=int(data.get("timeout", 90)),
            probes=_parse_probes(path, data.get("probes", [])) if "probes" in data else [],
            approval=_parse_approval(path, data.get("approval")),
            batch=str(data.get("batch", "")),
            post=posts,
            path=path,
            setup=list(data.get("setup", [])),
            cleanup=list(data.get("cleanup", [])),
            regression=regression,
            breaks=list(data.get("breaks", [])),
            effects=effects,
            reject_match=(None if "reject_match" not in data
                          else str(data["reject_match"])),
            refuse_match=(None if "refuse_match" not in data
                          else str(data["refuse_match"])),
            plan_match=(None if "plan_match" not in data
                        else str(data["plan_match"])),
            expect_password=(None if "expect_password" not in data
                             else str(data["expect_password"])),
            breaks_password=(None if "breaks_password" not in data
                             else [str(x) for x in data["breaks_password"]]),
            tier=(None if "tier" not in data else str(data["tier"])),
            tier_values=(None if "tier_values" not in data
                         else _parse_tier_values(path, data["tier_values"])),
            tier_batch_lines=(None if "tier_batch_lines" not in data
                              else int(data["tier_batch_lines"])),
            tier_fail_probe=(None if "tier_fail_probe" not in data
                             else _parse_tier_fail_probe(
                                 path, data["tier_fail_probe"])),
            tier_reboot=(bool(data["tier_reboot"])
                         if "tier_reboot" in data else True),
            client_checks=_parse_client_checks(
                path, data.get("client_checks", [])),
            expect_failed_claim=(None if "expect_failed_claim" not in data
                                 else str(data["expect_failed_claim"])),
            access=str(data.get("access", "installed")),
        ))
    return out


# ---------- Validation ----------

def _resolved_regression(scen: Scenario, lab: Lab) -> list[str]:
    """Expand `regression` into a concrete list of check names."""
    reg = scen.regression
    if reg is None:
        return []
    if isinstance(reg, str):
        if reg == "default":
            return list(lab.regression_default)
        return []  # unknown string; validate_scenarios will error
    return list(reg)


def _is_local_or_device(lab: Lab, name: str) -> bool:
    """A probe/step/post/effect device is 'local' or a defined [devices] name."""
    return name == "local" or name in lab.devices


def validate_scenarios(lab: Lab, scenarios: list[Scenario]) -> list[str]:
    """Return one human-readable error string per problem (empty list = valid).
    Each error names the scenario file it belongs to."""
    errors: list[str] = []
    for scen in scenarios:
        path = scen.path
        name = path.name
        # expect value
        if scen.expect not in VALID_EXPECT:
            errors.append(
                f"{name}: expect {scen.expect!r} is not one of "
                f"{sorted(VALID_EXPECT)}")
        if scen.access not in ACCESS_MODES:
            errors.append(
                f"{name}: access {scen.access!r} is not one of "
                f"{sorted(ACCESS_MODES)}")
        if scen.expect_password is not None and scen.expect_password not in VALID_EXPECT:
            errors.append(
                f"{name}: expect_password {scen.expect_password!r} is not one "
                f"of {sorted(VALID_EXPECT)}")
        if scen.client_checks:
            try:
                explanation.Explanation.model_validate({
                    "intent": "lab",
                    "steps": ["lab"],
                    "expect": scen.client_checks,
                    "risk": "lab",
                })
            except ValueError:
                errors.append(
                    f"{name}: client_checks do not form valid client claims")
            else:
                for index, claim in enumerate(scen.client_checks, start=1):
                    if not client_checks.is_client_claim(claim):
                        errors.append(
                            f"{name}: client_checks claim {index} is not a "
                            "client claim")
                    elif (claim.get("kind") == "client_blocked"
                          and not claim.get("targets")):
                        errors.append(
                            f"{name}: client_checks claim {index} must carry "
                            "targets")
            if scen.timeout < client_checks.MIN_TIMEOUT_S:
                errors.append(
                    f"{name}: client_checks need timeout >= "
                    f"{client_checks.MIN_TIMEOUT_S}, got {scen.timeout}")
            if scen.target != "lab-r1":
                errors.append(
                    f"{name}: client_checks require target lab-r1, got "
                    f"{scen.target!r}")
            if scen.tier is not None:
                errors.append(
                    f"{name}: client_checks cannot be used with tier "
                    f"{scen.tier!r}")
        if scen.expect_failed_claim is not None:
            if scen.expect != "rolled_back":
                errors.append(
                    f"{name}: expect_failed_claim is only allowed when "
                    "expect = 'rolled_back'")
            try:
                re.compile(scen.expect_failed_claim)
            except re.error as exc:
                errors.append(
                    f"{name}: expect_failed_claim is not a valid regex: {exc}")
        # setup / cleanup -> [steps]
        for s in scen.setup:
            if s not in lab.steps:
                errors.append(
                    f"{name}: setup step {s!r} not defined in [steps]")
        for s in scen.cleanup:
            if s not in lab.steps:
                errors.append(
                    f"{name}: cleanup step {s!r} not defined in [steps]")
        # regression -> [checks] (or [regression].default)
        reg = scen.regression
        if isinstance(reg, str) and reg != "default":
            errors.append(
                f"{name}: regression {reg!r} is not 'default' or a list")
            reg_list: list[str] = []
        elif isinstance(reg, str) and reg == "default":
            if not lab.regression_default:
                errors.append(
                    f"{name}: regression = 'default' but [regression].default "
                    f"is not set in lab.toml")
            reg_list = list(lab.regression_default)
        else:
            reg_list = list(reg) if reg else []
        for c in reg_list:
            if c not in lab.checks:
                errors.append(
                    f"{name}: regression check {c!r} not defined in [checks]")
        # breaks -> [checks]
        for c in scen.breaks:
            if c not in lab.checks:
                errors.append(
                    f"{name}: breaks check {c!r} not defined in [checks]")
        for c in scen.breaks_password or ():
            if c not in lab.checks:
                errors.append(
                    f"{name}: breaks_password check {c!r} not defined in [checks]")
        # reset -> [devices]; 'local' is NOT a valid reset target.
        for d in scen.reset:
            if d not in lab.devices:
                errors.append(
                    f"{name}: reset device {d!r} is not a defined device")
        # reset_after -> [devices], the same rules as reset.
        for d in scen.reset_after:
            if d not in lab.devices:
                errors.append(
                    f"{name}: reset_after device {d!r} is not a defined "
                    f"device")
        # after_reset -> [checks], and only with a reset_after to run after.
        for c in scen.after_reset:
            if c not in lab.checks:
                errors.append(
                    f"{name}: after_reset check {c!r} not defined in [checks]")
        if scen.after_reset and not scen.reset_after:
            errors.append(
                f"{name}: after_reset {scen.after_reset!r} needs a "
                f"reset_after to run after; without one there is no reset to "
                f"check")
        # a secret var may only reach the batch
        errors.extend(secret_scope_violations(lab, scen))
        # effect device -> 'local' or [devices]
        for i, e in enumerate(scen.effects):
            if not _is_local_or_device(lab, e.device):
                errors.append(
                    f"{name}: [[effect]] #{i} device '{e.device}' is not "
                    f"'local' or a defined device")
        # post device -> 'local' or [devices]
        for i, p in enumerate(scen.post):
            if not _is_local_or_device(lab, p.device):
                errors.append(
                    f"{name}: [[post]] #{i} device '{p.device}' is not "
                    f"'local' or a defined device")
        # referenced checks (regression + breaks + after_reset): device must be
        # 'local' or in [devices]; only check names that exist in lab.toml.
        for c in reg_list + scen.breaks + scen.after_reset:
            if c in lab.checks and not _is_local_or_device(lab, lab.checks[c].device):
                errors.append(
                    f"{name}: check {c!r} (from lab.toml) has unknown "
                    f"device '{lab.checks[c].device}'")
        # referenced steps (setup + cleanup): device must be 'local' or in
        # [devices]; only check names that exist in lab.toml.
        for s in scen.setup + scen.cleanup:
            if s in lab.steps and not _is_local_or_device(lab, lab.steps[s].device):
                errors.append(
                    f"{name}: step {s!r} (from lab.toml) has unknown "
                    f"device '{lab.steps[s].device}'")
        # batch <-> expect
        has_batch = bool(scen.batch.strip())
        if not has_batch and scen.expect != "none" and scen.tier is None:
            errors.append(
                f"{name}: batch is empty/missing but expect is "
                f"{scen.expect!r}, not 'none'")
        if has_batch and scen.expect == "none":
            errors.append(
                f"{name}: batch is present but expect is 'none'")
        # target in [devices] when a batch is present
        if has_batch and scen.target not in lab.devices:
            errors.append(
                f"{name}: target {scen.target!r} is not a defined device")
        # reject_match rules
        rm = scen.reject_match
        if scen.expect == "rejected":
            if rm is None or not rm.strip():
                errors.append(
                    f"{name}: expect = 'rejected' requires reject_match "
                    f"(a regex that the plan stdout+stderr must contain)")
            else:
                try:
                    re.compile(rm)
                except re.error as e:
                    errors.append(
                        f"{name}: reject_match is not a valid regex: {e}")
        elif rm is not None:
            errors.append(
                f"{name}: reject_match is only allowed when expect = 'rejected'")
        # plan_match: a regex the plan stdout+stderr must contain, for plans that stage
        pm = scen.plan_match
        if pm is not None:
            if scen.expect in ("rejected", "none"):
                errors.append(
                    f"{name}: plan_match needs a plan that stages "
                    f"(not expect = {scen.expect!r}); use reject_match")
            try:
                re.compile(pm)
            except re.error as e:
                errors.append(f"{name}: plan_match is not a valid regex: {e}")
        # refuse_match rules (same shape as reject_match, for expect = 'refused')
        fm = scen.refuse_match
        if scen.expect == "refused":
            if fm is None or not fm.strip():
                errors.append(
                    f"{name}: expect = 'refused' requires refuse_match "
                    f"(a regex that the apply stdout+stderr must contain)")
            else:
                try:
                    re.compile(fm)
                except re.error as e:
                    errors.append(
                        f"{name}: refuse_match is not a valid regex: {e}")
        elif fm is not None:
            errors.append(
                f"{name}: refuse_match is only allowed when expect = 'refused'")
        # tier scenario rules: empty batch, expect = 'confirmed', target in
        # [devices], tier name in TIER_NAMES, tier_batch_lines >= 1.
        if scen.tier is not None:
            if scen.tier not in newton_tiers.TIER_NAMES:
                errors.append(
                    f"{name}: tier {scen.tier!r} is not one of "
                    f"{list(newton_tiers.TIER_NAMES)}")
            if has_batch:
                errors.append(
                    f"{name}: tier scenarios must have an empty batch")
            if scen.expect != "confirmed":
                errors.append(
                    f"{name}: tier scenarios require expect = 'confirmed', "
                    f"got {scen.expect!r}")
            if scen.target not in lab.devices:
                errors.append(
                    f"{name}: tier target {scen.target!r} is not a defined"
                    f" device")
            if (scen.tier_batch_lines is not None
                    and scen.tier_batch_lines < 1):
                errors.append(
                    f"{name}: tier_batch_lines must be >= 1, "
                    f"got {scen.tier_batch_lines}")
    return errors


# ---------- Var resolution ----------

def used_placeholders(*texts: str) -> set[str]:
    used: set[str] = set()
    for t in texts:
        used.update(PLACEHOLDER_RE.findall(t))
    return used


def substitute(text: str, values: dict[str, str]) -> str:
    def repl(m: re.Match[str]) -> str:
        return values.get(m.group(1), m.group(0))
    return PLACEHOLDER_RE.sub(repl, text)


def resolve_vars(lab: Lab, used: set[str]) -> tuple[dict[str, str], str | None]:
    values: dict[str, str] = {}
    for name in sorted(used):
        spec = lab.var_defs.get(name)
        if spec is None:
            return {}, f"unknown var: {name}"
        device_name = spec["device"]
        cmd = spec["cmd"]
        if device_name == "local":
            proc = _run(["bash", "-c", cmd], env=_local_env(lab), timeout=30)
        elif device_name in lab.devices:
            dev = lab.devices[device_name]
            proc = _run(ssh_cmd(lab, dev, cmd), timeout=30)
        else:
            return {}, f"unknown device for var {name}: {device_name}"
        if proc.returncode != 0:
            return {}, f"var {name} cmd failed (rc={proc.returncode}): {proc.stderr.strip()[:200]}"
        values[name] = proc.stdout.strip()
    return values, None


# ---------- Secret vars ----------

# What rec["vars"] holds for a secret var: the name says there was a value, the
# value itself is not recorded anywhere.
SECRET_PLACEHOLDER = "<secret>"
SECRET_MASK = "***"
# Every secret value this process has resolved, for the masking passes. A
# single runner process resolves vars for the scenarios it runs and then
# writes one results file, so a module-level set is the whole lifetime of a
# secret here; an empty value is never registered (masking "" would replace
# every character).
SECRET_VALUES: set[str] = set()


def register_secret(value: str) -> None:
    """Remember a resolved secret value so it can be masked out of every
    record, every printed line and the results file."""
    if value:
        SECRET_VALUES.add(value)


def secret_var_names(lab: Lab) -> set[str]:
    return {n for n, spec in lab.var_defs.items() if spec.get("secret")}


def mask_text(text: str) -> str:
    """Every resolved secret value in `text` replaced with SECRET_MASK.
    Longest first, so a secret that contains another is replaced whole."""
    for value in sorted(SECRET_VALUES, key=len, reverse=True):
        text = text.replace(value, SECRET_MASK)
    return text


def mask_payload_text(text: str) -> str:
    """The write-time pass: the serialized results payload with every resolved
    secret value replaced. Belt and braces for anything a record missed."""
    return mask_text(text)


def mask_record(obj: Any) -> Any:
    """`obj` with every string in it masked (dicts, lists and tuples walked,
    other values untouched)."""
    if isinstance(obj, str):
        return mask_text(obj)
    if isinstance(obj, dict):
        return {k: mask_record(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [mask_record(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(mask_record(v) for v in obj)
    return obj


def secret_scope_violations(lab: Lab, scen: Scenario,
                            lane: str | None = None) -> list[str]:
    """Every reference to a secret var from outside the scenario batch.

    The batch reaches the router in a 0600 temp file whose PATH is what argv
    carries (plan_batch below), and owrt-change.sh pipes that file to
    `newton-router stage` over ssh stdin. A step, cleanup, post, effect or
    check cmd travels in ssh argv instead, where it is readable from
    /proc/<pid>/cmdline for as long as the process lives, and its output is
    recorded verbatim. So a secret var may be substituted into the batch
    only, and a scenario that names one from any other cmd is refused before
    it contacts a device. That covers an `after_reset` check too: it runs
    from run_scenario's finally, long after step 0.

    `lane` None (validate_scenarios, which runs before a lane is chosen) sees
    every post and effect; a run sees only the ones its lane runs. A
    scenario's own `probes` are not cmds: they travel in the sealed 0600
    probe file and are never recorded.
    """
    secrets = secret_var_names(lab)
    if not secrets:
        return []
    out: list[str] = []
    name = scen.path.name
    breaks = list(scen.breaks) if lane is None else scen.effective_breaks(lane)

    def scan(where: str, cmd: str) -> None:
        for var in sorted(used_placeholders(cmd) & secrets):
            out.append(
                f"{name}: {where} references secret var {var!r}; a secret "
                f"var may be used in the scenario batch only (that cmd "
                f"travels in ssh argv, where the value would be readable in "
                f"/proc/<pid>/cmdline)")

    for sn in scen.setup:
        if sn in lab.steps:
            scan(f"setup step {sn!r}", lab.steps[sn].cmd)
    for sn in scen.cleanup:
        if sn in lab.steps:
            scan(f"cleanup step {sn!r}", lab.steps[sn].cmd)
    for i, p in enumerate(scen.post):
        if lane is None or p.runs_in_lane(lane):
            scan(f"[[post]] #{i}", p.cmd)
    for i, e in enumerate(scen.effects):
        if lane is None or e.runs_in_lane(lane):
            scan(f"[[effect]] #{i}", e.cmd)
    for cn in _resolved_regression(scen, lab) + breaks:
        if cn in lab.checks:
            scan(f"check {cn!r}", lab.checks[cn].cmd)
    for cn in scen.after_reset:
        if cn in lab.checks:
            scan(f"after_reset check {cn!r}", lab.checks[cn].cmd)
    return out


# ---------- SSH / shell helpers ----------

def _physical_ssh(dev: Device, key: str, cmd: str) -> list[str]:
    """Direct (no proxy), host-key-pinned ssh to a physical device. `-F
    /dev/null` keeps the user's ssh config out; the key is the only
    identity offered."""
    return [
        "ssh", "-F", "/dev/null",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={dev.known_hosts}",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "IdentitiesOnly=yes",
        "-o", "ConnectTimeout=8",
        "-i", key,
        f"{dev.user}@{dev.host}", cmd,
    ]


def ssh_cmd(lab: Lab, dev: Device, cmd: str) -> list[str]:
    if dev.is_physical:
        # Like a VM's unrestricted observer key (lab.ssh_key): checks, steps,
        # vars, posts, settle and the reset use the device's admin key. Only
        # the change lane and the hello preflight use the restricted key.
        return _physical_ssh(dev, dev.admin_key, cmd)
    return [
        "ssh", "-i", lab.ssh_key,
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=8",
        f"-o", f"ProxyCommand={lab.ssh_proxy}",
        f"{dev.user}@{dev.host}", cmd,
    ]


def _host_key_failed(proc: subprocess.CompletedProcess) -> bool:
    err = proc.stderr
    if isinstance(err, bytes):
        err = err.decode("utf-8", "replace")
    return proc.returncode == 255 and "Host key verification failed" in (err or "")


def ssh_ready(lab: Lab, dev: Device, timeout_s: int = 120) -> bool:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            proc = _run(ssh_cmd(lab, dev, "true"), timeout=15)
        except subprocess.TimeoutExpired:
            proc = None
        if proc is not None and proc.returncode == 0:
            return True
        if (dev.is_physical and proc is not None
                and _host_key_failed(proc)):
            return False
        if time.monotonic() >= deadline:
            return False
        time.sleep(3)


def _preflight_sha(component: str) -> str:
    sha = PREFLIGHT_SHA_CACHE.get(component)
    if sha is None:
        sha = hashlib.sha256(
            (HERE.parent / PREFLIGHT_FILES[component]).read_bytes()).hexdigest()
        PREFLIGHT_SHA_CACHE[component] = sha
    return sha


def router_hello_preflight(lab: Lab, dev: Device) -> tuple[bool, str]:
    """Run `hello <nonce>` over the runner's restricted key and require the
    four code sha256 fields to equal the repo files' and guard-state=idle.
    Returns (ok, detail); the caller stops the run with
    PREFLIGHT_STOP_TEXT when ok is False."""
    nonce = secrets.token_hex(8)
    if dev.is_physical:
        cmd = _physical_ssh(dev, dev.router_key or lab.router_key,
                            f"{ROUTER_PROG} hello {nonce}")
    else:
        cmd = ["ssh", "-i", lab.router_key,
               "-o", "BatchMode=yes",
               "-o", "StrictHostKeyChecking=yes",
               "-o", f"UserKnownHostsFile={lab.known_hosts}",
               "-o", "ConnectTimeout=8",
               "-o", f"ProxyCommand={lab.ssh_proxy}"]
        cmd += [f"{dev.user}@{dev.host}", f"{ROUTER_PROG} hello {nonce}"]
    try:
        proc = _run(cmd, timeout=30)
    except subprocess.TimeoutExpired:
        return False, "no reply"
    reply = proc.stdout.strip()
    if proc.returncode != 0 or not reply:
        return False, "no reply"
    lines = reply.splitlines()
    if len(lines) != 1:
        return False, "malformed hello reply"
    toks = lines[0].split()
    if len(toks) < 3 or toks[0] != "hello" or toks[1] != nonce:
        return False, "malformed hello reply"
    fields: dict[str, str] = {}
    for tok in toks[2:]:
        if "=" not in tok:
            return False, "malformed hello reply"
        k, v = tok.split("=", 1)
        if not k or k in fields:
            return False, "malformed hello reply"
        fields[k] = v
    for comp in ("prog", "helper", "guard", "init"):
        want = _preflight_sha(comp)
        got = fields.get(comp, "")
        if got != want:
            return False, (f"{comp} {got[:8] or '?'}... differs from this "
                           f"controller's ({want[:8]}...)")
    state = fields.get("guard-state", "")
    if state != "idle":
        return False, f"guard-state={state or '?'} is not idle"
    return True, ""


def wait_settled(lab: Lab, dname: str) -> dict[str, Any]:
    """Wait until a device's settle fingerprint is unchanged and successful
    for the configured quiet period."""
    dev = lab.devices[dname]
    started = time.monotonic()
    record: dict[str, Any] = {
        "device": dname,
        "settled": None,
        "waited_s": 0.0,
        "polls": 0,
        "changes": 0,
        "last_rc": None,
    }
    if not dev.settle_cmd:
        return record

    deadline = started + lab.settle_timeout_s
    previous_stdout: str | None = None
    quiet_started: float | None = None
    while True:
        try:
            proc = _run(ssh_cmd(lab, dev, dev.settle_cmd), timeout=15)
            rc: int | None = proc.returncode
            stdout = proc.stdout
        except subprocess.TimeoutExpired:
            rc = None
            stdout = ""

        now = time.monotonic()
        record["polls"] += 1
        record["last_rc"] = rc
        if previous_stdout is not None and stdout != previous_stdout:
            record["changes"] += 1
        changed = previous_stdout is not None and stdout != previous_stdout
        previous_stdout = stdout

        if rc == 0:
            if quiet_started is None or changed:
                quiet_started = now
            if now - quiet_started >= lab.settle_quiet_s:
                record["settled"] = True
                record["waited_s"] = round(now - started, 1)
                return record
        else:
            quiet_started = None

        if now >= deadline:
            record["settled"] = False
            record["waited_s"] = round(now - started, 1)
            return record
        time.sleep(lab.settle_poll_s)


def _uci_export_hash(lab: Lab, dev: Device) -> str:
    """Run ``h=$(uci export) && [ -n "$h" ] && printf '%s\\n' "$h" | md5sum``
    over ssh and return the 32-hex md5 digest.  Raises ``ValueError``
    when the ssh rc is non-zero, the output is empty, the digest is
    not 32 hex chars, or the digest equals the md5 of empty input
    (``_EMPTY_MD5_DIGEST``).  The empty-export guard (``[ -n "$h" ]``)
    stops the chain from piping an empty string into ``md5sum``; the
    digest check is a belt-and-braces guard so a router that emits only
    whitespace or returns an empty digest cannot pass the rollback check
    vacuously."""
    cmd = ('h=$(uci export) && [ -n "$h" ] && '
           'printf \'%s\\n\' "$h" | md5sum')
    proc = _run(ssh_cmd(lab, dev, cmd), timeout=15)
    if proc.returncode != 0:
        raise ValueError(
            f"uci export md5sum failed rc={proc.returncode}: "
            f"{proc.stderr.strip()[:200]}")
    stdout = proc.stdout.strip()
    if not stdout:
        raise ValueError(
            "uci export md5sum returned empty stdout "
            "(the [ -n \"$h\" ] guard refused an empty export)")
    digest = stdout.split()[0]
    if not _MD5_HEX_RE.fullmatch(digest):
        raise ValueError(
            f"uci export md5 digest is not 32 hex chars: {digest!r}")
    if digest == _EMPTY_MD5_DIGEST:
        raise ValueError(
            "uci export md5 digest is the md5 of empty input "
            "(router returned an empty export)")
    return digest


# ---------- Reboot step (tier scenarios) ----------

# Module-level constants so tests can monkeypatch them down to zero.
REBOOT_WAIT_SSH_DOWN_S = 60
REBOOT_SSH_READY_TIMEOUT_S = 240


def _read_boot_id(lab: Lab, dev: Device) -> str:
    """``cat /proc/sys/kernel/random/boot_id`` over ssh. Returns the trimmed
    stdout (a 36-char UUID)."""
    proc = _run(ssh_cmd(lab, dev, "cat /proc/sys/kernel/random/boot_id"),
                timeout=15)
    return proc.stdout.strip()


def _wait_until_ssh_down(lab: Lab, dev: Device,
                          timeout_s: int | None = None) -> bool:
    """Block until ``ssh -o BatchMode=yes 'true'`` does NOT return rc=0 OR
    the timeout elapses.  Returns True when ssh first refused (we treat a
    timeout as ssh still answering; the caller treats that as 'reboot
    never took').  ``timeout_s`` reads ``REBOOT_WAIT_SSH_DOWN_S`` at call
    time so a test can monkeypatch the module constant down to 0."""
    if timeout_s is None:
        timeout_s = REBOOT_WAIT_SSH_DOWN_S
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            proc = _run(ssh_cmd(lab, dev, "true"), timeout=10)
        except subprocess.TimeoutExpired:
            return True
        if proc.returncode != 0:
            return True
        time.sleep(2)
    return False


def reboot_device(lab: Lab, dev: Device, rec_list: list,
                  lane: str) -> dict[str, Any]:
    """Reboot `dev`, then verify the boot id changed.

    Order:
      1. read the boot id over ssh (``cat /proc/sys/kernel/random/boot_id``)
      2. issue the admin ssh reboot as a detached command so the calling
         ssh returns rc=0:
         ``sh -c 'sleep 1; reboot' >/dev/null 2>&1 &``
      3. wait up to ~60 s for ssh to stop answering
      4. ``ssh_ready(timeout=240)``
      5. in the key lane, ``router_hello_preflight``
      6. ``wait_settled`` for the device
      7. read the boot id again.  If it differs, ok=True.  If it does
         NOT differ (the router never rebooted), ok=False.

    If the ssh reboot itself returns non-zero (rc != 0), the function
    falls back ONCE to a Proxmox guest reboot
    (``POST .../qemu/<vmid>/status/reboot``) and records
    ``fallback='proxmox'`` plus the ssh reason.  A Proxmox reboot that
    also does not change the boot id is recorded the same way (no second
    fallback).

    Returns ``{device, before_boot_id, after_boot_id, rebooted, fallback,
    settled, ok, reason (when ok is False)}``.  The record is appended to
    ``rec_list`` so a failure during the function does not erase evidence
    from the caller.
    """
    record: dict[str, Any] = {
        "device": dev.name,
        "before_boot_id": None,
        "after_boot_id": None,
        "rebooted": False,
        "fallback": None,
        "settled": None,
        "ok": False,
    }
    rec_list.append(record)

    if dev.is_physical:
        try:
            physical_identity_check(lab, dev)
        except _PhysicalStop as e:
            record["reason"] = str(e)
            return record

    before = _read_boot_id(lab, dev)
    record["before_boot_id"] = before

    # Issue the reboot as a detached background job so the parent shell
    # returns rc=0 even though the reboot will close the ssh connection.
    ssh_rc = 0
    ssh_reason = ""
    if dev.is_physical:
        # Plain admin `reboot`; the connection drops, so its result is not
        # checked. Never a Proxmox call: the boot-id check decides.
        try:
            _run(ssh_cmd(lab, dev, "reboot"), timeout=30)
        except subprocess.TimeoutExpired:
            pass
    else:
        reboot_cmd = "sh -c 'sleep 1; reboot' >/dev/null 2>&1 &"
        try:
            proc = _run(ssh_cmd(lab, dev, reboot_cmd), timeout=15)
            ssh_rc = proc.returncode
            ssh_reason = proc.stderr.strip()
        except subprocess.TimeoutExpired as e:
            ssh_rc = None
            ssh_reason = _exc_text(e.stderr) or "ssh timeout"

    fell_back = False
    if ssh_rc != 0:
        # Fall back ONCE to Proxmox.  A failure here is recorded but does
        # NOT raise: the boot-id check below is the source of truth.
        fell_back = True
        try:
            pve_guest_reboot(lab, dev)
        except Exception as e:
            record["ok"] = False
            record["reason"] = (
                f"ssh reboot rc={ssh_rc} ({ssh_reason}); "
                f"proxmox reboot also failed: {type(e).__name__}: {e}")
            return record

    # Wait for ssh to refuse (it will, briefly, while the device reboots).
    _wait_until_ssh_down(lab, dev)

    if not ssh_ready(lab, dev, timeout_s=REBOOT_SSH_READY_TIMEOUT_S):
        record["ok"] = False
        record["fallback"] = "proxmox" if fell_back else None
        record["reason"] = (
            f"ssh not ready within {REBOOT_SSH_READY_TIMEOUT_S}s "
            f"after reboot")
        return record

    if needs_hello_preflight(dev, lane):
        ok, detail = router_hello_preflight(lab, dev)
        if not ok:
            record["ok"] = False
            record["fallback"] = "proxmox" if fell_back else None
            record["reason"] = (
                f"hello preflight failed after reboot: {detail}; "
                f"{preflight_stop_text(dev)}")
            return record

    settle_rec = wait_settled(lab, dev.name)
    record["settled"] = settle_rec.get("settled")

    after = _read_boot_id(lab, dev)
    record["after_boot_id"] = after

    if before and after and before != after:
        record["ok"] = True
        record["rebooted"] = True
        record["fallback"] = "proxmox" if fell_back else None
        return record

    record["ok"] = False
    record["fallback"] = "proxmox" if fell_back else None
    record["reason"] = (
        f"boot id did not change after reboot: "
        f"before={before!r} after={after!r}")
    return record


# ---------- Proxmox ----------

def _curl_pve(lab: Lab, url: str, method: str = "GET",
              form: list[str] | None = None) -> dict:
    pin = Path(lab.pve_pin_file).read_text().strip()
    auth = Path(lab.pve_token_file).read_text().strip()
    args = ["curl", "-sk", "--pinnedpubkey", pin,
            "-H", f"Authorization: {auth}",
            "-X", method]
    if form:
        args += ["-d", form[0]]
    args.append(url)
    sleeps = PVE_CURL_RETRY_SLEEPS_S
    max_attempts = PVE_CURL_MAX_ATTEMPTS
    for attempt in range(1, max_attempts + 1):
        proc = _run(args, timeout=30)
        if proc.returncode == 0:
            return json.loads(proc.stdout)["data"]
        if proc.returncode != 7 or attempt == max_attempts:
            raise RuntimeError(
                f"curl failed rc={proc.returncode}: {proc.stderr.strip()}")
        wait = sleeps[attempt - 1]
        print(f"pve: curl rc={proc.returncode} (could not connect), "
              f"retry {attempt}/{max_attempts - 1} in {wait} s",
              file=sys.stderr)
        time.sleep(wait)
    raise RuntimeError("curl failed: unreachable")  # pragma: no cover


def pve_rollback(lab: Lab, dev: Device) -> str:
    url = (f"https://{lab.pve_host}:8006/api2/json/nodes/{lab.pve_node}"
           f"/qemu/{dev.vmid}/snapshot/{dev.snapshot}/rollback")
    return str(_curl_pve(lab, url, method="POST", form=["start=1"]))


def pve_guest_reboot(lab: Lab, dev: Device) -> str:
    """POST /qemu/<vmid>/status/reboot: Proxmox guest reboot (used as the
    fallback when an admin ssh reboot does not return rc=0)."""
    url = (f"https://{lab.pve_host}:8006/api2/json/nodes/{lab.pve_node}"
           f"/qemu/{dev.vmid}/status/reboot")
    return str(_curl_pve(lab, url, method="POST"))


def pve_task_status(lab: Lab, upid: str) -> dict:
    upid_q = urllib.parse.quote(upid, safe="")
    url = (f"https://{lab.pve_host}:8006/api2/json/nodes/{lab.pve_node}"
           f"/tasks/{upid_q}/status")
    return _curl_pve(lab, url)


def pve_wait_task(lab: Lab, upid: str, timeout_s: int = 120) -> dict:
    """Poll `pve_task_status` until the task stops or `timeout_s` elapses.
    Return the LAST status dict seen: the stopped dict (with `exitstatus`)
    or, on timeout, whatever the API last reported (e.g.
    `{"status": "running"}`)."""
    deadline = time.monotonic() + timeout_s
    while True:
        st = pve_task_status(lab, upid)
        if st.get("status") == "stopped":
            return st
        if time.monotonic() >= deadline:
            return st
        time.sleep(2)


def pve_wait_task_ok(lab: Lab, upid: str, timeout_s: int = 120) -> bool:
    """Thin wrapper: True iff the task stopped with exitstatus == "OK"."""
    st = pve_wait_task(lab, upid, timeout_s=timeout_s)
    return st.get("status") == "stopped" and st.get("exitstatus") == "OK"


def pve_reset(lab: Lab, dname: str, records: list[dict],
              attempts: int = RESET_MAX_ATTEMPTS,
              retry_sleep_s: int = RESET_RETRY_SLEEP_S) -> dict:
    """Roll one device back to its Proxmox snapshot baseline. Retry up to
    `attempts` times when the task's exitstatus contains PVE_LOCK_TEXT
    (the previous VM's `qm cleanup` holds the VM config lock for ~35 s);
    pause `retry_sleep_s` seconds between attempts. Every attempt is
    appended to `records` as soon as it finishes, so an exception in a
    later attempt leaves the earlier records behind. Returns the last
    record (the one whose outcome decided the loop)."""
    dev = lab.devices[dname]   # KeyError before any API call on unknown name
    last: dict = {}
    for attempt in range(1, attempts + 1):
        upid = pve_rollback(lab, dev)
        st = pve_wait_task(lab, upid)
        stopped = st.get("status") == "stopped"
        exitstatus = st.get("exitstatus")  # None when absent
        ok = stopped and exitstatus == "OK"
        rec = {"device": dname, "upid": upid, "task_ok": ok,
               "exitstatus": exitstatus, "attempt": attempt}
        records.append(rec)
        last = rec
        if ok:
            break
        if not stopped:
            break
        if PVE_LOCK_TEXT in str(exitstatus or "") and attempt < attempts:
            time.sleep(retry_sleep_s)
            continue
        break
    return last


# ---------- Physical device reset ----------

def needs_hello_preflight(dev: Device, lane: str) -> bool:
    """Key-lane hello preflight: VM devices gate on the baseline-newton-
    snapshot name, a physical device (no snapshot) on its kind."""
    return lane == "key" and (
        dev.is_physical or dev.snapshot.startswith(NEWTON_SNAPSHOT_PREFIX))


def preflight_stop_text(dev: Device) -> str:
    if dev.is_physical:
        return (f"re-run newton-router-setup {dev.name} install/check and "
                f"retake the baseline backup")
    return PREFLIGHT_STOP_TEXT


PHYSICAL_REMOTE_ARCHIVE = "/tmp/newton-baseline.tar.gz"
PHYSICAL_SSH_BACK_TIMEOUT_S = 240
PHYSICAL_SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")
# Safe package token: starts alphanumeric, then alphanumerics and . _ + -.
# Refuses world lines with a version constraint or a `!` ("!foo" means remove;
# "foo=2.93-r1" pins a version), which apk uses and which we never see at the
# baseline; if one shows up the runner stops with abort_run rather than echo
# it back into an `apk del` argument list.
PHYSICAL_PKG_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+-]*$")
# A world line is a name or a pinned name=version (Pulsar pins base-files,
# kernel and libc); `apk del` gets the name part only.
PHYSICAL_WORLD_TOKEN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_.+-]*(=[A-Za-z0-9][A-Za-z0-9_.+~-]*)?$")
# An `apk info -v` line is name-version; apk-tools 3 versions may hold a `~`
# (base-files-1711~f5dae5ece4 on Pulsar). These lines never reach a command.
PHYSICAL_PKG_VERSION_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+~-]*$")
# Two read-only package-state probes, run with the admin key before any reset
# change (so a hostile device can't make the runner `apk del` arbitrary
# paths). Fixed strings; LC_ALL=C so the sort matches what we expect.
PHYSICAL_PKG_LIST_CMD = "apk info -v | LC_ALL=C sort"
PHYSICAL_WORLD_CMD = "LC_ALL=C sort /etc/apk/world"
PHYSICAL_APK_UPDATE_CMD = "apk update"
PHYSICAL_PKG_DEL_TIMEOUT_S = 300
PHYSICAL_PKG_RECORD_DIR = "packages"
# Cap the number of names printed in a stop message so the abort_run summary
# stays readable when many packages are gone from the record.
PHYSICAL_PKG_LISTING_LIMIT = 20
# The fingerprint body: every regular file under /etc/config, /etc/newton and
# /etc/crontabs (skipping /etc/newton/approve.key and /etc/newton/guard.lock),
# the four named top-level files that exist on Pulsar when a scenario touches
# them (/etc/dropbear/authorized_keys, /etc/firewall.user, /etc/rc.local,
# /etc/sysupgrade.conf), hashed with sha256sum; the lines are sorted with
# LC_ALL=C and one final sha256sum taken. A fixed string; nothing is
# interpolated. We `cd /` first so the form is the same archive-side and
# router-side and `archive_fingerprint` can be reproduced for a test by
# running the body in a tmp tree (see test_fingerprint.py).
# Two files are left out, both for the same reason: no sysupgrade -b archive
# holds them, so the archive side can never have them, and a restore leaves the
# router's copy in place. /etc/newton/approve.key is a secret newton-router-setup
# keeps out of sysupgrade.conf; PHYSICAL_APPROVE_KEY_CMD checks it is still
# there. /etc/newton/guard.lock is the 1.1.0 guard's own lock: empty, held open
# while the guard runs, not one of the /etc/newton lines in sysupgrade.conf, and
# re-created by the guard after a restore -- counting it would make every
# post-restore check fail. The same two names are filtered out by
# `_in_fingerprint` on the archive side.
PHYSICAL_FINGERPRINT_BODY = (
    "{ find etc/config etc/newton etc/crontabs -type f 2>/dev/null "
    "| grep -vx -e etc/newton/approve.key -e etc/newton/guard.lock; "
    "for f in etc/dropbear/authorized_keys etc/firewall.user etc/rc.local "
    "etc/sysupgrade.conf; do "
    "[ -f \"$f\" ] && echo \"$f\"; "
    "done; } "
    "| while read -r f; do sha256sum \"$f\"; done "
    "| LC_ALL=C sort | sha256sum | cut -d' ' -f1")
PHYSICAL_FINGERPRINT_CMD = "cd / && " + PHYSICAL_FINGERPRINT_BODY
PHYSICAL_APPROVE_KEY_CMD = "[ -s /etc/newton/approve.key ]"
# A scenario leaves guard state under /etc/newton (guard.log, last_revert,
# lkg/<session>/); a VM snapshot wipes it, a restore does not. The reset waits
# while the guard is pending (an armed guard restores from lkg/ at boot), then
# removes every top-level /etc/newton entry the archive lacks, except the
# approval key and the guard's lock file: deleting guard.lock would take away
# the lock the guard is holding open, and it re-creates it anyway.
PHYSICAL_GUARD_STATUS_CMD = "/usr/libexec/newton-guard status"
PHYSICAL_GUARD_IDLE_TIMEOUT_S = 300
PHYSICAL_LIST_NEWTON_CMD = "find /etc/newton -mindepth 1 -maxdepth 1"


def _archive_names(path: str) -> dict[str, bytes]:
    """Regular files of a sysupgrade archive, keyed by name without any
    leading ./ or /. Streams the archive in memory: nothing is extracted to
    disk, so no secret is left behind."""
    out: dict[str, bytes] = {}
    with tarfile.open(path, "r:*") as tf:
        for m in tf:
            if not m.isreg():
                continue
            fh = tf.extractfile(m)
            if fh is None:
                continue
            name = m.name
            while name.startswith("./"):
                name = name[2:]
            out[name.lstrip("/")] = fh.read()
    return out


class ArchiveError(ValueError):
    """The baseline archive is not a usable sysupgrade backup."""


# Files every baseline archive must hold as regular files. Pulsar's baseline is
# taken with Newton installed (`sysupgrade -b`), so it carries the network,
# firewall, system and dropbear configs and the ssh authorized keys (without
# which a restore leaves no way back in) and some state under /etc/newton.
ARCHIVE_REQUIRED = (
    "etc/config/network", "etc/config/firewall", "etc/config/system",
    "etc/config/dropbear", "etc/dropbear/authorized_keys",
    "etc/newton/device-id", "etc/newton/profile")


ARCHIVE_IDENTITY = ("etc/newton/device-id", "etc/newton/profile")


def _archive_member_name(raw: str) -> str:
    name = raw
    while name.startswith("./"):
        name = name[2:]
    return name


def validate_baseline_archive(path: str, device: str) -> tuple[set[str], set[str]]:
    """Check, runner side and before anything is deleted on the router, that
    `path` is a readable tar.gz of a usable baseline: every member relative
    with no `..`, only regular files, directories and symlinks that stay
    inside the archive (hard links and devices are refused), the
    ARCHIVE_REQUIRED files present, etc/newton/device-id equal to `device` and
    etc/newton/profile equal to "lab" (one trailing newline stripped). Returns
    the keep sets (etc/config names, etc/newton top-level names); both are
    non-empty."""
    try:
        regs: set[str] = set()
        ident: dict[str, bytes] = {}
        with tarfile.open(path, "r:gz") as tf:
            for m in tf:
                name = _archive_member_name(m.name)
                if name in ("", "."):
                    if m.isdir():
                        continue
                    raise ArchiveError(f"member {m.name!r} has no usable name")
                if name.startswith("/") or "\0" in name:
                    raise ArchiveError(f"absolute member name {m.name!r}")
                if ".." in name.split("/"):
                    raise ArchiveError(f"member {m.name!r} contains '..'")
                if m.isreg():
                    regs.add(name)
                    if name in ARCHIVE_IDENTITY and m.size <= 4096:
                        ident[name] = tf.extractfile(m).read()
                elif m.isdir():
                    pass
                elif m.issym():
                    target = m.linkname
                    if target.startswith("/"):
                        raise ArchiveError(
                            f"symlink {m.name!r} points outside the archive "
                            f"({target!r})")
                    resolved = posixpath.normpath(
                        posixpath.join(posixpath.dirname(name), target))
                    if resolved == ".." or resolved.startswith("../") \
                            or resolved.startswith("/"):
                        raise ArchiveError(
                            f"symlink {m.name!r} points outside the archive "
                            f"({target!r})")
                else:
                    raise ArchiveError(
                        f"member {m.name!r} is a hard link or special file")
    except ArchiveError:
        raise
    except (tarfile.TarError, OSError, EOFError, zlib.error) as e:
        raise ArchiveError(f"not a readable tar.gz ({type(e).__name__})") \
            from None
    for need in ARCHIVE_REQUIRED:
        if need not in regs:
            raise ArchiveError(f"required file {need} is missing")
    for need, want in (("etc/newton/device-id", device),
                       ("etc/newton/profile", "lab")):
        raw = ident.get(need, b"")
        if raw.endswith(b"\n"):
            raw = raw[:-1]
        if raw != want.encode():
            raise ArchiveError(
                f"{need} in the archive is {raw[:40]!r}, expected {want!r}")
    keep = {n[len("etc/config/"):] for n in regs
            if n.startswith("etc/config/") and "/" not in n[len("etc/config/"):]}
    keep_n = {n[len("etc/newton/"):].split("/", 1)[0]
              for n in regs if n.startswith("etc/newton/")}
    if not keep or not keep_n:
        raise ArchiveError(
            "no files under " + ("etc/config" if not keep else "etc/newton"))
    return keep, keep_n


def _in_fingerprint(name: str) -> bool:
    # The archive-side twin of the `grep -vx` in PHYSICAL_FINGERPRINT_BODY: the
    # approval key and the guard's lock file are in no sysupgrade -b archive,
    # so they must not be counted here either (see the comment above the body).
    if name in ("etc/newton/approve.key", "etc/newton/guard.lock"):
        return False
    if (name.startswith("etc/config/") or name.startswith("etc/newton/")
            or name.startswith("etc/crontabs/")):
        return True
    return name in ("etc/dropbear/authorized_keys", "etc/firewall.user",
                    "etc/rc.local", "etc/sysupgrade.conf")


def archive_fingerprint(path: str) -> str:
    """The fingerprint PHYSICAL_FINGERPRINT_CMD yields on a router restored
    from this archive. Lines are `sha256  <relative path>` with no leading
    slash, matching the busybox `sha256sum` output the body produces; the
    lines are sorted with LC_ALL=C and the digest is the final sha256sum."""
    lines = sorted(
        f"{hashlib.sha256(data).hexdigest()}  {name}\n"
        for name, data in _archive_names(path).items()
        if _in_fingerprint(name))
    return hashlib.sha256("".join(lines).encode()).hexdigest()


class _PhysicalStop(Exception):
    """End one reset attempt. `transient` ssh failures may be retried."""

    def __init__(self, msg: str, *, transient: bool = False,
                 abort_run: bool = False, verify: str | None = None) -> None:
        super().__init__(msg)
        self.transient = transient
        self.abort_run = abort_run
        self.verify = verify


def _physical_step(lab: Lab, dev: Device, cmd: str, what: str, *,
                   stdin_path: str | None = None,
                   timeout: float = 60) -> subprocess.CompletedProcess:
    argv = ssh_cmd(lab, dev, cmd)
    try:
        if stdin_path is not None:
            proc = _run_stdin_file(argv, stdin_path, timeout=timeout)
        else:
            proc = _run(argv, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise _PhysicalStop(f"{what}: ssh timed out", transient=True)
    if _host_key_failed(proc):
        raise _PhysicalStop(
            f"{what}: ssh host key verification failed; the pinned host key "
            f"does not match the device at {dev.host}; not retrying",
            abort_run=True)
    if proc.returncode == 255:
        raise _PhysicalStop(f"{what}: ssh failed (rc=255)", transient=True)
    if proc.returncode != 0:
        raise _PhysicalStop(f"{what}: rc={proc.returncode}")
    return proc


# Read-only identity probe, run with the admin key before anything changes the
# router. Reads the router's own Newton identity (the files `newton-router
# hello` reports as device= and profile=) and the board name. Fixed string.
PHYSICAL_IDENTITY_CMD = (
    "printf 'device=%s\\n' \"$(head -n 1 /etc/newton/device-id 2>/dev/null)\"; "
    "printf 'profile=%s\\n' \"$(head -n 1 /etc/newton/profile 2>/dev/null)\"; "
    "printf 'board=%s\\n' \"$(head -n 1 /tmp/sysinfo/board_name 2>/dev/null)\"")


def physical_identity_check(lab: Lab, dev: Device) -> None:
    """Prove, read-only, that the device at dev.host is the intended lab
    router: /etc/newton/device-id equals the config name, /etc/newton/profile
    is exactly "lab", and /tmp/sysinfo/board_name equals board_name when the
    config pins one. Raises _PhysicalStop (abort_run) on a mismatch or an
    unreadable answer, a transient one on an ssh failure."""
    try:
        proc = _physical_step(lab, dev, PHYSICAL_IDENTITY_CMD,
                              "identity check")
    except _PhysicalStop as e:
        if e.transient or e.abort_run:
            raise
        raise _PhysicalStop(
            f"identity check failed: unreadable ({e}); not touching "
            f"{dev.name}", abort_run=True) from None
    got: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        k, sep, v = line.partition("=")
        if not sep or k in got:
            raise _PhysicalStop(
                f"identity check failed: malformed answer; not touching "
                f"{dev.name}", abort_run=True)
        got[k] = v
    if set(got) != {"device", "profile", "board"}:
        raise _PhysicalStop(
            f"identity check failed: malformed answer; not touching "
            f"{dev.name}", abort_run=True)
    problems = []
    if got["device"] != dev.name:
        problems.append(f"device-id is {got['device'][:40]!r}, expected "
                        f"{dev.name!r}")
    if got["profile"] != "lab":
        problems.append(f"profile is {got['profile'][:40]!r}, expected 'lab'")
    if dev.board_name and got["board"] != dev.board_name:
        problems.append(f"board is {got['board'][:40]!r}, expected "
                        f"{dev.board_name!r}")
    if problems:
        raise _PhysicalStop(
            "identity check failed: " + "; ".join(problems)
            + f"; not touching the device at {dev.host}", abort_run=True)


def _physical_wait_guard_idle(lab: Lab, dev: Device) -> None:
    deadline = time.monotonic() + PHYSICAL_GUARD_IDLE_TIMEOUT_S
    while True:
        proc = _physical_step(lab, dev, PHYSICAL_GUARD_STATUS_CMD,
                              "guard status")
        state = (proc.stdout.split() or [""])[0]
        # newton-guard status_line: idle, restored (after a rollback; the
        # cleanup below removes last_revert), pending (rollback armed: wait),
        # failed (a human must look).
        if state in ("idle", "restored"):
            return
        if state != "pending":
            raise _PhysicalStop(
                f"newton-guard is {state or '?'}; not resetting", abort_run=True)
        if time.monotonic() >= deadline:
            raise _PhysicalStop(
                f"newton-guard is {state or '?'}, not idle, after "
                f"{PHYSICAL_GUARD_IDLE_TIMEOUT_S}s; not resetting",
                abort_run=True)
        time.sleep(5)


def _physical_local_archive(dev: Device) -> tuple[set[str], set[str]]:
    """The local archive is still the pinned, usable one (re-checked at every
    reset: it is a file on disk). Returns the keep sets."""
    try:
        actual = hashlib.sha256(Path(dev.baseline_backup).read_bytes()).hexdigest()
    except OSError as e:
        raise _PhysicalStop(
            f"baseline archive unreadable ({type(e).__name__}); not touching "
            f"the router", abort_run=True) from None
    if actual != dev.baseline_sha256:
        raise _PhysicalStop(
            f"local sha256 of the baseline archive is {actual}, expected "
            f"{dev.baseline_sha256}; not touching the router", abort_run=True)
    try:
        return validate_baseline_archive(dev.baseline_backup, dev.name)
    except ArchiveError as e:
        raise _PhysicalStop(
            f"baseline archive is not usable: {e}; not touching the router",
            abort_run=True) from None


def _physical_remove_remote_archive(lab: Lab, dev: Device) -> None:
    """Best effort: the uploaded archive holds secrets; drop it from /tmp."""
    try:
        _run(ssh_cmd(lab, dev, f"rm -f {PHYSICAL_REMOTE_ARCHIVE}"), timeout=20)
    except Exception:
        pass


def _physical_pkg_record_paths(dev: Device) -> tuple[Path, Path]:
    """The on-disk record of the device's baseline package state. RESULTS_DIR
    is read at call time so a test can monkeypatch it before the reset
    starts."""
    d = RESULTS_DIR / PHYSICAL_PKG_RECORD_DIR
    return d / f"{dev.name}.installed", d / f"{dev.name}.world"


def _physical_write_pkg_record(installed: str, world: str, dev: Device) -> None:
    """One-time baseline record: directory 0700, files 0600, one sorted line
    each. Called only when neither record file exists yet, so the operator
    can keep the old record by deleting the new one explicitly."""
    ipath, wpath = _physical_pkg_record_paths(dev)
    d = ipath.parent
    # 0700 (a directory an operator left with looser bits, e.g. 0755 from an
    # older runner or hand-creation, is tightened rather than refused), and
    # never through a symlink: RESULTS_DIR is created on the way here too.
    _ensure_private_dir(d, "the package record directory")
    for payload, path in ((installed, ipath), (world, wpath)):
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, payload.encode())
        finally:
            os.close(fd)
        os.chmod(path, 0o600)


def _physical_read_pkg_record(dev: Device) -> tuple[set[str], set[str]] | None:
    """Load the recorded installed set and world set. Returns None if neither
    file exists yet (first-time setup), or raises _PhysicalStop(abort_run) if
    exactly one exists (the record is now incoherent; an operator must delete
    the surviving file to re-record)."""
    ipath, wpath = _physical_pkg_record_paths(dev)
    have_i = ipath.exists()
    have_w = wpath.exists()
    if not have_i and not have_w:
        return None
    if have_i != have_w:
        keep = ipath if have_i else wpath
        missing = wpath if have_i else ipath
        raise _PhysicalStop(
            f"package record for {dev.name} is half present: {keep} exists "
            f"but {missing} does not (delete both files to re-record): "
            f"{keep} and {missing}", abort_run=True)
    installed = {ln.strip() for ln in ipath.read_text().splitlines()
                 if ln.strip()}
    world = {ln.strip() for ln in wpath.read_text().splitlines()
             if ln.strip()}
    return installed, world


def _physical_lines_unsafe_pkg_token(lines: list[str],
                                     token: re.Pattern = PHYSICAL_PKG_TOKEN) -> str | None:
    """If any line fails the safe-token test, return that line; else None."""
    for ln in lines:
        if not token.match(ln):
            return ln
    return None


def _physical_remote_pkg_lines(lab: Lab, dev: Device, cmd: str,
                               what: str) -> list[str]:
    """Read a sorted, line-per-package list from the router. Empty output is
    treated as a stop; a line that is not a safe package token is a stop
    (the device may be hostile or the command may have produced a stray
    heading)."""
    proc = _physical_step(lab, dev, cmd, what)
    lines = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
    if not lines:
        raise _PhysicalStop(
            f"{what}: empty answer from {cmd!r}; the device's package state "
            f"is not recordable, delete both files {RESULTS_DIR / PHYSICAL_PKG_RECORD_DIR / (dev.name + '.installed')} and "
            f"{RESULTS_DIR / PHYSICAL_PKG_RECORD_DIR / (dev.name + '.world')} to re-record",
            abort_run=True)
    bad = _physical_lines_unsafe_pkg_token(
        lines, PHYSICAL_PKG_VERSION_TOKEN if cmd == PHYSICAL_PKG_LIST_CMD
        else PHYSICAL_WORLD_TOKEN)
    if bad is not None:
        raise _PhysicalStop(
            f"{what}: unsafe package token in the answer: {bad!r}; refusing "
            f"to use this list, delete both files "
            f"{RESULTS_DIR / PHYSICAL_PKG_RECORD_DIR / (dev.name + '.installed')} and "
            f"{RESULTS_DIR / PHYSICAL_PKG_RECORD_DIR / (dev.name + '.world')} to re-record",
            abort_run=True)
    return lines


def _physical_pkg_set_diff_message(label: str, missing: list[str],
                                   extra: list[str], dev: Device) -> str:
    """Format the stop message naming the missing / extra packages (limited
    to PHYSICAL_PKG_LISTING_LIMIT) and the record files an operator deletes
    to re-record."""
    lim = PHYSICAL_PKG_LISTING_LIMIT
    m = missing[:lim] + (["..."] if len(missing) > lim else [])
    e = extra[:lim] + (["..."] if len(extra) > lim else [])
    ibase = RESULTS_DIR / PHYSICAL_PKG_RECORD_DIR / (dev.name + ".installed")
    wbase = RESULTS_DIR / PHYSICAL_PKG_RECORD_DIR / (dev.name + ".world")
    return (f"{label}: extra {e} missing {m}; delete both files {ibase} and "
            f"{wbase} to re-record")


def _physical_pkgs_ensure_record(lab: Lab, dev: Device, rec: dict) -> None:
    """Step 1 of every physical reset: read the existing package record, or
    record it now from the router. No change is made on the device either
    way. Sets rec[\"packages\"][\"recorded\"]=True when a new record is
    written."""
    have = _physical_read_pkg_record(dev)
    if have is not None:
        return
    installed_lines = _physical_remote_pkg_lines(
        lab, dev, PHYSICAL_PKG_LIST_CMD, "list installed packages")
    world_lines = _physical_remote_pkg_lines(
        lab, dev, PHYSICAL_WORLD_CMD, "list /etc/apk/world")
    body_i = "\n".join(installed_lines) + "\n"
    body_w = "\n".join(world_lines) + "\n"
    _physical_write_pkg_record(body_i, body_w, dev)
    rec["packages"] = {"recorded": True, "installed": len(installed_lines),
                       "world": len(world_lines)}


def _physical_pkgs_restore(lab: Lab, dev: Device, rec: dict) -> None:
    """Step 3 of the physical reset: read the router's installed list and
    world, compare to the record, remove anything extra from /etc/apk/world
    with `apk del`, and re-verify the installed list. Raises _PhysicalStop
    on a missing recorded package (an operator must add it), an unsafe
    token, an installed-list mismatch after removal, or a step-level ssh
    failure (timeout or refused host key) -- those surface to the caller."""
    have = _physical_read_pkg_record(dev)
    if have is None:
        # Should not happen: the runner recorded at the start of this reset.
        raise _PhysicalStop(
            f"package record for {dev.name} vanished mid-reset; abort and "
            f"investigate the runner host's {RESULTS_DIR / PHYSICAL_PKG_RECORD_DIR}",
            abort_run=True)
    rec_installed, rec_world = have
    world_lines = _physical_remote_pkg_lines(
        lab, dev, PHYSICAL_WORLD_CMD, "list /etc/apk/world")
    installed_lines = _physical_remote_pkg_lines(
        lab, dev, PHYSICAL_PKG_LIST_CMD, "list installed packages")
    cur_world = set(world_lines)
    cur_installed = set(installed_lines)
    missing_world = sorted(rec_world - cur_world)
    extra_world = sorted(cur_world - rec_world)
    del_names = sorted({w.split("=", 1)[0] for w in extra_world})
    if missing_world:
        raise _PhysicalStop(
            _physical_pkg_set_diff_message(
                "recorded packages missing from /etc/apk/world",
                missing_world, [], dev),
            abort_run=True)
    rec["packages_removed"] = extra_world
    if extra_world:
        # Best effort: a refresh of the package index may be needed before
        # `apk del` will resolve. The package index is in /var/cache/apk
        # (a tmpfs on Pulsar), so a reboot drops it; ignore its rc but
        # still surface a timeout or host-key failure.
        try:
            proc = _run(ssh_cmd(lab, dev, PHYSICAL_APK_UPDATE_CMD),
                        timeout=PHYSICAL_PKG_DEL_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            raise _PhysicalStop(
                f"{PHYSICAL_APK_UPDATE_CMD}: ssh timed out",
                transient=True)
        if _host_key_failed(proc):
            raise _PhysicalStop(
                f"{PHYSICAL_APK_UPDATE_CMD}: ssh host key verification "
                f"failed; the pinned host key does not match the device "
                f"at {dev.host}; not retrying",
                abort_run=True)
        if proc.returncode == 255:
            raise _PhysicalStop(
                f"{PHYSICAL_APK_UPDATE_CMD}: ssh failed (rc=255)",
                transient=True)
        # apk update's own failures are absorbed.
        apk_del_argv = ssh_cmd(lab, dev,
                               f"apk del {' '.join(del_names)}")
        try:
            apk_del_proc = _run(apk_del_argv,
                                timeout=PHYSICAL_PKG_DEL_TIMEOUT_S)
        except subprocess.TimeoutExpired:
            raise _PhysicalStop(
                f"apk del {' '.join(del_names)}: ssh timed out",
                transient=True) from None
        if _host_key_failed(apk_del_proc):
            raise _PhysicalStop(
                f"apk del {' '.join(del_names)}: ssh host key verification "
                f"failed; the pinned host key does not match the device at "
                f"{dev.host}; not retrying",
                abort_run=True) from None
        if apk_del_proc.returncode == 255:
            raise _PhysicalStop(
                f"apk del {' '.join(del_names)}: ssh failed (rc=255)",
                transient=True) from None
        if apk_del_proc.returncode != 0:
            err = apk_del_proc.stderr or ""
            tail = err[-200:] if err else "(no stderr)"
            raise _PhysicalStop(
                f"apk del {' '.join(del_names)} failed (rc="
                f"{apk_del_proc.returncode}); last 200 chars of stderr: "
                f"{tail}; the device is NOT at its baseline package state "
                f"and a `sysupgrade -r` will not be run",
                abort_run=True) from None
    re_world_lines = _physical_remote_pkg_lines(
        lab, dev, PHYSICAL_WORLD_CMD, "list /etc/apk/world after apk del")
    re_installed_lines = _physical_remote_pkg_lines(
        lab, dev, PHYSICAL_PKG_LIST_CMD,
        "list installed packages after apk del")
    re_world = set(re_world_lines)
    re_installed = set(re_installed_lines)
    if re_world != rec_world:
        raise _PhysicalStop(
            _physical_pkg_set_diff_message(
                "/etc/apk/world", sorted(rec_world - re_world),
                sorted(re_world - rec_world), dev),
            abort_run=True)
    missing_installed = sorted(rec_installed - re_installed)
    extra_installed = sorted(re_installed - rec_installed)
    if missing_installed or extra_installed:
        raise _PhysicalStop(
            _physical_pkg_set_diff_message(
                "installed packages differ from the record",
                missing_installed, extra_installed, dev),
            abort_run=True)


def _physical_restore(lab: Lab, dev: Device, rec: dict) -> None:
    """Steps a-c of the physical reset. Raises _PhysicalStop. Order: local
    archive checks, identity proof, guard idle, package state record, then
    the first change."""
    keep, keep_n = _physical_local_archive(dev)
    # The two names no sysupgrade archive carries, so the reset never lists them
    # for removal: approve.key is the approval secret, guard.lock is the lock
    # the guard holds open (and re-creates) across the whole run.
    keep_n = keep_n | {"approve.key", "guard.lock"}
    physical_identity_check(lab, dev)
    _physical_wait_guard_idle(lab, dev)
    _physical_pkgs_ensure_record(lab, dev, rec)
    try:
        _physical_restore_changes(lab, dev, rec, keep, keep_n)
    finally:
        _physical_remove_remote_archive(lab, dev)
    # The connection drops as the router reboots; the result is not checked.
    try:
        _run(ssh_cmd(lab, dev, "reboot"), timeout=30)
    except subprocess.TimeoutExpired:
        pass


def _physical_restore_changes(lab: Lab, dev: Device, rec: dict,
                              keep: set[str], keep_n: set[str]) -> None:
    _physical_step(lab, dev, f"cat > {PHYSICAL_REMOTE_ARCHIVE}", "upload",
                   stdin_path=dev.baseline_backup, timeout=120)
    proc = _physical_step(lab, dev, f"sha256sum {PHYSICAL_REMOTE_ARCHIVE}",
                          "remote sha256")
    got = (proc.stdout.split() or [""])[0]
    if got != dev.baseline_sha256:
        raise _PhysicalStop(
            f"remote sha256 of the uploaded archive is {got or '?'}, "
            f"expected {dev.baseline_sha256}")
    # Remove extra packages before the config restore: a package's removal
    # scripts run on apk del, and they need to do their work before
    # sysupgrade -r overwrites /etc/config.
    _physical_pkgs_restore(lab, dev, rec)
    proc = _physical_step(lab, dev, "find /etc/config -maxdepth 1 -type f",
                          "list /etc/config")
    listed = {line.strip().removeprefix("/etc/config/")
              for line in proc.stdout.splitlines() if line.strip()}
    extra = sorted(listed - keep)
    for n in extra:
        if not PHYSICAL_SAFE_NAME.match(n) or n in (".", ".."):
            raise _PhysicalStop(
                f"unsafe file name in /etc/config: {n!r}; not deleting")
    rec["deleted"] = extra
    if extra:
        _physical_step(lab, dev,
                       "rm -f " + " ".join(f"/etc/config/{n}" for n in extra),
                       "delete extra config")
    proc = _physical_step(lab, dev, PHYSICAL_LIST_NEWTON_CMD, "list /etc/newton")
    listed_n = {line.strip().removeprefix("/etc/newton/")
                for line in proc.stdout.splitlines() if line.strip()}
    extra_n = sorted(listed_n - keep_n)
    for n in extra_n:
        if not PHYSICAL_SAFE_NAME.match(n) or n in (".", ".."):
            raise _PhysicalStop(
                f"unsafe file name in /etc/newton: {n!r}; not deleting")
    rec["deleted_newton"] = extra_n
    if extra_n:
        _physical_step(lab, dev,
                       "rm -rf " + " ".join(f"/etc/newton/{n}" for n in extra_n),
                       "delete guard leftovers")
    _physical_step(lab, dev, f"sysupgrade -r {PHYSICAL_REMOTE_ARCHIVE}",
                   "sysupgrade -r", timeout=120)


def _physical_attempt(lab: Lab, dev: Device, rec: dict) -> None:
    _physical_restore(lab, dev, rec)
    if not _wait_until_ssh_down(lab, dev):
        raise _PhysicalStop("router did not go down after reboot")
    if not ssh_ready(lab, dev, timeout_s=PHYSICAL_SSH_BACK_TIMEOUT_S):
        raise _PhysicalStop(
            f"ssh not back within {PHYSICAL_SSH_BACK_TIMEOUT_S}s after "
            f"reboot")
    settle = wait_settled(lab, dev.name)
    rec["settle"] = settle
    if settle["settled"] is False:
        raise _PhysicalStop(
            f"did not settle within {lab.settle_timeout_s:g}s "
            f"(changes={settle['changes']}, last_rc={settle['last_rc']})")
    proc = _physical_step(lab, dev, PHYSICAL_FINGERPRINT_CMD, "fingerprint")
    got = proc.stdout.strip()
    want = archive_fingerprint(dev.baseline_backup)
    if got != want:
        raise _PhysicalStop(
            f"state fingerprint mismatch after restore (router {got or '?'}, "
            f"archive {want}); the device is NOT verified",
            abort_run=True, verify="mismatch")
    # Re-read the installed list: a sysupgrade restore can put files back in
    # place but the package state is restored by the apk layer, not by the
    # sysupgrade tar, so we have to ask the device.
    have = _physical_read_pkg_record(dev)
    if have is None:
        # The record vanished during the reset (disk-full recovery, an
        # operator deleting it, anything that left us with nothing to
        # compare to). The fingerprint match above proved the archived
        # config is in place; it is the package state we cannot verify,
        # which is the whole point of the record. Stop with the same
        # mismatch shape the post-restore checks would have produced.
        ipath, wpath = _physical_pkg_record_paths(dev)
        raise _PhysicalStop(
            f"the package record for {dev.name} is gone after the reset "
            f"(neither {ipath} nor {wpath} exists); the device is NOT "
            f"verified, delete both files to re-record",
            abort_run=True, verify="mismatch")
    rec_installed, _ = have
    re_lines = _physical_remote_pkg_lines(
        lab, dev, PHYSICAL_PKG_LIST_CMD,
        "list installed packages after restore")
    re_installed = set(re_lines)
    missing = sorted(rec_installed - re_installed)
    extra = sorted(re_installed - rec_installed)
    if missing or extra:
        raise _PhysicalStop(
            _physical_pkg_set_diff_message(
                "installed packages differ from the record",
                missing, extra, dev)
            + "; the device is NOT verified",
            abort_run=True, verify="mismatch")
    try:
        approve = _run(ssh_cmd(lab, dev, PHYSICAL_APPROVE_KEY_CMD), timeout=30)
    except subprocess.TimeoutExpired:
        approve = None
    if approve is None or approve.returncode != 0:
        raise _PhysicalStop(
            "/etc/newton/approve.key is missing or empty after restore; "
            "re-run newton-router-setup approval-key; the device is NOT verified",
            abort_run=True, verify="mismatch")
    rec["verify"] = "ok"


def physical_reset(lab: Lab, dname: str, records: list[dict],
                   attempts: int = RESET_MAX_ATTEMPTS,
                   retry_sleep_s: int = RESET_RETRY_SLEEP_S) -> dict:
    """Restore a physical device to its baseline archive, then verify it.
    Returns a record shaped like pve_reset's (device, upid, task_ok,
    exitstatus, attempt) plus verify and abort_run. Only a transient ssh
    failure before the reboot is retried; a verify mismatch never is."""
    dev = lab.devices[dname]
    last: dict = {}
    for attempt in range(1, attempts + 1):
        rec: dict[str, Any] = {
            "device": dname, "upid": "physical", "task_ok": False,
            "exitstatus": None, "attempt": attempt, "verify": None,
            "abort_run": False}
        records.append(rec)
        last = rec
        try:
            _physical_attempt(lab, dev, rec)
        except _PhysicalStop as e:
            rec["exitstatus"] = str(e)
            rec["abort_run"] = e.abort_run
            if e.verify:
                rec["verify"] = e.verify
            if e.transient and attempt < attempts:
                time.sleep(retry_sleep_s)
                continue
            break
        rec["task_ok"] = True
        rec["exitstatus"] = "OK"
        break
    return last


def reset_device(lab: Lab, dname: str, records: list[dict]) -> dict:
    """Reset one device by its kind."""
    if lab.devices[dname].is_physical:
        return physical_reset(lab, dname, records)
    return pve_reset(lab, dname, records)


# ---------- owrt-change protocol ----------

def build_env(lab: Lab, lane: str = "password",
              device_name: str = "") -> dict[str, str]:
    env = os.environ.copy()
    env.pop("OWRT_SSH_KEY", None)
    env.pop("OWRT_KNOWN_HOSTS", None)
    env.pop("OWRT_SSH_PASSWORD_FILE", None)
    env.pop("OWRT_APPROVAL_TOKEN", None)
    # SW2 Item 2: the window travels with the token, so a stale pair
    # inherited from the operator's shell must not reach the wrapper.
    env.pop("OWRT_APPROVAL_NBF", None)
    env.pop("OWRT_APPROVAL_EXP", None)
    dev = lab.devices.get(device_name)
    physical = dev is not None and dev.is_physical
    env["OWRT_SSH_PROXY"] = "" if physical else lab.ssh_proxy
    if lane == "key":
        env["OWRT_SSH_KEY"] = (dev.router_key or lab.router_key
                               if physical else lab.router_key)
        known_hosts = dev.known_hosts if physical else lab.known_hosts
        if known_hosts:
            env["OWRT_KNOWN_HOSTS"] = known_hosts
    else:
        env["OWRT_SSH_PASSWORD_FILE"] = lab.ssh_password_file
    env["OWRT_EXPECT_DEVICE"] = device_name
    env["OWRT_EXPECT_PROFILE"] = "lab"
    env["OWRT_AUDIT_LOG"] = str(RESULTS_DIR / "audit.log")
    env["OWRT_BACKUP_DIR"] = str(RESULTS_DIR / "backups")
    env["OWRT_OPERATOR"] = "lab-runner"
    return env


def _write_0600(fd: int, path: str, text: str) -> None:
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(path, 0o600)


def probes_wire_bytes(probes: list[list[str]]) -> str:
    """The probe file body: fields TAB-joined, every line LF-terminated."""
    return "".join("\t".join(probe) + "\n" for probe in probes)


def _plan_rejected(combined: str) -> bool:
    """The plan was refused after the host looked at it: the router rejected the batch, a sealed probe was
    refused, or the staged firewall config failed its fw4 check and the session was discarded."""
    return ("staging rejected" in combined or "probes refused:" in combined
            or "staged firewall config fails fw4 check" in combined)


def _parse_plan_log(plan_log: str) -> dict[str, Any] | None:
    """Extract the diff block and SECTION lines from a plan_log string.

    Mirrors ``newton_mcp.server.parse_plan`` minimally: enough to feed the
    touched-control diff-union check.  Returns None on any malformed
    structure (the lab runner treats it as 'no union check possible')."""
    staged = SID_RE.search(plan_log)
    base_hash = BASEHASH_RE.search(plan_log)
    block = DIFF_BLOCK_RE.search(plan_log)
    if not staged or not base_hash or not block:
        return None
    head = plan_log[: block.start()]
    diff = block.group(1).rstrip("\n")
    return {
        "session_id": staged.group(1),
        "base_hash": base_hash.group(1),
        "diff": diff,
        "sections": [m.group(1) for m in _SECTION_LINE_RE.finditer(head)],
    }


def _derive_touched_probe_lines(
    batch: str,
    scenario_probes: "list[list[str]] | None" = None,
) -> tuple[list[int], list[list[str]], str | None]:
    """Return (auto_entries, manifest probes, error message or None).

    ``auto_entries`` are entry INDEXES (not ids): the
    ``derive_touched_entries`` call.  A duplicate-id sibling (e.g.
    OW-FW-06 '0' and '1') is a distinct entry.

    The error, when non-None, names the offending control id (caller passes
    it on as the scenario's ``error`` field).  Mirrors the MCP server's
    cap refusal so a plan with too many touched probes is refused the same
    way in both paths.  ``scenario_probes`` are the scenario's own probes;
    they count into the same sealed-probe cap as the manifest controls,
    so a refusal names the manifest ids being added (never a bare cap
    refusal from later probe validation)."""
    try:
        auto_entries = newton_touched.derive_touched_entries(batch)
        sealed_entries, manifest_probes = newton_touched.seal_manifest_ids(
            [], auto_entries, extra_probes=scenario_probes or [],
        )
    except ValueError as exc:
        return [], [], str(exc)
    return sealed_entries, manifest_probes, None


def _apply_touched_to_plan(
    lab: Lab,
    target: Device,
    batch: str,
    scenario_probes: list[list[str]],
    timeout_s: int,
    lane: str,
) -> dict[str, Any]:
    """Wrap ``plan_batch`` with the ADR-010 touched-control wiring.

    Returns a dict with the keys the rest of the runner reads after a
    successful plan:

    * ``rc``                plan_batch return code (0 ok)
    * ``pout`` / ``pe``     raw stdout/stderr (combined = plan_log)
    * ``sid``              the staged session id (newer one if restage ran)
    * ``auto_ids``         every auto-derived id the runner recorded
    * ``sealed_probe_count`` total sealed probe lines (manifest + scenario)
    * ``error``            refusal message (None on success)

    The diff-union restage compares entry INDEXES (a duplicate-id sibling
    is distinct); ids are only used for messages and the record.

    On failure paths ``rc`` is non-zero or ``error`` is set; the caller
    decides between ``noop`` / ``rejected`` / ``error`` based on the
    combined plan output, same as before this round.
    """
    sealed_entries, manifest_probes, seal_err = _derive_touched_probe_lines(
        batch, scenario_probes,
    )
    if seal_err is not None:
        return {"rc": 1, "pout": "", "pe": seal_err, "sid": None,
                "auto_ids": [], "sealed_probe_count": 0,
                "error": seal_err, "plan_log": seal_err}
    auto_entries = list(sealed_entries)
    combined_probes = list(manifest_probes) + list(scenario_probes)
    sealed_probe_count = len(combined_probes)
    controls = newton_probes._load_controls(newton_probes.manifest_path())
    auto_ids = newton_touched.entry_ids(controls, sealed_entries)

    rc, pout, pe = plan_batch(
        lab, target, batch,
        probes=combined_probes, timeout_s=timeout_s, lane=lane,
    )
    if rc != 0:
        return {"rc": rc, "pout": pout, "pe": pe, "sid": None,
                "auto_ids": auto_ids, "sealed_probe_count": sealed_probe_count,
                "error": None, "plan_log": (pout + pe)[-MAX_LOG:]}
    sid_m = SID_RE.search(pout)
    if not sid_m:
        return {"rc": rc, "pout": pout, "pe": pe, "sid": None,
                "auto_ids": auto_ids, "sealed_probe_count": sealed_probe_count,
                "error": "no SID in plan output",
                "plan_log": (pout + pe)[-MAX_LOG:]}
    sid = sid_m.group(1)

    parsed = _parse_plan_log(pout + pe)
    if parsed is None:
        # First plan staged but the log is unparseable: no diff block /
        # SECTION lines, so the diff-union check cannot run.  Abort the
        # staged session and refuse; do NOT silently pass through.
        abort_batch(lab, target, sid, lane=lane)
        msg = (
            "first plan log is unparseable; the diff-union check "
            "cannot run, aborting the staged session"
        )
        return {
            "rc": 1, "pout": pout, "pe": "", "sid": None,
            "auto_ids": auto_ids, "sealed_probe_count": sealed_probe_count,
            "error": msg, "plan_log": msg,
        }
    diff_entries = newton_touched.derive_touched_entries(
        batch, parsed["diff"], parsed["sections"],
    )
    needs, missing = newton_touched.needs_restage(
        sealed_entries, diff_entries,
    )
    if needs:
        # First plan staged with too few probes.  Abort, re-stage once
        # with the union, and re-check.  A second miss aborts the new
        # session and raises without leaving a stale plan record.
        abort_batch(lab, target, sid, lane=lane)
        union_entries = list(sealed_entries) + list(missing)
        try:
            sealed_entries2, manifest_probes2 = newton_touched.seal_manifest_ids(
                [], union_entries, extra_probes=scenario_probes,
            )
        except ValueError as exc:
            return {
                "rc": 1, "pout": pout, "pe": "", "sid": None,
                "auto_ids": auto_ids, "sealed_probe_count": sealed_probe_count,
                "error": f"manifest seal failed: {exc}",
                "plan_log": (pout + pe)[-MAX_LOG:],
            }
        # The union seal succeeded; refresh auto_ids so the record
        # carries every diff-added id, even when the second plan then
        # fails (the union was the most we could seal).
        auto_ids = newton_touched.entry_ids(controls, sealed_entries2)
        combined2 = list(manifest_probes2) + list(scenario_probes)
        rc2, pout2, pe2 = plan_batch(
            lab, target, batch,
            probes=combined2, timeout_s=timeout_s, lane=lane,
        )
        if rc2 != 0:
            return {
                "rc": rc2, "pout": pout2, "pe": pe2, "sid": None,
                "auto_ids": auto_ids, "sealed_probe_count": len(combined2),
                "error": None,
                "plan_log": (pout2 + pe2)[-MAX_LOG:],
            }
        sid_m2 = SID_RE.search(pout2)
        if not sid_m2:
            return {
                "rc": rc2, "pout": pout2, "pe": pe2, "sid": None,
                "auto_ids": auto_ids, "sealed_probe_count": len(combined2),
                "error": "no SID in second plan output",
                "plan_log": (pout2 + pe2)[-MAX_LOG:],
            }
        sid = sid_m2.group(1)
        rc, pout, pe = rc2, pout2, pe2
        sealed_probe_count = len(combined2)
        parsed2 = _parse_plan_log(pout2 + pe2)
        if parsed2 is None:
            # Second plan (post-union) staged but unparseable: abort that
            # session too, and refuse with a clear message.  The union
            # restage was wasted, but the router is left clean.
            abort_batch(lab, target, sid, lane=lane)
            msg = (
                "second plan log is unparseable after the union restage; "
                "the diff-union check cannot run, aborting the staged session"
            )
            return {
                "rc": 1, "pout": pout, "pe": "", "sid": None,
                "auto_ids": auto_ids,
                "sealed_probe_count": sealed_probe_count,
                "error": msg, "plan_log": msg,
            }
        diff_entries2 = newton_touched.derive_touched_entries(
            batch, parsed2["diff"], parsed2["sections"],
        )
        needs2, missing2 = newton_touched.needs_restage(
            sealed_entries2, diff_entries2,
        )
        if needs2:
            abort_batch(lab, target, sid, lane=lane)
            missing_ids = newton_touched.entry_ids(controls, missing2)
            msg = (
                "manifest checks keep needing more after the union; "
                f"aborting: control ids missing: {missing_ids!r}"
            )
            return {
                "rc": 1, "pout": pout, "pe": "", "sid": None,
                "auto_ids": auto_ids,
                "sealed_probe_count": sealed_probe_count,
                "error": msg,
                "plan_log": msg,
            }
        # diff-restage added the missing entries to the sealed set.
        for entry in missing:
            if entry not in sealed_entries:
                sealed_entries.append(entry)
        auto_ids = newton_touched.entry_ids(controls, sealed_entries)
    return {
        "rc": rc, "pout": pout, "pe": pe, "sid": sid,
        "auto_ids": auto_ids,
        "sealed_probe_count": sealed_probe_count,
        "error": None,
        "plan_log": (pout + pe)[-MAX_LOG:],
    }


def plan_batch(lab: Lab, target: Device, batch: str,
               probes: "list[list[str]] | None" = None,
               timeout_s: int = 90, lane: str = "password"
               ) -> tuple[int, str, str]:
    """Stage `batch` on `target`.

    Where the batch text travels: into a 0600 temp file, and only the file's
    PATH goes into argv -- argv is world-readable through
    /proc/<pid>/cmdline for as long as the process lives. scripts/owrt-change.sh
    opens that file and pipes it into `newton-router stage` over ssh STDIN
    (`r "$PROG stage" < "$F"`, and r() forwards its own stdin to ssh), so a
    batch holding a secret var reaches the router without ever being in an
    argument list, here or on the wrapper. The file is unlinked in the finally
    below. The probe file beside it is 0600 for the same reason.
    """
    env = build_env(lab, lane, target.name)
    fd, path = tempfile.mkstemp(suffix=".uci", prefix="newton-lab-")
    probe_path: str | None = None
    try:
        _write_0600(fd, path, batch)
        args = [str(OWRT_CHANGE), "plan", f"root@{target.host}", path,
                str(timeout_s)]
        if probes:
            pfd, probe_path = tempfile.mkstemp(suffix=".probes",
                                               prefix="newton-lab-")
            _write_0600(pfd, probe_path, probes_wire_bytes(probes))
            args.append(probe_path)
        # the installed transport runs here: owrt-change.sh over SSH
        _note_installed_transport()
        proc = _run(args, env=env, timeout=120)
        return proc.returncode, proc.stdout, proc.stderr
    finally:
        os.unlink(path)
        if probe_path is not None:
            os.unlink(probe_path)


def _approval_k(lab: Lab, device_name: str,
                cache: dict[str, str] | None) -> str:
    """K for one device, derived once per run when a cache is given."""
    if cache is not None and device_name in cache:
        return cache[device_name]
    pp = approve.read_passphrase_file(lab.approve_passphrase_file)
    k = approve.derive_k(pp, device_name)
    if cache is not None:
        cache[device_name] = k
    return k


def wrong_token(token: str) -> str:
    """A well-formed token whose last hex digit differs."""
    last = token[-1]
    return token[:-1] + ("0" if last != "0" else "1")


# SW2 Item 2: the v2 approval token binds the approval window, so every
# minted token needs a (not_before, not_after) pair and the wrapper needs
# both numbers.  1800 s is the window newton-approve mints; the router
# refuses any window longer than 3600 s and a token whose clock is more
# than 300 s ahead of its own.
APPROVAL_WINDOW_S = 1800


def approval_window() -> tuple[int, int]:
    """The (NBF, EXP) window a lab approval token is minted over: from
    now, for the 30-minute approval the host would create."""
    not_before = int(time.time())
    return not_before, not_before + APPROVAL_WINDOW_S


def approval_token_for(k_hex: str, digest: str,
                       window: tuple[int, int] | None = None) -> str:
    """approve.approval_token over a real window (one shared crypto)."""
    not_before, not_after = window if window is not None else approval_window()
    return approve.approval_token(k_hex, digest, not_before, not_after)


def client_check_env(scen: Scenario, sid: str) -> tuple[dict[str, str], Path]:
    inventory = Path(os.environ.get(
        "NEWTON_LAB_VANTAGE_INVENTORY",
        "~/.config/newton/lab-vantage/inventory.toml",
    )).expanduser()
    vantages = scans.load_vantages(inventory)
    local_check = client_checks.local_check_string(
        OWRT_CHANGE.parent / "newton-vantage-run", sid)
    spec = client_checks.build_spec(
        sid, scen.client_checks, vantages, scen.target)
    spec_path = client_checks.write_spec(RESULTS_DIR / "vantage-runs", spec)
    env = {
        "OWRT_LOCAL_CHECK": local_check,
        "NEWTON_VANTAGE_SPEC_DIR": str(spec_path.parent),
    }
    return env, spec_path


def apply_batch(lab: Lab, target: Device, sid: str, timeout_s: int,
                lane: str = "password",
                token: str | None = None,
                window: tuple[int, int] | None = None,
                extra_env: dict[str, str] | None = None) -> tuple[int, str, str]:
    env = build_env(lab, lane, target.name)
    if extra_env:
        env.update(extra_env)
    if token is not None:
        env["OWRT_APPROVAL_TOKEN"] = token
        # the window the token was minted over: the router recomputes
        # the HMAC over exactly these two numbers
        not_before, not_after = window if window is not None else approval_window()
        env["OWRT_APPROVAL_NBF"] = str(not_before)
        env["OWRT_APPROVAL_EXP"] = str(not_after)
    # the installed transport runs here: owrt-change.sh over SSH
    _note_installed_transport()
    proc = _run([str(OWRT_CHANGE), "apply",
                 f"root@{target.host}", sid, str(timeout_s)],
                env=env, timeout=timeout_s + 300)
    return proc.returncode, proc.stdout, proc.stderr


def abort_batch(lab: Lab, target: Device, sid: str,
                lane: str = "password") -> tuple[int, str, str]:
    """Abort a session the router refused to apply, so the router is clean
    for the posts and the next scenario."""
    env = build_env(lab, lane, target.name)
    proc = _run([str(OWRT_CHANGE), "abort", f"root@{target.host}", sid],
                env=env, timeout=120)
    return proc.returncode, proc.stdout, proc.stderr


# ---------- Outcome classification ----------

def classify_apply(rc: int, stdout: str, stderr: str, sid: str) -> str:
    escaped_sid = re.escape(sid)
    final = next((line for line in reversed(stdout.splitlines()) if line.strip()), "")
    if rc == 0 and re.match(rf"^CONFIRMED session={escaped_sid}(\s|$)", final):
        return "confirmed"
    if rc == 1 and re.match(rf"^ROLLBACK WINDOW PASSED session={escaped_sid}(\s|$)", final):
        return "rolled_back"
    # scripts/owrt-change.sh ends with this ALERT when the router rebooted inside
    # the window and the guard restored the config at boot: the not-compared
    # health reason comes from newton-router's `health: not compared: the router
    # rebooted during the window; the guard restored the config at boot`. The
    # match is anchored to the final line, this session, and that reason being
    # the ONLY rollback reason (a second reason is joined with "; " before the
    # " \u2014 check the router now" tail), so every other ALERT stays 'unknown'.
    if rc == 1 and re.match(
            rf"^ALERT session={escaped_sid} rolled back, but "
            r"service or firewall health was not compared after the rollback: "
            r"health: not compared: the router rebooted during the window; "
            r"the guard restored the config at boot \u2014 check the router now;",
            final):
        return "rebooted_restored"
    combined = stdout + "\n" + stderr
    if rc != 0 and "apply refused, nothing applied:" in combined:
        return "refused"
    # scripts/owrt-change.sh's apply-time health gate (around line 466) dies
    # with the same `nothing applied, session <SID> is still staged` shape as
    # the router-side apply refusal, but the wrapper and the helper's reason
    # differ. The wrapper carries `; helper said: ...` and is the router's
    # `the firewall config already fails fw4 check before the change` on
    # ev-10-fw4-already-broken. Other die texts that also contain
    # `nothing applied` (router unreachable, confighash failure, base mismatch,
    # ...) MUST stay 'unknown': they are not refused, and refuse_match against
    # them would silently turn a hard infrastructure error into a refused scenario.
    if rc != 0 and "cannot record service and firewall health before the apply; nothing applied" in combined:
        return "refused"
    return "unknown"


# ---------- Step / Post helpers ----------

def run_step(lab: Lab, step: Step,
             values: dict[str, str]) -> tuple[int | None, str, str]:
    """Run a setup/cleanup step. Returns (rc, cmd_substituted, stderr)."""
    cmd_sub = substitute(step.cmd, values)
    if step.device == "local":
        proc = _run(["bash", "-c", cmd_sub], env=_local_env(lab),
                    timeout=step.timeout)
        return proc.returncode, cmd_sub, proc.stderr
    if step.device in lab.devices:
        proc = _run(ssh_cmd(lab, lab.devices[step.device], cmd_sub),
                    timeout=step.timeout)
        return proc.returncode, cmd_sub, proc.stderr
    return 1, cmd_sub, f"unknown device: {step.device}"


def _exc_text(x: bytes | str | None) -> str:
    """Decode whatever TimeoutExpired carried back to str.
    `stdout`/`stderr` on the exception may be bytes (text mode does not change
    that for partial output), a str, or None; None becomes ""."""
    if x is None:
        return ""
    if isinstance(x, bytes):
        return x.decode("utf-8", errors="replace")
    return str(x)


def _tail(text: str, n: int = 200) -> str:
    """Last `n` characters of `text` with whitespace collapsed to single spaces
    so a one-line summary stays one line."""
    return " ".join(text.split())[-n:]


def _timed_out(p: Post, e: subprocess.TimeoutExpired) -> dict[str, Any]:
    """A probe or post that exceeds its timeout is a normal failed result."""
    return {
        "device": p.device, "cmd": p.cmd,
        "expect_rc": p.expect_rc, "expect_stdout": p.expect_stdout,
        "rc": None,
        "stdout": _exc_text(e.stdout)[-MAX_POST:],
        "stderr": _exc_text(e.stderr)[-MAX_POST:],
        "passed": False, "reason": f"timed out after {p.timeout}s",
    }


def run_post(lab: Lab, p: Post) -> dict[str, Any]:
    if p.device == "local":
        try:
            proc = _run(["bash", "-c", p.cmd], env=_local_env(lab),
                        timeout=p.timeout)
        except subprocess.TimeoutExpired as e:
            return _timed_out(p, e)
    elif p.device in lab.devices:
        try:
            proc = _run(ssh_cmd(lab, lab.devices[p.device], p.cmd),
                        timeout=p.timeout)
        except subprocess.TimeoutExpired as e:
            return _timed_out(p, e)
    else:
        return {
            "device": p.device, "cmd": p.cmd,
            "expect_rc": p.expect_rc, "expect_stdout": p.expect_stdout,
            "rc": None, "stdout": "", "stderr": f"unknown device: {p.device}",
            "passed": False, "reason": "unknown device",
        }
    rc_ok = proc.returncode == p.expect_rc
    regex_ok = True
    if p.expect_stdout is not None:
        regex_ok = re.search(p.expect_stdout, proc.stdout, re.MULTILINE) is not None
    passed = bool(rc_ok and regex_ok)
    reason = ""
    if not rc_ok:
        reason = f"rc {proc.returncode} != {p.expect_rc}"
    elif not regex_ok:
        reason = f"stdout did not match {p.expect_stdout!r}: {proc.stdout.strip()[:120]!r}"
    return {
        "device": p.device, "cmd": p.cmd,
        "expect_rc": p.expect_rc, "expect_stdout": p.expect_stdout,
        "rc": proc.returncode,
        "stdout": proc.stdout[-MAX_POST:],
        "stderr": proc.stderr[-MAX_POST:],
        "passed": passed, "reason": reason,
    }


def _record_probe(lab: Lab, p: "Check | Post", role: str, name: str,
                 want: str) -> dict[str, Any]:
    raw = run_post(lab, p)
    ok = raw["passed"] == (want == "pass")
    return {
        "role": role,
        "name": name,
        "device": raw["device"],
        "cmd": raw["cmd"],
        "rc": raw["rc"],
        "stdout": raw["stdout"],
        "stderr": raw["stderr"],
        "passed": raw["passed"],
        "want": want,
        "ok": ok,
        "reason": raw["reason"],
    }


def _run_probe_list(lab: Lab, items: list[tuple["Check | Post", str, str, str]],
                    target: list[dict[str, Any]] | None = None
                    ) -> list[dict[str, Any]]:
    """Run each probe in order. If `target` is given, append each result to it
    as soon as it exists so an exception leaves the completed records behind."""
    results: list[dict[str, Any]] = []
    for p, role, name, want in items:
        rec = _record_probe(lab, p, role, name, want)
        results.append(rec)
        if target is not None:
            target.append(rec)
    return results


def _build_before_probes(scen: Scenario, lab: Lab,
                         effects_sub: list[Post],
                         checks_sub: dict[str, Post],
                         breaks: list[str],
                         ) -> list[tuple[Any, str, str, str]]:
    items: list[tuple[Any, str, str, str]] = []
    for cn in _resolved_regression(scen, lab):
        items.append((checks_sub[cn], "regression", cn, "pass"))
    for cn in breaks:
        items.append((checks_sub[cn], "breaks", cn, "pass"))
    for i, e in enumerate(effects_sub):
        items.append((e, "effect", f"effect[{i}]", "fail"))
    return items


def _build_after_probes(scen: Scenario, lab: Lab, outcome: str,
                        effects_sub: list[Post],
                        checks_sub: dict[str, Post],
                        breaks: list[str],
                        ) -> list[tuple[Any, str, str, str]]:
    items: list[tuple[Any, str, str, str]] = []
    breaks_set = set(breaks)
    if outcome == "confirmed":
        # A check named in both regression and breaks is covered once by the
        # breaks loop below; skip it under the regression role so it doesn't
        # run twice in AFTER.
        for cn in _resolved_regression(scen, lab):
            if cn in breaks_set:
                continue
            items.append((checks_sub[cn], "regression", cn, "pass"))
        for cn in breaks:
            items.append((checks_sub[cn], "breaks", cn, "fail"))
        for i, e in enumerate(effects_sub):
            items.append((e, "effect", f"effect[{i}]", "pass"))
    else:
        for cn in _resolved_regression(scen, lab):
            items.append((checks_sub[cn], "regression", cn, "pass"))
        for cn in breaks:
            items.append((checks_sub[cn], "breaks", cn, "pass"))
        for i, e in enumerate(effects_sub):
            items.append((e, "effect", f"effect[{i}]", "fail"))
    return items


# ---------- Per-scenario runner ----------


def _resolve_applies_base(rec: dict[str, Any], pout: str, aout: str,
                          ) -> bool:
    """Design 9.4 G3: apply-time base equals the sealed base.  Sets
    ``rec["base"]`` when both lines are present, sets ``rec["error"]``
    on mismatch, sets ``rec["error"]`` when an apply was
    confirmed/rolled_back/rebooted_restored but emitted no APPLYBASE.  Returns True iff
    the call left the rec in a consistent state (no error set)."""
    apply_base_m = APPLYBASE_RE.search(aout)
    plan_base_m = BASEHASH_RE.search(pout)
    if apply_base_m is not None and plan_base_m is not None:
        plan_b = plan_base_m.group(1)
        apply_b = apply_base_m.group(1)
        rec["base"] = {"plan": plan_b, "apply": apply_b,
                       "match": plan_b == apply_b}
        if plan_b != apply_b:
            rec["error"] = (
                f"apply-time base {apply_b} != plan BASEHASH {plan_b}")
            return False
        return True
    if apply_base_m is None and rec.get("outcome") in (
            "confirmed", "rolled_back", "rebooted_restored"):
        rec["error"] = (
            f"outcome {rec['outcome']} but no APPLYBASE line in "
            f"apply stdout")
        return False
    return True


def _plan_apply_one_batch(lab: Lab, target: Device, batch_text: str,
                          scenario_probes: list[list[str]],
                          scen: Scenario, scen_log: dict[str, Any],
                          lane: str,
                          k_cache: dict[str, str] | None,
                          *, approval_mode: str = "scenario") -> tuple[
                              str, list[str], list[str], str | None]:
    """Plan + apply one batch through the tier pipeline.

    ``approval_mode`` selects the approval rule:

    * ``"scenario"`` (default): the scenario's ``approval`` flag drives
      token minting, and a mismatch with the router's APPROVAL line is
      an ERROR (the normal-path G3 self-check; the tier runner never
      passes this value today).
    * ``"auto"``: used by the tier runner.  The router's APPROVAL line
      alone decides: mint a token iff it says required, no token
      otherwise.  ``scen.approval`` is ignored, and a tier run NEVER
      fails because of it.  A missing PLANDIGEST when approval is
      required is still an error.

    On success the returned tuple is ``(outcome, auto_ids,
    sealed_probe_count, None)``; ``outcome`` is
    ``"confirmed"|"rolled_back"|"refused"`` and the call has run the G3
    BASEHASH/APPLYBASE check (mutating ``scen_log``).

    On a pre-apply failure the returned tuple is ``(error_outcome, [],
    0, reason)`` with ``error_outcome`` being
    ``"rejected"|"noop"|"error"``; ``reason`` names the failure.

    Per-batch evidence is written to ``scen_log``: ``plan_log`` (last
    MAX_LOG chars of the router's plan output), ``apply_log`` (last
    MAX_LOG chars of the router's apply output), and ``approval_required``
    (bool: the router's line).  The tier runner reads these to populate
    each per-batch / per-survival / rollback record.
    """
    plan = _apply_touched_to_plan(
        lab, target, batch_text, scenario_probes,
        scen.timeout, lane,
    )
    if plan["error"] is not None:
        return "error", [], plan["sealed_probe_count"], plan["error"]
    if plan["rc"] != 0:
        combined = plan["pout"] + "\n" + plan["pe"]
        if "no changes staged" in combined:
            return "noop", plan["auto_ids"], plan["sealed_probe_count"], None
        if _plan_rejected(combined):
            return ("rejected", plan["auto_ids"],
                    plan["sealed_probe_count"], None)
        return ("error", plan["auto_ids"],
                plan["sealed_probe_count"],
                f"plan failed (rc={plan['rc']}): {_tail(combined)}")
    sid = plan["sid"]
    if not sid:
        return "error", plan["auto_ids"], plan["sealed_probe_count"], \
            "no SID in plan output"
    # Per-batch evidence for the tier records: plan_log (last MAX_LOG
    # chars of the plan output) and the router's APPROVAL line.
    scen_log["plan_log"] = plan["plan_log"]
    appr_line = APPROVAL_RE.search(plan["pout"])
    router_requires = bool(appr_line
                           and appr_line.group(1) == "required")
    scen_log["approval_required"] = router_requires
    # G3 self-check + token minting, branched on approval_mode.
    # SW2 Item 2: the token binds the window, so the window is fixed once
    # here and both the token and the apply env carry it.
    token: str | None = None
    window: tuple[int, int] | None = None
    if approval_mode == "scenario":
        # Original behaviour: the scenario's approval flag must agree with
        # the router's APPROVAL line, and ``approval in (True, "wrong")``
        # mints (or flips) a token.  Tier runs never use this branch.
        if router_requires and scen.approval is None:
            return ("error", plan["auto_ids"], plan["sealed_probe_count"],
                    "scenario needs approval = true: the router "
                    "says APPROVAL required")
        if scen.approval is True and not router_requires:
            return ("error", plan["auto_ids"], plan["sealed_probe_count"],
                    "approval = true but the router says not-required")
        if scen.approval in (True, "wrong"):
            dig_m = PLANDIGEST_RE.search(plan["pout"])
            if not dig_m:
                return ("error", plan["auto_ids"],
                        plan["sealed_probe_count"],
                        "no PLANDIGEST in plan output")
            k = _approval_k(lab, target.name, k_cache)
            window = approval_window()
            token = approval_token_for(k, dig_m.group(1), window)
            if scen.approval == "wrong":
                token = wrong_token(token)
    else:
        # Tier ("auto") mode.  The runner follows the router's lead on
        # every batch: mint iff required, no token otherwise.  scen.approval
        # is ignored (a tier scenario will not set it; even if it does, it
        # has no effect in this branch).
        if router_requires:
            dig_m = PLANDIGEST_RE.search(plan["pout"])
            if not dig_m:
                return ("error", plan["auto_ids"],
                        plan["sealed_probe_count"],
                        "no PLANDIGEST in plan output")
            k = _approval_k(lab, target.name, k_cache)
            window = approval_window()
            token = approval_token_for(k, dig_m.group(1), window)
    rc, aout, aerr = apply_batch(lab, target, sid, scen.timeout,
                                 lane=lane, token=token, window=window)
    scen_log["apply_log"] = (aout + aerr)[-MAX_LOG:]
    outcome = classify_apply(rc, aout, aerr, sid)
    if outcome == "refused":
        abort_batch(lab, target, sid, lane=lane)
    return outcome, plan["auto_ids"], plan["sealed_probe_count"], None


def _run_tier(lab: Lab, scen: Scenario, rec: dict[str, Any],
              values: dict[str, str], lane: str,
              k_cache: dict[str, str] | None) -> None:
    """Tier run: split the tier, resolve placeholders per batch, plan +
    apply every batch (with approval token when required), the rollback
    check on the LAST batch FIRST (if tier_fail_probe), the REBOOT step
    (when tier_reboot), and SURVIVAL re-applies each batch's sealed
    manifest probes after the reboot.

    The function mutates ``rec["outcome"]``, ``rec["error"]``,
    ``rec["tier"]``, ``rec["manifest_checks_auto"]``, and
    ``rec["sealed_probe_count"]`` (the same fields the normal path
    sets).  When the function returns without raising, ``rec`` is in a
    consistent state for the AFTER / POST phase.
    """
    rec["tier"] = {
        "name": scen.tier,
        "batches": [],
        "skipped": [],
        "survival": [],
        "rollback": None,
    }
    target = lab.devices[scen.target]

    # 1. split the tier.
    try:
        split = newton_tiers.split_tier(
            scen.tier, max_lines=scen.tier_batch_lines,
        )
    except newton_tiers.TierError as e:
        rec["error"] = f"tier split failed: {e}"
        rec["outcome"] = "error"
        return
    rec["tier"]["skipped"] = split["skipped"]
    batches: list[dict[str, Any]] = split["batches"]
    # Zero batches (all blocks skipped / empty / lab-bound) means the
    # splitter produced nothing for the runner to apply.  The probe /
    # survival phase below would have nothing to seal, so refuse here.
    if not batches:
        rec["error"] = f"tier {scen.tier} has no batches"
        return

    # 2. substitute tier_values with the [vars]-resolved values.
    tier_values_substituted: dict[str, str] = {}
    for k, v in (scen.tier_values or {}).items():
        tier_values_substituted[k] = substitute(v, values)
    # The union of placeholders over all batches is the gate: every
    # batch's reference must have a value (resolve_batch will refuse).
    tier_names: list[str] = []
    seen_names: set[str] = set()
    for batch in batches:
        for n in newton_tiers.tier_placeholders(batch["text"]):
            if n not in seen_names:
                seen_names.add(n)
                tier_names.append(n)

    # 3. resolve placeholders in each batch.
    resolved: list[dict[str, Any]] = []
    for batch in batches:
        try:
            resolved_text = newton_tiers.resolve_batch(
                batch["text"], tier_values_substituted,
                tier_names=tier_names,
            )
        except newton_tiers.TierError as e:
            rec["error"] = f"tier placeholder resolution failed: {e}"
            rec["outcome"] = "error"
            return
        resolved.append({
            "index": batch["index"],
            "control_ids": batch["control_ids"],
            "text": resolved_text,
            "tier_placeholders": batch.get("placeholders", []),
            "probe_lines": batch.get("probe_lines"),
        })

    # 4. rollback check on the LAST batch FIRST (only if tier_fail_probe
    # is set).  The dry-run must roll back; the uci-export md5sum must
    # be identical before/after.
    if scen.tier_fail_probe and resolved:
        last = resolved[-1]
        rec["tier"]["rollback"] = {
            "batch_index": last["index"],
            "outcome": None,
            "hash_before": None,
            "hash_after": None,
            "equal": None,
            "plan_log": "",
            "apply_log": "",
            "approval_required": None,
        }
        # hash before: helper refuses on rc != 0, empty stdout, the md5
        # of empty, or a non-hex digest -- the helper's ValueError is
        # the only failure mode the runner has to translate.
        try:
            h0 = _uci_export_hash(lab, target)
        except ValueError as e:
            rec["error"] = (f"tier rollback hash before failed: "
                            f"{type(e).__name__}: {e}")
            rec["outcome"] = "error"
            return
        rec["tier"]["rollback"]["hash_before"] = h0
        # plan + apply with the fail probe as a scenario probe.  The
        # rollback record carries the per-batch evidence (plan_log,
        # apply_log, approval_required) for this dry run, distinct from
        # the regular-batch evidence the loop below records.
        rollback_log: dict[str, Any] = {}
        outcome, _auto_ids, _spc, reason = _plan_apply_one_batch(
            lab, target, last["text"], [scen.tier_fail_probe],
            scen, rollback_log, lane, k_cache,
            approval_mode="auto",
        )
        rec["tier"]["rollback"]["plan_log"] = rollback_log.get("plan_log", "")
        rec["tier"]["rollback"]["apply_log"] = rollback_log.get("apply_log", "")
        rec["tier"]["rollback"]["approval_required"] = (
            rollback_log.get("approval_required"))
        rec["tier"]["rollback"]["outcome"] = outcome
        if reason is not None:
            rec["error"] = f"tier rollback probe failed: {reason}"
            rec["outcome"] = "error"
            return
        # NOTE: do NOT promote the rollback probe's outcome onto
        # rec["outcome"] here.  The probe is a dry run; the real batch
        # apply (and any subsequent failure) is what determines
        # rec["outcome"], set in the final 'all confirmed' block at the
        # end of this function.  Promoting the probe outcome would
        # wrongly mark a tier 'rolled_back' when the probe rolled back
        # but a later real batch errored.
        if outcome != "rolled_back":
            rec["error"] = (f"tier rollback probe: expected rolled_back, "
                            f"got {outcome}")
            return
        # hash after
        try:
            h1 = _uci_export_hash(lab, target)
        except ValueError as e:
            rec["error"] = (f"tier rollback hash after failed: "
                            f"{type(e).__name__}: {e}")
            rec["outcome"] = "error"
            return
        rec["tier"]["rollback"]["hash_after"] = h1
        rec["tier"]["rollback"]["equal"] = (h0 == h1)
        if h0 != h1:
            rec["error"] = (f"tier rollback hash differs: before={h0}"
                            f" after={h1}")
            rec["outcome"] = "error"
            return

    # 5. every batch in order.
    total_sealed = 0
    all_auto_ids: list[str] = []
    for batch in resolved:
        scen_log: dict[str, Any] = {}
        outcome, auto_ids, spc, reason = _plan_apply_one_batch(
            lab, target, batch["text"], [],
            scen, scen_log, lane, k_cache,
            approval_mode="auto",
        )
        total_sealed += spc
        if auto_ids:
            all_auto_ids.extend(auto_ids)
        # The G3 BASEHASH/APPLYBASE check needs rec["outcome"] to be set
        # before running; mirror what the normal path does.  For the
        # "error" outcome (reason set), rec["outcome"] stays None so the
        # scenario rec mirrors the normal path's behavior on plan/apply
        # failures.
        if outcome != "error":
            rec["outcome"] = outcome
        rec["plan_log"] = scen_log.get("plan_log", "")
        if scen_log.get("apply_log"):
            rec["apply_log"] = scen_log["apply_log"]
        ok = _resolve_applies_base(rec, scen_log.get("plan_log", ""),
                                   scen_log.get("apply_log", "") or "")
        if not ok:
            rec["outcome"] = outcome
            return
        rec["tier"]["batches"].append({
            "index": batch["index"],
            "control_ids": batch["control_ids"],
            "sealed_probe_count": spc,
            "auto_ids": list(auto_ids),
            "outcome": outcome,
            "plan_log": scen_log.get("plan_log", ""),
            "apply_log": scen_log.get("apply_log", ""),
            "approval_required": scen_log.get("approval_required"),
        })
        if reason is not None:
            rec["error"] = (f"tier batch {batch['index']} failed: {reason}")
            # rec["outcome"] stays None for error outcomes (the normal
            # path's plan/apply failures leave it None too).
            return
        if outcome != "confirmed":
            rec["error"] = (f"tier batch {batch['index']} outcome "
                            f"{outcome}")
            return

    if all_auto_ids:
        rec["manifest_checks_auto"] = list(all_auto_ids)
    rec["sealed_probe_count"] = total_sealed

    # 6. REBOOT step.
    if scen.tier_reboot:
        rb = reboot_device(lab, target, [], lane)
        rec["tier"]["reboot"] = rb
        if not rb.get("ok"):
            rec["error"] = (f"tier reboot failed: "
                            f"{rb.get('reason', 'no reason')}")
            rec["outcome"] = "error"
            return

        # 7. SURVIVAL: re-run each batch's sealed manifest probes after
        # the reboot.  The router's own verify runs every probe on the
        # rebooted system; the marker batch is just enough to make it
        # verify them.  The survival log dict is named differently from
        # the regular-batch scen_log so each name is annotated once
        # (avoids the re-annotation lint smell).
        for batch in resolved:
            marker = (
                f"set system.@system[0].description="
                f"'tier-survival-{batch['index']}'\n"
            )
            # Rebuild the same manifest probes the plan would seal for
            # this batch's text.  A seal error here aborts the survival
            # immediately: the manifest could not be derived from this
            # batch, so re-running its probes is unsafe.
            sealed_entries, manifest_probes, seal_err = (
                _derive_touched_probe_lines(batch["text"], [])
            )
            if seal_err is not None:
                rec["error"] = seal_err
                return
            # The plan would seal exactly the splitter's probe_lines
            # for this batch's text.  If the survival step's derivation
            # produced a different count, the splitter and the
            # survival re-derivation disagree -- refuse rather than run
            # the wrong probe set on the rebooted router.
            expected = batch.get("probe_lines")
            if (expected is not None
                    and len(manifest_probes) != expected):
                rec["error"] = (
                    f"survival probe count {len(manifest_probes)}"
                    f" != splitter count {expected}"
                )
                return
            survival_log: dict[str, Any] = {}
            outcome, auto_ids, spc, reason = _plan_apply_one_batch(
                lab, target, marker, manifest_probes,
                scen, survival_log, lane, k_cache,
                approval_mode="auto",
            )
            rec["tier"]["survival"].append({
                "batch_index": batch["index"],
                "probe_count": len(manifest_probes),
                "outcome": outcome,
                "plan_log": survival_log.get("plan_log", ""),
                "apply_log": survival_log.get("apply_log", ""),
                "approval_required": survival_log.get("approval_required"),
            })
            if reason is not None:
                rec["error"] = (f"tier survival batch "
                                f"{batch['index']} failed: {reason}")
                rec["outcome"] = outcome
                return
            if outcome != "confirmed":
                rec["error"] = (f"tier survival batch "
                                f"{batch['index']} outcome {outcome}")
                rec["outcome"] = outcome
                return

    # 8. all confirmed
    rec["outcome"] = "confirmed"


def _run_scenario_inner(lab: Lab, scen: Scenario, rec: dict[str, Any],
                        t0: float, state: dict[str, Any],
                        lane: str = "password",
                        k_cache: dict[str, str] | None = None) -> None:
    """Run steps 1-7 of a scenario. Sets state["setup_started"] = True as
    soon as step 3 begins, so the caller can decide in its `finally` whether
    to run cleanup. Exceptions propagate to the caller; the caller records
    f"{type(e).__name__}: {e}" and runs cleanup iff state["setup_started"].

    Sets state["no_device_contact"] = True when the scenario is refused
    before step 1, so the caller resets nothing after it, and
    state["after_reset_checks"] to the substituted checks step 10 runs."""
    expect = scen.effective_expect(lane)
    breaks = scen.effective_breaks(lane)

    # 0. a secret var may only be substituted into the batch. Refuse the
    # scenario here, before the reset or any var cmd reaches a device.
    violations = secret_scope_violations(lab, scen, lane)
    if violations:
        rec["error"] = violations[0]
        state["no_device_contact"] = True
        rec["duration_s"] = round(time.monotonic() - t0, 3)
        return

    # 1. reset
    for dname in scen.reset:
        last = reset_device(lab, dname, rec["reset"])
        if not last["task_ok"]:
            if last.get("abort_run"):
                rec["abort_run"] = True
            rec["error"] = (
                f"reset of {dname} did not finish OK "
                f"(upid={last['upid']}, exitstatus={last['exitstatus']}, "
                f"attempt {last['attempt']} of {RESET_MAX_ATTEMPTS})")
            rec["duration_s"] = round(time.monotonic() - t0, 3)
            return
        if lab.devices[dname].is_physical:
            # physical_reset already waited for ssh, settled and verified
            rec["settle"].append(last.get("settle") or {})
            if needs_hello_preflight(lab.devices[dname], lane):
                ok, detail = router_hello_preflight(lab, lab.devices[dname])
                if not ok:
                    rec["abort_run"] = True
                    rec["error"] = (
                        f"{dname} hello preflight failed: {detail}; "
                        f"{preflight_stop_text(lab.devices[dname])}")
                    rec["duration_s"] = round(time.monotonic() - t0, 3)
                    return
            continue
        if not ssh_ready(lab, lab.devices[dname]):
            rec["error"] = f"ssh to {dname} not ready after reset"
            rec["duration_s"] = round(time.monotonic() - t0, 3)
            return
        if lane == "key" and lab.devices[dname].snapshot.startswith(
                NEWTON_SNAPSHOT_PREFIX):
            ok, detail = router_hello_preflight(lab, lab.devices[dname])
            if not ok:
                rec["error"] = (
                    f"{dname} hello preflight failed: {detail}; "
                    f"{PREFLIGHT_STOP_TEXT}")
                rec["duration_s"] = round(time.monotonic() - t0, 3)
                return
        settle_rec = wait_settled(lab, dname)
        rec["settle"].append(settle_rec)
        if settle_rec["settled"] is False:
            rec["error"] = (
                f"{dname} did not settle within {lab.settle_timeout_s:g}s "
                f"(changes={settle_rec['changes']}, "
                f"last_rc={settle_rec['last_rc']})")
            rec["duration_s"] = round(time.monotonic() - t0, 3)
            return

    # 2. var resolution
    posts_src = [p for p in scen.post if p.runs_in_lane(lane)]
    effects_src = [e for e in scen.effects if e.runs_in_lane(lane)]
    texts: list[str] = [scen.batch]
    for probe in scen.probes:
        texts.extend(probe)
    # tier_values may themselves reference [vars] placeholders; pull the
    # placeholders out of them and resolve them through the same [vars]
    # machinery before the tier split substitutes the resolved values.
    for _vk, _vv in (scen.tier_values or {}).items():
        texts.append(_vv)
    for p in posts_src:
        texts.append(p.cmd)
    for e in effects_src:
        texts.append(e.cmd)
    for cn in _resolved_regression(scen, lab):
        texts.append(lab.checks[cn].cmd)
    for cn in breaks:
        texts.append(lab.checks[cn].cmd)
    for cn in scen.after_reset:
        texts.append(lab.checks[cn].cmd)
    for sn in scen.setup:
        texts.append(lab.steps[sn].cmd)
    for sn in scen.cleanup:
        texts.append(lab.steps[sn].cmd)
    used = used_placeholders(*texts)
    values, err = resolve_vars(lab, used)
    if err:
        rec["error"] = err
        rec["duration_s"] = round(time.monotonic() - t0, 3)
        return
    # A secret var's value is remembered for the masking passes and recorded
    # as SECRET_PLACEHOLDER; it reaches the router in the batch alone (step 0
    # refused every cmd that would have put it in ssh argv). `values` itself
    # stays the real thing: the substitutions below need it.
    for vname in values:
        if lab.var_defs.get(vname, {}).get("secret"):
            register_secret(values[vname])
    rec["vars"] = {
        vname: (SECRET_PLACEHOLDER
                if lab.var_defs.get(vname, {}).get("secret") else value)
        for vname, value in values.items()}
    batch = substitute(scen.batch, values)
    probes_sub = [[substitute(f, values) for f in probe]
                  for probe in scen.probes]
    posts = [Post(p.device, substitute(p.cmd, values),
                  p.expect_rc, p.expect_stdout, p.timeout) for p in posts_src]
    effects_sub = [Post(p.device, substitute(p.cmd, values),
                          p.expect_rc, p.expect_stdout, p.timeout)
                   for p in effects_src]
    # Substitute placeholders inside every referenced check's cmd so the
    # substituted cmd is what ssh receives in BEFORE and AFTER, and what
    # rec["before"/[i]["cmd"] records.
    checks_sub: dict[str, Post] = {}
    for cn in (list(_resolved_regression(scen, lab)) + list(breaks)
               + list(scen.after_reset)):
        c = lab.checks[cn]
        checks_sub[cn] = Post(c.device, substitute(c.cmd, values),
                               c.expect_rc, c.expect_stdout, c.timeout)
    # Step 10 runs from run_scenario's finally, past everything else, so the
    # substituted after_reset checks travel out in `state` rather than in a
    # local. A scenario that errored before here leaves it empty and runs
    # none.
    state["after_reset_checks"] = {cn: checks_sub[cn]
                                   for cn in scen.after_reset}

    # 3. setup — set the marker BEFORE running any setup step so a step that
    # raises still triggers cleanup.
    state["setup_started"] = True
    setup_error: str | None = None
    for sn in scen.setup:
        step = lab.steps[sn]
        rc, cmd_sub, stderr = run_step(lab, step, values)
        rec["setup"].append({
            "name": sn,
            "device": step.device,
            "cmd": cmd_sub,
            "rc": rc,
            "stderr": stderr[-MAX_POST:],
            "passed": rc == 0,
        })
        if rc != 0:
            tail = (stderr or "").strip()[-200:]
            setup_error = f"setup {sn} failed (rc={rc}): {tail}"
            break
    if setup_error is not None:
        rec["error"] = setup_error
        rec["duration_s"] = round(time.monotonic() - t0, 3)
        return

    # 4. BEFORE probes
    before_items = _build_before_probes(scen, lab, effects_sub, checks_sub,
                                        breaks)
    rec["before"] = []
    before_results = _run_probe_list(lab, before_items, target=rec["before"])
    bad_before = [b for b in before_results if not b["ok"]]
    if bad_before:
        first = bad_before[0]
        if first["role"] == "effect":
            why = "already passes before apply; it cannot detect the change"
        else:
            why = first["reason"] or "probe failed"
        rec["error"] = f"before: {first['role']} {first['name']}: {why}"
        rec["duration_s"] = round(time.monotonic() - t0, 3)
        return

    # 5. plan / apply
    if scen.tier is not None:
        _run_tier(lab, scen, rec, values, lane, k_cache)
        # When _run_tier leaves rec["error"] set, the tier run is
        # already a failure: skip the AFTER probes and POST checks
        # (the router is in an unknown state, the AFTER probes'
        # want='pass' may not be the truth, and the POST commands
        # may fail for unrelated reasons that would muddy the
        # failure record).  Set rec["duration_s"] like the other
        # early-error paths and return; rec["passed"] stays False
        # (the run_scenario finally enforces that).
        if rec.get("error"):
            rec["duration_s"] = round(time.monotonic() - t0, 3)
            return
    elif not scen.batch.strip():
        rec["outcome"] = "none"
    else:
        target = lab.devices[scen.target]
        # ADR-010: the touched-control wiring derives the manifest probes
        # from the batch alone, prepends them to the scenario's own probes,
        # applies the same cap refusal the MCP server uses, and runs the
        # diff-union restage so a control surfaced only by the router's
        # diff still gets sealed.
        plan = _apply_touched_to_plan(
            lab, target, batch, probes_sub,
            scen.timeout, lane,
        )
        rc = plan["rc"]
        pout = plan["pout"]
        pe = plan["pe"]
        rec["plan_log"] = plan["plan_log"]
        if plan["auto_ids"]:
            rec["manifest_checks_auto"] = plan["auto_ids"]
        rec["sealed_probe_count"] = plan["sealed_probe_count"]
        if plan["error"] is not None:
            rec["error"] = plan["error"]
            rec["duration_s"] = round(time.monotonic() - t0, 3)
            return
        if rc != 0:
            combined = pout + "\n" + pe
            if "no changes staged" in combined:
                rec["outcome"] = "noop"
            elif _plan_rejected(combined):
                rec["outcome"] = "rejected"
                if scen.reject_match is not None:
                    rec["reject"] = {
                        "pattern": scen.reject_match,
                        "matched": re.search(
                            scen.reject_match, pout + "\n" + pe,
                            re.MULTILINE) is not None,
                    }
            else:
                rec["error"] = f"plan failed (rc={rc}): {_tail(combined)}"
                rec["duration_s"] = round(time.monotonic() - t0, 3)
                return
        else:
            sid = plan["sid"]
            if not sid:
                rec["error"] = "no SID in plan output"
                rec["duration_s"] = round(time.monotonic() - t0, 3)
                return
            # G3 self-check: the router's APPROVAL line vs the scenario's flag
            appr_line = APPROVAL_RE.search(pout)
            router_requires = bool(appr_line
                                   and appr_line.group(1) == "required")
            if router_requires and scen.approval is None:
                rec["error"] = ("scenario needs approval = true: the router "
                                "says APPROVAL required")
                rec["duration_s"] = round(time.monotonic() - t0, 3)
                return
            if scen.approval is True and not router_requires:
                rec["error"] = ("approval = true but the router says "
                                "not-required")
                rec["duration_s"] = round(time.monotonic() - t0, 3)
                return
            if scen.plan_match is not None:
                rec["plan_match"] = {
                    "pattern": scen.plan_match,
                    "matched": re.search(
                        scen.plan_match, pout + "\n" + pe,
                        re.MULTILINE) is not None,
                }
            token: str | None = None
            window: tuple[int, int] | None = None
            if scen.approval in (True, "wrong"):
                dig_m = PLANDIGEST_RE.search(pout)
                if not dig_m:
                    rec["error"] = "no PLANDIGEST in plan output"
                    rec["duration_s"] = round(time.monotonic() - t0, 3)
                    return
                k = _approval_k(lab, target.name, k_cache)
                window = approval_window()
                token = approval_token_for(k, dig_m.group(1), window)
                if scen.approval == "wrong":
                    token = wrong_token(token)
            extra_env: dict[str, str] | None = None
            spec_path: Path | None = None
            if scen.client_checks:
                try:
                    extra_env, spec_path = client_check_env(scen, sid)
                except Exception as exc:
                    rec["error"] = (
                        f"client checks could not be prepared: "
                        f"{type(exc).__name__}: {exc}")
                    rec["duration_s"] = round(time.monotonic() - t0, 3)
                    return
            try:
                rc, aout, aerr = apply_batch(
                    lab, target, sid, scen.timeout, lane=lane, token=token,
                    window=window, extra_env=extra_env)
            finally:
                if spec_path is not None:
                    spec_path.unlink(missing_ok=True)
            rec["apply_log"] = (aout + aerr)[-MAX_LOG:]
            rec["outcome"] = classify_apply(rc, aout, aerr, sid)
            if scen.client_checks:
                failed = explanation.failed_claim(
                    aout, sid, [], scen.client_checks)
                rec["failed_claim"] = failed
                if scen.expect_failed_claim is not None:
                    failed_text = failed["text"] if failed is not None else ""
                    if (rec["outcome"] != "rolled_back"
                            or failed is None
                            or re.search(scen.expect_failed_claim, failed_text)
                            is None):
                        rec["error"] = (
                            "expect_failed_claim did not match: "
                            f"outcome={rec['outcome']}, "
                            f"failed_claim={failed_text or 'none'}")
                if rec["outcome"] == "confirmed":
                    rec["client_checks_confirmed"] = True
            # Design 9.4 G3: the apply-time base equals the sealed base.
            # Parse from the FULL apply/plan stdout (not the MAX_LOG-truncated
            # apply_log); a confirmed/rolled_back apply with no APPLYBASE, or
            # a BASEHASH/APPLYBASE mismatch, fails the scenario. Scenarios
            # that never reach apply (rejected, noop, none) keep no rec["base"].
            apply_base_m = APPLYBASE_RE.search(aout)
            plan_base_m = BASEHASH_RE.search(pout)
            if apply_base_m is not None and plan_base_m is not None:
                plan_b = plan_base_m.group(1)
                apply_b = apply_base_m.group(1)
                rec["base"] = {"plan": plan_b, "apply": apply_b,
                               "match": plan_b == apply_b}
                if plan_b != apply_b:
                    rec["error"] = (
                        f"apply-time base {apply_b} != plan BASEHASH {plan_b}")
                    rec["duration_s"] = round(time.monotonic() - t0, 3)
                    return
            elif apply_base_m is None and rec["outcome"] in (
                    "confirmed", "rolled_back", "rebooted_restored"):
                rec["error"] = (
                    f"outcome {rec['outcome']} but no APPLYBASE line in "
                    f"apply stdout")
                rec["duration_s"] = round(time.monotonic() - t0, 3)
                return
            if rec["outcome"] == "refused":
                # the router left the session staged; clean it so the posts
                # and the next scenario see a clean router
                abort_batch(lab, target, sid, lane=lane)
                if scen.refuse_match is not None:
                    rec["refuse"] = {
                        "pattern": scen.refuse_match,
                        "matched": re.search(
                            scen.refuse_match, aout + "\n" + aerr,
                            re.MULTILINE) is not None,
                    }

    # 6. AFTER probes
    after_items = _build_after_probes(scen, lab, rec["outcome"],
                                      effects_sub, checks_sub, breaks)
    rec["after"] = []
    after_results = _run_probe_list(lab, after_items, target=rec["after"])
    all_after_ok = all(a["ok"] for a in after_results)

    # 7. post — append each result as it completes so an exception mid-loop
    # leaves the completed records in rec["post"].
    rec["post"] = []
    for p in posts:
        rec["post"].append(run_post(lab, p))
    all_post_ok = all(pr["passed"] for pr in rec["post"])

    reject_ok = (rec["reject"] is None
                 or rec["reject"].get("matched") is True)
    plan_ok = (rec.get("plan_match") is None
               or rec["plan_match"].get("matched") is True)
    refuse_ok = (rec["refuse"] is None
                 or rec["refuse"].get("matched") is True)
    rec["passed"] = bool(
        rec["outcome"] == expect
        and reject_ok
        and plan_ok
        and refuse_ok
        and all_after_ok
        and all_post_ok)
    rec["duration_s"] = round(time.monotonic() - t0, 3)


def _run_cleanup(lab: Lab, scen: Scenario, rec: dict[str, Any]) -> None:
    """Run the scenario's cleanup steps, each guarded by its own try/except.
    Failures (rc != 0 or an exception) append a rec["cleanup"] entry and set
    rec["error"] only if no earlier error exists."""
    cleanup_values = rec.get("vars", {}) or {}
    for sn in scen.cleanup:
        cmd = sn
        device = "?"
        try:
            step = lab.steps[sn]
            cmd = substitute(step.cmd, cleanup_values)
            device = step.device
            rc, _, stderr = run_step(lab, step, cleanup_values)
            rec["cleanup"].append({
                "name": sn,
                "device": device,
                "cmd": cmd,
                "rc": rc,
                "stderr": stderr[-MAX_POST:],
                "passed": rc == 0,
            })
            if rc != 0 and not rec.get("error"):
                tail = (stderr or "").strip()[-200:]
                rec["error"] = f"cleanup {sn} failed (rc={rc}): {tail}"
        except Exception as e:
            tail = f"{type(e).__name__}: {e}"
            rec["cleanup"].append({
                "name": sn,
                "device": device,
                "cmd": cmd,
                "rc": None,
                "stderr": tail[-MAX_POST:],
                "passed": False,
            })
            if not rec.get("error"):
                rec["error"] = f"cleanup {sn} failed (rc=None): {tail}"


def _run_reset_after(lab: Lab, scen: Scenario, rec: dict[str, Any]) -> None:
    """Run the scenario's `reset_after` devices: the same reset_device() the
    scenario got at the start, per named device, in the declared order, after
    the posts and the cleanup. Every attempt is appended to rec["reset_after"]
    as it finishes, so a failure (or an exception) in a later device leaves the
    earlier records behind.

    A reset that did not finish OK fails the scenario: rec["error"] is set
    when no earlier error exists (an earlier failure is never hidden), and
    rec["abort_run"] is set when the record carries it, exactly as at the start
    of a scenario, so a physical post-restore fingerprint mismatch stops the
    run after this scenario."""
    for dname in scen.reset_after:
        try:
            last = reset_device(lab, dname, rec["reset_after"])
        except Exception as e:
            rec["reset_after"].append({
                "device": dname, "upid": None, "task_ok": False,
                "exitstatus": None, "attempt": 0,
                "error": f"{type(e).__name__}: {e}",
            })
            if not rec.get("error"):
                rec["error"] = (f"reset_after of {dname} raised "
                                f"{type(e).__name__}: {e}")
            continue
        if last.get("task_ok"):
            continue
        if last.get("abort_run"):
            rec["abort_run"] = True
        if not rec.get("error"):
            rec["error"] = (
                f"reset_after of {dname} did not finish OK "
                f"(upid={last.get('upid')}, "
                f"exitstatus={last.get('exitstatus')}, "
                f"attempt {last.get('attempt')} of {RESET_MAX_ATTEMPTS})")


def _fail_after_reset_checks(rec: dict[str, Any],
                             results: list[dict[str, Any]]) -> None:
    """The first check that did not pass fails the scenario. rec["error"] is
    set only when no earlier error exists, so an earlier failure is never
    hidden."""
    bad = [r for r in results if not r["ok"]]
    if not bad:
        return
    first = bad[0]
    rec["passed"] = False
    if not rec.get("error"):
        rec["error"] = (f"after_reset: {first['name']}: "
                        f"{first['reason'] or 'probe failed'}")


def _run_after_reset_checks(lab: Lab, scen: Scenario, rec: dict[str, Any],
                            checks: dict[str, Post]) -> None:
    """Run the scenario's `after_reset` checks, in order, on the state the
    `reset_after` left behind. Records land in rec["after_reset"], shaped
    like the regression records.

    They run only when every reset finished OK: a failed reset already fails
    the scenario and a check would read a device that is not the baseline.
    `checks` is empty when the scenario never got that far (refused before
    step 1, or failed during the reset), which is the same rule.

    A check that fails fails the scenario: rec["error"] is set when no
    earlier error exists, so an earlier failure is never hidden. A check that
    raises is recorded as a failed check instead: this runs in the caller's
    `finally`, where an exception would escape run_scenario and lose the
    whole record, and the reset_after beside it is guarded the same way."""
    if not checks or not rec["reset_after"]:
        return
    if not all(r.get("task_ok") for r in rec["reset_after"]):
        return
    results: list[dict[str, Any]] = []
    for cn in scen.after_reset:
        p = checks[cn]
        try:
            entry = _record_probe(lab, p, "after_reset", cn, "pass")
        except Exception as e:
            entry = {
                "role": "after_reset", "name": cn, "device": p.device,
                "cmd": p.cmd, "rc": None, "stdout": "", "stderr": "",
                "passed": False, "want": "pass", "ok": False,
                "reason": f"{type(e).__name__}: {e}",
            }
        results.append(entry)
        rec["after_reset"].append(entry)
    _fail_after_reset_checks(rec, results)


def run_scenario(lab: Lab, scen: Scenario, lane: str = "password",
                 k_cache: dict[str, str] | None = None,
                 receipts: "RunReceipts | None" = None) -> dict[str, Any]:
    """Run one scenario and return its record.

    The record carries the access fact the run measured: the mode the
    scenario's receipts describe ("installed" when the runner drove the
    installed SSH change path, "no-install" when the rpcd transport
    wrote a receipt), and no fact at all when neither of them ran.
    The declaration of the scenario is kept beside it, so a reader can
    see what the scenario said and what it did.
    """
    global _EVIDENCE
    t0 = time.monotonic()
    rec: dict[str, Any] = {
        "name": scen.name,
        "description": scen.description,
        "expected": scen.effective_expect(lane),
        "access": None,
        "declared_access": scen.access,
        "outcome": None,
        "passed": False,
        "error": None,
        "reset": [],
        "reset_after": [],
        "after_reset": [],
        "settle": [],
        "setup": [],
        "before": [],
        "after": [],
        "cleanup": [],
        "post": [],
        "reject": None,
        "refuse": None,
        "abort_run": False,
        "plan_log": "",
        "apply_log": "",
        "vars": {},
        "duration_s": 0.0,
    }
    state: dict[str, Any] = {"setup_started": False,
                             "no_device_contact": False,
                             "after_reset_checks": {}}
    evidence = AccessEvidence()
    previous = _EVIDENCE
    _EVIDENCE = evidence
    try:
        _run_scenario_inner(lab, scen, rec, t0, state, lane=lane,
                            k_cache=k_cache)
    except Exception as e:
        rec["error"] = f"{type(e).__name__}: {e}"
        rec["duration_s"] = round(time.monotonic() - t0, 3)
    finally:
        if state["setup_started"]:
            _run_cleanup(lab, scen, rec)
        if not state["no_device_contact"]:
            # Step 9. Skipped only for a scenario that was refused before it
            # touched anything (a secret var in a cmd); a scenario that failed,
            # errored or raised still resets afterwards.
            _run_reset_after(lab, scen, rec)
            # Step 10, on the far side of that reset.
            _run_after_reset_checks(lab, scen, rec,
                                    state["after_reset_checks"])
        # the receipts of this scenario: the lines the no-install
        # transport wrote while the scenario ran, and the installed one
        # the runner recorded itself
        try:
            if receipts is not None:
                evidence.rpcd = any(
                    line.startswith(RPCD_RECEIPT_PREFIX)
                    for line in receipts.take())
            mode, access_error = derive_access_mode(evidence.installed,
                                                    evidence.rpcd)
            rec["access"] = mode
            rec["access_error"] = access_error
        finally:
            _EVIDENCE = previous
        if rec.get("error"):
            rec["passed"] = False
        rec["duration_s"] = round(time.monotonic() - t0, 3)
        # Last gate before the record leaves this function: every string in it
        # -- plan_log, apply_log, the stdout/stderr and cmd of setup steps,
        # posts and probes, error and reason texts -- has any resolved secret
        # value replaced with SECRET_MASK. mask_payload_text does it again on
        # the serialized payload before the file is written.
        masked = mask_record(rec)
        rec.clear()
        rec.update(masked)
    return rec


# ---------- Status / printing ----------

def status_letter(rec: dict[str, Any]) -> str:
    if rec.get("error"):
        return "ERROR"
    return "PASS" if rec.get("passed") else "FAIL"


def short_reason(rec: dict[str, Any]) -> str:
    if rec.get("error"):
        return str(rec["error"])
    if rec.get("outcome") != rec.get("expected"):
        return f"outcome={rec.get('outcome')} expected={rec.get('expected')}"
    reject = rec.get("reject")
    if isinstance(reject, dict) and reject.get("matched") is False:
        return (f"rejected, but plan output does not match reject_match "
                f"/{reject['pattern']}/: {_tail(rec.get('plan_log', ''))}")
    pm = rec.get("plan_match")
    if isinstance(pm, dict) and pm.get("matched") is False:
        return (f"plan output does not match plan_match "
                f"/{pm['pattern']}/: {_tail(rec.get('plan_log', ''))}")
    refuse = rec.get("refuse")
    if isinstance(refuse, dict) and refuse.get("matched") is False:
        return (f"refused, but apply output does not match refuse_match "
                f"/{refuse['pattern']}/: {_tail(rec.get('apply_log', ''))}")
    bad_after = [a for a in rec.get("after", []) if not a.get("ok")]
    if bad_after:
        a = bad_after[0]
        passed = "pass" if a["passed"] else "fail"
        return (f"after: {a['role']} {a['name']} wanted {a['want']}, "
                f"got {passed}: {a['reason']}")
    bad = [p for p in rec.get("post", []) if not p.get("passed")]
    if bad:
        parts = [p.get("reason", "post failed") for p in bad]
        return f"{len(bad)} post condition(s) failed: " + "; ".join(parts)
    return ""


def print_summary(results: list[dict[str, Any]]) -> None:
    """One line per scenario plus the tally. Every line goes through
    mask_text: a scenario's error, its post reasons and its plan/apply tails
    all come from device output, which may echo a secret var's value."""
    n_pass = sum(1 for r in results if status_letter(r) == "PASS")
    n_fail = sum(1 for r in results if status_letter(r) == "FAIL")
    n_err = sum(1 for r in results if status_letter(r) == "ERROR")
    for r in results:
        line = (f"{status_letter(r)}  {r['name']}  outcome={r.get('outcome')} "
                f"expected={r.get('expected')}  ({r['duration_s']}s)  {short_reason(r)}")
        print(mask_text(line))
    print(f"{n_pass} passed, {n_fail} failed, {n_err} errors")


# ---------- Main ----------

def inventory_entries() -> dict[str, Any]:
    """The devices table of the operator's Newton inventory, as it is
    now.  The inventory is the owner's own file (the one the MCP
    server reads): it says how a device was set up, and a run that
    contradicts it is refused."""
    path = Path(os.environ.get("NEWTON_INVENTORY",
                                "~/.config/newton/devices.toml")).expanduser()
    if not path.is_file():
        return {}
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
        return {}
    table = data.get("devices")
    return table if isinstance(table, dict) else {}


def inventory_access(device: str,
                      entries: dict[str, Any] | None = None) -> str | None:
    """The access mode the inventory declares for a device, or None when
    the inventory says nothing about it (the device is not in it, or its
    entry has no access field).  None means "no opinion", not
    "installed": the scenario is the first side of the check, the
    inventory the second."""
    if entries is None:
        entries = inventory_entries()
    entry = entries.get(device)
    if not isinstance(entry, dict):
        return None
    value = entry.get("access")
    return value if value in ACCESS_MODES else None


def declared_access_fact(scenarios: list[Scenario]) -> tuple[str | None,
                                                             list[dict[str, Any]],
                                                             str | None]:
    """The access mode the scenarios declare, and the checks against it.

    A scenario declares the mode it runs in (access = "installed" |
    "no-install", installed by default) and a run has one mode: a run
    that mixes the declarations is refused.  The inventory is the other
    side of the check: a scenario that declares one mode against a
    device whose inventory says the other is refused.  The refusal is
    an error, not a label.

    The declaration is not the fact.  What the run did is measured from
    the receipts (measured_access_fact); this check runs before
    anything is touched.

    Returns (declared mode, device facts, error message).  The mode is
    None and the error names the reason when the run is refused.
    """
    modes = {s.access for s in scenarios}
    if len(modes) > 1:
        detail = ", ".join(f"{s.name} is {s.access}" for s in scenarios)
        return None, [], ("the run mixes the access modes (%s); a run has "
                          "one mode" % detail)
    mode = modes.pop() if modes else None
    entries = inventory_entries()
    facts: list[dict[str, str]] = []
    for name in sorted({s.target for s in scenarios}):
        exercised = {s.access for s in scenarios if s.target == name}
        facts.append({"name": name, "access": sorted(exercised)[0]})
    for scen in scenarios:
        declared = inventory_access(scen.target, entries)
        if declared is not None and declared != scen.access:
            return None, [], (
                "%s runs in the %s mode but the inventory says %s is a "
                "%s device" % (scen.name, scen.access, scen.target, declared))
    return mode, facts, None


def measured_access_fact(scenarios: list[Scenario],
                         records: list[dict[str, Any]]
                         ) -> tuple[str | None, list[dict[str, Any]],
                                    str | None]:
    """The access fact of a run, from the receipts its scenarios produced.

    Every scenario that ran left a receipt or left none: the installed
    transport leaves one when the runner drove owrt-change.sh, the
    rpcd transport leaves one line in the run's receipt file.  The mode
    of a scenario is what its receipts say, and a run has one mode.

    The declaration of a scenario has to agree with the mode its
    receipts describe: a scenario that says one mode and did the other
    is refused, not labelled.  So is a scenario that used both
    transports, and so is a run whose scenarios measured two modes.

    Returns (mode, device facts, error message).  The mode is None when
    no scenario left a receipt: the run carries no access fact then.
    """
    modes: set[str] = set()
    by_device: dict[str, set[str]] = {}
    for scen, rec in zip(scenarios, records):
        error = rec.get("access_error")
        if error:
            return None, [], ("%s: %s" % (scen.name, error))
        mode = rec.get("access")
        if mode is None:
            # the scenario used neither transport: it carries no fact
            continue
        if mode != scen.access:
            return None, [], (
                "%s declares the %s mode but the run measured %s"
                % (scen.name, scen.access, mode))
        modes.add(mode)
        by_device.setdefault(scen.target, set()).add(mode)
    if len(modes) > 1:
        return None, [], ("the run mixes the access modes (%s); a run has "
                          "one mode" % ", ".join(sorted(modes)))
    mode = modes.pop() if modes else None
    facts: list[dict[str, Any]] = []
    for name in sorted({s.target for s in scenarios}):
        measured = by_device.get(name, set())
        facts.append({"name": name,
                      "access": sorted(measured)[0] if measured else None})
    return mode, facts, None


def _results_path(cli_arg: str | None) -> Path:
    if cli_arg:
        return Path(cli_arg)
    ts = time.strftime("%Y%m%d-%H%M%S")
    return RESULTS_DIR / f"results-{ts}.json"


def _lab_reset_path(results_path: Path) -> Path:
    text = str(results_path)
    if text.endswith(".json"):
        return Path(text[:-5] + "-lab-reset.json")
    return Path(text + "-lab-reset.json")


def _write_lab_reset_records(path: Path, records: list[dict[str, Any]]) -> None:
    # 0700, healed if an older runner left it looser; raises DirSetupError
    # rather than writing a record through a symlink.
    _ensure_output_parent(path, "the lab-reset record directory")
    path.write_text(json.dumps({
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "devices": records,
    }, indent=2))


def _reset_lab_at_run_start(lab: Lab, record_path: Path,
                            lane: str = "password") -> bool:
    records: list[dict[str, Any]] = []
    for dname, dev in lab.devices.items():
        if not dev.snapshot and not dev.is_physical:
            continue
        device_record: dict[str, Any] = {
            "device": dname,
            "reset": [],
            "ssh_ready": False,
            "settle": None,
        }
        records.append(device_record)
        try:
            last = reset_device(lab, dname, device_record["reset"])
        except Exception as e:
            _write_lab_reset_records(record_path, records)
            print(f"ERROR: lab-reset {dname} reset failed: "
                  f"{type(e).__name__}: {e}", file=sys.stderr)
            return False
        if not last["task_ok"]:
            _write_lab_reset_records(record_path, records)
            print(f"ERROR: lab-reset {dname} reset failed "
                  f"(exitstatus={last['exitstatus']})", file=sys.stderr)
            return False

        if dev.is_physical:
            # physical_reset already waited for ssh, settled and verified.
            settle_rec = last.get("settle") or {}
            device_record["ssh_ready"] = True
            device_record["settle"] = settle_rec
            if needs_hello_preflight(dev, lane):
                try:
                    ok, detail = router_hello_preflight(lab, dev)
                except Exception as e:
                    ok, detail = False, f"{type(e).__name__}: {e}"
                if not ok:
                    _write_lab_reset_records(record_path, records)
                    print(f"ERROR: lab-reset {dname} hello preflight failed: "
                          f"{detail}; {preflight_stop_text(dev)}",
                          file=sys.stderr)
                    return False
            print(f"lab-reset {dname} ok verified=physical "
                  f"settled={settle_rec.get('settled')}")
            continue

        try:
            device_record["ssh_ready"] = ssh_ready(lab, dev)
        except Exception as e:
            _write_lab_reset_records(record_path, records)
            print(f"ERROR: lab-reset {dname} ssh failed: "
                  f"{type(e).__name__}: {e}", file=sys.stderr)
            return False
        if not device_record["ssh_ready"]:
            _write_lab_reset_records(record_path, records)
            print(f"ERROR: lab-reset {dname} ssh failed: not ready",
                  file=sys.stderr)
            return False

        if lane == "key" and dev.snapshot.startswith(NEWTON_SNAPSHOT_PREFIX):
            try:
                ok, detail = router_hello_preflight(lab, dev)
            except Exception as e:
                _write_lab_reset_records(record_path, records)
                print(f"ERROR: lab-reset {dname} hello preflight failed: "
                      f"{type(e).__name__}: {e}; {PREFLIGHT_STOP_TEXT}",
                      file=sys.stderr)
                return False
            if not ok:
                _write_lab_reset_records(record_path, records)
                print(f"ERROR: lab-reset {dname} hello preflight failed: "
                      f"{detail}; {PREFLIGHT_STOP_TEXT}", file=sys.stderr)
                return False

        try:
            settle_rec = wait_settled(lab, dname)
            device_record["settle"] = settle_rec
        except Exception as e:
            _write_lab_reset_records(record_path, records)
            print(f"ERROR: lab-reset {dname} settle failed: "
                  f"{type(e).__name__}: {e}", file=sys.stderr)
            return False
        if settle_rec["settled"] is False:
            _write_lab_reset_records(record_path, records)
            print(f"ERROR: lab-reset {dname} settle failed "
                  f"(changes={settle_rec['changes']}, "
                  f"last_rc={settle_rec['last_rc']})", file=sys.stderr)
            return False
        print(f"lab-reset {dname} ok "
              f"settled_in={settle_rec['waited_s']}s "
              f"changes={settle_rec['changes']}")

    _write_lab_reset_records(record_path, records)
    return True


def _filter_scenarios(scenarios: list[Scenario], patterns: list[str]
                      ) -> tuple[list[Scenario] | None, str | None]:
    """Return (filtered, None) or (None, error_message). The selected
    scenarios keep their original (sorted) order regardless of pattern order;
    a name matched by more than one pattern or by an exact name plus a glob
    appears once."""
    selected: set[str] = set()
    for pat in patterns:
        any_match = False
        for s in scenarios:
            if s.name == pat or fnmatch.fnmatch(s.name, pat):
                any_match = True
                selected.add(s.name)
        if not any_match:
            return None, pat
    matched = [s for s in scenarios if s.name in selected]
    return matched, None


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="newton-lab-test",
        description="Run Newton lab scenarios against lab-r1 etc.",
    )
    ap.add_argument("--lab", default=str(DEFAULT_LAB),
                    help=f"Lab config TOML (default {DEFAULT_LAB})")
    ap.add_argument("--scenarios", default=str(SCEN_DIR),
                    help=f"Scenarios dir (default {SCEN_DIR})")
    ap.add_argument("--only", nargs="*", default=[],
                    help="Only run these scenario names or fnmatch patterns "
                         "(default: all)")
    ap.add_argument("--list", action="store_true",
                    help="List scenario names and descriptions, exit")
    ap.add_argument("--results", default=None,
                    help="Path for JSON results file")
    ap.add_argument("--no-lab-reset", action="store_true",
                    help="Skip the run-start reset of all snapshot devices")
    ap.add_argument("--lane", choices=list(LANES), default="key",
                    help="SSH lane the protocol runs over: the runner's "
                         "restricted key (default, RD7) or the root password")
    args = ap.parse_args(argv)

    lab = load_lab(Path(args.lab))

    if args.lane == "key" and not lab.known_hosts:
        print("ERROR: --lane key needs [ssh] known_hosts in the lab config "
              "(a file holding lab-r1's host key; create it at lab setup)",
              file=sys.stderr)
        return 2

    if args.lane == "key" and not lab.router_key:
        print("ERROR: --lane key but [ssh] router_key is not set in the lab "
              "config; set it to the runner's restricted key path",
              file=sys.stderr)
        return 2

    scen_path = Path(args.scenarios)
    if not scen_path.is_dir():
        print(f"ERROR: --scenarios {scen_path} is not a directory",
              file=sys.stderr)
        return 2

    try:
        scenarios = load_scenarios(scen_path)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    if not scenarios:
        print(f"ERROR: no scenarios found in {scen_path}", file=sys.stderr)
        return 2

    errs = validate_scenarios(lab, scenarios)
    if errs:
        for e in errs:
            print(f"ERROR: {e}", file=sys.stderr)
        return 2

    if args.only:
        matched, missing = _filter_scenarios(scenarios, args.only)
        if missing is not None:
            print(f"ERROR: --only matches no scenarios: {missing!r}",
                  file=sys.stderr)
            return 2
        scenarios = matched or []

    if args.list:
        for s in scenarios:
            print(f"{s.name} [{s.expect}]: {s.description}")
        return 0

    # The declared mode of the run, before anything is touched: the
    # check of the declarations against each other and against the
    # inventory.  A run that cannot be labelled is refused here, not
    # labelled afterwards (ADR-021 point 1).  What the run really did
    # is measured from the receipts, after the run.
    _declared, _declared_facts, access_error = declared_access_fact(scenarios)
    if access_error:
        print(f"ERROR: {access_error}", file=sys.stderr)
        return 2

    # Prove every physical device is the intended lab router before any step,
    # var, check or reset can touch it (also with --no-lab-reset).
    for dname, dev in lab.devices.items():
        if not dev.is_physical:
            continue
        try:
            physical_identity_check(lab, dev)
        except _PhysicalStop as e:
            print(f"ERROR: {dname}: {e}", file=sys.stderr)
            return 2

    # RESULTS_DIR and its backups dir hold every result JSON and every full
    # `sysupgrade -b` backup owrt-change.sh takes (secrets), and RESULTS_DIR is
    # the parent owrt-change.sh checks for OWRT_BACKUP_DIR. 0700, healed if an
    # older runner left them 0775, refused through a symlink or for a
    # directory we do not own.
    out_path = _results_path(args.results)
    try:
        _ensure_results_dirs(out_path)
    except DirSetupError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    if not args.no_lab_reset:
        try:
            reset_ok = _reset_lab_at_run_start(lab, _lab_reset_path(out_path),
                                               lane=args.lane)
        except DirSetupError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 2
        if not reset_ok:
            return 2

    # The receipt file of the run: the no-install transport writes its
    # own lines into it (one per rpcd call over HTTPS that got an
    # answer) and the runner reads the file after every scenario.  The
    # variable is exported to every scenario command, so the transport
    # a scenario runs finds it.  The file lives in the run's own temp
    # directory and goes away with it.
    receipt_dir = tempfile.mkdtemp(prefix="newton-lab-receipt-")
    receipt_path = Path(receipt_dir) / "receipts.txt"
    receipts = RunReceipts(receipt_path)
    previous_receipt = os.environ.get(RECEIPT_ENV)
    os.environ[RECEIPT_ENV] = str(receipt_path)
    results: list[dict[str, Any]] = []
    k_cache: dict[str, str] = {}
    try:
        for scen in scenarios:
            results.append(run_scenario(lab, scen, lane=args.lane,
                                        k_cache=k_cache, receipts=receipts))
            if results[-1].get("abort_run"):
                print(f"ERROR: stopping the run: {scen.name}: "
                      f"{results[-1].get('error')}", file=sys.stderr)
                break

        print_summary(results)

        # The access fact of the run, from the receipts its scenarios
        # produced: a run that cannot be labelled is refused here, and a
        # refused run writes no results file at all.
        run_access, device_facts, access_error = measured_access_fact(
            scenarios, results)
        if access_error:
            print(f"ERROR: {access_error}", file=sys.stderr)
            return 2
    finally:
        if previous_receipt is None:
            os.environ.pop(RECEIPT_ENV, None)
        else:
            os.environ[RECEIPT_ENV] = previous_receipt
        shutil.rmtree(receipt_dir, ignore_errors=True)

    # Re-checked before the write: the run has been going for a while and the
    # results directory must still be the 0700 directory of ours, not something
    # that was swapped for a symlink while we were on the routers.
    try:
        _ensure_results_dirs(out_path)
    except DirSetupError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    payload = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "summary": (f"{sum(1 for r in results if status_letter(r) == 'PASS')} passed, "
                    f"{sum(1 for r in results if status_letter(r) == 'FAIL')} failed, "
                    f"{sum(1 for r in results if status_letter(r) == 'ERROR')} errors"),
        "devices": device_facts,
        "access": run_access,
        "scenarios": results,
    }
    out_path.write_text(mask_payload_text(json.dumps(payload, indent=2)))

    if any(r.get("abort_run") for r in results):
        return 2
    any_fail = any(status_letter(r) != "PASS" for r in results)
    return 1 if any_fail else 0


if __name__ == "__main__":
    sys.exit(main())
