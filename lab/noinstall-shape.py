"""The seven support-table shapes on a no-install OpenWrt router.

usage: noinstall-shape.py SHAPE [ARG]

  n01            a DHCP static lease: auto plan, approved, applied, confirmed;
                 then deleted again through an owner script
  n02            the LAN address moved away: refused at plan time (a change
                 that cuts Newton's way in can never be confirmed)
  n03 ZONE       the LAN zone's input set to DROP (ZONE is e.g. @zone[0]):
                 refused at plan time, the same rule
  n04            a smuggled "commit": the plan must be refused
  n05            a "set" without a value: the plan must be refused
  n06 AGENT_IP   a WAN port forward to the agent host: owner script, the
                 owner keeps it, confirmed
  n06-restore    the restore plan of n06, kept, confirmed
  n06-cleanup    delete a forward an earlier n06 left behind
  n07            every uplink disabled: owner script, the internet check
                 fails, so Newton does not confirm and the router rolls back

It drives the REAL NewtonService of the installed package (run it with the
run's own venv python) and the real setup tool for the owner script. The
lab runner scenarios in lab/scenarios-pulsar-noinstall/ call it; every
rpcd call it makes writes a receipt line, so the run's access mode is
measured, not declared.  The no-install refusals (n04, n05) read the
router first, so their scenario carries an access fact too.

Env: NEWTON_INVENTORY, NEWTON_STATE_DIR, NEWTON_KEYS_DIR,
NEWTON_TRUSTED_KNOWN_HOSTS (Newton's own); NI_DEVICE (the device name),
NI_APPROVE_PP (the lab approval passphrase file), NI_SETUP (the setup
tool of the same source copy), NI_ADMIN_KEY and NI_ROOT_PW (the owner's
admin login).  The approval is the real one: only the terminal is
replaced.  Nothing secret is printed.
"""
import io
import json
import os
import pty
import re
import select
import signal
import subprocess
import sys
import time
from pathlib import Path

from newton_mcp import approve
from newton_mcp.server import NewtonError, NewtonService

DEV = os.environ["NI_DEVICE"]
STATE = Path(os.environ["NEWTON_STATE_DIR"])
WINDOW = 120
FAILS = []


LOG = open(STATE.parent / f"shape-{sys.argv[1]}.log", "a")


def say(*a):
    print(*a, flush=True)
    print(*a, file=LOG, flush=True)


def want(label, ok, detail=""):
    say(f"  {'PASS' if ok else 'FAIL'} {label} {detail}".rstrip())
    if not ok:
        FAILS.append(label)


def expl(path, value, intent, n=1):
    return {"intent": intent, "steps": [f"{intent} ({i + 1})" for i in range(n)],
            # a delete has no value to claim: the claim Newton's own restore plans use
            "expect": ([{"kind": "uci_equals", "path": path, "equals": value}] if value is not None
                       else [{"kind": "probe", "probe": ["ping", "127.0.0.1"]}]),
            "risk": "a lab shape on the dev router; it is undone by the router or by the run"}


def call(label, fn, *a, **kw):
    t0 = time.time()
    try:
        r = fn(*a, **kw)
    except NewtonError as exc:
        say(f"  {label}: t+{time.time() - t0:.1f}s NewtonError: {exc}")
        return exc
    say(f"  {label}: t+{time.time() - t0:.1f}s -> {json.dumps(r, default=str)[:600]}")
    return r


def ok(r):
    return isinstance(r, dict)


def approve_sid(sid):
    plan = json.loads((STATE / "plans" / f"{sid}.json").read_text())
    approve._getpass = lambda prompt="": approve.read_passphrase_file(
        os.environ["NI_APPROVE_PP"]).decode()
    old = sys.stdin
    sys.stdin = io.StringIO(f"approve {sid[:8]}\n")
    try:
        good, why = approve.approve_plan(sid, plan, program="noinstall-shape")
    finally:
        sys.stdin = old
    want(f"approve {sid[:8]}", good, why)
    return good


def owner_run(sid, keep=False):
    """Run the owner script the way an owner does: the setup tool's owner-run.

    The setup tool asks for "keep" on /dev/tty, so the run is on a pty and
    "keep" is typed only after the prompt is on the screen.
    """
    argv = [os.environ["NI_SETUP"], "--admin", "plain-key", "--plain-key",
            os.environ["NI_ADMIN_KEY"], "--password-file", os.environ["NI_ROOT_PW"],
            DEV, "owner-run", sid]
    t0 = time.time()
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(argv[0], argv)
    buf, last, status = b"", time.monotonic(), None
    while True:
        ready, _, _ = select.select([fd], [], [], 5)
        if ready:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                chunk = b""
            if not chunk:
                break
            sys.stdout.write(chunk.decode("utf-8", "replace"))
            LOG.write(chunk.decode("utf-8", "replace"))
            buf += chunk
            last = time.monotonic()
            if keep and re.search(rb"Type keep", buf):
                time.sleep(0.3)
                os.write(fd, b"keep\n")
                say("\n  <typed keep>")
                buf = b""
        done, st = os.waitpid(pid, os.WNOHANG)
        if done:
            status = st
            break
        if time.monotonic() - last > WINDOW + 300:
            os.kill(pid, signal.SIGTERM)
            os.waitpid(pid, 0)
            say("  owner-run stalled, killed")
            return 3
    if status is None:
        _, status = os.waitpid(pid, 0)
    rc = os.waitstatus_to_exitcode(status)
    say(f"\n  owner-run {sid[:8]}: rc={rc} t+{time.time() - t0:.1f}s")
    return rc


def uci_show(svc, config):
    r = call(f"read uci show {config}", svc.read, DEV, f"uci show {config}")
    return json.dumps(r) if ok(r) else ""


def owner_change(svc, batch, path, value, intent, expect_result, keep=False):
    """Plan an owner script, approve it, run it, and read its status."""
    p = call("plan", svc.plan, DEV, batch, WINDOW, owner_confirmed_in_chat=True,
             explanation=expl(path, value, intent, len(batch.splitlines())))
    want("plan is an owner script", ok(p) and p.get("mode") == "owner-script",
         str(ok(p) and p.get("auto_apply_reason")))
    if not ok(p) or not approve_sid(p["session_id"]):
        return None, None
    (STATE.parent / "ni-last.json").write_text(json.dumps(
        {"sid": p["session_id"], "rsid": p.get("restore_session_id")}))
    owner_run(p["session_id"], keep=keep)
    s = call("status", svc.status, DEV, p["session_id"])
    want(f"status is {expect_result}", ok(s) and s.get("result") == expect_result)
    return p, (s.get("result") if ok(s) else None)


def refused(svc, batch, needle):
    uci_show(svc, "system")
    r = call("plan", svc.plan, DEV, batch, WINDOW, owner_confirmed_in_chat=True,
             explanation=expl("system.@system[0].hostname", "x", "a refused change",
                              len(batch.splitlines())))
    want("plan refused", isinstance(r, NewtonError))
    want("refusal names the cause", isinstance(r, NewtonError) and needle in str(r), repr(needle))


def main():
    shape = sys.argv[1]
    svc = NewtonService()
    say(f"== {shape}; newton_mcp from {approve.__file__}")
    d = call("list_devices", svc.list_devices)
    entry = next((x for x in (d or {}).get("devices", []) if x.get("name") == DEV), None)
    want(f"{DEV} is no-install", bool(entry) and entry.get("access") == "no-install")
    if FAILS:
        return

    if shape == "n01":
        h = "ni_h1"
        batch = (f"set dhcp.{h}=host\nset dhcp.{h}.name='ni-h1'\n"
                 f"set dhcp.{h}.mac='02:00:00:00:00:77'\nset dhcp.{h}.ip='192.168.1.77'")
        p = call("plan lease", svc.plan, DEV, batch, WINDOW, owner_confirmed_in_chat=True,
                 explanation=expl(f"dhcp.{h}.ip", "192.168.1.77", "a DHCP static lease", 4))
        want("lease plan is auto", ok(p) and p.get("mode") == "auto",
             str(ok(p) and p.get("auto_apply_reason")))
        if ok(p) and approve_sid(p["session_id"]):
            call("apply", svc.apply, DEV, p["session_id"])
            s = call("status", svc.status, DEV, p["session_id"])
            want("lease confirmed", ok(s) and s.get("result") == "confirmed")
            want("lease on the router", "192.168.1.77" in uci_show(svc, "dhcp"))
        say("== n01 cleanup: the delete is an owner script (a delete is never auto)")
        owner_change(svc, f"delete dhcp.{h}", "dhcp.lan.interface", "lan",
                     "remove the test lease", "confirmed")
        want("lease gone", "192.168.1.77" not in uci_show(svc, "dhcp"))

    elif shape == "n02":
        # the no-install mode refuses a change that cuts Newton's own way in:
        # it could never be confirmed (owner_ops.REFUSED_REASONS), so there is
        # nothing to roll back
        refused(svc, "set network.lan.ipaddr='192.168.99.1/24'",
                "the policy refuses this change (mgmt-interface)")
        want("LAN address unchanged", "network.lan.ipaddr='192.168.1.1/24'" in uci_show(svc, "network"))

    elif shape == "n03":
        zone = sys.argv[2]
        refused(svc, f"set firewall.{zone}.input='DROP'",
                "the policy refuses this change (mgmt-zone)")

    elif shape == "n04":
        refused(svc, "set system.@system[0].description='x'\ncommit system",
                "only set, add_list, del_list, delete are allowed")

    elif shape == "n05":
        refused(svc, "set network.lan.ipaddr", "a change to an option needs a value")

    elif shape == "n06":
        agent = sys.argv[2]
        r = "ni_fwd"
        batch = "\n".join([
            f"set firewall.{r}=redirect", f"set firewall.{r}.name='ni ssh to client'",
            f"set firewall.{r}.src='wan'", f"set firewall.{r}.src_dport='2222'",
            f"set firewall.{r}.dest='lan'", f"set firewall.{r}.dest_ip='{agent}'",
            f"set firewall.{r}.dest_port='22'", f"set firewall.{r}.proto='tcp'",
            f"set firewall.{r}.target='DNAT'"])
        owner_change(svc, batch, f"firewall.{r}.src_dport", "2222",
                     "forward WAN tcp 2222 to the agent host", "confirmed", keep=True)

    elif shape == "n06-restore":
        ids = json.loads((STATE.parent / "ni-last.json").read_text())
        if ids.get("rsid") and approve_sid(ids["rsid"]):
            # taking a WAN rule away asks for "keep" too
            owner_run(ids["rsid"], keep=True)
            s = call("status", svc.status, DEV, ids["rsid"])
            want("restore confirmed", ok(s) and s.get("result") == "confirmed")
        want("forward gone", "ni_fwd" not in uci_show(svc, "firewall"))

    elif shape == "n06-cleanup":
        # a forward left by an earlier run whose restore was not kept
        owner_change(svc, "delete firewall.ni_fwd", "firewall.ni_fwd.target", None,
                     "remove the test forward", "confirmed", keep=True)
        want("forward gone", "ni_fwd" not in uci_show(svc, "firewall"))

    elif shape == "n07":
        net = uci_show(svc, "network")
        ups = [u for u in ("wan", "wan6", "wan2") if f"network.{u}=interface" in net]
        say(f"  uplinks: {ups}")
        p, result = owner_change(svc, "\n".join(f"set network.{u}.disabled='1'" for u in ups),
                                 "network.wan.disabled", "1", "disable every uplink",
                                 "rolled_back")
        if result == "confirmed" and p.get("restore_session_id"):
            say("  the uplinks stayed down: putting them back with the restore plan")
            if approve_sid(p["restore_session_id"]):
                owner_run(p["restore_session_id"])
        net = uci_show(svc, "network")
        want("uplinks back", not any(f"network.{u}.disabled='1'" in net for u in ups))

    else:
        sys.exit(f"unknown shape {shape}")


main()
say(f"== END fails={len(FAILS)} {FAILS}")
sys.exit(1 if FAILS else 0)
