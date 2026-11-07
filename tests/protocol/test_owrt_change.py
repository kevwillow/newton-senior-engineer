import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import textwrap

import pytest


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "owrt-change.sh"
HELPER = Path(__file__).resolve().parents[2] / "scripts" / "owrt-safe-apply.sh"
# the router program the host script speaks to (design 7.1 row 39)
PROG = "/usr/libexec/newton/newton-router"
SID = "0123456789abcdef0123456789abcdef"
DIFF = "dhcp.lab.limit='50'\n"
# real fw4 lines (land-d live-audit.log shape): notices and errors share the
# "[!]" prefix and cannot be told apart by prefix alone
FW4_NOTICE = "[!] Section @rule[1] (Allow-Ping) is disabled, ignoring section"
FW4_REAL_ERROR = "[!] Section @forwarding[0] option 'dest' specifies invalid value 'wan'"


def _unshare_ssh_or_skip():
    """The script resolves ssh via /usr/bin/ssh (with /bin/ssh fallback).  The
    fake ssh in tmp_path/"bin"/ssh must therefore be exposed there; bind-mount
    the fake onto /usr/bin/ssh inside a fresh user+mount namespace.  Skip
    the whole module when ``unshare -Urm`` is not available (no fake can
    be installed at /usr/bin/ssh without it)."""
    unshare = shutil.which("unshare")
    if unshare is None:
        pytest.skip("unshare is unavailable; cannot bind-mount a fake ssh over /usr/bin/ssh")
    probe = subprocess.run(
        [unshare, "-Urm", "true"], text=True, capture_output=True, timeout=10
    )
    if probe.returncode != 0:
        reason = probe.stderr.strip() or f"unshare exited {probe.returncode}"
        pytest.skip(f"unshare -Urm is unavailable: {reason}")


@pytest.fixture
def protocol(tmp_path):
    _unshare_ssh_or_skip()
    bindir = tmp_path / "bin"
    routerbin = tmp_path / "routerbin"
    bindir.mkdir()
    routerbin.mkdir()
    (tmp_path / "calls.log").write_text("")
    (tmp_path / "events.log").write_text("")
    (tmp_path / "stdin.log").write_text("")
    (tmp_path / "timed-events.log").write_text("")
    (tmp_path / "seal-stdin.log").write_text("")
    (tmp_path / "ssh-argv.log").write_text("")
    (tmp_path / "lc_all.log").write_text("")
    config_file = tmp_path / "network"
    config_file.write_text("config interface 'lan'\n")
    with tarfile.open(tmp_path / "backup.tar.gz", "w:gz") as archive:
        archive.add(config_file, arcname="etc/config/network")
    bash_env = tmp_path / "bash-env"
    bash_env.write_text(
        "sleep() { local s=${1%%.*}; [[ $s =~ ^[0-9]+$ ]] || s=0; "
        "SECONDS=$((SECONDS + s)); export NEWTON_VIRTUAL_SECONDS=$SECONDS; "
        "command sleep 0.01; }\n"
    )
    (tmp_path / "router.json").write_text(
        json.dumps(
            {
                "logd": ["1314"],
                "dnsmasq_running": True,
                "dhcp_listener": True,
                "dnsmasq_restart_kills_dhcp": False,
                "dnsmasq_dies_on_restart": False,
                "dnsmasq_running_after_rollback": None,
                "dnsmasq_start_fails": False,
                "dnsmasq_restart_output": None,
                "named": "",
                "fw_table": True,
                "fw_restart": ["ok"],
                "fw4_start_works": True,
                "fw_ssh": [],
                "fw_table_after_rollback": None,
                "status": "rolled-back",
                "status_ssh": [],
                "diff": DIFF,
                "health_snapshot": "ok",
                "health_checks": ["ok"],
                "health_after_rollback": None,
                "hostname": "lab-r1",
                "hello_overrides": {},
                "hello_rc": 0,
                "hello_stderr": "",
                "hello_raw": None,
                "stage_fail": None,
                "seal_fail": None,
                "seal_raw": None,
                "apply_stdout": None,
                "seal_profile": "prod",
                "seal_sections": [],
                "seal_leashes": [],
                "seal_approval": None,
                "apply_rc": 0,
                "apply_stderr": "",
                "confirm_rc": 0,
                "confirm_form": "plain",
                "confirm_stderr": "",
                "abort_how": "discarded",
                "abort_fail": None,
                "confighash": [
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb dhcp\n"
                    "cccccccccccccccccccccccccccccccc firewall\n"
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa network"
                ],
            }
        )
    )

    ssh = bindir / "ssh"
    ssh.write_text(
        textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import hashlib
            import json
            import os
            from pathlib import Path
            import shutil
            import stat
            import subprocess
            import sys

            root = Path(os.environ["STUB_ROOT"])
            PROG = "/usr/libexec/newton/newton-router"
            SID = "0123456789abcdef0123456789abcdef"

            def read_state():
                return json.loads((root / "router.json").read_text())

            def write_state(state):
                (root / "router.json").write_text(json.dumps(state))

            def src_sha(rel):
                path = Path(os.environ.get("NEWTON_FAKE_SRC_ROOT") or os.environ["OWRT_SRC_ROOT"]) / rel
                if not path.is_file():
                    return "missing"
                return hashlib.sha256(path.read_bytes()).hexdigest()

            def firewall_ssh_mode():
                state = read_state()
                modes = state["fw_ssh"]
                if not modes:
                    return "normal"
                mode = modes[0]
                state["fw_ssh"] = modes[1:]
                write_state(state)
                return mode

            def unreachable():
                print("ssh: connect to host 192.0.2.1 port 22: Connection timed out", file=sys.stderr)
                sys.exit(255)

            try:
                destination = next(i for i, arg in enumerate(sys.argv[1:], 1) if "@" in arg)
            except StopIteration:
                print("stub ssh: destination not found", file=sys.stderr)
                sys.exit(127)
            cmd = " ".join(sys.argv[destination + 1:])
            with (root / "calls.log").open("a") as calls:
                calls.write(json.dumps(cmd) + "\\n")
            with (root / "ssh-argv.log").open("a") as argv_log:
                argv_log.write(json.dumps(sys.argv) + "\\n")
            with (root / "timed-events.log").open("a") as events:
                events.write(json.dumps({
                    "time": int(os.environ.get("NEWTON_VIRTUAL_SECONDS", "0")),
                    "cmd": cmd,
                }) + "\\n")
            stdin_stat = os.fstat(0)
            devnull_stat = os.stat(os.devnull)
            stdin_is_devnull = stat.S_ISCHR(stdin_stat.st_mode) and stdin_stat.st_rdev == devnull_stat.st_rdev
            with (root / "stdin.log").open("a") as stdin_log:
                stdin_log.write(json.dumps({"cmd": cmd, "devnull": stdin_is_devnull}) + "\\n")
            with (root / "lc_all.log").open("a") as lc_all_log:
                lc_all_log.write((os.environ.get("LC_ALL") or "<unset>") + "\\n")

            if cmd.startswith(PROG + " hello "):
                nonce = cmd.split()[2]
                state = read_state()
                raw = state.get("hello_raw")
                if raw is not None:
                    sys.stdout.write(raw.replace("{nonce}", nonce))
                    sys.exit(state.get("hello_raw_rc", 0))
                rc = state.get("hello_rc", 0)
                if rc:
                    sys.stderr.write(state.get("hello_stderr", ""))
                    sys.exit(rc)
                fields = {
                    "api": "1",
                    "version": "1.0.0",
                    "mode": "prod",
                    "prog": src_sha("device/openwrt/newton-router/newton-router"),
                    "helper": src_sha("scripts/owrt-safe-apply.sh"),
                    "guard": src_sha("device/openwrt/newton-guard/newton-guard"),
                    "init": src_sha("device/openwrt/newton-guard/newton-guard.init"),
                    "device": "lab-r1",
                    "profile": "prod",
                    "approval-key": "present",
                    "guard-state": "idle",
                    "busy": "-",
                    "caller": "root",
                    "role": "change",
                    "door": "ssh",
                    "tty": "0",
                    "agent": "0",
                    "from": "-",
                }
                fields.update(state.get("hello_overrides") or {})
                missing = "missing" in fields.values()
                print("hello " + nonce + " " + " ".join(f"{k}={v}" for k, v in fields.items()))
                sys.exit(1 if missing else 0)
            if cmd == PROG + " hostname":
                sys.stdout.write(read_state()["hostname"])
                sys.exit(0)
            if cmd == PROG + " backup":
                sys.stdout.buffer.write((root / "backup.tar.gz").read_bytes())
                sys.exit(0)
            if cmd == PROG + " stage":
                sys.stdin.buffer.read()
                fail = read_state().get("stage_fail")
                if fail:
                    sys.stderr.write(fail["stderr"])
                    sys.exit(fail["rc"])
                print(SID)
                sys.exit(0)
            if cmd.startswith(PROG + " seal "):
                data = sys.stdin.buffer.read()
                with (root / "seal-stdin.log").open("a") as seal_log:
                    seal_log.write(json.dumps({"cmd": cmd, "data": data.hex()}) + "\\n")
                state = read_state()
                fail = state.get("seal_fail")
                if fail:
                    sys.stderr.write(fail["stderr"] + "\\n")
                    sys.exit(fail["rc"])
                if state.get("seal_raw") is not None:
                    for raw_line in state["seal_raw"]:
                        print(raw_line)
                    sys.exit(0)
                t = cmd.split()[3]
                values = state["confighash"]
                chash = values[0] if values else ""
                base_text = chash if chash.endswith("\\n") else chash + "\\n"
                base = hashlib.sha256(base_text.encode()).hexdigest()
                diff_text = state["diff"].rstrip("\\n") + "\\n"
                diff = hashlib.sha256(diff_text.encode()).hexdigest()
                probes_sha = hashlib.sha256(data).hexdigest()
                n = data.count(b"\\n") + (1 if data and not data.endswith(b"\\n") else 0)
                profile = state.get("seal_profile", "prod")
                sections = state.get("seal_sections", [])
                leashes = state.get("seal_leashes", [])
                approval = state.get("seal_approval")
                if approval is None:
                    approval = "required" if profile == "prod" or leashes else "not-required"
                digest = hashlib.sha256(
                    ("newton-fake-plan\\n%s\\n%s\\n%s\\n%s\\n" % (base, diff, probes_sha, t)).encode()
                ).hexdigest()
                print("base", base)
                print("diff", diff)
                print("probes", n, probes_sha)
                print("t", t)
                print("profile", profile)
                for section in sections:
                    print("section", section)
                for leash in leashes:
                    print("leash", leash)
                print("approval", approval)
                print("digest", digest)
                sys.exit(0)
            if cmd == PROG + " diff " + SID:
                sys.stdout.write(read_state()["diff"])
                sys.exit(0)
            if cmd == PROG + " named " + SID:
                sys.stdout.write(read_state()["named"])
                sys.exit(0)
            if cmd == PROG + " fw-loaded":
                print("1" if read_state()["fw_table"] else "0")
                sys.exit(0)
            if cmd == PROG + " confighash":
                state = read_state()
                values = state["confighash"]
                current = values[0]
                if len(values) > 1:
                    state["confighash"] = values[1:]
                    write_state(state)
                if current == "fail":
                    unreachable()
                if current.startswith("fail:"):
                    print(current.removeprefix("fail:"), file=sys.stderr)
                    sys.exit(1)
                print(current)
                sys.exit(0)
            if cmd == PROG + " logd-pid":
                state = read_state()
                pids = state["logd"]
                current = pids[0] if pids else ""
                if len(pids) > 1:
                    state["logd"] = pids[1:]
                    write_state(state)
                if current:
                    print(current)
                sys.exit(0)
            if cmd == PROG + " health-snapshot " + SID:
                result = read_state()["health_snapshot"]
                if result != "ok":
                    print(result, file=sys.stderr)
                    sys.exit(1)
                sys.exit(0)
            if cmd in (PROG + " health-check " + SID, PROG + " health-check " + SID + " after-rollback"):
                sys.exit(subprocess.run([str(root / "routerbin" / "health-check")]).returncode)
            if cmd.startswith(PROG + " verify "):
                need = cmd.split()[3]
                if (root / "fail-ping").exists():
                    print("verify: ping -c1 -W3 1.1.1.1 failed", file=sys.stderr)
                    sys.exit(1)
                if (root / "fail-nslookup").exists():
                    print("verify: nslookup openwrt.org 127.0.0.1 failed", file=sys.stderr)
                    sys.exit(1)
                state = read_state()
                if need == "1" and not (state["dnsmasq_running"] and state["dhcp_listener"]):
                    print(
                        "verify: dnsmasq is not running with its DHCP listener (udp 67) "
                        "after Newton restarted it",
                        file=sys.stderr,
                    )
                    sys.exit(1)
                if need == "2" and not state["dnsmasq_running"]:
                    print("verify: dnsmasq is not running after Newton restarted it", file=sys.stderr)
                    sys.exit(1)
                sys.exit(subprocess.run([str(root / "routerbin" / "health-check")]).returncode)
            if cmd.startswith(PROG + " apply "):
                state = read_state()
                if state.get("apply_rc"):
                    sys.stderr.write(state.get("apply_stderr", "") + "\\n")
                    sys.exit(state["apply_rc"])
                parts = cmd.split()
                out = state.get("apply_stdout") or "applied %s t=%s guard=4242" % (parts[2], parts[3])
                print(out)
                sys.exit(0)
            if cmd == PROG + " confirm " + SID:
                state = read_state()
                rc = state.get("confirm_rc", 0)
                if rc:
                    sys.stderr.write(state.get("confirm_stderr", "") + "\\n")
                    sys.exit(rc)
                form = state.get("confirm_form", "plain")
                if form in ("plain", "lost"):
                    line = "confirmed " + SID
                    if form == "lost":
                        line += " rpcd-timer-lost"
                    print(line)
                else:
                    print(form)
                sys.exit(0)
            if cmd == PROG + " status " + SID:
                state = read_state()
                modes = state.get("status_ssh", [])
                if modes:
                    mode = modes[0]
                    state["status_ssh"] = modes[1:]
                    write_state(state)
                    if mode == "fail":
                        unreachable()
                if state["health_after_rollback"] is not None:
                    state["health_checks"] = [state["health_after_rollback"]]
                    state["health_after_rollback"] = None
                if state["dnsmasq_running_after_rollback"] is not None:
                    state["dnsmasq_running"] = state["dnsmasq_running_after_rollback"]
                    state["dnsmasq_running_after_rollback"] = None
                if state["fw_table_after_rollback"] is not None:
                    state["fw_table"] = state["fw_table_after_rollback"]
                    state["fw_table_after_rollback"] = None
                write_state(state)
                print(state["status"])
                sys.exit(0)
            if cmd == PROG + " abort " + SID:
                state = read_state()
                if state.get("abort_fail"):
                    sys.stderr.write(state["abort_fail"])
                    sys.exit(1)
                print("aborted", SID, state.get("abort_how", "discarded"))
                sys.exit(0)
            if cmd.startswith(PROG + " fwrestart "):
                mode = firewall_ssh_mode()
                if mode == "fail":
                    unreachable()
                loaded_before = cmd.rsplit(" ", 1)[1]
                busybox = shutil.which("busybox")
                argv = [busybox, "sh", os.environ["HELPER"], "fwrestart", loaded_before]
                env = os.environ.copy()
                env["PATH"] = str(root / "routerbin") + os.pathsep + env["PATH"]
                env["NEWTON_FIREWALL_INIT"] = str(root / "routerbin" / "firewall-init")
                if mode == "fail-after":
                    env["FW_SSH_FAIL_AFTER"] = "1"
                    subprocess.run(
                        argv,
                        env=env,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    sys.exit(255)
                sys.exit(subprocess.run(argv, env=env).returncode)
            if cmd == PROG + " dnsmasq-repair":
                state = read_state()
                if state["dnsmasq_restart_output"] is not None:
                    sys.stdout.write(state["dnsmasq_restart_output"])
                    sys.exit(0)
                if state["dnsmasq_running"]:
                    dhcp = 1 if state["dhcp_listener"] else 0
                    failed = state["dnsmasq_dies_on_restart"]
                    print(f"restarted rc={1 if failed else 0} dhcp={dhcp}")
                    with (root / "events.log").open("a") as events:
                        events.write("DNSMASQ-RESTART\\n")
                    if failed:
                        state["dnsmasq_running"] = False
                    if state["dnsmasq_restart_kills_dhcp"]:
                        state["dhcp_listener"] = False
                    write_state(state)
                else:
                    print("not-running")
                sys.exit(0)
            if cmd == PROG + " dnsmasq-ensure":
                state = read_state()
                if state["dnsmasq_running"]:
                    print("running")
                    sys.exit(0)
                with (root / "events.log").open("a") as events:
                    events.write("DNSMASQ-START\\n")
                failed = state["dnsmasq_start_fails"]
                if not failed:
                    state["dnsmasq_running"] = True
                    write_state(state)
                print(f"started rc={1 if failed else 0}")
                sys.exit(0)
            if cmd.startswith(PROG + " dns-dhcp-check "):
                state = read_state()
                if not state["dnsmasq_running"]:
                    print("dnsmasq is not running", file=sys.stderr)
                    sys.exit(1)
                if (root / "fail-nslookup").exists():
                    print("nslookup openwrt.org 127.0.0.1 failed", file=sys.stderr)
                    sys.exit(1)
                if cmd.split()[2] == "1" and not state["dhcp_listener"]:
                    print("no DHCP listener (udp 67) from dnsmasq", file=sys.stderr)
                    sys.exit(1)
                sys.exit(0)
            print(f"stub ssh: unhandled remote command: {cmd}", file=sys.stderr)
            sys.exit(127)
            """
        )
    )
    ssh.chmod(0o755)

    sleep = bindir / "sleep"
    sleep.write_text("#!/bin/sh\nexec /bin/sleep 0.05\n")
    sleep.chmod(0o755)

    health_check = routerbin / "health-check"
    health_check.write_text(
        textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import json
            import os
            from pathlib import Path
            import sys

            state_file = Path(os.environ["STUB_ROOT"]) / "router.json"
            state = json.loads(state_file.read_text())
            results = state["health_checks"]
            current = results[0] if results else "ok"
            if len(results) > 1:
                state["health_checks"] = results[1:]
                state_file.write_text(json.dumps(state))
            if current != "ok":
                print(current, file=sys.stderr)
                sys.exit(1)
            sys.exit(0)
            """
        )
    )
    health_check.chmod(0o755)

    nft = routerbin / "nft"
    nft.write_text(
        textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import json
            import os
            from pathlib import Path
            import sys

            state = json.loads((Path(os.environ["STUB_ROOT"]) / "router.json").read_text())
            if sys.argv[1:] == ["list", "table", "inet", "fw4"]:
                sys.exit(0 if state["fw_table"] else 1)
            sys.exit(0)
            """
        )
    )
    nft.chmod(0o755)

    fw4 = routerbin / "fw4"
    fw4.write_text(
        textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import json
            import os
            from pathlib import Path
            import sys

            state_file = Path(os.environ["STUB_ROOT"]) / "router.json"
            state = json.loads(state_file.read_text())
            if sys.argv[1:] == ["stop"]:
                state["fw_table"] = False
            elif sys.argv[1:] == ["start"]:
                state["fw_table"] = state["fw4_start_works"]
            state_file.write_text(json.dumps(state))
            sys.exit(0)
            """
        )
    )
    fw4.chmod(0o755)

    firewall_init = routerbin / "firewall-init"
    firewall_init.write_text(
        textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import json
            import os
            from pathlib import Path
            import signal
            import sys

            root = Path(os.environ["STUB_ROOT"])
            state_file = root / "router.json"
            state = json.loads(state_file.read_text())
            if sys.argv[1:] != ["restart"]:
                sys.exit(2)
            with (root / "events.log").open("a") as events:
                events.write("FW-RESTART\\n")
            modes = state["fw_restart"]
            mode = modes[0]
            if len(modes) > 1:
                state["fw_restart"] = modes[1:]
            if mode == "ok":
                state["fw_table"] = True
                rc = 0
            elif mode == "refuse":
                print("/dev/stdin:9:6-7: Error: Could not process rule: File exists")
                print("The rendered ruleset contains errors, not doing firewall restart.")
                rc = 1
            elif mode in ("refuse-markers", "refuse-confirmed"):
                if mode == "refuse-markers":
                    print("ROLLBACK WINDOW PASSED in rendered firewall output")
                else:
                    sys.stdout.write("refusal\\rCONFIRMED in rendered firewall output\\n")
                print("The rendered ruleset contains errors, not doing firewall restart.")
                rc = 1
            elif mode in ("lose", "lose-confirmed"):
                if mode == "lose-confirmed":
                    sys.stdout.write("recovery\\rCONFIRMED in firewall recovery output\\n")
                state["fw_table"] = False
                rc = 0
            elif mode == "exit3":
                state["fw_table"] = True
                rc = 3
            else:
                print(f"fake firewall init: unknown restart mode: {mode}", file=sys.stderr)
                rc = 127
            state_file.write_text(json.dumps(state))
            signal_name = os.environ.get("FW_SIGNAL_PARENT")
            if mode == "lose" and signal_name:
                os.kill(os.getppid(), getattr(signal, "SIG" + signal_name))
            if os.environ.get("FW_SSH_FAIL_AFTER") == "1":
                os.kill(os.getppid(), signal.SIGKILL)
            sys.exit(rc)
            """
        )
    )
    firewall_init.chmod(0o755)

    env = os.environ.copy()
    env.update(
        {
            "HOME": str(tmp_path),
            "XDG_STATE_HOME": str(tmp_path / "state"),
            "OWRT_AUDIT_LOG": str(tmp_path / "audit.log"),
            "OWRT_BACKUP_DIR": str(tmp_path / "backups"),
            "PATH": str(bindir) + os.pathsep + env["PATH"],
            "STUB_ROOT": str(tmp_path),
            "HELPER": str(HELPER),
            "BASH_ENV": str(bash_env),
            "OWRT_SRC_ROOT": str(SCRIPT.parents[1]),
        }
    )
    # NB: the fixture does NOT pre-create the XDG_STATE_HOME / OWRT_BACKUP_DIR
    # parents.  Tests that need them (run() and run_plan()) chmod their own
    # creation to 0700 after mkdir; the script then takes the same step, and
    # tests like ``test_control_character_in_argument_dies_before_state_or_ssh``
    # still find no state directory after the script's early exit (the
    # "control character" guard sits above the mkdir).
    env.pop("OWRT_SSH_PASSWORD_FILE", None)
    env.pop("OWRT_SSH_PROXY", None)
    env.pop("OWRT_LOCAL_CHECK", None)
    env.pop("OWRT_APPROVAL_TOKEN", None)
    env.pop("OWRT_SSH_KEY", None)
    env.pop("OWRT_KNOWN_HOSTS", None)
    env.pop("OWRT_EXPECT_DEVICE", None)
    env.pop("OWRT_EXPECT_PROFILE", None)

    def _wrap_with_unshare(args, run_env, stdin_kwargs, timeout):
        """Run *args* in a private user+mount namespace where bindir/ssh is
        bind-mounted at /usr/bin/ssh.  The host script resolves ssh via
        /usr/bin/ssh (or /bin/ssh); the bind-mount is the only way to
        redirect that resolution without changing the script."""
        fake_ssh = str(bindir / "ssh")
        unshare_cmd = [
            "unshare", "-Urm", "--", "bash", "-c",
            'mount --bind "$1" /usr/bin/ssh && shift && exec "$@"',
            "noop", fake_ssh, *args,
        ]
        return subprocess.run(
            unshare_cmd, env=run_env, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=timeout, **stdin_kwargs,
        )

    def run(*, extra_env=None, stdin_data=None, timeout_s=60):
        plan = tmp_path / "state" / "network-agent" / "plans" / f"{SID}.sha256"
        plan.parent.mkdir(parents=True, exist_ok=True)
        # the script refuses a parent that is group- or world-writable without
        # the sticky bit; pytest's default umask (0002 here) lands the dirs at
        # 0775, so chmod each level to 0700 after mkdir.
        for parent in (plan.parent, plan.parent.parent, plan.parent.parent.parent):
            if parent.exists():
                os.chmod(parent, 0o700)
        diff = json.loads((tmp_path / "router.json").read_text())["diff"]
        plan.write_text(hashlib.sha256((diff.rstrip("\n") + "\n").encode()).hexdigest() + "\n")
        args = [str(SCRIPT), "apply", "root@192.0.2.1", SID, str(timeout_s)]
        run_env = env.copy()
        if extra_env:
            run_env.update(extra_env)
        stdin_kwargs = {"input": stdin_data} if stdin_data is not None else {"stdin": subprocess.DEVNULL}
        return _wrap_with_unshare(args, run_env, stdin_kwargs, 180)

    def run_plan(changes, *, probes=None, timeout=None, extra_env=None, extra_args=None):
        args = [str(SCRIPT), "plan", "root@192.0.2.1", str(changes)]
        if extra_args:
            args.extend(extra_args)
        elif timeout is not None or probes is not None:
            args.append(str(timeout if timeout is not None else 90))
            if probes is not None:
                args.append(str(probes))
        run_env = env.copy()
        if extra_env:
            run_env.update(extra_env)
        return _wrap_with_unshare(
            args, run_env, {"stdin": subprocess.DEVNULL}, 60
        )

    return {
        "run": run,
        "run_plan": run_plan,
        "root": tmp_path,
        "audit": tmp_path / "audit.log",
        "calls": tmp_path / "calls.log",
        "events": tmp_path / "events.log",
        "stdin": tmp_path / "stdin.log",
        "timed_events": tmp_path / "timed-events.log",
        "seal_stdin": tmp_path / "seal-stdin.log",
        "ssh_argv": tmp_path / "ssh-argv.log",
        "env": env,
        "router": tmp_path / "router.json",
        "routerbin": routerbin,
    }


def set_router_state(protocol, **updates):
    state = json.loads(protocol["router"].read_text())
    state.update(updates)
    protocol["router"].write_text(json.dumps(state))


def remote_calls(protocol):
    return [json.loads(line) for line in protocol["calls"].read_text().splitlines()]


def verify_rounds(protocol):
    return [call for call in remote_calls(protocol) if call.startswith(f"{PROG} verify ")]


def verify_need_dhcp(protocol):
    return [int(call.rsplit(" ", 1)[1]) for call in verify_rounds(protocol)]


def fail_verify_rounds(protocol):
    """The router-side ping fails every verify round (reaches the rollback path)."""
    (protocol["root"] / "fail-ping").touch()


def seal_stdin_records(protocol):
    return [json.loads(line) for line in protocol["seal_stdin"].read_text().splitlines()]


def run_named_helper(changes, *, staged=None, live=None, command=None, exports=None):
    staged = staged or {}
    live = live or {}
    exports = exports or {}
    command = command or ["named", SID]

    def cases(values):
        lines = []
        for key, value in values.items():
            lines.append(
                f"{shlex.quote(key)}) printf '%s\\n' {shlex.quote(value)}; return 0 ;;"
            )
        return "\n".join(lines)

    shell = textwrap.dedent(
        f"""\
        uci() {{
            if [ "${{1:-}}" = -q ] && [ "${{2:-}}" = export ]; then
                case "${{3:-}}" in
                    {cases(exports)}
                esac
                return 1
            fi
            if [ "${{1:-}}" = -P ] && [ "${{3:-}}" = changes ] && [ "${{4:-}}" = firewall ]; then
                printf '%s' {shlex.quote(changes)}
                return 0
            fi
            if [ "${{1:-}}" = -P ] && [ "${{3:-}}" = -q ] && [ "${{4:-}}" = get ]; then
                case "${{5:-}}" in
                    {cases(staged)}
                esac
                return 1
            fi
            if [ "${{1:-}}" = -q ] && [ "${{2:-}}" = get ]; then
                case "${{3:-}}" in
                    {cases(live)}
                esac
                return 1
            fi
            return 1
        }}
        ubus() {{ return 0; }}
        jsonfilter() {{ return 0; }}
        set -- {shlex.join(command)}
        . {shlex.quote(str(HELPER))}
        """
    )
    busybox = shutil.which("busybox")
    assert busybox is not None
    return subprocess.run(
        [busybox, "sh", "-c", shell],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )


def run_fwrestart_helper(protocol, loaded_before, signal_name=None):
    busybox = shutil.which("busybox")
    assert busybox is not None
    env = os.environ.copy()
    env.update(
        {
            "PATH": str(protocol["routerbin"]) + os.pathsep + env["PATH"],
            "STUB_ROOT": str(protocol["root"]),
            "NEWTON_FIREWALL_INIT": str(protocol["routerbin"] / "firewall-init"),
        }
    )
    if signal_name is not None:
        env["FW_SIGNAL_PARENT"] = signal_name
    return subprocess.run(
        [busybox, "sh", str(HELPER), "fwrestart", loaded_before],
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )


def router_state(protocol):
    return json.loads(protocol["router"].read_text())


def stdin_records(protocol):
    return [json.loads(line) for line in protocol["stdin"].read_text().splitlines()]


def load_lab_runner():
    path = SCRIPT.parents[1] / "lab" / "newton-lab-test.py"
    spec = importlib.util.spec_from_file_location("packet_c_lab_runner", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_mcp_server():
    mcp_root = SCRIPT.parents[1] / "mcp"
    sys.path.insert(0, str(mcp_root))
    try:
        return importlib.import_module("newton_mcp.server")
    finally:
        sys.path.remove(str(mcp_root))


def test_apply_rejects_timeout_below_60_before_hello_or_apply(protocol):
    result = protocol["run"](timeout_s=59)

    assert result.returncode == 1
    assert "timeout must be an integer 60..600" in result.stdout
    calls = remote_calls(protocol)
    assert not any(call.startswith(f"{PROG} hello ") for call in calls)
    assert not any(call.startswith(f"{PROG} apply ") for call in calls)


@pytest.mark.parametrize(("timeout_s", "returncode"), [(59, 1), (60, 0)])
def test_helper_enforces_60_second_minimum(timeout_s, returncode):
    result = run_named_helper("", command=["apply", SID, str(timeout_s)])

    assert result.returncode == returncode
    if timeout_s == 59:
        assert "timeout must be an integer 60..600" in result.stderr
    else:
        assert "APPLIED with rollback" in result.stdout


def run_confighash_helper(config_dir):
    busybox = shutil.which("busybox")
    assert busybox is not None
    env = os.environ.copy()
    env["NEWTON_CONFIG_DIR"] = str(config_dir)
    return subprocess.run(
        [busybox, "sh", str(HELPER), "confighash"],
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )


def run_health_helper_checks(tmp_path, before, afters, *, fw_before=(0, ""),
                             fw_after=(0, ""), with_fw4=True, modes=None):
    """Run health-snapshot and successive health-checks with fake OpenWrt commands."""
    bindir = tmp_path / "health-bin"
    bindir.mkdir()
    services = tmp_path / "services.json"
    fw_rc = tmp_path / "fw.rc"
    fw_output = tmp_path / "fw.output"

    ubus = bindir / "ubus"
    ubus.write_text(
        "#!/bin/sh\n"
        "if [ \"$1 $2 $3\" = \"call service list\" ]; then cat \"$HEALTH_SERVICES\"; fi\n"
        "exit 0\n"
    )
    ubus.chmod(0o755)

    ucode = bindir / "ucode"
    ucode.write_text(
        textwrap.dedent(
            """\
            #!/usr/bin/env python3
            import json
            import sys

            source = sys.argv[2]
            services = json.load(sys.stdin)
            snapshot = 'if (state?.running == true)' in source
            line_end = r'\\n' if r'\\\\n' in source else '\\n'
            tab = r'\\t' if r'\\\\t' in source else '\\t'
            for service, body in services.items():
                for instance, state in body.get("instances", {}).items():
                    running = state.get("running") is True
                    if snapshot:
                        if running:
                            sys.stdout.write(f"{service}/{instance}{line_end}")
                    else:
                        pid = state.get("pid", "")
                        sys.stdout.write(
                            f"{service}/{instance}{tab}"
                            f"{'true' if running else 'false'}{tab}{pid}{line_end}"
                        )
            """
        )
    )
    ucode.chmod(0o755)

    if with_fw4:
        fw4 = bindir / "fw4"
        fw4.write_text(
            "#!/bin/sh\ncat \"$HEALTH_FW_OUTPUT\"\nexit \"$(cat \"$HEALTH_FW_RC\")\"\n"
        )
        fw4.chmod(0o755)

    lock = tmp_path / "lock"
    lock.mkdir()
    (lock / "sid").write_text(SID)
    env = os.environ.copy()
    env.update({
        "PATH": str(bindir) + os.pathsep + env["PATH"],
        "NEWTON_LOCK": str(lock),
        "HEALTH_SERVICES": str(services),
        "HEALTH_FW_RC": str(fw_rc),
        "HEALTH_FW_OUTPUT": str(fw_output),
    })
    busybox = shutil.which("busybox")
    assert busybox is not None
    services.write_text(json.dumps(before))
    fw_rc.write_text(str(fw_before[0]))
    fw_output.write_text(fw_before[1])
    snapshot = subprocess.run(
        [busybox, "sh", str(HELPER), "health-snapshot", SID],
        env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=10,
    )
    fw_rc.write_text(str(fw_after[0]))
    fw_output.write_text(fw_after[1])
    checks = []
    if modes is None:
        modes = [None] * len(afters)
    assert len(modes) == len(afters)
    for after, mode in zip(afters, modes):
        services.write_text(json.dumps(after))
        command = [busybox, "sh", str(HELPER), "health-check", SID]
        if mode is not None:
            command.append(mode)
        checks.append(subprocess.run(
            command,
            env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=10,
        ))
    return snapshot, checks


def run_health_helper(tmp_path, before, after, *, fw_before=(0, ""),
                      fw_after=(0, ""), with_fw4=True):
    """Run one health-snapshot and health-check with fake OpenWrt commands."""
    snapshot, checks = run_health_helper_checks(
        tmp_path, before, [after], fw_before=fw_before, fw_after=fw_after,
        with_fw4=with_fw4,
    )
    return snapshot, checks[0]


def service_state(running, pid=100):
    state = {"running": running}
    if pid is not None:
        state["pid"] = pid
    return {"dnsmasq": {"instances": {"instance1": state}}}


def test_health_snapshot_and_check_pass_when_unchanged(tmp_path):
    """Guards escaping: unchanged real-ucode records stay healthy."""
    snapshot, check = run_health_helper(tmp_path, service_state(True), service_state(True))
    assert snapshot.returncode == 0, snapshot.stderr
    assert check.returncode == 0, check.stderr


def test_health_check_fails_when_existing_instance_stops(tmp_path):
    """Guards: an existing baseline-running instance must not become stopped."""
    _, check = run_health_helper(tmp_path, service_state(True), service_state(False))
    assert check.returncode == 1
    assert check.stderr == "health: service dnsmasq/instance1 is not running after the change\n"


def test_health_check_allows_removed_instance(tmp_path):
    """Guards: deleting a service instance in the staged config is allowed."""
    _, check = run_health_helper(tmp_path, service_state(True), {})
    assert check.returncode == 0, check.stderr


def test_health_check_ignores_instance_stopped_in_snapshot(tmp_path):
    """Guards: only instances running in the baseline snapshot are protected."""
    before = service_state(True)
    before["uhttpd"] = {"instances": {"instance1": {"running": False}}}
    after = service_state(True)
    after["uhttpd"] = {"instances": {"instance1": {"running": False}}}
    _, check = run_health_helper(tmp_path, before, after)
    assert check.returncode == 0, check.stderr


def test_health_check_fails_when_fw4_check_fails(tmp_path):
    """Guards: a nonzero post-change fw4 check blocks confirmation."""
    _, check = run_health_helper(
        tmp_path, service_state(True), service_state(True),
        fw_after=(1, "Error: invalid rule\n")
    )
    assert check.returncode == 1
    assert check.stderr == "health: fw4 check failed: Error: invalid rule\n"


def test_health_check_fails_on_new_fw4_warning(tmp_path):
    """Guards: a new fw4 [!] warning is a health regression."""
    _, check = run_health_helper(
        tmp_path, service_state(True), service_state(True),
        fw_after=(0, "[!] new warning\n"),
    )
    assert check.returncode == 1
    assert check.stderr == "health: new firewall warning: [!] new warning\n"


def test_health_check_allows_new_disabled_section_notice(tmp_path):
    """disabling a section may add this benign fw4 notice."""
    notice = "[!] Section @rule[1] (Allow-Ping) is disabled, ignoring section\n"
    _, check = run_health_helper(
        tmp_path, service_state(True), service_state(True),
        fw_after=(0, notice),
    )
    assert check.returncode == 0, check.stderr


@pytest.mark.parametrize(
    "warning",
    [
        "[!] Section @rule[2] references unknown set 'missing'",
        "[!] Section @rule[2] skipped due to invalid options",
    ],
)
def test_health_check_still_fails_on_other_new_fw4_warning(tmp_path, warning):
    """the disabled-section exception must not hide other warnings."""
    notice = "[!] Section @rule[1] (Allow-Ping) is disabled, ignoring section"
    _, check = run_health_helper(
        tmp_path, service_state(True), service_state(True),
        fw_after=(0, f"{notice}\n{warning}\n"),
    )
    assert check.returncode == 1
    assert check.stderr == f"health: new firewall warning: {warning}\n"


def test_health_check_allows_baseline_fw4_warning(tmp_path):
    """Guards: a pre-existing fw4 [!] warning remains permitted."""
    warning = "[!] baseline warning\n"
    _, check = run_health_helper(
        tmp_path, service_state(True), service_state(True),
        fw_before=(0, warning), fw_after=(0, warning)
    )
    assert check.returncode == 0, check.stderr


@pytest.mark.parametrize(
    ("fw_output", "problem"),
    [
        ("Error: invalid baseline rule\nError: later detail\n", "Error: invalid baseline rule"),
        ("", "no output"),
        (f"{FW4_NOTICE}\n{FW4_REAL_ERROR}\n", FW4_REAL_ERROR),
        (f"{FW4_NOTICE}\n", FW4_NOTICE),
        (f"{FW4_NOTICE}\n{FW4_NOTICE}\n{FW4_REAL_ERROR}\n", FW4_REAL_ERROR),
    ],
)
def test_health_snapshot_refuses_existing_fw4_failure(tmp_path, fw_output, problem):
    """C1: a broken pre-change firewall fails before publishing a snapshot.

    The real-fw4 rows check that a disabled-section notice (which health-check
    ignores) is skipped when naming the offending line; if every line is such a
    notice, the first line is named anyway.
    """
    snapshot, _ = run_health_helper_checks(
        tmp_path, service_state(True), [], fw_before=(1, fw_output)
    )

    assert snapshot.returncode == 1
    assert snapshot.stderr == (
        "ERROR: the firewall config already fails fw4 check before the change: "
        f"{problem}; fix it first\n"
    )
    assert not (tmp_path / "lock" / f"{SID}.health").exists()
    assert not (tmp_path / "lock" / f"{SID}.health.new").exists()


def test_health_snapshot_allows_existing_fw4_warning(tmp_path):
    """C1: fw4 warnings with a successful check are still saved as a baseline."""
    warning = "[!] baseline warning\n"
    snapshot, _ = run_health_helper_checks(
        tmp_path, service_state(True), [], fw_before=(0, warning)
    )

    health = tmp_path / "lock" / f"{SID}.health"
    assert snapshot.returncode == 0, snapshot.stderr
    assert health.is_dir()
    assert (health / "fw4.warnings").read_text() == warning


def test_health_check_without_fw4_skips_firewall_checks(tmp_path):
    """Guards: routers without fw4 still receive service health checks."""
    _, check = run_health_helper(
        tmp_path, service_state(True), service_state(True), with_fw4=False
    )
    assert check.returncode == 0, check.stderr


def test_health_snapshot_writes_one_real_line_per_running_instance(tmp_path):
    """Guards: ucode must emit newlines, not literal backslash-n text."""
    before = service_state(True)
    before["uhttpd"] = {
        "instances": {"instance1": {"running": True, "pid": 200}}
    }

    snapshot, _ = run_health_helper_checks(tmp_path, before, [])

    running = tmp_path / "lock" / f"{SID}.health" / "running"
    assert snapshot.returncode == 0, snapshot.stderr
    assert running.read_text().splitlines() == [
        "dnsmasq/instance1",
        "uhttpd/instance1",
    ]


def test_health_snapshot_fails_closed_when_no_service_is_running(tmp_path):
    """Guards: an empty protected-service baseline cannot pass vacuously."""
    snapshot, _ = run_health_helper_checks(tmp_path, service_state(False), [])

    assert snapshot.returncode == 1
    assert snapshot.stderr == "ERROR: no running services found\n"


def test_health_snapshot_rejects_malformed_ucode_records(tmp_path):
    """Guards: malformed snapshot records fail before state is saved."""
    malformed = {
        "bad/service": {
            "instances": {"instance1": {"running": True, "pid": 1}}
        }
    }

    snapshot, _ = run_health_helper_checks(tmp_path, malformed, [])

    assert snapshot.returncode == 1
    assert snapshot.stderr == "ERROR: invalid service health output\n"


def test_health_check_rejects_malformed_ucode_records(tmp_path):
    """Guards: malformed current-service records fail closed."""
    malformed = service_state(True)
    malformed["bad/service"] = {
        "instances": {"instance1": {"running": True, "pid": 1}}
    }

    _, check = run_health_helper(tmp_path, service_state(True), malformed)

    assert check.returncode == 1
    assert check.stderr == "ERROR: invalid service health output\n"


def test_health_check_fails_when_pid_changes_between_calls(tmp_path):
    """Guards: a restart between verify rounds fails that health round."""
    _, checks = run_health_helper_checks(
        tmp_path,
        service_state(True, 100),
        [service_state(True, 100), service_state(True, 101)],
    )

    assert checks[0].returncode == 0, checks[0].stderr
    assert checks[1].returncode == 1
    assert checks[1].stderr == (
        "health: service dnsmasq/instance1 restarted between verify rounds\n"
    )


def test_health_check_passes_after_one_pid_change_stabilizes(tmp_path):
    """Guards: a one-time restart costs one round, then stable PIDs pass."""
    _, checks = run_health_helper_checks(
        tmp_path,
        service_state(True, 100),
        [
            service_state(True, 100),
            service_state(True, 101),
            service_state(True, 101),
            service_state(True, 101),
        ],
    )

    assert [check.returncode for check in checks] == [0, 1, 0, 0]


def test_first_health_check_records_changed_pid_without_failing(tmp_path):
    """Guards: the first post-snapshot call establishes the PID baseline."""
    _, check = run_health_helper(
        tmp_path, service_state(True, 100), service_state(True, 200)
    )

    assert check.returncode == 0, check.stderr


def test_health_check_fails_when_running_instance_has_no_pid(tmp_path):
    """Guards: a protected running instance without a PID fails closed."""
    _, check = run_health_helper(
        tmp_path, service_state(True, 100), service_state(True, None)
    )

    assert check.returncode == 1
    assert check.stderr == (
        "health: service dnsmasq/instance1 restarted between verify rounds\n"
    )


def test_health_check_after_rollback_allows_pid_change(tmp_path):
    """Guards: rollback service restarts do not trigger the verify PID rule."""
    _, checks = run_health_helper_checks(
        tmp_path,
        service_state(True, 100),
        [service_state(True, 100), service_state(True, 200)],
        modes=[None, "after-rollback"],
    )

    assert checks[0].returncode == 0, checks[0].stderr
    assert checks[1].returncode == 0, checks[1].stderr


def test_health_check_after_rollback_still_fails_stopped_instance(tmp_path):
    """Guards: rollback mode still enforces baseline running state."""
    _, checks = run_health_helper_checks(
        tmp_path,
        service_state(True, 100),
        [service_state(False, None)],
        modes=["after-rollback"],
    )

    assert checks[0].returncode == 1
    assert checks[0].stderr == (
        "health: service dnsmasq/instance1 is not running after the change\n"
    )


def test_confighash_hashes_raw_bytes_and_skips_dotfiles_and_directories(tmp_path):
    """Catches an earlier version's uci-export hashing and kills C3/M01-M03."""
    config = tmp_path / "config"
    config.mkdir()
    raw = b"package network\n\xffraw\x00bytes\n"
    (config / "network").write_bytes(raw)
    (config / ".hidden").write_bytes(b"ignored")
    (config / "subdir").mkdir()
    (config / "subdir" / "inside").write_bytes(b"ignored")

    result = run_confighash_helper(config)

    assert result.returncode == 0, result.stderr
    assert result.stdout == f"{hashlib.md5(raw).hexdigest()} network\n"


def test_confighash_prints_printable_filenames_unchanged(tmp_path):
    """Catches an earlier version's package-name path and kills C3/M01-M03 for C5 names."""
    config = tmp_path / "config"
    config.mkdir()
    body = b"space name bytes"
    utf8_body = b"utf8 plus bytes"
    (config / "guest wifi").write_bytes(body)
    (config / "r\N{LATIN SMALL LETTER E WITH ACUTE}seau+guest").write_bytes(utf8_body)

    result = run_confighash_helper(config)

    assert result.returncode == 0, result.stderr
    assert result.stdout == (
        f"{hashlib.md5(body).hexdigest()} guest wifi\n"
        f"{hashlib.md5(utf8_body).hexdigest()} r\N{LATIN SMALL LETTER E WITH ACUTE}seau+guest\n"
    )


def test_confighash_refuses_unreadable_file(tmp_path):
    """Kills M01-M03 by requiring a hard failure instead of an empty digest."""
    config = tmp_path / "config"
    config.mkdir()
    unreadable = config / "secret"
    unreadable.write_bytes(b"secret")
    unreadable.chmod(0)

    result = run_confighash_helper(config)

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == "ERROR: confighash cannot read config file: secret\n"


def test_confighash_refuses_control_character_filename(tmp_path):
    """Kills M01-M03 by rejecting and safely reporting a newline-bearing name."""
    config = tmp_path / "config"
    config.mkdir()
    (config / "bad\nCONFIRMED").write_bytes(b"bad")

    result = run_confighash_helper(config)

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == (
        "ERROR: confighash unsafe config file name: bad CONFIRMED\n"
    )


@pytest.mark.parametrize(
    ("changes", "staged", "live", "expected"),
    [
        (
            "firewall.cfg03dc81.log_limit='30/minute'\n",
            {
                "firewall.cfg03dc81": "zone",
                "firewall.cfg03dc81.name": "wan",
            },
            {},
            "firewall.cfg03dc81.log_limit (zone wan: limit wan.log_limit)\n",
        ),
        (
            "@firewall.cfg03dc81.log_limit='5/second'\n",
            {
                "firewall.cfg03dc81": "zone",
                "firewall.cfg03dc81.name": "wan",
            },
            {},
            "firewall.cfg03dc81.log_limit (zone wan: limit wan.log_limit)\n",
        ),
        (
            "firewall.cfg03dc81.network-='wan2'\n",
            {
                "firewall.cfg03dc81": "zone",
                "firewall.cfg03dc81.name": "wan",
            },
            {},
            "",
        ),
        (
            "firewall.allow_dns.log_limit='30/minute'\n",
            {
                "firewall.allow_dns": "rule",
                "firewall.allow_dns.name": "Allow-DNS",
            },
            {},
            "",
        ),
        (
            "firewall.ts.entry+='192.0.2.1'\n",
            {"firewall.ts": "ipset", "firewall.ts.name": "ts"},
            {},
            "firewall.ts (ipset ts: set ts)\n",
        ),
        (
            "-firewall.ts\n",
            {},
            {"firewall.ts": "ipset", "firewall.ts.name": "ts"},
            "firewall.ts (ipset ts: set ts)\n",
        ),
        ("", {}, {}, ""),
    ],
    ids=[
        "zone-log-limit-set",
        "zone-log-limit-prefixed",
        "zone-network-only",
        "rule-log-limit",
        "ipset-entry-add",
        "deleted-ipset",
        "nothing-staged",
    ],
)
def test_named_helper_reports_only_named_nft_objects(changes, staged, live, expected):
    result = run_named_helper(changes, staged=staged, live=live)

    assert result.returncode == 0, result.stderr
    assert result.stdout == expected


def test_fwrestart_helper_restart_works(protocol):
    result = run_fwrestart_helper(protocol, "1")

    assert result.returncode == 0, result.stdout + result.stderr
    assert router_state(protocol)["fw_table"] is True
    assert protocol["events"].read_text().splitlines() == ["FW-RESTART"]


def test_fwrestart_helper_restart_refused(protocol):
    set_router_state(protocol, fw_restart=["refuse"])
    result = run_fwrestart_helper(protocol, "1")

    assert result.returncode == 1
    assert "/dev/stdin:9:6-7: Error: Could not process rule: File exists" in result.stdout
    assert "The rendered ruleset contains errors, not doing firewall restart." in result.stdout
    assert "firewall restart exited 1" in result.stdout
    assert router_state(protocol)["fw_table"] is True


def test_fwrestart_helper_restart_loses_table_and_recovers(protocol):
    set_router_state(protocol, fw_restart=["lose"])
    result = run_fwrestart_helper(protocol, "1")

    assert result.returncode == 98
    assert "the fw4 table is missing after the restart: loading it again" in result.stdout
    assert router_state(protocol)["fw_table"] is True


@pytest.mark.parametrize("signal_name", ["HUP", "PIPE"])
def test_fwrestart_helper_survives_dropped_transport_signal(protocol, signal_name):
    set_router_state(protocol, fw_restart=["lose"])
    result = run_fwrestart_helper(protocol, "1", signal_name=signal_name)

    assert result.returncode == 98
    assert "the fw4 table is missing after the restart: loading it again" in result.stdout
    assert router_state(protocol)["fw_table"] is True


def test_fwrestart_helper_restart_loses_table_and_recovery_fails(protocol):
    set_router_state(protocol, fw_restart=["lose"], fw4_start_works=False)
    result = run_fwrestart_helper(protocol, "1")

    assert result.returncode == 99
    assert "the fw4 table is STILL missing" in result.stdout
    assert router_state(protocol)["fw_table"] is False


def test_fwrestart_helper_leaves_previously_unloaded_firewall_alone(protocol):
    set_router_state(protocol, fw_table=False)
    result = run_fwrestart_helper(protocol, "0")

    assert result.returncode == 3
    assert "the firewall is not loaded (no table inet fw4): left as it is" in result.stdout
    assert protocol["events"].read_text() == ""


def test_fwrestart_helper_recovers_table_missing_before_attempt(protocol):
    set_router_state(protocol, fw_table=False)
    result = run_fwrestart_helper(protocol, "1")

    assert result.returncode == 98
    assert "missing although it was loaded before the apply" in result.stdout
    assert router_state(protocol)["fw_table"] is True
    assert protocol["events"].read_text() == ""


def test_fwrestart_helper_reports_table_missing_before_attempt_and_unrecoverable(protocol):
    set_router_state(protocol, fw_table=False, fw4_start_works=False)
    result = run_fwrestart_helper(protocol, "1")

    assert result.returncode == 99
    assert "the fw4 table is STILL missing" in result.stdout
    assert router_state(protocol)["fw_table"] is False
    assert protocol["events"].read_text() == ""


def test_fwrestart_helper_normalizes_restart_exit_3(protocol):
    set_router_state(protocol, fw_restart=["exit3"])
    result = run_fwrestart_helper(protocol, "1")

    assert result.returncode == 1
    assert "firewall restart exited 3" in result.stdout
    assert router_state(protocol)["fw_table"] is True


def test_fwrestart_helper_rejects_bad_loaded_before_argument(protocol):
    result = run_fwrestart_helper(protocol, "bad")

    assert result.returncode == 2
    assert "ERROR: fwrestart needs 0 or 1" in result.stderr
    assert protocol["events"].read_text() == ""


def test_no_named_objects_confirms_without_firewall_restart(protocol):
    result = protocol["run"]()

    assert result.returncode == 0, result.stdout
    assert f"CONFIRMED session={SID}" in result.stdout
    assert "FW-RESTART" not in protocol["events"].read_text()
    assert "NAMED NFT OBJECTS" not in result.stdout
    assert "FIREWALL" not in result.stdout
    assert f"{PROG} fw-loaded" not in remote_calls(protocol)


def test_health_failure_in_verify_rounds_prevents_confirm_and_rolls_back(protocol):
    """Guards: failed health rounds never confirm and reach rollback."""
    failure = "health: service uhttpd/instance1 is not running after the change"
    set_router_state(protocol, health_checks=[failure] * 8 + ["ok"])

    result = protocol["run"]()

    assert result.returncode == 1, result.stdout
    assert "ROLLBACK WINDOW PASSED" in result.stdout
    assert failure in result.stdout
    assert not any(f"{PROG} confirm {SID}" in call for call in remote_calls(protocol))


def test_health_snapshot_failure_refuses_before_apply(protocol):
    """Guards: an unavailable baseline leaves the session staged."""
    set_router_state(protocol, health_snapshot="ERROR: ubus call service list failed")

    result = protocol["run"]()

    assert result.returncode == 1
    assert "cannot record service and firewall health before the apply" in result.stdout
    assert f"session {SID} is still staged" in result.stdout
    assert not any(call.startswith(f"{PROG} apply {SID}") for call in remote_calls(protocol))


def test_health_snapshot_fw4_failure_refuses_before_apply(protocol):
    """C1: a broken baseline firewall leaves the wrapper session staged.

    Real fw4 shape: the notice line comes first, but the message must name the
    real error line, not the ignorable notice. The wrapper truncates the helper
    message to 120 characters (oneline), so the expected text is the first 120
    characters of the helper error — still enough to show the real error's
    section, never the notice.
    """
    snapshot, _ = run_health_helper_checks(
        protocol["root"], service_state(True), [],
        fw_before=(1, f"{FW4_NOTICE}\n{FW4_REAL_ERROR}\n"),
    )
    assert snapshot.returncode == 1
    helper_error = snapshot.stderr.rstrip("\n")
    assert FW4_REAL_ERROR in helper_error
    assert FW4_NOTICE not in helper_error
    set_router_state(protocol, health_snapshot=helper_error)

    result = protocol["run"]()

    assert result.returncode == 1
    assert "cannot record service and firewall health before the apply" in result.stdout
    assert f"session {SID} is still staged" in result.stdout
    assert f"helper said: {helper_error[:120]}" in result.stdout
    assert "firewall config already fails fw4 check before the change" in result.stdout
    assert "@forwarding[0]" in result.stdout
    assert FW4_NOTICE not in result.stdout
    assert not any(call.startswith(f"{PROG} apply {SID}") for call in remote_calls(protocol))


def test_health_failure_after_rollback_reports_alert_reason(protocol):
    """Guards: unrecovered service health produces an ALERT."""
    failure = "health: service uhttpd/instance1 is not running after the change"
    set_router_state(protocol, health_after_rollback=failure)
    fail_verify_rounds(protocol)

    result = protocol["run"]()

    assert result.returncode == 1
    assert "ALERT" in result.stdout
    assert "service or firewall health differs from before the apply after the rollback" in result.stdout
    assert failure in result.stdout
    assert "ROLLBACK WINDOW PASSED" not in result.stdout
    assert f"{PROG} health-check {SID} after-rollback" in remote_calls(protocol)


def test_apply_audits_masked_diff_and_operator_without_leaking_secret(protocol):
    """Guards: apply audit records masked diff/operator and never the raw secret."""
    secret = "lab-secret-123"
    community = "private-community"
    token = "mixed-case-token"
    diff = (
        f"system.cfg.newton_test_password='{secret}'\n"
        f"firewall.sec.community+='{community}'\n"
        f"rpcd.login.API_TOKEN='{token}'\n"
        "dhcp.lab.limit='60'\n"
    )
    set_router_state(protocol, diff=diff)

    result = protocol["run"](extra_env={"OWRT_OPERATOR": "test-operator"})

    audit = protocol["audit"].read_text()
    combined = result.stdout + audit
    assert result.returncode == 0, result.stdout
    assert f"DIFF session={SID}: system.cfg.newton_test_password='<masked>'" in audit
    assert f"DIFF session={SID}: firewall.sec.community+='<masked>'" in audit
    assert f"DIFF session={SID}: rpcd.login.API_TOKEN='<masked>'" in audit
    assert f"DIFF session={SID}: dhcp.lab.limit='60'" in audit
    assert f"OPERATOR session={SID}: test-operator" in audit
    assert secret not in combined
    assert community not in combined
    assert token not in combined


def test_plan_prints_masked_diff_without_leaking_secret(protocol, tmp_path):
    """Guards: the model-facing plan diff masks secret option values."""
    secret = "plan-secret-456"
    set_router_state(protocol, diff=f"wireless.default_radio0.key='{secret}'\n")
    changes = tmp_path / "change.uci"
    changes.write_text(f"set wireless.default_radio0.key='{secret}'\n")

    result = protocol["run_plan"](changes)

    audit = protocol["audit"].read_text()
    assert result.returncode == 0, result.stdout
    assert "wireless.default_radio0.key='<masked>'" in result.stdout
    raw_confighash = (
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb dhcp\n"
        "cccccccccccccccccccccccccccccccc firewall\n"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa network\n"
    )
    # the seal's base hashes the confighash text exactly as the program prints it:
    # every line LF-terminated (design 3.5b step 3)
    expected_base = hashlib.sha256(raw_confighash.encode()).hexdigest()
    assert f"BASEHASH {expected_base}" in result.stdout
    assert f"OPERATOR session={SID}: planner" not in audit  # plan ran without OWRT_OPERATOR
    assert secret not in result.stdout
    assert secret not in audit


def test_plan_reports_operator_when_set(protocol, tmp_path):
    changes = tmp_path / "change.uci"
    changes.write_text("set system.@system[0].description='lab'\n")

    result = protocol["run_plan"](changes, extra_env={"OWRT_OPERATOR": "planner"})

    assert result.returncode == 0, result.stdout
    assert f"OPERATOR session={SID}: planner" in protocol["audit"].read_text()


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (["59"], "timeout must be an integer 60..600"),
        (["90", "/nonexistent/probes"], "probes file not readable"),
        (["90", "TOO-BIG"], "probes file larger than 4096 bytes"),
        (["90", "HAS-CR"], "probes file contains CR"),
    ],
    ids=["bad-timeout", "unreadable-probes", "oversized-probes", "cr-in-probes"],
)
def test_plan_refuses_bad_arguments_before_any_ssh_call(protocol, tmp_path, extra, message):
    """Probes are validated on the host before any ssh call (design 7.1 row 136-139)."""
    changes = tmp_path / "change.uci"
    changes.write_text("set system.@system[0].description='lab'\n")
    probes = tmp_path / "probes"
    probes.write_text("probe-one\n")
    size = 4096 - probes.stat().st_size + 1
    (tmp_path / "TOO-BIG").write_bytes(b"x" * 4100)
    (tmp_path / "HAS-CR").write_bytes(b"probe-one\r\n")
    extra = [
        str(tmp_path / "TOO-BIG") if arg == "TOO-BIG" else str(tmp_path / "HAS-CR") if arg == "HAS-CR" else arg
        for arg in extra
    ]

    result = protocol["run_plan"](changes, extra_args=extra)

    assert result.returncode == 1
    assert message in result.stdout
    assert remote_calls(protocol) == []


def test_plan_without_probes_file_seals_from_devnull(protocol, tmp_path):
    """No probes file means seal's stdin is /dev/null and nothing is staged as probes."""
    changes = tmp_path / "change.uci"
    changes.write_text("set system.@system[0].description='lab'\n")

    result = protocol["run_plan"](changes)

    assert result.returncode == 0, result.stdout
    records = seal_stdin_records(protocol)
    assert [record["cmd"] for record in records] == [f"{PROG} seal {SID} 90"]
    assert bytes.fromhex(records[0]["data"]) == b""
    assert "PROBES 0 " in result.stdout
    stdin_by_cmd = {record["cmd"]: record["devnull"] for record in stdin_records(protocol)}
    assert stdin_by_cmd[f"{PROG} seal {SID} 90"] is True
    assert stdin_by_cmd[f"{PROG} stage"] is False


def test_plan_probes_file_reaches_seal_stdin_byte_for_byte(protocol, tmp_path):
    """A probes file reaches seal's stdin byte for byte (design 7.1 row 142-145)."""
    changes = tmp_path / "change.uci"
    changes.write_text("set system.@system[0].description='lab'\n")
    probes = tmp_path / "probes"
    content = b"uci-equals dhcp.lab.limit '50'\nfw-loaded\n"
    probes.write_bytes(content)

    result = protocol["run_plan"](changes, probes=probes, timeout=120)

    assert result.returncode == 0, result.stdout
    records = seal_stdin_records(protocol)
    assert [record["cmd"] for record in records] == [f"{PROG} seal {SID} 120"]
    assert bytes.fromhex(records[0]["data"]) == content
    assert f"PROBES 2 {hashlib.sha256(content).hexdigest()}" in result.stdout
    stdin_by_cmd = {record["cmd"]: record["devnull"] for record in stdin_records(protocol)}
    assert stdin_by_cmd[f"{PROG} seal {SID} 120"] is False
    assert stdin_by_cmd[f"{PROG} stage"] is False
    for cmd, devnull in stdin_by_cmd.items():
        if cmd not in (f"{PROG} seal {SID} 120", f"{PROG} stage"):
            assert devnull is True, cmd


def test_seal_refusal_aborts_stage_and_discards(protocol, tmp_path):
    """A seal failure aborts the stage and dies with the refusal (design 7.1 row 142-145)."""
    changes = tmp_path / "change.uci"
    changes.write_text("set system.@system[0].description='lab'\n")
    set_router_state(
        protocol,
        seal_fail={"rc": 2, "stderr": "error bad-probe 2 too-long"},
    )

    result = protocol["run_plan"](changes)

    assert result.returncode == 1
    assert (
        "probes refused: error bad-probe 2 too-long; the staged change was discarded"
        in result.stdout
    )
    assert f"{PROG} abort {SID}" in remote_calls(protocol)
    assert "STAGED" not in result.stdout


def test_plan_prints_seal_facts(protocol, tmp_path):
    """The plan output carries the seal lines: probes, profile, sections, leashes,
    approval and the plan digest (design 7.1 rows 142-145, 3.5b step 9)."""
    changes = tmp_path / "change.uci"
    changes.write_text("set dhcp.@dhcp[0].limit='50'\n")
    set_router_state(
        protocol,
        seal_profile="lab",
        seal_sections=["dhcp lab - -", "firewall wan zone wan"],
        seal_leashes=["wan-zone wan"],
    )

    result = protocol["run_plan"](changes)

    assert result.returncode == 0, result.stdout
    assert f"STAGED session={SID} from " in result.stdout
    assert re.search(r"^PROBES 0 [0-9a-f]{64}$", result.stdout, re.M)
    assert "PROFILE lab" in result.stdout
    assert "SECTION dhcp lab - -" in result.stdout
    assert "SECTION firewall wan zone wan" in result.stdout
    assert "LEASH wan-zone wan" in result.stdout
    # profile lab, but a leash code forces approval
    assert "APPROVAL required" in result.stdout
    assert re.search(r"^PLANDIGEST [0-9a-f]{64}$", result.stdout, re.M)
    assert f"next: {SCRIPT} apply root@192.0.2.1 {SID} [timeout]" in result.stdout


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"mode": "test"}, "this controller only talks to mode=prod routers"),
        ({"prog": "0" * 64}, "differs from this controller's"),
        ({"guard-state": "failed"}, "newton-guard is in state failed"),
    ],
    ids=["wrong-mode", "wrong-prog-hash", "guard-failed"],
)
def test_handshake_refuses_mismatched_router(protocol, tmp_path, overrides, message):
    changes = tmp_path / "change.uci"
    changes.write_text("set system.@system[0].description='lab'\n")
    set_router_state(protocol, hello_overrides=overrides)

    result = protocol["run_plan"](changes)

    assert result.returncode == 1
    assert message in result.stdout
    assert f"{PROG} stage" not in remote_calls(protocol)


def test_handshake_refuses_busy_router_at_plan(protocol, tmp_path):
    changes = tmp_path / "change.uci"
    changes.write_text("set system.@system[0].description='lab'\n")
    set_router_state(protocol, hello_overrides={"busy": "another-agent"})

    result = protocol["run_plan"](changes)

    assert result.returncode == 1
    assert "router busy with another change (owner another-agent)" in result.stdout
    assert f"{PROG} stage" not in remote_calls(protocol)


def test_expected_base_hash_drift_refuses_before_any_apply(protocol):
    result = protocol["run"](extra_env={"OWRT_EXPECT_BASE": "0" * 64})

    assert result.returncode == 1
    assert "router config changed since the plan; plan again" in result.stdout
    calls = remote_calls(protocol)
    assert any(call == f"{PROG} confighash" for call in calls)
    assert not any(call.startswith(f"{PROG} apply {SID}") for call in calls)


def test_matching_expected_base_hash_reaches_apply(protocol):
    raw_confighash = (
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb dhcp\n"
        "cccccccccccccccccccccccccccccccc firewall\n"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa network\n"
    )
    expected = hashlib.sha256(raw_confighash.encode()).hexdigest()

    result = protocol["run"](extra_env={"OWRT_EXPECT_BASE": expected})

    assert result.returncode == 0, result.stdout
    assert f"CONFIRMED session={SID}" in result.stdout


def test_applybase_logged_with_config_hash_and_equals_plan_basehash(protocol, tmp_path):
    """Design 9.4 G3: the host's apply-time base equals the sealed base.

    apply logs `APPLYBASE <sha>` where sha is sha256 of the router's
    confighash text, and that sha is exactly the BASEHASH the plan prints
    for the same unchanged config (the seal and the apply-time
    CURRENT_BASE both hash the same confighash bytes)."""
    raw_confighash = (
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb dhcp\n"
        "cccccccccccccccccccccccccccccccc firewall\n"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa network\n"
    )
    expected = hashlib.sha256(raw_confighash.encode()).hexdigest()

    changes = tmp_path / "change.uci"
    changes.write_text("set system.@system[0].description='lab'\n")
    plan_out = protocol["run_plan"](changes)
    assert plan_out.returncode == 0, plan_out.stdout
    plan_base = re.search(r"^BASEHASH ([0-9a-f]{64})$", plan_out.stdout, re.MULTILINE)
    assert plan_base is not None and plan_base.group(1) == expected, plan_out.stdout

    apply_out = protocol["run"]()
    assert apply_out.returncode == 0, apply_out.stdout
    apply_base = re.search(r"^APPLYBASE ([0-9a-f]{64})$", apply_out.stdout, re.MULTILINE)
    assert apply_base is not None, apply_out.stdout
    assert apply_base.group(1) == plan_base.group(1) == expected
    # The audit log gets the same line the runner sees (log() echoes + appends)
    assert f"APPLYBASE {expected}" in protocol["audit"].read_text()


def test_backup_sanitizes_hostile_hostname_inside_backup_directory(protocol):
    """Guards backup containment: path separators/control bytes cannot escape BACKUPS."""
    set_router_state(protocol, hostname="../../x\n")

    _prepare_state_dirs(protocol)
    result = subprocess.run(
        _wrap_args_with_unshare(
            [str(SCRIPT), "backup", "root@192.0.2.1"],
            protocol,
        ),
        env=protocol["env"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20,
    )

    backups = list((protocol["root"] / "backups").glob("*.tar.gz"))
    assert result.returncode == 0, result.stdout
    assert len(backups) == 1
    assert backups[0].parent == protocol["root"] / "backups"
    assert re.fullmatch(r"[A-Za-z0-9._-]{1,63}-\d{8}-\d{6}\.tar\.gz", backups[0].name)
    assert "/../" not in str(backups[0])
    # the backup count lists config FILES only (design 7.1 row 127)
    assert "(1 config files)" in result.stdout


def test_backup_line_keeps_a_long_path_whole(protocol):
    """The BACKUP line was cut at 120 characters, so a long state path pointed at no file."""
    set_router_state(protocol, hostname="h" * 63)

    _prepare_state_dirs(protocol)
    result = subprocess.run(
        _wrap_args_with_unshare(
            [str(SCRIPT), "backup", "root@192.0.2.1"],
            protocol,
        ),
        env=protocol["env"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20,
    )

    backups = list((protocol["root"] / "backups").glob("*.tar.gz"))
    assert result.returncode == 0, result.stdout
    assert len(backups) == 1 and len(str(backups[0])) > 120
    assert f"BACKUP {backups[0]} (1 config files)" in result.stdout


@pytest.mark.parametrize(
    "hostname",
    ["../x", "..", ".", "", ".hidden", "a/b", "lab-r1"],
    ids=["parent-slash-x", "double-dot", "single-dot", "empty", "leading-dot-hidden",
         "slash-replaced", "normal-hostname"],
)
def test_backup_filename_replaces_leading_dots_with_underscore(protocol, hostname):
    """Backup file name cannot start with a dot: `..` would hide in `ls`,
    `..x` and `.hidden` would be hidden files; the empty hostname must fall
    back to `router`. The tr/cut step keeps `..` and `.` as-is, so the leading-dot
    replacement is the only thing standing between these names and a hidden
    or misleading file (or, in the `..` case, a directory-traversal-looking
    name that `ls -A` lists but humans glance over).
    """
    set_router_state(protocol, hostname=hostname)

    _prepare_state_dirs(protocol)
    result = subprocess.run(
        _wrap_args_with_unshare(
            [str(SCRIPT), "backup", "root@192.0.2.1"],
            protocol,
        ),
        env=protocol["env"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20,
    )

    backups = list((protocol["root"] / "backups").glob("*.tar.gz"))
    assert result.returncode == 0, result.stdout
    # exactly one file, directly inside the backups directory
    assert len(backups) == 1
    assert backups[0].parent == protocol["root"] / "backups"
    # nothing written outside the backups dir
    assert "/../" not in str(backups[0])
    # the name must not start with a dot and must match the documented shape
    assert re.fullmatch(
        r"[A-Za-z0-9_][A-Za-z0-9._-]*-\d{8}-\d{6}\.tar\.gz", backups[0].name
    )
    name = backups[0].name
    if hostname == "":
        assert name.startswith("router-"), name
    elif hostname == "lab-r1":
        assert name.startswith("lab-r1-"), name
    # the backup count lists config FILES only (design 7.1 row 127)
    assert "(1 config files)" in result.stdout


def test_named_objects_restart_firewall_before_verification_and_confirm(protocol):
    named = "firewall.cfg03dc81.log_limit (zone wan: limit wan.log_limit)"
    set_router_state(protocol, named=named)
    result = protocol["run"]()

    assert result.returncode == 0, result.stdout
    assert result.stdout.index(f"NAMED NFT OBJECTS session={SID}") < result.stdout.index(
        f"APPLIED session={SID}"
    )
    assert protocol["events"].read_text().splitlines() == ["FW-RESTART"]
    calls = remote_calls(protocol)
    firewall_state_at = next(i for i, call in enumerate(calls) if call == f"{PROG} fw-loaded")
    apply_at = next(i for i, call in enumerate(calls) if call.startswith(f"{PROG} apply {SID}"))
    restart_at = next(
        i for i, call in enumerate(calls) if call == f"{PROG} fwrestart 1"
    )
    verify_at = next(i for i, call in enumerate(calls) if call.startswith(f"{PROG} verify "))
    assert firewall_state_at < apply_at < restart_at < verify_at
    assert all(
        call.endswith("fwrestart 1")
        for call in calls
        if call.startswith(f"{PROG} fwrestart")
    )
    assert f"FIREWALL RESTARTED session={SID} (after apply)" in result.stdout
    assert f"CONFIRMED session={SID}" in result.stdout


def test_firewall_state_is_read_before_apply_only_for_named_changes(protocol):
    set_router_state(protocol, named="firewall.ts (ipset ts: set ts)")
    named_result = protocol["run"]()

    assert named_result.returncode == 0, named_result.stdout
    named_calls = remote_calls(protocol)
    firewall_state_at = next(
        i for i, call in enumerate(named_calls) if call == f"{PROG} fw-loaded"
    )
    apply_at = next(
        i for i, call in enumerate(named_calls) if call.startswith(f"{PROG} apply {SID}")
    )
    assert firewall_state_at < apply_at
    assert [
        call for call in named_calls if call.startswith(f"{PROG} fwrestart")
    ] == [f"{PROG} fwrestart 1"]

    protocol["calls"].write_text("")
    protocol["events"].write_text("")
    set_router_state(protocol, named="")
    unnamed_result = protocol["run"]()

    assert unnamed_result.returncode == 0, unnamed_result.stdout
    assert f"{PROG} fw-loaded" not in remote_calls(protocol)


def test_named_objects_restart_after_apply_and_rollback(protocol):
    set_router_state(
        protocol,
        named="firewall.ts (ipset ts: set ts)",
        fw_restart=["ok", "lose"],
    )
    fail_verify_rounds(protocol)
    result = protocol["run"]()

    assert result.returncode == 1
    assert protocol["events"].read_text().splitlines() == [
        "FW-RESTART",
        "FW-RESTART",
    ]
    assert (
        f"FIREWALL RESTART FAILED session={SID} (after rollback): exit 98 "
        "(the fw4 table was loaded again): the fw4 table is missing after the restart: "
        "loading it again (fw4 stop; fw4 start)"
    ) in result.stdout
    assert "ALERT" not in result.stdout
    assert f"ROLLBACK WINDOW PASSED session={SID}" in result.stdout


def test_unloaded_firewall_is_left_alone_and_change_confirms(protocol):
    set_router_state(
        protocol,
        named="firewall.ts (ipset ts: set ts)",
        fw_table=False,
    )
    result = protocol["run"]()

    assert result.returncode == 0, result.stdout
    assert f"FIREWALL NOT RESTARTED session={SID} (after apply)" in result.stdout
    assert verify_rounds(protocol)
    assert f"CONFIRMED session={SID}" in result.stdout
    assert "FW-RESTART" not in protocol["events"].read_text()


def test_refused_apply_restart_skips_rounds_and_rolls_back(protocol):
    set_router_state(
        protocol,
        named="firewall.ts (ipset ts: set ts)",
        fw_restart=["refuse", "ok"],
        logd=["1314", "2020"],
    )
    result = protocol["run"]()

    assert result.returncode == 1
    assert (
        f"FIREWALL RESTART FAILED session={SID} (after apply): exit 1: "
        "/dev/stdin:9:6-7: Error: Could not process rule: File exists"
    ) in result.stdout
    assert f"VERIFY FAILED session={SID}" in result.stdout
    assert (
        f"VERIFY DETAIL session={SID} firewall restart exit=1 "
        "(the change cannot be made live; its output follows, last 20 lines, at most 2 KB)"
    ) in result.stdout
    assert "VERIFY STDERR" in result.stdout
    assert "not doing firewall restart" in result.stdout
    assert verify_rounds(protocol) == []
    assert f"FIREWALL RESTARTED session={SID} (after rollback)" in result.stdout
    assert protocol["events"].read_text().splitlines().count("DNSMASQ-RESTART") == 1
    assert f"LOGD RESTARTED session={SID} (after rollback)" in result.stdout
    assert "(after apply)" not in "\n".join(
        line for line in result.stdout.splitlines() if line.startswith("LOGD ")
    )
    assert f"ROLLBACK WINDOW PASSED session={SID}" in result.stdout


def test_failed_rollback_restart_reports_alert(protocol):
    set_router_state(
        protocol,
        named="firewall.ts (ipset ts: set ts)",
        fw_restart=["ok", "refuse"],
        logd=["1314", "2020", ""],
    )
    fail_verify_rounds(protocol)
    result = protocol["run"]()

    assert result.returncode == 1
    assert f"ALERT session={SID} rolled back, but " in result.stdout
    assert (
        "firewall restart after the rollback failed: "
        "/dev/stdin:9:6-7: Error: Could not process rule: File exists"
    ) in result.stdout
    assert "logd is not running after the rollback (was pid 2020)" in result.stdout
    assert "ROLLBACK WINDOW PASSED" not in result.stdout


def test_recovered_fw4_table_after_apply_skips_rounds_and_rolls_back(protocol):
    set_router_state(
        protocol,
        named="firewall.ts (ipset ts: set ts)",
        fw_restart=["lose", "ok"],
    )
    result = protocol["run"]()

    assert result.returncode == 1
    assert (
        f"FIREWALL RESTART FAILED session={SID} (after apply): exit 98 "
        "(the fw4 table was loaded again): the fw4 table is missing after the restart: "
        "loading it again (fw4 stop; fw4 start)"
    ) in result.stdout
    assert verify_rounds(protocol) == []
    assert f"ROLLBACK WINDOW PASSED session={SID}" in result.stdout


def test_still_missing_fw4_table_after_apply_skips_rounds_and_rolls_back(protocol):
    set_router_state(
        protocol,
        named="firewall.ts (ipset ts: set ts)",
        fw_restart=["lose", "ok"],
        fw4_start_works=False,
    )
    result = protocol["run"]()

    assert result.returncode == 1
    assert (
        f"FIREWALL RESTART FAILED session={SID} (after apply): exit 99: "
        "the fw4 table is missing after the restart: loading it again (fw4 stop; fw4 start)"
    ) in result.stdout
    assert "VERIFY STDERR" in result.stdout and "the fw4 table is STILL missing" in result.stdout
    assert verify_rounds(protocol) == []
    assert f"CONFIRMED session={SID}" not in result.stdout
    assert "firewall restart after the rollback failed" in result.stdout
    assert f"ALERT session={SID}" in result.stdout
    assert "ROLLBACK WINDOW PASSED" not in result.stdout


def test_firewall_restart_retries_transport_failure(protocol):
    set_router_state(
        protocol,
        named="firewall.ts (ipset ts: set ts)",
        fw_ssh=["fail"],
    )
    result = protocol["run"]()

    assert result.returncode == 0, result.stdout
    assert f"FIREWALL RESTARTED session={SID} (after apply)" in result.stdout
    assert f"CONFIRMED session={SID}" in result.stdout
    assert protocol["events"].read_text().splitlines() == ["FW-RESTART"]


def test_transport_failure_after_lost_table_recovers_without_confirming(protocol):
    set_router_state(
        protocol,
        named="firewall.ts (ipset ts: set ts)",
        fw_restart=["lose", "ok"],
        fw_ssh=["fail-after"],
    )
    result = protocol["run"]()

    assert result.returncode == 1
    assert (
        f"FIREWALL RESTART FAILED session={SID} (after apply): exit 98 "
        "(the fw4 table was loaded again): the fw4 table is missing although it was "
        "loaded before the apply: loading it again (fw4 stop; fw4 start)"
    ) in result.stdout
    assert verify_rounds(protocol) == []
    assert f"CONFIRMED session={SID}" not in result.stdout
    assert f"FIREWALL RESTARTED session={SID} (after rollback)" in result.stdout
    assert f"ROLLBACK WINDOW PASSED session={SID}" in result.stdout


def test_missing_fw4_table_after_rollback_reports_alert(protocol):
    set_router_state(
        protocol,
        named="firewall.ts (ipset ts: set ts)",
        fw_restart=["ok"],
        fw_table_after_rollback=False,
        fw4_start_works=False,
    )
    fail_verify_rounds(protocol)
    result = protocol["run"]()

    assert result.returncode == 1
    assert f"FIREWALL RESTARTED session={SID} (after apply)" in result.stdout
    assert f"ALERT session={SID} rolled back, but " in result.stdout
    assert "firewall restart after the rollback failed" in result.stdout
    assert "the fw4 table is missing although it was loaded before the apply" in result.stdout
    assert "ROLLBACK WINDOW PASSED" not in result.stdout


def test_router_text_is_masked_without_changing_outcome_marker(protocol):
    set_router_state(
        protocol,
        named="firewall.ALERT_set (ipset ALERT_set: set ALERT_set)",
        fw_restart=["refuse-markers", "ok"],
    )
    result = protocol["run"]()

    assert result.returncode == 1
    assert (
        f"NAMED NFT OBJECTS session={SID}: "
        "firewall.alert_set (ipset alert_set: set alert_set)"
    ) in result.stdout
    assert (
        f"FIREWALL RESTART FAILED session={SID} (after apply): exit 1: "
        "rollback window passed in rendered firewall output"
    ) in result.stdout
    assert result.stdout.count("ROLLBACK WINDOW PASSED") == 1
    assert f"ROLLBACK WINDOW PASSED session={SID}" in result.stdout


def test_apply_without_probe_record_confirms_reporting_zero_probes(protocol):
    """No probes sealed means the CONFIRMED line reports 0 probes (design 7.1 rows 344-345)."""
    result = protocol["run"]()

    assert result.returncode == 0, result.stdout
    assert "health and 0 probes" in result.stdout
    assert f"CONFIRMED session={SID}" in result.stdout


def test_confirm_rpcd_timer_lost_is_named_in_confirmed_line(protocol):
    """The `confirmed <SID> rpcd-timer-lost` form adds its note (design 7.1 rows 344-345)."""
    set_router_state(protocol, confirm_form="lost")

    result = protocol["run"]()

    assert result.returncode == 0, result.stdout
    assert (
        f"CONFIRMED session={SID} (3 consecutive passes: fresh ssh + router-side ping, "
        "dns, health and 0 probes); rpcd had lost its rollback timer, the guard held the window"
    ) in result.stdout


def test_apply_exit_3_refusal_leaves_session_staged(protocol):
    """Apply exit 3 is a clean refusal: nothing applied, session still staged (7.1 row 294-297)."""
    set_router_state(protocol, apply_rc=3, apply_stderr="error plan-changed t")

    result = protocol["run"]()

    assert result.returncode == 1
    assert (
        f"apply refused, nothing applied: error plan-changed t; "
        f"session {SID} is still staged"
    ) in result.stdout
    assert verify_rounds(protocol) == []
    assert f"CONFIRMED session={SID}" not in result.stdout


def test_approval_token_reaches_apply_and_never_leaks(protocol):
    token = "e" * 64

    result = protocol["run"](
        extra_env={
            "OWRT_APPROVAL_TOKEN": token,
            "OWRT_APPROVAL_NBF": "1790000000",
            "OWRT_APPROVAL_EXP": "1790001800",
        }
    )

    assert result.returncode == 0, result.stdout
    assert f"{PROG} apply {SID} 60 {token} 1790000000 1790001800" in remote_calls(protocol)
    assert token not in result.stdout
    assert token not in protocol["audit"].read_text()


def test_approval_window_defaults_to_zero_zero_with_a_hex_token_refused(protocol):
    """SW2 Item 2: a hex token with no window is a mismatch, not a default."""
    result = protocol["run"](extra_env={"OWRT_APPROVAL_TOKEN": "e" * 64})

    assert result.returncode == 1
    assert "OWRT_APPROVAL_NBF/OWRT_APPROVAL_EXP do not match OWRT_APPROVAL_TOKEN" in result.stdout
    assert "nothing applied" in result.stdout
    assert "e" * 64 not in result.stdout
    assert "e" * 64 not in protocol["audit"].read_text()
    assert remote_calls(protocol) == []


@pytest.mark.parametrize(
    ("nbf", "exp"),
    [
        ("0", "1790001800"),
        ("1790000000", "0"),
        ("0", "0"),
        ("999999999", "1790001800"),        # 9 digits
        ("1790000000", "10000000000"),      # 11 digits
        ("01790000000", "1790001800"),      # leading zero: not 10 digits
        ("179000000", "1790001800"),        # 9 digits
        ("1790000000", "179000180a"),       # not all digits
        ("-179000000", "1790001800"),
        ("1790000000 1790001800", "1790001800"),
        ("", ""),
    ],
    ids=[
        "nbf-zero", "exp-zero", "both-zero", "nbf-9-digits", "exp-11-digits",
        "leading-zero", "nbf-short", "exp-not-numeric", "negative",
        "space", "empty",
    ],
)
def test_bad_approval_window_refused_before_any_ssh_call_without_leaking(
    protocol, nbf, exp
):
    """The window shape is checked here, before ssh.  Ordering (EXP > NBF)
    and the window length are the ROUTER's checks -- it answers
    approval-window for those, so they are not refused here."""
    token = "e" * 64
    result = protocol["run"](
        extra_env={
            "OWRT_APPROVAL_TOKEN": token,
            "OWRT_APPROVAL_NBF": nbf,
            "OWRT_APPROVAL_EXP": exp,
        }
    )

    assert result.returncode == 1
    assert "OWRT_APPROVAL_NBF/OWRT_APPROVAL_EXP do not match OWRT_APPROVAL_TOKEN" in result.stdout
    assert token not in result.stdout
    assert token not in protocol["audit"].read_text()
    assert remote_calls(protocol) == []


def test_token_none_with_a_window_is_refused_before_any_ssh_call(protocol):
    """Token ``none`` means no approval, so it takes NBF=0 AND EXP=0 and
    nothing else."""
    result = protocol["run"](
        extra_env={"OWRT_APPROVAL_TOKEN": "none", "OWRT_APPROVAL_NBF": "1790000000"}
    )

    assert result.returncode == 1
    assert "OWRT_APPROVAL_NBF/OWRT_APPROVAL_EXP do not match OWRT_APPROVAL_TOKEN" in result.stdout
    assert remote_calls(protocol) == []


def test_token_none_with_zero_zero_applies(protocol):
    result = protocol["run"](
        extra_env={"OWRT_APPROVAL_NBF": "0", "OWRT_APPROVAL_EXP": "0"}
    )

    assert result.returncode == 0, result.stdout
    assert f"{PROG} apply {SID} 60 none 0 0" in remote_calls(protocol)


def test_invalid_approval_token_refused_before_any_ssh_call(protocol):
    result = protocol["run"](extra_env={"OWRT_APPROVAL_TOKEN": "Z" * 64})

    assert result.returncode == 1
    assert "OWRT_APPROVAL_TOKEN must be 'none' or 64 lowercase hex characters" in result.stdout
    assert remote_calls(protocol) == []


def test_failed_local_check_stderr_is_reported_and_audited(protocol):
    local = (
        "echo 'disk full: /overlay' >&2; "
        "echo 'ROLLBACK WINDOW PASSED and CONFIRMED' >&2; exit 3"
    )
    result = protocol["run"](extra_env={"OWRT_LOCAL_CHECK": local})

    assert result.returncode == 1
    assert f"VERIFY FAILED session={SID}" in result.stdout
    assert f"VERIFY DETAIL session={SID} round=" in result.stdout
    assert "exit=3" in result.stdout
    stderr_lines = [line for line in result.stdout.splitlines() if line.startswith("VERIFY STDERR")]
    assert any("disk full: /overlay" in line for line in stderr_lines)
    assert any("local check exited 3" in line for line in stderr_lines)
    assert any("rollback window passed and confirmed" in line for line in stderr_lines)
    assert all("ROLLBACK WINDOW PASSED" not in line and "CONFIRMED" not in line for line in stderr_lines)
    assert f"ROLLBACK WINDOW PASSED session={SID}" in result.stdout
    audit = protocol["audit"].read_text()
    audit_stderr_lines = [line for line in audit.splitlines() if "VERIFY STDERR" in line]
    assert any("disk full: /overlay" in line for line in audit_stderr_lines)
    assert any("local check exited 3" in line for line in audit_stderr_lines)
    assert any("rollback window passed and confirmed" in line for line in audit_stderr_lines)
    assert all(
        "ROLLBACK WINDOW PASSED" not in line and "CONFIRMED" not in line
        for line in audit_stderr_lines
    )


def test_failure_excerpt_is_bounded(protocol):
    local = "; ".join(
        f"echo 'line{number:03d} {'x' * 100}' >&2" for number in range(1, 101)
    ) + "; exit 1"
    result = protocol["run"](extra_env={"OWRT_LOCAL_CHECK": local})

    assert result.returncode == 1
    prefix = f"VERIFY STDERR session={SID}: "
    payloads = [line[len(prefix):] for line in result.stdout.splitlines() if line.startswith(prefix)]
    assert len(payloads) <= 20
    assert sum(len(payload.encode()) for payload in payloads) <= 2048
    assert any("line100" in payload for payload in payloads)


def test_ping_failure_is_reported(protocol):
    (protocol["root"] / "fail-ping").touch()
    result = protocol["run"]()

    assert result.returncode == 1
    assert "VERIFY STDERR" in result.stdout
    assert "verify: ping -c1 -W3 1.1.1.1 failed" in result.stdout


def test_failed_round_header_has_the_real_exit_code_and_the_router_verify_stage(protocol):
    (protocol["root"] / "fail-ping").touch()
    result = protocol["run"]()

    header = next(l for l in result.stdout.splitlines() if l.startswith(f"VERIFY DETAIL session={SID} round="))
    assert re.fullmatch(
        rf"VERIFY DETAIL session={SID} round=[0-9]+ exit=1 stage=router-verify \(last failed round;.*", header
    ), header
    assert "exit=rc" not in result.stdout


def test_failed_round_header_names_the_local_check_stage(protocol):
    result = protocol["run"](extra_env={"OWRT_LOCAL_CHECK": "exit 3"})

    header = next(l for l in result.stdout.splitlines() if l.startswith(f"VERIFY DETAIL session={SID} round="))
    assert re.fullmatch(
        rf"VERIFY DETAIL session={SID} round=[0-9]+ exit=3 stage=local-check \(last failed round;.*", header
    ), header


def test_local_check_that_fails_once_resets_the_pass_counter(protocol):
    """VC-18: a round that the local check fails is not a passing round.

    The confirm needs three passing rounds in a row, so a local check
    that fails on the third round must not be confirmed there: the
    counter starts again and the confirm waits for three more rounds.
    """
    counter = protocol["root"] / "local-check-count"
    local = (
        f"n=$(cat {counter} 2>/dev/null || echo 0); n=$((n + 1)); "
        f"printf '%s' \"$n\" > {counter}; "
        "if [ \"$n\" -eq 3 ]; then "
        "echo 'vantage-check: claim 2 FAIL open' >&2; exit 1; fi; exit 0"
    )

    result = protocol["run"](extra_env={"OWRT_LOCAL_CHECK": local})

    assert result.returncode == 0, result.stdout
    assert f"CONFIRMED session={SID}" in result.stdout
    # two rounds passed, the third failed, then three more passed
    assert counter.read_text() == "6"
    assert len(verify_rounds(protocol)) == 6


def test_local_check_that_never_passes_never_confirms(protocol):
    """VC-18: a local check that never passes blocks the confirm, and the
    log says which stage failed."""
    counter = protocol["root"] / "local-check-count"
    local = (
        f"n=$(cat {counter} 2>/dev/null || echo 0); n=$((n + 1)); "
        f"printf '%s' \"$n\" > {counter}; "
        "echo 'vantage-check: claim 2 NOT-TESTED unreachable' >&2; exit 1"
    )

    result = protocol["run"](extra_env={"OWRT_LOCAL_CHECK": local})

    assert result.returncode == 1
    assert not any(line.startswith("CONFIRMED") for line in result.stdout.splitlines())
    header = next(
        l for l in result.stdout.splitlines() if l.startswith(f"VERIFY DETAIL session={SID} round=")
    )
    assert re.fullmatch(
        rf"VERIFY DETAIL session={SID} round=[0-9]+ exit=1 stage=local-check \(last failed round;.*", header
    ), header
    assert "vantage-check: claim 2 NOT-TESTED unreachable" in result.stdout
    assert int(counter.read_text()) >= 3


def test_failed_round_header_names_the_logd_stage(protocol):
    set_router_state(protocol, logd=["1314", "1314", ""])
    result = protocol["run"]()

    header = next(l for l in result.stdout.splitlines() if l.startswith(f"VERIFY DETAIL session={SID} round="))
    assert re.fullmatch(
        rf"VERIFY DETAIL session={SID} round=[0-9]+ exit=3 stage=logd \(last failed round;.*", header
    ), header


def test_local_check_failure_is_reported(protocol):
    result = protocol["run"](
        extra_env={"OWRT_LOCAL_CHECK": "echo local-broke >&2; exit 4"}
    )

    assert result.returncode == 1
    assert "local check exited 4" in result.stdout
    assert "local-broke" in result.stdout


def test_invalid_local_check_is_refused_before_apply(protocol):
    result = protocol["run"](extra_env={"OWRT_LOCAL_CHECK": "if then"})

    assert result.returncode == 1
    assert "OWRT_LOCAL_CHECK is not valid bash" in result.stdout
    assert f"{PROG} apply {SID}" not in "\n".join(remote_calls(protocol))


def test_unchanged_logd_confirms_without_restarting_dnsmasq(protocol):
    result = protocol["run"]()

    assert result.returncode == 0, result.stdout
    assert f"CONFIRMED session={SID}" in result.stdout
    assert protocol["events"].read_text() == ""
    assert "LOGD RESTARTED" not in result.stdout
    assert "LOGD RESTARTED" not in protocol["audit"].read_text()
    assert verify_rounds(protocol)
    assert verify_need_dhcp(protocol) and all(n == 0 for n in verify_need_dhcp(protocol))


def test_apply_logd_restart_repairs_dnsmasq_and_checks_dhcp(protocol):
    set_router_state(protocol, logd=["1314", "2020"])
    result = protocol["run"]()

    assert result.returncode == 0, result.stdout
    expected = (
        f"LOGD RESTARTED session={SID} (after apply): "
        "logd pid 1314 -> 2020"
    )
    assert protocol["events"].read_text().splitlines() == ["DNSMASQ-RESTART"]
    assert expected in result.stdout
    assert expected in protocol["audit"].read_text()
    assert verify_rounds(protocol)
    assert all(n == 1 for n in verify_need_dhcp(protocol))
    assert f"CONFIRMED session={SID}" in result.stdout


def test_late_logd_restart_requires_fresh_passes(protocol):
    set_router_state(protocol, logd=["1314", "1314", "2020"])
    result = protocol["run"]()

    assert result.returncode == 0, result.stdout
    assert protocol["events"].read_text().splitlines() == ["DNSMASQ-RESTART"]
    assert f"LOGD RESTARTED session={SID} (before confirm)" in result.stdout
    calls = remote_calls(protocol)
    restart_at = next(
        index for index, call in enumerate(calls) if call == f"{PROG} dnsmasq-repair"
    )
    rounds_after_restart = [
        call for call in calls[restart_at + 1:] if call.startswith(f"{PROG} verify ")
    ]
    assert len(rounds_after_restart) >= 3
    assert all(call.endswith(" 1") for call in rounds_after_restart)
    assert f"CONFIRMED session={SID}" in result.stdout


def test_missing_logd_before_confirm_is_a_failed_verification_round(protocol):
    set_router_state(protocol, logd=["1314", "1314", ""])
    result = protocol["run"]()

    assert result.returncode == 1
    assert f"CONFIRMED session={SID}" not in result.stdout
    assert f"VERIFY DETAIL session={SID} round=" in result.stdout
    assert "exit=3" in result.stdout
    assert (
        f"VERIFY STDERR session={SID}: logd is not running (was pid 1314): "
        "not confirming while the system log is down"
    ) in result.stdout
    assert f"{PROG} abort {SID}" in protocol["calls"].read_text()


def test_rollback_logd_restart_repairs_and_verifies_dnsmasq(protocol):
    # Reads are pre-apply, after-apply, then after-rollback; no round passes far
    # enough to cause the before-confirm read.
    set_router_state(protocol, logd=["1314", "2020", "3030"])
    fail_verify_rounds(protocol)
    result = protocol["run"]()

    assert result.returncode == 1
    assert protocol["events"].read_text().splitlines() == [
        "DNSMASQ-RESTART",
        "DNSMASQ-RESTART",
    ]
    assert f"LOGD RESTARTED session={SID} (after rollback): logd pid 2020 -> 3030" in result.stdout
    assert f"DNS AND DHCP OK session={SID}" in result.stdout
    assert f"ROLLBACK WINDOW PASSED session={SID}" in result.stdout


def test_failed_post_rollback_dns_check_reports_alert(protocol):
    set_router_state(protocol, logd=["1314", "2020"])
    (protocol["root"] / "fail-nslookup").touch()
    result = protocol["run"]()

    assert result.returncode == 1
    assert (
        f"ALERT session={SID} rolled back, but DNS/DHCP check failed after the "
        "dnsmasq restart: nslookup openwrt.org 127.0.0.1 failed"
    ) in result.stdout
    assert "ROLLBACK WINDOW PASSED" not in result.stdout


def test_logd_restart_leaves_stopped_dnsmasq_alone(protocol):
    set_router_state(protocol, logd=["1314", "2020"], dnsmasq_running=False)
    result = protocol["run"]()

    assert result.returncode == 0, result.stdout
    assert protocol["events"].read_text() == ""
    assert "dnsmasq is not running, nothing to restart" in result.stdout
    assert verify_rounds(protocol)
    assert all(n == 0 for n in verify_need_dhcp(protocol))
    assert f"CONFIRMED session={SID}" in result.stdout


def test_logd_restart_without_dhcp_listener_requires_dnsmasq_only(protocol):
    set_router_state(
        protocol,
        logd=["1314", "2020"],
        dhcp_listener=False,
    )
    result = protocol["run"]()

    assert result.returncode == 0, result.stdout
    assert protocol["events"].read_text().splitlines() == ["DNSMASQ-RESTART"]
    assert "DHCP listener before the restart: no" in result.stdout
    assert verify_rounds(protocol)
    assert all(n == 2 for n in verify_need_dhcp(protocol))
    assert f"CONFIRMED session={SID}" in result.stdout


def test_dnsmasq_death_after_restart_is_reported_without_dhcp_listener(protocol):
    set_router_state(
        protocol,
        logd=["1314", "2020"],
        dhcp_listener=False,
        dnsmasq_dies_on_restart=True,
    )
    result = protocol["run"]()

    assert result.returncode == 1
    assert f"VERIFY FAILED session={SID}" in result.stdout
    assert "VERIFY STDERR" in result.stdout
    assert "verify: dnsmasq is not running after Newton restarted it" in result.stdout


def test_touched_dnsmasq_is_started_and_checked_after_rollback(protocol):
    set_router_state(
        protocol,
        logd=["1314", "2020"],
        dnsmasq_running_after_rollback=False,
    )
    fail_verify_rounds(protocol)
    result = protocol["run"]()

    assert result.returncode == 1
    assert (
        f"DNSMASQ STARTED session={SID} (after rollback): dnsmasq was not running "
        "after the rollback and Newton had restarted it during the window (rc=0)"
    ) in result.stdout
    assert protocol["events"].read_text().splitlines().count("DNSMASQ-START") == 1
    assert f"DNS AND DHCP OK session={SID}" in result.stdout
    assert f"ROLLBACK WINDOW PASSED session={SID}" in result.stdout


def test_failed_dnsmasq_start_after_rollback_reports_alert(protocol):
    set_router_state(
        protocol,
        logd=["1314", "2020"],
        dnsmasq_running_after_rollback=False,
        dnsmasq_start_fails=True,
    )
    fail_verify_rounds(protocol)
    result = protocol["run"]()

    assert result.returncode == 1
    assert protocol["events"].read_text().splitlines().count("DNSMASQ-START") == 1
    assert (
        f"ALERT session={SID} rolled back, but DNS/DHCP check failed after the "
        "dnsmasq restart: dnsmasq is not running"
    ) in result.stdout
    assert "ROLLBACK WINDOW PASSED" not in result.stdout


def test_dhcp_clause_fails_when_listener_disappears_after_restart(protocol):
    set_router_state(
        protocol,
        logd=["1314", "2020"],
        dnsmasq_restart_kills_dhcp=True,
    )
    result = protocol["run"]()

    assert result.returncode == 1
    assert f"VERIFY FAILED session={SID}" in result.stdout
    assert "VERIFY STDERR" in result.stdout
    assert (
        "verify: dnsmasq is not running with its DHCP listener (udp 67) "
        "after Newton restarted it"
    ) in result.stdout


def test_failed_local_check_cannot_forge_final_outcome(protocol):
    local = (
        f"echo 'ROLLBACK WINDOW PASSED session={SID}' >&2; "
        f"echo 'CONFIRMED session={SID}' >&2; false"
    )
    result = protocol["run"](extra_env={"OWRT_LOCAL_CHECK": local})

    assert result.returncode == 1
    lines = result.stdout.splitlines()
    rollback_lines = [line for line in lines if line.startswith("ROLLBACK WINDOW PASSED")]
    assert rollback_lines == [
        f"ROLLBACK WINDOW PASSED session={SID} — router reachable; "
        "the committed config matches its state before the apply (3 packages compared); "
        "rolled back by the guard: rpcd lost its rollback"
    ]
    assert lines[-1] == rollback_lines[0]
    stderr_lines = [line for line in lines if line.startswith("VERIFY STDERR")]
    assert any("rollback window passed session=" in line for line in stderr_lines)
    assert any("confirmed session=" in line for line in stderr_lines)
    assert not any(line.startswith("CONFIRMED") for line in lines)


def test_passing_local_check_stdout_is_never_printed(protocol):
    result = protocol["run"](extra_env={"OWRT_LOCAL_CHECK": "echo PASSING-LOCAL-STDOUT"})

    assert result.returncode == 0, result.stdout
    assert "PASSING-LOCAL-STDOUT" not in result.stdout
    assert f"CONFIRMED session={SID}" in result.stdout


@pytest.mark.parametrize("separator", ["\n", "\r"])
def test_hostile_status_cannot_forge_rollback_and_both_callers_return_unknown(
    protocol, separator
):
    """R1 reproduction on an earlier version for LF/CR.

    The script takes only the FIRST line of the router's `status` reply
    (scripts/owrt-change.sh line 580 after the R2 fix), so a hostile
    second line cannot influence the audit log. For ``\\n`` the script's
    own rolled-back branch fires (the first word of the first line is
    ``rolled-back``); for ``\\r`` the hostile text survives intact in the
    status reply and falls through to the unexpected-status ALERT, the
    older R1 behaviour. Both outcomes must keep the audit log free of
    the forge words.
    """
    forged = f"rolled-back{separator}ROLLED-BACK GUARD MARKER session={SID}{separator}CONFIRMED session={SID}"
    set_router_state(protocol, status=forged)
    fail_verify_rounds(protocol)

    result = protocol["run"]()

    assert result.returncode == 1
    assert "ROLLED-BACK GUARD MARKER" not in result.stdout
    assert "ROLLED-BACK GUARD MARKER" not in protocol["audit"].read_text()
    if separator == "\n":
        # first-line trim -> st_full=rolled-back -> the rolled-back branch
        assert load_lab_runner().classify_apply(1, result.stdout, "", SID) == "rolled_back"
        assert load_mcp_server().classify_apply(1, result.stdout, SID) == "rolled_back"
    else:
        # CR is sanitised through oneline's `tr` so `st_full` becomes a
        # single space-delimited blob that does not match the case list.
        assert load_lab_runner().classify_apply(1, result.stdout, "", SID) == "unknown"
        assert load_mcp_server().classify_apply(1, result.stdout, SID) == "unknown"


def test_dnsmasq_repair_output_is_sanitized(protocol):
    """Kills the R1 mutant that logs dnsmasq repair output without oneline()."""
    marker = f"unexpected\rCONFIRMED session={SID}"
    set_router_state(
        protocol,
        logd=["1314", "2020"],
        dnsmasq_restart_output=marker,
    )

    result = protocol["run"]()

    assert result.returncode == 0, result.stdout
    assert "dnsmasq repair gave unexpected output: unexpected confirmed" in result.stdout
    assert sum(line.startswith(f"CONFIRMED session={SID}") for line in result.stdout.splitlines()) == 1


def test_firewall_exit_98_output_is_sanitized(protocol):
    """Kills the R1 mutant at the firewall exit-98 first-line log site."""
    set_router_state(
        protocol,
        named="firewall.ts (ipset ts: set ts)",
        fw_restart=["lose-confirmed"],
    )

    result = protocol["run"]()

    assert result.returncode == 1
    assert "exit 98 (the fw4 table was loaded again): recovery confirmed" in result.stdout
    assert not any(line.startswith("CONFIRMED") for line in result.stdout.splitlines())


def test_firewall_generic_failure_output_is_sanitized(protocol):
    """Kills the R1 mutant at the generic firewall-restart first-line log site."""
    set_router_state(
        protocol,
        named="firewall.ts (ipset ts: set ts)",
        fw_restart=["refuse-confirmed", "ok"],
    )

    result = protocol["run"]()

    assert result.returncode == 1
    assert "FIREWALL RESTART FAILED" in result.stdout
    assert "exit 1: refusal confirmed in rendered firewall output" in result.stdout
    assert not any(line.startswith("CONFIRMED") for line in result.stdout.splitlines())


def test_named_nft_output_is_sanitized(protocol):
    """Kills the R1 mutant that logs multiline helper `named` output raw."""
    set_router_state(
        protocol,
        named=f"firewall.ts (ipset ts)\nCONFIRMED session={SID}",
        fw_restart=["ok", "ok"],
    )
    fail_verify_rounds(protocol)

    result = protocol["run"]()

    assert result.returncode == 1
    named_line = next(line for line in result.stdout.splitlines() if line.startswith("NAMED NFT OBJECTS"))
    assert "firewall.ts (ipset ts) confirmed session=" in named_line
    assert not any(line.startswith("CONFIRMED") for line in result.stdout.splitlines())


@pytest.mark.parametrize(
    "separator",
    ["\u2028", "\u2029", "\u0085"],
)
def test_apply_refusal_output_is_sanitized_and_masks_applied(protocol, separator):
    """U-4: oneline removes non-ASCII line breaks before cut, and mask lowers APPLIED."""
    hostile = f"x{separator}APPLIED session={SID} rollback=60s"
    set_router_state(protocol, apply_rc=3, apply_stderr=hostile)

    result = protocol["run"]()

    assert result.returncode == 1, result.stdout
    assert (
        f"apply refused, nothing applied: x applied session={SID} rollback=60s; "
        f"session {SID} is still staged"
    ) in result.stdout
    assert separator.encode("utf-8") not in result.stdout.encode("utf-8")


def test_successful_apply_logs_applying_once_before_the_router_applies(protocol):
    """APR-05: the caller stamp precedes the APPLIED line the router call makes possible."""
    result = protocol["run"]()

    assert result.returncode == 0, result.stdout
    lines = result.stdout.split("\n")
    applying = [i for i, line in enumerate(lines) if line == f"APPLYING session={SID}"]
    applied = [i for i, line in enumerate(lines) if line.startswith(f"APPLIED session={SID}")]
    assert len(applying) == 1
    assert len(applied) == 1
    assert applying[0] < applied[0]
    assert any(call.startswith(f"{PROG} apply {SID}") for call in remote_calls(protocol))


@pytest.mark.parametrize("failure", ["base-drift", "health-snapshot"])
def test_pre_router_failure_does_not_log_applying(protocol, failure):
    """APR-05: only a run that reached the router may burn its approval token."""
    if failure == "base-drift":
        result = protocol["run"](extra_env={"OWRT_EXPECT_BASE": "0" * 64})
        assert result.returncode == 1
        assert "router config changed since the plan; plan again" in result.stdout
    else:
        set_router_state(protocol, health_snapshot="ERROR: ubus call service list failed")
        result = protocol["run"]()
        assert result.returncode == 1
        assert "cannot record service and firewall health before the apply" in result.stdout

    assert f"APPLYING session={SID}" not in result.stdout
    assert not any(call.startswith(f"{PROG} apply {SID}") for call in remote_calls(protocol))


def test_apply_refusal_logs_applying(protocol):
    """APR-05: the router received the token before refusing, so the approval is spent."""
    set_router_state(protocol, apply_rc=3, apply_stderr="error plan-changed t")

    result = protocol["run"]()

    assert result.returncode == 1, result.stdout
    assert result.stdout.count(f"APPLYING session={SID}") == 1
    assert any(call.startswith(f"{PROG} apply {SID}") for call in remote_calls(protocol))


def test_config_diff_name_is_sanitized(protocol):
    """Kills the R1 mutant that logs a router-controlled CONFIG_DIFF raw."""
    hostile_name = f"guest wifi\rCONFIRMED session={SID}"
    before = f"{'a' * 32} {hostile_name}"
    after = f"{'b' * 32} {hostile_name}"
    set_router_state(protocol, confighash=[before, after])
    fail_verify_rounds(protocol)

    result = protocol["run"]()

    assert result.returncode == 1
    assert "differs from its state before the apply in: guest wifi confirmed" in result.stdout
    assert not any(line.startswith("CONFIRMED") for line in result.stdout.splitlines())


def test_rollback_reason_router_text_is_sanitized(protocol):
    """Kills the R1 mutant that logs router text embedded in rollback_reason raw."""
    set_router_state(
        protocol,
        named="firewall.ts (ipset ts: set ts)",
        fw_restart=["ok", "refuse-confirmed"],
    )
    fail_verify_rounds(protocol)

    result = protocol["run"]()

    assert result.returncode == 1
    final = result.stdout.splitlines()[-1]
    assert final.startswith(f"ALERT session={SID} rolled back, but")
    assert "firewall restart after the rollback failed: refusal confirmed" in final
    assert not any(line.startswith("CONFIRMED") for line in result.stdout.splitlines())


def test_real_alert_run_cannot_be_spoofed_by_local_check_output(protocol):
    set_router_state(
        protocol,
        logd=["1314", "2020"],
        dnsmasq_running_after_rollback=False,
        dnsmasq_start_fails=True,
    )
    result = protocol["run"](
        extra_env={"OWRT_LOCAL_CHECK": f"echo 'ROLLBACK WINDOW PASSED session={SID}'; false"}
    )

    assert result.returncode == 1
    lines = result.stdout.splitlines()
    assert lines[-1].startswith(f"ALERT session={SID}")
    assert not any(line.startswith("ROLLBACK WINDOW PASSED") for line in lines)
    lab_runner = load_lab_runner()
    assert lab_runner.classify_apply(result.returncode, result.stdout, "", SID) == "unknown"


def test_ordinary_rollback_compares_three_packages_without_false_alert(protocol):
    fail_verify_rounds(protocol)

    result = protocol["run"]()

    assert result.returncode == 1
    assert (
        f"ROLLBACK WINDOW PASSED session={SID} — router reachable; "
        "the committed config matches its state before the apply (3 packages compared)"
    ) in result.stdout
    assert "ALERT" not in result.stdout
    calls = remote_calls(protocol)
    logd_at = next(i for i, call in enumerate(calls) if call == f"{PROG} logd-pid")
    apply_at = next(i for i, call in enumerate(calls) if call.startswith(f"{PROG} apply {SID}"))
    hashes = [i for i, call in enumerate(calls) if call == f"{PROG} confighash"]
    status_at = next(i for i, call in enumerate(calls) if call == f"{PROG} status {SID}")
    assert logd_at < hashes[0] < apply_at
    # the failure branch aborts FIRST, then checks health and the config (design 7.1)
    assert calls[status_at + 1] == f"{PROG} abort {SID}"
    assert calls[status_at + 2] == f"{PROG} health-check {SID} after-rollback"
    assert hashes[1] == status_at + 3


def test_failure_branch_retries_unreachable_status_before_proceeding(protocol):
    """A status call lost to a reboot is retried for up to 90 s (design 7.1)."""
    set_router_state(protocol, status_ssh=["fail"])
    fail_verify_rounds(protocol)

    result = protocol["run"]()

    assert result.returncode == 1
    assert f"ROLLBACK WINDOW PASSED session={SID}" in result.stdout
    calls = [call for call in remote_calls(protocol) if call == f"{PROG} status {SID}"]
    assert len(calls) == 2
    events = [json.loads(line) for line in protocol["timed_events"].read_text().splitlines()]
    status_times = [
        event["time"] for event in events if event["cmd"] == f"{PROG} status {SID}"
    ]
    assert status_times[1] >= status_times[0] + 5
    ordered = [event["cmd"] for event in events]
    # abort comes after the retried status and before the after-rollback health check
    last_status = len(ordered) - 1 - ordered[::-1].index(f"{PROG} status {SID}")
    assert last_status < ordered.index(f"{PROG} abort {SID}")
    assert ordered.index(f"{PROG} abort {SID}") < ordered.index(
        f"{PROG} health-check {SID} after-rollback"
    )


def test_gone_status_with_changed_dhcp_hash_reports_live_change(protocol):
    before = (
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb dhcp\n"
        "cccccccccccccccccccccccccccccccc firewall\n"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa network"
    )
    after = before.replace("b" * 32, "d" * 32)
    set_router_state(protocol, status="gone", confighash=[before, after])
    fail_verify_rounds(protocol)
    result = protocol["run"]()

    assert result.returncode == 1
    assert f"ALERT session={SID} status=gone" in result.stdout
    assert "differs from its state before the apply in: dhcp — the change may still be live" in result.stdout
    assert "ROLLBACK WINDOW PASSED" not in result.stdout


def test_gone_named_change_still_live_reports_firewall_and_restarts(protocol):
    before = (
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb dhcp\n"
        "cccccccccccccccccccccccccccccccc firewall\n"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa network"
    )
    after = before.replace("c" * 32, "d" * 32)
    set_router_state(
        protocol,
        status="gone",
        confighash=[before, after],
        named="firewall.ts (ipset ts: set ts)",
        fw_restart=["ok", "ok"],
    )
    fail_verify_rounds(protocol)
    result = protocol["run"]()

    assert result.returncode == 1
    assert "differs from its state before the apply in: firewall — the change may still be live" in result.stdout
    assert protocol["events"].read_text().splitlines().count("FW-RESTART") == 2
    assert "ROLLBACK WINDOW PASSED" not in result.stdout


def test_rollback_with_removed_and_added_packages_names_both(protocol):
    before = (
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb dhcp\n"
        "cccccccccccccccccccccccccccccccc firewall\n"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa network"
    )
    after = (
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb dhcp\n"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa network\n"
        "dddddddddddddddddddddddddddddddd system"
    )
    set_router_state(protocol, confighash=[before, after])
    fail_verify_rounds(protocol)
    result = protocol["run"]()

    assert result.returncode == 1
    assert "differs from its state before the apply in: firewall system — the change" in result.stdout
    assert "ROLLBACK WINDOW PASSED" not in result.stdout


def test_rollback_compare_preserves_full_space_filename(protocol):
    """Catches an earlier version's field-splitting compare and kills the C5 mutant."""
    before = (
        f"{'a' * 32} guest wifi\n"
        f"{'b' * 32} lan+rules\n"
        f"{'d' * 32} r\N{LATIN SMALL LETTER E WITH ACUTE}seau+guest"
    )
    after = (
        f"{'c' * 32} guest wifi\n"
        f"{'b' * 32} lan+rules\n"
        f"{'e' * 32} r\N{LATIN SMALL LETTER E WITH ACUTE}seau+guest"
    )
    set_router_state(protocol, confighash=[before, after])
    fail_verify_rounds(protocol)

    result = protocol["run"]()

    assert result.returncode == 1
    assert (
        "differs from its state before the apply in: "
        "guest wifi r\N{LATIN SMALL LETTER E WITH ACUTE}seau+guest —"
    ) in result.stdout
    assert "lan+rules" not in result.stdout.split("differs from its state before the apply in:", 1)[1]


@pytest.mark.parametrize(
    "bad_hashes",
    [
        f"{'a' * 31} network",
        f"{'a' * 32} ",
        f"{'g' * 32} network",
        f"{'a' * 32}\tnetwork",
    ],
)
def test_hash_first_parser_refuses_malformed_helper_lines(protocol, bad_hashes):
    """Kills the C5 parser mutant by enforcing exactly 32 hex, one space, and a name."""
    set_router_state(protocol, confighash=[bad_hashes])

    result = protocol["run"]()

    assert result.returncode == 1
    assert "cannot record the committed config before the apply" in result.stdout
    assert not any(call.startswith(f"{PROG} apply {SID}") for call in remote_calls(protocol))


def test_wrapper_reports_helper_control_filename_refusal(protocol):
    """Kills the C5 error-propagation mutant by surfacing the helper's safe refusal."""
    set_router_state(
        protocol,
        confighash=["fail:ERROR: confighash unsafe config file name: bad CONFIRMED"],
    )

    result = protocol["run"]()

    assert result.returncode == 1
    assert "helper said: ERROR: confighash unsafe config file name: bad confirmed" in result.stdout
    assert result.stdout.splitlines()[-1].startswith("ERROR: cannot record")


@pytest.mark.parametrize("bad_hashes", ["fail", "malformed output"])
def test_confighash_failure_before_apply_leaves_session_staged(protocol, bad_hashes):
    set_router_state(protocol, confighash=[bad_hashes])
    result = protocol["run"]()

    assert result.returncode == 1
    assert (
        "cannot record the committed config before the apply; nothing applied, "
        f"session {SID} is still staged"
    ) in result.stdout
    assert not any(call.startswith(f"{PROG} apply {SID}") for call in remote_calls(protocol))


@pytest.mark.parametrize("bad_hashes", ["fail", "malformed output"])
def test_confighash_failure_after_window_reports_alert(protocol, bad_hashes):
    before = (
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb dhcp\n"
        "cccccccccccccccccccccccccccccccc firewall\n"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa network"
    )
    set_router_state(protocol, confighash=[before, bad_hashes])
    fail_verify_rounds(protocol)
    result = protocol["run"]()

    assert result.returncode == 1
    assert "ALERT" in result.stdout
    assert "could not read the config to compare it with its state before the apply" in result.stdout
    assert "ROLLBACK WINDOW PASSED" not in result.stdout


def test_apply_remote_calls_close_piped_stdin(protocol):
    result = protocol["run"](stdin_data="JSONRPC-FRAME\n")

    assert result.returncode == 0, result.stdout
    records = stdin_records(protocol)
    assert records
    for record in records:
        assert record["devnull"] is True, record["cmd"]


@pytest.mark.parametrize("command", ["status", "abort"])
def test_status_and_abort_remote_action_closes_piped_stdin(protocol, command):
    result = subprocess.run(
        _wrap_args_with_unshare(
            [str(SCRIPT), command, "root@192.0.2.1", SID],
            protocol,
        ),
        input="JSONRPC-FRAME\n", text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, env=protocol["env"], timeout=20,
    )

    assert result.returncode == 0, result.stdout
    records = stdin_records(protocol)
    action = next(record for record in records if record["cmd"] == f"{PROG} {command} {SID}")
    assert action["devnull"] is True


def test_all_remote_call_sites_explicitly_control_stdin():
    """Kills C6/M04-M08 by statically enforcing stdin handling at every call site."""
    allowed_readers = (
        'SID=$(r "$PROG stage" < "$F"',
        'SEAL=$(r "$PROG seal $SID $T" < "$PROBES"',
    )
    call_re = re.compile(
        r"(?<![-A-Za-z0-9_])(?:r(?=\s+[\"'])|logd_pid(?=[\s)]))"
    )
    violations = []
    for lineno, line in enumerate(SCRIPT.read_text().splitlines(), 1):
        if not call_re.search(line):
            continue
        if re.match(r"^\s*(r|logd_pid)\(\)", line):
            continue
        if any(allowed in line for allowed in allowed_readers):
            continue
        if "</dev/null" not in line:
            violations.append(f"{lineno}: {line.strip()}")
    assert violations == []


@pytest.mark.parametrize(
    "updates",
    [
        ({"logd": ["1314", "2020"]}),
        (
            {
                "named": "firewall.ts (ipset ts: set ts)",
                "fw_restart": ["ok"],
            }
        ),
        (
            {
                "logd": ["1314", "2020"],
                "dnsmasq_running_after_rollback": False,
            }
        ),
    ],
    ids=["logd-restart", "firewall-restart", "dnsmasq-repair"],
)
def test_piped_stdin_is_closed_on_repair_and_restart_paths(protocol, updates):
    """Kills M04-M08 dynamically on logd, firewall, and dnsmasq repair branches."""
    set_router_state(protocol, **updates)
    if updates.get("dnsmasq_running_after_rollback") is False:
        fail_verify_rounds(protocol)

    result = protocol["run"](stdin_data="JSONRPC-FRAME\n")

    expected_rc = 1 if updates.get("dnsmasq_running_after_rollback") is False else 0
    assert result.returncode == expected_rc, result.stdout
    for record in stdin_records(protocol):
        assert record["devnull"] is True, record["cmd"]


def test_post_window_status_and_hash_wait_until_deadline_plus_30(protocol):
    """Kills M12 by proving status and the second confighash run only after the wait."""
    fail_verify_rounds(protocol)
    result = protocol["run"](timeout_s=60)

    assert result.returncode == 1, result.stdout
    events = []
    for line in protocol["timed_events"].read_text().splitlines():
        event = json.loads(line)
        events.append((event["time"], event["cmd"]))
    apply_at = next(
        timestamp
        for timestamp, command in events
        if command.startswith(f"{PROG} apply {SID}")
    )
    status_at = next(
        timestamp
        for timestamp, command in events
        if command == f"{PROG} status {SID}"
    )
    hashes = [
        timestamp
        for timestamp, command in events
        if command == f"{PROG} confighash"
    ]
    assert len(hashes) == 2
    assert status_at >= apply_at + 75
    assert hashes[1] >= apply_at + 75


# ---------------------------------------------------------------------------
# Round ct2: design 7.4 bullet 1 and the c1/c2 script changes
# ---------------------------------------------------------------------------


def run_script(protocol, args, extra_env=None, *, prepare_state=True):
    env = protocol["env"].copy()
    if extra_env:
        env.update(extra_env)
    if prepare_state:
        _prepare_state_dirs(protocol)
    fake_ssh = str(protocol["root"] / "bin" / "ssh")
    unshare_cmd = [
        "unshare", "-Urm", "--", "bash", "-c",
        'mount --bind "$1" /usr/bin/ssh && shift && exec "$@"',
        "noop", fake_ssh, str(SCRIPT), *args,
    ]
    return subprocess.run(
        unshare_cmd, env=env, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, timeout=180, stdin=subprocess.DEVNULL,
    )


def apply_direct(protocol, timeout="60", extra_env=None):
    return run_script(
        protocol, ["apply", "root@192.0.2.1", SID, timeout], extra_env=extra_env
    )


def run_status(protocol, extra_env=None):
    return run_script(protocol, ["status", "root@192.0.2.1", SID], extra_env=extra_env)


def _prepare_state_dirs(protocol):
    """Chmod 0700 every state, backup and plan parent the script may inspect.

    The script's new parent-sticky check refuses a parent that is group- or
    world-writable without the sticky bit; pytest's default umask (0002)
    drops mkdir'd dirs to 0775, so we tighten each one to 0700 before the
    script runs.  Skipping this is the right move for the control-character
    tests, which assert NO state directory exists after the script's exit 2.
    """
    root = protocol["root"]
    for d in (root / "state", root / "backups"):
        if d.exists():
            os.chmod(d, 0o700)
    sub = root / "state" / "network-agent"
    for d in (sub, sub / "plans"):
        if d.exists():
            os.chmod(d, 0o700)


def _wrap_args_with_unshare(args, protocol):
    """Wrap a script invocation in `unshare -Urm` with bindir/ssh bind-mounted at /usr/bin/ssh.

    Return the argv list suitable for ``subprocess.run``.  Use this for any
    test that calls the script via a direct ``subprocess.run([str(SCRIPT), ...])``
    instead of going through ``protocol["run"]()`` / ``run_script()``.
    """
    fake_ssh = str(protocol["root"] / "bin" / "ssh")
    return [
        "unshare", "-Urm", "--", "bash", "-c",
        'mount --bind "$1" /usr/bin/ssh && shift && exec "$@"',
        "noop", fake_ssh, *args,
    ]


def plan_record(protocol, suffix):
    return protocol["root"] / "state" / "network-agent" / "plans" / f"{SID}{suffix}"


def ssh_argv_records(protocol):
    return [json.loads(line) for line in protocol["ssh_argv"].read_text().splitlines()]


def timed_events(protocol):
    return [
        json.loads(line) for line in protocol["timed_events"].read_text().splitlines()
    ]


def write_changes(tmp_path):
    changes = tmp_path / "change.uci"
    changes.write_text("set system.@system[0].description='lab'\n")
    return changes


def assert_hello_only(protocol, result, message):
    assert result.returncode == 1
    assert message in result.stdout
    calls = remote_calls(protocol)
    assert len(calls) == 1 and calls[0].startswith(f"{PROG} hello ")


# --- item 1: seal parsing and the plan output lines ---


def test_plan_prints_seal_lines_in_order_with_oneline_masking(protocol, tmp_path):
    """Several SECTION and LEASH lines, in order, each through oneline (7.1 row 142-145)."""
    changes = write_changes(tmp_path)
    set_router_state(
        protocol,
        seal_profile="lab",
        seal_sections=["dhcp lab \x01bad", "firewall wan zone wan"],
        seal_leashes=["wan-zone wan", "mgmt-zone mgmt"],
        seal_approval="not-required",
    )

    result = protocol["run_plan"](changes)

    assert result.returncode == 0, result.stdout
    lines = result.stdout.splitlines()
    at = {
        prefix: next(i for i, line in enumerate(lines) if line.startswith(prefix))
        for prefix in ("BASEHASH ", "PROBES ", "PROFILE ", "APPROVAL ", "PLANDIGEST ")
    }
    sections = [i for i, line in enumerate(lines) if line.startswith("SECTION ")]
    leashes = [i for i, line in enumerate(lines) if line.startswith("LEASH ")]
    assert len(sections) == 2 and len(leashes) == 2
    assert at["BASEHASH "] < at["PROBES "] < at["PROFILE "]
    assert at["PROFILE "] < sections[0] < sections[1] < leashes[0] < leashes[1]
    assert leashes[1] < at["APPROVAL "] < at["PLANDIGEST "]
    # a router-supplied control character is turned into a space (oneline)
    assert "SECTION dhcp lab  bad" in result.stdout
    assert "SECTION firewall wan zone wan" in result.stdout
    assert "LEASH wan-zone wan" in result.stdout
    assert "LEASH mgmt-zone mgmt" in result.stdout
    assert "APPROVAL not-required" in result.stdout
    assert re.fullmatch(r"PLANDIGEST [0-9a-f]{64}", lines[at["PLANDIGEST "]])
    assert re.fullmatch(r"PROBES 0 [0-9a-f]{64}", lines[at["PROBES "]])


GOOD_SEAL = [
    "base " + "a" * 64,
    "diff " + "b" * 64,
    "probes 0 " + "c" * 64,
    "t 90",
    "profile lab",
    "section dhcp lab - -",
    "approval not-required",
    "digest " + "d" * 64,
]


@pytest.mark.parametrize(
    "seal_raw",
    [
        GOOD_SEAL[:6] + GOOD_SEAL[7:],
        [GOOD_SEAL[1], GOOD_SEAL[0]] + GOOD_SEAL[2:],
        GOOD_SEAL[:-1] + ["digest " + "z" * 64],
        [line.replace("t 90", "t 61") for line in GOOD_SEAL],
        GOOD_SEAL[:5] + ["zones dhcp lab"] + GOOD_SEAL[5:],
    ],
    ids=["missing-line", "wrong-order", "non-hex-digest", "t-mismatch", "bad-section"],
)
def test_malformed_seal_reply_dies_without_plan_record(protocol, tmp_path, seal_raw):
    changes = write_changes(tmp_path)
    set_router_state(protocol, seal_raw=seal_raw)

    result = protocol["run_plan"](changes)

    assert result.returncode == 1
    assert "ERROR: malformed seal reply" in result.stdout
    assert not plan_record(protocol, ".sha256").exists()
    assert not plan_record(protocol, ".base").exists()
    assert "STAGED" not in result.stdout


# --- item 2: plan record files ---


def test_plan_records_hold_seal_facts_mode_600_and_no_hash_oracle(protocol, tmp_path):
    """triage #5: the diff hash lives only in the 0600 plan record, never the audit."""
    changes = write_changes(tmp_path)

    result = protocol["run_plan"](changes)

    assert result.returncode == 0, result.stdout
    state = router_state(protocol)
    expected_base = hashlib.sha256(
        "".join(line + "\n" for line in state["confighash"]).encode()
    ).hexdigest()
    expected_diff = hashlib.sha256(
        (state["diff"].rstrip("\n") + "\n").encode()
    ).hexdigest()
    assert plan_record(protocol, ".sha256").read_text() == expected_diff + "\n"
    assert plan_record(protocol, ".base").read_text() == expected_base + "\n"
    assert plan_record(protocol, ".probes").read_text() == "0\n"
    for suffix in (".sha256", ".base", ".probes"):
        assert plan_record(protocol, suffix).stat().st_mode & 0o777 == 0o600
    audit = protocol["audit"].read_text()
    assert expected_diff not in audit
    assert expected_diff[:12] not in audit


# --- item 3: abort on a seal failure ---


@pytest.mark.parametrize("rc", [1, 2, 3])
def test_seal_failure_aborts_and_discards_for_every_exit_code(protocol, tmp_path, rc):
    changes = write_changes(tmp_path)
    set_router_state(
        protocol, seal_fail={"rc": rc, "stderr": "error bad-probe 1 unknown-probe"}
    )

    result = protocol["run_plan"](changes)

    assert result.returncode == 1
    assert (
        "probes refused: error bad-probe 1 unknown-probe; "
        "the staged change was discarded"
    ) in result.stdout
    assert f"{PROG} abort {SID}" in remote_calls(protocol)
    assert "STAGED" not in result.stdout
    assert not plan_record(protocol, ".sha256").exists()


# --- item 4: stage error text masked (triage #6) ---


def test_stage_error_masks_secret_and_never_leaks_it(protocol, tmp_path):
    changes = tmp_path / "change.uci"
    changes.write_text("set wireless.x.key='SECRETVALUE'\n")
    set_router_state(
        protocol,
        stage_fail={
            "rc": 1,
            "stderr": "uci: /tmp/batch:1: uci set wireless.x.key=SECRETVALUE\n",
        },
    )

    result = protocol["run_plan"](changes)

    assert result.returncode == 1
    assert "SECRETVALUE" not in result.stdout
    assert "SECRETVALUE" not in protocol["audit"].read_text()
    assert "wireless.x.key='<masked>'" in result.stdout


def test_stage_error_masks_midline_secret_when_first_eq_is_harmless(protocol, tmp_path):
    """mask_secrets must scan the WHOLE line, not just the part before the FIRST '='.

    A stage-error line such as `uci: foo=bar password='S3cr3tValue'` had the
    secret leaking into both the screen and the audit log when mask_secrets
    only inspected the prefix before the first '='.  Confirm neither surface
    sees the secret value, and the harmless `foo=bar` prefix is preserved
    before the `password='<masked>'` truncation.
    """
    changes = tmp_path / "change.uci"
    changes.write_text("set wireless.x.key='X'\n")
    set_router_state(
        protocol,
        stage_fail={
            "rc": 1,
            "stderr": "uci: foo=bar password='S3cr3tValue'\n",
        },
    )

    result = protocol["run_plan"](changes)

    assert result.returncode == 1
    assert "S3cr3tValue" not in result.stdout
    assert "S3cr3tValue" not in protocol["audit"].read_text()
    assert "foo=bar password='<masked>'" in result.stdout


def test_stage_error_joins_at_most_three_lines(protocol, tmp_path):
    changes = write_changes(tmp_path)
    set_router_state(
        protocol,
        stage_fail={"rc": 1, "stderr": "\n".join(f"line{i} value{i}" for i in range(1, 6))},
    )

    result = protocol["run_plan"](changes)

    assert result.returncode == 1
    assert (
        "staging rejected: line1 value1 / line2 value2 / line3 value3"
    ) in result.stdout
    assert "line4" not in result.stdout


def test_stage_error_with_empty_stderr_is_exactly_staging_rejected(protocol, tmp_path):
    changes = write_changes(tmp_path)
    set_router_state(protocol, stage_fail={"rc": 1, "stderr": ""})

    result = protocol["run_plan"](changes)

    assert result.returncode == 1
    assert "ERROR: staging rejected" in result.stdout.splitlines()
    assert "staging rejected:" not in result.stdout


# --- item 5: handshake refusals ---


def test_handshake_refuses_api_not_1(protocol):
    set_router_state(protocol, hello_overrides={"api": "2"})
    assert_hello_only(
        protocol,
        run_status(protocol),
        "router program speaks api=2, this controller speaks api=1",
    )


@pytest.mark.parametrize(
    "component", ["helper", "guard", "init"], ids=["helper-hash", "guard-hash", "init-hash"]
)
def test_handshake_refuses_each_code_hash_mismatch(protocol, component):
    set_router_state(protocol, hello_overrides={component: "0" * 64})
    assert_hello_only(
        protocol,
        run_status(protocol),
        f"router {component} 1.0.0 ({component} 00000000...) differs from this controller's",
    )


def test_handshake_refuses_device_mismatch(protocol):
    set_router_state(protocol, hello_overrides={"device": "other-router"})
    result = run_status(protocol, extra_env={"OWRT_EXPECT_DEVICE": "lab-r1"})
    assert_hello_only(
        protocol,
        result,
        "router device=other-router is not the expected lab-r1; check OWRT_EXPECT_DEVICE",
    )


def test_handshake_refuses_profile_mismatch(protocol):
    set_router_state(protocol, hello_overrides={"profile": "lab"})
    result = run_status(protocol, extra_env={"OWRT_EXPECT_PROFILE": "prod"})
    assert_hello_only(
        protocol,
        result,
        "router profile=lab is not the expected prod; check OWRT_EXPECT_PROFILE",
    )


def test_handshake_allows_busy_router_at_apply(protocol):
    set_router_state(protocol, hello_overrides={"busy": "another-agent"})

    result = protocol["run"]()

    assert result.returncode == 0, result.stdout
    assert f"CONFIRMED session={SID}" in result.stdout


@pytest.mark.parametrize(
    "raw",
    [
        "hello {nonce} api=1 mode=prod\nmode=prod extra",
        "hello {nonce} api=1 api=1 mode=prod",
        "hello {nonce} api 1",
        "hello 0000000000000000 api=1 mode=prod",
        "",
    ],
    ids=["two-lines", "repeated-key", "no-equals", "wrong-nonce", "empty-reply"],
)
def test_handshake_refuses_malformed_hello_reply(protocol, raw):
    set_router_state(protocol, hello_raw=raw)
    assert_hello_only(protocol, run_status(protocol), "malformed hello reply")


def test_handshake_dies_when_ssh_exits_255(protocol):
    set_router_state(protocol, hello_rc=255)
    assert_hello_only(protocol, run_status(protocol), "router unreachable during hello")


def test_unchecked_device_and_profile_are_logged_without_compare(protocol):
    set_router_state(protocol, hello_overrides={"device": "who\x01knows"})

    result = run_status(protocol)

    assert result.returncode == 0, result.stdout
    audit = protocol["audit"].read_text()
    assert "unchecked device" in audit
    assert "unchecked profile" in audit


def test_unreadable_host_copy_dies_naming_the_file(protocol, tmp_path):
    empty_root = tmp_path / "emptyroot"
    empty_root.mkdir()

    result = run_status(protocol, extra_env={"OWRT_SRC_ROOT": str(empty_root)})

    assert_hello_only(
        protocol,
        result,
        "cannot read this controller's copy of the router's prog: "
        f"{empty_root}/device/openwrt/newton-router/newton-router",
    )


def test_owrt_src_root_redirects_the_host_copies(protocol, tmp_path):
    """The handshake hashes the host copies at OWRT_SRC_ROOT, not the script's tree."""
    src_root = tmp_path / "srcroot"
    repo = SCRIPT.parents[1]
    for rel in (
        "device/openwrt/newton-router/newton-router",
        "scripts/owrt-safe-apply.sh",
        "device/openwrt/newton-guard/newton-guard",
        "device/openwrt/newton-guard/newton-guard.init",
    ):
        target = src_root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(repo / rel, target)

    # the router keeps hashing the real repo; the host hashes the redirected copy
    ok = run_status(
        protocol,
        extra_env={
            "OWRT_SRC_ROOT": str(src_root),
            "NEWTON_FAKE_SRC_ROOT": str(repo),
        },
    )
    assert ok.returncode == 0, ok.stdout

    with (src_root / "device/openwrt/newton-router/newton-router").open("a") as prog:
        prog.write("# drifted\n")
    protocol["calls"].write_text("")
    drifted = run_status(
        protocol,
        extra_env={
            "OWRT_SRC_ROOT": str(src_root),
            "NEWTON_FAKE_SRC_ROOT": str(repo),
        },
    )
    assert_hello_only(protocol, drifted, "differs from this controller's")


# --- item 6: key-mode ssh options ---


def test_key_mode_adds_identity_options_to_every_ssh_call(protocol):
    key = str(protocol["root"] / "restricted-key")

    result = run_status(protocol, extra_env={"OWRT_SSH_KEY": key})

    assert result.returncode == 0, result.stdout
    records = ssh_argv_records(protocol)
    assert records
    for argv in records:
        assert argv[argv.index("-i") + 1] == key
        assert "IdentitiesOnly=yes" in argv


def test_known_hosts_mode_pins_the_host_key_on_every_ssh_call(protocol):
    known_hosts = str(protocol["root"] / "known_hosts")

    result = run_status(protocol, extra_env={"OWRT_KNOWN_HOSTS": known_hosts})

    assert result.returncode == 0, result.stdout
    records = ssh_argv_records(protocol)
    assert records
    for argv in records:
        assert "StrictHostKeyChecking=yes" in argv
        assert f"UserKnownHostsFile={known_hosts}" in argv


def test_password_mode_carries_no_key_or_known_hosts_options(protocol, tmp_path):
    password_file = tmp_path / "password"
    password_file.write_text("made-up-password\n")
    password_file.chmod(0o600)

    result = run_status(protocol, extra_env={"OWRT_SSH_PASSWORD_FILE": str(password_file)})

    assert result.returncode == 0, result.stdout
    records = ssh_argv_records(protocol)
    assert records
    for argv in records:
        assert "-i" not in argv
        assert "IdentitiesOnly=yes" not in argv
        assert "StrictHostKeyChecking=yes" not in argv
        assert not any(arg.startswith("UserKnownHostsFile=") for arg in argv)


# --- item 6b: OWRT_SSH_PROXY grammar (matches the python PROXY_COMMAND_RE) ---


_PROXY_BAD_CHARS = [";", "|", "&", "$", "`", "(", ")", "<", ">", "'", '"', "\\"]


@pytest.mark.parametrize("bad_char", _PROXY_BAD_CHARS)
def test_apply_refuses_owrt_ssh_proxy_with_disallowed_character(protocol, bad_char):
    bad_value = f"good{bad_char}good"

    result = protocol["run"](extra_env={"OWRT_SSH_PROXY": bad_value})

    assert result.returncode == 1
    assert (
        "ERROR: OWRT_SSH_PROXY contains characters outside"
        " [A-Za-z0-9 _./:@%~=,+-] or is longer than 512" in result.stdout
    )
    calls = remote_calls(protocol)
    assert not any(call.startswith(f"{PROG} hello ") for call in calls)
    assert not calls, calls


@pytest.mark.parametrize("bad_value", ["ssh \u00e9", "ssh \uff41", "ssh \u01c5"])
def test_apply_refuses_non_ascii_owrt_ssh_proxy_even_in_a_utf8_locale(protocol, bad_value):
    """In en_US.UTF-8 a bash [A-Za-z] range matches accented letters; the grammar is ASCII-only."""
    result = protocol["run"](
        extra_env={"OWRT_SSH_PROXY": bad_value, "LC_ALL": "en_US.UTF-8", "LANG": "en_US.UTF-8"}
    )

    assert result.returncode == 1
    assert "ERROR: OWRT_SSH_PROXY contains characters outside" in result.stdout
    assert not remote_calls(protocol)


def test_apply_refuses_owrt_ssh_proxy_longer_than_512(protocol):
    bad_value = "a" * 513

    result = protocol["run"](extra_env={"OWRT_SSH_PROXY": bad_value})

    assert result.returncode == 1
    assert "ERROR: OWRT_SSH_PROXY contains characters outside" in result.stdout
    assert "longer than 512" in result.stdout
    calls = remote_calls(protocol)
    assert not any(call.startswith(f"{PROG} hello ") for call in calls)


def test_apply_passes_documented_owrt_ssh_proxy_form_to_ssh(protocol):
    proxy = "ssh -i ~/.ssh/key -o BatchMode=yes -W %h:%p root@jump"

    result = protocol["run"](extra_env={"OWRT_SSH_PROXY": proxy}, timeout_s=90)

    assert "ERROR: OWRT_SSH_PROXY" not in result.stdout
    argv_lines = [json.loads(line) for line in protocol["ssh_argv"].read_text().splitlines()]
    assert argv_lines, "no ssh was called"
    expected = "ProxyCommand=" + proxy
    assert any(expected in argv for argv in argv_lines), argv_lines


# --- item 7: validate_timeout ---


@pytest.mark.parametrize(
    "timeout", ["59", "601", "0100", "0600", "0060", "060", "abc", "", "1e2"]
)
@pytest.mark.parametrize("command", ["plan", "apply"])
def test_bad_timeout_refused_before_any_ssh_call(
    protocol, tmp_path, command, timeout
):
    changes = write_changes(tmp_path)
    args = (
        ["plan", "root@192.0.2.1", str(changes), timeout]
        if command == "plan"
        else ["apply", "root@192.0.2.1", SID, timeout]
    )

    result = run_script(protocol, args)

    assert result.returncode == 1
    assert "timeout must be an integer 60..600" in result.stdout
    assert remote_calls(protocol) == []
    # an explicitly EMPTY timeout argument reaches validate_timeout (the default 90
    # applies only when the argument is absent: `${4-90}`, not `${4:-90}`)


def test_empty_probes_argument_is_refused_not_treated_as_none(protocol, tmp_path):
    changes = write_changes(tmp_path)

    result = protocol["run_plan"](changes, extra_args=["90", ""])

    assert result.returncode == 1
    assert "probes file not readable: " in result.stdout
    assert remote_calls(protocol) == []


@pytest.mark.parametrize("timeout", [60, 100, 600])
@pytest.mark.parametrize("command", ["plan", "apply"])
def test_good_timeouts_accepted(protocol, tmp_path, command, timeout):
    changes = write_changes(tmp_path)
    if command == "plan":
        result = protocol["run_plan"](changes, timeout=timeout)
    else:
        result = protocol["run"](timeout_s=timeout)
    assert result.returncode == 0, result.stdout


# --- item 8: probes file argument boundaries ---


def test_probes_file_of_exactly_4096_bytes_is_accepted(protocol, tmp_path):
    changes = write_changes(tmp_path)
    probes = tmp_path / "probes"
    probes.write_bytes(b"p" * 4096)

    result = protocol["run_plan"](changes, probes=probes)

    assert result.returncode == 0, result.stdout
    records = seal_stdin_records(protocol)
    assert records[0]["data"] == (b"p" * 4096).hex()
    assert f"PROBES 1 {hashlib.sha256(b'p' * 4096).hexdigest()}" in result.stdout


def test_probes_file_of_4097_bytes_is_refused_before_any_ssh_call(protocol, tmp_path):
    changes = write_changes(tmp_path)
    probes = tmp_path / "probes"
    probes.write_bytes(b"p" * 4097)

    result = protocol["run_plan"](changes, probes=probes)

    assert result.returncode == 1
    assert "probes file larger than 4096 bytes" in result.stdout
    assert remote_calls(protocol) == []


# --- item 9: apply token ---


def test_unset_approval_token_applies_with_none(protocol):
    result = protocol["run"]()

    assert result.returncode == 0, result.stdout
    # SW2 Item 2: apply takes five words; unset NBF/EXP default to 0 0
    assert f"{PROG} apply {SID} 60 none 0 0" in remote_calls(protocol)


@pytest.mark.parametrize(
    "token",
    [
        "A" * 64,
        "e" * 63,
        "e" * 65,
        "NONE",
        "e" * 32 + " " + "e" * 31,
        "e" * 32 + "\n" + "e" * 31,
    ],
    ids=["uppercase", "63-chars", "65-chars", "NONE", "space", "newline"],
)
def test_bad_approval_token_refused_before_any_ssh_call_without_leaking(
    protocol, token
):
    result = protocol["run"](extra_env={"OWRT_APPROVAL_TOKEN": token})

    assert result.returncode == 1
    assert "OWRT_APPROVAL_TOKEN must be 'none' or 64 lowercase hex characters" in result.stdout
    assert token not in result.stdout
    assert token not in protocol["audit"].read_text()
    assert remote_calls(protocol) == []


# --- item 10: apply exit 3 and the outcome-unknown branches ---


def test_apply_exit_1_is_outcome_unknown(protocol):
    set_router_state(protocol, apply_rc=1, apply_stderr="error rpcd-lock")

    result = protocol["run"]()

    assert result.returncode == 1
    assert (
        f"apply did not report success — OUTCOME UNKNOWN; run: {SCRIPT} status root@192.0.2.1 {SID}"
    ) in result.stdout
    assert f"APPLIED session={SID}" not in result.stdout
    assert verify_rounds(protocol) == []
    assert not any(call.startswith(f"{PROG} confirm") for call in remote_calls(protocol))


def test_apply_unexpected_stdout_is_outcome_unknown(protocol):
    set_router_state(protocol, apply_stdout="applied-ish")

    result = protocol["run"]()

    assert result.returncode == 1
    assert "apply did not report success — OUTCOME UNKNOWN" in result.stdout
    assert f"APPLIED session={SID}" not in result.stdout
    assert verify_rounds(protocol) == []
    assert not any(call.startswith(f"{PROG} confirm") for call in remote_calls(protocol))


def test_apply_exit_3_runs_no_failure_branch(protocol):
    set_router_state(protocol, apply_rc=3, apply_stderr="error plan-changed t")

    result = protocol["run"]()

    assert result.returncode == 1
    assert f"apply refused, nothing applied: error plan-changed t; session {SID} is still staged" in result.stdout
    assert f"APPLIED session={SID}" not in result.stdout
    calls = remote_calls(protocol)
    assert not any(call == f"{PROG} status {SID}" for call in calls)
    assert not any(call == f"{PROG} abort {SID}" for call in calls)
    assert not any(call.startswith(f"{PROG} confirm") for call in calls)
    assert "ROLLBACK WINDOW PASSED" not in result.stdout
    assert "ALERT" not in result.stdout
    assert "ABORTED" not in result.stdout


# --- item 11: diff re-hash and DIFF masking ---


def test_changed_staged_diff_dies_before_apply(protocol, tmp_path):
    changes = write_changes(tmp_path)
    plan = protocol["run_plan"](changes)
    assert plan.returncode == 0, plan.stdout
    set_router_state(protocol, diff="dhcp.lab.limit='99'\n")

    result = apply_direct(protocol)

    assert result.returncode == 1
    assert "staged diff changed since plan — re-plan and re-approve" in result.stdout
    assert not any(
        call.startswith(f"{PROG} apply {SID}") for call in remote_calls(protocol)
    )


def test_empty_diff_hashes_like_the_empty_input(protocol, tmp_path):
    set_router_state(protocol, diff="")
    record = plan_record(protocol, ".sha256")
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text(hashlib.sha256(b"").hexdigest() + "\n")

    result = apply_direct(protocol)

    assert result.returncode == 0, result.stdout
    assert f"CONFIRMED session={SID}" in result.stdout


def test_apply_masks_triage4_secret_names_in_diff_audit(protocol):
    """triage #4: r0kh, r1kh, authkey and apikey never appear raw in the audit."""
    secrets = {
        "r0kh": "R0KH-SECRET",
        "r1kh": "R1KH-SECRET",
        "authkey": "AUTH-SECRET",
        "apikey": "API-SECRET",
    }
    diff = (
        "uci set wireless.x.r0kh='R0KH-SECRET'\n"
        "uci set wireless.wifi.r1kh='R1KH-SECRET'\n"
        "uci set wireless.x.authkey='AUTH-SECRET'\n"
        "uci set rpcd.login.apikey='API-SECRET'\n"
    )
    set_router_state(protocol, diff=diff)

    result = protocol["run"]()

    audit = protocol["audit"].read_text()
    assert result.returncode == 0, result.stdout
    for name in secrets:
        assert f"DIFF session={SID}: uci set" in audit
        assert f"{name}='<masked>'" in audit
    for value in secrets.values():
        assert value not in audit
        assert value not in result.stdout


# --- item 12: confirm output ---


def test_confirmed_line_reports_probe_count_from_plan_record(protocol, tmp_path):
    changes = write_changes(tmp_path)
    probes = tmp_path / "probes"
    probes.write_bytes(b"uci-equals dhcp.lab.limit '50'\nfw-loaded\n")
    plan = protocol["run_plan"](changes, probes=probes)
    assert plan.returncode == 0, plan.stdout
    assert plan_record(protocol, ".probes").read_text() == "2\n"

    result = protocol["run"]()

    assert result.returncode == 0, result.stdout
    assert "fresh ssh + router-side ping, dns, health and 2 probes" in result.stdout


def test_confirm_unexpected_stdout_is_outcome_unknown(protocol):
    set_router_state(protocol, confirm_form=f"confirmed {SID} something-else")

    result = protocol["run"]()

    assert result.returncode == 1
    assert (
        f"CONFIRM DID NOT REPORT SUCCESS session={SID} — OUTCOME UNKNOWN; "
        f"run: {SCRIPT} status root@192.0.2.1 {SID}"
    ) in result.stdout
    assert f"CONFIRMED session={SID}" not in result.stdout


def test_confirm_exit_3_runs_the_failure_branch(protocol):
    set_router_state(protocol, confirm_rc=3)

    result = protocol["run"]()

    assert result.returncode == 1
    assert f"CONFIRMED session={SID}" not in result.stdout
    assert f"ROLLBACK WINDOW PASSED session={SID}" in result.stdout
    calls = remote_calls(protocol)
    assert any(call == f"{PROG} status {SID}" for call in calls)
    assert any(call == f"{PROG} abort {SID}" for call in calls)


@pytest.mark.parametrize(
    "stderr",
    ["error rpcd-confirm-failed: ping failed", "error confirm-incomplete probes"],
    ids=["rpcd-confirm-failed", "confirm-incomplete"],
)
def test_confirm_rpcd_errors_run_the_failure_branch(protocol, stderr):
    set_router_state(protocol, confirm_rc=1, confirm_stderr=stderr)

    result = protocol["run"]()

    assert result.returncode == 1
    assert f"CONFIRMED session={SID}" not in result.stdout
    assert f"ROLLBACK WINDOW PASSED session={SID}" in result.stdout
    calls = remote_calls(protocol)
    assert any(call == f"{PROG} status {SID}" for call in calls)
    assert any(call == f"{PROG} abort {SID}" for call in calls)


def test_confirm_exit_1_with_other_stderr_is_outcome_unknown(protocol):
    set_router_state(protocol, confirm_rc=1, confirm_stderr="error weird")

    result = protocol["run"]()

    assert result.returncode == 1
    assert (
        f"CONFIRM DID NOT REPORT SUCCESS session={SID} — OUTCOME UNKNOWN"
    ) in result.stdout
    assert f"ROLLBACK WINDOW PASSED session={SID}" not in result.stdout
    assert not any(call == f"{PROG} abort {SID}" for call in remote_calls(protocol))


REFUSED_SUFFIX = "; the router reverts on its own, waiting out the window"


def test_confirm_exit_3_empty_stderr_logs_one_confirm_refused_line(protocol):
    set_router_state(protocol, confirm_rc=3, confirm_stderr="")

    result = protocol["run"]()

    assert result.returncode == 1
    line = f"CONFIRM REFUSED session={SID}: exit 3 (too-late){REFUSED_SUFFIX}"
    assert line in result.stdout
    assert line in protocol["audit"].read_text()
    assert protocol["audit"].read_text().count("CONFIRM REFUSED") == 1


def test_confirm_exit_3_with_stderr_logs_confirm_refused_line(protocol):
    set_router_state(protocol, confirm_rc=3, confirm_stderr="error too-late: the rollback already ran")

    result = protocol["run"]()

    assert result.returncode == 1
    line = (
        f"CONFIRM REFUSED session={SID}: error too-late: the rollback already ran"
        f"{REFUSED_SUFFIX}"
    )
    assert line in result.stdout
    assert line in protocol["audit"].read_text()


@pytest.mark.parametrize(
    "stderr",
    ["error rpcd-confirm-failed: ping failed", "error confirm-incomplete probes"],
    ids=["rpcd-confirm-failed", "confirm-incomplete"],
)
def test_confirm_rpcd_errors_log_confirm_refused_line(protocol, stderr):
    set_router_state(protocol, confirm_rc=1, confirm_stderr=stderr)

    result = protocol["run"]()

    assert result.returncode == 1
    line = f"CONFIRM REFUSED session={SID}: {stderr}{REFUSED_SUFFIX}"
    assert line in result.stdout
    assert line in protocol["audit"].read_text()


def test_normal_confirm_logs_no_confirm_refused_line(protocol):
    result = protocol["run"]()

    assert result.returncode == 0, result.stdout
    assert "CONFIRM REFUSED" not in result.stdout
    assert "CONFIRM REFUSED" not in protocol["audit"].read_text()


# --- item 13: failure branch order ---


def test_status_retried_every_5s_up_to_90s_then_unreachable_alert(protocol):
    set_router_state(protocol, status_ssh=["fail"] * 40)
    fail_verify_rounds(protocol)

    result = protocol["run"]()

    assert result.returncode == 1
    assert (
        f"ALERT session={SID} status=unreachable after rollback window — "
        "check the router now; latest backup in" in result.stdout
    )
    calls = [call for call in remote_calls(protocol) if call == f"{PROG} status {SID}"]
    # first try plus one retry every 5 s while waited < 90 s
    assert len(calls) == 19
    times = [
        event["time"]
        for event in timed_events(protocol)
        if event["cmd"] == f"{PROG} status {SID}"
    ]
    # virtual seconds also absorb real spawn time, so the span is at least 90
    assert times[-1] - times[0] >= 90
    assert all(b - a >= 5 for a, b in zip(times, times[1:]))
    assert f"{PROG} abort {SID}" not in remote_calls(protocol)
    assert "ABORTED" not in result.stdout


def test_failed_abort_is_alerted_and_final_line_names_it(protocol):
    failure = "health: service uhttpd/instance1 is not running after the change"
    set_router_state(protocol, abort_fail="error rpcd-busy", health_checks=[failure])
    fail_verify_rounds(protocol)

    result = protocol["run"]()

    assert result.returncode == 1
    assert (
        f"ALERT session={SID} abort did not report success: error rpcd-busy"
    ) in result.stdout
    final = result.stdout.splitlines()[-1]
    assert final.startswith(f"ALERT session={SID} rolled back, but")
    assert final.endswith("(abort: failed)")


def test_after_rollback_health_retry_until_pass_leaves_no_reason(protocol):
    failure = "health: service uhttpd/instance1 is not running after the change"
    set_router_state(protocol, health_checks=[failure, "ok"])
    fail_verify_rounds(protocol)

    result = protocol["run"]()

    assert result.returncode == 1
    retries = [
        call
        for call in remote_calls(protocol)
        if call == f"{PROG} health-check {SID} after-rollback"
    ]
    assert len(retries) == 2
    assert "service or firewall health differs" not in result.stdout
    assert f"ROLLBACK WINDOW PASSED session={SID}" in result.stdout


def test_after_rollback_health_three_failures_add_the_reason(protocol):
    failure = "health: service uhttpd/instance1 is not running after the change"
    set_router_state(protocol, health_checks=[failure])
    fail_verify_rounds(protocol)

    result = protocol["run"]()

    assert result.returncode == 1
    retries = [
        call
        for call in remote_calls(protocol)
        if call == f"{PROG} health-check {SID} after-rollback"
    ]
    assert len(retries) == 3
    times = [
        event["time"]
        for event in timed_events(protocol)
        if event["cmd"] == f"{PROG} health-check {SID} after-rollback"
    ]
    assert all(b - a >= 5 for a, b in zip(times, times[1:]))
    assert (
        "service or firewall health differs from before the apply after the rollback"
    ) in result.stdout
    assert f"ABORTED session={SID} (discarded)" in result.stdout
    final = result.stdout.splitlines()[-1]
    assert final.startswith(f"ALERT session={SID} rolled back, but")
    assert final.endswith("(abort: discarded)")


@pytest.mark.parametrize(
    "failure",
    [
        "health: not compared: the router rebooted during the window; the guard restored the config at boot",
        "health: not compared: no health snapshot for session 0123456789abcdef0123456789abcdef",
    ],
    ids=["reboot-during-window", "no-snapshot"],
)
def test_after_rollback_health_not_compared_says_not_compared(protocol, failure):
    set_router_state(protocol, health_checks=[failure])
    fail_verify_rounds(protocol)

    result = protocol["run"]()

    assert result.returncode == 1
    retries = [
        call
        for call in remote_calls(protocol)
        if call == f"{PROG} health-check {SID} after-rollback"
    ]
    assert len(retries) == 3
    assert f"ABORTED session={SID} (discarded)" in result.stdout
    final = result.stdout.splitlines()[-1]
    assert final.startswith(f"ALERT session={SID} rolled back, but")
    assert final.endswith("(abort: discarded)")
    assert (
        "service or firewall health was not compared after the rollback: "
        + failure
    ) in final
    assert "health differs" not in result.stdout


def test_confirmed_status_alerts_with_design_text_and_never_aborts(protocol):
    set_router_state(protocol, status="confirmed")
    fail_verify_rounds(protocol)

    result = protocol["run"]()

    assert result.returncode == 1
    assert (
        f"ALERT session={SID} status=confirmed after the rollback window — "
        "the change was confirmed outside this run; check the router now; "
        f"latest backup in {protocol['root'] / 'backups'}"
    ) in result.stdout
    assert f"{PROG} abort {SID}" not in remote_calls(protocol)
    assert "ABORTED" not in result.stdout


@pytest.mark.parametrize("st", ["staged", "inconsistent"])
def test_staged_and_inconsistent_alert_without_abort(protocol, st):
    set_router_state(protocol, status=st)
    fail_verify_rounds(protocol)

    result = protocol["run"]()

    assert result.returncode == 1
    assert (
        f"ALERT session={SID} status={st} after rollback window — "
        "check the router now; latest backup in" in result.stdout
    )
    assert f"{PROG} abort {SID}" not in remote_calls(protocol)


def test_rpcd_rolled_back_status_names_rpcd_as_the_cause(protocol):
    set_router_state(protocol, status="rolled-back rpcd=rolled-back guard=idle")
    fail_verify_rounds(protocol)

    result = protocol["run"]()

    assert result.returncode == 1
    assert (
        f"ROLLBACK WINDOW PASSED session={SID} — router reachable; "
        "the committed config matches its state before the apply (3 packages compared); "
        "rolled back by rpcd"
    ) in result.stdout
    assert "the guard: rpcd lost its rollback" not in result.stdout
    assert f"ABORTED session={SID} (discarded)" in result.stdout


def rolled_back_line(guard, rpcd="-"):
    """The first line a real router prints after an abort during the
    window: `rolled-back sid=<sid> guard=<restorer> rpcd=- config=- boot=-`
    (design 6.5)."""
    return f"rolled-back sid={SID} guard={guard} rpcd={rpcd} config=- boot=-"


@pytest.mark.parametrize(
    "guard,cause",
    [
        ("restored:rpcd", "an abort during the window (rpcd rolled it back)"),
        ("restored:guard", "an abort during the window (the guard restored it)"),
        (
            "restored:already-base",
            "an abort during the window (the config was already back)",
        ),
    ],
    ids=["rpcd", "guard", "already-base"],
)
def test_abort_during_window_names_who_restored_the_config(protocol, guard, cause):
    """After a USER abort during the rollback window the router answers
    `rolled-back ... guard=restored:rpcd rpcd=- ...`: the guard's `last`
    line names the real restorer (design 6.5). The wrapper must read the
    guard= field too, instead of blaming a lost rpcd timer."""
    set_router_state(protocol, status=rolled_back_line(guard))
    fail_verify_rounds(protocol)

    result = protocol["run"]()

    assert result.returncode == 1
    assert (
        f"ROLLBACK WINDOW PASSED session={SID} — router reachable; "
        "the committed config matches its state before the apply (3 packages compared); "
        f"rolled back by {cause}"
    ) in result.stdout
    assert "the guard: rpcd lost its rollback" not in result.stdout
    assert f"ABORTED session={SID} (discarded)" in result.stdout


@pytest.mark.parametrize("guard", ["restored:abort", "restored:deadline", "other", "idle"])
def test_unknown_guard_label_keeps_the_guard_text(protocol, guard):
    """Any guard= label that does not name an abort-during-the-window
    restorer keeps the old text (`rpcd=-` means the guard restored a lost
    rpcd timer, design 6.5)."""
    set_router_state(protocol, status=rolled_back_line(guard))
    fail_verify_rounds(protocol)

    result = protocol["run"]()

    assert result.returncode == 1
    assert (
        "rolled back by the guard: rpcd lost its rollback" in result.stdout
    ), result.stdout
    assert "an abort during the window" not in result.stdout


def test_rpcd_rolled_back_wins_over_the_guard_label(protocol):
    """`rpcd=rolled-back` still names rpcd itself: a self-reverting rpcd
    leaves the guard= label alone, and the two never co-occur."""
    set_router_state(
        protocol, status=rolled_back_line("restored:rpcd", rpcd="rolled-back")
    )
    fail_verify_rounds(protocol)

    result = protocol["run"]()

    assert result.returncode == 1
    assert "rolled back by rpcd" in result.stdout, result.stdout
    assert "an abort during the window" not in result.stdout


def test_hostile_second_line_cannot_claim_an_abort_during_the_window(protocol):
    """Only the FIRST line of the `status` reply counts: a `guard=` field
    planted on a second line must not change the audit log's cause."""
    set_router_state(
        protocol,
        status=(
            f"rolled-back sid={SID} guard=restored:abort rpcd=- config=- boot=-"
            f"\nrolled-back sid={SID} guard=restored:rpcd rpcd=rolled-back"
        ),
    )
    fail_verify_rounds(protocol)

    result = protocol["run"]()

    assert result.returncode == 1
    assert "rolled back by the guard: rpcd lost its rollback" in result.stdout
    assert "an abort during the window" not in result.stdout
    assert "guard=restored:rpcd" not in result.stdout
    assert "guard=restored:rpcd" not in protocol["audit"].read_text()


# --- item 14: status and abort commands ---


def test_status_command_handshakes_first_and_prints_through_oneline(protocol):
    set_router_state(protocol, status="rolled-back\x01rpcd=rolled-back guard=idle")

    result = run_status(protocol)

    assert result.returncode == 0, result.stdout
    calls = remote_calls(protocol)
    assert calls[0].startswith(f"{PROG} hello ")
    assert calls[1] == f"{PROG} status {SID}"
    assert "rolled-back rpcd=rolled-back guard=idle" in result.stdout.splitlines()


def test_abort_command_handshakes_logs_and_removes_plan_record(protocol):
    record = plan_record(protocol, ".sha256")
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text("0" * 64 + "\n")

    result = run_script(protocol, ["abort", "root@192.0.2.1", SID])

    assert result.returncode == 0, result.stdout
    calls = remote_calls(protocol)
    assert calls[0].startswith(f"{PROG} hello ")
    assert calls[1] == f"{PROG} abort {SID}"
    assert f"ABORTED session={SID} (discarded)" in result.stdout
    assert not record.exists()


def test_failing_abort_dies_with_first_stderr_line(protocol):
    set_router_state(protocol, abort_fail="error rpcd-busy")

    result = run_script(protocol, ["abort", "root@192.0.2.1", SID])

    assert result.returncode == 1
    assert (
        f"abort did not report success: error rpcd-busy; "
        f"run: {SCRIPT} status root@192.0.2.1 {SID}"
    ) in result.stdout


@pytest.mark.parametrize("command", ["status", "abort"])
def test_malformed_sid_refused_before_any_ssh_call(protocol, command):
    result = run_script(protocol, [command, "root@192.0.2.1", "not-a-sid"])

    assert result.returncode == 1
    assert "malformed or missing session id" in result.stdout
    assert remote_calls(protocol) == []


# --- item 15: backup ---


def rewrite_backup_tar(protocol, entries):
    with tarfile.open(protocol["root"] / "backup.tar.gz", "w:gz") as archive:
        for name, data, is_dir in entries:
            info = tarfile.TarInfo(name)
            if is_dir:
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            else:
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))


def test_backup_counts_only_etc_config_file_entries(protocol):
    rewrite_backup_tar(
        protocol,
        [
            ("etc/config/", None, True),
            ("etc/config/network", b"config interface 'lan'\n", False),
            ("etc/config/firewall", b"config defaults\n", False),
            ("etc/config/wifi/ssid", b"config wifi-iface\n", False),
        ],
    )

    result = run_script(protocol, ["backup", "root@192.0.2.1"])

    assert result.returncode == 0, result.stdout
    assert "(2 config files)" in result.stdout
    calls = remote_calls(protocol)
    assert calls[0].startswith(f"{PROG} hello ")
    assert calls[1] == f"{PROG} hostname"
    backups = list((protocol["root"] / "backups").glob("*.tar.gz"))
    assert len(backups) == 1
    assert backups[0].stat().st_mode & 0o777 == 0o600


def test_corrupt_backup_dies(protocol):
    (protocol["root"] / "backup.tar.gz").write_bytes(b"not-a-tarball")

    result = run_script(protocol, ["backup", "root@192.0.2.1"])

    assert result.returncode == 1
    assert "backup failed or corrupt" in result.stdout


# --- item 16: catalog failure ---


def make_catalog_tree(tmp_path, catalog):
    root = tmp_path / "catroot"
    (root / "scripts").mkdir(parents=True)
    shutil.copy(SCRIPT, root / "scripts" / "owrt-change.sh")
    if catalog is not None:
        (root / "mcp" / "newton_mcp").mkdir(parents=True)
        (root / "mcp" / "newton_mcp" / "secret_names.txt").write_text(catalog)
    return root


@pytest.mark.parametrize("catalog", [None, "bogus word\n"], ids=["missing", "malformed"])
@pytest.mark.parametrize("command", ["plan", "apply"])
def test_catalog_failure_kills_plan_and_apply_before_any_ssh(
    protocol, tmp_path, command, catalog
):
    changes = write_changes(tmp_path)
    root = make_catalog_tree(tmp_path, catalog)
    args = (
        ["plan", "root@192.0.2.1", str(changes)]
        if command == "plan"
        else ["apply", "root@192.0.2.1", SID]
    )
    env = protocol["env"].copy()
    env["OWRT_SRC_ROOT"] = str(SCRIPT.parents[1])

    result = subprocess.run(
        _wrap_args_with_unshare(
            [str(root / "scripts" / "owrt-change.sh"), *args],
            protocol,
        ),
        env=env, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, timeout=60, stdin=subprocess.DEVNULL,
    )

    assert result.returncode == 1
    if catalog is None:
        assert "secret-name catalog missing or unreadable" in result.stdout
    else:
        assert "not 'exact|suffix|contains <lowercase word>'" in result.stdout
    assert remote_calls(protocol) == []


# --- item 17: control characters in arguments must die before state / ssh ---

# Each of positional arguments 1..5 (cmd, router, changes, timeout, probes
# for `plan`; cmd, router, SID, timeout for `apply`) is checked for any C0
# or DEL byte (newline and ESC included). The script prints `ERROR: control
# character in an argument` to stderr and exits 2 before anything else
# happens (audit log, state dirs, mktemp, ssh).

_CONTROL_CHARS = [
    pytest.param("\n", id="newline"),
    pytest.param("\x1b", id="esc"),
]


def _build_argv(command, tamper_index, control_char, tmp_path):
    """Return the argv list for `command` with the chosen positional
    argument (1-indexed: cmd=1, router=2, ...) decorated with `control_char`.
    """
    if command == "plan":
        base = ["plan", "root@192.0.2.1", str(write_changes(tmp_path)), "90"]
    else:
        base = ["apply", "root@192.0.2.1", SID, "60"]
    tampered = base[tamper_index - 1] + control_char
    return base[: tamper_index - 1] + [tampered] + base[tamper_index:]


@pytest.mark.parametrize("command", ["plan", "apply"])
@pytest.mark.parametrize("tamper_index", [1, 2, 3, 4])
@pytest.mark.parametrize("control_char", _CONTROL_CHARS)
def test_control_character_in_argument_dies_before_state_or_ssh(
    protocol, tmp_path, command, tamper_index, control_char
):
    args = _build_argv(command, tamper_index, control_char, tmp_path)

    result = run_script(protocol, args, prepare_state=False)

    assert result.returncode == 2
    assert "ERROR: control character in an argument" in result.stdout
    assert not protocol["audit"].exists(), protocol["audit"].read_text()
    assert remote_calls(protocol) == []
    # the state directory must NOT have been created either (prepare_state=False
    # keeps the protocol fixture from chmod-laying tmp_path/"state" down, so the
    # only path that could create it is the script itself).
    assert not (protocol["root"] / "state").exists()


@pytest.mark.parametrize("control_char", _CONTROL_CHARS)
def test_control_character_in_probes_argument_dies_before_state_or_ssh(
    protocol, tmp_path, control_char
):
    probes = tmp_path / "probes"
    probes.write_bytes(b"uci-equals dhcp.lab.limit '50'\n")

    args = ["plan", "root@192.0.2.1", str(write_changes(tmp_path)), "90", str(probes) + control_char]

    result = run_script(protocol, args, prepare_state=False)

    assert result.returncode == 2
    assert "ERROR: control character in an argument" in result.stdout
    assert not protocol["audit"].exists()
    assert remote_calls(protocol) == []


# --- item 17b: the control-character check must not leak LC_ALL=C to ssh/tar/sort ---


def test_control_character_loop_does_not_leak_lc_all_to_ssh(protocol):
    """The control-character check at the top of scripts/owrt-change.sh used
    to set LC_ALL=C as a plain assignment, which made LC_ALL=C persist for
    the rest of the script and leak into every child process (ssh, tar,
    sort, tr ...). The fix scopes LC_ALL=C to a subshell around the
    `[[ ]]` test only, so the controller's own LC_ALL is what the child
    processes see.
    """
    result = subprocess.run(
        _wrap_args_with_unshare(
            [str(SCRIPT), "backup", "root@192.0.2.1"],
            protocol,
        ),
        env={**protocol["env"], "LC_ALL": "en_US.UTF-8"},
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20,
    )
    assert result.returncode == 0, result.stdout
    records = (protocol["root"] / "lc_all.log").read_text().splitlines()
    assert records, "stub ssh was never called; the backup did not run"
    # the bug made every ssh call see LC_ALL=C; after the fix the value the
    # script inherits from its environment reaches the child unchanged
    for value in records:
        assert value != "C", f"LC_ALL leaked to ssh (saw {value!r})"
        assert value == "en_US.UTF-8", f"unexpected LC_ALL value: {value!r}"


# --- item 18: hostile `status` reply with a newline ---


def test_status_word_with_newline_takes_only_the_first_line(protocol, tmp_path):
    """A hostile `status` reply (the program is fed by ssh) that includes
    a newline must read as the first word only — the rest of the line is
    an attacker-controlled comment that must not influence the script.
    """
    set_router_state(protocol, status="rolled-back\n sid=x guard=idle")
    fail_verify_rounds(protocol)

    result = protocol["run"]()

    assert result.returncode == 1
    # After the fix `st_full=rolled-back` (the first line only); the script
    # takes the rolled-back|gone|applied-pending-confirm branch instead of
    # the unexpected-status ALERT. Without the fix the hostile `sid=x guard=
    # idle` text also reached the audit log through `oneline` of $st_full.
    lines = result.stdout.splitlines()
    final = lines[-1]
    assert final.startswith(f"ROLLBACK WINDOW PASSED session={SID}"), final
    # the `sid=x` text was on the second line of the status reply and must
    # NOT have leaked anywhere — neither stdout nor the audit log
    assert "sid=x" not in result.stdout
    assert "sid=x" not in protocol["audit"].read_text()
    assert "guard=idle" not in protocol["audit"].read_text()


# --- SW2 item 4: the fixed ssh path, and the state-dir parent rule ---------


def test_ssh_is_never_resolved_through_path(protocol):
    """A fake ssh FIRST ON PATH is never executed.

    scripts/owrt-change.sh resolves ssh the way mcp/newton_mcp/ssh_path.py
    does: the first of /usr/bin/ssh, /bin/ssh that is a regular executable
    file.  There is no PATH lookup and no env seam for the binary, so the
    fixture's stub is reached only because it is bind-mounted at /usr/bin/ssh
    by the runner wrapper, and the PATH-first fake below is never executed.
    """
    marker = protocol["root"] / "path-ssh-was-used"
    path_bin = protocol["root"] / "pathbin"
    path_bin.mkdir(parents=True, exist_ok=True)
    fake = path_bin / "ssh"
    fake.write_text(f"#!/bin/sh\n: > {marker}\nexit 0\n")
    fake.chmod(0o755)

    result = protocol["run"](
        extra_env={"PATH": str(path_bin) + os.pathsep + protocol["env"]["PATH"]}
    )

    # the stub bound at /usr/bin/ssh ran (so ssh really was called), and the
    # PATH-first fake never did
    assert remote_calls(protocol), result.stdout
    assert not marker.exists()
    assert remote_calls(protocol)


def test_missing_ssh_at_both_fixed_paths_dies_before_anything(tmp_path):
    """With neither /usr/bin/ssh nor /bin/ssh a regular executable file the
    script dies with the refusal, before it creates a state dir or an audit
    line.  Both paths are masked inside a private mount namespace (with
    /dev/null, which is a regular file but not executable) so nothing on the
    host changes; /bin is a symlink to usr/bin on a merged-/usr system, and
    masking both paths covers either layout."""
    result = subprocess.run(
        ["unshare", "-Urm", "--", "bash", "-c",
         'mount --bind /dev/null /usr/bin/ssh && mount --bind /dev/null /bin/ssh && exec "$@"',
         "noop", str(SCRIPT), "status", "root@192.0.2.1", "0" * 32],
        env={**os.environ, "HOME": str(tmp_path), "PATH": os.environ["PATH"],
             "XDG_STATE_HOME": str(tmp_path / "state")},
        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
        stdin=subprocess.DEVNULL,
    )
    assert result.returncode != 0, result.stdout
    assert "no ssh at /usr/bin/ssh or /bin/ssh" in result.stdout
    # the refusal sits above the state-dir creation, so nothing was laid down
    assert not (tmp_path / "state" / "network-agent").exists()


@pytest.mark.parametrize("hostile", ["state", "backups", "audit"])
def test_state_dir_under_group_writable_parent_is_refused(protocol, hostile):
    """A state dir whose PARENT is 0777 (no sticky bit) is refused before
    the script creates anything under it.

    The three cases cover every movable directory: XDG_STATE_HOME (which
    OWRT_BACKUP_DIR and OWRT_AUDIT_LOG default under), an explicitly set
    OWRT_BACKUP_DIR elsewhere, and an explicitly set OWRT_AUDIT_LOG elsewhere.
    """
    root = protocol["root"]
    parent = root / ("hostile-" + hostile)
    parent.mkdir(parents=True, exist_ok=True)
    os.chmod(parent, 0o777)
    extra = {
        "state": {"XDG_STATE_HOME": str(parent)},
        "backups": {"OWRT_BACKUP_DIR": str(parent / "backups")},
        "audit": {"OWRT_AUDIT_LOG": str(parent / "audit.log")},
    }[hostile]

    result = run_script(
        protocol, ["status", "root@192.0.2.1", SID],
        extra_env=extra, prepare_state=False,
    )

    assert result.returncode != 0, result.stdout
    assert "group- or world-writable without the sticky bit" in result.stdout
    # nothing was created under the hostile parent, and no ssh call happened
    assert list(parent.iterdir()) == []
    assert remote_calls(protocol) == []


def test_state_dir_under_sticky_parent_is_accepted(protocol):
    """The same parent with the sticky bit (the /tmp shape) is accepted."""
    root = protocol["root"]
    parent = root / "sticky"
    parent.mkdir(parents=True, exist_ok=True)
    os.chmod(parent, 0o1777)

    result = run_script(
        protocol, ["status", "root@192.0.2.1", SID],
        extra_env={"XDG_STATE_HOME": str(parent)},
    )

    assert result.returncode == 0, result.stdout
    assert (parent / "network-agent").is_dir()


# --- SW2 review: $STATE must still be healed, not refused -------------------


def test_legacy_group_writable_state_dir_is_healed_not_refused(protocol):
    """A $STATE created 0775 by an older version, owned by us, under a
    0755 parent: the run proceeds and the script's own
    ``chmod 700 "$STATE" "$BACKUPS" "$PLANS"`` tightens it to 0700.

    The parent checks for BACKUPS and PLANS sit ABOVE that chmod, so
    without the "$STATE is a real directory we own" skip a legacy 0775
    $STATE would be refused on the default layout (BACKUPS and PLANS
    directly under it) and the heal could never run.
    """
    root = protocol["root"]
    home = root / "legacy-home"
    state = home / "network-agent"
    state.mkdir(parents=True)
    os.chmod(home, 0o755)
    os.chmod(state, 0o775)

    result = run_script(
        protocol, ["status", "root@192.0.2.1", SID],
        extra_env={"XDG_STATE_HOME": str(home)},
    )

    assert result.returncode == 0, result.stdout
    assert "group- or world-writable without the sticky bit" not in result.stdout
    assert "0o%o" % (os.stat(state).st_mode & 0o777) == "0o700"
    assert (state / "plans").is_dir()
    assert remote_calls(protocol)


def test_symlinked_state_dir_to_group_writable_dir_is_refused(protocol):
    """The skip covers a REAL directory we own, never a symlink: a $STATE
    that is a symlink to a 0775 directory is still refused, so a hostile
    user cannot aim the heal at a directory we do not own."""
    root = protocol["root"]
    home = root / "link-home"
    target = root / "link-target"
    home.mkdir()
    target.mkdir()
    os.chmod(home, 0o700)
    os.chmod(target, 0o775)
    (home / "network-agent").symlink_to(target)

    result = run_script(
        protocol, ["status", "root@192.0.2.1", SID],
        extra_env={"XDG_STATE_HOME": str(home)},
    )

    assert result.returncode != 0, result.stdout
    assert "group- or world-writable without the sticky bit" in result.stdout
    # the refusal names $STATE (the symlink), which is the parent of PLANS
    assert str(home / "network-agent") in result.stdout
    assert list(target.iterdir()) == []
    assert remote_calls(protocol) == []


def test_symlinked_state_dir_to_world_writable_dir_is_refused(protocol):
    """The PLANS parent check is load-bearing even when it cannot be
    relocated: delete ``check_state_dir_parent_sticky "$PLANS" 'PLANS'``
    from the script and this test goes red.

    PLANS is always $STATE/plans, so the only parent it can have is
    $STATE itself.  The skip does not fire for a symlink, so pointing
    $STATE at a 0777 directory (the shape a not-owned $STATE would have
    -- a not-owned directory cannot be made as a non-root user) is the
    only way to reach that line with a bad parent.
    """
    root = protocol["root"]
    home = root / "world-link-home"
    target = root / "world-link-target"
    home.mkdir()
    target.mkdir()
    os.chmod(home, 0o700)
    os.chmod(target, 0o777)
    (home / "network-agent").symlink_to(target)

    result = run_script(
        protocol, ["status", "root@192.0.2.1", SID],
        extra_env={"XDG_STATE_HOME": str(home)},
    )

    assert result.returncode != 0, result.stdout
    assert "group- or world-writable without the sticky bit" in result.stdout
    assert str(home / "network-agent") in result.stdout
    assert list(target.iterdir()) == []
    assert remote_calls(protocol) == []


# ---------------------------------------------------------------------------
# CH-01..CH-05: the config hashes of a confirmed apply
# ---------------------------------------------------------------------------

# the hashes the fake router reports for the committed config
CONFIGHASH_BEFORE = (
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb dhcp\n"
    "cccccccccccccccccccccccccccccccc firewall\n"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa network"
)


def config_hash_lines(result):
    """The CONFIGHASH lines of a run's stdout, in the order they were printed."""
    return [
        line for line in result.stdout.splitlines() if line.startswith("CONFIGHASH ")
    ]


def test_confirmed_apply_prints_the_config_hashes_before_the_confirmed_line(protocol):
    """CH-01: a confirmed apply prints the config hashes, CONFIRMED stays last.

    The hashes are read from the router once, after it confirmed, and they
    are printed on stdout right before the CONFIRMED line.
    """
    set_router_state(protocol, confighash=[CONFIGHASH_BEFORE, CONFIGHASH_BEFORE])

    result = protocol["run"]()

    assert result.returncode == 0, result.stdout
    lines = result.stdout.splitlines()
    assert lines[-1].startswith(f"CONFIRMED session={SID}")
    assert lines[-4:-1] == [
        "CONFIGHASH bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb dhcp",
        "CONFIGHASH cccccccccccccccccccccccccccccccc firewall",
        "CONFIGHASH aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa network",
    ]
    assert config_hash_lines(result) == lines[-4:-1]
    # the router is asked for the hashes once before the apply and once after
    # the confirmation, never in between
    calls = remote_calls(protocol)
    hashes = [i for i, call in enumerate(calls) if call == f"{PROG} confighash"]
    confirms = [i for i, call in enumerate(calls) if call == f"{PROG} confirm {SID}"]
    assert len(hashes) == 2
    assert len(confirms) == 1
    assert hashes[0] < confirms[0] < hashes[1]

    # at most 200 hashes are printed, and they are still the last lines
    # before the CONFIRMED one
    many = "".join(f"{index:032x} pkg{index}\n" for index in range(250))
    set_router_state(protocol, confighash=[CONFIGHASH_BEFORE, many])

    result = protocol["run"]()

    assert result.returncode == 0, result.stdout
    lines = result.stdout.splitlines()
    assert lines[-1].startswith(f"CONFIRMED session={SID}")
    printed = config_hash_lines(result)
    assert len(printed) == 200
    assert printed[0] == f"CONFIGHASH {0:032x} pkg0"
    assert printed[-1] == f"CONFIGHASH {199:032x} pkg199"
    assert lines[-201:-1] == printed


def test_the_config_hashes_never_reach_the_audit_log(protocol):
    """CH-02: the hashes go to stdout only; the audit file never sees them."""
    set_router_state(protocol, confighash=[CONFIGHASH_BEFORE, CONFIGHASH_BEFORE])

    result = protocol["run"]()

    assert result.returncode == 0, result.stdout
    assert "CONFIGHASH" in result.stdout
    assert "CONFIGHASH" not in protocol["audit"].read_text()


def test_a_failing_confighash_after_the_confirm_changes_nothing(protocol):
    """CH-03: a confighash problem never changes the apply outcome.

    The router refuses the second confighash (the one after the
    confirmation): the run still confirms, still exits 0 and prints no hash.
    """
    set_router_state(
        protocol,
        confighash=[CONFIGHASH_BEFORE, "fail:ERROR: confighash could not read the config"],
    )

    result = protocol["run"]()

    assert result.returncode == 0, result.stdout
    lines = result.stdout.splitlines()
    assert lines[-1].startswith(f"CONFIRMED session={SID}")
    assert config_hash_lines(result) == []


def test_a_malformed_confighash_output_prints_no_config_hashes(protocol):
    """CH-04: an answer that is not a list of hashes is dropped whole.

    A name that is not a plain package name (a space, a control character)
    is dropped line by line: the rest of the answer is still printed.
    """
    set_router_state(
        protocol,
        confighash=[
            CONFIGHASH_BEFORE,
            "not-a-hash dhcp\nZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ network",
        ],
    )

    result = protocol["run"]()

    assert result.returncode == 0, result.stdout
    assert config_hash_lines(result) == []
    assert result.stdout.splitlines()[-1].startswith(f"CONFIRMED session={SID}")

    set_router_state(
        protocol,
        confighash=[
            CONFIGHASH_BEFORE,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb guest wifi\n"
            "cccccccccccccccccccccccccccccccc firewall",
        ],
    )

    result = protocol["run"]()

    assert result.returncode == 0, result.stdout
    assert config_hash_lines(result) == [
        "CONFIGHASH cccccccccccccccccccccccccccccccc firewall"
    ]
    assert result.stdout.splitlines()[-1].startswith(f"CONFIRMED session={SID}")


def test_a_rolled_back_apply_prints_no_config_hashes(protocol):
    """CH-05: only a confirmed apply prints the config hashes."""
    fail_verify_rounds(protocol)

    result = protocol["run"]()

    assert result.returncode == 1, result.stdout
    assert "ROLLBACK WINDOW PASSED" in result.stdout
    assert config_hash_lines(result) == []
    assert f"CONFIRMED session={SID}" not in result.stdout
