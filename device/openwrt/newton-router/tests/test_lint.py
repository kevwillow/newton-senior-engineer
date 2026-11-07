"""Design 9.2 group 1: lint, forbidden constructs, tool allowlist, M19."""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from conftest import BUSYBOX, GUARD, HELPER, PROGRAM, REPO, TRACE_CALLS

import leash_model

TOOLS = REPO / "device/openwrt/newton-router/router-tools.txt"
PROGRAM_TEXT = PROGRAM.read_text()

FORBIDDEN_CALLS = (
    "timeout", "stat", "ss", "dig", "base64", "od",
    "bash", "xargs", "paste", "seq", "expr",
)
# simple-command segments for the dot / sh -c checks
SEG_SPLIT = re.compile(r"\n|;|\|\||&&|\||&")
# the finer splitter for forbidden CALLS: also breaks on (, ), $(), backticks
# and the keywords that end a command position
CMD_SPLIT = re.compile(
    r"\n|;|\|\||&&|\||&|\(|\)|\$\(|`"
    r"|\b(?:then|do|else|elif|if|while|until|for|case|esac|in)\b"
    r"|(?<![A-Za-z0-9_$!])!(?=[A-Za-z_(])"
)
ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

ASH_BUILTINS = set(
    "[ : break continue exit export local printf read return set shift "
    "test trap true false unset wait cd umask kill echo type exec".split()
)


def forbidden_findings(text):
    """Forbidden constructs in shell text; comment lines stay in (arch.md)."""
    finds = []
    if "eval" in text:
        finds.append("eval")
    if "`" in text:
        finds.append("backtick")
    if re.search(r"\bsource\b", text):
        finds.append("source")
    for seg in SEG_SPLIT.split(text):
        toks = seg.split()
        words = [
            t for t in toks
            if not ASSIGN_RE.match(t) and t not in ("'", '"')
        ]
        if words and words[0] == ".":
            finds.append("dot-command: " + seg.strip())
        for a, b in zip(toks, toks[1:]):
            if a == "sh" and b == "-c":
                finds.append("sh -c: " + seg.strip())
                break
    # a forbidden CALL only in COMMAND position: the first word of the
    # simple command (path stripped), after leading VAR=value assignments
    for seg in CMD_SPLIT.split(text):
        words = [
            t for t in seg.split()
            if not ASSIGN_RE.match(t) and t not in ("'", '"')
        ]
        if words:
            first = words[0].rsplit("/", 1)[-1]
            if first in FORBIDDEN_CALLS:
                finds.append("forbidden call: " + seg.strip())
    return finds


def function_bodies(text):
    """name -> body text, for `name() {` ... `}` at column 0."""
    bodies = {}
    name = None
    for line in text.splitlines():
        if name is None:
            m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\(\)", line)
            if m:
                name = m.group(1)
                bodies[name] = []
            continue
        if line == "}":
            name = None
        else:
            bodies[name].append(line)
    return {k: "\n".join(v) for k, v in bodies.items()}


def tools_names():
    names = []
    for line in TOOLS.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            names.append(line)
    return names


# ---- syntax and shellcheck --------------------------------------------------


def test_busybox_sh_n():
    res = subprocess.run(
        [BUSYBOX, "sh", "-n", str(PROGRAM)], capture_output=True, text=True
    )
    assert res.returncode == 0, res.stderr


def test_shellcheck_clean():
    exe = shutil.which("shellcheck") or os.environ.get("NEWTON_SHELLCHECK")
    if not exe or not Path(exe).exists():
        pytest.skip("shellcheck not installed (set NEWTON_SHELLCHECK to its path)")
    res = subprocess.run(
        [exe, "-s", "sh", str(PROGRAM)], capture_output=True, text=True
    )
    assert res.returncode == 0, res.stdout + res.stderr


# ---- the detector itself is tested, so it cannot match nothing --------------


@pytest.mark.parametrize(
    "snippet",
    [
        'eval "$REQ"',
        "x=`touch /tmp/a`",
        "source /etc/rc.local",
        ". /etc/profile",
        'sh -c "ping h"',
        "/usr/bin/busybox sh -c id",
        "timeout 5 ping h",
        "stat /etc/config/network",
        "x=$(stat f)",
        "ss -lntu",
        "seq 1 5",
        "expr 1 + 2",
        "base64 f | od -c",
        "sort f | xargs rm",
        "paste a b",
        "dig example.com",
        "bash -x script",
    ],
    ids=[
        "eval", "backtick", "source", "dot", "sh-c", "busybox-sh-c",
        "timeout", "stat", "stat-subst", "ss", "seq", "expr",
        "base64-od", "xargs", "paste", "dig", "bash",
    ],
)
def test_detector_flags_forbidden(snippet):
    assert forbidden_findings(snippet) != []


@pytest.mark.parametrize(
    "snippet",
    [
        'status=$(newton-guard status) || fail guard "$status"',
        'detail=$(printf "%s" "$d" | tr -d "\\000" | cut -c 1-120)',
        'case $1 in hello) cmd_hello "$@" ;; esac',
        "REQ_TOKENS=$joined\nunset IFS",
        'while ! "$PIDOF" logd && [ "$i" -lt 5 ]; do sleep 1; done',
        'fail lock-timeout 1  # a hyphenated code is not a call',
        "# refresh the state before the next round",
        "PB_REASON=timeout",
        "local x expr",
        'expr="@1]"',
        '-e "$expr"',
        "fail read-timeout 124",
    ],
    ids=[
        "status-word", "pipeline", "case", "assignment", "logd-loop",
        "hyphenated-code", "comment", "reason-word", "local-var", "quoted-var",
        "test-flag-var", "read-timeout-code",
    ],
)
def test_detector_passes_clean(snippet):
    assert forbidden_findings(snippet) == []


def test_program_has_no_forbidden_constructs():
    assert forbidden_findings(PROGRAM_TEXT) == []


# ---- static pins (design 2.7, 3.1 step 3) -----------------------------------


def test_ssh_original_command_read_in_exactly_one_function():
    bodies = function_bodies(PROGRAM_TEXT)
    assert bodies, "no functions found in the program"
    readers = [n for n, b in bodies.items() if "SSH_ORIGINAL_COMMAND" in b]
    assert readers == ["read_request"]


def test_program_never_calls_helper_status_apply_confirm_abort():
    pat = re.compile(
        r"\$\{?HELPER\}?\s+(status|apply|confirm|abort)\b"
        r"|newton-safe-apply\s+(status|apply|confirm|abort)\b"
    )
    assert not pat.search(PROGRAM_TEXT)


def test_unset_list_covers_every_newton_name():
    m = re.search(r"^\s*unset (NEWTON_\S+.*)$", PROGRAM_TEXT, re.M)
    assert m, "the production unset list was not found"
    unset_names = set(re.findall(r"NEWTON_[A-Z_]+", m.group(1)))
    used = set()
    for path in (PROGRAM, HELPER, GUARD):
        used |= set(re.findall(r"NEWTON_[A-Z_]+", path.read_text()))
    assert used <= unset_names, sorted(used - unset_names)


def test_router_tools_file_shape():
    first = TOOLS.read_text().splitlines()[0]
    assert "sh" not in first  # the G0 gate script must not read it as a shell script
    assert TOOLS.is_file()
    assert tools_names(), "the allowlist is empty"


def test_router_tools_file_has_no_forbidden_names():
    bad = set(tools_names()) & set(FORBIDDEN_CALLS)
    assert not bad, sorted(bad)


# ---- known-package list cross-check ----------------------------
# The router program and the host policy each carry their own copy of the
# known-package list. If the two drift, the host policy and the router seal
# will disagree about whether a change to the drifted package fires
# unknown-package. The router list is the AWK `knownpkg` function in
# newton-router; the host list is mcp/newton_mcp/policy.KNOWN_PACKAGES, and
# leash_model.KNOWN is the corpus's local mirror of the same set so the model
# and the program stay in agreement. All three MUST carry the same set.

def _parse_knownpkg_awk(text):
    """Extract the package names from the AWK `knownpkg(c) { ... }` body.

    The function lives inside the router's AWK script (not as a top-level
    shell function), so a structural extraction is needed: match the function
    header and read the body up to the next line whose first non-whitespace
    character is ``}``.
    """
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"^\s*function\s+knownpkg\s*\(\s*c\s*\)\s*\{?\s*$", line)
        if m is None:
            continue
        body = []
        for j in range(i + 1, len(lines)):
            stripped = lines[j].lstrip()
            if stripped.startswith("}"):
                break
            body.append(lines[j])
        full = "\n".join(body)
        names = set(re.findall(r'c\s*==\s*"([A-Za-z0-9_-]+)"', full))
        if not names:
            pytest.fail("knownpkg() body parsed but no package names found")
        return names
    pytest.fail("newton-router has no knownpkg() function")


def _load_policy_known_packages():
    """KNOWN_PACKAGES from mcp/newton_mcp/policy.py, without importing the package."""
    path = REPO / "mcp" / "newton_mcp" / "policy.py"
    src = path.read_text()
    m = re.search(r"^KNOWN_PACKAGES\s*=\s*\(([^)]*)\)", src, re.M)
    if m is None:
        pytest.fail(f"could not locate KNOWN_PACKAGES in {path}")
    return set(re.findall(r'"([A-Za-z0-9_-]+)"', m.group(1)))


def test_known_package_list_agrees_across_router_and_host():
    router_set = _parse_knownpkg_awk(PROGRAM_TEXT)
    model_set = set(leash_model.KNOWN)  # type: ignore[attr-defined]
    policy_set = _load_policy_known_packages()
    assert model_set == policy_set, (
        f"leash_model.KNOWN != policy.KNOWN_PACKAGES "
        f"(only in model: {sorted(model_set - policy_set)}, "
        f"only in policy: {sorted(policy_set - model_set)})"
    )
    assert router_set == policy_set, (
        f"newton-router knownpkg != policy.KNOWN_PACKAGES "
        f"(only in router: {sorted(router_set - policy_set)}, "
        f"only in policy: {sorted(policy_set - router_set)})"
    )


def test_newton_wanhealth_is_a_known_package():
    """The WAN-health package is installed by newton-router-setup; a change
    to it must not fire the unknown-package leash code on either side."""
    router_set = _parse_knownpkg_awk(PROGRAM_TEXT)
    assert "newton_wanhealth" in router_set, (
        "newton-router's knownpkg() does not list newton_wanhealth"
    )
    policy_set = _load_policy_known_packages()
    assert "newton_wanhealth" in policy_set, (
        "policy.KNOWN_PACKAGES does not list newton_wanhealth"
    )


# ---- tool-allowlist trace (design 9.2 group 1) ------------------------------


def trace_word(tok):
    """The command word of a traced token, or None (assignment/fragment)."""
    if ASSIGN_RE.match(tok):
        return None
    if "'" in tok or '"' in tok:
        # only a cleanly quoted word (e.g. `'['`) names a command
        if len(tok) >= 2 and tok[0] in "'\"" and tok[-1] == tok[0]:
            inner = tok[1:-1]
            if "'" not in inner and '"' not in inner:
                return inner
        return None
    return tok


def trace_scan(res, router, allowed):
    """(command words seen, [(word, line)] not allowed) of one traced run."""
    seen_words, offenders = [], []
    for line in res.err.splitlines():
        if not line.startswith("+"):
            continue
        body = line.lstrip("+ \t").strip()
        if not body:
            continue
        word = None
        for tok in body.split():
            word = trace_word(tok)
            if word is not None:
                break
        if word is None:
            continue
        word = word.strip("'\"")
        if word.startswith(str(router.root) + "/"):
            word = word.rsplit("/", 1)[1]
        seen_words.append(word)
        if word not in allowed:
            offenders.append((word, line))
    return seen_words, offenders


def test_traced_command_words_are_allowed(router):
    tools = set(tools_names())
    funcs = set(function_bodies(PROGRAM_TEXT))
    allowed = ASH_BUILTINS | tools | funcs
    assert allowed > ASH_BUILTINS  # the lists were actually loaded
    for mode, argv, role in TRACE_CALLS:
        # The processes of one pipeline write their trace lines to the same stderr, so
        # under heavy load two lines can be spliced together (seen: "printfcut"). A real
        # violation shows on every run, a splice does not: try up to three times.
        for _ in range(3):
            if mode == "direct":
                res = router.direct(*argv, xtrace=True, timeout=20)
            else:
                res = router.forced(argv, role=role, xtrace=True, timeout=20)
            assert res.err, (mode, argv)
            seen_words, offenders = trace_scan(res, router, allowed)
            if not offenders:
                break
        assert not offenders, (mode, argv, offenders)
        assert seen_words, (mode, argv)


# ---- seams ignored at the install path (design 3.1 step 2) -------------


def test_prod_mode_at_install_path_ignores_seams(tmp_path):
    probe = subprocess.run(
        ["unshare", "-rm", "true"], capture_output=True, text=True
    )
    if probe.returncode != 0:
        pytest.skip("no user namespaces")
    mnt = tmp_path / "mnt"
    mnt.mkdir()
    script = f"""
set -e
mount -t tmpfs tmpfs {mnt}
cd {mnt}
mkdir -p usr/libexec/newton bin dev proc/sys/kernel/random tmp/rootfake
cp {PROGRAM} usr/libexec/newton/newton-router
cp /usr/bin/busybox bin/busybox
chmod 755 bin/busybox usr/libexec/newton/newton-router
printf '100.00 90.00\\n' > proc/uptime
touch dev/null
mount --bind /dev/null dev/null || true
NEWTON_ROUTER_ROOT=/tmp/rootfake NEWTON_LOCK=/tmp/evil.lock \\
NEWTON_CONFIG_DIR=/tmp/evil NEWTON_FIREWALL_INIT=/tmp/evil \\
NEWTON_GUARD_ROOT=/tmp/rootfake \\
  /usr/bin/busybox chroot {mnt} /bin/busybox sh \\
  /usr/libexec/newton/newton-router hello 0123456789abcdef \\
  || echo "hello rc=$?"
test -e {mnt}/tmp/rootfake/tmp/newton && echo FAKE_TOUCHED || echo FAKE_CLEAN
"""
    res = subprocess.run(
        ["unshare", "-rm", "/bin/sh", "-c", script],
        capture_output=True, text=True, timeout=60,
    )
    assert res.returncode == 0, res.stderr
    assert "FAKE_CLEAN" in res.stdout
    assert "FAKE_TOUCHED" not in res.stdout
    line = [l for l in res.stdout.splitlines() if l.startswith("hello ")]
    assert line, res.stdout + res.stderr
    assert re.search(r" mode=prod ", line[0]) or line[0].endswith(" mode=prod")
