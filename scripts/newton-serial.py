# /// script
# requires-python = ">=3.11"
# dependencies = ["pyserial>=3.5"]
# ///
"""A one-shot, safety-gated serial-console driver for Newton.

The command rules are a guard rail, not a sandbox: a short deny list of
known-destructive commands (refused always) and risky ones (need
--approved). A command the lists do not name is sent as typed; read every
command before it runs."""

from __future__ import annotations

import argparse
import datetime as dt
import errno
import fnmatch
import hashlib
import os
import posixpath
import re
import shlex
import stat
import sys
import time
import unicodedata
from pathlib import Path

import serial
from serial.tools import list_ports

try:
    import termios
    _LINE_ERRORS: tuple[type[BaseException], ...] = (OSError, termios.error)
except ImportError:                              # not a POSIX host
    _LINE_ERRORS = (OSError,)


DEFAULT_PROMPT = r"[#$>]\s*$"
HARD_RULES = (
    # mtd with erase or write anywhere after it: options may come first (mtd -r erase rootfs_data)
    r"firstboot", r"jffs2reset", r"(?s)\bmtd\b.*\b(write|erase)\b",
    r"dd\s+.*of=/dev/(mtd|ubi|mmcblk|sd)", r"ubiformat", r"ubirmvol",
    r"fw_setenv", r"sysupgrade\s+(-n|.*--force|-F)",
    r"rm\s+-[a-z]*r[a-z]*\s+/(overlay|rom)", r"nft\s+flush\s+ruleset",
    r"iptables\s+-F", r"write\s+erase", r"erase\s+startup-config",
    r"request\s+system\s+zeroize", r"/system\s+reset-configuration",
    r"format\s+flash:",
)
SOFT_RULES = (
    (r"reboot", "reboot"), (r"reload", "reload"), (r"sysupgrade", "firmware upgrade"),
    (r"apk\s+(upgrade|del)", "package change"), (r"passwd", "password change"),
    (r"uci\s+commit", "persistent configuration change"),
    (r"(?:/etc/init\.d/|\bservice\s+)(network|firewall|dropbear)\s+(restart|stop|disable)",
     "network/service interruption"),
    (r"\b(poweroff|halt|shutdown)\b", "power off"),
    (r"(?s)\bopkg\b.*\b(remove|upgrade)\b", "package change"),
    # any command that names dropbear and a verb that removes, stops or disables it, whatever wraps it
    (r"(?s)^(?=.*\bdropbear\b).*\b(disable|stop|restart|remove|del|kill|killall|pkill|rm|mv)\b",
     "SSH access change"),
    (r"(?s)\bifconfig\b.*\bdown\b", "link interruption"),
    (r"wifi(\s+(up|down|reload))?\s*$", "wireless interruption"),
    (r"ifdown", "network interruption"),
    (r"ip\s+link\s+set\s+\S+\s+down", "link interruption"),
    (r"configure\s+terminal", "configuration mode"), (r"conf\s+t", "configuration mode"),
    (r"commit(\s|$)", "persistent configuration change"),
    (r"copy\s+running-config\s+startup-config", "persistent configuration change"),
    (r"write\s+memory", "persistent configuration change"),
)
# files a wrong push turns into a lockout: push needs --i-know for them
LOGIN_FILES = frozenset({"/etc/dropbear/authorized_keys", "/etc/shadow", "/etc/passwd"})
ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\)|[@-_])")


def clean(text: str) -> str:
    return ANSI.sub("", text).replace("\r\n", "\n").replace("\r", "\n")


def _escape_console_text(text: str) -> str:
    """Escape control / bidi / zero-width characters in console text.

    Keeps "\\n" and "\\t"; every other C0 control (\\x00-\\x1f), DEL \\x7f,
    C1 controls (\\x80-\\x9f, including U+0085), U+2028, U+2029, and every
    Unicode Cf (Format) character -- U+00AD, U+061C, U+200B-U+200F,
    U+202A-U+202E, U+2060-U+2064, U+2066-U+2069, U+FEFF -- become a visible
    \\xNN or \\uXXXX escape. clean() has already removed ANSI; this only
    escapes what is left. The Cf set is taken from unicodedata.category so
    future additions (U+2061-U+2063, U+180E, U+06DD, etc.) are caught by
    the same rule.
    """
    out = []
    for ch in text:
        cp = ord(ch)
        if cp == 0x0A or cp == 0x09:        # \n, \t — keep
            out.append(ch)
            continue
        if cp < 0x20 or cp == 0x7F:        # other C0 + DEL
            out.append(f"\\x{cp:02x}")
            continue
        if 0x80 <= cp <= 0x9F:            # C1 incl. U+0085 (NEL)
            out.append(f"\\x{cp:02x}")
            continue
        if ch in ("\u2028", "\u2029"):
            out.append(f"\\u{cp:04x}")
            continue
        if unicodedata.category(ch) == "Cf":
            out.append(f"\\u{cp:04x}")
            continue
        out.append(ch)
    return "".join(out)


def classify(text: str, prompt: re.Pattern[str]) -> str:
    value = clean(text)
    if ("U-Boot" in value or "Hit any key to stop autoboot" in value or
            re.search(r"(?:^|\n)(?:=>\s*|Marvell>>\s*|CFE>\s*|rommon\s+\d+\s*>\s*|loader>\s*)$", value, re.I)):
        return "bootloader"
    if "--More--" in value or "-- More --" in value:
        return "pager"
    if re.search(r"(?:^|\n).*login:\s*$", value, re.I):
        return "login"
    if re.search(r"[Pp]assword:\s*$", value):
        return "password"
    if prompt.search(value):
        return "shell"
    return "unknown"


# A recursive rm of / or of one of these directories erases the router's
# system or its configuration, with no rollback over a console.
SYSTEM_DIRS = frozenset({
    "/", "/bin", "/boot", "/etc", "/lib", "/lib64", "/overlay", "/rom", "/root",
    "/sbin", "/usr", "/var", "/www",
    "/etc/config", "/etc/dropbear", "/root/.ssh", "/usr/lib", "/lib/modules",
})
# Anything below these is the router's writable layer or its firmware image:
# a recursive rm of any path under them is a factory reset.
RESET_DIRS = ("/overlay", "/rom")
# an escaped \( or \) is find's grouping, not a subshell, so it does not split
_SEGMENT_SPLIT = re.compile(r"&&|\|\||[;&|\n`]|\$\(|(?<!\\)[()]")


def _system_target(word: str) -> bool:
    if not word.startswith("/"):
        return False
    path = word
    while path.endswith("/*") or path.endswith("/.") or (path.endswith("/") and path != "/"):
        path = path[:-2] if path.endswith(("/*", "/.")) else path[:-1]
    path = posixpath.normpath(path or "/")
    if path.startswith("//"):
        path = "/" + path.lstrip("/")
    if path in SYSTEM_DIRS or path == "/*":
        return True
    top = "/" + path.lstrip("/").split("/", 1)[0]
    if any(fnmatch.fnmatchcase(d, top) for d in RESET_DIRS):
        return True
    # a glob the router's shell expands to a system directory (/etc*, /e??)
    return any(c in path for c in "*?[") and any(
        fnmatch.fnmatchcase(d, path) for d in SYSTEM_DIRS)


def _unknowable_target(word: str, after_cd: bool) -> bool:
    """A target whose real path the router's shell decides: ~ and $
    expansions, and a relative path once the command has changed directory.
    The guard cannot tell what they name, so it fails closed."""
    if "~" in word or "$" in word:
        return True
    # . and .. name the shell's own directory (a console login sits in /root)
    rel = posixpath.normpath(word)
    if rel in (".", "..") or rel.startswith("../"):
        return True
    return after_cd and not word.startswith("/")


def _inner_commands(words: list[str]) -> list[str]:
    """The command lines the words may hand to a shell: every word with a
    space in it (a -c string, an eval or a here-string, text piped into sh,
    with a written \\n as a line break), an option's attached =value, and
    env's attached -S string."""
    found: list[str] = []
    for index, word in enumerate(words):
        if " " in word or "\t" in word:
            found.append(word.replace("\\n", "\n"))
        if word.startswith("--") and "=" in word:
            found.append(word.partition("=")[2])
        elif (index and posixpath.basename(words[index - 1]) == "env" and word.startswith("-")
              and not word.startswith("--") and "S" in word):
            found.append(word.split("S", 1)[1])
        elif word.startswith("-") and not word.startswith("--") and "c" in word[1:]:
            # a shell's -c string attached to the option: sh -c'rm -rf /etc'
            found.append(word[1:].split("c", 1)[1])
    return found


def _find_deletes_from_a_system_dir(args: list[str], after_cd: bool) -> bool:
    """A find that deletes (-delete, or an -exec that runs rm, even behind a
    wrapper) from /, a top-level system directory or a start the shell
    decides (none given is .)."""
    while args and args[0] in ("-H", "-L", "-P"):
        args = args[1:]
    starts: list[str] = []
    while args and not args[0].startswith("-") and args[0] not in ("(", "!", "\\("):
        starts.append(args.pop(0))
    execs = [i for i, a in enumerate(args) if a in ("-exec", "-execdir", "-ok", "-okdir")]
    deletes = "-delete" in args or bool(execs) and any(
        posixpath.basename(a) == "rm" for a in args[execs[0]:])
    return deletes and any(
        _system_target(s) or _unknowable_target(s, after_cd) for s in starts or ["."])


def recursive_rm_of_system_dir(command: str) -> bool:
    """True when any part of the command is an rm with a recursive flag and a
    target that is / or a top-level system directory, or a target the shell
    expands (~, $, a command substitution, xargs), . or .., or a relative one
    after a cd in the same command.  The rm may be any word of the part, so a
    wrapper (timeout, nice, env, sudo, setsid, even echo: fail closed) does
    not hide it, nor may a variable command name ($R); every quoted
    command line (sh -c, su -c, eval, a here-string, text piped into sh) is
    checked the same way, and so is a find that deletes from such a start.
    Unparsable quoting counts as a match (fail closed).  A command name
    built by a command substitution ($(echo rm)) is not seen.
    A cd on an earlier line or run is not seen: a guard rail, not a sandbox."""
    after_cd = False
    for segment in _SEGMENT_SPLIT.split(command):
        try:
            words = shlex.split(segment)
        except ValueError:
            words = segment.split()
            if any(w.endswith("rm") for w in words):
                return True
        if any(recursive_rm_of_system_dir(inner) for inner in _inner_commands(words)):
            return True
        while words and (words[0] in ("sudo", "env", "busybox", "command", "exec", "nohup")
                         or "=" in words[0] and not words[0].startswith(("-", "/"))):
            words = words[1:]
        if words and words[0] in ("cd", "pushd"):
            after_cd = True
            continue
        for index, word in enumerate(words):
            name = posixpath.basename(word)
            if name == "find" and _find_deletes_from_a_system_dir(words[index + 1:], after_cd):
                return True
            # a command name the shell expands may be rm
            if (name == "rm" or index == 0 and word.startswith("$")) and _recursive_rm_args(
                    words[index + 1:], after_cd,
                    fed=any(posixpath.basename(w) == "xargs" for w in words[:index])):
                return True
    return False


def _recursive_rm_args(args: list[str], after_cd: bool, fed: bool = False) -> bool:
    recursive = any(
        a == "--recursive" or (a.startswith("-") and not a.startswith("--") and ("r" in a or "R" in a))
        for a in args
    )
    targets = [a for a in args if not a.startswith("-")]
    if recursive and (fed or not targets):
        # a command substitution ($(...) or backticks) split off the
        # target, or xargs feeds it: the shell decides it, fail closed
        return True
    return recursive and any(_system_target(a) or _unknowable_target(a, after_cd) for a in targets)


def safe_command(command: str, approved: bool) -> str | None:
    if recursive_rm_of_system_dir(command):
        return "refusing hard-blocked destructive command"
    for rule in HARD_RULES:
        if re.search(rule, command, re.I):
            return "refusing hard-blocked destructive command"
    for rule, risk in SOFT_RULES:
        if re.search(rule, command, re.I):
            if not approved:
                return f"refusing {risk}; rerun with --approved if intentional"
    return None


def read_password(path: str) -> str:
    candidate = Path(path)
    try:
        mode = stat.S_IMODE(candidate.stat().st_mode)
    except OSError as exc:
        raise ValueError(f"cannot read password file: {exc}") from exc
    if os.name == "posix" and mode != 0o600:
        raise ValueError("password file must have mode 0600")
    try:
        return candidate.read_text(encoding="utf-8").rstrip("\r\n")
    except OSError as exc:
        raise ValueError(f"cannot read password file: {exc}") from exc


class InsecureLogDirError(Exception):
    """The requested --log-dir or transcript file is not safe to use."""


def _secure_log_dir(path: Path) -> None:
    """Make *path* a directory we own with mode 0700, umask-independent.

    Refuses (raises InsecureLogDirError) if the PARENT is group- or
    world-writable without the sticky bit, or if the leaf exists, is a
    symlink, is not a directory, or is not owned by the current uid, so an
    attacker who can write to a parent we just created cannot redirect the
    transcript. The leaf's own parents are created by the caller (here:
    Session.__init__).
    """
    # parent-sticky check, the same rule as mcp/newton_mcp/receipts.py
    # check_state_dir_parent: the parent is stat()ed (links followed) because
    # a parent that resolves into a tight directory is fine.  A parent that
    # does not exist yet cannot be inspected and Session.__init__ makes it
    # under the process umask.
    try:
        parent_info = os.stat(path.parent)
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise InsecureLogDirError(
            f"refusing to use --log-dir {path}: parent {path.parent} cannot be inspected: {exc.strerror}"
        ) from exc
    else:
        if (stat.S_IMODE(parent_info.st_mode) & 0o022) and not (
            parent_info.st_mode & stat.S_ISVTX
        ):
            raise InsecureLogDirError(
                f"refusing to use --log-dir {path}: parent {path.parent} is group- or world-writable without the sticky bit"
            )
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        os.mkdir(path)
    else:
        if stat.S_ISLNK(st.st_mode):
            raise InsecureLogDirError(f"refusing to use --log-dir {path}: it is a symlink")
        if not stat.S_ISDIR(st.st_mode):
            raise InsecureLogDirError(f"refusing to use --log-dir {path}: not a directory")
        if st.st_uid != os.getuid():
            raise InsecureLogDirError(
                f"refusing to use --log-dir {path}: owned by uid {st.st_uid}, expected {os.getuid()}"
            )
    os.chmod(path, 0o700)


def _open_log_file(path: Path):
    """Open the transcript file with mode 0600, refusing symlinks.

    O_NOFOLLOW prevents an attacker from redirecting a log path to another
    file on the system. The fd is chmod'd to 0600 after open so the mode
    is umask-independent, then wrapped as an append-mode text stream.
    """
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        if getattr(exc, "errno", None) == errno.ELOOP:
            raise InsecureLogDirError(f"refusing to use log file {path}: it is a symlink") from exc
        raise
    os.fchmod(fd, 0o600)
    return os.fdopen(fd, "a", encoding="utf-8")


class Session:
    def __init__(self, args: argparse.Namespace, password: str | None):
        self.args = args
        self.password = password
        self.buffer = ""
        self.mark = 0          # buffer offset of the last write; state is judged only on text after it
        self.prompt = re.compile(args.prompt, re.M)
        log_dir = Path(args.log_dir).expanduser()
        log_dir.parent.mkdir(parents=True, exist_ok=True)
        _secure_log_dir(log_dir)
        stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        self.log = _open_log_file(log_dir / f"serial-{stamp}.log")
        kwargs: dict[str, object] = {"baudrate": args.baud, "timeout": 0.05}
        if os.name == "posix":
            kwargs["exclusive"] = True
        self.port = serial.serial_for_url(args.port, **kwargs)

    def close(self) -> None:
        self.port.close()
        self.log.close()

    def write(self, data: str, secret: bool = False) -> None:
        self.mark = len(self.buffer)
        self.log.write("SEND: " + ("********" if secret else data) + "\n")
        self.log.flush()
        raw = data.encode()
        for i in range(0, len(raw), 128):          # small chunks: long lines garbled a real ash console
            try:
                self.port.write(raw[i:i + 128])
                self.port.flush()
            except _LINE_ERRORS as exc:            # pyserial's flush raises termios.error on a dropped line
                raise serial.SerialException(f"write failed: {exc}") from exc
            if len(raw) > 128:
                time.sleep(0.02)

    def drain(self) -> str:
        data = self.port.read(self.port.in_waiting or 1)
        if not data:
            return ""
        decoded = data.decode("utf-8", errors="replace")
        self.buffer += decoded
        self.log.write("RECV: " + decoded)
        self.log.flush()
        return decoded

    def wait(self, seconds: float, wanted: set[str] | None = None) -> tuple[str, str]:
        captured = ""
        deadline = time.monotonic() + seconds
        # Judge state only on what arrived after the last write: the old buffer still ends with the
        # previous prompt (e.g. "login:" right after sending the username), which caused instant false matches.
        state = classify(self.buffer[self.mark:], self.prompt)
        while time.monotonic() < deadline:
            captured += self.drain()
            state = classify(self.buffer[self.mark:], self.prompt)
            if wanted and state in wanted:
                return state, captured
            time.sleep(0.01)
        captured += self.drain()
        return classify(self.buffer[self.mark:], self.prompt), captured

    def settle(self, quiet: float = 0.3, limit: float = 2.0) -> str:
        """Drain until the console has been silent for `quiet` seconds (late prompts, MOTD tails)."""
        captured, end, last = "", time.monotonic() + limit, time.monotonic()
        while time.monotonic() < end and time.monotonic() - last < quiet:
            chunk = self.drain()
            if chunk:
                captured, last = captured + chunk, time.monotonic()
            else:
                time.sleep(0.01)
        return captured

    def wake(self) -> tuple[str, str]:
        self.write("\r")
        return self.wait(self.args.timeout, {"login", "password", "shell", "bootloader", "pager"})

    def login(self, initial: str | None = None) -> tuple[str, str, bool]:
        captured = ""
        state = initial or "unknown"
        if state == "unknown":
            state, part = self.wake()
            captured += part
        if state == "bootloader":
            return state, captured, False
        if state == "shell":
            return state, captured, True
        if state != "login":
            return state, captured, False
        if not self.args.user or self.password is None:
            return state, captured, False
        self.write(self.args.user + "\r")
        state, part = self.wait(self.args.timeout, {"password", "shell", "bootloader", "login"})
        captured += part
        if state != "password":
            return state, captured, state == "shell"
        self.write(self.password + "\r", secret=True)
        state, part = self.wait(self.args.timeout, {"shell", "login", "bootloader"})
        captured += part
        return state, captured, state == "shell"


def marker_wrap(command: str, token: str) -> str:
    """Wrap a POSIX-shell command in start/end markers. The markers are printed with split format strings,
    so the echoed command line never contains the joined marker text (echo wrapping cannot fool it)."""
    # No "$?": VyOS/vbash (like Cisco) treats a typed "?" as context help, which ate the marker.
    # Success/failure via && / || instead; the reported exit is therefore 0 or 1.
    body = command.rstrip().rstrip(";").rstrip()
    end = "printf '\\n__NWE%s__%s\\n' " + token
    return f"printf '%s%s\\n' __NWS {token}__; {{ {body}; }} && {end} 0 || {end} 1"


def run_marked(session: "Session", command: str, timeout: float) -> tuple[int | None, str]:
    """Returns (remote_exit or None on timeout, output). Ctrl-C first clears a stuck line or PS2 prompt."""
    token = os.urandom(4).hex()
    session.write("\x03")
    session.settle()
    session.write(marker_wrap(command, token) + "\r")
    start_re, end_re = re.compile(rf"__NWS{token}__\n"), re.compile(rf"__NWE{token}__(\d+)")
    response, deadline, pages = "", time.monotonic() + timeout, 0
    while time.monotonic() < deadline:
        response += session.drain()
        cleaned = clean(response)
        tail_state = classify(cleaned[-400:], session.prompt)
        if tail_state == "bootloader":
            raise BootloaderError()
        if tail_state == "pager" and pages < 200:
            pages += 1
            session.write(" ")
            response = re.sub(r"(?:--More--|-- More --)\s*$", "", response)
            continue
        end = end_re.search(cleaned)
        if end:
            start = start_re.search(cleaned)
            body = cleaned[start.end():end.start()] if start else cleaned[:end.start()]
            session.settle()
            return int(end.group(1)), body.strip("\n")
        time.sleep(0.01)
    cleaned = clean(response)
    start = start_re.search(cleaned)
    return None, (cleaned[start.end():] if start else cleaned).strip("\n")


class BootloaderError(Exception):
    pass


def strip_run_output(text: str, command: str, prompt: re.Pattern[str]) -> str:
    value = clean(text)
    lines = value.splitlines()
    for index, line in enumerate(lines):
        if command in line:
            lines = lines[index + 1:]
            break
    while lines and prompt.search(lines[-1]):
        lines.pop()
    return "\n".join(lines).strip("\n")


def print_capture(text: str) -> None:
    """Print console text on stdout inside a delimited untrusted-text block.

    A fresh random token per call encloses the block; the device cannot
    predict or forge the matching END line. The body is cleaned (ANSI
    removed, CR normalised) and then escaped (control / bidi / zero-width
    characters become a visible \\xNN / \\uXXXX). An empty body still prints
    the two delimiter lines so the absence of output is explicit. Console
    text is data from the device, never instructions; the status trailers
    go to stderr and the exit code is the authority, not the body.
    """
    token = os.urandom(8).hex()
    escaped = _escape_console_text(clean(text))
    print(f"----- BEGIN UNTRUSTED CONSOLE TEXT {token} -----")
    if escaped:
        print(escaped, end="" if escaped.endswith("\n") else "\n")
    print(f"----- END UNTRUSTED CONSOLE TEXT {token} -----")


def parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--port", default=os.environ.get("NEWTON_SERIAL_PORT"))
    common.add_argument("--baud", type=int, default=115200)
    common.add_argument("--timeout", type=float, default=10)
    common.add_argument("--prompt", default=DEFAULT_PROMPT)
    common.add_argument("--user")
    common.add_argument("--password-file")
    common.add_argument("--approved", action="store_true")
    common.add_argument("--log-dir", default="~/.local/state/newton/serial/")
    common.add_argument("--no-marker", action="store_true",
                        help="non-POSIX CLI (RouterOS, IOS, Junos): detect completion by prompt instead of shell markers")
    result = argparse.ArgumentParser(description=__doc__, parents=[common],
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    subs = result.add_subparsers(dest="subcommand", required=True)
    subs.add_parser("list-ports")
    subs.add_parser("probe")
    subs.add_parser("login")
    run = subs.add_parser("run")
    run.add_argument("command")
    push = subs.add_parser("push", help="copy a text file to the device over the console (POSIX shells only)")
    push.add_argument("local")
    push.add_argument("remote")
    push.add_argument("--i-know", dest="i_know", action="store_true",
                      help="allow a push to a login file (/etc/dropbear/authorized_keys, /etc/shadow, /etc/passwd); "
                           "a wrong file there locks you out")
    send = subs.add_parser("send", help="send one line (or a secret from a file) and capture the reply; "
                                         "for interactive prompts such as first-boot wizards")
    send.add_argument("text", nargs="?", default="")
    send.add_argument("--secret-file", help="send this file's content (mode 0600) instead of text; masked in logs")
    send.add_argument("--wait", type=float, default=3, help="seconds to capture after sending")
    send.add_argument("--expect", help="stop capturing early once this regex matches the reply")
    read = subs.add_parser("read")
    read.add_argument("--seconds", type=float, default=5)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.subcommand == "list-ports":
        for item in list_ports.comports():
            print(f"{item.device}\t{item.description}")
        return 0
    if not args.port:
        print("--port or NEWTON_SERIAL_PORT is required", file=sys.stderr)
        return 2
    if args.timeout <= 0 or (args.subcommand == "read" and args.seconds < 0):
        print("timeouts must be positive", file=sys.stderr)
        return 2
    if args.subcommand == "run":
        refusal = safe_command(args.command, args.approved)
        if refusal:
            print(refusal, file=sys.stderr)
            return 2
    if args.subcommand == "send":
        if args.secret_file and args.text:
            print("give either text or --secret-file, not both", file=sys.stderr)
            return 2
        if args.text:
            refusal = safe_command(args.text, args.approved)
            if refusal:
                print(refusal, file=sys.stderr)
                return 2
        if args.secret_file:
            try:
                send_secret = read_password(args.secret_file)
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                return 2
    if args.subcommand == "push":
        if args.no_marker:
            print("push needs a POSIX shell on the device", file=sys.stderr)
            return 2
        if not re.fullmatch(r"/[A-Za-z0-9_./-]+", args.remote):
            print("remote path must be absolute and plain (letters, digits, _ . / -)", file=sys.stderr)
            return 2
        if posixpath.normpath("/" + args.remote.lstrip("/")) in LOGIN_FILES and not args.i_know:
            print(f"refusing to overwrite {args.remote}: a wrong file there locks you out; "
                  "rerun with --i-know if intentional (the old file is still backed up first)", file=sys.stderr)
            return 2
        try:
            push_text = Path(args.local).read_text(encoding="utf-8")
        except OSError as exc:
            print(f"cannot read {args.local}: {exc}", file=sys.stderr)
            return 2
        if "\t" in push_text:
            print("file contains tab characters, which trigger shell completion over a console; replace them", file=sys.stderr)
            return 2
        for line in push_text.splitlines():
            refusal = safe_command(line, args.approved)
            if refusal:
                print(f"{refusal} (in pushed file: {line[:80]})", file=sys.stderr)
                return 2
        if not push_text.endswith("\n"):
            push_text += "\n"
    password = None
    if args.password_file:
        try:
            password = read_password(args.password_file)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
    try:
        session = Session(args, password)
    except (OSError, serial.SerialException) as exc:
        print(f"cannot open serial port: {exc}", file=sys.stderr)
        return 2
    except InsecureLogDirError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    try:
        if args.subcommand == "read":
            _, captured = session.wait(args.seconds)
            print_capture(captured)
            return 0
        if args.subcommand == "send":
            _, before = session.wait(0.3)            # never type into a bootloader
            if classify(before, session.prompt) == "bootloader":
                print_capture(before)
                print("device is in its bootloader; a human must decide what to do", file=sys.stderr)
                return 4
            if args.secret_file:
                session.write(send_secret + "\r", secret=True)
            else:
                session.write(args.text + "\r")
            expect = re.compile(args.expect) if args.expect else None
            reply, deadline = "", time.monotonic() + args.wait
            while time.monotonic() < deadline:
                reply += session.drain()
                if expect and expect.search(clean(reply)):
                    break
                time.sleep(0.01)
            text = clean(reply)
            if args.secret_file:
                text = text.replace(send_secret, "********")
            print_capture(text)
            print(f"STATE: {classify(reply, session.prompt)}", file=sys.stderr)
            return 0
        if args.subcommand == "probe":
            state, captured = session.wake()
            print_capture(captured)
            print(f"STATE: {state}", file=sys.stderr)
            return 0 if state != "bootloader" else 4
        # Do not wake an already-chatty bootloader: unlike probe, login and run
        # must never write to a console once its bootloader is known.
        state, captured = session.wait(min(0.1, args.timeout),
                                       {"login", "password", "shell", "bootloader", "pager"})
        if state == "unknown":
            state, more = session.wake()
            captured += more
        if state == "bootloader":
            print("device is in its bootloader; a human must decide what to do", file=sys.stderr)
            return 4
        if args.subcommand == "login":
            state, more, ok = session.login(state)
            captured += more
            print_capture(captured)
            print(f"STATE: {state}", file=sys.stderr)
            return 0 if ok else 5
        state, more, ok = session.login(state)
        captured += more
        if state == "bootloader":
            print("device is in its bootloader; a human must decide what to do", file=sys.stderr)
            return 4
        if not ok:
            print_capture(captured)
            print("login failed", file=sys.stderr)
            return 5
        if args.subcommand == "push":
            backup = f"{args.remote}.newton-bak"
            try:
                exists_rc, _ = run_marked(session, f"test -e {args.remote}", args.timeout)
                if exists_rc not in (0, 1):
                    print(f"cannot tell whether {args.remote} exists (exit {exists_rc}); nothing written", file=sys.stderr)
                    return 7
                backup_rc = None
                if exists_rc == 0:
                    # a .newton-bak from an earlier push holds the file as it
                    # was before Newton touched it: never overwrite it
                    bak_rc, _ = run_marked(session, f"test -e {backup}", args.timeout)
                    if bak_rc not in (0, 1):
                        print(f"cannot tell whether {backup} exists (exit {bak_rc}); nothing written", file=sys.stderr)
                        return 7
                    if bak_rc == 0:
                        backup = f"{backup}-{time.strftime('%Y%m%dT%H%M%S')}-{os.urandom(3).hex()}"
                    backup_rc, _ = run_marked(session, f"cp -p {args.remote} {backup}", args.timeout)
            except BootloaderError:
                print("device entered its bootloader; a human must decide what to do", file=sys.stderr)
                return 4
            if exists_rc == 0 and backup_rc != 0:
                print(f"backup of {args.remote} to {backup} failed (exit {backup_rc}); nothing written", file=sys.stderr)
                return 7
            if exists_rc == 0:
                print(f"backup: {backup}")
            else:
                print(f"no earlier {args.remote}; nothing to back up")
            # until the line that writes the target is sent, the target is untouched
            if exists_rc == 0:
                overwritten = f"{args.remote} was not written; a copy of it is in {backup}"
            else:
                overwritten = f"{args.remote} was not written; there was no earlier file"
            cut_short = ""
            token = os.urandom(4).hex()
            delim = f"__NEWTON_EOF_{token}__"
            try:
                session.write("\x03")
                session.settle()
                session.write(f"cat > {args.remote} <<'{delim}'\r")
                # once the heredoc starts the target is overwritten: every failure from here says so
                if exists_rc == 0:
                    overwritten = f"{args.remote} was already overwritten; the old file is in {backup}"
                else:
                    overwritten = f"{args.remote} was already written; there was no earlier file"
                cut_short = ", possibly cut short"
                for line in push_text.splitlines():
                    session.write(line + "\r")
                session.write(delim + "\r")
                session.settle(0.5)
                rc, out = run_marked(session, f"wc -c < {args.remote}", args.timeout)
                want = len(push_text.encode())
                got = out.strip().splitlines()[-1].strip() if out.strip() else ""
                if rc != 0 or got != str(want):
                    print(f"push verification failed: expected {want} bytes, device reports {got!r} (exit {rc}); "
                          f"{overwritten}", file=sys.stderr)
                    return 7
                # a garbled line can keep the byte count: compare the contents too
                rc, out = run_marked(session, f"md5sum < {args.remote}", args.timeout)
            except BootloaderError:
                print(f"device entered its bootloader; a human must decide what to do; {overwritten}", file=sys.stderr)
                return 4
            except serial.SerialException as exc:
                print(f"serial line failed during push ({exc}); {overwritten}{cut_short}", file=sys.stderr)
                return 7
            wanted_sum = hashlib.md5(push_text.encode()).hexdigest()
            fields = out.strip().splitlines()[-1].split() if out.strip() else []
            got_sum = fields[0].lower() if fields else ""
            if rc != 0 or got_sum != wanted_sum:
                print(f"push verification failed: content checksum {got_sum or 'missing'!s} (exit {rc}) does not "
                      f"match the file sent ({wanted_sum}); {overwritten}", file=sys.stderr)
                return 7
            print(f"PUSHED {want} bytes to {args.remote} (md5 {wanted_sum})")
            return 0
        if not args.no_marker:
            try:
                rc, out = run_marked(session, args.command, args.timeout)
            except BootloaderError:
                print("device entered its bootloader; a human must decide what to do", file=sys.stderr)
                return 4
            print_capture(out)
            if rc is None:
                print("timeout waiting for completion marker", file=sys.stderr)
                return 3
            print(f"REMOTE-EXIT: {rc}", file=sys.stderr)
            print("EXIT-STATE: shell", file=sys.stderr)
            return 0 if rc == 0 else 6
        session.settle()                     # do not let a late prompt be mistaken for the command finishing
        session.write(args.command + "\r")
        pages = 0
        deadline = time.monotonic() + args.timeout
        response = ""
        while time.monotonic() < deadline:
            response += session.drain()
            # only a prompt that follows the echoed command counts as "finished"
            cleaned = clean(response)
            echo_at = cleaned.find(args.command)
            if echo_at == -1 and time.monotonic() < deadline - args.timeout / 2:
                time.sleep(0.01)
                continue
            state = classify(cleaned[echo_at + len(args.command):] if echo_at != -1 else response, session.prompt)
            if state == "bootloader":
                print("device entered its bootloader; a human must decide what to do", file=sys.stderr)
                return 4
            if state == "pager":
                pages += 1
                if pages > 200:
                    print("pager exceeded 200 pages", file=sys.stderr)
                    return 3
                session.write(" ")
                # Remove the current pager marker so the next page can be classified.
                response = re.sub(r"(?:--More--|-- More --)\s*$", "", response)
                continue
            if state == "shell":
                output = strip_run_output(response, args.command, session.prompt)
                print_capture(output)
                print("EXIT-STATE: shell", file=sys.stderr)
                return 0
            time.sleep(0.01)
        partial = strip_run_output(response, args.command, session.prompt)
        print_capture(partial)
        print("timeout waiting for prompt", file=sys.stderr)
        return 3
    finally:
        session.close()


if __name__ == "__main__":
    raise SystemExit(main())
