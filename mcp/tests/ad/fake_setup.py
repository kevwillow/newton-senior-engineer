"""The fake tools the Samba setup script runs against in the tests.

The setup script of the Samba collector is the owner's script: it runs
as root on a Samba domain controller, where ``samba-tool``, ``getent``,
``useradd``, ``passwd``, ``stat`` and ``install`` are the real tools.  A
test cannot run it there, so it runs it against these fakes, which
answer exactly what the lab DC (Samba 4.22.11) answered on 2026-11-08:

* ``samba-tool user list`` prints bare names, one per line, with no
  colon in them (``seed-revenc$`` and the like);
* ``samba-tool user show <name>`` exits 0 when the account exists and
  255 when it does not;
* ``samba-tool user show <name> --attributes=primaryGroupID,memberOf,userAccountControl``
  prints ``primaryGroupID: 513`` and no ``memberOf`` line;
* ``samba-tool user create <name>`` makes the account exist afterwards;
* ``getent passwd newton-audit`` prints
  ``NEWTONLAB\\newton-audit:*:3000022:100::/home/NEWTONLAB/newton-audit:/bin/false``;
* ``useradd newton-audit`` fails with "user 'newton-audit' already
  exists" and exits 9;
* ``passwd -S <name>`` prints the status of the password: ``L`` when
  it is locked and ``P`` when it is not;
* ``id -Gn <name>`` prints the groups of the local account, one name
  per group, and fails when the account is not there;
* ``visudo -cf <file>`` accepts the one sudoers line of the setup
  script (``newton-ssh ALL=(root) NOPASSWD:
  /usr/local/sbin/newton-ad-samba ""``) and refuses every other file:
  the whole content of the file must be that one line and a newline.

The ownership of a file is recorded and not real: a test runs as the
maintainer, and the script of the owner runs as root.  The mode of a
file is the real one, so a test can break it and watch the script
repair it.  ``chown`` records the ownership it is given, the way
``install`` does.

The record holds the owner and the group as a number and as a name,
because the script reads them with ``stat -c '%U:%G %a'``: root is
``root``, and any other owner is the local account of the lab DC,
``newton-ssh``.

Every call is written into a log, so a test sees what the script did:
that it created the local account and left the domain one alone.

The script writes to the absolute paths of the install (``/usr/local``,
``/var/lib`` and ``/etc/sudoers.d``), so a test runs it against a copy
of the script whose paths point into a temporary tree.  Only the paths
of the copy differ; the rest of it is the script of the package.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


# The paths the script writes to, and where a test puts them.
INSTALL_PATHS = (
    ("/usr/local/sbin", "usr/local/sbin"),
    ("/usr/local/lib/newton-ad", "usr/local/lib/newton-ad"),
    ("/var/lib/newton-ssh", "var/lib/newton-ssh"),
    ("/etc/sudoers.d", "etc/sudoers.d"),
    ("/etc/shadow", "etc/shadow"),
)

# The domain account of the lab DC.
DOMAIN_ACCOUNT = "newton-audit"

# The local account that logs in.
LOGIN_ACCOUNT = "newton-ssh"


# ---- the state of the fake --------------------------------------------------


def state_dir_of(root: Path) -> Path:
    """The directory the state of the fake lives in."""
    return root / "state"


def stat_sidecar(state_dir: Path, path: str) -> Path:
    """The file that holds the recorded ownership of a path."""
    return state_dir / ("stat-" + path.replace("/", "_"))


def set_owner(
    state_dir: Path,
    path: str,
    uid: int = 0,
    gid: int = 0,
    *,
    user: str | None = None,
    group: str | None = None,
    force: bool = False,
) -> None:
    """Record the ownership of a path, the way the fake install does.

    A record that is already there is kept: a test that wants a path
    that root does not own writes its own record first.  A test that
    wants to change the ownership of a path the script installed
    already passes ``force``.

    The names of the owner and of the group are recorded too, because
    the script reads them with ``stat -c '%U:%G %a'``.  Root is
    ``root``, and any other owner is the local account of the lab DC.
    """
    sidecar = stat_sidecar(state_dir, path)
    if sidecar.exists() and not force:
        return
    if user is None:
        user = "root" if uid == 0 else "newton-ssh"
    if group is None:
        group = "root" if gid == 0 else "newton-ssh"
    sidecar.write_text(
        f"uid={uid}\ngid={gid}\nuser={user}\ngroup={group}\n", encoding="utf-8"
    )


def write_local_account(
    state_dir: Path,
    name: str,
    home: str = "/var/lib/newton-ssh",
    shell: str = "/bin/sh",
    locked: bool = True,
    groups: str = "",
) -> None:
    """Write the state of a local account, the way useradd does.

    The groups are the names of the groups of the account: an empty
    text means the account is in its primary group only.
    """
    password = "!" if locked else "secret"
    (state_dir / f"local-{name}").write_text(
        f"home={home}\nshell={shell}\npassword={password}\ngroups={groups}\n",
        encoding="utf-8",
    )


# ---- the fakes --------------------------------------------------------------


SAMBA_TOOL = r"""#!/bin/sh
# The fake samba-tool of the lab DC.
printf 'samba-tool %s\n' "$*" >> "${NEWTON_FAKE_LOG}"
domain_account="${NEWTON_FAKE_DOMAIN_ACCOUNT}"
case "$1" in
user)
    case "$2" in
    list)
        # The names are bare, one per line: there is no colon in them.
        printf '%s\n' "${NEWTON_FAKE_USER_LIST}"
        exit 0
        ;;
    show)
        if [ "$3" != "${domain_account}" ] || [ ! -f "${NEWTON_FAKE_STATE}/domain-${domain_account}" ]; then
            printf 'Failed to find user %s\n' "$3" >&2
            exit 255
        fi
        printf 'dn: CN=%s,CN=Users,DC=lab,DC=newton,DC=test\n' "$3"
        if [ "$4" = "--attributes=primaryGroupID,memberOf,userAccountControl" ]; then
            printf 'primaryGroupID: %s\n' "${NEWTON_FAKE_PRIMARY_GROUP}"
            if [ -n "${NEWTON_FAKE_MEMBER_OF}" ]; then
                printf 'memberOf: %s\n' "${NEWTON_FAKE_MEMBER_OF}"
            fi
            printf 'userAccountControl: %s\n' "${NEWTON_FAKE_USER_ACCOUNT_CONTROL}"
        else
            printf 'sAMAccountName: %s\n' "$3"
            printf 'primaryGroupID: %s\n' "${NEWTON_FAKE_PRIMARY_GROUP}"
        fi
        exit 0
        ;;
    create)
        # The account exists afterwards.
        : > "${NEWTON_FAKE_STATE}/domain-${3}"
        printf 'Created user %s\n' "$3"
        exit 0
        ;;
    esac
    ;;
esac
printf 'unknown command\n' >&2
exit 1
"""

GETENT = r"""#!/bin/sh
# The fake getent of the lab DC.
printf 'getent %s\n' "$*" >> "${NEWTON_FAKE_LOG}"
source=""
if [ "$1" = "-s" ]; then
    source="$2"
    shift 2
fi
if [ "$1" != "passwd" ]; then
    exit 2
fi
name="$2"
if [ "${source}" = "files" ]; then
    # Only the files source answers for the local account: winbind
    # answers for the domain account.
    file="${NEWTON_FAKE_STATE}/local-${name}"
    if [ -f "${file}" ]; then
        home="$(sed -n 's/^home=//p' "${file}")"
        shell="$(sed -n 's/^shell=//p' "${file}")"
        printf '%s:*:3000023:100::%s:%s\n' "$name" "${home}" "${shell}"
        exit 0
    fi
    exit 2
fi
if [ "$name" = "${NEWTON_FAKE_DOMAIN_ACCOUNT}" ]; then
    printf 'NEWTONLAB\\%s:*:3000022:100::/home/NEWTONLAB/%s:/bin/false\n' "$name" "$name"
    exit 0
fi
exit 2
"""

USERADD = r"""#!/bin/sh
# The fake useradd of the lab DC.
printf 'useradd %s\n' "$*" >> "${NEWTON_FAKE_LOG}"
home=""
shell=""
password=""
name=""
while [ $# -gt 0 ]; do
    case "$1" in
    --home-dir) home="$2"; shift 2 ;;
    --shell) shell="$2"; shift 2 ;;
    --password) password="$2"; shift 2 ;;
    --*) shift ;;
    *) name="$1"; shift ;;
    esac
done
if [ "$name" = "${NEWTON_FAKE_DOMAIN_ACCOUNT}" ]; then
    printf "useradd: user '%s' already exists\n" "$name" >&2
    exit 9
fi
if [ -f "${NEWTON_FAKE_STATE}/local-${name}" ]; then
    printf "useradd: user '%s' already exists\n" "$name" >&2
    exit 9
fi
{
    printf 'home=%s\n' "${home}"
    printf 'shell=%s\n' "${shell}"
    printf 'password=%s\n' "${password}"
} > "${NEWTON_FAKE_STATE}/local-${name}"
exit 0
"""

PASSWD = r"""#!/bin/sh
# The fake passwd of the lab DC.
printf 'passwd %s\n' "$*" >> "${NEWTON_FAKE_LOG}"
if [ "$1" != "-S" ]; then
    exit 1
fi
name="$2"
file="${NEWTON_FAKE_STATE}/local-${name}"
if [ ! -f "${file}" ]; then
    printf 'passwd: user %s does not exist\n' "$name" >&2
    exit 2
fi
password="$(sed -n 's/^password=//p' "${file}")"
case "${password}" in
'!'*|'*'*) status='L' ;;
*) status='P' ;;
esac
printf '%s %s 08/08/2026 0 99999 7 -1\n' "$name" "${status}"
exit 0
"""

INSTALL = r"""#!/bin/sh
# The fake install of the lab DC.
printf 'install %s\n' "$*" >> "${NEWTON_FAKE_LOG}"
mode=""
owner="root"
group="root"
isdir=0
source=""
dest=""
while [ $# -gt 0 ]; do
    case "$1" in
    -m) mode="$2"; shift 2 ;;
    -o) owner="$2"; shift 2 ;;
    -g) group="$2"; shift 2 ;;
    -d) isdir=1; shift ;;
    *)
        if [ -z "$source" ]; then source="$1"; else dest="$1"; fi
        shift
        ;;
    esac
done
# The owner is recorded as a number and as a name: root is 0 and any
# other name is an account of the host.
if [ "${owner}" = "root" ]; then owner=0; owner_name=root; else owner=1000; owner_name="${owner}"; fi
if [ "${group}" = "root" ]; then group=0; group_name=root; else group=1000; group_name="${group}"; fi
if [ "$isdir" = "1" ]; then
    mkdir -p "$source"
    if [ -n "$mode" ]; then chmod "$mode" "$source"; fi
    sidecar="${NEWTON_FAKE_STATE}/stat-$(printf '%s' "$source" | tr '/' '_')"
    printf 'uid=%s\ngid=%s\nuser=%s\ngroup=%s\n' "${owner}" "${group}" "${owner_name}" "${group_name}" > "$sidecar"
    exit 0
fi
if [ -n "$dest" ]; then
    mkdir -p "$(dirname "$dest")"
    cp "$source" "$dest"
    if [ -n "$mode" ]; then chmod "$mode" "$dest"; fi
    sidecar="${NEWTON_FAKE_STATE}/stat-$(printf '%s' "$dest" | tr '/' '_')"
    printf 'uid=%s\ngid=%s\nuser=%s\ngroup=%s\n' "${owner}" "${group}" "${owner_name}" "${group_name}" > "$sidecar"
fi
exit 0
"""

STAT = r"""#!/bin/sh
# The fake stat of the lab DC.  The mode is the real one and the
# ownership is the recorded one: the script of the owner runs as root
# and a test does not.
printf 'stat %s\n' "$*" >> "${NEWTON_FAKE_LOG}"
format=""
path=""
while [ $# -gt 0 ]; do
    case "$1" in
    -c) format="$2"; shift 2 ;;
    -*) shift ;;
    *) path="$1"; shift ;;
    esac
done
sidecar="${NEWTON_FAKE_STATE}/stat-$(printf '%s' "$path" | tr '/' '_')"
uid="0"
gid="0"
user="root"
group="root"
if [ -f "${sidecar}" ]; then
    uid="$(sed -n 's/^uid=//p' "${sidecar}")"
    gid="$(sed -n 's/^gid=//p' "${sidecar}")"
    recorded_user="$(sed -n 's/^user=//p' "${sidecar}")"
    recorded_group="$(sed -n 's/^group=//p' "${sidecar}")"
    # A record without a name is one of an owner that is not root: the
    # local account of the lab DC.
    if [ -n "${recorded_user}" ]; then
        user="${recorded_user}"
    elif [ "${uid}" != "0" ]; then
        user="newton-ssh"
    fi
    if [ -n "${recorded_group}" ]; then
        group="${recorded_group}"
    elif [ "${gid}" != "0" ]; then
        group="newton-ssh"
    fi
fi
mode="$(/usr/bin/stat -c '%a' "$path" 2>/dev/null || true)"
if [ -z "${mode}" ]; then
    mode="644"
fi
result="$(printf '%s' "$format" | sed -e "s|%a|${mode}|g" -e "s|%u|${uid}|g" -e "s|%g|${gid}|g" -e "s|%U|${user}|g" -e "s|%G|${group}|g")"
printf '%s\n' "$result"
exit 0
"""

CHOWN = r"""#!/bin/sh
# The fake chown of the lab DC: the ownership is recorded, not set.
printf 'chown %s\n' "$*" >> "${NEWTON_FAKE_LOG}"
owner=""
paths=""
while [ $# -gt 0 ]; do
    case "$1" in
    -*) shift ;;
    *)
        if [ -z "$owner" ]; then
            owner="$1"
        else
            paths="$paths $1"
        fi
        shift
        ;;
    esac
done
owner_name="${owner%%:*}"
group_name="${owner#*:}"
if [ "${owner_name}" = "root" ]; then
    uid=0
else
    uid=1000
fi
if [ "${group_name}" = "root" ]; then
    gid=0
else
    gid=1000
fi
for path in ${paths}; do
    sidecar="${NEWTON_FAKE_STATE}/stat-$(printf '%s' "$path" | tr '/' '_')"
    printf 'uid=%s\ngid=%s\nuser=%s\ngroup=%s\n' "${uid}" "${gid}" "${owner_name}" "${group_name}" > "$sidecar"
done
exit 0
"""

VISUDO = r"""#!/bin/sh
# The fake visudo of the lab DC: it accepts the one line of the setup
# script and refuses every other file.
#
# The whole content of the file must be that one line and a newline: a
# file that holds the line and something else is refused, the way the
# real visudo refuses a file it cannot parse.
printf 'visudo %s\n' "$*" >> "${NEWTON_FAKE_LOG}"
file="$2"
if [ ! -f "${file}" ]; then
    printf 'visudo: cannot open %s\n' "${file}" >&2
    exit 1
fi
expected='newton-ssh ALL=(root) NOPASSWD: /usr/local/sbin/newton-ad-samba ""'
if [ "$(cat "${file}")" != "${expected}" ]; then
    printf 'visudo: parse error in %s\n' "${file}" >&2
    exit 1
fi
if [ "$(wc -c < "${file}")" -ne "$(( ${#expected} + 1 ))" ]; then
    printf 'visudo: parse error in %s\n' "${file}" >&2
    exit 1
fi
exit 0
"""

ID = r"""#!/bin/sh
# The fake id of the lab DC.
#
# "id -Gn <account>" prints the groups of the account, one name per
# group.  The setup script must never ask for the identification of
# the domain account: it resolves locally, so "id" would answer for
# an account that is not there.
printf 'id %s\n' "$*" >> "${NEWTON_FAKE_LOG}"
if [ "$1" != "-Gn" ]; then
    exit 0
fi
name="$2"
file="${NEWTON_FAKE_STATE}/local-${name}"
if [ ! -f "${file}" ]; then
    printf 'id: %s: no such user\n' "${name}" >&2
    exit 1
fi
groups="$(sed -n 's/^groups=//p' "${file}")"
if [ -z "${groups}" ]; then
    groups="${name}"
fi
printf '%s\n' "${groups}"
exit 0
"""

FAKES = {
    "samba-tool": SAMBA_TOOL,
    "getent": GETENT,
    "useradd": USERADD,
    "passwd": PASSWD,
    "install": INSTALL,
    "stat": STAT,
    "chown": CHOWN,
    "visudo": VISUDO,
    "id": ID,
}


# ---- the runner -------------------------------------------------------------


# The one sudoers line of the setup script.  It names the collector of
# the package, and the fake visudo accepts that line and no other, so
# the sandbox keeps it as it is.
SUDOERS_LINE = 'newton-ssh ALL=(root) NOPASSWD: /usr/local/sbin/newton-ad-samba ""'


def sandbox_script(script: str, root: Path) -> str:
    """The script with the paths of the install inside a temporary tree."""
    text = script
    # The sudoers line is kept as the package writes it: the fake
    # visudo checks that one line and no other.
    marker = "NEWTON_SUDOERS_LINE_OF_THE_PACKAGE"
    text = text.replace(SUDOERS_LINE, marker)
    for absolute, relative in INSTALL_PATHS:
        text = text.replace(absolute, str(root / relative))
    return text.replace(marker, SUDOERS_LINE)


def _write_fakes(bin_dir: Path) -> None:
    """Write the fake tools and make them executable."""
    for name, body in FAKES.items():
        path = bin_dir / name
        path.write_text(body, encoding="utf-8")
        path.chmod(0o755)


def run_script(
    script: str,
    root: Path,
    *,
    domain_user_exists: bool = True,
    primary_group: str = "513",
    local_account_exists: bool = False,
    local_home: str | None = None,
    local_shell: str = "/bin/sh",
    local_locked: bool = True,
    local_groups: str = "",
    domain_member_of: str = "",
    user_account_control: str = "512",
) -> tuple[subprocess.CompletedProcess, list[str]]:
    """Run the setup script against the fakes.

    The result of the run and the calls it made are returned.  The
    calls are the lines of the log of the fakes, one per call.
    """
    root.mkdir(parents=True, exist_ok=True)
    bin_dir = root / "bin"
    bin_dir.mkdir(exist_ok=True)
    state_dir = state_dir_of(root)
    state_dir.mkdir(exist_ok=True)
    # The directories of the install are there already, and they are
    # owned by root on a real host.
    for _absolute, relative in INSTALL_PATHS:
        directory = root / relative
        directory.mkdir(parents=True, exist_ok=True)
        # The umask of the machine may make a group write, and the
        # script of the owner refuses that.
        directory.chmod(0o755)
    set_owner(state_dir, str(root / "usr" / "local" / "sbin"))
    # The sudoers drop-in directory of a real system is there already.
    (root / "etc" / "sudoers.d").mkdir(parents=True, exist_ok=True)
    log = root / "calls.log"
    log.write_text("", encoding="utf-8")
    _write_fakes(bin_dir)
    if local_account_exists:
        # The home of the account is the one of the sandbox, unless the
        # test wants another one.
        home = local_home
        if home is None:
            home = str(root / "var" / "lib" / "newton-ssh")
        write_local_account(
            state_dir,
            LOGIN_ACCOUNT,
            home=home,
            shell=local_shell,
            locked=local_locked,
            groups=local_groups,
        )
    if domain_user_exists:
        (state_dir / f"domain-{DOMAIN_ACCOUNT}").write_text("", encoding="utf-8")

    path = root / "setup.sh"
    path.write_text(sandbox_script(script, root), encoding="utf-8")

    environment = dict(os.environ)
    environment["PATH"] = f"{bin_dir}{os.pathsep}{environment.get('PATH', '')}"
    environment["HOME"] = str(root)
    environment["NEWTON_FAKE_LOG"] = str(log)
    environment["NEWTON_FAKE_STATE"] = str(state_dir)
    environment["NEWTON_FAKE_DOMAIN_ACCOUNT"] = DOMAIN_ACCOUNT
    environment["NEWTON_FAKE_PRIMARY_GROUP"] = primary_group
    environment["NEWTON_FAKE_MEMBER_OF"] = domain_member_of
    environment["NEWTON_FAKE_USER_ACCOUNT_CONTROL"] = user_account_control
    environment["NEWTON_FAKE_USER_LIST"] = "Administrator\nnewton-audit\nseed-revenc$"

    result = subprocess.run(
        ["bash", str(path)],
        capture_output=True,
        text=True,
        check=False,
        env=environment,
    )
    calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    return result, calls
