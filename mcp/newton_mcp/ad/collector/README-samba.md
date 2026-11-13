# Samba AD collector (`newton-ad-samba`)

The collector runs on the Samba domain controller as root, takes no input, and prints one JSON
document on stdout. It is the Samba half of the Newton AD audit; the Windows half is
`collector.ps1` and the two produce the same shape of document.

## Install

| file | source | mode | owner |
|---|---|---|---|
| `/usr/local/sbin/newton-ad-samba` | `mcp/newton_mcp/ad/collector/newton-ad-samba` | 0755 | root:root |
| `/usr/local/lib/newton-ad/queries.json` | the query set Newton ships (`mcp/newton_mcp/ad/queries.json`) | 0644 | root:root |
| `/usr/local/lib/newton-ad/forbidden.json` | the forbidden attribute list Newton dumps | 0644 | root:root |

The directory `/usr/local/lib/newton-ad` is root:root 0755. At start the collector checks the two
directories and the three files: a path that is not owned by root, or that its group or the others
may write, is refused with exit 2. Every parent of the two directories is checked as well, up to
`/`: `/usr/local`, `/usr/local/lib`, `/usr` and `/` must be owned by root and must not be writable by
their group or by the others. The check runs before the samba bindings are imported, and the two
files of the query set are opened with `O_NOFOLLOW` and checked on the descriptor of the open file,
so a link is never read. The collector reads `queries.json` and `forbidden.json` from
`/usr/local/lib/newton-ad` and reports the SHA-256 of the bytes of `queries.json` as
`querysetsha`; Newton refuses a document whose hash differs from its own copy ("collector out of
date: rerun the setup").

The generator of the setup script is `newton-ad-setup samba`; it writes these files, the local
account, the authorized key and the sudoers line, and it checks every file against the hash of the
package.

## The two accounts

There are two accounts on the DC and they are not the same one.

`newton-audit` is the **domain** account. It is created by
`samba-tool user create newton-audit --random-password` and it is the account the audit runs
for: the collector reports its `objectSid` and its `tokenGroups` as the identity of the
document.

`newton-ssh` is the **local** unix account that logs in. It has no password, so it cannot log in
with one, and the forced command of its authorized key is the whole session.

The two names have to differ. A Samba DC with `passwd: files winbind` resolves the domain account
locally already (measured on the lab DC on 2026-11-08):

```
getent passwd newton-audit
NEWTONLAB\newton-audit:*:3000022:100::/home/NEWTONLAB/newton-audit:/bin/false
```

`useradd newton-audit` then fails with "user 'newton-audit' already exists" (exit 9), and the
shell of the domain account is `/bin/false`, so it is never the account of a login anyway. The
local account therefore carries another name, and the setup script looks it up with
`getent -s files passwd newton-ssh`: the `files` source only, so that winbind never answers for
it.

## The authorized key and the sudoers line

The authorized key of the local account holds one line, and the forced command of that line is
the whole session. The `restrict` option of OpenSSH turns every other restriction off at once:

```
restrict,command="sudo -n /usr/local/sbin/newton-ad-samba" ssh-ed25519 <the public key>
```

The one sudoers line that lets that account run the collector as root lives in
`/etc/sudoers.d/newton-ssh`, mode 0440, root:root. The empty argument is what allows the collector
to run with no argument at all:

```
newton-ssh ALL=(root) NOPASSWD: /usr/local/sbin/newton-ad-samba ""
```

The setup script refuses instead of adopting: a sudoers file of the host that is not the one line of
the script is never overwritten, a local account whose home, shell or password is not the one of the
script stops the script, and a domain account whose primary group is not Domain Users, that is a
member of a group or that is disabled stops it too.

The home of the local account, its `.ssh` folder and the authorized key belong to root, with the
modes 0755, 0755 and 0644. `sshd` reads the key as root, before it drops the privileges of the
session, and `StrictModes` accepts a file in the home of the account that root owns as long as
neither its group nor the others may write it: 0755 and 0644 are not writable by the group or by
the others, so the key is accepted. The account writes nothing in its home: the forced command of
the key is the collector, and it runs as root.

The setup script refuses two more things, because both of them would give the account more than the
collector needs: a `.ssh` folder that holds a file other than `authorized_keys` (a planted
`authorized_keys2` would be an authorized key of another kind, and it would survive the run), and a
local account that is in a group besides its primary one (`id -Gn newton-ssh` must print the
primary group only).

The collector refuses a run whose `SUDO_USER` is anything but `newton-ssh` (exit 1), and reads
the identity of the domain account `newton-audit` from the directory. When `SUDO_USER` is missing
or the lookup of the domain account fails, the run exits 1.

## The directory

The collector reads `sam.ldb` through the samba python bindings:

```python
lp = LoadParm()
lp.load_default()
db = SamDB(url=lp.private_path("sam.ldb"), session_info=system_session(), lp=lp)
```

`ldbsearch` is never used: the LDIF it writes rewrites SIDs and security descriptors as text. The
security descriptor comes with the control `sd_flags:1:5` (owner and DACL, never the SACL) and is
base64 in the document. The collector asks for the descriptor by name as well, because the real ldb
returns only the attributes a search names: with the control alone the rows of the domain head and of
the AdminSDHolder carried no descriptor (measured on the lab DC on 2026-11-08). Every other value is
the raw bytes of the directory as text, and a value that is not text makes the query that brought it
an error.

The settings of the collector host are the nine loadparm parameters of SPEC-1.3 section 7, read
from `lp.get()`, and they are collected only when the host is a domain controller (`server role` is
`active directory domain controller`).

The SYSVOL is `<lp.get("path", "sysvol")>/<realm lower>/Policies`, the same layout Samba
provisions: the second argument of the get of the loadparm is the name of a share and not a default
value (measured on the lab DC on 2026-11-08: `lp.get("realm")` is the realm, `lp.get("realm", "")`
is None and `lp.get("path", "sysvol")` is the path of the sysvol share), and a base that is not an
absolute path is refused. The folders of a GPO are looked up without their case, because Samba
provisions them in upper case (`MACHINE` and `USER`, measured on the lab DC on 2026-11-08) and
Windows in mixed case.

The walk of the SYSVOL is the collector's own and it is done by descriptor. The base is opened
with `O_DIRECTORY | O_NOFOLLOW`, every folder is opened relative to the descriptor of its parent
and every file is opened relative to the descriptor of its folder, so no path string is ever opened
below the base: a name that is swapped for a link between the listing and the open is refused, and
the link is never followed. A file is opened with `O_NOFOLLOW` and `O_NONBLOCK` and must be a
regular file of at most four mebibytes, so a named pipe never hangs the collector and a link out
of the SYSVOL never brings a file in. A file that is a symlink or another special file is counted in
`skipped_special`, a file that is too big or that does not parse is counted in `parse_refused`, and
so is every entry past the cap of the walk (10000 entries in one directory and a depth of 8).

The path in the document carries only the fixed names of the spec
(`Machine/Preferences/Groups/Groups.xml`), so that the document of the two collectors is the same
and so that the name of a file of the SYSVOL never reaches the document. The seven file names of a
GPO are `Groups.xml`, `Services.xml`, `ScheduledTasks.xml`, `DataSources.xml`, `Drives.xml`,
`Printers.xml` and `Registry.xml`, matched without their case; any other XML file with a cpassword
is reported as `Machine/Preferences/other.xml`.

The template of a GPO (`GptTmpl.inf`) is read as UTF-16 (it has a byte order mark) and falls back
to UTF-8 without one. Only the keys the checks of Newton read are emitted, and only when their
value is a number. A key that no check reads is dropped silently: the template of a stock Samba
domain controller holds ten keys of the `[System Access]` section and one of the `[Kerberos Policy]`
section that Newton does not read, and a key that is not read is not a refusal. A key that is read
and whose value is not a number is counted in `parse_refused` and never emitted, so the text of a
file of the SYSVOL never reaches the document. Every case variant of the folders that hold the
template is read, the way the walk reads every case variant of the folder of a scope: two variants
that hold a key with the same value emit it once, and two that do not agree on it emit neither value
and are counted once in `parse_refused`. The items of the files count against the byte budget of the
document as the rows of the queries do.

## Running it by hand

As root, on the DC:

```
sudo -n /usr/local/sbin/newton-ad-samba > out.json
```

The document is on stdout; stderr carries only the refusal messages. Exit codes: 0 when a document
was produced, 1 when no document could be produced, 2 on a forbidden-list refusal, an unsafe install
or an argument.

Two runs on the same domain should agree on `querysetsha`, `domain` and `identity`. Check the
document against the contract in `docs/proposals/ad/SPEC-1.3.md` section 5 before handing it to
Newton.

## What the collector never does

It never reads stdin, never takes an argument, never runs anything dynamic, never prints an
exception message, and never puts a cpassword value, a user name or file content from SYSVOL into
the document. GPP files are refused when they contain `<!DOCTYPE` or `<!ENTITY` and are parsed with
the standard library, which reads no DTD and expands no entity. A file is decoded the way the
Windows collector decodes it: a byte order mark picks UTF-8, UTF-16 little endian or UTF-16 big
endian, and a file without one is read as UTF-8 with the replacement characters. A file that still
does not parse is counted in `parse_refused` and never skipped silently.
