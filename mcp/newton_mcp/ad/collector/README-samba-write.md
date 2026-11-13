# Samba AD write helper (`newton-ad-samba-write`)

The helper runs on the Samba domain controller as root. It is the write half of the Newton 1.4
contract (`docs/proposals/ad/SPEC-1.4-REQUEST.md`): it reads one JSON request on stdin, changes the
directory under a signed approval, and puts the change back when the approval never comes. The read
half is the collector (`newton-ad-samba`), and the plan that feeds the helper is built by Newton
(`mcp/newton_mcp/ad/write/`).

The helper is a standalone Python 3 script. It imports nothing of Newton, so it can be installed on
a DC that knows nothing about the Newton machine.

## What it does

One run of the helper is one request and one answer:

| mode | what it does |
|---|---|
| `read` | answers with what this DC sees: `live`, `ids` and the `facts` of the target |
| `apply` | checks the token, arms the undo, writes the after-image and reads it back |
| `confirm` | re-reads the target and cancels the timer of the undo |
| `abort` | runs the undo at once |
| `status` | answers with the state of a transaction |

The answer is one JSON object on stdout, `{"v":1,"code":<code>, ...}`. The exit code is 0 whatever
the outcome; a non-zero exit means the helper itself crashed. The codes are `ok`, `schema`,
`bad_token`, `expired`, `replay`, `not_found`, `conflict`, `privileged`, `denied`, `unavailable`,
`not_pdc`, `risk_mismatch` and `error`.

Every write is one atomic LDAP modify: the message holds the exact old value with `FLAG_MOD_DELETE`
and the new value with `FLAG_MOD_ADD`, and it holds the name of the object, because that is the
shape the bindings take: `modify(message)` and not `modify(dn, message)`. A stale old value answers
16 (a conflict), a write outside the delegation of `newton-ops` answers 50 (a denial) and a missing
object answers 32. A move of an object is not a modify: it is a `rename` of it, because a modify of
the distinguished name answers 53 on Samba. A new user is not a modify either: it is an `add` of
one dict that holds the name and the `objectClass` of the object.

The `tokenGroups` of an object are only given by the directory in a base search on one name, so the
helper asks for them in no other search: a subtree search that names them is refused by Samba.
The names of the accounts in the ids of a read are lowercased, because the request schema of the
contract only accepts a lowercase name: a real `Administrator` comes back as `administrator`.

Only the domain controller that holds the PDC emulator role may apply: the head of the domain names
the owner of the role in `fSMORoleOwner`, and it must be the NTDS Settings object of this DC, the
one the rootDSE of this DC answers in its `dsServiceName`. Any other DC answers `not_pdc`.

The helper derives the risk of the change itself, from its own read of the target, and refuses a
request whose `risk` is not the one it derives (`risk_mismatch`). The privileged set is the one of
SPEC-1.4-REQUEST section 5; it is walked here with a breadth first walk of the `memberOf` values,
a visited set and a depth cap of 32, and the matching rule `1.2.840.113556.1.4.1941` is not used
because it is unmeasured on Samba. The walk fails closed: a chain that reaches the cap, a name of
the chain that cannot be read, and a write account whose `tokenGroups` are missing, empty or hold a
value that is not a SID all count as privileged. A privileged account is only touched by `uac-clear`,
`enc-types` and `unlock`; every other verb on it is refused with `privileged`.

The transaction store is `/var/lib/newton-ad/tx`. Every mode but `read` holds an exclusive `flock`
on `/var/lib/newton-ad/tx/.lock` for the whole run. Every run first undoes the armed records whose
deadline has passed: the sweep covers a reboot or a lost timer, and it never confirms anything.

The undo is armed with `systemd-run` and cancelled with `systemctl stop`. Both commands run with an
argv list, never through a shell.

## Its files

| file | mode | what it is |
|---|---|---|
| `/usr/local/sbin/newton-ad-samba-write` | root 0755 | the helper itself |
| `/etc/newton-ad/approval.key` | root 0600 | the key K of the approval: 64 lowercase hex and a newline |
| `/etc/newton-ad/device.txt` | root 0644 | the name of the device that stands for the domain, the same on every DC of the domain: `^[a-z][a-z0-9-]{0,31}$` |
| `/etc/newton-ad/ops.keytab` | root 0600 | the identity of the write account: the keytab of `newton-ops` on this DC |
| `/var/lib/newton-ad/tx/` | root 0700 | the transaction store: one `<txid>.json` per transaction |
| `/run/newton-ad/` | root 0700 | the credential caches of the helper: one fresh file per bind |

Each of the three files of the configuration is opened without following a link and is checked with
`fstat` on the descriptor of the open file: it must be a regular file of root with the mode above.
The install is checked the same way: the helper, the three files and every directory of the install,
up to the root of the filesystem, must be owned by root and must not be writable by their group or by
the others. The check runs before the samba bindings are imported.

## The identity of the write account

The helper never holds the password of `newton-ops`: no password is stored on the DC and none is
moved from one DC to another. The identity is the keytab of the account, and it is made on **each**
DC from that DC's own `sam.ldb`, once the account has replicated there:

```
samba-tool domain exportkeytab /etc/newton-ad/ops.keytab --principal=newton-ops@<REALM>
```

The file is root 0600. The helper takes a ticket from it with

```
kinit -k -t /etc/newton-ad/ops.keytab -c FILE:/run/newton-ad/ccache-XXXX newton-ops@<REALM>
```

and binds over LDAP with that ticket, as the measured code of SPEC-1.4-REQUEST section 9 does: the
realm and the workgroup of the loadparm, the kerberos state `MUST_USE_KERBEROS` and the named
cache. The credentials are never guessed: a guess would leave the principal as `root` and the bind
would fail.

The cache is a fresh file of mode 0600 in `/run/newton-ad`, a directory of root with the mode 0700
that the helper creates when it is not there. The cache is removed when the bind is done. A keytab
that is missing, that is not a regular file of root with the mode 0600, or a `kinit` that fails,
answers `unavailable`: the helper never binds with a password instead.

The records are never deleted, so a transaction id can never be replayed. A record holds the request
without its secret and without its token, the state of the transaction, its deadline, what the undo
restored and the conflicts it found. The state is `undone` only when the undo restored the value:
an undo that met a conflict, an error, or an object that is not there any more leaves the record in
`undo_failed`. Only an armed transaction may be aborted; the timer of the undo of a transaction
that is not armed changes nothing.

The secret of a `user-create` is in the request and in nothing else: it is in no record, in no
answer and in no line of the log.

## The login

The local account `newton-ops-ssh` logs in and runs the helper through one `NOPASSWD` sudoers line:

```
newton-ops-ssh ALL=(root) NOPASSWD: /usr/local/sbin/newton-ad-samba-write ""
```

and its `authorized_keys` carries a forced command and no port forwarding:

```
restrict,command="sudo -n /usr/local/sbin/newton-ad-samba-write" <key>
```

The helper refuses to run unless `SUDO_USER` is exactly `newton-ops-ssh`, and it refuses the undo
(`--undo <txid>`) when `SUDO_USER` is set at all: the undo runs from the timer of systemd, never
through the SSH channel.

## Running it by hand

As `newton-ops-ssh`, on the DC:

```
echo '{"v":1,"mode":"status","device":"<the name of this dc>","txid":"<32 hex>"}' \
  | sudo -n /usr/local/sbin/newton-ad-samba-write
```

The answer is on stdout; stderr carries the refusal lines. The answer never holds the secret of a
request.

## What the helper never does

It never takes a filter, a DN or a free text from a request, never runs a command through a shell,
never writes the secret anywhere, never holds the password of the write account, and never deletes a
record.
