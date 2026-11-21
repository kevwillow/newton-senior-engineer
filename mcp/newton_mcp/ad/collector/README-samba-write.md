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
| `read` | answers with what this DC sees: `live` (the planning image), `outcome` (the image Newton verifies every DC with: a value the account cannot read is left out), `ids` and the `facts` of the target |
| `apply` | answers `replay` when a record of the transaction is already there, before the token and the approval window are checked (a retry of an apply this DC holds answers `replay`, never `bad_token` or `expired`); then checks the token, arms the undo, writes the after-image and reads it back |
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
on `/var/lib/newton-ad/tx/.lock` for the whole run. Every run first runs the undo of each armed record
whose deadline has passed (the sweep). Each record is undone on its own: one that is malformed (a
request that is not an object), or whose bind or undo raises, is logged and left armed, and it never stops the others or the mode that runs the sweep, and a record that cannot be read is never taken for absent: a read of it that raises (a denied access, an IO error) makes `status`, `confirm`, `abort` and the timer answer `error` and write nothing, and the sweep leaves it for a later pass. An undo that
ran records `undone` when it restored the value and `undo_failed` when it did not; `undo_failed` is
final and is not tried again; an undo whose outcome is unknown stays armed and is tried again. An
unlock that is written is recorded `confirmed`, or stays armed when that record cannot be written. An
unlock has no undo: the sweep reads the account again and records it `confirmed` (the after-image), or
leaves it armed (the before-image included: its write may still land, so it is never recorded `refused`). It reads an armed unlock again only for an hour
after its `undo_at`; an unlock it could not settle by then stays armed and is not read again.
A final record (`undone`, `undo_failed`, `confirmed` or `refused`) moves to `/var/lib/newton-ad/tx/done/`
(root 0700, created by the helper) once seven days have passed its `undo_at`, so the sweep, which lists only the
store itself, no longer reads it. `status`, `confirm`, `abort`, the undo and the replay check still find it there, and
nothing is ever deleted. A record that cannot be moved stays in the store for a later pass.

The undo is armed with `systemd-run` and cancelled with `systemctl stop`. Both commands run with an
argv list, never through a shell. The one-shot timer lives under `/run`, so a reboot drops it, and an
undo whose run fails (a bind or an LDAP error) is not tried again by it. The setup therefore installs
a persistent timer, `newton-ad-sweep.timer`, which runs `newton-ad-samba-write --sweep` once after boot
and about once a minute: an armed change whose deadline has passed is put back then. A DC set up
before the sweep timer existed retries only at the next Newton request; run the write setup again to
install it.

## Its files

| file | mode | what it is |
|---|---|---|
| `/usr/local/sbin/newton-ad-samba-write` | root 0755 | the helper itself |
| `/etc/newton-ad/approval.key` | root 0600 | the key K of the approval: 64 lowercase hex and a newline |
| `/etc/newton-ad/device.txt` | root 0644 | the name of the device that stands for the domain, the same on every DC of the domain: `^[a-z][a-z0-9-]{0,31}$` |
| `/etc/newton-ad/ops.keytab` | root 0600 | the identity of the write account: the keytab of `newton-ops` on this DC |
| `/var/lib/newton-ad/tx/` | root 0700 | the transaction store: one `<txid>.json` per transaction |
| `/var/lib/newton-ad/tx/done/` | root 0700 | the archive of final records older than seven days past their `undo_at` |
| `/run/newton-ad/` | root 0700 | the credential caches of the helper: one fresh file per bind |
| `/etc/systemd/system/newton-ad-sweep.service` | root 0644 | runs `newton-ad-samba-write --sweep` once |
| `/etc/systemd/system/newton-ad-sweep.timer` | root 0644 | starts that service 60 s after boot and every 60 s |

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

The records are never deleted, so a transaction id can never be replayed. A record is created
`refused` (nothing is written yet) and reads `armed` only once its undo timer is armed, right before the write; a
store that refuses that armed record stops the apply with `error` before anything is sent. On this helper a record write that fails
is read back, and the helper acts on what the disk holds: `write_record` can fail after the record replaced the old
one (the flush of the directory failed; a read-back that fails counts as the armed record having landed), so an armed record that landed is written `refused` again and nothing is
sent, and an armed record of a write that was never sent that cannot be written `refused` again answers with
`unmarked` (an unlock is never `unmarked`). On this helper a refusal after the undo timer was armed cancels the
timer, and when its refused record cannot be written it answers with `unmarked`, and with `error` in place of
`conflict` (a move whose rename answered 32 is such a refusal). A record holds the request
without its secret and without its token, the state of the transaction, its deadline, what the undo
restored and the conflicts it found. The state is `undone` only when the undo restored the value, or
found the before-image already there (a new user counts as put back only when the object of its created GUID is gone; one with no
recorded GUID is never `undone` from a lookup by its name: it is left in place and recorded `undo_failed` with its
planned DN). An
undo whose write failed without a conflict reads the target again, since its answer may be lost
while the write landed: the before-image there is `undone`. An undo that met a conflict, an error
the server itself answered, or a moved or changed object leaves the record in `undo_failed`. An
undo whose outcome is unknown (it raised, or its write, the delete of a new user included, got a
code the server did not answer itself and the target then cannot be read or still shows the after-image) leaves the record armed, so the
timer or the sweep runs it again. A new user whose undo facts are missing right after the add is
put back at once, and only by its objectGUID: with the GUID read, the object of that GUID is
deleted wherever it is (`undone`; `undo_failed` with the GUID when it is still there after the
delete; armed when it cannot be looked for again); with no GUID nothing is deleted, since an
account at the planned DN may not be Newton's, and the record is `undo_failed` with the DN.
Every delete, modify and rename the helper sends, in an apply and in an undo, names its object by
the GUID form of its DN (`<GUID=...>`, which Samba resolves inside the one request), never by a DN
a search answered earlier: the object written is never an account somebody made at that DN after
moving Newton's away (the machine account quota is written on the domain head by its DN, which cannot
be moved). Three names inside a write are still DNs read just before it: the member value of a
membership change, the new parent of a move and the parent of a new user. A member or an OU somebody
moves away and replaces at that DN in that moment would be the one written, and the undo of that
membership, which matches the member by GUID, then records `undone` while the other account stays in
the group (a known limit, in the CHANGELOG). The GUID of a user Newton creates is read right after the
add, by its planned DN, so an account that replaces it in that moment is the one recorded, and its undo
would delete that account. The GUID form was not run live on the lab DC; tests cover it.
Whether a member is in a group is decided in one search: the group is read by its GUID with the
extended DN control (`extended_dn:1:1`), and each member value comes with the GUID of the object it
names, so the member is matched by its GUID, never by a DN read in another search. A member
somebody moves between two reads, even moves back, never reads as out of the group. A member value
that comes without its GUID makes the presence unreadable, never "absent". The control was not run
live on the lab DC; tests cover it.
The helper binds as the DC's account, so the directory's ACLs apply: an attribute it cannot read is
left out of the answer, like one that is not there. A group that answers no member value (empty, or
a member list the account cannot read) is never taken for "the member is out": the undo of a
membership then writes, and the server checks the write against the values it holds; the read-back
and the confirm of a member-add read it as a target that cannot be read (a member-remove takes it
for its after-image, a known limit). A missing quota, a missing `lockoutTime` and a missing
`msDS-SupportedEncryptionTypes` (unless removing it is the change) are read as a target that cannot
be read too, never as 0 or as "no value", and the enc-types undo writes the remove when it reads
no value. The `read` mode answers the same image as `outcome`, which Newton verifies every DC with
(each DC binds as its own account, so a replica that holds another value it cannot read never shows
the after-image, a removal's after-image aside), and Newton refuses to plan a change whose before-image the account cannot read
(a quota, a `userAccountControl`, a moved object's parent). A new user counts as gone only when a
base search of its GUID name (`<GUID=...>`) answers `LDB_ERR_NO_SUCH_OBJECT` (Samba's extended DN
module resolves the name as the system; an object the account cannot see at all answers the same, a
known limit), never from a search
on `objectGUID` that finds nothing (a filter on an `objectGUID` the account cannot read matches
nothing); a base search that answers no entry is a user the account cannot read, never gone.
The apply is refused with `conflict` (with `live` and `armed`) while another armed record names
the same target (the same value of the same object; an unlock has no undo and is never counted):
that record's undo could write the before-image over this change once confirmed. Nothing is armed
or written, and a store that cannot be listed or a record that cannot be read answers `error`.
The check reads only the store of the domain controller it runs on: if the PDC role moves while a change is still armed on the old
PDC, a change of the same target applied on the new PDC is not refused, and the old PDC's undo can
write the earlier before-image over it when the target shows the same after-image (a known limit).
A write that fails for a reason other than a conflict is recorded by what the directory then shows:
the before-image after an error the server itself answered is `refused` (nothing was written); the
before-image after a code that may be the client's own (a lost or busy connection) stays armed, so
the timer runs the undo at the deadline; the after-image after a code that may be the client's own
runs the undo at once, except that a new user found at its DN is left in place and recorded
`undo_failed` with that DN (the object there may not be the one Newton's add made); the after-image
after an error the server itself answered is somebody else's same change (the write is atomic, so
nothing of Newton's was written): it is recorded `refused` with the conflict, the timer is cancelled,
the undo never runs and the answer is `conflict` (an unlock is refused too); after any error the server itself
answered, the helper first marks the record (`answered`) so no later undo of it writes anything, cancels the timer
even when the refused record cannot be written; when that record cannot be written, the answer is the write's own code
(`error` for one that maps to `conflict`), never `conflict`; a store that takes neither the mark nor the refused
record (a full disk, say) leaves the record armed with no mark, which the timer and the sweep cannot tell from a write
whose answer was lost: the answer then carries `unmarked`, and Newton reports `apply_unknown` and tells the owner that
the undo may write the before-image over somebody else's change (a known limit; an unlock is never `unmarked`); any other value is
somebody else's change: after an error the server itself answered nothing of Newton's was written,
so it is recorded `refused` with the conflict and answered `conflict`; after any other code Newton's
write may have landed before that change, so the outcome is unknown: the record is `undo_failed`
with the conflict, the timer is cancelled so the undo never writes over the other change (an unlock
stays armed), and the answer keeps the write's code with the `live` value. A target that cannot
be read again, including a move whose current parent, a domain head or a `userAccountControl` that
cannot be read, stays armed (after an error the server itself answered, the mark makes the timer or the sweep record it
`refused` and write nothing). Only an armed transaction may be aborted, and never an unlock, which has
no undo; the timer of the undo of a transaction that is not armed changes nothing.

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
(`--undo <txid>`) and the sweep (`--sweep`) when `SUDO_USER` is set at all: both run from the timers
of systemd, never through the SSH channel.

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
