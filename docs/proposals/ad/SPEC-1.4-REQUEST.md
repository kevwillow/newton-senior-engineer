# SPEC 1.4: the write request (2026-11-08)

This is the one contract shared by the four parts of the write path:
- the Newton side, in Python, newton-approve included;
- the Windows write helper, `write.ps1`;
- the Samba write helper, `newton-ad-samba-write`;
- the setup, `newton-ad-setup`.

The design is DESIGN-1.4.md. Where the code and this file disagree, this file states the contract.

## 1. Transport

The helper takes no arguments over SSH. It reads one JSON object on stdin, at most 64 KiB of UTF-8, and writes one JSON object on stdout. It exits 0 whatever the outcome; a non-zero exit means the helper itself crashed.

The only other way in is the undo argv, used by the local undo timer or task (section 7) and never through SSH:
- **Samba:** `--undo <txid>`, refused when `SUDO_USER` is set.
- **Windows:** `-Undo <txid>`, refused when `SSH_CONNECTION` or `SSH_CLIENT` is set.

The txid matches `^[0-9a-f]{32}$` before it is used in any path.

Every DC's helper is configured with the name of the device that stands for the domain (`device.txt` next to the key, section 8), the same name on every DC of the domain. A request whose `device` differs is refused with `schema`. `device` names the domain; every DC in the domain holds the same K.

## 2. Request fields

Every field is required unless marked optional. All of these are refused with code `schema`, at every level:
- a field outside this list;
- a duplicate key, or two keys that differ only in case;
- a wrong type, or a boolean where an int is expected;
- an int that is not written in JSON as `^(0|[1-9][0-9]*)$` (no sign, fraction or exponent);
- a value outside its pattern.

Both helpers check the raw JSON text for the int form and for duplicate keys. Use Python's `object_pairs_hook`; on Windows, use a scanner over the raw text before `ConvertFrom-Json`.

| Field | Type | Pattern / range |
|---|---|---|
| `v` | int | exactly `1` |
| `mode` | str | `apply`, `confirm`, `abort`, `status` or `read` |
| `device` | str | `^[a-z][a-z0-9-]{0,31}$` |
| `txid` | str | `^[0-9a-f]{32}$` (not in `read`) |
| `verb` | str | section 3 (in `apply` and `read`) |
| `target` | object | section 3 (in `apply` and `read`) |
| `before` | object | section 3 (in `apply`) |
| `after` | object | section 3 (in `apply`) |
| `window` | int | 120..1800: the undo deadline, in seconds after apply (in `apply`; for `unlock` it must be 120 and is unused) |
| `nbf`, `exp` | int | the approval window, in UNIX seconds, 10 digits, with `nbf < exp` and `exp - nbf <= 1800` (in `apply`) |
| `token` | str | `^[0-9a-f]{64}$` (in `apply`) |
| `risk` | str | `LOW`, `MED` or `HIGH` (in `apply`; section 4) |
| `secret` | str | `user-create` only: the initial password, 16..128 printable ASCII (0x21..0x7e) |

Patterns:
- GUID: `^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`. This is the standard string form of objectGUID: Python `str(uuid.UUID(bytes_le=raw))`, PowerShell `([guid]::new($raw)).ToString()`. Never `uuid.UUID(bytes=raw)`.
- SID: `^S-1-5-21-[0-9]{1,10}-[0-9]{1,10}-[0-9]{1,10}-[0-9]{1,10}$`.
- SAM: `^[a-z0-9][a-z0-9._-]{0,19}$` for users; a computer's is the same plus a trailing `$`.

## 3. Verbs

Every value is an int, a GUID, a SID, a SAM, or one of the words `present` and `absent`. No DN, filter or free text ever appears in a request.

Every account target carries `guid`, `sid` and `sam`. The helper finds the object by `guid` and refuses with `not_found` unless both its objectSid equals `sid` and its sAMAccountName equals `sam`, compared case-insensitively. A group or member reference carries the same three fields, prefixed: `group_guid`, `group_sid`, `group_sam`, `member_guid`, `member_sid`, `member_sam`.

"DC account" means userAccountControl has 0x2000 (SERVER_TRUST_ACCOUNT) or 0x4000000 (PARTIAL_SECRETS_ACCOUNT).

| Verb | `target` keys | `before` / `after` | Rules the helper enforces |
|---|---|---|---|
| `uac-clear` | `guid sid sam bit` | `{uac}` | `bit` in {4194304, 32, 128, 524288, 65536} (the helpers' table); `before.uac & bit != 0`; `after.uac == before.uac & ~bit`. The plan refuses bit 524288 (TRUSTED_FOR_DELEGATION), so no request for it reaches a helper, whose own refusals of it stay: the directory lets only a holder of SeEnableDelegationPrivilege change it, and the write account does not hold that privilege by design (measured on both lab domains on 2026-11-13: LDAP error 50). The owner clears it with the admin tools |
| `disable` | `guid sid sam` | `{uac}` | user or computer only; refused on a DC account and on RID 500; `before.uac & 2 == 0`; `after.uac == before.uac \| 2` |
| `enable` | `guid sid sam` | `{uac}` | user or computer only; `before.uac & 2 != 0`; `after.uac == before.uac & ~2` |
| `enc-types` | `guid sid sam` | `{etypes}`: int, or `absent` (treated as 0 for the rules) | `after & 3 == 0` (DES never enabled); `(after & ~63) == (before & ~63)`; `after != before` |
| `unlock` | `guid sid sam` | `{lockout}` | `before.lockout > 0`; `after.lockout == 0`; no undo is armed |
| `member-add` | `group_* member_*` | `{member: absent}` → `{member: present}` | the group is not privileged (section 5); the group is in a delegated location |
| `member-remove` | `group_* member_*` | `{member: present}` → `{member: absent}` | the same |
| `maq` | `guid` | `{maq}` | the target's objectClass includes `domainDNS`; `after.maq` in 0..1000 |
| `user-create` | `parent_guid sam` | `{object: absent}` → `{object: present}` | `absent` means no object anywhere in the domain has that sAMAccountName, or the UPN `sam@<domain DNS name>`. The new user gets cn = sam, UPN = `sam@<domain DNS name>`, UAC 514 (512 + 2: normal account, disabled), and the parent with that GUID |
| `move` | `guid sid sam` | `{parent}`: a GUID | `after.parent` is an organizationalUnit or a container; neither the old nor the new parent is the Domain Controllers OU or inside it; refused on a DC account |

## 4. The digest and the token

The canonical bytes are these lines, each ending in `\n` (0x0A), in this order, in ASCII only:

```
newton-ad-request-v1
device=<device>
txid=<txid>
verb=<verb>
target=<k1>=<v1>,<k2>=<v2>,...
before=<k>=<v>,...
after=<k>=<v>,...
window=<window>
risk=<LOW, MED or HIGH>
secret=<sha256 hex of the secret's ASCII bytes, or ->
helper=1
```

- Pairs are joined by `,`.
- Keys are sorted ordinally, by byte value: Python `sorted()` on str, PowerShell `[string]::CompareOrdinal`.
- An int is decimal with no sign and no leading zeros.
- Every other value is the string exactly as parsed.
- There is no trailing `,`.

Then:
- `digest = sha256(canonical bytes)`, as 64 lowercase hex;
- `token = HMAC-SHA256(K, "newton-approval-v2\n" + digest + "\n" + nbf + "\n" + exp + "\n")`, as 64 lowercase hex. This is `approval_token` in `mcp/newton_mcp/approve.py` byte for byte.

**Who computes the digest:**
- `newton-approve` builds the canonical bytes itself from the plan's fields. It shows every field to the owner, with each target's sam, and HMACs only the digest it computed. It never reads a digest from the plan record, because the agent can write that file.
- The helper builds the canonical bytes itself from the request it parsed.
- Neither ever takes a digest as input.

**Risk is signed and re-derived.** `risk` is a required string field in `apply`, one of `LOW`, `MED` or `HIGH`. It is in the canonical bytes, so the owner approves the level they were shown. The helper computes the level itself, from its own read of the target, before step 4 of `apply`:
- HIGH when any object in the target is privileged (section 5), has `adminCount` 1, or is a DC account;
- otherwise LOW for `unlock`;
- otherwise MED.

When its level differs from the request's, it refuses with `risk_mismatch` and writes nothing. newton-approve shows the HIGH warning from the plan's `risk`, and the helper's check makes a lowered level fail.

**Refusals, checked in this order:**
1. `bad_token`, unless the tokens are equal under a constant-time compare;
2. `expired`, unless `nbf - 60 <= now <= exp` on the DC clock (60 s of allowed skew);
3. `replay`, when the record file already exists (section 7).

**Test vector.** The tests of every component use:
- `K = "11" * 32`, i.e. 32 bytes of 0x11;
- the `uac-clear` request in `mcp/tests/ad/fixtures/write-request-v1.json`;
- the expected canonical bytes (base64), digest and token in `write-request-v1.expected.json`.

The Newton side generates the fixture once with the Python implementation. The two helpers must reproduce it exactly.

## 5. Privileged objects

The privileged set is exactly SPEC-1.3's:
- the RIDs 512, 516, 518, 519, 520, 521, 498, 526 and 527, under the SID of ANY domain in the forest (518, 519, 527 and 498 live under the forest root's SID);
- the BUILTIN groups S-1-5-32-544, 548, 549, 550 and 551;
- everything nested in any of them.

1.4 adds three for writes:
- 525 (Protected Users);
- S-1-5-32-552 (Replicator);
- any object whose `adminCount` is 1.

**Nesting** is checked transitively at the time of the write. Neither helper uses the matching rule `1.2.840.113556.1.4.1941` (LDAP_MATCHING_RULE_IN_CHAIN), which is unmeasured on Samba: both walk the `memberOf` values recursively, with a visited set and a depth cap of 32, and the primary group counts as a membership. The walk fails closed: a chain that reaches the cap and a group of the chain that cannot be read both count as privileged.

**The rules:**
- `member-add` and `member-remove` on a privileged group are refused with `privileged`.
- An account target that is privileged is allowed only for `uac-clear`, `enc-types` and `unlock`. The Newton plan marks those HIGH.
- Before every write, the helper reads the write account's own `tokenGroups`, which is transitive. It refuses with `privileged` if any entry is in the set.
- Rights granted directly by an ACL, such as DCSync, are 1.3 check AD-A-51's job. The setup runs that check against `newton-ops` and refuses to install if it fails.

## 6. Modes and responses

The response is `{"v":1,"code":<code>, ...}`. The codes are `ok`, `schema`, `bad_token`, `expired`, `replay`, `not_found`, `conflict`, `privileged`, `denied`, `unavailable`, `not_pdc`, `risk_mismatch` and `error`.

All modes except `read` take an exclusive lock on the transaction store for their whole run:
- Samba: `flock` on `/var/lib/newton-ad/tx/.lock`;
- Windows: the file `C:\ProgramData\Newton\ad\tx\.lock`, opened with `FileShare.None` and held for the run; an open that fails is retried every 200 ms for up to 30 s, then the result is `unavailable`. (A plain account generally lacks SeCreateGlobalPrivilege, so a `Global\` mutex is not used.)

The start-up sweep (section 7) takes the same lock.

### `apply`

`apply` runs only on the DC that holds the PDC emulator role (the domain head's `fSMORoleOwner`). On any other DC it returns `not_pdc`. Its steps:

1. Schema check, token check.
2. Create the record file exclusively: `O_CREAT|O_EXCL`, or `FileMode.CreateNew`. If a record of the txid already exists, return `replay`. The Windows helper checks for an existing record under the store lock first and answers `replay` there; a `CreateNew` collision after that check means another writer broke the lock, and it answers `error`, never `replay`, having changed no record.
3. Look up the target.
4. Compare the live values with `before`. A difference returns `conflict` with `live`, and the record's state becomes `refused`.
5. Arm the undo for now + `window`, and store `undo_at`.
6. Write `after` in ONE LDAP modify that deletes the exact old value and adds the new one. For `before` = `absent`, it adds only; for `member`, it adds or deletes that one value. If the server answers noSuchAttribute (16), or the entry was changed meanwhile, the result is `conflict`: disarm the undo and set state `refused`.
7. Read the result back. Store in the record:
   - for `user-create`, the new objectGUID as `created` and its `uSNChanged`.

The response is `ok`, with `live` and `undo_at`, plus `created` for `user-create`.

If step 6 fails for any reason other than a conflict, run the undo at once and return the error code. The server may have applied the write and lost the answer, so the helper reads the target again first. On Windows: a target that still shows `before` was never written, so the undo is disarmed and the state becomes `refused`; any other value is undone now, and the record says what the undo restored (`undone` or `undo_failed`); a target that cannot be read again leaves the record `armed` and the undo task registered, so the task undoes it at `undo_at`. The Samba helper disarms its timer and runs the undo, which leaves a value that is already `before` alone. A `user-create` whose add failed has no `created` facts, so its undo records `undo_failed` rather than delete an object it cannot identify. An `unlock` arms no undo and is `refused`.

### The other modes

- **`confirm`** `{txid}`.
  1. Re-read the target on this DC. If it no longer shows `after`, return `conflict`.
  2. Otherwise cancel the timer or task, and set state `confirmed`.

  `confirm` on `undone` or `undo_failed` returns `conflict`. Cross-DC verification is the Newton side's job, before it sends confirm.
- **`abort`** `{txid}`. Only an `armed` transaction: run the undo now (section 7). It returns `ok` with `restored` and `conflicts`. On any other state, `confirmed` included, it returns `conflict` and restores nothing. An armed change is one whose confirm was lost: the Newton side confirms as soon as every DC shows `after`, so a cleanly applied change is already `confirmed`. A confirmed change is reversed by a new plan of the opposite change (a `uac-clear` and a `user-create` have no opposite verb: the owner uses the admin tools), and Newton's abort answer says so.
- **`status`** `{txid}`. It returns the state (`armed`, `confirmed`, `undone`, `undo_failed` or `refused`), plus `undo_at`, `restored` and `conflicts`.
- **`read`** `{verb, target}`. It returns, as read on THIS DC:
  - `live`, in the shape of `before` for that verb;
  - `ids`, the full target with every guid, sid and sam filled in. Every sam is LOWERCASED, since the request schema accepts only lowercase sams and the helper compares sams case-insensitively. A real `Administrator` comes back as `administrator`;
   - `facts`: `{"admin_count": int, "dc_account": bool, "privileged": bool, "object_class": [str], "pdc": bool}` for each account or group in the target, keyed `target`, `group` or `member`.  The `pdc` flag says that the DC which answered holds the PDC emulator role: it is how the Newton side finds the domain controller of a domain, which is the only DC that may apply.

  For `read` only, a target may give just the sam fields (`sam`, or `group_sam` and `member_sam`). The helper then finds the object with an equality search on sAMAccountName; the value is already restricted to the SAM pattern. Zero matches, or more than one, is `not_found`. The Newton side uses `read` to resolve names, take the before-image, and verify on every DC. It never needs a token.

The response never contains `secret`, and no record or log stores it. On Windows, build the SecureString with `AppendChar`, one character at a time, never `ConvertTo-SecureString -AsPlainText`, which module logging records.

## 7. The transaction record and the undo

On Windows the transaction store is append-only. The first record is
`<txid>.0.json`; every later state or metadata write creates
`<txid>.<n>.json` with `FileMode.CreateNew`, where `n` is the next integer.
The file with the highest `n` is the current record. A legacy `<txid>.json`
is read as generation zero. Any legacy or numbered record file makes the
txid a replay. Leftover `*.new` files are ignored. Record files are never deleted or rewritten.

Each generation holds:
- the request, minus `secret` and `token`;
- `created` and its uSNChanged;
- `state`, `undo_at`, `restored` and `conflicts`.

Where the store lives:
- **Samba:** `/var/lib/newton-ad/tx/`, root-owned mode 0700. The Samba helper may keep its own record scheme because it runs as root under that private directory.
- **Windows:** `C:\ProgramData\Newton\ad\tx\`. The measured ACL is: SYSTEM and Administrators Full, and newton-ops CreateFiles, Read, Synchronize with (OI)(CI) and NO Delete. A handle that creates a new file may write it; reopening an existing file for write, or replacing, deleting or moving one, is denied.

**The undo** writes the inverse for each attribute, using the same single delete-old/add-new modify as apply: it deletes the `after` value and adds the `before` value, so it writes only when the live value still equals `after`. A noSuchAttribute (16) answer means someone changed the value meanwhile; it records a conflict and leaves the attribute alone. (Measured 2026-11-09 on Samba 4.22.11: this modify works as `newton-ops`, and a stale old value gives 16. `msDS-ReplAttributeMetaData` returned nothing to `newton-ops`, so there is no per-attribute version check.)

For `user-create`, the undo deletes the object whose objectGUID is `created`, and only if all of these hold:
- it is still disabled;
- its uSNChanged equals the recorded one;
- it has no members and no memberOf.

Otherwise it records a conflict. At the end, the state becomes `undone`, or `undo_failed` if any write errored.

**Arming:**
- **Samba:** `systemd-run --unit=newton-ad-undo-<txid> --on-active=<window>s /usr/local/sbin/newton-ad-samba-write --undo <txid>`. Confirm runs `systemctl stop newton-ad-undo-<txid>.timer`.
- **Windows:** a one-shot scheduled task `newton-undo-<txid>` in the root task folder, registered through the COM API as measured in section 9 (S4U, `LogonType = 2`), running as the write account, which runs `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\ProgramData\Newton\ad\write.ps1 -Undo <txid>`. Confirm deletes the task.

**The start-up sweep:** every run of the helper first undoes any `armed` record whose `undo_at` has passed. That covers a reboot or a lost timer. It never confirms anything.

## 8. Files the setup installs

| | Samba | Windows |
|---|---|---|
| helper | `/usr/local/sbin/newton-ad-samba-write`, root 0755 | `C:\ProgramData\Newton\ad\write.ps1`, same ACL rules as `collector.ps1` |
| key K | `/etc/newton-ad/approval.key`, root 0600, 64 hex + `\n` | `C:\ProgramData\Newton\ad\approval.key`, ACL: SYSTEM, Administrators, write account read |
| domain device name | `/etc/newton-ad/device.txt`, root 0644 | `C:\ProgramData\Newton\ad\device.txt` |
| write identity | `/etc/newton-ad/ops.keytab`, root 0600, made on EACH DC by `samba-tool domain exportkeytab /etc/newton-ad/ops.keytab --principal=newton-ops@<REALM>` from that DC's own sam.ldb; no password is ever stored or moved. The helper gets a ticket with `kinit -k -t` into a private ccache and binds over LDAP as `newton-ops`, so AD's delegation applies (section 9) | the SSH session itself runs as `newton-ops` |
| login | local `newton-ops-ssh`; sudoers `newton-ops-ssh ALL=(root) NOPASSWD: /usr/local/sbin/newton-ad-samba-write ""`; authorized_keys `restrict,command="sudo -n /usr/local/sbin/newton-ad-samba-write" <key>` | sshd `Match User <netbios>\newton-ops` (the measured form of the 1.3 audit block) with `AuthorizedKeysFile __PROGRAMDATA__/Newton/ad/write_authorized_keys`, `ForceCommand`, `AllowTcpForwarding no`, `PermitTunnel no`, `X11Forwarding no`, `AllowAgentForwarding no`, `PermitTTY no` |

**What `newton-ops` is delegated** on the OUs and containers the owner names, CN=Users included if named:
- write userAccountControl, msDS-SupportedEncryptionTypes and lockoutTime;
- create and delete user objects;
- write `member` on groups;
- create-child and delete-child of user and computer objects, for move and user-create;
- write `name` and `cn` on user and computer objects, for move. Measured 2026-11-09 on Samba 4.22.11 by an exhaustive search over candidate rights: a rename across two delegated OUs is refused with 50 without both, and works with exactly these added.

On the domain head, it can write ms-DS-MachineAccountQuota. Nothing else.

## 9. Measured on the lab DCs (2026-11-09); build to these facts

**Samba** (dc1.lab.newton.test, Samba 4.22.11), bound as `newton-ops`:
- `SamDB(url="ldap://dc1.lab.newton.test", credentials=c, lp=lp)` binds, with `c = Credentials(); c.guess(lp); c.set_username("newton-ops"); c.set_password(<from ops.secret>); c.set_domain(<NetBIOS domain>)`.
- The atomic modify is one `ldb.Message` holding two elements under distinct keys, for example `m["0"] = ldb.MessageElement(old, ldb.FLAG_MOD_DELETE, "userAccountControl")` and `m["1"] = ldb.MessageElement(new, ldb.FLAG_MOD_ADD, "userAccountControl")`. It succeeds. A stale old value raises `LdbError` 16 (NO_SUCH_ATTRIBUTE).
- A write outside the delegation raises `LdbError` 50.
- `db.add({... "unicodePwd": ('"' + pw + '"').encode("utf-16-le"), "userAccountControl": "514"})` in the delegated OU works, and so does `db.delete(dn)`.
- `fSMORoleOwner` on the domain head and `tokenGroups` on the account's own object are readable.
- `msDS-ReplAttributeMetaData` returns nothing to `newton-ops`, which is why section 7 has no version check.
- **Keytab bind (measured 2026-11-09 on the supernova sandbox, sdc1 and sdc2 of lab2.newton.test, Samba 4.22.11):**
  - `samba-tool domain exportkeytab <file> --principal=newton-ops@<REALM>` works on every DC once the account has replicated there; before that it fails with "No keys found".
  - `env KRB5CCNAME=FILE:<private path> kinit -k -t <file> newton-ops@<REALM>` works, and so does `c = Credentials(); c.set_realm(lp.get('realm')); c.set_domain(lp.get('workgroup')); c.set_kerberos_state(MUST_USE_KERBEROS); c.set_named_ccache('FILE:<path>', SPECIFIED, lp)`, followed by `SamDB(url='ldap://<this DC FQDN>', credentials=c, lp=lp)`. That binds as `newton-ops@<REALM>`.
  - Calling `c.guess(lp)` first, or passing `obtained` 1, leaves the principal as `root@<REALM>`, and the bind fails with NT_STATUS_UNSUCCESSFUL.
  - Bound this way, tokenGroups are 513 and 545 only. A create inside the delegated OU works, and one outside it gives LdbError 50.
  - Replication between the two Samba DCs can lag by minutes (a new user was missing on sdc2 until `samba-tool drs replicate`), so verify polls each DC until its deadline and never checks just once.
- **Measured on real DCs, both platforms:** see `docs/proposals/ad/MEASURED-2026-11-09.md`. In short:
  - the PDC is the DC whose rootDSE `dsServiceName` equals the domain head's `fSMORoleOwner`;
  - the DC container is `OU=Domain Controllers`;
  - a modify of `distinguishedName` gives 53, so a move is a rename/ModifyDN, and a stale source gives 32.

**Windows** (WINDC1.win.newton.test, Server 2025), in a key-authenticated SSH session as `newton-ops`:
- `System.DirectoryServices.Protocols.LdapConnection('<DC FQDN>')` with `SessionOptions.Signing = $true` and `SessionOptions.Sealing = $true`, then `Bind()` with the default credentials, works.
- A `ModifyRequest` with a `Delete` of the old value and an `Add` of the new value succeeds. A stale old value throws "The requested attribute does not exist" (LDAP 16). A write outside the delegation throws "The user has insufficient access rights" (LDAP 50).
- An `AddRequest` with `unicodePwd` (UTF-16LE of the quoted password, as `byte[]`) and `userAccountControl` 514 succeeds; so does `DeleteRequest`.
- `tokenGroups` reads. `msDS-ReplAttributeMetaData` also reads, but the contract does not use it.
- Read values with `.GetValues([string])` and index that array. A single value unrolls to a string in PowerShell, and indexing a string gives a character.
- **The undo task:**
  - The ScheduledTasks cmdlets fail with "Cannot connect to CIM server. Access denied", and `schtasks /NP` gives "Access is denied". Use the COM API: `New-Object -ComObject Schedule.Service`, then `Connect()`, then `NewTask(0)` with `Principal.LogonType = 2` (S4U), then `RegisterTaskDefinition(name, def, 6, $null, $null, 2)`. That registers.
  - The task RUNS only if the account holds SeBatchLogonRight. Without it, the run fails with 0x80070569 (logon type not granted). With it, the task ran as `newtonwin\newton-ops`, and its S4U token wrote userAccountControl over LDAP.
  - The setup must therefore grant SeBatchLogonRight to `newton-ops` through the Default Domain Controllers Policy, or a GPO linked to the Domain Controllers OU, adding it to the existing holders and never replacing them.
- **The SSH login:**
  - sshd has `AllowGroups administrators "openssh users"`, so the setup adds `newton-ops` to the builtin `OpenSSH Users` group, which is not privileged.
  - The key file needs the ACL `SYSTEM:F`, `Administrators:F` and `newton-ops:RX`, as `newton-audit`'s has.
  - A restart of sshd launched as a child of the SSH session dies with the session, so the setup restarts sshd as its own last step.

**The delegation of the Windows setup, one row per grant.**  Every row is granted on each delegated
location (`--ou`) and inherited by its subtree, and every ace is added only when it is missing.  The
read-back of a grant compares the five fields of the rule: the rights, the object type, the
inherited object type, the inheritance and the trustee.

| | The right | The class it is inherited to | The trustee | The measured grant |
|---|---|---|---|---|
| the properties | write `userAccountControl`, `msDS-SupportedEncryptionTypes`, `lockoutTime`, `name` and `cn`; write `member` on groups | the class of the object | `newton-ops` | `dsacls <OU> /I:S /G "<SID>:WP;<attribute>;<class>"` |
| the children | create-child and delete-child, in ONE ace | the class of the child | `newton-ops` | `dsacls <OU> /I:T /G "<SID>:CCDC;<class>"` |
| **the password of a new user** | the right of a password reset (`Reset Password`, `00299570-246d-11d0-a768-00aa006e0529`) | `user` | **CREATOR OWNER (`S-1-3-0`)** | `dsacls <OU> /I:S /G "S-1-3-0:CA;Reset Password;user"` |
| the head of the domain | write `ms-DS-MachineAccountQuota`, not inherited | none | `newton-ops` | `dsacls <domain DN> /G "<SID>:WP;ms-DS-MachineAccountQuota"` |

Thirteen aces per delegated location and one on the head of the domain.

**The right of a password reset is the CREATOR OWNER, and not the write account.**  A `user-create`
with a secret sets `unicodePwd`, and the directory checks the right of a password reset of the
creator of the object.  Measured 2026-11-09 on `WSBXDC1.win2.newton.test`: a `user-create` without a
secret answered `ok`, and a `user-create` with a secret answered `denied` (LDAP result 50), because
the setup granted only `CCDC;user` on the OU.  The right is granted to the CREATOR OWNER of the
location, so the write account may set the password of the accounts it creates and of no other
account: an account that holds the right directly could reset the password of any user of the
location, and a password reset is a change Newton never makes itself (section 1).  The setup
refuses, before any change, when the write account already holds that right on a delegated location
or on an object below it.  Samba needs none of it: the same `user-create` passed live on Samba
4.22.11 without it.

