# Windows AD write helper (`write.ps1`)

The write helper changes Active Directory on the Windows domain controller. It is the 1.4
half of the Newton AD write path: the owner approves a change outside the chat, the helper
checks the approval on the DC itself, writes the change and arms its own undo.

The helper is separate from the read collector and has its own key, its own account and its
own forced command. The 1.3 audit account stays read-only.

## What it does

The helper reads one JSON request on stdin, at most 64 KiB, and writes one JSON object on
stdout. It exits 0 whatever the outcome; a non-zero exit means the helper itself crashed.
The request, the modes and the refusals are the contract of
`docs/proposals/ad/SPEC-1.4-REQUEST.md`.

The other way in is the undo argv, `-Undo <txid>`, used by the undo task and never through
SSH. It is refused when `SSH_CONNECTION` or `SSH_CLIENT` is set, and the transaction id is
checked against `^[0-9a-f]{32}$` before it is used in a path.

The helper:

- scans the raw text of the request itself before `ConvertFrom-Json` sees it, and refuses a
  duplicate key, two keys that differ only in case and any number that is not written in
  the int form `^(0|[1-9][0-9]*)$`;
- refuses a request that is nested deeper than 32 levels, so the scan stays linear in the
  size of the input;
- keeps the text of every string and every number of the request, so a value that the
  parser of PowerShell 7 would turn into a date is the text the request wrote;
- answers `replay` when a record of the transaction is already there, before the token and the approval
  window are checked, so a retry of an apply this DC holds answers `replay`, never `bad_token` or
  `expired` (the answer says only that a record file exists, which the status mode answers too,
  except for a txid none of whose generations parses, which the status answers `not_found`; an
  unparsable generation is skipped and the one below it read);
- computes the canonical bytes of the request, their SHA-256 digest and the approval token
  `HMAC-SHA256(K, "newton-approval-v2\n" + digest + "\n" + nbf + "\n" + exp + "\n")`, and
  compares the token in constant time;
- reads the live values of the target and refuses a request whose before-image does not
  match them (`conflict`);
- re-derives the risk level itself and refuses a request that does not carry it
  (`risk_mismatch`);
- refuses a privileged target, a privileged write account and a domain controller account
  where the contract refuses them (`privileged`, `denied`);
- writes the after-image in one LDAP modify that deletes the exact old value and adds the
  new one, so a value that changed meanwhile is a conflict and is never overwritten;
- moves an object with one `ModifyDNRequest` and never with a modify of
  `distinguishedName`, which the directory refuses with 53;
- arms the undo first, as a one-shot scheduled task, and undoes itself when the owner does
  not confirm in time;
- reads the target again when the write fails for a reason other than a conflict, since the
  server may have applied it and lost the answer: a target that still shows the before-image
  after an error the server answered is refused and the undo disarmed; one that still shows it
  after a failure with no answer from the server (a client timeout, a dropped connection) stays
  armed with its task, since the write may still land; the after-image after a failure with no
  answer from the server is undone at once (an unlock, which has no undo, is confirmed, or stays armed when that record cannot be written); the
  after-image after an error the server itself answered is somebody else's same change (the
  write is atomic, so nothing of Newton's was written): it is refused with the conflict, the task
  is removed, the undo never runs and the answer is `conflict` (an unlock is refused too); after
  any error the server answered, the helper first marks the record (`answered`) so no later undo
  of it writes anything, removes the task even when the refused record cannot be written; when that
  record cannot be written, the answer is `error`, never `conflict`; a store that takes neither the mark
  nor the refused record (a full disk, say) leaves the record armed with no mark, which the sweep (and the
  task, when it is still registered) cannot tell from a write whose answer was lost: the answer then carries
  `unmarked`, and Newton reports `apply_unknown` and tells the owner that the undo may write the
  before-image over somebody else's change (a known limit; an unlock is never `unmarked`); any
  other value is somebody else's change: after an
  error the server answered it is refused with the conflict, and after a failure with no answer
  from the server Newton's write may have landed before that change, so the record is
  `undo_failed` with the conflict and the task is removed, so the undo never writes over the
  other change (an unlock stays armed), and the answer keeps the error code with the `live`
  value; and a target that cannot be read again, including a move whose current parent or an
  account whose `userAccountControl` cannot be read, stays armed so the task undoes it on time
  (after an error the server answered, the mark makes the task record it `refused` and write
  nothing);
  a failure inside that handling after the write was sent leaves the record armed with its task. 16, 20 and 68 are conflicts: an atomic write that wrote nothing;
- records a refusal before the undo is armed in one record of state `refused`, and creates the
  armed record only right before the task and the write; a record write that fails is read back,
  and the helper acts on what the disk holds (a generation can land and its flush to the disk
  then throw; a read-back that fails counts as the armed record having landed), so an armed record that landed is written `refused` again and nothing is sent,
  and an armed record of a write that was never sent that cannot be written `refused` again
  answers with `unmarked` (an unlock is never `unmarked`); a generation whose write failed after
  its file was made (a full disk) stays on the disk, since the store cannot delete it, and the
  current record is the highest generation that can be read and parses; a generation that cannot be read stops the reader, so a torn
  generation never hides the record below it, and a record that cannot be read is never taken for absent: a read of
  the newest generation that throws (a sharing violation, an IO error) makes `status`, `confirm`, `abort` and the
  task answer `error` and write nothing, and the sweep leaves that transaction for a later pass; a Windows store that
  cannot be listed is never taken for empty either: the apply, `status`, `confirm`, `abort` and the task answer
  `error`, and the sweep leaves every record for a later pass;
- refuses an apply with `conflict` (with `live` and `armed`) while another armed record names the
  same target (the same value of the same object; an unlock has no undo and is never counted):
  that record's undo could write the before-image over this change once confirmed. Nothing is
  armed or written, and a store that cannot be listed or a record that cannot be read answers
  `error`. The check reads only the store of the domain controller it runs on: if the PDC role moves while a change is still armed
  on the old PDC, a change of the same target applied on the new PDC is not refused, and the old
  PDC's undo can write the earlier before-image over it when the target shows the same after-image
  (a known limit);
- puts a new user whose undo facts are missing right after the add back at once, and only by its
  objectGUID: with the GUID read, the object of that GUID is deleted wherever it is (`undone`;
  `undo_failed` with the GUID when it is still there; armed when it cannot be looked for again);
  with no GUID nothing is deleted, since an account at the planned DN may not be Newton's, and the
  record is `undo_failed` with the DN;
- sends every delete, modify and rename, in an apply and in an undo, with the GUID form of its
  object's DN (`<GUID=...>`, the group's for a membership), never with a DN a search answered
  earlier, so the object written is never an account somebody made at that DN after moving
  Newton's away. Three names inside a write are still DNs read just before it: the member value of
  a membership change, the new parent of a move and the parent of a new user; a member or an OU
  somebody moves away and replaces at that DN in that moment would be the one written, and the undo
  of that membership, which matches the member by GUID, then records `undone` while the other
  account stays in the group (a known limit, in the CHANGELOG). The GUID of a user Newton creates
  is read right after the add, by its sAMAccountName, so an account that replaces it in that moment
  is the one recorded, and its undo would delete that account. The GUID form was not run live on
  the lab DCs; tests cover it;
- records an undo by what the directory shows: an undo that failed or met a conflict is read
  again, and the before-image is `undone`; a new user with a recorded GUID is looked up again by
  that GUID, never by its planned names, so one somebody renamed is still there (`undo_failed`
  with the GUID), one that is gone is `undone`, and one that cannot be looked up stays armed; a
  new user with no recorded GUID is never `undone` from a lookup by its names (somebody may
  have renamed it): it is left, `undo_failed` with its DN as the conflict; an undo that got no answer from the server while the
  target still shows the after-image, an undo whose outcome cannot be read, or one that cannot be
  recorded, leaves the record armed and the task registered and answers an error. The sweep
  runs the undo of each expired record on its own: one that is malformed or throws stays armed
  and never stops the others.

Every pattern of the helper is anchored with `\A` and `\z`, so a trailing newline never
passes a validation. The bit arithmetic of the contract is 64-bit.

## Files

Install path: `C:\ProgramData\Newton\ad\`.

| file | what it is |
|---|---|
| `write.ps1` | the helper (`mcp/newton_mcp/ad/collector/write.ps1`) |
| `approval.key` | the approval key `K`: 64 lowercase hexadecimal characters and a newline |
| `device.txt` | the name of the device that stands for the domain, the same on every DC of the domain: the name every request of the domain carries |
| `tx\` | the transaction store: one `<txid>.<generation>.json` per state of a change (append-only), never deleted |

The transaction store is `C:\ProgramData\Newton\ad\tx\`. The helper takes the lock of the
store, the file `tx\.lock` opened with `FileShare.None`, for the whole run of every mode
except the read. An open that fails is retried every 200 ms for up to 30 s, and the answer
is then `unavailable`.

## ACL

Administrators and SYSTEM have full control, `newton-ops` has read and execute on the
helper and read on the key, and nothing is inherited from the parent:

```
icacls "C:\ProgramData\Newton\ad" /inheritance:r
icacls "C:\ProgramData\Newton\ad" /grant:r "BUILTIN\Administrators:(OI)(CI)F" "NT AUTHORITY\SYSTEM:(OI)(CI)F"
icacls "C:\ProgramData\Newton\ad" /grant:r "DOMAIN\newton-ops:(OI)(CI)RX"
icacls "C:\ProgramData\Newton\ad\write.ps1" /grant:r "BUILTIN\Administrators:F" "NT AUTHORITY\SYSTEM:F" "DOMAIN\newton-ops:RX"
icacls "C:\ProgramData\Newton\ad\approval.key" /grant:r "BUILTIN\Administrators:F" "NT AUTHORITY\SYSTEM:F" "DOMAIN\newton-ops:R"
icacls "C:\ProgramData\Newton\ad\device.txt" /grant:r "BUILTIN\Administrators:F" "NT AUTHORITY\SYSTEM:F" "DOMAIN\newton-ops:R"
icacls "C:\ProgramData\Newton\ad\tx" /grant:r "BUILTIN\Administrators:(OI)(CI)F" "NT AUTHORITY\SYSTEM:(OI)(CI)F" "DOMAIN\newton-ops:(OI)(CI)F"
```

No other principal may hold a write-type right on the directory or on any of the files. The
helper checks exactly these rights: `WriteData`/`CreateFiles`, `AppendData`/`CreateDirectories`,
`WriteExtendedAttributes`, `WriteAttributes`, `Delete`, `DeleteSubdirectoriesAndFiles`,
`ChangePermissions` and `TakeOwnership`. It never uses an aggregate mask such as `Modify` or
`FullControl`, because those carry read bits too: a `Read` or a `ReadAndExecute` ACE for the
write account or for `Users` is safe and passes the check. At start the helper reads the ACL
of the directory, of the key, of the device file and of the transaction store, and refuses
to run when any such ACE exists for a SID other than Administrators (`S-1-5-32-544`) or
SYSTEM (`S-1-5-18`). An ACE the helper cannot resolve to a SID is treated as unsafe.

The key file is the one of `newton-audit` in its ACL: `SYSTEM:F`, `Administrators:F` and
`newton-ops:RX`.

## sshd

In `C:\ProgramData\ssh\sshd_config` (Windows OpenSSH), for the group the setup script
creates for the write account:

```
Match Group newton-ad-write
    ForceCommand powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\ProgramData\Newton\ad\write.ps1
    AllowTcpForwarding no
    PermitTunnel no
    X11Forwarding no
    AllowAgentForwarding no
    PermitTTY no
```

The group name above is a placeholder: a live check has to confirm the exact `Match` spelling
Windows OpenSSH accepts for a domain group before the setup script is generated.

## What the setup must grant the write account

Two things the helper needs and cannot grant itself.

**SeBatchLogonRight.** The undo task runs as `newton-ops` with the S4U logon type. Such a
task only runs when the account holds `SeBatchLogonRight`; without it the run fails with
`0x80070569` (the logon type is not granted). SETUP grants the right through the Default
Domain Controllers Policy, or through a GPO linked to the Domain Controllers OU, **adding**
it to the existing holders and never replacing them.

**The builtin OpenSSH Users group.** sshd has `AllowGroups administrators "openssh users"`,
so SETUP adds `newton-ops` to the builtin `OpenSSH Users` group, which is not privileged.

A restart of sshd launched as a child of the SSH session dies with the session, so SETUP
restarts sshd as its own last step.

## The undo task

The helper registers the undo through the COM API of the Task Scheduler, because the
ScheduledTasks cmdlets and `schtasks` fail as the write account ("Cannot connect to CIM
server. Access denied" and "Access is denied"). The task is a one-shot task of the root
folder, named `newton-undo-<txid>`, registered with `RegisterTaskDefinition(name, def, 6,
$null, $null, 2)` and `Principal.LogonType = 2` (S4U). It runs:

```
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\ProgramData\Newton\ad\write.ps1 -Undo <txid>
```

A confirm deletes the task with `GetFolder('\').DeleteTask(name, 0)`.

## The delegation

`newton-ops` writes only what the verbs need, and only in the places the owner names:

- write `userAccountControl`, `msDS-SupportedEncryptionTypes` and `lockoutTime`;
- create and delete user objects;
- write `member` on groups;
- create-child and delete-child, for the move;
- write `ms-DS-MachineAccountQuota` on the domain head.

It is never a member of a privileged group. The helper re-checks that before every write:
it reads the `tokenGroups` of the write account on the account's own distinguished name,
base scope, and refuses with `privileged` when one of them is in the privileged set of the
contract, when the read fails or when it cannot be decoded.

The presence of a member in a group is decided by base-scope searches of the group named by
its GUID (`<GUID=...>`): `(member=<GUID=member>)` matches when the member is in it (the
directory resolves the GUID inside the one request, so a member moved between two reads never
changes the answer), `(member=*)` matches when the group holds member values the account can
read, and `(objectClass=*)` says the group is there. After `(member=*)` matches, both searches run
again, and the member reads out only when the first still misses and the second still matches (a
right on `member` that changes between the searches never reads "absent"; one that changes more
than once inside one read is a known limit). A group of more than 1500 members still
works and the whole member list is never read. An empty group and a member list the account
cannot read answer the same (an attribute it cannot read is treated as one that is not there),
so that answer is never taken for "the member is out": the undo writes (the server checks it),
and the read-back, the re-reads and the confirm of a member-add read it as a target that cannot
be read. A missing quota, a missing `lockoutTime` and a missing encryption-types value (unless
removing it is the change) are read so too, never as 0 or as "no value", and so is a missing
`userAccountControl`. The `read` mode answers that image as `outcome` beside the planning image
`live`; Newton verifies every DC on `outcome` (each DC binds as its own account, so a replica that
holds another value it cannot read never shows the after-image, a removal's after-image aside) and refuses to plan a change whose
before-image the account cannot read. A new user counts as gone only when a base search of its GUID
name (`<GUID=...>`) answers noSuchObject (an object the account cannot see at all may answer the
same, a known limit), never from a search on `objectGUID` that finds nothing (a
filter on an `objectGUID` the account cannot read matches nothing); a base search that answers no
entry is a user the account cannot read, never gone. The GUID form of the filter value and of a
base was not run live on the lab DC; tests cover it.

## What the helper never does

It never reads a filter, a DN or free text from the request: the request holds ids, ints
and the words of the contract. It never runs anything dynamic, never prints an exception
message, never puts the secret of a user-create in a record, an answer or a log, and never
builds that password with a cmdlet that would record it. The password is the UTF-16LE of
the quoted secret, sent as `unicodePwd`, and the bytes are cleared as soon as the write is
done.

## The live probe

`mcp/tests/ad/win_write_live_probe.ps1` is the probe to run on a real domain
controller, under Windows PowerShell 5.1, as the write account:

```
powershell.exe -NoProfile -ExecutionPolicy Bypass -File win_write_live_probe.ps1
```

It writes nothing. It dot-sources the helper, builds the real LDAP adapter and prints one
JSON line per check: the bind, the rootDSE read, the PDC check, a read-mode resolve of
`Administrator`, the token groups of the current account decoded, the privileged flag of
that account, the DN of the Domain Controllers OU and a hex decode of a fixed test string.
