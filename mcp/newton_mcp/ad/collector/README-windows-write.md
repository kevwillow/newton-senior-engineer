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
  is refused and the undo disarmed, any other value is undone at once, and a target that cannot
  be read again stays armed so the task undoes it on time.

Every pattern of the helper is anchored with `\A` and `\z`, so a trailing newline never
passes a validation. The bit arithmetic of the contract is 64-bit.

## Files

Install path: `C:\ProgramData\Newton\ad\`.

| file | what it is |
|---|---|
| `write.ps1` | the helper (`mcp/newton_mcp/ad/collector/write.ps1`) |
| `approval.key` | the approval key `K`: 64 lowercase hexadecimal characters and a newline |
| `device.txt` | the name of the device that stands for the domain, the same on every DC of the domain: the name every request of the domain carries |
| `tx\` | the transaction store: one `<txid>.json` per change, never deleted |

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

The group name above is a placeholder: LVR-AD-02 has to confirm the exact `Match` spelling
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

The presence of a member in a group is a base-scope search on the group with the filter
`(member=<the distinguished name>)`, so a group of more than 1500 members still works and
the whole member list is never read.

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
