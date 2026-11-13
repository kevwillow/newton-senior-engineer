# Windows AD collector (`collector.ps1`)

The collector runs on the Windows domain controller, takes no input, and prints one JSON document
on stdout. It is the Windows half of the Newton AD audit; the checks in `mcp/newton_mcp/ad/checks/` read
the document.

## Install

Install path: `C:\ProgramData\Newton\ad\`. The directory holds exactly three files:

| file | source |
|---|---|
| `collector.ps1` | `mcp/newton_mcp/ad/collector/collector.ps1` |
| `queries.json` | the query set Newton ships (`mcp/newton_mcp/ad/queries.json`) |
| `forbidden.json` | the forbidden attribute list Newton dumps |

`queries.json` must be byte-identical to the copy Newton holds: the collector reports the SHA-256
of the bytes it ran as `querysetsha`, and Newton refuses a document whose hash differs from its own
copy ("collector out of date: rerun the setup"). The copy in this directory is the reference used by
the static test; install the one Newton ships.

## ACL

Administrators and SYSTEM have full control, `newton-audit` has read and execute, and nothing is
inherited from the parent:

```
icacls "C:\ProgramData\Newton\ad" /inheritance:r
icacls "C:\ProgramData\Newton\ad" /grant:r "BUILTIN\Administrators:(OI)(CI)F" "NT AUTHORITY\SYSTEM:(OI)(CI)F"
icacls "C:\ProgramData\Newton\ad" /grant:r "DOMAIN\newton-audit:(OI)(CI)RX"
icacls "C:\ProgramData\Newton\ad\collector.ps1" /grant:r "BUILTIN\Administrators:F" "NT AUTHORITY\SYSTEM:F" "DOMAIN\newton-audit:RX"
icacls "C:\ProgramData\Newton\ad\queries.json" /grant:r "BUILTIN\Administrators:F" "NT AUTHORITY\SYSTEM:F" "DOMAIN\newton-audit:RX"
icacls "C:\ProgramData\Newton\ad\forbidden.json" /grant:r "BUILTIN\Administrators:F" "NT AUTHORITY\SYSTEM:F" "DOMAIN\newton-audit:RX"
```

No other principal may hold write, modify, full control, change-permissions, take-ownership or
append rights on the directory or on any of the three files. At start the collector reads the ACL of
the directory and of the three files and exits 2 if any such ACE exists for a SID other than
Administrators (`S-1-5-32-544`), SYSTEM (`S-1-5-18`) or TrustedInstaller
(`S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464`). An ACE the collector cannot
resolve to a SID is treated as unsafe. Watch out for `CREATOR OWNER` (`S-1-3-0`) and for inherited
write ACEs: both make the install unsafe.

## sshd

In `C:\ProgramData\ssh\sshd_config` (Windows OpenSSH), for the group the setup script creates for
`newton-audit`:

```
Match Group newton-ad-collectors
    ForceCommand powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\ProgramData\Newton\ad\collector.ps1
```

The group name above is a placeholder: LVR-AD-02 has to confirm the exact `Match` spelling Windows
OpenSSH accepts for a domain group before the setup script is generated.

## Running it by hand

As the audit account, on the DC:

```
powershell -NoProfile -File collector.ps1 > out.json
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
DTD processing off.
