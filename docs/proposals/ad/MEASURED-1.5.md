# AD 1.5 task 0: measurements (2026-11-10 and 11, nested lab on supernova)

Every answer below was measured in the nested lab. Nothing ran on the supernova host except managing NLAB VMs.

## The lab

| VM | Where | OS | CPU / RAM | Address |
|---|---|---|---|---|
| NLAB-HVHOST | supernova, NewtonLab switch | Server 2025 Standard Eval (Core), Hyper-V role | 4 vCPU, 7 GB fixed, `ExposeVirtualizationExtensions` | 10.120.0.51 |
| BUILD1 | inside NLAB-HVHOST, switch `BuildLab` (internal, NAT `BuildLabNat` 10.121.0.0/24) | Server 2025 Standard Eval (Core) | 2 vCPU, 2 GB fixed | 10.121.0.11 |

NLAB-HVHOST has 7 GB, not the design's 10 GB: supernova had 10.9 GB free when it was built.

Reaching BUILD1: ssh through supernova, then through NLAB-HVHOST (`ProxyCommand` twice), with `IdentitiesOnly=yes`.
Without it, ssh offers every agent key first and Windows sshd disconnects with "Too many authentication failures".

## Answers

### 1. Nested virtualisation with supernova's VBS on

Works. Inside NLAB-HVHOST: `VirtualizationFirmwareEnabled True`, the Hyper-V role installs, `HypervisorPresent True`,
`vmms` Running, and BUILD1 installs and runs from the ISO.

Trap: a disk made by `Expand-WindowsImage` + `bcdboot /f BIOS` (no setup run) bugchecks 0xEF
(CRITICAL_PROCESS_DIED) about 7 s into every boot, with 1 or 2 vCPU; the same ISO booted normally. Build L2 guests
from the ISO plus an answer-file CD.

### 2. Does a local `newton-build` key login survive the first promotion?

The account survives; its sshd block does not match any more.
- Before: `BUILD1\newton-build`, SID `...-1000`, auth NTLM, in BUILTIN\Administrators. The forced command ran;
  any other command was refused.
- After `Install-ADDSForest` (build.newton.test, NBUILD, Win2025 levels): the same SID, now `NBUILD\newton-build`,
  member of `CN=Administrators,CN=Builtin`. The key login failed: "Permission denied (publickey)", because
  `Match User newton-build` no longer matches, so the administrators block (without the build key) applied.
- Fix, measured: `Match User newton-build,nbuild\newton-build`. After it, the login works, the token is Kerberos S4U
  (S-1-18-2), and the forced command still runs.
- For the bootstrap: write both names, the second with the plan's NetBIOS name in lower case.

### 3. Which operations need a password session (not the S4U key login)?

| Operation | S4U key login | Password scheduled task |
|---|---|---|
| list `\\<domain>\SYSVOL` | pass | pass |
| New-GPO, Set-GPRegistryValue, New-GPLink, Remove-GPLink, Backup-GPO, Remove-GPO | pass 27 of 32: 3 "access rights" failures, 2 "server instance not found" while ADWS started (see below) | pass 7 of 7 |
| Enable-ADOptionalFeature Recycle Bin | fail (the token lacked Enterprise Admins) | first forest: fail 2 of 2, cause unknown; fresh forest: pass 1 of 1 |
| Update-LapsADSchema | not run | pass |
| `wbadmin start systemstatebackup` | pass (450 s) | not run |

- Groups added after a logon session's ticket was issued are missing from later S4U tokens: after adding
  newton-build to Domain, Enterprise and Schema Admins, every new S4U login still lacked 512, 518 and 519 until a
  reboot. After the reboot they were present and enabled. A password logon had them at once.
- The built-in Administrator (Enterprise Admin since promotion) enabled the Recycle Bin over its S4U key login.
- On the first forest, Recycle Bin through the password task failed twice with "Insufficient access rights" although
  that token held 512, 518 and 519, enabled, at High integrity. Not explained. After restoring the pre-promotion
  checkpoint and promoting again, the same task call passed at once (groups added, then `task:recyclebin`). One pass
  and two failures: the build treats a failed stage 3 as a stop, as for any stage.
- The 3 GPO failures ("You do not have sufficient access rights") came in a row a few minutes after a reboot. They did
  not come back in 27 later runs, including a reboot test that ran it every 15 s from 53 s of uptime.
- After a reboot, `ADWS` reports Running while the AD cmdlets still answer "Server instance not found on the given
  port" (seen at 53 s and 67 s of uptime, fine from 79 s). Readiness is "Get-ADDomain answers", not the service state.

Design consequences:
- Stage 2 adds the memberships, then reboots, before stages 3 and 4 run; or the helper runs those stages in the
  password session. The run waits for Get-ADDomain after every reboot.
- The DPAPI LocalMachine password file written before promotion still decrypts after it (the task path used it).

- Probe caveat (found in review): `direct:gpoedit` and `task:gpoedit` report `ok: true` even when a step fails,
  because the op catches its own error. The counts above come from the step text instead: a pass reads `new setreg
  link unlink backup`, a failure would end in `FAIL@<step>=<message>`. The 3 "access rights" failures came from the
  earlier version of the op, which did not catch.
- The LAPS schema update is real on Server 2025: on BUILD1's second forest, where `Update-LapsADSchema` never ran,
  the schema is objectVersion 91 and `msLAPS-Password`, `msLAPS-PasswordExpirationTime`, `msLAPS-EncryptedPassword`
  and `ms-Mcs-AdmPwd` are absent, and the computer class's `mayContain` lacks `msLAPS-Password` (2026-11-11). On the
  first forest the task's update made `msLAPS-Password` present.

### 4. Checkpoints

- Hyper-V `Get-VMSnapshot` reports `SnapshotType Standard` for production checkpoints too: that field is not the
  checkpoint type. Read the VM's `CheckpointType`, and prove VSS ran from inside the guest.
- `Set-VM -CheckpointType ProductionOnly; Checkpoint-VM` on the BUILD1 DC: 7 s. `repadmin /showbackup` on BUILD1 then
  showed `dSASignature` changed at the checkpoint's second (00:23:51) on all five partitions. That is the read-back:
  the snapshot exists and every partition's backup time is no older than its creation time.
- The checkpoint login: local user `hv-checkpoint`, member of Hyper-V Administrators (S-1-5-32-578) only, with a
  forced command (`hv-checkpoint.ps1`) that does `create <name>` and `list` for the one VM in `vm.txt`.
  - Windows Server 2025's sshd_config has `AllowGroups administrators "openssh users"`: the account must also be in
    `OpenSSH Users`, or sshd refuses it before authentication.
  - Measured: `list` and `create m-hvcp-1` answer JSON with name, id and UTC time; `cmd /c whoami` and a name with
    `;` answer `refused`.
  - The account's own rights are wider than the script (Hyper-V Administrators can restore, delete or change VMs):
    the forced command is the boundary, as for newton-build.
- `wbadmin start systemstatebackup -backupTarget:B: -quiet` as newton-build over S4U: exit 0 in 450 s; `wbadmin get
  versions -backupTarget:B:` shows `Version identifier: 11/11/2026-00:26` and `Can recover: ... System State`.

### 5. Restoring the pre-promotion checkpoint

`Restore-VMSnapshot build1-fresh-workgroup` (taken before newton-build existed), then start. Read back over
PowerShell Direct: `DomainRole 2`, `PartOfDomain False`, `Workgroup WORKGROUP`, no local `newton-build`, AD DS
`Available` (not installed). BUILD1 was a workgroup server again.

Trap: after the restore the SSH firewall rule read `Profile Private` and the network was Public, so port 22 was closed,
although the answer file set `-Profile Any` and SSH had worked before the checkpoint. Not explained; fixed over
PowerShell Direct. A restore read-back must not assume SSH answers.

Then BUILD1 was promoted again, with `Match User newton-build,nbuild\newton-build` written before promotion: the key
login worked straight after the promotion, which is what the bootstrap will do.

### 6. Proxmox: a scoped token and vmgenid

NLAB-PVE: an NLAB VM on supernova (Gen1, 4 vCPU, 6 GB fixed, nested virtualisation, 10.120.0.61), run on its own while
NLAB-HVHOST was off. Proxmox VE 9.2-1 ISO (sha256 4e88fe416df9b527624a175f24c9aa07c714d3332afb1ee3dbf3879573ef2c6c, as published), installed unattended with
`proxmox-auto-install-assistant prepare-iso --fetch-from iso` 9.2.8. pve-manager 9.2.2, kernel 7.0.2-6-pve. KVM runs
nested (`/dev/kvm`, `svm` on 4 CPUs). Test guests: VM 100 (running, no OS) and VM 101, 1 GB disks on `local-lvm`.

Setup: role `NewtonCheckpoint` = `VM.Snapshot,VM.Audit`; user `newton-cp@pve`; token `newton-cp@pve!build` with
`--privsep 1`; ACL on `/vms/100` for both the user and the token. All calls were made with the token, against
`https://127.0.0.1:8006/api2/json` on the node.

| Call | Answer |
|---|---|
| `GET /access/permissions` | 200 `{"/vms/100":{"VM.Snapshot":1,"VM.Audit":1}}` |
| `GET /nodes/{n}/qemu/100/config` | 200, includes `vmgenid` |
| `POST .../100/snapshot snapname=nb-disk-1 vmstate=0` | 200, a UPID; the task's status (readable with the token) `exitstatus OK` |
| `POST .../100/snapshot snapname=nb-ram-1 vmstate=1` (running VM) | 200, UPID, `exitstatus OK` |
| `GET .../100/snapshot` | 200, both snapshots with `name`, `snaptime`, `vmstate`, `parent` |
| `GET .../101/config`, `POST .../101/snapshot` | 403 `Permission check failed (/vms/101, VM.Audit)` / `VM.Snapshot` |
| `POST .../100/status/stop` | 403 `(/vms/100, VM.PowerMgmt)` |
| `GET /nodes/{n}/qemu` | 200, lists VM 100 only |
| `POST .../100/snapshot/nb-disk-1/rollback` | 200, `exitstatus OK`: VM 100 rolled back and stopped |
| `DELETE .../100/snapshot/nb-ram-1` | 200, `exitstatus OK` |
| `pveum user token modify newton-cp@pve build --expire <now+21600> --output-format json` (run as root after the table above) | answered `expire: 1794381102` |

Findings:
- `VM.Snapshot` alone lets the token roll back and delete snapshots, not only create them. A stolen token cannot read
  or touch other VMs or call `status/stop`, but it can roll the VM back, and a rollback to the `vmstate=0` snapshot
  left the running VM 100 stopped (`qm status 100` after it: `stopped`). The token cannot start it again (no
  `VM.PowerMgmt`). So a stolen token can undo the build back to a checkpoint and leave the DC off. The Hyper-V forced command does not have this problem; the token needs an expiry and must be deleted at
  cleanup.
- vmgenid is on by default: `qm create` without `--vmgenid` still set one. The plan's check still matters for an
  imported or edited VM: `qm set 101 --delete vmgenid` removes it.
- The rollback changed VM 100's vmgenid (`44387c6b-...` at creation, read with `qm config 100` in measure.sh;
  `a117f654-...` after it, read with the token from `GET /nodes/{n}/qemu/100/config` in a follow-up command, not in
  measure.sh): Proxmox issues a new generation ID on rollback. Section 7 shows the same on VM 200 and what Windows
  does with it.
- Not measured: a Windows DC guest under Proxmox. A crash-consistent snapshot of a DC needs the QEMU guest agent
  (`agent: 1`, whose fs-freeze uses VSS on Windows); the test VM had no agent. Whether the `dSASignature` read-back
  works there is still open.

At the end the token was removed and NLAB-PVE powered off.

### 7. A Windows DC under Proxmox (guest agent, VSS, vmgenid)

VM 200 `pvedc1` inside NLAB-PVE: Server 2025 eval from the ISO with an answer-file CD, 2 cores, 3 GB, SATA disk on
`local-lvm`, `e1000e` on an internal bridge `vmbr1` (10.122.0.0/24, masqueraded by NLAB-PVE), `agent: 1`, vmgenid set.
The QEMU guest agent came from `virtio-win.iso` (`guest-agent\qemu-ga-x86_64.msi`, installed at first logon). Promoted
to the forest root `pve.newton.test` (NPVE). Snapshots taken with a fresh scoped token (`VM.Snapshot,VM.Audit` on
`/vms/200`, privsep, 6 h expiry); rollbacks done as root, as the owner would.

- The agent needs the VirtIO serial driver as well as QEMU-GA: with only the MSI, the service ran but `qm agent 200
  ping` answered "QEMU guest agent is not running". `pnputil /add-driver <cd>\vioserial\2k25\amd64\vioser.inf
  /install` fixed it.
- Windows sees the vmgenid device as "Microsoft Hyper-V Generation Counter" (`ACPI\QEMUVGID`, status OK).
- Snapshot with `vmstate=0`: the task log (readable with the token) says `freeze guest filesystem`, the disk snapshot,
  `thaw guest filesystem`, `TASK OK`; the guest logged `guest-fsfreeze called` at 02:09:40 and `guest-fsthaw called` at
  02:10:15 (a 35 s freeze; DFSR's database stopped and restarted inside it).
- `repadmin /showbackup` shows no `dSASignature` after that snapshot: the agent's VSS freeze is consistent but does not
  record an AD backup. The Hyper-V read-back (section 4) does not carry over to Proxmox.
- Snapshot with `vmstate=1`: saves the RAM (2.69 GB in 7 s) and does not freeze the file systems.
- Rollback 1 (to the snapshot taken 6 minutes after promotion, after one post-promotion boot): the vmgenid changed and a
  user made after the snapshot was gone, but the invocationID stayed `e7736909-...`. The DS log on the first boot after
  promotion had 2168 (generation ID detected) but no 2179: the DC had not stored `msDS-GenerationId`. After the
  rollback: 2173 (could not read `msDS-GenerationId`, "does not exist during the first reboot after dcpromo") and 2179
  (stored now). **No safeguard ran: a rollback to that snapshot would have been a USN rollback had there been a second
  DC.**
- Rollback 2 (snapshot taken once `msDS-GenerationId` was stored on the DC's computer object): 2172 (read the stored
  ID), 2170 ("A Generation ID change has been detected", old and new values), 1109 (invocationID changed
  `e7736909-...` to `2765f64e-...`); the user made after the snapshot was gone. The safeguard works.

Design consequences:
- A DC checkpoint is trusted only when `msDS-GenerationId` is present on the DC's computer object. After stage 2 the
  helper reboots until it is (one more reboot in this test), and every DC checkpoint's read-back includes that check.
  The Hyper-V side follows the same Windows logic but was not measured for this case.
- Proxmox DC checkpoints use `vmstate=0`. Their read-back: the snapshot is listed and the task log has both the freeze
  and the thaw lines.
- The bootstrap on a Proxmox guest installs the VirtIO serial driver and QEMU-GA, and stage 0 checks `qm agent ping`.
  The token cannot call the agent API, so stage 0 checks it inside the guest: the QEMU-GA service running and the VirtIO
  Serial device OK.

NLAB-PVE was powered off at the end. VM 200 kept its three snapshots; the token and both ACL entries were removed.

## Not measured yet

- The Hyper-V first-boot case: a production checkpoint taken before `msDS-GenerationId` is stored.
- The replica promotion (BUILD2), which is task 10 work rather than a design question.

All NLAB VMs were off at the end (2026-11-11). BUILD1 is a DC of `build.newton.test` again, with newton-build in
Domain, Enterprise and Schema Admins and the Recycle Bin enabled; its checkpoint `build1-fresh-workgroup` is the clean
start for the task 10 runs.

## apollo lab, 2026-11-13

The 1.5 build lab on apollo (the maintainer's decision of 2026-11-13). Nothing was promoted: promotion is task 5's own work.

### The lab

| VM | Name | OS | CPU / RAM | Disk | Address |
|---|---|---|---|---|---|
| 731 | `ad-build1` (BUILD1) | Server 2025 Standard Evaluation, Server Core, build 26100, workgroup | 2 vCPU (`cpu: host`), 2560 MB fixed (`balloon: 0`) | 32 GB thin on `vmdata`, SATA | 10.111.0.41/24 |
| 732 | `ad-build2` (BUILD2) | the same | 2 vCPU, 2048 MB fixed | 32 GB thin on `vmdata`, SATA | 10.111.0.42/24 |

- Both tagged `newton-ad-build`, `agent: enabled=1`, `vmgenid` set, `localtime: 0`, `e1000e` on `vmbr111`,
  `onboot: 0`, machine `pc-i440fx-11.0` (pinned by Proxmox for a Windows `ostype`). The virtio-win ISO stays on
  `ide0` (the bootstrap reads `vioserial` and the QEMU-GA MSI from it).
- Installed from `windows-server-2025-eval-26100.1742-en-us.iso` with a per-VM answer-file CD (the 723 template:
  install index 1, Server Core, the lab key for Administrator; plus a static IP with gateway 10.111.0.1 and no DNS
  server, the OpenSSH rule with `-Profile Any`, and `pnputil /add-driver <cd>\vioserial\2k25\amd64\vioser.inf
  /install` + `qemu-ga-x86_64.msi /qn`). About 5 minutes from `qm start` to SSH. The local Administrator password is in
  `~/.config/newton/ad-lab/build-admin.pw`; the answer-file ISOs were shredded after the installs.
- `vmbr111`: a new bridge with no port, apollo 10.111.0.1/24, `ip-forward off` (added with a 120 s revert timer;
  the pre-change files are `/root/interfaces.pre-vmbr111-2026-11-13` and `/root/interfaces.pre-vmbr111-ipfwd-2026-11-13`).
- The AD lab DC2s 722 and 724 were shut down first (722 by `qm shutdown`; 724 ignored the ACPI request for 300 s
  and was shut down from inside with `shutdown /s`).

Traps found while building it:
- **Per-interface forwarding.** apollo has `net.ipv4.ip_forward = 0` but `net.ipv4.conf.vmbr0.forwarding = 1`,
  `vmbr110.forwarding = 1`, and the new `vmbr111` came up with `forwarding = 1` too. BUILD1 could ping 723
  (10.110.0.31) through apollo: `ip route get 10.110.0.31 from 10.111.0.41 iif vmbr111` answered `dev vmbr110`. After
  `ip-forward off` on `vmbr111`, BUILD1 reaches 10.111.0.1 and apollo's own management address and nothing else:

  ```
  ping 10.111.0.1 : True
  ping <apollo management address> : True
  ping <the home router> : False
  ping 10.110.0.31 : False
  ping 1.1.1.1 : False
  ```
  `vmbr110` (the AD lab) still forwards; nothing answers from the home network because it has no route back.
- **The guest clock.** With `ostype: win11` Proxmox puts the RTC in the host's local time (apollo: America/Adak,
  UTC-10) and the answer file sets the guest to UTC, so the guest read 2026-11-12T20:33Z at 06:33Z: stage 0's 5-minute
  `clock_skew` check would refuse every build. `qm set <id> --localtime 0` fixed it (guest 06:36:48.96Z, host
  06:36:50Z). Build VMs need `localtime: 0` (or a guest time zone that matches the host).

### The scoped token

```
pveum role add NewtonBuildCheckpoint --privs VM.Snapshot,VM.Snapshot.Rollback,VM.Audit
pveum user add newton-build@pve --expire 1795737600          # 2026-11-27T00:00:00Z
pveum acl modify /vms/731 --roles NewtonBuildCheckpoint --users newton-build@pve --propagate 0   # and /vms/732
pveum user token add newton-build@pve checkpoint --privsep 1 --expire 1795737600
pveum acl modify /vms/731 --roles NewtonBuildCheckpoint --tokens 'newton-build@pve!checkpoint' --propagate 0   # and /vms/732
```

The secret is in `~/.config/newton/ad-lab/pve-build-token` (600). Every call below used the token
(`Authorization: PVEAPIToken=newton-build@pve!checkpoint=<secret>`) against `https://<apollo>:8006/api2/json`,
TLS checked against `/etc/pve/pve-root-ca.pem`. `digest` values shortened to `…`.

| Call | Answer |
|---|---|
| `GET /access/permissions` | 200 `{"data":{"/vms/731":{"VM.Snapshot.Rollback":0,"VM.Audit":0,"VM.Snapshot":0},"/vms/732":{"VM.Snapshot":0,"VM.Audit":0,"VM.Snapshot.Rollback":0}}}` (the values are the propagate flag) |
| `GET /nodes/Apollo/qemu` | 200, VMs 731 and 732 only |
| `GET .../723/config` | 403 `Permission check failed (/vms/723, VM.Audit)` |
| `GET .../723/snapshot` | 403 `(/vms/723, VM.Audit)` |
| `POST .../723/snapshot snapname=nb-refused` | 403 `(/vms/723, VM.Snapshot)` |
| `POST .../723/snapshot/dc2-ready-20261112/rollback` | 403 `(/vms/723, VM.Snapshot\|VM.Snapshot.Rollback)` |
| `POST .../731/status/stop`, `.../status/start` | 403 `(/vms/731, VM.PowerMgmt)` |
| `POST` or `PUT .../731/config memory=4096` | 403 `(/vms/731, VM.Config.Disk\|VM.Config.CDROM\|VM.Config.CPU\|VM.Config.Memory\|VM.Config.Network\|VM.Config.HWType\|VM.Config.Options\|VM.Config.Cloudinit)` |
| `POST .../731/agent/ping`, `GET .../731/agent/get-osinfo` | 403 `(/vms/731, VM.GuestAgent.Audit\|VM.GuestAgent.Unrestricted)` |
| `DELETE .../731` | 403 `(/vms/731, VM.Allocate)` |
| `POST /access/users/newton-build@pve/token/second` | 403 `Permission check failed` |
| `GET /nodes/Apollo/storage`, `GET /access/users` | 200 `{"data":[]}` |

The rollback check names `VM.Snapshot|VM.Snapshot.Rollback`: either privilege allows a rollback, so adding
`VM.Snapshot.Rollback` to the role widens nothing (section 6: `VM.Snapshot` alone already rolls back and deletes).
PVE 9.2 has `VM.GuestAgent.Audit`; the role leaves it out, so the token cannot ping the agent (stage 0 checks the
agent inside the guest, as designed).

Snapshot of the running BUILD1 (agent running), list, status, log:

```
$ POST /nodes/Apollo/qemu/731/snapshot snapname=m-disk-1 vmstate=0 description=newton-1.5-measure
{"data":"UPID:Apollo:00187787:10C0798B:6AF6AF7E:qmsnapshot:731:newton-build@pve!checkpoint:"}
$ GET /nodes/Apollo/tasks/<UPID>/status
{"data":{"upid":"UPID:Apollo:00187787:10C0798B:6AF6AF7E:qmsnapshot:731:newton-build@pve!checkpoint:","starttime":1794551678,"pid":1603463,"user":"newton-build@pve","pstart":281049483,"tokenid":"checkpoint","id":"731","type":"qmsnapshot","exitstatus":"OK","node":"Apollo","status":"stopped"}}
$ GET /nodes/Apollo/tasks/<UPID>/log
{"data":[{"n":1,"t":"freeze guest filesystem"},{"t":"snapshotting 'drive-sata0' (vmdata:vm-731-disk-0)","n":2},{"n":3,"t":"  WARNING: You have not turned on protection against thin pools running out of space."},{"t":"  WARNING: Set activation/thin_pool_autoextend_threshold below 100 to trigger automatic extension of thin pools before they get full.","n":4},{"t":"  Consider pruning vmdata VG archive with more than 328 MiB in 7326 files (see archiving settings in lvm.conf).","n":5},{"t":"  Consider pruning vmdata VG archive with more than 328 MiB in 7327 files (see archiving settings in lvm.conf).","n":6},{"n":7,"t":"  Logical volume \"snap_vm-731-disk-0_m-disk-1\" created."},{"t":"  WARNING: Sum of all thin volume sizes (1.44 TiB) exceeds the size of thin pool vmdata/vmdata and the size of whole volume group (238.47 GiB).","n":8},{"t":"thaw guest filesystem","n":9},{"t":"TASK OK","n":10}],"total":10}
$ GET /nodes/Apollo/qemu/731/snapshot
{"data":[{"vmstate":0,"description":"newton-1.5-measure","snaptime":1794551678,"name":"m-disk-1"},{"name":"current","parent":"m-disk-1","digest":"…","running":1,"description":"You are here!"}]}
```

Snapshot with the agent stopped inside the guest (`Stop-Service QEMU-GA`; the VM config still has `agent: 1`):

```
$ POST /nodes/Apollo/qemu/731/snapshot snapname=m-nofreeze vmstate=0
$ GET /nodes/Apollo/tasks/UPID:Apollo:0018A49E:10C3A0BA:6AF6B791:qmsnapshot:731:newton-build@pve!checkpoint:/status
{"data":{"exitstatus":"OK","node":"Apollo","status":"stopped","id":"731","type":"qmsnapshot","tokenid":"checkpoint","pstart":281256122,"user":"newton-build@pve","starttime":1794553745,"pid":1615006,"upid":"UPID:Apollo:0018A49E:10C3A0BA:6AF6B791:qmsnapshot:731:newton-build@pve!checkpoint:"}}
$ GET .../log
{"data":[{"n":1,"t":"skipping guest filesystem freeze - agent configured but not running?"},{"n":2,"t":"snapshotting 'drive-sata0' (vmdata:vm-731-disk-0)"},{"t":"  WARNING: You have not turned on protection against thin pools running out of space.","n":3},{"n":4,"t":"  WARNING: Set activation/thin_pool_autoextend_threshold below 100 to trigger automatic extension of thin pools before they get full."},{"n":5,"t":"  Consider pruning vmdata VG archive with more than 328 MiB in 7336 files (see archiving settings in lvm.conf)."},{"t":"  Consider pruning vmdata VG archive with more than 328 MiB in 7337 files (see archiving settings in lvm.conf).","n":6},{"t":"  Logical volume \"snap_vm-731-disk-0_m-nofreeze\" created.","n":7},{"t":"  WARNING: Sum of all thin volume sizes (<1.53 TiB) exceeds the size of thin pool vmdata/vmdata and the size of whole volume group (238.47 GiB).","n":8},{"t":"snapshotting 'drive-sata2' (vmdata:vm-731-disk-1)","n":9},{"t":"  WARNING: You have not turned on protection against thin pools running out of space.","n":10},{"t":"  WARNING: Set activation/thin_pool_autoextend_threshold below 100 to trigger automatic extension of thin pools before they get full.","n":11},{"n":12,"t":"  Consider pruning vmdata VG archive with more than 328 MiB in 7338 files (see archiving settings in lvm.conf)."},{"n":13,"t":"  Consider pruning vmdata VG archive with more than 328 MiB in 7339 files (see archiving settings in lvm.conf)."},{"n":14,"t":"  Logical volume \"snap_vm-731-disk-1_m-nofreeze\" created."},{"n":15,"t":"  WARNING: Sum of all thin volume sizes (1.55 TiB) exceeds the size of thin pool vmdata/vmdata and the size of whole volume group (238.47 GiB)."},{"n":16,"t":"TASK OK"}],"total":16}
```

Snapshot of a stopped VM (`fresh-2026-11-13` on 731; 732 the same): `exitstatus OK`, and the log has no freeze or
thaw line at all: `snapshotting 'drive-sata0' (vmdata:vm-731-disk-0)`, the same LVM lines, `Logical volume
"snap_vm-731-disk-0_fresh-2026-11-13" created.`, `TASK OK`.

What this means for task 7's Proxmox read-back:
- `exitstatus OK` and `TASK OK` do not prove a freeze: a stopped agent gives `skipping guest filesystem freeze -
  agent configured but not running?` and still `OK`. The read-back must find `freeze guest filesystem` and `thaw
  guest filesystem`, in that order, and must refuse the `skipping guest filesystem freeze` line.
- On apollo's `vmdata` every snapshot log carries LVM `WARNING:` lines between the freeze and the thaw (thin-pool
  autoextend off, sum of thin volumes over the pool). "No warning between freeze and thaw" as a plain substring rule
  refuses every apollo checkpoint. The rule has to tell the LVM lines from a freeze or VSS failure; what a VSS failure
  inside the freeze looks like is not measured yet.
- A snapshot covers every disk of the VM (a second disk added for wbadmin got its own `snap_..._m-nofreeze`).
- A snapshot of a stopped VM has no freeze lines, so a rule that demands them refuses it; a workgroup checkpoint of a
  stopped VM is consistent anyway. The adapter must decide which it wants (the design takes checkpoints of running
  servers).

Rollback with the token, then delete:

```
$ POST /nodes/Apollo/qemu/731/snapshot/m-disk-1/rollback
{"data":"UPID:Apollo:00187838:10C08669:6AF6AF9F:qmrollback:731:newton-build@pve!checkpoint:"}
$ GET .../status
{"data":{"user":"newton-build@pve","starttime":1794551711,"pid":1603640,"upid":"UPID:Apollo:00187838:10C08669:6AF6AF9F:qmrollback:731:newton-build@pve!checkpoint:","status":"stopped","node":"Apollo","exitstatus":"OK","type":"qmrollback","id":"731","tokenid":"checkpoint","pstart":281052777}}
$ GET .../log   (LVM lines only, then)  {"n":12,"t":"TASK OK"}
$ GET /nodes/Apollo/qemu/731/status/current
{"data":{"qmpstatus":"stopped", ... "status":"stopped", ... "vmid":731,"name":"ad-build1"}}
$ DELETE /nodes/Apollo/qemu/731/snapshot/m-disk-1
{"data":"UPID:Apollo:001879FA:10C0A37A:6AF6AFEA:qmdelsnapshot:731:newton-build@pve!checkpoint:"}   -> exitstatus OK
```

The rollback left the running VM stopped (as in section 6), and the token cannot start it (403 `VM.PowerMgmt`
above); it was started as root.

### vmgenid on rollback, as the guest sees it

| When | `qm config 731` vmgenid |
|---|---|
| created | `590e3ddf-88e7-48eb-a4cf-ba1df5816086` |
| after the token's rollback to `m-disk-1` | `6f526e03-b3b1-4b97-a0ff-6b0c95745d9f` |
| after root's `qm rollback 731 fresh-2026-11-13` | `8a634019-55f4-4b19-8eb2-6314380216c9` |

Inside BUILD1, before and after the rollback (`Get-PnpDevice -PresentOnly` filtered on `ACPI\QEMUVGID*`):

```
FriendlyName : Microsoft Hyper-V Generation Counter
InstanceId   : ACPI\QEMUVGID\2&DABA3FF&0
Status       : OK
Class        : System
Service      : gencounter
```

The device is the same and OK on both sides. `CreateFile("\\.\VmGenerationCounter")` opens, but every
`DeviceIoControl` code tried answered win32 error 50 (not supported): 0x220000, 0x220004, 0x220008, 0x224000,
0x224004, 0x224008, 0x22C004, 0x228004 (error 5 with a read-only handle, 50 with read-write), 0x320000, 0x320004,
0x324000, 0x324004. So a workgroup server gives no readable generation ID through this device; the value Windows
uses is seen through AD (events 2170 and 1109, `msDS-GenerationId`), as section 7 measured on VM 200. The guest view
of the rollback itself:
- a file written after the snapshot is gone (`Test-Path C:\Windows\Temp\newton\after-m-disk-1.txt`: `True`
  before, `False` after);
- the boot after the rollback logs Kernel-Power 41 ("The system has rebooted without cleanly shutting down first")
  and EventLog 6008 ("The previous system shutdown at 8:33:44 PM on 11/12/2026 was unexpected", guest clock still
  UTC-10 then): to Windows, a `vmstate=0` rollback is a power loss at the snapshot.

### wbadmin on BUILD1

A 24 GB thin disk (`sata2`), formatted NTFS as `B:` (`D:` is the virtio-win CD, `E:` and `F:` the empty install
drives), and `Install-WindowsFeature Windows-Server-Backup` (Success, no restart, from the image: no network).
Each backup ran as SYSTEM in a one-shot scheduled task (`cmd /c <command> > log 2>&1`), so the backup does not depend on the
SSH session staying up.

`wbadmin start systemstatebackup -backupTarget:B: -quiet`: 06:38:39 to 06:51, exit 0, 83358 files,
`The backup of the system state successfully completed [11/13/2026 6:51 AM].` Then `wbadmin get versions
-backupTarget:B:`:

```
Backup time: 11/13/2026 6:38 AM 
Backup target: 1394/USB Disk labeled B:
Version identifier: 11/13/2026-06:38
Can recover: Volume(s), File(s), Application(s), System State
Snapshot ID: {d3d4a14b-6e88-4364-afe0-6ffe6d4b346f}
```

`wbadmin start backup -allCritical -backupTarget:B: -quiet`: started 06:58:23, done (exit 0) by the 06:59:46 poll (`The backup of volume
Windows(C:) completed successfully.`, `The backup of volume  (674.00 MB) completed successfully.`: the WinRE
partition). Then `wbadmin get versions -backupTarget:B:`:

```
Backup time: 11/13/2026 6:38 AM 
Backup target: 1394/USB Disk labeled B:
Version identifier: 11/13/2026-06:38
Can recover: Volume(s), File(s), Application(s), System State
Snapshot ID: {d3d4a14b-6e88-4364-afe0-6ffe6d4b346f}

Backup time: 11/13/2026 6:58 AM 
Backup target: 1394/USB Disk labeled nbackup(B:)
Version identifier: 11/13/2026-06:58
Can recover: Volume(s), File(s), Application(s), Bare Metal Recovery, System State
Snapshot ID: {8033a50b-0e6d-415f-b71b-5916d8d50079}
```

For task 7: a system-state version also lists `Volume(s), File(s), Application(s)`; only the all-critical one has
`Bare Metal Recovery`. The output lists every version on the target, oldest first, so the read-back has to pick the
version it took (by `Version identifier`), not any line. The `Backup target` text changes with the volume label. The
all-critical backup took under 83 s after the system-state one (it updates the same target). `B:` was 51% full (12 GB of
24) after both. The disk was deleted afterwards (the rollback to `fresh-2026-11-13` dropped it from the config, then
`qm disk unlink 731 --idlist unused0 --force 1`), so BUILD1 is back to the fresh state without the feature.

### Stage 0 reads on a fresh build VM (BUILD1)

```
os: Microsoft Windows Server 2025 Standard Evaluation | Version 10.0.26100 | BuildNumber 26100 | OperatingSystemSKU 79
InstallationType: Server Core
cs: Name BUILD1 | DomainRole 2 | PartOfDomain False | Workgroup WORKGROUP
AD-Domain-Services Available | DNS Available | RSAT-AD-PowerShell Available | RSAT-ADDS-Tools Available
Get-NetIPAddress: Ethernet 10.111.0.41 /24 PrefixOrigin Manual
Get-NetRoute 0.0.0.0/0: Ethernet NextHop 10.111.0.1 RouteMetric 256
Get-DnsClientServerAddress: Ethernet {}
Get-NetConnectionProfile: Ethernet Public
OpenSSH-Server-In-TCP: Enabled True, Profile Any, Inbound, Allow
C: free bytes 25329442816 (23.6 GB)
Resolve-DnsName build.newton.test: System.ComponentModel.Win32Exception | build.newton.test : This operation returned because the timeout period expired | FullyQualifiedErrorId ERROR_TIMEOUT,Microsoft.DnsClient.Commands.ResolveDnsName
[System.Net.Dns]::GetHostAddresses('build.newton.test'): System.Net.Sockets.SocketException | No such host is known
QEMU-GA: Running, Automatic
VirtIO Serial Driver: OK, System, PCI\VEN_1AF4&DEV_1003&SUBSYS_00031AF4&REV_00\3&267A616A&0&40
Microsoft Hyper-V Generation Counter: OK, System, ACPI\QEMUVGID\2&DABA3FF&0
PSVersion 5.1.26100.1591
```

(`Windows-Server-Backup` read `Installed` in that run because the wbadmin work had installed it; the fresh snapshot
predates it.) From apollo: `qm agent 731 ping` exit 0, `qm guest cmd 731 info` version `110.2.3`, `get-osinfo`
`"pretty-name" : "Windows Server 2025 Standard Evaluation"`, `"version-id" : "2025"`.

For task 5's stage 0:
- With no DNS server configured, `Resolve-DnsName` fails with `ERROR_TIMEOUT` and .NET says `No such host is known`.
  Neither means the name is free: `domain_exists` must tell "no answer because there is no resolver" from NXDOMAIN,
  or stage 0 must also require a DNS server set (the plan's forwarders, or itself after stage 1).
- The network profile is `Public`; the SSH rule's `Profile Any` is what keeps port 22 open (section 5's trap).
- The QEMU-GA file version is empty in `VersionInfo.ProductVersion`; read the service and `qm guest cmd info`, not the
  file.

Task 5's first measurement (stage 2's post-boot writes through the password task) needs a promotion, so it is not
here.

### State at the end

| VM | State | Snapshots |
|---|---|---|
| 731 BUILD1 | stopped | `fresh-2026-11-13` (disk only, taken with the token while stopped), current = fresh |
| 732 BUILD2 | stopped | `fresh-2026-11-13` (the same) |
| 721, 723 | running | unchanged |
| 722, 724 | stopped | unchanged |

`lvs vmdata/vmdata`: 62.70% before, 75.70% at the most (both installs plus the two backups), 69.85% at the end.
`free -g`: 4 GB available before, 7 GB at the end. The token expires 2026-11-27T00:00:00Z; delete it with `pveum
user token remove newton-build@pve checkpoint` and `pveum user delete newton-build@pve` when the lab work ends.

## Stages 0 to 4 on BUILD1, 2026-11-13

PLAN-1.5 task 5's first measurement: stages 0 to 4 run by hand on BUILD1 (VM 731, from `fresh-2026-11-13`), in
PowerShell over the Administrator key login, the way the stage templates will run them. Stage 2's checkpoint was
skipped. BUILD1 was rolled back to `fresh-2026-11-13` afterwards, so none of this is on the VM now.

### Set-up (the bootstrap's part, by hand)

A stand-in for the bootstrap, run as Administrator: `C:\NewtonBuild` (ACL SYSTEM and Administrators only, not
inherited); a local `newton-build` with a random 32-character password generated on the VM, never shown, stored with
`ProtectedData.Protect(..., LocalMachine)` in `C:\NewtonBuild\pw.bin` (262 bytes); `newton-build` in Administrators;
and in `sshd_config` (backed up first), `PasswordAuthentication no` and `KbdInteractiveAuthentication no` at the top
and this block ahead of `Match Group administrators`:

```
Match User newton-build,nbuild\newton-build
       AuthorizedKeysFile C:/NewtonBuild/authorized_keys
       ForceCommand powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\NewtonBuild\probe.ps1
       PermitTTY no
       AllowTcpForwarding no
```

`sshd -t` exit 0. The forced command here is a probe (`whoami /user`, `WindowsIdentity.AuthenticationType`, and the
`whoami /groups /fo csv /nh` lines for 544, 512, 518, 519, `S-1-18-*` and the integrity label), not the helper. The
login with `cmd /c whoami` as its command ran the probe:

```
whoami /user: "build1\newton-build","S-1-5-21-4035822249-418844242-2991919587-1000"
logon: NTLM | ImpersonationLevel None
"BUILTIN\Administrators","Alias","S-1-5-32-544","Mandatory group, Enabled by default, Enabled group, Group owner"
"Mandatory Label\High Mandatory Level","Label","S-1-16-12288",""
```

The password task, used for the promotion and for every write from stage 2 on: the runner decrypts `pw.bin`, writes
the op to `C:\NewtonBuild\ops\<op>.ps1`, and registers a one-shot task with `Register-ScheduledTask -User <user>
-Password <pw> -RunLevel Highest` (the password is a cmdlet parameter in the runner's process, never on a command
line). The action is `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File <op>`; the op writes
its own output to `C:\NewtonBuild\out\<op>.txt`. The runner starts it, polls `State` and `LastTaskResult` every 2 s,
prints the output and unregisters the task. Readback of a registration: `LogonType Password RunLevel Highest`. The
user is `newton-build` before promotion and `NBUILD\newton-build` after it.

### Stage 0 (the reads missing from the earlier run)

Clock skew, against pioneer and apollo (both `System clock synchronized: yes`), three brackets of one key-login read:

```
pioneer before 2026-11-13T13:56:50.845Z | guest 2026-11-13T13:56:54.9422198Z | pioneer after 2026-11-13T13:56:55.734Z
pioneer before 2026-11-13T13:56:55.735Z | guest 2026-11-13T13:56:56.9049388Z | pioneer after 2026-11-13T13:56:57.612Z
pioneer before 2026-11-13T13:56:57.613Z | guest 2026-11-13T13:56:58.7562987Z | pioneer after 2026-11-13T13:56:59.467Z
```

The guest falls inside every bracket (skew under 2 s). Its time service before stage 1: `w32tm /query /source` =
`Local CMOS Clock`, `Leap Indicator: 3(not synchronized)`, `Stratum: 0 (unspecified)`.

`domain_exists` on the fresh VM (no DNS server set: `Get-DnsClientServerAddress` empty):

```
Resolve-DnsName nothere-7f3a.newton.test  FAIL in 90 ms: System.ComponentModel.Win32Exception | NativeErrorCode 1460 | nothere-7f3a.newton.test : This operation returned because the timeout period expired | ERROR_TIMEOUT,Microsoft.DnsClient.Commands.ResolveDnsName
Resolve-DnsName nothere-7f3a.newton.test -DnsOnly True FAIL in 16 ms: ... NativeErrorCode 1460 ... ERROR_TIMEOUT
Resolve-DnsName build.newton.test -DnsOnly True FAIL in 0 ms: ... NativeErrorCode 1460 ... ERROR_TIMEOUT
Resolve-DnsName build.newton.test -Server 10.111.0.1 -DnsOnly True FAIL in 12030 ms: ... NativeErrorCode 1460 ... ERROR_TIMEOUT
Resolve-DnsName localhost  OK in 7 ms: localhost AAAA ::1 / A 127.0.0.1 (Section Question)
Resolve-DnsName BUILD1  OK in 0 ms: BUILD1 AAAA fe80::f77f:9b7f:9cf0:ddd7 / A 10.111.0.41 (Section Question)
Resolve-DnsName BUILD1 -DnsOnly True FAIL in 2 ms: ... NativeErrorCode 1460 ... ERROR_TIMEOUT
```

With no server configured, the "timeout" comes back in milliseconds (no query was sent); with a server that does not
answer (apollo has nothing on port 53) it takes 12 s. Without `-DnsOnly` the machine's own name answers from local
resolution, so `-DnsOnly` is required. A name that exists and one that does not, against a server that answers
(measured after promotion, against the DC's own DNS):

```
Resolve-DnsName build.newton.test -Server 127.0.0.1 OK in 10 ms: A 10.111.0.41
Resolve-DnsName nothere-7f3a.build.newton.test -Server 127.0.0.1 FAIL in 55 ms: System.ComponentModel.Win32Exception | NativeErrorCode 9003 | nothere-7f3a.build.newton.test : DNS name does not exist | DNS_ERROR_RCODE_NAME_ERROR,Microsoft.DnsClient.Commands.ResolveDnsName
Resolve-DnsName nothere-7f3a.newton.test -Server 127.0.0.1 FAIL in 11087 ms: System.ComponentModel.Win32Exception | NativeErrorCode 9002 | nothere-7f3a.newton.test : DNS server failure | RCODE_SERVER_FAILURE,Microsoft.DnsClient.Commands.ResolveDnsName
Resolve-DnsName nothere-7f3a.newton.test -Server 10.111.0.1 FAIL in 12020 ms: System.ComponentModel.Win32Exception | NativeErrorCode 1460 | nothere-7f3a.newton.test : This operation returned because the timeout period expired | ERROR_TIMEOUT,Microsoft.DnsClient.Commands.ResolveDnsName
```

For the stage 0 template: an answer is `domain_exists`; only `NativeErrorCode 9003` (`DNS_ERROR_RCODE_NAME_ERROR`)
means the name is free; 1460 (no server, or no answer) and 9002 (the server could not forward) mean the check could
not be made and stage 0 must stop, not pass. In this lab nothing upstream answers, so the check can never pass before
promotion: the live runs need a resolver on `vmbr111` or a plan option that accepts "no resolver" explicitly.

QEMU-GA and VirtIO Serial:

```
Name     Status StartType
QEMU-GA Running Automatic
FriendlyName         Status      Problem Class  InstanceId
VirtIO Serial Driver OK     CM_PROB_NONE System PCI\VEN_1AF4&DEV_1003&SUBSYS_00031AF4&REV_00\3&267A616A&0&40
```

`qm agent 731 ping` on apollo: exit 0.

### Stage 1

As Administrator over the key login:

```powershell
Rename-Computer -NewName BDC1 -Force
w32tm /config /manualpeerlist:"10.111.0.1,0x8" /syncfromflags:manual /reliable:yes /update
Restart-Service w32time
Set-DnsClientServerAddress -InterfaceAlias Ethernet -ServerAddresses 10.111.0.1
Install-WindowsFeature AD-Domain-Services, RSAT-AD-Tools, Windows-Server-Backup
```

```
before ip: 10.111.0.41/24 Manual gw 10.111.0.1
Rename-Computer: The changes will take effect after you restart the computer BUILD1.
w32tm /config exit 0
AnnounceFlags: 5 (Local) | Type: NTP (Local) | NtpServer: 10.111.0.1,0x8 (Local)
dns client: 10.111.0.1
Install-WindowsFeature in 27933 ms: Success True RestartNeeded No ExitCode Success
  AD-Domain-Services, RSAT, RSAT-AD-AdminCenter, RSAT-AD-PowerShell, RSAT-AD-Tools, RSAT-ADDS, RSAT-ADDS-Tools,
  RSAT-ADLDS, RSAT-Role-Tools, Windows-Server-Backup: Success True, RestartNeeded False
after ip: 10.111.0.41/24 Manual gw 10.111.0.1
```

`RSAT-AD-Tools` pulls in `RSAT-AD-PowerShell`, `RSAT-ADDS` and the rest; the features need no restart, only the rename
does. `Restart-Computer -Force` at 13:59:12.58Z; the key login answered with a new `LastBootUpTime` (13:59:23.5Z) 24 s
after the call. Read-back:

```
cs: Name BDC1 | DomainRole 2 | PartOfDomain False | Workgroup WORKGROUP
AD-Domain-Services Installed | DNS Available | RSAT-AD-Tools Installed | RSAT-AD-PowerShell Installed | RSAT-ADDS Installed
RSAT-AD-AdminCenter Installed | RSAT-ADDS-Tools Installed | RSAT-ADLDS Installed | Windows-Server-Backup Installed
ip: 10.111.0.41/24 Manual gw 10.111.0.1
dns client: 10.111.0.1
w32tm source: Local CMOS Clock
Type: NTP (Local) | NtpServer: 10.111.0.1,0x8 (Local)
```

`w32tm /query /source` still says `Local CMOS Clock` because nothing answers NTP at 10.111.0.1: the stage's read-back
of the time source has to read the configuration (`NtpServer`, `Type`), not the source, unless the peer answers.

### Stage 2

The DSRM password went to the VM on stdin (`powershell -EncodedCommand <script>` reading `[Console]::In`, from
`build-dsrm.pw`) into `C:\NewtonBuild\dsrm.bin` (DPAPI LocalMachine, 246 bytes); it was never on a command line, in
a script or in output. The promotion ran in the password task as `newton-build`:

```powershell
$sec = ConvertTo-SecureString ([Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($f), $null, 'LocalMachine'))) -AsPlainText -Force
Remove-Item $f
Install-ADDSForest -DomainName build.newton.test -DomainNetbiosName NBUILD -ForestMode Win2025 -DomainMode Win2025 -InstallDns -SafeModeAdministratorPassword $sec -NoRebootOnCompletion -Force
```

```
registered NewtonBuild-promote as newton-build LogonType Password RunLevel Highest
task state Ready LastTaskResult 0 after 139 s
task identity: bdc1\newton-build | auth NTLM
dsrm.bin deleted: True
A delegation for this DNS server cannot be created because the authoritative parent zone cannot be found or it does not run Windows DNS server. [...] (twice)
Install-ADDSForest returned after 135 s
Message        : You must restart this computer to complete the operation.
Context        : DCPromo.General.4
RebootRequired : True
Status         : Success
```

So a local administrator's password task can promote, and `-NoRebootOnCompletion` returns `Status Success,
RebootRequired True` with the task's `LastTaskResult 0`.

First reboot: `Restart-Computer -Force` at 14:03:18.49Z; `LastBootUpTime` 14:03:25.5Z, but the key login answered only
**333 s** after the call (sshd waits behind the first boot's directory set-up). `Get-ADDomain` answered on the first try
then (uptime 333 s). After the first boot:

```
msDS-GenerationId on CN=BDC1,OU=Domain Controllers,DC=build,DC=newton,DC=test: absent
  DS event 2168 at 2026-11-13T14:03:28.9631802Z: The DC is running on a supported hypervisor. VM Generation ID is detected.
```

The forced-command key login after the first boot (the `Match User ...,nbuild\newton-build` line matched):

```
whoami /user: "nbuild\newton-build","S-1-5-21-4035822249-418844242-2991919587-1000"
logon: Kerberos | ImpersonationLevel None
"BUILTIN\Administrators","Alias","S-1-5-32-544",...
"Service asserted identity","Well-known group","S-1-18-2",...
"Mandatory Label\High Mandatory Level","Label","S-1-16-12288",""
```

Post-boot writes, in the password task as `NBUILD\newton-build`:

```
task identity: nbuild\newton-build | auth Kerberos
token groups at task start: S-1-5-32-544
Add-ADGroupMember 'Domain Admins' newton-build: ok
Add-ADGroupMember 'Enterprise Admins' newton-build: ok
Add-ADGroupMember 'Schema Admins' newton-build: ok
Get-ADPrincipalGroupMembership: Administrators, Domain Admins, Domain Users, Enterprise Admins, Schema Admins
LastTaskResult 0 after 7 s
```

Straight after the add, before the second reboot: a new S4U key login still had only 544 and `S-1-18-2` (no 512, 518,
519), while a new password task had them at once (`groups: S-1-5-32-544, ...-512, ...-519, ...-518`). The section 3
measurement holds on apollo.

Second reboot: call at 14:09:55.35Z, `LastBootUpTime` 14:10:05.5Z, key login back **63 s** after the call. Then
readiness:

```
Attempting to perform the InitializeDefaultDrives operation on the 'ActiveDirectory' provider failed.
  try 1 at uptime 58 s: ArgumentException: Server instance not found on the given port. | ADWS Running
Get-ADDomain answered on try 7, 23 s after this wait started, uptime 78 s: build.newton.test NBUILD DomainMode Windows2025Domain
```

`msDS-GenerationId`, polled every 5 s: present on the first read, 2 s into the poll (uptime 89 s):

```
msDS-GenerationId on CN=BDC1,OU=Domain Controllers,DC=build,DC=newton,DC=test: present, 8 bytes, 1940638af455194b
  DS event 2168 at 2026-11-13T14:03:28.9631802Z: The DC is running on a supported hypervisor. VM Generation ID is detected.
  DS event 2179 at 2026-11-13T14:09:55.8288396Z: The msDS-GenerationId attribute of the Domain Controller's computer object has been set to the following parameter:
  DS event 2172 at 2026-11-13T14:10:08.9499399Z: Read the msDS-GenerationId attribute of the Domain Controller's computer object.
  DS event 2168 at 2026-11-13T14:10:08.9499399Z: The DC is running on a supported hypervisor. VM Generation ID is detected.
```

The attribute was written (2179) at 14:09:55.83Z, half a second after `Restart-Computer`: during the first boot's
shutdown, not during the first boot (it was absent at uptime 338 s). So one reboot after the first post-promotion boot
is enough here, and the poll after the second boot finds it at once. The forced-command key login after the second
reboot has the groups:

```
"BUILTIN\Administrators","Alias","S-1-5-32-544",...
"NBUILD\Domain Admins","Group","S-1-5-21-4035822249-418844242-2991919587-512","Mandatory group, Enabled by default, Enabled group"
"NBUILD\Enterprise Admins","Group","S-1-5-21-4035822249-418844242-2991919587-519","Mandatory group, Enabled by default, Enabled group"
"NBUILD\Schema Admins","Group","S-1-5-21-4035822249-418844242-2991919587-518","Mandatory group, Enabled by default, Enabled group"
"Service asserted identity","Well-known group","S-1-18-2",...
```

Read-back (as Administrator, after the second boot):

```
dcdiag /q exit 0, 42 lines: BDC1 failed test DFSREvent; BDC1 failed test SystemLog
  (DFSREvent: event 0x422 at 14:08:45, Group Policy could not read \\build.newton.test\sysvol\...\{31B2F340-016D-11D2-945F-00C04FB984F9}\gpt.ini;
   SystemLog: 0xC0001B7A "The OpenSSH SSH Server service terminated unexpectedly" at 13:59:17 and 14:03:18 (the restarts),
   0xC0000007 at 14:10:49 "The Security Account Manager failed a KDC request in an unexpected way ... lookup type 0x108")
dcdiag exit 0; passed: Connectivity Advertising FrsEvent SysVolCheck KccEvent KnowsOfRoleHolders MachineAccount NCSecDesc
  NetLogons ObjectsReplicated Replications RidManager Services VerifyReferences, and every partition test, LocatorCheck, Intersite
NETLOGON C:\WINDOWS\SYSVOL\sysvol\build.newton.test\SCRIPTS
SYSVOL   C:\WINDOWS\SYSVOL\sysvol
SYSVOLReady: 1
SRV _ldap._tcp.dc._msdcs.build.newton.test -> bdc1.build.newton.test:389
SRV _kerberos._tcp.build.newton.test -> bdc1.build.newton.test:88
SRV _gc._tcp.build.newton.test -> bdc1.build.newton.test:3268
SRV _ldap._tcp.pdc._msdcs.build.newton.test -> bdc1.build.newton.test:389
ForestMode Windows2025Forest DomainMode Windows2025Domain | forest build.newton.test | NetBIOS NBUILD
msDS-Behavior-Version: forest 10 domain 10
dns client after promotion: 127.0.0.1,::1
DNS forwarders: 10.111.0.1
newton-build memberships (Get-ADPrincipalGroupMembership): Administrators, Domain Admins, Domain Users, Enterprise Admins, Schema Admins
```

For the stage 2 template:
- `dcdiag` exits 0 with failed tests: the read-back parses the `passed test` / `failed test` lines. A fresh forest fails
  `DFSREvent` and `SystemLog` on events from its own first boot and from sshd restarts, so the read-back needs a list of
  the tests that must pass (or an accepted-event list), not "no failed test".
- Promotion turned the client DNS server set in stage 1 into the forwarder and set the client to `127.0.0.1,::1`: stage 1
  sets the plan's forwarders as client DNS servers and stage 2 reads them back as `Get-DnsServerForwarder`.

### Stage 3

In the password task as `NBUILD\newton-build` (after the second reboot):

```
token groups: NBUILD\Domain Admins, NBUILD\Enterprise Admins, NBUILD\Schema Admins
before: EnabledScopes count 0 | FeatureScope ForestOrConfigurationSet | RequiredForestMode Windows2008R2Forest
Enabling 'Recycle Bin Feature' on 'CN=Partitions,CN=Configuration,DC=build,DC=newton,DC=test' is an irreversible action! [...]
Enable-ADOptionalFeature returned in 326 ms
after: EnabledScopes:
  CN=Partitions,CN=Configuration,DC=build,DC=newton,DC=test
msDS-EnabledFeature on Partitions: CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=build,DC=newton,DC=test
LastTaskResult 0 after 5 s
```

The command was `Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target
build.newton.test -Confirm:$false`. It passed first time (the section 3 failures on the first supernova forest did not
recur).

### Stage 4

In the password task as `NBUILD\newton-build`, one op: the schema read, `Update-LapsADSchema -Confirm:$false
-Verbose`, the schema read again, `New-ADOrganizationalUnit -Name 'Newton Servers'` (a test OU; the plan's OU tree is
stage 5's), `Set-LapsADComputerSelfPermission -Identity 'OU=Newton Servers,DC=build,DC=newton,DC=test'`, the OU's
SELF ACEs, then `Remove-ADGroupMember` from Enterprise and Schema Admins. `LastTaskResult 0` after 7 s.

```
schema before : objectVersion 91
  ms-LAPS-Password : absent
  ms-LAPS-PasswordExpirationTime : absent
  ms-LAPS-EncryptedPassword : absent
  ms-LAPS-EncryptedPasswordHistory : absent
  ms-LAPS-EncryptedDSRMPassword : absent
  ms-LAPS-EncryptedDSRMPasswordHistory : absent
  ms-Mcs-AdmPwd : absent
  computer mayContain msLAPS-*:
Update-LapsADSchema returned in 1075 ms
  (verbose: binds to the schema FSMO BDC1.build.newton.test; adds the seven attributes above minus ms-Mcs-AdmPwd plus
   ms-LAPS-CurrentPasswordVersion, the extended right ms-LAPS-Encrypted-Password-Attributes, and the 7 mayContains on computer)
schema after : objectVersion 91
  ms-LAPS-Password : present, lDAPDisplayName msLAPS-Password, schemaIDGUID c2669bb2-4ab3-468b-87cd-ceb5b1de5011
  ms-LAPS-PasswordExpirationTime : present, lDAPDisplayName msLAPS-PasswordExpirationTime, schemaIDGUID a2e8a763-9d06-46ae-addc-67f929ea585f
  ms-LAPS-EncryptedPassword : present, lDAPDisplayName msLAPS-EncryptedPassword, schemaIDGUID bb4e3d7d-e402-462f-a7bc-986b9434181a
  ms-LAPS-EncryptedPasswordHistory : present, lDAPDisplayName msLAPS-EncryptedPasswordHistory, schemaIDGUID a78db058-f916-44ab-9393-30e33d4ba79b
  ms-LAPS-EncryptedDSRMPassword : present, lDAPDisplayName msLAPS-EncryptedDSRMPassword, schemaIDGUID 9b06beb0-7501-4261-b3c2-a2c88c2e93c7
  ms-LAPS-EncryptedDSRMPasswordHistory : present, lDAPDisplayName msLAPS-EncryptedDSRMPasswordHistory, schemaIDGUID 3b8c969d-fba6-497e-ad37-de47532571cc
  ms-Mcs-AdmPwd : absent
  computer mayContain msLAPS-*: msLAPS-CurrentPasswordVersion, msLAPS-EncryptedDSRMPassword, msLAPS-EncryptedDSRMPasswordHistory, msLAPS-EncryptedPassword, msLAPS-EncryptedPasswordHistory, msLAPS-Password, msLAPS-PasswordExpirationTime
OU ACEs for SELF (explicit ones first):
  NT AUTHORITY\SELF | ReadProperty, WriteProperty | Allow | ObjectType a2e8a763-9d06-46ae-addc-67f929ea585f (msLAPS-PasswordExpirationTime) | InheritanceType Descendents | InheritedObjectType bf967a86-0de6-11d0-a285-00aa003049e2 | IsInherited False
  NT AUTHORITY\SELF | ReadProperty, WriteProperty, ExtendedRight | Allow | ObjectType f3531ec6-6330-4f8e-8d39-7a671fbac605 (extended right ms-LAPS-Encrypted-Password-Attributes) | InheritanceType Descendents | InheritedObjectType bf967a86-0de6-11d0-a285-00aa003049e2 | IsInherited False
  NT AUTHORITY\SELF | WriteProperty | Allow | ObjectType c2669bb2-4ab3-468b-87cd-ceb5b1de5011 (msLAPS-Password) | InheritanceType Descendents | InheritedObjectType bf967a86-0de6-11d0-a285-00aa003049e2 | IsInherited False
  (4 inherited SELF ACEs from the domain root, IsInherited True)
Remove-ADGroupMember 'Enterprise Admins' newton-build: ok
Remove-ADGroupMember 'Schema Admins' newton-build: ok
Get-ADPrincipalGroupMembership after: Administrators, Domain Admins, Domain Users
  Domain Admins members: Administrator, newton-build
  Enterprise Admins members: Administrator
  Schema Admins members: Administrator
```

`bf967a86-...` is the `computer` class. The schema `objectVersion` stays 91: it is not a LAPS read-back. The OU
read-back is the three explicit SELF ACEs above (by `ObjectType`, `InheritedObjectType` computer, not inherited).

After the removal, without a reboot:

```
forced-command S4U key login:  ... -512 (Domain Admins), -519 (Enterprise Admins), -518 (Schema Admins), S-1-18-2 ...
a new password task:           groups: S-1-5-32-544, S-1-5-21-4035822249-418844242-2991919587-512
```

The S4U key login keeps Enterprise and Schema Admins after they are removed, until a reboot (the mirror of section
3's "groups added are missing until a reboot"). For the stage 4 template: the membership read-back reads the directory
(`Get-ADPrincipalGroupMembership`, `Get-ADGroupMember`) or a new password task, never the S4U token; and until the next
reboot the key login itself still holds EA and SA. The stage table has no DC1 reboot in stages 5 to 8, so the build key login keeps
EA and SA until stage 9 unless stage 4 ends with a reboot. That is a design question for the maintainer, not settled here.
(the maintainer chose the reboot, 2026-11-13: stage 4 now ends with a DC1 reboot and reads the groups back; measured in "Stage 4
reboot, 2026-11-13/14" below.)

### Timings

| Step | Time |
|---|---|
| `qm start 731` to the key login | 16 s |
| Stage 1 `Install-WindowsFeature` | 28 s |
| Stage 1 reboot, `Restart-Computer` to key login | 24 s |
| `Install-ADDSForest -NoRebootOnCompletion` in the task | 135 s (task 139 s) |
| First post-promotion reboot, `Restart-Computer` to key login | 333 s (`Get-ADDomain` answered at once then) |
| Add the three groups (task) | 7 s |
| Second reboot, `Restart-Computer` to key login | 63 s; `Get-ADDomain` at uptime 78 s (23 s of "Server instance not found") |
| `msDS-GenerationId` after the second boot | present on the first read (uptime 89 s) |
| Stage 3 task / Stage 4 task | 5 s / 7 s |
| `qm shutdown 731` | 6 s |

### After

`qm shutdown 731 --timeout 300` (exit 0 in 6 s), `qm rollback 731 fresh-2026-11-13` as root (exit 0); `qm status
731` stopped, `qm listsnapshot 731` shows `fresh-2026-11-13` then `current`; vmgenid `5781ffdf-9551-49ab-b94c-1d189c4fe1cc`
(a new one, as every rollback). `vmdata` 70.89% before, 70.90% after; `free -m` available 5858 MB before, 6654 MB
after. 721 and 723 running, 722, 724 and 732 stopped, unchanged.

## The ops of stages 0 to 4 on BUILD1, second run (2026-11-13)

The ops of task 5 themselves, rendered by `build.ps1` (`Get-NewtonOpScript`, the lab's values: `build.newton.test`,
`NBUILD`, `BDC1`, 10.111.0.41, time peer and forwarder 10.111.0.1) and run on BUILD1 from `fresh-2026-11-13`. The
renders equal the golden renders with the addresses swapped. This run answers the open question of the stage 4
target (the self-permission on `OU=Domain Controllers`, not a test OU), and its output files are the fixtures of
`test_build_stages_0_4.py`, wrapper lines included.

### How it ran

A stand-in for the bootstrap, as before (`C:\NewtonBuild` with SYSTEM and Administrators only, a local `newton-build`
with a random password in `pw.bin`, 262 bytes, in Administrators). Each op went to `C:\NewtonBuild\ops\<op>.ps1` (UTF-8
with BOM, as `Invoke-NewtonStageOp` writes it). s0-read, s1-base and s1-read ran with `powershell.exe -File` as
Administrator (the helper's own session runs them; here the key login was Administrator's). Every op from s2-promote
on ran in a one-shot task registered the way `Invoke-NewtonPasswordTask` does it, with `-User` `BDC1\newton-build`
before the promotion and `NBUILD\newton-build` after it (readback: `LogonType Password RunLevel Highest`). The DSRM
file went to the VM on stdin as before (246 bytes); `dsrm.bin deleted: True`. The reboots were `shutdown /r /t 2`.

| Op | Result | Time |
|---|---|---|
| s0-read | exit 0; the DNS line is 1460 (`-DnsOnly`, no DNS server), so stage 0 would stop with `dns_unchecked` | 7 s |
| s1-base | exit 0, `Install-WindowsFeature` 27818 ms, the IP unchanged | 32 s |
| s1-read (after the reboot) | `BDC1`, the features `Installed`, `NtpServer: 10.111.0.1,0x8 (Local)`, `w32tm source: Local CMOS Clock` | 8 s |
| s2-promote | task `LastTaskResult 0`; `RebootRequired : True`, `Status : Success`; `Install-ADDSForest returned after 135 s` | 144 s |
| first reboot | key login back 333 s after the call (polled every 6 s after a 60 s wait) | |
| s2-groups | `token groups at task start: S-1-5-32-544`; the three adds ok | 10 s |
| s2-genid | `absent`, `uptime s 349`, only event 2168 | 6 s |
| second reboot | key login back 57 s after the call (polled every 6 s after a 30 s wait); `Get-ADDomain` on try 8 (3 s apart) | |
| s2-genid | `present, 8 bytes`, `uptime s 90`; events 2168, 2179 (at 16:13:12.24Z, during the shutdown for the second reboot), 2172, 2168 | 10 s |
| s2-read | dcdiag fails `DFSREvent` and `SystemLog` only (the same events as the first run); SYSVOLReady 1; the four SRV records; levels 10; `dns client after promotion: 127.0.0.1` (the first run printed `127.0.0.1,::1`); forwarder 10.111.0.1 | 12 s |
| s3-recyclebin | `EnabledScopes count 0` before; the Partitions scope after | 6 s |
| s4-laps | below | 8 s |

### Stage 4 on the Domain Controllers OU

```
Update-LapsADSchema returned in 1016 ms
schema after : objectVersion 91
  ms-LAPS-Password : present, lDAPDisplayName msLAPS-Password, schemaIDGUID e95aa6f5-1f87-4e83-a213-ff09e5941996
  ms-LAPS-PasswordExpirationTime : present, lDAPDisplayName msLAPS-PasswordExpirationTime, schemaIDGUID 9b5c1e57-ff56-4f14-9bd2-aa657d0390a9
  ms-LAPS-EncryptedPassword : present, lDAPDisplayName msLAPS-EncryptedPassword, schemaIDGUID 3d0be8e4-b268-46b9-9a2a-de2301fa5cae
  ms-LAPS-EncryptedPasswordHistory : present, lDAPDisplayName msLAPS-EncryptedPasswordHistory, schemaIDGUID ec250db9-15d4-4886-9e93-68f8a7d9df38
  ms-LAPS-EncryptedDSRMPassword : present, lDAPDisplayName msLAPS-EncryptedDSRMPassword, schemaIDGUID 7fcdfb83-6396-457f-a518-d0b4dc0944e9
  ms-LAPS-EncryptedDSRMPasswordHistory : present, lDAPDisplayName msLAPS-EncryptedDSRMPasswordHistory, schemaIDGUID 292d652a-ba0e-48e7-988d-10150df64436
  ms-Mcs-AdmPwd : absent
  computer mayContain msLAPS-*: msLAPS-CurrentPasswordVersion, msLAPS-EncryptedDSRMPassword, msLAPS-EncryptedDSRMPasswordHistory, msLAPS-EncryptedPassword, msLAPS-EncryptedPasswordHistory, msLAPS-Password, msLAPS-PasswordExpirationTime
Set-LapsADComputerSelfPermission: OU=Domain Controllers,DC=build,DC=newton,DC=test
Name              : Domain Controllers
DistinguishedName : OU=Domain Controllers,DC=build,DC=newton,DC=test
OU ACEs for SELF:
  NT AUTHORITY\SELF | ReadProperty, WriteProperty, ExtendedRight | Allow | ObjectType f3531ec6-6330-4f8e-8d39-7a671fbac605 () | InheritanceType Descendents | InheritedObjectType bf967a86-0de6-11d0-a285-00aa003049e2 | IsInherited False
  NT AUTHORITY\SELF | ReadProperty, WriteProperty | Allow | ObjectType 9b5c1e57-ff56-4f14-9bd2-aa657d0390a9 (msLAPS-PasswordExpirationTime) | InheritanceType Descendents | InheritedObjectType bf967a86-0de6-11d0-a285-00aa003049e2 | IsInherited False
  NT AUTHORITY\SELF | WriteProperty | Allow | ObjectType e95aa6f5-1f87-4e83-a213-ff09e5941996 (msLAPS-Password) | InheritanceType Descendents | InheritedObjectType bf967a86-0de6-11d0-a285-00aa003049e2 | IsInherited False
  (4 inherited SELF ACEs, IsInherited True, the same four as on the test OU)
Remove-ADGroupMember 'Enterprise Admins' newton-build: ok
Remove-ADGroupMember 'Schema Admins' newton-build: ok
Get-ADPrincipalGroupMembership after: Administrators, Domain Admins, Domain Users
```

Then, as Administrator:

```
extended right ms-LAPS-Encrypted-Password-Attributes: rightsGuid f3531ec6-6330-4f8e-8d39-7a671fbac605 | appliesTo  | validAccesses 48
ms-LAPS-Password : schemaIDGUID e95aa6f5-1f87-4e83-a213-ff09e5941996 | attributeID 1.2.840.113556.1.6.44.1.2
ms-LAPS-CurrentPasswordVersion : schemaIDGUID 4cfc6390-d4fa-4ab0-b2dc-22b7c4d36413 | attributeID 1.2.840.113556.1.6.44.1.7
```

For the stage 4 template:
- On `OU=Domain Controllers` the self-permission gives the same three explicit SELF ACEs as on the test OU (the rights,
  `InheritanceType Descendents`, `InheritedObjectType` computer, not inherited), in another order.
- **The LAPS schemaIDGUIDs are not constants.** Each forest has its own: `msLAPS-Password` was `c2669bb2-...` in the
  first forest and `e95aa6f5-...` in this one, and all six differ. `Update-LapsADSchema` leaves the schemaIDGUID to the
  directory; the attributeIDs (OIDs) are fixed. The extended right's rightsGuid `f3531ec6-...` is the same in both
  forests. So the read-back takes each attribute's GUID from its own schema read and holds the two attribute ACEs to
  those GUIDs; only the extended right is pinned. The helper as first written pinned the first forest's GUIDs and
  would have stopped every new forest at stage 4 with `readback_failed`.

### After

`qm shutdown 731 --timeout 300` exit 0, `qm rollback 731 fresh-2026-11-13` exit 0; `qm status 731` stopped, the
snapshot list `fresh-2026-11-13` then `current`, a new vmgenid. `vmdata` 70.93% before, 70.94% after; available RAM
16056 MB before, 15596 MB after. 721 and 723 running, 722, 724 and 732 stopped, unchanged.

Still open for the maintainer (unchanged by this run): stage 0 cannot pass on a fresh VM with no resolver (the 1460 line above);
the time peer is the plan's gateway because the plan has no time-source field; stage 4 does not reboot, so the S4U key
login keeps Enterprise and Schema Admins until stage 9. (the maintainer chose the reboot, 2026-11-13: stage 4 now ends with a DC1
reboot; see "Stage 4 reboot, 2026-11-13/14".)

## Stage 2 resumed: the role of the server (BUILD1, 2026-11-13)

The question (the task 5 triage, X2): a stage 2 that stops after its promotion succeeded (a refused restart, a failed
group add, `directory_unready`, `generation_id_missing`, a failed read-back) is resumed by a new plan with
`start_stage` 2. Nothing had measured what the server reports in those states, so a resumed stage 2 could not tell a
server it must promote from one it already promoted. Measured on BUILD1 from `fresh-2026-11-13`: the bootstrap
stand-in and stage 1 as in the second run above, then the read below (the `s2-role` op of `build.ps1`, rendered
byte for byte as it ran here) at each point, as Administrator in the helper's own kind of session and, where marked,
in the password task as newton-build. The promotion was the `s2-promote` op in the password task (`LastTaskResult 0`
after 142 s).

```powershell
$cs = Get-CimInstance -ClassName Win32_ComputerSystem
'cs: Name ' + $cs.Name + ' | DomainRole ' + $cs.DomainRole + ' | PartOfDomain ' + $cs.PartOfDomain + ' | Domain ' + $cs.Domain + ' | Workgroup ' + $cs.Workgroup
'ProductType: ' + (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions').ProductType
$ntds = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -ErrorAction SilentlyContinue
if ($ntds) { 'NTDS Parameters: present | Root Domain ' + $ntds.'Root Domain' + ' | Machine DN Name ' + $ntds.'Machine DN Name' } else { 'NTDS Parameters: absent' }
$svc = Get-Service -Name NTDS -ErrorAction SilentlyContinue
'NTDS service: ' + $(if ($svc) { [string]$svc.Status + ', ' + [string]$svc.StartType } else { 'absent' })
try { $d = Get-ADDomain -ErrorAction Stop; 'Get-ADDomain: DNSRoot ' + $d.DNSRoot + ' | NetBIOSName ' + $d.NetBIOSName } catch { 'Get-ADDomain: FAIL ' + $_.Exception.GetType().FullName + ': ' + $_.Exception.Message }
```

```
fresh (before stage 1):
cs: Name BUILD1 | DomainRole 2 | PartOfDomain False | Domain WORKGROUP | Workgroup WORKGROUP
ProductType: ServerNT
NTDS Parameters: absent
NTDS service: absent
Get-ADDomain: FAIL System.Management.Automation.CommandNotFoundException: The term 'Get-ADDomain' is not recognized [...]

after stage 1 and its reboot, before the promotion:
cs: Name BDC1 | DomainRole 2 | PartOfDomain False | Domain WORKGROUP | Workgroup WORKGROUP
ProductType: ServerNT
NTDS Parameters: absent
NTDS service: Stopped, Disabled
Get-ADDomain: FAIL Microsoft.ActiveDirectory.Management.ADServerDownException: Unable to find a default server with Active Directory Web Services running.

after Install-ADDSForest -NoRebootOnCompletion, before any reboot (the same as Administrator and in the task):
cs: Name BDC1 | DomainRole 3 | PartOfDomain True | Domain build.newton.test | Workgroup
ProductType: LanmanNT
NTDS Parameters: present | Root Domain DC=build,DC=newton,DC=test | Machine DN Name CN=NTDS Settings,CN=BDC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=build,DC=newton,DC=test
NTDS service: Stopped, Automatic
Get-ADDomain: FAIL Microsoft.ActiveDirectory.Management.ADServerDownException: Unable to find a default server with Active Directory Web Services running.

after the first boot (uptime about 330 s; the same once Get-ADDomain answered, and in the task as NBUILD\newton-build):
cs: Name BDC1 | DomainRole 5 | PartOfDomain True | Domain build.newton.test | Workgroup
ProductType: LanmanNT
NTDS Parameters: present | Root Domain DC=build,DC=newton,DC=test | Machine DN Name CN=NTDS Settings,CN=BDC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=build,DC=newton,DC=test
NTDS service: Running, Automatic
Get-ADDomain: DNSRoot build.newton.test | NetBIOSName NBUILD
```

Then `s2-groups` in the password task twice: the second run, with newton-build already in the three groups (its
token at task start held 512, 518 and 519), printed `Add-ADGroupMember '<group>' newton-build: ok` for each and
`LastTaskResult 0`: adding a member that is already there does not fail.

For the stage 2 template:
- **Between the promotion and the first boot, `DomainRole` is 3, the member-server value**, not 4 or 5. A read of
  `DomainRole` alone would take the promoted server for a member server. `ProductType LanmanNT` and the NTDS `Root
  Domain` of the plan's forest are what tell it apart, before and after the boot.
- `Get-ADDomain` does not answer before the first boot, so it can only confirm the plan's DNS and NetBIOS names when
  it answers; it cannot be required.
- The helper's rule (`Get-NewtonRoleVerdict`): the workgroup server above (2, `False`, `ServerNT`, no NTDS
  parameters) is promoted; this plan's forest root (`LanmanNT`, `DomainRole` 3 or 5, `PartOfDomain True`, the plan's
  domain, the NTDS `Root Domain` of the plan's DN, and `Get-ADDomain` either failing or naming the plan's DNS and
  NetBIOS names) skips the promotion and goes on to the reboot, the groups (re-adding is measured harmless above),
  the second reboot and the `msDS-GenerationId` read; any other `LanmanNT` server with a root domain is
  `domain_mismatch`, and any other role (a member server, a workgroup server with NTDS parameters) is `not_workgroup`.
  The other-domain and member-server bytes in the tests are the measured lines with the domain changed; neither was
  measured on a real server of another domain.

After: `qm shutdown 731` exit 0, `qm rollback 731 fresh-2026-11-13` exit 0, `qm status 731` stopped, the snapshot list
`fresh-2026-11-13` then `current`. `vmdata` 70.94% before and after; available RAM 15877 MB before, 15527 MB after;
721 and 723 running, 722, 724 and 732 stopped, unchanged.

### The op's result file (the same day, a second short run)

The ops now end by writing their exit code to `C:\NewtonBuild\out\<op>.rc` (`FileMode CreateNew`, `Flush($true)`)
after the output file is closed, so a status request can record the outcome of an op whose helper session dropped
(the task 5 triage, X1). The `s2-role` op rendered with those lines ran on BUILD1 from `fresh-2026-11-13` (bootstrap
stand-in only), once in the session and once in the password task as `BUILD1\newton-build` (`LastTaskResult 0` after
9 s):

```
C:\NewtonBuild\out\s2-role.rc: 1 bytes, text [0]
C:\NewtonBuild\out\s2-role.txt: 588 bytes        (in the session)
C:\NewtonBuild\out\s2-role.rc: 1 bytes, text [0]
C:\NewtonBuild\out\s2-role.txt: 587 bytes        (in the task)
```

After: shutdown and rollback exit 0, `qm status 731` stopped at `fresh-2026-11-13`; `vmdata` 70.94% before and after.

## Stage 4 reboot, 2026-11-13/14

The maintainer's decision (2026-11-13): stage 4 ends with a DC1 reboot, and after the boot Newton reads the build login's groups
back and stops the stage if Enterprise Admins or Schema Admins remain. Measured on BUILD1 (VM 731) from
`fresh-2026-11-13` before the helper was changed. Log: `lab.log` in the session scratchpad folder `s4r` (the script
`lab.sh` beside it); the ops are `build.ps1`'s renders with the lab's values, `s4-groups` included.

How it ran: the bootstrap stand-in with the forced command a probe (`probe.ps1`) that, for the login's
`SSH_ORIGINAL_COMMAND`, runs `C:\NewtonBuild\ops\<op>.ps1` with `powershell.exe -File` in the key login's own session
(the way `Invoke-NewtonStageOp` runs a session op), prints the op's output and `.rc`, and prints the session's own
`whoami /groups /fo csv /nh`; `restart` runs `shutdown.exe /r /t 10` (the helper's `Invoke-NewtonRestart`). Then s1-base
and its reboot, the DSRM file, s2-promote (task `LastTaskResult 0` after 143 s; `Install-ADDSForest returned after 136
s`), the first reboot (key login back 276 s after the call; `Get-ADDomain` at once, uptime 334 s), s2-groups (7 s), the
second reboot (34 s; `Get-ADDomain` on try 7, uptime 77 s), s2-genid (`present, 8 bytes`, uptime 89 s), s3-recyclebin
(6 s), s4-laps (8 s; the measured read-back, a third forest's schemaIDGUIDs again all new). Then:

```
after s4-laps, before the reboot, the newton-build S4U key login (whoami /groups, the domain SID masked):
"NBUILD\Domain Admins","Group","S-1-5-21-1000000001-1000000002-1000000003-512","Mandatory group, Enabled by default, Enabled group"
"NBUILD\Enterprise Admins","Group","S-1-5-21-1000000001-1000000002-1000000003-519","Mandatory group, Enabled by default, Enabled group"
"NBUILD\Schema Admins","Group","S-1-5-21-1000000001-1000000002-1000000003-518","Mandatory group, Enabled by default, Enabled group"
(13 lines in all; the same before the restart call)

s4-groups in a password task, before the reboot (the directory has already let go):
Get-ADPrincipalGroupMembership: Administrators (S-1-5-32-544), Domain Admins (S-1-5-21-...-512), Domain Users (S-1-5-21-...-513)
  Enterprise Admins (S-1-5-21-...-519) members: Administrator
  Schema Admins (S-1-5-21-...-518) members: Administrator

the restart from the key login: shutdown.exe /r /t 10 exit 0; the key login back 52 s after the call (LastBootUpTime
21:51:24.5Z)

s4-groups over the key login as soon as it answered (uptime about 55 s): exit 1, .rc [1]
FAIL: System.ArgumentException: Server instance not found on the given port.

s4-groups over the key login once Get-ADDomain answered (twice, the same bytes): exit 0, .rc [0], 625 bytes
task identity: nbuild\newton-build | auth Kerberos
LastBootUpTime: 2026-11-13T21:51:24.5000000Z
domain: build.newton.test | DomainSID S-1-5-21-1000000001-1000000002-1000000003
Get-ADPrincipalGroupMembership: Administrators (S-1-5-32-544), Domain Admins (S-1-5-21-...-512), Domain Users (S-1-5-21-...-513)
  Enterprise Admins (S-1-5-21-...-519) members: Administrator
  Schema Admins (S-1-5-21-...-518) members: Administrator

the key login's token after the boot: 11 lines, -512 and no -518 or -519
```

So the ruling holds: the directory drops newton-build from EA and SA at once, the S4U key login keeps both SIDs until
the reboot, and after it neither. The directory read works over the S4U key login (no password task needed) once
`Get-ADDomain` answers; before that it fails, so the post-boot status waits for the directory first, as stage 2 does.
The restart works from the S4U key login.

IC-7 (a review): `s2-role` over the newton-build S4U key login on the promoted DC (after the stage 4 boot) printed `cs:
Name BDC1 | DomainRole 5 | PartOfDomain True | Domain build.newton.test`, `ProductType: LanmanNT`, the NTDS parameters
of the forest, `NTDS service: Running, Automatic` and `Get-ADDomain: DNSRoot build.newton.test | NetBIOSName NBUILD`:
the same lines as `s2-role-dc.txt` (Administrator), so `Get-NewtonRoleVerdict` reads the key login's bytes as this
plan's forest root. The first try of the run, straight after s2-genid, did not run (the op file was not on the VM yet:
a lab-script slip), so this read is after the stage 4 boot, not before it.

Fixtures (`mcp/tests/ad/build/fixtures/stages_0_4`, BOM and CR dropped, the domain SID masked): `s4-groups.txt`,
`s4-groups-directory-unready.txt`, `s4-groups-task-before-boot.txt`, `s4-s4u-groups-before-boot.txt`,
`s4-s4u-groups-after-boot.txt`, `s2-role-key-login.txt`.

After: `qm shutdown 731` exit 0, `qm rollback 731 fresh-2026-11-13` exit 0, `qm status 731` stopped, the snapshot list
`fresh-2026-11-13` then `current`. `vmdata` 70.94% before, 70.95% after; available RAM 15505 MB before, 15249 MB after;
721 and 723 running, 722, 724 and 732 stopped, unchanged.

## Stages 5 and 6 on BUILD1, 2026-11-14

PLAN-1.5 task 6, measured before the stage 5 and 6 templates were trusted. BUILD1 (VM 731) from `fresh-2026-11-13`,
twice. Stages 1 to 3 ran as in "Stage 4 reboot" (the helper's own renders through the probe, `session.sh`); then
`steps.sh` (run 1) and `steps2.sh` (run 2) ran `build.ps1`'s own renders of s4-state, s4-laps, s5-structure,
s6-gpo-domain, s6-gpo-dc and s6-read in the password task as `NBUILD\newton-build` (the lab values: OUs `IT`,
`IT/Servers`, `Staff`, groups `IT Admins` and `Staff Users`, owner admin `owner-admin`). The admin secret went to
`C:\NewtonBuild\admin.bin` (DPAPI LocalMachine) over stdin, the way the DSRM file does; it was never printed.
Logs, in the session scratchpad folder `wf15t6/lab`: `run1/session.log` and `run1/steps.log` (00:15 to 00:31Z),
`session2.log` and `run2/steps2.log` (00:32 to 00:48Z), with each op's output as `m-<label>.txt` beside them.

Run 1:
- s4-state before s4-laps printed the measured before-state (no LAPS schema, no SELF ACE, newton-build in EA and SA),
  and after it the after-state (the schema attributes, the SELF ACE on the Domain Controllers OU, newton-build in
  Domain Admins only in the directory). These are the bytes the resumed stage 4 checks.
- s5-structure (random-password) and s5-structure with `disabled` (a rerun, every object already present: the op
  creates nothing and reads back the same) both ended rc 0. After `disabled` the built-in Administrator's key login
  was dead, as it should be.
- s6-gpo-domain failed: `Import-Module GroupPolicy` is not found. Stage 1 installs `RSAT-AD-Tools`, which does not
  include GPMC. The design does not say who installs GPMC; the op now installs it when it is absent (open point in
  DESIGN-1.5), and run 2 measured that.

Run 2 (the same stages 1 to 4, then):
- Before stage 5, `secedit /export /areas SECURITYPOLICY` on the new DC printed `MinimumPasswordLength = 0`,
  `PasswordHistorySize = 0`, `MaximumPasswordAge = 42`, `LockoutBadCount = 0`, while the Default Domain Policy's
  `GptTmpl.inf` in SYSVOL says `MinimumPasswordLength = 7`, `PasswordHistorySize = 24`, `MaximumPasswordAge = 42`.
  `Get-ADDefaultDomainPasswordPolicy` (the s6-read line before stage 5) agreed with secedit, not with the file.
- s5-structure: rc 0 after 10 s; `admin secret file deleted: True`; three OUs (protected), two Global Security groups
  in `CN=Users`, `owner-admin` (enabled, pwdLastSet 0) in Domain Admins (512) and Protected Users (525);
  `Set-ADDefaultDomainPasswordPolicy: ok` and the read-back 14 / 24 / 365 / 1 / complexity True / reversible False /
  10 / 15 min / 15 min; the PSO `Newton Tier 0 Admins`, precedence 10, min length 20, applied to Domain Admins;
  `built-in Administrator: password reset` and its `PasswordLastSet`.
- secedit straight after stage 5 and again after `gpupdate /force`: `MinimumPasswordLength = 14` both times. The
  domain object holds the baseline and a policy refresh does not revert it, although the DDP `GptTmpl.inf` still
  says 7 (open point in DESIGN-1.5).
- s6-gpo-domain: `GPMC: Available`, `Install-WindowsFeature GPMC: Success True RestartNeeded No ExitCode Success`,
  `before: GPOs of the name: 0`, `New-GPO`, seven `Set-GPRegistryValue ...: ok`, `New-GPLink ... | Enabled True |
  Order 2`; read-back `Computer DSVersion 7 SysvolVersion 7`, each value `DWord | Set`, the links DDP order 1 and the
  baseline order 2. 33 s, most of it the feature install.
- s6-gpo-dc: `GPMC: Installed`, two values, `Computer DSVersion 2 SysvolVersion 2`, linked to `OU=Domain Controllers`
  at order 2 after the Default Domain Controllers Policy. 5 s.
- s6-read: `gpupdate /target:computer /force exit 0`, all nine registry values at the baseline value, and the secedit
  export's `[System Access]` equal to the baseline (`MinimumPasswordAge = 1`, `MaximumPasswordAge = 365`,
  `MinimumPasswordLength = 14`, `PasswordComplexity = 1`, `PasswordHistorySize = 24`, `LockoutBadCount = 10`,
  `ClearTextPassword = 0`, lockout duration and reset 15). `[Registry Values]` lists each GPO value as
  `MACHINE\<path>\<name>=4,<value>`, with secedit's own case for the path (`LanManServer`), so the verdict compares
  the path without case.
- s5-structure with `disabled` again at the end: rc 0, nothing created, `built-in Administrator: disabled`,
  `Enabled False`.

Fixtures (`mcp/tests/ad/build/fixtures/stages_5_6`, BOM and CR dropped, the domain SID masked to
`S-1-5-21-1000000001-1000000002-1000000003`, GPO ids as measured): `s4-state-before.txt`, `s4-state-after.txt`,
`s5-structure.txt`, `s5-structure-disabled.txt` (run 1), `s6-gpo-domain.txt`, `s6-gpo-dc.txt`, `s6-read.txt`,
`secedit-default.txt` (run 2, the export before stage 5, which the stage 6 read verdict refuses); the golden renders
are in `golden/`.

After, both runs: `qm shutdown 731` exit 0, `qm rollback 731 fresh-2026-11-13` exit 0, `qm status 731` stopped, the
snapshot list `fresh-2026-11-13` then `current`. `vmdata` 70.95%; available RAM about 15.1 GB; 721 and 723 running,
722, 724 and 732 stopped, unchanged.

## Checkpoints on BUILD1, 2026-11-14

Task 7's measurement (PLAN-1.5 task 7, the maintainer, 2026-11-13). BUILD1 (VM 731) from `fresh-2026-11-13`, with a 24 GB thin
`sata2` disk added as root and formatted `B:` (label `nbackup`), stage 1 and stage 2 by the helper's own renders of
b115b91 (`s1-base`, `s2-promote`, `s2-groups`, `s2-genid`, the two reboots, as in "Stage 4 reboot"), then the reads
below. Every snapshot was taken, listed, read and deleted with the scoped token (`newton-build@pve!checkpoint`,
`VM.Snapshot,VM.Snapshot.Rollback,VM.Audit`, "The scoped token"), all `vmstate=0` of the running VM. Each DC read was
the `s2-genid` op in the password task (as `NBUILD\newton-build`), and `repadmin /showbackup` and `wbadmin get
versions -backupTarget:B:` as Administrator. Raw logs: the session's scratchpad `wf15t7/lab` (`session.log`,
`m-snap-*.log`, `m-showbackup-*.txt`, `m-versions-*.txt`, `m-genid-*.txt`, `m-galog-*.txt`); the bytes the tests pin are
in `mcp/tests/ad/build/fixtures/checkpoints/`.

| Snapshot | Guest state | `exitstatus` | Log (the LVM thin-pool lines left out) |
|---|---|---|---|
| `m7-wg` | workgroup, after stage 1, agent running | `OK` | `freeze guest filesystem`, `snapshotting 'drive-sata0'`, its volume, `snapshotting 'drive-sata2'`, its volume, `thaw guest filesystem`, `TASK OK` (17 lines) |
| `m7-dc` | DC, `msDS-GenerationId` stored, agent running | `OK` | the same shape (17 lines); the agent logged `guest-fsfreeze called` 07:18:08.4, `guest-fsthaw called` 07:18:13.8 (a 5 s freeze) |
| `m7-dc-noagent` | `Stop-Service QEMU-GA` | `OK` | `skipping guest filesystem freeze - agent configured but not running?` first, no thaw line, `TASK OK` (16 lines) |
| `m7-dc-novss` | VSS service `Disabled` and stopped | `OK` | `freeze guest filesystem`, then `unable to freeze guest fs - failed to initialize for backup: Windows error 0x80042302: `, the disks, `thaw guest filesystem`, `TASK OK` (18 lines) |
| `m7-dc-noprov` | the `QEMU Guest Agent VSS Provider` service `Disabled` and stopped | `OK` | `freeze guest filesystem`, then `unable to freeze guest fs - failed to add \\?\Volume{186374ba-0000-0000-0000-100000000000}\ (display name: C:\) to snapshot set: Windows error 0x8004230f: `, the disks, `thaw guest filesystem`, `TASK OK` (18 lines) |
| `m7-dc-busy` | 10 s into `wbadmin start systemstatebackup` | `OK` | the `m7-dc` shape: the freeze worked while wbadmin's own shadow copy ran (the backup still ended rc 0) |

What this means for the Proxmox read-back:
- **A failed freeze is forced and it is still `OK`.** With VSS disabled, or the agent's VSS provider disabled, the task
  log still has `freeze guest filesystem` and `thaw guest filesystem` in order, `TASK OK`, and the status says
  `exitstatus OK`. The only trace is one line between them, `unable to freeze guest fs - ...`, which is not a
  `WARNING:` line. So neither the exit status, nor the freeze and thaw lines, nor "no warning between them" catches
  it; only a rule that accepts nothing between freeze and thaw but the measured disk and LVM lines does. The guest's
  Application log shows the same (VSS 13 and 8193, `0x80070422`, for the disabled service; VSS 13 and 12292 with
  `SW_PROV` for the disabled provider), then `guest-fsthaw called` twice.
- The LVM lines are the four of "The scoped token", each matched whole: `WARNING: You have not turned on protection
  against thin pools running out of space.`, `WARNING: Set activation/thin_pool_autoextend_threshold below 100 ...`,
  `Consider pruning vmdata VG archive with more than <n> MiB in <n> files (see archiving settings in lvm.conf).`
  (twice per disk), and, after each volume line, `WARNING: Sum of all thin volume sizes (<1.53 TiB) exceeds the size
  of thin pool vmdata/vmdata and the size of whole volume group (238.47 GiB).` (the size may carry `<`).
- Every disk of the VM gets its own `snapshotting 'drive-<bus><n>' (<storage>:vm-<vmid>-disk-<n>)` line and its
  `Logical volume "snap_vm-<vmid>-disk-<n>_<snapshot>" created.` line; only SATA was measured.
- The workgroup snapshot of the running VM has the freeze and the thaw as the DC one does; a stopped VM's has neither
  ("The scoped token", `fresh-2026-11-13`).

`msDS-GenerationId` after each snapshot, read by `s2-genid`: present, 8 bytes, `65af35ee9de38e46` every time (before
the snapshots, after `m7-dc`, `m7-dc-noagent`, `m7-dc-novss`, and after the system-state backup). The DS events were
2168 at the first boot after promotion, 2179 (stored) at 07:16:22 just before the second boot, then 2172 and 2168. A
`vmstate=0` snapshot does not touch it; a rollback is what changes it (section 7, "vmgenid on rollback").

`repadmin /showbackup`, raw (blank lines left out):

```
Repadmin: running command /showbackup against full DC localhost
Loc.USN                           Originating DSA  Org.USN  Org.Time/Date        Ver Attribute
=======                           =============== ========= =============        === =========
DC=ForestDnsZones,DC=build,DC=newton,DC=test
DC=DomainDnsZones,DC=build,DC=newton,DC=test
CN=Schema,CN=Configuration,DC=build,DC=newton,DC=test
CN=Configuration,DC=build,DC=newton,DC=test
DC=build,DC=newton,DC=test
```

That is the answer before any backup and, unchanged, after the `m7-dc` snapshot: the agent's VSS freeze records no AD
backup on BUILD1 either (section 7). After `wbadmin start systemstatebackup -backupTarget:B: -quiet` (07:19:34 to
07:31:42, rc 0), every partition carries one row:

```
DC=ForestDnsZones,DC=build,DC=newton,DC=test
  16578      b8de3f20-e4b5-4bf3-b93c-9e285d6b2143     16578 2026-11-14 07:31:08    1 dSASignature
```

(the same for the other four, USNs 16577 to 16574). After `wbadmin start backup -allCritical -backupTarget:B: -quiet`
(07:32:07 to 07:33:57, rc 0; the C: volume and the 674 MB recovery partition): `2026-11-14 07:33:25    2 dSASignature`
on all five. The time is the DC's local time (the guest runs UTC) and it is the end of the backup, not its start.

`wbadmin get versions -backupTarget:B:` after the system-state backup:

```
Backup time: 11/14/2026 7:19 AM 
Backup target: 1394/USB Disk labeled B:
Version identifier: 11/14/2026-07:19
Can recover: Volume(s), File(s), Application(s), System State
Snapshot ID: {2947caea-5068-4137-94ef-505142d23356}
```

and after the all-critical one, that block and then:

```
Backup time: 11/14/2026 7:32 AM 
Backup target: 1394/USB Disk labeled nbackup(B:)
Version identifier: 11/14/2026-07:32
Can recover: Volume(s), File(s), Application(s), Bare Metal Recovery, System State
Snapshot ID: {967d8fd8-7c2e-4838-bbc9-e099444671f3}
```

The same shape as "wbadmin on BUILD1" (the header, then six lines per version, the `Backup time` line ending in a
space). The version identifier is the minute the backup started (07:19 and 07:32), so a version taken in a run's
window can be told from one of an earlier run by its identifier; the `dSASignature` is stamped later, when it ends.
On a DC the all-critical backup took 110 s after the system-state one.

After: the EXIT trap shut 731 down, deleted any `m7-*` snapshot (none was left: each was deleted with the token right
after its reads), rolled back to `fresh-2026-11-13`, and unlinked the backup disk (`unused0: vmdata:vm-731-disk-1`).
`qm listsnapshot 731`: `fresh-2026-11-13` and `current` only; `qm status 731`: stopped. `vmdata` 70.97% before, 73.74%
at the most (before the all-critical backup), 70.97% after. 732, 722 and 724 stayed off; 721 and 723 were not touched.

## Stage 7 on BUILD1 and BUILD2, 2026-11-15

Task 8 part B. BUILD1 (VM 731, 10.111.0.41) and BUILD2 (VM 732, 10.111.0.42) on vmbr111, both from
`fresh-2026-11-13`. Free RAM 14 GB and `vmdata` 70.95% before each start. BUILD1 was taken through stages 0 to 6 by the
helper's own renders (`Get-NewtonOpScript` over the two-server plan, run in the password task or the key login as the
helper runs them), BUILD2 through stages 0 and 1. The bootstrap was a stand-in (the newton-build account, its keys file
and sshd block, pw.bin, K and the helper), as in the earlier runs. The lab scripts and every step's log are in the
session's scratchpad (`t8b/lab`, `steps7.log`); the blob, the DSRM and admin secrets were files there (0600, never
printed) and were shredded after the run.

One lab-only step: the plan's `administrator` option `disabled` made stage 5 disable the domain Administrator, which is
the lab's own key login, so the stage 6 ops' first attempt failed with "Connection closed". The account was enabled
again with `Enable-ADAccount Administrator` through the QEMU guest agent (SYSTEM) and stage 6 was run again; it passed.
A plan with `disabled` takes away any Administrator key login the owner relied on (open point 21 of task 8).

### The DC reads of part B0 (DC1, the newton-build key login, S4U)

Time zone UTC, offset 0 minutes. `repadmin /showbackup` exit 0, the shape of `repadmin-showbackup-before.txt` byte for
byte (`repadmin-showbackup-s4u-before.txt`). `wbadmin get versions` exit -2, `ERROR - No backup was found.`
(`wbadmin-versions-s4u-none.txt`). `msDS-GenerationId` present (`281b73ad44cbf44c`).

### The stage 7 checkpoints

Through the scoped token `newton-build@pve!checkpoint`: `m8-dc2-wg` on 732 (workgroup) and `m8-dc1-dc` on 731 (DC),
each `exitstatus OK` with the freeze and thaw lines; DC1's `msDS-GenerationId` was present after its snapshot. Both
were deleted by the session's EXIT trap.

### DC2 before the join

`DomainRole 2`, `WORKGROUP`; WinRM Running (Automatic), one listener `Transport=HTTP;Address=*`, TrustedHosts empty,
service auth Kerberos true, Negotiate true, Basic false, AllowUnencrypted false; the firewall rule `WINRM-HTTP-In-TCP`
enabled for Domain and Private, `WINRM-HTTP-In-TCP-PUBLIC` for Public from the local subnet; the network profile
Public; the DNS client 10.111.0.1. Server 2025's defaults: nothing was configured for WinRM.

### djoin /provision on DC1 (the password task, nbuild\newton-build, Kerberos)

Before: `Get-ADComputer BDC2` threw `ADIdentityNotFoundException`. `djoin.exe /provision /domain build.newton.test
/machine BDC2 /savefile C:\NewtonBuild\out\s7-odj.txt` exit 0 in under a second, 14 lines (the empty ones elided):

```
Provisioning the computer...
Successfully provisioned [BDC2] in the domain [build.newton.test].
Provisioning data was saved successfully to [C:\NewtonBuild\out\s7-odj.txt].
Computer provisioning completed successfully.
The operation completed successfully.
```

The blob: 6532 bytes, starting `ff fe` (UTF-16LE with a byte order mark), owner `BUILTIN\Administrators`, two
inherited ACEs (SYSTEM and Administrators FullControl), not protected; 8712 base64 characters. The computer object:
`CN=BDC2,CN=Computers,...`, userAccountControl 4096, primaryGroupID 515, pwdLastSet 134392455248383064, dNSHostName
`BDC2.build.newton.test`, SPNs `HOST/BDC2`, `HOST/BDC2.build.newton.test`, `RestrictedKrbHost/BDC2`,
`RestrictedKrbHost/BDC2.build.newton.test`.

The blob holds BDC2's machine account password (the offline domain join format). The same pwdLastSet was read after
the promotion, so the password the blob carried was the new DC's own machine password until a
`Reset-ComputerMachinePassword` on BDC2 changed it (pwdLastSet 134392460009348769, ran ok in BDC2's key login after the
promotion). Open point 16 of task 8.

### Carried, then djoin /requestODJ on DC2 (the key login, bdc2\newton-build, NTLM)

The blob was read on DC1, hashed (sha256 starts 5a431b23), deleted on DC1, and written on DC2 with the same
hash. On DC2, in the local newton-build key login: the DNS client set from 10.111.0.1 to 10.111.0.41;
`build.newton.test` resolves to 10.111.0.41 and its `_ldap._tcp.dc._msdcs` SRV to `bdc1.build.newton.test`.
`djoin.exe /requestODJ /loadfile C:\NewtonBuild\s7-odj.txt /windowspath C:\Windows /localos` exit 0 in under a second:

```
Loading provisioning data from the following file: [C:\NewtonBuild\s7-odj.txt].
The provisioning request completed successfully.
A reboot is required for changes to be applied.
The operation completed successfully.
```

The blob was deleted (`blob deleted: True`); before the reboot, `DomainRole 2`, `WORKGROUP`. `shutdown.exe /r /t 10`
from the key login; the boot time moved 8 s after the call. After the boot: `DomainRole 3`, `PartOfDomain True`,
`build.newton.test`, the network profile DomainAuthenticated; the key login is still the local `bdc2\newton-build`
(NTLM, `S-1-5-114`), so DC2's helper keeps working after the join.

### WinRM from DC1's password task

`Test-WSMan BDC2.build.newton.test -Authentication Kerberos` answered (ProductVersion OS 10.0.26100, Stack 3.0); an
`Invoke-Command -Authentication Kerberos` session on BDC2 ran as `nbuild\newton-build`, auth Kerberos, with
`BUILTIN\Administrators`, `NBUILD\Domain Admins` and High integrity; `klist` held `krbtgt/BUILD.NEWTON.TEST` and
`HOST/BDC2.build.newton.test`. No TrustedHosts entry, no SPN change and no CredSSP: the `HOST` SPN covers WinRM, and the
join's own `Dfsr-12F9A27C-...` SPN appeared on the computer object.

### Install-ADDSDomainController over WinRM (DC1's password task)

In the `Invoke-Command` session on BDC2: the DSRM secret read from DC2's own DPAPI LocalMachine file
`C:\NewtonBuild\dsrm.bin` (written there by DC2's key login over stdin before the join) and the file deleted (`True`);
`Install-ADDSDomainController -DomainName build.newton.test -SiteName Default-First-Site-Name -InstallDns
-Credential <nbuild\newton-build from DC1's pw.bin> -SafeModeAdministratorPassword <it> -NoRebootOnCompletion -Force`
returned after 64 s (`Invoke-Command` after 65 s, the task after 70 s):

```
Message        : You must restart this computer to complete the operation.
Context        : DCPromo.General.4
RebootRequired : True
Status         : Success
```

The computer object after: `CN=BDC2,OU=Domain Controllers,...`, userAccountControl 532480, primaryGroupID 516,
pwdLastSet unchanged (134392455248383064). The credential went from DC1's task to DC2 inside the Kerberos session; it
never left the two DCs, and Newton carried none.

The restart was `shutdown.exe /r /t 10` from DC2's key login (still the local account; the promotion was not
complete). Back 59 s after the call (boot 19:47:49Z).

### DC2 after the promotion

The key login is now `nbuild\newton-build` (the domain account's SID, Kerberos, `BUILTIN\Administrators` and
`NBUILD\Domain Admins`): the local account went with the SAM, so DC2's pw.bin (the local password) is of no use, and
no password task can run on DC2 any more. The helper's files (K, the helper, the keys file) were still there and the
key login still reached them. `Get-ADDomain` answered 261 s after the wait started (uptime 323 s; ADWS Running from
the first try). `msDS-GenerationId` on `CN=BDC2,OU=Domain Controllers,...`: present, 8 bytes, `20438291f74fcb45` (DS
events 2168, 2173, 2179 at 19:47:52Z). `Win32_ComputerSystem`: `DomainRole 4`, `PartOfDomain True`; DNS client
`10.111.0.41,127.0.0.1` (the promotion added the loopback second).

### The read-backs (contradict the design's "0 failures both ways" at the measured times)

- 19:53:15Z (about 5.5 minutes after DC2's boot), DC1's password task: `repadmin /replsummary` exit 0 with no DSA rows
  and "58 - 8227c936-...._msdcs.build.newton.test"; `repadmin /showrepl * /csv` `showrepl_ERROR,-,8227c936-...,LDAP
  error 81 (Server Down) Win32 Err 58.` (BDC2's DSA CNAME did not resolve yet: its DNS registrations against
  10.111.0.41 had failed at 19:48:08 to 19:48:33, events 0x168E).
- 19:53:18Z, DC2's key login: `repadmin /showrepl` exit 234: five inbound naming contexts from BDC1, each "Last
  attempt @ 2026-11-15 19:48:33 failed, result 1908 (0x774): Could not find the domain controller for this domain.";
  `dcdiag /q` exit 0 but failed DFSREvent, KnowsOfRoleHolders (`DsBindWithSpnEx() failed with error 5`), Replications,
  RidManager and SystemLog.
- 19:58Z, an Administrator key login (S4U, no network credential): `DsBindWithCred ... failed with status 5` both ways,
  so a key login cannot read the other DC's replication at all.
- 19:58:46Z, a one-shot SYSTEM task on each DC (the DC's machine account): the DSA CNAMEs of both DCs resolve;
  `repadmin /showrepl * /csv` exit 0 on both, the same rows:

```
showrepl_INFO,Default-First-Site-Name,BDC2,"DC=build,DC=newton,DC=test",Default-First-Site-Name,BDC1,RPC,0,0,2026-11-15 19:58:34,0
showrepl_INFO,Default-First-Site-Name,BDC2,"CN=Configuration,DC=build,DC=newton,DC=test",Default-First-Site-Name,BDC1,RPC,1,2026-11-15 19:48:33,2026-11-15 19:47:07,1908
showrepl_INFO,Default-First-Site-Name,BDC2,"CN=Schema,CN=Configuration,DC=build,DC=newton,DC=test",Default-First-Site-Name,BDC1,RPC,1,2026-11-15 19:48:33,2026-11-15 19:47:06,1908
showrepl_INFO,Default-First-Site-Name,BDC2,"DC=DomainDnsZones,DC=build,DC=newton,DC=test",Default-First-Site-Name,BDC1,RPC,1,2026-11-15 19:48:33,2026-11-15 19:47:12,1908
showrepl_INFO,Default-First-Site-Name,BDC2,"DC=ForestDnsZones,DC=build,DC=newton,DC=test",Default-First-Site-Name,BDC1,RPC,0,0,2026-11-15 19:53:33,0
```

  No row has BDC1 as the destination: 11 minutes after the promotion's boot BDC1 had no inbound connection from BDC2
  yet (the KCC runs every 15 minutes), and three of BDC2's inbound contexts still carried the failure from its boot.
  `dcdiag /q` on BDC1 failed DFSREvent and SystemLog only (the accepted pair); on BDC2 DFSREvent, Replications and
  SystemLog.

So the design's read-back (repadmin 0 failures both ways, dcdiag on both) did not hold at 5 or at 11 minutes after
the promotion, and a key login cannot make it. Nothing was forced (no `repadmin /kcc` or `/syncall`). Open point 17 of
task 8.

### Stage 9 on BUILD2, then BUILD1

- The removal from Domain Admins was never made. The op, in the key login (S4U), first read the account's groups
  with `Get-ADPrincipalGroupMembership -Identity newton-build`, and that read threw on both: on BDC2
  `ADException: The operation being requested was not performed because the user has not been authenticated`, on
  BDC1 `ADException: An unspecified error has occurred`; the token held RID 512 before. So `Remove-ADGroupMember` in a
  key login, and in DC1's password task, are both unmeasured. On DC2 no password task can run (above), and the
  membership is one domain-wide value, so DC2's stage 9 has no removal of its own to make. Open point 18 of task 8.
- The one-shot SYSTEM task (`NT AUTHORITY\SYSTEM`, LogonType ServiceAccount, registered from the key login, 2505-byte
  script under `C:\ProgramData\Newton`), on BDC2 then BDC1, logged: `sshd_config restored, sha256 equal True`, `sshd -t
  exit 0`, `sshd restarted: Running`, then `deleted ... True` for the keys file, the probe, `build.ps1`, `key.hex` and
  `pw.bin`; on BDC1 then `account before: CN=newton-build,CN=Users,...`, `Remove-ADUser newton-build: ok`, `account
  after: ADIdentityNotFoundException`; then `task unregistered`, `cleanup script deleted`. The account was still in
  Domain Admins when SYSTEM deleted it (the removal had failed).
- After: on both, sshd_config equals the backup, no `Match` line left, every deleted file absent, the task absent, sshd
  Running, and `newton-build@<ip>: Permission denied (publickey,password,keyboard-interactive).` What stays in
  `C:\NewtonBuild`: `sshd_config.bak`, `ops\*.ps1` and `out\*` (the op scripts and their outputs; the cleanup did not
  delete them). On BDC2 the account read `CN=newton-build,CN=Users,...` until BDC1's delete replicated (absent at
  19:56:30Z).
- Whether SYSTEM deletes an account that has left Domain Admins, measured on BDC1 with a probe account: created,
  added to Domain Admins, removed (`member of DA after remove: False`; adminCount empty, inheritance not protected),
  then a one-shot SYSTEM task: `identity nt authority\system`, `Remove-ADUser nb-probe9: ok`, `after:
  ADIdentityNotFoundException`, LastTaskResult 0. So SYSTEM on a DC deletes it both ways (in and out of Domain Admins).

### Timings

Stage 7 from the first checkpoint to DC2's `Get-ADDomain`: 19:45:00Z to 19:53:11Z. Provision under 1 s; the join 2 s;
the join's reboot 8 s (the boot time); WinRM checks 2.5 s; the install 64 s; the promotion's reboot 59 s; DC2's
directory 261 s after that. Stage 9: the SYSTEM task about 2 s on each DC.

### After

The session's EXIT trap shut 731 and 732 down, deleted the `m8-*` snapshots and rolled both back to
`fresh-2026-11-13`: `qm listsnapshot` shows `fresh-2026-11-13` and `current` only on each; `qm status`: stopped for
both. `vmdata` 70.95% after. No other VM was touched.

## Stage 8 and 9 on BUILD1, 2026-11-16

**Not measured: the lab was blocked.** The lab rule says a VM starts only with at least 6 GB of RAM free on apollo
and `vmdata` under 85%. On 2026-11-16, before any VM start, `free -m` on apollo read 4187 MB free (4339 MB
available), and `pvesm status` read `vmdata` at 78.90%. `qm status` read 731 (BUILD1) and 732 (BUILD2) stopped,
and `qm listsnapshot` showed `fresh-2026-11-13` on both. The check was made twice in the session, and both reads
were below the RAM bound. No VM was started, and nothing on apollo was changed.

So none of the following is measured yet. Each is what the next lab run records here; the tests use constructed
lines until then (DESIGN-1.5 open point 66):

- `sshd_config` before and after stage 8: the 1.3 block (`# newton-ad collector`, `Match User <netbios>\newton-audit`)
  and the 1.4 block (`# newton-ad write`, `Match User <netbios>\newton-ops`), both appended after
  `Match Group administrators`, with the bootstrap's build block still ahead of it;
- `sshd_config` before and after stage 9: only the build block gone, the two stage 8 blocks byte for byte the same;
- the restart inside the helper session: whether `NewtonBuild-sshd-restart` (SYSTEM, 10 s after the answer) drops the
  helper's session, how long sshd takes to answer again, and the s8-sshd result file's lines;
- both logins answering: newton-ops reaching the write helper (a `write.ps1` answer over its key) and newton-audit
  returning a 1.3 audit document;
- after stage 9: `newton-build@<ip>` refused, with newton-ops and newton-audit still answering;
- the s8-read lines (the explicit ACE scan of newton-ops, newton-audit's tokenGroups), to replace
  `tests/ad/build/fixtures/stage8/s8-read-constructed.txt` with measured bytes, lab IPs masked as 192.0.2.x.

The lab scripts under the session's scratchpad (`wf17/apollo-lab`) were not recreated: with the block they had no
run to serve.

## Stage 8 on BUILD1, 2026-11-18

**Stage 8 did not run: its run request never reached the helper.** Stages 0 to 7 were measured on the way there,
through Newton's own path. In every run below the runner (`run_build`) sent signed plan and stage tokens to the
`newton-build` key login. The bootstraps were the rendered ones, and checkpoints went through the scoped Proxmox token.
Apollo read free RAM of at least 6 GB and `vmdata` under 85% before each VM start (for example 9929 MB free and
78.83% at 03:40:59Z). Only 731 (BUILD1, 10.111.0.41) and 732 (BUILD2, 10.111.0.42) were used.

### The lab around the run

- Stage 0 checks that the server's DNS client answers (open point 79). vmbr111 has no resolver, so a one-file NXDOMAIN responder ran on
  apollo at 10.111.0.1:53 (UDP, pid file `/root/nxdns.pid`). The owner's prep set each VM's DNS client to 10.111.0.1
  before stage 0. The teardown removed the responder.
- The plan: `build.newton.test` / `NBUILD`, Windows Server 2025, OUs `IT`, `IT/Servers`, `Staff`, groups `IT Admins`
  and `Staff Users`, owner admin `owner-admin`, baseline 2026.11, and an ops section with a lab key for each of the
  two logins. The `write_helper_sha256` came from the installed Newton.

### The bootstrap on a fresh server (fixed tests first, e092173)

- `Unable to find type [System.Security.Cryptography.ProtectedData]` (PowerShell 5.1 does not load System.Security):
  the bootstrap now runs `Add-Type -AssemblyName System.Security` first.
- `pw.bin` held the password as UTF-16, but the helper decodes UTF-8. Stage 2's password task then failed with "The
  user name or password is incorrect.". The bootstrap now writes UTF-8.
- `pnputil` exit 259 ("Driver package is up-to-date on device") stopped step 10. 259 now passes only when
  `Get-PnpDevice -PresentOnly -FriendlyName 'VirtIO Serial Driver'` reads every device OK.
- Not fixed (open points 75, 76): `Read-Host -AsSecureString` hangs when stdin is a pipe over ssh, so the lab
  answered the two passphrase prompts over `ssh -tt`. A re-run after step 7 did not restart sshd because the
  configuration was unchanged.

### Stages 0 to 6 (one DC, plan 8f274516..., 03:42Z to 03:57Z)

| stage | run | answer |
|---|---|---|
| 0 | 8.5 s | done |
| 1 | 35.6 s | rebooting, then done at 03:43:28Z |
| 2 | 73.0 s (checkpoint 3.9 s first) | rebooting |
| 3 | 8.9 s | done |
| 4 | 9.0 s | rebooting |
| 5 | 9.8 s | done |
| 6 | 51.4 s | done (both GPOs linked, registry and secedit equal the baseline) |

An earlier run (plan 34f20ebc..., 02:42Z) read the same with two DCs. The genid reads answered `msDS-GenerationId on
CN=BDC1,OU=Domain Controllers,...: present, 8 bytes, ...`. One helper defect stopped stage 2 there, and the next run
passed after the fix:

- The status after stage 2's second boot stopped with `error`: "Attempting to perform the InitializeDefaultDrives
  operation on the 'ActiveDirectory' provider failed." The fix retries the import inside the wait for
  the directory.

### Stage 7 option B on BUILD1 and BUILD2 (plan 34f20ebc..., 03:00Z to 03:39Z)

- DC1, `s7_provision` (password task, Kerberos): no computer BDC2 before; `djoin /provision` exit 0, 14 lines; the
  blob was 6532 bytes; then `CN=BDC2,CN=Computers,... | userAccountControl 4096 | primaryGroupID 515`.
- DC2, `s7_join`: SRV `bdc1.build.newton.test`; `djoin /requestODJ` exit 0, 10 lines; blob deleted True; workgroup
  before the reboot. 32 s later the status read `DomainRole 3 | PartOfDomain True`.
- DC1, `s7_install` (79.0 s): `Test-WSMan` Kerberos OK; remote identity `nbuild\newton-build`, auth Kerberos;
  `Install-ADDSDomainController` Status Success, RebootRequired True; dsrm.bin deleted on BDC2; afterwards
  `OU=Domain Controllers`, `userAccountControl 532480`, `primaryGroupID 516`.
- DC2's status after the promotion's boot answered `answer_invalid` at first. With ADWS not serving yet,
  `Import-Module ActiveDirectory` succeeds but prints "WARNING: Error initializing default drive: 'Unable to contact
  the server. ...'" on stdout, so the answer held more than one JSON object. With the fix the status was
  done at 274.8 s: `DomainRole 4`; DC2's own genid present, 8 bytes; machine password reset (pwdLastSet
  134394444106767482 to 134394448696078631, 03:07:49Z, after the boot at 03:02:21Z); `nltest /sc_verify` exit 0,
  5 lines.
- DC1, `s7_read` (K17: poll `repadmin /showrepl * /csv` every 30 s, up to 30 minutes, nothing forced): the task
  ran from 03:08:01Z to 03:39:32Z (1889 s, 61 polls) and ended `converged False`. The helper's 600 s wait ended
  first. The helper then read `C:\NewtonBuild\out\s7-read.txt` while the task still held it open, and the stage
  stopped with `error` ("being used by another process"). The fix does not read a running op's output.
  The final rows:

```
showrepl_INFO,Default-First-Site-Name,BDC1,"DC=build,DC=newton,DC=test",Default-First-Site-Name,BDC2,RPC,0,0,2026-11-18 03:20:06,0
showrepl_INFO,Default-First-Site-Name,BDC1,"CN=Configuration,DC=build,DC=newton,DC=test",Default-First-Site-Name,BDC2,RPC,0,0,2026-11-18 03:16:43,0
showrepl_INFO,Default-First-Site-Name,BDC1,"CN=Schema,CN=Configuration,DC=build,DC=newton,DC=test",Default-First-Site-Name,BDC2,RPC,0,0,2026-11-18 03:16:13,0
showrepl_INFO,Default-First-Site-Name,BDC1,"DC=DomainDnsZones,DC=build,DC=newton,DC=test",Default-First-Site-Name,BDC2,RPC,0,0,2026-11-18 03:16:13,0
showrepl_INFO,Default-First-Site-Name,BDC1,"DC=ForestDnsZones,DC=build,DC=newton,DC=test",Default-First-Site-Name,BDC2,RPC,0,0,2026-11-18 03:16:13,0
showrepl_INFO,Default-First-Site-Name,BDC2,"DC=build,DC=newton,DC=test",Default-First-Site-Name,BDC1,RPC,0,0,2026-11-18 03:35:02,0
showrepl_INFO,Default-First-Site-Name,BDC2,"CN=Configuration,DC=build,DC=newton,DC=test",Default-First-Site-Name,BDC1,RPC,0,0,2026-11-18 03:16:28,0
showrepl_INFO,Default-First-Site-Name,BDC2,"CN=Schema,CN=Configuration,DC=build,DC=newton,DC=test",Default-First-Site-Name,BDC1,RPC,1,2026-11-18 03:03:06,2026-11-18 03:01:43,1908
showrepl_INFO,Default-First-Site-Name,BDC2,"DC=DomainDnsZones,DC=build,DC=newton,DC=test",Default-First-Site-Name,BDC1,RPC,0,0,2026-11-18 03:16:34,0
showrepl_INFO,Default-First-Site-Name,BDC2,"DC=ForestDnsZones,DC=build,DC=newton,DC=test",Default-First-Site-Name,BDC1,RPC,0,0,2026-11-18 03:16:37,0
```

  These rows contradict the design's read-back in three ways (open point 77):
  1. BDC2's inbound Schema NC keeps the failure from its boot (1908, "A KDC was not found"). Nothing in the schema
     changes, so no replication clears it, and "0 failures both ways" did not hold within 30 minutes. Every other NC
     succeeded both ways by 03:35Z.
  2. `msDS-GenerationId` of BDC2 read from DC1 is `absent`. The attribute is not replicated (DC2 reads its own as
     present), so a check of DC2's genid made from DC1 can never pass.
  3. `dcdiag /s:BDC2` from DC1 failed `KccEvent`, `SystemLog` and `DFSREvent` with `error 0x6ba "The RPC server is
     unavailable."` (BDC2's remote event log), and failed `Replications` on the Schema row above. `KccEvent` is not
     in the accepted list. `dcdiag` on BDC1 itself failed only `DFSREvent` and `SystemLog`, the accepted pair.

  Stage 7 cannot pass the read-back as designed, so stage 8 was measured with a one-DC plan.
- The constructed stage 7 fixtures were not replaced. The run stopped before the read-back passed.

### Stage 8 (one DC, 03:57:41Z to 04:10:03Z): the request does not reach the helper

- The runner checked the installed write helper against the plan (`newton_mcp/ad/collector/write.ps1`, 135894
  bytes, 181192 base64 characters) and sent the stage 8 run, with keys `action exp nbf run stage token
  write_helper`. After 720 s it read `HelperUnavailable: the build helper did not answer`. The status after that
  answered `pending` with stages 0 to 6 completed, and the run stopped `connection_lost`.
- On BDC1 at 04:10Z and again at 04:26Z, the helper process from 03:57:41Z (`powershell.exe -NoProfile
  -NonInteractive -ExecutionPolicy Bypass -File C:\ProgramData\Newton\ad-build\build.ps1`) was still running. There
  was no `s8*` file under `C:\NewtonBuild\out` or `ops`, no stage 8 journal entry, no stage 8 task, and the install
  root held only `build.ps1`, `device.txt`, `key.hex`, `journal` and the two templates. Nothing of stage 8 ran: the
  helper never finished reading its stdin.
- The limit, measured over the Administrator key login on BDC1. Each probe read stdin to its end with
  `[Console]::In.Read` and printed the count, under a 60 s or 30 s timeout:

| bytes on stdin | result |
|---|---|
| 4001, 8001, 16001, 65001, 66001, 70001 | read in full at once |
| 80001, 90001, 100001, 131001, 190001 | no answer, timeout |
| 190000 in lines of 1000 | no answer |
| 190000 to `[Console]::OpenStandardInput()` | no answer |
| 190000 to a `-File` script, with and without `-InputFormat Text` | no answer |
| 48 writes of 4000 bytes, 50 ms apart | no answer |
| 190000 in lines of 1000 to `find /c "A"` (cmd) | `190`, exit 0 |

  The transport delivers the bytes, because cmd reads them all. Windows PowerShell 5.1 under this OpenSSH stops
  reading stdin somewhere between 70 001 and 80 001 bytes. A stage 8 request that carries the write helper (about
  182 KB) cannot reach the helper. The stage 7 request with the djoin blob (8712 characters) did. This contradicts
  the design's "the stage 8 run carries the 1.4 write helper's bytes" (open point 78). That part was stopped there:
  the transport was not changed. A tests-first change that installs the write helper from the bootstrap was drafted
  and then discarded (see point 78).
- So the following are still unmeasured, and their fixtures stay constructed (open point 66): the sshd Match blocks,
  the keys files, the ACLs, the OU delegation read-backs (`s8-read`), the 1.4 read through the installed
  `newton-ops` login, and the 1.3 audit read through `newton-audit`. The stage 8 schema refusal of a request without
  the write helper stays, since dropping it is not proven safe. The lab scripts for those reads (`measure8.ps1`,
  `post8.sh`) are ready under the session's scratchpad (`wf17/apollo-lab`).

### After

The EXIT trap stopped the responder (no listener on :53, `/root/nxdns.py` and the pid file absent), shut 731 and 732
down, deleted the `newton-*` checkpoints and rolled both back to `fresh-2026-11-13`. `qm status` read stopped and
`qm listsnapshot` showed `fresh-2026-11-13` and `current` only, on both. `vmdata` read 78.83%. A lab trap: the
rollback left no `protection` line in either VM's config, because the snapshot's config predates the flag. So
`qm set --protection 1` ran again on both, and `qm config` then read `protection: 1` and `parent:
fresh-2026-11-13`. No other VM was touched.
