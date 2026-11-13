# AD-GAPS: merged check catalogue for Newton's read-only AD audit (release 1.3)

Written 2026-11-08. Sources: the AD persona's design decisions (D or DESIGN), two independent gap
reviews ("the first review" and "the second review" below; neither is shipped), licence and prior-art notes, and the ActiveDirectoryMCP (ADMCP) source in a local
checkout of ActiveDirectoryMCP (MIT, Alperen Adalar 2024; v5.0.0, 45 tools: 22 read / 17 write / 4
destructive). All ADMCP file:line references below were verified against that tree. Rule ids are quoted
only where a source gave one; "(unverified)" = the source itself could not confirm the id. ANSSI ids are
unverified throughout (the first review could not fetch the checklist). Nothing here was tested against a live
directory.

Flag legend for section 1:
- **P** = needs more than a read-only delegated LDAP account (JEA host cmdlet, event log, root helper, or admin right)
- **V** = needs SYSVOL file reads (not LDAP)
- Src = where the row came from: D = the persona's design decisions, GR = one or both gap reviews.
- ADMCP = existing query in ActiveDirectoryMCP (`file:function`); "partial" = reads part of the data, no dedicated finding.

## 1. Check catalogue for 1.3 (read-only audit)

The first review's own placeholder rows (WHfB detail, dynamic objects) are dropped per its
caveats. AD CS checks (ESC1–16, in both reviews) are deferred with the design draft's "later"
and are not catalogued here.

### 1a. Accounts, privilege, delegation

| ID | Finds | Windows read | Samba read | Diff | Sev (why) | Maps to | Src | ADMCP | Flags |
|---|---|---|---|---|---|---|---|---|---|
| AD-A-01 | RID-500 Administrator enabled/active | LDAP: `objectSid` `*-500`, `userAccountControl` (UAC), `lastLogonTimestamp`, `pwdLastSet` | same LDAP | none | med (cannot be locked out; prime brute-force/persistence target) | MS Learn SIDs; ANSSI (unverified) | GR | no | |
| AD-A-02 | Guest enabled | LDAP: UAC `ACCOUNTDISABLE` unset on RID 501 | same | none | low (anonymous-ish access) | MS Learn SIDs | GR | no | |
| AD-A-03 | Privileged group inventory: Domain/Enterprise/Schema Admins, Administrators, Operators groups, DnsAdmins, Cert Publishers, GPCO, Key Admins (RID 526/527); nested membership and cycles | LDAP `member` + matching rule `1.2.840.113556.1.4.1941` (or `Get-ADGroupMember -Recursive`) | same LDAP OID (verify); `samba-tool group listmembers` | Key Admins needs 2016 schema; DnsAdmins plugin abuse is Windows DNS only; not all groups exist on Samba | high (hidden admins = domain compromise) | MS Learn SIDs/best practices; ATT&CK T1574 (DnsAdmins, the second review) | D, GR | partial: `security.py:get_privileged_groups` (9 groups by English name, direct members only) + `directory.py:get_nested_group_members` (recursive, per group) | |
| AD-A-04 | Privilege via `primaryGroupID` invisible to `member` traversal | LDAP `primaryGroupID` vs group SIDs | same | none | med (missed admin paths) | MS Schema | GR | no | |
| AD-A-05 | `adminCount=1` orphans (AdminSDHolder aftermath) | LDAP `adminCount=1` not in any privileged group | same; Samba SDProp equivalent (verify) | Samba propagation unverified | med (stale elevated ACLs persist) | MS best practices; ANSSI (unverified) | D, GR | no (read only as guard input in `user.py:reset_password`) | |
| AD-A-06 | Tier-0 not in Protected Users (RID 525) | LDAP `member` of S-1-5-...-525 | same (FL2012R2+) | Samba honors group only at FL (verify) | med (NTLM/RC4/unconstrained not blocked for admins) | MS Learn Protected Users | D, GR | no | |
| AD-A-07 | Kerberoastable: user objects with `servicePrincipalName`; higher if privileged or non-gMSA | LDAP `servicePrincipalName` on `(objectClass=user)` + UAC | same | none | high (offline-crackable service password) | ATT&CK T1558.003 | D, GR | no | |
| AD-A-08 | AS-REP roastable: `DONT_REQ_PREAUTH` (0x400000) | LDAP UAC bit | same | none | high (hash retrievable without preauth) | ATT&CK T1558.004 (id unverified) | D, GR | no | |
| AD-A-09 | Privileged accounts without `NOT_DELEGATED` (0x100000) | LDAP UAC + effective privileged membership | same | none | med (delegation abuse of admin sessions) | MS best practices; Security | D, GR | partial: UAC read in `security.py:get_user_permissions`, bit not tested | |
| AD-A-10 | Shadow credentials: unexpected `msDS-KeyCredentialLink` | LDAP attr; parse public-key blob metadata only | same (Samba: verify semantics) | enforcement differs | high (PKINIT account takeover) | SpecterOps Shadow Credentials; ATT&CK T1556 (id unverified) | GR | no (blocked in `filter_criteria` at `validation.py:254` but not in `attributes` param — see §3) | |
| AD-A-11 | Unconstrained delegation on non-DCs (0x80000) | LDAP UAC on computers | same | none | high (printer-bug capture of DA) | ATT&CK T1558; SpecterOps | D, GR | no | |
| AD-A-12 | Constrained delegation + protocol transition (0x1000000 + `msDS-AllowedToDelegateTo`) | LDAP UAC + attr | same (Samba P, verify) | partial Samba interop | high (S4U2Self abuse) | SpecterOps S4U | D, GR | no | |
| AD-A-13 | RBCD set + who can write it | LDAP `msDS-AllowedToActOnBehalfOfOtherIdentity` (descriptor) + ACL on targets | same (verify) | none known (verify) | high (computer takeover) | SpecterOps "Wagging the Dog"; ATT&CK T1558 | GR | no | |
| AD-A-14 | Weak/missing `msDS-SupportedEncryptionTypes` (0, RC4/DES-only, no 0x18 AES) | LDAP attr on users/computers/trusts | same | none | med-high (RC4 downgrade, crackable) | MS Kerberos encryption-types doc (URL unverified) | D, GR | no | |
| AD-A-15 | Observed RC4/DES in ticket events | Security events 4768/4769/4771 encryption fields | Samba auth logs (limited) | Windows events only | med (configured bits do not prove keys in use) | KB5021131 | GR | no | P |
| AD-A-16 | `PASSWD_NOTREQD` (0x20) | LDAP UAC | same | none | high (blank-password risk) | CIS (id unverified) | D, GR | yes: `security.py:get_password_policy_violations` | |
| AD-A-17 | `DONT_EXPIRE_PASSWORD` (0x10000) misuse | LDAP UAC | same | none | med (no rotation) | CIS (id unverified) | D, GR | yes: `security.py:get_password_policy_violations` | |
| AD-A-18 | Reversible encryption: UAC 0x80 accounts; domain `pwdProperties` 0x10 | LDAP | same (`pwdProperties` supported) | none | high (cleartext-stored passwords) | CIS (id unverified) | D | no | |
| AD-A-19 | `sIDHistory` populated; unresolved foreign SIDs in privileged groups | LDAP `sIDHistory`; CN=ForeignSecurityPrincipals | same | none | high (cross-domain privilege smuggling) | MS Learn SIDs; ATT&CK T1134.005 | D, GR | no | |
| AD-A-20 | Secrets in text attributes (`description`, `info`, `userPassword`, `unixUserPassword`, `msSFU30Password`) — presence only, values scrubbed | LDAP | same (Samba historically allows `userPassword`) | none | med (trivially readable credentials) | ATT&CK T1552 | GR | no | |
| AD-A-21 | `pwdLastSet=0` on enabled account; password never set | LDAP `pwdLastSet` + UAC | same | none | med (initial/forced-change state) | CIS (id unverified) | GR | partial: "Password never set" in `security.py:get_password_policy_violations` | |
| AD-A-22 | Expiry misuse: enabled + `accountExpires` in past; never-expiring contractors | LDAP `accountExpires` (0 / 0x7FFFFFFFFFFFFFFF = never) | same | none | low-med (lifecycle) | MS best practices lifecycle | GR | partial: "Account expired" flagged | |
| AD-A-23 | gMSA state: non-gMSA service accounts (SPN + `pwdLastSet` > 1y); `msDS-GroupMSAMembership` breadth; KDS root key present/effective | LDAP `objectClass=msDS-GroupManagedServiceAccount`, `msDS-GroupMSAMembership`, `msDS-ManagedPasswordInterval`, CN=Master Root Keys; `Get-KdsRootKey` | same LDAP; gMSA from Samba 4.21 (verify) | Samba release-dependent | med-high (static crackable passwords; overbroad retrieval) | MS gMSA docs | GR | no. Never request `msDS-ManagedPassword` | |
| AD-A-24 | Stale users (no logon N days) | LDAP `lastLogonTimestamp` (+`lastLogon` per DC, label DC) | same | none (both must label DC for `lastLogon`) | low (hygiene) | CIS (unverified) | D, GR | yes: `security.py:get_inactive_users` (single-DC caveat noted) | |
| AD-A-25 | Stale computers / stale machine passwords | LDAP `lastLogonTimestamp`, `pwdLastSet` on computers | same | none | low-med (broken rotation = stale trust) | CIS machine-password age (unverified) | D, GR | yes: `computer.py:get_stale_computers` | |
| AD-A-26 | Smart-card-required (0x40000) with stale `pwdLastSet` | LDAP UAC + `pwdLastSet` | same (DC rotation only from 2016 FL; Samba verify) | Windows-only rotation | med (static NT hash retained) | MS smart card doc (unverified) | GR | no | |
| AD-A-27 | krbtgt password age; RODC krbtgt staleness | LDAP `pwdLastSet` on krbtgt (+ `msDS-KrbTgtLink`) | same (`samba-tool user show krbtgt` equivalently LDAP) | RODC rows Windows-only | high (long-lived key material; Zerologon aftermath) | MS forest-recovery krbtgt guidance | D, GR | no | |
| AD-A-28 | Lockout anomalies: `lockoutTime`, `badPwdCount`, `badPasswordTime` vs effective PSO (query PDC) | LDAP (+ `msDS-ResultantPSO`) | same (computed attrs on Samba: verify) | computed-attr support | low (brute-force visibility) | MS PSAD | GR | partial: locked flag in `security.py:get_user_permissions` | |
| AD-A-29 | Privileged accounts with `scriptPath`/`profilePath`/`homeDirectory` on writable shares | LDAP attrs + referenced share ACLs (file read) | same + host file ACLs | share ACL read differs | high (code exec in privileged logon) | ATT&CK T1037.001 | GR | no | V/P (share reads) |
| AD-A-30 | Pre-W2K Compatible Access contains Everyone/Anonymous | LDAP `member` of S-1-5-32-554 | same (group exists; semantics verify) | verify on Samba | med (anonymous enumeration) | MS Learn SIDs | GR | no | |
| AD-A-31 | Hybrid sync accounts: `MSOL_*`, `AAD_*`, `AZUREADSSOACC$` present, key age | LDAP name patterns + `pwdLastSet` | same (only if sync used) | none | med-high (DCSync-class accounts) | MS AZUREADSSO rollover doc (unverified) | GR | no | |
| AD-A-32 | RODC password-replication policy breadth; cached principals | LDAP `msDS-RevealOnDemandGroup`, `msDS-NeverRevealGroup`; `Get-ADDomainControllerPasswordReplicationPolicy` | n/a | Windows-only (Samba RODC: verify, exclude) | high (privileged creds in branch cache) | MS PSAD/ADTS | GR | no. Never retrieve passwords | |

### 1b. Domain policy and auth protocols

| ID | Finds | Windows read | Samba read | Diff | Sev (why) | Maps to | Src | ADMCP | Flags |
|---|---|---|---|---|---|---|---|---|---|
| AD-A-33 | Domain password + lockout policy (min length, history, ages, `pwdProperties`, threshold/duration/window) | LDAP domain head | same; `samba-tool domain passwordsettings show` | none | med (weak floor for everything) | CIS DC (unverified) | D | yes: `security.py:get_domain_info`, `check_password_policy` | |
| AD-A-34 | Kerberos policy (MaxTicketAge, MaxServiceAge, MaxRenewAge, MaxClockSkew) | GPO Default Domain Policy `GptTmpl.inf` (SYSVOL) | defaults in Samba, not GPO (verify) | storage differs | med (long-lived tickets) | CIS DC (unverified) | D, GR | no | V |
| AD-A-35 | PSO inventory, precedence, `msDS-PSOAppliesTo`, resultant | LDAP CN=Password Settings Container + `msDS-ResultantPSO` | same; `samba-tool domain passwordsettings pso` | none known (verify) | med (weaker privileged policy unnoticed) | MS FGPP | D, GR | no | |
| AD-A-36 | LDAP signing enforcement: configured + observed | registry `NTDS\Parameters\LDAPServerIntegrity` (JEA cmdlet); events 2886–2889 | `testparm` `ldap server require strong auth` (helper) | Windows has server+client knobs + events; Samba one smb.conf value | high (NTLM relay to LDAP) | MS KB935834; ADV190023; KB4520412 | D, GR | no | P |
| AD-A-37 | LDAP channel binding | `NTDS\Parameters\LdapEnforceChannelBinding`; events 3039–3041 | not implemented (verify) | Windows-only | high (NTLM relay to LDAPS) | ADV190023; KB4520412 | D, GR | no | P |
| AD-A-38 | NTLM posture + observed NTLM dependencies | `Lsa\MSV1_0`/Netlogon policies (JEA); events 4776, NTLM operational log | `testparm` `ntlm auth` + auth logs | events Windows-only | med (relay/PtH surface) | MS Restrict NTLM settings | D, GR | no | P |
| AD-A-39 | SMB signing / SMBv1 / encryption on DC | `Get-SmbServerConfiguration`, registry SMB1 (JEA) | `testparm` `server signing`, `server min protocol` | different mechanisms, same facts | med (relay + legacy exploits) | CIS (unverified); MS SMB hardening | GR | no | P |
| AD-A-40 | Netlogon secure-channel enforcement (Zerologon) | `Netlogon\Parameters\FullSecureChannelProtection`; events 5827–5831 | `server schannel` (patched long ago) | Windows has exceptions group | high (CVE-2020-1472 exposure) | KB4557222 | GR | no | P |
| AD-A-41 | PAC-signature / cert-binding enforcement currency (`KrbtgtFullPacSignature`, `StrongCertificateBindingEnforcement`, `CertificateMappingMethods`) | registry + patch state, lifecycle-aware | n/a | Windows-only; historical values are not current switches | med (noPac / ESC9-10 conditions) | KB5008380; KB5020805; KB5014754 | GR | no | P |
| AD-A-42 | Host auth registry baseline: `LmCompatibilityLevel`, `NoLMHash`, WDigest `UseLogonCredential`, `RunAsPPL`, `CachedLogonsCount` | registry via JEA | `lanman auth`/`ntlm auth` via `testparm` | partial overlap | med (LM hash, LSASS cleartext) | CIS (unverified); KB2871997 | GR | no | P |
| AD-A-43 | Anonymous LDAP + `dsHeuristics` decode (pos 7 fLDAPBlockAnonOps, pos 3 list-object, pos 16 dwAdminSDExMask; unknown positions = findings) | LDAP on CN=Directory Service,CN=Windows NT | same LDAP (subset honored: verify) | Samba honors subset | med (anonymous recon, protected-group dilution) | MS-ADTS 7.1.1.2.4.1.2; ANSSI (unverified) | GR | no | |
| AD-A-44 | `ms-DS-MachineAccountQuota` > 0 + join hardening (KB5020276) + prestaged ownership (`msDS-CreatorSID`) | LDAP domain head + container ACLs | same LDAP | reuse enforcement Windows-only | med (RBCD / noPac chains) | KB5020276; SpecterOps | GR | no | |
| AD-A-45 | Functional levels, optional features (Recycle Bin, PAM), schema `objectVersion` | LDAP `msDS-Behavior-Version`, rootDSE functionality attrs | same; Samba 2008R2 default / 2016 opt-in | feature support matrix differs | low-med (blocks Protected Users silos etc.) | MS functional-levels doc | GR | yes: `directory.py:get_rootdse_info` (functionality attrs) | |
| AD-A-46 | LAPS deployment state (schema attrs present, expiration attrs, password-attr ACLs) — never values | LDAP schema + ACLs (`Find-LapsADExtendedRights` equivalent) | schema-extended manually (verify) | Windows legacy/Windows-LAPS variants | med (local-admin password hygiene) | MS LAPS | D, GR | no | |
| AD-A-47 | Authentication policies/silos defined and enforced; tier-0 outside | LDAP CN=AuthN Policy Configuration, `msDS-AssignedAuthNPolicy(Silo)`, `msDS-AuthNPolicyEnforced` | same storage; enforcement Samba 4.20+/FL2016 (verify) | enforcement Windows-only | med (tier-0 containment claims unproven) | MS Auth policies | GR | no | |
| AD-A-48 | Trust inventory + protections: direction, SID filtering (`trustAttributes`), TREAT_AS_EXTERNAL, selective auth, trust enc types, `msDS-TrustForestTrustInfo`; channel health | LDAP `trustedDomain` objects; `nltest /sc_query:`; interdomain account `pwdLastSet`; never trust-secret attrs | same LDAP; `samba-tool domain trust` | validation commands differ | high (cross-forest escalation) | MS trust design; ATT&CK T1134.005 | D, GR | no | P (nltest) |
| AD-A-49 | LDAPS/KDC cert lifecycle: expiry, EKU, chain, size; NTAuth anchors | TLS peer cert; LocalMachine/NTDS stores (JEA); `cACertificate` of NTAuthCertificates | `tls certfile` chain (helper) | store vs files | med (outage / downgrade) | MS LDAPS doc (unverified); KB5014754/KB5020805 | GR | partial: `directory.py:get_tls_posture` (own channel only, no cert inventory) | P |
| AD-A-50 | Explicit cert mappings `altSecurityIdentities`: weak/duplicate/attacker-writable | LDAP + ACLs; classify per KB5014754 | same storage | enforcement Windows | med (ESC14-adjacent; schedule with AD CS phase) | KB5014754; Certipy wiki | GR | no | |

### 1c. ACLs, GPOs, SYSVOL

| ID | Finds | Windows read | Samba read | Diff | Sev (why) | Maps to | Src | ADMCP | Flags |
|---|---|---|---|---|---|---|---|---|---|
| AD-A-51 | DCSync rights: non-DC principals with DS-Replication-Get-Changes(All)/In-Filtered-Set, incl. via groups | `nTSecurityDescriptor` on domain head | same LDAP; `samba-tool dsacl get` | none known | high (credential replication without DC logon) | ATT&CK T1003.006; MS-ADTS | GR | no | |
| AD-A-52 | Dangerous ACL attack paths: GenericAll/WriteDacl/WriteOwner/GenericWrite/WriteProperty (`member`, `servicePrincipalName`, RBCD, `msDS-KeyCredentialLink`, `scriptPath`) by non-admins on privileged objects; owner anomalies; tier boundaries; schema/partition/extended-right control | `nTSecurityDescriptor` + `schemaIDGUID`/`rightsGuid` map; BloodHound-style graph | same LDAP (descriptors) | Samba ACL tooling weaker; graph identical in principle | high (escalation graph) | BloodHound docs; ANSSI control-paths (unverified); ATT&CK T1098; T1484 | GR | no | |
| AD-A-53 | AdminSDHolder ACL drift + `dwAdminSDExMask` exclusions | ACL on CN=AdminSDHolder + `dsHeuristics` pos 16 | same (SDProp behavior verify) | verify | high (persistence) | ATT&CK T1098; MS best practices | GR | no | |
| AD-A-54 | GPO control: GPC ACL/owner, SYSVOL GPT file ACLs, edit/link rights, dangling links, enforced/block-inheritance, WMI filters excluding DCs, GPC↔GPT version drift | LDAP `gPLink`/`gPOptions`/`nTSecurityDescriptor`/`versionNumber` + SYSVOL `GPT.INI` manifest | same LDAP + `samba-tool ntacl sysvolcheck` | DFSR vs rsync divergence (see AD-A-66) | high (policy takeover) | ATT&CK T1484.001; MS-GPOL | GR | no | V |
| AD-A-55 | SYSVOL/NETLOGON content: GPP `cpassword` present (scrubbed), autologon in `Groups.xml`/`Registry.xml`, credentials in scripts, non-admin-writable scripts/EXEs, scheduled-task/service GPO persistence | file reads under SYSVOL | same | none | high (world-readable credentials) | MS14-025; ATT&CK T1552.006 | D, GR | no | V |
| AD-A-56 | Missing accidental-deletion protection on OUs/critical containers | DACL DELETE/DELETE_CHILD/DELETE_TREE coverage | same | none | low (availability) | MS PSAD/ADTS | GR | no | |
| AD-A-57 | DPAPI backup-key objects `BCKUPKEY_*`: who controls/reads; names+ACLs only, never `currentValue`/`priorValue` | LDAP CN=System | same | none | high (domain DPAPI master-key retrieval) | ATT&CK T1555 | GR | no | |
| AD-A-58 | Confidential/secret custom attributes exposed: attributeSchema `searchFlags` (0x80 confidential, 0x200 RODC-filtered) cleared; unlisted secret attrs world-readable | LDAP schema NC + ACLs | same | none | med-high (custom secret store) | MS-ADTS/Schema | GR | no | |

### 1d. DC health, replication, DNS, time

| ID | Finds | Windows read | Samba read | Diff | Sev (why) | Maps to | Src | ADMCP | Flags |
|---|---|---|---|---|---|---|---|---|---|
| AD-A-59 | Replication failures, stale DCs (tombstone), NC coverage; quarantine signals (events 2095/1988/2042, strict replication consistency, divergent-partner override) | `repadmin /showrepl`, `/replsummary`, `/showutdvec`; DS events | `samba-tool drs showrepl` (helper) | Windows event detail richer | med-high (security changes never reach a DC) | MS replication troubleshooting | D (AD-2 verify), GR | no | P |
| AD-A-60 | FSMO holders reachable/placed | LDAP `fSMORoleOwner`; `netdom query fsmo` | `samba-tool fsmo show` | none | low-med (single point roles) | MS FSMO | GR | no | |
| AD-A-61 | Sites/subnets/topology: subnetless clients, DC placement, link cost/schedule | LDAP CN=Sites | same; `samba-tool sites` | none known | low-med (wrong-DC auth latency) | MS Sites | GR | no | |
| AD-A-62 | RID pool health | LDAP `rIDAvailablePool` + DC RID sets; `dcdiag /test:RIDManager` | same LDAP | dcdiag Windows-only | med (exhaustion outage) | MS Schema/Replication | GR | no | P (dcdiag) |
| AD-A-63 | Tombstone/deleted-object lifetime vs backup age and restore evidence | LDAP `tombstoneLifetime`, `msDS-DeletedObjectLifetime`, `garbageCollPeriod`; `repadmin /showbackup`, `wbadmin get versions` | same LDAP; `samba-tool domain backup` records | backup evidence sources differ | med (stale backup = lingering objects) | MS Recovery; Samba wiki | GR | no | P (backup cmds) |
| AD-A-64 | AD Recycle Bin enabled | LDAP `msDS-EnabledFeature`; `Get-ADOptionalFeature` | unsupported (verify) | Windows-only | low (undelete capability) | MS Recycle Bin | GR | no | |
| AD-A-65 | SYSVOL replication engine: FRS vs DFSR state, DFSR backlog, share publication; per-DC SYSVOL divergence | `dfsrmig /getglobalstate`; DFSR event log; `Get-SmbShare` | per-DC manifest hashes (Samba has no DFSR) | engine differs entirely | med (GPO drift/corruption) | MS DFSR; Samba wiki | GR | no | P/V |
| AD-A-66 | Time hierarchy: PDCe external sync, NT5DS below, skew | `w32tm /query /configuration,/status,/peers` | `chronyc tracking/sources` (helper) | different NTP daemons | med (Kerberos skew, evidence chronology) | MS W32Time | GR | no | P |
| AD-A-67 | DC OS/build/patch currency vs advisories | LDAP `operatingSystem(Version)` + host build/UBR and update inventory | `samba -V` + distro package/backport metadata | sources differ | med (known CVEs unpatched) | MS Security Update Guide; Samba advisories | D, GR | partial: `operatingSystem` via `computer.py:list_computers`; no patch state | P |
| AD-A-68 | DNS posture: non-secure dynamic updates, zone transfers, WPAD/wildcard/stale/rogue records, global query block list, scavenging safety, forwarders/recursion/DNSSEC | `Get-DnsServerZone`, `Get-DnsServerResourceRecord` | `samba-tool dns zoneinfo/query` + LDAP DNS partitions | cmd surface differs | med (poisoning paths) | MS DNS | GR | no | P |
| AD-A-69 | Stale DC metadata after incomplete demotion (server/nTDSDSA objects, SRV/CNAME records) | LDAP + DNS | same | none | med (ghost DCs) | MS Recovery/Replication | GR | no | |
| AD-A-70 | LDAP query policy limits (`lDAPAdminLimits`: MaxPageSize etc.) + per-DC `queryPolicyObject` | LDAP CN=Default Query Policy | fixed limits (partial) | Samba not policy-driven | low (DoS/truncation) | MS ntdsutil LDAP policy | GR | no | |

### 1e. Host posture, Samba-specific, process self-checks

| ID | Finds | Windows read | Samba read | Diff | Sev (why) | Maps to | Src | ADMCP | Flags |
|---|---|---|---|---|---|---|---|---|---|
| AD-A-71 | DC service exposure: Spooler, WebClient, RemoteRegistry, Browser, web roles, sockets; unquoted/writable service paths | `Get-Service`, `Win32_Service` (JEA) | host service/socket inventory (helper) | Windows-rich | high (coercion/priv-esc: PrinterBug, PrintNightmare) | CVE-2021-34527 (MS); MS baseline; ATT&CK T1210, T1574.009 | GR | no | P |
| AD-A-72 | DC user rights assignment + GPO restricted-groups/GPP effects on DC groups | `secedit /export`; `GptTmpl.inf` `[Group Membership]` | n/a | Windows-only | med (SeDebug/SeBackup/logon rights) | MS Security baseline | GR | no | P |
| AD-A-73 | Audit-policy coverage + log survivability (subcategories incl. Directory Service Changes, Kerberos; `SCENoApplyLegacyAuditPolicy`; log size/forwarding) | `auditpol /get /category:*`; `wevtutil gl` | n/a (host logs only) | Windows-only | med (no detection/evidence) | MS audit-policy recommendations | GR | no | P |
| AD-A-74 | DC management-plane exposure (firewall, RDP NLA, WinRM/SSH listeners, management groups) | host reads | `sshd_config` (helper) | none in kind | med (attack surface) | MS Security; SSH/JEA | GR | no | P |
| AD-A-75 | Directory file protection: NTDS DIT/log ACLs, disk encryption; Samba private dir (`sam.ldb`, `secrets.ldb`, keytabs, TLS keys) modes — metadata only, never open | host paths (JEA) | host paths (root helper) | same idea | high (offline credential access) | ATT&CK T1003.003; Recovery | GR | no | P |
| AD-A-76 | Sensitive shares on DCs (backups, IFM media, exported hives) — filename/metadata scan only, owner-approved | share + filesystem ACLs | same | none | high (credential-bearing files) | ATT&CK T1552.001 | GR | no | P |
| AD-A-77 | Samba effective auth/transport config + include provenance | n/a | `testparm -s` (`ldap server require strong auth`, `ntlm auth`, `server signing`, `server min protocol`, `smb encrypt`, `server role`) | Samba-only | high (Samba equivalent of AD-A-36/38/39) | smb.conf(5) | GR | no | P |
| AD-A-78 | Samba DB consistency: link/schema/metadata errors | n/a | `samba-tool dbcheck --cross-ncs` — never `--fix` | Samba-only | med (pre-replication-failure drift) | Samba wiki | GR | no | P |
| AD-A-79 | Samba SYSVOL ACL conformance | n/a | `samba-tool ntacl sysvolcheck` — never `sysvolreset` | Samba-only | med (broken/exposed policy) | the second review | GR | no | P |
| AD-A-80 | Samba role/package/backport currency, custom modules | n/a | `samba -V`, distro packages (helper) | Samba-only | med (unpatched server) | Samba advisories | GR | no | P |
| AD-A-81 | Agent-boundary self-check: SSH subsystem/forced-command or JEA role/session configs, helper sudoers, allowed-verb lists, receipt/transcript storage ACLs; endpoint must not require FullLanguage | local config files | local config files | same idea both | high (the audit's whole trust boundary) | MS SSH/JEA docs; DESIGN (FullLanguage check) | GR | no | P |
| AD-A-82 | RFC2307 Unix attribute collisions (`uidNumber`/`gidNumber`/`loginShell`) | LDAP | same (Samba-heavy) | relevance differs | low (identity collisions) | Samba wiki | GR | no | |
| AD-A-83 | Exchange-privilege ACEs ("Exchange Windows Permissions" WriteDacl on domain head) | ACL | n/a (no Exchange) | situational | med (PrivExchange-class paths) | SpecterOps/MS ADV (unverified) | GR | no | |

Count: 83 checks (D = design draft list fully covered; F/S = extensions deduplicated).

## 2. Must-have safety rules for the audit

1. **Forbidden attributes — never requested, never returned.** Values (not names) of: `unicodePwd`,
   `dBCSPwd`, `ntPwdHistory`, `lmPwdHistory`, `pwdHistory`, `supplementalCredentials` (hashes);
   `ms-Mcs-AdmPwd`, `msLAPS-Password`, `msLAPS-EncryptedPassword(History)` (LAPS);
   `msFVE-RecoveryPassword`, `msFVE-KeyPackage` (BitLocker); `msDS-ManagedPassword*` (gMSA — the second review:
   "Never request msDS-ManagedPassword"); `secret` `currentValue`/`priorValue` (DPAPI backup keys, the second
   review); `trustAuthIncoming/Outgoing`, `initialAuth*` (trust secrets); `msPKI-DPAPIMasterKeys`,
   `msPKI-CredentialRoamingTokens`; `userPassword`/`unixUserPassword`/`msSFU30Password` (presence only,
   AD-A-20); `msDS-KeyCredentialLink` blob metadata only (the second review). Sources: DESIGN
   (forbidden-attribute list; "LAPS deployed or not (never its values)"), the second review's cross-cutting "Secret
   exclusion", ADMCP `validation.py:254` `SENSITIVE_FILTER_ATTRIBUTES` (same list, MIT; extend it —
   see §3 defect D4).
2. **Denylist and allowlist both, never `*`.** Every LDAP read names its attributes; no `-Properties *`,
   no unrestricted dumps, no registry exports, no keytab exports. Source: the second review's cross-cutting (Secret
   exclusion); ADMCP's `search(..., attributes=ALL_ATTRIBUTES)` default (`ldap_manager.py:289`) is the
   anti-pattern.
3. **Empty read = "could not read", never "nothing there".** Silent ACL denials must not read as
   compliance. Source: DESIGN (silent ACL denials). Widen per the second review's architectural correction 5: access-denied,
   unsupported-feature, unavailable-DC, truncated/ranged, missing-telemetry are all **UNKNOWN**, never
   PASS.
4. **GPP `cpassword` scrub with a planted-secret test.** Report presence (file, GPO GUID), never the
   decrypted or raw value; a planted secret in the lab proves the scrub. Sources: DESIGN (collector
   rule + planted-secret test), the first review, MS14-025.
5. **Untrusted envelope for every directory string.** No directory-originated string (DN, CN, SPN,
   description, GPO name, error text) reaches tool names, descriptions, log format strings or
   `next_steps`. Source: DESIGN (persona shares Newton's envelope); Newton design AGENTS rule 9. ADMCP
   shows the partial version of this: fixed error codes to avoid leaking ldap3 text
   (`directory.py:get_tls_posture`).
6. **Size and time caps.** Per-check result caps with truncation flags, LDAP paging, server-side time
   limit, hard ceilings even when config says unlimited. Source: ADMCP `base.py:_capped_search`,
   `_audit_scan`/`_cap_findings` (scan uncapped, findings capped after filtering — the right shape),
   `directory.py:43-44` `HARD_MAX_RESULTS=10000`, `SEARCH_TIME_LIMIT_SECONDS=30`; the second review's cross-cutting
   (evidence freshness, concurrency).
7. **No Domain Admin key.** Delegated read-only service account; setup checks and refuses a Domain Admin
   credential. Source: DESIGN (transport/account section).
8. **Read-only means no repair or active-write probes.** No `dbcheck --fix`, `sysvolreset`, replication
   forcing, DNS dynamic-update tests, certificate enrollment, password retrieval, credential-dumping
   probes. Source: the second review's architectural correction 3.
9. **Convergence-aware, DC-labeled reads.** Non-replicated attributes (`lastLogon`, RID sets) are labeled
   with the DC they came from; "identical on every DC" is asserted only where replication guarantees it.
   Sources: the second review's correction 4; ADMCP `LASTLOGON_NOTE` (`security.py:14`).
10. **Per-GPO backup, never `Backup-GPO -All`.** Applies the moment the audit copies GPO state for
    evidence. Source: DESIGN.
11. **FullLanguage check on the PowerShell endpoint.** The JEA/SSH endpoint must run constrained
    language; the audit verifies rather than assumes it. Source: DESIGN, with AD-A-81.
12. **No secret in receipts or transcripts.** Findings carry presence/counts/metadata, not values.
    Source: the second review's cross-cutting (Receipt hygiene); DESIGN AD-2 "passwords never pass through the model"
    applied to the audit too.

## 3. What to take from ActiveDirectoryMCP (MIT, Alperen Adalar 2024)

Read in full: `validation.py`, `attribute_policy.py`, `redaction.py`, `audit.py`, `policy.py`,
`core/ldap_manager.py`, `tools/base.py`, `tools/directory.py`, `tools/security.py`, `registry.py`;
relevant parts of `tools/user.py`, `tools/group.py`, `tools/computer.py`; tests skimmed; golden tool
surfaces. Line counts from `wc -l`.

| File (lines) | Verdict | Reason |
|---|---|---|
| `validation.py` (355) | **keep/adapt** | LDAP filter-fragment policy (balanced parens, no extensible-match, no OIDs, sensitive-attr denylist), DN confinement to base DN, RDN escaping. Best single file in the tree. |
| `attribute_policy.py` (151) | **keep for 1.4** | Modify allowlists + `HARD_DENY` with a build-time disjointness check; only relevant once write verbs exist. |
| `redaction.py` (155) | **adapt ideas** | Secret-variant registration (base64/URL-quote/JSON/`unicodePwd` UTF-16-LE forms), fail-closed log filter. Newton already has a redaction core (design: share it, no library split). |
| `audit.py` (275) | **adapt** | JSONL, default-deny arg redaction (`AUDIT_TARGET_KEYS` allowlist), outcome classification ("unknown" never "success"), rotation-safe 0600 append. Newton has receipts; take the default-deny arg handling. |
| `policy.py` (214) | **keep** | Risk classification + read-only-by-default dispatch gate; unknown tools classify DESTRUCTIVE (fail closed). Maps onto Newton's tiering. |
| `core/ldap_manager.py` (567) | **adapt with changes** | Server pool, retry, paged search with size/time limits, `is_secure_channel()` (LDAPS-or-StartTLS **and** cert validation) — good. Replace simple bind (defect D3), drop `ALL_ATTRIBUTES` default (D4). |
| `core/logging.py` (111) | **skip** | Newton has structured logging. |
| `tools/base.py` (523) | **adapt** | AD time/interval conversion incl. "never" sentinels, UAC decode, `_capped_search`/`_audit_scan`/`_cap_findings` pair, `_protected_target_refusal`, `_require_secure_channel` pre-flight. |
| `tools/directory.py` (302) | **keep** | `get_rootdse_info` (fixed allowlist), `get_nested_group_members` (one server-side chain query, caps + time limit), `get_tls_posture` (fixed error codes, single-attempt bind to avoid lockout). Directly reusable for AD-A-03/45/49. |
| `tools/security.py` (1004) | **adapt carefully** | Query shapes for AD-A-03/16/17/21/22/24/33 are here, but groups are matched by English display name (D5) and members are truncated at 10; rebuild SID-based. |
| `tools/user.py` (843), `group.py` (779), `computer.py` (801) | **read parts for 1.4** | Write tools out of 1.3 scope; read helpers (`get_stale_computers`, default attribute lists) feed AD-A-24/25. Contains defects D1 (user) and D1 (computer). |
| `tools/organizational_unit.py` (896) | **skip for 1.3** | All write/list OU management; no audit value now. |
| `tools/definitions.py` (931) | **skip** | Hand-maintained tool descriptions/schemas; Newton generates schemas. |
| `registry.py` (626) | **adapt pattern** | One declaration point per tool, guard seam for all tools, transports can't drift; golden-surface test keeps the tool surface frozen. |
| `server.py` (304), `server_http.py` (316), `http_app.py` (64), `middleware.py` (81), `auth.py` (238) | **skip** | Newton has its own MCP server, approval and enrolment layers (design: share them). |
| `config/loader.py` (363), `config/models.py` (373) | **adapt** | Env-file/config hygiene, SecretStr handling, per-domain configs. |
| `config/keyvault.py` (69) | **skip** | Azure Key Vault; not our deployment. |
| `tests/` (34 unit files, 4 integration, 4 e2e, golden surfaces) | **adapt patterns** | `test_credential_leak.py`, `test_tls_posture.py`, `test_hardening_guards.py`, golden tool-surface fingerprints, mock directory fixtures — the test ideas outlive the code. |

Known defects (each verified against the ADMCP source):

- **D1 — password returned to the model**: `tools/user.py:603` (`"new_password": new_password` in the
  `reset_password` response) and `tools/computer.py:587` (same in `reset_computer_password`, despite a
  `"sensitive": True` flag). `register_secret` scrubs logs, not the tool response. Violates DESIGN's
  "passwords never pass through the model" — do not port these response shapes.
- **D2 — privileged guard on 3 of 17 write tools**: `_protected_target_refusal` is called only in
  `user.py:571` (`reset_password`), `group.py:470` (`add_member`), `group.py:549` (`remove_member`).
  The other 14 write tools (e.g. `enable_user`, `disable_user`, `create_user`, `move_organizational_unit`)
  can touch privileged targets. Newton's HIGH classification must not replicate this gap (1.4 concern,
  noted now).
- **D3 — simple bind only**: `core/ldap_manager.py:179` (`authentication=ldap3.SIMPLE`), bind DN +
  password from config. No Kerberos/SASL path. Transport is mitigated by `is_secure_channel()`
  (cert-validated TLS required before `unicodePwd` writes), but the bind is always a password bind.
- **D4 — no denylist on requested read attributes**: `get_user`/`list_users`/`get_computer`/
  `list_computers` accept a caller-controlled `attributes` list (`user.py:28,133`; `computer.py` same
  shape) checked against nothing, and `search()` defaults to `ALL_ATTRIBUTES` (`ldap_manager.py:289`).
  `SENSITIVE_FILTER_ATTRIBUTES` guards only `filter_criteria`. A model could request
  `ms-Mcs-AdmPwd`/`msDS-ManagedPassword` directly (subject to directory ACLs). Our catalogue must
  request explicit allowlists per check (§2 rule 2).
- **D5 — privileged groups by English name**: `security.py:112-122` and `753-769` match
  "Domain Admins" etc. by display name; renamed or localized groups are missed; `_has_privileged_groups`
  (`security.py:771-781`) string-slices `CN=` out of DNs. Use well-known SIDs/RIDs.
- **D6 — membership analysis is direct-only**: `get_user_permissions` walks one level of `memberOf`;
  nesting exists only in the separate `get_nested_group_members`. The audit needs the recursive form
  everywhere.
- **D7 — minor**: `audit_admin_accounts` does N+1 BASE searches per member (`security.py:574-590`);
  `get_schema_info` (`security.py:1003`) advertises a "critical" risk level nothing emits;
  `test_connection` echoes the bind DN (`ldap_manager.py:538`); `lastLogon` single-DC figures are used
  for staleness (they do document the caveat).

## 4. Disagreements between the two reviews, with recommendations

1. **JEA over SSH.** DESIGN assumes OpenSSH → JEA endpoint; the second review's architectural correction 2 says
   PowerShell-over-SSH does not provide JEA endpoint configuration (documented SSH-remoting limitation)
   — an SSH login launching PowerShell is not a JEA boundary. *Recommendation*: treat the fixed-verb
   command allowlist at the SSH subsystem level (mirroring the Samba helper's NOPASSWD sudoers design)
   as the boundary, verify it as AD-A-81 in the lab, and do not rely on JEA session semantics; keep
   pypsrp (MIT) as the fallback transport if a real JEA endpoint is required.
2. **Configured vs observed state (LDAP signing, channel binding, NTLM, Kerberos crypto).** The first review reads
   registry values/policy; the second review insists observed
   events are the dependency evidence and "configured bits do not prove available keys". *Recommendation*:
   report both, in two labeled fields (configured / observed), and UNKNOWN when events are unreadable —
   never infer enforcement from the registry value alone.
3. **`dsHeuristics` decoding.** The first review flags char positions as "verify"; the second review says decode each
   position from the ADTS spec and preserve unknown positions as findings. *Recommendation*: the second review's — a
   table-driven decoder that emits `unknown-position` findings, never a blind string compare.
4. **Trust checks: one row vs split.** The first review bundles inventory, SID filtering and trust
   encryption in one row; the second review splits boundaries from channel health and forbids inferring trust-secret
   age from TDO `whenChanged`. *Recommendation*: split (AD-A-48 carries both halves, separately
   reported); never use `whenChanged` as a secret-age signal.
5. **gMSA and KDS on Samba.** The first review: "gMSA from 4.21, KDS commands reworked 4.20" (web-search-sourced,
   marked verify); the second review: B† — must be verified against the exact release. *Recommendation*: verify on the
   lab's pinned Samba 4.22 before shipping AD-A-23; until then report UNKNOWN on Samba.
6. **AD Recycle Bin on Samba.** The first review: N (a 2016 mailing-list thread); the second review: B† verify. *Recommendation*:
   test in the lab; report UNKNOWN (not "absent") if unverified (§2 rule 3).
7. **Empty-read semantics.** DESIGN: empty read = "could not read" (silent ACL denials); the second review widens to a
   five-case UNKNOWN taxonomy including unsupported-feature and truncated results. *Recommendation*:
   adopt the second review's superset; it also covers Samba feature gaps found in disagreements 5–6.
8. **Audit breadth.** The first review proposes 73 checks including deep host-registry sweeps; the second review proposes 90 with
   strict effective-vs-configured discipline; DESIGN scopes 1.3 to the listed findings. *Recommendation*:
   ship 1.3 as LDAP-first (§1a–1c plus D via the fixed forced-command collector on Windows and the Samba helper), and hold the
   Windows host-baseline sweep (AD-A-71–74) behind the lab twins so the first release proves the loop,
   not the breadth. Drop the first review's self-flagged placeholders (done).
9. **RODC coverage.** The first review marks Samba "no RODC"; the second review says verify. *Recommendation*: AD-A-32 stays
   Windows-only in 1.3; revisit if a Samba RODC joins the scenario set.

## 5. Deferred to the change release (1.4): everything that writes

All mutating verbs from both gap analyses — the first review's 63 settings and 65 actions, the second review's
75 settings and 60 actions — are 1.4 or later, on DESIGN's AD-2 flow (undo armed first, verify on a fresh connection
on every DC, no deletes in v1, HIGH for privileged-group/delegation/Tier-0/DC-object changes,
passwords never through the model). Grouped:

- **Account lifecycle**: create/enable/disable/unlock, attribute edits (ADMCP `attribute_policy.py`
  allowlists are the input), expiry, logon hours/workstations, offboarding bundles, bulk import.
- **Group and membership**: add/remove (recursive-aware), scope/type conversion, TTL membership (PAM),
  managedBy.
- **Delegation/ACL**: OU delegation, dangerous-ACL repair, AdminSDHolder template changes, RBCD/
  constrained-delegation edits, `sIDHistory` clears, key/cert mappings.
- **GPO**: setting edits for the audit's fixes (password, lockout, Kerberos, LDAP signing, NTLM),
  link/unlink, per-GPO backup-then-restore undo (never `Backup-GPO -All`).
- **Policy objects**: PSOs, auth policies/silos, Protected Users membership.
- **Identity plumbing**: password reset (generated by Newton, shown only to the owner), computer
  reset/prestage/rename, gMSA creation and retriever rights, KDS root key (no routine rollback), SPN
  management (`setspn -S` semantics).
- **Infrastructure**: DNS records/zones, sites/subnets/links, FSMO transfer/seize, replication forcing,
  krbtgt double reset, trust create/rotate, LAPS rotation (never read), DC metadata cleanup, SYSVOL
  ACL repair, certificate enrollment.
- **Explicitly later than 1.4**: schema extensions and FL raises (the second review: effectively irreversible),
  deletes (DESIGN: only with Recycle Bin on, HIGH), AD CS template changes, and the read-only AD CS
  audit itself (DESIGN: "later", not 1.3 — see note atop §1).

Not verified: every ANSSI rule id; exact CIS benchmark ids; Samba release facts in
§4 items 5–6; whether Samba honors matching-rule-in-chain identically (ADMCP's chain query is
Samba-untested); `samba-tool` subcommand availability beyond those read in the man page;
and the JEA-over-SSH limitation itself (the second review cites MS docs; not fetched here — flagged
as the first thing to test in the lab).
