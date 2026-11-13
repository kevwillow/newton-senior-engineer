# Newton 1.4 design: guarded AD changes (draft, 2026-11-08, for the maintainer's review)

1.3 reads AD. 1.4 lets Newton change it, inside the three-way split the maintainer decided on 2026-11-08:
- Newton writes changes that have a clean undo and a small blast radius;
- Newton writes a script for the owner when a change cannot be cleanly undone;
- Newton explains judgement calls and leaves them to the owner.

This document covers the first two. Build mode (1.5, a whole new domain from a reviewed plan) reuses everything here.

**Status (2026-11-13):** the Newton-writes part is built and on the main branch, not yet released: the flow of section 1, the verbs of section 2, the write path on the DC (section 3), the write account (section 4), the replication check (section 5), the password rule (section 6) and the four tools `newton_ad_plan_change`, `newton_ad_apply_change`, `newton_ad_change_status` and `newton_ad_abort_change`. Not built: the script tier of section 7 and its tool `newton_ad_plan_script` (section 8), and the GPO edits of phase B. The rest of this document is the design as it was drafted.

**The maintainer decided the three open questions on 2026-11-08**: the DC verifies the approval signature (section 3); privileged-group changes go to the script tier (section 4); two more lab DCs are added on apollo (section 5).

## 1. The flow

1.4 uses the same flow as a router change: plan, owner approval, undo armed on the DC first, apply, verify over a fresh connection on every DC that has a write entry in the inventory, confirm, receipt.

1. **Plan.** `newton_ad_plan_change(device, verb, target, value)` reads the target's current state through a fresh collector run and builds a plan. The plan holds:
   - the verb;
   - the target by objectGUID and SID, never by name;
   - the before-image: the exact attribute values the verb will change, as read;
   - the after-image;
   - the risk level;
   - the inverse.

   The plan digest covers all of these plus the device id and the 1.4 helper version.
2. **Approve.** The owner approves with `newton-approve`, outside the chat. Unlike routers, nothing on the DC produces a digest before approval, so `newton-approve` builds the canonical bytes itself from the plan's fields and shows every field (SPEC-1.4-REQUEST section 4); it never trusts a digest in the plan file. HIGH changes show the extra warning text the router flow uses.
3. **Arm the undo, then apply.** One call to the DC-side write helper (section 3) does three things in this order:
   1. it checks that the target's live values equal the before-image (a conflict means stop, nothing written);
   2. it writes the undo record and schedules the undo;
   3. it applies the after-image.
4. **Verify.** A fresh session reads the target back from **every** DC in the domain (section 5). Every DC must show the after-image. A DC that has not caught up within the window is NOT TESTED, which blocks the confirm.
5. **Confirm or undo.** Confirm cancels the scheduled undo. If confirm does not come in time, because Newton died, the session dropped or verify failed, the DC itself puts the before-image back. The undo restores only attributes whose live value still equals the after-image. An attribute someone else changed in the meantime is left alone and reported as a conflict in the receipt.

## 2. Verbs in 1.4

Each verb maps to one or more audit findings, so that a finding's fix can become a plan.

| Verb | Change | Undo | Risk |
|---|---|---|---|
| `uac-clear` | clear DONT_REQ_PREAUTH (0x400000), PASSWD_NOTREQD (0x20), ENCRYPTED_TEXT_PWD_ALLOWED (0x80), TRUSTED_FOR_DELEGATION (0x80000) or DONT_EXPIRE_PASSWORD (0x10000) on one account | restore the before-image bits | MED; HIGH on a DC or Tier 0 account |
| `enc-types` | set msDS-SupportedEncryptionTypes on one account | restore the before-image | MED |
| `disable` / `enable` | ACCOUNTDISABLE (0x2) | the opposite | MED; HIGH on Tier 0 |
| `unlock` | lockoutTime to 0 | none needed (nothing to undo); LOW | LOW |
| `member-remove` / `member-add` | one membership of a non-privileged group | the opposite | MED |
| `maq` | ms-DS-MachineAccountQuota on the domain head | restore the before-image | MED |
| `user-create` | a new user, disabled, in a chosen OU, with a password only the owner sees (section 6) | delete the object this transaction created, matched by its GUID | MED |
| `move` | an account to another OU | move it back | MED |

**Not in 1.4 Newton-writes**; these go to the script tier:
- deletes of existing objects;
- password resets of existing accounts;
- the krbtgt reset;
- trusts and functional levels;
- anything that changes a privileged group (section 4);
- GPO edits.

The domain password and lockout policy on Windows live in the Default Domain Policy GPO, so a policy change is a GPO edit. **GPO edits come in 1.4 phase B**, after phase A ships. Phase B:
- backs up that one GPO first (never `Backup-GPO -All`);
- has the undo restore that backup;
- verifies through the GPO version number and SYSVOL on every DC.

## 3. The write path on the DC

The write helper is separate from the read collector and has its own key, account and forced command. The 1.3 audit account stays read-only.

- **Windows:** `C:\ProgramData\Newton\ad\write.ps1`, run by an sshd `Match Group` plus a `ForceCommand` for a new group, with the same file ACL rules as the collector.
- **Samba:** `/usr/local/sbin/newton-ad-samba-write`, run by one `NOPASSWD` sudoers line, like the collector.

The helper takes no arguments. It reads one JSON request on stdin: verb, GUIDs, before-image, after-image, deadline and the owner's approval signature. It runs only the fixed verbs above. It never takes an LDAP filter, a cmdlet name or a script.

- **The approval is checked on the DC (decided 2026-11-08).** This works exactly as on routers (`mcp/newton_mcp/approve.py`):
  - `newton-ad-setup` installs the per-device approval key `K = PBKDF2-HMAC-SHA256(passphrase, "newton-approve-v1:" + device, 600000, 32)` in the helper's directory, readable only by the write account and administrators. The Newton machine keeps only K's fingerprint.
  - The helper computes the plan digest itself, from the canonical bytes of the request it received. It never takes a digest from Newton.
  - It accepts the write only if the request's token equals `HMAC-SHA256(K, "newton-approval-v2\n" + digest + "\n" + NBF + "\n" + EXP + "\n")`, compared in constant time, and the DC's clock is inside [NBF, EXP].

  A compromised Newton machine or agent therefore cannot write to AD without the owner's passphrase. The alternative, trusting Newton's own approval check, is simpler but makes the Newton machine a path to writing AD.
- **The undo on the DC.**
  - On Windows, a one-shot scheduled task runs as the write account at the deadline: `write.ps1` in undo mode for that transaction id.
  - On Samba, it is `systemd-run --on-active=<window>` calling the helper in undo mode.
  - The undo record (before- and after-images) is stored in the helper's directory, readable only by the account and administrators.
  - Confirm deletes the task or timer. Records are never deleted, so a txid can never be replayed.
  - After a reboot: Windows scheduled tasks survive one, and the helper's boot check runs any undo whose deadline has passed. This is never an auto-confirm (design rule 8).

## 4. The write account

The write account (proposed name `newton-ops`) is a domain account delegated **only** the rights its verbs need:
- on the user and computer OUs and containers the owner names: write userAccountControl, msDS-SupportedEncryptionTypes and lockoutTime; create and delete user objects (the user-create undo deletes); create-child and delete-child for move; write the `member` of groups in those locations;
- on the domain head: write ms-DS-MachineAccountQuota.

It is never a member of a privileged group. The setup refuses if it is, and every write re-checks it, as the 1.3 identity guard does.

**Privileged groups (decided 2026-11-08: script tier).** The earlier decision said "privileged-group changes are HIGH". To write the membership of Domain Admins, Enterprise Admins or any other AdminSDHolder-protected group, the account needs rights that make it Tier 0 itself: whoever holds its key could make themselves a Domain Admin. Privileged-group changes therefore go to the script tier: the owner runs them as their own admin, and `newton-ops` stays outside Tier 0. This replaces the earlier "privileged-group changes are HIGH" decision.

## 5. Replication

1.4 applies every write on one DC, the PDC emulator, and verifies on every DC that has a write entry in the inventory. A DC of the domain without a write entry is never read; the plan lists the DCs it will read and warns about this. Verify passes only when each of those DCs shows the after-image, and each DC is reached over its own SSH entry, which `newton-ad-setup` creates per DC.

The lab needs a second DC in each domain to prove this: WINDC2 on apollo, and a second Samba DC. **(Decided 2026-11-08: add both.)**

## 6. Passwords

A password never passes through the model or the chat.
- For `user-create`, Newton generates the initial password and shows it only in the `newton-approve` terminal, once, at the first approval of the plan. It reaches the DC on the helper's stdin, inside the request, is dropped from the plan record once the apply has sent it, and never appears in a log or receipt.
- The account is created disabled. Enabling it is a separate plan, after the owner has handed the password over.

## 7. The script tier

For everything in the "not in 1.4" list, Newton renders a reviewed owner script from a fixed template, exactly as the router owner script does:
- the exact bytes are approved;
- the bytes are deterministic and round-trip parsed;
- the script contains a before-image export and the rollback commands;
- it says what breaks if the change is wrong.

The owner runs it as their own admin. Newton then re-runs the audit to show the result.

## 8. MCP tools

`newton_ad_plan_change`, `newton_ad_apply_change`, `newton_ad_change_status`, `newton_ad_abort_change` and `newton_ad_plan_script`. These mirror the router tools. There is no approve tool, and no tool that takes a filter or free text bound for the DC.

## 9. Tests and live proof

- **Unit:** each verb's plan, digest and inverse; the conflict rule; the undo's "only if still the after-image" rule; signature refusal; the request schema refusing any field outside it; and hostile names, with no directory string inside any command.
- **Live proof**, on both domains (lab only), the AD lab scenario set:
  - a normal change confirms;
  - a verify failure undoes itself;
  - Newton killed mid-window undoes itself;
  - a reboot mid-window undoes itself;
  - a concurrent admin edit is a conflict and is not overwritten;
  - a write with a bad signature is refused;
  - a key for a privileged account is refused;
  - a DC that has not replicated blocks the confirm.

## 10. Parts

The four parts below depend only on SPEC-1.4-REQUEST.md, not on each other:
1. **The Newton side (Python):** the request schema, plan and digest, signatures, receipts and MCP tools.
2. **The Windows write helper:** `write.ps1` and its undo task.
3. **The Samba write helper:** `newton-ad-samba-write` and its timer.
4. **The setup:** `newton-ad-setup` gains the write account, its delegation, the per-DC entries and the approval key install.

After those: the script tier, the live proof on both domains, an independent review of the whole, then the maintainer approves. Phase B (GPO edits) follows the same steps.
