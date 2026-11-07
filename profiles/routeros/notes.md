# RouterOS profile notes

## Status
Experimental read-only. Tier T0-exp on the capability registry.
The enabled getter and account-setup recipe are lab-observed on CHR 7.24.5
(2026-10-18). The nine enabled rows carry that receipt and `os_range = "7.24.5"`.
This is a T0 read-only observation, not write certification.

Verification scope: `vpn` was seen only as an empty table (no IPsec peer
existed), so its receipt covers the command and the empty path, not populated
output. The `firewall_policy` and `nat` recordings, and the 80-line paging
check, used entries planted on a throwaway CHR for the run. Of the error
markers, only `bad command name` was observed.

## Getters
- `version` — `/system resource print` — enabled.
- `interfaces` — `/interface print` — enabled.
- `routes` — `/ip route print` — enabled.
- `firewall_policy` — `/ip firewall filter print` — enabled.
- `nat` — `/ip firewall nat print` — enabled.
- `mgmt_services` — `/ip service print` — enabled.
- `admins` — `/user print` — **disabled** — the account list shows each
  account's last login time, which decision 10 (personal data) keeps out of
  v1 until the maintainer decides; it is disabled, not redacted.
- `logging` — `/system logging print` — enabled.
- `ntp` — `/system ntp client print` — enabled.
- `vpn` — `/ip ipsec active-peers print` — enabled.
- `running_config` — `/export` — **disabled** — `/export` masks only values
  RouterOS marks sensitive. CHR masked PPP passwords, RADIUS secrets and
  WireGuard private keys on the device, but `/export` still exposed the SNMP
  community name and a static DHCP lease. It stays disabled until a
  section-aware rule redacts `name=` under `/snmp community` and the maintainer decides
  on the client-table data (decision 10).

## Lab observations
- A no-PTY SSH exec channel did not page: an 83-line print completed without
  an ESC byte or RouterOS pager prompt, and `without-paging` was byte-identical.
- Empty firewall, NAT and IPsec peer tables return successful empty output.
- The custom `read,ssh` group could run `/export` without `sensitive`, with the
  device-side masking limits described above.
- `device_role_enforced` remains false: the policy flags were observed, but a
  write refusal was not tested through Newton's read-only grammar.

## Setup recipe — lab-observed on CHR 7.24.5 (2026-10-18)
Read-only account only. No write access to the device from this account.

1. Create a custom user group with **only** the `read` and `ssh` policies
   (`/user group add name=newton-read policy=read,ssh`). The built-in `read`
   group is not used. `/user group print detail where name=newton-read` showed
   `ssh,read` and `!` for local, telnet, ftp, reboot, write, policy, test,
   winbox, password, web, sniff, sensitive, api, romon and rest-api.
2. Add a user in that group with an address restriction to the Newton host
   (`/user add name=newton-ro group=newton-read address=<newton-host>/32`).
   On serial, build the public key in short `:global` chunks and add it with
   `/user ssh-keys add user=newton-ro key=("ssh-ed25519 ".$k1.$k2.$k3)`;
   long single-line key input garbled. `/ip ssh print` reported
   `password-authentication: yes-if-no-key`.
3. Capture the host key out of band on serial. CHR's default host key was RSA:
   `/ip ssh export-host-key key-file-prefix=mv1hk` wrote a public PEM file.
   Read that file in short `:global`/`:pick` chunks, convert it with
   `ssh-keygen -i -m PKCS8 -f <public-pem>`, write the OpenSSH result to the
   per-device `known_hosts`, then remove the exported files. Keep
   `StrictHostKeyChecking=yes`; never trust the first SSH probe.
4. Inventory entry for this device sets `platform = "routeros"`, `host`,
   `user`, `key_file` (the key used only by Newton), `known_hosts` (the
   per-device file from step 3), and `experimental_readonly = true`.
   `device_role_enforced` is a result field Newton sets, not an inventory
   field, and it is false for every device in v1.

## Sources
Getter `source` values retain the MikroTik documentation root. The operational
claims above come from the recorded CHR 7.24.5 lab run dated 2026-10-18.
