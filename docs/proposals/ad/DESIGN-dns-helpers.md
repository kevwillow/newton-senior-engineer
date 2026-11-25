# DESIGN: DNS helpers (discovery and DNS audit checks)

Status: owner-approved, 2026-11-21. Branch `newton/ad-dns-helpers`. Two features, built
and tested without contacting any host. **Every new check below is covered by tests only,
unmeasured on a lab DC.** No lab measurement was possible when this was written.

Hard rule 12 (no network-facing dependency without an ADR): the owner approved `dnspython` for Feature A
in the request; no ADR file was written (docs/design is protected). The dependency is used only by
`newton-ad-discover`, never by the MCP server or the audit.

## Feature A: `newton-ad-discover`

What: given a domain, print the setup commands the owner would run, so setup is mostly
hands-off. It prints and never runs anything, holds no credential and writes nothing.

Inputs: `--domain DNS`, `--platform windows|samba`, `--pubkey FILE`, optional `--write --ou DN`
(repeatable, as in `newton-ad-setup write`) and `--resolver IP`. Without `--resolver` the system
resolver is used.

DNS queries (read only): SRV `_ldap._tcp.dc._msdcs.<domain>` (all DCs), SRV
`_ldap._tcp.pdc._msdcs.<domain>` (the PDC emulator), then A and AAAA for every target.

Outputs: the DCs found (PDC marked), a read inventory entry and the exact
`newton-ad-setup windows|samba ...` command per DC, and with `--write` the
`newton-ad-setup write ...` commands, PDC first, every other DC with `--domain-device <PDC device>`.
Device names come from the DC short host name (lowercased, validated).

Trust boundary: DNS answers are untrusted (anyone who can spoof DNS can name any host).
Every host name must be strict LDH labels (1 to 63 characters, no leading or trailing hyphen),
at most 253 characters in total, and end in `.<domain>`; anything else is skipped with a printed
reason. At most 32 DCs are used; more are refused with a printed reason. Every value in a printed
command goes through `shlex.quote`. The output tells the owner to check the list against their
DCs. The SSH host key pinning in setup still protects the logins; discovery adds no trust.
Addresses are printed as a hint only; the command uses the validated host name. An address with a
scope id (a `%` and the name of an interface of the host the tool runs on) is dropped with a
printed reason that shows it escaped: the tool cannot know which interface it names, so it never
connects to it. The work one host can cost is bounded: at most 64 A and AAAA records are read for
it (A and AAAA together) and at most 8 scope-id refusals are printed for it, and what was cut is
said out loud, in a note.

Errors (exit codes, documented in the script header): 0 printed; 2 arguments or key refused;
3 domain has no such SRV name (NXDOMAIN or no answer); 4 DNS timeout or no resolver answer;
5 no usable DC after validation; 6 `--write` asked and no PDC could be named. A missing PDC record, or a PDC that is not in the DC list, is
printed plainly with the next step, and the DC commands are still printed: without `--write` the
run ends with exit 0, with `--write` it ends with exit 6 and prints no write command.

Unmeasured: behaviour against a real Windows or Samba DNS server. Tests use a fake resolver.

## Feature B: DNS readers in the audit (read only)

Three new queries in `queries.json` (the query set hash changes, so owners re-run the setup
script to install the new file; the measured fixtures are re-hashed and the new queries are
`not_collected` in them, because they were not measured):

- `dns_zones`: `dnsZone` objects under `CN=MicrosoftDNS,DC=DomainDnsZones,{domain}`, attributes
  `dNSProperty` (binary), `name`.
- `dns_ldap_srv`: `dnsNode` objects named `_ldap` under the same container, attribute
  `dnsRecord` (binary).
- `dc_hosts`: computer objects with primaryGroupID 516 or 521, attributes `dNSHostName`,
  `primaryGroupID`.

Both collectors run queries generically from `queries.json`, so neither collector script changes.
The read account is unchanged: these are ordinary LDAP reads. Whether the ordinary audit account
may read `dnsZone` and `dnsNode` objects is **unmeasured**; if it cannot, the status is
`denied` or the sentinel fails and the checks are UNKNOWN(access_denied), never PASS.

All zone names, record data and host names are device data: they go only into `Affected.dn`,
`name` and `evidence`, which the renderer puts inside the untrusted envelope.

### MS-DNSP constants (from learn.microsoft.com, fetched 2026-11-21)

dNSProperty structure, section 2.3.2.1 ("dnsProperty"): DataLength u32, NameLength u32 (ignored),
Flag u32 (0), Version u32 (1), Id u32, Data (DataLength bytes), Name (1 byte, ignored). The
spec does not state the byte order of this structure; the one place that says big-endian is the
TtlSeconds of dnsRecord, which implies the rest is little-endian. Newton reads it little-endian and
requires total length exactly 21 + DataLength, else the value is unreadable (UNKNOWN).

Property Ids, section 2.3.2.1.1 ("Property Id"):
`DSPROPERTY_ZONE_TYPE` 0x00000001, `DSPROPERTY_ZONE_ALLOW_UPDATE` 0x00000002,
`DSPROPERTY_ZONE_AGING_STATE` 0x00000040 (all DWORD data).

Values: DNS_ZONE_TYPE, section 2.2.5.1.1: PRIMARY 0x01. fAllowUpdate in DNS_RPC_ZONE_INFO_W2K,
section 2.2.5.2.4.1: ZONE_UPDATE_OFF 0, ZONE_UPDATE_UNSECURE 1, ZONE_UPDATE_SECURE 2. fAging,
same section: TRUE 1 / FALSE 0. A property with DataLength 0 takes the Id default; the spec gives
a default for the zone type (PRIMARY 0x01) and for aging (0), and none for allow-update, so a
zero-length allow-update is unreadable, and so is a zone whose type property is absent.

dnsRecord, section 2.3.2.2: DataLength u16, Type u16, Version u8 (5), Rank u8, Flags u16,
Serial u32, TtlSeconds u32 (big-endian), Reserved u32, TimeStamp u32, Data. Fixed header 24 bytes.
DNS_RECORD_TYPE SRV 0x0021, section 2.2.2.1.1. DNS_RPC_RECORD_SRV, section 2.2.2.2.4.18:
wPriority u16, wWeight u16, wPort u16, nameTarget. In the directory the name is a DNS_COUNT_NAME
(section 2.2.2.2.3 as cited by section 3.1.6.3 "dnsRecord in the Directory Server"; the DNS_COUNT_NAME
page itself is headed 2.2.2.2.2): Length u8 (bytes of RawName including the null), LabelCount u8,
RawName (a length byte before each label, null terminated). The priority, weight and port byte
order is not stated in the spec, so Newton does not read them; it reads only the target name
after the first 6 bytes of Data.

The record layout under the zone (one `dnsNode` per label: `_ldap` under `_tcp` under the zone
`<domain>`) is **not in MS-DNSP**; it is the layout seen in practice and is unmeasured here. The check
builds the full name from the RDNs of the node DN, so it also copes with dotted RDNs.

MS-ADTS "SRV Records": a non-RODC DC registers `_ldap._tcp.<domain>` with Target its FQDN. An
RODC registers only site records, so the "missing" expectation uses primaryGroupID 516 only,
and the "stale" test accepts both 516 and 521 hosts.

### Checks (ids AD-A-68a, 68b, 69a, 69b; GAPS rows AD-A-68 and AD-A-69)

- AD-A-68a zone allows non-secure dynamic updates (primary zone, fAllowUpdate = 1). High.
- AD-A-68b zone aging off (primary zone, fAging = 0). Low. Scavenging is a server-level setting
  and is not read.
- AD-A-69a DC SRV record (`_ldap._tcp.<domain>`) missing for a DC. Medium.
- AD-A-69b DC SRV record points at a host that is not a DC (stale). Medium.

### Left out, and why

- **Zone transfers to any server.** MS-DNSP lists no dnsProperty Id for the secondary security
  setting (fSecureSecondaries) or for the secondaries list; section 2.3.2.1.1 has only masters
  (for secondary zones), scavenging and auto-NS lists. The setting is held by the DNS server,
  reachable only over the DNS RPC (R_DnssrvQuery) or the DnsServer module, which needs more
  than the read account has. Not widening rights.
- **Forwarders.** Server-level setting, not in a dnsZone object; same reason. Not checked, not
  reported.
- ForestDnsZones, `_msdcs` zones and the legacy `CN=MicrosoftDNS,CN=System` container are not
  read (the placeholders cover the domain only; a forest partition base would need a new
  placeholder in both collectors).

### Unmeasured

Everything in Feature B: the read rights of the audit account on the DNS objects, the dnsNode
layout, the real byte encodings (the fixtures are built from the spec encodings and named
spec-derived, not measured), and the behaviour of both collectors on the DNS partitions
(a missing partition gives status `unavailable`, so the checks are UNKNOWN).

## Feature C: the preflight of `newton-ad-discover` (read only)

Opt-in (`--preflight`), on the host the tool runs on, for every controller it found, at the
address DNS gave it:

- TCP connect to 22 (SSH), 389 (LDAP) and 88 (Kerberos), 3 s timeout each
  (`socket.create_connection`, connect then close, nothing is ever sent). Each port is reported
  as open, closed or timeout.
- One SNTP query on UDP 123, over IPv6 when the address of the controller is an IPv6 literal (`ipaddress` decides, then
  `AF_INET6`; `AF_INET` otherwise). The request is a 48 byte packet whose first byte is 0x23 (LI 0, version 4, mode 3
  client) and whose transmit timestamp (bytes 40..47) holds the local time (seconds) and a random 32 bit fraction
  (`secrets.randbits`, injectable in the tests). Up to 512 bytes are read, and any length other than 48 is refused (a
  datagram longer than 512 bytes is cut short by the read, and is still refused, not trimmed to a length that looks
  right). The reply is
  accepted only when all of this holds:
  - it is exactly 48 bytes long;
  - `byte0 & 0x07 == 4` (a time server);
  - the leap indicator (`byte0 >> 6`) is not 3: the clock of the time server is not synchronized, so its time is not used
    (0, 1 and 2 are accepted);
  - the stratum (byte 1) is 1..15;
  - the reply belongs to the request: its originate timestamp (bytes 24..31) is the transmit timestamp of the request
    (bytes 40..47), byte for byte. The offsets are the ones of RFC 4330, figure 1: a time server copies the transmit
    timestamp of the client into the originate timestamp of its reply; the random fraction is what makes that binding
    meaningful, so a reply to another query (or a stray packet) is never read as the clock of the controller;
  - its transmit timestamp (bytes 40..47) is not all zero: an all-zero transmit timestamp carries no time at all, so the
    reply is discarded (RFC 4330, section 5, check 4).

  A reply that fails any of these leaves the clock UNKNOWN, never a PASS (the DC is still a FAIL when 389 or 88
  is not open). The version field is not checked: it is not
  in the RFC's list of reply checks.
- The server's transmit timestamp (bytes 40..47, two big-endian uint32: seconds and fraction/2\*\*32 since 1900-01-01,
  less 2208988800) gives the skew: `server_transmit - (t_sent + t_received)/2`. The skew uses the local times of the
  query, not the request. A seconds value below 2208988800 is read in the next NTP era (2^32 is added); there is no
  other era check, and a time from a wrong era can only give a huge skew, never a PASS.

A timeout of the time query, a network error and a reply that is not accepted all leave the clock of the controller
UNKNOWN.

A skew of more than 300 s (the Kerberos default) is FAIL, and the run exits 1; a controller whose
time cannot be read is UNKNOWN, and the run exits 1 as well. Ruled by the maintainer, 2026-11-22: a controller
whose LDAP port 389 or Kerberos port 88 is not open (closed or timed out) is a FAIL as well, and
that FAIL wins over the UNKNOWN of a clock that cannot be read. The SSH port 22 is still reported
only: a controller that has no SSH yet is expected (the setup script installs it), so a closed port
22 does not fail the run. Without the flag nothing is contacted at all.

Trust boundary: unlike the DNS part, this reaches hosts named by untrusted DNS answers. The tool
says so in its output, and the owner must check the list of controllers first. The probes run in
the same run as the list, before the owner has read it, so the owner runs the tool without
`--preflight` first, checks the list against their own controllers, and only then runs it again
with the flag. That second run reads DNS again: the first list does not limit what the second run
probes, and the addresses it probes are the ones that run prints. Nothing is pinned: the second
run trusts DNS as much as the first one did. The check of the first list catches a wrong answer
that is already there; it does not protect against an answer that changes between the two runs.

Unmeasured: the behaviour against a real Windows or Samba domain controller. The tests use fake
sockets, a fixed clock and an injected fraction; no controller was contacted.
