---
source: Peterson & Davie, Computer Networks: A Systems Approach (6th ed), chapter dir security/ ; https://github.com/SystemsApproach/book (commit 5deec5e)
license: CC BY 4.0, (c) Larry Peterson and Bruce Davie. Summarised/condensed by an AI agent; not the original text.
---

# Chapter 8: Network Security

## Key ideas

- Security properties (exact terms):
  - **Confidentiality** (and **traffic confidentiality**: hiding volume/destination).
  - **Integrity** (detect tampering).
  - **Authentication** (talking to whom you think; implies integrity).
  - **Access control** (who may do what).
  - **Availability** (resist DoS).
  - Also: non-repudiation (digital signatures), originality and timeliness (anti-replay).
- Threat classes: eavesdropping, tampering, DNS poisoning / false site, defacement, DoS/DDoS, malware (worm = self-replicating program; virus = code inserted in other files; spyware; backdoor; botnet).
- **Trust and threat are two sides of one coin.** Security = explicit assumptions about trust + threat evaluation + risk mitigation. "We will inevitably fail"; no perfect security. State trust assumptions out loud so changing circumstances do not surprise you (open campus WiFi = threat; locked datacenter fibre may be trusted; cost/benefit decides, e.g. 10% encryption overhead).
- The original Internet trusted everything inside the network; most security tools are retrofits ("patches"), strongly grounded in crypto but add-ons.
- Perspective: **microsegmentation** (SDN virtual switches enforce per-VM/tier policy) vs coarse zone + firewall segmentation, which accumulates rules and lets lateral movement spread.
- Building blocks flow: ciphers + hashes -> key distribution (PKI/KDC/DH) -> authentication protocols -> complete systems (PGP, SSH, TLS, IPsec, 802.11i, firewalls).
- **Kerckhoffs principle** (1883): cipher algorithm is public, only the key is secret. Switching keys = switching ciphers; long public scrutiny builds confidence.
- Algorithm independence: protocols negotiate ciphers/hashes so a broken algorithm is replaceable without redesigning the protocol.
- Different layers protect against different threats: link (802.11i), network (IPsec), transport (TLS), application (PGP, SSH). Key Takeaway: which layer solves a problem changes over time (TLS 1.3 changed session resumption once HTTP persistent connections removed the need).

## Principles and rules of thumb

- Use secret-key (symmetric) crypto for bulk data (fast); use public-key crypto only for authentication and session-key establishment (orders of magnitude slower).
- Use short-lived **session keys** derived under longer-lived predistributed keys: limits ciphertext exposed, attack time, and damage on key compromise.
- Key size: attacker average work = 2^(n-1). DES 56-bit is dead (hours by late 1990s). 3DES (168-bit, 64-bit block) is legacy. Use AES (128/192/256-bit key, 128-bit block). RSA/ElGamal need >= 1024-bit keys (book's figure; larger is the modern practice); elliptic-curve variants give similar strength with smaller keys. Plan for data that must stay secret for decades.
- Never use ECB mode (equal plaintext blocks give equal ciphertext). Use chaining (CBC with random IV) or counter mode; prefer authenticated encryption (AEAD) which gives confidentiality + integrity in one primitive and can authenticate plaintext headers (associated data).
- Encryption alone does not give integrity or authentication. Always add an authenticator (MAC/signature). To get both, encrypt message plus its MAC.
- Avoid weak hashes: MD5 and early SHA are broken/weakened; use SHA-2/SHA-3. Hash must be one-way; birthday bound means collision resistance is only 2^(n/2) (128-bit digest -> 2^64 work).
- Need originality (replay) and timeliness (suppress-replay/delay): use timestamps, nonces, or challenge-response. Challenge-response with your own clock/nonce needs no clock sync.
- Authenticate the server out of band the first time if possible (SSH host key fingerprint) to avoid the first-connection risk.
- Firewall design: **default deny** (discard everything not explicitly allowed); rules overlap in complex ways so keep them simple; use stateful filtering for dynamic client ports.
- Firewalls only work if they are the only path in (no bypass via wireless, dial-up, VPN, second gateway). They cannot protect inside-inside traffic or traffic from compromised/partner hosts.
- Patch machines: firewall breaches routinely exploit old, known, fixable bugs; crypto cannot fix unpatched software.
- Put exposed services in a **DMZ**: internet and inside can reach it, but DMZ cannot reach inside; restore DMZ to a clean state periodically.
- Prefer per-user keys (802.1X/EAP) over one shared PSK so you can revoke one client without touching others.
- Application-layer knowledge lets you choose which attacks to defend (e.g. PGP ignores replay/delay of email because email tolerates duplicates).

## Techniques and protocol mechanics

### Ciphers
- Encrypt: plaintext -> ciphertext via keyed function; attacks: ciphertext-only, known-plaintext, chosen-plaintext. Best ciphers resist even when attacker has plaintext and ciphertext, leaving only brute force.
- **Secret-key**: both parties share the same key (two-way channel). DES -> 3DES (encrypt-key1, decrypt-key2, encrypt-key3; backward compatible with DES when keys equal) -> AES (Rijndael).
- **Public-key**: key pair; public encrypts, private decrypts (one-way, many-to-one channel). Private key used with the same algorithm "encrypts" so only the public key decrypts = authentication/signature. RSA (factoring), ElGamal (discrete log), elliptic curve cryptography.
- Modes: ECB (bad), CBC (XOR with previous ciphertext block, IV for first), counter mode.

### Authenticators
- **Cryptographic hash/message digest**: fixed-size output regardless of input; one-way; random-looking.
- **Digital signature** = digest encrypted with sender's private key; gives non-repudiation (third party can verify with public key). DSS (NIST) can use RSA, ElGamal or ECDSA. Secret-key encryption of a digest is not non-repudiable (both parties know the key).
- **HMAC**: `HMAC = H((K xor opad) || H((K xor ipad) || text))`; keyed hash with shared secret; secure if H is collision resistant.
- **Authenticated encryption (with associated data)**: one algorithm for both.

### Key distribution (PKI)
- **Public Key Infrastructure**: binds identities to public keys, bootstrapped out of band. A **certificate** is a signed statement of the binding. **X.509** certificate contains: subject identity, subject public key, issuer identity, signature, signature algorithm ID, optional expiration. Identities need a defined namespace (email address, DNS name).
- **Certification Authority (CA) model**: binary trust, **chains of trust**, tree hierarchy rooted at a CA whose key you hold; browsers ship a set of root CA certificates; a single sloppy CA breaks the chain; X.509 can restrict what a subject may certify.
- **Web of trust (PGP)**: no CAs; each user assigns degree of trust; certificates carry a confidence level; several moderately trusted signatures can add up; key-signing parties.
- **Revocation**: **Certificate Revocation List (CRL)**, a signed list published by the CA; certificates carry an expiry so CRLs can drop old entries (limits CRL growth).
- **Secret-key predistribution**: N(N-1)/2 pairwise keys is unmanageable; use a **Key Distribution Center (KDC)** sharing one key with each entity (N-1 keys). KDC authenticates parties and mints a session key; traffic does not flow through it. Kerberos is the archetype.
- **Diffie-Hellman**: public p (prime) and g (primitive root mod p). Alice picks secret a, sends `g^a mod p`; Bob picks b, sends `g^b mod p`; shared key = `g^(ab) mod p`. Security rests on the discrete logarithm problem. Worked example p=5, g=2, a=3, b=4 gives key 1. **Unauthenticated, so vulnerable to man-in-the-middle** (Mallory runs DH with each side). Fix: authenticate the exchange (signatures, or "fixed DH" with certificates of DH parameters). Used in IKE.

### Authentication protocols
- Threats beyond tampering: **replay attack**, **suppress-replay** (delay). Need **originality** and **timeliness**.
- Techniques: **timestamp** (needs clock sync; covered by authenticator), **nonce** (random once-only; must be remembered; combine with timestamp window), **challenge-response** (sign/encrypt the other party's timestamp or nonce).
- Authentication protocols usually establish a session key too; Diffie-Hellman is the exception that gives a key but no authentication.
- **Public-key protocol (clock-synced)**: Alice sends {timestamp, identity} signed; Bob replies {timestamp, identity, session key encrypted to Alice} signed.
- **Public-key protocol without sync**: three messages echoing each side's own timestamp (used as nonces) so each side checks freshness against its own clock; final message carries session key encrypted with Bob's public key.
- **Needham-Schroeder** (secret key, KDC): Alice -> KDC (identities + nonce); KDC -> Alice (session key + nonce + ticket encrypted under Bob's master key); Alice -> Bob (ticket, nonce); Bob challenge/response. Known flaw: the freshness of the third message is not actually assured.
- **Kerberos**: derived from Needham-Schroeder; master key derived from the user's password; password used only briefly client-side to decrypt the KDC reply, then erased. KDC split into **Authentication Server (AS)** (gives a ticket-granting credential) and **Ticket Granting Server (TGS)** (gives per-service tickets without returning to AS). Uses timestamps and lifetimes (assumes loose clock sync), fixing N-S weakness; pluggable ciphers/hashes.

### PGP (email)
- Web-of-trust keys, email address as identity. Sender: sign message (hash + private key) -> generate one-off session key -> encrypt signed message with it (AES/3DES) -> encrypt session key with recipient's public key -> base64 for ASCII transport. Recipient reverses. Provides authentication, confidentiality, integrity, non-repudiation. No replay/timeliness protection (acceptable for email).

### SSH (v2)
- Three protocols: **SSH-TRANS** (encrypted channel over TCP: server authenticated via RSA host key, algorithm negotiation, session key, integrity checks), **SSH-AUTH** (user authentication), **SSH-CONN** (multiplexing/port forwarding).
- Server host key learned at first connect (trust on first use); stored in `~/.ssh/known_hosts`; mismatch triggers a warning. Prudent: verify key out of band.
- User auth methods: password (safe inside the encrypted channel), **public key** (client public key in server `~/.ssh/authorized_keys`; private key e.g. `~/.ssh/id_rsa`), **host-based** (trusted hosts vouch for users).
- **Port forwarding** tunnels other TCP apps through SSH (confidentiality + authentication); can approximate a VPN.

### TLS / SSL / HTTPS
- Sits between application and TCP; gives confidentiality, integrity, authentication; HTTPS = HTTP over TLS, TCP port 443. SSL (Netscape) -> TLS (IETF); not interoperable.
- **Handshake protocol**: client lists supported algorithm combinations (preference order) + client nonce; server picks one + server nonce; server sends certificate or DH parameters (and requests client auth if wanted); client replies per negotiated key exchange; both derive **master secret** (48 bytes) from the **pre-master secret** + both nonces; finished messages contain a hash of all handshake messages (detects downgrade tampering). Modes: server-only auth (common), mutual, anonymous DH.
- Six keys derived from master secret: cipher key + IV per direction, MAC key per direction.
- **Record protocol**: fragment -> optional compress -> HMAC (includes implicit sequence number to stop replay/reorder) -> encrypt -> TCP. Relies on TCP in-order delivery for the implicit sequence number.
- **Session resumption**: TLS <= 1.2 reused a session ID; TLS 1.3 uses an opaque server-encrypted **session ticket** and by default does a fresh key exchange on resumption. Original motive was HTTP/1.0 opening a TCP+TLS handshake per object (TCP 3-way + at least 2 more RTTs for TLS).

### IPsec
- Framework (optional in IPv4, mandatory in IPv6) with three degrees of freedom: modular algorithms, menu of security properties, protect narrow (one TCP flow) or wide (all traffic between routers) streams.
- Protocols: **AH** (integrity/auth/anti-replay/access control; rarely used) and **ESP** (adds confidentiality). Key management under **ISAKMP**, with **IKE** (IKEv2 in practice).
- **Security Association (SA)**: simplex, one-way; two per bidirectional flow; identified by **SPI** (chosen by receiver) + destination IP.
- **ESP format**: `SPI`, `SeqNum` (replay protection), `PayloadData`, padding (`PadLength`), `NextHdr`, `AuthenticationData`.
- **Transport mode** (payload is higher-layer segment; host-to-host) vs **tunnel mode** (payload is an entire inner IP packet; inner and outer addresses differ; gateway-to-gateway VPN). Tunnels hide traffic volume per flow (traffic confidentiality) and a mesh of tunnels forms a VPN; hosts need not know.

### Wireless (802.11i / WPA)
- WEP is broken. 802.11i/WPA3 (certification name) uses **CCMP** (AES in counter mode + CBC-MAC, 48-bit packet number as nonce/anti-replay, MAC about 8 bytes).
- Auth modes: **Personal/PSK** (passphrase derives the **Pairwise Master Key**; convenient, weaker, one shared secret) vs **802.1X with EAP** (Authentication Server, mutual authentication required, per-client keys; EAP is a framework, **EAP methods** such as EAP-TLS).
- **4-way handshake** turns PMK into **Pairwise Transient Key** (includes the Temporal session key).

### Firewalls and detection
- Packet filter table of 4-tuples (src IP, src port, dst IP, dst port) with wildcards, e.g. `(*, *, 128.19.20.21, 25)` allows only SMTP to a mail server. Needs L4 information ("level 4 switch").
- **Stateless** (per packet) vs **stateful** (tracks connections; permits replies to client-chosen dynamic ports). Modern ones also do application-protocol filtering.
- Zones of trust: internal, **DMZ**, outside. NAT and firewall often co-located but logically separate.
- Malware detection by signatures (evadable, costs performance); **IDS** (detect anomalies, alert) / **IPS** (act on them).

## Common pitfalls / anti-patterns

- Keeping the cipher secret instead of the key; inventing your own cipher.
- ECB mode; reused IV/nonce; DES/3DES/MD5/RSA-1024 in new designs; WEP.
- Encrypting without authenticating (bit-flipping goes undetected).
- Unauthenticated Diffie-Hellman (MITM).
- Blindly answering "yes" to SSH/TLS first-contact prompts; ignoring changed host-key warnings.
- Trusting every CA in the store equally; no revocation plan; long-lived certs without expiry.
- Replays: authenticator alone does not guarantee originality or timeliness; timestamps without clock security.
- Allow-by-default firewall rules; overlapping, accumulated rules nobody understands; forgetting wireless or VPN bypass paths; admitting partners whose security is weaker than yours.
- Assuming a firewall stops internal threats or malware carried by allowed traffic (spyware looks like legitimate traffic).
- One flat zone for many unrelated machines (lateral movement).
- Treating one layer as sufficient: TLS does not protect DNS answers or the network layer; IPsec does not authenticate the application user.
- Relying on a shared Wi-Fi passphrase that cannot be revoked per device.

## Relevance to managing a small OpenWrt router network

- Firewall: OpenWrt fw4 (nftables) uses zones (lan/wan/guest/IoT); keep wan input/forward default reject, stateful conntrack on, explicit port-forwards only; put exposed services in a DMZ-like zone that cannot initiate to lan; use separate zones/VLANs for IoT and guests (poor-man's microsegmentation).
- VPN: WireGuard (modern, small, public-key peers, session keys) or IPsec/IKEv2 (strongswan) in tunnel mode for site-to-site/road-warrior; same ideas as SAs, key rotation, and authenticating both ends.
- SSH/LuCI: use Dropbear/OpenSSH with key-only login (`authorized_keys`), disable password and root-from-WAN, verify host key fingerprints on first connect, serve LuCI over HTTPS with a real or pinned certificate.
- Wi-Fi: WPA3-SAE or WPA2/3 with a strong passphrase (never WEP/TKIP); consider 802.1X/RADIUS (EAP-TLS) for per-device keys if you need revocation; keep guest SSID isolated.
- Keep packages and firmware patched (the chapter's main lesson: crypto and firewalls do not fix known unpatched bugs); watch for DNS/DoT/DNSSEC integrity as the DNS-attack example.

## Quick reference: which mechanism for which job

| Need | Mechanism (chapter terms) | Layer |
|---|---|---|
| Encrypt bulk data | Secret-key cipher (AES), CTR/CBC/AEAD | any |
| Prove sender and detect tampering, shared secret | HMAC / MAC | any |
| Prove sender to third parties | Digital signature (private key signs digest) | any |
| Agree a session key with no prior secret | Diffie-Hellman (must be authenticated) | IKE, TLS |
| Bind key to identity at scale | X.509 certificate, CA chain, CRL | PKI |
| Bind key to identity, no central authority | Web of trust (PGP) | email |
| Many users, one trusted key holder | KDC / Kerberos (AS + TGS, tickets) | enterprise |
| Secure web traffic | TLS (handshake + record), HTTPS port 443 | transport |
| Secure remote login/file copy/tunnel | SSH (TRANS/AUTH/CONN), port forwarding | application |
| Secure email | PGP/OpenPGP | application |
| Site-to-site or host-to-host VPN | IPsec ESP (tunnel mode) with IKEv2 | network |
| Secure Wi-Fi link | 802.11i/WPA3, CCMP, 802.1X + EAP | link |
| Block unwanted inbound traffic | Stateful default-deny firewall, DMZ | network/transport |
| Detect or stop anomalies | IDS / IPS | network |

## Quick reference: authentication checklist for any protocol you design or audit

1. Who must be authenticated (server only, both, user vs host)?
2. How does each side learn the other's key (out of band, certificate, KDC, trust on first use)?
3. How is originality guaranteed (nonce, sequence number, challenge-response)?
4. How is timeliness guaranteed (timestamp with clock sync, or own-clock challenge)?
5. Is a fresh session key derived, and from what (DH, public-key transport, KDC)?
6. Is the negotiation itself protected against downgrade (TLS finished message hashes all handshake messages)?
7. Is there a revocation or expiry path for keys and certificates?
8. State the trust assumptions (what you trust the OS, CA, or physical link to do) explicitly.

## Quick reference: numbers to remember

- DES 56-bit key; 3DES 168-bit key, 64-bit block; AES 128/192/256-bit key, 128-bit block.
- RSA/ElGamal keys at least 1024 bits per the text (use more today).
- Average brute-force work 2^(n-1); collision (birthday) work 2^(n/2) for an n-bit digest.
- TLS master secret 48 bytes (384 bits); six derived keys per session; HTTPS TCP port 443.
- CCMP packet number 48 bits; MAC about 8 bytes.
- Kerberos/Needham-Schroeder keys: N-1 master keys with a KDC vs N(N-1)/2 pairwise.
