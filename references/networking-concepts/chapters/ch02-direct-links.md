---
source: Peterson & Davie, Computer Networks: A Systems Approach (6th ed), chapter dir direct/ ; https://github.com/SystemsApproach/book (commit 5deec5e)
license: CC BY 4.0, (c) Larry Peterson and Bruce Davie. Summarised/condensed by an AI agent; not the original text.
---

# Chapter 2: Direct Links (encoding, framing, errors, reliability, Ethernet, Wi-Fi, access)

## Key ideas

### The five link problems (chapter spine)
1. Encoding: bits onto signals.
2. Framing: finding where a frame starts and ends in the bit stream.
3. Error detection (and correction).
4. Reliable delivery (ARQ) where the link provides it.
5. Media access control (MAC) when the link is shared.
- Link = physical medium carrying electromagnetic waves (copper twisted pair, coax, fibre, free space). The network architecture offers a common link abstraction so a host or router does not care which kind it is.
- Bits flow between network adaptors; signals travel between signalling components; frames are exchanged between hosts. The adaptor (NIC) plus driver implements link-layer functions.
- Wave facts: wavelength = speed / frequency (300 Hz in copper gives about 667 km). Modulation varies frequency, amplitude or phase; chapter assumes two signals, high and low.
- Link classes: last-mile/access (DSL up to 100 Mbps, G.Fast up to 1 Gbps, PON up to 10 Gbps, cellular), backbone (fibre, SONET), LAN (Ethernet, Wi-Fi), PAN (Bluetooth).

### Encoding schemes (name and trade-off)
- NRZ: 1 = high, 0 = low. Problems: baseline wander (receiver average drifts on long runs) and clock recovery (needs transitions).
- NRZI: transition encodes 1, no transition encodes 0. Fixes runs of 1s only.
- Manchester: XOR of NRZ data and clock; 0 = low-to-high, 1 = high-to-low. Always a transition, but doubles the baud rate: 50% efficient. Differential Manchester is a variant. Used by original 10 Mbps Ethernet.
- 4B/5B: every 4 data bits mapped to a 5-bit code with at most one leading 0 and at most two trailing 0s (so at most three consecutive 0s), then sent NRZI. 80% efficient. 16 of 32 codes unused for data: 11111 idle, 00000 dead, 00100 halt, 6 control symbols, 7 invalid. 8B/10B is a similar scheme. Used on faster Ethernets.
- Baud rate = signal changes per second; bit rate can exceed baud with multi-level modulation: 4 levels = 2 bits/symbol, 8 levels = 3 bits; QAM varies phase and amplitude (16-QAM = 4 bits/symbol, 64-QAM = 6 bits/symbol).

### Framing approaches
- Byte-oriented (PPP, BISYNC, DDCMP): sentinel characters (SYN, STX, ETX) with DLE escape ("character stuffing"), or a length count in the header (DDCMP).
- Bit-oriented (HDLC, SDLC): flag 01111110 marks start/end and is sent while idle for clock sync; bit stuffing.
- Clock-based (SONET): fixed-size frames at fixed times, no stuffing.
- Stuffing means frame size depends on payload contents; clock-based framing does not.

### Error handling vocabulary
- Error-detecting codes (redundant bits derived from the message). "Checksum" strictly means an addition-based code; CRC is not a checksum even though PPP labels its field that way.
- Error-correcting codes (ECC) and forward error correction (FEC): extra bits sent all the time. Detection costs extra only when errors occur.
- Automatic repeat request (ARQ): ACK plus timeout plus retransmission.
- Sliding window can play three roles: reliable delivery, ordered delivery, flow control. Separation of concerns: ask whether each is needed at this layer.

### Ethernet (CSMA/CD) and Wi-Fi (CSMA/CA)
- Multi-access problem: fair, efficient use of a shared medium. Origins: Aloha packet radio.
- Collision domain: set of hosts whose transmissions reach each other; hubs/repeaters extend it, switches do not.
- Modern Ethernet is point-to-point to a switch; CSMA/CD is now mostly historical but its ideas shaped Wi-Fi.
- Wireless is inherently shared, cannot transmit and receive on the same frequency (own transmit power swamps receiver), and has hidden/exposed nodes.

### Access networks
- PON: point-to-multipoint passive optical tree, up to 1024 homes per tree; OLT (ISP side) and ONU (home); BNG is the gateway/metering point between access and Internet; Agg switch aggregates OLTs.
- Cellular (LTE/5G): licensed spectrum, base stations (BBU/eNB/gNB), UE, EPC (MME, HSS, S/PGW), RAN. Reservation-based (OFDMA) because it assumes high utilisation; Wi-Fi is contention-based because it assumes light load.

## Principles and rules of thumb

- Keep the pipe full: window size must cover delay x bandwidth (RTT x bandwidth) or throughput collapses to window/RTT.
- Stop-and-wait example: 1.5 Mbps, 45 ms RTT, 1 KB frames = 182 kbps, about 1/8 of the link.
- Pick the receiver window by what you want buffered: RWS = 1 (no out-of-order buffering) or RWS = SWS; RWS > SWS is pointless.
- Sequence number space must exceed outstanding frames: with RWS = 1 need MaxSeqNum >= SWS + 1; with RWS = SWS need SWS < (MaxSeqNum + 1)/2. This assumes no reordering in transit (true on a single link, false across a network).
- Rule: detect errors cheaply at every layer, correct only when errors are common (wireless) or retransmission is costly (satellite).
- Internet checksum is weak but adequate because it is the last line of defence behind strong link-level CRCs.
- Ethernet's success factors: no routing/config tables to maintain, cheap, backwards compatible, incrementally deployable (switches replaced hubs one host at a time).
- Wireless: lower bit rate = more noise tolerance (more redundancy, simpler modulation). Rate selection is vendor-specific: estimate SNR or loss rate, occasionally probe a higher rate.
- Wi-Fi APs should sit on different channels from neighbours.
- Wireless is a broadcast medium: assume eavesdropping and unauthorised injection; require link-layer security (WPA2).
- Power matters on wireless: transmit power drives range, interference and regulation; reduce power to shrink coverage.
- Mesh (peer) vs base-station topology: mesh gives redundancy and range extension at the cost of smarter, costlier nodes.

## Techniques / protocol mechanics

### Internet checksum (used by IP, ICMP, UDP, TCP; not a link-level code)
1. Treat data as 16-bit words (pad with zero to a 16-bit boundary).
2. Add with ones' complement arithmetic: any carry out of bit 15 is added back in.
3. Transmit the ones' complement (bitwise inversion) of the sum.
4. Receiver sums everything including the checksum; the result should be all 1s (complement 0).
- Only 16 redundant bits regardless of message length. Misses pairs of compensating errors (one word +1, another -1).

### CRC (cyclic redundancy check)
- Message bits are coefficients of a polynomial M(x); sender and receiver agree on a divisor C(x) of degree k (CRC-32 for Ethernet, k = 32). Arithmetic is modulo 2, so add/subtract = XOR.
- Sender: (1) append k zeros (multiply by x^k); (2) divide by C(x) with XOR long division; (3) subtract the remainder (XOR it into the k zeros). Transmit M followed by the k-bit remainder.
- Receiver divides the whole frame by C(x); nonzero remainder = error.
- Example: message 10011010, C = 1101 (x^3 + x^2 + 1), send 10011010 000 -> remainder 101 -> transmit 10011010101.
- CRC-32 polynomial: x^32 + x^26 + x^23 + x^22 + x^16 + x^12 + x^11 + x^10 + x^8 + x^7 + x^5 + x^4 + x^2 + x + 1.
- Guarantees given a suitable C(x): all single-bit errors (x^k and x^0 terms nonzero); all double-bit errors given conditions on the x^0 term and (x^j + 1) divisibility; any odd number of bit errors if (x + 1) divides C(x); any burst shorter than k bits (most longer bursts too).
- Hardware: k-bit shift register with XOR gates at positions n where C(x) has a term x^n.
- Ethernet: 32-bit CRC protects up to 12,000 bits (1500 bytes) of data.

### Framing mechanics
- PPP frame: Flag 01111110, Address, Control (both default values), Protocol (demux key, e.g. IP, LCP), Payload (default 1500 bytes, negotiable), Checksum (really a CRC; 2 bytes default or 4). LCP negotiates field sizes and brings the link up.
- Byte stuffing: escape any sentinel appearing in data with DLE; DLE itself is doubled.
- Length-count framing: corrupted count produces a framing error; the receiver reads the wrong length, fails the CRC, then resyncs at the next SYN.
- HDLC bit stuffing: sender inserts a 0 after five consecutive 1s in the body. Receiver sees five 1s, then looks at the next bit: 0 = stuffed bit, remove it; 1 followed by 0 (01111110) = end-of-frame; 1 followed by 1 (01111111) = error, discard frame and wait for the next flag (may lose two frames).
- SONET STS-1: 51.84 Mbps, 9 rows x 90 bytes = 810 bytes, first 3 bytes of each row are overhead, frame every 125 microseconds. Receiver finds a 2-byte sync pattern recurring every 810 bytes. Payload is scrambled (XOR with a 127-bit pattern) to guarantee transitions. STS-N = byte-interleaved N x STS-1 (rates up to STS-768 at 39,813,120 Mbps; STS-3 = 155.52 Mbps = 2430 bytes). STS-Nc ("c" = concatenated) is a single N x 51.84 Mbps pipe, vs STS-N which is N separate channels sharing a fibre. Payload may "float" across frame boundaries; a pointer in the overhead locates it. OC-N names the optical signal (OC-3 = STS-3).

### ARQ algorithms
Stop-and-wait:
1. Send a frame, start a timer, wait for ACK.
2. On timeout, retransmit.
3. Use a 1-bit sequence number (alternate 0/1) so the receiver can tell a retransmitted copy from a new frame; the receiver still re-ACKs duplicates in case the ACK was lost.
- Four timelines to know: ACK arrives in time; frame lost; ACK lost; timeout too early (duplicate).

Sliding window:
- Sender state: SWS (send window size), LAR (last ack received), LFS (last frame sent). Invariant: LFS - LAR <= SWS. Buffer up to SWS frames and keep a timer per frame.
- Receiver state: RWS, LAF (largest acceptable frame), LFR (last frame received). Invariant: LAF - LFR <= RWS.
- Receiver on arrival with SeqNum: if SeqNum <= LFR or SeqNum > LAF discard; else accept/buffer. Send a cumulative ACK for the highest in-order frame (SeqNumToAck), advance LFR, set LAF = LFR + RWS.
- Example: LFR = 5, RWS = 4 so LAF = 9. Frames 7 and 8 buffered, no new ACK; when 6 arrives ACK 8, LFR = 8, LAF = 12.
- Loss-signalling variants: NAK (usually unnecessary), duplicate ACKs (hint of a loss), selective ACKs (SACK; more info, more complexity).
- Wraparound check: seq numbers are modular; in-window test is (seqno - min) < (max - min + 1) using unsigned subtraction.
- Header: SeqNum, AckNum, Flags. Real implementation uses network byte order and strips compiler padding; a counting semaphore (sendWindowNotFull, initial SWS) blocks the sender when the window is full.

Concurrent logical channels (ARPANET):
- Run stop-and-wait independently on several multiplexed logical channels; 3 bits state per channel (busy, next send seq, next expected seq). Keeps the link full without ordering or flow control. 8 channels on ground links (3-bit channel + 1-bit seq = 4 bits header), 16 on satellite.

### Ethernet (802.3) in detail
- Frame: 64-bit preamble (alternating 0/1 for sync), 48-bit destination, 48-bit source, 16-bit type (demux key), data 46-1500 bytes, 32-bit CRC. Host sees 14-byte header (6+6+2). Preamble and CRC added/removed by the adaptor.
- Minimum frame 512 bits = 64 bytes (14 + 46 + 4); pad if needed. Jumbo frames up to 9000 bytes exist on modern links.
- Address: 48 bits, burned into the NIC; written as six hex bytes (e.g. 8:0:2b:e4:b1:2). First 24 bits = manufacturer prefix (OUI, e.g. 080020). All 1s = broadcast; first bit 1 (not broadcast) = multicast.
- Adaptor accepts: own address, broadcast, subscribed multicast, everything in promiscuous mode.
- Transmit algorithm (1-persistent CSMA/CD):
  1. If line idle: transmit immediately. If busy: wait until idle, then transmit immediately; wait 9.6 microseconds inter-frame gap.
  2. Listen while transmitting. On collision: send a 32-bit jam sequence, stop (minimum 96 bits sent = 64 preamble + 32 jam: a "runt").
  3. Exponential backoff: after n-th collision pick k uniformly in 0..2^n - 1 and wait k x 51.2 microseconds. n capped at 10; give up after 16 attempts and report an error.
- Why 512 bits and 2500 m: worst case collision detection takes 2d (round trip). Max 2500 m with up to 4 repeaters gives 51.2 microsecond RTT = 512 bits at 10 Mbps. Sender must still be transmitting when the collision signal returns.
- p-persistent concept: transmit with probability p when idle, defer with 1-p to next slot (Aloha slotted).
- Physical: original coax segments up to 500 m, repeater/hub forwards signal bit-for-bit on all ports (single collision domain), terminators stop reflections. Speeds: 10 Mbps standard 1978, then 100 Mbps, 1/10/40/100 Gbps (802.3).

### 802.11 (Wi-Fi) mechanics
- PHY generations: original 2 Mbps (frequency hopping over 79 x 1 MHz, or direct sequence with 11-bit chipping), 802.11b 11 Mbps (2.4 GHz), 802.11a 54 Mbps (5 GHz, OFDM), 802.11g 54 Mbps (2.4 GHz, backward compatible with b), 802.11n/ac 150-450 Mbps via MIMO and wider channels, 802.11ax adds cellular-style coding/modulation. 802.11a rates: 6, 9, 12, 18, 24, 36, 48, 54 Mbps.
- Spread spectrum: frequency hopping (pseudorandom sequence shared by seed) and direct sequence (XOR each bit with n pseudorandom chipping bits; bandwidth widens n times).
- CSMA/CA steps: carrier sense; transmit; receiver returns an explicit ACK after CRC passes; no ACK = assume collision, back off exponentially.
- Optional RTS/CTS: sender sends short RTS (includes duration); receiver answers CTS; nodes hearing either defer for that duration. Counters hidden nodes. RTS collisions detected by missing CTS.
- Hidden node: A and C both reach B but not each other, collide at B unaware. Exposed node: C hears B->A but could safely send to D; defer would waste capacity.
- Infrastructure mode: access points (APs) linked by a distribution system (link-layer, e.g. Ethernet). Node associates with one AP.
- Scanning: active = Probe -> Probe Response -> Association Request -> Association Response; passive = AP Beacon frames advertise capabilities and rates, node then sends Association Request. New AP notifies old AP via the distribution system.
- Frame: Control (6-bit Type, ToDS, FromDS), four 48-bit addresses, up to 2312 bytes data, 32-bit CRC. ToDS=FromDS=0: Addr1 target, Addr2 source. Both 1: Addr1 final destination, Addr2 immediate sender (last AP), Addr3 first AP, Addr4 original source.
- Bluetooth (802.15.1): about 10 m, 1-3 Mbps, 2.45 GHz, piconet = 1 master + up to 7 active slaves (up to 255 parked), frequency hopping 79 channels x 625 microsecond slots, master transmits in odd slots, slave replies in even. ZigBee 802.15.4 for very low power sensors.

### PON mechanics
- Splitters are passive; every downstream frame reaches every ONU, which filters by identifier; encryption stops neighbours snooping.
- Separate wavelengths for upstream and downstream. Upstream is TDM: OLT sends grants to ONUs with time slots (different slot sizes = different service levels). G-PON about 2.25 Gbps (book figure), XGS-PON 10 Gbps.

### LTE/5G scheduling
- OFDMA: 12 orthogonal subcarriers (15 kHz spacing in the example) per Resource Element (RE); a Physical Resource Block (PRB) = 7 x 12 = 84 REs; 1 ms Transmission Time Interval (TTI). UEs report Channel Quality Indicator (CQI = observed SNR) each TTI; the scheduler adapts. Scheduler is vendor-proprietary.
- 5G: sub-1 GHz (up to 50 MHz, 15/30 kHz spacing), 1-6 GHz (up to 100 MHz, 15/30/60 kHz), mmWave above 24 GHz (up to 400 MHz, 60/120 kHz). Handoff decided by MME. CBRS 3.5 GHz band allows private cellular.

## Common pitfalls / anti-patterns

- Calling a CRC a checksum (and vice versa); assuming the Internet checksum catches everything.
- Window = 1 on long fat links (stop-and-wait) so the link runs at a fraction of capacity.
- Sequence space too small for the window (RWS = SWS needs seq space of at least 2 x window) or reordering assumed absent.
- Treating bit-stuffing/length-count framing errors as isolated: one corrupt count or flag can eat two consecutive frames.
- Forgetting minimum frame size: frames under 64 bytes are runts; Ethernet pads. Cable length beyond spec breaks collision detection (late collisions).
- Assuming Wi-Fi can detect collisions like Ethernet: it cannot, hence ACKs and RTS/CTS. Hidden nodes cause collisions that carrier sense cannot see.
- Mixing 802.11b-only clients with g/n networks slows everyone (backwards-compat modes). (Inference from the compatibility discussion, not an explicit book statement.)
- Combining reliability, ordering and flow control at the wrong layer without asking whether each is needed there.
- Assuming wireless range equals bandwidth; high rates need strong signal; rate adaptation lowers the rate with noise.
- Overlapping channels between neighbouring APs.

## Relevance to managing a small OpenWrt router network

- Link counters: `ip -s link` / `ethtool -S` RX errors, CRC errors and drops indicate bad cables/ports (CRC-32 detects them; frames silently discarded). Duplex/speed mismatch shows as late collisions (legacy) or autoneg to 100 Mbps.
- Ethernet: 14-byte header, MTU 1500 default (jumbo 9000 only if every device in the L2 domain supports it); MAC address is 48-bit, first bit set = multicast; ff:ff:ff:ff:ff:ff broadcast. Switches (the DSA ports on OpenWrt) replace collision domains; each port is its own domain.
- Wi-Fi on OpenWrt: choose non-overlapping channels per AP (1/6/11 on 2.4 GHz), expect lower rates at distance, scanning/association are what `iw dev wlan0 station dump` and hostapd logs show; roaming between APs of the same SSID relies on the distribution system (wired Ethernet). RTS threshold and rate sets are hostapd/uci options; WPA2/WPA3 is required because the medium is shared.
- PPP appears as PPPoE WAN on DSL/fibre ONT setups; MTU drops to 1492 (PPPoE overhead). PON ONT is the ONU; the BNG is the ISP edge.
- Delay x bandwidth thinking sizes TCP buffers and SQM shaper settings on the WAN link.
