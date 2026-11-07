---
source: Peterson & Davie, Computer Networks: A Systems Approach (6th ed), chapter dir congestion/ ; https://github.com/SystemsApproach/book (commit 5deec5e)
license: CC BY 4.0, (c) Larry Peterson and Bruce Davie. Summarised/condensed by an AI agent; not the original text.
---

# Chapter 6: Congestion Control and Resource Allocation (congestion/)

Sections: 6.1 Issues in resource allocation, 6.2 Queuing disciplines (FIFO, FQ), 6.3 TCP congestion control, 6.4 Advanced congestion control (AQM: DECbit, RED, ECN; source-based: Vegas, BBR, DCTCP), 6.5 QoS (IntServ/RSVP, DiffServ EF/AF, equation-based), perspective on software-defined traffic engineering.
Note: this source does NOT cover CoDel, fq_codel, CAKE, or bufferbloat by name; those appear only in the OpenWrt section below as clearly marked outside context.

## Key ideas

- Congestion: queues at a router fill, delay rises, then packets drop. Resource allocation (who gets bandwidth and buffers) and congestion control (prevent or recover from overload) are two sides of one problem.
- Flow control (receiver protection) vs congestion control (network protection). Congestion control is not routing: routing around a congested link does not help when a bottleneck router cannot be bypassed.
- Flow: sequence of packets between a source/destination pair following one route; visible to routers (a channel is end-to-end only). Router keeps soft state per flow (not required for correctness, improves handling); contrast hard state in virtual circuits.
- Taxonomy (three axes): router-centric vs host-centric; reservation-based vs feedback-based; window-based vs rate-based. In practice two combos dominate: best-effort = feedback + host-centric + window (Internet); QoS = reservation + router-centric + rate.
- Effectiveness metric: Power = Throughput / Delay. Peak of the power curve is the ideal load. Past it, delay dominates; unstable schemes go to congestion collapse (1980s Internet before Jacobson's fix).
- Fairness: equal share is the default notion; Jain's fairness index = (sum x_i)^2 / (n * sum x_i^2), range 0 to 1 (1 = perfectly fair; if only k of n flows get any, index = k/n).
- Separate policy and mechanism: queuing discipline is the mechanism (knobs: priority, weight), policy is the knob setting.
- Scalability vs state: per-flow reservations do not scale (39,000 64-kbps flows on a 2.5-Gbps link); per-class approaches do.
- TCP needs losses to find capacity; AQM and delay-based schemes try to avoid loss.
- Traffic engineering vs congestion control vs routing: boundaries blur when implemented in software (Google B4 runs links near 100% utilisation versus the typical 30-40%).

## Principles and rules of thumb

- Make multiplicative decrease aggressive and additive increase gentle; AIMD is needed for stability. Over-large windows compound (retransmits add load).
- Real-time traffic needs the network's help: retransmission cannot fix lateness. Late data is worthless; elastic apps just slow down.
- A tail-drop FIFO pushes all responsibility to the edge; non-TCP flows (UDP voice, video) can then steal capacity. FQ isolates them.
- Priority queues need a hard cap on high-priority traffic or they starve everything else; never let users self-mark unpoliced.
- Prefer WFQ over strict priority for EF so best-effort and routing traffic still get some link time.
- Set premium weight conservatively: weight 1 vs 4 reserves 20% of link; if premium offered load exceeds its share, premium delay is worse than best effort.
- RED tuning rules: MaxThreshold about 2 x MinThreshold; leave buffer above MaxThreshold for bursts; Weight small enough to filter queue changes shorter than about one RTT (100 ms typical).
- Early random drop beats tail drop: one drop per RTT is enough to make a flow back off; clustered drops send flows into slow start.
- Admission control (per-flow yes/no) is not policing (per-packet conformance to TSpec). Policing options: drop or mark non-conforming "drop me first".
- Edge routers mark and limit; core routers only apply per-hop behaviour.
- Bound EF load: sum of EF rates entering a domain should be below the slowest link.
- Modern default congestion control on Linux is CUBIC; BBR is delay-based and can be unfair to CUBIC.

## Techniques and protocol mechanics

### Queuing disciplines (6.2)
- FIFO (scheduling) + tail drop (drop policy) are separable; FIFO + tail drop is the common default. Priority queuing = multiple FIFOs served highest first; used to protect routing updates (identified by DSCP).
- Fair Queuing (FQ): one queue per flow, served round-robin; ill-behaved flow only fills its own queue. Needs to be bit-by-bit fair, simulated per packet:
  - `F_i = max(F_(i-1), A_i) + P_i` (finish time of packet i; A_i arrival measured on a virtual clock that ticks once per bit from every active flow; P_i length).
  - Transmit the packet with the lowest F. No preemption of a packet already on the wire.
  - Work conserving (link never idle if anything queued); each flow gets at least 1/n when loaded, more if others idle.
  - Weighted FQ (WFQ): weights 2, 1, 3 give 1/3, 1/6, 1/2 of the link. Can be applied to classes (DSCP) rather than flows.
  - FQ is scheduling only; still needs a drop policy and still relies on end-to-end congestion control.

### TCP congestion control (6.3)
- Introduced by Van Jacobson (late 1980s) after congestion collapse. Self-clocking: ACK arrival means a packet left the network, so send another.
- State: CongestionWindow (cwnd). `MaxWindow = MIN(CongestionWindow, AdvertisedWindow)`; `EffectiveWindow = MaxWindow - (LastByteSent - LastByteAcked)`.
- AIMD: on loss (timeout or dup-ACKs) cwnd = cwnd / 2 (not below 1 MSS). Additive increase: per ACK, `Increment = MSS x (MSS / CongestionWindow)` (about +1 MSS per RTT). Produces the sawtooth.
- Slow start: cwnd = 1 packet, +1 per ACK, i.e. doubling every RTT. Used at connection start and after a coarse timeout. "Slow" relative to dumping a full advertised window. Can overshoot: with cwnd 16 to 32 and capacity 16, up to 16 packets lost; worse with big delay x bandwidth.
- CongestionThreshold (ssthresh): set to cwnd/2 on loss; slow start up to threshold, then additive increase:
  ```
  if (cw > CongestionThreshold) incr = incr * incr / cw   (incr starts as maxseg)
  CongestionWindow = MIN(cw + incr, TCP_MAXWIN)
  ```
- Fast retransmit: receiver sends a duplicate ACK for every out-of-order segment; sender retransmits after 3 duplicate ACKs without waiting for timeout. Removes about half of coarse timeouts (about 20% throughput gain); cannot help with small windows or heavy loss. Detects up to about 3 drops per window.
- Fast recovery: after fast retransmit, halve cwnd and continue additive increase using ACKs still in flight (skip slow start). Slow start only at start and after real timeouts.
- Quick-start (research): request an initial rate in the SYN via IP option; needs all routers to cooperate.
- CUBIC (Linux default): window as a function of time since the last congestion event, `CWND(t) = C x (t-K)^3 + W_max`, `K = cuberoot(W_max x (1 - beta)/C)`, beta = 0.7 (standard TCP uses 0.5). Fast approach to W_max, near-flat plateau around it, then probing beyond. Update is time-based, so fair to short-RTT flows. Aimed at long fat networks.

### Active queue management and ECN (6.4.1)
- DECbit: router sets a congestion bit if average queue length (over last busy+idle cycle plus current busy) >= 1; receiver echoes bit in ACKs; source: if < 50% of last window had bit set, cwnd + 1; else cwnd x 0.875.
- RED (Random Early Detection, Floyd and Jacobson):
  - `AvgLen = (1 - Weight) x AvgLen + Weight x SampleLen` (low-pass filter of queue length).
  - If AvgLen <= MinThreshold: enqueue. If between: drop with probability P. If >= MaxThreshold: drop all.
  - `TempP = MaxP x (AvgLen - MinThreshold)/(MaxThreshold - MinThreshold)`; `P = TempP / (1 - count x TempP)`, count = packets enqueued since last drop (spreads drops evenly). Example: MaxP 0.02 mid-way gives P 0.01, doubling after about 50 undropped packets.
  - Drop probability roughly proportional to a flow's bandwidth share (rough fairness). Not very effective against unresponsive flows. Not widely deployed due to tuning difficulty, but is the AQM benchmark.
- ECN: two IP bits in the old TOS byte: ECT (sender is ECN-capable) and CE (router set Congestion Encountered, instead of dropping). TCP flags: ECE (receiver echoes CE to sender) and CWR (sender says it reduced window). Marking beats dropping because there is no loss to recover.

### Source-based avoidance (6.4.2)
- Delay or throughput-flattening heuristics (RTT above mean of min/max: cut 1/8; sign of (window change x RTT change); throughput comparison per RTT).
- TCP Vegas: `BaseRTT` = min RTT; `ExpectedRate = CongestionWindow / BaseRTT`; `ActualRate` measured once per RTT; `Diff = Expected - Actual`; thresholds alpha < beta (about 1 and 3 extra buffers): Diff < alpha, increase linearly; Diff > beta, decrease linearly; between, hold. Keeps a small, stable amount of "extra data" queued. Multiplicative decrease still on timeout. Analogy: speedometer (cwnd) vs seeing people walk past (actual rate).
- BBR (Google): delay-based using min RTT and max bandwidth; pacing, periodic bandwidth probing (rate up) and RTT probing (rate down, synchronised across BBR flows). Known issues: fairness (CUBIC flows reported getting 100x less in some tests, BBR-vs-BBR unfairness) and high retransmission rates (up to about 10% in some cases).
- DCTCP (datacenter): switch sets CE when queue K > (RTT x C)/7 (C = link rate in packets/s); receiver state machine SeenCE sends an immediate ACK on each CE transition, otherwise delayed ACKs as usual; sender computes the fraction of bytes marked per observation window (about 1 RTT) and cuts cwnd in proportion rather than by half. Works with shallow buffers; only for self-contained networks.

### QoS (6.5)
- Application classes: elastic (SSH, FTP, mail, web) vs real-time. Real-time: tolerant vs intolerant of loss; adaptive (delay-adaptive via playback point, rate-adaptive via codec) vs not. Playback buffer absorbs jitter; voice limit about 300 ms one way; example path: 97% of packets under 100 ms, tail beyond 200 ms.
- Two approaches: fine-grained (Integrated Services, RSVP) and coarse-grained (Differentiated Services).
- IntServ service classes: guaranteed (hard delay bound, for intolerant apps; WFQ gives a computable bound) and controlled load (emulates a lightly loaded network, loss about 10% or less tolerated; WFQ isolation plus admission control).
- IntServ components: flowspec = TSpec (traffic) + RSpec (service requested); admission control; reservation protocol; packet classifying (5-tuple: src, dst, protocol, src port, dst port; IPv6 FlowLabel could shortcut) and scheduling.
- Token bucket: rate r, depth B; need n tokens to send n bytes; allows bursts up to B, long-run rate r. Example: flow A 1 MBps constant needs B = 1 byte; flow B (0.5 MBps for 2 s, 2 MBps for 1 s) needs B >= 1 MB.
- RSVP: receiver-oriented, soft state (refresh about every 30 s, state times out about a minute). Sender sends PATH (carries TSpec, installs reverse-path state); receiver returns RESV (TSpec + RSpec) hop by hop; routers admit or reject; reservations merge up the multicast tree; styles: all speakers, any n speakers, specific speakers. Handles route change by refresh. Not widely deployed because of per-flow state scaling.
- DiffServ: 6-bit DSCP in the former TOS byte (other 2 bits are ECN). Packets marked at administrative boundary (edge) according to a profile; per-hop behaviours (PHBs) at routers.
  - EF (Expedited Forwarding): minimal delay and loss; requires edge rate limits; implement by strict priority or WFQ with a high weight.
  - AF (Assured Forwarding): built on RED with In and Out (RIO) / Weighted RED (WRED): separate drop curves, "out" packets dropped first (lower MinThreshold); no reordering of in/out packets. Typical form: 4 queues (WFQ weights) x 3 drop preferences = 12 code points.
  - Class-based WFQ via DSCP queue selection (example weights 1:4 reserves 20%).
- Equation-based (TCP-friendly) congestion control for real-time: smooth rate, adapt per RTT, obey `Rate proportional to 1 / (RTT x sqrt(loss))`; receiver reports loss; sender adjusts. Stops UDP video from starving TCP.
- Software-defined TE (B4): central controller, ECMP tunnels, app classes (user data highest priority and lowest volume; storage access; bulk sync lowest) pushing utilisation near 100%.

## Common pitfalls / anti-patterns

- Treating loss as only a transmission error; on the Internet it is mostly congestion.
- Unresponsive UDP flows with no congestion control.
- Strict priority with uncontrolled high-priority load; self-marked DSCP with no policing.
- Over-long drop-tail buffers: delay grows with no throughput gain (right of the power peak).
- Mis-tuned RED (thresholds too close, Weight too large, MaxThreshold with no headroom).
- Judging fairness by flow count only; one multi-connection app takes more share.
- Reserving per-flow state in the core.
- Premium class weight set below offered premium load.
- Mixing CUBIC and BBR flows without expecting unfairness.
- Reordering marked packets across queues (breaks TCP; RIO avoids by using one queue).
- Assuming ECN is on everywhere: it is optional and needs both endpoints and routers.
- Using slow-start-heavy parallel connections to speed transfers (each ramps and overshoots).
- Ignoring that 100% link utilisation implies queueing delay (power metric).

## Worked numbers and examples from the text

- Multiplicative decrease from 16 packets: 8, 4, 2, 1 on repeated losses; floor is 1 MSS.
- Slow start overshoot: cwnd 16 doubles to 32 on a path that holds 16, so up to 16 of 32 packets can be dropped; with a 500 KB delay x bandwidth product up to 500 KB can be lost at connection start.
- Fast retransmit example: packets 1, 2 arrive, 3 lost; receiver sends duplicate ACK 2 as 4, 5, 6 arrive; on the third duplicate sender resends 3; receiver then cumulatively ACKs through 6.
- Trace example: cwnd about 34 KB at first loss, timeout halves to about 17 KB; later 22 KB halves to 11 KB; fast recovery avoids the slow-start dip.
- RED example: MaxP 0.02, count 0, AvgLen midway: P = 0.01; after 50 undropped packets P = 0.02; after 99, P = 1.
- RED rule of thumb: MaxThreshold = 2 x MinThreshold; ignore queue changes much shorter than 100 ms.
- Vegas example: BaseRTT 100 ms, 1 KB packets, alpha 30 KBps and beta 60 KBps equals 3 and 6 extra buffers; practical setting 1 and 3 buffers.
- WFQ example: queue weights 1 (premium) and 4 (best effort) reserve 20% of the link to premium; premium at 10% load is excellent, at 30% load it is worse than best effort.
- WFQ weights 2, 1, 3 give 1/3, 1/6, 1/2.
- Admission control example: ten users each wanting 2 Mbps on a 10 Mbps link, so some must be refused.
- IntServ scale: 2.5 Gbps / 64 kbps = about 39,000 reservations to track and refresh.
- Jain index: n equal flows = 1; k of n flows served = k/n.
- Playback point: set at 100 ms, 3 of 100 packets arrive too late; the tail needs over 200 ms to catch everything.
- Token buckets: flow A (1 MBps steady) r = 1 MBps, B = 1 byte; flow B (0.5 MBps for 2 s, 2 MBps for 1 s) r = 1 MBps, B >= 1 MB.
- CUBIC beta = 0.7 versus standard TCP 0.5.
- Link utilisation: typical WANs provisioned at 30-40% average; B4 with central TE reaches near 100%.

## Quick reference

- Window-based sender rule: send at most min(cwnd, rwnd) unacknowledged bytes; ACKs clock new data.
- cwnd evolution cheat sheet: start 1 MSS; slow start doubles per RTT until ssthresh; congestion avoidance +1 MSS per RTT; triple dup-ACK: cwnd and ssthresh = cwnd/2 (fast recovery, no slow start); timeout: ssthresh = cwnd/2, cwnd = 1 MSS, slow start.
- Loss signals in order of severity: ECN mark (mildest, no loss), triple duplicate ACK, retransmission timeout (harshest).
- AQM parameter list: RED needs MinThreshold, MaxThreshold, MaxP, Weight; DECbit trigger average queue >= 1; DCTCP trigger K > (RTT x C)/7.
- Scheduling choices: FIFO (no isolation), priority (starvation risk), FQ (per-flow fair), WFQ (weighted shares, bound on delay), class-based WFQ (DiffServ).
- DSCP is 6 bits in the old TOS byte; ECN is the other 2 bits (ECT, CE). Well-known PHBs: EF, AF (4 classes x 3 drop precedences = 12 code points), default (best effort).
- Token bucket (r, B): burst up to B bytes, sustained rate r; used as TSpec in IntServ and as the policer/shaper model in DiffServ edges.
- RSVP timers: refresh roughly 30 s; soft state expires after about a minute without refresh.
- Equation-based friendliness: rate proportional to 1/(RTT x sqrt(p)).
- Evaluation metrics: power = throughput/delay; Jain's index for fairness.
- Delay targets for interactive audio: one-way under about 300 ms including playback buffer.

## Relevance to managing a small OpenWrt router network

- Bufferbloat: the book's point that long tail-drop FIFOs add delay and that FQ plus AQM fix it is the theory behind SQM. On OpenWrt install `sqm-scripts` (luci-app-sqm), pick `cake` (preferred) or `fq_codel` as qdisc with `piece_of_cake.qos`/`layer_cake.qos`; set download/upload to about 85-95% of measured line rate so the router's queue, not the modem's, is the bottleneck. (fq_codel/cake/CoDel not in this source; outside context.)
- Shaping must happen at the bottleneck: ingress shaping uses an IFB device; egress on the WAN interface.
- DSCP/DiffServ: cake (diffserv3/4/8) maps DSCP (EF 46 for voice, AF classes, CS1 for background) to tiers; mark VoIP/RTP and gaming at the edge (nftables `ip dscp set`/`ip6 dscp set`) and expect ISPs often bleach DSCP, so it matters mostly for your own LAN/WAN egress.
- ECN: `net.ipv4.tcp_ecn` (1 or 2); fq_codel/cake mark ECN-capable flows instead of dropping.
- Per-flow fairness (FQ, host isolation in cake `dual-srchost/dual-dsthost`, `nat`) stops one device or torrent from hogging the link; enable nat keyword when cake runs behind NAT.
- Use `tc -s qdisc show dev <wan>` to see drops, marks, backlog; test with a bufferbloat test (loaded latency) after enabling.
- Kernel TCP congestion control choice (cubic default, bbr available via `kmod-tcp-bbr`) only affects traffic the router itself originates; forwarded flows use endpoints' algorithm.
