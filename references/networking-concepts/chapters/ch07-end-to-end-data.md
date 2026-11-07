---
source: Peterson & Davie, Computer Networks: A Systems Approach (6th ed), chapter dir data/ ; https://github.com/SystemsApproach/book (commit 5deec5e)
license: CC BY 4.0, (c) Larry Peterson and Bruce Davie. Summarised/condensed by an AI agent; not the original text.
---

# Chapter 7: End-to-End Data (presentation formatting, compression, multimedia)

## Key ideas

- The network moves uninterpreted bytes; applications need an agreed **presentation format** so both ends read the same data. Two concerns: (1) receiver extracts the same message (framing/encoding), (2) efficiency (compression).
- **Data manipulation functions** = presentation formatting and compression. They touch every byte, so they can limit end-to-end throughput (unlike most protocols, which ignore payload).
- Two opposing forces: add redundancy for error detection/correction (lower layers) vs remove redundancy for compression (this chapter).
- Argument marshalling = serialization = encode/decode. Term comes from RPC.
- Marshalling difficulty: endianness (big vs little vs bi-endian ARM), integer width, float format (IEEE 754 vs legacy), compiler struct padding, pointers (complex types must be flattened).
- Taxonomy of marshalling systems (five axes):
  - Data types: base types, flat types (structs/arrays; must be packed), complex types (pointer structures; must be linearized).
  - Conversion strategy: **canonical intermediate form** (convert to one external format, e.g. big-endian "network byte order") vs **receiver-makes-right** (send native, receiver converts; N-by-N problem). Hybrid: receiver-makes-right if same architecture.
  - Tags: typed/length/architecture tags (self-describing) vs untagged (receiver "programmed to know"; true end to end).
  - Stubs: compiled (fast, common) vs interpreted (flexible).
- Lossless vs lossy compression. Lossy gets an order of magnitude more, exploits human perception (less sensitive to high spatial frequency, chrominance, high audio frequencies).
- HTTP adaptive streaming: pre-encode N quality levels x M short segments; client picks per segment by watching its playback buffer.
- Edge-native applications and In-band Network Telemetry (INT) are the "perspective" topics: edge reduces upload volume (summaries, not raw data); INT writes device state into packet headers as they transit (needs programmable data plane).

## Principles and rules of thumb

- Canonical form is conventional wisdom (Internet headers use big-endian), but when most peers share an architecture the double conversion is wasteful; N is small in practice.
- Untagged formats are smaller/faster but need the schema out of band and break middlebox inspection; tagged formats cost bytes and CPU but are self-describing and evolvable.
- Give every field in a long-lived wire format a stable numeric ID (Protobufs) so the schema can evolve without breaking old peers.
- Pick text (XML/JSON/HTML) for human readability and tooling; pick binary for compactness and parse speed. XML is bulky and slow to parse; binary XML forms exist (Fast Infoset, EXI).
- Use XML namespaces (URI-qualified names) to avoid name clashes when composing schemas.
- Multimedia: spend more bits on luminance than chrominance; spend bits on low-frequency content.
- Interactive video must not depend on future frames: B frames add delay (GOP `I B B B B P` at 15 fps delays first B by 4 x 67 ms, about 0.27 s, exceeding the ~100 ms perception threshold). Use `I P P P P I` or motion-JPEG for conferencing.
- Do not use TCP for interactive real-time video (abrupt rate cuts, retransmit delay); use UDP and packetize at macroblock boundaries (Application Level Framing) so one loss damages one block.
- Protect I frames (mark with lower drop probability, e.g. DiffServ) since losing one kills dependent P/B frames; dropping a B frame is cheap.
- Audio loss is less tolerable than video loss; do not drop audio frames under congestion.
- Do not respond to loss by adding redundancy at the codec level; it is analogous to growing TCP's window under loss. Reduce bitrate instead.

## Techniques and protocol mechanics

### Marshalling formats
- **XDR** (SunRPC): C types minus function pointers; canonical big-endian; untagged (except array length); compiled stubs (`rpcgen`). Integer = 32-bit two's complement, big-endian; every element padded to multiple of 4 bytes (chars 1 byte each); variable array = 4-byte count then elements; struct = fields in declaration order. Byte-swap about 3 instructions/byte, so memory-bandwidth bound.
- **ASN.1 BER**: canonical, tagged `(tag, length, value)` triples, nested for compound types; stubs compiled or interpreted. Length in 1 byte if value <= 127 bytes; otherwise top bit set and low 7 bits give number of following length bytes. 32-bit int = 1 type + 1 length + 4 value bytes. Slower than XDR (tags + unaligned data). Used by SNMP and X.509.
- **NDR** (DCE): receiver-makes-right; 4-byte architecture tag at front (`IntegrRep` 0=big/1=little, `CharRep` 0=ASCII/1=EBCDIC, `FloatRep` 0=IEEE754/1=VAX/2=Cray/3=IBM, 2 reserved bytes); data items untagged; stubs from IDL.
- **Protocol Buffers** (gRPC): tagged, canonical; `.proto` file generates stubs both sides; each field has a unique number, `required`/`optional`. **Varint**: 7 data bits per byte, MSB = "more bytes follow", least-significant group first. Example 365 encodes as `1110 1101 0000 0010` (drop MSBs -> `110 1101`, `000 0010`; reverse -> `000 0010 || 110 1101` = 365). Wire types: Varint, 32-bit, 64-bit, length-delimited (strings, embedded messages). Key = (field id, wire type).
- **Markup languages**: HTML (presentation), XML (framework for defining languages; nested tag/value tree). Schema languages (XML Schema/XSD) define datatypes and an abstract data model, separate from syntax. Namespaces: `targetNamespace`, prefix `xmlns:emp="URI"`, qualified name `emp:title`.

### Lossless compression
- **Run-length encoding**: `AAABBCDDDD` -> `3A2B1C4D`; about 8:1 on scanned text/fax; can expand data with local variation.
- **DPCM**: send reference then differences; works for images/audio with similar neighbours (about 1.5:1 measured on images). **Delta encoding**: difference from previous symbol; combine with RLE (long zero runs).
- **Dictionary/Lempel-Ziv**: replace repeated strings with dictionary index (`compress`, `gzip`); adaptive dictionary. About 2:1 on source code. **Huffman**: shorter codes for probable symbols.

### Image: GIF and JPEG
- Colour spaces: RGB vs YUV. `Y = 0.299R + 0.587G + 0.114B`, `U = (B-Y) x 0.565`, `V = (R-Y) x 0.713`. Both ends must agree on the space.
- GIF: reduce 24-bit to 256-colour palette (lossy if >256 colours), then LZ (lossless). Good for logos (~10:1), poor for photos.
- JPEG pipeline: RGB -> YUV -> subsample chroma 4:2:0 (average each 2x2 block; 6 values per 4 pixels, 50% saving) -> per 8x8 block: **DCT** (lossless, to spatial-frequency domain; coefficient (0,0) = DC = block average, other 63 = AC) -> **quantization** (lossy: `round(DCT(i,j)/Quantum(i,j))`, big quanta for high frequencies, many become 0) -> **encoding** (zigzag scan, RLE on zeros, Huffman or arithmetic coding, DC coded as delta from previous block's DC). Typical 30:1; artifacts rise with ratio.

### Video: MPEG
- Frame types: **I** (self-contained, about JPEG), **P** (delta from previous I/P), **B** (interpolated between previous and next I/P). Transmit order differs from display order (`I B B P B B I` sent as `I P B B I B B`). Unit = 16x16 macroblock; chroma 8x8.
- B-macroblock reconstruction: `Fc(x,y) = (Fp(x+xp,y+yp) + Ff(x+xf,y+yf))/2 + delta(x,y)` using two motion vectors; deltas get DCT + quantization. Each macroblock has a type field (can fall back to intra coding).
- Motion estimation is the expensive encoder-side step (not standardized); encoding offline, decoding real-time.
- Typical ratio about 90:1 (up to 150:1); I frames about 30:1, P/B 3-5x smaller than I. HDTV raw is over 1 Gbps (1080x1920x24 = about 50 Mb/frame), compressed about 10 Mbps. H.264/MPEG-4 is used by Blu-ray and streaming; H.261/H.263 are ITU predecessors.
- Stream structure (main profile): `SeqHdr` -> GOPs (`GOPHdr`) -> pictures (`PictureHdr`) -> slices (`SliceHdr`) -> macroblocks (6 blocks: 4 Y, 1 U, 1 V); `SeqEndCode` 0xb7. Quantization tables, frame rate and picture size can change at GOP boundaries, enabling rate adaptation.
- **HTTP adaptive streaming** (DASH, HLS): manifest lists URLs for N x M chunks; each chunk (a few seconds, GOP-aligned) fetched with HTTP GET; client raises quality when buffer is full, lowers it when empty; chunks also make trick play easy.

### Audio: MP3
- CD audio: 44.1 kHz x 16 bit x 2 ch = 1.41 Mbps (4.32 Mbps with CD overhead); telephone 8 kHz x 8 bit = 64 kbps.
- MPEG layers: I 384 kbps (14x), II 192 kbps (18x), III (MP3) 128 kbps (12x).
- Method: split into frequency subbands -> blocks of 64-1024 samples -> modified DCT -> quantize (psychoacoustic model decides bits per subband) -> Huffman; fixed-size frames with header (sync, bit allocation); interleaves with video in MPEG stream.

## Common pitfalls / anti-patterns

- Sending raw structs across machines (padding, endianness, pointers).
- Assuming network byte order is automatic; forgetting to convert on little-endian hosts.
- Using modulo-style assumptions for floats/characters (EBCDIC, VAX/IBM floats) when mixing legacy systems.
- Tagged formats where tags are inspected by intermediaries ("ad hoc" middlebox fixes) create hidden dependencies.
- RLE on noisy data increases size; GIF on photos looks bad; heavy JPEG quantization shows artifacts.
- Running B-frame GOPs for live conferencing; carrying live video over TCP; losing I frames without protection.
- Treating XML as free: parse cost and size matter on constrained devices.
- Forgetting that compression plus encryption order matters: compress before encrypting (ciphertext does not compress).

## Relevance to managing a small OpenWrt router network

- Mostly background: routers forward bytes and do not marshal data, but UCI/ubus use JSON, and management APIs (SNMP uses ASN.1 BER; gNMI uses Protobufs) use these encodings.
- Streaming and video calls over the WAN are bandwidth/latency sensitive: use SQM (cake/fq_codel) on the upstream link and DSCP marking (EF for voice) as in ch9; ABR streaming adapts to whatever rate you leave it.
- Choose MTU/MSS and avoid double compression/encryption overhead on VPN links; compressed media will not shrink further.
- Edge/INT ideas map to local logging: summarize on the router (counters, collectd/netdata) rather than shipping raw packet data over a thin uplink.
