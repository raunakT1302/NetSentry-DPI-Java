# Detailed code walkthrough

This document explains the program as a student project, from the big picture down to the important methods.

## 1. End-to-end flow

The application is an offline pipeline:

`PCAP file -> packet bytes -> parse -> identify metadata -> apply policy -> output PCAP + CSV`

It does not create packets or modify packet payloads. If a packet passes policy, the original packet header and bytes are copied into the output capture. If policy matches, that packet is left out of the output capture, and the directional and reverse five-tuple are marked blocked for the remainder of this capture.

## 2. `Main.java` — entry point and CLI

Java starts in `public static void main(String[] args)`. `args` contains words typed after `java -jar ...`.

- `parseArgs()` groups options such as `--input` and repeated `--block-domain`.
- `Policy` stores the rules in sets. A set makes duplicate rules harmless and gives efficient membership checks.
- `Engine.process()` performs the actual processing.
- `try/catch` turns file or argument errors into a concise message rather than a confusing stack trace.

Example:

`--block-domain example.com --block-port 23`

means: omit packets whose parsed domain matches `example.com` or whose source/destination port is 23.

## 3. `PcapFile.java` — binary capture files

Classic PCAP begins with a 24-byte global header. Each packet then has a 16-byte packet header followed by the captured bytes.

The global header describes byte order, version, snapshot length and link type. Multi-byte values may be stored little-endian or big-endian. `u16()` and `u32()` read values explicitly rather than depending on the machine's native byte order.

`nextPacket()`:
1. Reads one 16-byte packet header.
2. Reads `incl_len` from the header.
3. Rejects unreasonable lengths.
4. Reads exactly that many packet bytes.
5. Saves the packet header so `writePacket()` can preserve it if the packet is forwarded.

The writer copies the original global header into the output. This keeps the output in the same classic-PCAP format as the input.

## 4. `Inspector.java` — packet parsing

The parser is bounds-checked: before reading bytes at an offset, it verifies that those bytes exist. This matters because a capture can contain truncated packets.

### Ethernet

The first 14 bytes are the Ethernet header. Bytes 12–13 contain EtherType. `0x0800` means IPv4. If EtherType is `0x8100`, the parser skips one VLAN tag and reads the next EtherType.

### IPv4

The IPv4 header's first byte stores version and Internet Header Length (IHL). IHL is measured in 32-bit words, so multiply by four to get bytes. The protocol field identifies TCP (`6`) or UDP (`17`). Source and destination IPv4 addresses each occupy four bytes.

### TCP and UDP

TCP's header length comes from the data-offset field; the payload begins after that variable-length header. UDP has an eight-byte header and includes its length. Ports are unsigned 16-bit big-endian values.

The parser currently does not reassemble IP fragments or TCP streams. A fragment may not contain a complete transport header, and a TLS ClientHello may span multiple TCP segments.

## 5. HTTP Host and TLS SNI

`extractHttpHost()` checks for common HTTP request methods, then searches header lines for `Host:` without case sensitivity. It only handles plaintext HTTP headers visible in that packet.

`extractTlsSni()` checks for TLS record type 22 (handshake) and handshake type 1 (ClientHello), then advances through the session ID, cipher suites and compression methods to reach extensions. Extension type `0` is SNI. The hostname bytes are decoded as ASCII.

This is metadata inspection, not HTTPS decryption. Encrypted application content remains encrypted. Modern encrypted-client-hello configurations may hide the real hostname.

## 6. Application labels

`classify()` maps a few recognizable domain substrings to labels such as `YOUTUBE` and `GITHUB`. If no domain is available, it uses conventional ports to label HTTP, HTTPS, DNS or UDP/443.

This is a heuristic, not a guaranteed application detector. Port 443 is commonly HTTPS, but port numbers alone cannot prove what application generated a packet.

## 7. `Policy.java` — block rules

The policy checks:
1. Whether either endpoint IP appears in `blockedIps`.
2. Whether either endpoint port appears in `blockedPorts`.
3. Whether the extracted domain equals a blocked domain or is a subdomain of it.
4. Whether the application label is blocked.

Domain matching is case-insensitive. `example.com` matches `example.com` and `api.example.com`, but does not match `notexample.com`. A rule written `*.example.com` is treated as the same suffix policy.

`rules.example.properties` provides persistent configuration. The file is loaded with Java's `Properties` class.

## 8. `Engine.java` — orchestrator and report

For each packet, `Engine` increments total packet and byte counters, asks `Inspector` for metadata, then calls `Policy.matches()`.

It tracks blocked flows in both directions after the first policy match, then groups report rows by a directional flow key. A `FlowStats` row accumulates packet count, byte count, most recently observed domain/application metadata, and action. The CSV writer quotes text fields and doubles embedded quotes so commas in fields do not corrupt columns.

At the end, the result contains total, forwarded and dropped counts. The output PCAP contains only forwarded packets.

## 9. How to demonstrate it

Use a capture you are allowed to inspect. First run with no block rules and compare the input and output packet counts. Then run with a rule matching a domain or port you know appears in the capture. Compare `Packets dropped` and inspect `flows.csv`.

If no domain is detected, that may be because the capture uses encrypted metadata, QUIC, TCP segmentation, or simply does not contain a ClientHello/HTTP request packet. It is not necessarily a code failure.

## 10. Interview explanation

“NetSentry DPI is a Java 17 offline PCAP analyzer. It reads classic Ethernet PCAP files, parses Ethernet, IPv4, TCP and UDP headers, and performs best-effort extraction of HTTP Host and TLS SNI metadata. A policy engine evaluates IP, port, domain and application rules. Allowed packets are copied unchanged into a filtered PCAP, while a CSV report summarizes directional flows, bytes, packet counts and actions. The project emphasizes safe byte parsing, configurable policies and clear limitations: it does not decrypt TLS, reassemble TCP streams or enforce live network blocking.”
