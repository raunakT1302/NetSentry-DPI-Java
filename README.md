# NetSentry DPI

**A Java-based Deep Packet Inspection prototype for offline PCAP analysis and network traffic filtering.**

NetSentry DPI reads packet capture files, inspects supported network protocols, classifies application traffic using available packet metadata, applies configurable filtering rules, and generates a filtered PCAP alongside a CSV flow report.

## Features

- Reads classic PCAP files
- Inspects Ethernet, IPv4, TCP, and UDP packet metadata
- Supports basic HTTP Host and TLS ClientHello SNI extraction when the required information is present in an individual packet
- Classifies selected application traffic using domain and port heuristics
- Supports filtering rules for domains, IP addresses, ports, and applications
- Exports permitted packets to a new PCAP file
- Generates a CSV flow report
- Uses Java 17 and Maven

## How It Works

1. Load an existing PCAP file.
2. Parse supported packet headers and inspect available application-level indicators.
3. Classify traffic and evaluate configured filtering rules.
4. Write permitted packets to a new PCAP file.
5. Export flow information to CSV.

## Requirements

- Java 17 or later
- Maven
- Wireshark (optional, for inspecting PCAP files)

## Build

```bash
mvn clean package
```

## Example Usage

```bash
java -jar target/netsentry-dpi-1.0.0.jar --help
```

Example filtering command:

```bash
java -jar target/netsentry-dpi-1.0.0.jar --input samples/test_dpi.pcap --output blocked-test.pcap --report blocked-flows.csv --block-domain youtube.com
```

Open the generated PCAP in Wireshark to inspect the output. Review the terminal summary and CSV report to evaluate the filtering results.

## Limitations

- This is an offline PCAP analysis prototype, not a live firewall.
- It does not decrypt TLS traffic.
- Domain detection is best-effort and depends on the required information being present in the inspected packet.
- It does not perform TCP stream reassembly.
- It supports classic PCAP with the implemented link-layer and protocol constraints; it is not a general-purpose parser for every capture format or protocol.

## Technology Stack

- Java 17
- Maven
- Wireshark for packet inspection

## Project Structure

```text
NetSentry-DPI-Java/
├── src/
├── samples/
├── docs/
├── pom.xml
├── rules.example.properties
├── README.md
├── LICENSE
└── .gitignore
```

## Disclaimer

Use this project only with packet captures you own or are authorized to analyze. It is intended for educational and defensive network-analysis purposes.