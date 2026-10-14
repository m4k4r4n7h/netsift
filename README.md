# NetSift

NetSift is a command-line packet capture (`.pcap`) analysis and summarization tool written in C and Python. It combines a lightweight C binary for rapid binary header inspection with a Scapy-based Python engine for protocol classification, traffic flow aggregation, DNS query extraction, and heuristic anomaly detection.

## Features

- **Fast Binary Header Pre-Scan**: Parses raw 24-byte global `.pcap` headers and 16-byte record headers in C to compute total packets, capture duration, wire volume, and average packet size.
- **Protocol Distribution**: Classifies traffic across Layer 2, Layer 3, and Layer 4/7 protocols (ARP, ICMP, TCP, UDP, DNS, HTTP, HTTPS, SSH, FTP, Telnet, SMTP, SMB, RDP, MySQL).
- **Flow & Endpoint Aggregation**: Identifies top source IP addresses, destination IP addresses, and host-to-host conversations (`src -> dst`).
- **DNS Inspection**: Extracts and counts queried domain names from UDP DNS requests.
- **Heuristic Anomaly Detection**:
  - **Port Scanning**: Flags source hosts connecting to 20 or more distinct destination TCP ports.
  - **SYN Flood / Half-Open Sweeps**: Detects sources sending 50+ `SYN` packets where `SYN` volume exceeds `ACK` volume by more than 3x.
  - **DNS Tunneling / DGA Indicators**: Calculates Shannon entropy on queried subdomains and flags excessively long domain names (>52 characters) or high-entropy labels (>3.8 bits across >24 characters).
  - **ICMP Volume Spikes**: Alerts on hosts generating 40 or more ICMP packets.
  - **Cleartext Protocol Detection**: Identifies traffic over unencrypted legacy ports (FTP, Telnet, HTTP, POP3, IMAP).
- **JSON Reporting**: Exports structured analysis summaries and triggered alerts for downstream tooling.

## Prerequisites

- **Python**: 3.8 or higher
- **C Compiler**: `gcc` or `clang` (optional; required only for the C pre-scanner)
- **Make**: GNU Make (optional)

## Installation

1. Clone the repository:
   ```bash
   git clone [https://github.com/yourusername/netsift.git](https://github.com/yourusername/netsift.git)
   cd netsift
   ```

2. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Compile the C pre-scanner:
   ```bash
   make
   ```
   On Windows (without `make`):
   ```bash
   gcc -O2 -o fast_scan.exe fast_scan.c
   ```
   *Note: If the C binary is not compiled, NetSift automatically falls back to the Python parser.*

## Usage

Run a standard analysis on a `.pcap` file:

```bash
python main.py capture.pcap
```

Limit terminal tables to the top 5 entries and export the full report to JSON:

```bash
python main.py capture.pcap --top 5 --out report.json
```

### Command-Line Arguments

| Argument | Short | Description | Default |
| :--- | :--- | :--- | :--- |
| `pcap` | — | Path to the target `.pcap` file (required) | — |
| `--top` | `-t` | Number of top entries to display per summary table | `10` |
| `--out` | `-o` | Output file path for the JSON report | `None` |

## Limitations

- `fast_scan.c` supports standard libpcap files (magic numbers `0xa1b2c3d4` and `0xd4c3b2a1`). For `.pcapng` files, the C pre-scanner exits gracefully and analysis proceeds via the Python engine.

