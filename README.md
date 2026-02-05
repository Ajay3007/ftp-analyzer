# FTP File Reconstruction from PCAP (C++ Network Analyzer)

## Overview

This project implements a C++ utility to reconstruct files transferred using FTP by analyzing raw network traffic stored in PCAP files.

The tool parses captured packets, extracts FTP control information, performs TCP reassembly, and reconstructs transferred files from network payloads — even when the PCAP contains unrelated “noise” protocols such as ARP, ICMP, DHCP, mDNS, etc.

It works completely offline and does not require access to the original FTP server.

---

## Problem Statement

Given:

- An FTP server
- Files transferred using FTP
- A PCAP file captured on the network

Design a utility that:

- Parses the PCAP file
- Identifies FTP control and data channels
- Extracts raw file bytes
- Reassembles TCP streams
- Reconstructs the original files

---

## Features

✔ Offline PCAP analysis using libpcap
✔ FTP control channel parsing
✔ Passive FTP (PASV / EPSV) support
✔ Active FTP (PORT / EPRT) parsing support
✔ IPv4 and IPv6 support
✔ TCP segment reassembly
✔ Duplicate packet handling
✔ Multi-session file reconstruction
✔ Filename extraction from control channel
✔ Works with noisy PCAPs (mixed protocols)
✔ Modular and extensible design

---

## Project Structure

```bash
ftp-analyzer/
│
├── src/
│   ├── main.cpp
│   ├── pcap_reader.cpp / .h
│   ├── link_layer.cpp / .h
│   ├── ftp_parser.cpp / .h
  ├── tcp_reassembly.cpp / .h
  └── session_manager.h
│
├── captures/
│   ├── ftp_2file.pcap
│   └── ftp6.pcap
│
├── docs/
│   ├── 100G_SCALE_DESIGN.md
│   └── architecture-uml-doc.md
│
├── CMakeLists.txt
└── README.md
```

---

## High-Level Architecture

The system is organized into independent modules.

```bash
+-------------+
|   main()    |
+-------------+
     |
     v
+-------------+
| PcapReader  |
+-------------+
     |
     v
+-------------+
| FTPParser   |
+-------------+
     |
     v
+-------------+
| SessionMap  |
+-------------+
     |
     v
+-------------+
| TCPReasmblr |
+-------------+
     |
     v
+-------------+
| Output File |
+-------------+
```

---

## Architecture Components

### 1. Main Module (`main.cpp`)

Responsibilities:

- Parse command-line arguments
- Initialize session structures
- Start PCAP processing
- Trigger TCP reassembly

---

### 2. PCAP Reader (`pcap_reader.*`)

Responsibilities:

- Open PCAP file
- Read packets using `pcap_next_ex()` / libpcap APIs
- Detect link-layer offsets
- Parse IPv4 / IPv6 headers
- Parse TCP headers
- Extract payload
- Filter non-TCP traffic and ignore protocol noise
- Identify FTP control and data channels

---

### 3. Link Layer Handler (`link_layer.*`)

Responsibilities:

- Detect capture type (Ethernet / Loopback)
- Calculate network-layer offset

Uses:

- `pcap_datalink()`
- `DLT_EN10MB`, `DLT_NULL`

---

### 4. FTP Parser (`ftp_parser.*`)

Responsible for parsing FTP control messages.

Supported commands:

| Mode    | Command | Protocol |
|---------|---------|----------|
| Passive | PASV    | IPv4     |
| Passive | EPSV    | IPv6     |
| Active  | PORT    | IPv4     |
| Active  | EPRT    | IPv6     |

Extracts:

- Data channel port
- Current filename (from `STOR` / `STOU` commands)

---

### 5. Session Manager (`session_manager.h`)

Defines core data structures:

- TCP Segment
- Unified IPv4 / IPv6 Address
- Connection Key
- Session Map

Each session is uniquely identified by:

`<Src IP, Dst IP, Src Port, Dst Port, Filename>`

---

### 6. TCP Reassembly (`tcp_reassembly.*`)

Responsibilities:

- Sort segments by sequence number
- Remove duplicates
- Handle retransmissions and overlapping segments
- Rebuild byte stream
- Write output files
- Support multiple sessions concurrently

---

## Data Flow

```bash
PCAP File
  ↓
PcapReader
  ↓
Packet Parsing
  ↓
SessionMap (ConnKey → Segments)
  ↓
TCP Reassembly
  ↓
Reconstructed Files
```

---

## FTP Protocol Handling

### FTP Connections

FTP uses two connections:

| Channel | Purpose        | Port    |
|---------|----------------|---------|
| Control | Commands       | 21      |
| Data    | File Transfer  | Dynamic |

### Passive Mode

```bash
Client → Server: PASV / EPSV
Server → Client: Port Info
Client → Server: Data Connection
```

### Active Mode

```bash
Client → Server: PORT / EPRT
Server → Client: Data Connection
```

## TCP Reassembly Strategy

Steps:

- Store segments per connection
- Sort by sequence number
- Skip overlapping data
- Ignore duplicates
- Write payload in order

Handles:

- ✔ Out-of-order packets
- ✔ Retransmissions
- ✔ Overlapping segments
- ✔ Packet duplication

---

## Environment Setup

### Dependencies

- libpcap
- CMake
- C++17
- pure-ftpd (for testing)

### macOS

```bash
brew install pure-ftpd libpcap cmake
xcode-select --install
```

### Linux

```bash
sudo apt install libpcap-dev cmake g++
```

### FTP Server Configuration (macOS)

#### Create FTP Root

```bash
sudo mkdir -p /tmp/ftp
sudo chown $USER /tmp/ftp
sudo chmod 755 /tmp/ftp
```

#### Create Virtual User

```bash
sudo pure-pw useradd ftpuser \
  -u $USER \
  -d /tmp/ftp \
  -m
```

#### Build Database

```bash
sudo pure-pw mkdb
```

#### Start Server

```bash
sudo pure-ftpd -B -l puredb:/opt/homebrew/etc/pureftpd.pdb
```

#### Verify

```bash
sudo lsof -i :21
```

---

## Packet Capture

Start capture before transfer:

```bash
sudo tcpdump -i lo0 -w ftp.pcap
```

Example capture output:

```text
tcpdump: listening on lo0
1494 packets captured
```

---

## FTP File Transfer

Connect:

```bash
ftp -4 localhost
# OR
ftp -6 ::1
```

Inside FTP:

```text
binary
passive
put file.pdf
bye
```

Example session:

```text
ftp> binary
ftp> passive
ftp> put sample.pdf
ftp> put image.png
ftp> bye
```

---

## Build Instructions

```bash
mkdir build
cd build
cmake ..
make
```

### Usage

```bash
./ftp_analyzer <pcap_file> <output_prefix>
```

### Example

```bash
./ftp_analyzer ftp_2file.pcap recovered
```

Expected output examples printed by the tool:

```text
[+] Ethernet capture
[+] PASV Port: 27895
[+] File: sample.pdf
[+] PASV Port: 62175
[+] File: image.png
[+] Reconstructed: recovered_sample.pdf
[+] Reconstructed: recovered_image.png
```

---

## Testing Procedure

1. Start FTP server
2. Start capture
3. Transfer files
4. Stop capture
5. Run analyzer
6. Verify hash

```bash
shasum original.pdf recovered_sample.pdf
```

---

## Debugging FTP Server Issues

1. Database Error

Error:

Unable to read indexed puredb file

Fix:

```bash
sudo pure-pw mkdb
sudo pkill pure-ftpd
sudo pure-ftpd -B -l puredb:/opt/homebrew/etc/pureftpd.pdb
```

2. Home Directory Error

Error:

Home directory not available

Fix:

```bash
sudo mkdir -p /tmp/ftp
sudo chown $USER /tmp/ftp
sudo chmod 755 /tmp/ftp
```

3. Verify User

```bash
sudo pure-pw show ftpuser
```

Check:

- UID
- Directory
- Permissions

4. Check Listening Ports

```bash
sudo lsof -i :21
```

Confirms IPv4 / IPv6 availability.

---

## Handling Noisy PCAP Files

The analyzer ignores unrelated traffic such as ARP, ICMP, DHCP, mDNS, STP and UDP. Only TCP + FTP packets are processed, enabling reconstruction from real-world mixed-protocol captures.

---

## Current Capabilities

| Feature            | Status |
|--------------------|--------|
| IPv4               | ✅     |
| IPv6               | ✅     |
| Passive FTP        | ✅     |
| Active FTP         | ✅     |
| Multi-Session      | ✅     |
| TCP Reassembly     | ✅     |
| Noise Handling     | ✅     |
| Filename Mapping   | ✅     |

---

## Learning Outcomes

This project demonstrates:

- Low-level packet analysis
- TCP/IP protocol understanding
- FTP protocol internals
- libpcap usage
- Systems programming
- Debugging network services
- Scalable design thinking

---

## Conclusion

This project successfully reconstructs FTP-transferred files from raw PCAP files. It demonstrates practical expertise in packet capture analysis, protocol parsing, TCP reassembly and C++ systems programming. The tool works reliably on real-world captures containing mixed protocol traffic.

---

## 📐 Architecture & Design Documents

Detailed scalable system design:


- 📄 [Scalable FTP Architecture Design](./Scalable_FTP_Architecture.pdf)
- 🖼️ [100 Gbps Architecture Diagram (SVG)](./100gbps-architecture-design.svg)
