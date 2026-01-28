# FTP PCAP File Reconstruction

## 📌 Project Overview

This project demonstrates how to reconstruct a file transferred over FTP by analyzing raw network packets captured in a PCAP file.

The system captures FTP traffic, extracts the data channel, reassembles TCP segments, and rebuilds the original file using C++ and libpcap.

This setup was implemented and tested on **macOS (Homebrew + Pure-FTPd)**.

---

## 🎯 Objectives

* Configure an FTP server on macOS
* Transfer files using FTP
* Capture packets using tcpdump
* Analyze PCAP using C++
* Reconstruct transferred files
* Validate reconstruction using checksums

---

## 📂 Repository Structure

```
ftp-pcap-reconstruction/
│
├── src/
│   └── main.cpp            # PCAP analyzer
│
├── bin/
│   └── ftp_reconstruct     # Compiled binary
│
├── captures/
│   └── ftp4.pcap           # Sample PCAP
│
├── samples/
│   └── recovered.jpg       # Output file
│
└── README.md
```

---

## 🛠️ System Requirements

* macOS
* Homebrew
* g++ (Xcode Command Line Tools)
* libpcap
* Pure-FTPd
* tcpdump

Install dependencies:

```bash
brew install pure-ftpd libpcap
xcode-select --install
```

---

# 🔧 Phase 1: FTP Server Setup

## 1. Install Pure-FTPd

```bash
brew install pure-ftpd
```

### Error Encountered

```
/opt/homebrew/var/log not writable
```

### Fix

```bash
sudo chown -R $USER /opt/homebrew/var/log
chmod u+w /opt/homebrew/var/log
```

---

## 2. Create FTP Root Directory

```bash
sudo mkdir -p /tmp/ftp
sudo chown $USER /tmp/ftp
chmod 755 /tmp/ftp
```

---

## 3. Create Virtual FTP User

```bash
sudo pure-pw useradd ftpuser \
  -u $USER \
  -d /tmp/ftp \
  -m
```

Set password when prompted.

### Errors Encountered

```
pureftpd.passwd.tmp cannot be written
```

### Fix

```bash
sudo chown -R $USER /opt/homebrew/etc
chmod u+w /opt/homebrew/etc
rm /opt/homebrew/etc/pureftpd.passwd*
```

---

## 4. Start FTP Server

```bash
sudo pkill pure-ftpd
sudo pure-ftpd -B -l puredb:/opt/homebrew/etc/pureftpd.pdb
```

Verify:

```bash
sudo lsof -i :21
```

---

# 📡 Phase 2: FTP Transfer

## 1. Connect to Server

```bash
ftp -4 localhost
```

Login:

```
Username: ftpuser
Password: <your_password>
```

---

## 2. Enable Binary & Passive Mode

```bash
binary
passive
```

Important: Prevents corruption and enforces PASV.

---

## 3. Upload File

```bash
put sha_sign.jpg
```

Verify:

```
226 Transfer complete
```

---

# 📥 Phase 3: Packet Capture

## 1. Start Capture (Before FTP)

```bash
sudo tcpdump -i any -w ftp4.pcap
```

Reason: macOS loopback requires `any` interface.

---

## 2. Stop Capture

Press `Ctrl + C` after transfer.

Verify file size:

```bash
ls -lh ftp4.pcap
```

Expected: Larger than control traffic (>100 KB for large files).

---

# 🔍 Phase 4: PCAP Analysis & Reconstruction

## 1. Compile Analyzer

```bash
g++ -std=c++17 src/main.cpp -lpcap -o bin/ftp_reconstruct
```

---

## 2. Run Analyzer

```bash
./bin/ftp_reconstruct captures/ftp4.pcap samples/recovered.jpg
```

Expected Output:

```
[+] Loopback capture
[+] PASV Data Port: xxxx
[+] Reconstructed: recovered.jpg
```

---

# ✅ Phase 5: Verification

```bash
shasum original.jpg recovered.jpg
```

Hashes must match.

---

# 🧠 Phase 6: Major Errors & Fixes

## 1. vsftpd Issues

* Config ownership errors
* PAM failures
* secure_chroot_dir errors

Solution: Switched to Pure-FTPd.

---

## 2. Authentication Failure

```
530 Login failed
```

Cause: Missing virtual user DB

Fix:

```bash
sudo pure-pw mkdb
```

---

## 3. No Data Found in Analyzer

```
No data found
```

Causes:

* IPv6 capture
* Active FTP
* Wrong interface
* Loopback header ignored

Fixes:

* Use `ftp -4`
* Enable passive mode
* Capture with `-i any`
* Detect DLT_NULL in code

---

## 4. Compilation Errors (macOS vs Linux)

Linux structs not supported on macOS:

| Linux | macOS     |
| ----- | --------- |
| iphdr | struct ip |
| doff  | th_off    |
| seq   | th_seq    |

Solution: Rewrite parsing using BSD headers.

---

# 📐 Phase 7: Internal Architecture

## System Flow

1. FTP Client uploads file
2. Server opens data channel (PASV)
3. tcpdump captures packets
4. Analyzer parses PCAP
5. TCP segments reassembled
6. File reconstructed

---

## Analyzer Pipeline

```
PCAP → Link Layer → IP → TCP → FTP Control → Data Channel → Reassembly → File
```

---

# 🏗️ Phase 8: Core Implementation Highlights

* Uses `pcap_open_offline` for PCAP parsing
* Dynamically detects link-layer headers
* Extracts PASV port from control channel
* Tracks TCP sequence numbers
* Sorts and merges segments
* Writes binary output

---

# 💼 Resume-Ready Summary

"Implemented an FTP traffic analyzer in C++ using libpcap to reconstruct files from raw packet captures. Parsed FTP control/data channels, handled BSD loopback headers, reassembled TCP streams, and validated integrity using SHA-1."

---

# 📌 Important Notes

* FTP is insecure and unencrypted (used for analysis only)
* Always use binary mode
* Passive mode simplifies reconstruction
* Loopback requires special handling
* macOS differs from Linux networking stack

---

# 🚀 Future Enhancements

* IPv6 support
* Active mode support (PORT/EPRT)
* Multi-session handling
* Retransmission recovery
* GUI interface

---

# 👤 Author

Ajay Gupta

---

# 📜 License

MIT License
