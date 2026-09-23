# 📝 README.md  

Create a file called `README.md` in your **`C:\Users\Hxtreme\Documents\packet-analyzer\`** folder (replace the existing one). Copy-paste this:

---

```markdown
# 🛡️ Network Packet Analyzer

A Python-based **mid-level network packet analyzer** that captures live traffic, dissects multiple protocols, and detects suspicious activity in real time — built for the **CodSoft Cyber Security Internship (Task 1)**.

---

## 📌 Features

- ✅ **Live Packet Capture** using Scapy + Npcap (Windows) / libpcap (Linux/macOS)
- ✅ **Protocol Dissection** — IP, TCP, UDP, DNS, ARP, ICMP
- ✅ **Threat Detection Engine** with modular rules:
  - Port Scan Detection (TCP SYN flood on multiple ports)
  - ARP Spoofing Detection *(extensible)*
  - DNS Tunneling Detection *(extensible)*
  - Brute Force Detection *(extensible)*
- ✅ **Severity Levels** — LOW / MEDIUM / HIGH / CRITICAL
- ✅ **Colored Console Alerts** (colorama)
- ✅ **JSON Alert Logging** for SIEM integration
- ✅ **PCAP Export** for Wireshark inspection
- ✅ **Config-driven** via YAML (interface, filter, thresholds)
- ✅ **CLI overrides** — `--iface`, `--filter`, `--count`, `--verbose`

---

## 🏗️ Project Structure

```
packet-analyzer/
├── core/                   # Core engine
│   ├── capture.py          # Scapy sniff() wrapper
│   ├── dissector.py        # Protocol parsing
│   ├── detector.py         # Detection engine dispatcher
│   └── stats.py            # Thread-safe statistics
├── detection/              # Detection rules
│   ├── base.py             # Base Detector interface
│   ├── port_scan.py        # Port scan detection
│   ├── arp_spoof.py        # ARP spoofing detection
│   ├── dns_tunnel.py       # DNS tunneling detection
│   └── brute_force.py      # Brute force detection
├── output/                 # Alerts & logging
│   ├── alerts.py           # Alert dataclass + severity
│   ├── logger.py           # JSON logger
│   └── pcap_writer.py      # PCAP exporter
├── ui/                     # Interface
│   ├── cli.py              # Argument parsing
│   └── dashboard.py        # Live stats
├── config/
│   └── config.yaml         # Thresholds & settings
├── logs/                   # Runtime output
├── tests/                  # Unit tests
├── main.py                 # Entry point
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation

### 1. Clone the repository
```bash
git clone https://github.com/poojathirumalaisamy23/CODSOFT_TASKS.git
cd CODSOFT_TASKS
```

### 2. Create a virtual environment *(optional but recommended)*
```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Install Npcap (Windows only)
Download and install **Npcap 1.89+** from https://npcap.com

⚠️ During installation, check **"Install Npcap in WinPcap API-compatible Mode"**.

---

## 🚀 Usage

### List available interfaces
```bash
python main.py --list-ifaces
```

### Run the analyzer
```bash
# Windows
python main.py -i "Wi-Fi" -v

# Linux/macOS
sudo python main.py -i eth0 -v
```

### CLI Options

| Flag | Description |
|------|-------------|
| `-i, --iface` | Network interface (overrides config) |
| `-f, --filter` | BPF filter (e.g., `tcp`, `udp port 53`) |
| `-c, --count` | Stop after N packets (0 = infinite) |
| `-v, --verbose` | Print every packet |
| `--config` | Path to config file (default: `config/config.yaml`) |
| `--list-ifaces` | List interfaces and exit |

---

## 🧪 Example — Detecting a Port Scan

**Terminal 1 — Run the analyzer:**
```bash
python main.py -i "Wi-Fi" -v
```

**Terminal 2 — Generate a scan against localhost:**
```bash
python -c "from scapy.all import IP, TCP, send; [send(IP(dst='127.0.0.1')/TCP(dport=p, flags='S'), verbose=0) for p in range(1,50)]"
```

**Terminal 1 — Alert fires:**
```
[HIGH] PORT_SCAN | 127.0.0.1 -> 127.0.0.1 | Port scan detected: 45 unique ports in 5s
```

The alert is also appended to `logs/alerts.json`.

---

## 🔧 Configuration

Edit `config/config.yaml` to tune behavior:

```yaml
capture:
  interface: "Wi-Fi"
  bpf_filter: "ip"
  packet_count: 0
  promiscuous: true

detection:
  port_scan:
    enabled: true
    unique_ports_threshold: 15
    time_window_seconds: 5
    severity: HIGH
```

---

## 📊 Output Files

| File | Purpose |
|------|---------|
| `logs/alerts.json` | JSON-lines alert log (SIEM-friendly) |
| `logs/capture.pcap` | Raw packet capture for Wireshark |

---

## 🧠 How Port Scan Detection Works

1. Every TCP **SYN** packet (without ACK) is tracked.
2. A sliding window (default: 5 seconds) is maintained per source→destination pair.
3. If a single source hits **N unique ports** (default: 15) on one target within the window → **HIGH severity alert**.
4. A de-dup set prevents flooding the same alert repeatedly.

---

## 🛠️ Tech Stack

- **Python 3.10+**
- **Scapy 2.7** — packet capture & crafting
- **Npcap** — Windows packet driver
- **PyYAML** — configuration
- **Colorama** — colored console output
- **Rich** — live dashboard (in progress)

---

## 🎯 Skills Demonstrated

- Network security fundamentals
- Packet-level protocol analysis
- Real-time threat detection
- Python modular architecture
- Configuration management
- SIEM-ready logging



---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgements

Built as part of the **CodSoft Cyber Security Internship** — Task 1.

- 🌐 [CodSoft](https://www.codsoft.in)
- 🐍 [Scapy](https://scapy.net)
- 🛡️ [Npcap](https://npcap.com)

---




