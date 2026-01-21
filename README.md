# 📡 SNMP + ICMP Network Monitoring System

A **Python-based network monitoring system** that automatically discovers devices on a network using **SNMP**, continuously monitors them using **SNMP + ICMP**, and exposes all metrics in **Prometheus format** for visualization in tools like **Grafana**.

---

## 🚀 Features

### 🔍 Automatic Network Discovery
- Scans a CIDR network (e.g. `192.168.0.0/24`)
- Discovers **SNMP-enabled devices** using SNMP v2c
- Extracts device name (`sysName`) automatically

### 📶 ICMP Monitoring (Ping)
- Reachability (`up/down`)
- Round-trip latency (RTT)
- Packet loss (sliding window)
- Last successful response timestamp
- Cross-platform (Linux, Windows, macOS)

### 📊 SNMP Monitoring
- **System Information**
  - Hostname
  - Description
  - Location
  - Uptime

- **Network Interfaces**
  - Input/Output octets
  - Input/Output errors
  - Operational status (up/down)

- **CPU Monitoring**
  - Per-core CPU utilization (HOST-RESOURCES-MIB)
  - Windows-safe sparse index handling

- **Memory Monitoring**
  - Total RAM
  - Used RAM
  - Memory utilization percentage

### 📈 Prometheus Metrics
- Metrics served on `/metrics`
- Compatible with **Prometheus** and **Grafana**
- Real-time and historical observability

---

## 🧱 Architecture

```
┌─────────────┐
│   Network   │
│  Devices    │
└─────┬───────┘
      │ SNMP (UDP 161)
      │ ICMP (Ping)
      ▼
┌────────────────────┐
│ Python Async Agent │
│ (This Project)     │
└─────────┬──────────┘
          │
          │ Prometheus Metrics
          ▼
┌────────────────────┐
│ Prometheus Server  │
└─────────┬──────────┘
          │
          ▼
┌────────────────────┐
│ Grafana Dashboards │
└────────────────────┘
```

---

## 📦 Tech Stack

- **Python 3.9+**
- `asyncio` (fully async, non-blocking)
- **pysnmp** (SNMP v2c with asyncio backend)
- **prometheus_client**
- System `ping` command (cross-platform)

---

## 📁 Repository Structure

```
.
├── .idea/                  # IDE configuration files (PyCharm)
├── .gitignore              # Git ignore rules
├── main.py                 # Main entry point (SNMP + ICMP monitoring)
├── snmp_poller.py          # Optimized SNMP polling logic (reduced poll time)
├── setup.ps1               # PowerShell installer/build script
├── setup.msi               # Windows installer package
```

### 📄 File Descriptions

#### `main.py`
- Core application entry point
- Handles:
  - Network discovery via SNMP
  - ICMP (ping) monitoring
  - SNMP polling (system, interfaces, CPU, memory)
  - Prometheus metrics export
- Runs fully asynchronously using `asyncio`

#### `snmp_poller.py`
- Dedicated SNMP polling module
- Optimized polling logic with reduced poll intervals
- Handles:
  - System info
  - Interface statistics
  - CPU utilization
  - Memory utilization
- Designed for better performance and modularity

#### `setup.ps1`
- PowerShell script for building/installing the project on Windows
- Used to generate the MSI installer

#### `setup.msi`
- Windows installer package
- Allows easy installation and execution on Windows machines
- Useful for deployment without Python setup

#### `.gitignore`
- Prevents committing unnecessary files (venv, cache, IDE files, etc.)

#### `.idea/`
- IDE-specific settings (safe to ignore for non-PyCharm users)

---

### 🧩 Project Status

- ✅ ICMP monitoring implemented
- ✅ SNMP system & interface monitoring implemented
- ✅ CPU & memory utilization implemented
- ✅ Windows-compatible SNMP polling
- ✅ Prometheus-ready metrics
- ⏳ Future: SNMP v3, alerts, Docker exporter


## 📥 Installation

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/yourusername/snmp-icmp-monitor.git
cd snmp-icmp-monitor
```

### 2️⃣ Install Dependencies
```bash
pip install prometheus_client pysnmp
```

> ⚠️ On Windows, run the script as **Administrator** to allow ICMP ping.

---

## ⚙️ Configuration

Default configuration (can be edited in the script):

```python
NETWORK_CIDR = '10.147.62.0/24'
SNMP_COMMUNITY = 'public'
PROBE_INTERVAL = 10        # ICMP interval (seconds)
SNMP_POLL_INTERVAL = 10   # SNMP interval (seconds)
METRICS_PORT = 8000
```

---

## ▶️ Running the Monitor

```bash
python snmp_icmp_monitor.py
```

Metrics will be available at:

```
http://localhost:8000/metrics
```

---

## 📊 Exposed Prometheus Metrics

### ICMP Metrics
| Metric | Description |
|------|------------|
| `icmp_up` | Device reachable (1 = up, 0 = down) |
| `icmp_rtt_ms` | ICMP round-trip time |
| `icmp_packet_loss_percent` | Packet loss percentage |
| `icmp_last_seen_timestamp_seconds` | Last successful ping |

### SNMP System Metrics
| Metric | Description |
|------|------------|
| `snmp_system_uptime_seconds` | Device uptime |
| `snmp_system_info` | System metadata |

### Interface Metrics
| Metric | Description |
|------|------------|
| `snmp_interface_octets_in` | Incoming traffic |
| `snmp_interface_octets_out` | Outgoing traffic |
| `snmp_interface_errors_in` | Input errors |
| `snmp_interface_errors_out` | Output errors |
| `snmp_interface_oper_status` | Interface state |

### CPU & Memory
| Metric | Description |
|------|------------|
| `snmp_cpu_load_percent` | Per-CPU utilization |
| `snmp_memory_total_bytes` | Total RAM |
| `snmp_memory_used_bytes` | Used RAM |
| `snmp_memory_used_percent` | RAM usage % |

---

## 📈 Grafana Integration

1. Add Prometheus as a data source  
2. Import dashboards using the metrics above  
3. Visualize:
   - Device availability
   - Latency & packet loss
   - Interface throughput
   - CPU & memory usage

---

## 🛡️ Notes & Limitations

- SNMP v2c only (community-based)
- ICMP requires ping permissions
- Naive SNMP walk (index-based, stable on Windows & Linux)
- Best suited for **LAN / enterprise networks**

---

## 🧠 Future Improvements

- SNMP v3 support
- Alerting (Prometheus Alertmanager)
- Dockerized exporter
- Interface utilization %
- Web UI for discovery
- Device tagging & labels

---

## 👨‍💻 Author

Built as a **high-performance async network monitoring agent** using  
**SNMP + ICMP + Prometheus** for real-time observability.
