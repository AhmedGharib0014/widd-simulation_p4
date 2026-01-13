# WIDD - Wireless Intrusion Detection & Defense System

An SDN-based security system for wireless networks implementing **OODA loops** and **Cyber Kill Chain** detection, based on the Zanna et al. paper "Preventing Attacks on Wireless Networks Using SDN Controlled OODA Loops & Cyber Kill Chains" (2022).

## Architecture

```
+-----------------------------------------------------------+
|             CONTROL PLANE (Python/POX Logic)              |
|                                                           |
|  +---------------------+        +-----------------------+ |
|  |   MOCC Algorithm    |        |  Kill Chain State     | |
|  | (RF Identification) |<------>|  Machine (KCSM)       | |
|  +----------^----------+        +-----------^-----------+ |
+-------------|-------------------------------|-------------+
              | OpenFlow / Thrift             |
+-------------|-------------------------------|-------------+
|  DATA PLANE (bmv2 Switch - P4 Program)     |             |
|                                             |             |
|  +----------v----------+        +-----------v-----------+ |
|  |  Observe/Orientate  |        |     Decision/Act      | |
|  | (Header Extraction) |        | (Drop/Pass/Inject)    | |
|  +----------^----------+        +-----------|-----------+ |
+-------------|-------------------------------|-------------+
              |                               |
+-------------|-------------------------------v-------------+
|  MININET-WIFI (Virtual Wireless Medium)                   |
|                                                           |
|  [Legit Client] ----(Frames + Simulated RF)----> [WAP]    |
|  [Attacker]     ----(Spoofed Deauth)----------->          |
+-----------------------------------------------------------+
```

## Project Structure

```
widd/
├── README.md                 # This file
├── config/
│   ├── __init__.py
│   └── settings.py           # Global configuration
├── controller/
│   ├── __init__.py
│   ├── mocc.py               # MOCC algorithm (RF fingerprinting)
│   ├── kcsm.py               # Kill Chain State Machine
│   ├── ooda_controller.py    # Main OODA loop controller
│   └── switch_interface.py   # bmv2 Thrift interface
├── attacks/
│   ├── __init__.py
│   └── attack_generator.py   # Simulated attack traffic
├── topology/
│   └── widd_topo.py          # Mininet-WiFi network topology
├── p4/
│   ├── widd.p4               # P4 program for bmv2 switch
│   ├── widd.json             # Compiled P4 program
│   └── Makefile              # P4 compilation rules
├── demo_launcher.sh          # Multi-terminal demo script
└── interactive_attack.py     # Interactive attack CLI
```

## Components

### Control Plane

#### MOCC Algorithm (`controller/mocc.py`)
Malicious OODA Counter-Cycle algorithm for RF-based device identification:
- Maintains RF signatures (RSSI, phase offset, pilot offset) per device
- Uses probabilistic matching to detect spoofed frames
- Trains on legitimate traffic to build device profiles

#### Kill Chain State Machine (`controller/kcsm.py`)
Tracks attack progression through cyber kill chain phases:
- **Reconnaissance**: Probe request floods, beacon analysis
- **Weaponization**: Tool preparation (passive)
- **Delivery**: Deauth/disassoc frame injection
- **Exploitation**: Client disconnection
- **Installation**: Evil twin AP deployment
- **Command & Control**: Rogue AP association
- **Actions**: Credential capture, MitM attacks

#### OODA Controller (`controller/ooda_controller.py`)
Main control loop implementing Observe-Orient-Decide-Act:
1. **Observe**: Receive Packet-In from bmv2 (management frames)
2. **Orient**: Parse frame, extract RF features, call MOCC
3. **Decide**: Update KCSM, determine attack state
4. **Act**: Drop/Pass/Inject countermeasures

### Data Plane

#### P4 Program (`p4/widd.p4`)
bmv2 switch program for 802.11 frame processing:
- Extracts frame type, subtype, addresses
- Simulates RF feature extraction (RSSI, phase)
- Forwards management frames to CPU port for analysis
- Applies drop/pass decisions from controller

### Network Layer

#### Mininet-WiFi Topology (`topology/widd_topo.py`)
Virtual wireless network with:
- 1 Access Point (WIDD_Network, channel 6)
- 3 Legitimate client stations (sta1, sta2, sta3)
- 1 Attacker station
- wmediumd for realistic RF propagation simulation
- bmv2 P4 switch integration

## Connection Flow

```
┌──────────────────────────────────────────────────────────────────┐
│  1. CLIENTS → MININET-WIFI (Wireless 802.11)                     │
│                                                                  │
│     sta1/sta2/sta3/attacker ──(WiFi)──► ap1 (Access Point)      │
│     - autoAssociation enabled                                    │
│     - wmediumd simulates RSSI/propagation                        │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  2. ACCESS POINT → BMV2 SWITCH (Ethernet Link)                   │
│                                                                  │
│     ap1 ──(addLink)──► s1 (P4Switch running widd.p4)            │
│     - P4 extracts 802.11 headers                                 │
│     - Management frames → CPU port 255                           │
│     - Thrift API on port 9090                                    │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  3. BMV2 SWITCH → OODA CONTROLLER                                │
│                                                                  │
│     s1 ──(Thrift API)────► OODA Controller (port 9090)          │
│        ──(CPU Port)──────► Packet-In for analysis               │
│                                                                  │
│     Controller processes (ooda_controller.py):                   │
│     - Deauth frames → MOCC identification → KCSM state update   │
│     - Beacon frames → Evil twin detection                        │
│     - Auth/Assoc floods → Rate limiting                          │
└──────────────────────────────────────────────────────────────────┘
```

## Requirements

### System Dependencies
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y \
    python3 python3-pip \
    mininet \
    xterm \
    tcpdump \
    git
```

### Mininet-WiFi
```bash
git clone https://github.com/intrig-unicamp/mininet-wifi
cd mininet-wifi
sudo util/install.sh -Wlnfv
```

### bmv2 (P4 Software Switch)
```bash
# Install from p4lang
git clone https://github.com/p4lang/behavioral-model.git
cd behavioral-model
./install_deps.sh
./autogen.sh
./configure
make
sudo make install
```

### Python Dependencies
```bash
pip3 install scapy thrift
```

## Usage

### Real Network Mode (Recommended)

**This is the recommended way** - tests the complete system with real packets!

See **[NETWORK_SETUP.md](NETWORK_SETUP.md)** for detailed step-by-step guide.

#### Quick Start:

**Terminal 1: Start Mininet-WiFi**
```bash
sudo python3 topology/widd_topo.py
```

**Terminal 2: Start OODA Controller**
```bash
python3 run_controller.py
```

**Terminal 3: Launch Attack CLI (from mininet)**
```bash
mininet-wifi> xterm attacker

# In attacker terminal:
python3 interactive_attack.py --interface attacker-wlan0
```

**Architecture Flow:**
```
Attack CLI → Scapy → Mininet-WiFi → BMV2 P4 Switch → OODA Controller
            (NO BYPASS - TESTS COMPLETE SYSTEM!)
```

Features:
- ✅ Real 802.11 frame generation via Scapy
- ✅ Real P4 switch processing
- ✅ Real packet-in handling
- ✅ Real MOCC RF fingerprinting
- ✅ Real KCSM state machine detection
- ✅ Production-like environment

### Simulation Mode (For Algorithm Testing Only)

For quick algorithm testing without network (bypasses P4 switch):

```bash
# Start simulation server (Terminal 1)
python3 start_server.py

# Packet monitor (Terminal 2)
python3 packet_monitor.py
```

**⚠️ Note**: Simulation mode bypasses the network and P4 switch - use only for quick algorithm testing, not for full system validation.

## Attack Types Detected

| Attack | Kill Chain Phase | Detection Method |
|--------|------------------|------------------|
| Deauth Flood | Delivery | Frame rate + MOCC RF mismatch |
| Disassoc Flood | Delivery | Frame rate + MOCC RF mismatch |
| Evil Twin AP | Installation | SSID match + BSSID mismatch |
| Auth Flood | Reconnaissance | Frame rate threshold |
| Assoc Flood | Reconnaissance | Frame rate threshold |
| Beacon Spoofing | Installation | RF fingerprint mismatch |

## Countermeasures

When an attack is detected, the system can:
1. **Drop** spoofed frames at the P4 switch
2. **Alert** the administrator
3. **Inject false handshakes** to poison attacker captures
4. **Blacklist** attacker MAC addresses

## Configuration

Edit `config/settings.py`:
```python
# Network settings
SSID = 'WIDD_Network'
CHANNEL = 6

# Detection thresholds
DEAUTH_THRESHOLD = 3        # frames before attack detection
AUTH_FLOOD_THRESHOLD = 10   # frames per second
RSSI_TOLERANCE = 10         # dB variance allowed

# Controller settings
POX_PORT = 6633
THRIFT_PORT = 9090
```

## Development Status

- [x] MOCC algorithm implementation
- [x] KCSM state machine
- [x] OODA controller logic
- [x] P4 program for 802.11 parsing
- [x] Mininet-WiFi topology
- [x] Attack generator
- [x] Standalone controller (no POX dependency)
- [ ] Real 802.11 frame injection
- [ ] Production deployment guide

## References

- Zanna, P. et al. "Preventing Attacks on Wireless Networks Using SDN Controlled OODA Loops & Cyber Kill Chains" (2022)
- [Mininet-WiFi](https://github.com/intrig-unicamp/mininet-wifi)
- [bmv2 P4 Switch](https://github.com/p4lang/behavioral-model)
- [P4 Language](https://p4.org/)

## License

This project is for educational and research purposes.
