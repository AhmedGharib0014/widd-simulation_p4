# WIDD - Wireless Intrusion Detection & Defense System

An SDN-based security system for wireless networks implementing **OODA loops** and **Cyber Kill Chain** detection, based on the Zanna et al. paper "Preventing Attacks on Wireless Networks Using SDN Controlled OODA Loops & Cyber Kill Chains" (2022).

## Architecture

```
+-----------------------------------------------------------+
|             CONTROL PLANE (Python)                        |
|                                                           |
|  +---------------------+        +-----------------------+ |
|  |   MOCC Algorithm    |        |  Kill Chain State     | |
|  | (RF Identification) |<------>|  Machine (KCSM)       | |
|  +----------^----------+        +-----------^-----------+ |
+-------------|-------------------------------|-------------+
              | Packet-In/Out (CPU port)      |
+-------------|-------------------------------|-------------+
|  DATA PLANE (bmv2 Switch - P4 Program)     |             |
|                                             |             |
|  +----------v----------+        +-----------v-----------+ |
|  |  Observe/Orientate  |        |     Decision/Act      | |
|  | (Header Extraction) |        | (Drop/Pass/Forward)   | |
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
│   ├── switch_interface.py   # bmv2 Thrift + Packet-In/Out handling
│   └── logger.py             # Color-coded logging system
├── attacks/
│   ├── __init__.py
│   └── attack_generator.py   # Scapy-based attack traffic generation
├── topology/
│   └── widd_topo.py          # Mininet-WiFi network topology
├── p4/
│   ├── widd.p4               # P4 program for bmv2 switch
│   ├── widd.json             # Compiled P4 program
│   └── Makefile              # P4 compilation rules
├── docs/
│   ├── README.md             # Architecture documentation
│   ├── component_diagram.puml
│   └── architecture_uml.puml
├── demo_launcher.sh          # Multi-terminal demo script
├── start_server.py           # OODA Controller server entry point
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
4. **Act**: Drop spoofed frames OR forward legitimate via Packet-Out

#### Switch Interface (`controller/switch_interface.py`)
Unified interface for P4 switch communication:
- Thrift API connection to bmv2 (table management, counters)
- Packet-In listener (Scapy-based sniffing on CPU port)
- Packet-Out sender (raw socket injection to CPU port)
- WIDD frame parsing (CPU header, Ethernet, WiFi FC, WiFi Addr, RF Features)

### Data Plane

#### P4 Program (`p4/widd.p4`)
bmv2 switch program for 802.11 frame processing:
- Parses WIDD-encapsulated frames (ethertype 0x88B5)
- Extracts frame type, subtype, addresses, RF features
- Forwards management frames to CPU port 255 for analysis
- Handles Packet-Out from controller (forwards to destination port)
- Maintains blocklist table for dropping attacker frames

### Network Layer

#### Mininet-WiFi Topology (`topology/widd_topo.py`)
Virtual wireless network with:
- 1 Access Point (WIDD_Network, channel 6)
- 2 Legitimate client stations (sta1, sta2)
- 1 Attacker station
- bmv2 P4 switch with CPU port veth pair
- TC mirroring from AP wireless to switch port

## Packet Flow

```
┌──────────────────────────────────────────────────────────────────┐
│  1. ATTACKER → P4 SWITCH (via AP mirroring)                      │
│                                                                  │
│     attacker-wlan0 ──(WiFi)──► ap1-wlan1 ──(tc mirror)──► s1    │
│     - Sends WIDD-encapsulated 802.11 frames                      │
│     - RF features included (RSSI, phase, pilot, mag)             │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  2. P4 SWITCH → OODA CONTROLLER (Packet-In)                      │
│                                                                  │
│     s1 ──(CPU port 255)──► s1-cpu-h ──(sniff)──► Controller     │
│     - P4 extracts 802.11 headers                                 │
│     - Prepends CPU header (reason, port, rssi)                   │
│     - Management frames sent to CPU for analysis                 │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│  3. OODA CONTROLLER PROCESSING                                   │
│                                                                  │
│     OBSERVE: Parse WIDD frame structure                          │
│     ORIENT:  MOCC RF signature verification                      │
│     DECIDE:  KCSM state machine update                           │
│     ACT:     DROP (spoofed) or PASS (legitimate via Packet-Out)  │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼ (if legitimate)
┌──────────────────────────────────────────────────────────────────┐
│  4. PACKET-OUT (Forward legitimate frames)                       │
│                                                                  │
│     Controller ──(CPU header + raw 802.11)──► s1-cpu-h           │
│     P4 switch forwards to destination port                       │
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

### Quick Start (Demo Mode)
```bash
# Launch multi-terminal demo (3 windows)
sudo ./demo_launcher.sh
```

This opens:
- **Terminal 1**: Mininet-WiFi topology with P4 switch
- **Terminal 2**: OODA Controller (start_server.py)
- **Terminal 3**: Interactive Attack CLI

### Manual Start

1. **Start Mininet-WiFi Topology** (Terminal 1):
```bash
sudo python3 topology/widd_topo.py
```

2. **Start OODA Controller** (Terminal 2):
```bash
sudo python3 start_server.py
```

3. **Launch Attack CLI** (Terminal 3 - from attacker namespace):
```bash
# Find attacker PID
ATTACKER_PID=$(pgrep -f "mininet:attacker")

# Run attack CLI in attacker namespace
sudo mnexec -a $ATTACKER_PID python3 interactive_attack.py --interface attacker-wlan0
```

### Attack CLI Commands

```bash
# Deauthentication attack
deauth sta1 5              # Send 5 deauth frames targeting sta1

# Disassociation attack
disassoc sta1 3            # Send 3 disassoc frames

# Evil twin beacon
evil_twin                  # Broadcast fake AP beacon

# Auth/Assoc floods
auth_flood 20              # Send 20 auth frames
assoc_flood 15             # Send 15 assoc frames

# Training data (legitimate traffic)
train sta1 100             # Send 100 data frames as sta1

# Pre-configured demos
demo1                      # Deauth attack demo
demo2                      # Spoofed deauth demo
```

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

When an attack is detected, the system:
1. **Drops** spoofed frames (does NOT forward via Packet-Out)
2. **Alerts** via colored console logging
3. **Forwards** legitimate frames via Packet-Out to victim
4. **Blocklists** attacker MAC addresses in P4 switch table

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
THRIFT_PORT = 9090
CPU_INTERFACE = 's1-cpu-h'
```

## Development Status

- [x] MOCC algorithm implementation
- [x] KCSM state machine
- [x] OODA controller logic
- [x] P4 program for 802.11 parsing
- [x] Mininet-WiFi topology with P4 switch
- [x] Attack generator (Scapy-based)
- [x] Packet-In handling (SwitchInterface)
- [x] Packet-Out forwarding for legitimate frames
- [x] Interactive attack CLI
- [ ] Production deployment guide
- [ ] Web-based monitoring dashboard

## References

- Zanna, P. et al. "Preventing Attacks on Wireless Networks Using SDN Controlled OODA Loops & Cyber Kill Chains" (2022)
- [Mininet-WiFi](https://github.com/intrig-unicamp/mininet-wifi)
- [bmv2 P4 Switch](https://github.com/p4lang/behavioral-model)
- [P4 Language](https://p4.org/)

## License

This project is for educational and research purposes.
