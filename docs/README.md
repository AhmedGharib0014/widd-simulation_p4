# WIDD System Architecture Documentation

This directory contains UML diagrams documenting the WIDD (Wireless Intrusion Detection & Defense) system architecture.

## Diagrams

### 1. Component Diagram (`component_diagram.puml`)
**High-level system architecture** showing the major components and their interactions:

- **Data Plane**: P4 switch for 802.11 frame processing
- **Control Plane**: OODA controller with MOCC and KCSM detection algorithms
- **Attack Simulation**: Tools for testing the system
- **Network Layer**: Mininet-WiFi topology

**View this diagram to understand:**
- How packets flow through the system
- Communication protocols between components (Thrift, CPU port, WiFi)
- Separation of concerns (data vs control plane)

### 2. Class Diagram (`architecture_uml.puml`)
**Detailed object-oriented design** showing all classes, their attributes, methods, and relationships:

#### Major Packages:
- **OODA Controller**: Main control loop implementing Observe-Orient-Decide-Act pattern
- **MOCC**: Multiplexed One-Class Classifier for RF device fingerprinting
- **KCSM**: Kill Chain State Machines for attack detection
  - DeauthKCSM: Deauthentication attack detection
  - DisassocKCSM: Disassociation attack detection
  - AuthFloodKCSM: Authentication flood detection
  - AssocFloodKCSM: Association flood detection
- **Switch Interface**: BMV2 Thrift API + Packet-In/Out handling
- **AP Agent**: Receives controller decisions and executes deauth/disassoc via hostapd
- **Attack Generation**: Scapy-based attack simulation tools
- **Logging System**: Comprehensive color-coded logging

**View this diagram to understand:**
- Class hierarchies and composition
- Data models (RFFeatures, ClientState, ParsedFrame, WIDDFrameInfo, etc.)
- Method signatures and class responsibilities
- Design patterns used (composition, callbacks, state machines)

## Viewing the Diagrams

### Online Viewers
You can paste the `.puml` files into:
- [PlantUML Online Editor](https://www.plantuml.com/plantuml/uml/)
- [PlantText](https://www.planttext.com/)

### Local Generation
Install PlantUML and generate PNG/SVG:

```bash
# Install PlantUML
sudo apt install plantuml

# Generate PNG images
plantuml component_diagram.puml
plantuml architecture_uml.puml

# Or generate SVG (scalable)
plantuml -tsvg component_diagram.puml
plantuml -tsvg architecture_uml.puml
```

### VS Code Extension
Install the "PlantUML" extension by jebbs to preview diagrams directly in VS Code.

## Key Design Patterns

### 1. OODA Loop Pattern
The system implements the Observe-Orient-Decide-Act loop:
```
Packet-In → OBSERVE (parse) → ORIENT (MOCC) → DECIDE (KCSM) → ACT (drop/forward)
```

### 2. State Machine Pattern
Each attack type has a dedicated state machine tracking attack progression over time with 2-second timeout windows.

### 3. Strategy Pattern
MOCC uses Gaussian probability calculation to identify legitimate vs spoofed frames based on RF signatures.

### 4. Observer Pattern
Logger observes all controller events for real-time visualization and debugging.

### 5. Unified Interface Pattern
SwitchInterface consolidates all P4 switch communication:
- Thrift API for table management
- Packet-In listening (Scapy sniff on CPU port)
- Packet-Out sending (raw socket on CPU port)
- WIDD frame parsing

## Attack Detection Flow

```
┌─────────────┐
│ WiFi Frame  │
└──────┬──────┘
       │
       ▼
┌─────────────────┐
│ P4 Switch       │  Extract: Frame type, addresses, RF features
│ (Data Plane)    │  Action: Forward to CPU port 255
└──────┬──────────┘
       │ Packet-In (CPU header + WIDD frame)
       ▼
┌─────────────────┐
│ SwitchInterface │  Parse: CPU header, Ethernet, WiFi FC,
│ (Packet-In)     │         WiFi Addr, RF Features
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│ OBSERVE Phase   │  Parse frame structure, create ParsedFrame
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│ ORIENT Phase    │  MOCC: Check RF signature
│ (MOCC)          │  Output: (probability, is_legitimate)
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│ DECIDE Phase    │  KCSM: Update state machine
│ (KCSM)          │  Output: (attack_type, should_drop)
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│ ACT Phase       │  • DROP: Do nothing (don't forward)
│                 │  • PASS: Forward via Packet-Out
│                 │  • Alert via logger
└──────┬──────────┘
       │ (if PASS)
       ▼
┌─────────────────┐
│ SwitchInterface │  Build standard 802.11 management frame (26 bytes)
│ (Packet-Out)    │  Send: CPU header + raw 802.11 frame to CPU port
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│ P4 Switch       │  Forward to destination port (AP eth interface)
│ (Packet-Out)    │  (strips CPU header, emits 802.11 payload)
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│ AP Agent        │  Sniff on ap1-eth2, parse 802.11 frame
│ (ap_agent.py)   │  Execute: hostapd_cli -i ap1-wlan1 deauthenticate <MAC>
└──────┬──────────┘
       │
       ▼
┌─────────────────┐
│ Station         │  Receives deauth from hostapd
│ Disconnected    │  Actually removed from network
└─────────────────┘
```

## RF Feature Fingerprinting (MOCC)

The MOCC algorithm identifies devices by their unique RF characteristics:

1. **Training Phase**: Collect 100+ data frames from legitimate devices
2. **Feature Extraction**: Extract RSSI, phase offset, pilot offset, magnitude squared
3. **Statistical Model**: Calculate mean and standard deviation for each feature
4. **Classification**: Use Gaussian probability (threshold: 35%)

**Formula**: `P = Π(exp(-0.5 * z²))^0.25` where `z = (feature - mean) / std`

## State Machine Thresholds

| Attack Type | Threshold | Window |
|-------------|-----------|---------|
| Deauth Attack | 2 false deauths OR 3 total | 2 seconds |
| Disassoc Attack | 2 false disassocs OR 3 total | 2 seconds |
| Auth Flood | 10 auth frames | 2 seconds |
| Assoc Flood | 10 assoc frames | 2 seconds |
| Evil Twin | SSID match + BSSID mismatch | Instant |

## Packet Formats

### WIDD Frame Format (from attack_generator)
```
[Ethernet Header (14 bytes)]
  - dst_mac: 6 bytes
  - src_mac: 6 bytes
  - ethertype: 0x88B5 (WIDD)
[802.11 Frame Control (2 bytes)]
  - protocol: 2 bits
  - type: 2 bits (0=Mgmt, 1=Ctrl, 2=Data)
  - subtype: 4 bits
  - flags: 8 bits
[802.11 Addresses (20 bytes)]
  - addr1: 6 bytes (Receiver)
  - addr2: 6 bytes (Transmitter)
  - addr3: 6 bytes (BSSID)
  - seq_ctrl: 2 bytes
[RF Features (8 bytes)]
  - rssi: int16
  - phase_offset: uint16
  - pilot_offset: uint16
  - mag_squared: uint16
[Payload (variable)]
```

### P4 Packet-In Format (to controller)
```
[CPU Header (4 bytes)]
  - reason: uint8 (1=deauth, 2=assoc, etc.)
  - orig_port: uint8
  - rf_rssi: int16
[WIDD Frame (as above)]
```

### Packet-Out Format (from controller)
```
[CPU Header (4 bytes)]
  - reason: 0 (PASS)
  - dest_port: uint8 (port 1 = AP eth interface)
  - unused: int16
[Standard 802.11 Management Frame (26 bytes for deauth/disassoc)]
  - Frame Control: 2 bytes (type=0 mgmt, subtype=0xC deauth or 0xA disassoc)
  - Duration: 2 bytes (0x0000)
  - Address 1 (Destination): 6 bytes - target station MAC
  - Address 2 (Source): 6 bytes - AP/BSSID MAC
  - Address 3 (BSSID): 6 bytes - AP/BSSID MAC
  - Sequence Control: 2 bytes
  - Reason Code: 2 bytes (e.g., 3 = "station is leaving")
```

The controller constructs a proper 802.11 management frame without RF features.
The P4 switch forwards this to port 1 (AP eth interface).
The AP Agent sniffs on ap1-eth1, parses the frame, and executes hostapd_cli to disconnect the station.

## References

Based on the research paper:
> Zanna et al. (2022). "Preventing Attacks On Wireless Networks Using SDN-Controlled OODA Loops & Cyber Kill Chains"

## Contributing

When modifying the architecture:
1. Update the relevant `.puml` file
2. Regenerate images
3. Update this README if needed
4. Document any new design patterns or flows
