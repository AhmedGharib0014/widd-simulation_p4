# WIDD System Architecture Documentation

This directory contains UML diagrams documenting the WIDD (Wireless Intrusion Detection & Defense) system architecture.

## Diagrams

### 1. Component Diagram (`component_diagram.puml`)
**High-level system architecture** showing the major components and their interactions:

- **Data Plane**: P4 switch for 802.11 frame processing
- **Control Plane**: OODA controller with MOCC and KCSM detection algorithms
- **Attack Simulation**: Tools for testing the system
- **Demo/Visualization**: Real-time monitoring and CLI interface
- **Network Layer**: Mininet-WiFi topology

**View this diagram to understand:**
- How packets flow through the system
- Communication protocols between components (Thrift, sockets, WiFi)
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
- **Switch Interface**: BMV2 Thrift API wrapper for P4 switch control
- **Attack Generation**: Scapy-based attack simulation tools
- **Simulation & Demo**: Socket-based server for interactive demos
- **Logging System**: Comprehensive color-coded logging

**View this diagram to understand:**
- Class hierarchies and composition
- Data models (RFFeatures, ClientState, ParsedFrame, etc.)
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
Packet-In → OBSERVE (parse) → ORIENT (MOCC) → DECIDE (KCSM) → ACT (drop/inject)
```

### 2. State Machine Pattern
Each attack type has a dedicated state machine tracking attack progression over time with 2-second timeout windows.

### 3. Strategy Pattern
MOCC uses Gaussian probability calculation to identify legitimate vs spoofed frames based on RF signatures.

### 4. Observer Pattern
Logger observes all controller events for real-time visualization and debugging.

### 5. Facade Pattern
SimulationServer provides a simplified interface for external attack tools and monitors.

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
       │ Packet-In
       ▼
┌─────────────────┐
│ OBSERVE Phase   │  Parse frame structure
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
│ ACT Phase       │  • Drop spoofed frames
│                 │  • Inject false handshakes
│                 │  • Alert administrator
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

## References

Based on the research paper:
> Zanna et al. (2022). "Preventing Attacks On Wireless Networks Using SDN-Controlled OODA Loops & Cyber Kill Chains"

## Contributing

When modifying the architecture:
1. Update the relevant `.puml` file
2. Regenerate images
3. Update this README if needed
4. Document any new design patterns or flows
