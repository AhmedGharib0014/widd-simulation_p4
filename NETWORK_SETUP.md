# WIDD Network Mode Setup Guide

This guide shows you how to run the **complete real network flow** with mininet-wifi, bmv2 P4 switch, and the OODA controller.

## Architecture Flow

```
┌─────────────────────────────────────────────────────────────┐
│                   COMPLETE REAL FLOW                        │
└─────────────────────────────────────────────────────────────┘

Attack CLI (interactive_attack.py --interface attacker-wlan0)
    ↓
  Scapy sends real 802.11 frames
    ↓
Mininet-WiFi Network (wireless simulation)
    ↓
BMV2 P4 Switch (widd.p4 program)
    - Parses 802.11 frames
    - Extracts RF features
    - Forwards to CPU port 255
    ↓
OODA Controller (run_controller.py)
    - OBSERVE: Parse frames
    - ORIENT: MOCC RF fingerprinting
    - DECIDE: KCSM state machines
    - ACT: Drop/Pass/Countermeasures
```

**NO SIMULATION BYPASS** - Every packet goes through all layers!

## Prerequisites

1. **Mininet-WiFi** installed
2. **bmv2 (P4 behavioral model)** installed
3. **Python 3** with Scapy, Thrift
4. **Root privileges** (for mininet)

## Step-by-Step Setup

### Terminal 1: Start Mininet-WiFi Topology

```bash
cd /home/user/widd-simulation_p4
sudo python3 topology/widd_topo.py
```

**Wait for:**
```
*** Starting network
*** Configuring wifi nodes
*** Starting controller(s)

*** Starting L2 nodes
*** Running CLI
mininet-wifi>
```

The topology creates:
- `ap1`: Access Point (00:11:22:33:44:55)
- `sta1`, `sta2`, `sta3`: Legitimate clients
- `attacker`: Attacker station
- `s1`: BMV2 P4 switch running `widd.p4`

### Terminal 2: Start OODA Controller

```bash
cd /home/user/widd-simulation_p4
python3 run_controller.py
```

**You should see:**
```
╔═══════════════════════════════════════════════════════════════════╗
║   WIDD OODA CONTROLLER                                            ║
╚═══════════════════════════════════════════════════════════════════╝

======================================================================
  CONFIGURATION
======================================================================
  BMV2 Thrift:    127.0.0.1:9090
  CPU Interface:  s1-cpu
  Network SSID:   WIDD_Network
  Network BSSID:  00:11:22:33:44:55
======================================================================

[INFO] Registered client: 00:00:00:00:00:01 (RSSI=-45dBm)
[INFO] Registered client: 00:00:00:00:00:02 (RSSI=-55dBm)
[INFO] Starting OODA loop...
[INFO] Connected to bmv2 at 127.0.0.1:9090
[INFO] Started Packet-In listener on s1-cpu

======================================================================
  OODA CONTROLLER RUNNING
======================================================================
  Listening for packets from P4 switch CPU port...
  Ready to detect attacks!
  Press Ctrl+C to stop
======================================================================
```

### Terminal 3: Launch Attack CLI (from Mininet)

Back in Terminal 1 (mininet CLI):

```bash
mininet-wifi> xterm attacker
```

In the new attacker terminal:

```bash
cd /home/user/widd-simulation_p4
python3 interactive_attack.py --interface attacker-wlan0
```

**You should see:**
```
╔═══════════════════════════════════════════════════════════════════╗
║              WIDD Attack Console - Network Mode                   ║
╚═══════════════════════════════════════════════════════════════════╝

  Initializing attack generator...
  [+] Network interface: attacker-wlan0
  [+] Attack packets will be sent via Scapy
  [*] Target AP: 00:11:22:33:44:55
  [*] Attacker MAC: 00:00:00:00:00:99

[NETWORK] attack>
```

## Running Attacks

### Example 1: Deauth Attack

In the Attack CLI:
```bash
[NETWORK] attack> deauth sta1 5
```

**In Terminal 2 (OODA Controller), you'll see:**
```
[SWITCH] PACKET-IN: DEAUTH from 00:00:00:00:00:01 port=1 rssi=-70
[OBSERVE] Frame: DEAUTH, Source: 00:00:00:00:00:01
[ORIENT-MOCC] Device: 00:00:00:00:00:01, Probability: 0.05, MISMATCH!
[DECIDE-KCSM] DEAUTH, State: 1, Attack: False
[ACT] DROP: Spoofed frame (RF mismatch)

[SWITCH] PACKET-IN: DEAUTH from 00:00:00:00:00:01 port=1 rssi=-70
[OBSERVE] Frame: DEAUTH, Source: 00:00:00:00:00:01
[ORIENT-MOCC] Device: 00:00:00:00:00:01, Probability: 0.05, MISMATCH!
[DECIDE-KCSM] DEAUTH, State: 2, ATTACK DETECTED: DEAUTH
[ACT] DROP: Spoofed frame (RF mismatch)
[ACT] COUNTERMEASURE: INJECT_FALSE_HANDSHAKE -> 00:00:00:00:00:01
[ACT] ALERT: DEAUTH - Client 00:00:00:00:00:01 under attack!
```

### Example 2: Evil Twin

```bash
[NETWORK] attack> evil_twin
```

**Expected Detection:**
```
[SWITCH] PACKET-IN: BEACON from AA:BB:CC:DD:EE:FF
[OBSERVE] Frame: BEACON, Source: AA:BB:CC:DD:EE:FF
[DECIDE-KCSM] EVIL_TWIN detected: Same SSID, different BSSID!
[ACT] ALERT: EVIL_TWIN - Rogue AP detected!
```

### Example 3: Auth Flood

```bash
[NETWORK] attack> auth_flood 12
```

**Expected Detection:**
```
[SWITCH] PACKET-IN: AUTH from 3a:5f:...
[OBSERVE] Frame: AUTH
[DECIDE-KCSM] AUTH_FLOOD detected: 12 frames > 10 threshold
[ACT] ALERT: AUTH_FLOOD - Flooding attack detected!
```

## Available Commands

### Attack Commands
- `deauth <victim> [count]` - Deauth attack (e.g., `deauth sta1 5`)
- `disassoc <victim> [count]` - Disassociation attack
- `evil_twin` - Broadcast rogue AP beacon
- `auth_flood [count]` - Authentication flood (default: 12)
- `assoc_flood [count]` - Association flood

### Legitimate Traffic
- `data <client> [count]` - Send legitimate data frames
- `train <client>` - Train MOCC with 100 frames

### Demo Scenarios
- `demo1` - Single spoofed deauth
- `demo2` - Full deauth attack (triggers KCSM)
- `demo3` - Evil Twin detection
- `demo4` - Auth flood attack
- `demo_all` - Run all demos in sequence

### System Commands
- `clients` - Show registered devices
- `interface` - Show network configuration
- `help` - Show all commands
- `quit` - Exit

## Verification Checklist

✅ **Mininet topology running** - Check Terminal 1 shows `mininet-wifi>` prompt

✅ **BMV2 switch compiled** - `widd.json` exists in `p4/` directory

✅ **OODA controller connected** - Terminal 2 shows "Connected to bmv2"

✅ **CPU port listener active** - Terminal 2 shows "Started Packet-In listener"

✅ **Attack CLI ready** - Terminal 3 shows `[NETWORK] attack>` prompt

✅ **Packets flowing** - When you send attacks, Terminal 2 shows PACKET-IN messages

## Troubleshooting

### "Failed to connect to bmv2"
- Check mininet topology is running
- Verify bmv2 thrift port (default: 9090)
- Try: `netstat -tuln | grep 9090`

### "No such device: attacker-wlan0"
- Check mininet created the attacker station
- In mininet CLI: `nodes`
- Try: `ip link show` inside attacker xterm

### "Permission denied (Scapy)"
- Run attack CLI as root or with capabilities
- Inside attacker xterm: `sudo python3 interactive_attack.py --interface attacker-wlan0`

### "No PACKET-IN messages"
- Verify P4 program is loaded on switch
- Check CPU port interface exists
- Try: `ip link show s1-cpu`

## Architecture Notes

### Why This Is Better Than Simulation Mode

**OLD (Simulation with start_server.py):**
```
Attack CLI → Socket (9999) → SimulationServer → controller.simulate_frame()
                                    ↓
                      (BYPASSES EVERYTHING!)
```
❌ Skips network layer
❌ Skips P4 switch
❌ Skips packet-in processing
❌ Just calls Python method directly

**NEW (Real Network with run_controller.py):**
```
Attack CLI → Scapy → Mininet-WiFi → BMV2 Switch → CPU Port → OODA Controller
```
✅ Tests complete system
✅ Real P4 program execution
✅ Real packet parsing
✅ Real network latency
✅ Production-like environment

## Next Steps

After successful testing:

1. **Add more clients** - Register additional MAC addresses
2. **Tune thresholds** - Adjust MOCC/KCSM parameters
3. **Test countermeasures** - Verify packet injection works
4. **Performance testing** - Measure detection latency
5. **Real hardware** - Deploy to actual WiFi hardware

## References

- **Paper**: Zanna et al. (2022) - WIDD system design
- **P4 Spec**: p4/widd.p4 - Data plane program
- **MOCC Algorithm**: controller/mocc.py - RF fingerprinting
- **KCSM**: controller/kcsm.py - Kill chain state machines
