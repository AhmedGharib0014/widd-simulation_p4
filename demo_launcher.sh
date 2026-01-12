#!/bin/bash
#
# WIDD Multi-Terminal Demo Launcher
#
# Launches multiple xterm windows to visualize the complete WIDD system:
#   - Terminal 1: Mininet-WiFi topology
#   - Terminal 2: OODA Controller (MOCC + KCSM)
#   - Terminal 3: bmv2 Switch Logs (optional)
#   - Terminal 4: Attack Generator CLI (optional)
#
# Usage:
#   sudo ./demo_launcher.sh
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Project directory
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Screen positions (adjust based on your screen resolution)
# Format: geometry WIDTHxHEIGHT+X+Y
TERM1_GEOM="100x30+0+0"       # Top-left: Mininet
TERM2_GEOM="100x30+720+0"     # Top-right: OODA Controller
TERM3_GEOM="100x20+0+500"     # Bottom-left: bmv2 logs
TERM4_GEOM="100x20+720+500"   # Bottom-right: Attack CLI
TERM5_GEOM="80x15+1440+0"     # Far right: Packet monitor (optional)

# XTerm colors and fonts
XTERM_OPTS="-fa 'Monospace' -fs 11 -bg black -fg white"

print_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════════╗"
    echo "║                                                                   ║"
    echo "║   ██╗    ██╗██╗██████╗ ██████╗     ██████╗ ███████╗███╗   ███╗   ║"
    echo "║   ██║    ██║██║██╔══██╗██╔══██╗    ██╔══██╗██╔════╝████╗ ████║   ║"
    echo "║   ██║ █╗ ██║██║██║  ██║██║  ██║    ██║  ██║█████╗  ██╔████╔██║   ║"
    echo "║   ██║███╗██║██║██║  ██║██║  ██║    ██║  ██║██╔══╝  ██║╚██╔╝██║   ║"
    echo "║   ╚███╔███╔╝██║██████╔╝██████╔╝    ██████╔╝███████╗██║ ╚═╝ ██║   ║"
    echo "║    ╚══╝╚══╝ ╚═╝╚═════╝ ╚═════╝     ╚═════╝ ╚══════╝╚═╝     ╚═╝   ║"
    echo "║                                                                   ║"
    echo "║              Multi-Terminal Visualization Demo                    ║"
    echo "╚═══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_requirements() {
    echo -e "${YELLOW}[*] Checking requirements...${NC}"

    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[!] This script must be run as root (sudo)${NC}"
        exit 1
    fi

    # Check for xterm
    if ! command -v xterm &> /dev/null; then
        echo -e "${RED}[!] xterm not found. Install with: sudo apt install xterm${NC}"
        exit 1
    fi

    # Check for Python3
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}[!] python3 not found${NC}"
        exit 1
    fi

    # Check for Mininet-WiFi (optional for simulation mode)
    if ! python3 -c "from mn_wifi.net import Mininet_wifi" 2>/dev/null; then
        echo -e "${YELLOW}[!] Mininet-WiFi not found - will run in simulation mode${NC}"
        SIMULATION_MODE=true
    else
        SIMULATION_MODE=false
    fi

    echo -e "${GREEN}[+] Requirements check passed${NC}"
}

cleanup() {
    echo -e "\n${YELLOW}[*] Cleaning up...${NC}"

    # Kill all xterm windows we started
    pkill -f "xterm.*WIDD" 2>/dev/null || true

    # Kill OODA controller
    pkill -f "ooda_controller" 2>/dev/null || true

    # Kill any running mininet
    mn -c 2>/dev/null || true

    echo -e "${GREEN}[+] Cleanup complete${NC}"
}

# Trap ctrl-c and cleanup
trap cleanup EXIT INT TERM

launch_ooda_controller() {
    echo -e "${BLUE}[*] Launching OODA Controller (MOCC + KCSM)...${NC}"

    # Run the OODA controller directly
    xterm -title "WIDD-OODA-Controller" \
          -geometry $TERM2_GEOM \
          $XTERM_OPTS \
          -fg green \
          -e "cd $PROJECT_DIR && echo '=== WIDD OODA Controller ===' && echo 'Components: MOCC (RF Identification) + KCSM (Kill Chain State Machine)' && echo '' && echo 'Starting in 2 seconds...' && sleep 2 && python3 -m controller.ooda_controller; read -p 'Press Enter to close...'" &

    sleep 3
    echo -e "${GREEN}[+] OODA Controller launched${NC}"
}

launch_mininet_topology() {
    echo -e "${BLUE}[*] Launching Mininet-WiFi Topology...${NC}"

    if [ "$SIMULATION_MODE" = true ]; then
        # Simulation mode - show topology info and run local OODA test
        xterm -title "WIDD-Topology-Simulation" \
              -geometry $TERM1_GEOM \
              $XTERM_OPTS \
              -fg cyan \
              -e "cd $PROJECT_DIR && python3 -c \"
import sys
sys.path.insert(0, '.')

print('=' * 60)
print('  WIDD Network Topology (Simulation Mode)')
print('=' * 60)
print()
print('  Topology:')
print('    sta1 (00:00:00:00:00:01) ─┐')
print('    sta2 (00:00:00:00:00:02) ─┼─ AP ─── Switch ─── Controller')
print('    sta3 (00:00:00:00:00:03) ─┤')
print('    attacker (00:00:00:00:00:99) ─┘')
print()
print('  [!] Mininet-WiFi not available')
print('  [*] Running in SIMULATION mode')
print()
print('  Watch the OODA Controller terminal for:')
print('    - DATA PLANE logs (packet reception)')
print('    - CTRL PLANE logs (OBSERVE/ORIENT/DECIDE/ACT)')
print('    - Attack detection and countermeasures')
print()
print('=' * 60)
input('Press Enter to exit...')
\"; read -p 'Press Enter to close...'" &
    else
        # Real Mininet-WiFi mode - launch topology directly
        xterm -title "WIDD-Mininet-Topology" \
              -geometry $TERM1_GEOM \
              $XTERM_OPTS \
              -fg cyan \
              -e "cd $PROJECT_DIR && python3 -c \"
import sys
sys.path.insert(0, '.')

print('=== WIDD Mininet-WiFi Topology ===')
print('Starting network...')

from topology.widd_topo import create_topology, test_connectivity
from mn_wifi.cli import CLI
from mininet.log import setLogLevel

setLogLevel('info')

net = None
try:
    net = create_topology(use_bmv2=True)
    test_connectivity(net)
    print()
    print('*** Network is ready ***')
    print('*** Type help for commands ***')
    print()
    CLI(net)
except Exception as e:
    print(f'Error: {e}')
    import traceback
    traceback.print_exc()
finally:
    if net:
        print('Stopping network...')
        net.stop()
\"; read -p 'Press Enter to close...'" &
    fi

    echo -e "${GREEN}[+] Topology terminal launched${NC}"
}

launch_switch_monitor() {
    echo -e "${BLUE}[*] Launching Switch Monitor...${NC}"

    # Create a simple switch monitor script
    cat > /tmp/widd_switch_monitor.sh << 'MONITOR_EOF'
#!/bin/bash
echo "=== bmv2 Switch Monitor ==="
echo ""
echo "Monitoring P4 switch activity..."
echo "Looking for bmv2 logs..."
echo ""

# Try to find bmv2 log file
BMV2_LOG="/tmp/bmv2.log"

if [ -f "$BMV2_LOG" ]; then
    echo "Found bmv2 log at $BMV2_LOG"
    tail -f "$BMV2_LOG"
else
    echo "bmv2 log not found. Showing simulated switch activity..."
    echo ""
    echo "┌─────────────────────────────────────────────────────────────┐"
    echo "│                    P4 Switch Status                         │"
    echo "├─────────────────────────────────────────────────────────────┤"
    echo "│  Port 1: sta1-wlan0     │  Port 2: sta2-wlan0              │"
    echo "│  Port 3: sta3-wlan0     │  Port 4: attacker-wlan0          │"
    echo "│  CPU Port: 255          │  Status: ACTIVE                   │"
    echo "└─────────────────────────────────────────────────────────────┘"
    echo ""
    echo "Waiting for packets..."
    echo ""

    # Simulated packet flow
    i=0
    while true; do
        sleep 2
        timestamp=$(date +"%H:%M:%S")
        echo "[$timestamp] Packet processed - Port 1 -> CPU (Management Frame)"
        ((i++))
        if [ $((i % 5)) -eq 0 ]; then
            echo "[$timestamp] Table match: wifi_classify -> send_to_cpu"
        fi
    done
fi
MONITOR_EOF
    chmod +x /tmp/widd_switch_monitor.sh

    xterm -title "WIDD-Switch-Monitor" \
          -geometry $TERM3_GEOM \
          $XTERM_OPTS \
          -fg yellow \
          -e "/tmp/widd_switch_monitor.sh; read -p 'Press Enter to close...'" &

    echo -e "${GREEN}[+] Switch monitor launched${NC}"
}

launch_attack_cli() {
    echo -e "${BLUE}[*] Launching Attack CLI...${NC}"

    xterm -title "WIDD-Attack-CLI" \
          -geometry $TERM4_GEOM \
          $XTERM_OPTS \
          -fg red \
          -e "cd $PROJECT_DIR && python3 interactive_attack.py; read -p 'Press Enter to close...'" &

    echo -e "${GREEN}[+] Attack CLI launched${NC}"
}

launch_packet_monitor() {
    echo -e "${BLUE}[*] Launching Packet Monitor...${NC}"

    # Create packet monitor script
    cat > /tmp/widd_packet_monitor.sh << 'PKT_EOF'
#!/bin/bash
echo "=== Packet Monitor ==="
echo ""
echo "Monitoring network interfaces..."
echo ""

# Find wireless interface or use any
IFACE=$(ip link | grep -E "wlan|wifi" | head -1 | awk -F: '{print $2}' | tr -d ' ')

if [ -z "$IFACE" ]; then
    IFACE="any"
fi

echo "Interface: $IFACE"
echo ""

# Try tcpdump if available
if command -v tcpdump &> /dev/null; then
    echo "Starting tcpdump..."
    tcpdump -i $IFACE -n -l 2>/dev/null || echo "tcpdump failed - may need permissions"
else
    echo "tcpdump not available"
    echo "Install with: sudo apt install tcpdump"
    echo ""
    echo "Showing simulated packet flow..."
    while true; do
        sleep 1
        echo "[$(date +%H:%M:%S)] 00:00:00:00:00:01 -> ff:ff:ff:ff:ff:ff (Beacon)"
    done
fi
PKT_EOF
    chmod +x /tmp/widd_packet_monitor.sh

    xterm -title "WIDD-Packet-Monitor" \
          -geometry $TERM5_GEOM \
          $XTERM_OPTS \
          -fg magenta \
          -e "/tmp/widd_packet_monitor.sh; read -p 'Press Enter to close...'" &

    echo -e "${GREEN}[+] Packet monitor launched${NC}"
}

show_help() {
    echo ""
    echo -e "${CYAN}=== Full Architecture ===${NC}"
    echo ""
    echo "  ┌─────────────────────────┬─────────────────────────┐"
    echo "  │                         │                         │"
    echo "  │   Mininet-WiFi          │   OODA Controller       │"
    echo "  │   (Network + Attacker)  │   (MOCC + KCSM output)  │"
    echo "  │                         │                         │"
    echo "  └─────────────────────────┴─────────────────────────┘"
    echo ""
    echo -e "${YELLOW}Architecture:${NC}"
    echo "  Attacker → Mininet-WiFi → bmv2 Switch → OODA Controller"
    echo ""
    echo -e "${YELLOW}How to use:${NC}"
    echo "  1. Wait for Mininet-WiFi to start (shows 'mininet-wifi>')"
    echo "  2. In Mininet terminal, run attacks from the attacker node:"
    echo ""
    echo -e "${YELLOW}Mininet Commands (in Mininet-WiFi terminal):${NC}"
    echo "  attacker ping sta1              - Test connectivity"
    echo "  attacker python3 -c '...'       - Run attack script"
    echo "  xterm attacker                  - Open attacker shell"
    echo ""
    echo -e "${YELLOW}To send attacks from attacker xterm:${NC}"
    echo "  cd /home/gharib/Desktop/latest_demo"
    echo "  python3 attacks/attack_generator.py"
    echo ""
    echo -e "${GREEN}Press Ctrl+C to stop all terminals and cleanup${NC}"
}

main() {
    print_banner
    check_requirements

    echo ""
    echo -e "${YELLOW}[*] Starting WIDD Demo Environment...${NC}"
    echo ""

    # Launch terminals for full architecture
    # 1. OODA Controller FIRST (must be running before Mininet connects)
    launch_ooda_controller
    sleep 3  # Give controller time to start

    # 2. Mininet-WiFi topology (connects to controller)
    launch_mininet_topology
    sleep 5  # Give network time to start

    # 3. Attack CLI is not needed - attacks are launched from Mininet CLI
    # launch_attack_cli

    # launch_switch_monitor
    # launch_packet_monitor

    show_help

    echo -e "${GREEN}[+] All terminals launched!${NC}"
    echo ""
    echo -e "${CYAN}Demo is running. Press Ctrl+C to stop.${NC}"

    # Wait for user to stop
    while true; do
        sleep 1
    done
}

# Run main
main "$@"
