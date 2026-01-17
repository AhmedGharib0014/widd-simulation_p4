#!/bin/bash
#
# WIDD Multi-Terminal Demo Launcher
#
# Launches multiple xterm windows to visualize the complete WIDD system:
#   - Terminal 0: Mininet-WiFi Network (with bmv2 P4 switch)
#   - Terminal 1: OODA Controller (MOCC + KCSM) in server mode
#   - Terminal 2: Attack CLI (interactive attack console)
#   - Terminal 3: Packet Monitor (real-time flow visualization)
#
# Usage:
#   ./demo_launcher.sh              # Smart mode (auto-detects if P4 needs recompilation)
#   ./demo_launcher.sh --force-p4   # Force P4 recompilation
#

# Project directory
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# PID file for Mininet process
MININET_PID_FILE="/tmp/widd_mininet.pid"

# Screen positions (adjust based on your screen resolution)
# Format: geometry WIDTHxHEIGHT+X+Y
TERM_MININET="80x20+0+0"         # Top-left: Mininet Network
TERM_CONTROLLER="80x30+0+350"    # Bottom-left: OODA Controller
TERM_ATTACKER="80x30+950+0"      # Top-right: Attack CLI
TERM_MONITOR="80x30+950+350"     # Bottom-right: Packet Monitor

# XTerm colors and fonts - all terminals use the same settings
XTERM_OPTS="-fa 'Monospace' -fs 7 -bg black -fg white"

cleanup() {
    echo "[*] Cleaning up..."

    # Kill all xterm windows we started
    pkill -f "xterm.*WIDD" 2>/dev/null || true

    # Kill Python processes
    pkill -f "start_server" 2>/dev/null || true
    pkill -f "interactive_attack" 2>/dev/null || true
    pkill -f "packet_monitor" 2>/dev/null || true

    # Clean up Mininet network
    echo "[*] Stopping Mininet network..."
    if [ -f "$MININET_PID_FILE" ]; then
        MININET_PID=$(cat "$MININET_PID_FILE")
        if ps -p "$MININET_PID" > /dev/null 2>&1; then
            sudo kill -TERM "$MININET_PID" 2>/dev/null || true
            sleep 2
            sudo kill -9 "$MININET_PID" 2>/dev/null || true
        fi
        rm -f "$MININET_PID_FILE"
    fi

    # Cleanup Mininet resources
    sudo mn -c 2>/dev/null || true

    # Kill bmv2 switch processes
    sudo pkill -f "simple_switch" 2>/dev/null || true

    echo "[+] Cleanup complete"

    # Exit the script completely
    exit 0
}

# Trap ctrl-c and cleanup
trap cleanup EXIT INT TERM

compile_p4() {
    echo "[*] Checking P4 program..."

    P4_SOURCE="$PROJECT_DIR/p4/widd.p4"
    P4_JSON="$PROJECT_DIR/p4/widd.json"

    # Check if JSON exists and is newer than source
    if [ -f "$P4_JSON" ] && [ "$P4_JSON" -nt "$P4_SOURCE" ]; then
        echo "[+] P4 JSON is up to date (no recompilation needed)"
        return 0
    fi

    echo "[*] Compiling P4 program..."

    # Check if P4 compiler is available
    if ! command -v p4c &> /dev/null && ! command -v p4c-bm2-ss &> /dev/null; then
        echo "[ERROR] P4 compiler (p4c or p4c-bm2-ss) not found!"
        echo "        Install with: sudo apt install p4lang-bmv2 p4lang-p4c"
        exit 1
    fi

    # Compile P4 to JSON
    cd "$PROJECT_DIR/p4"
    if make 2>&1 | tee /tmp/p4_compile.log; then
        echo "[+] P4 program compiled successfully"

        # Verify JSON was created
        if [ ! -f "$P4_JSON" ]; then
            echo "[ERROR] widd.json not found after compilation!"
            echo "        Check /tmp/p4_compile.log for errors"
            exit 1
        fi
    else
        echo "[ERROR] P4 compilation failed! Check /tmp/p4_compile.log"
        exit 1
    fi

    cd "$PROJECT_DIR"
}

launch_mininet() {
    echo "[*] Launching Mininet-WiFi network with bmv2 P4 switch..."

    # Check if running as root or with sudo
    if [ "$EUID" -ne 0 ]; then
        echo "[*] Mininet requires sudo privileges..."
    fi

    # Clean up any previous Mininet instances
    sudo mn -c 2>/dev/null || true

    # Launch Mininet in an xterm window
    xterm -title "WIDD-Mininet-Network" \
          -geometry $TERM_MININET \
          $XTERM_OPTS \
          -e "cd $PROJECT_DIR && sudo python3 topology/widd_topo.py; read -p 'Press Enter to close...'" &

    MININET_PID=$!
    echo $MININET_PID > "$MININET_PID_FILE"

    echo "[+] Mininet network starting (PID: $MININET_PID)..."
    echo "[*] Waiting for network to initialize (15 seconds)..."

    # Wait for network to be ready
    for i in {10..1}; do
        echo -ne "    $i seconds remaining...\r"
        sleep 1
    done
    echo ""

    echo "[+] Mininet network is running and ready!"
    echo "[*] Note: Attack CLI will run inside the attacker's network namespace"
}

launch_controller() {
    echo "[*] Launching OODA Controller (Server Mode)..."

    xterm -title "WIDD-OODA-Controller" \
          -geometry $TERM_CONTROLLER \
          $XTERM_OPTS \
          -e "cd $PROJECT_DIR && sudo python3 start_server.py; read -p 'Press Enter to close...'" &

    sleep 2
    echo "[+] OODA Controller started (requires sudo for packet capture)"
}

launch_attacker() {
    echo "[*] Launching Attack CLI (via attacker wireless interface)..."

    # The attacker sends frames through the AP's wireless interface
    # TC mirroring on the AP captures and forwards to the switch
    ATTACK_IFACE="attacker-wlan0"

    echo "[*] Attack interface: $ATTACK_IFACE (through AP with tc mirroring)"

    # Mininet-WiFi creates station interfaces in the station's PID namespace
    # We need to find the attacker station's PID and use mnexec to run commands
    echo "[*] Waiting for attacker station PID..."

    ATTACKER_PID=""
    for i in {1..3}; do
        # Find the attacker station process - Mininet creates a bash process for each station
        ATTACKER_PID=$(pgrep -f "mininet:attacker" 2>/dev/null | head -1)
        if [ -n "$ATTACKER_PID" ]; then
            echo "[+] Found attacker station PID: $ATTACKER_PID"
            break
        fi
        sleep 1
    done

    if [ -z "$ATTACKER_PID" ]; then
        echo "[!] Warning: Could not find attacker station PID"
        echo "[*] Mininet processes:"
        pgrep -a mininet 2>/dev/null | head -5 || echo "  (none found)"
        echo "[*] Falling back to direct interface access..."
    fi

    # Launch attack CLI using mnexec to enter the attacker's namespace
    if [ -n "$ATTACKER_PID" ]; then
        # Use mnexec to run in the attacker's namespace
        xterm -title "WIDD-Attack-CLI" \
              -geometry $TERM_ATTACKER \
              $XTERM_OPTS \
              -e "cd $PROJECT_DIR && sudo mnexec -a $ATTACKER_PID python3 interactive_attack.py --interface $ATTACK_IFACE; read -p 'Press Enter to close...'" &
    else
        # Fallback: try direct access (interface might be in root namespace)
        xterm -title "WIDD-Attack-CLI" \
              -geometry $TERM_ATTACKER \
              $XTERM_OPTS \
              -e "cd $PROJECT_DIR && sudo python3 interactive_attack.py --interface $ATTACK_IFACE; read -p 'Press Enter to close...'" &
    fi

    sleep 2
    echo "[+] Attack CLI launched (sending frames via $ATTACK_IFACE)"
}

launch_monitor() {
    echo "[*] Launching Packet Monitor..."

    xterm -title "WIDD-Packet-Monitor" \
          -geometry $TERM_MONITOR \
          $XTERM_OPTS \
          -e "cd $PROJECT_DIR && python3 packet_monitor.py; read -p 'Press Enter to close...'" &

    sleep 1
    echo "[+] Packet Monitor launched (listening for events)"
}

check_prerequisites() {
    echo "[*] Checking prerequisites..."

    # Check for required commands
    local missing_deps=()

    if ! command -v xterm &> /dev/null; then
        missing_deps+=("xterm")
    fi

    if ! command -v simple_switch &> /dev/null; then
        missing_deps+=("simple_switch (bmv2)")
    fi

    if ! python3 -c "import mn_wifi" 2>/dev/null; then
        missing_deps+=("mininet-wifi (pip3 install mininet-wifi)")
    fi

    if ! python3 -c "import scapy" 2>/dev/null; then
        missing_deps+=("scapy (pip3 install scapy)")
    fi

    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo "[ERROR] Missing dependencies:"
        for dep in "${missing_deps[@]}"; do
            echo "  - $dep"
        done
        exit 1
    fi

    echo "[+] All prerequisites satisfied"
}

main() {
    echo ""
    echo "========================================"
    echo "  WIDD Interactive Demo Launcher"
    echo "========================================"
    echo ""

    # Parse command line arguments
    FORCE_P4_COMPILE=false
    if [[ "$*" == *"--force-p4"* ]]; then
        FORCE_P4_COMPILE=true
        echo "[*] Forcing P4 recompilation (--force-p4 flag)"
    fi

    # Check prerequisites
    check_prerequisites

    # Compile P4 program (smart compilation - only if needed)
    if [ "$FORCE_P4_COMPILE" = true ]; then
        # Force recompilation by removing JSON first
        rm -f "$PROJECT_DIR/p4/widd.json"
        compile_p4
    else
        # Smart compilation - only recompile if source changed
        compile_p4
    fi



    # Launch Mininet network FIRST (creates interfaces)
    launch_mininet

    # Give Mininet extra time to fully stabilize
    echo "[*] Waiting for Mininet network to stabilize (5 seconds)..."
    sleep 5

    # Launch OODA Controller AFTER network is ready
    launch_controller

    # Give controller time to start listening
    echo "[*] Waiting for OODA Controller to initialize (3 seconds)..."
    sleep 3

    launch_monitor

    # Launch monitoring and attack terminals
    launch_attacker
  

    echo ""
    echo "========================================"
    echo "  All components launched!"
    echo "========================================"
    echo "Press Ctrl+C to stop all components."
    echo ""

    # Wait for user to stop
    while true; do
        sleep 1
    done
}

# Run main
main "$@"