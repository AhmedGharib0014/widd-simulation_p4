#!/bin/bash
#
# WIDD Demo Launcher - DEPRECATED
#
# ⚠️  This script is deprecated and no longer functional.
#
# The interactive attack CLI now requires real network mode with mininet-wifi,
# and no longer supports the simulation mode that this launcher was designed for.
#
# For real network testing (RECOMMENDED):
#   See NETWORK_SETUP.md for step-by-step instructions
#
# What changed:
#   - interactive_attack.py now sends real packets via Scapy
#   - All attacks go through: Scapy → Mininet-WiFi → BMV2 P4 Switch → OODA Controller
#   - This tests the complete system (no simulation bypass)
#

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Project directory
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Screen positions (adjust based on your screen resolution)
# Format: geometry WIDTHxHEIGHT+X+Y
TERM_CONTROLLER="120x35+0+0"      # Left: OODA Controller
TERM_ATTACKER="100x25+850+0"      # Top-right: Attack CLI
TERM_MONITOR="100x25+850+450"     # Bottom-right: Packet Monitor

# XTerm colors and fonts
XTERM_OPTS="-fa 'Monospace' -fs 10 -bg black"

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
    echo "║              Interactive Attack & Detection Demo                  ║"
    echo "╚═══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_requirements() {
    echo -e "${YELLOW}[*] Checking requirements...${NC}"

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

    echo -e "${GREEN}[+] Requirements check passed${NC}"
}

cleanup() {
    echo -e "\n${YELLOW}[*] Cleaning up...${NC}"

    # Kill all xterm windows we started
    pkill -f "xterm.*WIDD" 2>/dev/null || true

    # Kill Python processes
    pkill -f "start_server" 2>/dev/null || true
    pkill -f "interactive_attack" 2>/dev/null || true
    pkill -f "packet_monitor" 2>/dev/null || true

    echo -e "${GREEN}[+] Cleanup complete${NC}"
}

# Trap ctrl-c and cleanup
trap cleanup EXIT INT TERM

launch_controller() {
    echo -e "${BLUE}[*] Launching OODA Controller (Server Mode)...${NC}"

    xterm -title "WIDD-OODA-Controller" \
          -geometry $TERM_CONTROLLER \
          $XTERM_OPTS \
          -fg green \
          -e "cd $PROJECT_DIR && python3 start_server.py; read -p 'Press Enter to close...'" &

    sleep 3
    echo -e "${GREEN}[+] OODA Controller started (listening on port 9999)${NC}"
}

launch_attacker() {
    echo -e "${RED}[*] Launching Attack CLI...${NC}"

    xterm -title "WIDD-Attack-CLI" \
          -geometry $TERM_ATTACKER \
          $XTERM_OPTS \
          -fg red \
          -e "cd $PROJECT_DIR && python3 interactive_attack.py; read -p 'Press Enter to close...'" &

    sleep 2
    echo -e "${GREEN}[+] Attack CLI launched${NC}"
}

launch_monitor() {
    echo -e "${MAGENTA}[*] Launching Packet Monitor...${NC}"

    xterm -title "WIDD-Packet-Monitor" \
          -geometry $TERM_MONITOR \
          $XTERM_OPTS \
          -fg magenta \
          -e "cd $PROJECT_DIR && python3 packet_monitor.py --simulate; read -p 'Press Enter to close...'" &

    sleep 1
    echo -e "${GREEN}[+] Packet Monitor launched${NC}"
}

show_help() {
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                        DEMO LAYOUT                                ║${NC}"
    echo -e "${CYAN}╠═══════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║                                                                   ║${NC}"
    echo -e "${CYAN}║  ┌─────────────────────┐  ┌─────────────────────┐                ║${NC}"
    echo -e "${CYAN}║  │                     │  │                     │                ║${NC}"
    echo -e "${CYAN}║  │   OODA Controller   │  │    Attack CLI       │                ║${NC}"
    echo -e "${CYAN}║  │   (Green text)      │  │    (Red text)       │                ║${NC}"
    echo -e "${CYAN}║  │                     │  │                     │                ║${NC}"
    echo -e "${CYAN}║  │   Shows:            │  ├─────────────────────┤                ║${NC}"
    echo -e "${CYAN}║  │   - OODA phases     │  │                     │                ║${NC}"
    echo -e "${CYAN}║  │   - MOCC results    │  │   Packet Monitor    │                ║${NC}"
    echo -e "${CYAN}║  │   - KCSM states     │  │   (Magenta text)    │                ║${NC}"
    echo -e "${CYAN}║  │   - Attack alerts   │  │                     │                ║${NC}"
    echo -e "${CYAN}║  │                     │  │                     │                ║${NC}"
    echo -e "${CYAN}║  └─────────────────────┘  └─────────────────────┘                ║${NC}"
    echo -e "${CYAN}║                                                                   ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}HOW TO USE:${NC}"
    echo ""
    echo -e "  1. ${GREEN}OODA Controller${NC} window shows the detection system"
    echo -e "     - Watch for OBSERVE/ORIENT/DECIDE/ACT phases"
    echo -e "     - Green = legitimate traffic, Red = attacks"
    echo ""
    echo -e "  2. ${RED}Attack CLI${NC} window lets you launch attacks"
    echo -e "     - Type 'help' to see available commands"
    echo -e "     - Try: demo1, demo2, demo3, demo4"
    echo -e "     - Or: deauth sta1 5, evil_twin, auth_flood"
    echo ""
    echo -e "  3. ${MAGENTA}Packet Monitor${NC} shows packet flow visualization"
    echo ""
    echo -e "${CYAN}ATTACK COMMANDS:${NC}"
    echo -e "  deauth sta1 5     - Send 5 spoofed deauth frames"
    echo -e "  evil_twin         - Broadcast evil twin beacon"
    echo -e "  auth_flood 12     - Send 12 auth flood frames"
    echo -e "  demo_all          - Run all attack demos automatically"
    echo ""
    echo -e "${GREEN}Press Ctrl+C to stop all terminals and exit${NC}"
}

show_deprecation_notice() {
    echo ""
    echo -e "${RED}╔═══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║                     ⚠️  DEPRECATED SCRIPT ⚠️                       ║${NC}"
    echo -e "${RED}╚═══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}This demo launcher is no longer functional.${NC}"
    echo ""
    echo -e "The WIDD system has been updated to use ${GREEN}Real Network Mode${NC} which tests"
    echo -e "the complete flow through mininet-wifi and bmv2 P4 switch."
    echo ""
    echo -e "${CYAN}Why this change?${NC}"
    echo -e "  • Old: Attack CLI → Socket → Controller ${RED}(bypassed all layers!)${NC}"
    echo -e "  • New: Attack CLI → Scapy → Mininet → BMV2 → Controller ${GREEN}(real flow!)${NC}"
    echo ""
    echo -e "${CYAN}How to run WIDD now:${NC}"
    echo ""
    echo -e "  ${GREEN}Step 1:${NC} Read the setup guide"
    echo -e "          ${BLUE}cat NETWORK_SETUP.md${NC}"
    echo ""
    echo -e "  ${GREEN}Step 2:${NC} Start mininet-wifi topology (Terminal 1)"
    echo -e "          ${BLUE}sudo python3 topology/widd_topo.py${NC}"
    echo ""
    echo -e "  ${GREEN}Step 3:${NC} Start OODA controller (Terminal 2)"
    echo -e "          ${BLUE}python3 run_controller.py${NC}"
    echo ""
    echo -e "  ${GREEN}Step 4:${NC} Launch attack CLI from mininet (Terminal 3)"
    echo -e "          ${BLUE}mininet-wifi> xterm attacker${NC}"
    echo -e "          ${BLUE}python3 interactive_attack.py --interface attacker-wlan0${NC}"
    echo ""
    echo -e "${YELLOW}For complete instructions, see: ${GREEN}NETWORK_SETUP.md${NC}"
    echo ""
}

main() {
    print_banner
    show_deprecation_notice
}

# Run main
main "$@"
