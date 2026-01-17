#!/usr/bin/env python3
"""
WIDD Interactive Attack CLI

A colorful command-line interface for launching attacks using Scapy.

This CLI sends WIDD-formatted frames (Ethernet + 802.11 headers + RF features)
directly to the P4 switch interface for processing by the OODA Controller.

The frames simulate what an AP would produce after capturing real 802.11 frames
and encapsulating them in WIDD Ethernet format.

Usage:
    sudo python3 interactive_attack.py --interface s1-eth1
"""

import sys
import os
import time
import argparse
import readline  # For command history
from datetime import datetime

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from attacks.attack_generator import AttackGenerator

# ANSI Colors
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[35m'
    WHITE = '\033[97m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'


def colored(text, color):
    return f"{color}{text}{Colors.ENDC}"


def print_banner():
    banner = """
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║     █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗            ║
║    ██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝            ║
║    ███████║   ██║      ██║   ███████║██║     █████╔╝             ║
║    ██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗             ║
║    ██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗            ║
║    ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝            ║
║                                                                   ║
║          WIDD Attack Console - Direct Injection Mode              ║
║       Sends WIDD frames directly to P4 switch for detection       ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
"""
    print(colored(banner, Colors.RED))


def print_help():
    help_text = """
┌─────────────────────────────────────────────────────────────────────┐
│                        AVAILABLE COMMANDS                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ATTACKS (sent via Scapy to network):                               │
│    deauth <victim> [count]    - Deauth attack spoofing victim MAC   │
│    disassoc <victim> [count]  - Disassociation attack               │
│    evil_twin                  - Broadcast evil twin beacon          │
│    auth_flood [count]         - Authentication request flood        │
│    assoc_flood [count]        - Association request flood           │
│                                                                     │
│  LEGITIMATE TRAFFIC:                                                │
│    data <client> [count]      - Send legitimate data frames         │
│    train <client>             - Send 100 data frames for training   │
│                                                                     │
│  DEMO SCENARIOS:                                                    │
│    demo1                      - Single spoofed deauth               │
│    demo2                      - Full deauth attack (triggers KCSM)  │
│    demo3                      - Evil Twin detection                 │
│    demo4                      - Auth flood attack                   │
│    demo_all                   - Run all demos in sequence           │
│                                                                     │
│  SYSTEM:                                                            │
│    clients                    - Show registered clients             │
│    interface                  - Show current network interface      │
│    clear                      - Clear screen                        │
│    help                       - Show this help                      │
│    quit / exit                - Exit the CLI                        │
│                                                                     │
│  NOTE: Check the OODA Controller terminal for detection results!   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
"""
    print(colored(help_text, Colors.CYAN))


def print_clients():
    clients_text = """
┌─────────────────────────────────────────────────────────────────────┐
│                      NETWORK DEVICES                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  LEGITIMATE CLIENTS (RF signatures trained):                        │
│    sta1    00:00:00:00:00:01    RSSI: -45 dBm    [TRAINED]          │
│    sta2    00:00:00:00:00:02    RSSI: -55 dBm    [REGISTERED]       │
│                                                                     │
│  ACCESS POINT:                                                      │
│    ap1     00:11:22:33:44:55    SSID: WIDD_Network                  │
│                                                                     │
│  ATTACKER (you):                                                    │
│    evil    00:00:00:00:00:99    RSSI: -70 dBm    [DIFFERENT RF!]    │
│                                                                     │
│  NOTE: Spoofed frames use YOUR RF signature, which won't match     │
│        the victim's trained signature - this is how MOCC detects!  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
"""
    print(colored(clients_text, Colors.YELLOW))


class InteractiveAttackCLI:
    def __init__(self, interface: str = None):
        self.interface = interface
        self.attack_gen = None

        # Client MAC shortcuts
        self.clients = {
            'sta1': '00:00:00:00:00:01',
            'sta2': '00:00:00:00:00:02',
            'ap': '00:11:22:33:44:55',
        }

        self.attacker_mac = '00:00:00:00:00:99'
        self.wap_mac = '00:11:22:33:44:55'
        self.wap_bssid = '00:11:22:33:44:55'

    def initialize(self):
        """Initialize the attack generator."""
        if not self.interface:
            print(colored("\n  ERROR: Network interface is required!", Colors.RED + Colors.BOLD))
            print(colored("  This CLI sends real 802.11 packets through mininet-wifi.", Colors.YELLOW))
            print(colored("  Usage: python3 interactive_attack.py --interface <iface>\n", Colors.DIM))
            print(colored("  Example interfaces:", Colors.CYAN))
            print(colored("    - attacker-wlan0 (mininet-wifi attacker station)", Colors.WHITE))
            print(colored("    - wlan0 (physical wireless adapter)", Colors.WHITE))
            print()
            sys.exit(1)

        # Check if interface exists
        import subprocess
        try:
            result = subprocess.run(['ip', 'link', 'show', self.interface],
                                  capture_output=True, text=True, timeout=2)
            if result.returncode != 0:
                print(colored(f"\n  ERROR: Network interface '{self.interface}' not found!", Colors.RED + Colors.BOLD))
                print(colored(f"  The mininet-wifi network may not be running yet.", Colors.YELLOW))
                print(colored(f"\n  To fix this:", Colors.CYAN))
                print(colored(f"    1. Make sure the Mininet network is running", Colors.WHITE))
                print(colored(f"    2. Check the Mininet terminal for errors", Colors.WHITE))
                print(colored(f"    3. Verify interface exists with: ip link show", Colors.WHITE))
                print()
                sys.exit(1)
        except Exception as e:
            print(colored(f"\n  WARNING: Could not verify interface: {e}", Colors.YELLOW))

        self.attack_gen = AttackGenerator(
            interface=self.interface,
            wap_mac=self.wap_mac,
            wap_bssid=self.wap_bssid
        )

        print(colored(f"  [+] Network interface: {self.interface}", Colors.GREEN))
        print(colored(f"  [+] Sending real 802.11 packets via Scapy", Colors.GREEN))
        print(colored(f"  [*] Target AP: {self.wap_mac}", Colors.CYAN))
        print(colored(f"  [*] Attacker MAC: {self.attacker_mac}", Colors.CYAN))

    def resolve_mac(self, name_or_mac):
        """Resolve client name to MAC address."""
        if name_or_mac.lower() in self.clients:
            return self.clients[name_or_mac.lower()]
        return name_or_mac

    def log_attack(self, attack_type, target=None, count=1):
        """Log an attack with timestamp."""
        timestamp = datetime.now().strftime('%H:%M:%S')
        target_str = f" -> {target}" if target else ""

        print(colored(f"\n[{timestamp}] ", Colors.DIM) +
              colored(f"SENDING: {attack_type}", Colors.RED + Colors.BOLD) +
              colored(f"{target_str} x{count}", Colors.YELLOW))

    def show_sent(self, count: int, attack_type: str):
        """Display confirmation of sent packets."""
        print(colored(f"\n  ✓ Sent {count} {attack_type} frames via {self.interface or 'N/A'}",
                     Colors.GREEN))
        print(colored(f"  → Check OODA Controller terminal for detection results", Colors.CYAN))

    def cmd_deauth(self, args):
        """Send deauthentication attack."""
        if len(args) < 1:
            print(colored("Usage: deauth <victim> [count]", Colors.YELLOW))
            print(colored("Example: deauth sta1 5", Colors.DIM))
            return

        victim = self.resolve_mac(args[0])
        count = int(args[1]) if len(args) > 1 else 3

        self.log_attack("SPOOFED DEAUTH", victim, count)

        print(colored("\n  Spoofing as: ", Colors.WHITE) +
              colored(victim, Colors.CYAN))
        print(colored("  Your RF sig: ", Colors.WHITE) +
              colored(self.attacker_mac, Colors.RED) +
              colored(" (won't match!)", Colors.DIM))

        # Send via Scapy
        sent = self.attack_gen.deauth_attack(
            victim_mac=victim,
            count=count,
            interval=0.1,
            spoof=True
        )

        self.show_sent(sent, "deauth")

    def cmd_disassoc(self, args):
        """Send disassociation attack."""
        if len(args) < 1:
            print(colored("Usage: disassoc <victim> [count]", Colors.YELLOW))
            return

        victim = self.resolve_mac(args[0])
        count = int(args[1]) if len(args) > 1 else 3

        self.log_attack("SPOOFED DISASSOC", victim, count)

        # Send via Scapy
        self.attack_gen.disassoc_attack(
            victim_mac=victim,
            count=count,
            interval=0.1
        )

        self.show_sent(count, "disassoc")

    def cmd_evil_twin(self, args):
        """Broadcast evil twin beacon."""
        self.log_attack("EVIL TWIN BEACON", "SSID: WIDD_Network", 10)

        print(colored("\n  Rogue BSSID: ", Colors.WHITE) +
              colored("AA:BB:CC:DD:EE:FF", Colors.RED))
        print(colored("  Same SSID:   ", Colors.WHITE) +
              colored("WIDD_Network", Colors.YELLOW))

        # Send via Scapy
        self.attack_gen.evil_twin_beacon(
            ssid='WIDD_Network',
            count=10,
            interval=0.1
        )

        self.show_sent(10, "evil twin beacon")

    def cmd_auth_flood(self, args):
        """Send authentication flood."""
        count = int(args[0]) if len(args) > 0 else 12

        self.log_attack("AUTH FLOOD", "AP", count)

        print(colored("\n  Flooding with random source MACs...", Colors.WHITE))

        # Send via Scapy
        self.attack_gen.auth_flood(
            count=count,
            interval=0.001
        )

        self.show_sent(count, "auth flood")

    def cmd_assoc_flood(self, args):
        """Send association flood."""
        count = int(args[0]) if len(args) > 0 else 12

        self.log_attack("ASSOC FLOOD", "AP", count)

        print(colored("\n  Flooding with random source MACs...", Colors.WHITE))

        # Send via Scapy
        self.attack_gen.assoc_flood(
            count=count,
            interval=0.001
        )

        self.show_sent(count, "assoc flood")

    def cmd_data(self, args):
        """Send legitimate data frames for training."""
        if len(args) < 1:
            print(colored("Usage: data <client> [count]", Colors.YELLOW))
            return

        client = self.resolve_mac(args[0])
        count = int(args[1]) if len(args) > 1 else 10

        timestamp = datetime.now().strftime('%H:%M:%S')
        print(colored(f"\n[{timestamp}] ", Colors.DIM) +
              colored("SENDING: LEGITIMATE DATA", Colors.GREEN + Colors.BOLD) +
              colored(f" from {client} x{count}", Colors.WHITE))

        # Send via Scapy with legitimate RF characteristics
        self.attack_gen.generate_legitimate_data(
            client_mac=client,
            count=count,
            rssi=-50,  # Use client's expected RSSI
            phase=200,
            pilot=100,
            mag=2000
        )

        print(colored(f"\n  ✓ Sent {count} data frames for MOCC training", Colors.GREEN))

    def cmd_train(self, args):
        """Train MOCC with data frames."""
        if len(args) < 1:
            print(colored("Usage: train <client>", Colors.YELLOW))
            return

        client = self.resolve_mac(args[0])
        print(colored(f"\n  Training MOCC with 100 frames from {client}...", Colors.CYAN))

        self.attack_gen.generate_legitimate_data(
            client_mac=client,
            count=100,
            rssi=-50,
            phase=200,
            pilot=100,
            mag=2000
        )

        print(colored(f"  ✓ MOCC training complete for {client}", Colors.GREEN))

    def cmd_interface(self, args):
        """Show current interface."""
        print(colored("\n┌─────────────────────────────────────────┐", Colors.CYAN))
        print(colored("│         NETWORK CONFIGURATION           │", Colors.CYAN + Colors.BOLD))
        print(colored("├─────────────────────────────────────────┤", Colors.CYAN))
        print(colored(f"│  Interface:  {self.interface or 'None (dry-run mode)':20}      │", Colors.WHITE))
        print(colored(f"│  Target AP:  {self.wap_mac:20}      │", Colors.WHITE))
        print(colored(f"│  Attacker:   {self.attacker_mac:20}      │", Colors.WHITE))
        print(colored("└─────────────────────────────────────────┘", Colors.CYAN))

    def cmd_demo1(self, args):
        """Demo 1: Single spoofed deauth."""
        print(colored("\n" + "="*60, Colors.YELLOW))
        print(colored("  DEMO 1: Single Spoofed Deauth Frame", Colors.YELLOW + Colors.BOLD))
        print(colored("="*60, Colors.YELLOW))
        print(colored("\n  Sending ONE spoofed deauth frame via network.", Colors.WHITE))
        print(colored("  The OODA Controller will:", Colors.WHITE))
        print(colored("    1. OBSERVE - Receive frame from P4 switch", Colors.CYAN))
        print(colored("    2. ORIENT  - MOCC checks RF signature (MISMATCH!)", Colors.YELLOW))
        print(colored("    3. DECIDE  - KCSM updates state, decides DROP", Colors.RED))
        print(colored("    4. ACT     - Frame dropped (no alert yet, just 1 frame)", Colors.MAGENTA))
        input(colored("\n  Press Enter to attack...", Colors.DIM))

        self.cmd_deauth(['sta1', '1'])

    def cmd_demo2(self, args):
        """Demo 2: Full deauth attack."""
        print(colored("\n" + "="*60, Colors.RED))
        print(colored("  DEMO 2: Full Deauth Attack (Triggers KCSM!)", Colors.RED + Colors.BOLD))
        print(colored("="*60, Colors.RED))
        print(colored("\n  Sending 5 rapid spoofed deauth frames via network.", Colors.WHITE))
        print(colored("  After 2 spoofed frames, KCSM triggers ATTACK ALERT!", Colors.RED))
        print(colored("  Countermeasure: False handshake injection activated", Colors.MAGENTA))
        input(colored("\n  Press Enter to attack...", Colors.DIM))

        self.cmd_deauth(['sta1', '5'])

    def cmd_demo3(self, args):
        """Demo 3: Evil twin detection."""
        print(colored("\n" + "="*60, Colors.MAGENTA))
        print(colored("  DEMO 3: Evil Twin AP Attack", Colors.MAGENTA + Colors.BOLD))
        print(colored("="*60, Colors.MAGENTA))
        print(colored("\n  Broadcasting beacon with:", Colors.WHITE))
        print(colored("    SSID: WIDD_Network (same as legitimate)", Colors.YELLOW))
        print(colored("    BSSID: AA:BB:CC:DD:EE:FF (DIFFERENT from AP!)", Colors.RED))
        print(colored("  KCSM detects SSID match + BSSID mismatch = EVIL TWIN!", Colors.RED))
        input(colored("\n  Press Enter to attack...", Colors.DIM))

        self.cmd_evil_twin([])

    def cmd_demo4(self, args):
        """Demo 4: Auth flood attack."""
        print(colored("\n" + "="*60, Colors.BLUE))
        print(colored("  DEMO 4: Authentication Flood Attack", Colors.BLUE + Colors.BOLD))
        print(colored("="*60, Colors.BLUE))
        print(colored("\n  Flooding AP with 12 auth requests via network.", Colors.WHITE))
        print(colored("  KCSM threshold: 10 frames in 2 seconds", Colors.YELLOW))
        print(colored("  After threshold, AUTH_FLOOD attack detected!", Colors.RED))
        input(colored("\n  Press Enter to attack...", Colors.DIM))

        self.cmd_auth_flood(['12'])

    def cmd_demo_all(self, args):
        """Run all demos in sequence."""
        print(colored("\n" + "="*60, Colors.CYAN))
        print(colored("  RUNNING ALL DEMOS", Colors.CYAN + Colors.BOLD))
        print(colored("="*60, Colors.CYAN))

        demos = [
            ('Demo 1: Single Spoofed Deauth', lambda: self.cmd_deauth(['sta1', '1'])),
            ('Demo 2: Full Deauth Attack', lambda: self.cmd_deauth(['sta1', '5'])),
            ('Demo 3: Evil Twin', lambda: self.cmd_evil_twin([])),
            ('Demo 4: Auth Flood', lambda: self.cmd_auth_flood(['12'])),
        ]

        for name, func in demos:
            print(colored(f"\n{'='*50}", Colors.YELLOW))
            print(colored(f"  {name}", Colors.YELLOW + Colors.BOLD))
            print(colored(f"{'='*50}", Colors.YELLOW))
            time.sleep(1)
            func()
            print(colored("\n  [Waiting 3 seconds for KCSM reset...]", Colors.DIM))
            time.sleep(3)

        print(colored("\n  ALL DEMOS COMPLETE!", Colors.GREEN + Colors.BOLD))

    def run(self):
        """Main CLI loop."""
        print_banner()

        print(colored("\n  Initializing attack generator...", Colors.CYAN))
        self.initialize()

        print_help()

        print(colored("\nType 'help' for commands, 'quit' to exit.\n", Colors.DIM))

        while True:
            try:
                # Prompt with network interface name
                status = colored(f"[{self.interface}]", Colors.GREEN)
                prompt = status + " " + colored("attack", Colors.RED) + colored("> ", Colors.WHITE)
                cmd_input = input(prompt).strip()

                if not cmd_input:
                    continue

                parts = cmd_input.split()
                cmd = parts[0].lower()
                args = parts[1:]

                # Command dispatch
                if cmd in ['quit', 'exit', 'q']:
                    print(colored("\nExiting attack console...\n", Colors.YELLOW))
                    break

                elif cmd == 'help':
                    print_help()

                elif cmd == 'clear':
                    os.system('clear')
                    print_banner()

                elif cmd == 'clients':
                    print_clients()

                elif cmd == 'interface':
                    self.cmd_interface(args)

                elif cmd == 'deauth':
                    self.cmd_deauth(args)

                elif cmd == 'disassoc':
                    self.cmd_disassoc(args)

                elif cmd in ['evil_twin', 'eviltwin', 'evil']:
                    self.cmd_evil_twin(args)

                elif cmd in ['auth_flood', 'authflood']:
                    self.cmd_auth_flood(args)

                elif cmd in ['assoc_flood', 'assocflood']:
                    self.cmd_assoc_flood(args)

                elif cmd == 'data':
                    self.cmd_data(args)

                elif cmd == 'train':
                    self.cmd_train(args)

                elif cmd == 'demo1':
                    self.cmd_demo1(args)

                elif cmd == 'demo2':
                    self.cmd_demo2(args)

                elif cmd == 'demo3':
                    self.cmd_demo3(args)

                elif cmd == 'demo4':
                    self.cmd_demo4(args)

                elif cmd == 'demo_all':
                    self.cmd_demo_all(args)

                else:
                    print(colored(f"Unknown command: {cmd}", Colors.RED))
                    print(colored("Type 'help' for available commands", Colors.DIM))

            except KeyboardInterrupt:
                print(colored("\n\nUse 'quit' to exit.\n", Colors.YELLOW))

            except Exception as e:
                print(colored(f"Error: {e}", Colors.RED))
                import traceback
                traceback.print_exc()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='WIDD Interactive Attack CLI - Network Mode',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--interface', '-i', type=str, required=True,
                       help='Network interface to send packets (REQUIRED, e.g., attacker-wlan0)')

    args = parser.parse_args()

    cli = InteractiveAttackCLI(interface=args.interface)
    cli.run()
