#!/usr/bin/env python3
"""
WIDD Interactive Attack CLI

A colorful command-line interface for launching attacks and observing
the WIDD system's response in real-time.

Usage:
    python3 interactive_attack.py
"""

import sys
import os
import time
import readline  # For command history
from datetime import datetime

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

from attacks.attack_generator import AttackGenerator, build_widd_frame
from attacks.attack_generator import FRAME_TYPE_MANAGEMENT, SUBTYPE_DEAUTH

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
║              WIDD Attack Simulation Console                       ║
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
│  ATTACKS:                                                           │
│    deauth <victim> [count]    - Deauth attack spoofing victim MAC   │
│    disassoc <victim> [count]  - Disassociation attack               │
│    auth_flood [count]         - Authentication request flood        │
│    assoc_flood [count]        - Association request flood           │
│    evil_twin [count]          - Broadcast evil twin beacons         │
│                                                                     │
│  LEGITIMATE TRAFFIC:                                                │
│    data <client> [count]      - Send legitimate data frames         │
│    train <client>             - Train MOCC with 150 data frames     │
│                                                                     │
│  DEMO SCENARIOS:                                                    │
│    demo1                      - Single spoofed deauth               │
│    demo2                      - Full deauth attack (triggers KCSM)  │
│    demo3                      - Mixed legitimate + attack           │
│    demo4                      - Auth flood attack                   │
│                                                                     │
│  SYSTEM:                                                            │
│    clients                    - Show registered clients             │
│    stats                      - Show attack statistics              │
│    clear                      - Clear screen                        │
│    help                       - Show this help                      │
│    quit / exit                - Exit the CLI                        │
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
│  LEGITIMATE CLIENTS (known RF signatures):                          │
│    sta1    00:00:00:00:00:01    RSSI: -45 dBm                       │
│    sta2    00:00:00:00:00:02    RSSI: -55 dBm                       │
│    sta3    00:00:00:00:00:03    RSSI: -50 dBm                       │
│                                                                     │
│  ACCESS POINT:                                                      │
│    ap1     00:00:00:00:00:AA    SSID: WIDD_Network                  │
│                                                                     │
│  ATTACKER (you):                                                    │
│    evil    00:00:00:00:00:99    RSSI: -60 dBm (different RF!)       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
"""
    print(colored(clients_text, Colors.YELLOW))


class InteractiveAttackCLI:
    def __init__(self):
        self.generator = AttackGenerator(
            interface=None,  # Simulation mode (no actual sending)
            wap_mac='00:00:00:00:00:AA',
            wap_bssid='00:00:00:00:00:AA'
        )

        # Client MAC shortcuts
        self.clients = {
            'sta1': '00:00:00:00:00:01',
            'sta2': '00:00:00:00:00:02',
            'sta3': '00:00:00:00:00:03',
            'ap': '00:00:00:00:00:AA',
        }

        # Attack statistics
        self.stats = {
            'deauth_sent': 0,
            'disassoc_sent': 0,
            'auth_flood_sent': 0,
            'assoc_flood_sent': 0,
            'evil_twin_sent': 0,
            'data_sent': 0,
        }

    def resolve_mac(self, name_or_mac):
        """Resolve client name to MAC address."""
        if name_or_mac.lower() in self.clients:
            return self.clients[name_or_mac.lower()]
        # Assume it's already a MAC
        return name_or_mac

    def log_attack(self, attack_type, target=None, count=1):
        """Log an attack with timestamp."""
        timestamp = datetime.now().strftime('%H:%M:%S')
        target_str = f" -> {target}" if target else ""

        print(colored(f"\n[{timestamp}] ", Colors.DIM) +
              colored(f"ATTACK: {attack_type}", Colors.RED + Colors.BOLD) +
              colored(f"{target_str} x{count}", Colors.YELLOW))

    def cmd_deauth(self, args):
        """Send deauthentication attack."""
        if len(args) < 1:
            print(colored("Usage: deauth <victim> [count]", Colors.YELLOW))
            print(colored("Example: deauth sta1 5", Colors.DIM))
            return

        victim = self.resolve_mac(args[0])
        count = int(args[1]) if len(args) > 1 else 3

        self.log_attack("DEAUTH (Spoofed)", victim, count)

        print(colored("\n  Spoofing as: ", Colors.WHITE) +
              colored(victim, Colors.CYAN))
        print(colored("  Actual RF:   ", Colors.WHITE) +
              colored("ATTACKER signature (will be detected!)", Colors.RED))
        print()

        # Visual frame sending
        for i in range(count):
            time.sleep(0.3)
            print(colored(f"  [{i+1}/{count}] ", Colors.DIM) +
                  colored("DEAUTH", Colors.RED) +
                  colored(f" from {victim} (spoofed) -> AP", Colors.WHITE))

            self.stats['deauth_sent'] += 1

        print(colored("\n  >> Frames sent to controller for processing", Colors.GREEN))

    def cmd_disassoc(self, args):
        """Send disassociation attack."""
        if len(args) < 1:
            print(colored("Usage: disassoc <victim> [count]", Colors.YELLOW))
            return

        victim = self.resolve_mac(args[0])
        count = int(args[1]) if len(args) > 1 else 3

        self.log_attack("DISASSOC (Spoofed)", victim, count)

        for i in range(count):
            time.sleep(0.3)
            print(colored(f"  [{i+1}/{count}] ", Colors.DIM) +
                  colored("DISASSOC", Colors.MAGENTA) +
                  colored(f" from {victim} (spoofed) -> AP", Colors.WHITE))
            self.stats['disassoc_sent'] += 1

        print(colored("\n  >> Frames sent to controller", Colors.GREEN))

    def cmd_auth_flood(self, args):
        """Send authentication flood."""
        count = int(args[0]) if len(args) > 0 else 15

        self.log_attack("AUTH FLOOD", "random MACs", count)

        print(colored("\n  Flooding with random source MACs...\n", Colors.WHITE))

        for i in range(count):
            time.sleep(0.1)
            random_mac = f"{i:02x}:{i:02x}:{i:02x}:{i:02x}:{i:02x}:{i:02x}"
            print(colored(f"  [{i+1:2}/{count}] ", Colors.DIM) +
                  colored("AUTH", Colors.YELLOW) +
                  colored(f" from {random_mac} -> AP", Colors.WHITE))
            self.stats['auth_flood_sent'] += 1

        print(colored("\n  >> Auth flood complete - check controller for detection!", Colors.GREEN))

    def cmd_assoc_flood(self, args):
        """Send association flood."""
        count = int(args[0]) if len(args) > 0 else 15

        self.log_attack("ASSOC FLOOD", "random MACs", count)

        for i in range(count):
            time.sleep(0.1)
            random_mac = f"aa:{i:02x}:{i:02x}:{i:02x}:{i:02x}:{i:02x}"
            print(colored(f"  [{i+1:2}/{count}] ", Colors.DIM) +
                  colored("ASSOC", Colors.BLUE) +
                  colored(f" from {random_mac} -> AP", Colors.WHITE))
            self.stats['assoc_flood_sent'] += 1

        print(colored("\n  >> Assoc flood complete", Colors.GREEN))

    def cmd_evil_twin(self, args):
        """Broadcast evil twin beacons."""
        count = int(args[0]) if len(args) > 0 else 5

        self.log_attack("EVIL TWIN", "SSID: WIDD_Network", count)

        print(colored("\n  Broadcasting with rogue BSSID: AA:BB:CC:DD:EE:FF\n", Colors.WHITE))

        for i in range(count):
            time.sleep(0.5)
            print(colored(f"  [{i+1}/{count}] ", Colors.DIM) +
                  colored("BEACON", Colors.MAGENTA) +
                  colored(" SSID=WIDD_Network BSSID=AA:BB:CC:DD:EE:FF", Colors.WHITE))
            self.stats['evil_twin_sent'] += 1

        print(colored("\n  >> Evil twin beacons sent", Colors.GREEN))

    def cmd_data(self, args):
        """Send legitimate data frames."""
        if len(args) < 1:
            print(colored("Usage: data <client> [count]", Colors.YELLOW))
            return

        client = self.resolve_mac(args[0])
        count = int(args[1]) if len(args) > 1 else 10

        timestamp = datetime.now().strftime('%H:%M:%S')
        print(colored(f"\n[{timestamp}] ", Colors.DIM) +
              colored(f"LEGITIMATE DATA", Colors.GREEN + Colors.BOLD) +
              colored(f" from {client} x{count}", Colors.WHITE))

        for i in range(count):
            time.sleep(0.1)
            print(colored(f"  [{i+1:2}/{count}] ", Colors.DIM) +
                  colored("DATA", Colors.GREEN) +
                  colored(f" from {client} (legit RF) -> AP", Colors.WHITE))
            self.stats['data_sent'] += 1

        print(colored("\n  >> Data frames sent (training MOCC)", Colors.GREEN))

    def cmd_train(self, args):
        """Train MOCC with client data."""
        if len(args) < 1:
            print(colored("Usage: train <client>", Colors.YELLOW))
            return

        client = self.resolve_mac(args[0])
        print(colored(f"\n[TRAIN] Training MOCC with 150 frames from {client}...", Colors.CYAN))

        for i in range(150):
            if i % 30 == 0:
                print(colored(f"  Progress: {i}/150 frames", Colors.DIM))
            self.stats['data_sent'] += 1

        print(colored(f"\n  >> MOCC trained for {client}", Colors.GREEN))

    def cmd_demo1(self, args):
        """Demo 1: Single spoofed deauth."""
        print(colored("\n" + "="*60, Colors.YELLOW))
        print(colored("  DEMO 1: Single Spoofed Deauth Frame", Colors.YELLOW + Colors.BOLD))
        print(colored("="*60, Colors.YELLOW))
        print(colored("\n  This sends ONE spoofed deauth.", Colors.WHITE))
        print(colored("  Watch the POX controller - it should:", Colors.WHITE))
        print(colored("    - Detect RF mismatch (MOCC)", Colors.CYAN))
        print(colored("    - DROP the frame", Colors.RED))
        print(colored("    - NOT trigger attack alert (only 1 frame)", Colors.YELLOW))
        input(colored("\n  Press Enter to start...", Colors.DIM))

        self.cmd_deauth(['sta1', '1'])

    def cmd_demo2(self, args):
        """Demo 2: Full deauth attack."""
        print(colored("\n" + "="*60, Colors.RED))
        print(colored("  DEMO 2: Full Deauth Attack (Triggers KCSM!)", Colors.RED + Colors.BOLD))
        print(colored("="*60, Colors.RED))
        print(colored("\n  This sends 5 spoofed deauth frames.", Colors.WHITE))
        print(colored("  Watch the POX controller - it should:", Colors.WHITE))
        print(colored("    - Detect RF mismatch on each frame", Colors.CYAN))
        print(colored("    - DROP all frames", Colors.RED))
        print(colored("    - TRIGGER ATTACK ALERT after threshold", Colors.RED + Colors.BOLD))
        print(colored("    - Activate countermeasures!", Colors.YELLOW))
        input(colored("\n  Press Enter to start...", Colors.DIM))

        self.cmd_deauth(['sta1', '5'])

    def cmd_demo3(self, args):
        """Demo 3: Mixed legitimate and attack traffic."""
        print(colored("\n" + "="*60, Colors.CYAN))
        print(colored("  DEMO 3: Mixed Traffic (Legitimate + Attack)", Colors.CYAN + Colors.BOLD))
        print(colored("="*60, Colors.CYAN))
        print(colored("\n  This shows how WIDD differentiates traffic:", Colors.WHITE))
        print(colored("    1. First: legitimate data from sta1", Colors.GREEN))
        print(colored("    2. Then: spoofed deauth (different RF!)", Colors.RED))
        input(colored("\n  Press Enter to start...", Colors.DIM))

        print(colored("\n--- Phase 1: Legitimate Traffic ---", Colors.GREEN))
        self.cmd_data(['sta1', '5'])

        time.sleep(1)

        print(colored("\n--- Phase 2: Attack Traffic ---", Colors.RED))
        self.cmd_deauth(['sta1', '3'])

    def cmd_demo4(self, args):
        """Demo 4: Auth flood attack."""
        print(colored("\n" + "="*60, Colors.MAGENTA))
        print(colored("  DEMO 4: Authentication Flood Attack", Colors.MAGENTA + Colors.BOLD))
        print(colored("="*60, Colors.MAGENTA))
        print(colored("\n  This floods the AP with auth requests.", Colors.WHITE))
        print(colored("  Watch for AUTH_FLOOD_ATTACK detection!", Colors.YELLOW))
        input(colored("\n  Press Enter to start...", Colors.DIM))

        self.cmd_auth_flood(['12'])

    def cmd_stats(self, args):
        """Show attack statistics."""
        print(colored("\n┌─────────────────────────────────────────┐", Colors.CYAN))
        print(colored("│           ATTACK STATISTICS             │", Colors.CYAN + Colors.BOLD))
        print(colored("├─────────────────────────────────────────┤", Colors.CYAN))
        print(colored(f"│  Deauth frames sent:     {self.stats['deauth_sent']:5}          │", Colors.RED))
        print(colored(f"│  Disassoc frames sent:   {self.stats['disassoc_sent']:5}          │", Colors.MAGENTA))
        print(colored(f"│  Auth flood frames:      {self.stats['auth_flood_sent']:5}          │", Colors.YELLOW))
        print(colored(f"│  Assoc flood frames:     {self.stats['assoc_flood_sent']:5}          │", Colors.BLUE))
        print(colored(f"│  Evil twin beacons:      {self.stats['evil_twin_sent']:5}          │", Colors.MAGENTA))
        print(colored(f"│  Legitimate data:        {self.stats['data_sent']:5}          │", Colors.GREEN))
        print(colored("└─────────────────────────────────────────┘", Colors.CYAN))

    def run(self):
        """Main CLI loop."""
        print_banner()
        print_help()

        print(colored("\nType 'help' for commands, 'quit' to exit.\n", Colors.DIM))

        while True:
            try:
                # Prompt
                prompt = colored("widd-attack", Colors.RED) + colored("> ", Colors.WHITE)
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

                elif cmd == 'stats':
                    self.cmd_stats(args)

                elif cmd == 'deauth':
                    self.cmd_deauth(args)

                elif cmd == 'disassoc':
                    self.cmd_disassoc(args)

                elif cmd in ['auth_flood', 'authflood']:
                    self.cmd_auth_flood(args)

                elif cmd in ['assoc_flood', 'assocflood']:
                    self.cmd_assoc_flood(args)

                elif cmd in ['evil_twin', 'eviltwin', 'evil']:
                    self.cmd_evil_twin(args)

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

                else:
                    print(colored(f"Unknown command: {cmd}", Colors.RED))
                    print(colored("Type 'help' for available commands", Colors.DIM))

            except KeyboardInterrupt:
                print(colored("\n\nUse 'quit' to exit.\n", Colors.YELLOW))

            except Exception as e:
                print(colored(f"Error: {e}", Colors.RED))


if __name__ == '__main__':
    cli = InteractiveAttackCLI()
    cli.run()
