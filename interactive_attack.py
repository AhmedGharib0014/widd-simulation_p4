#!/usr/bin/env python3
"""
WIDD Interactive Attack CLI

A colorful command-line interface for launching attacks and observing
the WIDD system's response in real-time.

This CLI connects to the OODA Controller's simulation server to send
attacks and receive real-time feedback.

Usage:
    python3 interactive_attack.py
"""

import sys
import os
import time
import socket
import json
import readline  # For command history
from datetime import datetime

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_ROOT)

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
║         Connected to OODA Controller for live detection          ║
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
│  ATTACKS (sent to OODA Controller):                                 │
│    deauth <victim> [count]    - Deauth attack spoofing victim MAC   │
│    evil_twin                  - Broadcast evil twin beacon          │
│    auth_flood [count]         - Authentication request flood        │
│                                                                     │
│  LEGITIMATE TRAFFIC:                                                │
│    data <client> [count]      - Send legitimate data frames         │
│    train <client>             - Train MOCC with 100 data frames     │
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
│    stats                      - Show controller statistics          │
│    connect                    - Reconnect to controller             │
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
    def __init__(self):
        self.socket = None
        self.connected = False

        # Client MAC shortcuts
        self.clients = {
            'sta1': '00:00:00:00:00:01',
            'sta2': '00:00:00:00:00:02',
            'ap': '00:11:22:33:44:55',
        }

        self.attacker_mac = '00:00:00:00:00:99'

    def connect(self) -> bool:
        """Connect to the OODA controller's simulation server."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect(('127.0.0.1', 9999))
            self.socket.settimeout(30.0)
            self.connected = True
            print(colored("  [+] Connected to OODA Controller", Colors.GREEN))
            return True
        except ConnectionRefusedError:
            print(colored("  [!] OODA Controller not running!", Colors.RED))
            print(colored("      Start it first with: python3 -m controller.ooda_controller --server", Colors.YELLOW))
            self.connected = False
            return False
        except Exception as e:
            print(colored(f"  [!] Connection failed: {e}", Colors.RED))
            self.connected = False
            return False

    def send_command(self, msg: dict) -> dict:
        """Send command to controller and get response."""
        if not self.connected:
            return {'error': 'Not connected'}

        try:
            self.socket.send(json.dumps(msg).encode())
            response = self.socket.recv(8192)
            return json.loads(response.decode())
        except Exception as e:
            self.connected = False
            return {'error': str(e)}

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

    def show_result(self, result: dict):
        """Display the result from controller."""
        if 'error' in result:
            print(colored(f"  ERROR: {result['error']}", Colors.RED))
            return

        results = result.get('results', [])
        for r in results:
            frame_num = r.get('frame', '')
            attack = r.get('attack', 'NONE')
            dropped = r.get('dropped', False)
            prob = r.get('prob', 0)

            # Format output
            frame_str = f"[{frame_num}] " if frame_num else ""

            if attack != 'NONE':
                print(colored(f"  {frame_str}", Colors.DIM) +
                      colored("ATTACK DETECTED: ", Colors.RED + Colors.BOLD) +
                      colored(attack, Colors.YELLOW))
            elif dropped:
                print(colored(f"  {frame_str}", Colors.DIM) +
                      colored("DROPPED ", Colors.RED) +
                      colored(f"(MOCC prob: {prob:.1%})", Colors.DIM))
            else:
                print(colored(f"  {frame_str}", Colors.DIM) +
                      colored("PASSED ", Colors.GREEN) +
                      colored(f"(MOCC prob: {prob:.1%})", Colors.DIM))

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
        print()

        # Send to controller
        result = self.send_command({
            'type': 'attack',
            'attack': 'deauth',
            'params': {
                'victim': victim,
                'count': count,
                'attacker': self.attacker_mac
            }
        })

        print(colored("  Controller Response:", Colors.CYAN))
        self.show_result(result)

    def cmd_evil_twin(self, args):
        """Broadcast evil twin beacon."""
        self.log_attack("EVIL TWIN BEACON", "SSID: WIDD_Network", 1)

        print(colored("\n  Rogue BSSID: ", Colors.WHITE) +
              colored("AA:BB:CC:DD:EE:FF", Colors.RED))
        print(colored("  Same SSID:   ", Colors.WHITE) +
              colored("WIDD_Network", Colors.YELLOW))
        print()

        result = self.send_command({
            'type': 'attack',
            'attack': 'evil_twin',
            'params': {}
        })

        print(colored("  Controller Response:", Colors.CYAN))
        self.show_result(result)

    def cmd_auth_flood(self, args):
        """Send authentication flood."""
        count = int(args[0]) if len(args) > 0 else 12

        self.log_attack("AUTH FLOOD", "AP", count)

        print(colored("\n  Flooding with random source MACs...", Colors.WHITE))
        print()

        result = self.send_command({
            'type': 'attack',
            'attack': 'auth_flood',
            'params': {'count': count}
        })

        print(colored("  Controller Response:", Colors.CYAN))
        self.show_result(result)

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

        result = self.send_command({
            'type': 'attack',
            'attack': 'data',
            'params': {'source': client, 'count': count}
        })

        print(colored(f"  Sent {count} data frames for MOCC training", Colors.GREEN))

    def cmd_train(self, args):
        """Train MOCC with data frames."""
        if len(args) < 1:
            print(colored("Usage: train <client>", Colors.YELLOW))
            return

        client = self.resolve_mac(args[0])
        print(colored(f"\n  Training MOCC with 100 frames from {client}...", Colors.CYAN))

        result = self.send_command({
            'type': 'attack',
            'attack': 'data',
            'params': {'source': client, 'count': 100}
        })

        print(colored(f"  MOCC training complete for {client}", Colors.GREEN))

    def cmd_stats(self, args):
        """Show controller statistics."""
        result = self.send_command({'type': 'stats'})

        if 'error' in result:
            print(colored(f"  Error: {result['error']}", Colors.RED))
            return

        stats = result.get('stats', {})

        print(colored("\n┌─────────────────────────────────────────┐", Colors.CYAN))
        print(colored("│       OODA CONTROLLER STATISTICS        │", Colors.CYAN + Colors.BOLD))
        print(colored("├─────────────────────────────────────────┤", Colors.CYAN))
        print(colored(f"│  Deauth frames:        {stats.get('deauth_frames', 0):5}            │", Colors.WHITE))
        print(colored(f"│  Deauth dropped:       {stats.get('deauth_dropped', 0):5}            │", Colors.RED))
        print(colored(f"│  Attacks detected:     {stats.get('attacks_detected', 0):5}            │", Colors.RED + Colors.BOLD))
        print(colored(f"│  MOCC devices:         {stats.get('mocc_devices', 0):5}            │", Colors.GREEN))
        print(colored("└─────────────────────────────────────────┘", Colors.CYAN))

    def cmd_demo1(self, args):
        """Demo 1: Single spoofed deauth."""
        print(colored("\n" + "="*60, Colors.YELLOW))
        print(colored("  DEMO 1: Single Spoofed Deauth Frame", Colors.YELLOW + Colors.BOLD))
        print(colored("="*60, Colors.YELLOW))
        print(colored("\n  Sending ONE spoofed deauth frame.", Colors.WHITE))
        print(colored("  The OODA Controller will:", Colors.WHITE))
        print(colored("    1. OBSERVE - Receive frame from switch", Colors.CYAN))
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
        print(colored("\n  Sending 5 rapid spoofed deauth frames.", Colors.WHITE))
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
        print(colored("\n  Flooding AP with 12 auth requests.", Colors.WHITE))
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
        self.cmd_stats([])

    def run(self):
        """Main CLI loop."""
        print_banner()

        print(colored("\n  Connecting to OODA Controller...", Colors.CYAN))
        if not self.connect():
            print(colored("\n  Running in OFFLINE mode (no live detection)", Colors.YELLOW))
            print(colored("  Start controller first: python3 -m controller.ooda_controller --server", Colors.DIM))

        print_help()

        print(colored("\nType 'help' for commands, 'quit' to exit.\n", Colors.DIM))

        while True:
            try:
                # Prompt with connection status
                if self.connected:
                    status = colored("[LIVE]", Colors.GREEN)
                else:
                    status = colored("[OFFLINE]", Colors.RED)

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

                elif cmd == 'connect':
                    self.connect()

                elif cmd == 'stats':
                    if self.connected:
                        self.cmd_stats(args)
                    else:
                        print(colored("  Not connected to controller", Colors.RED))

                elif cmd == 'deauth':
                    if self.connected:
                        self.cmd_deauth(args)
                    else:
                        print(colored("  Not connected - run 'connect' first", Colors.RED))

                elif cmd in ['evil_twin', 'eviltwin', 'evil']:
                    if self.connected:
                        self.cmd_evil_twin(args)
                    else:
                        print(colored("  Not connected", Colors.RED))

                elif cmd in ['auth_flood', 'authflood']:
                    if self.connected:
                        self.cmd_auth_flood(args)
                    else:
                        print(colored("  Not connected", Colors.RED))

                elif cmd == 'data':
                    if self.connected:
                        self.cmd_data(args)
                    else:
                        print(colored("  Not connected", Colors.RED))

                elif cmd == 'train':
                    if self.connected:
                        self.cmd_train(args)
                    else:
                        print(colored("  Not connected", Colors.RED))

                elif cmd == 'demo1':
                    if self.connected:
                        self.cmd_demo1(args)
                    else:
                        print(colored("  Not connected", Colors.RED))

                elif cmd == 'demo2':
                    if self.connected:
                        self.cmd_demo2(args)
                    else:
                        print(colored("  Not connected", Colors.RED))

                elif cmd == 'demo3':
                    if self.connected:
                        self.cmd_demo3(args)
                    else:
                        print(colored("  Not connected", Colors.RED))

                elif cmd == 'demo4':
                    if self.connected:
                        self.cmd_demo4(args)
                    else:
                        print(colored("  Not connected", Colors.RED))

                elif cmd == 'demo_all':
                    if self.connected:
                        self.cmd_demo_all(args)
                    else:
                        print(colored("  Not connected", Colors.RED))

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
