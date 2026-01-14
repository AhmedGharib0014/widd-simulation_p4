#!/usr/bin/env python3
"""
WIDD Packet Flow Monitor

Real-time visualization of packet flow through the WIDD system.
Shows packets moving through: Switch -> OBSERVE -> ORIENT -> DECIDE -> ACT

Usage:
    python3 packet_monitor.py
"""

import sys
import os
import socket
import json
import time
import threading
from datetime import datetime
from collections import deque

# ANSI Colors and formatting
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

    # Foreground
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

    # Bright
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'

    # Background
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_BLUE = '\033[44m'


def colored(text, *colors):
    return ''.join(colors) + str(text) + Colors.RESET


def clear_screen():
    os.system('clear')


class PacketFlowMonitor:
    """
    Real-time packet flow visualization.

    Displays packets as they flow through the OODA loop stages.
    """

    def __init__(self):
        self.running = False
        self.events = deque(maxlen=50)  # Keep last 50 events
        self.stats = {
            'total_packets': 0,
            'dropped': 0,
            'passed': 0,
            'attacks': 0,
        }

        # Stage colors
        self.stage_colors = {
            'SWITCH': Colors.CYAN,
            'OBSERVE': Colors.BLUE,
            'ORIENT': Colors.YELLOW,
            'DECIDE': Colors.GREEN,
            'ACT': Colors.MAGENTA,
            'ATTACK': Colors.RED,
            'DROP': Colors.BRIGHT_RED,
            'PASS': Colors.BRIGHT_GREEN,
        }

        # Frame type symbols
        self.frame_symbols = {
            'DEAUTH': '⚠',
            'DISASSOC': '⚡',
            'AUTH': '🔑',
            'ASSOC': '📡',
            'BEACON': '📶',
            'DATA': '📦',
        }

    def print_banner(self):
        """Print the monitor header."""
        banner = """
╔══════════════════════════════════════════════════════════════════════╗
║                     WIDD PACKET FLOW MONITOR                         ║
║                                                                      ║
║  Visualizing packets through: Switch → OBSERVE → ORIENT → DECIDE → ACT  ║
╚══════════════════════════════════════════════════════════════════════╝
"""
        print(colored(banner, Colors.CYAN, Colors.BOLD))

    def print_legend(self):
        """Print the color legend."""
        print(colored("┌─ LEGEND ─────────────────────────────────────────────┐", Colors.DIM))
        print(colored("│ ", Colors.DIM) +
              colored("SWITCH ", Colors.CYAN) +
              colored("→ ", Colors.DIM) +
              colored("OBSERVE ", Colors.BLUE) +
              colored("→ ", Colors.DIM) +
              colored("ORIENT ", Colors.YELLOW) +
              colored("→ ", Colors.DIM) +
              colored("DECIDE ", Colors.GREEN) +
              colored("→ ", Colors.DIM) +
              colored("ACT", Colors.MAGENTA) +
              colored("    │", Colors.DIM))
        print(colored("│ ", Colors.DIM) +
              colored("PASS", Colors.BRIGHT_GREEN) +
              colored(" = Allowed  ", Colors.DIM) +
              colored("DROP", Colors.BRIGHT_RED) +
              colored(" = Blocked  ", Colors.DIM) +
              colored("ATTACK", Colors.RED, Colors.BOLD) +
              colored(" = Detected  │", Colors.DIM))
        print(colored("└──────────────────────────────────────────────────────┘", Colors.DIM))
        print()

    def print_stats(self):
        """Print current statistics."""
        stats_line = (
            colored("│ ", Colors.DIM) +
            colored(f"Packets: {self.stats['total_packets']:4}", Colors.WHITE) +
            colored(" │ ", Colors.DIM) +
            colored(f"Passed: {self.stats['passed']:4}", Colors.GREEN) +
            colored(" │ ", Colors.DIM) +
            colored(f"Dropped: {self.stats['dropped']:4}", Colors.RED) +
            colored(" │ ", Colors.DIM) +
            colored(f"Attacks: {self.stats['attacks']:4}", Colors.BRIGHT_RED, Colors.BOLD) +
            colored(" │", Colors.DIM)
        )
        print(colored("┌─ STATISTICS ────────────────────────────────────────────┐", Colors.DIM))
        print(stats_line)
        print(colored("└─────────────────────────────────────────────────────────┘", Colors.DIM))
        print()

    def format_event(self, event: dict) -> str:
        """Format a packet event for display."""
        timestamp = datetime.fromtimestamp(event.get('timestamp', time.time()))
        time_str = timestamp.strftime('%H:%M:%S.%f')[:-3]

        stage = event.get('stage', '?').upper()
        frame_type = event.get('frame_type', '?')
        src_mac = event.get('src_mac', '?')
        details = event.get('details', {})

        # Get stage color
        stage_color = self.stage_colors.get(stage, Colors.WHITE)

        # Get frame symbol
        symbol = self.frame_symbols.get(frame_type.upper(), '?')

        # Build the flow visualization
        flow = self._build_flow_indicator(stage)

        # Format the line
        line = (
            colored(f"[{time_str}] ", Colors.DIM) +
            flow +
            colored(f" {symbol} {frame_type:8}", stage_color) +
            colored(f" MAC={src_mac}", Colors.WHITE)
        )

        # Add details
        if details:
            if 'prob' in details:
                prob = details['prob']
                prob_color = Colors.GREEN if prob > 0.5 else Colors.RED
                line += colored(f" MOCC={prob:.1%}", prob_color)
            if 'attack' in details:
                line += colored(f" [{details['attack']}]", Colors.RED, Colors.BOLD)
            if 'action' in details:
                action = details['action']
                action_color = Colors.GREEN if action == 'PASS' else Colors.RED
                line += colored(f" → {action}", action_color, Colors.BOLD)

        return line

    def _build_flow_indicator(self, stage: str) -> str:
        """Build the OODA flow stage indicator."""
        stages = ['SWITCH', 'OBSERVE', 'ORIENT', 'DECIDE', 'ACT']
        indicators = []

        for s in stages:
            if s == stage:
                indicators.append(colored(f"[{s[:3]}]", self.stage_colors.get(s, Colors.WHITE), Colors.BOLD))
            else:
                indicators.append(colored(f" {s[:3]} ", Colors.DIM))

        return colored("→", Colors.DIM).join(indicators)

    def add_event(self, event: dict):
        """Add a new event and update display."""
        self.events.append(event)
        self.stats['total_packets'] += 1

        details = event.get('details', {})
        if details.get('action') == 'DROP':
            self.stats['dropped'] += 1
        elif details.get('action') == 'PASS':
            self.stats['passed'] += 1
        if details.get('attack'):
            self.stats['attacks'] += 1

        # Print the event
        print(self.format_event(event))

    def simulate_traffic(self):
        """Simulate packet traffic for demonstration."""
        import random

        print(colored("\n  Simulating packet traffic...\n", Colors.YELLOW))
        time.sleep(1)

        # Simulate training phase
        print(colored("  === Training Phase (50 data frames) ===\n", Colors.CYAN))
        for i in range(10):
            self.add_event({
                'timestamp': time.time(),
                'stage': 'OBSERVE',
                'frame_type': 'DATA',
                'src_mac': '00:00:00:00:00:01',
                'details': {'action': 'TRAIN'}
            })
            time.sleep(0.1)

        print()
        time.sleep(1)

        # Simulate legitimate traffic
        print(colored("  === Legitimate Deauth (should PASS) ===\n", Colors.GREEN))
        stages = ['SWITCH', 'OBSERVE', 'ORIENT', 'DECIDE']
        for stage in stages:
            self.add_event({
                'timestamp': time.time(),
                'stage': stage,
                'frame_type': 'DEAUTH',
                'src_mac': '00:00:00:00:00:01',
                'details': {'prob': 0.85} if stage == 'ORIENT' else {}
            })
            time.sleep(0.3)
        self.add_event({
            'timestamp': time.time(),
            'stage': 'ACT',
            'frame_type': 'DEAUTH',
            'src_mac': '00:00:00:00:00:01',
            'details': {'action': 'PASS', 'prob': 0.85}
        })

        print()
        time.sleep(1)

        # Simulate spoofed attack
        print(colored("  === Spoofed Deauth Attack (should DROP) ===\n", Colors.RED))
        for i in range(3):
            for stage in ['SWITCH', 'OBSERVE', 'ORIENT', 'DECIDE']:
                self.add_event({
                    'timestamp': time.time(),
                    'stage': stage,
                    'frame_type': 'DEAUTH',
                    'src_mac': '00:00:00:00:00:01',
                    'details': {'prob': 0.15, 'spoofed': True} if stage == 'ORIENT' else {}
                })
                time.sleep(0.2)

            if i >= 1:  # Attack detected after 2nd frame
                self.add_event({
                    'timestamp': time.time(),
                    'stage': 'ACT',
                    'frame_type': 'DEAUTH',
                    'src_mac': '00:00:00:00:00:01',
                    'details': {'action': 'DROP', 'attack': 'DEAUTH_ATTACK', 'prob': 0.15}
                })
            else:
                self.add_event({
                    'timestamp': time.time(),
                    'stage': 'ACT',
                    'frame_type': 'DEAUTH',
                    'src_mac': '00:00:00:00:00:01',
                    'details': {'action': 'DROP', 'prob': 0.15}
                })
            print()
            time.sleep(0.5)

        print()
        time.sleep(1)

        # Simulate evil twin
        print(colored("  === Evil Twin Beacon ===\n", Colors.MAGENTA))
        self.add_event({
            'timestamp': time.time(),
            'stage': 'SWITCH',
            'frame_type': 'BEACON',
            'src_mac': 'AA:BB:CC:DD:EE:FF',
            'details': {}
        })
        time.sleep(0.3)
        self.add_event({
            'timestamp': time.time(),
            'stage': 'OBSERVE',
            'frame_type': 'BEACON',
            'src_mac': 'AA:BB:CC:DD:EE:FF',
            'details': {'ssid': 'WIDD_Network'}
        })
        time.sleep(0.3)
        self.add_event({
            'timestamp': time.time(),
            'stage': 'DECIDE',
            'frame_type': 'BEACON',
            'src_mac': 'AA:BB:CC:DD:EE:FF',
            'details': {'attack': 'EVIL_TWIN'}
        })
        time.sleep(0.3)
        self.add_event({
            'timestamp': time.time(),
            'stage': 'ACT',
            'frame_type': 'BEACON',
            'src_mac': 'AA:BB:CC:DD:EE:FF',
            'details': {'action': 'ALERT', 'attack': 'EVIL_TWIN'}
        })

        print()

    def listen_for_events(self, port: int = 9998):
        """Listen for events from the simulation server."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            sock.bind(('127.0.0.1', port))
            sock.settimeout(1.0)
            print(colored(f"  [DEBUG] Socket bound to 127.0.0.1:{port}", Colors.CYAN))
            print(colored(f"  [DEBUG] Listening for packets on port {port}...", Colors.CYAN))
            print(colored(f"  [DEBUG] Waiting for events from OODA Controller...\n", Colors.DIM))

            heartbeat_counter = 0
            while self.running:
                try:
                    data, addr = sock.recvfrom(4096)
                    print(colored(f"  [DEBUG] Received {len(data)} bytes from {addr}", Colors.GREEN))
                    event = json.loads(data.decode())
                    print(colored(f"  [DEBUG] Parsed event: {event}", Colors.GREEN))
                    self.add_event(event)
                except socket.timeout:
                    # Print heartbeat every 10 seconds
                    heartbeat_counter += 1
                    if heartbeat_counter % 10 == 0:
                        print(colored(f"  [DEBUG] Still listening... ({heartbeat_counter}s)", Colors.DIM))
                    continue
                except json.JSONDecodeError as e:
                    print(colored(f"  [DEBUG] JSON decode error: {e}", Colors.RED))
                    print(colored(f"  [DEBUG] Raw data: {data}", Colors.RED))
                    continue
                except KeyboardInterrupt:
                    break
        except OSError as e:
            print(colored(f"  Could not bind to port {port}: {e}", Colors.RED))
            print(colored("  The port may already be in use.", Colors.YELLOW))
            print(colored("  Monitor will stay open but won't receive events.\n", Colors.DIM))
            # Stay open anyway
            try:
                while self.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
        finally:
            sock.close()

    def run(self, simulate: bool = False):
        """Run the packet monitor."""
        clear_screen()
        self.print_banner()
        self.print_legend()
        self.print_stats()
        print(colored("─" * 70, Colors.DIM))
        print()

        self.running = True

        if simulate:
            self.simulate_traffic()
        else:
            try:
                self.listen_for_events()
            except KeyboardInterrupt:
                pass

        print()
        self.print_stats()
        print(colored("\n  Monitor stopped.\n", Colors.YELLOW))


def main():
    import argparse

    parser = argparse.ArgumentParser(description='WIDD Packet Flow Monitor')
    parser.add_argument('--simulate', '-s', action='store_true',
                        help='Run simulation instead of listening for real packets')
    args = parser.parse_args()

    monitor = PacketFlowMonitor()

    try:
        monitor.run(simulate=args.simulate)
    except KeyboardInterrupt:
        print(colored("\n\n  Interrupted by user.\n", Colors.YELLOW))


if __name__ == '__main__':
    main()
