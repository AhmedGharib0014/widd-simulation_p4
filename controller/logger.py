#!/usr/bin/env python3
"""
WIDD Logger - Comprehensive logging for packet flow visualization

Provides structured logging to trace packets through:
1. DATA PLANE (P4/bmv2) - Header extraction, classification
2. CONTROL PLANE - OODA loop processing
   - OBSERVE: Frame received from switch
   - ORIENT: MOCC device identification
   - DECIDE: KCSM state machine decision
   - ACT: Response action (drop/pass/inject)

Log Format:
[LAYER] [COMPONENT] [ACTION] Details...

Colors (for terminal):
- CYAN: Data plane / Switch events
- GREEN: Legitimate traffic / Pass decisions
- YELLOW: Warnings / Orientation phase
- RED: Attacks detected / Drop decisions
- MAGENTA: Countermeasures / Act phase
- BLUE: Info / Statistics
"""

import sys
import time
from enum import Enum
from typing import Optional
from dataclasses import dataclass


class LogLevel(Enum):
    DEBUG = 0
    INFO = 1
    WARNING = 2
    ERROR = 3
    CRITICAL = 4


class Colors:
    """ANSI color codes for terminal output."""
    RESET = '\033[0m'
    BOLD = '\033[1m'

    # Foreground colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

    # Bright colors
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'


class WIDDLogger:
    """
    Centralized logger for WIDD system.

    Provides consistent formatting and color-coded output
    for tracing packet flow through the system.
    """

    def __init__(self, use_colors: bool = True, log_level: LogLevel = LogLevel.INFO):
        self.use_colors = use_colors
        self.log_level = log_level
        self.start_time = time.time()

        # Statistics
        self.stats = {
            'packets_received': 0,
            'packets_dropped': 0,
            'packets_passed': 0,
            'attacks_detected': 0,
            'countermeasures_triggered': 0,
        }

    def _color(self, text: str, color: str) -> str:
        """Apply color to text if colors enabled."""
        if self.use_colors:
            return f"{color}{text}{Colors.RESET}"
        return text

    def _timestamp(self) -> str:
        """Get formatted timestamp."""
        elapsed = time.time() - self.start_time
        return f"{elapsed:8.3f}s"

    def _log(self, level: LogLevel, layer: str, component: str,
             action: str, details: str, color: str):
        """Internal log method."""
        if level.value < self.log_level.value:
            return

        timestamp = self._timestamp()
        layer_str = self._color(f"[{layer:^12}]", color)
        component_str = self._color(f"[{component:^8}]", Colors.WHITE)
        action_str = self._color(f"{action}", Colors.BOLD)

        print(f"{timestamp} {layer_str} {component_str} {action_str}: {details}")

    # ==================== DATA PLANE LOGS ====================

    def switch_packet_in(self, frame_type: str, src_mac: str, dst_mac: str,
                         port: int, rssi: int = 0):
        """Log packet received from switch (Packet-In)."""
        self.stats['packets_received'] += 1
        details = f"Type={frame_type}, Src={src_mac}, Dst={dst_mac}, Port={port}, RSSI={rssi}dBm"
        self._log(LogLevel.INFO, "DATA PLANE", "SWITCH",
                  "PACKET-IN", details, Colors.CYAN)

    def switch_packet_out(self, action: str, port: int, details: str = ""):
        """Log packet sent to switch (Packet-Out)."""
        msg = f"Action={action}, Port={port}"
        if details:
            msg += f", {details}"
        self._log(LogLevel.INFO, "DATA PLANE", "SWITCH",
                  "PACKET-OUT", msg, Colors.CYAN)

    def p4_classification(self, frame_type: str, subtype: int,
                          table_hit: str, action: str):
        """Log P4 table classification result."""
        details = f"Frame={frame_type}, Subtype={subtype}, Table={table_hit}, Action={action}"
        self._log(LogLevel.DEBUG, "DATA PLANE", "P4",
                  "CLASSIFY", details, Colors.CYAN)

    # ==================== OODA LOOP LOGS ====================

    def ooda_observe(self, frame_type: str, src_mac: str,
                     rf_features: dict = None):
        """Log OBSERVE phase - frame received and parsed."""
        details = f"Frame={frame_type}, MAC={src_mac}"
        if rf_features:
            details += f", RSSI={rf_features.get('rssi', '?')}dBm"
        self._log(LogLevel.INFO, "CTRL PLANE", "OBSERVE",
                  "FRAME PARSED", details, Colors.BLUE)

    def ooda_orient_mocc(self, claimed_mac: str, probability: float,
                         is_legitimate: bool, rf_distance: float = 0):
        """Log ORIENT phase - MOCC identification result."""
        status = self._color("LEGITIMATE", Colors.GREEN) if is_legitimate else self._color("SPOOFED", Colors.RED)
        details = f"MAC={claimed_mac}, Prob={probability:.1%}, Status={status}"
        if rf_distance > 0:
            details += f", RF_Dist={rf_distance:.2f}"

        color = Colors.GREEN if is_legitimate else Colors.YELLOW
        self._log(LogLevel.INFO, "CTRL PLANE", "ORIENT",
                  "MOCC ID", details, color)

    def ooda_orient_training(self, mac: str, samples: int, trained: bool):
        """Log MOCC training update."""
        status = "READY" if trained else f"LEARNING ({samples} samples)"
        details = f"MAC={mac}, Status={status}"
        self._log(LogLevel.DEBUG, "CTRL PLANE", "ORIENT",
                  "TRAINING", details, Colors.BLUE)

    def ooda_decide_kcsm(self, kcsm_type: str, mac: str, state: int,
                         attack_detected: bool, attack_type: str = None):
        """Log DECIDE phase - KCSM state machine result."""
        if attack_detected:
            self.stats['attacks_detected'] += 1
            details = f"KCSM={kcsm_type}, MAC={mac}, State={state}, ATTACK={attack_type}"
            self._log(LogLevel.WARNING, "CTRL PLANE", "DECIDE",
                      "ATTACK DETECTED", details, Colors.BRIGHT_RED)
        else:
            details = f"KCSM={kcsm_type}, MAC={mac}, State={state}, Status=NORMAL"
            self._log(LogLevel.DEBUG, "CTRL PLANE", "DECIDE",
                      "STATE UPDATE", details, Colors.BLUE)

    def ooda_decide_drop(self, reason: str, mac: str):
        """Log DECIDE phase - drop decision."""
        self.stats['packets_dropped'] += 1
        details = f"Reason={reason}, MAC={mac}"
        self._log(LogLevel.INFO, "CTRL PLANE", "DECIDE",
                  "DROP", details, Colors.RED)

    def ooda_decide_pass(self, mac: str):
        """Log DECIDE phase - pass decision."""
        self.stats['packets_passed'] += 1
        details = f"MAC={mac}, Verdict=ALLOW"
        self._log(LogLevel.DEBUG, "CTRL PLANE", "DECIDE",
                  "PASS", details, Colors.GREEN)

    def ooda_act_countermeasure(self, action: str, target: str, details: str = ""):
        """Log ACT phase - countermeasure triggered."""
        self.stats['countermeasures_triggered'] += 1
        msg = f"Action={action}, Target={target}"
        if details:
            msg += f", {details}"
        self._log(LogLevel.WARNING, "CTRL PLANE", "ACT",
                  "COUNTERMEASURE", msg, Colors.MAGENTA)

    def ooda_act_alert(self, alert_type: str, details: str):
        """Log ACT phase - alert generated."""
        self._log(LogLevel.WARNING, "CTRL PLANE", "ACT",
                  f"ALERT: {alert_type}", details, Colors.BRIGHT_YELLOW)

    # ==================== ATTACK LOGS ====================

    def attack_detected(self, message: str):
        """Log a generic attack detection message."""
        self.stats['attacks_detected'] += 1
        self._log(LogLevel.WARNING, "ATTACK", "DETECT",
                  "ALERT", message, Colors.BRIGHT_RED)

    def attack_deauth(self, src_mac: str, target_mac: str,
                      spoofed: bool, count: int):
        """Log deauthentication attack."""
        status = "SPOOFED" if spoofed else "LEGITIMATE"
        details = f"Src={src_mac}, Target={target_mac}, Status={status}, Count={count}"
        color = Colors.RED if spoofed else Colors.YELLOW
        self._log(LogLevel.WARNING, "ATTACK", "DEAUTH",
                  "DETECTED" if spoofed else "FRAME", details, color)

    def attack_evil_twin(self, ssid: str, legit_bssid: str, rogue_bssid: str):
        """Log evil twin attack."""
        details = f"SSID={ssid}, Legit={legit_bssid}, Rogue={rogue_bssid}"
        self._log(LogLevel.CRITICAL, "ATTACK", "EVIL TWIN",
                  "DETECTED", details, Colors.BRIGHT_RED)

    def attack_flood(self, flood_type: str, count: int, threshold: int):
        """Log flood attack."""
        details = f"Type={flood_type}, Count={count}/{threshold}"
        self._log(LogLevel.WARNING, "ATTACK", "FLOOD",
                  "DETECTED", details, Colors.RED)

    # ==================== SYSTEM LOGS ====================

    def system_start(self, component: str):
        """Log system component start."""
        self._log(LogLevel.INFO, "SYSTEM", component,
                  "STARTED", f"{component} initialized", Colors.GREEN)

    def system_stop(self, component: str):
        """Log system component stop."""
        self._log(LogLevel.INFO, "SYSTEM", component,
                  "STOPPED", f"{component} shutdown", Colors.YELLOW)

    def system_error(self, component: str, error: str):
        """Log system error."""
        self._log(LogLevel.ERROR, "SYSTEM", component,
                  "ERROR", error, Colors.RED)

    def system_info(self, message: str):
        """Log general system info."""
        self._log(LogLevel.INFO, "SYSTEM", "INFO",
                  "INFO", message, Colors.WHITE)

    # ==================== STATISTICS ====================

    def print_stats(self):
        """Print current statistics."""
        print("\n" + "="*60)
        print(self._color("               WIDD STATISTICS", Colors.BOLD))
        print("="*60)
        print(f"  Packets Received:        {self.stats['packets_received']:>8}")
        print(f"  Packets Passed:          {self._color(str(self.stats['packets_passed']).rjust(8), Colors.GREEN)}")
        print(f"  Packets Dropped:         {self._color(str(self.stats['packets_dropped']).rjust(8), Colors.RED)}")
        print(f"  Attacks Detected:        {self._color(str(self.stats['attacks_detected']).rjust(8), Colors.BRIGHT_RED)}")
        print(f"  Countermeasures:         {self._color(str(self.stats['countermeasures_triggered']).rjust(8), Colors.MAGENTA)}")
        print("="*60 + "\n")

    def print_banner(self):
        """Print WIDD banner."""
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██╗    ██╗██╗██████╗ ██████╗                                ║
║   ██║    ██║██║██╔══██╗██╔══██╗                               ║
║   ██║ █╗ ██║██║██║  ██║██║  ██║                               ║
║   ██║███╗██║██║██║  ██║██║  ██║                               ║
║   ╚███╔███╔╝██║██████╔╝██████╔╝                               ║
║    ╚══╝╚══╝ ╚═╝╚═════╝ ╚═════╝                                ║
║                                                               ║
║   Wireless Intrusion Detection & Defense System               ║
║   OODA Loop + Kill Chain State Machine                        ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""
        print(self._color(banner, Colors.CYAN))


# Global logger instance
logger = WIDDLogger()


# Test the logger
if __name__ == '__main__':
    logger.print_banner()
    logger.system_start("OODA Controller")

    print("\n--- Simulating packet flow ---\n")

    # Simulate legitimate traffic
    logger.switch_packet_in("DATA", "00:00:00:00:00:01", "ff:ff:ff:ff:ff:ff", 1, -45)
    logger.ooda_observe("DATA", "00:00:00:00:00:01", {'rssi': -45})
    logger.ooda_orient_training("00:00:00:00:00:01", 50, False)
    logger.ooda_decide_pass("00:00:00:00:00:01")

    print()

    # Simulate attack
    logger.switch_packet_in("DEAUTH", "00:00:00:00:00:01", "00:00:00:00:00:02", 2, -70)
    logger.ooda_observe("DEAUTH", "00:00:00:00:00:01", {'rssi': -70})
    logger.ooda_orient_mocc("00:00:00:00:00:01", 0.25, False, 15.5)
    logger.attack_deauth("00:00:00:00:00:99", "00:00:00:00:00:01", True, 1)
    logger.ooda_decide_kcsm("DEAUTH", "00:00:00:00:00:01", 1, False)
    logger.ooda_decide_drop("Spoofed deauth frame", "00:00:00:00:00:01")

    print()

    # More attacks leading to detection
    for i in range(2):
        logger.switch_packet_in("DEAUTH", "00:00:00:00:00:01", "00:00:00:00:00:02", 2, -68)
        logger.ooda_orient_mocc("00:00:00:00:00:01", 0.22, False)

    logger.ooda_decide_kcsm("DEAUTH", "00:00:00:00:00:01", 3, True, "DEAUTH_ATTACK")
    logger.ooda_act_countermeasure("INJECT_FALSE_HANDSHAKE", "00:00:00:00:00:99",
                                    "Poisoning attacker capture")
    logger.ooda_act_alert("DEAUTH_ATTACK", "Client 00:00:00:00:00:01 under attack")

    print()
    logger.print_stats()
