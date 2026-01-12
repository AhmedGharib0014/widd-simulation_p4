#!/usr/bin/env python3
"""
WIDD KCSM - Kill Chain State Machines

Implements the state machines from the paper (Figures 4-7):
- Deauthentication KCSM
- Disassociation KCSM
- Authentication Flood KCSM
- Association Flood KCSM

Each state machine tracks attack progression on a per-client basis.
States are maintained with timeouts (2-second window from paper).

State Machine Inputs (Table 2 from paper):
| Input                | Qa | Qb | Qc | Qd |
|---------------------|----|----|----|----|
| Data Frame          | 0  | 0  | 0  | x  |
| Authentication      | 0  | 0  | 1  | x  |
| Deauth (False ID)   | 0  | 1  | 0  | 1  |
| Deauth (True ID)    | 0  | 1  | 0  | 0  |
| Evil Twin Beacon    | 0  | 1  | 1  | x  |
| Association         | 1  | 0  | 0  | x  |
| Disassoc (False ID) | 1  | 0  | 1  | 1  |
| Disassoc (True ID)  | 1  | 0  | 1  | 0  |

State Machine Outputs (Table 3 from paper):
| Output           | Ka | Kb | Kc |
|-----------------|----|----|-----|
| No Attack       | 0  | 0  | 0   |
| Deauth Attack   | 0  | 0  | 1   |
| Disassoc Attack | 0  | 1  | 0   |
| Evil Twin       | 0  | 1  | 1   |
| Credential Atk  | 1  | 0  | 0   |
| Auth Flood      | 1  | 0  | 1   |
| Assoc Flood     | 1  | 1  | 0   |
"""

import time
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple
from collections import defaultdict


class AttackType(Enum):
    """Detected attack types."""
    NONE = 0
    DEAUTH = 1
    DISASSOC = 2
    EVIL_TWIN = 3
    CREDENTIAL = 4
    AUTH_FLOOD = 5
    ASSOC_FLOOD = 6


class FrameType(Enum):
    """Frame types for state machine input."""
    DATA = auto()
    AUTH = auto()
    DEAUTH_TRUE = auto()   # Deauth from verified device
    DEAUTH_FALSE = auto()  # Deauth from unverified device
    ASSOC = auto()
    DISASSOC_TRUE = auto()
    DISASSOC_FALSE = auto()
    BEACON_EVIL = auto()   # Beacon with same SSID, different BSSID


@dataclass
class ClientState:
    """State tracking for a single client."""
    mac_address: str

    # Deauth KCSM state (Figure 4)
    # States: 0000 -> 0001 -> 0010 -> 0011 (attack)
    deauth_state: int = 0
    deauth_false_count: int = 0
    deauth_total_count: int = 0
    deauth_last_time: float = 0

    # Disassoc KCSM state (Figure 5)
    disassoc_state: int = 0
    disassoc_false_count: int = 0
    disassoc_total_count: int = 0
    disassoc_last_time: float = 0

    # Auth flood KCSM state (Figure 6)
    auth_flood_state: int = 0
    auth_count: int = 0
    auth_last_time: float = 0

    # Assoc flood KCSM state (Figure 7)
    assoc_flood_state: int = 0
    assoc_count: int = 0
    assoc_last_time: float = 0

    # Evil twin detection
    evil_twin_detected: bool = False


class DeauthKCSM:
    """
    Deauthentication Kill Chain State Machine (Figure 4 from paper).

    States:
    - 0000: Normal (no attack)
    - 0001: First suspicious deauth received
    - 0010: Second suspicious deauth received
    - 0011: Attack confirmed (trigger countermeasures)

    Transitions:
    - Any deauth with false ID: increment false count, advance state
    - Total of 3 deauths OR 2 false deauths: attack confirmed
    - Timeout (2s): reset to state 0000
    """

    # Timeout in seconds (from paper: hostapd deauth timeout)
    TIMEOUT = 2.0

    # Thresholds
    FALSE_DEAUTH_THRESHOLD = 2   # 2 false deauths = attack
    TOTAL_DEAUTH_THRESHOLD = 3   # 3 total deauths = attack

    def __init__(self):
        # Per-client states: MAC -> ClientState
        self.clients: Dict[str, ClientState] = {}

    def get_client(self, mac_address: str) -> ClientState:
        """Get or create client state."""
        if mac_address not in self.clients:
            self.clients[mac_address] = ClientState(mac_address=mac_address)
        return self.clients[mac_address]

    def update(self, mac_address: str, is_legitimate: bool) -> Tuple[AttackType, bool]:
        """
        Update state machine with a deauth frame.

        Args:
            mac_address: Client MAC address (claimed)
            is_legitimate: True if MOCC verified the device identity

        Returns:
            Tuple of (AttackType, should_drop)
        """
        client = self.get_client(mac_address)
        now = time.time()

        # Check for timeout - reset if too much time has passed
        if now - client.deauth_last_time > self.TIMEOUT:
            client.deauth_state = 0
            client.deauth_false_count = 0
            client.deauth_total_count = 0

        client.deauth_last_time = now
        client.deauth_total_count += 1

        if not is_legitimate:
            client.deauth_false_count += 1

        # State transitions (based on Figure 4)
        attack_detected = False
        should_drop = False

        if not is_legitimate:
            # False deauth - always drop and advance state
            should_drop = True
            client.deauth_state = min(client.deauth_state + 1, 3)

            if client.deauth_false_count >= self.FALSE_DEAUTH_THRESHOLD:
                attack_detected = True

        # Check total count threshold
        if client.deauth_total_count >= self.TOTAL_DEAUTH_THRESHOLD:
            attack_detected = True

        if attack_detected:
            client.deauth_state = 3  # 0011 = attack state
            return (AttackType.DEAUTH, should_drop)

        return (AttackType.NONE, should_drop)

    def reset(self, mac_address: str):
        """Reset state for a client."""
        if mac_address in self.clients:
            client = self.clients[mac_address]
            client.deauth_state = 0
            client.deauth_false_count = 0
            client.deauth_total_count = 0


class DisassocKCSM:
    """
    Disassociation Kill Chain State Machine (Figure 5 from paper).

    Similar structure to DeauthKCSM.
    """

    TIMEOUT = 2.0
    FALSE_THRESHOLD = 2
    TOTAL_THRESHOLD = 3

    def __init__(self):
        self.clients: Dict[str, ClientState] = {}

    def get_client(self, mac_address: str) -> ClientState:
        if mac_address not in self.clients:
            self.clients[mac_address] = ClientState(mac_address=mac_address)
        return self.clients[mac_address]

    def update(self, mac_address: str, is_legitimate: bool) -> Tuple[AttackType, bool]:
        client = self.get_client(mac_address)
        now = time.time()

        if now - client.disassoc_last_time > self.TIMEOUT:
            client.disassoc_state = 0
            client.disassoc_false_count = 0
            client.disassoc_total_count = 0

        client.disassoc_last_time = now
        client.disassoc_total_count += 1

        if not is_legitimate:
            client.disassoc_false_count += 1

        attack_detected = False
        should_drop = not is_legitimate

        if not is_legitimate:
            client.disassoc_state = min(client.disassoc_state + 1, 3)

            if client.disassoc_false_count >= self.FALSE_THRESHOLD:
                attack_detected = True

        if client.disassoc_total_count >= self.TOTAL_THRESHOLD:
            attack_detected = True

        if attack_detected:
            client.disassoc_state = 3
            return (AttackType.DISASSOC, should_drop)

        return (AttackType.NONE, should_drop)


class AuthFloodKCSM:
    """
    Authentication Flood Kill Chain State Machine (Figure 6 from paper).

    Detects flood of authentication requests.
    """

    TIMEOUT = 2.0
    FLOOD_THRESHOLD = 10  # Frames per timeout window

    def __init__(self):
        self.auth_count = 0
        self.last_time = 0.0
        self.state = 0

    def update(self) -> AttackType:
        now = time.time()

        if now - self.last_time > self.TIMEOUT:
            self.auth_count = 0
            self.state = 0

        self.last_time = now
        self.auth_count += 1
        self.state = min(self.state + 1, 3)

        if self.auth_count >= self.FLOOD_THRESHOLD:
            return AttackType.AUTH_FLOOD

        return AttackType.NONE


class AssocFloodKCSM:
    """
    Association Flood Kill Chain State Machine (Figure 7 from paper).

    Detects flood of association requests.
    """

    TIMEOUT = 2.0
    FLOOD_THRESHOLD = 10

    def __init__(self):
        self.assoc_count = 0
        self.last_time = 0.0
        self.state = 0

    def update(self) -> AttackType:
        now = time.time()

        if now - self.last_time > self.TIMEOUT:
            self.assoc_count = 0
            self.state = 0

        self.last_time = now
        self.assoc_count += 1
        self.state = min(self.state + 1, 3)

        if self.assoc_count >= self.FLOOD_THRESHOLD:
            return AttackType.ASSOC_FLOOD

        return AttackType.NONE


class KCSMManager:
    """
    Manager for all Kill Chain State Machines.

    Provides unified interface for updating and querying state.
    """

    def __init__(self):
        self.deauth_kcsm = DeauthKCSM()
        self.disassoc_kcsm = DisassocKCSM()
        self.auth_flood_kcsm = AuthFloodKCSM()
        self.assoc_flood_kcsm = AssocFloodKCSM()

        # Evil twin tracking
        self.known_ssid: Optional[str] = None
        self.known_bssid: Optional[str] = None
        self.evil_twin_detected = False

        # Attack statistics
        self.attack_counts: Dict[AttackType, int] = defaultdict(int)

    def set_network_info(self, ssid: str, bssid: str):
        """Set the legitimate network SSID and BSSID."""
        self.known_ssid = ssid
        self.known_bssid = bssid

    def process_deauth(self, mac_address: str, is_legitimate: bool) -> Tuple[AttackType, bool]:
        """Process a deauthentication frame."""
        attack, should_drop = self.deauth_kcsm.update(mac_address, is_legitimate)
        if attack != AttackType.NONE:
            self.attack_counts[attack] += 1
            print(f"[KCSM] DEAUTH ATTACK detected for client {mac_address}")
        return (attack, should_drop)

    def process_disassoc(self, mac_address: str, is_legitimate: bool) -> Tuple[AttackType, bool]:
        """Process a disassociation frame."""
        attack, should_drop = self.disassoc_kcsm.update(mac_address, is_legitimate)
        if attack != AttackType.NONE:
            self.attack_counts[attack] += 1
            print(f"[KCSM] DISASSOC ATTACK detected for client {mac_address}")
        return (attack, should_drop)

    def process_auth(self) -> AttackType:
        """Process an authentication frame."""
        attack = self.auth_flood_kcsm.update()
        if attack != AttackType.NONE:
            self.attack_counts[attack] += 1
            print(f"[KCSM] AUTH FLOOD ATTACK detected")
        return attack

    def process_assoc(self) -> AttackType:
        """Process an association frame."""
        attack = self.assoc_flood_kcsm.update()
        if attack != AttackType.NONE:
            self.attack_counts[attack] += 1
            print(f"[KCSM] ASSOC FLOOD ATTACK detected")
        return attack

    def process_beacon(self, ssid: str, bssid: str) -> AttackType:
        """Process a beacon frame to detect evil twin."""
        if self.known_ssid and self.known_bssid:
            if ssid == self.known_ssid and bssid != self.known_bssid:
                self.evil_twin_detected = True
                self.attack_counts[AttackType.EVIL_TWIN] += 1
                print(f"[KCSM] EVIL TWIN detected: SSID={ssid}, rogue BSSID={bssid}")
                return AttackType.EVIL_TWIN
        return AttackType.NONE

    def get_stats(self) -> Dict:
        """Get attack statistics."""
        return {
            'attacks_detected': dict(self.attack_counts),
            'total_attacks': sum(self.attack_counts.values()),
            'evil_twin_active': self.evil_twin_detected
        }


# Test the KCSM
if __name__ == '__main__':
    print("Testing KCSM...")

    manager = KCSMManager()
    manager.set_network_info('WIDD_Network', '00:11:22:33:44:55')

    # Test 1: Legitimate deauth (should pass)
    print("\n--- Test 1: Single legitimate deauth ---")
    attack, drop = manager.process_deauth('00:00:00:00:00:01', is_legitimate=True)
    print(f"Attack: {attack.name}, Drop: {drop}")

    # Test 2: Spoofed deauth attack
    print("\n--- Test 2: Spoofed deauth attack (3 false deauths) ---")
    for i in range(3):
        attack, drop = manager.process_deauth('00:00:00:00:00:01', is_legitimate=False)
        print(f"Frame {i+1}: Attack: {attack.name}, Drop: {drop}")

    # Test 3: Auth flood
    print("\n--- Test 3: Auth flood (15 auth frames) ---")
    for i in range(15):
        attack = manager.process_auth()
        if attack != AttackType.NONE:
            print(f"Frame {i+1}: Flood detected!")
            break

    # Test 4: Evil twin
    print("\n--- Test 4: Evil twin beacon ---")
    attack = manager.process_beacon('WIDD_Network', 'AA:BB:CC:DD:EE:FF')
    print(f"Attack: {attack.name}")

    # Print stats
    print("\n--- Attack Statistics ---")
    print(manager.get_stats())
