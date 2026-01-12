#!/usr/bin/env python3
"""
WIDD Attack Generator - Scapy-based attack simulation

Generates attack traffic for testing the WIDD system:
- Deauthentication attacks (spoofed MAC)
- Disassociation attacks
- Authentication floods
- Association floods
- Evil Twin beacons

Uses WIDD frame format (Ethernet + 802.11 headers + RF features).
"""

import struct
import random
import time
from typing import Optional
from scapy.all import Ether, sendp, Raw, conf

# Disable Scapy warnings
conf.verb = 0

# WIDD Ethertype (local experimental)
ETHERTYPE_WIDD = 0x88B5

# 802.11 Frame Types
FRAME_TYPE_MANAGEMENT = 0
FRAME_TYPE_CONTROL = 1
FRAME_TYPE_DATA = 2

# 802.11 Management Subtypes
SUBTYPE_ASSOC_REQ = 0x0
SUBTYPE_AUTH = 0xB
SUBTYPE_DEAUTH = 0xC
SUBTYPE_DISASSOC = 0xA
SUBTYPE_BEACON = 0x8


def mac_to_bytes(mac: str) -> bytes:
    """Convert MAC address string to bytes."""
    return bytes.fromhex(mac.replace(':', ''))


def build_wifi_fc(frame_type: int, subtype: int) -> bytes:
    """
    Build 802.11 Frame Control field (2 bytes).

    Format: protocol(2) | type(2) | subtype(4) | flags(8)
    """
    # protocol version = 0, flags = 0
    fc = (frame_type << 2) | (subtype << 4)
    return struct.pack('!H', fc)


def build_wifi_addr(addr1: str, addr2: str, addr3: str, seq: int = 0) -> bytes:
    """
    Build 802.11 address fields.

    addr1: Receiver address
    addr2: Transmitter address (source)
    addr3: BSSID
    seq: Sequence number
    """
    return (
        mac_to_bytes(addr1) +
        mac_to_bytes(addr2) +
        mac_to_bytes(addr3) +
        struct.pack('!H', seq)
    )


def build_rf_features(rssi: int = -50, phase: int = 200,
                      pilot: int = 100, mag: int = 2000) -> bytes:
    """
    Build simulated RF features.

    These would normally come from the PHY layer.
    For attack simulation, we use different values than legitimate devices.
    """
    return struct.pack('!HHHH', rssi & 0xFFFF, phase, pilot, mag)


def build_widd_frame(frame_type: int, subtype: int,
                     dst_mac: str, src_mac: str, bssid: str,
                     rssi: int = -50, phase: int = 200,
                     pilot: int = 100, mag: int = 2000,
                     payload: bytes = b'') -> bytes:
    """
    Build a complete WIDD frame.

    Structure:
    [Ethernet Header][802.11 FC][802.11 Addr][RF Features][Payload]
    """
    # 802.11 headers
    wifi_fc = build_wifi_fc(frame_type, subtype)
    wifi_addr = build_wifi_addr(dst_mac, src_mac, bssid)
    rf_features = build_rf_features(rssi, phase, pilot, mag)

    # Combine into payload (after Ethernet header)
    wifi_payload = wifi_fc + wifi_addr + rf_features + payload

    return wifi_payload


class AttackGenerator:
    """
    Generator for various WiFi attacks using WIDD frame format.
    """

    def __init__(self, interface: str = None, wap_mac: str = '00:00:00:00:00:AA',
                 wap_bssid: str = '00:00:00:00:00:AA'):
        """
        Initialize attack generator.

        Args:
            interface: Network interface to send packets (e.g., 'attacker-wlan0')
            wap_mac: MAC address of target WAP
            wap_bssid: BSSID of target network
        """
        self.interface = interface
        self.wap_mac = wap_mac
        self.wap_bssid = wap_bssid

        # Attacker's real RF characteristics (different from legitimate devices)
        self.attacker_rssi = -60
        self.attacker_phase = 350
        self.attacker_pilot = 150
        self.attacker_mag = 3500

    def send_frame(self, frame: bytes, dst_mac: str = None, src_mac: str = None):
        """Send a WIDD frame via Scapy."""
        dst = dst_mac or self.wap_mac
        src = src_mac or 'ff:ff:ff:ff:ff:ff'

        # Build Ethernet frame with WIDD payload
        pkt = Ether(dst=dst, src=src, type=ETHERTYPE_WIDD) / Raw(load=frame)

        if self.interface:
            sendp(pkt, iface=self.interface, verbose=False)
        else:
            # Just build without sending (for testing)
            return bytes(pkt)

    def deauth_attack(self, victim_mac: str, count: int = 64,
                      interval: float = 0.01, spoof: bool = True):
        """
        Perform deauthentication attack.

        This simulates aireplay-ng -0 attack.

        Args:
            victim_mac: MAC address to impersonate (if spoofing) or target
            count: Number of deauth frames to send
            interval: Time between frames
            spoof: If True, spoof victim's MAC in the frame
        """
        print(f"[ATTACK] Starting deauth attack")
        print(f"[ATTACK]   Target WAP: {self.wap_mac}")
        print(f"[ATTACK]   Victim MAC: {victim_mac}")
        print(f"[ATTACK]   Count: {count}")
        print(f"[ATTACK]   Spoofed: {spoof}")

        frames_sent = 0

        for i in range(count):
            # Build deauth frame
            if spoof:
                # Spoofed: claim to be victim, but use attacker's RF
                frame = build_widd_frame(
                    frame_type=FRAME_TYPE_MANAGEMENT,
                    subtype=SUBTYPE_DEAUTH,
                    dst_mac=self.wap_mac,
                    src_mac=victim_mac,  # Spoofed source
                    bssid=self.wap_bssid,
                    rssi=self.attacker_rssi,  # Attacker's RF
                    phase=self.attacker_phase,
                    pilot=self.attacker_pilot,
                    mag=self.attacker_mag,
                    payload=b'\x07\x00'  # Reason code: Class 3 frame from nonassociated STA
                )
            else:
                # Legitimate: use victim's RF (for testing)
                frame = build_widd_frame(
                    frame_type=FRAME_TYPE_MANAGEMENT,
                    subtype=SUBTYPE_DEAUTH,
                    dst_mac=self.wap_mac,
                    src_mac=victim_mac,
                    bssid=self.wap_bssid,
                    rssi=-50,
                    phase=200,
                    pilot=100,
                    mag=2000,
                    payload=b'\x03\x00'  # Reason code: Leaving BSS
                )

            self.send_frame(frame, dst_mac=self.wap_mac, src_mac=victim_mac)
            frames_sent += 1

            if interval > 0:
                time.sleep(interval)

        print(f"[ATTACK] Sent {frames_sent} deauth frames")
        return frames_sent

    def disassoc_attack(self, victim_mac: str, count: int = 64,
                        interval: float = 0.01):
        """Perform disassociation attack."""
        print(f"[ATTACK] Starting disassociation attack on {victim_mac}")

        for i in range(count):
            frame = build_widd_frame(
                frame_type=FRAME_TYPE_MANAGEMENT,
                subtype=SUBTYPE_DISASSOC,
                dst_mac=self.wap_mac,
                src_mac=victim_mac,
                bssid=self.wap_bssid,
                rssi=self.attacker_rssi,
                phase=self.attacker_phase,
                pilot=self.attacker_pilot,
                mag=self.attacker_mag,
                payload=b'\x08\x00'  # Reason code
            )
            self.send_frame(frame, dst_mac=self.wap_mac, src_mac=victim_mac)

            if interval > 0:
                time.sleep(interval)

        print(f"[ATTACK] Sent {count} disassoc frames")

    def auth_flood(self, count: int = 100, interval: float = 0.001):
        """
        Perform authentication flood attack.

        Sends many auth requests from random MACs.
        """
        print(f"[ATTACK] Starting auth flood ({count} frames)")

        for i in range(count):
            # Random source MAC
            random_mac = ':'.join(f'{random.randint(0,255):02x}' for _ in range(6))

            frame = build_widd_frame(
                frame_type=FRAME_TYPE_MANAGEMENT,
                subtype=SUBTYPE_AUTH,
                dst_mac=self.wap_mac,
                src_mac=random_mac,
                bssid=self.wap_bssid,
                rssi=random.randint(-80, -40),
                phase=random.randint(100, 400),
                pilot=random.randint(50, 200),
                mag=random.randint(1000, 4000),
                payload=b'\x00\x00\x01\x00\x00\x00'  # Open auth, seq 1
            )
            self.send_frame(frame, dst_mac=self.wap_mac, src_mac=random_mac)

            if interval > 0:
                time.sleep(interval)

        print(f"[ATTACK] Sent {count} auth flood frames")

    def assoc_flood(self, count: int = 100, interval: float = 0.001):
        """Perform association flood attack."""
        print(f"[ATTACK] Starting assoc flood ({count} frames)")

        for i in range(count):
            random_mac = ':'.join(f'{random.randint(0,255):02x}' for _ in range(6))

            frame = build_widd_frame(
                frame_type=FRAME_TYPE_MANAGEMENT,
                subtype=SUBTYPE_ASSOC_REQ,
                dst_mac=self.wap_mac,
                src_mac=random_mac,
                bssid=self.wap_bssid,
                rssi=random.randint(-80, -40),
                phase=random.randint(100, 400),
                pilot=random.randint(50, 200),
                mag=random.randint(1000, 4000)
            )
            self.send_frame(frame, dst_mac=self.wap_mac, src_mac=random_mac)

            if interval > 0:
                time.sleep(interval)

        print(f"[ATTACK] Sent {count} assoc flood frames")

    def evil_twin_beacon(self, ssid: str = 'WIDD_Network', count: int = 10,
                         interval: float = 0.1):
        """
        Broadcast evil twin beacons.

        Uses same SSID but different BSSID.
        """
        rogue_bssid = 'AA:BB:CC:DD:EE:FF'
        print(f"[ATTACK] Broadcasting evil twin beacons")
        print(f"[ATTACK]   SSID: {ssid}")
        print(f"[ATTACK]   Rogue BSSID: {rogue_bssid}")

        for i in range(count):
            # Build beacon frame (simplified)
            # In real beacon, SSID is in IE field
            frame = build_widd_frame(
                frame_type=FRAME_TYPE_MANAGEMENT,
                subtype=SUBTYPE_BEACON,
                dst_mac='ff:ff:ff:ff:ff:ff',  # Broadcast
                src_mac=rogue_bssid,
                bssid=rogue_bssid,
                rssi=self.attacker_rssi,
                phase=self.attacker_phase,
                pilot=self.attacker_pilot,
                mag=self.attacker_mag,
                payload=ssid.encode()  # Simplified SSID (not proper IE format)
            )
            self.send_frame(frame, dst_mac='ff:ff:ff:ff:ff:ff', src_mac=rogue_bssid)

            if interval > 0:
                time.sleep(interval)

        print(f"[ATTACK] Sent {count} evil twin beacons")

    def generate_legitimate_data(self, client_mac: str, count: int = 100,
                                 rssi: int = -50, phase: int = 200,
                                 pilot: int = 100, mag: int = 2000):
        """
        Generate legitimate data frames for MOCC training.

        These use consistent RF characteristics for the client.
        """
        print(f"[GEN] Generating {count} data frames for {client_mac}")

        for i in range(count):
            # Add small noise to RF features
            frame = build_widd_frame(
                frame_type=FRAME_TYPE_DATA,
                subtype=0,  # Data
                dst_mac=self.wap_mac,
                src_mac=client_mac,
                bssid=self.wap_bssid,
                rssi=rssi + random.randint(-3, 3),
                phase=phase + random.randint(-10, 10),
                pilot=pilot + random.randint(-5, 5),
                mag=mag + random.randint(-50, 50)
            )
            self.send_frame(frame, dst_mac=self.wap_mac, src_mac=client_mac)

        print(f"[GEN] Sent {count} data frames")


# Test the attack generator
if __name__ == '__main__':
    print("Testing Attack Generator (no actual sending)...\n")

    # Create generator without interface (won't actually send)
    gen = AttackGenerator(
        interface=None,
        wap_mac='00:00:00:00:00:AA',
        wap_bssid='00:00:00:00:00:AA'
    )

    # Test frame building
    print("--- Building test frames ---")

    # Deauth frame
    frame = build_widd_frame(
        frame_type=FRAME_TYPE_MANAGEMENT,
        subtype=SUBTYPE_DEAUTH,
        dst_mac='00:00:00:00:00:AA',
        src_mac='00:00:00:00:00:01',
        bssid='00:00:00:00:00:AA',
        rssi=-60,
        phase=350,
        pilot=150,
        mag=3500
    )
    print(f"Deauth frame: {len(frame)} bytes")
    print(f"  Hex: {frame.hex()}")

    # Test attack simulation
    print("\n--- Attack simulation (dry run) ---")
    gen.deauth_attack('00:00:00:00:00:01', count=3, interval=0)
