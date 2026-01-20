#!/usr/bin/env python3
"""
WIDD AP Agent - Listens for management frame commands from the controller

This agent runs on the AP (or in the AP's network namespace) and:
1. Listens on the AP's eth interface (connected to the P4 switch)
2. Receives 802.11 management frames forwarded by the controller
3. Executes the appropriate action (e.g., deauth station via hostapd_cli)

Flow:
    Controller -> P4 Switch (Packet-Out) -> AP eth interface -> AP Agent -> hostapd_cli -> Station disconnected

Usage:
    sudo python3 ap_agent.py --interface ap1-eth2 --wlan ap1-wlan1

    Or run inside AP namespace:
    sudo mnexec -a <ap_pid> python3 ap_agent.py --interface ap1-eth2 --wlan ap1-wlan1
"""

import argparse
import struct
import subprocess
import sys
import os
from typing import Optional

try:
    from scapy.all import sniff, Raw, conf
    conf.verb = 0
except ImportError:
    print("Error: Scapy not found. Install with: pip install scapy")
    sys.exit(1)


# 802.11 Frame Control parsing
FRAME_TYPE_MANAGEMENT = 0
SUBTYPE_DEAUTH = 0xC
SUBTYPE_DISASSOC = 0xA

# Reason code descriptions
REASON_CODES = {
    1: "Unspecified reason",
    2: "Previous authentication no longer valid",
    3: "Deauthenticated because sending station is leaving",
    4: "Disassociated due to inactivity",
    5: "Disassociated because AP is unable to handle all associated stations",
    6: "Class 2 frame received from nonauthenticated station",
    7: "Class 3 frame received from nonassociated station",
    8: "Disassociated because sending station is leaving",
}


def parse_80211_mgmt_frame(raw_bytes: bytes) -> Optional[dict]:
    """
    Parse a raw 802.11 management frame.

    Expected format (26 bytes for deauth/disassoc):
    - Frame Control: 2 bytes
    - Duration: 2 bytes
    - Address 1 (Destination): 6 bytes
    - Address 2 (Source): 6 bytes
    - Address 3 (BSSID): 6 bytes
    - Sequence Control: 2 bytes
    - Reason Code: 2 bytes (for deauth/disassoc)

    Returns:
        Dictionary with parsed frame info or None if invalid
    """
    if len(raw_bytes) < 24:  # Minimum management frame header
        return None

    # Parse Frame Control (2 bytes, little-endian)
    fc = raw_bytes[0] | (raw_bytes[1] << 8)

    # Extract type and subtype
    # Byte 0: Protocol(2b) + Type(2b) + Subtype(4b)
    frame_type = (raw_bytes[0] >> 2) & 0x3
    subtype = (raw_bytes[0] >> 4) & 0xF

    # Only process management frames
    if frame_type != FRAME_TYPE_MANAGEMENT:
        return None

    # Parse addresses
    addr1 = ':'.join(f'{b:02x}' for b in raw_bytes[4:10])   # Destination
    addr2 = ':'.join(f'{b:02x}' for b in raw_bytes[10:16])  # Source
    addr3 = ':'.join(f'{b:02x}' for b in raw_bytes[16:22])  # BSSID

    # Parse sequence control
    seq_ctrl = struct.unpack('<H', raw_bytes[22:24])[0]
    seq_num = seq_ctrl >> 4

    # Parse reason code if present (for deauth/disassoc)
    reason_code = None
    if len(raw_bytes) >= 26 and subtype in (SUBTYPE_DEAUTH, SUBTYPE_DISASSOC):
        reason_code = struct.unpack('<H', raw_bytes[24:26])[0]

    return {
        'frame_type': frame_type,
        'subtype': subtype,
        'dst_mac': addr1,
        'src_mac': addr2,
        'bssid': addr3,
        'seq_num': seq_num,
        'reason_code': reason_code,
        'raw': raw_bytes
    }


def deauth_station(wlan_iface: str, station_mac: str, reason_code: int = 3) -> bool:
    """
    Deauthenticate a station using hostapd_cli.

    Args:
        wlan_iface: Wireless interface running hostapd (e.g., 'ap1-wlan1')
        station_mac: MAC address of station to deauthenticate
        reason_code: Deauth reason code

    Returns:
        True if successful
    """
    try:
        # Use hostapd_cli to deauthenticate the station
        cmd = ['hostapd_cli', '-i', wlan_iface, 'deauthenticate', station_mac]
        print(f"[AP-Agent] Executing: {' '.join(cmd)}")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

        if result.returncode == 0:
            print(f"[AP-Agent] Successfully deauthenticated {station_mac}")
            print(f"[AP-Agent] Reason: {REASON_CODES.get(reason_code, f'Code {reason_code}')}")
            return True
        else:
            print(f"[AP-Agent] hostapd_cli failed: {result.stderr}")
            return False

    except subprocess.TimeoutExpired:
        print(f"[AP-Agent] hostapd_cli timed out")
        return False
    except FileNotFoundError:
        print(f"[AP-Agent] hostapd_cli not found - trying alternative method")
        return deauth_station_scapy(wlan_iface, station_mac, reason_code)
    except Exception as e:
        print(f"[AP-Agent] Error deauthenticating station: {e}")
        return False


def disassoc_station(wlan_iface: str, station_mac: str, reason_code: int = 8) -> bool:
    """
    Disassociate a station using hostapd_cli.

    Args:
        wlan_iface: Wireless interface running hostapd
        station_mac: MAC address of station to disassociate
        reason_code: Disassoc reason code

    Returns:
        True if successful
    """
    try:
        cmd = ['hostapd_cli', '-i', wlan_iface, 'disassociate', station_mac]
        print(f"[AP-Agent] Executing: {' '.join(cmd)}")

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

        if result.returncode == 0:
            print(f"[AP-Agent] Successfully disassociated {station_mac}")
            print(f"[AP-Agent] Reason: {REASON_CODES.get(reason_code, f'Code {reason_code}')}")
            return True
        else:
            print(f"[AP-Agent] hostapd_cli failed: {result.stderr}")
            return False

    except Exception as e:
        print(f"[AP-Agent] Error disassociating station: {e}")
        return False


def deauth_station_scapy(wlan_iface: str, station_mac: str, reason_code: int = 3) -> bool:
    """
    Fallback: Send deauth frame directly using Scapy (requires monitor mode or injection support).

    Args:
        wlan_iface: Wireless interface
        station_mac: MAC address of station
        reason_code: Deauth reason

    Returns:
        True if frame was sent
    """
    try:
        from scapy.all import sendp, Dot11, Dot11Deauth, RadioTap

        # Get BSSID from interface (simplified - assume it's the interface MAC)
        import fcntl
        import socket

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', wlan_iface[:15].encode()))
        bssid = ':'.join('%02x' % b for b in info[18:24])
        s.close()

        # Build deauth frame
        frame = RadioTap() / Dot11(
            type=0,  # Management
            subtype=12,  # Deauth
            addr1=station_mac,  # Destination
            addr2=bssid,  # Source (AP)
            addr3=bssid   # BSSID
        ) / Dot11Deauth(reason=reason_code)

        print(f"[AP-Agent] Sending deauth via Scapy on {wlan_iface}")
        sendp(frame, iface=wlan_iface, verbose=False, count=3)
        return True

    except Exception as e:
        print(f"[AP-Agent] Scapy deauth failed: {e}")
        return False


class APAgent:
    """
    AP Agent that listens for controller commands and executes them.
    """

    def __init__(self, eth_iface: str, wlan_iface: str):
        """
        Initialize AP Agent.

        Args:
            eth_iface: Ethernet interface connected to P4 switch (e.g., 'ap1-eth2')
            wlan_iface: Wireless interface running hostapd (e.g., 'ap1-wlan1')
        """
        self.eth_iface = eth_iface
        self.wlan_iface = wlan_iface
        self.running = False

        # Statistics
        self.stats = {
            'frames_received': 0,
            'deauth_executed': 0,
            'disassoc_executed': 0,
            'errors': 0
        }

    def handle_packet(self, pkt):
        """Process received packet from P4 switch."""
        try:
            raw_bytes = bytes(pkt)
            self.stats['frames_received'] += 1

            # Parse the 802.11 management frame
            frame_info = parse_80211_mgmt_frame(raw_bytes)

            if frame_info is None:
                return

            subtype = frame_info['subtype']
            dst_mac = frame_info['dst_mac']
            src_mac = frame_info['src_mac']
            reason_code = frame_info['reason_code'] or 3

            print(f"\n[AP-Agent] Received management frame:")
            print(f"[AP-Agent]   Type: {'Deauth' if subtype == SUBTYPE_DEAUTH else 'Disassoc' if subtype == SUBTYPE_DISASSOC else f'Unknown({subtype})'}")
            print(f"[AP-Agent]   Destination: {dst_mac}")
            print(f"[AP-Agent]   Source: {src_mac}")
            print(f"[AP-Agent]   Reason: {reason_code} ({REASON_CODES.get(reason_code, 'Unknown')})")
            print(f"[AP-Agent]   Frame hex: {raw_bytes[:26].hex()}")

            # Execute the appropriate action
            if subtype == SUBTYPE_DEAUTH:
                # The destination of the deauth is the station to disconnect
                # In a deauth from station to AP, dst_mac would be AP
                # In a deauth from AP to station, dst_mac would be station
                # We need to determine which station to deauth based on the frame

                # If dst is broadcast or AP's MAC, the station to deauth is src_mac
                # If dst is a specific station, that's who we deauth
                target_mac = dst_mac
                if dst_mac == 'ff:ff:ff:ff:ff:ff' or dst_mac == frame_info['bssid']:
                    target_mac = src_mac

                print(f"[AP-Agent] Executing DEAUTH for station: {target_mac}")
                if deauth_station(self.wlan_iface, target_mac, reason_code):
                    self.stats['deauth_executed'] += 1
                else:
                    self.stats['errors'] += 1

            elif subtype == SUBTYPE_DISASSOC:
                target_mac = dst_mac
                if dst_mac == 'ff:ff:ff:ff:ff:ff' or dst_mac == frame_info['bssid']:
                    target_mac = src_mac

                print(f"[AP-Agent] Executing DISASSOC for station: {target_mac}")
                if disassoc_station(self.wlan_iface, target_mac, reason_code):
                    self.stats['disassoc_executed'] += 1
                else:
                    self.stats['errors'] += 1
            else:
                print(f"[AP-Agent] Ignoring non-deauth/disassoc frame (subtype={subtype})")

        except Exception as e:
            print(f"[AP-Agent] Error processing packet: {e}")
            self.stats['errors'] += 1
            import traceback
            traceback.print_exc()

    def start(self):
        """Start listening for packets from the P4 switch."""
        print(f"\n{'='*60}")
        print(f"  WIDD AP Agent Started")
        print(f"{'='*60}")
        print(f"  Listening on: {self.eth_iface} (from P4 switch)")
        print(f"  Wireless interface: {self.wlan_iface}")
        print(f"  Waiting for management frames from controller...")
        print(f"{'='*60}\n")

        self.running = True

        try:
            # Use Scapy to sniff packets on the eth interface
            sniff(
                iface=self.eth_iface,
                prn=self.handle_packet,
                filter=None,  # Accept all packets
                stop_filter=lambda x: not self.running,
                store=False
            )
        except PermissionError:
            print(f"[AP-Agent] Permission denied. Run with sudo.")
            sys.exit(1)
        except OSError as e:
            print(f"[AP-Agent] Interface error: {e}")
            print(f"[AP-Agent] Make sure {self.eth_iface} exists")
            sys.exit(1)
        except KeyboardInterrupt:
            print("\n[AP-Agent] Stopping...")

        self.print_stats()

    def stop(self):
        """Stop the agent."""
        self.running = False

    def print_stats(self):
        """Print statistics."""
        print(f"\n{'='*60}")
        print(f"  AP Agent Statistics")
        print(f"{'='*60}")
        print(f"  Frames received: {self.stats['frames_received']}")
        print(f"  Deauths executed: {self.stats['deauth_executed']}")
        print(f"  Disassocs executed: {self.stats['disassoc_executed']}")
        print(f"  Errors: {self.stats['errors']}")
        print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description='WIDD AP Agent - Execute controller decisions'
    )
    parser.add_argument(
        '--interface', '-i',
        default='ap1-eth2',
        help='Ethernet interface connected to P4 switch (default: ap1-eth2)'
    )
    parser.add_argument(
        '--wlan', '-w',
        default='ap1-wlan1',
        help='Wireless interface running hostapd (default: ap1-wlan1)'
    )

    args = parser.parse_args()

    # Check if running as root
    if os.geteuid() != 0:
        print("Error: AP Agent requires root privileges.")
        print("Please run with: sudo python3 ap_agent.py")
        sys.exit(1)

    agent = APAgent(
        eth_iface=args.interface,
        wlan_iface=args.wlan
    )

    try:
        agent.start()
    except KeyboardInterrupt:
        agent.stop()


if __name__ == '__main__':
    main()
