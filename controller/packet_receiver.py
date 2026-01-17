#!/usr/bin/env python3
"""
P4 Switch Packet Receiver
Listens for packets from the P4 switch and forwards them to the OODA Controller

IMPORTANT: The P4 deparser emits packets in this order:
  [CPU Header (4 bytes)][Ethernet (14 bytes)][WiFi FC (2)][WiFi Addr (20)][RF Features (8)]

So we need to parse raw bytes, not rely on Scapy's Ethernet parsing.
"""

import threading
from scapy.all import sniff, Ether, Raw, conf
from typing import Callable, Optional


# WIDD Ethertype
ETHERTYPE_WIDD = 0x88B5

# Header sizes
CPU_HEADER_SIZE = 4      # reason(1) + origPort(1) + rfRssi(2)
ETHERNET_SIZE = 14       # dst(6) + src(6) + type(2)
WIFI_FC_SIZE = 2         # Frame Control
WIFI_ADDR_SIZE = 20      # addr1(6) + addr2(6) + addr3(6) + seqCtrl(2)
RF_FEATURES_SIZE = 8     # rssi(2) + phase(2) + pilot(2) + mag(2)


class PacketReceiver:
    """
    Receives packets from P4 switch interface and forwards to controller.
    Uses Scapy to sniff packets on the switch's interface.

    The P4 switch sends packets with CPU header prepended:
    [CPU Header][Ethernet][WiFi FC][WiFi Addr][RF Features][Payload]
    """

    def __init__(self, interface: str = 's1-cpu-h', callback: Optional[Callable] = None):
        """
        Initialize packet receiver.

        Args:
            interface: Network interface to listen on (e.g., 's1-cpu-h')
            callback: Function to call when packet is received
        """
        self.interface = interface
        self.callback = callback
        self.running = False
        self.thread = None

    def start(self):
        """Start listening for packets in background thread."""
        if self.running:
            print("[PacketReceiver] Already running")
            return

        self.running = True
        self.thread = threading.Thread(target=self._sniff_packets, daemon=True)
        self.thread.start()
        print(f"[PacketReceiver] Started listening on {self.interface}")

    def stop(self):
        """Stop listening for packets."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        print("[PacketReceiver] Stopped")

    def _sniff_packets(self):
        """Sniff packets on the interface and forward to callback."""
        try:
            print(f"[PacketReceiver] Starting sniff on {self.interface}")
            print(f"[PacketReceiver] Expecting P4 format: [CPU(4)][Ether(14)][WiFi FC(2)][WiFi Addr(20)][RF(8)]")

            # Sniff ALL packets - use Raw socket to get raw bytes
            sniff(
                iface=self.interface,
                prn=self._handle_packet,
                filter=None,
                stop_filter=lambda x: not self.running,
                store=False
            )
        except PermissionError as e:
            print(f"[PacketReceiver] Permission Error: {e}")
            print(f"[PacketReceiver] This script must be run with sudo/root privileges")
            import traceback
            traceback.print_exc()
            self.running = False
        except OSError as e:
            print(f"[PacketReceiver] Interface Error: {e}")
            print(f"[PacketReceiver] Interface '{self.interface}' may not exist or is not accessible")
            print(f"[PacketReceiver] Check: sudo ip link show {self.interface}")
            import traceback
            traceback.print_exc()
            self.running = False
        except Exception as e:
            print(f"[PacketReceiver] Unexpected Error: {e}")
            import traceback
            traceback.print_exc()
            self.running = False

    def _handle_packet(self, pkt):
        """Handle received packet from P4 CPU port.

        P4 deparser output format:
        [CPU Header 4B][Ethernet 14B][WiFi FC 2B][WiFi Addr 20B][RF Features 8B][Payload]
        """
        if not self.running:
            return

        try:
            # Get raw bytes from packet
            raw_bytes = bytes(pkt)
            print(f"[PacketReceiver] Received {len(raw_bytes)} bytes: {raw_bytes[:20].hex()}...")

            # Minimum size check: CPU(4) + Ethernet(14) + WiFi FC(2) + WiFi Addr(20) + RF(8) = 48 bytes
            min_size = CPU_HEADER_SIZE + ETHERNET_SIZE + WIFI_FC_SIZE + WIFI_ADDR_SIZE + RF_FEATURES_SIZE
            if len(raw_bytes) < min_size:
                print(f"[PacketReceiver] Packet too short ({len(raw_bytes)} < {min_size} bytes)")
                # Try to parse as regular Ethernet for debugging
                if Ether in pkt:
                    print(f"[PacketReceiver] (Scapy sees: {pkt.summary()})")
                return

            # Parse CPU Header (4 bytes)
            offset = 0
            cpu_reason = raw_bytes[offset]
            cpu_orig_port = raw_bytes[offset + 1]
            cpu_rf_rssi = int.from_bytes(raw_bytes[offset + 2:offset + 4], 'big', signed=True)
            offset += CPU_HEADER_SIZE

            print(f"[PacketReceiver] CPU Header: reason={cpu_reason}, origPort={cpu_orig_port}, rfRssi={cpu_rf_rssi}")

            # Parse Ethernet Header (14 bytes)
            eth_dst = ':'.join(f'{b:02x}' for b in raw_bytes[offset:offset + 6])
            eth_src = ':'.join(f'{b:02x}' for b in raw_bytes[offset + 6:offset + 12])
            eth_type = int.from_bytes(raw_bytes[offset + 12:offset + 14], 'big')
            offset += ETHERNET_SIZE

            print(f"[PacketReceiver] Ethernet: dst={eth_dst}, src={eth_src}, type=0x{eth_type:04x}")

            # Check if this is a WIDD packet
            if eth_type != ETHERTYPE_WIDD:
                print(f"[PacketReceiver] Not a WIDD packet (ethertype=0x{eth_type:04x}), skipping")
                return

            print(f"[PacketReceiver] WIDD packet detected!")

            # Parse WiFi Frame Control (2 bytes)
            wifi_fc = int.from_bytes(raw_bytes[offset:offset + 2], 'big')
            offset += WIFI_FC_SIZE

            # Parse WiFi Addresses (20 bytes)
            addr1 = ':'.join(f'{b:02x}' for b in raw_bytes[offset:offset + 6])      # Receiver
            addr2 = ':'.join(f'{b:02x}' for b in raw_bytes[offset + 6:offset + 12])  # Transmitter
            addr3 = ':'.join(f'{b:02x}' for b in raw_bytes[offset + 12:offset + 18]) # BSSID
            seq_ctrl = int.from_bytes(raw_bytes[offset + 18:offset + 20], 'big')
            offset += WIFI_ADDR_SIZE

            # Parse RF Features (8 bytes)
            rssi = int.from_bytes(raw_bytes[offset:offset + 2], 'big', signed=True)
            phase = int.from_bytes(raw_bytes[offset + 2:offset + 4], 'big')
            pilot = int.from_bytes(raw_bytes[offset + 4:offset + 6], 'big')
            mag = int.from_bytes(raw_bytes[offset + 6:offset + 8], 'big')
            offset += RF_FEATURES_SIZE

            # Extract frame type and subtype from FC
            # P4 FC format: protocol(2) | type(2) | subtype(4) | flags(8)
            # Bits: [15-14: proto] [13-12: type] [11-8: subtype] [7-0: flags]
            frame_type = (wifi_fc >> 12) & 0x3
            subtype = (wifi_fc >> 8) & 0xF

            # Frame type names
            type_names = {0: 'Management', 1: 'Control', 2: 'Data'}
            subtype_names = {
                0x0: 'Assoc Req', 0xA: 'Disassoc', 0xB: 'Auth', 0xC: 'Deauth',
                0x8: 'Beacon'
            }

            frame_info = {
                'frame_type': type_names.get(frame_type, f'Unknown({frame_type})'),
                'subtype': subtype_names.get(subtype, f'0x{subtype:X}'),
                'frame_type_num': frame_type,
                'subtype_num': subtype,
                'src_mac': addr2,
                'dst_mac': addr1,
                'bssid': addr3,
                'seq_ctrl': seq_ctrl,
                'rssi': rssi,
                'phase': phase,
                'pilot': pilot,
                'mag': mag,
                'cpu_reason': cpu_reason,
                'cpu_orig_port': cpu_orig_port,
                'raw_payload': raw_bytes[offset:] if len(raw_bytes) > offset else b''
            }

            print(f"[PacketReceiver] Parsed WIDD frame: {frame_info['frame_type']}/{frame_info['subtype']} from {frame_info['src_mac']}")

            if self.callback:
                self.callback(frame_info)
            else:
                print(f"[PacketReceiver] Frame details: {frame_info}")

        except Exception as e:
            print(f"[PacketReceiver] Error handling packet: {e}")
            import traceback
            traceback.print_exc()

    def _parse_widd_frame(self, payload: bytes) -> dict:
        """
        Parse WIDD frame structure.

        Structure:
        [802.11 FC (2 bytes)][802.11 Addr (20 bytes)][RF Features (8 bytes)][Payload]
        """
        if len(payload) < 30:
            return {'error': 'Packet too short'}

        # Parse 802.11 Frame Control (2 bytes)
        fc = int.from_bytes(payload[0:2], 'big')
        frame_type = (fc >> 2) & 0x3
        subtype = (fc >> 4) & 0xF

        # Parse 802.11 Addresses (20 bytes)
        addr1 = ':'.join(f'{b:02x}' for b in payload[2:8])    # Receiver
        addr2 = ':'.join(f'{b:02x}' for b in payload[8:14])   # Transmitter (Source)
        addr3 = ':'.join(f'{b:02x}' for b in payload[14:20])  # BSSID
        seq_ctrl = int.from_bytes(payload[20:22], 'big')

        # Parse RF Features (8 bytes)
        rssi = int.from_bytes(payload[22:24], 'big', signed=True)
        phase = int.from_bytes(payload[24:26], 'big')
        pilot = int.from_bytes(payload[26:28], 'big')
        mag = int.from_bytes(payload[28:30], 'big')

        # Frame type names
        type_names = {0: 'Management', 1: 'Control', 2: 'Data'}
        subtype_names = {
            0x0: 'Assoc Req', 0xA: 'Disassoc', 0xB: 'Auth', 0xC: 'Deauth',
            0x8: 'Beacon'
        }

        return {
            'frame_type': type_names.get(frame_type, f'Unknown({frame_type})'),
            'subtype': subtype_names.get(subtype, f'0x{subtype:X}'),
            'frame_type_num': frame_type,
            'subtype_num': subtype,
            'src_mac': addr2,
            'dst_mac': addr1,
            'bssid': addr3,
            'seq_ctrl': seq_ctrl,
            'rssi': rssi,
            'phase': phase,
            'pilot': pilot,
            'mag': mag,
            'raw_payload': payload[30:] if len(payload) > 30 else b''
        }


# Test function
if __name__ == '__main__':
    def print_frame(frame_info):
        print(f"Received: {frame_info['frame_type']} / {frame_info['subtype']} "
              f"from {frame_info['src_mac']} RSSI={frame_info['rssi']}dBm")

    receiver = PacketReceiver(interface='s1-cpu-h', callback=print_frame)
    receiver.start()

    try:
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        receiver.stop()
