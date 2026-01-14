#!/usr/bin/env python3
"""
P4 Switch Packet Receiver
Listens for packets from the P4 switch and forwards them to the OODA Controller
"""

import threading
from scapy.all import sniff, Ether, Raw
from typing import Callable, Optional


# WIDD Ethertype
ETHERTYPE_WIDD = 0x88B5


class PacketReceiver:
    """
    Receives packets from P4 switch interface and forwards to controller.
    Uses Scapy to sniff packets on the switch's interface.
    """

    def __init__(self, interface: str = 's1-cpu-h', callback: Optional[Callable] = None):
        """
        Initialize packet receiver.

        Args:
            interface: Network interface to listen on (e.g., 's1-eth1')
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
            print(f"[PacketReceiver] NOTE: This requires root privileges and interface must exist")
            print(f"[PacketReceiver] Capturing ALL packets (no BPF filter) for debugging")

            # Sniff ALL packets for debugging (no filter)
            sniff(
                iface=self.interface,
                prn=self._handle_packet,
                filter=None,  # No filter - capture everything for debugging
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
        """Handle received packet from P4 CPU port."""
        if not self.running:
            return

        try:
            print(f"[PacketReceiver] Received packet: {pkt.summary()}")

            # Packets from CPU port have Ethernet header, then the original packet
            if Ether in pkt:
                # Check if this is a WIDD packet
                if pkt[Ether].type == ETHERTYPE_WIDD:
                    print(f"[PacketReceiver] Packet has WIDD ethertype (0x{ETHERTYPE_WIDD:04x})")

                    if Raw in pkt:
                        payload = bytes(pkt[Raw].load)
                        print(f"[PacketReceiver] Total payload length: {len(payload)} bytes")

                        # P4 sends packets with CPU header prepended
                        # CPU Header: 4 bytes (reason, origPort, rfRssi)
                        if len(payload) >= 4:
                            # Parse CPU header
                            cpu_reason = payload[0]
                            cpu_orig_port = payload[1]
                            cpu_rf_rssi = int.from_bytes(payload[2:4], 'big', signed=True)

                            print(f"[PacketReceiver] CPU Header: reason={cpu_reason}, origPort={cpu_orig_port}, rfRssi={cpu_rf_rssi}")

                            # Skip CPU header, parse WIDD frame
                            widd_payload = payload[4:]
                            print(f"[PacketReceiver] WIDD payload length: {len(widd_payload)} bytes")

                            # Parse 802.11 headers from payload
                            frame_info = self._parse_widd_frame(widd_payload)
                            frame_info['cpu_reason'] = cpu_reason
                            frame_info['cpu_orig_port'] = cpu_orig_port

                            print(f"[PacketReceiver] Parsed frame: {frame_info}")

                            if self.callback:
                                self.callback(frame_info)
                            else:
                                print(f"[PacketReceiver] Received WIDD frame: {frame_info}")
                        else:
                            print(f"[PacketReceiver] Payload too short for CPU header ({len(payload)} bytes)")
                    else:
                        print(f"[PacketReceiver] No Raw layer in packet")
                else:
                    # Not a WIDD packet - might be ARP, IP, etc
                    print(f"[PacketReceiver] Non-WIDD packet: ethertype=0x{pkt[Ether].type:04x}")
            else:
                print(f"[PacketReceiver] No Ethernet layer in packet")

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
