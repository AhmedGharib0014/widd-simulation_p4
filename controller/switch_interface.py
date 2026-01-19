#!/usr/bin/env python3
"""
WIDD Switch Interface - Thrift connection to bmv2

Provides:
- Connection to bmv2 simple_switch via Thrift
- Table entry management (add/delete/modify)
- Register read/write
- Packet-In/Packet-Out handling via CPU port
- WIDD frame parsing (consolidated from packet_receiver.py)
"""

import sys
import os
import socket
import struct
from threading import Thread, Event
from queue import Queue
from typing import Optional, Callable, Dict, Any
from dataclasses import dataclass

# Add bmv2 thrift paths
BMV2_THRIFT_PATH = '/usr/local/lib/python3/dist-packages/bm_runtime'
if os.path.exists(BMV2_THRIFT_PATH):
    sys.path.insert(0, BMV2_THRIFT_PATH)

try:
    from bm_runtime.standard import Standard
    from bm_runtime.standard.ttypes import *
except ImportError:
    print("Warning: bmv2 runtime not found. Using mock interface.")
    Standard = None

try:
    from thrift.transport import TSocket
    from thrift.transport import TTransport
    from thrift.protocol import TBinaryProtocol
    from thrift.protocol import TMultiplexedProtocol
except ImportError:
    print("Error: Thrift library not found. Install with: pip install thrift")
    sys.exit(1)


# CPU header format (must match P4 cpu_header_t)
# reason (1 byte) + origPort (1 byte) + rfRssi (2 bytes) = 4 bytes
CPU_HEADER_FORMAT = '!BBH'
CPU_HEADER_SIZE = 4

# Header sizes for WIDD frame parsing
ETHERNET_SIZE = 14       # dst(6) + src(6) + type(2)
WIFI_FC_SIZE = 2         # Frame Control
WIFI_ADDR_SIZE = 20      # addr1(6) + addr2(6) + addr3(6) + seqCtrl(2)
RF_FEATURES_SIZE = 8     # rssi(2) + phase(2) + pilot(2) + mag(2)

# WIDD Ethertype
ETHERTYPE_WIDD = 0x88B5

# CPU reasons (from P4 program)
CPU_REASON_DEAUTH = 1
CPU_REASON_ASSOC = 2
CPU_REASON_AUTH = 3
CPU_REASON_BEACON = 4
CPU_REASON_DISASSOC = 5
CPU_REASON_DATA = 6

# Frame type names
FRAME_TYPE_NAMES = {0: 'Management', 1: 'Control', 2: 'Data'}
SUBTYPE_NAMES = {
    0x0: 'Assoc Req', 0x1: 'Assoc Resp', 0x2: 'Reassoc Req', 0x3: 'Reassoc Resp',
    0x4: 'Probe Req', 0x5: 'Probe Resp', 0x8: 'Beacon',
    0xA: 'Disassoc', 0xB: 'Auth', 0xC: 'Deauth'
}


@dataclass
class WIDDFrameInfo:
    """Parsed WIDD frame information."""
    frame_type: str = 'Unknown'
    subtype: str = 'Unknown'
    frame_type_num: int = 0
    subtype_num: int = 0
    src_mac: str = '00:00:00:00:00:00'
    dst_mac: str = '00:00:00:00:00:00'
    bssid: str = '00:00:00:00:00:00'
    seq_ctrl: int = 0
    rssi: int = 0
    phase: int = 0
    pilot: int = 0
    mag: int = 0
    cpu_reason: int = 0
    cpu_orig_port: int = 0
    raw_payload: bytes = b''
    raw_bytes: bytes = b''
    error: str = None


class PacketInEvent:
    """Represents a Packet-In event from bmv2 with full WIDD frame parsing."""

    def __init__(self, raw_packet: bytes):
        self.raw_packet = raw_packet
        self.reason = 0
        self.orig_port = 0
        self.rssi = 0
        self.payload = b''
        self.frame_info: Optional[WIDDFrameInfo] = None

        self._parse()

    def _parse(self):
        """Parse CPU header and WIDD frame from packet."""
        if len(self.raw_packet) < CPU_HEADER_SIZE:
            return

        # Parse CPU header
        self.reason, self.orig_port, self.rssi = struct.unpack(
            CPU_HEADER_FORMAT,
            self.raw_packet[:CPU_HEADER_SIZE]
        )
        self.payload = self.raw_packet[CPU_HEADER_SIZE:]

        # Parse full WIDD frame
        self.frame_info = self._parse_widd_frame()

    def _parse_widd_frame(self) -> WIDDFrameInfo:
        """Parse full WIDD frame structure.

        P4 deparser output format:
        [CPU Header 4B][Ethernet 14B][WiFi FC 2B][WiFi Addr 20B][RF Features 8B][Payload]
        """
        raw_bytes = self.raw_packet
        min_size = CPU_HEADER_SIZE + ETHERNET_SIZE + WIFI_FC_SIZE + WIFI_ADDR_SIZE + RF_FEATURES_SIZE

        if len(raw_bytes) < min_size:
            return WIDDFrameInfo(
                error=f'Packet too short ({len(raw_bytes)} < {min_size} bytes)',
                raw_bytes=raw_bytes
            )

        offset = CPU_HEADER_SIZE

        # Parse Ethernet Header (14 bytes)
        eth_dst = ':'.join(f'{b:02x}' for b in raw_bytes[offset:offset + 6])
        eth_src = ':'.join(f'{b:02x}' for b in raw_bytes[offset + 6:offset + 12])
        eth_type = int.from_bytes(raw_bytes[offset + 12:offset + 14], 'big')
        offset += ETHERNET_SIZE

        # Check if this is a WIDD packet
        if eth_type != ETHERTYPE_WIDD:
            return WIDDFrameInfo(
                error=f'Not a WIDD packet (ethertype=0x{eth_type:04x})',
                raw_bytes=raw_bytes
            )

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

        return WIDDFrameInfo(
            frame_type=FRAME_TYPE_NAMES.get(frame_type, f'Unknown({frame_type})'),
            subtype=SUBTYPE_NAMES.get(subtype, f'0x{subtype:X}'),
            frame_type_num=frame_type,
            subtype_num=subtype,
            src_mac=addr2,
            dst_mac=addr1,
            bssid=addr3,
            seq_ctrl=seq_ctrl,
            rssi=rssi,
            phase=phase,
            pilot=pilot,
            mag=mag,
            cpu_reason=self.reason,
            cpu_orig_port=self.orig_port,
            raw_payload=raw_bytes[offset:] if len(raw_bytes) > offset else b'',
            raw_bytes=raw_bytes
        )

    def get_reason_name(self) -> str:
        """Get human-readable reason name."""
        reasons = {
            CPU_REASON_DEAUTH: 'DEAUTH',
            CPU_REASON_ASSOC: 'ASSOC',
            CPU_REASON_AUTH: 'AUTH',
            CPU_REASON_BEACON: 'BEACON',
            CPU_REASON_DISASSOC: 'DISASSOC',
            CPU_REASON_DATA: 'DATA',
        }
        return reasons.get(self.reason, f'UNKNOWN({self.reason})')

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format (compatible with old PacketReceiver callback)."""
        if self.frame_info is None:
            return {'error': 'No frame info'}

        if self.frame_info.error:
            return {'error': self.frame_info.error}

        return {
            'frame_type': self.frame_info.frame_type,
            'subtype': self.frame_info.subtype,
            'frame_type_num': self.frame_info.frame_type_num,
            'subtype_num': self.frame_info.subtype_num,
            'src_mac': self.frame_info.src_mac,
            'dst_mac': self.frame_info.dst_mac,
            'bssid': self.frame_info.bssid,
            'seq_ctrl': self.frame_info.seq_ctrl,
            'rssi': self.frame_info.rssi,
            'phase': self.frame_info.phase,
            'pilot': self.frame_info.pilot,
            'mag': self.frame_info.mag,
            'cpu_reason': self.frame_info.cpu_reason,
            'cpu_orig_port': self.frame_info.cpu_orig_port,
            'raw_payload': self.frame_info.raw_payload,
            'raw_bytes': self.frame_info.raw_bytes
        }

    def __repr__(self):
        return (f"PacketInEvent(reason={self.get_reason_name()}, "
                f"port={self.orig_port}, rssi={self.rssi}, "
                f"payload_len={len(self.payload)})")


class SwitchInterface:
    """Interface to bmv2 switch via Thrift."""

    def __init__(self, thrift_ip: str = '127.0.0.1', thrift_port: int = 9090,
                 cpu_iface: str = None):
        """
        Initialize switch interface.

        Args:
            thrift_ip: IP address of bmv2 Thrift server
            thrift_port: Port of bmv2 Thrift server
            cpu_iface: Interface name for CPU port (for packet-in/out)
        """
        self.thrift_ip = thrift_ip
        self.thrift_port = thrift_port
        self.cpu_iface = cpu_iface

        self.transport = None
        self.client = None
        self.connected = False

        # Packet-In handling
        self.packet_in_queue = Queue()
        self.packet_in_callback: Optional[Callable[[PacketInEvent], None]] = None
        self.packet_in_thread: Optional[Thread] = None
        self.stop_event = Event()

        # CPU socket for packet-in/out
        self.cpu_socket = None

    def connect(self) -> bool:
        """Connect to bmv2 Thrift server."""
        if Standard is None:
            print("Warning: bmv2 runtime not available, running in mock mode")
            self.connected = True
            return True

        try:
            self.transport = TSocket.TSocket(self.thrift_ip, self.thrift_port)
            self.transport = TTransport.TBufferedTransport(self.transport)
            protocol = TBinaryProtocol.TBinaryProtocol(self.transport)

            # Use multiplexed protocol for standard service
            self.client = Standard.Client(
                TMultiplexedProtocol.TMultiplexedProtocol(protocol, "standard")
            )

            self.transport.open()
            self.connected = True
            print(f"Connected to bmv2 at {self.thrift_ip}:{self.thrift_port}")
            return True

        except Exception as e:
            print(f"Failed to connect to bmv2: {e}")
            self.connected = False
            return False

    def disconnect(self):
        """Disconnect from bmv2."""
        self.stop_packet_in_listener()

        if self.transport:
            try:
                self.transport.close()
            except:
                pass
        self.connected = False
        print("Disconnected from bmv2")

    def add_table_entry(self, table_name: str, match_fields: Dict[str, Any],
                        action_name: str, action_params: Dict[str, Any] = None,
                        priority: int = 0) -> bool:
        """
        Add entry to a P4 table.

        Args:
            table_name: Name of the table
            match_fields: Dictionary of match field names to values
            action_name: Name of the action to execute
            action_params: Dictionary of action parameter names to values
            priority: Entry priority (for ternary/range matches)

        Returns:
            True if successful, False otherwise
        """
        if not self.connected or self.client is None:
            print("Not connected to switch")
            return False

        try:
            # Build match spec
            match_spec = []
            for field_name, value in match_fields.items():
                if isinstance(value, bytes):
                    match_spec.append(BmMatchParam(type=BmMatchParamType.EXACT,
                                                   exact=BmMatchParamExact(value)))
                elif isinstance(value, int):
                    # Convert int to bytes
                    byte_len = (value.bit_length() + 7) // 8 or 1
                    value_bytes = value.to_bytes(byte_len, 'big')
                    match_spec.append(BmMatchParam(type=BmMatchParamType.EXACT,
                                                   exact=BmMatchParamExact(value_bytes)))

            # Build action spec
            action_data = []
            if action_params:
                for param_name, value in action_params.items():
                    if isinstance(value, bytes):
                        action_data.append(value)
                    elif isinstance(value, int):
                        byte_len = (value.bit_length() + 7) // 8 or 1
                        action_data.append(value.to_bytes(byte_len, 'big'))

            # Add entry
            entry_handle = self.client.bm_mt_add_entry(
                0,  # cxt_id
                table_name,
                match_spec,
                action_name,
                action_data,
                BmAddEntryOptions(priority=priority)
            )
            print(f"Added table entry: {table_name} -> {action_name} (handle={entry_handle})")
            return True

        except Exception as e:
            print(f"Failed to add table entry: {e}")
            return False

    def delete_table_entry(self, table_name: str, entry_handle: int) -> bool:
        """Delete entry from a P4 table by handle."""
        if not self.connected or self.client is None:
            return False

        try:
            self.client.bm_mt_delete_entry(0, table_name, entry_handle)
            return True
        except Exception as e:
            print(f"Failed to delete table entry: {e}")
            return False

    def block_attacker(self, mac_address: str) -> Optional[int]:
        """
        Add attacker MAC to blocklist table in P4 switch.

        Args:
            mac_address: MAC address to block (format: 'xx:xx:xx:xx:xx:xx')

        Returns:
            Entry handle if successful, None otherwise
        """
        # Convert MAC string to bytes
        mac_bytes = bytes.fromhex(mac_address.replace(':', ''))

        if not self.connected or self.client is None:
            print(f"[SwitchInterface] Not connected - cannot block {mac_address}")
            # Return a fake handle for mock mode
            return 0

        try:
            from bm_runtime.standard.ttypes import BmMatchParam, BmMatchParamType, BmMatchParamExact, BmAddEntryOptions

            match_spec = [
                BmMatchParam(type=BmMatchParamType.EXACT,
                            exact=BmMatchParamExact(mac_bytes))
            ]

            entry_handle = self.client.bm_mt_add_entry(
                0,  # cxt_id
                "WiddIngress.blocklist",  # table name
                match_spec,
                "WiddIngress.drop",  # action name
                [],  # no action params
                BmAddEntryOptions(priority=0)
            )
            print(f"[SwitchInterface] Blocked attacker {mac_address} (handle={entry_handle})")
            return entry_handle

        except Exception as e:
            print(f"[SwitchInterface] Failed to block attacker {mac_address}: {e}")
            return None

    def unblock_attacker(self, entry_handle: int) -> bool:
        """
        Remove attacker from blocklist table.

        Args:
            entry_handle: Handle returned from block_attacker()

        Returns:
            True if successful
        """
        if not self.connected or self.client is None:
            return True  # Mock mode

        try:
            self.client.bm_mt_delete_entry(0, "WiddIngress.blocklist", entry_handle)
            print(f"[SwitchInterface] Unblocked attacker (handle={entry_handle})")
            return True
        except Exception as e:
            print(f"[SwitchInterface] Failed to unblock attacker: {e}")
            return False

    def read_register(self, register_name: str, index: int) -> Optional[int]:
        """Read value from a P4 register."""
        if not self.connected or self.client is None:
            return None

        try:
            value = self.client.bm_register_read(0, register_name, index)
            return value
        except Exception as e:
            print(f"Failed to read register: {e}")
            return None

    def write_register(self, register_name: str, index: int, value: int) -> bool:
        """Write value to a P4 register."""
        if not self.connected or self.client is None:
            return False

        try:
            self.client.bm_register_write(0, register_name, index, value)
            return True
        except Exception as e:
            print(f"Failed to write register: {e}")
            return False

    def read_counter(self, counter_name: str, index: int) -> Optional[tuple]:
        """Read counter value (packets, bytes)."""
        if not self.connected or self.client is None:
            return None

        try:
            counter = self.client.bm_counter_read(0, counter_name, index)
            return (counter.packets, counter.bytes)
        except Exception as e:
            print(f"Failed to read counter: {e}")
            return None

    def start_packet_in_listener(self, callback: Callable[[PacketInEvent], None],
                                  iface: str = None):
        """
        Start listening for Packet-In events.

        Args:
            callback: Function to call when packet received
            iface: Interface to listen on (e.g., 's1-cpu')
        """
        self.packet_in_callback = callback
        self.stop_event.clear()

        iface = iface or self.cpu_iface
        if not iface:
            print("No CPU interface specified for Packet-In listener")
            return

        self.packet_in_thread = Thread(
            target=self._packet_in_loop,
            args=(iface,),
            daemon=True
        )
        self.packet_in_thread.start()
        print(f"Started Packet-In listener on {iface}")

    def stop_packet_in_listener(self):
        """Stop Packet-In listener."""
        self.stop_event.set()
        if self.cpu_socket:
            try:
                self.cpu_socket.close()
            except:
                pass
        if self.packet_in_thread:
            self.packet_in_thread.join(timeout=2)

    def _packet_in_loop(self, iface: str):
        """Internal loop for receiving Packet-In events using Scapy."""
        try:
            from scapy.all import sniff

            print(f"[SwitchInterface] Starting Packet-In listener on {iface}")
            print(f"[SwitchInterface] Expecting P4 format: [CPU(4)][Ether(14)][WiFi FC(2)][WiFi Addr(20)][RF(8)]")

            def handle_packet(pkt):
                if self.stop_event.is_set():
                    return

                try:
                    raw_packet = bytes(pkt)
                    event = PacketInEvent(raw_packet)

                    # Log parsed frame info
                    if event.frame_info and not event.frame_info.error:
                        print(f"[SwitchInterface] Received: {event.frame_info.frame_type}/{event.frame_info.subtype} "
                              f"from {event.frame_info.src_mac} RSSI={event.frame_info.rssi}dBm")

                    if self.packet_in_callback:
                        self.packet_in_callback(event)
                    else:
                        self.packet_in_queue.put(event)

                except Exception as e:
                    print(f"[SwitchInterface] Packet-In error: {e}")
                    import traceback
                    traceback.print_exc()

            # Use Scapy's sniff for reliable packet capture
            sniff(
                iface=iface,
                prn=handle_packet,
                filter=None,
                stop_filter=lambda x: self.stop_event.is_set(),
                store=False
            )

        except PermissionError as e:
            print(f"[SwitchInterface] Permission Error: {e}")
            print("[SwitchInterface] This script must be run with sudo/root privileges")
        except OSError as e:
            print(f"[SwitchInterface] Interface Error: {e}")
            print(f"[SwitchInterface] Interface '{iface}' may not exist or is not accessible")
        except Exception as e:
            print(f"[SwitchInterface] Failed to start Packet-In listener: {e}")
            import traceback
            traceback.print_exc()

    def send_packet_out(self, port: int, packet: bytes, iface: str = None) -> bool:
        """
        Send a packet out through the switch via CPU port.

        The packet will be sent to the CPU port interface and the P4 switch
        will forward it to the specified destination port.

        Args:
            port: Output port number (where to forward the packet)
            packet: Raw packet bytes (Ethernet frame without CPU header)
            iface: CPU interface to send on (defaults to self.cpu_iface)

        Returns:
            True if successful
        """
        iface = iface or self.cpu_iface
        if not iface:
            print("[SwitchInterface] No CPU interface specified for Packet-Out")
            return False

        try:
            # Build CPU header for Packet-Out
            # reason=0 means PASS (forward this frame)
            # origPort contains the destination port
            # rfRssi is unused for Packet-Out
            cpu_header = struct.pack(CPU_HEADER_FORMAT, 0, port, 0)

            # Full packet: CPU header + packet payload
            full_packet = cpu_header + packet

            # Create a raw socket to send on the CPU interface
            send_socket = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.htons(0x0003)  # ETH_P_ALL
            )
            send_socket.bind((iface, 0))
            send_socket.send(full_packet)
            send_socket.close()

            print(f"[SwitchInterface] Sent Packet-Out ({len(full_packet)} bytes) to port {port} via {iface}")
            return True

        except Exception as e:
            print(f"[SwitchInterface] Failed to send Packet-Out: {e}")
            import traceback
            traceback.print_exc()
            return False


# Simple test
if __name__ == '__main__':
    import time

    print("Testing SwitchInterface...")

    def print_frame(event: PacketInEvent):
        if event.frame_info and not event.frame_info.error:
            print(f"Received: {event.frame_info.frame_type} / {event.frame_info.subtype} "
                  f"from {event.frame_info.src_mac} RSSI={event.frame_info.rssi}dBm")
        else:
            print(f"Received event: {event}")

    sw = SwitchInterface(thrift_port=9090, cpu_iface='s1-cpu-h')
    if sw.connect():
        print("Connection test passed")

        # Try to read a counter
        counter = sw.read_counter('frameCounter', 0)
        if counter:
            print(f"Frame counter: {counter}")

        # Test Packet-In listener
        print("\nStarting Packet-In listener (press Ctrl+C to stop)...")
        sw.start_packet_in_listener(callback=print_frame)

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

        sw.disconnect()
    else:
        print("Connection test failed (bmv2 may not be running)")
