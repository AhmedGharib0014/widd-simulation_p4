#!/usr/bin/env python3
"""
WIDD Switch Interface - Thrift connection to bmv2

Provides:
- Connection to bmv2 simple_switch via Thrift
- Table entry management (add/delete/modify)
- Register read/write
- Packet-In/Packet-Out handling via CPU port
"""

import sys
import os
import socket
import struct
from threading import Thread, Event
from queue import Queue
from typing import Optional, Callable, Dict, Any

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

# CPU reasons (from P4 program)
CPU_REASON_DEAUTH = 1
CPU_REASON_ASSOC = 2
CPU_REASON_AUTH = 3
CPU_REASON_BEACON = 4
CPU_REASON_DISASSOC = 5
CPU_REASON_DATA = 6


class PacketInEvent:
    """Represents a Packet-In event from bmv2."""

    def __init__(self, raw_packet: bytes):
        self.raw_packet = raw_packet
        self.reason = 0
        self.orig_port = 0
        self.rssi = 0
        self.payload = b''

        self._parse()

    def _parse(self):
        """Parse CPU header from packet."""
        if len(self.raw_packet) >= CPU_HEADER_SIZE:
            self.reason, self.orig_port, self.rssi = struct.unpack(
                CPU_HEADER_FORMAT,
                self.raw_packet[:CPU_HEADER_SIZE]
            )
            self.payload = self.raw_packet[CPU_HEADER_SIZE:]

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
        """Internal loop for receiving Packet-In events."""
        try:
            # Create raw socket to receive packets
            self.cpu_socket = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.htons(0x0003)  # ETH_P_ALL
            )
            self.cpu_socket.bind((iface, 0))
            self.cpu_socket.settimeout(1.0)

            while not self.stop_event.is_set():
                try:
                    raw_packet, addr = self.cpu_socket.recvfrom(65535)
                    event = PacketInEvent(raw_packet)

                    if self.packet_in_callback:
                        self.packet_in_callback(event)
                    else:
                        self.packet_in_queue.put(event)

                except socket.timeout:
                    continue
                except Exception as e:
                    if not self.stop_event.is_set():
                        print(f"Packet-In error: {e}")

        except Exception as e:
            print(f"Failed to start Packet-In listener: {e}")

    def send_packet_out(self, port: int, packet: bytes) -> bool:
        """
        Send a packet out through the switch.

        Args:
            port: Output port number
            packet: Raw packet bytes (including CPU header if needed)

        Returns:
            True if successful
        """
        if not self.cpu_socket:
            print("CPU socket not initialized")
            return False

        try:
            # Add CPU header for packet-out
            cpu_header = struct.pack(CPU_HEADER_FORMAT, 0, port, 0)
            full_packet = cpu_header + packet
            self.cpu_socket.send(full_packet)
            return True
        except Exception as e:
            print(f"Failed to send packet-out: {e}")
            return False


# Simple test
if __name__ == '__main__':
    print("Testing SwitchInterface...")

    sw = SwitchInterface(thrift_port=9090)
    if sw.connect():
        print("Connection test passed")

        # Try to read a counter
        counter = sw.read_counter('frameCounter', 0)
        if counter:
            print(f"Frame counter: {counter}")

        sw.disconnect()
    else:
        print("Connection test failed (bmv2 may not be running)")
