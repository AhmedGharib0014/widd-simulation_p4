#!/usr/bin/env python3
"""
WIDD Simulation Server - Connects attacker CLI to OODA Controller

Provides a simple socket-based communication for the demo:
- Attacker CLI sends attack commands
- OODA Controller processes them and responds
- Packet Monitor displays the flow

This enables real-time visualization without actual network hardware.
"""

import socket
import threading
import json
import time
from queue import Queue
from typing import Optional, Callable

# Communication ports
CONTROLLER_PORT = 9999
MONITOR_PORT = 9998

# Message types
MSG_ATTACK = 'attack'
MSG_PACKET = 'packet'
MSG_DECISION = 'decision'
MSG_STATS = 'stats'


class PacketEvent:
    """Represents a packet flow event for monitoring."""

    def __init__(self, stage: str, frame_type: str, src_mac: str,
                 dst_mac: str = "ff:ff:ff:ff:ff:ff", details: dict = None):
        self.timestamp = time.time()
        self.stage = stage  # 'switch', 'observe', 'orient', 'decide', 'act'
        self.frame_type = frame_type
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.details = details or {}

    def to_dict(self):
        return {
            'timestamp': self.timestamp,
            'stage': self.stage,
            'frame_type': self.frame_type,
            'src_mac': self.src_mac,
            'dst_mac': self.dst_mac,
            'details': self.details
        }


class SimulationServer:
    """
    Server that connects all demo components.

    Runs in the OODA controller process and accepts connections from:
    - Attack CLI (sends attack commands)
    - Packet Monitor (receives packet flow events)
    """

    def __init__(self, controller):
        self.controller = controller
        self.running = False

        # Sockets
        self.cmd_socket = None
        self.monitor_clients = []

        # Event queue for monitor
        self.event_queue = Queue()

        # Threads
        self.cmd_thread = None
        self.monitor_thread = None
        self.broadcast_thread = None

    def start(self):
        """Start the simulation server."""
        self.running = True

        # Start command listener
        self.cmd_thread = threading.Thread(target=self._cmd_listener, daemon=True)
        self.cmd_thread.start()

        # Start monitor broadcaster
        self.broadcast_thread = threading.Thread(target=self._event_broadcaster, daemon=True)
        self.broadcast_thread.start()

        print(f"[SimServer] Listening for attacks on port {CONTROLLER_PORT}")
        print(f"[SimServer] Monitor broadcast on port {MONITOR_PORT}")

    def stop(self):
        """Stop the server."""
        self.running = False
        if self.cmd_socket:
            self.cmd_socket.close()

    def emit_event(self, event: PacketEvent):
        """Emit a packet event to all monitors."""
        self.event_queue.put(event)

    def _cmd_listener(self):
        """Listen for attack commands."""
        self.cmd_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.cmd_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.cmd_socket.bind(('127.0.0.1', CONTROLLER_PORT))
            self.cmd_socket.listen(5)
            self.cmd_socket.settimeout(1.0)

            while self.running:
                try:
                    client, addr = self.cmd_socket.accept()
                    threading.Thread(
                        target=self._handle_cmd_client,
                        args=(client,),
                        daemon=True
                    ).start()
                except socket.timeout:
                    continue
        except Exception as e:
            print(f"[SimServer] Command listener error: {e}")

    def _handle_cmd_client(self, client: socket.socket):
        """Handle a connected attack CLI."""
        try:
            client.settimeout(60.0)

            while self.running:
                data = client.recv(4096)
                if not data:
                    break

                try:
                    msg = json.loads(data.decode())
                    response = self._process_command(msg)
                    client.send(json.dumps(response).encode())
                except json.JSONDecodeError:
                    client.send(b'{"error": "Invalid JSON"}')
        except Exception as e:
            pass
        finally:
            client.close()

    def _process_command(self, msg: dict) -> dict:
        """Process an attack command from CLI."""
        cmd_type = msg.get('type', '')

        if cmd_type == 'attack':
            attack_type = msg.get('attack')
            params = msg.get('params', {})

            # Process through controller
            results = []

            if attack_type == 'deauth':
                victim = params.get('victim', '00:00:00:00:00:01')
                count = params.get('count', 1)
                attacker = params.get('attacker', '00:00:00:00:00:99')

                for i in range(count):
                    result = self.controller.simulate_frame(
                        'deauth', attacker,
                        is_spoofed=True, spoofed_mac=victim
                    )
                    results.append({
                        'frame': i + 1,
                        'attack': result[0].name if result else 'NONE',
                        'dropped': result[1] if result else False,
                        'prob': result[2] if result else 0
                    })
                    time.sleep(0.1)

            elif attack_type == 'auth_flood':
                count = params.get('count', 10)

                for i in range(count):
                    result = self.controller.simulate_frame(
                        'auth', f'00:00:00:00:{i:02x}:{i:02x}'
                    )
                    results.append({
                        'frame': i + 1,
                        'attack': result[0].name if result else 'NONE'
                    })

            elif attack_type == 'evil_twin':
                result = self.controller.simulate_frame(
                    'beacon', 'AA:BB:CC:DD:EE:FF'
                )
                results.append({
                    'attack': result[0].name if result else 'NONE'
                })

            elif attack_type == 'data':
                source = params.get('source', '00:00:00:00:00:01')
                count = params.get('count', 10)

                for i in range(count):
                    self.controller.simulate_frame('data', source)

                results.append({'trained': count})

            return {'status': 'ok', 'results': results}

        elif cmd_type == 'stats':
            return {'status': 'ok', 'stats': self.controller.get_stats()}

        return {'status': 'error', 'message': 'Unknown command'}

    def _event_broadcaster(self):
        """Broadcast events to monitor clients via UDP."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        while self.running:
            try:
                event = self.event_queue.get(timeout=1.0)
                data = json.dumps(event.to_dict()).encode()
                sock.sendto(data, ('127.0.0.1', MONITOR_PORT))
            except:
                continue


class AttackClient:
    """Client for sending attacks to the simulation server."""

    def __init__(self, host: str = '127.0.0.1', port: int = CONTROLLER_PORT):
        self.host = host
        self.port = port
        self.socket = None

    def connect(self) -> bool:
        """Connect to the simulation server."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.socket.settimeout(10.0)
            return True
        except Exception as e:
            print(f"Failed to connect: {e}")
            return False

    def disconnect(self):
        """Disconnect from server."""
        if self.socket:
            self.socket.close()

    def send_attack(self, attack_type: str, **params) -> dict:
        """Send an attack command."""
        msg = {
            'type': 'attack',
            'attack': attack_type,
            'params': params
        }

        try:
            self.socket.send(json.dumps(msg).encode())
            response = self.socket.recv(4096)
            return json.loads(response.decode())
        except Exception as e:
            return {'error': str(e)}

    def get_stats(self) -> dict:
        """Get controller statistics."""
        msg = {'type': 'stats'}

        try:
            self.socket.send(json.dumps(msg).encode())
            response = self.socket.recv(4096)
            return json.loads(response.decode())
        except Exception as e:
            return {'error': str(e)}


class PacketMonitor:
    """Monitor that displays packet flow in real-time."""

    def __init__(self, port: int = MONITOR_PORT):
        self.port = port
        self.running = False
        self.callback: Optional[Callable] = None

    def start(self, callback: Callable = None):
        """Start listening for events."""
        self.running = True
        self.callback = callback

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('127.0.0.1', self.port))
        sock.settimeout(1.0)

        while self.running:
            try:
                data, addr = sock.recvfrom(4096)
                event = json.loads(data.decode())

                if self.callback:
                    self.callback(event)
                else:
                    self._default_display(event)
            except socket.timeout:
                continue
            except Exception as e:
                continue

    def stop(self):
        """Stop the monitor."""
        self.running = False

    def _default_display(self, event: dict):
        """Default event display."""
        stage = event.get('stage', '?')
        frame_type = event.get('frame_type', '?')
        src = event.get('src_mac', '?')

        print(f"[{stage:^8}] {frame_type:8} from {src}")
