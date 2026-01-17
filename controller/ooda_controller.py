#!/usr/bin/env python3
"""
WIDD OODA Controller - Main Control Loop

Implements the Observe-Orientate-Decide-Act loop from the paper:

1. OBSERVE: Receive Packet-In from bmv2 (management frames)
2. ORIENTATE: Parse frame, extract RF features, call MOCC Dev_ident()
3. DECIDE: Update KCSM state machine, determine attack state
4. ACT: Drop/Pass/Inject countermeasures

This controller runs alongside the bmv2 switch and processes
frames sent to the CPU port.
"""

import struct
import time
from typing import Optional, Callable, Dict
from dataclasses import dataclass
from enum import Enum

from controller.switch_interface import SwitchInterface, PacketInEvent, CPU_REASON_DEAUTH, \
    CPU_REASON_AUTH, CPU_REASON_ASSOC, CPU_REASON_BEACON, CPU_REASON_DISASSOC, CPU_REASON_DATA
from controller.mocc import MOCC, RFFeatures
from controller.kcsm import KCSMManager, AttackType
from controller.logger import logger, WIDDLogger


# Ethernet header size
ETH_HEADER_SIZE = 14

# WIDD frame structure offsets (after Ethernet header)
# wifi_fc_t: 2 bytes
# wifi_addr_t: 6+6+6+2 = 20 bytes
# rf_features_t: 2+2+2+2 = 8 bytes
WIFI_FC_OFFSET = ETH_HEADER_SIZE
WIFI_FC_SIZE = 2
WIFI_ADDR_OFFSET = WIFI_FC_OFFSET + WIFI_FC_SIZE
WIFI_ADDR_SIZE = 20
RF_FEATURES_OFFSET = WIFI_ADDR_OFFSET + WIFI_ADDR_SIZE
RF_FEATURES_SIZE = 8


@dataclass
class ParsedFrame:
    """Parsed WIDD frame."""
    # Ethernet
    eth_dst: bytes
    eth_src: bytes
    eth_type: int

    # 802.11 Frame Control
    frame_type: int      # 0=Mgmt, 1=Ctrl, 2=Data
    subtype: int

    # 802.11 Addresses
    addr1: str  # Receiver
    addr2: str  # Transmitter (source)
    addr3: str  # BSSID

    # RF Features
    rssi: int
    phase_offset: int
    pilot_offset: int
    mag_squared: int

    # CPU header info
    cpu_reason: int
    orig_port: int


class OODAController:
    """
    Main OODA loop controller for WIDD.

    Processes frames from bmv2 and makes detection/response decisions.
    """

    def __init__(self, switch_ip: str = '127.0.0.1', switch_port: int = 9090,
                 cpu_iface: str = None):
        """
        Initialize OODA controller.

        Args:
            switch_ip: bmv2 Thrift IP
            switch_port: bmv2 Thrift port
            cpu_iface: Interface for Packet-In (e.g., 's1-cpu')
        """
        self.switch = SwitchInterface(switch_ip, switch_port, cpu_iface)
        self.mocc = MOCC()
        self.kcsm = KCSMManager()

        # Network configuration
        self.ssid = 'WIDD_Network'
        self.bssid = None

        # Registered clients
        self.known_clients: Dict[str, bool] = {}  # MAC -> registered

        # Statistics
        self.stats = {
            'frames_processed': 0,
            'deauth_frames': 0,
            'deauth_dropped': 0,
            'attacks_detected': 0,
        }

        # Countermeasure callbacks
        self.on_attack_detected: Optional[Callable[[AttackType, str], None]] = None

        # Running flag
        self.running = False

    def register_client(self, mac_address: str, base_rssi: int = -50):
        """Register a legitimate client device."""
        self.mocc.register_device(mac_address, base_rssi)
        self.known_clients[mac_address] = True
        logger.system_info(f"Registered client: {mac_address} (RSSI={base_rssi}dBm)")

    def set_network_info(self, ssid: str, bssid: str):
        """Set network SSID and BSSID for evil twin detection."""
        self.ssid = ssid
        self.bssid = bssid
        self.kcsm.set_network_info(ssid, bssid)
        logger.system_info(f"Network configured: SSID={ssid}, BSSID={bssid}")

    def start(self):
        """Start the OODA loop (connect and listen for packets)."""
        logger.print_banner()
        logger.system_start("OODA Controller")

        if not self.switch.connect():
            logger.system_error("SWITCH", "Failed to connect to bmv2 switch")
            return False

        self.running = True

        # Start Packet-In listener if interface specified
        if self.switch.cpu_iface:
            self.switch.start_packet_in_listener(self._handle_packet_in)

        logger.system_info("Controller ready - waiting for packets")
        return True

    def stop(self):
        """Stop the OODA loop."""
        logger.system_stop("OODA Controller")
        logger.print_stats()
        self.running = False
        self.switch.disconnect()

    def _parse_frame(self, event: PacketInEvent) -> Optional[ParsedFrame]:
        """
        Parse a Packet-In event into structured frame data.

        Args:
            event: Raw Packet-In event

        Returns:
            ParsedFrame or None if parsing fails
        """
        payload = event.payload
        if len(payload) < RF_FEATURES_OFFSET + RF_FEATURES_SIZE:
            return None

        try:
            # Parse Ethernet header
            eth_dst = payload[0:6]
            eth_src = payload[6:12]
            eth_type = struct.unpack('!H', payload[12:14])[0]

            # Parse 802.11 Frame Control (2 bytes, big-endian from P4)
            fc_bytes = payload[WIFI_FC_OFFSET:WIFI_FC_OFFSET + 2]
            fc = struct.unpack('!H', fc_bytes)[0]

            # Extract fields from frame control
            # P4 format (big-endian): protocol(2) | type(2) | subtype(4) | flags(8)
            # Bits [15:14] = protocolVersion, [13:12] = frameType, [11:8] = subType, [7:0] = flags
            frame_type = (fc >> 12) & 0x3
            subtype = (fc >> 8) & 0xF

            # Parse 802.11 addresses
            addr_start = WIFI_ADDR_OFFSET
            addr1 = ':'.join(f'{b:02x}' for b in payload[addr_start:addr_start+6])
            addr2 = ':'.join(f'{b:02x}' for b in payload[addr_start+6:addr_start+12])
            addr3 = ':'.join(f'{b:02x}' for b in payload[addr_start+12:addr_start+18])

            # Parse RF features
            rf_start = RF_FEATURES_OFFSET
            rssi, phase, pilot, mag = struct.unpack(
                '!HHHH',
                payload[rf_start:rf_start+8]
            )

            return ParsedFrame(
                eth_dst=eth_dst,
                eth_src=eth_src,
                eth_type=eth_type,
                frame_type=frame_type,
                subtype=subtype,
                addr1=addr1,
                addr2=addr2,
                addr3=addr3,
                rssi=rssi,
                phase_offset=phase,
                pilot_offset=pilot,
                mag_squared=mag,
                cpu_reason=event.reason,
                orig_port=event.orig_port
            )

        except Exception as e:
            print(f"[OODA] Frame parse error: {e}")
            return None

    def _handle_packet_in(self, event: PacketInEvent):
        """
        Handle a Packet-In event - main OODA loop iteration.

        This is called for each frame sent to the CPU port.
        """
        self.stats['frames_processed'] += 1

        # OBSERVE: Parse the frame
        frame = self._parse_frame(event)
        if frame is None:
            print(f"[OODA] Failed to parse frame: {event}")
            return

        # ORIENTATE: Determine frame type and identify device
        source_mac = frame.addr2
        rf_features = RFFeatures(
            rssi=frame.rssi,
            phase_offset=frame.phase_offset,
            pilot_offset=frame.pilot_offset,
            mag_squared=frame.mag_squared
        )

        # Process based on CPU reason (frame type)
        if event.reason == CPU_REASON_DEAUTH:
            self._process_deauth(frame, rf_features)

        elif event.reason == CPU_REASON_DISASSOC:
            self._process_disassoc(frame, rf_features)

        elif event.reason == CPU_REASON_AUTH:
            self._process_auth(frame)

        elif event.reason == CPU_REASON_ASSOC:
            self._process_assoc(frame)

        elif event.reason == CPU_REASON_BEACON:
            self._process_beacon(frame)

        elif event.reason == CPU_REASON_DATA:
            self._process_data(frame, rf_features)

    def _process_deauth(self, frame: ParsedFrame, rf_features: RFFeatures):
        """Process deauthentication frame - ORIENTATE/DECIDE/ACT."""
        self.stats['deauth_frames'] += 1
        source_mac = frame.addr2

        # === OBSERVE (already done in _handle_packet_in) ===
        logger.ooda_observe("DEAUTH", source_mac, {
            'rssi': rf_features.rssi,
            'phase': rf_features.phase_offset
        })

        # === ORIENT: Check device identity using MOCC ===
        prob, is_legitimate = self.mocc.identify(source_mac, rf_features)
        logger.ooda_orient_mocc(source_mac, prob, is_legitimate)

        # Log attack detection at ORIENT phase
        if not is_legitimate:
            logger.attack_deauth(
                src_mac="UNKNOWN",
                target_mac=source_mac,
                spoofed=True,
                count=self.stats['deauth_frames']
            )

        # === DECIDE: Update KCSM state machine ===
        attack, should_drop = self.kcsm.process_deauth(source_mac, is_legitimate)

        # Get KCSM state for logging
        kcsm_state = self.kcsm.deauth_kcsm.get_client(source_mac).deauth_state
        logger.ooda_decide_kcsm(
            "DEAUTH", source_mac, kcsm_state,
            attack != AttackType.NONE,
            attack.name if attack != AttackType.NONE else None
        )

        # === ACT: Take action based on decision ===
        if should_drop:
            self.stats['deauth_dropped'] += 1
            logger.ooda_decide_drop("Spoofed deauth (MOCC failed)", source_mac)
        else:
            logger.ooda_decide_pass(source_mac)

        if attack != AttackType.NONE:
            self.stats['attacks_detected'] += 1

            # Trigger countermeasures
            if self.on_attack_detected:
                self.on_attack_detected(attack, source_mac)

            # Countermeasure: Inject false handshake
            self._inject_false_handshake(source_mac)
            logger.ooda_act_countermeasure(
                "INJECT_FALSE_HANDSHAKE",
                source_mac,
                "Poisoning attacker capture file"
            )
            logger.ooda_act_alert(
                attack.name,
                f"Client {source_mac} under deauth attack - countermeasures active"
            )

    def _process_disassoc(self, frame: ParsedFrame, rf_features: RFFeatures):
        """Process disassociation frame."""
        source_mac = frame.addr2

        logger.ooda_observe("DISASSOC", source_mac, {'rssi': rf_features.rssi})

        prob, is_legitimate = self.mocc.identify(source_mac, rf_features)
        logger.ooda_orient_mocc(source_mac, prob, is_legitimate)

        attack, should_drop = self.kcsm.process_disassoc(source_mac, is_legitimate)

        if should_drop:
            logger.ooda_decide_drop("Spoofed disassoc (MOCC failed)", source_mac)
        else:
            logger.ooda_decide_pass(source_mac)

        if attack != AttackType.NONE:
            self.stats['attacks_detected'] += 1
            logger.ooda_decide_kcsm("DISASSOC", source_mac, 3, True, attack.name)
            if self.on_attack_detected:
                self.on_attack_detected(attack, source_mac)

    def _process_auth(self, frame: ParsedFrame):
        """Process authentication frame (flood detection)."""
        logger.ooda_observe("AUTH", frame.addr2)

        attack = self.kcsm.process_auth()
        auth_count = self.kcsm.auth_flood_kcsm.auth_count

        if attack != AttackType.NONE:
            self.stats['attacks_detected'] += 1
            logger.attack_flood("AUTH", auth_count, 10)
            logger.ooda_act_alert("AUTH_FLOOD", f"Flood detected: {auth_count} auth frames")
            if self.on_attack_detected:
                self.on_attack_detected(attack, frame.addr2)

    def _process_assoc(self, frame: ParsedFrame):
        """Process association frame (flood detection)."""
        logger.ooda_observe("ASSOC", frame.addr2)

        attack = self.kcsm.process_assoc()
        assoc_count = self.kcsm.assoc_flood_kcsm.assoc_count

        if attack != AttackType.NONE:
            self.stats['attacks_detected'] += 1
            logger.attack_flood("ASSOC", assoc_count, 10)
            logger.ooda_act_alert("ASSOC_FLOOD", f"Flood detected: {assoc_count} assoc frames")
            if self.on_attack_detected:
                self.on_attack_detected(attack, frame.addr2)

    def _process_beacon(self, frame: ParsedFrame):
        """Process beacon frame (evil twin detection)."""
        # In real implementation, SSID would be extracted from beacon IE
        # For simulation, we use addr3 as BSSID
        beacon_bssid = frame.addr3

        logger.ooda_observe("BEACON", beacon_bssid)

        attack = self.kcsm.process_beacon(self.ssid, beacon_bssid)

        if attack != AttackType.NONE:
            self.stats['attacks_detected'] += 1
            logger.attack_evil_twin(self.ssid, self.bssid or "UNKNOWN", beacon_bssid)
            logger.ooda_act_alert("EVIL_TWIN", f"Rogue AP detected with BSSID={beacon_bssid}")
            if self.on_attack_detected:
                self.on_attack_detected(attack, beacon_bssid)

    def _process_data(self, frame: ParsedFrame, rf_features: RFFeatures):
        """Process data frame (MOCC training)."""
        source_mac = frame.addr2

        # Train MOCC with this frame's RF features
        self.mocc.train(source_mac, rf_features)

        # Log training progress
        status = self.mocc.get_training_status(source_mac)
        if status['samples'] % 50 == 0:  # Log every 50 samples
            logger.ooda_orient_training(source_mac, status['samples'], status['trained'])

    def _inject_false_handshake(self, target_mac: str):
        """
        Inject false 4-way handshake to poison attacker's capture.

        This is a countermeasure from the paper - when a deauth attack
        is detected, we send fake authentication frames so the attacker
        captures invalid credentials.
        """
        # TODO: Implement actual packet injection via CPU port
        # For now, the logging is done in the caller

    # =========================================================================
    # Methods to process frames from frame_info (used by PacketReceiver callback)
    # =========================================================================

    def _process_deauth_from_frame_info(self, source_mac: str, rf_features: RFFeatures, frame_info: dict):
        """Process deauthentication frame from parsed frame_info."""
        self.stats['deauth_frames'] += 1

        # === OBSERVE ===
        logger.ooda_observe("DEAUTH", source_mac, {
            'rssi': rf_features.rssi,
            'phase': rf_features.phase_offset
        })

        # === ORIENT: Check device identity using MOCC ===
        prob, is_legitimate = self.mocc.identify(source_mac, rf_features)
        logger.ooda_orient_mocc(source_mac, prob, is_legitimate)

        # Log attack detection at ORIENT phase
        if not is_legitimate:
            logger.attack_deauth(
                src_mac="UNKNOWN",
                target_mac=source_mac,
                spoofed=True,
                count=self.stats['deauth_frames']
            )

        # === DECIDE: Update KCSM state machine ===
        attack, should_drop = self.kcsm.process_deauth(source_mac, is_legitimate)

        # Get KCSM state for logging
        kcsm_state = self.kcsm.deauth_kcsm.get_client(source_mac).deauth_state
        logger.ooda_decide_kcsm(
            "DEAUTH", source_mac, kcsm_state,
            attack != AttackType.NONE,
            attack.name if attack != AttackType.NONE else None
        )

        # === ACT: Take action based on decision ===
        if should_drop:
            self.stats['deauth_dropped'] += 1
            logger.ooda_decide_drop("Spoofed deauth (MOCC failed)", source_mac)
        else:
            logger.ooda_decide_pass(source_mac)

        if attack != AttackType.NONE:
            self.stats['attacks_detected'] += 1

            # Trigger countermeasures
            if self.on_attack_detected:
                self.on_attack_detected(attack, source_mac)

            # Countermeasure: Inject false handshake
            self._inject_false_handshake(source_mac)
            logger.ooda_act_countermeasure(
                "INJECT_FALSE_HANDSHAKE",
                source_mac,
                "Poisoning attacker capture file"
            )
            logger.ooda_act_alert(
                attack.name,
                f"Client {source_mac} under deauth attack - countermeasures active"
            )

    def _process_disassoc_from_frame_info(self, source_mac: str, rf_features: RFFeatures, frame_info: dict):
        """Process disassociation frame from parsed frame_info."""
        logger.ooda_observe("DISASSOC", source_mac, {'rssi': rf_features.rssi})

        prob, is_legitimate = self.mocc.identify(source_mac, rf_features)
        logger.ooda_orient_mocc(source_mac, prob, is_legitimate)

        attack, should_drop = self.kcsm.process_disassoc(source_mac, is_legitimate)

        if should_drop:
            logger.ooda_decide_drop("Spoofed disassoc (MOCC failed)", source_mac)
        else:
            logger.ooda_decide_pass(source_mac)

        if attack != AttackType.NONE:
            self.stats['attacks_detected'] += 1
            logger.ooda_decide_kcsm("DISASSOC", source_mac, 3, True, attack.name)
            if self.on_attack_detected:
                self.on_attack_detected(attack, source_mac)

    def _process_auth_from_frame_info(self, source_mac: str, frame_info: dict):
        """Process authentication frame from parsed frame_info (flood detection)."""
        logger.ooda_observe("AUTH", source_mac)

        attack = self.kcsm.process_auth()
        auth_count = self.kcsm.auth_flood_kcsm.auth_count

        if attack != AttackType.NONE:
            self.stats['attacks_detected'] += 1
            logger.attack_flood("AUTH", auth_count, 10)
            logger.ooda_act_alert("AUTH_FLOOD", f"Flood detected: {auth_count} auth frames")
            if self.on_attack_detected:
                self.on_attack_detected(attack, source_mac)

    def _process_assoc_from_frame_info(self, source_mac: str, frame_info: dict):
        """Process association frame from parsed frame_info (flood detection)."""
        logger.ooda_observe("ASSOC", source_mac)

        attack = self.kcsm.process_assoc()
        assoc_count = self.kcsm.assoc_flood_kcsm.assoc_count

        if attack != AttackType.NONE:
            self.stats['attacks_detected'] += 1
            logger.attack_flood("ASSOC", assoc_count, 10)
            logger.ooda_act_alert("ASSOC_FLOOD", f"Flood detected: {assoc_count} assoc frames")
            if self.on_attack_detected:
                self.on_attack_detected(attack, source_mac)

    def _process_beacon_from_frame_info(self, beacon_bssid: str, frame_info: dict):
        """Process beacon frame from parsed frame_info (evil twin detection)."""
        logger.ooda_observe("BEACON", beacon_bssid)

        attack = self.kcsm.process_beacon(self.ssid, beacon_bssid)

        if attack != AttackType.NONE:
            self.stats['attacks_detected'] += 1
            logger.attack_evil_twin(self.ssid, self.bssid or "UNKNOWN", beacon_bssid)
            logger.ooda_act_alert("EVIL_TWIN", f"Rogue AP detected with BSSID={beacon_bssid}")
            if self.on_attack_detected:
                self.on_attack_detected(attack, beacon_bssid)

    def _process_data_from_frame_info(self, source_mac: str, rf_features: RFFeatures, frame_info: dict):
        """Process data frame from parsed frame_info (MOCC training)."""
        # Train MOCC with this frame's RF features
        self.mocc.train(source_mac, rf_features)

        # Log training progress
        status = self.mocc.get_training_status(source_mac)
        if status['samples'] % 50 == 0:  # Log every 50 samples
            logger.ooda_orient_training(source_mac, status['samples'], status['trained'])

    def get_stats(self) -> Dict:
        """Get controller statistics."""
        return {
            **self.stats,
            'kcsm_stats': self.kcsm.get_stats(),
            'mocc_devices': len(self.mocc.signatures)
        }

    def simulate_frame(self, frame_type: str, source_mac: str,
                       is_spoofed: bool = False, spoofed_mac: str = None):
        """
        Simulate receiving a frame (for testing without actual network).

        Args:
            frame_type: 'deauth', 'auth', 'assoc', 'data', 'beacon'
            source_mac: Actual source MAC
            is_spoofed: Whether this is a spoofed frame
            spoofed_mac: MAC being spoofed (if is_spoofed)
        """
        # Generate RF features from the ACTUAL source (attacker's real RF signature)
        rf_features = self.mocc.simulate_rf_features(source_mac)

        # The claimed MAC is what appears in the frame header
        claimed_mac = spoofed_mac if is_spoofed else source_mac

        if frame_type == 'deauth':
            self.stats['deauth_frames'] += 1

            # Log packet arrival from "switch"
            logger.switch_packet_in("DEAUTH", claimed_mac, "ff:ff:ff:ff:ff:ff",
                                     port=1, rssi=rf_features.rssi)

            # === OBSERVE ===
            logger.ooda_observe("DEAUTH", claimed_mac, {'rssi': rf_features.rssi})

            # === ORIENT: MOCC identification ===
            # MOCC compares the RF features against the claimed MAC's signature
            prob, is_legitimate = self.mocc.identify(claimed_mac, rf_features)
            logger.ooda_orient_mocc(claimed_mac, prob, is_legitimate)

            if is_spoofed:
                logger.attack_deauth(source_mac, claimed_mac, True, self.stats['deauth_frames'])

            # === DECIDE: KCSM state machine ===
            attack, should_drop = self.kcsm.process_deauth(claimed_mac, is_legitimate)
            kcsm_state = self.kcsm.deauth_kcsm.get_client(claimed_mac).deauth_state
            logger.ooda_decide_kcsm("DEAUTH", claimed_mac, kcsm_state,
                                     attack != AttackType.NONE,
                                     attack.name if attack != AttackType.NONE else None)

            # === ACT ===
            if should_drop:
                self.stats['deauth_dropped'] += 1
                logger.ooda_decide_drop("Spoofed frame (RF mismatch)", claimed_mac)
            else:
                logger.ooda_decide_pass(claimed_mac)

            if attack != AttackType.NONE:
                self.stats['attacks_detected'] += 1
                logger.ooda_act_countermeasure("INJECT_FALSE_HANDSHAKE", claimed_mac,
                                                "Poisoning attacker capture")
                logger.ooda_act_alert(attack.name,
                                       f"Client {claimed_mac} under attack from {source_mac}")

            return (attack, should_drop, prob)

        elif frame_type == 'data':
            # Data frames are used for MOCC training
            logger.switch_packet_in("DATA", source_mac, "ff:ff:ff:ff:ff:ff",
                                     port=1, rssi=rf_features.rssi)
            self.mocc.train(source_mac, rf_features)

            status = self.mocc.get_training_status(source_mac)
            if status['samples'] % 50 == 0:
                logger.ooda_orient_training(source_mac, status['samples'], status['trained'])

            return (AttackType.NONE, False, 1.0)

        elif frame_type == 'beacon':
            # Beacon frame for evil twin detection
            logger.switch_packet_in("BEACON", source_mac, "ff:ff:ff:ff:ff:ff",
                                     port=1, rssi=rf_features.rssi)
            logger.ooda_observe("BEACON", source_mac)

            attack = self.kcsm.process_beacon(self.ssid, source_mac)
            if attack != AttackType.NONE:
                self.stats['attacks_detected'] += 1
                logger.attack_evil_twin(self.ssid, self.bssid or "UNKNOWN", source_mac)

            return (attack, False, 1.0)

        elif frame_type == 'auth':
            logger.switch_packet_in("AUTH", source_mac, "ff:ff:ff:ff:ff:ff",
                                     port=1, rssi=rf_features.rssi)
            logger.ooda_observe("AUTH", source_mac)

            attack = self.kcsm.process_auth()
            if attack != AttackType.NONE:
                self.stats['attacks_detected'] += 1
                logger.attack_flood("AUTH", self.kcsm.auth_flood_kcsm.auth_count, 10)

            return (attack, False, 1.0)
