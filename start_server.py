#!/usr/bin/env python3
"""
WIDD Server - Entry point for running OODA Controller in server mode

This script initializes the OODA Controller and listens for Packet-In
events from the P4 switch via the CPU port interface.

Usage:
    sudo python3 start_server.py
    sudo python3 start_server.py --help

Note: Requires root privileges for packet capture.
"""

import sys
import time
import os
import argparse
from controller.ooda_controller import OODAController
from controller.logger import logger
from controller.switch_interface import (
    SwitchInterface, PacketInEvent,
    CPU_REASON_DEAUTH, CPU_REASON_AUTH, CPU_REASON_ASSOC,
    CPU_REASON_BEACON, CPU_REASON_DISASSOC, CPU_REASON_DATA
)


def main():
    # Check if running as root
    if os.geteuid() != 0:
        print("ERROR: This script requires root privileges for packet capture.")
        print("Please run with: sudo python3 start_server.py")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description='WIDD OODA Controller - Server Mode',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 start_server.py
  sudo python3 start_server.py --ssid MyNetwork --bssid 00:11:22:33:44:55
        """
    )

    parser.add_argument('--ssid', default='WIDD_Network',
                        help='Network SSID (default: WIDD_Network)')
    parser.add_argument('--bssid', default='00:11:22:33:44:55',
                        help='Network BSSID (default: 00:11:22:33:44:55)')
    parser.add_argument('--client1', default='00:00:00:00:00:01',
                        help='Client 1 MAC address (default: 00:00:00:00:00:01)')
    parser.add_argument('--client2', default='00:00:00:00:00:02',
                        help='Client 2 MAC address (default: 00:00:00:00:00:02)')
    parser.add_argument('--attacker', default='00:00:00:00:00:99',
                        help='Attacker MAC address (default: 00:00:00:00:00:99)')
    parser.add_argument('--rssi1', type=int, default=-45,
                        help='Client 1 base RSSI (default: -45)')
    parser.add_argument('--rssi2', type=int, default=-55,
                        help='Client 2 base RSSI (default: -55)')
    parser.add_argument('--rssi-attacker', type=int, default=-70,
                        help='Attacker base RSSI (default: -70)')

    args = parser.parse_args()

    # Print banner
    logger.print_banner()
    logger.system_start("OODA Controller Server")

    # CPU port interface for P4 Packet-In/Out
    cpu_interface = 's1-cpu-h'

    # Initialize controller with CPU interface for Packet-Out
    controller = OODAController(cpu_iface=cpu_interface)

    # Configure network
    controller.set_network_info(args.ssid, args.bssid)
    logger.system_info(f"Network: SSID={args.ssid}, BSSID={args.bssid}")

    # Register legitimate clients
    logger.system_info("Registering legitimate clients...")
    controller.register_client(args.client1, base_rssi=args.rssi1)
    controller.register_client(args.client2, base_rssi=args.rssi2)

    # Register attacker (for simulation purposes)
    controller.mocc.register_device(args.attacker, base_rssi=args.rssi_attacker)
    logger.system_info(f"Attacker device registered: {args.attacker} (RSSI={args.rssi_attacker}dBm)")

    # Train MOCC with client 1 data frames
    logger.system_info(f"Training MOCC with 100 data frames from {args.client1}...")
    for i in range(100):
        controller.simulate_frame('data', args.client1)

    status = controller.mocc.get_training_status(args.client1)
    logger.system_info(f"MOCC training complete: {status['samples']} samples, trained={status['trained']}")

    # Define callback to process received packets
    def handle_packet(event: PacketInEvent):
        """Process received WIDD frame through OODA controller."""
        from controller.ooda_controller import ParsedFrame
        from controller.mocc import RFFeatures

        try:
            # Get frame_info from the PacketInEvent
            frame_info = event.to_dict()

            # Check if frame parsing had errors
            if 'error' in frame_info:
                logger.system_info(f"[SwitchInterface] Error parsing frame: {frame_info['error']}")
                return

            # Log received frame
            frame_type_str = frame_info.get('frame_type', 'Unknown')
            subtype_str = frame_info.get('subtype', 'Unknown')
            src_mac = frame_info.get('src_mac', 'Unknown')
            rssi = frame_info.get('rssi', 0)

            print(f"[SwitchInterface] Received: {frame_type_str}/{subtype_str} from {src_mac} RSSI={rssi}dBm")

            # Create ParsedFrame dataclass from frame_info
            # This allows us to use the existing _process_* methods in the controller
            frame = ParsedFrame(
                eth_dst=bytes.fromhex(frame_info.get('dst_mac', '00:00:00:00:00:00').replace(':', '')),
                eth_src=bytes.fromhex(frame_info.get('src_mac', '00:00:00:00:00:00').replace(':', '')),
                eth_type=0x88B5,  # WIDD ethertype
                frame_type=frame_info.get('frame_type_num', 0),
                subtype=frame_info.get('subtype_num', 0),
                addr1=frame_info.get('dst_mac', '00:00:00:00:00:00'),    # Receiver
                addr2=frame_info.get('src_mac', '00:00:00:00:00:00'),    # Transmitter
                addr3=frame_info.get('bssid', '00:00:00:00:00:00'),      # BSSID
                rssi=rssi,
                phase_offset=frame_info.get('phase', 0),
                pilot_offset=frame_info.get('pilot', 0),
                mag_squared=frame_info.get('mag', 0),
                cpu_reason=frame_info.get('cpu_reason', 0),
                orig_port=frame_info.get('cpu_orig_port', 0),
                raw_bytes=frame_info.get('raw_bytes', b'')  # Full raw packet for Packet-Out
            )

            # Create RFFeatures for MOCC
            rf_features = RFFeatures(
                rssi=rssi,
                phase_offset=frame_info.get('phase', 0),
                pilot_offset=frame_info.get('pilot', 0),
                mag_squared=frame_info.get('mag', 0)
            )

            cpu_reason = frame_info.get('cpu_reason', 0)

            # Process through controller's OODA pipeline using existing methods
            if cpu_reason == CPU_REASON_DEAUTH or subtype_str == 'Deauth':
                controller._process_deauth(frame, rf_features)
            elif cpu_reason == CPU_REASON_DISASSOC or subtype_str == 'Disassoc':
                controller._process_disassoc(frame, rf_features)
            elif cpu_reason == CPU_REASON_AUTH or subtype_str == 'Auth':
                controller._process_auth(frame)
            elif cpu_reason == CPU_REASON_ASSOC or subtype_str == 'Assoc Req':
                controller._process_assoc(frame)
            elif cpu_reason == CPU_REASON_BEACON or subtype_str == 'Beacon':
                controller._process_beacon(frame)
            elif cpu_reason == CPU_REASON_DATA or frame_type_str == 'Data':
                controller._process_data(frame, rf_features)
            else:
                # Unknown frame type, log and skip
                print(f"[SwitchInterface] Unknown frame type: cpu_reason={cpu_reason}, subtype={subtype_str}")

        except Exception as e:
            logger.system_info(f"[SwitchInterface] Error processing frame: {e}")
            import traceback
            traceback.print_exc()

    # Wait for network interface to be available
    # NOTE: We listen on the CPU port veth interface created by bmv2
    # This receives Packet-In messages from the P4 switch
    import subprocess
    logger.system_info(f"Checking for P4 CPU port interface {cpu_interface}...")

    max_retries = 30
    for i in range(max_retries):
        try:
            result = subprocess.run(['ip', 'link', 'show', cpu_interface],
                                  capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                logger.system_info(f"Interface {cpu_interface} found!")
                break
        except Exception:
            pass

        if i == 0:
            logger.system_info(f"Waiting for {cpu_interface} to be available...")

        time.sleep(1)
    else:
        logger.system_info(f"WARNING: Interface {cpu_interface} not found after {max_retries} seconds")
        logger.system_info("Available interfaces:")
        try:
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if ':' in line and not line.startswith(' '):
                    logger.system_info(f"  {line.strip()}")
        except Exception as e:
            logger.system_info(f"Could not list interfaces: {e}")

        logger.system_info("\nTrying to continue anyway...")

    # Create SwitchInterface for Packet-In/Out handling
    logger.system_info(f"Starting SwitchInterface on {cpu_interface}...")
    switch_interface = SwitchInterface(cpu_iface=cpu_interface)
    switch_interface.start_packet_in_listener(callback=handle_packet)

    # Ready to receive packets from P4 switch
    print("\n" + "="*70)
    print("  OODA CONTROLLER READY")
    print("="*70)
    print(f"  Listening for P4 Packet-In on CPU port: {cpu_interface}")
    print("  P4 switch filters management frames and sends via Packet-In")
    print("  Send attacks via mininet-wifi using interactive_attack.py")
    print("  Press Ctrl+C to stop")
    print("="*70 + "\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n")
        logger.system_info("Stopping SwitchInterface...")
        switch_interface.stop_packet_in_listener()
        logger.system_stop("OODA Controller")
        logger.print_stats()
        sys.exit(0)


if __name__ == '__main__':
    main()
