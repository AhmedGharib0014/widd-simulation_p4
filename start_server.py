#!/usr/bin/env python3
"""
WIDD Server - Entry point for running OODA Controller in server mode

This script initializes the OODA Controller and starts the SimulationServer
to accept connections from the Attack CLI and Packet Monitor.

Usage:
    python3 start_server.py
    python3 start_server.py --help
"""

import sys
import time
import argparse
from controller.ooda_controller import OODAController
from controller.simulation_server import SimulationServer
from controller.logger import logger


def main():
    parser = argparse.ArgumentParser(
        description='WIDD OODA Controller - Server Mode',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 start_server.py
  python3 start_server.py --ssid MyNetwork --bssid 00:11:22:33:44:55
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
    parser.add_argument('--port', type=int, default=9999,
                        help='Server port for attack CLI (default: 9999)')

    args = parser.parse_args()

    # Print banner
    logger.print_banner()
    logger.system_start("OODA Controller Server")

    # Initialize controller
    controller = OODAController()

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

    # Start simulation server
    print("\n" + "="*70)
    print("  SERVER MODE - READY")
    print("="*70)
    print(f"  Listening for attack CLI connections on port {args.port}")
    print(f"  Monitor events broadcast on port 9998")
    print(f"  Press Ctrl+C to stop")
    print("="*70 + "\n")

    server = SimulationServer(controller)
    server.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n")
        logger.system_stop("OODA Controller Server")
        logger.print_stats()
        server.stop()
        sys.exit(0)


if __name__ == '__main__':
    main()
