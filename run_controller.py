#!/usr/bin/env python3
"""
WIDD OODA Controller - Real Network Mode

Connects to bmv2 P4 switch and processes real packets from the network.

Usage:
    python3 run_controller.py
    python3 run_controller.py --thrift-port 9090 --cpu-iface s1-cpu
"""

import sys
import time
import argparse
import signal
from controller.ooda_controller import OODAController
from controller.logger import logger


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully."""
    print("\n")
    logger.system_stop("OODA Controller")
    logger.print_stats()
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        description='WIDD OODA Controller - Real Network Mode',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This script connects the OODA Controller to a running bmv2 P4 switch
and processes real packets from the mininet-wifi network.

Prerequisites:
  1. Mininet-WiFi topology must be running
  2. bmv2 switch must be running with widd.p4 program
  3. CPU port interface must be available (e.g., s1-cpu)

Examples:
  # Default settings:
  python3 run_controller.py

  # Custom bmv2 connection:
  python3 run_controller.py --thrift-port 9090 --cpu-iface s1-cpu

  # Custom network config:
  python3 run_controller.py --ssid MyNetwork --bssid 00:11:22:33:44:55
        """
    )

    parser.add_argument('--thrift-ip', default='127.0.0.1',
                       help='BMV2 Thrift server IP (default: 127.0.0.1)')
    parser.add_argument('--thrift-port', type=int, default=9090,
                       help='BMV2 Thrift server port (default: 9090)')
    parser.add_argument('--cpu-iface', default='s1-cpu',
                       help='CPU port interface name (default: s1-cpu)')
    parser.add_argument('--ssid', default='WIDD_Network',
                       help='Network SSID (default: WIDD_Network)')
    parser.add_argument('--bssid', default='00:11:22:33:44:55',
                       help='Network BSSID (default: 00:11:22:33:44:55)')
    parser.add_argument('--client1', default='00:00:00:00:00:01',
                       help='Client 1 MAC address (default: 00:00:00:00:00:01)')
    parser.add_argument('--client2', default='00:00:00:00:00:02',
                       help='Client 2 MAC address (default: 00:00:00:00:00:02)')
    parser.add_argument('--rssi1', type=int, default=-45,
                       help='Client 1 base RSSI (default: -45)')
    parser.add_argument('--rssi2', type=int, default=-55,
                       help='Client 2 base RSSI (default: -55)')

    args = parser.parse_args()

    # Setup signal handler
    signal.signal(signal.SIGINT, signal_handler)

    # Print banner
    logger.print_banner()
    logger.system_start("OODA Controller - Real Network Mode")

    print("\n" + "="*70)
    print("  CONFIGURATION")
    print("="*70)
    print(f"  BMV2 Thrift:    {args.thrift_ip}:{args.thrift_port}")
    print(f"  CPU Interface:  {args.cpu_iface}")
    print(f"  Network SSID:   {args.ssid}")
    print(f"  Network BSSID:  {args.bssid}")
    print("="*70 + "\n")

    # Initialize OODA Controller
    controller = OODAController(
        switch_ip=args.thrift_ip,
        switch_port=args.thrift_port,
        cpu_iface=args.cpu_iface
    )

    # Configure network
    controller.set_network_info(args.ssid, args.bssid)

    # Register legitimate clients
    logger.system_info("Registering legitimate clients...")
    controller.register_client(args.client1, base_rssi=args.rssi1)
    controller.register_client(args.client2, base_rssi=args.rssi2)

    # Start the controller
    logger.system_info("Starting OODA loop...")
    if not controller.start():
        logger.system_error("CONTROLLER", "Failed to start - check bmv2 connection")
        sys.exit(1)

    print("\n" + "="*70)
    print("  OODA CONTROLLER RUNNING")
    print("="*70)
    print("  Listening for packets from P4 switch CPU port...")
    print("  Ready to detect attacks!")
    print("  Press Ctrl+C to stop")
    print("="*70 + "\n")

    # Keep running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass

    # Cleanup
    controller.stop()


if __name__ == '__main__':
    main()
