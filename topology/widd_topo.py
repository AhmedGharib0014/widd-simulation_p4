#!/usr/bin/env python3
"""
WIDD Simulation - Mininet-WiFi Topology with bmv2 Switch

Creates a virtual wireless network with:
- 1 Access Point (WAP) connected to bmv2 switch
- 3 Legitimate client stations
- 1 Attacker station
- wmediumd for RF simulation (RSSI)
- bmv2 switch for P4-based packet processing

Architecture:
    [sta1] --\
    [sta2] ----> [ap1] <---> [s1 (bmv2)] <---> [Python Controller]
    [sta3] --/                    |
    [attacker] -/                 |
                             [Thrift API]
"""

from mn_wifi.net import Mininet_wifi
from mn_wifi.node import OVSKernelAP, Station
from mn_wifi.cli import CLI
from mn_wifi.link import wmediumd
from mn_wifi.wmediumdConnector import interference
from mininet.node import Controller, RemoteController, Switch
from mininet.log import setLogLevel, info
from mininet.link import Intf
import os
import sys
import subprocess
import time


# Path to P4 compiled JSON (will be created in Phase 2)
P4_JSON_PATH = os.path.join(os.path.dirname(__file__), '..', 'p4', 'widd.json')
BMV2_SWITCH = 'simple_switch'
THRIFT_PORT = 9090


class P4Switch(Switch):
    """Custom switch class that runs bmv2 simple_switch."""

    def __init__(self, name, sw_path=BMV2_SWITCH, json_path=None,
                 thrift_port=THRIFT_PORT, pcap_dump=False, log_console=False,
                 **kwargs):
        Switch.__init__(self, name, **kwargs)
        self.sw_path = sw_path
        self.json_path = json_path
        self.thrift_port = thrift_port
        self.pcap_dump = pcap_dump
        self.log_console = log_console
        self.bmv2_pid = None

    def start(self, controllers):
        """Start bmv2 switch."""
        info(f"*** Starting bmv2 switch {self.name} ***\n")

        # Build interface list
        ifaces = []
        for port, intf in self.intfs.items():
            if port > 0:  # Skip loopback
                ifaces.extend(['-i', f'{port}@{intf.name}'])

        # Build command
        cmd = [self.sw_path]

        if self.json_path and os.path.exists(self.json_path):
            cmd.append(self.json_path)
        else:
            info(f"*** Warning: P4 JSON not found at {self.json_path}, running without P4 program ***\n")

        cmd.extend(ifaces)
        cmd.extend(['--thrift-port', str(self.thrift_port)])

        if self.pcap_dump:
            cmd.extend(['--pcap'])

        if self.log_console:
            cmd.extend(['--log-console'])

        # Add CPU port for Packet-In/Out
        cmd.extend(['--', '--cpu-port', '255'])

        info(f"*** bmv2 command: {' '.join(cmd)} ***\n")

        # Start bmv2 in background
        log_file = f'/tmp/{self.name}.log'
        with open(log_file, 'w') as f:
            self.bmv2_proc = subprocess.Popen(cmd, stdout=f, stderr=f)
            self.bmv2_pid = self.bmv2_proc.pid

        info(f"*** bmv2 started with PID {self.bmv2_pid}, log: {log_file} ***\n")
        time.sleep(1)  # Give bmv2 time to start

    def stop(self):
        """Stop bmv2 switch."""
        info(f"*** Stopping bmv2 switch {self.name} ***\n")
        if self.bmv2_pid:
            try:
                os.kill(self.bmv2_pid, 9)
            except OSError:
                pass
        Switch.stop(self)


def create_topology(use_bmv2=True, remote_controller=True):
    """Create WIDD simulation topology.

    Args:
        use_bmv2: If True, use bmv2 P4 switch. If False, use standard OVS.
        remote_controller: If True, connect to POX on localhost:6633.
    """

    info("*** Creating WIDD Simulation Network ***\n")

    # Create network with wmediumd for realistic wireless simulation
    net = Mininet_wifi(
        controller=RemoteController if remote_controller else Controller,
        link=wmediumd,
        wmediumd_mode=interference,
        autoAssociation=True
    )

    info("*** Adding controller ***\n")
    if remote_controller:
        # Connect to POX controller running on localhost:6633
        c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)
        info("*** Using RemoteController at 127.0.0.1:6633 (POX) ***\n")
    else:
        c0 = net.addController('c0', controller=Controller)

    info("*** Adding access point (WAP) ***\n")
    # Access Point - the device we're protecting
    ap1 = net.addAccessPoint(
        'ap1',
        ssid='WIDD_Network',
        mode='g',
        channel='6',
        position='50,50,0',
        range=50
    )

    # Add bmv2 switch if enabled
    if use_bmv2:
        info("*** Adding bmv2 P4 switch ***\n")
        s1 = net.addSwitch(
            's1',
            cls=P4Switch,
            json_path=P4_JSON_PATH,
            thrift_port=THRIFT_PORT,
            log_console=False
        )
    else:
        info("*** Adding standard OVS switch ***\n")
        s1 = net.addSwitch('s1')

    info("*** Adding legitimate stations ***\n")
    # Legitimate client stations
    sta1 = net.addStation(
        'sta1',
        mac='00:00:00:00:00:01',
        ip='10.0.0.1/24',
        position='30,50,0'
    )
    sta2 = net.addStation(
        'sta2',
        mac='00:00:00:00:00:02',
        ip='10.0.0.2/24',
        position='50,30,0'
    )
    sta3 = net.addStation(
        'sta3',
        mac='00:00:00:00:00:03',
        ip='10.0.0.3/24',
        position='70,50,0'
    )

    info("*** Adding attacker station ***\n")
    # Attacker station - will send spoofed deauth frames
    attacker = net.addStation(
        'attacker',
        mac='00:00:00:00:00:99',
        ip='10.0.0.99/24',
        position='50,70,0'
    )

    info("*** Configuring propagation model ***\n")
    net.setPropagationModel(model="logDistance", exp=4)

    info("*** Configuring WiFi nodes ***\n")
    net.configureWifiNodes()

    info("*** Creating links ***\n")
    # Stations associate with AP automatically due to autoAssociation=True

    # Link AP to bmv2 switch
    info("*** Linking AP to switch ***\n")
    net.addLink(ap1, s1)

    info("*** Starting network ***\n")
    net.build()
    c0.start()
    ap1.start([c0])
    s1.start([c0])

    info("*** Network is ready ***\n")
    info("*** Topology: ***\n")
    info("    sta1 (00:00:00:00:00:01) ---\\\n")
    info("    sta2 (00:00:00:00:00:02) ----> ap1 <---> s1 (bmv2) <---> Controller\n")
    info("    sta3 (00:00:00:00:00:03) ---/            |\n")
    info("    attacker (00:00:00:00:00:99) -/     Thrift:9090\n")
    info("\n")

    # Print station info
    info("*** Station Information ***\n")
    for sta in [sta1, sta2, sta3, attacker]:
        info(f"    {sta.name}: MAC={sta.MAC()}, IP={sta.IP()}\n")

    info("\n*** Access Point Information ***\n")
    info(f"    ap1: SSID=WIDD_Network, Channel=6\n")

    # Print interface information for the attacker station
    info("\n*** Attacker Interface Information ***\n")
    try:
        # Get interface names directly from the Mininet station object
        attacker_intfs = list(attacker.intfs.values())
        if attacker_intfs:
            info("    Interfaces created for attacker station:\n")
            for intf in attacker_intfs:
                info(f"      - {intf.name} (MAC: {intf.MAC()}, IP: {intf.IP()})\n")

            # The first wireless interface is what we need
            wireless_intf = attacker_intfs[0].name
            info(f"\n    ✓ ATTACKER INTERFACE: {wireless_intf}\n")
            info(f"    ✓ MAC: {attacker_intfs[0].MAC()}\n")
            info(f"    ✓ IP: {attacker_intfs[0].IP()}\n")
            info(f"\n    NOTE: This interface exists in the attacker's network namespace\n")
            info(f"    To run commands in this namespace, use:\n")
            info(f"      mininet> attacker <command>\n")
        else:
            info("    Warning: No interfaces found for attacker station\n")

    except Exception as e:
        info(f"    Could not query attacker interfaces: {e}\n")

    return net


def test_connectivity(net):
    """Test basic connectivity between stations."""
    info("\n*** Testing connectivity ***\n")

    sta1 = net.get('sta1')
    sta2 = net.get('sta2')

    # Ping test
    info("*** Ping test: sta1 -> sta2 ***\n")
    result = sta1.cmd('ping -c 3 10.0.0.2')
    info(result)

    return net


def main():
    """Main entry point."""
    setLogLevel('info')

    # Check if running as root
    if os.geteuid() != 0:
        print("Error: Mininet-WiFi requires root privileges.")
        print("Please run with: sudo python3 widd_topo.py")
        sys.exit(1)

    # Parse command line arguments
    use_bmv2 = '--no-bmv2' not in sys.argv

    if not use_bmv2:
        info("*** Running without bmv2 (--no-bmv2 flag) ***\n")

    net = None
    try:
        net = create_topology(use_bmv2=use_bmv2)
        test_connectivity(net)

        info("\n*** Starting CLI ***\n")
        info("*** Type 'help' for available commands ***\n")
        info("*** Type 'exit' or Ctrl+D to quit ***\n\n")

        CLI(net)

    except Exception as e:
        info(f"\n*** Error: {e} ***\n")
        import traceback
        traceback.print_exc()
    finally:
        if net:
            info("\n*** Stopping network ***\n")
            net.stop()


if __name__ == '__main__':
    main()
