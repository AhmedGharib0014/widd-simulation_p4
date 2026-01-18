/*
 * WIDD P4 Program - Wireless Impersonation Detection and Defense
 *
 * Implements the OODA loop Observe/Orientate stages:
 * - Parse Ethernet frames with encapsulated 802.11 headers
 * - Identify frame type: Data, Control, Management
 * - Detect Deauthentication frames (subtype 0xC)
 * - Send suspicious frames to CPU (control plane)
 *
 * Frame Structure (simplified for simulation):
 * [Ethernet Header][802.11 Frame Control][802.11 Addresses][Payload]
 *
 * 802.11 Frame Control (2 bytes):
 * - Protocol Version: 2 bits
 * - Type: 2 bits (0=Management, 1=Control, 2=Data)
 * - Subtype: 4 bits (for Management: 0xC=Deauth, 0xA=Disassoc, 0xB=Auth, 0x0=Assoc)
 * - Flags: 8 bits
 */

#include <core.p4>
#include <v1model.p4>

/*************************************************************************
 *                         CONSTANTS
 *************************************************************************/

const bit<16> ETHERTYPE_WIFI = 0x0800;  // Using IPv4 ethertype as placeholder
const bit<16> ETHERTYPE_WIDD = 0x88B5; // Local experimental ethertype for WIDD

// 802.11 Frame Types
const bit<2> FRAME_TYPE_MANAGEMENT = 0;
const bit<2> FRAME_TYPE_CONTROL = 1;
const bit<2> FRAME_TYPE_DATA = 2;

// 802.11 Management Frame Subtypes
const bit<4> SUBTYPE_ASSOC_REQ = 0x0;
const bit<4> SUBTYPE_ASSOC_RESP = 0x1;
const bit<4> SUBTYPE_REASSOC_REQ = 0x2;
const bit<4> SUBTYPE_REASSOC_RESP = 0x3;
const bit<4> SUBTYPE_PROBE_REQ = 0x4;
const bit<4> SUBTYPE_PROBE_RESP = 0x5;
const bit<4> SUBTYPE_BEACON = 0x8;
const bit<4> SUBTYPE_DISASSOC = 0xA;
const bit<4> SUBTYPE_AUTH = 0xB;
const bit<4> SUBTYPE_DEAUTH = 0xC;

// CPU Port for Packet-In
const bit<9> CPU_PORT = 255;

/*************************************************************************
 *                         HEADERS
 *************************************************************************/

typedef bit<48> macAddr_t;
typedef bit<9> egressSpec_t;

// Standard Ethernet header
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

// Simplified 802.11 Frame Control header (encapsulated after Ethernet)
header wifi_fc_t {
    bit<2>  protocolVersion;
    bit<2>  frameType;
    bit<4>  subType;
    bit<1>  toDS;
    bit<1>  fromDS;
    bit<1>  moreFragments;
    bit<1>  retry;
    bit<1>  powerManagement;
    bit<1>  moreData;
    bit<1>  wep;
    bit<1>  order;
}

// 802.11 Addresses (simplified - 3 addresses for most frames)
header wifi_addr_t {
    macAddr_t addr1;  // Receiver/Destination
    macAddr_t addr2;  // Transmitter/Source
    macAddr_t addr3;  // BSSID or other
    bit<16>   seqCtrl; // Sequence control
}

// Simulated RF features (appended by our simulation layer)
header rf_features_t {
    bit<16> rssi;        // Received Signal Strength Indicator
    bit<16> phaseOffset; // Phase offset
    bit<16> pilotOffset; // Pilot offset
    bit<16> magSquared;  // Magnitude squared
}

// CPU header for Packet-In/Out metadata
header cpu_header_t {
    bit<8>  reason;      // Why sent to CPU (1=deauth, 2=assoc, 3=auth, 4=beacon)
    bit<8>  origPort;    // Original ingress port
    bit<16> rfRssi;      // Copy of RSSI for MOCC
}

// Header struct
struct headers_t {
    cpu_header_t  cpu;
    ethernet_t    ethernet;
    wifi_fc_t     wifiFC;
    wifi_addr_t   wifiAddr;
    rf_features_t rfFeatures;
}

// Metadata struct
struct metadata_t {
    bit<1>  sendToCpu;
    bit<8>  cpuReason;
    bit<1>  dropPacket;
    bit<1>  isDeauth;
    bit<1>  isKnownDevice;
}

/*************************************************************************
 *                         PARSER
 *************************************************************************/

parser WiddParser(
    packet_in packet,
    out headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t standard_metadata
) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHERTYPE_WIDD: parse_wifi_fc;
            default: accept;
        }
    }

    state parse_wifi_fc {
        packet.extract(hdr.wifiFC);
        transition parse_wifi_addr;
    }

    state parse_wifi_addr {
        packet.extract(hdr.wifiAddr);
        transition parse_rf_features;
    }

    state parse_rf_features {
        packet.extract(hdr.rfFeatures);
        transition accept;
    }
}

/*************************************************************************
 *                    CHECKSUM VERIFICATION
 *************************************************************************/

control WiddVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

/*************************************************************************
 *                    INGRESS PROCESSING
 *************************************************************************/

control WiddIngress(
    inout headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t standard_metadata
) {
    // Counter for statistics
    counter(256, CounterType.packets) frameCounter;

    // Register to store known device MACs (simplified - just a flag)
    register<bit<1>>(256) knownDevices;

    // Action: Drop the packet
    action drop() {
        mark_to_drop(standard_metadata);
        meta.dropPacket = 1;
    }

    // Action: Forward to specified port
    action forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    // Action: Send to CPU for control plane processing
    action send_to_cpu(bit<8> reason) {
        standard_metadata.egress_spec = CPU_PORT;
        meta.sendToCpu = 1;
        meta.cpuReason = reason;

        // Add CPU header
        hdr.cpu.setValid();
        hdr.cpu.reason = reason;
        hdr.cpu.origPort = (bit<8>)standard_metadata.ingress_port;
        hdr.cpu.rfRssi = hdr.rfFeatures.rssi;
    }

    // Action: Flood to all ports
    action flood() {
        standard_metadata.mcast_grp = 1;
    }

    // Table for L2 forwarding
    table l2_forward {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            forward;
            flood;
            drop;
        }
        size = 256;
        default_action = flood();
    }

    // Table for device identification lookup
    table device_lookup {
        key = {
            hdr.wifiAddr.addr2: exact;  // Source MAC
        }
        actions = {
            NoAction;
        }
        size = 256;
        default_action = NoAction();
    }

    // Table for blocking malicious sources (populated by controller)
    table blocklist {
        key = {
            hdr.wifiAddr.addr2: exact;  // Source MAC (transmitter)
        }
        actions = {
            drop;
            NoAction;
        }
        size = 256;
        default_action = NoAction();
    }

    apply {
        // Initialize metadata
        meta.sendToCpu = 0;
        meta.dropPacket = 0;
        meta.isDeauth = 0;
        meta.cpuReason = 0;

        // Check blocklist first - drop packets from known attackers
        if (hdr.wifiAddr.isValid()) {
            blocklist.apply();
            if (meta.dropPacket == 1) {
                // Packet is from blocked attacker, already marked for drop
                return;
            }
        }

        // OBSERVE: Check if this is a WIDD frame
        if (hdr.wifiFC.isValid()) {

            // Count frames by type
            frameCounter.count((bit<32>)hdr.wifiFC.frameType);

            // ORIENTATE: Determine frame type and subtype
            if (hdr.wifiFC.frameType == FRAME_TYPE_MANAGEMENT) {

                // Check for Deauthentication frame
                if (hdr.wifiFC.subType == SUBTYPE_DEAUTH) {
                    meta.isDeauth = 1;
                    // Always send deauth frames to CPU for MOCC/KCSM processing
                    send_to_cpu(1);  // reason=1 for deauth
                }
                // Check for Authentication frame
                else if (hdr.wifiFC.subType == SUBTYPE_AUTH) {
                    send_to_cpu(3);  // reason=3 for auth
                }
                // Check for Association frames
                else if (hdr.wifiFC.subType == SUBTYPE_ASSOC_REQ ||
                         hdr.wifiFC.subType == SUBTYPE_ASSOC_RESP) {
                    send_to_cpu(2);  // reason=2 for assoc
                }
                // Check for Disassociation frame
                else if (hdr.wifiFC.subType == SUBTYPE_DISASSOC) {
                    send_to_cpu(5);  // reason=5 for disassoc
                }
                // Check for Beacon frame
                else if (hdr.wifiFC.subType == SUBTYPE_BEACON) {
                    send_to_cpu(4);  // reason=4 for beacon
                }
                else {
                    // Other management frames - forward normally
                    meta.sendToCpu = 0;
                }
            }
            else if (hdr.wifiFC.frameType == FRAME_TYPE_DATA) {
                // Data frames - use for MOCC training
                // Send copy to CPU for learning
                send_to_cpu(6);  // reason=6 for data (training)
            }
            // Control frames (FRAME_TYPE_CONTROL) - just pass through
        }

        // Apply L2 forwarding for non-CPU packets
        if (meta.sendToCpu == 0 && meta.dropPacket == 0) {
            l2_forward.apply();
        }
    }
}

/*************************************************************************
 *                    EGRESS PROCESSING
 *************************************************************************/

control WiddEgress(
    inout headers_t hdr,
    inout metadata_t meta,
    inout standard_metadata_t standard_metadata
) {
    apply {
        // Remove CPU header if not going to CPU
        if (standard_metadata.egress_port != CPU_PORT && hdr.cpu.isValid()) {
            hdr.cpu.setInvalid();
        }
    }
}

/*************************************************************************
 *                    CHECKSUM COMPUTATION
 *************************************************************************/

control WiddComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply { }
}

/*************************************************************************
 *                    DEPARSER
 *************************************************************************/

control WiddDeparser(packet_out packet, in headers_t hdr) {
    apply {
        packet.emit(hdr.cpu);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.wifiFC);
        packet.emit(hdr.wifiAddr);
        packet.emit(hdr.rfFeatures);
    }
}

/*************************************************************************
 *                    SWITCH INSTANTIATION
 *************************************************************************/

V1Switch(
    WiddParser(),
    WiddVerifyChecksum(),
    WiddIngress(),
    WiddEgress(),
    WiddComputeChecksum(),
    WiddDeparser()
) main;
