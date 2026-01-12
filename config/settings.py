#!/usr/bin/env python3
"""
WIDD Configuration Settings
"""

# Network configuration
NETWORK_SSID = 'WIDD_Network'
NETWORK_CHANNEL = 6

# bmv2 switch configuration
BMV2_THRIFT_IP = '127.0.0.1'
BMV2_THRIFT_PORT = 9090

# P4 program
P4_JSON_PATH = 'p4/widd.json'

# MOCC settings
MOCC_IDENTIFICATION_THRESHOLD = 0.55  # 55% probability threshold
MOCC_MIN_TRAINING_SAMPLES = 100       # Minimum frames for training

# KCSM settings
KCSM_TIMEOUT = 2.0                    # Seconds (from hostapd deauth timeout)
KCSM_DEAUTH_FALSE_THRESHOLD = 2       # False deauths to trigger attack
KCSM_DEAUTH_TOTAL_THRESHOLD = 3       # Total deauths to trigger attack
KCSM_FLOOD_THRESHOLD = 10             # Frames per window for flood detection

# Legitimate client devices (MAC -> base RSSI)
LEGITIMATE_CLIENTS = {
    '00:00:00:00:00:01': -45,  # sta1
    '00:00:00:00:00:02': -55,  # sta2
    '00:00:00:00:00:03': -50,  # sta3
}

# Attacker device
ATTACKER_MAC = '00:00:00:00:00:99'
ATTACKER_RSSI = -60

# RF noise parameters
RF_RSSI_NOISE_STD = 3
RF_PHASE_NOISE_STD = 10
RF_PILOT_NOISE_STD = 5
RF_MAG_NOISE_STD = 50
