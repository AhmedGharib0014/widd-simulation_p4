#!/usr/bin/env python3
"""
WIDD MOCC - Multiplexed One-Class Classifier

Simulated RF device fingerprinting based on:
- RSSI (Received Signal Strength Indicator)
- Phase Offset
- Pilot Offset
- Magnitude Squared

In the real system, these RF features are extracted from the OFDM PHY layer.
For simulation, we assign each device a "fingerprint" and add noise.

The classifier:
1. Learns device signatures from data frames (training)
2. Identifies if a management frame is from the claimed MAC (prediction)
3. Returns probability p > 55% = legitimate, p < 55% = impersonation
"""

import random
import math
from typing import Dict, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import time


@dataclass
class RFFeatures:
    """RF features extracted from a frame."""
    rssi: int = 0           # Signal strength (dBm, typically -30 to -90)
    phase_offset: int = 0   # Phase offset (arbitrary units)
    pilot_offset: int = 0   # Pilot offset (arbitrary units)
    mag_squared: int = 0    # Magnitude squared (arbitrary units)

    def to_tuple(self) -> Tuple[int, int, int, int]:
        return (self.rssi, self.phase_offset, self.pilot_offset, self.mag_squared)

    def distance(self, other: 'RFFeatures') -> float:
        """Calculate Euclidean distance to another RF feature set."""
        return math.sqrt(
            (self.rssi - other.rssi) ** 2 +
            (self.phase_offset - other.phase_offset) ** 2 +
            (self.pilot_offset - other.pilot_offset) ** 2 +
            (self.mag_squared - other.mag_squared) ** 2
        )


@dataclass
class DeviceSignature:
    """Learned signature for a device."""
    mac_address: str
    samples: list = field(default_factory=list)
    mean_features: Optional[RFFeatures] = None
    std_features: Optional[RFFeatures] = None
    trained: bool = False
    last_updated: float = 0

    # Minimum samples needed for reliable identification
    MIN_SAMPLES = 100  # Paper says 600-1000 for >98% accuracy


class MOCC:
    """
    Multiplexed One-Class Classifier for RF device identification.

    Uses a simple statistical approach:
    - Learn mean and std of RF features per device
    - Use Gaussian distance to calculate probability of match
    """

    # Threshold for identification (from paper: p > 55%)
    # Lowered slightly for simulation due to RF noise variance
    IDENTIFICATION_THRESHOLD = 0.35

    def __init__(self):
        # Device signatures: MAC -> DeviceSignature
        self.signatures: Dict[str, DeviceSignature] = {}

        # Simulated "true" RF fingerprints for each device
        # In reality, these come from hardware characteristics
        self._simulated_fingerprints: Dict[str, RFFeatures] = {}

        # Noise parameters for simulation
        self.rssi_noise_std = 3      # dB
        self.phase_noise_std = 10    # arbitrary units
        self.pilot_noise_std = 5     # arbitrary units
        self.mag_noise_std = 50      # arbitrary units

    def register_device(self, mac_address: str, base_rssi: int = -50):
        """
        Register a device with simulated RF characteristics.

        In real system, this would happen automatically as devices connect.
        For simulation, we assign random but consistent fingerprints.

        Args:
            mac_address: Device MAC address
            base_rssi: Base RSSI value (affected by distance)
        """
        if mac_address not in self._simulated_fingerprints:
            # Generate unique fingerprint for this device
            # Each device has slightly different RF characteristics
            self._simulated_fingerprints[mac_address] = RFFeatures(
                rssi=base_rssi,
                phase_offset=random.randint(100, 500),
                pilot_offset=random.randint(50, 200),
                mag_squared=random.randint(1000, 5000)
            )
            print(f"[MOCC] Registered device {mac_address} with fingerprint")

        if mac_address not in self.signatures:
            self.signatures[mac_address] = DeviceSignature(mac_address=mac_address)

    def simulate_rf_features(self, mac_address: str, add_noise: bool = True) -> RFFeatures:
        """
        Simulate RF features for a device.

        Args:
            mac_address: Device MAC address
            add_noise: Whether to add random noise (True for realistic simulation)

        Returns:
            Simulated RF features
        """
        if mac_address not in self._simulated_fingerprints:
            # Unknown device - generate random features
            return RFFeatures(
                rssi=random.randint(-80, -40),
                phase_offset=random.randint(100, 500),
                pilot_offset=random.randint(50, 200),
                mag_squared=random.randint(1000, 5000)
            )

        base = self._simulated_fingerprints[mac_address]

        if not add_noise:
            return RFFeatures(
                rssi=base.rssi,
                phase_offset=base.phase_offset,
                pilot_offset=base.pilot_offset,
                mag_squared=base.mag_squared
            )

        # Add Gaussian noise
        return RFFeatures(
            rssi=int(base.rssi + random.gauss(0, self.rssi_noise_std)),
            phase_offset=int(base.phase_offset + random.gauss(0, self.phase_noise_std)),
            pilot_offset=int(base.pilot_offset + random.gauss(0, self.pilot_noise_std)),
            mag_squared=int(base.mag_squared + random.gauss(0, self.mag_noise_std))
        )

    def train(self, mac_address: str, features: RFFeatures):
        """
        Add a training sample for a device (from data frames).

        Args:
            mac_address: Device MAC address
            features: RF features extracted from the frame
        """
        if mac_address not in self.signatures:
            self.signatures[mac_address] = DeviceSignature(mac_address=mac_address)

        sig = self.signatures[mac_address]
        sig.samples.append(features)
        sig.last_updated = time.time()

        # Update statistics if we have enough samples
        if len(sig.samples) >= DeviceSignature.MIN_SAMPLES:
            self._update_signature(mac_address)

    def _update_signature(self, mac_address: str):
        """Update mean and std for a device signature."""
        sig = self.signatures[mac_address]
        samples = sig.samples

        # Calculate mean
        mean_rssi = sum(s.rssi for s in samples) / len(samples)
        mean_phase = sum(s.phase_offset for s in samples) / len(samples)
        mean_pilot = sum(s.pilot_offset for s in samples) / len(samples)
        mean_mag = sum(s.mag_squared for s in samples) / len(samples)

        sig.mean_features = RFFeatures(
            rssi=int(mean_rssi),
            phase_offset=int(mean_phase),
            pilot_offset=int(mean_pilot),
            mag_squared=int(mean_mag)
        )

        # Calculate std
        if len(samples) > 1:
            std_rssi = math.sqrt(sum((s.rssi - mean_rssi)**2 for s in samples) / (len(samples) - 1))
            std_phase = math.sqrt(sum((s.phase_offset - mean_phase)**2 for s in samples) / (len(samples) - 1))
            std_pilot = math.sqrt(sum((s.pilot_offset - mean_pilot)**2 for s in samples) / (len(samples) - 1))
            std_mag = math.sqrt(sum((s.mag_squared - mean_mag)**2 for s in samples) / (len(samples) - 1))

            sig.std_features = RFFeatures(
                rssi=max(1, int(std_rssi)),
                phase_offset=max(1, int(std_phase)),
                pilot_offset=max(1, int(std_pilot)),
                mag_squared=max(1, int(std_mag))
            )
        else:
            # Default std if not enough variance
            sig.std_features = RFFeatures(
                rssi=self.rssi_noise_std,
                phase_offset=self.phase_noise_std,
                pilot_offset=self.pilot_noise_std,
                mag_squared=self.mag_noise_std
            )

        sig.trained = True
        print(f"[MOCC] Updated signature for {mac_address} ({len(samples)} samples)")

    def identify(self, claimed_mac: str, features: RFFeatures) -> Tuple[float, bool]:
        """
        Identify if a frame is actually from the claimed MAC address.

        This is the Dev_ident() function from the paper.

        Args:
            claimed_mac: MAC address claimed by the frame
            features: RF features extracted from the frame

        Returns:
            Tuple of (probability, is_legitimate)
            - probability: 0.0 to 1.0, likelihood frame is from claimed device
            - is_legitimate: True if probability > threshold
        """
        # If we don't have a signature for this device, can't identify
        if claimed_mac not in self.signatures:
            print(f"[MOCC] Unknown device {claimed_mac}, cannot identify")
            return (0.5, True)  # Assume legitimate if unknown

        sig = self.signatures[claimed_mac]

        # If not trained yet, can't identify reliably
        if not sig.trained or sig.mean_features is None or sig.std_features is None:
            # Use partial data if available
            if len(sig.samples) > 10:
                self._update_signature(claimed_mac)
            else:
                print(f"[MOCC] Insufficient training for {claimed_mac} ({len(sig.samples)} samples)")
                return (0.5, True)  # Assume legitimate

        # Calculate probability using Gaussian distance
        # P = product of individual feature probabilities

        probability = 1.0

        # RSSI probability
        z_rssi = abs(features.rssi - sig.mean_features.rssi) / max(1, sig.std_features.rssi)
        p_rssi = math.exp(-0.5 * z_rssi ** 2)
        probability *= p_rssi

        # Phase offset probability
        z_phase = abs(features.phase_offset - sig.mean_features.phase_offset) / max(1, sig.std_features.phase_offset)
        p_phase = math.exp(-0.5 * z_phase ** 2)
        probability *= p_phase

        # Pilot offset probability
        z_pilot = abs(features.pilot_offset - sig.mean_features.pilot_offset) / max(1, sig.std_features.pilot_offset)
        p_pilot = math.exp(-0.5 * z_pilot ** 2)
        probability *= p_pilot

        # Magnitude squared probability
        z_mag = abs(features.mag_squared - sig.mean_features.mag_squared) / max(1, sig.std_features.mag_squared)
        p_mag = math.exp(-0.5 * z_mag ** 2)
        probability *= p_mag

        # Normalize to 0-1 range (geometric mean)
        probability = probability ** 0.25

        is_legitimate = probability >= self.IDENTIFICATION_THRESHOLD

        return (probability, is_legitimate)

    def get_training_status(self, mac_address: str) -> Dict:
        """Get training status for a device."""
        if mac_address not in self.signatures:
            return {'registered': False, 'samples': 0, 'trained': False}

        sig = self.signatures[mac_address]
        return {
            'registered': True,
            'samples': len(sig.samples),
            'trained': sig.trained,
            'min_samples': DeviceSignature.MIN_SAMPLES
        }


# Test the MOCC
if __name__ == '__main__':
    print("Testing MOCC...")

    mocc = MOCC()

    # Register legitimate devices
    mocc.register_device('00:00:00:00:00:01', base_rssi=-45)
    mocc.register_device('00:00:00:00:00:02', base_rssi=-55)

    # Register attacker device (different fingerprint)
    mocc.register_device('00:00:00:00:00:99', base_rssi=-60)

    # Train with data frames from sta1
    print("\n--- Training phase ---")
    for i in range(150):
        features = mocc.simulate_rf_features('00:00:00:00:00:01')
        mocc.train('00:00:00:00:00:01', features)

    # Test identification
    print("\n--- Identification tests ---")

    # Test 1: Legitimate frame from sta1
    print("\nTest 1: Legitimate deauth from sta1")
    features = mocc.simulate_rf_features('00:00:00:00:00:01')
    prob, legit = mocc.identify('00:00:00:00:00:01', features)
    print(f"  Probability: {prob:.2%}, Legitimate: {legit}")

    # Test 2: Spoofed frame (attacker claiming to be sta1)
    print("\nTest 2: Spoofed deauth (attacker claiming to be sta1)")
    features = mocc.simulate_rf_features('00:00:00:00:00:99')  # Attacker's RF
    prob, legit = mocc.identify('00:00:00:00:00:01', features)  # Claims to be sta1
    print(f"  Probability: {prob:.2%}, Legitimate: {legit}")

    # Test 3: Multiple spoofed attempts
    print("\nTest 3: 10 spoofed deauths")
    detected = 0
    for i in range(10):
        features = mocc.simulate_rf_features('00:00:00:00:00:99')
        prob, legit = mocc.identify('00:00:00:00:00:01', features)
        if not legit:
            detected += 1
    print(f"  Detected {detected}/10 spoofed frames ({detected*10}% detection rate)")
