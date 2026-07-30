"""
bb84_core.py
Core BB84 Quantum Key Distribution protocol simulation.

Physics model (statistical / Born-rule level, no full quantum circuit simulator
needed for this speed/scale — see qiskit_circuit_demo.py for the circuit-level
version used to show judges the actual quantum gates).

Basis encoding convention:
    basis 0 = rectilinear (Z basis): bit 0 -> |0>, bit 1 -> |1>
    basis 1 = diagonal   (X basis): bit 0 -> |+>, bit 1 -> |->

Measurement rule (Born rule, simplified to classical probabilities):
    - If measurement basis == encoding basis: result is deterministic (matches sent bit)
    - If measurement basis != encoding basis: result is uniformly random (50/50)

This reproduces the real quantum statistics of BB84 without needing a full
quantum state simulator, and scales to millions of qubits instantly.
"""

import numpy as np


def generate_random_bits(n, rng):
    return rng.integers(0, 2, size=n)


def generate_random_bases(n, rng):
    return rng.integers(0, 2, size=n)


def measure(bits_sent, bases_sent, bases_measure, rng):
    """
    Simulate Bob's (or Eve's) measurement of qubits.
    Returns the measured bit for each qubit.
    """
    n = len(bits_sent)
    results = np.empty(n, dtype=int)

    same_basis = bases_sent == bases_measure
    # Same basis -> deterministic, correct result
    results[same_basis] = bits_sent[same_basis]

    # Different basis -> random 50/50 outcome
    n_random = np.sum(~same_basis)
    if n_random > 0:
        results[~same_basis] = rng.integers(0, 2, size=n_random)

    return results


def apply_channel_noise(bits, noise_prob, rng):
    """Simulate a simple depolarizing/bit-flip channel independent of Eve."""
    if noise_prob <= 0:
        return bits
    flips = rng.random(len(bits)) < noise_prob
    noisy = bits.copy()
    noisy[flips] = 1 - noisy[flips]
    return noisy


def eve_intercept_resend(bits_sent, bases_sent, eve_fraction, rng):
    """
    Eve intercepts a fraction of the qubits, measures each in a random guessed
    basis, and resends a qubit re-encoded according to what she measured.

    Returns:
        bits_after_eve, bases_after_eve  (what actually reaches Bob)
    """
    n = len(bits_sent)
    intercepted = rng.random(n) < eve_fraction

    bits_after = bits_sent.copy()
    bases_after = bases_sent.copy()

    if np.any(intercepted):
        eve_bases = generate_random_bases(np.sum(intercepted), rng)
        eve_results = measure(bits_sent[intercepted], bases_sent[intercepted], eve_bases, rng)

        # Eve resends according to what she measured (in her own basis)
        bits_after[intercepted] = eve_results
        bases_after[intercepted] = eve_bases

    return bits_after, bases_after, intercepted


def run_bb84(n_qubits, eve_active, eve_fraction, noise_prob, sample_fraction, seed=None):
    """
    Run one full BB84 session and return a results dict.
    """
    rng = np.random.default_rng(seed)

    # Step 1: Alice generates bits and bases, "encodes" qubits
    alice_bits = generate_random_bits(n_qubits, rng)
    alice_bases = generate_random_bases(n_qubits, rng)

    transmitted_bits = alice_bits.copy()
    transmitted_bases = alice_bases.copy()
    eve_mask = np.zeros(n_qubits, dtype=bool)

    # Step 2: Eve's attack (optional)
    if eve_active and eve_fraction > 0:
        transmitted_bits, transmitted_bases, eve_mask = eve_intercept_resend(
            transmitted_bits, transmitted_bases, eve_fraction, rng
        )

    # Step 3: Channel noise (independent of Eve)
    transmitted_bits = apply_channel_noise(transmitted_bits, noise_prob, rng)

    # Step 4: Bob measures with his own random bases
    bob_bases = generate_random_bases(n_qubits, rng)
    bob_results = measure(transmitted_bits, transmitted_bases, bob_bases, rng)

    # Step 5: Public basis reconciliation (sifting)
    matching = alice_bases == bob_bases
    sifted_alice = alice_bits[matching]
    sifted_bob = bob_results[matching]
    sifted_len = len(sifted_alice)

    # Step 6: QBER estimation on a random public sample
    qber = None
    final_key_len = 0
    if sifted_len > 0:
        n_sample = max(1, int(sifted_len * sample_fraction))
        sample_idx = rng.choice(sifted_len, size=n_sample, replace=False)
        mismatches = np.sum(sifted_alice[sample_idx] != sifted_bob[sample_idx])
        qber = mismatches / n_sample
        final_key_len = sifted_len - n_sample

    return {
        "n_qubits": n_qubits,
        "sifted_key_len": sifted_len,
        "qber": qber,
        "final_key_len": final_key_len,
        "eve_active": eve_active,
        "eve_fraction": eve_fraction,
        "noise_prob": noise_prob,
        "eve_intercepted_count": int(np.sum(eve_mask)),
    }


def run_bb84_stepwise(n_qubits, eve_active, eve_fraction, noise_prob, seed=None):
    """
    Generator version of BB84 that yields one qubit-transmission event at a
    time, for real-time / animated demos ("Alice speaks, Bob listens").
    """
    rng = np.random.default_rng(seed)

    for i in range(n_qubits):
        alice_bit = int(rng.integers(0, 2))
        alice_basis = int(rng.integers(0, 2))

        travel_bit, travel_basis = alice_bit, alice_basis
        eve_hit, eve_basis, eve_result = False, None, None

        if eve_active and rng.random() < eve_fraction:
            eve_hit = True
            eve_basis = int(rng.integers(0, 2))
            eve_result = alice_bit if eve_basis == alice_basis else int(rng.integers(0, 2))
            travel_bit, travel_basis = eve_result, eve_basis

        noise_flip = False
        if noise_prob > 0 and rng.random() < noise_prob:
            travel_bit = 1 - travel_bit
            noise_flip = True

        bob_basis = int(rng.integers(0, 2))
        bob_result = travel_bit if bob_basis == travel_basis else int(rng.integers(0, 2))

        yield {
            "i": i,
            "alice_bit": alice_bit,
            "alice_basis": alice_basis,
            "eve_hit": eve_hit,
            "eve_basis": eve_basis,
            "eve_result": eve_result,
            "noise_flip": noise_flip,
            "bob_basis": bob_basis,
            "bob_result": bob_result,
            "basis_match": alice_basis == bob_basis,
        }


def decide_secure(qber, threshold=0.11):
    """Standard BB84 fixed threshold decision (~11% theoretical bound)."""
    if qber is None:
        return None
    return qber <= threshold


def hypothesis_test_decision(qber, baseline_mean, baseline_std, n_sample, z_critical=2.33):
    """
    More rigorous decision rule: is the observed QBER statistically higher
    than the noise-only baseline distribution?  (one-sided z-test, ~99th percentile
    critical value by default)

    Returns (is_secure: bool, z_score: float)
    """
    if qber is None or baseline_std == 0:
        return None, None
    se = baseline_std / np.sqrt(max(n_sample, 1))
    z = (qber - baseline_mean) / se if se > 0 else float("inf")
    is_secure = z < z_critical
    return is_secure, z
