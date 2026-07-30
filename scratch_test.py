import numpy as np
import hashlib
import os

def derive_aes_key(sifted_bits: list) -> bytes:
    bit_string = "".join(str(b) for b in sifted_bits)
    return hashlib.sha256(bit_string.encode("utf-8")).digest()

n_qubits = 400
sample_fraction = 0.5
rng = np.random.default_rng(42)

# Alice
alice_bits = rng.integers(0, 2, size=n_qubits).tolist()
alice_bases = rng.integers(0, 2, size=n_qubits).tolist()

sent_bits = list(alice_bits)
sent_bases = list(alice_bases)

# Bob measures
bob_bases = rng.integers(0, 2, size=n_qubits).tolist()
transmitted_bits = list(sent_bits)
transmitted_bases = list(sent_bases)

bob_results = []
for i in range(n_qubits):
    if bob_bases[i] == transmitted_bases[i]:
        bob_results.append(transmitted_bits[i])
    else:
        bob_results.append(int(rng.integers(0, 2)))

# Sifting
matching_indices = [
    i for i in range(n_qubits) if alice_bases[i] == bob_bases[i]
]
sifted_len = len(matching_indices)
n_sample = max(1, int(sifted_len * sample_fraction))
# Alice choice
sample_positions = rng.choice(sifted_len, size=n_sample, replace=False).tolist()
sample_indices = [matching_indices[pos] for pos in sample_positions]
alice_sample_bits = [alice_bits[idx] for idx in sample_indices]

# Bob QBER check
mismatches = 0
for idx_pos, sample_idx in enumerate(sample_indices):
    bob_bit = bob_results[sample_idx]
    alice_bit = alice_sample_bits[idx_pos]
    if bob_bit != alice_bit:
        mismatches += 1
qber = mismatches / n_sample
print("QBER:", qber)

# Keys derivation
sample_set = set(sample_indices)
final_key_bits_alice = [
    alice_bits[idx] for idx in matching_indices if idx not in sample_set
]
final_key_bits_bob = [
    bob_results[idx] for idx in matching_indices if idx not in sample_set
]

print("Alice key len:", len(final_key_bits_alice))
print("Bob key len:", len(final_key_bits_bob))
print("Keys match:", final_key_bits_alice == final_key_bits_bob)
if final_key_bits_alice != final_key_bits_bob:
    for i, (a, b) in enumerate(zip(final_key_bits_alice, final_key_bits_bob)):
        if a != b:
            print(f"Mismatch at index {i}: Alice={a}, Bob={b}")
            break
