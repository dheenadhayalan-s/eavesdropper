"""
blockchain.py
Custom lightweight blockchain implementation to provide an immutable,
cryptographically verified audit trail for BB84 session runs.
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple


@dataclass
class Block:
    index: int
    timestamp: float
    audit_data: Dict[str, Any]
    previous_hash: str
    hash: str = ""

    def calculate_hash(self) -> str:
        """
        Calculates the SHA-256 hash of the block.
        The audit_data dictionary is serialized with sorted keys to ensure deterministic hashing.
        """
        serialized_data = json.dumps(self.audit_data, sort_keys=True)
        block_string = f"{self.index}{self.timestamp}{serialized_data}{self.previous_hash}"
        return hashlib.sha256(block_string.encode("utf-8")).hexdigest()

    def __post_init__(self):
        # Automatically calculate the current hash if it is not provided (e.g. when creating a new block)
        if not self.hash:
            self.hash = self.calculate_hash()


class Blockchain:
    def __init__(self):
        self.chain: List[Block] = []

    def create_genesis_block(self) -> Block:
        """Creates the initial genesis block for the blockchain."""
        return Block(
            index=0,
            timestamp=1700000000.0,  # Constant timestamp for genesis block predictability
            audit_data={"message": "Genesis Block - Secure Quantum Audit Trail Initiated"},
            previous_hash="0",
        )

    def initialize_chain(self):
        """Initializes the chain with a genesis block if it is currently empty."""
        if not self.chain:
            self.chain = [self.create_genesis_block()]

    def add_block(self, audit_data: Dict[str, Any]) -> Block:
        """
        Creates, hashes, and appends a new block to the blockchain.
        """
        self.initialize_chain()
        previous_block = self.chain[-1]
        new_block = Block(
            index=previous_block.index + 1,
            timestamp=time.time(),
            audit_data=audit_data,
            previous_hash=previous_block.hash,
        )
        self.chain.append(new_block)
        return new_block

    def verify_chain(self) -> Tuple[bool, int]:
        """
        Verifies the cryptographic integrity of the blockchain.
        Returns:
            (True, -1) if the chain is valid and untampered.
            (False, index) of the first block that failed validation.
        """
        if not self.chain:
            return True, -1

        # Verify Genesis block hash
        genesis = self.chain[0]
        if genesis.hash != genesis.calculate_hash():
            return False, 0

        # Verify subsequent blocks
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            # 1. Check if the block's current hash matches its calculated hash
            if current.hash != current.calculate_hash():
                return False, i

            # 2. Check if the current block links correctly to the previous block's hash
            if current.previous_hash != previous.hash:
                return False, i

            # 3. Check index order consistency
            if current.index != previous.index + 1:
                return False, i

        return True, -1

    def save_chain(self, filepath: str) -> None:
        """Serializes and saves the current blockchain to a JSON file."""
        serialized = []
        for block in self.chain:
            serialized.append({
                "index": block.index,
                "timestamp": block.timestamp,
                "audit_data": block.audit_data,
                "previous_hash": block.previous_hash,
                "hash": block.hash,
            })
        with open(filepath, "w") as f:
            json.dump(serialized, f, indent=4)

    def load_chain(self, filepath: str) -> None:
        """Loads and deserializes the blockchain from a JSON file."""
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
            self.chain = []
            for item in data:
                block = Block(
                    index=item["index"],
                    timestamp=item["timestamp"],
                    audit_data=item["audit_data"],
                    previous_hash=item["previous_hash"],
                    hash=item["hash"],
                )
                self.chain.append(block)
        except (FileNotFoundError, json.JSONDecodeError, KeyError):
            self.chain = []
            self.initialize_chain()


class AuditManager:
    def __init__(self, filepath: str = "blockchain.json"):
        self.filepath = filepath
        self.blockchain = Blockchain()
        self.load_audit_trail()

    def load_audit_trail(self) -> None:
        """Reloads the blockchain from disk, initializing if missing."""
        self.blockchain.load_chain(self.filepath)
        if not self.blockchain.chain:
            self.blockchain.initialize_chain()
            self.blockchain.save_chain(self.filepath)

    def verify_chain(self) -> Tuple[bool, int]:
        """Delegates chain verification to the underlying Blockchain object."""
        self.load_audit_trail()
        return self.blockchain.verify_chain()

    def log_simulation(
        self,
        session_id: str,
        key_length: int,
        qber: float,
        eve_detected: bool,
        timestamp: float = None,
    ) -> Block:
        """
        Receives BB84 simulation results, converts them into blockchain records,
        and appends them to the blockchain.
        """
        if timestamp is None:
            timestamp = time.time()

        audit_record = {
            "session_id": session_id,
            "key_length": key_length,
            "qber": qber,
            "eve_detected": eve_detected,
            "timestamp": timestamp,
        }

        # Always reload the latest state from disk first to keep synchronized
        self.load_audit_trail()
        new_block = self.blockchain.add_block(audit_record)
        self.blockchain.save_chain(self.filepath)
        return new_block

