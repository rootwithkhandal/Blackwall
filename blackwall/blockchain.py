#!/usr/bin/env python3
"""
blockchain.py — Immutable append-only ledger with RSA block signing,
optional proof-of-work, and JSON export.

PoW note: mining is intentionally applied only to the genesis block and
rule-change blocks, NOT to high-frequency packet-log blocks.  Applying
PoW to every packet would stall the sniffer thread under real traffic.
"""

import hashlib
import json
import os
import threading
import time
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Project root is two levels up from this file (blackwall/blockchain.py)
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Block types that warrant proof-of-work
_POW_TYPES = {"genesis", "rule_add", "rule_delete"}


class Block:
    def __init__(
        self,
        index: int,
        prev_hash: str,
        data,
        signer: str | None = None,
        signature: bytes | None = None,
    ):
        self.index     = index
        self.timestamp = time.time()
        self.data      = data
        self.prev_hash = prev_hash
        self.nonce     = 0
        self.signer    = signer
        self.signature = signature
        self.hash      = self.calc_hash()

    # ------------------------------------------------------------------
    # Hashing
    # ------------------------------------------------------------------

    def calc_hash(self) -> str:
        block_str = (
            f"{self.index}{self.timestamp}"
            f"{json.dumps(self.data, sort_keys=True, default=str)}"
            f"{self.prev_hash}{self.nonce}"
        )
        return hashlib.sha256(block_str.encode()).hexdigest()

    def mine(self, difficulty: int = 2) -> None:
        """Proof-of-work: increment nonce until hash starts with *difficulty* zeros."""
        prefix = "0" * difficulty
        while not self.hash.startswith(prefix):
            self.nonce += 1
            self.hash = self.calc_hash()

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "index":     self.index,
            "timestamp": self.timestamp,
            "data":      self.data,
            "prev_hash": self.prev_hash,
            "nonce":     self.nonce,
            "signer":    self.signer,
            "signature": self.signature.hex() if self.signature else None,
            "hash":      self.hash,
        }

    @staticmethod
    def from_dict(d: dict) -> "Block":
        sig       = d.get("signature")
        sig_bytes = bytes.fromhex(sig) if sig else None
        blk = Block(
            d["index"],
            d["prev_hash"],
            d["data"],
            signer=d.get("signer"),
            signature=sig_bytes,
        )
        blk.timestamp = d.get("timestamp", time.time())
        blk.nonce     = d.get("nonce", 0)
        blk.hash      = d.get("hash", blk.calc_hash())
        return blk

    # ------------------------------------------------------------------
    # Signing / verification
    # ------------------------------------------------------------------

    def sign(self, private_key) -> None:
        self.signature = private_key.sign(
            self.hash.encode(), padding.PKCS1v15(), hashes.SHA256()
        )

    def verify(self, public_key) -> bool:
        """Return True only when the signature is cryptographically valid."""
        if not self.signature or not public_key:
            return False
        try:
            public_key.verify(
                self.signature,
                self.hash.encode(),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False


class Blockchain:
    def __init__(
        self,
        public_key=None,
        private_key=None,
        ledger_file: str | None = None,
        difficulty: int = 2,
    ):
        self.chain       : list[Block] = []
        self.public_key  = public_key
        self.private_key = private_key
        self.difficulty  = difficulty
        self._lock       = threading.Lock()   # serialise concurrent add_block calls

        # Default ledger lives in <project_root>/data/ledger.json
        if ledger_file is None:
            data_dir = os.path.join(_ROOT, "data")
            os.makedirs(data_dir, exist_ok=True)
            ledger_file = os.path.join(data_dir, "ledger.json")
        self.ledger_file = ledger_file

        self.load()
        if not self.chain:
            self.add_block("genesis")

    # ------------------------------------------------------------------
    # Block operations
    # ------------------------------------------------------------------

    def add_block(self, data) -> Block:
        """Append a new block. PoW is applied only to rule/genesis blocks."""
        with self._lock:
            prev_hash = self.chain[-1].hash if self.chain else "0"
            blk = Block(len(self.chain), prev_hash, data, signer="fw")

            # Determine whether this block type warrants PoW
            block_type = data if isinstance(data, str) else data.get("type", "")
            if self.difficulty > 0 and block_type in _POW_TYPES:
                blk.mine(self.difficulty)

            if self.private_key:
                blk.sign(self.private_key)

            self.chain.append(blk)
            self._append_block_file(blk)
        return blk

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _append_block_file(self, blk: Block) -> None:
        """Append a single block line to the ledger file (called under lock)."""
        with open(self.ledger_file, "a") as f:
            f.write(json.dumps(blk.to_dict()) + "\n")

    def load(self) -> None:
        """Load the chain from disk. Skips corrupted lines gracefully."""
        self.chain = []
        if not os.path.exists(self.ledger_file):
            return
        with open(self.ledger_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    self.chain.append(Block.from_dict(json.loads(line)))
                except (json.JSONDecodeError, KeyError):
                    continue

    def export_json(self, path: str | None = None) -> str:
        """Export the full chain to a pretty-printed JSON file."""
        if path is None:
            path = os.path.join(_ROOT, "data", "ledger_export.json")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with self._lock:
            chain_copy = [b.to_dict() for b in self.chain]
        with open(path, "w") as f:
            json.dump(chain_copy, f, indent=2)
        return path

    # ------------------------------------------------------------------
    # Integrity
    # ------------------------------------------------------------------

    def check_integrity(self) -> list[dict]:
        """
        Walk the chain and return a list of issue dicts {index, issue}.
        Empty list means the chain is clean.
        """
        issues: list[dict] = []
        with self._lock:
            chain = list(self.chain)
        for i, blk in enumerate(chain):
            if blk.hash != blk.calc_hash():
                issues.append({"index": i, "issue": "Hash mismatch"})
            if i > 0 and blk.prev_hash != chain[i - 1].hash:
                issues.append({"index": i, "issue": "Prev-hash mismatch"})
            if self.public_key and not blk.verify(self.public_key):
                issues.append({"index": i, "issue": "Invalid signature"})
        return issues

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def __len__(self) -> int:
        return len(self.chain)

    def summary(self) -> dict:
        with self._lock:
            latest = self.chain[-1].hash if self.chain else None
            total  = len(self.chain)
        return {
            "total_blocks": total,
            "latest_hash":  latest,
            "difficulty":   self.difficulty,
        }
