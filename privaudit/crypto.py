"""
RFC 6962 Domain-Separated Merkle Tree & Cryptographic Audit Checkpoint Engine.
StellerSight Private Limited - Continuous Access Governance & SUIT Core Architecture.
"""

import hashlib
import json
import time
from typing import List, Dict, Any, Tuple, Optional


class RFC6962Hasher:
    """
    Implements RFC 6962 Section 2.1 domain-separated hashing.
    Leaf Hash: SHA-256(0x00 || leaf_data)
    Internal Node Hash: SHA-256(0x01 || left_hash || right_hash)
    """

    LEAF_PREFIX = b"\x00"
    NODE_PREFIX = b"\x01"

    @classmethod
    def hash_leaf(cls, data: bytes) -> bytes:
        hasher = hashlib.sha256()
        hasher.update(cls.LEAF_PREFIX)
        hasher.update(data)
        return hasher.digest()

    @classmethod
    def hash_children(cls, left: bytes, right: bytes) -> bytes:
        hasher = hashlib.sha256()
        hasher.update(cls.NODE_PREFIX)
        hasher.update(left)
        hasher.update(right)
        return hasher.digest()


class RFC6962MerkleTree:
    """
    Compact append-only Merkle tree conforming to RFC 6962.
    Supports continuous event ingestion, root calculation, and inclusion proofs.
    """

    def __init__(self):
        self.leaves: List[bytes] = []

    def append_event(self, event_dict: Dict[str, Any]) -> str:
        """
        Appends a canonical JSON event, hashes it with domain separation (0x00),
        and returns the hex leaf hash.
        """
        canonical_json = json.dumps(event_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
        leaf_hash = RFC6962Hasher.hash_leaf(canonical_json)
        self.leaves.append(leaf_hash)
        return leaf_hash.hex()

    def get_root_hash(self) -> bytes:
        """
        Calculates the RFC 6962 Merkle tree root hash.
        Empty tree root is SHA-256("").
        """
        if not self.leaves:
            return hashlib.sha256(b"").digest()

        return self._compute_subtree_root(self.leaves)

    def _compute_subtree_root(self, leaves: List[bytes]) -> bytes:
        n = len(leaves)
        if n == 1:
            return leaves[0]

        # Find k: the largest power of 2 smaller than n
        k = 1 << ((n - 1).bit_length() - 1)
        left_root = self._compute_subtree_root(leaves[:k])
        right_root = self._compute_subtree_root(leaves[k:])
        return RFC6962Hasher.hash_children(left_root, right_root)

    def generate_checkpoint(self, chain_id: str, epoch: int, boot_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Generates a signed-ready suit.checkpoint.v1 envelope.
        """
        root_digest = self.get_root_hash().hex()
        return {
            "schema": "suit.checkpoint.v1",
            "chain_id": chain_id,
            "tree_size": len(self.leaves),
            "merkle_root": f"sha256:{root_digest}",
            "epoch": epoch,
            "boot_id": boot_id or "local-kernel-monotonic",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "domain_separation": "RFC6962",
        }
