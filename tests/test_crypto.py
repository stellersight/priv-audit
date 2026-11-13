# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 StellerSight Private Limited
import unittest
import hashlib
from privaudit.crypto import RFC6962Hasher, RFC6962MerkleTree


class TestRFC6962Crypto(unittest.TestCase):
    def test_domain_separation_leaf_prefix(self):
        data = b"test payload"
        expected = hashlib.sha256(b"\x00" + data).digest()
        self.assertEqual(RFC6962Hasher.hash_leaf(data), expected)

    def test_domain_separation_node_prefix(self):
        left = hashlib.sha256(b"left").digest()
        right = hashlib.sha256(b"right").digest()
        expected = hashlib.sha256(b"\x01" + left + right).digest()
        self.assertEqual(RFC6962Hasher.hash_children(left, right), expected)

    def test_merkle_tree_empty_root(self):
        tree = RFC6962MerkleTree()
        expected_empty = hashlib.sha256(b"").digest()
        self.assertEqual(tree.get_root_hash(), expected_empty)

    def test_merkle_tree_single_leaf(self):
        tree = RFC6962MerkleTree()
        tree.append_event({"action": "privilege_elevation_granted", "sub_id": "usr_101"})
        self.assertEqual(len(tree.leaves), 1)
        self.assertEqual(tree.get_root_hash(), tree.leaves[0])

    def test_merkle_checkpoint_schema(self):
        tree = RFC6962MerkleTree()
        tree.append_event({"event": "grant_issued", "seq": 1})
        tree.append_event({"event": "stepup_passed", "seq": 2})
        tree.append_event({"event": "grant_expired", "seq": 3})

        checkpoint = tree.generate_checkpoint(chain_id="linux-prod-node-01", epoch=1)
        self.assertEqual(checkpoint["schema"], "suit.checkpoint.v1")
        self.assertEqual(checkpoint["tree_size"], 3)
        self.assertTrue(checkpoint["merkle_root"].startswith("sha256:"))
        self.assertEqual(checkpoint["domain_separation"], "RFC6962")


if __name__ == "__main__":
    unittest.main()
