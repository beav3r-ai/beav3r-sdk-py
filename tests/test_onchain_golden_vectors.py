from __future__ import annotations

import json
import unittest
from pathlib import Path

from beav3r_sdk.onchain import (
    compute_onchain_action_hash,
    compute_onchain_authorization_digest,
    verify_onchain_authorization,
)


GOLDEN_VECTORS_PATH = (
    Path(__file__).resolve().parents[2]
    / "beav3r-server"
    / "contracts"
    / "spec"
    / "onchain"
    / "v1"
    / "golden-vectors.json"
)


class OnchainGoldenVectorTests(unittest.TestCase):
    def test_onchain_v1_action_hash_and_digest_match_golden_vectors(self) -> None:
        if not GOLDEN_VECTORS_PATH.exists():
            self.skipTest(f"canonical onchain v1 golden vectors not found: {GOLDEN_VECTORS_PATH}")

        document = json.loads(GOLDEN_VECTORS_PATH.read_text(encoding="utf-8"))
        self.assertEqual(document.get("protocolVersion"), "onchain-v1")

        vectors = document.get("vectors") or []
        self.assertGreater(len(vectors), 0)

        for vector in vectors:
            with self.subTest(vector=vector.get("name", "<unnamed>")):
                request = vector["request"]
                artifact = vector["artifact"]
                expected = vector.get("expected") or {}
                expected_action_hash = expected.get("actionHash") or artifact["payload"]["actionHash"]
                expected_digest = expected.get("digest") or artifact["digest"]

                try:
                    action_hash = compute_onchain_action_hash(request)
                    digest = compute_onchain_authorization_digest(artifact)
                    verified = verify_onchain_authorization(
                        {
                            "artifact": artifact,
                            "request": request,
                        }
                    )
                except ImportError as error:
                    if "keccak256 requires" in str(error):
                        self.skipTest(str(error))
                    raise

                self.assertEqual(action_hash, expected_action_hash)
                self.assertEqual(artifact["payload"]["actionHash"], expected_action_hash)
                self.assertEqual(digest, expected_digest)
                self.assertEqual(artifact["digest"], expected_digest)
                self.assertEqual(
                    verified,
                    {
                        "actionHash": expected_action_hash,
                        "digest": expected_digest,
                    },
                )


if __name__ == "__main__":
    unittest.main()
