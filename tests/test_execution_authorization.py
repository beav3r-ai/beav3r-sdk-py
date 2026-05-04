from __future__ import annotations

import base64
import unittest

from beav3r_sdk.execution_authorization import (
    canonicalize,
    hash_action,
    is_valid_execution_authorization,
    verify_execution_authorization,
)

try:
    from nacl.signing import SigningKey
except ImportError:  # pragma: no cover
    SigningKey = None  # type: ignore[assignment]


class ExecutionAuthorizationTests(unittest.TestCase):
    def test_canonicalize_sorts_nested_keys(self) -> None:
        value = {"z": 1, "a": {"y": 2, "x": 1}}
        self.assertEqual(canonicalize(value), '{"a":{"x":1,"y":2},"z":1}')

    def test_hash_action_is_stable(self) -> None:
        action = {
            "actionId": "act_1",
            "agentId": "agent_1",
            "actionType": "payments.send_usdt",
            "payload": {"amount": 25, "asset": "USDT"},
            "attributes": {"asset": "USDT", "amount": 25},
            "timestamp": 1700000000,
            "nonce": "nonce_1",
            "expiry": 1700000300,
        }
        expected = hash_action(action)
        self.assertEqual(expected, hash_action(action))
        self.assertEqual(len(expected), 64)

    @unittest.skipIf(SigningKey is None, "PyNaCl not installed in local test environment")
    def test_verify_execution_authorization_accepts_valid_signature(self) -> None:
        assert SigningKey is not None
        signing_key = SigningKey.generate()
        verify_key = signing_key.verify_key
        public_key = base64.b64encode(bytes(verify_key)).decode("utf-8")

        action = {
            "actionId": "act_2",
            "agentId": "agent_2",
            "actionType": "payments.send_usdt",
            "payload": {"amount": 10, "recipient": "0xabc"},
            "attributes": {"amount": 10, "recipient": "0xabc"},
            "timestamp": 1700000100,
            "nonce": "nonce_2",
            "expiry": 1700000400,
        }
        action_hash = hash_action(action)
        payload = {
            "version": "v1",
            "artifactId": "authz_1",
            "actionId": "act_2",
            "actionHash": action_hash,
            "decision": "allow",
            "issuedAt": 1700000100,
            "expiresAt": 4700000100,
            "audience": "payments-executor",
            "keyId": "kid_1",
        }
        payload_bytes = canonicalize(payload).encode("utf-8")
        signature = base64.b64encode(signing_key.sign(payload_bytes).signature).decode(
            "utf-8"
        )

        artifact = {
            "payload": payload,
            "signature": signature,
            "algorithm": "ed25519",
            "keyId": "kid_1",
        }
        verified = verify_execution_authorization(
            {
                "artifact": artifact,
                "action": action,
                "audience": "payments-executor",
                "publicKeys": {"kid_1": public_key},
                "now": 1700000200,
            }
        )
        self.assertEqual(verified["artifactId"], "authz_1")
        self.assertTrue(
            is_valid_execution_authorization(
                {
                    "artifact": artifact,
                    "action": action,
                    "audience": "payments-executor",
                    "publicKeys": {"kid_1": public_key},
                    "now": 1700000200,
                }
            )
        )

    @unittest.skipIf(SigningKey is None, "PyNaCl not installed in local test environment")
    def test_verify_execution_authorization_rejects_audience_mismatch(self) -> None:
        assert SigningKey is not None
        signing_key = SigningKey.generate()
        public_key = base64.b64encode(bytes(signing_key.verify_key)).decode("utf-8")

        action = {
            "actionId": "act_3",
            "agentId": "agent_3",
            "actionType": "payments.send_usdt",
            "payload": {"amount": 10},
            "attributes": {"amount": 10},
            "timestamp": 1700000100,
            "nonce": "nonce_3",
            "expiry": 1700000400,
        }
        payload = {
            "version": "v1",
            "artifactId": "authz_2",
            "actionId": "act_3",
            "actionHash": hash_action(action),
            "decision": "allow",
            "issuedAt": 1700000100,
            "expiresAt": 4700000100,
            "audience": "executor-A",
            "keyId": "kid_2",
        }
        signature = base64.b64encode(
            signing_key.sign(canonicalize(payload).encode("utf-8")).signature
        ).decode("utf-8")
        artifact = {"payload": payload, "signature": signature, "algorithm": "ed25519"}

        with self.assertRaisesRegex(ValueError, "audience mismatch"):
            verify_execution_authorization(
                {
                    "artifact": artifact,
                    "action": action,
                    "audience": "executor-B",
                    "publicKeys": {"kid_2": public_key},
                    "now": 1700000200,
                }
            )

    @unittest.skipIf(SigningKey is None, "PyNaCl not installed in local test environment")
    def test_verify_execution_authorization_ignores_server_added_presentation_metadata(self) -> None:
        assert SigningKey is not None
        signing_key = SigningKey.generate()
        public_key = base64.b64encode(bytes(signing_key.verify_key)).decode("utf-8")

        action = {
            "actionId": "act_3b",
            "agentId": "agent_3b",
            "actionType": "payments.send_usdt",
            "payload": {"amount": 10},
            "attributes": {"amount": 10},
            "timestamp": 1700000100,
            "nonce": "nonce_3b",
            "expiry": 1700000400,
        }
        payload = {
            "version": "v1",
            "artifactId": "authz_2b",
            "actionId": "act_3b",
            "actionHash": hash_action(action),
            "decision": "allow",
            "issuedAt": 1700000100,
            "expiresAt": 4700000100,
            "audience": "executor-A",
            "keyId": "kid_2b",
        }
        signature = base64.b64encode(
            signing_key.sign(canonicalize(payload).encode("utf-8")).signature
        ).decode("utf-8")
        artifact = {"payload": payload, "signature": signature, "algorithm": "ed25519"}

        action_with_presentation = {
            **action,
            "payload": {
                **action["payload"],
                "presentation": {
                    "review": {
                        "title": "Display-only metadata",
                    }
                },
            },
        }

        verified = verify_execution_authorization(
            {
                "artifact": artifact,
                "action": action_with_presentation,
                "audience": "executor-A",
                "publicKeys": {"kid_2b": public_key},
                "now": 1700000200,
            }
        )
        self.assertEqual(verified["actionHash"], hash_action(action))

    @unittest.skipIf(SigningKey is None, "PyNaCl not installed in local test environment")
    def test_verify_execution_authorization_can_enforce_one_time_usage(self) -> None:
        assert SigningKey is not None
        signing_key = SigningKey.generate()
        public_key = base64.b64encode(bytes(signing_key.verify_key)).decode("utf-8")

        action = {
            "actionId": "act_4",
            "agentId": "agent_4",
            "actionType": "payments.send_usdt",
            "payload": {"amount": 12},
            "attributes": {"amount": 12},
            "timestamp": 1700000100,
            "nonce": "nonce_4",
            "expiry": 1700000400,
        }
        payload = {
            "version": "v1",
            "artifactId": "authz_replay_1",
            "actionId": "act_4",
            "actionHash": hash_action(action),
            "decision": "allow",
            "issuedAt": 1700000100,
            "expiresAt": 4700000100,
            "audience": "executor-A",
            "keyId": "kid_4",
        }
        signature = base64.b64encode(
            signing_key.sign(canonicalize(payload).encode("utf-8")).signature
        ).decode("utf-8")
        artifact = {"payload": payload, "signature": signature, "algorithm": "ed25519"}

        used_artifact_ids: set[str] = set()
        verified = verify_execution_authorization(
            {
                "artifact": artifact,
                "action": action,
                "audience": "executor-A",
                "publicKeys": {"kid_4": public_key},
                "now": 1700000200,
                "usedArtifactIds": used_artifact_ids,
            }
        )
        self.assertEqual(verified["artifactId"], "authz_replay_1")

        with self.assertRaisesRegex(ValueError, "has already been used"):
            verify_execution_authorization(
                {
                    "artifact": artifact,
                    "action": action,
                    "audience": "executor-A",
                    "publicKeys": {"kid_4": public_key},
                    "now": 1700000200,
                    "usedArtifactIds": used_artifact_ids,
                }
            )
