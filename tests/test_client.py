from __future__ import annotations

import json
import time
import unittest

from beav3r_sdk import BeaverClient, BeaverDeniedError, Beav3r, Beav3rDeniedError


class Beav3rClientTests(unittest.TestCase):
    def test_guard_posts_action_request(self) -> None:
        seen: dict[str, object] = {}

        def transport(url: str, method: str, headers: dict[str, str], body: bytes | None):
            seen["url"] = url
            seen["method"] = method
            seen["headers"] = headers
            seen["body"] = json.loads((body or b"{}").decode("utf-8"))
            return {
                "status": 200,
                "headers": {},
                "text": json.dumps(
                    {
                        "status": "pending",
                        "actionId": "act_test",
                        "actionHash": "hash_test",
                        "reason": "manual review",
                        "evaluation": {
                            "decision": "require_approval",
                            "severity": "elevated",
                            "reason": "manual review",
                        },
                    }
                ),
            }

        client = Beav3r(
            base_url="http://beav3r.test",
            agent_id="agent_test",
            api_key="bvr_test_key",
            transport=transport,
        )

        result = client.guard(
            {
                "actionType": "transfer",
                "payload": {"amount": 22},
                "attributes": {"amount": 22},
                "actionId": "act_test",
                "timestamp": 1_700_000_001,
                "nonce": "nonce_test",
                "expiry": 4_100_000_000,
            }
        )

        self.assertEqual(result["status"], "pending")
        self.assertEqual(seen["method"], "POST")
        self.assertEqual(seen["url"], "http://beav3r.test/actions/request")
        self.assertEqual(seen["headers"]["authorization"], "Bearer bvr_test_key")
        self.assertEqual(seen["body"]["agentId"], "agent_test")
        self.assertEqual(seen["body"]["actionType"], "transfer")

    def test_relay_action_posts_reason(self) -> None:
        seen: dict[str, object] = {}

        def transport(url: str, method: str, headers: dict[str, str], body: bytes | None):
            seen["url"] = url
            seen["method"] = method
            seen["headers"] = headers
            seen["body"] = json.loads((body or b"{}").decode("utf-8"))
            return {
                "status": 200,
                "headers": {},
                "text": json.dumps({"status": "pending", "actionId": "act_relay"}),
            }

        client = Beav3r(
            base_url="http://beav3r.test",
            api_key="bvr_test_key",
            transport=transport,
        )

        result = client.relay_action(
            {
                "actionType": "transfer",
                "payload": {"amount": 22},
                "attributes": {"amount": 22},
                "reason": "manual review",
            }
        )

        self.assertEqual(result["status"], "pending")
        self.assertEqual(seen["method"], "POST")
        self.assertEqual(seen["url"], "http://beav3r.test/actions/relay")
        self.assertEqual(seen["headers"]["authorization"], "Bearer bvr_test_key")
        self.assertEqual(seen["body"]["reason"], "manual review")
        self.assertEqual(seen["body"]["action"]["actionType"], "transfer")

    def test_relay_action_requires_reason(self) -> None:
        client = Beav3r(base_url="http://beav3r.test", transport=lambda *args: {})

        with self.assertRaisesRegex(ValueError, "reason is required"):
            client.relay_action(
                {
                    "actionType": "transfer",
                    "payload": {"amount": 22},
                    "attributes": {"amount": 22},
                }
            )

    def test_guard_or_throw_raises_on_denied(self) -> None:
        def transport(url: str, method: str, headers: dict[str, str], body: bytes | None):
            return {
                "status": 200,
                "headers": {},
                "text": json.dumps(
                    {
                        "status": "denied",
                        "actionId": "act_denied",
                        "reason": "blocked",
                        "evaluation": {
                            "decision": "deny",
                            "severity": "critical",
                            "reason": "blocked",
                        },
                    }
                ),
            }

        client = Beav3r(base_url="http://beav3r.test", transport=transport)
        with self.assertRaises(Beav3rDeniedError):
            client.guard_or_throw(
                {
                    "actionType": "unknown_critical",
                    "payload": {"target": "prod"},
                    "attributes": {"target": "prod"},
                }
            )

    def test_alias_exports_match_primary_classes(self) -> None:
        self.assertIs(BeaverClient, Beav3r)
        self.assertIs(BeaverDeniedError, Beav3rDeniedError)

    def test_denied_error_matches_ts_shape(self) -> None:
        error = Beav3rDeniedError("act_denied", "blocked")
        self.assertEqual(error.action_id, "act_denied")
        self.assertEqual(error.actionId, "act_denied")
        self.assertEqual(error.name, "Beav3rDeniedError")
        self.assertEqual(str(error), "blocked")

    def test_guard_and_wait_returns_terminal_status(self) -> None:
        calls: list[str] = []

        def transport(url: str, method: str, headers: dict[str, str], body: bytes | None):
            calls.append(url)
            if url.endswith("/actions/request"):
                return {
                    "status": 200,
                    "headers": {},
                    "text": json.dumps(
                        {
                            "status": "pending",
                            "actionId": "act_wait",
                            "actionHash": "hash_wait",
                            "reason": "manual review",
                            "evaluation": {
                                "decision": "require_approval",
                                "severity": "elevated",
                                "reason": "manual review",
                            },
                        }
                    ),
                }
            return {
                "status": 200,
                "headers": {},
                "text": json.dumps({"status": "approved", "actionId": "act_wait"}),
            }

        client = Beav3r(base_url="http://beav3r.test", transport=transport)
        result = client.guard_and_wait(
            {"actionType": "transfer", "payload": {"amount": 1}, "attributes": {"amount": 1}},
            poll_interval_ms=1,
            timeout_ms=50,
        )

        self.assertEqual(result["status"], "approved")
        self.assertEqual(result["actionId"], "act_wait")
        self.assertEqual(result["actionHash"], "hash_wait")
        self.assertGreaterEqual(len(calls), 2)

    def test_guard_and_wait_times_out_as_pending(self) -> None:
        def transport(url: str, method: str, headers: dict[str, str], body: bytes | None):
            if url.endswith("/actions/request"):
                return {
                    "status": 200,
                    "headers": {},
                    "text": json.dumps(
                        {
                            "status": "pending",
                            "actionId": "act_timeout",
                            "actionHash": "hash_timeout",
                            "reason": "manual review",
                            "evaluation": {
                                "decision": "require_approval",
                                "severity": "elevated",
                                "reason": "manual review",
                            },
                        }
                    ),
                }
            return {
                "status": 200,
                "headers": {},
                "text": json.dumps({"status": "pending", "actionId": "act_timeout"}),
            }

        client = Beav3r(base_url="http://beav3r.test", transport=transport)
        result = client.guard_and_wait(
            {"actionType": "transfer", "payload": {"amount": 1}, "attributes": {"amount": 1}},
            poll_interval_ms=1,
            timeout_ms=5,
        )

        self.assertEqual(result["status"], "pending")
        self.assertEqual(result["actionId"], "act_timeout")
        self.assertEqual(result["actionHash"], "hash_timeout")
        self.assertIn("pendingForMs", result)

    def test_get_action_status_with_action_hash_uses_query(self) -> None:
        seen: dict[str, object] = {}

        def transport(url: str, method: str, headers: dict[str, str], body: bytes | None):
            seen["url"] = url
            return {
                "status": 200,
                "headers": {},
                "text": json.dumps({"status": "pending", "actionId": "act_hash"}),
            }

        client = Beav3r(base_url="http://beav3r.test", transport=transport)
        result = client.get_action_status("act_hash", {"actionHash": "hash_only"})

        self.assertEqual(result["actionId"], "act_hash")
        self.assertEqual(
            seen["url"],
            "http://beav3r.test/actions/act_hash/status?actionHash=hash_only",
        )

    def test_get_action_status_with_signed_query_uses_client_device_credentials(self) -> None:
        seen: dict[str, object] = {}
        original_sign = Beav3r._sign_utf8_message
        original_uuid = Beav3r.__dict__["_create_uuid"]
        original_time = time.time
        try:
            Beav3r._sign_utf8_message = lambda self, message, key: "signed-status"
            Beav3r._create_uuid = staticmethod(lambda: "nonce-123")
            time.time = lambda: 1700000000

            def transport(url: str, method: str, headers: dict[str, str], body: bytes | None):
                seen["url"] = url
                return {
                    "status": 200,
                    "headers": {},
                    "text": json.dumps({"status": "pending", "actionId": "act_signed"}),
                }

            client = Beav3r(
                base_url="http://beav3r.test",
                device_id="device_123",
                secret_key_base64="secret_base64",
                transport=transport,
            )
            client.get_action_status("act_signed")
        finally:
            Beav3r._sign_utf8_message = original_sign
            Beav3r._create_uuid = original_uuid
            time.time = original_time

        self.assertEqual(
            seen["url"],
            "http://beav3r.test/actions/act_signed/status?deviceId=device_123&timestamp=1700000000&nonce=nonce-123&signature=signed-status",
        )

    def test_get_action_alias_uses_options_method(self) -> None:
        seen: dict[str, object] = {}

        def transport(url: str, method: str, headers: dict[str, str], body: bytes | None):
            seen["url"] = url
            return {
                "status": 200,
                "headers": {},
                "text": json.dumps({"actionId": "act_details", "status": "pending"}),
            }

        client = Beav3r(base_url="http://beav3r.test", transport=transport)
        result = client.get_action_with_options("act_details", {"actionHash": "hash_details"})

        self.assertEqual(result["actionId"], "act_details")
        self.assertEqual(
            seen["url"],
            "http://beav3r.test/actions/act_details?actionHash=hash_details",
        )

    def test_list_methods_include_signed_query_and_filters(self) -> None:
        seen: list[str] = []
        original_sign = Beav3r._sign_utf8_message
        original_uuid = Beav3r.__dict__["_create_uuid"]
        original_time = time.time
        try:
            Beav3r._sign_utf8_message = lambda self, message, key: "signed-list"
            Beav3r._create_uuid = staticmethod(lambda: "nonce-list")
            time.time = lambda: 1700001111

            def transport(url: str, method: str, headers: dict[str, str], body: bytes | None):
                seen.append(url)
                return {"status": 200, "headers": {}, "text": json.dumps({"items": []})}

            client = Beav3r(
                base_url="http://beav3r.test",
                device_id="device_999",
                secret_key_base64="secret_base64",
                transport=transport,
            )
            client.list_pending_actions({"projectId": "proj_1"})
            client.list_recent_actions({"projectId": "proj_2"})
            client.list_policy_rules({"agentId": "agent_x"})
        finally:
            Beav3r._sign_utf8_message = original_sign
            Beav3r._create_uuid = original_uuid
            time.time = original_time

        self.assertIn(
            "http://beav3r.test/actions/pending?projectId=proj_1&deviceId=device_999&timestamp=1700001111&nonce=nonce-list&signature=signed-list",
            seen,
        )
        self.assertIn(
            "http://beav3r.test/actions/recent?projectId=proj_2&deviceId=device_999&timestamp=1700001111&nonce=nonce-list&signature=signed-list",
            seen,
        )
        self.assertIn(
            "http://beav3r.test/policy-rules?agentId=agent_x&deviceId=device_999&timestamp=1700001111&nonce=nonce-list&signature=signed-list",
            seen,
        )

    def test_register_device_challenge_flow(self) -> None:
        requests: list[tuple[str, str, dict[str, object]]] = []
        original_sign = Beav3r._sign_utf8_message
        try:
            Beav3r._sign_utf8_message = lambda self, message, key: "challenge-signature"

            def transport(url: str, method: str, headers: dict[str, str], body: bytes | None):
                payload = json.loads((body or b"{}").decode("utf-8"))
                requests.append((url, method, payload))
                if url.endswith("/devices/register/challenge"):
                    return {
                        "status": 200,
                        "headers": {},
                        "text": json.dumps({"challengeId": "challenge_1", "challenge": "sign-me"}),
                    }
                return {
                    "status": 200,
                    "headers": {},
                    "text": json.dumps({"status": "registered"}),
                }

            client = Beav3r(base_url="http://beav3r.test", transport=transport)
            result = client.register_device(
                {
                    "deviceId": "device_1",
                    "publicKey": "pub_1",
                    "label": "Pixel",
                    "pairingToken": "pairing_1",
                    "secretKeyBase64": "secret_key",
                }
            )
        finally:
            Beav3r._sign_utf8_message = original_sign

        self.assertEqual(result["status"], "registered")
        self.assertEqual(requests[0][0], "http://beav3r.test/devices/register/challenge")
        self.assertEqual(requests[0][2]["installationId"], "device_1")
        self.assertEqual(requests[1][0], "http://beav3r.test/devices/register")
        self.assertEqual(requests[1][2]["challengeSignature"], "challenge-signature")

    def test_submit_approval_posts_token(self) -> None:
        seen: dict[str, object] = {}

        def transport(url: str, method: str, headers: dict[str, str], body: bytes | None):
            seen["url"] = url
            seen["method"] = method
            seen["body"] = json.loads((body or b"{}").decode("utf-8"))
            return {
                "status": 200,
                "headers": {},
                "text": json.dumps({"status": "approved", "actionId": "act_approve"}),
            }

        client = Beav3r(base_url="http://beav3r.test", transport=transport)
        result = client.submit_approval({"actionHash": "hash_approve", "deviceId": "device_1"})

        self.assertEqual(result["status"], "approved")
        self.assertEqual(seen["url"], "http://beav3r.test/approvals/submit")
        self.assertEqual(seen["method"], "POST")
        self.assertEqual(seen["body"]["actionHash"], "hash_approve")

    def test_reject_approval_preserves_explicit_signature_payload(self) -> None:
        seen: dict[str, object] = {}

        def transport(url: str, method: str, headers: dict[str, str], body: bytes | None):
            seen["body"] = json.loads((body or b"{}").decode("utf-8"))
            return {
                "status": 200,
                "headers": {},
                "text": json.dumps({"status": "rejected", "actionId": "act_reject"}),
            }

        client = Beav3r(base_url="http://beav3r.test", transport=transport)
        result = client.reject_approval(
            {
                "actionHash": "hash_reject",
                "deviceId": "device_2",
                "signature": "sig_1",
                "expiry": 1700001000,
                "reason": "operator rejected",
            }
        )

        self.assertEqual(result["status"], "rejected")
        self.assertEqual(seen["body"]["reason"], "operator rejected")
        self.assertEqual(seen["body"]["signature"], "sig_1")
        self.assertEqual(seen["body"]["expiry"], 1700001000)

    def test_reject_approval_signs_when_device_credentials_present(self) -> None:
        seen: dict[str, object] = {}
        original_sign = Beav3r._sign_utf8_message
        original_time = time.time
        try:
            Beav3r._sign_utf8_message = lambda self, message, key: "reject-signature"
            time.time = lambda: 1700000100

            def transport(url: str, method: str, headers: dict[str, str], body: bytes | None):
                seen["body"] = json.loads((body or b"{}").decode("utf-8"))
                return {
                    "status": 200,
                    "headers": {},
                    "text": json.dumps({"status": "rejected", "actionId": "act_reject_auto"}),
                }

            client = Beav3r(
                base_url="http://beav3r.test",
                device_id="device_auto",
                secret_key_base64="secret_base64",
                default_expiry_seconds=60,
                transport=transport,
            )
            client.reject_approval({"actionHash": "hash_auto", "reason": "manual rejection"})
        finally:
            Beav3r._sign_utf8_message = original_sign
            time.time = original_time

        self.assertEqual(seen["body"]["deviceId"], "device_auto")
        self.assertEqual(seen["body"]["signature"], "reject-signature")
        self.assertEqual(seen["body"]["expiry"], 1700000160)
        self.assertEqual(seen["body"]["reason"], "manual rejection")

    def test_transport_http_error_propagates_server_message(self) -> None:
        def transport(url: str, method: str, headers: dict[str, str], body: bytes | None):
            return {
                "status": 404,
                "headers": {},
                "text": json.dumps({"error": "Project not found"}),
            }

        client = Beav3r(base_url="http://beav3r.test", transport=transport)
        with self.assertRaisesRegex(RuntimeError, "Project not found"):
            client.list_pending_actions()

    def test_transport_invalid_json_raises_clear_error(self) -> None:
        def transport(url: str, method: str, headers: dict[str, str], body: bytes | None):
            return {"status": 200, "headers": {}, "text": "{not-json"}

        client = Beav3r(base_url="http://beav3r.test", transport=transport)
        with self.assertRaisesRegex(RuntimeError, "Received invalid JSON from Beav3r"):
            client.list_recent_actions()

    def test_transport_network_error_uses_reachability_message(self) -> None:
        def transport(url: str, method: str, headers: dict[str, str], body: bytes | None):
            raise OSError("connection refused")

        client = Beav3r(base_url="http://beav3r.test", transport=transport)
        with self.assertRaisesRegex(RuntimeError, "Cannot reach Beav3r at http://beav3r.test"):
            client.list_policy_rules()


if __name__ == "__main__":
    unittest.main()
