from __future__ import annotations

import base64
import json as jsonlib
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Callable, Mapping, Optional


JSON = dict[str, Any]
TransportResponse = dict[str, Any]
Transport = Callable[[str, str, Mapping[str, str], Optional[bytes]], TransportResponse]


class Beav3rDeniedError(Exception):
    def __init__(self, action_id: str, reason: str | None = None) -> None:
        super().__init__(reason or f"Action {action_id} was denied by Beav3r")
        self.action_id = action_id
        self.actionId = action_id
        self.name = "Beav3rDeniedError"


class Beav3r:
    def __init__(
        self,
        *,
        base_url: str,
        agent_id: str | None = None,
        api_key: str | None = None,
        device_id: str | None = None,
        secret_key_base64: str | None = None,
        default_expiry_seconds: int = 60,
        timeout: float = 30.0,
        transport: Transport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.agent_id = agent_id
        self.api_key = api_key
        self.device_id = device_id
        self.secret_key_base64 = secret_key_base64
        self.default_expiry_seconds = default_expiry_seconds
        self.timeout = timeout
        self.transport = transport

    def request_action(self, input: JSON) -> JSON:
        action = self._build_action(input)
        return self._request("POST", "/actions/request", json=action)

    def relay_action(self, input: JSON) -> JSON:
        action = self._build_action(input)
        reason = str(input.get("reason") or "").strip()
        if not reason:
            raise ValueError("reason is required")
        return self._request(
            "POST",
            "/actions/relay",
            json={"action": action, "reason": reason},
        )

    def guard(self, input: JSON) -> JSON:
        return self.request_action(input)

    def guard_and_wait(
        self,
        input: JSON,
        *,
        poll_interval_ms: int = 3000,
        timeout_ms: int = 5 * 60 * 1000,
    ) -> JSON:
        started_at = time.time()
        initial = self.guard(input)
        if initial["status"] in ("executed", "denied"):
            return initial

        while (time.time() - started_at) * 1000 < timeout_ms:
            status = self.get_action_status(initial["actionId"])
            if status["status"] in ("approved", "executed"):
                return {
                    "status": status["status"],
                    "actionId": initial["actionId"],
                    "actionHash": initial["actionHash"],
                    "evaluation": initial["evaluation"],
                }
            if status["status"] in ("denied", "rejected", "expired"):
                return {
                    "status": status["status"],
                    "actionId": status["actionId"],
                    "reason": status.get("reason"),
                }
            time.sleep(poll_interval_ms / 1000)

        return {
            "status": "pending",
            "actionId": initial["actionId"],
            "actionHash": initial["actionHash"],
            "reason": initial.get("reason"),
            "pendingForMs": int((time.time() - started_at) * 1000),
        }

    def guard_or_throw(self, input: JSON) -> JSON:
        result = self.guard(input)
        if result["status"] == "denied":
            raise Beav3rDeniedError(result["actionId"], result.get("reason"))
        return result

    def get_action_status(self, action_id: str, options: JSON | None = None) -> JSON:
        query = self._build_action_read_query(f"action-status:{action_id}", options or {})
        return self._request(
            "GET",
            f"/actions/{urllib.parse.quote(action_id, safe='')}/status",
            params=query,
        )

    def get_action(self, action_id: str, options: JSON | None = None) -> JSON:
        query = self._build_action_read_query(f"action-read:{action_id}", options or {})
        return self._request(
            "GET",
            f"/actions/{urllib.parse.quote(action_id, safe='')}",
            params=query,
        )

    def get_action_status_with_options(self, action_id: str, options: JSON | None = None) -> JSON:
        return self.get_action_status(action_id, options)

    def get_action_with_options(self, action_id: str, options: JSON | None = None) -> JSON:
        return self.get_action(action_id, options)

    def list_pending_actions(self, options: JSON | None = None) -> JSON:
        options = options or {}
        query = {
            "projectId": options.get("projectId"),
            **self._build_signed_device_query(
                "actions-pending",
                options.get("deviceId"),
                options.get("secretKeyBase64"),
            ),
        }
        return self._request("GET", "/actions/pending", params=query)

    def list_recent_actions(self, options: JSON | None = None) -> JSON:
        options = options or {}
        query = {
            "projectId": options.get("projectId"),
            **self._build_signed_device_query(
                "actions-recent",
                options.get("deviceId"),
                options.get("secretKeyBase64"),
            ),
        }
        return self._request("GET", "/actions/recent", params=query)

    def list_policy_rules(self, options: JSON | None = None) -> JSON:
        options = options or {}
        query = {
            "agentId": options.get("agentId"),
            **self._build_signed_device_query(
                "policy-rules",
                options.get("deviceId"),
                options.get("secretKeyBase64"),
            ),
        }
        return self._request("GET", "/policy-rules", params=query)

    def register_device(self, device: JSON) -> JSON:
        secret_key_base64 = device.get("secretKeyBase64") or self.secret_key_base64
        pairing_token = device.get("pairingToken")
        installation_id = device.get("installationId") or device.get("deviceId")
        if not secret_key_base64:
            raise ValueError("register_device requires secretKeyBase64")
        if not pairing_token:
            raise ValueError("register_device requires pairingToken")
        if not installation_id:
            raise ValueError("register_device requires installationId or deviceId")

        challenge = self._request(
            "POST",
            "/devices/register/challenge",
            json={
                "deviceId": device["deviceId"],
                "publicKey": device["publicKey"],
                "pairingToken": pairing_token,
                "installationId": installation_id,
            },
        )
        challenge_signature = self._sign_utf8_message(
            challenge["challenge"], secret_key_base64
        )
        payload = {
            "deviceId": device["deviceId"],
            "publicKey": device["publicKey"],
            "label": device["label"],
            "challengeId": challenge["challengeId"],
            "challengeSignature": challenge_signature,
            "pairingToken": pairing_token,
            "installationId": installation_id,
        }
        return self._request("POST", "/devices/register", json=payload)

    def submit_approval(self, token: JSON) -> JSON:
        return self._request("POST", "/approvals/submit", json=token)

    def reject_approval(self, rejection: JSON) -> JSON:
        payload = self._complete_rejection(rejection)
        return self._request("POST", "/approvals/reject", json=payload)

    def _build_action(self, input: JSON) -> JSON:
        now = int(time.time())
        return {
            "actionId": input.get("actionId") or self._create_uuid(),
            "agentId": input.get("agentId") or self.agent_id or "agent_default",
            "actionType": input["actionType"],
            "payload": input["payload"],
            "attributes": input.get("attributes") or {},
            "timestamp": input.get("timestamp") or now,
            "nonce": input.get("nonce") or self._create_uuid(),
            "expiry": input.get("expiry") or now + self.default_expiry_seconds,
        }

    def _build_action_read_query(self, purpose: str, options: JSON) -> dict[str, str]:
        action_hash = options.get("actionHash")
        if action_hash:
            return {"actionHash": str(action_hash)}
        return self._build_signed_device_query(
            purpose,
            options.get("deviceId"),
            options.get("secretKeyBase64"),
        )

    def _build_signed_device_query(
        self,
        purpose: str,
        device_id: str | None,
        secret_key_base64: str | None,
    ) -> dict[str, str]:
        effective_device_id = device_id or self.device_id
        effective_secret_key = secret_key_base64 or self.secret_key_base64
        if not effective_device_id or not effective_secret_key:
            return {}
        timestamp = str(int(time.time()))
        nonce = self._create_uuid()
        signature = self._sign_utf8_message(
            f"{purpose}:{effective_device_id}:{timestamp}:{nonce}",
            effective_secret_key,
        )
        return {
            "deviceId": effective_device_id,
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": signature,
        }

    def _complete_rejection(self, rejection: JSON) -> JSON:
        if rejection.get("signature") and isinstance(rejection.get("expiry"), int):
            payload = dict(rejection)
            payload["actionHash"] = rejection["actionHash"]
            payload["deviceId"] = rejection["deviceId"]
            payload["signature"] = rejection["signature"]
            payload["expiry"] = rejection["expiry"]
            return payload

        effective_device_id = rejection.get("deviceId") or self.device_id
        effective_secret_key = self.secret_key_base64
        if not effective_device_id or not effective_secret_key:
            raise ValueError(
                "reject_approval requires signature/expiry or signer device credentials"
            )

        payload = dict(rejection)
        payload["actionHash"] = rejection["actionHash"]
        payload["deviceId"] = effective_device_id
        payload["signature"] = self._sign_utf8_message(
            rejection["actionHash"],
            effective_secret_key,
        )
        payload["expiry"] = int(time.time()) + self.default_expiry_seconds
        return payload

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: JSON | None = None,
        params: dict[str, str] | None = None,
    ) -> JSON:
        url = f"{self.base_url}{path}"
        headers = {"content-type": "application/json"}
        if self.api_key:
            headers["authorization"] = f"Bearer {self.api_key}"
        full_url = url
        filtered_params = {k: v for k, v in (params or {}).items() if v}
        if filtered_params:
            full_url = f"{url}?{urllib.parse.urlencode(filtered_params)}"

        body = None
        if json is not None:
            body = json_module_dumps(json).encode("utf-8")

        try:
            if self.transport is not None:
                response = self.transport(full_url, method, headers, body)
                status = int(response.get("status", 200))
                body_text = str(response.get("text", "") or "")
                if status >= 400:
                    parsed = json_module_loads(body_text) if body_text else {}
                    raise RuntimeError(
                        parsed.get("error") or f"Request to {url} failed with status {status}"
                    )
                return json_module_loads(body_text) if body_text else {}
            request = urllib.request.Request(
                url=full_url,
                method=method,
                headers=headers,
                data=body,
            )
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body_text = response.read().decode("utf-8")
                return json_module_loads(body_text) if body_text else {}
        except RuntimeError:
            raise
        except urllib.error.HTTPError as error:
            body_text = error.read().decode("utf-8")
            parsed = json_module_loads(body_text) if body_text else {}
            raise RuntimeError(
                parsed.get("error") or f"Request to {url} failed with status {error.code}"
            ) from error
        except urllib.error.URLError as error:
            raise RuntimeError(
                f"Cannot reach Beav3r at {self.base_url}. "
                "Make sure the server is running, bound to 0.0.0.0, and reachable from this machine. "
                f"Original error: {error}"
            ) from error
        except jsonlib.JSONDecodeError as error:
            raise RuntimeError(
                f"Received invalid JSON from Beav3r at {url}. "
                f"Original error: {error}"
            ) from error
        except Exception as error:
            raise RuntimeError(
                f"Cannot reach Beav3r at {self.base_url}. "
                "Make sure the server is running, bound to 0.0.0.0, and reachable from this machine. "
                f"Original error: {error}"
            ) from error

    def _sign_utf8_message(self, message: str, secret_key_base64: str) -> str:
        try:
            from nacl.signing import SigningKey
        except ImportError as error:
            raise RuntimeError(
                "PyNaCl is required for signer registration and signed device operations. "
                "Install it with: pip install PyNaCl"
            ) from error
        secret_key = base64.b64decode(secret_key_base64)
        signature = SigningKey(secret_key[:32]).sign(message.encode("utf-8")).signature
        return base64.b64encode(signature).decode("utf-8")

    @staticmethod
    def _create_uuid() -> str:
        return str(uuid.uuid4())


BeaverClient = Beav3r
BeaverDeniedError = Beav3rDeniedError


def json_module_dumps(value: JSON) -> str:
    return jsonlib.dumps(value, separators=(",", ":"))


def json_module_loads(value: str) -> JSON:
    return jsonlib.loads(value)
