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
        audience: str | None = None,
        execution_auth_audience: str | None = None,
    ) -> JSON:
        started_at = time.time()
        resolved_audience = self._resolve_execution_auth_audience(
            audience=audience,
            execution_auth_audience=execution_auth_audience,
        )
        initial = self.guard(input)
        if initial["status"] in ("approved", "executed", "denied"):
            if initial["status"] in ("approved", "executed"):
                return self._attach_execution_authorization_if_needed(
                    initial, resolved_audience
                )
            return initial

        while (time.time() - started_at) * 1000 < timeout_ms:
            status = self.get_action_status(initial["actionId"])
            if status["status"] in ("approved", "executed"):
                approved = {
                    "status": status["status"],
                    "actionId": initial["actionId"],
                    "actionHash": initial["actionHash"],
                    "evaluation": initial["evaluation"],
                }
                return self._attach_execution_authorization_if_needed(
                    approved, resolved_audience
                )
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

    def mint_execution_authorization(self, input: JSON) -> JSON:
        action_id = str(input.get("actionId") or "").strip()
        audience = str(input.get("audience") or "").strip()
        if not action_id:
            raise ValueError(
                "mint_execution_authorization requires a non-empty actionId"
            )
        if not audience:
            raise ValueError(
                "mint_execution_authorization requires a non-empty audience"
            )
        return self._request(
            "POST",
            f"/actions/{urllib.parse.quote(action_id, safe='')}/execution-authorization",
            json={"audience": audience},
        )

    def redeem_execution_authorization(self, input: JSON) -> JSON:
        action_id = str(input.get("actionId") or "").strip()
        artifact = input.get("artifact")
        audience = str(input.get("audience") or "").strip()
        action_hash = str(input.get("actionHash") or "").strip()
        if not action_id:
            raise ValueError(
                "redeem_execution_authorization requires a non-empty actionId"
            )
        if not isinstance(artifact, Mapping):
            raise ValueError("redeem_execution_authorization requires an artifact")
        if not audience:
            raise ValueError(
                "redeem_execution_authorization requires a non-empty audience"
            )
        if not action_hash:
            raise ValueError(
                "redeem_execution_authorization requires a non-empty actionHash"
            )
        return self._request(
            "POST",
            f"/actions/{urllib.parse.quote(action_id, safe='')}/execution-authorization/redeem",
            json={
                "artifact": artifact,
                "audience": audience,
                "actionHash": action_hash,
            },
        )

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

    def guard_and_exit(self, input: JSON) -> JSON:
        return self.guard(input)

    def get_execution_authorization_keys(self) -> JSON:
        self._require_api_key("get_execution_authorization_keys")
        return self._request("GET", "/.well-known/execution-authorization-keys")

    def get_exact_action_request(self, action_id: str, options: JSON | None = None) -> JSON:
        action = self.get_action(action_id, options)
        return {
            "actionId": action["actionId"],
            "agentId": action["agentId"],
            "actionType": action["actionType"],
            "payload": {**(action.get("payload") or {})},
            "attributes": action.get("attributes") or {},
            "timestamp": action["timestamp"],
            "nonce": action["nonce"],
            "expiry": action["expiry"],
        }

    def authorize_and_execute(self, input: JSON) -> JSON:
        self._require_api_key("authorize_and_execute")
        action = input.get("action")
        artifact = input.get("artifact")
        audience = str(input.get("audience") or "").strip()
        public_keys = input.get("publicKeys")
        execute = input.get("execute")

        if not isinstance(action, Mapping):
            raise ValueError("authorize_and_execute requires an exact action object")
        if not isinstance(artifact, Mapping):
            raise ValueError("authorize_and_execute requires a structured artifact object")
        if not audience:
            raise ValueError("authorize_and_execute requires a non-empty audience")
        if public_keys is None:
            raise ValueError("authorize_and_execute requires trusted public keys")
        if not callable(execute):
            raise ValueError("authorize_and_execute requires an execute callable")

        from .execution_authorization import verify_execution_authorization

        authorization = verify_execution_authorization({
            "artifact": artifact,
            "action": action,
            "audience": audience,
            "publicKeys": public_keys,
            "now": input.get("now"),
        })
        redemption = self.redeem_execution_authorization({
            "actionId": authorization["actionId"],
            "artifact": artifact,
            "audience": audience,
            "actionHash": authorization["actionHash"],
        })
        execution_result = execute({
            "action": action,
            "actionHash": authorization["actionHash"],
            "artifact": artifact,
            "authorization": authorization,
            "redemption": redemption,
        })
        return {
            "actionId": authorization["actionId"],
            "actionHash": authorization["actionHash"],
            "artifactId": redemption["artifactId"],
            "authorization": authorization,
            "redemption": redemption,
            "executionResult": execution_result,
        }

    # --- Onchain methods ---

    def authorize_onchain_action(self, input: JSON) -> JSON:
        self._require_api_key("authorize_onchain_action")
        account = str(input.get("account") or "").strip()
        to = str(input.get("to") or "").strip()
        value = str(input.get("value") or "").strip()
        data = str(input.get("data") or "").strip()
        executor = str(input.get("executor") or "").strip()
        if not account:
            raise ValueError("authorize_onchain_action requires a non-empty account")
        if not to:
            raise ValueError("authorize_onchain_action requires a non-empty to address")
        if not value:
            raise ValueError("authorize_onchain_action requires a non-empty value")
        if not data:
            raise ValueError("authorize_onchain_action requires non-empty calldata")
        if not executor:
            raise ValueError("authorize_onchain_action requires a non-empty executor address")
        chain_id = _parse_uint_like(input.get("chainId"), "authorize_onchain_action chainId")
        if chain_id <= 0:
            raise ValueError("authorize_onchain_action requires chainId > 0")
        nonce = _parse_uint_like(input.get("nonce"), "authorize_onchain_action nonce")
        expires_at = _parse_uint_like(input.get("expiresAt") or 0, "authorize_onchain_action expiresAt")
        query = _build_query_string({"projectId": str(input.get("projectId") or "").strip() or None,
                                     "actorId": str(input.get("actorId") or "").strip() or None})
        return self._request(
            "POST",
            f"/onchain/actions/authorize{query}",
            json={
                "account": account,
                "to": to,
                "value": value,
                "data": data,
                "chainId": _to_safe_json_uint(chain_id, "authorize_onchain_action chainId"),
                "nonce": _to_safe_json_uint(nonce, "authorize_onchain_action nonce"),
                "expiresAt": _to_safe_json_uint(expires_at, "authorize_onchain_action expiresAt"),
                "executor": executor,
            },
        )

    def provision_onchain_user(self, input: JSON) -> JSON:
        self._require_api_key("provision_onchain_user")
        chain_id = input.get("chainId")
        if not isinstance(chain_id, int) or chain_id <= 0:
            raise ValueError("provision_onchain_user requires chainId > 0")
        intended_owner = str(input.get("intendedOwner") or "").strip()
        if not intended_owner:
            raise ValueError("provision_onchain_user requires a non-empty intendedOwner")
        template_id = str(input.get("templateId") or "").strip() if input.get("templateId") is not None else None
        if input.get("templateId") is not None and not template_id:
            raise ValueError("provision_onchain_user templateId must be non-empty when provided")
        metadata = input.get("metadata")
        if metadata is not None and (metadata is None or isinstance(metadata, list)):
            raise ValueError("provision_onchain_user metadata must be an object when provided")
        body: JSON = {"chainId": chain_id, "intendedOwner": intended_owner}
        if template_id:
            body["templateId"] = template_id
        if metadata is not None:
            body["metadata"] = metadata
        return self._request("POST", "/v1/onchain/users/provision", json=body)

    def get_onchain_authorization(self, authorization_id: str, options: JSON | None = None) -> JSON:
        self._require_api_key("get_onchain_authorization")
        trimmed = authorization_id.strip()
        if not trimmed:
            raise ValueError("get_onchain_authorization requires a non-empty authorizationId")
        project_id = str((options or {}).get("projectId") or "").strip() or None
        query = _build_query_string({"projectId": project_id})
        return self._request("GET", f"/onchain/actions/{urllib.parse.quote(trimmed, safe='')}{query}")

    def upsert_onchain_account_key(self, input: JSON) -> JSON:
        self._require_api_key("upsert_onchain_account_key")
        account = str(input.get("account") or "").strip()
        signer_address = str(input.get("signerAddress") or "").strip()
        key_id = str(input.get("keyId") or "").strip() or None
        if not account:
            raise ValueError("upsert_onchain_account_key requires a non-empty account")
        if not signer_address:
            raise ValueError("upsert_onchain_account_key requires a non-empty signerAddress")
        return self._request(
            "POST",
            f"/onchain/accounts/{urllib.parse.quote(account, safe='')}/keys",
            json={"keyId": key_id, "signerAddress": signer_address},
        )

    def list_onchain_account_keys(self, account: str) -> JSON:
        self._require_api_key("list_onchain_account_keys")
        trimmed = account.strip()
        if not trimmed:
            raise ValueError("list_onchain_account_keys requires a non-empty account")
        return self._request("GET", f"/onchain/accounts/{urllib.parse.quote(trimmed, safe='')}/keys")

    def delete_onchain_account_key(self, account: str, key_id: str) -> JSON:
        self._require_api_key("delete_onchain_account_key")
        trimmed_account = account.strip()
        trimmed_key_id = key_id.strip()
        if not trimmed_account:
            raise ValueError("delete_onchain_account_key requires a non-empty account")
        if not trimmed_key_id:
            raise ValueError("delete_onchain_account_key requires a non-empty keyId")
        return self._request(
            "DELETE",
            f"/onchain/accounts/{urllib.parse.quote(trimmed_account, safe='')}/keys/{urllib.parse.quote(trimmed_key_id, safe='')}",
        )

    def list_onchain_actors(self, project_id: str) -> JSON:
        self._require_api_key("list_onchain_actors")
        trimmed = project_id.strip()
        if not trimmed:
            raise ValueError("list_onchain_actors requires a non-empty projectId")
        return self._request("GET", f"/onchain/actors/{urllib.parse.quote(trimmed, safe='')}")

    def get_onchain_actor(self, project_id: str, actor_id: str) -> JSON:
        self._require_api_key("get_onchain_actor")
        trimmed_project = project_id.strip()
        trimmed_actor = actor_id.strip()
        if not trimmed_project:
            raise ValueError("get_onchain_actor requires a non-empty projectId")
        if not trimmed_actor:
            raise ValueError("get_onchain_actor requires a non-empty actorId")
        return self._request(
            "GET",
            f"/onchain/actors/{urllib.parse.quote(trimmed_project, safe='')}/{urllib.parse.quote(trimmed_actor, safe='')}",
        )

    def create_onchain_actor(self, input: JSON) -> JSON:
        self._require_api_key("create_onchain_actor")
        project_id, body = _normalize_onchain_actor_input("create_onchain_actor", input)
        return self._request(
            "POST",
            f"/onchain/actors/{urllib.parse.quote(project_id, safe='')}",
            json=body,
        )

    def update_onchain_actor(self, input: JSON) -> JSON:
        self._require_api_key("update_onchain_actor")
        actor_id = str(input.get("actorId") or "").strip()
        if not actor_id:
            raise ValueError("update_onchain_actor requires a non-empty actorId")
        project_id, body = _normalize_onchain_actor_input("update_onchain_actor", input)
        return self._request(
            "PUT",
            f"/onchain/actors/{urllib.parse.quote(project_id, safe='')}/{urllib.parse.quote(actor_id, safe='')}",
            json=body,
        )

    def delete_onchain_actor(self, project_id: str, actor_id: str) -> JSON:
        self._require_api_key("delete_onchain_actor")
        trimmed_project = project_id.strip()
        trimmed_actor = actor_id.strip()
        if not trimmed_project:
            raise ValueError("delete_onchain_actor requires a non-empty projectId")
        if not trimmed_actor:
            raise ValueError("delete_onchain_actor requires a non-empty actorId")
        return self._request(
            "DELETE",
            f"/onchain/actors/{urllib.parse.quote(trimmed_project, safe='')}/{urllib.parse.quote(trimmed_actor, safe='')}",
        )

    def register_onchain_actor(self, actor: JSON, options: JSON | None = None) -> JSON:
        created = self.create_onchain_actor(actor)
        signer_address = str((options or {}).get("signerAddress") or "").strip()
        if not signer_address:
            return {"actor": created["item"]}
        key = self.upsert_onchain_account_key({
            "account": created["item"]["accountAddress"],
            "keyId": (options or {}).get("keyId"),
            "signerAddress": signer_address,
        })
        return {"actor": created["item"], "key": key["item"]}

    def _require_api_key(self, method_name: str) -> None:
        if self.api_key and str(self.api_key).strip():
            return
        raise ValueError(
            f"Beav3r API key is required for {method_name}. Configure api_key when creating the client."
        )

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

    @staticmethod
    def _resolve_execution_auth_audience(
        *, audience: str | None, execution_auth_audience: str | None
    ) -> str | None:
        if execution_auth_audience is not None:
            trimmed = execution_auth_audience.strip()
            return trimmed or None
        if audience is not None:
            trimmed = audience.strip()
            return trimmed or None
        return None

    def _attach_execution_authorization_if_needed(
        self, result: JSON, audience: str | None
    ) -> JSON:
        if not audience:
            return result

        artifact = self.mint_execution_authorization(
            {"actionId": result["actionId"], "audience": audience}
        )
        merged = dict(result)
        merged["executionAuthorizationArtifact"] = artifact
        return merged

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


def _parse_uint_like(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a non-negative integer")
    if isinstance(value, int):
        if value < 0:
            raise ValueError(f"{field} must be >= 0")
        return value
    if isinstance(value, float):
        if not value.is_integer() or value < 0:
            raise ValueError(f"{field} must be a non-negative integer")
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        if not text.isdigit():
            raise ValueError(f"{field} must be a base-10 unsigned integer string")
        return int(text)
    raise ValueError(f"{field} must be a non-negative integer")


def _to_safe_json_uint(value: int, field: str) -> int:
    _MAX_SAFE = (1 << 53) - 1
    if value > _MAX_SAFE:
        raise ValueError(f"{field} exceeds Number.MAX_SAFE_INTEGER and cannot be encoded in JSON safely")
    return value


def _build_query_string(params: dict[str, str | None]) -> str:
    filtered = {k: v for k, v in params.items() if v}
    if not filtered:
        return ""
    return "?" + urllib.parse.urlencode(filtered)


def _normalize_onchain_actor_input(method_name: str, input: JSON) -> tuple[str, JSON]:
    project_id = str(input.get("projectId") or "").strip()
    actor_type = str(input.get("type") or "").strip()
    label = str(input.get("label") or "").strip()
    account_address = str(input.get("accountAddress") or "").strip()
    executor_address = str(input.get("executorAddress") or "").strip()
    metadata_json = str(input.get("metadataJson") or "").strip() or "{}"
    chain_id = input.get("chainId")

    if not project_id:
        raise ValueError(f"{method_name} requires a non-empty projectId")
    if actor_type not in ("wallet", "smart_account"):
        raise ValueError(f'{method_name} requires type "wallet" or "smart_account"')
    if not label:
        raise ValueError(f"{method_name} requires a non-empty label")
    if not isinstance(chain_id, int) or isinstance(chain_id, bool) or chain_id <= 0:
        raise ValueError(f"{method_name} requires chainId > 0")
    if not account_address:
        raise ValueError(f"{method_name} requires a non-empty accountAddress")
    if not executor_address:
        raise ValueError(f"{method_name} requires a non-empty executorAddress")

    body: JSON = {
        "type": actor_type,
        "label": label,
        "chainId": chain_id,
        "accountAddress": account_address,
        "executorAddress": executor_address,
        "metadataJson": metadata_json,
    }
    return project_id, body


def json_module_dumps(value: JSON) -> str:
    return jsonlib.dumps(value, separators=(",", ":"))


def json_module_loads(value: str) -> JSON:
    return jsonlib.loads(value)
