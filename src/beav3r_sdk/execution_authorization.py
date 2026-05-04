from __future__ import annotations

import base64
import binascii
import hashlib
import json
import time
from typing import Any, Mapping, Sequence

JSON = dict[str, Any]


def canonicalize(value: Any) -> str:
    return json.dumps(_sort_value(value), separators=(",", ":"))


def hash_action(action: Mapping[str, Any]) -> str:
    canonical_payload = canonicalize(action.get("payload"))
    canonical_attributes = canonicalize(action.get("attributes"))
    text = "".join(
        [
            str(action["actionId"]),
            str(action["agentId"]),
            str(action["actionType"]),
            canonical_payload,
            canonical_attributes,
            str(action["timestamp"]),
            str(action["nonce"]),
            str(action["expiry"]),
        ]
    )
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_execution_authorization_action(action: Mapping[str, Any]) -> JSON:
    payload = action.get("payload")
    normalized_payload = dict(payload) if isinstance(payload, Mapping) else payload
    if isinstance(normalized_payload, dict):
        normalized_payload.pop("presentation", None)

    normalized = dict(action)
    normalized["payload"] = normalized_payload
    return normalized


def verify_execution_authorization(input: Mapping[str, Any]) -> JSON:
    artifact = _require_mapping(input.get("artifact"), "artifact")
    payload = _require_mapping(artifact.get("payload"), "artifact.payload")
    action = _require_mapping(input.get("action"), "action")
    audience = str(input.get("audience") or "").strip()
    if not audience:
        raise ValueError("Execution authorization audience is required")

    algorithm = _normalize_optional_string(artifact.get("algorithm"))
    if algorithm and algorithm != "ed25519":
        raise ValueError(
            f'Execution authorization signature algorithm "{algorithm}" is not supported; expected "ed25519"'
        )

    key_id = _resolve_key_id(payload, artifact)
    if not key_id:
        raise ValueError(
            "Execution authorization keyId is missing from artifact payload and envelope"
        )

    public_key = _resolve_public_key(input.get("publicKeys"), key_id)
    if not public_key:
        raise ValueError(f'Execution authorization keyId "{key_id}" is not trusted')

    if not _verify_artifact_signature(payload, artifact, public_key):
        raise ValueError("Execution authorization signature is invalid")

    now = _resolve_now(input.get("now"))
    expires_at = _to_int(payload.get("expiresAt"), "artifact.payload.expiresAt")
    if expires_at < now:
        raise ValueError("Execution authorization artifact is expired")

    payload_audience = str(payload.get("audience") or "")
    if payload_audience != audience:
        raise ValueError(
            f'Execution authorization audience mismatch: expected "{audience}", got "{payload_audience}"'
        )

    decision = str(payload.get("decision") or "")
    if decision not in {"allow", "approved", "executed"}:
        raise ValueError(
            f'Execution authorization decision must be "allow", "approved", or "executed", got "{decision}"'
        )

    expected_action_hash = hash_action(normalize_execution_authorization_action(action))
    payload_action_hash = str(payload.get("actionHash") or "")
    if payload_action_hash != expected_action_hash:
        raise ValueError(
            "Execution authorization actionHash does not match the provided action input"
        )

    used_artifact_ids = input.get("usedArtifactIds")
    if used_artifact_ids is not None:
        artifact_id = str(payload.get("artifactId") or "").strip()
        if not artifact_id:
            raise ValueError("Execution authorization artifactId is missing")
        if artifact_id in used_artifact_ids:
            raise ValueError(
                f'Execution authorization artifactId "{artifact_id}" has already been used'
            )
        _mark_artifact_id_used(used_artifact_ids, artifact_id)

    return dict(payload)


def is_valid_execution_authorization(input: Mapping[str, Any]) -> bool:
    try:
        verify_execution_authorization(input)
        return True
    except Exception:
        return False


def _sort_value(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, list):
        return [_sort_value(item) for item in value]
    if isinstance(value, tuple):
        return [_sort_value(item) for item in value]
    if isinstance(value, dict):
        sorted_items = sorted(
            ((str(key), nested) for key, nested in value.items()),
            key=lambda item: item[0],
        )
        return {key: _sort_value(nested) for key, nested in sorted_items}
    if isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _resolve_key_id(payload: Mapping[str, Any], artifact: Mapping[str, Any]) -> str | None:
    payload_key_id = _normalize_optional_string(payload.get("keyId"))
    if payload_key_id:
        return payload_key_id
    return _normalize_optional_string(artifact.get("keyId"))


def _resolve_public_key(raw_key_set: Any, key_id: str) -> str | None:
    if isinstance(raw_key_set, Mapping):
        candidate = raw_key_set.get(key_id)
        if candidate is None:
            return None
        resolved = _normalize_optional_string(candidate)
        return resolved
    if isinstance(raw_key_set, Sequence) and not isinstance(
        raw_key_set, (str, bytes, bytearray)
    ):
        for item in raw_key_set:
            if not isinstance(item, Mapping):
                continue
            if _normalize_optional_string(item.get("keyId")) != key_id:
                continue
            return _normalize_optional_string(item.get("publicKey"))
    return None


def _verify_artifact_signature(
    payload: Mapping[str, Any], artifact: Mapping[str, Any], public_key_base64: str
) -> bool:
    try:
        from nacl.signing import VerifyKey
    except ImportError as error:
        raise RuntimeError(
            "PyNaCl is required to verify execution authorization artifacts. "
            "Install it with: pip install PyNaCl"
        ) from error

    signature_value = _normalize_optional_string(artifact.get("signature"))
    if not signature_value:
        raise ValueError("Execution authorization signature is missing")

    try:
        signature = base64.b64decode(signature_value, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("Execution authorization signature is invalid")

    try:
        public_key_bytes = base64.b64decode(public_key_base64, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("Execution authorization trusted public key is invalid")

    canonical_payload = canonicalize(payload).encode("utf-8")
    try:
        VerifyKey(public_key_bytes).verify(canonical_payload, signature)
        return True
    except Exception:
        return False


def _resolve_now(now_value: Any) -> int:
    if now_value is None:
        return int(time.time())
    if isinstance(now_value, bool):
        raise ValueError("now must be an integer unix timestamp")
    if isinstance(now_value, int):
        return now_value
    if isinstance(now_value, float):
        return int(now_value)
    raise ValueError("now must be an integer unix timestamp")


def _to_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be an integer unix timestamp")
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip():
        try:
            return int(value)
        except ValueError:
            pass
    raise ValueError(f"{field_name} must be an integer unix timestamp")


def _require_mapping(value: Any, field_name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field_name} must be an object")
    return value


def _normalize_optional_string(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    trimmed = value.strip()
    return trimmed or None


def _mark_artifact_id_used(store: Any, artifact_id: str) -> None:
    add = getattr(store, "add", None)
    if callable(add):
        add(artifact_id)
        return
    raise ValueError("usedArtifactIds must support membership checks and add()")


verifyExecutionAuthorization = verify_execution_authorization
isValidExecutionAuthorization = is_valid_execution_authorization
