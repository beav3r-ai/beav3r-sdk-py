from __future__ import annotations

from typing import Any, Mapping


def _keccak256(data: bytes) -> bytes:
    try:
        import sha3 as _sha3  # pysha3
        return _sha3.keccak_256(data).digest()
    except ImportError:
        pass
    try:
        from Crypto.Hash import keccak as _keccak  # pycryptodome
        k = _keccak.new(digest_bits=256)
        k.update(data)
        return k.digest()
    except ImportError:
        pass
    raise ImportError(
        "keccak256 requires pysha3 or pycryptodome. "
        'Install with: pip install "beav3r-sdk[onchain]"'
    )


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


def _normalize_non_empty_string(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError(f"{field} is required")
    return text


def _normalize_hex(value: Any, field: str) -> str:
    text = _normalize_non_empty_string(value, field).lower()
    if not text.startswith("0x") or not all(c in "0123456789abcdef" for c in text[2:]):
        raise ValueError(f"{field} must be a valid 0x-prefixed hex string")
    if (len(text) - 2) % 2 != 0:
        raise ValueError(f"{field} must contain an even number of hex characters")
    return text


def _normalize_bytes32(value: Any, field: str) -> str:
    text = _normalize_hex(value, field)
    if len(text) != 66:
        raise ValueError(f"{field} must be a 32-byte hex string")
    return text


def _normalize_address(value: Any, field: str) -> str:
    text = _normalize_hex(value, field)
    if len(text) != 42:
        raise ValueError(f"{field} must be a 20-byte address")
    return text


def _normalize_onchain_key_id(value: Any, field: str) -> str:
    return _normalize_non_empty_string(value, field)


def _hex_to_bytes(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str[2:])


def _utf8_bytes(value: str) -> bytes:
    return value.encode("utf-8")


def _hexlify(data: bytes) -> str:
    return "0x" + data.hex()


def _word_from_big_int(value: int) -> bytes:
    if value < 0:
        raise ValueError("_word_from_big_int value must be non-negative")
    if value > (1 << 256) - 1:
        raise ValueError("_word_from_big_int value exceeds uint256 range")
    return value.to_bytes(32, "big")


def _word_from_address(address: str) -> bytes:
    return _hex_to_bytes("0x" + _normalize_address(address, "address")[2:].zfill(64))


def _concat_bytes(*parts: bytes) -> bytes:
    return b"".join(parts)


def _normalize_bytes32_or_hash_key_id(key_id: str) -> bytes:
    import re
    if re.match(r"^0x[0-9a-f]{64}$", key_id, re.IGNORECASE):
        return _hex_to_bytes(key_id.lower())
    return _keccak256(_utf8_bytes(key_id))


def _encode_dynamic_bytes(value: bytes) -> bytes:
    length_word = _word_from_big_int(len(value))
    pad_length = (32 - len(value) % 32) % 32
    return length_word + value + bytes(pad_length)


def compute_onchain_action_hash(input: Mapping[str, Any]) -> str:
    account = _normalize_address(input.get("account"), "computeOnchainActionHash account")
    to = _normalize_address(input.get("to"), "computeOnchainActionHash to")
    executor = _normalize_address(input.get("executor"), "computeOnchainActionHash executor")
    value = _parse_uint_like(input.get("value"), "computeOnchainActionHash value")
    chain_id = _parse_uint_like(input.get("chainId"), "computeOnchainActionHash chainId")
    nonce = _parse_uint_like(input.get("nonce"), "computeOnchainActionHash nonce")
    expires_at_raw = input.get("expiresAt")
    expires_at = _parse_uint_like(0 if expires_at_raw is None else expires_at_raw, "computeOnchainActionHash expiresAt")
    data = _normalize_hex(input.get("data"), "computeOnchainActionHash data")

    result = _keccak256(
        _concat_bytes(
            _word_from_address(account),
            _word_from_address(to),
            _word_from_big_int(value),
            _keccak256(_hex_to_bytes(data)),
            _word_from_big_int(chain_id),
            _word_from_big_int(nonce),
            _word_from_big_int(expires_at),
            _word_from_address(executor),
        )
    )
    return _hexlify(result)


def compute_onchain_authorization_digest(artifact: Mapping[str, Any]) -> str:
    payload = artifact.get("payload") or {}
    action_hash = _normalize_bytes32(payload.get("actionHash"), "computeOnchainAuthorizationDigest actionHash")
    account = _normalize_address(payload.get("account"), "computeOnchainAuthorizationDigest account")
    executor = _normalize_address(payload.get("executor"), "computeOnchainAuthorizationDigest executor")
    chain_id = _parse_uint_like(payload.get("chainId"), "computeOnchainAuthorizationDigest chainId")
    nonce = _parse_uint_like(payload.get("nonce"), "computeOnchainAuthorizationDigest nonce")
    expires_at = _parse_uint_like(payload.get("expiresAt"), "computeOnchainAuthorizationDigest expiresAt")
    key_id = _normalize_onchain_key_id(payload.get("keyId"), "computeOnchainAuthorizationDigest keyId")

    domain_type_hash = _keccak256(_utf8_bytes("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"))
    auth_type_hash = _keccak256(_utf8_bytes("ExecutionAuthorization(bytes32 actionHash,address account,address executor,uint256 chainId,uint256 nonce,uint256 expiresAt,bytes32 keyId)"))
    domain_name_hash = _keccak256(_utf8_bytes("Beav3rExecutionAuthorization"))
    domain_version_hash = _keccak256(_utf8_bytes("1"))
    key_id_hash = _normalize_bytes32_or_hash_key_id(key_id)

    domain_separator = _keccak256(
        _concat_bytes(
            domain_type_hash,
            domain_name_hash,
            domain_version_hash,
            _word_from_big_int(chain_id),
            _word_from_address(executor),
        )
    )

    struct_hash = _keccak256(
        _concat_bytes(
            auth_type_hash,
            _hex_to_bytes(action_hash),
            _word_from_address(account),
            _word_from_address(executor),
            _word_from_big_int(chain_id),
            _word_from_big_int(nonce),
            _word_from_big_int(expires_at),
            key_id_hash,
        )
    )

    return _hexlify(_keccak256(_concat_bytes(bytes([0x19, 0x01]), domain_separator, struct_hash)))


def verify_onchain_authorization(input: Mapping[str, Any]) -> dict[str, str]:
    artifact = input.get("artifact") or {}
    request = input.get("request") or {}
    payload = (artifact.get("payload") or {})

    action_hash = compute_onchain_action_hash({
        **request,
        "expiresAt": payload.get("expiresAt"),
    })
    stored_action_hash = _normalize_bytes32(payload.get("actionHash"), "verifyOnchainAuthorization artifact.payload.actionHash")
    if stored_action_hash != action_hash:
        raise ValueError("Onchain authorization actionHash mismatch")

    digest = compute_onchain_authorization_digest(artifact)
    stored_digest = _normalize_bytes32(artifact.get("digest"), "verifyOnchainAuthorization artifact.digest")
    if stored_digest != digest:
        raise ValueError("Onchain authorization digest mismatch")

    return {"actionHash": action_hash, "digest": digest}


def prepare_execute_with_auth_call(request: Mapping[str, Any], artifact: Mapping[str, Any]) -> dict[str, Any]:
    payload = artifact.get("payload") or {}
    to = _normalize_address(request.get("to"), "prepareExecuteWithAuthCall to")
    value = _parse_uint_like(request.get("value"), "prepareExecuteWithAuthCall value")
    data = _normalize_hex(request.get("data"), "prepareExecuteWithAuthCall data")
    signature = _normalize_hex(artifact.get("signature"), "prepareExecuteWithAuthCall signature")
    action_hash = _normalize_bytes32(payload.get("actionHash"), "prepareExecuteWithAuthCall actionHash")
    account = _normalize_address(payload.get("account"), "prepareExecuteWithAuthCall account")
    executor = _normalize_address(payload.get("executor"), "prepareExecuteWithAuthCall executor")
    chain_id = _parse_uint_like(payload.get("chainId"), "prepareExecuteWithAuthCall chainId")
    nonce = _parse_uint_like(payload.get("nonce"), "prepareExecuteWithAuthCall nonce")
    expires_at = _parse_uint_like(payload.get("expiresAt"), "prepareExecuteWithAuthCall expiresAt")
    raw_key_id = _normalize_onchain_key_id(payload.get("keyId"), "prepareExecuteWithAuthCall keyId")
    key_id = _hexlify(_normalize_bytes32_or_hash_key_id(raw_key_id))

    return {
        "to": to,
        "value": value,
        "data": data,
        "auth": {
            "actionHash": action_hash,
            "account": account,
            "executor": executor,
            "chainId": chain_id,
            "nonce": nonce,
            "expiresAt": expires_at,
            "keyId": key_id,
        },
        "signature": signature,
    }


def encode_execute_with_auth_calldata(input: Mapping[str, Any]) -> str:
    auth = input.get("auth") or {}
    selector = _keccak256(
        _utf8_bytes("executeWithAuth(address,uint256,bytes,(bytes32,address,address,uint256,uint256,uint256,bytes32),bytes)")
    )[:4]

    data_bytes = _hex_to_bytes(_normalize_hex(input.get("data"), "encodeExecuteWithAuthCalldata data"))
    signature_bytes = _hex_to_bytes(_normalize_hex(input.get("signature"), "encodeExecuteWithAuthCalldata signature"))

    static_words = 11
    static_length = static_words * 32
    data_offset = static_length
    data_tail = _encode_dynamic_bytes(data_bytes)
    signature_offset = static_length + len(data_tail)
    signature_tail = _encode_dynamic_bytes(signature_bytes)

    args = _concat_bytes(
        _word_from_address(input["to"]),
        _word_from_big_int(int(input["value"])),
        _word_from_big_int(data_offset),
        _hex_to_bytes(_normalize_bytes32(auth.get("actionHash"), "encodeExecuteWithAuthCalldata auth.actionHash")),
        _word_from_address(auth.get("account")),
        _word_from_address(auth.get("executor")),
        _word_from_big_int(int(auth.get("chainId", 0))),
        _word_from_big_int(int(auth.get("nonce", 0))),
        _word_from_big_int(int(auth.get("expiresAt", 0))),
        _hex_to_bytes(_normalize_bytes32(auth.get("keyId"), "encodeExecuteWithAuthCalldata auth.keyId")),
        _word_from_big_int(signature_offset),
        data_tail,
        signature_tail,
    )

    return "0x" + selector.hex() + args.hex()


def prepare_onchain_execution(input: Mapping[str, Any]) -> dict[str, Any]:
    actor = input.get("actor") or {}
    action = input.get("action") or {}
    artifact = input.get("artifact") or {}
    payload = (artifact.get("payload") or {})

    verify_onchain_authorization({
        "artifact": artifact,
        "request": {
            "account": actor.get("accountAddress"),
            "to": action.get("to"),
            "value": action.get("value"),
            "data": action.get("data"),
            "chainId": actor.get("chainId"),
            "nonce": action.get("nonce"),
            "executor": actor.get("executorAddress"),
        },
    })
    call = prepare_execute_with_auth_call(action, artifact)
    return {
        **call,
        "calldata": encode_execute_with_auth_calldata(call),
    }


# camelCase aliases
computeOnchainActionHash = compute_onchain_action_hash
computeOnchainAuthorizationDigest = compute_onchain_authorization_digest
verifyOnchainAuthorization = verify_onchain_authorization
prepareExecuteWithAuthCall = prepare_execute_with_auth_call
encodeExecuteWithAuthCalldata = encode_execute_with_auth_calldata
prepareOnchainExecution = prepare_onchain_execution
