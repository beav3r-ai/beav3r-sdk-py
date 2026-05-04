# beav3r-sdk

Python SDK for Beav3r action requests, relay approvals, signer registration, and approval submission.

## Install

### From PyPI

```bash
python3 -m pip install beav3r-sdk
```

### From source

```bash
cd beav3r-sdk-py
python3 -m pip install -e .
```

For direct source execution without installing the package, use `PYTHONPATH=src`.

Environment endpoints:

- Staging: `https://staging.server.beav3r.ai`
- Production: `https://server.beav3r.ai`

## Quick example

```python
from beav3r_sdk import Beav3r

client = Beav3r(
    base_url="https://staging.server.beav3r.ai",
    agent_id="agent_demo_1",
    api_key="bvr_test_...",
    default_expiry_seconds=180,
)

result = client.guard(
    {
        "actionType": "transfer",
        "payload": {"asset": "USDT", "amount": 5, "destination": "0xlowdemo"},
        "attributes": {"asset": "USDT", "amount": 5, "destination": "0xlowdemo"},
    }
)

print(result)
```

## Execution authorization helpers

The SDK includes execution-gating helpers for fail-closed executors:

- `guard_and_wait(..., audience="your-executor")` to attach a signed execution authorization artifact on approved/executed outcomes
- `mint_execution_authorization({"actionId": "...", "audience": "..."})` to mint directly
- `verify_execution_authorization(...)` and `is_valid_execution_authorization(...)` to validate signature, expiry, audience, and `actionHash`

Where to get verification keys:

- Preferred: configure the execution-authorization private key on the Beav3r server, then fetch public keys from:
  - `GET /.well-known/execution-authorization-keys`
- Optional fallback: if discovery is unavailable, provide a static map like:
  - `{"keyId":"BASE64_PUBLIC_KEY"}`
  - Example env override (same format): `BEAV3R_EXECUTION_PUBLIC_KEYS={"keyId":"BASE64_PUBLIC_KEY"}`

```python
from beav3r_sdk import Beav3r, verify_execution_authorization

public_keys = {
    # Prefer loading from GET /.well-known/execution-authorization-keys
    "kid_1": "<base64-ed25519-public-key>",
}

result = client.guard_and_wait(
    {"actionType": "payments.send_usdt", "payload": {...}, "attributes": {...}},
    audience="payments-executor",
)

artifact = result.get("executionAuthorizationArtifact")
if artifact:
    verify_execution_authorization(
        {
            "artifact": artifact,
            "action": {
                "actionId": "...",
                "agentId": "...",
                "actionType": "payments.send_usdt",
                "payload": {...},
                "attributes": {...},
                "timestamp": 1700000000,
                "nonce": "...",
                "expiry": 1700000300,
            },
            "audience": "payments-executor",
            "publicKeys": public_keys,
        }
    )
```

## Demo

```bash
python3 examples/agent_demo.py high
python3 examples/agent_demo.py watch act_high_123
```

The demo looks for `BEAV3R_ENV_FILE` first, then nearby `.env` files in the SDK repo or sibling `beav3r-server` and `beav3r-demo` folders. If you use the signing flows, install `PyNaCl` so device signing works.

## Compatibility note

As of the 2026-04-03 security hardening pass:

- `reject_approval(...)` must send `signature` and `expiry`
- device-scoped reads use signed query parameters for:
  - `get_action_status_with_options`
  - `get_action_with_options`
  - `list_pending_actions`
  - `list_recent_actions`
- `/actions/request` now requires an API key with `actions:relay`
- `/actions/{actionId}/execution-authorization` requires an API key with `actions:execute`
- `/actions/{actionId}/execution-authorization/redeem` requires an API key with `actions:execute`

`verify_execution_authorization(...)` also accepts an optional `usedArtifactIds` set so an executor can fail closed on replayed artifacts. For production executors, back that check with durable shared storage instead of process-local memory.

Typical enforced executor flow:
1. call `guard_and_wait(...)`
2. receive `executionAuthorizationArtifact`
3. verify the artifact locally
4. call `redeem_execution_authorization(...)`
5. only execute if redemption succeeds

If the Beav3r server changes auth or approval-signing behavior again, review the sibling integrations in the shared `~/beav3r` workspace before release.
