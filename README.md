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

If the Beav3r server changes auth or approval-signing behavior again, review the sibling integrations in the shared `~/beav3r` workspace before release.
