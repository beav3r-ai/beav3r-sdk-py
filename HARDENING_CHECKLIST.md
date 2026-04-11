# Python SDK Hardening Checklist

## Goal

Bring `beav3r-sdk-py` closer to the operational standard of the TypeScript SDK.

## Current pass

- [x] Fix standalone demo path assumptions.
- [x] Fix CLI help behavior.
- [x] Remove machine-specific documentation.
- [x] Preserve JS-style client aliases and denied-error shape.
- [x] Improve request error handling so server errors are not misreported as reachability failures.
- [x] Increase test coverage across core SDK flows.
- [ ] Verify packaging and smoke-test commands still pass.

## Client parity

- Keep the public surface aligned with the TypeScript SDK:
  - `request_action`
  - `relay_action`
  - `guard`
  - `guard_and_wait`
  - `guard_or_throw`
  - `get_action_status`
  - `get_action`
  - `list_pending_actions`
  - `list_recent_actions`
  - `list_policy_rules`
  - `register_device`
  - `submit_approval`
  - `reject_approval`
- Preserve aliases:
  - `BeaverClient`
  - `BeaverDeniedError`
- Confirm signed query behavior for:
  - action status reads
  - action detail reads
  - pending action listing
  - recent action listing
  - policy listing

## Demo hardening

- Keep the standalone demo working without hardcoded workstation paths.
- Ensure `--help` exits cleanly.
- Ensure the watch flow prints clear usage and status output.
- Ensure relay scenarios fail clearly when an API key is missing.

## Documentation hardening

- Remove machine-specific install commands.
- Keep example commands relative to the standalone repo.
- Document editable install and direct `PYTHONPATH` usage.
- Document the `PyNaCl` signing dependency clearly.

## Coverage expansion

- [x] Add tests for:
  - `relay_action`
  - `guard_and_wait`
  - `get_action_status`
  - `get_action`
  - `list_pending_actions`
  - `list_recent_actions`
  - `list_policy_rules`
  - `register_device`
  - `submit_approval`
  - `reject_approval`
- [x] Add failure-path coverage for:
  - denied actions
  - HTTP error payload propagation
  - network reachability errors
  - invalid JSON responses
  - missing relay reason

## Validation

- `python3 -m py_compile`
- `python3 -m unittest discover`
- demo `--help`
- optional live smoke test against a running local Beav3r server

## Later, if needed

- richer type modeling
- async client
- publish workflow
- live end-to-end CI smoke test
