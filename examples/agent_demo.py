from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from beav3r_sdk import Beav3r


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 examples/agent_demo.py",
        description="Run a standalone Beav3r demo request or watch an action.",
    )
    parser.add_argument(
        "scenario",
        nargs="?",
        default="high",
        choices=["low", "high", "deny", "exec", "email", "deploy", "watch"],
        help="Demo scenario to run.",
    )
    parser.add_argument(
        "action_id",
        nargs="?",
        help="Action ID to watch when running the watch scenario.",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    bridge_env = load_bridge_env()
    base_url = (
        os.getenv("BEAV3R_URL")
        or os.getenv("BEAVER_URL")
        or "https://staging.server.beav3r.ai"
    )
    agent_id = os.getenv("BEAV3R_AGENT_ID") or os.getenv("BEAVER_AGENT_ID") or "agent_demo_1"
    api_key = os.getenv("BEAV3R_API_KEY") or os.getenv("BEAVER_API_KEY") or bridge_env.get("BEAV3R_API_KEY")

    client = Beav3r(
        base_url=base_url,
        agent_id=agent_id,
        api_key=api_key,
        default_expiry_seconds=180,
    )

    if args.scenario == "watch":
        if not args.action_id:
            parser.error("watch requires action_id")
        watch_action(client, args.action_id, base_url)
        return

    result = request_scenario(client, args.scenario, api_key)
    print_result(result, base_url, agent_id)

    if result["status"] == "pending":
        print(f"\nPending approval on phone for actionId={result['actionId']}")
        print(f"Watch with: python3 examples/agent_demo.py watch {result['actionId']}")
        watch_action(client, result["actionId"], base_url)


def request_scenario(client: Beav3r, scenario: str, api_key: str | None) -> dict:
    suffix = int(time.time() * 1000)

    if scenario == "low":
        return client.guard(
            {
                "actionId": f"act_low_{suffix}",
                "actionType": "transfer",
                "payload": {"asset": "USDT", "amount": 5, "destination": "0xlowdemo"},
                "attributes": transfer_attributes("USDT", 5, "0xlowdemo"),
            }
        )
    if scenario == "high":
        if not api_key:
            raise RuntimeError("Missing Beav3r API key. Set BEAV3R_API_KEY or BEAVER_API_KEY.")
        return client.relay_action(
            {
                "actionId": f"act_high_{suffix}",
                "actionType": "transfer",
                "payload": {"asset": "USDT", "amount": 25, "destination": "0xhighdemo"},
                "attributes": transfer_attributes("USDT", 25, "0xhighdemo"),
                "reason": "High-risk transfer routed through the relay",
            }
        )
    if scenario == "deny":
        return client.guard(
            {
                "actionId": f"act_deny_{suffix}",
                "actionType": "unknown_critical",
                "payload": {"target": "prod"},
                "attributes": {"target": "prod", "environment": "prod"},
            }
        )
    if scenario == "exec":
        return client.guard(
            {
                "actionId": f"act_exec_{suffix}",
                "actionType": "exec",
                "payload": {"command": "deploy --target prod"},
                "attributes": exec_attributes("deploy --target prod"),
            }
        )
    if scenario == "email":
        return client.guard(
            {
                "actionId": f"act_email_{suffix}",
                "actionType": "send_email",
                "payload": {
                    "to": "ops@example.com",
                    "subject": "Agent status",
                    "body": "Deployment report is ready.",
                },
                "attributes": email_attributes("ops@example.com", "Agent status"),
            }
        )
    if scenario == "deploy":
        return client.guard(
            {
                "actionId": f"act_deploy_{suffix}",
                "actionType": "deploy_service",
                "payload": {"service": "checkout-api", "environment": "production"},
                "attributes": deploy_attributes("checkout-api", "production"),
            }
        )
    raise RuntimeError(f"Unknown scenario: {scenario}")


def watch_action(client: Beav3r, action_id: str, base_url: str) -> None:
    print(f"Watching {action_id} on {base_url}")
    started = time.time()
    while (time.time() - started) < 300:
        status = client.get_action_status(action_id)
        reason = f" ({status['reason']})" if status.get("reason") else ""
        print(f"[{time.strftime('%H:%M:%S')}] {status['actionId']} -> {status['status']}{reason}")
        if status["status"] in {"approved", "executed", "denied", "rejected", "expired"}:
            return
        time.sleep(3)
    raise RuntimeError(f"Timed out waiting for {action_id}")


def print_result(result: dict, base_url: str, agent_id: str) -> None:
    print(f"Beav3r URL: {base_url}")
    print(f"Agent ID: {agent_id}")
    print(f"Result: {result['status']}")
    print(f"Action ID: {result['actionId']}")
    if result.get("actionHash"):
        print(f"Action Hash: {result['actionHash']}")
    if result.get("reason"):
        print(f"Reason: {result['reason']}")


def transfer_attributes(asset: str, amount: int, destination: str) -> dict:
    return {
        "asset": asset,
        "amount": amount,
        "target_kind": "wallet",
        "destination": destination,
    }


def exec_attributes(command: str) -> dict:
    is_prod = "prod" in command.lower()
    return {
        "operation": "exec",
        "command_family": command.split(" ")[0] if command else "exec",
        "target_env": "prod" if is_prod else "unknown",
        "touches_runtime": True,
    }


def email_attributes(to: str, subject: str) -> dict:
    return {
        "operation": "send_email",
        "recipient_domain": to.split("@", 1)[1] if "@" in to else "unknown",
        "has_subject": bool(subject.strip()),
    }


def deploy_attributes(service: str, environment: str) -> dict:
    environment = environment.lower()
    return {
        "operation": "deploy",
        "service": service,
        "environment": environment,
        "target_env": environment,
    }


def load_bridge_env() -> dict[str, str]:
    override = os.getenv("BEAV3R_ENV_FILE")
    if override:
        candidate_paths = [Path(override).expanduser()]
    else:
        script_path = Path(__file__).resolve()
        candidate_paths = []
        for parent in [script_path.parent, *script_path.parents]:
            candidate_paths.extend(
                [
                    parent / ".env",
                    parent / "beav3r-server" / ".env",
                    parent / "beav3r-demo" / ".env",
                ]
            )
    env_path = next((path for path in candidate_paths if path.exists()), None)
    if env_path is None:
        return {}
    result: dict[str, str] = {}
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip()
    return result


if __name__ == "__main__":
    main()
