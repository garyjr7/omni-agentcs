"""Token-free administrative and debugging CLI for NEXUS."""

from __future__ import annotations

import argparse
import asyncio
import json

from nexus_core.config import NEXUS_DB_PATH
from nexus_core.kernel.store_factory import get_control_store
from nexus_core.llm.abstraction import LLMConfig, LLMFactory, LLMMessage, LLMProvider


def output(value) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, default=str))


def main() -> None:
    parser = argparse.ArgumentParser(prog="nexus", description="BAJIOWARE NEXUS CLI")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    list_parser = commands.add_parser("list")
    list_parser.add_argument("resource", choices=("tenants", "agents", "tools"))
    list_parser.add_argument("--tenant", default="system")
    fake = commands.add_parser("fake-llm")
    fake.add_argument("message")
    fake.add_argument("--scenario", default="echo")
    goal = commands.add_parser("submit-goal")
    goal.add_argument("goal")
    goal.add_argument("--tenant", default="system")
    goal.add_argument("--idempotency-key", required=True)
    debug_task = commands.add_parser("enqueue-debug")
    debug_task.add_argument("message")
    debug_task.add_argument("--scenario", default="echo")
    debug_task.add_argument("--tenant", default="system")
    debug_task.add_argument("--idempotency-key", required=True)
    args = parser.parse_args()

    store = get_control_store(NEXUS_DB_PATH)
    store.initialize()
    if args.command == "status":
        output({"status": "ready", "database": str(NEXUS_DB_PATH), "offline_llm": True})
    elif args.command == "list":
        if args.resource == "tenants":
            output(store.list_tenants())
        else:
            table = "kernel_agents" if args.resource == "agents" else "kernel_tools"
            output(store.list_definitions(table, args.tenant))
    elif args.command == "fake-llm":
        client = LLMFactory.create(LLMConfig(provider=LLMProvider.FAKE, model="nexus-fake-v1"))
        response = asyncio.run(client.complete(
            [LLMMessage(role="user", content=args.message)], scenario=args.scenario
        ))
        output({"content": response.content, "provider": response.provider.value})
    elif args.command == "submit-goal":
        output(store.create_run(
            args.tenant, {"goal": args.goal, "source": "cli"}, args.idempotency_key
        ))
    elif args.command == "enqueue-debug":
        run = store.create_run(
            args.tenant, {"source": "cli"}, args.idempotency_key
        )
        output(store.enqueue_task(
            tenant_id=args.tenant,
            run_id=run["id"],
            task_type="debug.fake_llm",
            payload={"message": args.message, "scenario": args.scenario},
        ))


if __name__ == "__main__":
    main()
