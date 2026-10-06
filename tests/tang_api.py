#!/usr/bin/env python3
"""Talks to tests/tang-test.yaml through the ESPHome API, the way Home
Assistant does, and prints what the device reports back.

    tang_api.py <host> <api_encryption_key> run <action> [password]
        Runs an API action (tang_activate, tang_deactivate, tang_wipe,
        tang_conditions) and prints the tang_server log lines that follow.
    tang_api.py <host> <api_encryption_key> entities
        Lists the entities with their current state.
    tang_api.py <host> <api_encryption_key> watch <seconds>
        Prints every entity state change for that long.
    tang_api.py <host> <api_encryption_key> press <button name>
    tang_api.py <host> <api_encryption_key> text <text name> <value>
        Presses a button or sets a text, then prints the log and the state
        changes that follow.

Needs aioesphomeapi, which ESPHome's Python already has."""
import asyncio
import re
import sys

from aioesphomeapi import APIClient, LogLevel

ANSI = re.compile(r"\x1b\[[0-9;]*m")
# Long enough for an activation with PBKDF2 at the test firmware's cost.
SETTLE = 4


def show(value):
    return f"{value:g}" if isinstance(value, float) else repr(value)


async def main(host, key, command, args):
    client = APIClient(host, 6053, None, noise_psk=key)
    await client.connect(login=True)
    try:
        entities, services = await client.list_entities_services()
        names = {e.key: e.name for e in entities}
        by_name = {e.name: e for e in entities}

        states = {}
        changes = []

        def on_state(state):
            value = getattr(state, "state", None)
            if names.get(state.key) and states.get(state.key) != value:
                states[state.key] = value
                changes.append(f"STATE {names[state.key]} = {show(value)}")

        lines = []

        def on_log(message):
            line = ANSI.sub("", message.message.decode(errors="replace"))
            if "tang_server" in line or "TRIGGER" in line or "CONDITION" in line:
                lines.append(line)

        client.subscribe_states(on_state)
        await asyncio.sleep(1)  # the initial states
        initial = len(changes)

        if command == "entities":
            for line in sorted(changes):
                print(line)
            return
        if command == "watch":
            await asyncio.sleep(float(args[0]))
            for line in changes[initial:]:
                print(line)
            return

        client.subscribe_logs(on_log, log_level=LogLevel.LOG_LEVEL_DEBUG)
        if command == "run":
            service = {s.name: s for s in services}.get(args[0])
            if service is None:
                sys.exit(f"no API action {args[0]}; the device has {sorted(s.name for s in services)}")
            await client.execute_service(service, dict(zip((a.name for a in service.args), args[1:])))
        elif command in ("press", "text"):
            entity = by_name.get(args[0])
            if entity is None:
                sys.exit(f"no entity {args[0]!r}; the device has {sorted(by_name)}")
            if command == "press":
                client.button_command(entity.key)
            else:
                client.text_command(entity.key, args[1])
        else:
            sys.exit(__doc__)
        await asyncio.sleep(SETTLE)
        for line in lines + changes[initial:]:
            print(line)
    finally:
        await client.disconnect()


if __name__ == "__main__":
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    asyncio.run(main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:]))
