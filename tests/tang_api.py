#!/usr/bin/env python3
"""Runs one of the API actions of tests/tang-test.yaml, the way a Home
Assistant automation would, and prints the device log that follows.

    tang_api.py <host> <api_encryption_key> tang_activate [password]
    tang_api.py <host> <api_encryption_key> tang_deactivate|tang_wipe|tang_conditions

Needs aioesphomeapi, which ESPHome's Python already has."""
import asyncio
import re
import sys

from aioesphomeapi import APIClient, LogLevel


async def main(host, key, action, args):
    client = APIClient(host, 6053, None, noise_psk=key)
    await client.connect(login=True)
    try:
        _, services = await client.list_entities_services()
        by_name = {s.name: s for s in services}
        if action not in by_name:
            sys.exit(f"no API action {action}; the device has {sorted(by_name)}")
        service = by_name[action]
        data = dict(zip((a.name for a in service.args), args))

        # The tang_server lines that follow, e.g. the TRIGGER and CONDITION
        # lines, and the activation result from its task.
        lines = []
        ansi = re.compile(r"\x1b\[[0-9;]*m")
        client.subscribe_logs(lambda m: lines.append(ansi.sub("", m.message.decode(errors="replace"))),
                              log_level=LogLevel.LOG_LEVEL_DEBUG)
        await client.execute_service(service, data)
        # Long enough for an activation with PBKDF2 at the test firmware's cost.
        await asyncio.sleep(4)
        for line in lines:
            if "tang_server" in line or "TRIGGER" in line or "CONDITION" in line:
                print(line)
    finally:
        await client.disconnect()


if __name__ == "__main__":
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    asyncio.run(main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:5]))
