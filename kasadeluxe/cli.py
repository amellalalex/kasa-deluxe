"""Command line: talk to a plug directly, or run the server.

    kasadeluxe info                     # uses config.toml / KASA_* env
    kasadeluxe --host 192.168.1.50 on
    kasadeluxe raw get_emeter_data
    kasadeluxe serve
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

from . import config as config_mod
from .device import SmartPlug
from .transport import TpapError, TpapTransport


def _pick_device(a) -> config_mod.DeviceConfig:
    cfg = config_mod.load(a.config)
    if a.host:
        base = cfg.devices[0] if cfg.devices else None
        return config_mod.DeviceConfig(
            id="cli", host=a.host, port=a.port,
            username=a.username or (base.username if base else os.environ.get("KASA_USERNAME", "")),
            password=base.password if base else os.environ.get("KASA_PASSWORD", ""),
        )  # fmt: skip
    for d in cfg.devices:
        if a.device in (None, d.id):
            return d
    raise SystemExit("No device: pass --host or configure config.toml (see config.example.toml)")


async def _run(a) -> object:
    dc = _pick_device(a)
    t = TpapTransport(dc.host, port=dc.port, username=dc.username, password=dc.password)
    plug = SmartPlug(t)
    try:
        if a.cmd == "info":
            return await plug.info()
        if a.cmd == "on":
            await plug.set_on(True)
            return {"on": True}
        if a.cmd == "off":
            await plug.set_on(False)
            return {"on": False}
        if a.cmd == "toggle":
            return {"on": await plug.toggle()}
        if a.cmd == "power":
            return SmartPlug.sample_from_snapshot(await plug.snapshot())
        if a.cmd == "settings":
            return await plug.settings()
        if a.cmd == "discover":
            p = await t.discover()
            return {"pake": p.pake, "tls": p.tls, "port": p.port, "dac": p.dac, "mac": p.mac,
                    "owner": p.owner, "passcode_type": p.passcode_type}  # fmt: skip
        if a.cmd == "raw":
            return await plug.call(a.method, json.loads(a.params) if a.params else None)
    finally:
        await t.close()
    raise SystemExit(f"unknown command {a.cmd}")


def _default(o):
    return o.__dict__ if hasattr(o, "__dict__") else str(o)


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="kasadeluxe", description="Local control for TPAP Kasa/Tapo plugs (KP125M)")
    ap.add_argument("-c", "--config", help="config.toml path")
    ap.add_argument("--device", help="device id from config")
    ap.add_argument("--host", help="plug IP (overrides config)")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--username", help="TP-Link account email (password from config or KASA_PASSWORD)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, hlp in [("info", "device info"), ("on", "turn on"), ("off", "turn off"), ("toggle", "toggle relay"),
                      ("power", "live power/voltage/current/energy"), ("settings", "LED, auto-off, protection, ..."),
                      ("discover", "unauthenticated TPAP login parameters"), ("serve", "run the API server + web UI")]:  # fmt: skip
        sub.add_parser(name, help=hlp)
    raw = sub.add_parser("raw", help="send any SMART method")
    raw.add_argument("method")
    raw.add_argument("params", nargs="?", help="JSON object")
    a = ap.parse_args(argv)

    if a.cmd == "serve":
        from . import server

        sys.argv = [sys.argv[0]] + (["-c", a.config] if a.config else [])
        server.main()
        return
    try:
        out = asyncio.run(_run(a))
    except TpapError as e:
        raise SystemExit(f"error: {e}") from None
    print(json.dumps(out, indent=2, default=_default))


if __name__ == "__main__":
    main()
