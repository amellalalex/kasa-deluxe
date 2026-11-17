"""Configuration: config.toml (see config.example.toml) plus environment overrides."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class DeviceConfig:
    id: str
    host: str
    port: int = 80
    username: str = ""
    password: str = ""
    name: str = ""


@dataclass
class Config:
    bind: str = "127.0.0.1"
    port: int = 8125
    token: str = ""
    poll_interval: float = 5.0
    db: str = "data/kasa.db"
    keep_days: float = 90.0
    devices: list[DeviceConfig] = field(default_factory=list)


def load(path: str | os.PathLike | None = None) -> Config:
    path = Path(path or os.environ.get("KASA_CONFIG", "config.toml"))
    raw: dict = {}
    if path.exists():
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    srv = raw.get("server", {})
    acct = raw.get("account", {})
    cfg = Config(
        bind=os.environ.get("KASA_BIND", srv.get("bind", Config.bind)),
        port=int(os.environ.get("KASA_PORT_HTTP", srv.get("port", Config.port))),
        token=os.environ.get("KASA_API_TOKEN", srv.get("token", "")),
        poll_interval=float(os.environ.get("KASA_POLL", srv.get("poll_interval", Config.poll_interval))),
        db=os.environ.get("KASA_DB", srv.get("db", Config.db)),
        keep_days=float(srv.get("keep_days", Config.keep_days)),
    )
    # Account credentials: env wins, then [account], then per-device overrides.
    user = os.environ.get("KASA_USERNAME", acct.get("username", ""))
    pw = os.environ.get("KASA_PASSWORD", acct.get("password", ""))
    for d in raw.get("device", []):
        cfg.devices.append(
            DeviceConfig(
                id=str(d["id"]),
                host=str(d["host"]),
                port=int(d.get("port", 80)),
                username=d.get("username", user),
                password=d.get("password", pw),
                name=d.get("name", ""),
            )
        )
    if not cfg.devices and os.environ.get("KASA_HOST"):
        cfg.devices.append(DeviceConfig(id="plug", host=os.environ["KASA_HOST"],
                                        port=int(os.environ.get("KASA_DEVICE_PORT", 80)),
                                        username=user, password=pw))  # fmt: skip
    return cfg
