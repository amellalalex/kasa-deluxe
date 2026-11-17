"""HTTP API + background poller + web UI.

    python -m kasadeluxe.server            # reads config.toml
"""

from __future__ import annotations

import asyncio
import contextlib
import csv
import io
import json
import logging
import time
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field

from . import config as config_mod
from .device import DeviceError, SmartPlug
from .store import SAMPLE_COLS, Store
from .transport import TpapAuthError, TpapConnectionError, TpapError, TpapLockedError, TpapTransport

log = logging.getLogger("kasadeluxe")
STATIC = Path(__file__).parent / "static"


class Runner:
    """Owns one plug: its connection, poll loop, latest state and subscribers."""

    def __init__(self, dc: config_mod.DeviceConfig, store: Store, interval: float):
        self.cfg = dc
        self.store = store
        self.interval = interval
        self.transport = TpapTransport(dc.host, port=dc.port, username=dc.username, password=dc.password)
        self.plug = SmartPlug(self.transport)
        self.info: dict[str, Any] = {}
        self.sample: dict[str, Any] | None = None
        self.status = "starting"
        self.error: str | None = None
        self.last_ok: float | None = None
        self.subscribers: set[asyncio.Queue] = set()
        self._wake = asyncio.Event()
        self._task: asyncio.Task | None = None

    @property
    def id(self) -> str:
        return self.cfg.id

    def summary(self) -> dict:
        tp = self.transport.params
        return {
            "id": self.id,
            "name": self.cfg.name or self.info.get("nickname") or self.id,
            "host": self.cfg.host,
            "status": self.status,
            "error": self.error,
            "last_ok": self.last_ok,
            "model": self.info.get("model"),
            "fw_ver": self.info.get("fw_ver"),
            "info": self.info,
            "sample": self.sample,
            "tpap": None if tp is None else {"pake": tp.pake, "tls": tp.tls, "dac": tp.dac, "mac": tp.mac},
            "session_started": self.transport.session_started,
        }

    def start(self) -> None:
        self._task = asyncio.create_task(self._loop(), name=f"poll-{self.id}")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        await self.transport.close()

    def poke(self) -> None:
        """Poll right away (after a command) and resume a stopped loop."""
        self._wake.set()

    def _publish(self, kind: str, data: Any) -> None:
        msg = json.dumps({"device": self.id, "kind": kind, "data": data})
        for q in list(self.subscribers):
            with contextlib.suppress(asyncio.QueueFull):
                q.put_nowait(msg)

    def _set_status(self, status: str, error: str | None = None) -> None:
        if status != self.status or error != self.error:
            if status in ("offline", "auth_failed", "locked") and self.status != status:
                self.store.add_event(self.id, status, error or "")
            elif status == "online" and self.status in ("offline", "auth_failed", "locked"):
                self.store.add_event(self.id, "reconnected", "")
            self.status, self.error = status, error
            self._publish("status", {"status": status, "error": error})

    async def poll_once(self) -> None:
        snap = await self.plug.snapshot()
        info = snap.get("get_device_info")
        if isinstance(info, dict):
            if self.info and info.get("device_on") != self.info.get("device_on"):
                self.store.add_event(self.id, "on" if info.get("device_on") else "off", "observed")
            self.info = info
        s = SmartPlug.sample_from_snapshot(snap)
        self.sample = s
        self.last_ok = s["ts"]
        await asyncio.to_thread(self.store.add_sample, self.id, s)
        self._set_status("online")
        self._publish("sample", s)

    async def _loop(self) -> None:
        backoff = self.interval
        while True:
            try:
                if self.transport.auth_failure:
                    self._set_status("auth_failed", self.transport.auth_failure)
                    await self._wake.wait()  # resumes only after /reconnect
                else:
                    await self.poll_once()
                    backoff = self.interval
            except TpapAuthError as e:
                locked = isinstance(e, TpapLockedError)
                self._set_status("locked" if locked else "auth_failed", str(e))
                backoff = 300 if locked else backoff
            except (TpapConnectionError, TpapError, DeviceError, OSError) as e:
                self._set_status("offline", str(e))
                backoff = min(60.0, backoff * 2)
            except Exception as e:  # keep the loop alive no matter what
                log.exception("poll failed for %s", self.id)
                self._set_status("offline", f"{type(e).__name__}: {e}")
                backoff = min(60.0, backoff * 2)
            self._wake.clear()
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._wake.wait(), timeout=backoff)


# ----------------------------------------------------------------------------- app


class PowerBody(BaseModel):
    on: bool


class LedBody(BaseModel):
    rule: str = Field(pattern="^(always|never|night_mode)$")


class AutoOffBody(BaseModel):
    enable: bool
    delay_min: int | None = Field(default=None, ge=1, le=1440)


class ProtectionBody(BaseModel):
    enabled: bool
    threshold_w: int | None = Field(default=None, ge=1)


class NameBody(BaseModel):
    name: str = Field(min_length=1, max_length=64)


class DefaultStateBody(BaseModel):
    type: str = Field(pattern="^(last_states|custom)$")
    on: bool | None = None


class CountdownBody(BaseModel):
    seconds: int = Field(ge=1, le=86400)
    on: bool


class ScheduleBody(BaseModel):
    minute_of_day: int = Field(ge=0, le=1439)
    on: bool
    week_days: int = Field(default=127, ge=1, le=127)


class ScheduleEnableBody(BaseModel):
    enabled: bool


class RawBody(BaseModel):
    method: str
    params: dict | None = None


class CredentialsBody(BaseModel):
    username: str | None = None
    password: str | None = None


def create_app(cfg: config_mod.Config | None = None) -> FastAPI:
    cfg = cfg or config_mod.load()
    store = Store(cfg.db)
    runners: dict[str, Runner] = {d.id: Runner(d, store, cfg.poll_interval) for d in cfg.devices}

    async def prune_loop():
        while True:
            await asyncio.to_thread(store.prune, cfg.keep_days)
            await asyncio.sleep(3600)

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):
        for r in runners.values():
            r.start()
        pruner = asyncio.create_task(prune_loop())
        yield
        pruner.cancel()
        for r in runners.values():
            await r.stop()

    app = FastAPI(title="python-kasa-deluxe", version="0.1.0", lifespan=lifespan)
    app.state.runners = runners
    app.state.store = store

    def auth(request: Request) -> None:
        if not cfg.token:
            return
        hdr = request.headers.get("authorization", "")
        tok = hdr[7:] if hdr.lower().startswith("bearer ") else request.query_params.get("token", "")
        if tok != cfg.token:
            raise HTTPException(401, "missing or bad token")

    def runner(device_id: str) -> Runner:
        r = runners.get(device_id)
        if r is None:
            raise HTTPException(404, f"unknown device {device_id}")
        return r

    async def act(r: Runner, coro):
        """Run a device command, mapping protocol errors to HTTP errors."""
        try:
            result = await coro
        except TpapAuthError as e:
            raise HTTPException(401, f"plug login failed: {e}") from e
        except DeviceError as e:
            raise HTTPException(502, str(e)) from e
        except (TpapError, OSError) as e:
            raise HTTPException(504, f"plug unreachable: {e}") from e
        except ValueError as e:
            raise HTTPException(400, str(e)) from e
        r.poke()
        return result

    api = Depends(auth)

    # ---------------------------------------------------------------- routes
    @app.get("/", include_in_schema=False)
    async def index():
        return FileResponse(STATIC / "index.html")

    @app.get("/api/health")
    async def health():
        return {"ok": True, "devices": {k: r.status for k, r in runners.items()}}

    @app.get("/api/devices", dependencies=[api])
    async def list_devices():
        return [r.summary() for r in runners.values()]

    @app.get("/api/devices/{device_id}", dependencies=[api])
    async def get_device(device_id: str):
        return runner(device_id).summary()

    @app.post("/api/devices/{device_id}/power", dependencies=[api])
    async def set_power(device_id: str, body: PowerBody):
        r = runner(device_id)
        await act(r, r.plug.set_on(body.on))
        r.info["device_on"] = body.on  # so the poller does not log it again
        store.add_event(device_id, "on" if body.on else "off", "api")
        return {"on": body.on}

    @app.post("/api/devices/{device_id}/toggle", dependencies=[api])
    async def toggle(device_id: str):
        r = runner(device_id)
        on = await act(r, r.plug.toggle())
        r.info["device_on"] = on
        store.add_event(device_id, "on" if on else "off", "api")
        return {"on": on}

    @app.get("/api/devices/{device_id}/usage", dependencies=[api])
    async def usage(device_id: str):
        r = runner(device_id)
        res = await act(r, r.plug.multi([("get_energy_usage", None), ("get_device_usage", None),
                                         ("get_electricity_price_config", None)]))  # fmt: skip
        return {k: (v if not isinstance(v, DeviceError) else {"error": v.code}) for k, v in res.items()}

    @app.get("/api/devices/{device_id}/energy-history", dependencies=[api])
    async def energy_history(device_id: str, period: str = "day"):
        """Plug's own on-board history. period: day (hourly) | month (daily) | year (monthly)."""
        r = runner(device_id)
        now = time.time()
        lt = time.localtime(now)
        if period == "day":
            start, interval = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, 0, 0, 0, 0, 0, -1)), 60
        elif period == "month":
            start, interval = time.mktime((lt.tm_year, lt.tm_mon, 1, 0, 0, 0, 0, 0, -1)), 1440
        elif period == "year":
            start, interval = time.mktime((lt.tm_year, 1, 1, 0, 0, 0, 0, 0, -1)), 43200
        else:
            raise HTTPException(400, "period must be day, month or year")
        return await act(r, r.plug.energy_history(interval, int(start), int(now)))

    @app.get("/api/devices/{device_id}/history", dependencies=[api])
    async def history(device_id: str, hours: float = 1.0, until: float | None = None, points: int = 300):
        """Locally recorded samples, bucketed into ~`points` points."""
        runner(device_id)
        until = until or time.time()
        since = until - hours * 3600
        bucket = max(1.0, hours * 3600 / max(10, min(points, 5000)))
        rows = await asyncio.to_thread(store.history, device_id, since, until, bucket)
        wh = await asyncio.to_thread(store.energy_between, device_id, since, until)
        return {"since": since, "until": until, "bucket_s": bucket, "energy_wh": wh, "points": rows}

    @app.get("/api/devices/{device_id}/history.csv", dependencies=[api])
    async def history_csv(device_id: str, hours: float = 24.0):
        runner(device_id)
        now = time.time()
        rows = await asyncio.to_thread(store.raw, device_id, now - hours * 3600, now)
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(("ts", "iso_time", *SAMPLE_COLS))
        for row in rows:
            w.writerow((row[0], time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(row[0])), *row[1:]))
        return PlainTextResponse(buf.getvalue(), media_type="text/csv",
                                 headers={"Content-Disposition": f'attachment; filename="{device_id}.csv"'})  # fmt: skip

    @app.get("/api/devices/{device_id}/events", dependencies=[api])
    async def events(device_id: str, limit: int = 100):
        runner(device_id)
        return await asyncio.to_thread(store.events, device_id, limit)

    @app.get("/api/devices/{device_id}/settings", dependencies=[api])
    async def settings(device_id: str):
        r = runner(device_id)
        return await act(r, r.plug.settings())

    @app.put("/api/devices/{device_id}/led", dependencies=[api])
    async def set_led(device_id: str, body: LedBody):
        r = runner(device_id)
        await act(r, r.plug.set_led(body.rule))
        return {"ok": True}

    @app.put("/api/devices/{device_id}/auto-off", dependencies=[api])
    async def set_auto_off(device_id: str, body: AutoOffBody):
        r = runner(device_id)
        await act(r, r.plug.set_auto_off(body.enable, body.delay_min))
        return {"ok": True}

    @app.put("/api/devices/{device_id}/protection", dependencies=[api])
    async def set_protection(device_id: str, body: ProtectionBody):
        r = runner(device_id)
        await act(r, r.plug.set_power_protection(body.enabled, body.threshold_w))
        return {"ok": True}

    @app.put("/api/devices/{device_id}/name", dependencies=[api])
    async def set_name(device_id: str, body: NameBody):
        r = runner(device_id)
        await act(r, r.plug.set_nickname(body.name))
        return {"ok": True}

    @app.put("/api/devices/{device_id}/default-state", dependencies=[api])
    async def set_default_state(device_id: str, body: DefaultStateBody):
        r = runner(device_id)
        await act(r, r.plug.set_default_state(body.type, body.on))
        return {"ok": True}

    @app.post("/api/devices/{device_id}/countdown", dependencies=[api])
    async def set_countdown(device_id: str, body: CountdownBody):
        r = runner(device_id)
        await act(r, r.plug.set_countdown(body.seconds, body.on))
        return {"ok": True}

    @app.delete("/api/devices/{device_id}/countdown", dependencies=[api])
    async def cancel_countdown(device_id: str):
        r = runner(device_id)
        await act(r, r.plug.cancel_countdown())
        return {"ok": True}

    @app.get("/api/devices/{device_id}/schedules", dependencies=[api])
    async def schedules(device_id: str):
        r = runner(device_id)
        return await act(r, r.plug.schedules())

    @app.post("/api/devices/{device_id}/schedules", dependencies=[api])
    async def add_schedule(device_id: str, body: ScheduleBody):
        r = runner(device_id)
        await act(r, r.plug.add_schedule(body.minute_of_day, body.on, body.week_days))
        return {"ok": True}

    @app.patch("/api/devices/{device_id}/schedules/{rule_id}", dependencies=[api])
    async def enable_schedule(device_id: str, rule_id: str, body: ScheduleEnableBody):
        r = runner(device_id)
        try:
            await act(r, r.plug.set_schedule_enabled(rule_id, body.enabled))
        except KeyError as e:
            raise HTTPException(404, f"no schedule {rule_id}") from e
        return {"ok": True}

    @app.delete("/api/devices/{device_id}/schedules/{rule_id}", dependencies=[api])
    async def delete_schedule(device_id: str, rule_id: str):
        r = runner(device_id)
        await act(r, r.plug.remove_schedules([rule_id]))
        return {"ok": True}

    @app.post("/api/devices/{device_id}/reboot", dependencies=[api])
    async def reboot(device_id: str):
        r = runner(device_id)
        await act(r, r.plug.reboot())
        store.add_event(device_id, "reboot", "api")
        return {"ok": True}

    @app.post("/api/devices/{device_id}/raw", dependencies=[api])
    async def raw(device_id: str, body: RawBody):
        """Send any SMART method, e.g. {"method":"get_wireless_scan_info"}."""
        r = runner(device_id)
        return await act(r, r.plug.call(body.method, body.params))

    @app.post("/api/devices/{device_id}/reconnect", dependencies=[api])
    async def reconnect(device_id: str, body: CredentialsBody | None = None):
        """Clear a credential failure (optionally with new credentials) and retry login once."""
        r = runner(device_id)
        if body and (body.username is not None or body.password is not None):
            r.transport.set_credentials(
                body.username if body.username is not None else r.transport.username,
                body.password if body.password is not None else r.transport.password,
            )
        else:
            r.transport.clear_auth_failure()
        r._set_status("starting")
        r.poke()
        return {"ok": True}

    @app.get("/api/stream", dependencies=[api])
    async def stream(request: Request):
        """Server-sent events: {"device","kind":"sample"|"status","data"}."""
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        for r in runners.values():
            r.subscribers.add(q)

        async def gen():
            try:
                for r in runners.values():
                    yield f"data: {json.dumps({'device': r.id, 'kind': 'summary', 'data': r.summary()})}\n\n"
                while not await request.is_disconnected():
                    try:
                        msg = await asyncio.wait_for(q.get(), timeout=15)
                        yield f"data: {msg}\n\n"
                    except asyncio.TimeoutError:
                        yield ": keepalive\n\n"
            finally:
                for r in runners.values():
                    r.subscribers.discard(q)

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})  # fmt: skip

    @app.get("/metrics", dependencies=[api], response_class=PlainTextResponse)
    async def metrics():
        """Prometheus exposition format."""
        out = []
        gauges = {
            "kasa_power_watts": "power_w",
            "kasa_voltage_volts": "voltage_v",
            "kasa_current_amps": "current_a",
            "kasa_energy_today_wh": "today_wh",
            "kasa_energy_month_wh": "month_wh",
            "kasa_wifi_rssi_dbm": "rssi",
        }
        for metric, key in gauges.items():
            out.append(f"# TYPE {metric} gauge")
            for r in runners.values():
                v = (r.sample or {}).get(key)
                if v is not None:
                    out.append(f'{metric}{{device="{r.id}"}} {v}')
        out.append("# TYPE kasa_relay_on gauge")
        for r in runners.values():
            if r.sample and r.sample.get("on") is not None:
                out.append(f'kasa_relay_on{{device="{r.id}"}} {int(r.sample["on"])}')
        out.append("# TYPE kasa_up gauge")
        for r in runners.values():
            out.append(f'kasa_up{{device="{r.id}"}} {int(r.status == "online")}')
        return "\n".join(out) + "\n"

    return app


def main() -> None:
    import argparse

    import uvicorn

    ap = argparse.ArgumentParser(description="python-kasa-deluxe server")
    ap.add_argument("-c", "--config", default=None, help="path to config.toml")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")  # fmt: skip
    cfg = config_mod.load(a.config)
    if not cfg.devices:
        raise SystemExit("No devices configured: copy config.example.toml to config.toml")
    if cfg.bind not in ("127.0.0.1", "localhost", "::1") and not cfg.token:
        log.warning("Listening on %s without an API token: anyone on the network can control the plug", cfg.bind)
    uvicorn.run(create_app(cfg), host=cfg.bind, port=cfg.port, log_level="info")


if __name__ == "__main__":
    main()
