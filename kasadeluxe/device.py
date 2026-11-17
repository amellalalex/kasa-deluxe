"""High-level client for Kasa/Tapo "SMART" plugs (KP125M and friends) over TPAP."""

from __future__ import annotations

import base64
import hashlib
import time
import uuid
from typing import Any, Iterable

from .transport import TpapTransport

BATCH_SIZE = 5  # plugs reject large multipleRequest batches


class DeviceError(Exception):
    def __init__(self, method: str, code: int):
        super().__init__(f"{method} failed with error_code {code}")
        self.method = method
        self.code = code


def _b64dec(v: Any) -> Any:
    if not isinstance(v, str):
        return v
    try:
        return base64.b64decode(v).decode("utf-8")
    except Exception:
        return v


def _b64enc(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


class SmartPlug:
    """Thin, explicit wrapper around the plug's JSON methods."""

    def __init__(self, transport: TpapTransport) -> None:
        self.t = transport
        self._terminal_uuid = base64.b64encode(hashlib.md5(uuid.uuid4().bytes).digest()).decode()  # noqa: S324
        self.components: dict[str, int] = {}

    # ----------------------------------------------------------- primitives
    def _envelope(self, method: str, params: dict | None) -> dict:
        req: dict[str, Any] = {
            "method": method,
            "request_time_milis": round(time.time() * 1000),
            "terminal_uuid": self._terminal_uuid,
        }
        if params is not None:
            req["params"] = params
        return req

    async def call(self, method: str, params: dict | None = None) -> Any:
        resp = await self.t.send(self._envelope(method, params))
        code = resp.get("error_code", 0)
        if code:
            raise DeviceError(method, code)
        return resp.get("result", {})

    async def multi(
        self, calls: Iterable[tuple[str, dict | None]], *, raise_on_error: bool = False
    ) -> dict[str, Any]:
        """Run several methods; returns {method: result or DeviceError}."""
        calls = list(calls)
        out: dict[str, Any] = {}
        for i in range(0, len(calls), BATCH_SIZE):
            chunk = calls[i : i + BATCH_SIZE]
            reqs = [{"method": m, **({"params": p} if p is not None else {})} for m, p in chunk]
            result = await self.call("multipleRequest", {"requests": reqs})
            for r in result.get("responses", []):
                m, code = r.get("method"), r.get("error_code", 0)
                if code:
                    if raise_on_error:
                        raise DeviceError(m, code)
                    out[m] = DeviceError(m, code)
                else:
                    out[m] = r.get("result", {})
        return out

    # ----------------------------------------------------------- discovery
    async def negotiate(self) -> dict[str, int]:
        res = await self.call("component_nego")
        self.components = {c["id"]: c.get("ver_code", 1) for c in res.get("component_list", [])}
        return self.components

    # ----------------------------------------------------------- info/state
    async def info(self) -> dict:
        info = await self.call("get_device_info")
        return self.decode_info(info)

    @staticmethod
    def decode_info(info: dict) -> dict:
        info = dict(info)
        for k in ("nickname", "ssid"):
            if k in info:
                info[k] = _b64dec(info[k])
        return info

    async def set_on(self, on: bool) -> None:
        await self.call("set_device_info", {"device_on": bool(on)})

    async def toggle(self) -> bool:
        info = await self.call("get_device_info")
        new = not info.get("device_on", False)
        await self.set_on(new)
        return new

    async def set_nickname(self, name: str) -> None:
        await self.call("set_device_info", {"nickname": _b64enc(name)})

    async def set_default_state(self, kind: str, on: bool | None = None) -> None:
        """kind: 'last_states' or 'custom' (with on=True/False)."""
        ds: dict[str, Any] = {"type": kind}
        if kind == "custom":
            ds["state"] = {"on": bool(on)}
        await self.call("set_device_info", {"default_states": ds})

    async def reboot(self, delay: int = 1) -> None:
        await self.call("device_reboot", {"delay": delay})

    # ----------------------------------------------------------- energy
    async def snapshot(self) -> dict[str, Any]:
        """Everything the poller needs, in one round trip."""
        res = await self.multi(
            [
                ("get_device_info", None),
                ("get_emeter_data", None),
                ("get_energy_usage", None),
                ("get_current_power", None),
            ]
        )
        info = res.get("get_device_info")
        if isinstance(info, dict):
            res["get_device_info"] = self.decode_info(info)
        return res

    @staticmethod
    def sample_from_snapshot(snap: dict[str, Any]) -> dict[str, Any]:
        """Flatten a snapshot into SI units for storage/charts."""
        info = snap.get("get_device_info") or {}
        em = snap.get("get_emeter_data")
        eu = snap.get("get_energy_usage")
        cp = snap.get("get_current_power")
        em = em if isinstance(em, dict) else {}
        eu = eu if isinstance(eu, dict) else {}
        cp = cp if isinstance(cp, dict) else {}
        power_w = None
        if "power_mw" in em:
            power_w = em["power_mw"] / 1000
        elif "current_power" in cp:
            power_w = float(cp["current_power"])
        elif "current_power" in eu:
            power_w = eu["current_power"] / 1000
        return {
            "ts": time.time(),
            "on": bool(info.get("device_on")) if isinstance(info, dict) else None,
            "power_w": power_w,
            "voltage_v": em["voltage_mv"] / 1000 if "voltage_mv" in em else None,
            "current_a": em["current_ma"] / 1000 if "current_ma" in em else None,
            "energy_wh": em.get("energy_wh"),
            "today_wh": eu.get("today_energy"),
            "month_wh": eu.get("month_energy"),
            "today_runtime_min": eu.get("today_runtime"),
            "rssi": info.get("rssi") if isinstance(info, dict) else None,
        }

    async def energy_usage(self) -> dict:
        return await self.call("get_energy_usage")

    async def device_usage(self) -> dict:
        return await self.call("get_device_usage")

    async def energy_history(self, interval: int, start_ts: int, end_ts: int) -> dict:
        """interval 60 = hourly (one day), 1440 = daily (one month), 43200 = monthly (one year)."""
        return await self.call(
            "get_energy_data",
            {"start_timestamp": int(start_ts), "end_timestamp": int(end_ts), "interval": interval},
        )

    async def electricity_price(self) -> dict:
        return await self.call("get_electricity_price_config")

    # ----------------------------------------------------------- settings
    async def settings(self) -> dict[str, Any]:
        res = await self.multi(
            [
                ("get_led_info", None),
                ("get_auto_off_config", None),
                ("get_protection_power", None),
                ("get_max_power", None),
                ("get_countdown_rules", None),
                ("get_schedule_rules", {"start_index": 0}),
                ("get_device_time", None),
                ("get_latest_fw", None),
                ("get_auto_update_info", None),
                ("get_matter_setup_info", None),
            ]
        )
        return {k: (v if not isinstance(v, DeviceError) else {"error": v.code}) for k, v in res.items()}

    async def set_led(self, rule: str) -> None:
        """rule: 'always' | 'never' | 'night_mode'."""
        cur = await self.call("get_led_info")
        await self.call("set_led_info", {**cur, "led_rule": rule, "led_status": rule != "never"})

    async def set_auto_off(self, enable: bool, delay_min: int | None = None) -> None:
        cur = await self.call("get_auto_off_config")
        params = {"enable": bool(enable), "delay_min": int(delay_min or cur.get("delay_min", 120))}
        await self.call("set_auto_off_config", params)

    async def set_power_protection(self, enabled: bool, threshold_w: int | None = None) -> None:
        cur = await self.call("get_protection_power")
        mx = (await self.call("get_max_power")).get("max_power", 1875)
        if threshold_w is None:
            threshold_w = cur.get("protection_power") or mx // 2
        if not 0 < threshold_w <= mx:
            raise ValueError(f"threshold must be 1..{mx} W")
        await self.call(
            "set_protection_power", {**cur, "enabled": bool(enabled), "protection_power": int(threshold_w)}
        )

    # ----------------------------------------------------------- timers
    async def countdown(self) -> dict:
        return await self.call("get_countdown_rules")

    async def set_countdown(self, seconds: int, turn_on: bool) -> None:
        cur = await self.countdown()
        rule = {"delay": int(seconds), "desired_states": {"on": bool(turn_on)}, "enable": True, "remain": int(seconds)}
        existing = cur.get("rule_list") or []
        if existing:
            await self.call("edit_countdown_rule", {**rule, "id": existing[0]["id"]})
        else:
            await self.call("add_countdown_rule", rule)

    async def cancel_countdown(self) -> None:
        cur = await self.countdown()
        for r in cur.get("rule_list") or []:
            await self.call("edit_countdown_rule", {**r, "enable": False})

    async def schedules(self) -> dict:
        return await self.call("get_schedule_rules", {"start_index": 0})

    async def add_schedule(self, minute_of_day: int, turn_on: bool, week_days: int = 127) -> None:
        """week_days is a bitmask, bit0 = Sunday ... bit6 = Saturday (127 = every day)."""
        lt = time.localtime()
        await self.call(
            "add_schedule_rule",
            {
                "s_type": "normal",
                "s_min": int(minute_of_day),
                "e_type": "normal",
                "e_action": "none",
                "e_min": 0,
                "time_offset": 0,
                "mode": "repeat",
                "week_day": int(week_days),
                "year": lt.tm_year,
                "month": lt.tm_mon,
                "day": lt.tm_mday,
                "desired_states": {"on": bool(turn_on)},
                "enable": True,
            },
        )

    async def set_schedule_enabled(self, rule_id: str, enabled: bool) -> None:
        rules = (await self.schedules()).get("rule_list") or []
        rule = next((r for r in rules if r.get("id") == rule_id), None)
        if rule is None:
            raise KeyError(rule_id)
        await self.call("edit_schedule_rule", {**rule, "enable": bool(enabled)})

    async def remove_schedules(self, rule_ids: list[str]) -> None:
        await self.call("remove_schedule_rules", {"remove_ids": list(rule_ids)})
