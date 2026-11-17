"""A fake KP125M that speaks TPAP, for tests and UI work without the real plug.

    python -m kasadeluxe.simulator --port 9999 --username me@example.com --password secret

The device side of SPAKE2+, the session cipher and the SMART method set mirror
what a KP125M(US) on firmware 1.4.x reports (taken from python-kasa fixtures).
"""

from __future__ import annotations

import argparse
import base64
import json
import math
import random
import secrets
import time
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from . import crypto

MAC = "B8-FB-B3-00-00-01"


class FakePlug:
    def __init__(self, username: str, password: str, *, extra_crypt: dict | None = None):
        self.username, self.password = username, password
        self.extra_crypt = extra_crypt
        self.salt = secrets.token_bytes(16)
        self.iterations = 1000
        self.sessions: dict[str, crypto.SessionCipher] = {}
        self.pending: dict[str, Any] | None = None
        self.failed = 0
        self.on = True
        self.on_since = time.time()
        self.energy_wh = 0.0
        self._last = time.time()
        self.state: dict[str, Any] = {
            "nickname": "Simulated Plug",
            "led": {"led_rule": "always", "led_status": True, "night_mode": {"night_mode_type": "sunrise_sunset", "start_time": 1199, "end_time": 377, "sunrise_offset": 0, "sunset_offset": 0}},
            "auto_off": {"delay_min": 120, "enable": False},
            "protection": {"enabled": False, "protection_power": 0},
            "countdown": [],
            "schedules": [],
            "default_states": {"type": "last_states"},
        }  # fmt: skip
        self._sched_n = 0

    # ---------------------------------------------------------------- load model
    def _power_w(self) -> float:
        if not self.on:
            return 0.0
        t = time.time()
        return 60 + 25 * math.sin(t / 30) + random.uniform(-3, 3) + (400 if int(t / 120) % 5 == 0 else 0)

    def _tick(self) -> None:
        now = time.time()
        self.energy_wh += self._power_w() * (now - self._last) / 3600
        self._last = now

    # ---------------------------------------------------------------- login
    def owner_hash(self) -> str:
        return crypto.md5_hex(self.username)

    def login(self, params: dict) -> dict:
        sub = params.get("sub_method")
        if self.failed >= 5:
            return {"error_code": -40404, "error_info": {"lockedMinute": 1, "remainAttempts": 0}}
        if sub == "discover":
            return {"error_code": 0, "result": {"mac": MAC, "owner": self.owner_hash(),
                    "tpap": {"dac": 1, "noc": 1, "pake": [2], "port": 0, "tls": 0}}}  # fmt: skip
        if sub == "pake_register":
            encoded = crypto.encode_passcode(self.extra_crypt, self.username, self.password, MAC)
            dev = crypto.Spake2pDevice(encoded.encode(), suite_type=1, salt=self.salt, iterations=self.iterations)
            dev_random = secrets.token_bytes(32)
            self.pending = {"dev": dev, "user_random": base64.b64decode(params["user_random"]), "dev_random": dev_random}
            res = {
                "dev_random": base64.b64encode(dev_random).decode(),
                "dev_salt": base64.b64encode(self.salt).decode(),
                "dev_share": base64.b64encode(dev.Y).decode(),
                "cipher_suites": 1,
                "iterations": self.iterations,
                "encryption": "aes_128_ccm",
            }
            if self.extra_crypt:
                res["extra_crypt"] = self.extra_crypt
            return {"error_code": 0, "result": res}
        if sub == "pake_share":
            if not self.pending:
                return {"error_code": -1501}
            p, self.pending = self.pending, None
            exp_user, dev_confirm, shared = p["dev"].finish(
                user_random=p["user_random"], dev_random=p["dev_random"],
                user_share=base64.b64decode(params["user_share"]),
            )  # fmt: skip
            if base64.b64decode(params.get("user_confirm", "")) != exp_user:
                self.failed += 1
                return {"error_code": -1501, "error_info": {"remainAttempts": 5 - self.failed}}
            self.failed = 0
            stok = secrets.token_hex(16)
            seq = random.randint(1, 1 << 20)
            self.sessions[stok] = crypto.SessionCipher("aes_128_ccm", shared, seq)
            return {"error_code": 0, "result": {"dev_confirm": base64.b64encode(dev_confirm).decode(), "stok": stok, "start_seq": seq}}
        return {"error_code": -1002}

    # ---------------------------------------------------------------- methods
    def device_info(self) -> dict:
        return {
            "device_id": "SIM0000000000000000000000000000000000000", "fw_ver": "1.4.1 Build 260721 Rel.065650",
            "hw_ver": "1.0", "type": "SMART.KASAPLUG", "model": "KP125M", "mac": MAC, "ip": "127.0.0.1",
            "device_on": self.on, "on_time": int(time.time() - self.on_since) if self.on else 0,
            "nickname": base64.b64encode(self.state["nickname"].encode()).decode(),
            "ssid": base64.b64encode(b"HomeWiFi").decode(), "rssi": -48 + random.randint(-3, 3), "signal_level": 3,
            "overcurrent_status": "normal", "power_protection_status": "normal", "charging_status": "normal",
            "auto_off_status": "off", "auto_off_remain_time": 0, "default_states": self.state["default_states"],
            "region": "America/Chicago", "time_diff": -360, "lang": "en_US", "avatar": "plug",
        }  # fmt: skip

    def handle(self, method: str, params: dict | None) -> tuple[int, Any]:
        self._tick()
        p = params or {}
        s = self.state
        if method == "multipleRequest":
            out = []
            for r in p.get("requests", []):
                code, res = self.handle(r["method"], r.get("params"))
                out.append({"method": r["method"], "error_code": code, "result": res})
            return 0, {"responses": out}
        pw = self._power_w()
        table: dict[str, Any] = {
            "component_nego": lambda: {"component_list": [{"id": i, "ver_code": 1} for i in (
                "device", "firmware", "time", "schedule", "countdown", "led", "auto_off",
                "energy_monitoring", "power_protection", "matter", "tpap")]},
            "get_device_info": self.device_info,
            "get_current_power": lambda: {"current_power": round(pw)},
            "get_emeter_data": lambda: {"power_mw": int(pw * 1000), "voltage_mv": 120000 + random.randint(-900, 900),
                                         "current_ma": int(pw / 120 * 1000), "energy_wh": int(self.energy_wh), "energy_mwh": int(self.energy_wh * 1000)},
            "get_energy_usage": lambda: {"current_power": int(pw * 1000), "today_energy": int(self.energy_wh),
                                          "month_energy": int(self.energy_wh) + 4200, "today_runtime": 300, "month_runtime": 9000,
                                          "local_time": time.strftime("%Y-%m-%d %H:%M:%S")},
            "get_device_usage": lambda: {"power_usage": {"today": int(self.energy_wh), "past7": 2100, "past30": 9000},
                                          "time_usage": {"today": 300, "past7": 2400, "past30": 9000}},
            "get_energy_data": lambda: {"interval": p.get("interval"), "start_timestamp": p.get("start_timestamp"),
                                         "end_timestamp": p.get("end_timestamp"),
                                         "data": [random.randint(20, 140) for _ in range({60: 24, 1440: 30, 43200: 12}.get(p.get("interval"), 24))]},
            "get_led_info": lambda: s["led"],
            "get_auto_off_config": lambda: s["auto_off"],
            "get_protection_power": lambda: s["protection"],
            "get_max_power": lambda: {"max_power": 1888},
            "get_countdown_rules": lambda: {"enable": bool(s["countdown"]), "countdown_rule_max_count": 1, "rule_list": s["countdown"]},
            "get_schedule_rules": lambda: {"enable": True, "rule_list": s["schedules"], "schedule_rule_max_count": 32, "start_index": 0, "sum": len(s["schedules"])},
            "get_device_time": lambda: {"timestamp": int(time.time()), "time_diff": -360, "region": "America/Chicago"},
            "get_latest_fw": lambda: {"fw_ver": "1.4.1 Build 260721 Rel.065650", "need_to_upgrade": False, "release_note": ""},
            "get_auto_update_info": lambda: {"enable": True, "random_range": 120, "time": 180},
            "get_matter_setup_info": lambda: {"setup_code": "34970112332", "setup_payload": "MT:Y.K9042C00KA0648G00"},
            "get_electricity_price_config": lambda: {"type": "constant", "constant_price": 150},
        }  # fmt: skip
        if method in table:
            return 0, table[method]()
        if method == "set_device_info":
            if "device_on" in p:
                if p["device_on"] and not self.on:
                    self.on_since = time.time()
                self.on = bool(p["device_on"])
            if "nickname" in p:
                s["nickname"] = base64.b64decode(p["nickname"]).decode()
            if "default_states" in p:
                s["default_states"] = p["default_states"]
            return 0, {}
        if method == "set_led_info":
            s["led"] = {**s["led"], **p}
            return 0, {}
        if method == "set_auto_off_config":
            s["auto_off"] = {**s["auto_off"], **p}
            return 0, {}
        if method == "set_protection_power":
            s["protection"] = {"enabled": p.get("enabled"), "protection_power": p.get("protection_power")}
            return 0, {}
        if method in ("add_countdown_rule", "edit_countdown_rule"):
            s["countdown"] = [{**p, "id": "C1"}]
            return 0, {}
        if method == "add_schedule_rule":
            self._sched_n += 1
            s["schedules"].append({**p, "id": f"S{self._sched_n}"})
            return 0, {}
        if method == "edit_schedule_rule":
            s["schedules"] = [p if r["id"] == p.get("id") else r for r in s["schedules"]]
            return 0, {}
        if method == "remove_schedule_rules":
            s["schedules"] = [r for r in s["schedules"] if r["id"] not in p.get("remove_ids", [])]
            return 0, {}
        if method == "device_reboot":
            self.sessions.clear()
            return 0, {}
        return -1, {}


def build_app(plug: FakePlug) -> Starlette:
    async def root(request: Request) -> Response:
        body = await request.json()
        if body.get("method") != "login":
            return JSONResponse({"error_code": -1002})
        return JSONResponse(plug.login(body.get("params") or {}))

    async def ds(request: Request) -> Response:
        stok = request.path_params["stok"]
        cipher = plug.sessions.get(stok)
        if cipher is None:
            return JSONResponse({"error_code": -40401})
        seq, plain = cipher.open(await request.body())
        req = json.loads(plain)
        code, result = plug.handle(req["method"], req.get("params"))
        reply = {"error_code": code, "result": result} if code == 0 else {"error_code": code}
        return Response(cipher.seal(json.dumps(reply).encode(), seq), media_type="application/octet-stream")

    return Starlette(routes=[Route("/", root, methods=["POST"]), Route("/stok={stok}/ds", ds, methods=["POST"])])


def main() -> None:
    import uvicorn

    ap = argparse.ArgumentParser(description="Fake TPAP KP125M")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9999)
    ap.add_argument("--username", default="me@example.com")
    ap.add_argument("--password", default="secret")
    ap.add_argument("--sha1", action="store_true", help="ask clients for sha1 password_shadow encoding")
    a = ap.parse_args()
    ec = {"type": "password_shadow", "params": {"passwd_id": 2}} if a.sha1 else None
    uvicorn.run(build_app(FakePlug(a.username, a.password, extra_crypt=ec)), host=a.host, port=a.port, log_level="warning")


if __name__ == "__main__":
    main()

