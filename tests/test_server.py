import time

from fastapi.testclient import TestClient

from kasadeluxe.config import Config, DeviceConfig
from kasadeluxe.server import create_app

from .test_tpap import PW, USER, sim  # noqa: F401  (fixture)


def _client(port, tmp_path, token=""):
    cfg = Config(token=token, poll_interval=0.3, db=str(tmp_path / "t.db"),
                 devices=[DeviceConfig(id="plug", host="127.0.0.1", port=port, username=USER, password=PW)])
    return TestClient(create_app(cfg))


def _wait(c, pred, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        d = c.get("/api/devices/plug").json()
        if pred(d):
            return d
        time.sleep(0.1)
    raise AssertionError(f"timeout, last: {d}")


def test_api_end_to_end(sim, tmp_path):
    plug, port = sim
    with _client(port, tmp_path) as c:
        d = _wait(c, lambda d: d["status"] == "online" and d["sample"])
        assert d["model"] == "KP125M" and d["sample"]["voltage_v"] > 100
        assert c.post("/api/devices/plug/power", json={"on": False}).json() == {"on": False}
        assert plug.on is False
        assert c.post("/api/devices/plug/toggle").json() == {"on": True}
        assert c.put("/api/devices/plug/led", json={"rule": "never"}).status_code == 200
        assert c.put("/api/devices/plug/protection", json={"enabled": True, "threshold_w": 1500}).status_code == 200
        assert c.put("/api/devices/plug/protection", json={"enabled": True, "threshold_w": 99999}).status_code == 400
        assert c.post("/api/devices/plug/schedules", json={"minute_of_day": 420, "on": True, "week_days": 62}).status_code == 200
        rid = c.get("/api/devices/plug/schedules").json()["rule_list"][0]["id"]
        assert c.patch(f"/api/devices/plug/schedules/{rid}", json={"enabled": False}).status_code == 200
        assert c.patch("/api/devices/plug/schedules/nope", json={"enabled": False}).status_code == 404
        assert c.delete(f"/api/devices/plug/schedules/{rid}").status_code == 200
        s = c.get("/api/devices/plug/settings").json()
        assert s["get_led_info"]["led_rule"] == "never" and s["get_schedule_rules"]["rule_list"] == []
        assert c.post("/api/devices/plug/countdown", json={"seconds": 60, "on": False}).status_code == 200
        assert len(c.get("/api/devices/plug/energy-history?period=day").json()["data"]) == 24
        assert c.post("/api/devices/plug/raw", json={"method": "get_max_power"}).json() == {"max_power": 1888}
        time.sleep(1)
        h = c.get("/api/devices/plug/history?hours=0.1").json()
        assert h["points"] and h["energy_wh"] >= 0
        assert c.get("/api/devices/plug/history.csv?hours=1").text.startswith("ts,iso_time,on_state")
        kinds = [e["kind"] for e in c.get("/api/devices/plug/events").json()]
        assert "off" in kinds and "on" in kinds
        m = c.get("/metrics").text
        assert 'kasa_up{device="plug"} 1' in m and "kasa_power_watts" in m
        assert c.get("/").status_code == 200


def test_token_and_auth_failure_pauses_polling(sim, tmp_path):
    plug, port = sim
    cfg = Config(token="s3cret", poll_interval=0.2, db=str(tmp_path / "t.db"),
                 devices=[DeviceConfig(id="plug", host="127.0.0.1", port=port, username=USER, password="bad")])
    with TestClient(create_app(cfg)) as c:
        assert c.get("/api/devices").status_code == 401
        hdr = {"Authorization": "Bearer s3cret"}
        end = time.time() + 10
        while c.get("/api/devices/plug", headers=hdr).json()["status"] != "auth_failed" and time.time() < end:
            time.sleep(0.1)
        time.sleep(1)  # several poll intervals: must not keep trying
        assert plug.failed == 1
        r = c.post("/api/devices/plug/reconnect", headers=hdr, json={"password": PW})
        assert r.status_code == 200
        end = time.time() + 10
        while c.get("/api/devices/plug?token=s3cret").json()["status"] != "online" and time.time() < end:
            time.sleep(0.1)
        assert c.get("/api/devices/plug?token=s3cret").json()["status"] == "online"
