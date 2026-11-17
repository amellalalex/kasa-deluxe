import asyncio
import socket
import threading
import time

import pytest
import uvicorn

from kasadeluxe import crypto
from kasadeluxe.device import SmartPlug
from kasadeluxe.simulator import FakePlug, build_app
from kasadeluxe.transport import TpapAuthError, TpapTransport

USER, PW = "me@example.com", "hunter2"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(params=[None, {"type": "password_shadow", "params": {"passwd_id": 2}}], ids=["plain", "sha1"])
def sim(request):
    plug = FakePlug(USER, PW, extra_crypt=request.param)
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(build_app(plug), host="127.0.0.1", port=port, log_level="error"))
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield plug, port
    server.should_exit = True
    th.join(5)


def test_spake2p_roundtrip_all_suites():
    for suite in (1, 2, 3, 5, 8):
        dev = crypto.Spake2pDevice(b"pw", suite_type=suite, salt=b"s" * 16, iterations=100)
        ur, dr = b"u" * 32, b"d" * 32
        cs = crypto.spake2p_client(b"pw", suite_type=suite, salt=b"s" * 16, iterations=100,
                                   user_random=ur, dev_random=dr, dev_share=dev.Y)
        exp_user, dev_confirm, shared = dev.finish(user_random=ur, dev_random=dr, user_share=cs.user_share)
        assert exp_user == cs.user_confirm and dev_confirm == cs.expected_dev_confirm
        assert shared == cs.shared_key


def test_known_crypt_vectors():
    # reference values from `openssl passwd -1/-5`
    assert crypto.md5_crypt("password", "$1$saltsalt$") == "$1$saltsalt$qjXMvbEw8oaL.CzflDtaK/"
    assert crypto.sha256_crypt("Hello world!", "$5$saltstring") == (
        "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5")


def test_session_against_simulator(sim):
    plug, port = sim

    async def go():
        t = TpapTransport("127.0.0.1", port=port, username=USER, password=PW)
        dev = SmartPlug(t)
        info = await dev.info()
        assert info["model"] == "KP125M" and info["nickname"] == "Simulated Plug"
        await dev.set_on(False)
        assert (await dev.info())["device_on"] is False
        snap = await dev.snapshot()
        s = SmartPlug.sample_from_snapshot(snap)
        assert s["on"] is False and s["power_w"] == 0
        # session loss -> transparent re-login
        plug.sessions.clear()
        await dev.set_on(True)
        assert t.logins == 2
        await dev.add_schedule(8 * 60, True)
        assert len((await dev.schedules())["rule_list"]) == 1
        await t.close()

    asyncio.run(go())


def test_wrong_password_does_not_retry(sim):
    plug, port = sim

    async def go():
        t = TpapTransport("127.0.0.1", port=port, username=USER, password="wrong")
        with pytest.raises(TpapAuthError):
            await SmartPlug(t).info()
        with pytest.raises(TpapAuthError, match="disabled"):
            await SmartPlug(t).info()
        assert plug.failed == 1
        await t.close()

    asyncio.run(go())


def test_owner_mismatch_is_refused_before_login(sim):
    plug, port = sim

    async def go():
        t = TpapTransport("127.0.0.1", port=port, username="someone@else.com", password=PW)
        with pytest.raises(TpapAuthError, match="owned by a different"):
            await SmartPlug(t).info()
        assert plug.failed == 0
        await t.close()

    asyncio.run(go())
