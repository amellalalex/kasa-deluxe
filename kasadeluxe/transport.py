"""TPAP transport: SPAKE2+ login over HTTP, then AEAD-encrypted JSON requests.

Flow (all JSON POSTs to ``http://<host>:<port>/``)::

    {"method":"login","params":{"sub_method":"discover"}}        -> tpap {pake,tls,port,dac}, mac
    {"method":"login","params":{"sub_method":"pake_register",..}} -> dev_random, dev_salt, dev_share,...
    {"method":"login","params":{"sub_method":"pake_share",..}}    -> dev_confirm, stok, start_seq

then every request is ``<seq:4 BE><AEAD ciphertext>`` POSTed to ``/stok=<stok>/ds``.

A rejected ``pake_share`` counts toward the plug's lockout, so after one
credential rejection this transport refuses to log in again until
``clear_auth_failure()`` is called (e.g. after the user fixes the password).
"""

from __future__ import annotations

import asyncio
import base64
import hmac
import json
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

import httpx
from cryptography.exceptions import InvalidTag

from . import crypto

log = logging.getLogger(__name__)

SESSION_LOST_CODES = frozenset({-2402, -2101, -40420, -40421, -40401})
AUTH_ERROR_CODES = frozenset({-1501, -1012, -40401, -40411, -40412, -1005})


class TpapError(Exception):
    """Generic transport failure."""

    def __init__(self, msg: str, code: int | None = None):
        super().__init__(msg)
        self.code = code


class TpapAuthError(TpapError):
    """The plug rejected our credentials (counts toward its lockout)."""


class TpapLockedError(TpapAuthError):
    """The plug is temporarily locked after too many failed logins."""


class TpapConnectionError(TpapError):
    """Network-level failure talking to the plug."""


class _SessionLost(TpapError):
    pass


@dataclass
class TpapParams:
    """What the plug advertises about its TPAP login."""

    pake: list[int] = field(default_factory=list)
    tls: int = 0
    port: int | None = None
    dac: bool = False
    mac: str = ""
    owner: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def passcode_type(self) -> str:
        p = set(self.pake)
        if 0 in p:
            return "default_userpw"
        if p & {2, 5}:
            return "userpw"
        if 3 in p:
            return "shared_token"
        return "default_userpw"


def _as_int(v: Any) -> int | None:
    if isinstance(v, bool):
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


class TpapTransport:
    """Async TPAP client for one plug."""

    def __init__(
        self,
        host: str,
        *,
        username: str = "",
        password: str = "",
        port: int = 80,
        timeout: float = 10.0,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username.strip()
        self.password = password
        self._client = httpx.AsyncClient(timeout=timeout, headers={"Connection": "close"})
        self._lock = asyncio.Lock()
        self._params: TpapParams | None = None
        self._cipher: crypto.SessionCipher | None = None
        self._ds_url: str | None = None
        self._auth_failure: str | None = None
        self.session_started: float | None = None
        self.logins = 0

    # ------------------------------------------------------------------ utils
    @property
    def base_url(self) -> str:
        port = (self._params.port if self._params and self._params.port else None) or self.port
        scheme = "https" if self._params and self._params.tls else "http"
        return f"{scheme}://{self.host}:{port}"

    @property
    def params(self) -> TpapParams | None:
        return self._params

    @property
    def auth_failure(self) -> str | None:
        return self._auth_failure

    def clear_auth_failure(self) -> None:
        self._auth_failure = None

    def set_credentials(self, username: str, password: str) -> None:
        self.username, self.password = username.strip(), password
        self._auth_failure = None
        self._drop_session()

    def _drop_session(self) -> None:
        self._cipher = None
        self._ds_url = None
        self.session_started = None

    async def close(self) -> None:
        self._drop_session()
        await self._client.aclose()

    async def _post_json(self, url: str, body: dict) -> dict:
        try:
            r = await self._client.post(url, json=body, headers={"Content-Type": "application/json"})
        except httpx.HTTPError as e:
            raise TpapConnectionError(f"{self.host}: {type(e).__name__}: {e}") from e
        try:
            data = r.json()
        except ValueError as e:
            raise TpapError(f"{self.host}: non-JSON reply (HTTP {r.status_code})") from e
        if not isinstance(data, dict):
            raise TpapError(f"{self.host}: unexpected reply type")
        return data

    @staticmethod
    def _check_login_error(data: dict, step: str) -> dict:
        code = _as_int(data.get("error_code")) or 0
        if code == 0:
            result = data.get("result")
            if not isinstance(result, dict):
                raise TpapError(f"{step}: reply without result")
            return result
        info = data.get("error_info") if isinstance(data.get("error_info"), dict) else {}
        locked = _as_int(info.get("lockedMinute")) or 0
        remain = _as_int(info.get("remainAttempts"))
        if locked > 0 or remain == 0:
            raise TpapLockedError(
                f"{step}: plug locked after failed logins"
                + (f", retry in {locked} min" if locked else ""),
                code,
            )
        if step == "pake_share":
            left = f" ({remain} attempts left before lockout)" if remain is not None else ""
            raise TpapAuthError(f"Credentials rejected by plug (error {code}){left}", code)
        raise TpapError(f"{step} failed with error {code}", code)

    # ------------------------------------------------------------------ login
    async def discover(self) -> TpapParams:
        """Ask the plug for its TPAP login parameters (unauthenticated)."""
        data = await self._post_json(
            f"http://{self.host}:{self.port}/",
            {"method": "login", "params": {"sub_method": "discover"}},
        )
        result = self._check_login_error(data, "discover")
        tp = result.get("tpap")
        if not isinstance(tp, dict):
            raise TpapError("discover reply has no tpap object (is this a TPAP device?)")
        pake = tp.get("pake")
        self._params = TpapParams(
            pake=[x for x in map(_as_int, pake) if x is not None] if isinstance(pake, list) else [],
            tls=_as_int(tp.get("tls")) or 0,
            port=_as_int(tp.get("port")),
            dac=_as_int(tp.get("dac")) == 1,
            mac=str(result.get("mac") or ""),
            owner=str(result.get("owner") or "").lower(),
            raw=result,
        )
        if self._params.tls:
            # Plugs seen so far use tls 0; TLS would need TP-Link's device CA to verify.
            log.warning("%s announces TLS mode %s; TLS is not verified", self.host, self._params.tls)
            self._client = httpx.AsyncClient(
                timeout=self._client.timeout, verify=False, headers={"Connection": "close"}
            )
        return self._params

    def _check_owner(self, params: TpapParams) -> None:
        if not params.owner or not self.username:
            return
        names = {self.username, self.username.lower()}
        if "@" not in self.username:
            names |= {f"{n}@tplink.id" for n in names}
        if params.owner not in {crypto.md5_hex(n) for n in names}:
            raise TpapAuthError(
                "This plug is owned by a different TP-Link account than the one configured "
                "(owner hash mismatch); not attempting login to avoid a lockout."
            )

    async def login(self) -> None:
        if self._auth_failure:
            raise TpapAuthError(f"Login disabled after previous rejection: {self._auth_failure}")
        params = self._params or await self.discover()
        ptype = params.passcode_type
        if ptype == "default_userpw":
            if not params.mac:
                raise TpapError("default passcode needs the plug MAC")
            secret = crypto.default_passcode_from_mac(params.mac)
        else:
            if not self.password:
                raise TpapAuthError("No password configured (plug requires TP-Link account login)")
            self._check_owner(params)
            secret = self.password

        user_random = secrets.token_bytes(32)
        register = self._check_login_error(
            await self._post_json(
                self.base_url + "/",
                {
                    "method": "login",
                    "params": {
                        "sub_method": "pake_register",
                        "username": crypto.md5_hex("admin"),
                        "user_random": base64.b64encode(user_random).decode(),
                        "cipher_suites": [1],
                        "encryption": ["aes_128_ccm"],
                        "passcode_type": ptype,
                    },
                },
            ),
            "pake_register",
        )
        for k in ("dev_random", "dev_salt", "dev_share"):
            if not register.get(k):
                raise TpapError(f"pake_register reply missing {k}")
        suite = _as_int(register.get("cipher_suites"))
        if suite is None:
            raise TpapError("pake_register reply has invalid cipher_suites")
        iterations = _as_int(register.get("iterations")) or 10_000
        cipher = crypto.normalize_cipher(str(register.get("encryption") or "aes_128_ccm"))

        use_dac = ptype == "default_userpw" and params.dac and params.tls == 0
        if use_dac:
            cred = secret
        else:
            cred = crypto.encode_passcode(
                register.get("extra_crypt") if isinstance(register.get("extra_crypt"), dict) else None,
                "" if ptype == "default_userpw" else self.username,
                secret,
                params.mac,
            )

        share = await asyncio.to_thread(
            crypto.spake2p_client,
            cred.encode(),
            suite_type=suite,
            salt=base64.b64decode(register["dev_salt"]),
            iterations=iterations,
            user_random=user_random,
            dev_random=base64.b64decode(register["dev_random"]),
            dev_share=base64.b64decode(register["dev_share"]),
        )
        share_params: dict[str, Any] = {
            "sub_method": "pake_share",
            "user_share": base64.b64encode(share.user_share).decode(),
            "user_confirm": base64.b64encode(share.user_confirm).decode(),
        }
        if use_dac:
            # The plug signs (shared_key || nonce) with its attestation cert. We
            # request it for protocol compliance; the SPAKE2+ confirmation below
            # already proves the plug knows the passcode.
            share_params["dac_nonce"] = base64.b64encode(secrets.token_bytes(32)).decode()

        try:
            result = self._check_login_error(
                await self._post_json(self.base_url + "/", {"method": "login", "params": share_params}),
                "pake_share",
            )
        except TpapAuthError as e:
            self._auth_failure = str(e)
            raise

        dev_confirm = str(result.get("dev_confirm") or "")
        expected = base64.b64encode(share.expected_dev_confirm).decode()
        if not hmac.compare_digest(dev_confirm.encode(), expected.encode()):
            raise TpapError("Plug confirmation mismatch (possible MITM or protocol change)")
        stok = str(result.get("sessionId") or result.get("stok") or "")
        start_seq = _as_int(result.get("start_seq"))
        if not stok or start_seq is None:
            raise TpapError("pake_share reply missing session fields")
        self._cipher = crypto.SessionCipher(cipher, share.shared_key, start_seq)
        self._ds_url = f"{self.base_url}/stok={stok}/ds"
        self.session_started = time.time()
        self.logins += 1
        log.info("TPAP session established with %s (cipher %s, suite %s)", self.host, cipher, suite)

    # ------------------------------------------------------------------ send
    async def _send_once(self, body: bytes) -> dict:
        if self._cipher is None:
            await self.login()
        assert self._cipher and self._ds_url
        payload, seq = self._cipher.next_request(body)
        try:
            r = await self._client.post(
                self._ds_url, content=payload, headers={"Content-Type": "application/octet-stream"}
            )
        except httpx.HTTPError as e:
            self._drop_session()
            raise TpapConnectionError(f"{self.host}: {type(e).__name__}: {e}") from e

        data = r.content
        plain_reply: dict | None = None
        try:
            obj = json.loads(data)
            plain_reply = obj if isinstance(obj, dict) else None
        except (ValueError, UnicodeDecodeError):
            pass
        if plain_reply is not None:
            code = _as_int(plain_reply.get("error_code", plain_reply.get("err_code")))
            self._drop_session()
            if code in SESSION_LOST_CODES or r.status_code != 200:
                raise _SessionLost(f"session dropped by plug ({code}, HTTP {r.status_code})", code)
            raise TpapError(f"plug returned an unencrypted reply (error {code})", code)
        if r.status_code != 200:
            self._drop_session()
            raise _SessionLost(f"HTTP {r.status_code}")
        try:
            rseq, plaintext = self._cipher.open(data)
        except (InvalidTag, crypto.TpapCryptoError) as e:
            self._drop_session()
            raise _SessionLost(f"could not decrypt reply: {e}") from e
        if rseq != seq:
            log.debug("reply seq %s != request seq %s", rseq, seq)
        obj = json.loads(plaintext)
        if not isinstance(obj, dict):
            raise TpapError("decrypted reply is not an object")
        return obj

    async def send(self, request: dict) -> dict:
        """Send one SMART request dict, re-logging in once if the session dropped."""
        body = json.dumps(request, separators=(",", ":")).encode()
        async with self._lock:
            try:
                return await self._send_once(body)
            except _SessionLost as e:
                log.info("%s: %s; logging in again", self.host, e)
                self._drop_session()
                return await self._send_once(body)
