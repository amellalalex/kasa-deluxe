"""Cryptography for TP-Link's TPAP login: SPAKE2+, password encodings, session cipher.

The algorithms here follow the TPAP transport written for python-kasa
(https://github.com/python-kasa/python-kasa/pull/1592, GPL-3.0), reduced to what
Kasa/Tapo plugs need and with the elliptic-curve math done in plain Python so the
only dependency is ``cryptography``.

Both sides of the exchange live here (client *and* device), so the bundled
simulator can exercise exactly the same code paths the real plug does.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers.aead import AESCCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PAKE_CONTEXT_TAG = b"PAKE V1"
MAX_ITERATIONS = 100_000  # pake_register is unauthenticated; cap the PBKDF2 work
MAX_CRYPT_ROUNDS = 100_000


class TpapCryptoError(Exception):
    """Raised for malformed or unsupported crypto parameters."""


# --------------------------------------------------------------------------- #
# Minimal short-Weierstrass curve arithmetic (NIST P-256 / P-384 / P-521)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Curve:
    name: str
    p: int
    a: int
    b: int
    gx: int
    gy: int
    n: int

    @property
    def size(self) -> int:
        return (self.p.bit_length() + 7) // 8

    @property
    def G(self) -> tuple[int, int]:
        return (self.gx, self.gy)


P256 = Curve(
    "P-256",
    p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    a=-3,
    b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
    n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
)
P384 = Curve(
    "P-384",
    p=int(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"
        "FFFFFFFF0000000000000000FFFFFFFF",
        16,
    ),
    a=-3,
    b=int(
        "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875A"
        "C656398D8A2ED19D2A85C8EDD3EC2AEF",
        16,
    ),
    gx=int(
        "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A38"
        "5502F25DBF55296C3A545E3872760AB7",
        16,
    ),
    gy=int(
        "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C0"
        "0A60B1CE1D7E819D7A431D7C90EA0E5F",
        16,
    ),
    n=int(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF"
        "581A0DB248B0A77AECEC196ACCC52973",
        16,
    ),
)
P521 = Curve(
    "P-521",
    p=2**521 - 1,
    a=-3,
    b=int(
        "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF1"
        "09E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B50"
        "3F00",
        16,
    ),
    gx=int(
        "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D"
        "3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5"
        "BD66",
        16,
    ),
    gy=int(
        "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E"
        "662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD1"
        "6650",
        16,
    ),
    n=int(
        "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        "FFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB7"
        "1E91386409",
        16,
    ),
)

Point = tuple[int, int] | None  # None is the point at infinity


def _add(c: Curve, P: Point, Q: Point) -> Point:
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2:
        if (y1 + y2) % c.p == 0:
            return None
        lam = (3 * x1 * x1 + c.a) * pow(2 * y1, -1, c.p) % c.p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, c.p) % c.p
    x3 = (lam * lam - x1 - x2) % c.p
    return (x3, (lam * (x1 - x3) - y1) % c.p)


def _neg(c: Curve, P: Point) -> Point:
    return None if P is None else (P[0], (-P[1]) % c.p)


def _mul(c: Curve, k: int, P: Point) -> Point:
    R: Point = None
    k %= c.n
    while k:
        if k & 1:
            R = _add(c, R, P)
        P = _add(c, P, P)
        k >>= 1
    return R


def _on_curve(c: Curve, P: Point) -> bool:
    if P is None:
        return False
    x, y = P
    return (y * y - (x * x * x + c.a * x + c.b)) % c.p == 0


def decode_point(c: Curve, data: bytes) -> tuple[int, int]:
    """Decode a SEC1 compressed or uncompressed point and check it is on the curve."""
    size = c.size
    if len(data) == 1 + 2 * size and data[0] == 4:
        P = (int.from_bytes(data[1 : 1 + size], "big"), int.from_bytes(data[1 + size :], "big"))
    elif len(data) == 1 + size and data[0] in (2, 3):
        x = int.from_bytes(data[1:], "big")
        rhs = (x * x * x + c.a * x + c.b) % c.p
        y = pow(rhs, (c.p + 1) // 4, c.p)  # all NIST primes here are 3 mod 4
        if (y & 1) != (data[0] & 1):
            y = c.p - y
        P = (x, y)
    else:
        raise TpapCryptoError("Bad SEC1 point encoding")
    if not _on_curve(c, P):
        raise TpapCryptoError("Point is not on the curve")
    return P


def encode_point(c: Curve, P: Point) -> bytes:
    if P is None:
        raise TpapCryptoError("Cannot encode the point at infinity")
    return b"\x04" + P[0].to_bytes(c.size, "big") + P[1].to_bytes(c.size, "big")


# --------------------------------------------------------------------------- #
# SPAKE2+ (TP-Link flavour)
# --------------------------------------------------------------------------- #

# suite id -> (curve, M, N) ; the M/N constants are the RFC 9383 ones
_M_N = {
    "P-256": (
        "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f",
        "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49",
    ),
    "P-384": (
        "030ff0895ae5ebf6187080a82d82b42e2765e3b2f8749c7e05eba366434b363d3dc36f15314739074d2eb8613fceec2853",
        "02c72cf2e390853a1c1c4ad816a62fd15824f56078918f43f922ca21518f9c543bb252c5490214cf9aa3f0baab4b665c10",
    ),
    "P-521": (
        "02003f06f38131b2ba2600791e82488e8d20ab889af753a41806c5db18d37d85608cfae06b82e4a72cd744c719193562a653ea1f119eef9356907edc9b56979962d7aa",
        "0200c7924b9ec017f3094562894336a53c50167ba8c5963876880542bc669e494b2532d76c5b53dfb349fdf69154b9e0048c58a42e8ed04cef052a3bc349d95575cd25",
    ),
}


@dataclass(frozen=True)
class Suite:
    curve: Curve
    hash_name: str  # "sha256" | "sha512"
    cmac: bool

    @property
    def digest_len(self) -> int:
        return 64 if self.hash_name == "sha512" else 32

    @property
    def M(self) -> tuple[int, int]:
        return decode_point(self.curve, bytes.fromhex(_M_N[self.curve.name][0]))

    @property
    def N(self) -> tuple[int, int]:
        return decode_point(self.curve, bytes.fromhex(_M_N[self.curve.name][1]))


def get_suite(suite_type: int) -> Suite:
    if suite_type in (1, 2, 8, 9):
        curve = P256
    elif suite_type in (3, 4):
        curve = P384
    elif suite_type == 5:
        curve = P521
    else:
        raise TpapCryptoError(f"Unsupported TPAP cipher suite {suite_type}")
    hash_name = "sha512" if suite_type in (2, 4, 5, 7, 9) else "sha256"
    return Suite(curve, hash_name, cmac=suite_type in (8, 9))


def _hash(name: str, data: bytes) -> bytes:
    return hashlib.new(name, data).digest()


def _hkdf(name: str, ikm: bytes, *, salt: bytes, info: bytes, length: int) -> bytes:
    algo = hashes.SHA512() if name == "sha512" else hashes.SHA256()
    return HKDF(algorithm=algo, length=length, salt=salt, info=info).derive(ikm)


def _len8le(b: bytes) -> bytes:
    return len(b).to_bytes(8, "little") + b


def derive_w(credentials: bytes, salt: bytes, iterations: int, suite: Suite) -> tuple[int, int]:
    """PBKDF2 the encoded password into the SPAKE2+ scalars (w0, w1)."""
    if not 0 < iterations <= MAX_ITERATIONS:
        raise TpapCryptoError(f"Refusing PBKDF2 iteration count {iterations}")
    chunk = 32 + 8
    out = hashlib.pbkdf2_hmac("sha256", credentials, salt, iterations, 2 * chunk)
    n = suite.curve.n
    return int.from_bytes(out[:chunk], "big") % n, int.from_bytes(out[chunk:], "big") % n


def _confirm_and_key(
    suite: Suite,
    *,
    user_random: bytes,
    dev_random: bytes,
    X: bytes,
    Y: bytes,
    Z: bytes,
    V: bytes,
    w0: int,
) -> tuple[bytes, bytes, bytes]:
    """Return (user_confirm, dev_confirm, shared_key) from the transcript."""
    c = suite.curve
    context = _hash(suite.hash_name, PAKE_CONTEXT_TAG + user_random + dev_random)
    transcript = b"".join(
        _len8le(part)
        for part in (
            context,
            b"",
            b"",
            encode_point(c, suite.M),
            encode_point(c, suite.N),
            X,
            Y,
            Z,
            V,
            w0.to_bytes((c.n.bit_length() + 7) // 8, "big"),
        )
    )
    th = _hash(suite.hash_name, transcript)
    zero = b"\x00" * suite.digest_len
    mac_len = 16 if suite.cmac else suite.digest_len
    kc = _hkdf(suite.hash_name, th, salt=zero, info=b"ConfirmationKeys", length=2 * mac_len)
    shared = _hkdf(suite.hash_name, th, salt=zero, info=b"SharedKey", length=suite.digest_len)

    def mac(key: bytes, data: bytes) -> bytes:
        if suite.cmac:
            m = CMAC(algorithms.AES(key))
            m.update(data)
            return m.finalize()
        return hmac.new(key, data, suite.hash_name).digest()

    return mac(kc[:mac_len], Y), mac(kc[mac_len:], X), shared


@dataclass
class ClientShare:
    user_share: bytes
    user_confirm: bytes
    expected_dev_confirm: bytes
    shared_key: bytes


def spake2p_client(
    credentials: bytes,
    *,
    suite_type: int,
    salt: bytes,
    iterations: int,
    user_random: bytes,
    dev_random: bytes,
    dev_share: bytes,
) -> ClientShare:
    """Client ("prover") side of pake_share."""
    suite = get_suite(suite_type)
    c = suite.curve
    w0, w1 = derive_w(credentials, salt, iterations, suite)
    x = secrets.randbelow(c.n - 1) + 1
    X_pt = _add(c, _mul(c, x, c.G), _mul(c, w0, suite.M))
    Y_pt = decode_point(c, dev_share)
    Yp = _add(c, Y_pt, _neg(c, _mul(c, w0, suite.N)))
    Z_pt = _mul(c, x, Yp)
    V_pt = _mul(c, w1, Yp)
    X, Y = encode_point(c, X_pt), encode_point(c, Y_pt)
    user_confirm, dev_confirm, shared = _confirm_and_key(
        suite,
        user_random=user_random,
        dev_random=dev_random,
        X=X,
        Y=Y,
        Z=encode_point(c, Z_pt),
        V=encode_point(c, V_pt),
        w0=w0,
    )
    return ClientShare(X, user_confirm, dev_confirm, shared)


class Spake2pDevice:
    """Device ("verifier") side, used by the simulator and the tests."""

    def __init__(self, credentials: bytes, *, suite_type: int, salt: bytes, iterations: int):
        self.suite = get_suite(suite_type)
        c = self.suite.curve
        self.w0, w1 = derive_w(credentials, salt, iterations, self.suite)
        self.L = _mul(c, w1, c.G)
        self.y = secrets.randbelow(c.n - 1) + 1
        self.Y = encode_point(c, _add(c, _mul(c, self.y, c.G), _mul(c, self.w0, self.suite.N)))

    def finish(
        self, *, user_random: bytes, dev_random: bytes, user_share: bytes
    ) -> tuple[bytes, bytes, bytes]:
        """Return (expected_user_confirm, dev_confirm, shared_key)."""
        c = self.suite.curve
        X_pt = decode_point(c, user_share)
        Xp = _add(c, X_pt, _neg(c, _mul(c, self.w0, self.suite.M)))
        Z_pt = _mul(c, self.y, Xp)
        V_pt = _mul(c, self.y, self.L)
        return _confirm_and_key(
            self.suite,
            user_random=user_random,
            dev_random=dev_random,
            X=encode_point(c, X_pt),
            Y=self.Y,
            Z=encode_point(c, Z_pt),
            V=encode_point(c, V_pt),
            w0=self.w0,
        )


# --------------------------------------------------------------------------- #
# Password encodings requested by the device via ``extra_crypt``
# --------------------------------------------------------------------------- #


def md5_hex(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()  # noqa: S324 - protocol-mandated


def _sha1_hex(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()  # noqa: S324 - protocol-mandated


_CRYPT_ALPHABET = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _b64c(value: int, length: int) -> str:
    return "".join(_CRYPT_ALPHABET[(value >> 6 * i) & 0x3F] for i in range(length))


def _repeat(data: bytes, length: int) -> bytes:
    return (data * (length // len(data) + 1))[:length]


def md5_crypt(password: str, prefix: str) -> str | None:
    """glibc crypt() for a ``$1$`` prefix."""
    if not prefix.startswith("$1$"):
        return None
    salt = prefix[3:].split("$", 1)[0][:8]
    pw, sb = password.encode(), salt.encode()
    md5 = lambda d: hashlib.md5(d).digest()  # noqa: E731,S324
    alt = md5(pw + sb + pw)
    data = pw + b"$1$" + sb + _repeat(alt, len(pw))
    n = len(pw)
    while n:
        data += b"\x00" if n & 1 else pw[:1]
        n >>= 1
    final = md5(data)
    for i in range(1000):
        d = pw if i & 1 else final
        if i % 3:
            d += sb
        if i % 7:
            d += pw
        d += final if i & 1 else pw
        final = md5(d)
    order = ((0, 6, 12), (1, 7, 13), (2, 8, 14), (3, 9, 15), (4, 10, 5))
    enc = "".join(_b64c(final[a] << 16 | final[b] << 8 | final[c], 4) for a, b, c in order)
    return f"$1${salt}${enc}{_b64c(final[11], 2)}"


def sha256_crypt(password: str, prefix: str) -> str | None:
    """glibc crypt() for a ``$5$`` prefix (see akkadia.org/drepper/SHA-crypt.txt)."""
    if not prefix:
        return None
    spec = prefix[3:] if prefix.startswith("$5$") else prefix
    rounds: int | None = None
    if spec.startswith("rounds="):
        rp, _, spec = spec.partition("$")
        try:
            rounds = int(rp.split("=", 1)[1])
        except ValueError:
            rounds = 5000
    salt = spec.split("$", 1)[0][:16]
    if rounds is not None and rounds > MAX_CRYPT_ROUNDS:
        raise TpapCryptoError(f"Refusing crypt rounds {rounds}")
    rounds_spec = ""
    if rounds is not None:
        rounds = max(1000, rounds)
        rounds_spec = f"rounds={rounds}$"
    sha = lambda d: hashlib.sha256(d).digest()  # noqa: E731
    pw, sb = password.encode(), salt.encode()
    alt = sha(pw + sb + pw)
    data = pw + sb + _repeat(alt, len(pw))
    n = len(pw)
    while n:
        data += alt if n & 1 else pw
        n >>= 1
    final = sha(data)
    p = _repeat(sha(pw * len(pw)), len(pw))
    s = _repeat(sha(sb * (16 + final[0])), len(sb))
    for i in range(rounds or 5000):
        d = p if i & 1 else final
        if i % 3:
            d += s
        if i % 7:
            d += p
        d += final if i & 1 else p
        final = sha(d)
    order = (
        (0, 10, 20), (21, 1, 11), (12, 22, 2), (3, 13, 23), (24, 4, 14),
        (15, 25, 5), (6, 16, 26), (27, 7, 17), (18, 28, 8), (9, 19, 29),
    )  # fmt: skip
    enc = "".join(_b64c(final[a] << 16 | final[b] << 8 | final[c], 4) for a, b, c in order)
    return f"$5${rounds_spec}{salt}${enc}{_b64c(final[31] << 8 | final[30], 3)}"


def encode_passcode(extra_crypt: dict | None, username: str, passcode: str, mac: str) -> str:
    """Encode the account password the way the device's ``extra_crypt`` asks for."""
    plain = f"{username}/{passcode}" if username else passcode
    if not extra_crypt:
        return plain
    kind = str(extra_crypt.get("type") or "").lower()
    params = extra_crypt.get("params")
    if not isinstance(params, dict):
        return plain
    if kind == "password_shadow":
        pid = int(params.get("passwd_id", 0) or 0)
        prefix = str(params.get("passwd_prefix") or "")
        if pid == 1:
            return md5_crypt(passcode, prefix) or passcode
        if pid == 2:
            return _sha1_hex(passcode)
        if pid == 3:
            mac12 = mac.replace(":", "").replace("-", "")
            if username and len(mac12) == 12:
                pretty = ":".join(mac12[i : i + 2] for i in range(0, 12, 2)).upper()
                return _sha1_hex(md5_hex(username) + "_" + pretty)
            return passcode
        if pid == 5:
            return sha256_crypt(passcode, prefix) or passcode
        return passcode
    if kind == "password_authkey":
        tmp = str(params.get("authkey_tmpkey") or "")
        dic = str(params.get("authkey_dictionary") or "")
        if not (tmp and dic):
            return passcode
        out = []
        for i in range(max(len(tmp), len(passcode))):
            a = ord(passcode[i]) if i < len(passcode) else 0xBB
            b = ord(tmp[i]) if i < len(tmp) else 0xBB
            out.append(dic[(a ^ b) % len(dic)])
        return "".join(out)
    if kind == "password_sha_with_salt":
        name = "admin" if int(params.get("sha_name", -1)) == 0 else "user"
        salt = base64.b64decode(str(params.get("sha_salt") or "")).decode()
        return hashlib.sha256((name + salt + passcode).encode()).hexdigest()
    return plain


def default_passcode_from_mac(mac: str) -> str:
    """The factory passcode (passcode_type ``default_userpw``) derived from the MAC."""
    mb = bytes.fromhex(mac.replace(":", "").replace("-", ""))
    ikm = b"GqY5o136oa4i6VprTlMW2DpVXxmfW8" + mb[3:6] + mb[0:3]
    return (
        HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"tp-kdf-salt-default-passcode",
            info=b"tp-kdf-info-default-passcode",
        )
        .derive(ikm)
        .hex()
        .upper()
    )


# --------------------------------------------------------------------------- #
# Session cipher used after login for /stok=<id>/ds requests
# --------------------------------------------------------------------------- #

_CIPHERS = {
    "aes_128_ccm": (b"aes128", 16),
    "aes_256_ccm": (b"aes256", 32),
    "chacha20_poly1305": (b"chacha20", 32),
}


def normalize_cipher(name: str) -> str:
    return name.lower().replace("-", "_")


class SessionCipher:
    """AEAD with a per-request sequence number baked into the nonce."""

    TAG_LEN = 16

    def __init__(self, cipher: str, shared_key: bytes, start_seq: int):
        cipher = normalize_cipher(cipher)
        if cipher not in _CIPHERS:
            raise TpapCryptoError(f"Unsupported session cipher {cipher}")
        tag, key_len = _CIPHERS[cipher]
        self.cipher = cipher
        self.key = _hkdf(
            "sha256", shared_key,
            salt=b"tp-kdf-salt-" + tag + b"-key", info=b"tp-kdf-info-" + tag + b"-key",
            length=key_len,
        )  # fmt: skip
        self.base_nonce = _hkdf(
            "sha256", shared_key,
            salt=b"tp-kdf-salt-" + tag + b"-iv", info=b"tp-kdf-info-" + tag + b"-iv",
            length=12,
        )  # fmt: skip
        self.seq = start_seq

    def _aead(self):
        if self.cipher.startswith("aes_"):
            return AESCCM(self.key, tag_length=self.TAG_LEN)
        return ChaCha20Poly1305(self.key)

    def _nonce(self, seq: int) -> bytes:
        return self.base_nonce[:-4] + struct.pack(">I", seq)

    def seal(self, plaintext: bytes, seq: int) -> bytes:
        return struct.pack(">I", seq) + self._aead().encrypt(self._nonce(seq), plaintext, None)

    def open(self, payload: bytes) -> tuple[int, bytes]:
        if len(payload) < 4 + self.TAG_LEN:
            raise TpapCryptoError("Encrypted payload too short")
        seq = struct.unpack(">I", payload[:4])[0]
        return seq, self._aead().decrypt(self._nonce(seq), payload[4:], None)

    def next_request(self, plaintext: bytes) -> tuple[bytes, int]:
        seq = self.seq
        self.seq += 1
        return self.seal(plaintext, seq), seq
