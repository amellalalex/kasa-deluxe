# python-kasa-deluxe

Local control, energy logging and a web dashboard for the Kasa **KP125M** smart plug
(and other TP-Link plugs that only speak the newer **TPAP** login), without the cloud
and without the Kasa app.

Stock `python-kasa` can't log in to a KP125M on firmware 1.4.x. That firmware dropped
the KLAP/AES handshakes and only accepts TPAP (a SPAKE2+ password exchange). This
project has its own TPAP client and puts a server around it:

- **Control:** on, off, toggle, a countdown timer, schedules, nickname, LED mode,
  auto-off, overload cutoff, power-on behaviour and reboot.
- **Live readings:** power (W), voltage, current, today's and this month's energy,
  runtime and Wi-Fi RSSI, polled every few seconds and pushed to the browser over
  server-sent events.
- **History:** every reading goes into SQLite. You get charts from 15 minutes to
  30 days and a CSV export. The plug's own on-board hourly, daily and monthly energy
  counters are also shown.
- **API:** a REST API with OpenAPI docs at `/docs`, an SSE stream at `/api/stream`
  and Prometheus metrics at `/metrics`. A `/raw` endpoint lets you call any SMART
  method the plug supports.
- **Safety:** if the plug rejects the password, polling stops instead of retrying.
  A few bad attempts lock the plug, so this matters. Login is also refused before
  any password is sent if the plug reports a different owner account.
- **Simulator:** a fake KP125M that speaks TPAP, so you can develop and test without
  the hardware.

## Setup

```bash
python -m venv .venv
.venv/Scripts/pip install -e .[dev]        # Windows; use .venv/bin/pip elsewhere
cp config.example.toml config.toml        # then edit it
```

In `config.toml`, put in the plug's IP and **your TP-Link (Kasa app) account email and
password**. The KP125M checks them locally against the account it was set up with.
Credentials can also come from `KASA_USERNAME` and `KASA_PASSWORD`.

The machine running the server must be able to reach the plug on TCP port 80. That
usually means the same LAN or VLAN. Give the plug a DHCP reservation so its IP doesn't
change.

```bash
kasadeluxe discover --host 192.168.1.50   # no password needed; shows TPAP params + owner hash
kasadeluxe info                         # logs in using config.toml
kasadeluxe power
kasadeluxe off
kasadeluxe raw get_wireless_scan_info
kasadeluxe serve                        # http://127.0.0.1:8125
```

Before you put the server on your network (`bind = "0.0.0.0"`), set `token`. The UI
asks for the token once and remembers it in that browser.

### Running it permanently

To run it permanently, use any process supervisor that runs `kasadeluxe serve` from
the project directory: a systemd unit, NSSM or Task Scheduler on Windows, or a
container. It uses very little memory and CPU. At the default 5-second poll, the
database grows by about 1.5 MB per day, and `keep_days` caps it.

## API

The full schema is at `http://host:8125/docs`. Each `{id}` is a device id from
`config.toml`.

| Method | Path | |
|---|---|---|
| GET | `/api/devices`, `/api/devices/{id}` | status, last reading, device info |
| POST | `/api/devices/{id}/power` `{"on": true}` · `/toggle` | relay |
| GET | `/api/devices/{id}/history?hours=24&points=300` | bucketed avg/peak W, V, A + Wh used |
| GET | `/api/devices/{id}/history.csv?hours=24` | raw samples |
| GET | `/api/devices/{id}/energy-history?period=day\|month\|year` | plug's on-board counters |
| GET | `/api/devices/{id}/usage` | 7/30-day energy and runtime, price config |
| GET | `/api/devices/{id}/settings` | LED, auto-off, protection, timers, schedules, firmware, Matter code |
| PUT | `/led` `{"rule":"always\|night_mode\|never"}` · `/auto-off` `{"enable","delay_min"}` · `/protection` `{"enabled","threshold_w"}` · `/name` · `/default-state` | settings |
| POST/DELETE | `/countdown` `{"seconds","on"}` | one-shot timer |
| GET/POST | `/schedules` `{"minute_of_day","on","week_days"}` | `week_days` bitmask, bit0 = Sunday |
| PATCH/DELETE | `/schedules/{rule_id}` `{"enabled"}` | |
| POST | `/reboot`, `/reconnect` (optionally `{"username","password"}`), `/raw` `{"method","params"}` | |
| GET | `/api/stream` | SSE: `{"device","kind":"sample\|status\|summary","data"}` |
| GET | `/metrics` | `kasa_power_watts`, `kasa_voltage_volts`, `kasa_relay_on`, `kasa_up`, ... |

## Matter

The KP125M is also a Matter device. Its pairing code is shown on the dashboard (from
`get_matter_setup_info`). With it you can add the plug to Home Assistant, Apple Home or
Google Home **in parallel** with this server, since Matter allows multiple controllers.
Over Matter the plug exposes on/off and basic electrical measurement. The local TPAP
API has more: on-board energy history, schedules, protection and LED settings. That's
why this project uses TPAP and doesn't act as a Matter controller itself.

## Development

```bash
.venv/Scripts/python -m pytest -q
.venv/Scripts/python -m kasadeluxe.simulator --port 9999 --username me@example.com --password secret
```

To point the server at the simulator, add `host = "127.0.0.1"` and `port = 9999` to a
device and use the same credentials. The simulator runs the device side of the
protocol with the same crypto module. That makes it good for testing the client logic
end to end, but it doesn't prove interoperability with real firmware.

### How TPAP works

1. `POST /` `{"method":"login","params":{"sub_method":"discover"}}` returns the
   supported PAKE types, the MAC and an MD5 of the owner's email.
2. `pake_register` sends the client random and the md5("admin") username. The plug
   returns its random, PBKDF2 salt and iterations, its SPAKE2+ share and the cipher
   suite, plus an optional `extra_crypt` telling the client how to hash the password
   first.
3. `pake_share` sends the client share and confirmation. The plug returns its own
   confirmation, a `stok` and a starting sequence number.
4. Requests then go to `POST /stok=<stok>/ds` as `seq (4 bytes BE) || AEAD(json)`,
   using AES-CCM or ChaCha20-Poly1305 with a key and nonce derived by HKDF from the
   SPAKE2+ shared secret.

## Credits and license

The TPAP handshake is based on work by ZeliardM in python-kasa
[PR #1592](https://github.com/python-kasa/python-kasa/pull/1592), with background from
[python-kasa#1590](https://github.com/python-kasa/python-kasa/issues/1590) and
[kasa-rs#20](https://github.com/cmackenzie1/kasa-rs/pull/20). python-kasa is
GPL-3.0, so this project is released under **GPL-3.0-or-later**.

This project isn't affiliated with TP-Link.
