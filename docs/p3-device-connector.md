# P3: the device connector

Phase 3 of the MQTT work is the device side: `pigeon`'s
`CONFIG_PIGEON_CONNECTOR_MQTT` and the `mqtt_init` sample in
`pigeon-examples`, speaking MQTT 3.1.1 over TLS to this broker. This is the
phase record, reconstructed from the two `mqtt-connector` branches and
re-verified from scratch on one workstation against the broker at `1bb93e8`:
every commit read, every requirement from `design.md` section 6, T10 and
T11 and the review findings the device plan carries mapped to the code that
satisfies it, and every acceptance criterion run again rather than taken from
the branch's own notes. The bench boards were not touched: the ESP32-C6 is
compile-verified only, by ruling (open question 6), and that is stated as
such below rather than folded into the green.

Verdict first: everything T10 and T11 ask for is in the branches and passes.
Two things are recorded as deviations from the design text rather than
defects, both cases of a later ruling superseding an earlier sentence, and
four things stay open by design, none of them blocking the merge.

## What landed

`~/pigeon`, branch `mqtt-connector`, eight commits on `c39e8c7`, in order:

| Commit | What it does |
|---|---|
| `660bf38` | Lifts PSK registration out of the CoAP connector into `src/pigeon_psk.{c,h}`: `pigeon_psk_register(sec_tag, identity, secret)`, both credential stores (`tls_credential_add` natively, `modem_key_mgmt_write` with the digest compare-before-write on `CONFIG_MODEM_KEY_MGMT` boards). `pigeon_coap_register_psk()` becomes a thin wrapper keeping its own latch. |
| `d9098e0` | Renames the WS push events to the connector-neutral `enum pigeon_event` / `pigeon_event_cb_t` (`include/pigeon.h`), keeping `enum pigeon_ws_event`, `PIGEON_WS_EVENT_*` and `pigeon_ws_event_cb_t` as aliases so existing consumers compile unchanged. |
| `d6c1ef3` | The pure decision layer `src/pigeon_mqtt_policy.{c,h}`: topic map, CONNACK classification (3.1.1 return codes and v5 reason codes in one function), the close-after-publish threshold, the backoff schedule and jitter, and the pending table that makes QoS 1 redelivery the connector's own. `tests/mqtt_policy`, 23 ztest cases on native_sim. |
| `43892cf` | The connector itself, `src/pigeon_mqtt.c` (1278 lines), plus `zephyr/Kconfig` (the connector choice entry, `PIGEON_MQTT_AUTH_CERT` / `_PSK`, and the session knobs), `pigeon.h` (`struct pigeon_mqtt_config`, `pigeon_mqtt_start/stop/connected`), `pigeon_core.c` (keeps `device_id`, dispatches the MQTT connector, registers the PSK eagerly on modem boards) and `pigeon_internal.h`. |
| `e4b6761` | Keeps the firmware fetch on HTTPS when the connector is MQTT: `pigeon_https.c` is compiled for an MQTT+FOTA build with its four connector hooks `#ifdef`'d out, the endpoint comes from the new `CONFIG_PIGEON_FOTA_HTTPS_ENDPOINT`, and both that and `CONFIG_PIGEON_TOKEN` are `BUILD_ASSERT`ed non-empty. `CONFIG_PIGEON_FOTA` now depends on `PIGEON_CONNECTOR_HTTPS || PIGEON_CONNECTOR_MQTT`. |
| `22c971a` | `CLAUDE.md`: the connector, and what it does differently. |
| `d8aa3bf` | Logs the negotiated TLS suite per session (`TLS_CIPHERSUITE_USED`), which is what closed the CCM8 question in P2. |
| `666c56d` | `CLAUDE.md`: batched telemetry does not reach the MQTT connector, and why that is a two-sided decision. |

`~/pigeon-examples`, branch `mqtt-connector`, thirteen commits on `e9b78cc`:

| Commit | What it does |
|---|---|
| `8fc87ec` | `samples/mqtt_init`: `main.c`, `shadow.c/h`, two connection managers (native_sim over NSOS connectivity-sim, ESP32-C6 WiFi), `boards/native_sim_native_64.conf` (TLS-PSK), `boards/esp32c6_devkitc_hpcore.conf` (certificate), the two cross-mode overlays, `cert/isrg-root-x2.pem`, `Kconfig` (`MQTT_INIT_PIGEON_ID`), `Kconfig.sysbuild`, `prj.conf`. |
| `89b4e0e` | `scripts/test/native-sim-e2e.sh` and `scripts/test/mock_dovecote.py`: the workstation end-to-end (real broker, real device build, mocked edge), asserting on what arrived at the platform's routes. |
| `4b07415`, `a0b3e76`, `ea91341`, `aa48478`, `227563b`, `c9dbac6`, `c2812e0`, `55ff5c8` | README and CLAUDE.md: the sample, its two modes, the e2e, the TLS 1.2 certificate defect the sample found in the broker, and the CCM8 record as it was corrected step by step (`0x00A8` is GCM; the block was OpenSSL's security level; the device negotiates `0xC0A8` once the broker relaxes it per hello). |
| `eab0ea1` | Drops the retracted CCM8 claim from the native_sim board conf comment (comment-only change). |
| `98b1bf8` | README: why `CONFIG_PIGEON_TELEMETRY_BATCH` is inert on an MQTT build. |

Only three of the thirteen touch code or scripts (`8fc87ec`, `89b4e0e`,
`eab0ea1`); the e2e driver has not changed since it was added.

## Requirement matrix

Sources: `design.md` section 6 (the device-side plan), T10 and T11 in
section 8, the ADR obligations that bind a device, and the review findings
section 6 says the connector work must carry (R1, R18, R20 as amended by
V3, N6). Evidence is file:line on the branch tips.

### T10, `~/pigeon`

| # | Requirement | Status | Evidence |
|---|---|---|---|
| 1 | `CONFIG_PIGEON_CONNECTOR_MQTT` in the `PIGEON_CONNECTOR_TYPE` choice, `select MQTT_LIB MQTT_LIB_TLS JSON_LIBRARY` | satisfied | `zephyr/Kconfig:33-38` (also selects `NET_CONTEXT_SNDTIMEO`, see 13) |
| 2 | `pigeon_shadow_get()` serves the latest retained target; the first call after connect waits on a semaphore up to a Kconfig timeout | satisfied | `src/pigeon_mqtt.c:1090-1124` (`pigeon_mqtt_shadow_sem`, `CONFIG_PIGEON_MQTT_SHADOW_WAIT_SEC`, `-EAGAIN` on timeout); Kconfig `zephyr/Kconfig:376-385` |
| 3 | `pigeon_shadow_report()` at QoS 1, returns after PUBACK | satisfied | `src/pigeon_mqtt.c:1126-1183`: `MQTT_QOS_1_AT_LEAST_ONCE`, returns only once `pigeon_mqtt_publish_report()` has seen the ack |
| 4 | `pigeon_transport_report_telemetry()` (section 6 text says QoS 1) | satisfied, with a deviation recorded below | `src/pigeon_mqtt.c:1185-1202`: QoS 0 by default, QoS 1 under `CONFIG_PIGEON_MQTT_TELEMETRY_QOS1` (`zephyr/Kconfig:328-347`). ADR B's "chosen per publish by the device" and the adopted R15 fast path are what the default follows |
| 5 | `pigeon_transport_upload_logs()` at QoS 1, binary payload | satisfied | `src/pigeon_mqtt.c:1204-1220`, chunked at `PIGEON_MQTT_LOG_CHUNK_MAX` (16 KiB, `:91`) to the broker's payload cap |
| 6 | Worker thread on the `pigeon_ws.c` pattern owning connect/reconnect with backoff, `mqtt_live()` keepalive and `mqtt_input()` polling | satisfied | `pigeon_mqtt_thread_fn` `src/pigeon_mqtt.c:842-943`; `pigeon_mqtt_service` `:458-486` (poll, `mqtt_input`, `mqtt_live`); backoff `:808-840` |
| 7 | Shadow-update callback in the `PIGEON_WS_EVENT_SHADOW_UPDATE` shape, surfaced connector-neutrally | satisfied | `include/pigeon.h:534-577` (`enum pigeon_event`, aliases for the WS names); delivered from `pigeon_mqtt_apply_shadow` `src/pigeon_mqtt.c:333-368` |
| 8 | `CONFIG_PIGEON_ENDPOINT` is `mqtts://host:8883`; `CONFIG_PIGEON_TOKEN` is the CONNECT password on certificate builds and may be empty on PSK builds | satisfied | `pigeon_mqtt_parse_endpoint` `src/pigeon_mqtt.c:231-296` (refuses any scheme but `mqtts`, refuses a path); password set only under `CONFIG_PIGEON_MQTT_AUTH_CERT` `:600-607`; `pigeon_core.c:215-226` requires the token only on HTTPS and cert-mode MQTT |
| 9 | Client id and username are `pigeon_config.device_id` | satisfied | `src/pigeon_mqtt.c:585-597`; `pigeon_core.c:109-117` keeps the id; `pigeon.h:86-97` documents why it is load-bearing here |
| 10 | TLS through a sec tag: an app-provisioned CA, or the PSK pair registered by the library through the CoAP helper generalised into core, `modem_key_mgmt` branch included | satisfied | `src/pigeon_psk.c` (both stores), `pigeon_mqtt_register_psk` `src/pigeon_mqtt.c:202-228`, eager modem registration `pigeon_core.c:255-269`; `CONFIG_PIGEON_MQTT_SEC_TAG` `zephyr/Kconfig:286-294` |
| 11 | Transport lock discipline (`pigeon_transport_lock`) kept for the handshake | satisfied | `src/pigeon_mqtt.c:633-660`: the lock covers exactly `mqtt_connect()`, bounded rather than `K_FOREVER` |
| 12 | R1: redelivery is the connector's own; on any close before PUBACK republish from the pending store with `dup_flag`; repeated close-after-publish is a long-backoff condition | satisfied | pending table `src/pigeon_mqtt_policy.c:80-170`; `pigeon_mqtt_pending_session_lost` sets `dup`; republish loop `src/pigeon_mqtt.c:945-1088`; `unacked_closes` counted in `pigeon_mqtt_teardown` `:763-800` and `PIGEON_MQTT_UNACKED_CLOSES_PERSISTENT` (3) switches to `CONFIG_PIGEON_MQTT_AUTH_BACKOFF_SEC` in `pigeon_mqtt_backoff_after` `:824-840`; tested in `tests/mqtt_policy/src/main.c` |
| 13 | R18: send-timeout socket option from the start | satisfied | `SO_SNDTIMEO` 10 s `src/pigeon_mqtt.c:671-683`; `select NET_CONTEXT_SNDTIMEO` `zephyr/Kconfig:38` |
| 14 | N6: `CONFIG_MQTT_KEEPALIVE` deliberate per target | satisfied | the library documents the obligation in the connector's help text `zephyr/Kconfig:57-61`; the sample sets it explicitly with the reasoning `samples/mqtt_init/prj.conf:20-26` |
| 15 | N6: `CONFIG_PIGEON_LOG_UPLOAD` `depends on` extended to the MQTT connector | satisfied | `zephyr/Kconfig:447` |
| 16 | R18: `CONFIG_MBEDTLS_SSL_MAX_CONTENT_LEN` minded against the broker's 4096-byte max send fragment, the chain and the largest retained shadow | satisfied | native_sim 7168 (`boards/native_sim_native_64.conf:39-43`), ESP32-C6 8192 (`boards/esp32c6_devkitc_hpcore.conf:104-109`); the connector's own payload buffer is `2 * CONFIG_PIGEON_SHADOW_CONFIG_MAX + 512` (`src/pigeon_mqtt.c:84`) |
| 17 | FOTA download transport factored so an MQTT+FOTA build compiles | satisfied, and built here | `e4b6761`; an MQTT+FOTA ESP32-C6 build was compiled in this verification (below) with `pigeon_https.c` and `pigeon_fota.c` in the link |
| 18 | Unit tests where the CoAP connector has them | satisfied | `tests/mqtt_policy`, 23 cases, the same pure-layer split as `tests/coap_udp` |
| 19 | Acceptance: builds for native_sim and C6 | satisfied | below: native_sim both modes (run, not only built), ESP32-C6 cert, PSK and MQTT+FOTA |

### T11, `~/pigeon-examples`

| # | Requirement | Status | Evidence |
|---|---|---|---|
| 20 | `samples/mqtt_init` with two board targets on the `coap_dtls_init` board-conditional pattern: native_sim PSK, C6 cert | satisfied | `samples/mqtt_init/CMakeLists.txt:51-60` selects the connection manager by board; `boards/native_sim_native_64.conf:9`, `boards/esp32c6_devkitc_hpcore.conf:10` |
| 21 | C6: connection manager and PSA/TLS Kconfig from `wifi_init`; mbedTLS configured for the pinned ECDSA chain, P-256 + P-384, peer verification required, hostname set (R20, V3) | satisfied | `boards/esp32c6_devkitc_hpcore.conf:70-102` (ECDHE-ECDSA, both curves, both hashes, no RSA want); `TLS_PEER_VERIFY_REQUIRED` + `hostname` `src/pigeon_mqtt.c:614-620`; the built `.config` has no `MBEDTLS_RSA` or `PSA_WANT_*RSA*` symbol set |
| 22 | Trust anchor: ISRG Root X2 (ADR D as amended by V3; section 6 still says X1, see deviations) | satisfied | `samples/mqtt_init/cert/isrg-root-x2.pem` (self-signed X2, SHA-256 fingerprint `69:72:9B:8E...CB:14:70`), provisioned in `src/net/wifi_connection_manager.c:17-42`; `-DPIGEON_MQTT_CA_FILE` repoints it (`CMakeLists.txt:20-32`) |
| 23 | `scripts/test/native-sim-e2e.sh` drives native_sim against a local broker + mock dovecote | satisfied | `scripts/test/native-sim-e2e.sh`, `scripts/test/mock_dovecote.py` |
| 24 | Acceptance: e2e script green | satisfied | both modes, re-run here (below) |
| 25 | Acceptance: C6 hardware run | deferred by ruling | open question 6: the bench C6 waits behind loft's Phase 6 CoAP regression pass; no hardware was touched in this verification |

### Design obligations that bind a device

| # | Requirement | Status | Evidence |
|---|---|---|---|
| 26 | ADR C: topics exactly `pigeon/telemetry`, `pigeon/shadow/report`, `pigeon/logs` out, `pigeon/shadow/target` in; no pigeon id | satisfied | `src/pigeon_mqtt_policy.h:26-29`; the e2e's mock saw the shadow and logs routes, telemetry as device-socket frames, and nothing else, and the retained target arrived |
| 27 | ADR D: certificate session is `username` = pigeon id, `password` = token, `client_id` = pigeon id; PSK session is identity = pigeon id, key = UTF-8 bytes of the secret, username equal to the identity, no password | satisfied | `src/pigeon_mqtt.c:585-607`; PSK identity is the same `device_id` string by construction (`samples/mqtt_init/src/main.c:31`, `:57-58`), and the library deliberately has no separate identity symbol (`zephyr/Kconfig:319-324`) |
| 28 | ADR B: the first-party connector never sends QoS 2; SUBSCRIBE at QoS 1 | satisfied | only `MQTT_QOS_0_AT_MOST_ONCE` / `MQTT_QOS_1_AT_LEAST_ONCE` appear in `src/pigeon_mqtt.c`; subscribe `:724-736` |
| 29 | ADR D: no cleartext, ever | satisfied | `mqtt://` refused at parse time `src/pigeon_mqtt.c:243-253`; `MQTT_TRANSPORT_SECURE` `:597` |
| 30 | Section 5: a 3.1.1 device under the fuse sees only close-after-publish and must treat repeats as long backoff | satisfied | item 12 |
| 31 | ADR C: a device's own report-back must not read as fresh config | satisfied, and needed | `pigeon_shadow_report()` folds the acknowledged `current_version`/`current_config` into the cached shadow (`src/pigeon_mqtt.c:1160-1182`); without it the sample re-applied the same target every pass |
| 32 | ADR C: firmware has no MQTT surface; the device fetches over HTTPS with its bearer token | satisfied | item 17 |
| 33 | Section 6: nRF91 modem-store PSK write path exists but is not yet hardware-verified | carried, still unverified | `src/pigeon_psk.c:17-128` is the same code the CoAP connector had; no nRF91 MQTT sample and no modem bench time in this phase |

Counts: 33 rows; 31 satisfied, 1 deferred by ruling (25), 1 carried
unverified by the design's own statement (33). Nothing missing. Two of the
satisfied rows (4, 22) carry a deviation from the design text, recorded
below.

## Verification

Everything in this section was run for this record, not copied from the
branch notes. Workstation: the same one P1 and P2 used; Zephyr SDK from the
`pigeon-examples` west workspace (`west-vanilla.yml`), broker built from
`~/pigeonhole` at `1bb93e8`.

### Host test harness

All six `~/pigeon/tests/*` suites, built for `native_sim/native/64` and run,
at the branch tip:

| Suite | Cases | Result |
|---|---|---|
| `coap_udp` | 17 | pass |
| `fota_attempts` | 18 (two ztest suites, 9 + 9) | pass |
| `fota_resume` | 14 (two ztest suites, 9 + 5) | pass |
| `http_status` | 10 | pass |
| `telemetry_batch` | 24 | pass |
| `mqtt_policy` (new) | 23 | pass |

**106 / 106**, 0 failed, 0 skipped. `main` has 83; the branch adds 23.

### native_sim against the broker

`scripts/test/native-sim-e2e.sh`, unmodified, once per mode. Each run
builds the broker, starts the mock edge on 8788 and the broker on 8883
(TLS, dev CA), builds `mqtt_init` for `native_sim/native/64` with the mode's
overlay, runs it, and asserts on the mock's recorded state.

| Step | PSK mode | Certificate mode |
|---|---|---|
| session up | ok, `MQTT TLS ciphersuite: 0xc0a8` | ok, `MQTT TLS ciphersuite: 0xc02b` |
| broker: session accepted | `version="3.1.1" keep_alive=60 clean_start=false transport="psk"` | same, `transport="certificate"` |
| retained target delivered unasked, applied | `Target shadow received: target_version 1`, `Applied shadow v1` at t+1.09 s | same at t+1.12 s |
| shadow report reached its route | 1 (`POST .../shadow`, bearer present) | 1 |
| telemetry reached the platform | 2, as `telemetry` frames on the held device socket (QoS 0 path) | 2 |
| log chunk reached its route | 1 (`POST .../logs`, `application/octet-stream`) | 1 |
| config push mid-session (v2) applied and reported converged | `Applied shadow v2`, `current_version: 2` at the mock | same |
| broker killed and restarted under the device | reconnected, second session `0xc0a8` again | reconnected, `0xc02b` again |
| final | `PASS (psk mode)`; upgrades 2, refused 0, shadow 2/2 | `PASS (cert mode)`; upgrades 2, refused 0, shadow 2/2 |

So the two suites the P2 record names for the device (`0xC0A8`,
`TLS_PSK_WITH_AES_128_CCM_8`, and `0xC02B`,
`TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`) are what this tree negotiates
today, twice per run, initial connect and post-restart reconnect.

One incidental observation, worth keeping because it exercised a path the
design asked for: with the endpoint written as `mqtts://localhost:8883` the
resolver returns `::1` first and the broker binds `127.0.0.1`, so the first
candidate refuses (`-111`) and the connector walks to the second. That is
the address-list walk `src/pigeon_mqtt.c:121-129` describes, seen for real.

### The exchange, packet by packet

A separate run of the same PSK build with the broker at `debug` and the
mock verbose, to record the sequence rather than only the outcome. The
pigeon id is a fixed fake test identity from the e2e script, elided here.

The three vantage points, merged in order (device uptime on the left; the
mock's request log and the broker's session line are the platform's view):

```
device  00:00:01.070  net_mqtt: Connect completed                (TLS up, CONNECT sent)
mock                  GET /internal/device-psk/<pigeon>  200     (PSK resolved mid-handshake)
mock                  GET /device/pigeons/<pigeon>/ws    101     (the upgrade IS the auth; snapshot seeds the retained target)
broker  15:51:15.111  session accepted version="3.1.1" keep_alive=60 clean_start=false transport="psk"
device  00:00:01.070  pigeon: MQTT TLS ciphersuite: 0xc0a8       (TLS_PSK_WITH_AES_128_CCM_8)
device  00:00:01.090  pigeon: MQTT session up                    (CONNACK 0, SUBACK for pigeon/shadow/target)
device  00:00:01.090  pigeon: Target shadow received: target_version 1   (retained PUBLISH, unasked)
device  00:00:01.090  shadow: Applied shadow v1: log=false telemetry_interval=15
mock                  frame {"type":"telemetry","metrics":{"reset_cause":"8","uptime_s":"1","poll_count":"1"}}   (QoS 0 -> device-socket frame)
mock                  POST /device/pigeons/<pigeon>/shadow  200  (QoS 1 -> PUBACK)
device  00:00:01.140  shadow: Reported current_config back to platform at v1
mock                  POST /device/pigeons/<pigeon>/logs    200  (dictionary-log chunk, 1450 B, QoS 1)
mock                  POST /_control/shadow                      (the dashboard's half: target v2)
device  00:00:10.010  pigeon: Target shadow received: target_version 2   (pushed retained value)
device  00:00:10.010  shadow: Applied shadow v2: log=true telemetry_interval=20
mock                  POST /device/pigeons/<pigeon>/shadow  200  (current_version 2 reported back)
device  00:00:10.060  shadow: Reported current_config back to platform at v2
broker  15:51:35.050  stopped summary=... accepted=1 refused=0 publishes=4 publish_errors=0 pushes=2
```

Mock state at the end: 1 upgrade, 0 refusals; four device-route calls
(shadow, logs, shadow, logs), every one with a bearer token, JSON on the
shadow route and `application/octet-stream` on the logs route; three
telemetry frames on the held socket and no telemetry POST, which is the QoS
0 fast path working as adopted; shadow `target_version 2 / current_version
2` with `current_config` `{"log": true, "telemetry_interval": 20, "reboot":
false}`. Every byte the device sent arrived on the route the topic map says
it should, with the token the broker resolved from the PSK identity.

The device's own MQTT packet trace was not captured: Zephyr's `net_mqtt`
debug lines compile in under `CONFIG_MQTT_LOG_LEVEL_DBG` but did not reach
the console in this build, and chasing that was not worth the time against
three independent observers agreeing.

### ESP32-C6, compile only

`esp32c6_devkitc/esp32c6/hpcore`, `west build -p`, no hardware:

| Build | Result | FLASH (irom) | SRAM |
|---|---|---|---|
| certificate mode (board default) | ok | 538,320 B, 6.42 % of irom0 (800,244 B, 9.54 % of FLASH) | 306,688 B, 60.20 % |
| PSK mode (`overlay-psk-native-tls.conf`) | ok | 549,536 B, 6.55 % (800,676 B, 9.55 %) | 306,800 B, 60.22 % |
| MQTT + FOTA (cert mode plus `CONFIG_PIGEON_FOTA=y`, MCUboot/IMG_MANAGER/NVS/SETTINGS, `CONFIG_PIGEON_FOTA_HTTPS_ENDPOINT` and a placeholder token) | ok | 802,228 B, 9.56 % of FLASH | 299,584 B, 61.27 % (smaller region under the MCUboot layout) |

The MQTT+FOTA `.config` shows `CONFIG_PIGEON_FOTA=y`, `CONFIG_HTTP_CLIENT=y`,
`CONFIG_PIGEON_HTTPS_SEC_TAG=2` beside `CONFIG_PIGEON_MQTT_SEC_TAG=1`, and
`pigeon_https.c` and `pigeon_fota.c` in the link where the plain cert build
has neither. That is the acceptance for item 17 done, not assumed. The cert
build's `.config` has every `PSA_WANT_*RSA*` and `MBEDTLS_RSA*` symbol unset:
the all-ECDSA anchoring does what R20 wanted from it.

### Every commit builds on its own

Each of the eight `pigeon` commits was checked out in its own worktree and
built against the branch-tip samples for `native_sim/native/64`:
`coap_dtls_init` (the CoAP UDP transport, which the PSK lift touched),
`ws_init` (the HTTPS connector plus the WS channel, which the event rename
touched), `mqtt_init` from the commit that adds the connector onward, and
every `tests/*` suite present at that commit, built and run.

| Commit | `coap_dtls_init` | `ws_init` | `mqtt_init` | `tests/*` built and run |
|---|---|---|---|---|
| `660bf38` (PSK lift) | ok | ok | n/a | 5 suites, all pass |
| `d9098e0` (event rename) | ok | ok | n/a | 5 suites, all pass |
| `d6c1ef3` (policy layer + tests) | ok | ok | n/a | 6 suites, all pass |
| `43892cf` (the connector) | ok | ok | ok | 6 suites, all pass |
| `e4b6761` (FOTA on HTTPS) | ok | ok | ok | 6 suites, all pass |
| `22c971a` (docs) | ok | ok | ok | 6 suites, all pass |
| `d8aa3bf` (suite log line) | ok | ok | ok | 6 suites, all pass |
| `666c56d` (docs (tip)) | ok | ok | ok | 6 suites, all pass |

67 build-or-run cells, 67 green. (`mqtt_init` is n/a before the commit that
adds the connector; `tests/mqtt_policy` appears at `d6c1ef3`.)

The three code-bearing `pigeon-examples` commits were built the same way
from their own worktrees against `pigeon` at the branch tip:

| Commit | Target | Result |
|---|---|---|
| `8fc87ec` (the sample as first committed) | `mqtt_init`, `native_sim/native/64` | ok |
| `8fc87ec` | `mqtt_init`, `esp32c6_devkitc/esp32c6/hpcore` | ok, 306,688 B SRAM (60.20 %) |
| `eab0ea1` (board-conf comment) | `mqtt_init`, `native_sim/native/64` | ok |
| `98b1bf8` (branch tip) | `mqtt_init`, `native_sim/native/64` | ok |

`89b4e0e` adds only the two scripts, which are the ones every e2e run above
executed unchanged.

## Deviations from the design text

Neither is a defect; both are the design being ahead of one of its own
sentences.

- **Telemetry QoS.** Section 6 lists `pigeon_transport_report_telemetry()`
  as QoS 1. The connector publishes telemetry at QoS 0 by default and at
  QoS 1 under `CONFIG_PIGEON_MQTT_TELEMETRY_QOS1`. ADR B says QoS is
  "chosen per publish by the device", and the adopted R15 fast path (a QoS
  0 publish rides the held device socket as a frame, one DO write, no
  Worker request) is the cheaper report by design; the section 6 wording
  predates R15. The trade is stated in the option's help text, including
  the cross-class ordering caveat P2 measured live. Shadow reports and log
  chunks are always QoS 1. If the owner wants QoS 1 telemetry as the
  shipped default, it is one Kconfig default, not a code change.
- **Trust anchor.** Section 6 says "trust anchor ISRG Root X1"; ADR D as
  amended by V3, and open question 7 as ruled, say the device anchors X2
  with P-256 + P-384 only. The sample anchors X2. The section 6 sentence is
  the stale one.

## Open, by design

- **The ESP32-C6 hardware run** (T11's second acceptance, section 7's
  "then the C6"). Deferred by open question 6 until loft's Phase 6 CoAP
  regression pass has had the board; reflashing is routine and
  pre-approved either way. The three C6 images above are what would be
  flashed.
- **The nRF91 modem-store PSK path** stays as section 6 states it: the
  code exists (`pigeon_psk.c`, unchanged from the CoAP connector's copy)
  and is not hardware-verified. There is no nRF91 MQTT sample; the first
  cellular MQTT build is where that gets its bench time.
- **Batched telemetry does not reach this connector.**
  `CONFIG_PIGEON_TELEMETRY_BATCH` still depends on the HTTPS connector, so
  an MQTT build sends the flat report it is specified to send. Extending it
  is a two-sided decision because of the QoS 0 frame path (the broker wraps
  a QoS 0 payload as `{"type":"telemetry","metrics":<payload>}`, so a
  batched body would nest under `metrics`). Recorded in both repos'
  documentation; not a P3 item.
- **PSK mode against staging** is unreachable for the same reason P2
  recorded: the internal credential route's source allowlist is empty for
  staging. PSK is proven against the mock here and against the broker's own
  admission tests, and stays on the production bring-up checklist.

## Small things noticed on the way, not fixed here

- `include/pigeon.h:331`, the `pigeon_shadow_get()` note, says `-ENOTCONN` "means
  the session is down"; the code returns `-ENOTCONN` only when the session
  was never started, and serves the last retained value while a started
  session is reconnecting. The behaviour is the better one (a polling app
  keeps its config across a blip); the sentence is loose.
- The `pigeon-examples` README's MQTT section still narrates PSK mode as
  landing on `0x00A8` before saying, a few paragraphs later, that it now
  lands on `0xC0A8`. Accurate as history, and the commits that corrected it
  are the reason it reads that way.

## Merge record

Both repositories were fast-forwarded locally after the matrix above came
back green; nothing was pushed.

| Repository | Before | After | How |
|---|---|---|---|
| `~/pigeon` | `main` at `c39e8c7` | `main` at `666c56d` | `git merge --ff-only mqtt-connector` |
| `~/pigeon-examples` | `main` at `e9b78cc` | `main` at `98b1bf8` | `git merge --ff-only mqtt-connector` |

A fast-forward rather than a merge commit because that is the shape both
histories already have: linear, with a single genuine merge each from a
branch that had diverged, and `main` had not moved under either of these.
No commit was amended or rewritten.
