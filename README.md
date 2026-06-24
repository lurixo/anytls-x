# anytls-x

`anytls-x` is an enhanced fork of [`sing-anytls`](https://github.com/anytls/sing-anytls), the Go
implementation of the AnyTLS proxy protocol. It keeps the AnyTLS wire framing but bakes three
capabilities into the source — **session resilience**, **TLS record-level traffic shaping**, and a
**0-RTT rail-switch migration** — and is consumed by sing-box as the `anytls-x` inbound/outbound type.

- **Module:** `github.com/lurixo/anytls-x`
- **Package:** `anytlsx`
- **Upstream baseline:** [anytls/sing-anytls](https://github.com/anytls/sing-anytls) `v0.0.11` (verbatim), with the three capabilities applied on top.

> **⚠️ Breaking change — not drop-in with stock `anytls-go`.** The [record shaper](#record-shaper)
> replaces the upstream padding system on the wire and is **always on**: the client advertises `rs=1`
> in its settings and an `anytls-x` server rejects a client that does not with `cmdAlert`
> (`client does not support record shaper, please upgrade`). Run `anytls-x` on **both** ends. The
> AnyTLS framing is otherwise unchanged. The [migration](#0-rtt-rail-switch-migration) rail-switch is
> **on by default** (TLS flows only); set `migration: false` to keep everything on the multiplex.

---

## sing-box configuration

`anytls-x` is registered in sing-box as the `anytls-x` inbound/outbound type (config `"type": "anytls-x"`).
It accepts the standard AnyTLS options (`users`, `password`, `idle_session_check_interval`,
`idle_session_timeout`, `min_idle_session`, `padding_scheme`) plus the tuning and migration fields below.
The stock `anytls` type continues to track unmodified upstream `sing-anytls`, so a build can offer both.

### Outbound options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `handshake_timeout` | duration | `5s` | The outbound TLS dial runs under this context timeout, so a stalled handshake fails fast instead of hanging on the dialer. |
| `max_session` | int | `0` (unlimited) | Soft upper bound on concurrent underlying sessions (TLS connections). When `> 0` and reached, new streams multiplex onto the least-loaded existing session; if none can accept the stream a new one is dialed anyway, so the bound is a target, not a hard limit. |
| `heartbeat_interval` | duration | `15s` | Idle liveness-probe cadence (±25 % jitter); also the application-layer keepalive period. See [Idle session heartbeat](#idle-session-heartbeat). |
| `heartbeat_quiet_window` | duration | `10s` | Skip the probe if a `cmdHeartResponse` arrived within this window; must be `< heartbeat_interval`. |
| `heartbeat_timeout` | duration | `5s` | How long to wait for the reply after a probe before declaring the session dead. |
| `migration` | bool | `true` | The [0-RTT rail-switch](#0-rtt-rail-switch-migration) for this endpoint, **on by default**. Set `false` to disable; `ANYTLS_MIGRATION=1` forces it on regardless. |

```json
{
  "type": "anytls-x",
  "server": "example.com",
  "server_port": 443,
  "password": "your-password",
  "handshake_timeout": "5s",
  "max_session": 4,
  "heartbeat_interval": "15s",
  "heartbeat_quiet_window": "10s",
  "heartbeat_timeout": "5s",
  "migration": true,
  "tls": { "enabled": true, "server_name": "example.com" }
}
```

### Inbound options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `padding_scheme` | []string | built-in | Record-shaper scheme, one key per element. See [padding_scheme configuration](#padding_scheme-configuration). |
| `migration` | bool | `true` | The rail-switch for this endpoint, **on by default**. Set `false` to disable. |
| `migration_min_bulk_bytes` | int | `0` (→ `65536`) | Post-handshake byte threshold a flow must cross before it migrates. `0` uses the built-in `65536` (64 KB); a non-zero value below the `2048`-byte floor is clamped up to it. |
| `migration_tls_only` | bool | `true` | **On by default** — only TLS flows migrate; opaque flows (UoT-UDP, plaintext, …) stay on the shaped multiplex (a non-TLS bulk flow on the dedicated connection is not record-shaped and would expose its inner datagram sizing). Set `false` to also migrate opaque flows. |

```json
{
  "type": "anytls-x",
  "listen": "::",
  "listen_port": 443,
  "users": [{ "name": "user", "password": "your-password" }],
  "padding_scheme": [
    "pad_dist=35-35:100",
    "pad_targets=14,14,17,17,17,45,22-30",
    "headers_target=90-140",
    "wnd_update_interval=131072"
  ],
  "migration": true,
  "migration_min_bulk_bytes": 65536,
  "migration_tls_only": true,
  "tls": { "enabled": true, "certificate_path": "fullchain.pem", "key_path": "privkey.pem" }
}
```

---

## Session resilience and connection safety

Session-pool resilience, connection safety, protocol robustness, and per-stream timeouts — everything
in the library except the record shaper. Touches `client.go`, `service.go`,
`session/{client,frame,session,stream}.go`, and `util/`.

### Session resilience

Keeps the session pool healthy across connection failures and network changes.

When `OpenStream` fails on a reused idle session (e.g. the pooled connection was reset), the error is
caught and a fresh session is created instead of being propagated.

`Reset()` on the client closes all sessions (idle and active) without cancelling the client context, so
new sessions can still be created afterward; sing-box calls it on network-interface changes
(`InterfaceUpdated`). Data-frame writes hold `connLock` with no write deadline, so on a half-open
connection (the typical state just after a network change) a plain `Close()` can block on `connLock`
until the kernel's TCP retransmit timeout (minutes). `Reset()` therefore sets `SetWriteDeadline` in the
past on every connection first — interrupting any in-flight write and releasing `connLock` promptly —
then closes the sessions asynchronously, so one stuck connection blocks neither the others nor the
network-change callback.

`getIdleSession` and `idleCleanupExpTime` check `IsClosed()` and `connBroken`: `getIdleSession` loops
past closed sessions instead of handing one back, and `idleCleanupExpTime` removes closed sessions
before applying timeout and `min_idle_session` logic. This keeps a silently-dead session (NAT timeout,
carrier drop) from being handed to the next request, and is needed because with `min_idle_session >= 1`,
`idleCleanupExpTime` resets `idleSince` on the last remaining session every cycle, so a dead session is
never reaped by timeout alone. `idleCleanupExpTime` also unpools any session that still has active
streams (`activeStreams > 0`), so a session briefly multiplexed onto while idle — possible under the
`max_session` cap — is never torn down by the idle timer with a live stream on it.

### Idle session heartbeat

A client-side liveness probe that detects a silently-dead pooled session **before** a request reuses it
— the case that otherwise leaves the request blocked on the 5-second per-stream SYNACK timeout, repeated
on every reuse of the pinned session when `min_idle_session >= 1`. The passive `IsClosed` / `connBroken`
checks above only catch a session already marked dead by a failed write; a connection dropped silently
while idle (NAT / carrier timeout) has had no write to fail, so it needs an active probe.

Each client session runs a background `heartbeatLoop` after the handshake (server sessions do not). On
each tick — every `heartbeat_interval` (default 15 s, ±25 % jitter) — it sends one `cmdHeartRequest` and
waits up to `heartbeat_timeout` (default 5 s) for the matching `cmdHeartResponse`; if none arrives it
marks the session `connBroken` and closes it, so the pool skips it and the next request dials fresh. One
exception keeps this from misfiring under load: if `recvLoop` is at that moment blocked handing a
just-received data frame to a slow-reading stream — a backpressured but provably live link — the probe
leaves the session alone rather than tearing it (and its sibling streams) down on what is really local
read backpressure. The probe is skipped only when a `cmdHeartResponse` arrived within
`heartbeat_quiet_window` (default 10 s) — a confirmed round-trip. Because liveness depends on a completed
round-trip, a half-open connection (downlink still delivering data while the uplink is dead) is detected
even on a busy session. The probe is a connection-level `cmdHeartRequest` (stream 0) that the shaper
sizes to an H2 PING-like record, and the server answers it with `cmdHeartResponse` (stock upstream
behaviour) — so **no server-side change or configuration is required**.

The same exchange doubles as an **application-layer (L7) keepalive** — an AnyTLS round-trip carried
inside the TLS tunnel, one layer above the kernel's **L4 TCP keepalive**. A round-trip on the order of
the interval keeps NAT mappings from expiring. The loop is frozen during deep Doze along with the rest
of the process; on wake it resumes and the next probe evicts any session that died while idle, so
post-sleep connectivity is restored per dead session rather than by dropping every connection.

This is separate from the record shaper's optional [idle keepalive injection](#record-shaper) (`idle_*`
padding-scheme keys), which writes cosmetic waste records for traffic-analysis resistance and is off by
default; the heartbeat is a real protocol round-trip for liveness and is always on.

The three options are surfaced on the sing-box `anytls-x` **outbound**. All are optional and fall back
to their defaults when unset (`0`). The one constraint is `heartbeat_quiet_window` **<**
`heartbeat_interval`: otherwise the heartbeat's own replies keep the quiet window satisfied and probes
stop going out on idle connections.

### Write deadline handling

`SetWriteDeadline` is set inside `writeConn` under `connLock`, so concurrent data and control frame
writes do not interfere with each other's deadlines. The `writeDataFrame` error path sets
`connBroken.Store(true)` so the session is not reused, without calling `Close()` — letting `recvLoop`
keep draining in-flight responses for the other streams.

### Unknown command data skip

The `default` branch in `recvLoop` reads and discards `hdr.Length()` bytes for an unknown command, so a
frame with an unknown command carrying data (a newer peer, or an active prober) does not desynchronize
subsequent frame parsing.

### uint16 frame length safety

Frame length is a `uint16`. `writeDataFrame` chunks an oversized payload into multiple `cmdPSH` frames;
`writeControlFrame` returns an error if its data exceeds the 65535-byte limit — so a payload over 65535
bytes can never be silently truncated into a desynchronized stream.

### Per-stream SYNACK timeout

Each stream gets its own 5-second SYNACK timer. On timeout that stream is closed, and the session is
torn down only when the timing-out stream is the session's **sole** stream — so closing it cannot drop a
live sibling — or when a session-wide counter of consecutive SYNACK timeouts crosses the threshold (5),
at which point an alert is logged (`the server completed its handshake but is no longer acknowledging new
streams`). Any received SYNACK resets the counter. `OpenStream` also refuses to open a stream on a
session already marked `connBroken`.

### Concurrency / data-race safety

Synchronization on the `Stream` close path and on a `Session` handshake field. These paths are exercised
heavily because `Reset()` closes active sessions on every network change, concurrently with stream
creation and I/O.

- **`dieErr` (`atomic.Pointer[error]`).** Read via `Load()` and written via `Store()`, so `Stream.Read` /
  `Stream.Write` and a concurrent `closeLocally` / `closeWithError` cannot tear the two-word interface
  value. `sync.Once` guarantees the closing goroutine's store completes before any `Do()` returns.
- **`dieHook` set before publish.** Threaded into `OpenStream` (via `streamDieHook`) and set before the
  stream is published into `s.streams` under `streamLock`, so it is set before any closer can observe it.
- **`synTimer` write-once.** Set in `OpenStream` before publish, then only read and `Stop()`-ed; `Stop()`
  is idempotent.
- **`peerVersion` (`atomic.Uint32`).** Written via `Store` on `cmdSettings` / `cmdServerSettings`, read
  via `Load` in `OpenStream` and the handshake helpers.

---

## Traffic shaping

TLS record-level traffic shaping that gives the connection a fingerprint close to a Caddy (Go stdlib)
HTTP/2 server. Touches `padding/padding.go`, `session/record_shaper.go`, and the shaper integration in
`session.go` / `client.go` / `frame.go` / `stream.go`.

### Record shaper

A `RecordShaper` sits between the session frame layer and the TLS connection.

**Auth packet.** The auth packet (34 B overhead + padding) is sized to exactly 69 bytes, matching a real
Go H2 connection preface (24 B magic + 45 B SETTINGS). The padding length is fixed at 35 bytes, so every
connection produces an identical first TLS record size — a delta-function distribution matching a real
Caddy server, where a random range would be trivially distinguishable across a handful of connections.
Padding bytes are PRNG output (`math/rand/v2` ChaCha8), not zeros. The `pad_dist` scheme key controls
this; the default is `35-35:100`. Custom ranges are accepted but capped at 1100 bytes so the auth packet
fits in the first TLS record across all cipher suites.

**Initial flush shaping.** For a new session the client buffers `cmdSettings`, `cmdSYN`, and `cmdPSH`
(target address) into one blob and writes it through `WriteInitialFlush`, which pads the blob with a
`cmdWaste` trailer to a size sampled from the `headers_target` range (default `90-140` bytes) — the size
of a Go H2 HEADERS frame for a typical HTTPS request with HPACK.

**Control frame padding.** Bare control frames (e.g. `cmdSYN`, `cmdFIN`, `cmdHeartRequest`,
`cmdHeartResponse`, `cmdSYNACK` without data) are as small as 7 bytes — a size that never appears in real
HTTP/2. The shaper pads any control frame smaller than the largest configured target with a `cmdWaste`
trailer to a size sampled from the `pad_targets` distribution. The default targets are weighted to real
Caddy frame frequency: `14` (≈SETTINGS_ACK, ×2), `17` (PING, ×3), `45` (SETTINGS with 6 params, ×1), and
`22-30` (bundled SETTINGS_ACK + WINDOW_UPDATE, ×1).

**Data frame chunking.** Data frames are chunked at 16384 bytes (`h2MaxFramePayload`), the HTTP/2 default
`MAX_FRAME_SIZE`, so each `cmdPSH` frame maps to one TLS record of ≤ 16 KB. Go's `crypto/tls` already
splits writes at 16 KB, so this adds no extra TCP writes or measurable throughput cost.

**WINDOW_UPDATE injection.** Inline in `recvLoop` (via `writeWindowUpdateWaste`), the receiver sends a
26-byte `cmdWaste` record — two back-to-back 13-byte frames — after every `wnd_update_interval` bytes
(default 131072, ~128 KB) of received DATA, reproducing the `DATA, …, WINDOW_UPDATE, DATA, …` pattern of
Go H2 flow control. The byte counter is owned solely by the `recvLoop` goroutine, so no extra goroutine
or lock is involved.

**SETTINGS_ACK exchange.** Both ends simulate the H2 SETTINGS_ACK handshake. On `cmdSettings` the server
sends a `cmdWaste` frame (shaped via `padControlFrame`) after `cmdServerSettings`; on `cmdServerSettings`
the client sends one the same way.

**Server-side frame ordering.** On `cmdSettings` the server replies with `cmdServerSettings` first
(shaped via `WriteControl`), then the SETTINGS_ACK waste frame, then `cmdUpdatePaddingScheme` if needed —
each as its own TLS record, matching the discrete SETTINGS → SETTINGS_ACK → WINDOW_UPDATE sequence a
Caddy server emits after a client preface.

**GOAWAY simulation.** On session close, `Close()` emits a 17-byte `cmdWaste` frame (7 B header + 10 B
random payload) before closing the connection, matching the wire size of a real H2 GOAWAY. The write is
best-effort with a 1-second deadline.

**Idle keepalive injection.** An optional background goroutine writes small waste TLS records during idle
periods to resist traffic-analysis detection of inactivity. **Off by default** — a real Caddy H2 server
sends no H2 PING during idle. Enabled via `idle_sizes`, `idle_interval`, and `idle_threshold` in the
padding scheme.

The patched client advertises `rs=1` in `cmdSettings`; a server that does not see this flag sends
`cmdAlert` and closes the session.

Most shaper parameters are set in the padding scheme and propagate to live sessions through the existing
`cmdUpdatePaddingScheme` mechanism — the shaper reloads its config when the scheme MD5 changes.
Exceptions: `wnd_update_interval` is fixed at session creation; `idle_*` keys propagate to sessions that
already have idle injection enabled but cannot enable it on a session created with it disabled;
`headers_target` propagates but affects only the once-per-session initial flush.

| Key | Format | Default | Description |
|-----|--------|---------|-------------|
| `pad_dist` | `min-max:weight,...` | `35-35:100` | Weighted bucket distribution for auth packet padding (capped at 1100) |
| `pad_targets` | `size,size,...` | `14,14,17,17,17,45,22-30` | Target sizes for control frame padding (fixed or range, weighted by repetition) |
| `headers_target` | `min-max` | `90-140` | Target size for the initial flush blob (H2 HEADERS) |
| `wnd_update_interval` | `bytes` | `131072` | Received DATA bytes between WINDOW_UPDATE-like waste frames (0 = disabled) |
| `idle_sizes` | `size,size,...` | *(empty — disabled)* | Record sizes for idle injection (weighted by repetition) |
| `idle_interval` | `min-max` | *(disabled)* | Injection interval range, in ms |
| `idle_threshold` | `ms` | *(disabled)* | Silence before idle detection, in ms |

### padding_scheme configuration

`padding_scheme` is a string array on the sing-box `anytls-x` **inbound** config, one scheme line per
element. The server pushes the full scheme to clients via `cmdUpdatePaddingScheme` on first connect. When
omitted the built-in default is used; all keys are optional — include only the ones you override. To
enable idle injection, add `idle_sizes` and `idle_interval`; `idle_threshold` is recommended so injection
avoids active transfers.

```json
{
  "type": "anytls-x",
  "padding_scheme": [
    "pad_dist=35-35:100",
    "pad_targets=14,14,17,17,17,45,22-30",
    "headers_target=90-140",
    "wnd_update_interval=131072"
  ]
}
```

---

## 0-RTT rail-switch migration

The 0-RTT rail-switch ("migration") backing the [`migration` option](#sing-box-configuration). **On by
default** (restricted to TLS flows by the default-on `migration_tls_only`); set `migration: false` to
disable, in which case the wire output and code paths are byte-for-byte unchanged. Touches
`session/migration.go`, `session/migration_detect.go`, and the integration in
`session/{frame,session,stream,client}.go`, `client.go`, `service.go`.

Every flow still starts on the established, traffic-shaped multiplex (0-RTT) and, for a TLS flow, runs
its **entire inner TLS handshake there**. Only once the handshake is past and a bulk threshold is crossed
does the server move that one flow's steady state — **both directions** — onto a **dedicated raw
connection ("carrier")**. After the cut-over the flow is a standalone TCP connection with its own
congestion window, so it no longer suffers (nor inflicts) the multiplex's single-connection
head-of-line blocking; and because the carrier only ever carries post-handshake bytes, the inner TLS
handshake never appears on it — preserving the shaped multiplex's resistance to TLS-in-TLS analysis.

### When a flow migrates

- **TLS flows** migrate only after the inner handshake completes **and** a post-handshake bulk margin is
  reached — the `migration_min_bulk_bytes` gate (default 64 KB), biased deliberately late so the whole
  nested handshake stays on the shaped multiplex.
- **Opaque flows** (UoT-UDP, plaintext, custom protocols) have no handshake to gate on and migrate on a
  both-directions volume gate; `migration_tls_only` keeps them on the multiplex instead. A non-TLS bulk
  flow on the carrier is unshaped, so its inner datagram sizing is visible there — the reason for that
  option.
- **TLS 1.2 is never migrated.** Only TLS 1.2 has renegotiation — a mid-stream handshake that would
  otherwise land on the carrier — so a flow detected as TLS 1.2 (a cleartext-typed handshake record after
  the ServerHello, unlike TLS 1.3's encrypted flight) stays on the multiplex. Anything not recognized as
  a clean TLS 1.3 or opaque-bulk flow likewise stays put (fail-safe).

The cut-over uses symmetric barriers on the multiplex, so the byte stream is exact across the seam in
both directions (each side drains the multiplex up to the barrier before reading the carrier).
End-of-stream is a **graceful four-way close**: each side half-closes its carrier write direction (FIN)
when its source ends and runs the final close only after reading the peer's clean EOF, so the carrier
ends on a FIN rather than a data-discarding RST, with a short watchdog backstopping a peer that never
closes. A short flow that never crosses the gate, or any flow the detector rejects, simply finishes on
the multiplex — the original, always-correct path.
