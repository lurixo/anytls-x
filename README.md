# anytls-x

`anytls-x` is an enhanced fork of [`sing-anytls`](https://github.com/anytls/sing-anytls)
(the Go implementation of the AnyTLS proxy protocol). It keeps the AnyTLS wire
framing but ships three additional capabilities baked into the source:

- **Session resilience** — idle-session heartbeat, write deadlines,
  unknown-command skip, uint16 overflow protection, per-stream SYN/ACK timeout
  reaping, and a set of concurrency / data-race fixes.
- **Traffic shaping** — TLS record-level shaping so per-flow record sizes
  follow the configured padding scheme instead of leaking inner payload
  boundaries.
- **0-RTT rail-switch migration** — inner-TLS-handshake-gated, bidirectional
  cut-over of a bulk stream from the shaped multiplexed connection onto a
  dedicated raw carrier, removing mux head-of-line blocking. Opt-in via the
  `EnableMigration` config option (or the `ANYTLS_MIGRATION=1` environment
  default); TLS 1.2 is refused and stays on the mux (fail-safe).

## Module path

```
github.com/lurixo/anytls-x
```

The Go package is `anytlsx`.

## Compatibility

This fork shares the AnyTLS framing but is **not drop-in compatible with stock
`anytls-go`**: the server requires the client to advertise the record shaper
(`rs=1` in its settings) and closes the connection with an alert otherwise. Use
a matching `anytls-x` client and server on both ends.

## sing-box

`anytls-x` is consumed by sing-box as the `anytls-x` inbound / outbound type,
which exposes the migration / heartbeat / handshake-timeout options on top of
the standard AnyTLS options. The stock `anytls` type continues to track upstream
`github.com/anytls/sing-anytls` unchanged.
