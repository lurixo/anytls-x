# sing-anytls

Some TLS Proxy Protocol

- Wire-compatible with the `anytls-go` framing, **but this fork is not
  drop-in compatible with stock `anytls-go`**: the server requires the
  client to advertise the record shaper (`rs=1` in its settings) and
  closes the connection with an alert otherwise. Use the matching
  patched client and server from this fork on both ends.
