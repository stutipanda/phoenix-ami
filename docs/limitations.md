# Known Limitations

- Euler-totient token stitching is a nonstandard construction and has not been
  peer reviewed. Do not treat it as production-grade security.
- Cryptographic key creation intentionally retains the crypto engine's
  operating-system randomness. Scenario topology, failures, telemetry,
  simulation nonces, and baseline session-key samples use seeded NumPy state.
- Crypto compute time is measured with a wall clock and therefore varies
  between repeated runs even when all seeded scenario inputs match. Topology,
  failures, packet counts, and control-byte counts are repeatable.
- Network delay is modeled as 10 ms per hop; heartbeat detection is modeled
  as three missed 1-second heartbeats. Neither is a radio measurement.
- A graph partition with no remaining route cannot deliver telemetry or
  support remote centralized re-keying. Such nodes are counted as lost or
  unrecovered, and trials with no recovered affected node have `recovery_ms`
  recorded as missing rather than zero.
- Adjacent simultaneous relay failures can remove every usable local bridge
  for a neighbor. Euler mode only stitches from the first recorded failed
  neighbor and does not implement multi-hop token composition.
- The centralized baseline uses one unicast REKEY per directly affected node,
  sent over surviving routes. Every hop's transmission contributes one packet
  and that packet's CBOR frame size to control overhead. An unreachable
  Gateway control service leaves affected nodes unrecovered.
- Affected nodes are surviving direct neighbors of failed relays. Nodes
  outside that set retain their pre-failure session key.
