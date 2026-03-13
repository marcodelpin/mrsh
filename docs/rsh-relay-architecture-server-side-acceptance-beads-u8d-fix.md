# rsh Relay Architecture — Server-Side Acceptance (beads-u8d fix)

<!-- Added via KB MCP -->
*Created: 2026-03-13 14:34*
*Scope: project:/mnt/s/Commesse/00-09_System/worktrees/remote-tools/rsh*

## Problem

TLS handshake EOF when connecting via relay to hosts behind NAT (mdp-hp, ntbk-omni). Root cause: rsh server never connected to hbbr to complete relay pairing.

## Architecture (after fix, commit c1d50eb)

### Full relay flow:

1. **Client** sends `PunchHoleRequest` (UDP) to hbbs → gets target addr + relay_server
2. **Client** tries P2P direct connect (5s timeout) → fails for NAT'd hosts
3. **Client** sends `RequestRelay` (TCP, BytesCodec) to hbbs with UUID + target device_id
4. **hbbs** looks up target in registered peers, sends `RelayResponse` (UDP) to target's address
5. **Server** receives `RelayResponse` on its persistent registration socket
6. **Server** connects to hbbr with the UUID via `connect_relay()`
7. **Client** connects to hbbr with the same UUID
8. **hbbr** pairs both connections by UUID → raw TCP bridge
9. TLS handshake happens over the bridge (client→server)
10. Normal command dispatch

### Key components:

- **hbbs TCP listener** (`rendezvous.rs`): Spawned alongside UDP in `listen_and_serve()`. Same port (TCP+UDP can share). Handles `RequestRelay` → forwards as `RelayResponse` to target via UDP.
- **Client::run_registration_loop()** (`rendezvous.rs`): Persistent UDP socket (not ephemeral like `register_once()`). Sends RegisterPeer every 30s. Listens for RelayResponse → sends to mpsc channel.
- **accept_relay_connection()** (`main.rs`): Receives RelayNotification from channel, connects to hbbr, does TLS accept, dispatches.
- **RelayNotification** struct: `{ uuid: String, relay_server: String }`

### Why the old approach failed:

- `register_once()` created ephemeral sockets that were immediately dropped
- No UDP listener on server side → couldn't receive relay notifications from hbbs
- hbbs had no TCP listener → `request_relay_uuid()` TCP connection went nowhere
- Client connected to hbbr alone → no pairing partner → TLS handshake EOF

### Relay pairing timeout: 30s (hbbr PAIRING_TIMEOUT)

Both client and server must connect to hbbr within 30s of each other. Since hbbs forwarding is near-instant, this is not a concern in practice.

### Config requirements for relay to work:

Server side (`~/.rsh/config` or system config):
- `DeviceID` — must be set for registration
- `RendezvousServer` — hbbs address
- `RendezvousKey` — must match hbbs key

hbbs must be running with `--relay` pointing to hbbr address.
