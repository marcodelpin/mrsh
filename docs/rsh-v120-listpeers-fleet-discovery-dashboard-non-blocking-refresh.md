# Repository Analysis: RustDesk (github.com/rustdesk/rustdesk)
Generated: 2026-03-13

## 1. Architecture Overview

### Crate/Workspace Structure

RustDesk v1.4.6 is a monorepo with a Cargo workspace. The main binary produces `librustdesk` (cdylib/staticlib/rlib) plus two additional binaries (`naming`, `service`).

**Workspace members:**

| Crate | Path | Purpose |
|-------|------|---------|
| `rustdesk` | `.` (root) | Main application: client + server |
| `hbb_common` | `libs/hbb_common` (git submodule) | Shared: protobuf, config, tcp/udp/ws/tls, fs, password, crypto |
| `scrap` | `libs/scrap` | Screen capture + video codec (VP8/VP9/H264/H265/AV1) |
| `enigo` | `libs/enigo` | Cross-platform keyboard/mouse simulation |
| `clipboard` | `libs/clipboard` | File copy/paste (Windows/Linux/macOS) |
| `virtual_display` | `libs/virtual_display` | Windows virtual display driver |
| `portable` | `libs/portable` | Portable (non-installed) mode support |
| `remote_printer` | `libs/remote_printer` | Remote printer redirection (Windows) |

**UI layer:** Flutter (primary) + legacy Sciter (deprecated). Flutter lives in `flutter/` with platform targets for desktop and mobile.

### Source File Complexity (top files by LOC)

| File | LOC | Role |
|------|-----|------|
| `src/server/connection.rs` | 5,602 | Session management, auth, permission enforcement |
| `src/client.rs` | 4,195 | Peer connection initiation, codec negotiation, audio decode |
| `src/flutter_ffi.rs` | 3,059 | Flutter-Rust bridge |
| `src/common.rs` | 2,519 | Shared utilities |
| `src/client/io_loop.rs` | 2,441 | Client-side message processing loop |
| `src/server/input_service.rs` | 2,373 | Mouse/keyboard input injection (via enigo + rdev) |
| `src/server/terminal_service.rs` | 1,847 | PTY terminal sessions with persistence |
| `src/server/video_service.rs` | 1,419 | Screen capture + encode loop |
| `src/keyboard.rs` | 1,401 | Keyboard mapping across platforms/modes |
| `src/rendezvous_mediator.rs` | 933 | Rendezvous server communication, NAT traversal |

Total: ~50k LOC in `src/`, plus ~10k in `libs/`.

---

## 2. Feature Inventory

### Connection Types (from `rendezvous.proto`)

| ConnType enum | Purpose |
|---------------|---------|
| `DEFAULT_CONN` | Remote desktop (video + input + clipboard) |
| `FILE_TRANSFER` | Dedicated file transfer session |
| `PORT_FORWARD` | TCP port forwarding / tunneling |
| `RDP` | RDP-over-tunnel (local mstsc to forwarded port) |
| `VIEW_CAMERA` | Webcam viewing |
| `TERMINAL` | Remote terminal/shell session |

### Feature Map

| Feature | Server File | Client File | Protocol |
|---------|------------|-------------|----------|
| **Video streaming** | `server/video_service.rs` | `client.rs` + `client/io_loop.rs` | `VideoFrame` protobuf (VP8/VP9/H264/H265/AV1) |
| **Audio forwarding** | `server/audio_service.rs` | `client.rs` (audio decode) | `AudioFrame` protobuf (Opus encoded) |
| **Keyboard input** | `server/input_service.rs` | `client/io_loop.rs` | `KeyEvent` protobuf (3 modes: Legacy/Map/Translate) |
| **Mouse input** | `server/input_service.rs` | `client/io_loop.rs` | `MouseEvent` + `PointerDeviceEvent` + `TouchEvent` |
| **Clipboard sync** | `server/clipboard_service.rs` + `clipboard.rs` | `client/io_loop.rs` | `Clipboard` (text/RTF/HTML/image) + `MultiClipboards` |
| **Clipboard files** | `clipboard_file.rs` + `libs/clipboard` | same | `Cliprdr*` messages (freeRDP-derived protocol) |
| **File transfer** | handled in `server/connection.rs` | `client/file_trait.rs` | `FileAction`/`FileResponse` protobuf |
| **Port forwarding** | `server/connection.rs` | `port_forward.rs` | Raw TCP relay via `BytesCodec` |
| **Terminal/PTY** | `server/terminal_service.rs` + `terminal_helper.rs` | client terminal UI | `TerminalAction`/`TerminalResponse` protobuf |
| **Remote printer** | `server/printer_service.rs` | Flutter UI | XPS data via `FileTransferSendRequest` |
| **Privacy mode** | `privacy_mode/*.rs` | Flutter UI toggle | `TogglePrivacyMode` + `BackNotification` |
| **Virtual display** | `virtual_display_manager.rs` + `libs/virtual_display` | Flutter UI | `ToggleVirtualDisplay` |
| **Whiteboard** | `whiteboard/*.rs` | `whiteboard/client.rs` | Custom overlay window |
| **2FA/TOTP** | `auth_2fa.rs` | Flutter UI | `Auth2FA` protobuf |
| **Voice call** | `server/audio_service.rs` | `client.rs` | `VoiceCallRequest`/`VoiceCallResponse` |
| **Screenshot** | `client/screenshot.rs` | Flutter UI | `ScreenshotRequest`/`ScreenshotResponse` |
| **LAN discovery** | `lan.rs` | Flutter UI | UDP broadcast `PeerDiscovery` protobuf |
| **Video QoS** | `server/video_qos.rs` | client sends `TestDelay` | Adaptive FPS (1-120) + bitrate ratio |
| **Multi-display** | `server/display_service.rs` | Flutter UI | `SwitchDisplay` + `CaptureDisplays` |
| **Elevation/UAC** | `server/connection.rs` | Flutter UI | `ElevationRequest` (direct or logon) |
| **Plugin framework** | `plugin/*.rs` | Flutter bridge | `PluginRequest`/`PluginFailure` |
| **Session switching** | `server/connection.rs` | client side | `SwitchSidesRequest`/`SwitchSidesResponse` |
| **Auto-update** | `updater.rs` | built-in | `SoftwareUpdate` rendezvous message |
| **Recording** | `libs/scrap/src/common/record.rs` | client side | WebM container recording |

---

## 3. Protocol Details

### Two Protocol Layers

**Layer 1: Rendezvous Protocol** (`rendezvous.proto`, UDP/TCP/WebSocket to rendezvous server)
- `RegisterPeer` / `RegisterPeerResponse` — periodic heartbeat registration
- `RegisterPk` / `RegisterPkResponse` — public key registration (ed25519 via sodiumoxide)
- `PunchHoleRequest` / `PunchHole` / `PunchHoleSent` / `PunchHoleResponse` — NAT traversal
- `FetchLocalAddr` / `LocalAddr` — LAN/intranet direct connection
- `RequestRelay` / `RelayResponse` — relay fallback when hole-punching fails
- `TestNatRequest` / `TestNatResponse` — NAT type detection (Unknown/Asymmetric/Symmetric)
- `PeerDiscovery` — LAN broadcast discovery (ping/pong)
- `OnlineRequest` / `OnlineResponse` — batch peer online status check
- `KeyExchange` — key exchange for secure relay
- `ConfigUpdate` — server-pushed config (rendezvous server list, serial)

**Layer 2: Session Protocol** (`message.proto`, TCP/KCP/WebRTC between peers)
- `Message` oneof union with 32 message types (video, audio, input, clipboard, file, terminal, etc.)
- Encryption: `sodiumoxide` secretbox (NaCl) on TCP stream — key derived from DH exchange
- Framing: length-prefixed via `BytesCodec` (custom in `hbb_common/src/bytes_codec.rs`)
- Compression: `zstd` for clipboard, terminal data, file blocks

### Transport Stack

| Transport | Implementation | Use Case |
|-----------|---------------|----------|
| UDP | `hbb_common/src/udp.rs` + SOCKS5 proxy | Rendezvous registration, NAT test |
| TCP | `hbb_common/src/tcp.rs` (FramedStream) | Primary peer-to-peer data |
| KCP over UDP | `src/kcp_stream.rs` (kcp-sys) | Reliable UDP for hole-punched connections |
| WebSocket | `hbb_common/src/websocket.rs` (tokio-tungstenite) | Alternative when UDP blocked |
| TLS | `hbb_common/src/tls.rs` (tokio-rustls) | Secure transport option |
| WebRTC | `hbb_common/src/webrtc.rs` (optional feature) | Experimental P2P |
| SOCKS5 | tokio-socks | Proxy support for both UDP and TCP |

### Connection Establishment Flow

1. Client sends `PunchHoleRequest` to rendezvous server
2. Server relays `PunchHole` to target peer (contains NAT type, socket addresses)
3. If same LAN: `FetchLocalAddr`/`LocalAddr` for direct local connection
4. If NAT traversal possible: UDP hole punching with STUN (`stunclient` crate)
5. If hole-punch fails or forced: relay via `RequestRelay`/`RelayResponse`
6. Once connected: `PublicKey` exchange, then `LoginRequest`/`LoginResponse`
7. Stream encrypted with NaCl secretbox (key from DH)

### Permission Model (from `rendezvous.proto` and `message.proto`)

```
ControlPermissions bitmask: keyboard, remote_printer, clipboard, file, audio,
  camera, terminal, tunnel, restart, recording, block_input, remote_modify
```

Server-side `PermissionInfo` sent per-session:
- Keyboard, Clipboard, Audio, File, Restart, Recording, BlockInput

Configurable approval modes: Password / Click / Both.
Verification methods: Temporary password / Permanent password / Both.
Optional 2FA via TOTP (with Telegram bot notification).
Trusted devices (remember approved HWIDs).

---

## 4. Key Capabilities rsh Does NOT Have (with implementation details)

### 4.1 Remote Desktop Streaming (VIDEO)

**Implementation:**
- `libs/scrap` handles screen capture per-platform:
  - Windows: DXGI Desktop Duplication API (`dxgi/mod.rs`) + GDI fallback (`dxgi/gdi.rs`) + Magnification API (`dxgi/mag.rs` for privacy mode)
  - Linux: X11 (`x11/`) + Wayland PipeWire (`wayland/pipewire.rs`) + GStreamer
  - macOS: Quartz/CoreGraphics (`quartz/`) + ScreenCaptureKit
  - Android: MediaProjection via JNI (`android/`)
- Codec stack (`libs/scrap/src/common/codec.rs`):
  - Software: VP8, VP9 (libvpx), AV1 (libaom) — always available
  - Hardware: H.264/H.265 via `hwcodec` crate (NVENC, Intel QSV, AMD AMF)
  - VRAM: GPU texture path for zero-copy encode (Windows)
  - Android: MediaCodec H.264/H.265
- QoS (`server/video_qos.rs`): Adaptive FPS (1-120, default 30) + bitrate ratio, driven by `TestDelay` round-trip measurements
- Cursor: Sent separately as `CursorData` (ARGB bitmap) + `CursorPosition`
- Multi-monitor: `DisplayInfo` array, `SwitchDisplay`, `CaptureDisplays` for selective capture

**Complexity to integrate:** HIGH. This is the core of RustDesk (~5,000 LOC for video path alone). Requires libvpx/libaom C dependencies via vcpkg. The codec abstraction (`EncoderApi` trait) is well-designed and could be extracted.

### 4.2 Audio Forwarding

**Implementation:**
- Capture: `cpal` (Windows WASAPI loopback, macOS CoreAudio) on non-Linux; PulseAudio (`libpulse-binding`) on Linux
- Codec: Opus via `magnum-opus` crate (48kHz stereo, 960 samples/frame = 20ms)
- Protocol: `AudioFormat` negotiation then `AudioFrame` stream
- Voice calls: Bidirectional audio with `VoiceCallRequest`/`VoiceCallResponse`

**Complexity:** MEDIUM. ~527 LOC server side. The cpal + opus pipeline is fairly self-contained. Linux requires PulseAudio.

### 4.3 File Transfer (their approach vs rsh delta-sync)

**Implementation:**
- GUI-driven file browser: `ReadDir`/`FileDirectory` for remote directory listing
- Block transfer: `FileTransferBlock` (data chunks, optional zstd compression, block IDs)
- Resume support: `FileTransferDigest` with `transferred_size` + `is_resume` flag, `.digest` sidecar files
- Operations: Send, Receive, Cancel, Create dir, Remove dir/file, Rename
- No delta-sync/rsync: Transfers entire files or resumes from byte offset. No rolling checksums.

**Comparison with rsh:** rsh's rsync-style delta transfer with rolling checksums is more efficient for updating modified files. RustDesk's approach is simpler (sequential blocks + resume) but wastes bandwidth on partially-changed large files. RustDesk does have zstd compression on blocks which rsh could adopt.

### 4.4 Clipboard Sync (Bidirectional)

**Implementation:**
- `clipboard_service.rs` + `clipboard.rs`: Monitor clipboard changes via `clipboard-master` crate (Windows: clipboard viewer chain, Linux: X11/Wayland selection)
- Format support: Text, RTF, HTML, ImageRGBA, ImagePNG, ImageSVG, Special formats
- `MultiClipboards`: Batch multiple clipboard formats in one message
- File clipboard: Full `Cliprdr*` protocol (derived from freeRDP) for cross-platform file copy/paste
- Compression: zstd on clipboard content

**Complexity:** MEDIUM-HIGH. The text/image clipboard is ~885 LOC. File clipboard adds ~427 LOC (`clipboard_file.rs`) plus the entire `libs/clipboard` crate. The Cliprdr protocol is complex (format negotiation, file contents streaming).

### 4.5 P2P Hole Punching

**Implementation:**
- NAT type detection: STUN (`stunclient` crate) to determine Unknown/Asymmetric/Symmetric
- UDP hole punching: Both peers send packets to each other's external IP:port (from rendezvous server)
- KCP over UDP: `kcp-sys` crate provides reliable ordered delivery over punched UDP socket
- TCP fallback: Direct TCP connection attempt (works on some NATs)
- IPv6: Parallel IPv6 path (`socket_addr_v6` fields throughout)
- UPnP: Optional UPnP port mapping (`upnp_port` field)
- Relay fallback: When all direct methods fail, relay through server

**Complexity:** MEDIUM. The rendezvous mediator is ~933 LOC. KCP stream adapter is ~80 LOC. The real complexity is in the rendezvous server (separate repo: rustdesk-server).

### 4.6 Permission/Access Control

**Implementation:**
- `ControlPermissions` bitmask: 12 granular permissions (keyboard, clipboard, file, audio, camera, terminal, tunnel, restart, recording, block_input, remote_printer, remote_modify)
- Approval modes: Password-only, Click-to-approve, Both
- Password types: Temporary (auto-generated 6/8/10 digit) + Permanent
- 2FA: TOTP with optional Telegram bot notification
- Trusted devices: HWID-based device trust (bypass password after first approval)
- IP allow/deny: CIDR-based IP filtering (`cidr-utils`)
- Privacy mode: Multiple implementations (Magnification API, Exclude-from-capture, Virtual display)
- Block input: Remote can block local keyboard/mouse during session
- Session-level: Per-connection permission negotiation

**Complexity:** HIGH. Distributed across `connection.rs` (5,602 LOC) + `password_security.rs` + `auth_2fa.rs`. The permission model is comprehensive but tightly coupled to the connection handler.

### 4.7 Multi-Platform (Android, iOS, Web)

**Implementation:**
- Flutter UI: `flutter/` directory with `lib/desktop/`, `lib/mobile/`, `lib/common/`
- Android: JNI bridge (`src/flutter_ffi.rs`), MediaProjection capture, MediaCodec, accessibility service for input
- iOS: Limited (view-only client, no controlled mode)
- Web: Flutter web build + JavaScript bridge (`flutter/web/`)
- Build scripts: `build.py`, platform-specific CI in `.github/workflows/`

**Complexity:** VERY HIGH. This is an entire Flutter application plus platform-specific native code.

---

## 5. Key Dependencies

### Core Crates

| Crate | Version | Purpose |
|-------|---------|---------|
| `sodiumoxide` | 0.2 | NaCl crypto (DH key exchange, secretbox encryption, ed25519 signing) |
| `protobuf` | 3.7 | Protocol buffers (message serialization) |
| `tokio` | 1.44 | Async runtime |
| `tokio-rustls` | 0.26 | TLS transport |
| `tokio-tungstenite` | 0.26 | WebSocket transport |
| `tokio-socks` | (git) | SOCKS5 proxy |
| `zstd` | 0.13 | Compression (clipboard, file blocks, terminal) |
| `serde` / `serde_json` | 1.0 | Serialization |
| `confy` | (git fork) | Config file management |
| `reqwest` | 0.12 | HTTP client (API server communication) |

### Media Crates

| Crate | Purpose |
|-------|---------|
| `magnum-opus` (git fork) | Opus audio codec |
| `cpal` (git fork) | Cross-platform audio I/O (WASAPI, CoreAudio, ALSA) |
| `libpulse-binding` | PulseAudio (Linux audio capture) |
| `dasp` | Audio sample rate conversion (default resampler) |

### Screen/Input Crates

| Crate | Purpose |
|-------|---------|
| `scrap` (in-tree) | Screen capture abstraction |
| libvpx (C, via vcpkg) | VP8/VP9 video codec |
| libaom (C, via vcpkg) | AV1 video codec |
| libyuv (C, via vcpkg) | Color space conversion (RGB/YUV) |
| `hwcodec` (git) | Hardware encode/decode (NVENC, QSV, AMF) |
| `nokhwa` (git fork) | Camera/webcam capture |
| `enigo` (in-tree) | Keyboard/mouse simulation |
| `rdev` (git fork) | Raw input device events |

### Platform-Specific

| Crate | Platform | Purpose |
|-------|----------|---------|
| `winapi` | Windows | Win32 API bindings |
| `windows` | Windows | Modern Windows API |
| `windows-service` | Windows | Windows service management |
| `virtual_display` (in-tree) | Windows | Virtual display driver |
| `impersonate_system` (git) | Windows | System impersonation |
| `pam` (git fork) | Linux | PAM authentication |
| `evdev` (git fork) | Linux | Input device access |
| `cocoa` / `objc` | macOS | Cocoa/ObjC bindings |
| `jni` | Android | JNI bridge |

### Notable: Heavy use of forked crates

RustDesk maintains forks of ~15 crates under `github.com/rustdesk-org/`. This includes cpal, rdev, clipboard-master, pam, evdev, pulsectl, keepawake, confy, kcp-sys, and others. This indicates significant customization beyond upstream.

---

## 6. Code Quality Assessment

### Strengths
- **Well-structured modules:** Clear separation (server services, client logic, platform code)
- **Good protobuf design:** `message.proto` and `rendezvous.proto` are well-organized with proper oneofs
- **Platform abstraction:** Consistent `#[cfg(target_os)]` gating, platform modules per feature
- **QoS system:** Sophisticated adaptive bitrate/FPS with delay measurement
- **Codec abstraction:** `EncoderApi` trait allows clean codec switching

### Weaknesses
- **Minimal testing:** Only 8 files contain `#[cfg(test)]` modules in ~50k LOC. No dedicated test directory. No integration tests.
- **Large files:** `connection.rs` at 5,602 LOC is a god-object handling auth, permissions, all message types, session management
- **Tight coupling:** Server connection handler directly processes all message types inline
- **Fork burden:** ~15 forked crates create maintenance overhead
- **Documentation:** Minimal doc comments. CLAUDE.md is auto-generated. No architecture doc.
- **Error handling:** Heavy use of `allow_err!` macro (swallow errors) and `.ok()` (discard results)

### Code Organization Rating: 6/10
Good module boundaries but some files are too large. Missing test coverage is a significant gap for a security-sensitive application. The protocol design is solid.

---

## 7. Recommendations for rsh Integration

### High-Value, Low-Effort Features

1. **Clipboard sync (text only)** — rsh already has the connection infrastructure. Adding a `Clipboard` message type with text content and a clipboard monitor thread is ~200 LOC. Skip the Cliprdr file clipboard protocol.

2. **KCP reliable UDP** — The `kcp-sys` crate could improve rsh's relay performance. Currently rsh uses TCP exclusively; KCP over UDP would reduce latency for interactive sessions.

3. **zstd compression on transfers** — RustDesk compresses file blocks and clipboard with zstd. rsh could add zstd compression to its binary protocol for better throughput.

4. **NAT type detection** — The `stunclient` crate (tiny, no dependencies) could tell rsh whether hole-punching is viable, improving connection strategy.

### Medium-Value Features

5. **Audio forwarding** — If rsh needs audio, the cpal+opus pipeline is self-contained (~500 LOC). Requires `magnum-opus` and `cpal` crates.

6. **Permission bitmask** — RustDesk's `ControlPermissions` bitmask is a clean design. rsh could adopt a similar per-connection permission model to restrict what remote clients can do.

7. **Video QoS algorithm** — Even without video streaming, the adaptive quality algorithm in `video_qos.rs` could inform rsh's screenshot quality/timing.

### High-Value, High-Effort Features (Probably NOT worth integrating)

8. **Remote desktop streaming** — Requires libvpx/libaom C dependencies, platform-specific capture code, and a rendering client. This is essentially building a different product. If needed, consider embedding a lightweight VNC-like protocol instead.

9. **Multi-platform Flutter UI** — Entirely separate product scope.

10. **Full Cliprdr file clipboard** — The freeRDP-derived protocol is complex. rsh already has superior file transfer with delta-sync.

### What rsh Already Does Better

- **Delta file transfer:** rsh's rsync-style rolling checksum approach is superior to RustDesk's sequential block transfer
- **Ed25519 auth:** rsh uses ed25519 directly vs RustDesk's sodiumoxide DH + symmetric key approach
- **Fleet management:** rsh has ListPeers, fleet update, service management — RustDesk has none of this
- **Persistent shell sessions:** rsh has this; RustDesk just added `terminal_service.rs` with persistence
- **GUI automation:** rsh's screenshot + mouse/keyboard + window targeting is more automation-focused vs RustDesk's full desktop streaming
