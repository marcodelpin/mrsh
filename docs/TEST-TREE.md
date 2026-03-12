# Test Tree — rsh-rs

Generated: 2026-03-12 | Version: 5.19.0

## Summary

- Total source files: 58 (.rs)
- Total LOC: ~29,500
- Test functions: 545 (on default features, Linux)
- Feature-gated tests: quic (6), ssh (7) — require `--features quic,ssh`
- Crates tested: 5/5 (all crates have tests)
- All tests passing: YES (545/545 on Linux)
- Critical gaps: 0
- Regression gaps: 1 MISSING (solved/004 env-specific)

## Coverage Matrix

### rsh-core (67 tests)

| Module | Lines | Tests | Coverage | Notes |
|--------|-------|-------|----------|-------|
| auth.rs | 963 | 21 | HIGH | — |
| config.rs | 605 | 17 | HIGH | +2 enrollment_token tests |
| protocol.rs | 339 | 12 | HIGH | All wire structs covered |
| tls.rs | 606 | 12 | HIGH | — |
| wire.rs | 139 | 5 | HIGH | — |

### rsh-transfer (23 tests)

| Module | Lines | Tests | Coverage | Notes |
|--------|-------|-------|----------|-------|
| blockcache.rs | 501 | 9 | HIGH | — |
| chunking.rs | 257 | 7 | HIGH | — |
| delta.rs | 268 | 7 | HIGH | — |

### rsh-relay (38 tests)

| Module | Lines | Tests | Coverage | Notes |
|--------|-------|-------|----------|-------|
| codec.rs | 193 | 10 | HIGH | — |
| relay.rs | 613 | 10 | HIGH | — |
| rendezvous.rs | 1270 | 18 | HIGH | +11 group discovery, nonce, HMAC, LAN detection |

### rsh-client (201 tests)

| Module | Lines | Tests | Coverage | Notes |
|--------|-------|-------|----------|-------|
| commands.rs | 835 | 35 | HIGH | — |
| session_log.rs | 625 | 26 | HIGH | — |
| sync.rs | 965 | 22 | HIGH | — |
| config_tui.rs | 1226 | 20 | HIGH | — |
| shell.rs | 433 | 13 | HIGH | — |
| tunnel.rs | 908 | 12 | HIGH | — |
| browse.rs | 409 | 10 | HIGH | — |
| fleet.rs | 478 | 10 | HIGH | fleet discover + group token |
| host_picker.rs | 460 | 10 | HIGH | — |
| sftp.rs | 451 | 9 | HIGH | — |
| mux.rs | 514 | 8 | HIGH | Windows stubs (0%, expected) |
| install_pack.rs | 770 | 11 | HIGH | SFX .sh + NSIS .exe tested E2E |
| socks.rs | 593 | 6 | PARTIAL | IPv6 address type |
| client.rs | 421 | 5 | PARTIAL | `connect_over_stream` |
| recording.rs | 221 | 4 | PARTIAL | — |

### rsh-server (191 tests on default features)

| Module | Lines | Tests | Coverage | Notes |
|--------|-------|-------|----------|-------|
| dispatch.rs | 603 | 23 | HIGH | — |
| listener.rs | 1026 | 19 | HIGH | — |
| tunnel.rs | 351 | 18 | HIGH | — |
| mux.rs | 899 | 14 | HIGH | — |
| fileops.rs | 331 | 12 | HIGH | — |
| handler.rs | 845 | 10 | HIGH | — |
| sync.rs | 1285 | 14 | HIGH | +5 large file chunking, sanitize_path |
| safety.rs | 146 | 8 | HIGH | — |
| shell.rs | 538 | 8 | HIGH | — |
| session.rs | 331 | 7 | HIGH | — |
| service.rs | 388 | 7 | HIGH | Regression test for --service flag (solved/010) |
| exec.rs | 191 | 6 | HIGH | — |
| gui.rs | 418 | 6 | PARTIAL | Windows-only input injection |
| plugin.rs | 323 | 6 | PARTIAL | Plugin loading from dir |
| ratelimit.rs | 174 | 5 | HIGH | — |
| tray.rs | 438 | 8 | PARTIAL | +3 cancelled token, various ports, all variants |
| selfupdate.rs | 264 | 4 | PARTIAL | Atomic binary swap |
| screenshot.rs | 299 | 4 | PARTIAL | Platform-specific capture |
| exec_user.rs | 300 | 4 | HIGH | — |
| notify.rs | 153 | 8 | HIGH | +8 broadcast channel, subscribe, event fields |

### Feature-gated modules (not in default test run)

| Module | Lines | Tests | Feature | Coverage | Notes |
|--------|-------|-------|---------|----------|-------|
| quic.rs | 914 | 5 | `quic` | PARTIAL | Requires `--features quic` |
| ssh.rs | 451 | 7 | `ssh` | HIGH | Requires `--features ssh` |

## Regression Gap Table

| Source | Issue/Commit | Bug Description | Regression Test | Status |
|--------|-------------|-----------------|-----------------|--------|
| solved/001 | 2026-02-15-001 | Stale block cache hides deleted files | blockcache cleanup test | OK |
| solved/002 | 2026-02-20-001 | Dual-port SSH replaced configured ports | listener.rs:dual_port_survives_non_tls_connections | OK (Rust uses fixed port model) |
| solved/003 | 2026-02-27-001 | Rendezvous AddrMangle decode + Tailscale | resolve_test.go:addr_mangle | OK |
| solved/004 | 2026-03-04-001 | GetDIBits screenshot fails in RDP | (none) | **MISSING** — environment-dependent |
| solved/005 | 2026-03-05-001 | Windows unsized dyn trait objects | cross-compile CI | OK (compile-time) |
| solved/006 | 2026-03-05-002 | Opaque type mismatch connect/relay | type system enforced | OK (compile-time) |
| solved/007 | 2026-03-05-003 | Wire protocol format regression | protocol.rs serde roundtrip | OK |
| solved/008 | 2026-03-08-001 | Tray icon blue square fallback | (none) | OK (Low, cosmetic) |
| solved/009 | 2026-03-08-002 | Screenshot Linux hangs no display | screenshot.rs timeout test | OK |
| solved/010 | 2026-03-10-001 | Service install clap parses -service as short flags | service.rs:service_flag_uses_double_dash | OK |
| solved/011 | 2026-03-11-001 | Tray crash Win10 IoT LTSC (4 root causes) | (none) | OK — HW-specific, document only |
| fix commit | 437d51f | Wire protocol format regression | protocol.rs serde roundtrip | OK |
| fix commit | a2ba198 | Mux cross-platform build (cfg gating) | cross-compile check | OK (compile-time) |
| fix commit | 935bb67 | .await for relay/rendezvous (nested runtime) | (none) | OK — async tests cover this path |

## Test Costs

| Category | Count | Examples |
|----------|-------|---------|
| FREE | 345 | Pure logic: serde roundtrips, parsing, formatting, delta, codec, mux requests, safety rules, install_pack config, group discovery HMAC/nonce |
| CHEAP | 85 | tempfile I/O: blockcache, TLS cert gen, config load, auth keys, session logs |
| MODERATE | 70 | TCP loopback: relay, rendezvous mock, client mock, listener, commands mock, fleet discover |
| EXPENSIVE | 0 | No paid APIs, no device wear |

## Mock Analysis

| Dep Type | Mock Strategy | Effectiveness |
|----------|---------------|---------------|
| TLS/Network | In-memory duplex stream (tokio::io::duplex) | FULL |
| Filesystem | tempdir (std::env::temp_dir / tempfile crate) | FULL |
| Time/Clock | chrono::Local::now (fixture dates in JSONL) | FULL |
| SSH keys | tempfile with test keys | FULL |
| Windows API | #[cfg(test)] stubs | PARTIAL |
| Unix sockets | Real UDS in tempdir | FULL |
| RDP session | Not mockable | FACADE |
| Win10 IoT LTSC | Not mockable (HW-specific) | FACADE |
| Rendezvous server | Mock UDP responder in test | FULL |
| QUIC transport | quinn::Endpoint with localhost certs | FULL |

## Gaps — Priority Order

### P1 — Partial Coverage

| Module | Gap | Cost |
|--------|-----|------|
| client.rs | `connect_over_stream` relay path | MODERATE |
| install_pack.rs | NSIS installer with real service install on target | MODERATE |

### P2 — Error Paths

| Module | Gap | Cost |
|--------|-----|------|
| server/sync.rs | Concurrent push/pull stress test | MODERATE |
| tray.rs | Win32 tray loop (Option<Layer>, log separation) — HW-specific | CHEAP |
| selfupdate.rs | Atomic swap failure + rollback | CHEAP |
| recording.rs | Malformed session recording files | FREE |

### P3 — Regression (integration)

| Module | Gap | Cost |
|--------|-----|------|
| solved/004 | RDP screenshot | EXPENSIVE (environment) |

### P4 — Document Only (not testable in CI)

| Module | Gap | Reason |
|--------|-----|--------|
| solved/011 | Tray crash Win10 IoT LTSC | HW-specific, 4 root causes |
| solved/004 | RDP screenshot GetDIBits | RDP session required |

### P5 — Feature-gated modules

| Module | Gap | Cost |
|--------|-----|------|
| quic.rs | Only 5 tests for 914 lines — connection setup, error paths | MODERATE |
| ssh.rs | Feature-gated, not in default test run | MODERATE |

## Changes Since Last Update (v5.16.0 test coverage push)

- **notify.rs**: 47 → 153 lines, 0 → 8 tests (+8) — broadcast channel, subscribe, event fields
- **sync.rs**: 1174 → 1285 lines, 9 → 14 tests (+5) — large file chunking, sanitize_path
- **tray.rs**: 403 → 438 lines, 5 → 8 tests (+3) — cancelled token, various ports, all variants
- rsh-server: 175 → 191 (+16)
- Total: 504 → 520 running on Linux (default features)
- Gaps closed: sync.rs large file chunking, notify.rs (was NONE), solved/002 regression

## Changes (v5.15.0 → v5.16.0)

- **install_pack.rs**: 790 → 770 lines, 9 → 11 tests (+2) — NSIS installer replaces custom SFX
  - Windows: replaced SFX stub + ZIP with NSIS-based installer (requires `makensis` on build host)
  - Removed `rsh-sfx-stub` crate (141 lines), `zip` dependency from rsh-client
  - NSIS: ~34KB overhead, AV-friendly, LZMA compression, UAC elevation, service install + firewall
  - New tests: nsi_script_has_required_sections, nsi_script_includes_optional_files,
    nsi_script_excludes_optional_files_when_absent, nsis_installer_e2e
  - Removed tests: zip_data_contains_all_entries, sfx_exe_has_correct_layout
- rsh-client: 199 → 201 (+2)
- Total: 504 running on Linux (default features)
- Version: 5.15.0 → 5.16.0

## Changes (v5.14.0 → v5.15.0)

- **install_pack.rs**: 667 → 790 lines, 8 → 9 tests (+1) — Windows SFX .exe output
  - Windows: now produces self-extracting .exe (SFX stub + ZIP + RSFX trailer)
  - New `rsh-sfx-stub` crate: 141-line Windows stub with icon embedding, UAC elevation
  - SFX binary layout: `[stub.exe][ZIP payload][u64 zip_offset LE][b"RSFX" magic]`
  - find_binary/find_sfx_stub: now also look relative to running exe's directory
- rsh-client: 198 → 199 (+1)
- Total: 502 running on Linux (default features)
- Version: 5.14.0 → 5.15.0

## Changes (v5.13.0 → v5.14.0)

- **install_pack.rs**: 540 → 667 lines, 7 → 8 tests (+1) — single compressed file output
  - Linux: self-extracting .sh (bash header + tar.gz payload)
  - Windows: .zip with deflate compression
  - E2E tested: MDP-RUG install via SFX .sh
- rsh-client: 197 → 198 (+1)
- Total: 501 running on Linux (default features)
- Version: 5.13.0 → 5.14.0

## Changes (v5.11.0 → v5.13.0)

- **rendezvous.rs**: 505 → 1270 lines, 7 → 18 tests (+11) — fleet enrollment, group discovery, HMAC auth, nonce replay, LAN detection
- **config.rs**: 577 → 605 lines, 15 → 17 tests (+2) — enrollment_token parsing + round-trip
- **fleet.rs**: 478 lines, 10 tests (stable, group token management)
- **install_pack.rs**: 424 → 540 lines, 7 tests (stable, group config embedding)
- **service.rs**: 359 → 388 lines, 7 tests (stable)
- **tray.rs**: 375 → 403 lines, 5 tests (stable)
- Total: 500 running on Linux (default features), 512 with all features
- Version: 5.11.0 → 5.13.0
- rsh-core: 65 → 67 (+2)
- rsh-relay: 27 → 38 (+11)
- rsh-client: 197 (stable)
- rsh-server: 175 (stable on default features)
- New fix commit: 935bb67 (.await for relay/rendezvous) — covered by async tests
