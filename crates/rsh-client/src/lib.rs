//! Cross-platform client — exec, push, pull, shell, fleet, browse, sftp, recording.

pub mod browse;
pub mod client;
pub mod commands;
pub mod config_tui;
pub mod fleet;
pub mod host_picker;
pub mod mux;
pub mod recording;
pub mod session_log;
pub mod sftp;
pub mod shell;
pub mod socks;
pub mod sync;
pub mod install_pack;
pub mod relay_connect;
pub mod tunnel;
#[cfg(feature = "quic")]
pub mod quic;
