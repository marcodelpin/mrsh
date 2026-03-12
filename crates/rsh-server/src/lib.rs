//! rsh server — TLS listener, auth dispatch, command execution.
//! Core modules work cross-platform; Windows-specific modules use cfg(windows).

pub mod dispatch;
pub mod exec;
pub mod exec_user;
pub mod fileops;
pub mod gui;
pub mod handler;
pub mod listener;
pub mod mux;
pub mod notify;
pub mod plugin;
pub mod ratelimit;
pub mod safety;
pub mod screenshot;
pub mod selfupdate;
pub mod service;
pub mod session;
pub mod shell;
pub mod sync;
pub mod tray;
pub mod tunnel;

#[cfg(feature = "quic")]
pub mod quic;

#[cfg(feature = "ssh")]
pub mod ssh;
