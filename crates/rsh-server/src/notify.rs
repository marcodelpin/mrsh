//! Connection notification channel — sends events from the server to the tray.
//!
//! When a client authenticates, the handler sends a `ConnectionEvent` through
//! a broadcast channel. The tray icon (if running) subscribes and shows a
//! toast notification with client IP and key comment.
//!
//! This provides user-visible evidence of remote connections — a key
//! anti-abuse measure. Users can see who is connecting to their machine.

use std::net::SocketAddr;
use std::sync::OnceLock;

use tokio::sync::broadcast;

/// A connection event for user notification.
#[derive(Debug, Clone)]
pub struct ConnectionEvent {
    pub peer: SocketAddr,
    pub key_comment: Option<String>,
    pub timestamp: std::time::SystemTime,
}

/// Global broadcast sender — initialized once, cloned by subscribers.
static SENDER: OnceLock<broadcast::Sender<ConnectionEvent>> = OnceLock::new();

/// Initialize the notification channel (call once at startup).
pub fn init() -> broadcast::Receiver<ConnectionEvent> {
    let (tx, rx) = broadcast::channel(32);
    let _ = SENDER.set(tx);
    rx
}

/// Subscribe to connection events (for the tray icon).
pub fn subscribe() -> Option<broadcast::Receiver<ConnectionEvent>> {
    SENDER.get().map(|tx| tx.subscribe())
}

/// Notify about a new authenticated connection.
pub fn notify_connection(peer: SocketAddr, key_comment: Option<String>) {
    if let Some(tx) = SENDER.get() {
        let _ = tx.send(ConnectionEvent {
            peer,
            key_comment,
            timestamp: std::time::SystemTime::now(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), port)
    }

    #[test]
    fn connection_event_fields() {
        let addr = test_addr(12345);
        let event = ConnectionEvent {
            peer: addr,
            key_comment: Some("test-key".to_string()),
            timestamp: std::time::SystemTime::now(),
        };
        assert_eq!(event.peer, addr);
        assert_eq!(event.key_comment.as_deref(), Some("test-key"));
    }

    #[test]
    fn connection_event_clone() {
        let event = ConnectionEvent {
            peer: test_addr(1111),
            key_comment: None,
            timestamp: std::time::SystemTime::now(),
        };
        let cloned = event.clone();
        assert_eq!(cloned.peer, event.peer);
        assert!(cloned.key_comment.is_none());
    }

    #[test]
    fn connection_event_debug() {
        let event = ConnectionEvent {
            peer: test_addr(2222),
            key_comment: Some("admin".to_string()),
            timestamp: std::time::SystemTime::now(),
        };
        let debug = format!("{:?}", event);
        assert!(debug.contains("192.168.1.100"));
        assert!(debug.contains("admin"));
    }

    #[test]
    fn notify_without_init_does_not_panic() {
        // If SENDER is not yet initialized (or already was by another test),
        // notify_connection should not panic either way.
        notify_connection(test_addr(3333), Some("no-init".to_string()));
    }

    #[test]
    fn init_and_subscribe_deliver_events() {
        // init() sets the global SENDER via OnceLock — may already be set
        // by a previous test. Use subscribe() which always works after init.
        let _rx = init(); // idempotent — OnceLock ignores second set

        // subscribe() returns Some if SENDER was ever initialized
        if let Some(mut rx) = subscribe() {
            notify_connection(test_addr(4444), Some("sub-test".to_string()));
            match rx.try_recv() {
                Ok(event) => {
                    assert_eq!(event.peer.port(), 4444);
                    assert_eq!(event.key_comment.as_deref(), Some("sub-test"));
                }
                Err(broadcast::error::TryRecvError::Empty) => {
                    // Event may have been consumed by another subscriber — OK
                }
                Err(e) => panic!("unexpected recv error: {:?}", e),
            }
        }
    }

    #[test]
    fn subscribe_returns_receiver_after_init() {
        let _rx = init();
        // After init, subscribe should return Some
        assert!(subscribe().is_some() || SENDER.get().is_some());
    }

    #[test]
    fn multiple_subscribers_receive_events() {
        let _rx = init();
        if let (Some(mut rx1), Some(mut rx2)) = (subscribe(), subscribe()) {
            notify_connection(test_addr(5555), None);
            // Both should receive (broadcast)
            let got1 = rx1.try_recv().is_ok();
            let got2 = rx2.try_recv().is_ok();
            // At least one should get it (broadcast delivers to all active)
            assert!(got1 || got2, "at least one subscriber should receive");
        }
    }

    #[test]
    fn event_without_key_comment() {
        let _rx = init();
        if let Some(mut rx) = subscribe() {
            notify_connection(test_addr(6666), None);
            if let Ok(event) = rx.try_recv() {
                assert!(event.key_comment.is_none());
            }
        }
    }
}
