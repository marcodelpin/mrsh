//! Persistent shell session management.
//! Sessions survive client disconnects and can be reattached.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

/// Information about a persistent session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: String,
    pub command: String,
    pub user: String,
    pub state: String, // "attached", "detached", "exited"
    pub clients: usize,
    pub created: String,
    pub idle_secs: u64,
    pub cols: u16,
    pub rows: u16,
}

/// A persistent session entry.
#[derive(Debug)]
pub struct SessionEntry {
    pub id: String,
    pub command: String,
    pub cols: u16,
    pub rows: u16,
    pub created_at: u64,
    pub last_activity: u64,
    pub client_count: usize,
    pub exited: bool,
}

/// Thread-safe session store.
#[derive(Debug, Clone)]
pub struct SessionStore {
    sessions: Arc<Mutex<HashMap<String, SessionEntry>>>,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Generate a cryptographically random session ID (32 hex chars, 128 bits).
    fn generate_id() -> String {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 16];
        rng.fill_bytes(&mut bytes);
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Create a new session, returning its ID.
    pub async fn create(&self, command: String, cols: u16, rows: u16) -> String {
        let id = Self::generate_id();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let entry = SessionEntry {
            id: id.clone(),
            command,
            cols,
            rows,
            created_at: now,
            last_activity: now,
            client_count: 1,
            exited: false,
        };

        let mut sessions = self.sessions.lock().await;
        sessions.insert(id.clone(), entry);
        id
    }

    /// List all sessions.
    pub async fn list(&self) -> Vec<SessionInfo> {
        let sessions = self.sessions.lock().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        sessions
            .values()
            .map(|s| {
                let state = if s.exited {
                    "exited"
                } else if s.client_count > 0 {
                    "attached"
                } else {
                    "detached"
                };

                SessionInfo {
                    id: s.id.clone(),
                    command: s.command.clone(),
                    user: String::new(),
                    state: state.to_string(),
                    clients: s.client_count,
                    created: format_unix_ts(s.created_at),
                    idle_secs: now.saturating_sub(s.last_activity),
                    cols: s.cols,
                    rows: s.rows,
                }
            })
            .collect()
    }

    /// Kill a session by ID. Returns true if found and removed.
    pub async fn kill(&self, id: &str) -> bool {
        let mut sessions = self.sessions.lock().await;
        sessions.remove(id).is_some()
    }

    /// Get session info by ID.
    pub async fn get(&self, id: &str) -> Option<SessionInfo> {
        let sessions = self.sessions.lock().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        sessions.get(id).map(|s| {
            let state = if s.exited {
                "exited"
            } else if s.client_count > 0 {
                "attached"
            } else {
                "detached"
            };

            SessionInfo {
                id: s.id.clone(),
                command: s.command.clone(),
                user: String::new(),
                state: state.to_string(),
                clients: s.client_count,
                created: format_unix_ts(s.created_at),
                idle_secs: now.saturating_sub(s.last_activity),
                cols: s.cols,
                rows: s.rows,
            }
        })
    }

    /// Mark a session as having one more attached client.
    pub async fn attach(&self, id: &str) -> bool {
        let mut sessions = self.sessions.lock().await;
        if let Some(s) = sessions.get_mut(id) {
            s.client_count += 1;
            s.last_activity = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            true
        } else {
            false
        }
    }

    /// Mark a session as having one fewer attached client.
    pub async fn detach(&self, id: &str) {
        let mut sessions = self.sessions.lock().await;
        if let Some(s) = sessions.get_mut(id) {
            s.client_count = s.client_count.saturating_sub(1);
        }
    }

    /// Cleanup idle sessions (no clients, idle > max_idle_secs).
    pub async fn cleanup(&self, max_idle_secs: u64) -> usize {
        let mut sessions = self.sessions.lock().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let to_remove: Vec<String> = sessions
            .iter()
            .filter(|(_, s)| {
                s.client_count == 0 && now.saturating_sub(s.last_activity) > max_idle_secs
            })
            .map(|(id, _)| id.clone())
            .collect();

        let count = to_remove.len();
        for id in to_remove {
            sessions.remove(&id);
        }
        count
    }
}

fn format_unix_ts(ts: u64) -> String {
    // Simple ISO 8601 UTC format
    let secs_per_day = 86400u64;
    let days = ts / secs_per_day;
    let day_secs = ts % secs_per_day;
    let hours = day_secs / 3600;
    let minutes = (day_secs % 3600) / 60;
    let seconds = day_secs % 60;

    // Days since epoch to Y-M-D (same algorithm as fileops)
    let (y, m, d) = days_to_date(days as i64);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hours, minutes, seconds
    )
}

fn days_to_date(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn create_and_list() {
        let store = SessionStore::new();
        let id = store.create("powershell".to_string(), 80, 24).await;
        assert!(!id.is_empty());

        let sessions = store.list().await;
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, id);
        assert_eq!(sessions[0].state, "attached");
        assert_eq!(sessions[0].cols, 80);
    }

    #[tokio::test]
    async fn kill_session() {
        let store = SessionStore::new();
        let id = store.create("sh".to_string(), 80, 24).await;
        assert!(store.kill(&id).await);
        assert!(!store.kill(&id).await); // already killed
        assert!(store.list().await.is_empty());
    }

    #[tokio::test]
    async fn attach_detach() {
        let store = SessionStore::new();
        let id = store.create("sh".to_string(), 80, 24).await;

        // Initial client count is 1
        let info = store.get(&id).await.unwrap();
        assert_eq!(info.clients, 1);

        // Attach another
        assert!(store.attach(&id).await);
        let info = store.get(&id).await.unwrap();
        assert_eq!(info.clients, 2);

        // Detach both
        store.detach(&id).await;
        store.detach(&id).await;
        let info = store.get(&id).await.unwrap();
        assert_eq!(info.clients, 0);
        assert_eq!(info.state, "detached");
    }

    #[tokio::test]
    async fn cleanup_idle() {
        let store = SessionStore::new();
        let id = store.create("sh".to_string(), 80, 24).await;

        // Detach and backdate
        store.detach(&id).await;
        {
            let mut sessions = store.sessions.lock().await;
            if let Some(s) = sessions.get_mut(&id) {
                s.last_activity -= 100;
            }
        }

        // Cleanup with 50s threshold should remove it
        let removed = store.cleanup(50).await;
        assert_eq!(removed, 1);
        assert!(store.list().await.is_empty());
    }

    #[tokio::test]
    async fn cleanup_keeps_attached() {
        let store = SessionStore::new();
        let _id = store.create("sh".to_string(), 80, 24).await;
        // Still attached (client_count=1), should not be cleaned up
        let removed = store.cleanup(0).await;
        assert_eq!(removed, 0);
    }

    #[tokio::test]
    async fn get_nonexistent() {
        let store = SessionStore::new();
        assert!(store.get("nonexistent").await.is_none());
    }

    #[test]
    fn session_id_has_128_bits_entropy() {
        let id = SessionStore::generate_id();
        assert_eq!(id.len(), 32, "session ID must be 32 hex chars (128 bits)");
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        // Two IDs should be different (probabilistically)
        let id2 = SessionStore::generate_id();
        assert_ne!(id, id2);
    }
}
