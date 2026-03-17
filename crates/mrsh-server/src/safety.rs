//! Exec safety guard — blocks commands that would kill/stop this mrsh process.
//!
//! AI agents frequently use mrsh for remote management. Without server-side
//! guards, a command like `taskkill /im rsh.exe /f` sent via `rsh exec`
//! kills the server, cutting off the agent's only access channel.
//!
//! This module detects self-destructive patterns and rejects them with a
//! clear error message explaining why and suggesting safe alternatives.

use tracing::warn;

/// Result of a safety check.
pub enum SafetyVerdict {
    /// Command is safe to execute.
    Allow,
    /// Command would kill/stop/remove mrsh itself.
    Block { reason: String },
}

/// Check if a command would be self-destructive for the mrsh server process.
///
/// Returns `SafetyVerdict::Block` with an explanation if the command matches
/// known dangerous patterns.
pub fn check_exec(command: &str) -> SafetyVerdict {
    let lower = command.to_lowercase();
    // Remove extra whitespace for reliable matching
    let normalized: String = lower.split_whitespace().collect::<Vec<_>>().join(" ");

    // Pattern 1: taskkill targeting rsh
    if normalized.contains("taskkill") && normalized.contains("rsh") {
        return block("taskkill would kill the mrsh process serving this connection. \
            Use 'rsh self-update' for safe binary replacement, or schedule \
            via schtask if you need to restart.");
    }

    // Pattern 2: Stop-Service / net stop targeting rsh
    if (normalized.contains("stop-service") || normalized.contains("net stop"))
        && (normalized.contains("rsh") || normalized.contains("mrsh")
            || normalized.contains("remote shell"))
    {
        return block("Stopping the mrsh service would cut off this connection. \
            Use 'rsh self-update' for safe binary replacement.");
    }

    // Pattern 3: Stop-Process targeting rsh
    if normalized.contains("stop-process") && normalized.contains("rsh") {
        return block("Stop-Process would kill the mrsh process serving this connection. \
            Use 'rsh self-update' for safe replacement.");
    }

    // Pattern 4: Remove-Item / del targeting rsh.exe binary
    if (normalized.contains("remove-item") || normalized.contains("del "))
        && normalized.contains("rsh.exe")
    {
        return block("Deleting rsh.exe while it's running would prevent service restart. \
            Push the new binary as rsh-new.exe first, then use 'rsh self-update'.");
    }

    // Pattern 5: sc delete targeting mrsh service
    if normalized.contains("sc") && normalized.contains("delete")
        && (normalized.contains("rsh") || normalized.contains("mrsh"))
    {
        return block("Deleting the mrsh service registration would prevent restart. \
            Use 'rsh self-update' or manual schtask-based update instead.");
    }

    SafetyVerdict::Allow
}

fn block(reason: &str) -> SafetyVerdict {
    warn!("SAFETY GUARD: blocked self-destructive command");
    SafetyVerdict::Block {
        reason: format!("BLOCKED by safety guard: {}", reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_blocked(cmd: &str) -> bool {
        matches!(check_exec(cmd), SafetyVerdict::Block { .. })
    }

    fn is_allowed(cmd: &str) -> bool {
        matches!(check_exec(cmd), SafetyVerdict::Allow)
    }

    #[test]
    fn blocks_taskkill_rsh() {
        assert!(is_blocked("taskkill /im rsh.exe /f"));
        assert!(is_blocked("taskkill /IM rsh.exe"));
        assert!(is_blocked("TASKKILL /F /IM rsh.exe"));
    }

    #[test]
    fn blocks_stop_service() {
        assert!(is_blocked("Stop-Service rsh"));
        assert!(is_blocked("net stop rsh"));
        assert!(is_blocked("net stop mrsh"));
        assert!(is_blocked("Stop-Service 'mrsh'"));
    }

    #[test]
    fn blocks_stop_process() {
        assert!(is_blocked("Stop-Process -Name rsh"));
        assert!(is_blocked("Stop-Process -Name mrsh -Force"));
        assert!(is_blocked("Get-Process mrsh | Stop-Process"));
    }

    #[test]
    fn blocks_delete_binary() {
        assert!(is_blocked("Remove-Item C:\\ProgramData\\mrsh\\rsh.exe"));
        assert!(is_blocked("del C:\\ProgramData\\mrsh\\rsh.exe"));
    }

    #[test]
    fn blocks_sc_delete() {
        assert!(is_blocked("sc delete rsh"));
        assert!(is_blocked("sc delete mrsh"));
    }

    #[test]
    fn allows_safe_commands() {
        assert!(is_allowed("Get-Process"));
        assert!(is_allowed("hostname"));
        assert!(is_allowed("dir C:\\ProgramData\\mrsh\\"));
        assert!(is_allowed("taskkill /im notepad.exe /f"));
        assert!(is_allowed("Stop-Service Spooler"));
        assert!(is_allowed("net stop Spooler"));
    }

    #[test]
    fn allows_rsh_new_operations() {
        // Pushing/deleting rsh-new.exe should be allowed (safe update path)
        assert!(is_allowed("Remove-Item C:\\temp\\rsh-new.exe"));
        assert!(is_allowed("Copy-Item rsh-new.exe rsh.exe"));
    }

    #[test]
    fn allows_mrsh_client_commands() {
        // Running mrsh as a client command is fine
        assert!(is_allowed("rsh -h other-host ping"));
        assert!(is_allowed("C:\\ProgramData\\mrsh\\rsh.exe -h 192.168.1.1 exec hostname"));
    }
}
