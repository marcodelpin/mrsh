//! DLL plugin loader — loads plugins from a directory at startup.
//! Each plugin exports C-ABI functions: RSH_GetPluginInfo, RSH_Execute.
//! Windows-only in production; cross-platform types and manager interface.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use rsh_core::protocol::Response;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// Plugin metadata returned by RSH_GetPluginInfo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    pub name: String,
    pub version: String,
    pub description: String,
    pub commands: Vec<String>,
}

/// Plugin execution result from RSH_Execute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginResult {
    pub success: bool,
    pub output: Option<String>,
    pub error: Option<String>,
    pub data: Option<String>, // base64 binary data
}

/// Plugin manager — loads and manages DLL plugins.
#[derive(Debug)]
pub struct PluginManager {
    plugins: HashMap<String, LoadedPlugin>,
    /// Maps command name → plugin name for direct dispatch.
    command_map: HashMap<String, String>,
}

#[derive(Debug)]
#[allow(dead_code)]
struct LoadedPlugin {
    info: PluginInfo,
    path: PathBuf,
    // On Windows: libloading::Library handle
    #[cfg(target_os = "windows")]
    _library: libloading::Library,
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginManager {
    /// Create a new empty plugin manager.
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
            command_map: HashMap::new(),
        }
    }

    /// Load all .dll plugins from a directory.
    pub fn load_dir(&mut self, dir: &Path) -> Vec<String> {
        let mut loaded = Vec::new();

        if !dir.exists() {
            debug!("plugin dir does not exist: {}", dir.display());
            return loaded;
        }

        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) => {
                warn!("cannot read plugin dir: {}", e);
                return loaded;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|ext| ext != "dll") {
                continue;
            }

            match self.load_plugin(&path) {
                Ok(name) => {
                    info!("loaded plugin: {} from {}", name, path.display());
                    loaded.push(name);
                }
                Err(e) => {
                    warn!("failed to load plugin {}: {}", path.display(), e);
                }
            }
        }

        loaded
    }

    /// Load a single plugin from a DLL path.
    #[cfg(target_os = "windows")]
    fn load_plugin(&mut self, path: &Path) -> anyhow::Result<String> {
        use anyhow::Context;

        // Safety: loading a shared library is inherently unsafe
        let lib = unsafe { libloading::Library::new(path) }.context("load DLL")?;

        // Call RSH_GetPluginInfo
        let info = unsafe {
            let get_info: libloading::Symbol<unsafe extern "C" fn(*mut u8, *mut u32) -> i32> = lib
                .get(b"RSH_GetPluginInfo\0")
                .context("RSH_GetPluginInfo not found")?;

            let mut buf = vec![0u8; 4096];
            let mut buf_len = buf.len() as u32;
            let rc = get_info(buf.as_mut_ptr(), &mut buf_len);
            if rc != 0 {
                anyhow::bail!("RSH_GetPluginInfo returned {}", rc);
            }
            let json_str =
                std::str::from_utf8(&buf[..buf_len as usize]).context("plugin info not UTF-8")?;
            serde_json::from_str::<PluginInfo>(json_str).context("parse plugin info")?
        };

        // Optional: call RSH_Initialize
        if let Ok(init) = unsafe { lib.get::<unsafe extern "C" fn() -> i32>(b"RSH_Initialize\0") } {
            let rc = unsafe { init() };
            if rc != 0 {
                warn!("RSH_Initialize returned {}", rc);
            }
        }

        // Register commands
        let name = info.name.clone();
        for cmd in &info.commands {
            self.command_map.insert(cmd.clone(), name.clone());
        }

        self.plugins.insert(
            name.clone(),
            LoadedPlugin {
                info,
                path: path.to_path_buf(),
                _library: lib,
            },
        );

        Ok(name)
    }

    #[cfg(not(target_os = "windows"))]
    fn load_plugin(&mut self, path: &Path) -> anyhow::Result<String> {
        // DLL loading not supported on non-Windows
        anyhow::bail!(
            "plugin loading not available on this platform: {}",
            path.display()
        )
    }

    /// List loaded plugins.
    pub fn list(&self) -> Vec<PluginInfo> {
        self.plugins.values().map(|p| p.info.clone()).collect()
    }

    /// Check if a command is handled by a plugin.
    pub fn has_command(&self, command: &str) -> bool {
        self.command_map.contains_key(command)
    }

    /// Execute a plugin command.
    #[cfg(target_os = "windows")]
    pub fn execute(&self, command: &str, args: &[String]) -> Response {
        let plugin_name = match self.command_map.get(command) {
            Some(n) => n,
            None => return error_response(&format!("no plugin handles: {}", command)),
        };

        let plugin = match self.plugins.get(plugin_name) {
            Some(p) => p,
            None => return error_response(&format!("plugin not loaded: {}", plugin_name)),
        };

        // Build request JSON
        let req_json = serde_json::json!({
            "command": command,
            "args": args,
        });
        let req_bytes = serde_json::to_vec(&req_json).unwrap_or_default();

        // Call RSH_Execute
        unsafe {
            let lib = &plugin._library;
            let execute: Result<
                libloading::Symbol<unsafe extern "C" fn(*const u8, u32, *mut u8, *mut u32) -> i32>,
                _,
            > = lib.get(b"RSH_Execute\0");

            match execute {
                Ok(func) => {
                    let mut resp_buf = vec![0u8; 65536];
                    let mut resp_len = resp_buf.len() as u32;
                    let rc = func(
                        req_bytes.as_ptr(),
                        req_bytes.len() as u32,
                        resp_buf.as_mut_ptr(),
                        &mut resp_len,
                    );

                    if rc != 0 {
                        return error_response(&format!("plugin execute returned {}", rc));
                    }

                    let resp_json =
                        std::str::from_utf8(&resp_buf[..resp_len as usize]).unwrap_or("{}");
                    match serde_json::from_str::<PluginResult>(resp_json) {
                        Ok(result) => Response {
                            success: result.success,
                            output: result.output,
                            error: result.error,
                            size: None,
                            binary: result.data.as_ref().map(|_| true),
                            gzip: None,
                        },
                        Err(e) => error_response(&format!("parse plugin response: {}", e)),
                    }
                }
                Err(e) => error_response(&format!("RSH_Execute not found: {}", e)),
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn execute(&self, command: &str, _args: &[String]) -> Response {
        error_response(&format!(
            "plugin execution not available on this platform: {}",
            command
        ))
    }
}

/// Handle a plugin management command (list, reload).
pub fn handle_plugin_command(action: &str, manager: &PluginManager) -> Response {
    match action {
        "list" => {
            let plugins = manager.list();
            let json = serde_json::to_string(&plugins).unwrap_or_default();
            Response {
                success: true,
                output: Some(json),
                error: None,
                size: None,
                binary: None,
                gzip: None,
            }
        }
        other => error_response(&format!("unknown plugin action: {}", other)),
    }
}

fn error_response(msg: &str) -> Response {
    Response {
        success: false,
        output: None,
        error: Some(msg.to_string()),
        size: None,
        binary: None,
        gzip: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_manager_empty() {
        let mgr = PluginManager::new();
        assert!(mgr.list().is_empty());
        assert!(!mgr.has_command("test"));
    }

    #[test]
    fn plugin_info_serializes() {
        let info = PluginInfo {
            name: "test-plugin".to_string(),
            version: "1.0.0".to_string(),
            description: "A test plugin".to_string(),
            commands: vec!["cmd1".to_string(), "cmd2".to_string()],
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("test-plugin"));
        assert!(json.contains("cmd1"));
    }

    #[test]
    fn handle_plugin_list_empty() {
        let mgr = PluginManager::new();
        let resp = handle_plugin_command("list", &mgr);
        assert!(resp.success);
        assert_eq!(resp.output.as_deref(), Some("[]"));
    }

    #[test]
    fn handle_plugin_unknown_action() {
        let mgr = PluginManager::new();
        let resp = handle_plugin_command("unknown", &mgr);
        assert!(!resp.success);
    }

    #[test]
    fn load_dir_nonexistent() {
        let mut mgr = PluginManager::new();
        let loaded = mgr.load_dir(Path::new("/nonexistent/plugin/dir"));
        assert!(loaded.is_empty());
    }

    #[test]
    fn execute_unknown_command() {
        let mgr = PluginManager::new();
        let resp = mgr.execute("nonexistent", &[]);
        assert!(!resp.success);
    }
}
