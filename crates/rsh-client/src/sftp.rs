//! SFTP-like interactive shell over the rsh protocol.
//!
//! Provides familiar sftp commands (ls, cd, get, put, etc.)
//! using the existing TLS connection.

use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;
use rsh_core::protocol::FileInfo;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::client::RshClient;

/// Run the interactive SFTP shell.
pub async fn run_sftp<S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut RshClient<S>,
    host_display: &str,
) -> Result<()> {
    // Get initial remote cwd
    let resp = crate::commands::exec(client, "(Get-Location).Path", &[]).await?;
    let mut remote_cwd = resp.trim().to_string();

    let mut local_cwd = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .to_string_lossy()
        .to_string();

    eprintln!("Connected to {}", host_display);
    eprintln!("Remote: {}", remote_cwd);
    eprintln!("Type 'help' for available commands.");

    let stdin = io::stdin();
    let reader = stdin.lock();

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        let line = line.trim().to_string();
        if line.is_empty() {
            eprint!("sftp> ");
            let _ = io::stderr().flush();
            continue;
        }

        let parts = split_args(&line);
        if parts.is_empty() {
            eprint!("sftp> ");
            let _ = io::stderr().flush();
            continue;
        }

        let cmd = &parts[0];
        let args = &parts[1..];

        match cmd.as_str() {
            "help" | "?" => print_help(),

            "quit" | "exit" | "bye" => return Ok(()),

            "pwd" => println!("{}", remote_cwd),

            "lpwd" => println!("{}", local_cwd),

            "cd" => {
                if args.is_empty() {
                    eprintln!("Usage: cd <path>");
                } else {
                    let path = resolve_remote_path(&remote_cwd, &args[0]);
                    let ps_cmd = format!("(Resolve-Path '{}').Path", escape_ps(&path));
                    match crate::commands::exec(client, &ps_cmd, &[]).await {
                        Ok(out) => remote_cwd = out.trim().to_string(),
                        Err(e) => eprintln!("cd: {}", e),
                    }
                }
            }

            "lcd" => {
                if args.is_empty() {
                    eprintln!("Usage: lcd <path>");
                } else {
                    let target = if Path::new(&args[0]).is_absolute() {
                        args[0].clone()
                    } else {
                        format!("{}/{}", local_cwd, args[0])
                    };
                    match std::fs::metadata(&target) {
                        Ok(m) if m.is_dir() => local_cwd = target,
                        Ok(_) => eprintln!("lcd: not a directory"),
                        Err(e) => eprintln!("lcd: {}", e),
                    }
                }
            }

            "ls" | "dir" => {
                let path = if args.is_empty() {
                    remote_cwd.clone()
                } else {
                    resolve_remote_path(&remote_cwd, &args[0])
                };
                match crate::commands::ls(client, &path).await {
                    Ok(files) => print_listing(&files),
                    Err(e) => eprintln!("ls: {}", e),
                }
            }

            "lls" => {
                let path = if args.is_empty() {
                    local_cwd.clone()
                } else {
                    format!("{}/{}", local_cwd, args[0])
                };
                match std::fs::read_dir(&path) {
                    Ok(entries) => {
                        for entry in entries.flatten() {
                            if let Ok(meta) = entry.metadata() {
                                if meta.is_dir() {
                                    println!(
                                        "drw  {:>12}  {}/",
                                        "-",
                                        entry.file_name().to_string_lossy()
                                    );
                                } else {
                                    println!(
                                        "-rw  {:>12}  {}",
                                        meta.len(),
                                        entry.file_name().to_string_lossy()
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => eprintln!("lls: {}", e),
                }
            }

            "cat" => {
                if args.is_empty() {
                    eprintln!("Usage: cat <remote-path>");
                } else {
                    let path = resolve_remote_path(&remote_cwd, &args[0]);
                    match crate::commands::cat(client, &path).await {
                        Ok(data) => {
                            let _ = io::stdout().write_all(&data);
                        }
                        Err(e) => eprintln!("cat: {}", e),
                    }
                }
            }

            "get" => {
                if args.is_empty() {
                    eprintln!("Usage: get <remote-path> [local-path]");
                } else {
                    let remote_path = resolve_remote_path(&remote_cwd, &args[0]);
                    let local_path = if args.len() > 1 {
                        if Path::new(&args[1]).is_absolute() {
                            args[1].clone()
                        } else {
                            format!("{}/{}", local_cwd, args[1])
                        }
                    } else {
                        let base = Path::new(&args[0])
                            .file_name()
                            .map(|f| f.to_string_lossy().to_string())
                            .unwrap_or_else(|| args[0].clone());
                        format!("{}/{}", local_cwd, base)
                    };
                    eprintln!("Downloading {} -> {}", remote_path, local_path);
                    // Read existing local data for delta
                    let local_data = std::fs::read(&local_path).ok();
                    match crate::sync::pull(client, local_data.as_deref(), &remote_path).await {
                        Ok(pr) => {
                            if let Err(e) = std::fs::write(&local_path, &pr.data) {
                                eprintln!("get: write error: {}", e);
                            } else {
                                eprintln!("Downloaded {} bytes", pr.data.len());
                            }
                        }
                        Err(e) => eprintln!("get: {}", e),
                    }
                }
            }

            "put" => {
                if args.is_empty() {
                    eprintln!("Usage: put <local-path> [remote-path]");
                } else {
                    let local_path = if Path::new(&args[0]).is_absolute() {
                        args[0].clone()
                    } else {
                        format!("{}/{}", local_cwd, args[0])
                    };
                    let remote_path = if args.len() > 1 {
                        resolve_remote_path(&remote_cwd, &args[1])
                    } else {
                        let base = Path::new(&args[0])
                            .file_name()
                            .map(|f| f.to_string_lossy().to_string())
                            .unwrap_or_else(|| args[0].clone());
                        format!("{}\\{}", remote_cwd, base)
                    };
                    match std::fs::read(&local_path) {
                        Ok(data) => {
                            eprintln!("Uploading {} -> {}", local_path, remote_path);
                            match crate::sync::push(client, &data, &remote_path).await {
                                Ok(_) => eprintln!("Uploaded {} bytes", data.len()),
                                Err(e) => eprintln!("put: {}", e),
                            }
                        }
                        Err(e) => eprintln!("put: {}", e),
                    }
                }
            }

            "mkdir" => {
                if args.is_empty() {
                    eprintln!("Usage: mkdir <remote-path>");
                } else {
                    let path = resolve_remote_path(&remote_cwd, &args[0]);
                    let ps_cmd = format!(
                        "New-Item -ItemType Directory -Path '{}' -Force | Out-Null; echo 'OK'",
                        escape_ps(&path)
                    );
                    match crate::commands::exec(client, &ps_cmd, &[]).await {
                        Ok(_) => eprintln!("Created {}", path),
                        Err(e) => eprintln!("mkdir: {}", e),
                    }
                }
            }

            "rm" | "del" => {
                if args.is_empty() {
                    eprintln!("Usage: rm <remote-path>");
                } else {
                    let path = resolve_remote_path(&remote_cwd, &args[0]);
                    let ps_cmd = format!(
                        "Remove-Item -Force -Recurse '{}'; echo 'OK'",
                        escape_ps(&path)
                    );
                    match crate::commands::exec(client, &ps_cmd, &[]).await {
                        Ok(_) => eprintln!("Removed {}", path),
                        Err(e) => eprintln!("rm: {}", e),
                    }
                }
            }

            "mv" | "rename" => {
                if args.len() < 2 {
                    eprintln!("Usage: mv <source> <dest>");
                } else {
                    let src = resolve_remote_path(&remote_cwd, &args[0]);
                    let dst = resolve_remote_path(&remote_cwd, &args[1]);
                    let ps_cmd = format!(
                        "Move-Item '{}' '{}'; echo 'OK'",
                        escape_ps(&src),
                        escape_ps(&dst)
                    );
                    match crate::commands::exec(client, &ps_cmd, &[]).await {
                        Ok(_) => eprintln!("Moved {} -> {}", src, dst),
                        Err(e) => eprintln!("mv: {}", e),
                    }
                }
            }

            "stat" => {
                if args.is_empty() {
                    eprintln!("Usage: stat <remote-path>");
                } else {
                    let path = resolve_remote_path(&remote_cwd, &args[0]);
                    let ps_cmd = format!(
                        "Get-Item '{}' | Format-List Name,Length,LastWriteTime,Attributes",
                        escape_ps(&path)
                    );
                    match crate::commands::exec(client, &ps_cmd, &[]).await {
                        Ok(out) => print!("{}", out),
                        Err(e) => eprintln!("stat: {}", e),
                    }
                }
            }

            "df" => {
                let ps_cmd =
                    "Get-PSDrive -PSProvider FileSystem | Format-Table Name,Used,Free -AutoSize";
                match crate::commands::exec(client, ps_cmd, &[]).await {
                    Ok(out) => print!("{}", out),
                    Err(e) => eprintln!("df: {}", e),
                }
            }

            _ => {
                eprintln!("Unknown command: {} (type 'help' for commands)", cmd);
            }
        }

        eprint!("sftp> ");
        let _ = io::stderr().flush();
    }

    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────

fn print_help() {
    eprintln!(
        "Available commands:
  ls [path]              List remote directory
  lls [path]             List local directory
  cd <path>              Change remote directory
  lcd <path>             Change local directory
  pwd                    Print remote working directory
  lpwd                   Print local working directory
  cat <file>             Display remote file contents
  get <remote> [local]   Download file
  put <local> [remote]   Upload file
  mkdir <path>           Create remote directory
  rm <path>              Remove remote file/directory
  mv <src> <dst>         Move/rename remote file
  stat <path>            Show remote file info
  df                     Show remote disk usage
  help                   Show this help
  quit                   Exit"
    );
}

fn print_listing(files: &[FileInfo]) {
    for f in files {
        if f.is_dir {
            println!("drw  {:>12}  {}  {}/", "-", f.mod_time, f.name);
        } else {
            println!("-rw  {:>12}  {}  {}", f.size, f.mod_time, f.name);
        }
    }
}

/// Resolve a path relative to the remote cwd.
pub fn resolve_remote_path(cwd: &str, path: &str) -> String {
    // Absolute Windows paths
    if path.len() >= 2 && path.as_bytes()[1] == b':' {
        return path.to_string();
    }
    if path.starts_with("\\\\") || path.starts_with('/') {
        return path.to_string();
    }
    format!("{}\\{}", cwd, path)
}

/// Escape single quotes for PowerShell string literals.
fn escape_ps(s: &str) -> String {
    s.replace('\'', "''")
}

/// Split a command line respecting quoted strings.
pub fn split_args(line: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;
    let mut quote_char = 0u8;

    for &c in line.as_bytes() {
        if in_quote {
            if c == quote_char {
                in_quote = false;
            } else {
                current.push(c as char);
            }
        } else if c == b'"' || c == b'\'' {
            in_quote = true;
            quote_char = c;
        } else if c == b' ' || c == b'\t' {
            if !current.is_empty() {
                args.push(std::mem::take(&mut current));
            }
        } else {
            current.push(c as char);
        }
    }
    if !current.is_empty() {
        args.push(current);
    }
    args
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_args_simple() {
        assert_eq!(split_args("ls foo"), vec!["ls", "foo"]);
    }

    #[test]
    fn split_args_quoted() {
        assert_eq!(
            split_args(r#"get "C:\Program Files\test.txt" local.txt"#),
            vec!["get", "C:\\Program Files\\test.txt", "local.txt"]
        );
    }

    #[test]
    fn split_args_single_quoted() {
        assert_eq!(
            split_args("exec 'hello world'"),
            vec!["exec", "hello world"]
        );
    }

    #[test]
    fn split_args_empty() {
        assert!(split_args("").is_empty());
        assert!(split_args("   ").is_empty());
    }

    #[test]
    fn resolve_absolute_windows() {
        assert_eq!(resolve_remote_path("C:\\Users", "D:\\Temp"), "D:\\Temp");
    }

    #[test]
    fn resolve_unc() {
        assert_eq!(
            resolve_remote_path("C:\\Users", "\\\\server\\share"),
            "\\\\server\\share"
        );
    }

    #[test]
    fn resolve_relative() {
        assert_eq!(
            resolve_remote_path("C:\\Users\\test", "docs"),
            "C:\\Users\\test\\docs"
        );
    }

    #[test]
    fn resolve_unix_absolute() {
        assert_eq!(resolve_remote_path("C:\\Users", "/tmp/test"), "/tmp/test");
    }

    #[test]
    fn escape_ps_quotes() {
        assert_eq!(escape_ps("it's a test"), "it''s a test");
        assert_eq!(escape_ps("no quotes"), "no quotes");
    }
}
