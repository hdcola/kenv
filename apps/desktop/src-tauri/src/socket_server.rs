use crate::handlers;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::thread;
use tauri::Emitter;
use zeroize::Zeroizing;

#[derive(Debug, Serialize, Deserialize)]
struct Request {
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize, Deserialize)]
struct Response {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

pub fn start_socket_server(app_handle: tauri::AppHandle) {
    thread::spawn(move || {
        if let Err(e) = run_socket_server(app_handle) {
            eprintln!("Socket server error: {}", e);
        }
    });
}

fn socket_path() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or("home directory not found")?;
    Ok(home.join(".kenv").join("desktop.sock"))
}

struct SocketGuard(PathBuf);

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn run_socket_server(app_handle: tauri::AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    let path = socket_path()?;

    // Create parent directory if needed
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    if path.exists() {
        if UnixStream::connect(&path).is_ok() {
            return Err("another instance of kenv desktop is already running".into());
        }
        let _ = fs::remove_file(&path);
    }

    let listener = UnixListener::bind(&path)?;
    let _guard = SocketGuard(path.clone());

    // Set socket permissions to 0600
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }

    for stream in listener.incoming() {
        match stream {
            Ok(mut socket) => {
                let handle = app_handle.clone();
                thread::spawn(move || {
                    if let Err(e) = handle_client(&mut socket, handle) {
                        eprintln!("Client handler error: {}", e);
                    }
                });
            }
            Err(e) => {
                eprintln!("Connection error: {}", e);
            }
        }
    }

    Ok(())
}

fn handle_client(
    socket: &mut std::os::unix::net::UnixStream,
    app_handle: tauri::AppHandle,
) -> Result<(), Box<dyn std::error::Error>> {
    // Read request with length-prefixed framing
    let request_bytes = read_message(socket)?;
    let request_str = Zeroizing::new(String::from_utf8(request_bytes)?);
    let request: Request = serde_json::from_str(&request_str)?;
    drop(request_str); // zero and free the raw JSON bytes before processing

    let response = handle_request(request, &app_handle);

    let response_json = serde_json::to_string(&response)?;
    send_message(socket, response_json.as_bytes())?;

    Ok(())
}

fn read_exact(
    socket: &mut std::os::unix::net::UnixStream,
    buf: &mut [u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut offset = 0;
    while offset < buf.len() {
        match socket.read(&mut buf[offset..])? {
            0 => return Err("unexpected EOF while reading message".into()),
            n => offset += n,
        }
    }
    Ok(())
}

fn read_message(
    socket: &mut std::os::unix::net::UnixStream,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Read exactly 4 bytes for length header
    let mut len_bytes = [0u8; 4];
    read_exact(socket, &mut len_bytes)?;

    let payload_len = u32::from_be_bytes(len_bytes) as usize;

    const MAX_PAYLOAD: usize = 100 * 1024 * 1024; // 100 MB
    if payload_len == 0 || payload_len > MAX_PAYLOAD {
        return Err(format!("invalid message length: {}", payload_len).into());
    }

    // Allocate and read exactly payload_len bytes
    let mut payload = vec![0u8; payload_len];
    read_exact(socket, &mut payload)?;

    Ok(payload)
}

fn send_message(
    socket: &mut std::os::unix::net::UnixStream,
    payload: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let len = payload.len() as u32;
    socket.write_all(&len.to_be_bytes())?;
    socket.write_all(payload)?;
    Ok(())
}

fn emit_state_changed(app_handle: &tauri::AppHandle) {
    let _ = app_handle.emit("vault-state-changed", ());
}

fn handle_request(req: Request, app_handle: &tauri::AppHandle) -> Response {
    let Request { method, params } = req;
    match method.as_str() {
        "unlock" => match serde_json::from_value::<handlers::UnlockRequest>(params) {
            Ok(unlock_req) => match handlers::handle_unlock(unlock_req) {
                Ok(result) => {
                    emit_state_changed(app_handle);
                    Response {
                        success: true,
                        result: Some(Value::String(result)),
                        error: None,
                    }
                }
                Err(e) => Response {
                    success: false,
                    result: None,
                    error: Some(e),
                },
            },
            Err(e) => Response {
                success: false,
                result: None,
                error: Some(format!("invalid params: {}", e)),
            },
        },
        "list_slots" => match handlers::handle_list_slots() {
            Ok(result) => Response {
                success: true,
                result: serde_json::to_value(&result).ok(),
                error: None,
            },
            Err(e) => Response {
                success: false,
                result: None,
                error: Some(e),
            },
        },
        "list_keys" => match handlers::handle_list_keys() {
            Ok(result) => Response {
                success: true,
                result: serde_json::to_value(&result).ok(),
                error: None,
            },
            Err(e) => Response {
                success: false,
                result: None,
                error: Some(e),
            },
        },
        "remove_slot" => match serde_json::from_value::<handlers::RemoveSlotRequest>(params) {
            Ok(remove_req) => match handlers::handle_remove_slot(remove_req) {
                Ok(result) => {
                    emit_state_changed(app_handle);
                    Response {
                        success: true,
                        result: Some(Value::String(result)),
                        error: None,
                    }
                }
                Err(e) => Response {
                    success: false,
                    result: None,
                    error: Some(e),
                },
            },
            Err(e) => Response {
                success: false,
                result: None,
                error: Some(format!("invalid params: {}", e)),
            },
        },
        "reauth_password" => {
            let pw = params
                .get("password")
                .and_then(|v| v.as_str())
                .map(|s| Zeroizing::new(s.to_string()));
            drop(params);
            match pw {
                Some(pw) => match handlers::handle_reauth_password(pw) {
                    Ok(result) => Response {
                        success: true,
                        result: Some(Value::String(result)),
                        error: None,
                    },
                    Err(e) => Response {
                        success: false,
                        result: None,
                        error: Some(e),
                    },
                },
                None => Response {
                    success: false,
                    result: None,
                    error: Some("missing password parameter".to_string()),
                },
            }
        }
        "status" => match handlers::handle_status() {
            Ok(result) => Response {
                success: true,
                result: Some(Value::String(result)),
                error: None,
            },
            Err(e) => Response {
                success: false,
                result: None,
                error: Some(e),
            },
        },
        "lock" => match handlers::handle_lock() {
            Ok(result) => {
                emit_state_changed(app_handle);
                Response {
                    success: true,
                    result: Some(Value::String(result)),
                    error: None,
                }
            }
            Err(e) => Response {
                success: false,
                result: None,
                error: Some(e),
            },
        },
        "create" => {
            let pw = params
                .get("password")
                .and_then(|v| v.as_str())
                .map(|s| Zeroizing::new(s.to_string()));
            drop(params);
            match pw {
                Some(pw) => match handlers::handle_create(pw) {
                    Ok(result) => {
                        emit_state_changed(app_handle);
                        Response {
                            success: true,
                            result: Some(Value::String(result)),
                            error: None,
                        }
                    }
                    Err(e) => Response {
                        success: false,
                        result: None,
                        error: Some(e),
                    },
                },
                None => Response {
                    success: false,
                    result: None,
                    error: Some("missing password parameter".to_string()),
                },
            }
        }
        _ => Response {
            success: false,
            result: None,
            error: Some(format!("unknown method: {}", method)),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::SocketGuard;
    use std::path::PathBuf;

    #[test]
    fn socket_guard_removes_file_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let path: PathBuf = dir.path().join("test.sock");
        std::fs::write(&path, b"").unwrap();
        assert!(path.exists());
        let guard = SocketGuard(path.clone());
        drop(guard);
        assert!(!path.exists());
    }
}
