use crate::handlers;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::thread;

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

pub fn start_socket_server() {
    thread::spawn(|| {
        if let Err(e) = run_socket_server() {
            eprintln!("Socket server error: {}", e);
        }
    });
}

fn socket_path() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or("home directory not found")?;
    Ok(home.join(".kenv").join("desktop.sock"))
}

fn run_socket_server() -> Result<(), Box<dyn std::error::Error>> {
    let path = socket_path()?;

    // Create parent directory if needed
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Remove old socket file if exists
    let _ = fs::remove_file(&path);

    let listener = UnixListener::bind(&path)?;

    // Set socket permissions to 0600
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }

    for stream in listener.incoming() {
        match stream {
            Ok(mut socket) => {
                thread::spawn(move || {
                    if let Err(e) = handle_client(&mut socket) {
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

fn handle_client(socket: &mut std::os::unix::net::UnixStream) -> Result<(), Box<dyn std::error::Error>> {
    let mut buffer = vec![0; 4096];
    let n = socket.read(&mut buffer)?;

    if n == 0 {
        return Ok(());
    }

    let request_str = String::from_utf8_lossy(&buffer[..n]);
    let request: Request = serde_json::from_str(&request_str)?;

    let response = handle_request(&request);

    let response_json = serde_json::to_string(&response)?;
    socket.write_all(response_json.as_bytes())?;
    socket.write_all(b"\n")?;

    Ok(())
}

fn handle_request(req: &Request) -> Response {
    match req.method.as_str() {
        "unlock" => {
            match serde_json::from_value::<handlers::UnlockRequest>(req.params.clone()) {
                Ok(unlock_req) => match handlers::handle_unlock(unlock_req) {
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
                Err(e) => Response {
                    success: false,
                    result: None,
                    error: Some(format!("invalid params: {}", e)),
                },
            }
        }
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
        "sign" => {
            match serde_json::from_value::<handlers::SignRequest>(req.params.clone()) {
                Ok(sign_req) => match handlers::handle_sign(sign_req) {
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
                Err(e) => Response {
                    success: false,
                    result: None,
                    error: Some(format!("invalid params: {}", e)),
                },
            }
        }
        "remove_slot" => {
            match serde_json::from_value::<handlers::RemoveSlotRequest>(req.params.clone()) {
                Ok(remove_req) => match handlers::handle_remove_slot(remove_req) {
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
                Err(e) => Response {
                    success: false,
                    result: None,
                    error: Some(format!("invalid params: {}", e)),
                },
            }
        }
        "reauth_password" => {
            match req.params.get("password").and_then(|v| v.as_str()) {
                Some(password) => match handlers::handle_reauth_password(password.to_string()) {
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
        "lock" => match handlers::handle_lock() {
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
        _ => Response {
            success: false,
            result: None,
            error: Some(format!("unknown method: {}", req.method)),
        },
    }
}
