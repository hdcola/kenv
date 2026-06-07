use serde_json::{json, Value};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

pub struct IpcClient;

#[derive(Debug, Clone)]
pub enum IpcError {
    /// Socket not found or connection to server failed.
    /// Safe to fallback to local operations (desktop app not running).
    SocketUnavailable(String),
    /// Request sent but desktop app returned an error response.
    /// Examples: vault already exists, weak password, etc.
    /// Do NOT retry — server has processed the request.
    RemoteError(String),
    /// Request transmission or timeout failed before reaching desktop.
    /// Desktop has not processed the request.
    /// Future: may be safe to retry, but must be explicit.
    RequestFailed(String),
    /// Response transmission or parsing failed.
    /// Desktop likely processed the request (vault may exist, etc.).
    /// CRITICAL: Do NOT retry — vault may have been created.
    ResponseFailed(String),
}

impl std::fmt::Display for IpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::SocketUnavailable(s) => write!(f, "{}", s),
            Self::RemoteError(s) => write!(f, "{}", s),
            Self::RequestFailed(s) => write!(f, "{}", s),
            Self::ResponseFailed(s) => write!(f, "{}", s),
        }
    }
}

impl std::error::Error for IpcError {}

impl IpcError {
    /// Returns true only for SocketUnavailable errors (safe to fallback to local operations).
    /// RequestFailed and ResponseFailed must NOT trigger fallback for non-idempotent operations.
    pub fn is_socket_unavailable(&self) -> bool {
        matches!(self, Self::SocketUnavailable(_))
    }

    pub fn contains(&self, needle: &str) -> bool {
        self.to_string().contains(needle)
    }
}

/// Error classification invariant:
///
/// This enum explicitly separates errors by fallback safety for non-idempotent IPC operations:
///
/// **SocketUnavailable** — Safe to fallback:
/// - Socket file doesn't exist → desktop not running
/// - Connection fails → desktop not listening
/// - Desktop has NOT processed the request
/// - Local fallback is safe (no duplicate work)
///
/// **RequestFailed** — Unsafe to fallback (future consideration):
/// - Request transmission failed (write, timeout, config)
/// - Desktop may or may not have processed the request
/// - Current policy: Don't retry (non-idempotent)
/// - Future: May enable explicit retry for specific errors
///
/// **ResponseFailed** — CRITICAL: Never fallback:
/// - Response transmission/parsing failed (read, timeout, JSON parse)
/// - Desktop HAS LIKELY processed the request
/// - Vault may have been created, SSH key may have been signed, etc.
/// - Local fallback WILL cause duplicate work or incorrect state
/// - Examples: "vault already exists" error to user, silent data loss
///
/// **RemoteError** — Server returned explicit error:
/// - Desktop processed request and returned intentional error
/// - Examples: vault already exists, weak password, key not found
/// - No fallback, return error to user
///
/// In create_new_vault() (main.rs), only SocketUnavailable triggers fallback:
/// ```ignore
/// match ipc::IpcClient::create(&password) {
///     Ok(()) => Ok(()),
///     Err(SocketUnavailable(_)) => create_vault(...),  // Safe: desktop never heard us
///     Err(RequestFailed(_)) => Err(...),               // Unsafe: desktop might process
///     Err(ResponseFailed(_)) => Err(...),              // CRITICAL: vault likely created
///     Err(RemoteError(e)) => Err(e),                   // Server error
/// }
/// ```

#[derive(Debug)]
pub struct Response {
    pub success: bool,
    pub result: Option<Value>,
    pub error: Option<String>,
}

impl IpcClient {
    pub fn send_request(method: &str, params: Value) -> Result<Response, IpcError> {
        let socket_path = socket_path()
            .map_err(|e| IpcError::SocketUnavailable(e))?;

        // Check if socket exists
        if !socket_path.exists() {
            return Err(IpcError::SocketUnavailable(
                "desktop app not running or socket inaccessible".to_string(),
            ));
        }

        // Connect to socket with timeout
        let mut stream = UnixStream::connect(&socket_path)
            .map_err(|_| IpcError::SocketUnavailable(
                "desktop app not running or socket inaccessible".to_string(),
            ))?;

        stream.set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| IpcError::RequestFailed(format!("socket error: {}", e)))?;

        // Build request
        let request = json!({
            "method": method,
            "params": params
        });

        let request_str = request.to_string();

        // Send request
        stream
            .write_all(request_str.as_bytes())
            .map_err(|e| IpcError::RequestFailed(format!("failed to send request: {}", e)))?;
        stream
            .write_all(b"\n")
            .map_err(|e| IpcError::RequestFailed(format!("failed to send newline: {}", e)))?;

        // Read response
        let mut buffer = vec![0; 8192];
        let n = stream
            .read(&mut buffer)
            .map_err(|e| IpcError::ResponseFailed(format!("failed to read response: {}", e)))?;

        if n == 0 {
            return Err(IpcError::ResponseFailed(
                "no response from socket server".to_string(),
            ));
        }

        let response_str = String::from_utf8_lossy(&buffer[..n]);
        let response: Response = serde_json::from_str(&response_str)
            .map_err(|e| IpcError::ResponseFailed(format!("failed to parse response: {}", e)))?;

        if response.success {
            Ok(response)
        } else {
            Err(IpcError::RemoteError(
                response.error.unwrap_or_else(|| "unknown error".to_string()),
            ))
        }
    }

    pub fn unlock(password: &str) -> Result<(), IpcError> {
        let params = json!({
            "password": password
        });

        Self::send_request("unlock", params)?;
        Ok(())
    }

    pub fn list_slots() -> Result<Vec<SlotInfo>, IpcError> {
        let response = Self::send_request("list_slots", json!({}))?;

        if let Some(result) = response.result {
            let slots_response: SlotsResponse = serde_json::from_value(result)
                .map_err(|e| IpcError::ResponseFailed(format!("failed to parse slots: {}", e)))?;
            Ok(slots_response.slots)
        } else {
            Err(IpcError::ResponseFailed("no result in response".to_string()))
        }
    }

    pub fn list_keys() -> Result<Vec<KeyInfo>, IpcError> {
        let response = Self::send_request("list_keys", json!({}))?;

        if let Some(result) = response.result {
            let keys_response: KeysResponse = serde_json::from_value(result)
                .map_err(|e| IpcError::ResponseFailed(format!("failed to parse keys: {}", e)))?;
            Ok(keys_response.keys)
        } else {
            Err(IpcError::ResponseFailed("no result in response".to_string()))
        }
    }

    pub fn sign(key_id: &str, data: &[u8]) -> Result<Vec<u8>, IpcError> {
        let data_b64 = base64_encode(data);
        let params = json!({
            "key_id": key_id,
            "data": data_b64
        });

        let response = Self::send_request("sign", params)?;

        if let Some(result) = response.result {
            let sign_response: SignResponse = serde_json::from_value(result)
                .map_err(|e| IpcError::ResponseFailed(format!("failed to parse signature: {}", e)))?;
            Ok(sign_response.signature)
        } else {
            Err(IpcError::ResponseFailed("no result in response".to_string()))
        }
    }

    pub fn remove_slot(slot_id: u8) -> Result<(), IpcError> {
        let params = json!({
            "slot_id": slot_id
        });

        Self::send_request("remove_slot", params)?;
        Ok(())
    }

    pub fn reauth_password(password: &str) -> Result<(), IpcError> {
        let params = json!({
            "password": password
        });

        Self::send_request("reauth_password", params)?;
        Ok(())
    }

    pub fn lock() -> Result<(), IpcError> {
        Self::send_request("lock", json!({}))?;
        Ok(())
    }

    pub fn create(password: &str) -> Result<(), IpcError> {
        let params = json!({
            "password": password
        });

        Self::send_request("create", params)?;
        Ok(())
    }
}

fn socket_path() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or("home directory not found")?;
    Ok(home.join(".kenv").join("desktop.sock"))
}

// Base64 encoding for binary data
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b1 = chunk[0];
        let b2 = chunk.get(1).copied().unwrap_or(0);
        let b3 = chunk.get(2).copied().unwrap_or(0);

        let n = ((b1 as u32) << 16) | ((b2 as u32) << 8) | (b3 as u32);

        result.push(CHARS[(((n >> 18) & 0x3F) as usize)] as char);
        result.push(CHARS[(((n >> 12) & 0x3F) as usize)] as char);
        if chunk.len() > 1 {
            result.push(CHARS[(((n >> 6) & 0x3F) as usize)] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[((n & 0x3F) as usize)] as char);
        } else {
            result.push('=');
        }
    }
    result
}

#[derive(serde::Deserialize)]
pub struct SlotInfo {
    pub slot_id: u8,
    pub slot_type: String,
    pub label: String,
    pub last_used: Option<i64>,
    pub disabled: bool,
}

#[derive(serde::Deserialize)]
struct SlotsResponse {
    slots: Vec<SlotInfo>,
}

#[derive(serde::Deserialize)]
pub struct KeyInfo {
    pub key_id: String,
    pub name: String,
}

#[derive(serde::Deserialize)]
struct KeysResponse {
    keys: Vec<KeyInfo>,
}

#[derive(serde::Deserialize)]
struct SignResponse {
    signature: Vec<u8>,
}

impl<'de> serde::de::Deserialize<'de> for Response {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct ResponseHelper {
            success: bool,
            result: Option<Value>,
            error: Option<String>,
        }

        let helper = ResponseHelper::deserialize(deserializer)?;
        Ok(Response {
            success: helper.success,
            result: helper.result,
            error: helper.error,
        })
    }
}

impl serde::ser::Serialize for Response {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("Response", 3)?;
        state.serialize_field("success", &self.success)?;
        state.serialize_field("result", &self.result)?;
        state.serialize_field("error", &self.error)?;
        state.end()
    }
}
