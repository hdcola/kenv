use kenv_cli::ipc::IpcError;

#[test]
fn ipc_error_socket_unavailable_variant_exists() {
    let err = IpcError::SocketUnavailable("test".into());
    assert!(matches!(err, IpcError::SocketUnavailable(_)));
}

#[test]
fn ipc_error_remote_error_variant_exists() {
    let err = IpcError::RemoteError("test".into());
    assert!(matches!(err, IpcError::RemoteError(_)));
}

#[test]
fn ipc_error_protocol_error_variant_exists() {
    let err = IpcError::ProtocolError("test".into());
    assert!(matches!(err, IpcError::ProtocolError(_)));
}

#[test]
fn ipc_error_display_formats_correctly() {
    let unavailable = IpcError::SocketUnavailable("socket not found".into());
    assert_eq!(unavailable.to_string(), "socket not found");

    let remote = IpcError::RemoteError("vault already exists".into());
    assert_eq!(remote.to_string(), "vault already exists");

    let protocol = IpcError::ProtocolError("parse failed".into());
    assert_eq!(protocol.to_string(), "parse failed");
}

#[test]
fn ipc_error_contains_method_works() {
    let unavailable = IpcError::SocketUnavailable("desktop app not running".into());
    assert!(unavailable.contains("not running"));
    assert!(unavailable.contains("desktop"));
    assert!(!unavailable.contains("vault"));

    let remote = IpcError::RemoteError("vault already exists".into());
    assert!(remote.contains("already exists"));
    assert!(!remote.contains("socket"));

    let protocol = IpcError::ProtocolError("no response from server".into());
    assert!(protocol.contains("no response"));
    assert!(!protocol.contains("created"));
}

#[test]
fn ipc_error_clone_works() {
    let original = IpcError::SocketUnavailable("test".into());
    let cloned = original.clone();

    assert_eq!(original.to_string(), cloned.to_string());
    assert!(cloned.contains("test"));
}

#[test]
fn ipc_error_is_error_trait_implemented() {
    let err: Box<dyn std::error::Error> = Box::new(
        IpcError::RemoteError("test error".into())
    );
    assert_eq!(err.to_string(), "test error");
}
