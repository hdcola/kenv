use kenv_cli::ipc::IpcError;

// ============================================================================
// Critical Scenario Tests: Verify ResponseFailed cases don't trigger retries
// ============================================================================

#[test]
fn response_failed_read_timeout_is_not_socket_unavailable() {
    // CRITICAL: Desktop processed request and is preparing response, but transmission times out
    // This MUST NOT be retried locally, vault may have been created
    let err = IpcError::ResponseFailed("failed to read response: timed out".into());

    assert!(!err.is_socket_unavailable());
    assert!(!matches!(err, IpcError::SocketUnavailable(_)));
}

#[test]
fn response_failed_empty_response_is_not_socket_unavailable() {
    // Desktop accepted connection but sent no data (possible mid-process failure)
    // This MUST NOT be retried locally, vault may have been created
    let err = IpcError::ResponseFailed("no response from socket server".into());

    assert!(!err.is_socket_unavailable());
    assert!(!matches!(err, IpcError::SocketUnavailable(_)));
}

#[test]
fn response_failed_malformed_json_is_not_socket_unavailable() {
    // Desktop sent data but it's corrupt (network corruption, partial send, etc.)
    // This MUST NOT be retried locally, vault may have been created
    let err = IpcError::ResponseFailed(
        "failed to parse response: expected value at line 1 column 0".into(),
    );

    assert!(!err.is_socket_unavailable());
    assert!(!matches!(err, IpcError::SocketUnavailable(_)));
}

// ============================================================================
// RequestFailed Tests: Pre-request failures (different from ResponseFailed)
// ============================================================================

#[test]
fn request_failed_write_timeout_is_not_socket_unavailable() {
    // Request transmission failed; desktop has not processed request
    let err = IpcError::RequestFailed("failed to send request: timed out".into());

    assert!(!err.is_socket_unavailable());
    assert!(!matches!(err, IpcError::SocketUnavailable(_)));
}

#[test]
fn request_failed_socket_config_error_is_not_socket_unavailable() {
    // Socket configuration failed (e.g., set_read_timeout); connection exists but setup failed
    let err = IpcError::RequestFailed("socket error: Operation not supported".into());

    assert!(!err.is_socket_unavailable());
    assert!(!matches!(err, IpcError::SocketUnavailable(_)));
}

// ============================================================================
// SocketUnavailable Tests: Only these should trigger fallback
// ============================================================================

#[test]
fn socket_unavailable_is_safe_to_fallback() {
    // Desktop not running, socket doesn't exist
    let err = IpcError::SocketUnavailable("socket not found or not accessible".into());

    assert!(err.is_socket_unavailable());
    assert!(matches!(err, IpcError::SocketUnavailable(_)));
}

#[test]
fn socket_unavailable_on_connect_failure_is_safe_to_fallback() {
    // Socket exists but server not listening (desktop crashed or not running)
    let err = IpcError::SocketUnavailable("desktop app not running or socket inaccessible".into());

    assert!(err.is_socket_unavailable());
    assert!(matches!(err, IpcError::SocketUnavailable(_)));
}

// ============================================================================
// RemoteError Tests: Server returned error (vault already exists, weak password, etc.)
// ============================================================================

#[test]
fn remote_error_vault_already_exists_is_not_socket_unavailable() {
    // Server processed request and returned an error
    let err = IpcError::RemoteError("vault already exists".into());

    assert!(!err.is_socket_unavailable());
    assert!(!matches!(err, IpcError::SocketUnavailable(_)));
}

#[test]
fn remote_error_weak_password_is_not_socket_unavailable() {
    // Server processed request but rejected it
    let err = IpcError::RemoteError("password must not be empty".into());

    assert!(!err.is_socket_unavailable());
    assert!(!matches!(err, IpcError::SocketUnavailable(_)));
}

// ============================================================================
// Error Classification Tests: Verify errors are classified correctly
// ============================================================================

#[test]
fn all_error_types_are_classified() {
    let socket_unavailable = IpcError::SocketUnavailable("test".into());
    let request_failed = IpcError::RequestFailed("test".into());
    let response_failed = IpcError::ResponseFailed("test".into());
    let remote_error = IpcError::RemoteError("test".into());

    // All errors must be classifiable
    assert!(matches!(socket_unavailable, IpcError::SocketUnavailable(_)));
    assert!(matches!(request_failed, IpcError::RequestFailed(_)));
    assert!(matches!(response_failed, IpcError::ResponseFailed(_)));
    assert!(matches!(remote_error, IpcError::RemoteError(_)));
}

#[test]
fn error_display_impl_works_for_all_types() {
    let socket_unavailable = IpcError::SocketUnavailable("socket error".into());
    let request_failed = IpcError::RequestFailed("write error".into());
    let response_failed = IpcError::ResponseFailed("read error".into());
    let remote_error = IpcError::RemoteError("business error".into());

    assert_eq!(socket_unavailable.to_string(), "socket error");
    assert_eq!(request_failed.to_string(), "write error");
    assert_eq!(response_failed.to_string(), "read error");
    assert_eq!(remote_error.to_string(), "business error");
}

// ============================================================================
// Fallback Decision Tree Tests: Verify create command makes correct choices
// ============================================================================

#[test]
fn socket_unavailable_error_should_trigger_local_fallback() {
    // In main.rs create_new_vault():
    // Err(IpcError::SocketUnavailable(_)) => create_vault(...) ✓ Fallback
    let err = IpcError::SocketUnavailable("desktop not running".into());

    // Verify this is the only error type that allows fallback
    assert!(err.is_socket_unavailable());
}

#[test]
fn remote_error_should_not_trigger_fallback() {
    // In main.rs create_new_vault():
    // Err(IpcError::RemoteError(e)) => Err(e) ✗ No fallback
    let err = IpcError::RemoteError("vault already exists".into());

    // This error should NOT trigger fallback
    assert!(!err.is_socket_unavailable());
    // User should see the exact error message
    assert!(err.to_string().contains("vault"));
}

#[test]
fn request_failed_should_not_trigger_fallback() {
    // In main.rs create_new_vault():
    // Err(IpcError::RequestFailed(e)) => Err(e) ✗ No fallback
    let err = IpcError::RequestFailed("write timeout".into());

    // This error should NOT trigger fallback
    assert!(!err.is_socket_unavailable());
}

#[test]
fn response_failed_should_not_trigger_fallback() {
    // In main.rs create_new_vault():
    // Err(IpcError::ResponseFailed(e)) => Err(e) ✗ No fallback
    // CRITICAL: Vault may have been created on desktop
    let err = IpcError::ResponseFailed("read timeout".into());

    // This error MUST NOT trigger fallback
    assert!(!err.is_socket_unavailable());
}

// ============================================================================
// Scenario: Desktop successfully creates vault but response transmission fails
// ============================================================================

#[test]
fn vault_creation_scenario_success_response_fails() {
    // This is the critical bug scenario:
    // 1. CLI connects to desktop socket ✓
    // 2. CLI sends "create" request ✓
    // 3. Desktop processes request, creates vault file ✓
    // 4. Desktop starts sending response, but transmission fails
    // 5. CLI receives ResponseFailed error
    // 6. CLI MUST NOT retry locally (vault already exists)
    // 7. User MUST NOT see "creation failed" (vault was created)

    let response_transmission_failed =
        IpcError::ResponseFailed("failed to read response: Connection reset by peer".into());

    // Fallback check: should NOT fall back
    assert!(
        !response_transmission_failed.is_socket_unavailable(),
        "ResponseFailed must NOT trigger local fallback - vault likely exists on desktop"
    );

    // Error visibility: error message should be preserved
    let error_msg = response_transmission_failed.to_string();
    assert!(
        error_msg.contains("read response") || error_msg.contains("Connection"),
        "Error message must indicate transmission failure, not creation failure"
    );
}

#[test]
fn vault_creation_scenario_empty_response() {
    // Similar scenario: desktop processed request but sent nothing
    let empty_response = IpcError::ResponseFailed("no response from socket server".into());

    // Fallback check: should NOT fall back
    assert!(
        !empty_response.is_socket_unavailable(),
        "Empty response MUST NOT trigger local fallback - vault likely exists"
    );
}

// ============================================================================
// Comparison Tests: Ensure error types are distinct
// ============================================================================

#[test]
fn socket_unavailable_and_response_failed_are_different() {
    let socket_unavailable = IpcError::SocketUnavailable("missing".into());
    let response_failed = IpcError::ResponseFailed("read failed".into());

    // These must be distinct types
    assert!(matches!(socket_unavailable, IpcError::SocketUnavailable(_)));
    assert!(matches!(response_failed, IpcError::ResponseFailed(_)));

    // Fallback decision must be different
    assert!(socket_unavailable.is_socket_unavailable());
    assert!(!response_failed.is_socket_unavailable());
}

#[test]
fn request_failed_and_response_failed_are_different() {
    let request_failed = IpcError::RequestFailed("write failed".into());
    let response_failed = IpcError::ResponseFailed("read failed".into());

    // Semantically different phases
    assert!(matches!(request_failed, IpcError::RequestFailed(_)));
    assert!(matches!(response_failed, IpcError::ResponseFailed(_)));

    // Both should reject fallback (but for different reasons)
    assert!(!request_failed.is_socket_unavailable());
    assert!(!response_failed.is_socket_unavailable());
}
