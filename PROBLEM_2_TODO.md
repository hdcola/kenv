# Problem 2: CLI IPC Delegation — Completion Guide

## Current Status

The Unix socket IPC framework is implemented and working:
- ✅ Socket server running in Tauri backend (`~/.kenv/desktop.sock`)
- ✅ Handlers module with all business logic
- ✅ CLI IPC client library (`crates/kenv-cli/src/ipc.rs`)

## Remaining Work

### 1. Modify CLI Commands to Use IPC (2–3 hours)

The following CLI commands need to be updated to delegate through IPC when available:

**File**: `crates/kenv-cli/src/main.rs`

#### Commands to Update:

1. **`Unlock` command**:
   ```rust
   // Current: unlock_vault() calls kenv_core::unlock() directly
   // New: Try socket first, fall back to local unlock if socket unavailable
   fn unlock_vault() -> Result<(), Box<dyn std::error::Error>> {
       match IpcClient::unlock(&password) {
           Ok(_) => {
               println!("vault_status=unlocked");
               Ok(())
           }
           Err(_) => {
               // Fallback to local unlock
               kenv_core::unlock(&password)?;
               println!("vault_status=unlocked");
               Ok(())
           }
       }
   }
   ```

2. **`Slots` command**:
   ```rust
   // Must use IPC (requires desktop to be running)
   // Falls back with helpful error message if socket unavailable
   fn print_slots() -> Result<(), Box<dyn std::error::Error>> {
       match IpcClient::list_slots() {
           Ok(slots) => {
               for slot in slots {
                   println!("slot_id={}", slot.slot_id);
                   println!("slot_type={}", slot.slot_type);
                   // ... etc
               }
               Ok(())
           }
           Err(e) => {
               // Provide helpful error message
               if e.contains("not running") {
                   eprintln!("Error: desktop app not running");
                   eprintln!("Hint: Start the desktop app to use this command");
               } else {
                   eprintln!("Error: {}", e);
               }
               Err(e.into())
           }
       }
   }
   ```

3. **`Keys` command**:
   - Similar pattern to `Slots`
   - Must use IPC (stateful operation)

4. **`Sign` command**:
   - Read stdin data to sign
   - Call `IpcClient::sign(key_id, &data)`
   - Handle `reauthentication_required` error specially
   - Provide prompt for password reauthentication

5. **`RemoveSlot` command**:
   - Similar to above
   - May require reauthentication

6. **`Lock` command**:
   - Try IPC first (lock state in desktop app)
   - Fall back to local lock if socket unavailable

### 2. Error Handling Strategy

Error messages should distinguish between:
- **Desktop not running**: "desktop app not running or socket inaccessible"
- **Reauthentication needed**: "reauthentication_required" → prompt for password
- **Socket communication error**: Report as connection error
- **Operation error**: Pass through from desktop (e.g., "vault is locked")

### 3. Update Main Function Dispatch

Add IPC module to `main.rs`:
```rust
mod ipc;

// In main():
match cli.command {
    Commands::Slots => print_slots(),       // Must use IPC
    Commands::Keys => list_keys(),          // Must use IPC
    Commands::Sign { key_id } => sign_with_key(&key_id), // Try IPC, fall back
    Commands::RemoveSlot { slot_id } => remove_slot_interactive(slot_id), // Try IPC
    Commands::Unlock => unlock_vault(),     // Try IPC, fall back to local
    Commands::Lock => lock_vault(),         // Try IPC, fall back
    Commands::Status => print_status(),     // Use local check
    Commands::Create => create_new_vault(), // Use local creation
}
```

### 4. Testing Checklist

Before completing, verify:
- [ ] `kenv unlock <password>` works locally (no desktop running)
- [ ] `kenv slots` fails gracefully with helpful message when desktop not running
- [ ] Start desktop app, then:
  - [ ] `kenv unlock <password>` delegates to desktop via socket
  - [ ] `kenv slots` lists slots from desktop
  - [ ] `kenv keys` lists keys from desktop
  - [ ] `kenv sign <key_id>` delegates to desktop
  - [ ] `kenv remove-slot <id>` delegates to desktop
  - [ ] `kenv lock` locks vault in desktop app
- [ ] Reauthentication flow:
  - [ ] High-risk operation triggers "reauthentication_required"
  - [ ] User prompted for password
  - [ ] Operation retried with reauthentication

### 5. Output Format

Preserve CLI output format for backward compatibility:
- `unlock`: `vault_status=unlocked`
- `slots`: `slot_id=1\nslot_type=Password\nlabel=password\n...`
- `keys`: `key_id=...\nname=...\n...`
- `sign`: `key_id=...\nsignature_len=...\n`
- `lock`: `vault_status=locked`

## Code References

- **IPC client**: `crates/kenv-cli/src/ipc.rs`
- **Socket server**: `apps/desktop/src-tauri/src/socket_server.rs`
- **Handlers**: `apps/desktop/src-tauri/src/handlers.rs`
- **CLI main**: `crates/kenv-cli/src/main.rs` (functions to modify)

## Socket Protocol Reference

Request format (JSON over Unix socket):
```json
{
  "method": "unlock|list_slots|list_keys|sign|remove_slot|reauth_password|lock",
  "params": { ... }
}
```

Response format:
```json
{
  "success": true|false,
  "result": { ... } or null,
  "error": "error message" or null
}
```

## Next Steps

1. Import `ipc` module in `main.rs`
2. Update each command handler in order (start with `unlock`)
3. Test each command after modification
4. Commit with descriptive message for each command group
