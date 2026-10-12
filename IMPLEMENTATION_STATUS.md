# NetPaste Implementation Status

## Overview

> **Tested:** Python client on a remote Linux box (CLI + Claude Code MCP) → Windows PowerShell server. WSL is untested.
> **Untested:** Linux server, macOS server, PowerShell client, Python client on macOS/native Windows.
> Known protocol weaknesses are listed in [SECURITY.md](SECURITY.md).
NetPaste is a network clipboard and system integration tool with server implementations for Windows (PowerShell) and macOS (Swift), and a Python client for Linux/WSL.

## Server Feature Comparison

### ✅ Windows PowerShell Server (NetPaste-Windows.ps1)
**Status: Implemented, tested, in daily use**

New, not yet verified end to end: `get_text`, `get_file` server-to-client messages.

#### Security Features
- [x] Diffie-Hellman key exchange (RFC 3526 2048-bit MODP Group)
- [x] AES-256-CBC encryption with PKCS7 padding
- [x] Protocol v2: per-client secret mixed into the session key (never sent over the network)
- [x] Pairing with a 6-digit code confirmed on both ends (`--pair`), no trust-on-first-use
- [x] Pairings in `%APPDATA%\NetPaste\pairings.json` (owner-only ACL, plaintext, no DPAPI)

#### Message Handlers
- [x] `paste` - Clipboard operations with user dialog
- [x] `explorer` - Open File Explorer at specified path
- [x] `open_file` - Open files with default application
- [x] `open_url` - Open URLs in default browser
- [x] `vscode` - Open in Visual Studio Code
- [x] `notification` - Desktop notifications
- [x] `restart` - Server restart functionality
- [x] Tray menu "Clear Client Pairings"

#### Dynamic Features
- [x] SSHFS mount detection via `net use` and process inspection
- [x] Automatic drive letter mapping based on remote IP
- [x] Mount information caching (5-minute TTL)
- [x] Path conversion from Unix to Windows format

#### User Interface
- [x] System tray icon with menu
- [x] User confirmation dialogs
- [x] Text preview in paste dialogs
- [x] Console window show/hide functionality

#### Command Line Options
- [x] `-Port` - Custom port configuration
- [x] `-NoTray` - Run without system tray
- [x] `-NoEncrypt` - Disable encryption
- [x] `-Child` - Internal use for subprocess

### ⚠️ Linux Python Server (NetPaste-Linux.py)
**Status: Implemented, untested** (no `get_text` / `get_file` handlers)

#### Security Features
- [x] Diffie-Hellman key exchange (RFC 3526 2048-bit MODP Group)
- [x] Native Python implementation for DH operations
- [x] AES-256-CBC encryption with PKCS7 padding (via cryptography library)
- [x] Shared secret authentication (protocol v1 — incompatible with the current v2 client)
- [x] Auto-provisioning on first connection
- [x] Secure secret storage in `~/.config/netpaste/secret.key`

#### Message Handlers
- [x] `paste` - Clipboard operations with GTK dialog
- [x] `explorer` - Open file manager at specified path
- [x] `open_file` - Open files with xdg-open
- [x] `open_url` - Open URLs in default browser
- [x] `vscode` - Open in Visual Studio Code
- [x] `notification` - Desktop notifications via libnotify
- [x] `restart` - Server restart functionality
- [x] `clear_secret` - Clear stored authentication

#### Dynamic Features
- [x] SSHFS mount detection via mount command
- [x] Automatic path mapping based on remote IP
- [x] Mount information caching (5-minute TTL)
- [x] Path conversion from Unix to local format

#### User Interface
- [x] System tray icon with AppIndicator3
- [x] GTK3 dialogs for user confirmation
- [x] Text preview in paste dialogs
- [x] Console log viewing via terminal
- [x] Fallback to CLI mode if GTK unavailable

#### Command Line Options
- [x] `-p` / `--port` - Custom port configuration
- [x] `--no-tray` - Run without system tray
- [x] `--no-encrypt` - Disable encryption

### ⚠️ macOS Swift Server (NetPaste-macOS.swift)
**Status: Implemented, untested (requires compilation)** (no `get_text` / `get_file` handlers)

#### Security Features
- [x] Diffie-Hellman key exchange (RFC 3526 2048-bit MODP Group)
- [x] Custom BigInt implementation for DH operations
- [x] AES-256-CBC encryption with PKCS7 padding
- [x] Shared secret authentication (protocol v1 — incompatible with the current v2 client)
- [x] Auto-provisioning on first connection
- [x] Secure secret storage in `~/Library/Application Support/NetPaste/secret.key`

#### Message Handlers
- [x] `paste` - Clipboard operations with user dialog
- [x] `explorer` - Open Finder at specified path
- [x] `open_file` - Open files with default application
- [x] `open_url` - Open URLs in default browser
- [x] `vscode` - Open in Visual Studio Code
- [x] `notification` - Desktop notifications
- [x] `restart` - Server restart functionality
- [x] `clear_secret` - Clear stored authentication

#### Dynamic Features
- [x] SSHFS mount detection in `/Volumes/`
- [x] macFUSE mount point detection
- [x] Automatic path mapping based on remote IP
- [x] Path conversion from Unix to macOS format

#### User Interface
- [x] Menu bar app with status icon
- [x] User confirmation dialogs
- [x] Text preview in paste dialogs
- [x] Console log viewing via Terminal

#### Command Line Options
- [x] `-Port` / `--port` - Custom port configuration
- [x] `-NoTray` / `--no-tray` - Run without menu bar
- [x] `-NoEncrypt` / `--no-encrypt` - Disable encryption

## Cross-Platform Compatibility

### Encryption & Authentication
All servers implement the same DH key exchange and AES encryption, but only one pairing has been tested:
- ✅ Python client (remote Linux) → Windows server: tested
- ⚠️ Python client → macOS server: untested
- ⚠️ Python client → Linux server: untested

### BigInt Implementation Note
The macOS Swift server includes a custom BigInt implementation for Diffie-Hellman operations:
- Uses binary method (square-and-multiply) for modular exponentiation
- Implements multiplication, modulo, comparison, and subtraction
- Fully compatible with Windows PowerShell's System.Numerics.BigInteger
- For production deployment, consider using SwiftGMP or similar library for better performance

## Client Implementation

### Python Client (netpaste.py)
**Status: Implemented; tested on remote Linux only**

#### Platform Support
- ✅ **Linux** - Full support with auto IP detection via mosh/syslog
- ⚠️ **WSL** - Untested; no mosh-based IP detection (set `NETPASTE_IP`); on the server's own machine, Windows paths via `wslpath` are used (no SSHFS); on another box, normal SSHFS translation
- ⚠️ **macOS** - Untested
- ⚠️ **Windows (native)** - Untested
- Installed package / MCP mode requires Python 3.10+ (`mcp` 2.x)

#### Features
- [x] All message types supported
- [x] DH key exchange client
- [x] AES encryption/decryption
- [x] Pairing (`--pair`) and per-server secrets in `~/.config/netpaste/pairings.json` (protocol v2)
- [x] Automatic IP detection via mosh/syslog (Linux only)
- [x] Manual IP configuration via environment variables (all platforms)
- [x] MCP server mode for Claude Code integration (`mcp` 2.x `MCPServer`)
- [x] Command-line interface

#### Shell Aliases (.zshrc.np)
- [x] `np` - Send piped input to clipboard
- [x] `npf` - Send file contents to clipboard
- [x] `npd` - Open file explorer
- [x] `npcode` - Open in VS Code
- [x] `npurl` - Open URL in browser
- [x] `npnotify` - Send desktop notification
- [x] Additional utility functions
- Works with bash, zsh, fish (with adaptation)

## Testing Requirements

### Windows Server
1. Run PowerShell as Administrator (optional, for system tray)
2. Execute: `.\server\NetPaste-Windows.ps1`
3. Test with Python client from Linux/WSL

### macOS Server
1. Compile on macOS: `swiftc NetPaste-macOS.swift -o NetPaste`
2. Run: `./NetPaste`
3. Grant necessary permissions for network access
4. Test with Python client from Linux

### Security Testing (Python client ↔ Windows server only)
- [ ] DH key exchange between all platform combinations (only client ↔ Windows exercised)
- [x] Pairing with code confirmation (v2; tested against the server functions under pwsh on Linux, not yet on Windows)
- [x] Rejection of invalid shared secrets
- [x] Encrypted message transmission
- [ ] Rejection of unauthenticated plaintext commands (not implemented; see SECURITY.md)

## Known Limitations

1. **macOS BigInt Performance**: The custom BigInt implementation works correctly but is not optimized for performance. Consider using a proper BigInt library for production.

2. **SSHFS Mount Detection**: Both servers assume standard mount patterns. Custom mount configurations may require manual path configuration.

3. **Swift Compilation**: The macOS server requires Swift compiler and macOS SDK. Cannot be compiled on Linux without significant modifications.

## Deployment Recommendations

1. **Production Use**: 
   - Use proper BigInt library for macOS (SwiftGMP)
   - Implement rate limiting for connection attempts
   - Add logging for security auditing

2. **Network Security**:
   - Run on trusted networks only
   - Consider VPN for remote access
   - Implement IP whitelisting if needed

3. **Performance**:
   - Windows: Consider using background runspace for better performance
   - macOS: Use GCD for better concurrency handling
   - Both: Implement connection pooling for frequently communicating hosts

## Summary

NetPaste covers clipboard and desktop integration between remote development environments and local desktops. The Python client and Windows PowerShell server are tested and in daily use. The Linux and macOS servers are implemented but untested. The protocol has known security weaknesses (see [SECURITY.md](SECURITY.md)), so use it only on trusted networks.
