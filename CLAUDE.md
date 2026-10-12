# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

NetPaste is a network clipboard and system integration tool that bridges remote development environments and local desktop systems. It enables secure clipboard sharing, file system integration, and desktop control across network boundaries.

## Architecture

### Core Components
- **Server Implementations**: Platform-specific servers for Windows (PowerShell), macOS (Swift), and Linux (Python)
- **Python Client**: Dual-purpose tool serving as both CLI and MCP server for Claude Code integration
- **Security Layer**: Diffie-Hellman key exchange with AES-256 encryption and shared secret authentication
- **Network Discovery**: Automatic IP detection via mosh/syslog for seamless transitions between network connections

### Key Files
- `client/netpaste.py` - Main Python client with CLI and MCP server functionality
- `client/.zshrc.np` - Shell aliases for common operations (source in .zshrc/.bashrc)
- `server/NetPaste-Windows.ps1` - Windows PowerShell server implementation
- `server/NetPaste-macOS.swift` - macOS Swift server implementation (requires compilation)
- `server/NetPaste-Linux.py` - Linux Python server implementation
- `pyproject.toml` - Package configuration with entry points for `netpaste` and `netpaste-mcp`

## Development Commands

### Building and Installation
```bash
# Install in development mode (from repository root)
pip install -e .

# Install MCP server with uv (recommended)
uv tool install --from . netpaste-mcp

# Build distribution
python -m build

# Compile macOS server
swiftc server/NetPaste-macOS.swift -o NetPaste
```

### Running Servers
```bash
# Windows PowerShell server
./server/NetPaste-Windows.ps1 [-Port 8888] [-NoTray] [-NoEncrypt]

# Linux Python server
python3 server/NetPaste-Linux.py [--port 8888] [--no-tray] [--no-encrypt]

# macOS server (after compilation)
./NetPaste [-Port 8888] [-NoTray] [-NoEncrypt]
```

### Using the Client
```bash
# CLI mode - send piped text
echo "text" | python3 client/netpaste.py

# MCP server mode (for Claude Code integration)
python3 client/netpaste.py -m

# With shell aliases (source client/.zshrc.np first)
echo "text" | np              # Send to clipboard
npcode ~/project              # Open in VS Code
npd /path/to/dir             # Open file explorer
npnotify "Build complete"    # Send notification
npt                          # Send tmux buffer to clipboard
npgit status                 # Send git output to clipboard

# Server-to-client commands
npget "Enter your name"      # Show text input on server, output to stdout
npgetfile ~/downloads        # Show file picker on server, save to ~/downloads

# After installation via pip/uv
netpaste -t "hello"          # CLI command
netpaste-mcp                 # MCP server mode
```

### Smoke-testing locally
No automated test suite exists. Manual checks:
```bash
python3 client/netpaste.py --pair                       # one-time pairing (confirm code on both ends)
echo "test" | python3 client/netpaste.py -s              # basic connectivity
python3 client/netpaste.py -t "test" --verbose           # inspect encryption handshake
python3 client/netpaste.py --get-text "Enter something"  # server-to-client text input
python3 client/netpaste.py --get-file .                  # server-to-client file transfer
python3 client/netpaste.py -m                            # MCP server mode (drive via Claude Code)
```

## Message Protocol

The system uses a custom protocol with these message types:

### Client-to-Server Messages:
- `paste` - Clipboard operations
- `explorer` - Open file explorer
- `open_file` - Open files with default application
- `open_url` - Open URLs in browser
- `vscode` - Open in Visual Studio Code
- `notification` - Desktop notifications
- `restart` - Server restart

### Server-to-Client Messages:
- `get_text` - Request text input from server (shows dialog, returns text to client)
- `get_file` - Request file from server (shows file picker, transfers file to client)

All messages follow this flow (protocol v2; see `SECURITY.md` for the design):
1. Diffie-Hellman key exchange (RFC 3526 2048-bit MODP Group); handshake carries `client_id` / `server_id`
2. Either a one-time `pair_request` (`--pair`: both ends confirm a 6-digit code, each derives and stores a per-pair secret) or an `auth` message encrypted with `session_key = HMAC(secret, transcript)`
3. AES-256-CBC encrypted payload under the session key, with PKCS7 padding
4. Server-side path translation (for SSHFS mounts)

The key-derivation layout is specified in comments in both `client/netpaste.py` and `server/NetPaste-Windows.ps1` and must stay byte-for-byte identical. Only the Windows server implements v2; the Linux/macOS servers and `np-client.ps1` are still v1.

Path translation logic:
- Server detects SSHFS mounts by scanning for remote IP addresses
- Windows: Checks `net use` and process information for mapped drives
- Linux: Parses `/proc/mounts` for FUSE mounts
- macOS: Scans `/Volumes/` for macFUSE mounts
- Converts Unix paths (e.g., `/home/user/file`) to local paths (e.g., `F:\home\user\file` on Windows)

## Environment Variables

- `NETPASTE_IP` - Target server IP (auto-detected on Linux if not set, from mosh-server's `user X connected from host: IP` journal line; needs mosh built with `--enable-syslog`, which Debian's package omits)
- `NETPASTE_PORT` - Target server port (default: 9999)
Pairing storage (protocol v2):
- Linux/WSL client: `~/.config/netpaste/pairings.json` (client_id + one secret per server_id)
- Windows server: `%APPDATA%\NetPaste\pairings.json` (server_id + one secret per client_id)
- Legacy v1 `secret.key` files are ignored (Linux/macOS servers still use them)

## Security Considerations

- Pairing requires confirming a matching code on both ends; secrets are derived, never sent
- Only an explicit `--pair` from a terminal starts pairing; other paths fail with "not paired"
- Each session establishes new encryption keys; the server dispatches only authenticated, decrypted messages (unless `-NoEncrypt`)
- Path translation is dynamic (scans `net use` / `/proc/mounts` / `/Volumes`); F: on Windows and `/Volumes/<host>` on macOS are the typical SSHFS mount points but not hardcoded

## Dependencies

### Python Client/Server
- Python 3.10+ for the installed package (required by `mcp` 2.x)
- `cryptography` (optional, for enhanced encryption)
- `mcp[cli]` 2.x (for MCP server mode; uses `mcp.server.mcpserver.MCPServer`)

### Platform-Specific
- Windows: PowerShell 5.1+, .NET Framework
- macOS: Swift 5+, CommonCrypto
- Linux: Optional GTK3 for GUI, xclip/xsel for clipboard

## MCP Server Integration

The Python client doubles as an MCP server. The authoritative list of tools and their shell-alias mapping (np, npd, npcode, npgit, …) lives in the MCPServer `instructions=` string in `client/netpaste.py::run_mcp_server` — loaded into Claude's context automatically when the MCP is connected. Individual tool definitions are the `@mcp.tool()` functions in the same file.

Register with Claude Code (user scope so it's available in every project):
```bash
claude mcp add -s user netpaste -- uvx --from /path/to/netpaste netpaste-mcp
```

The user's `~/.zshrc` has a `deploy_netpaste_mcp` alias that runs the above (following the repo's `deploy_<name>_mcp` convention).

## Additional Documentation
- `docs/dh-compatibility-findings.md` - DH parameter cross-platform compatibility notes (Windows/macOS/Linux interop quirks)
- `docs/NETPASTE_ALIASES.md` - Expanded reference for the `np*` shell aliases
- `IMPLEMENTATION_STATUS.md` - Feature completeness snapshot
- `SECURITY.md` - Known protocol weaknesses and the tested/untested component matrix (only Python client on Linux/WSL → Windows PowerShell server is tested)
