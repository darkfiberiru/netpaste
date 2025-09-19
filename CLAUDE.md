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
- `server/NetPaste-Windows.ps1` - Windows PowerShell server implementation
- `server/NetPaste-macOS.swift` - macOS Swift server implementation (requires compilation)
- `server/NetPaste-Linux.py` - Linux Python server implementation
- `netpaste_aliases.sh` - Shell aliases for common operations

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

# MCP server mode (for Claude Code)
python3 client/netpaste.py -m

# With shell aliases (source netpaste_aliases.sh first)
echo "text" | np              # Send to clipboard
npcode ~/project              # Open in VS Code
npd /path/to/dir             # Open file explorer
npnotify "Build complete"    # Send notification
```

### Testing
```bash
# Test Python client connectivity
echo "test" | python3 client/netpaste.py -s

# Test MCP server
python3 client/netpaste.py -m  # Then interact via Claude Code

# Verify encryption handshake
python3 client/netpaste.py -t "test" --verbose
```

## Message Protocol

The system uses a custom protocol with these message types:
- `paste` - Clipboard operations
- `explorer` - Open file explorer
- `open_file` - Open files with default application
- `open_url` - Open URLs in browser
- `vscode` - Open in Visual Studio Code
- `notification` - Desktop notifications
- `restart` - Server restart
- `clear_secret` - Clear authentication

All messages follow this flow:
1. Diffie-Hellman key exchange
2. Shared secret authentication
3. AES-256-CBC encrypted payload transmission
4. Server-side path translation (for SSHFS mounts)

## Environment Variables

- `NETPASTE_IP` - Target server IP (auto-detected from mosh if not set)
- `NETPASTE_PORT` - Target server port (default: 9999)
- `NETPASTE_SHARE_SECRET` - Path to shared secret file

## Security Considerations

- Shared secrets are auto-provisioned on first connection
- Secrets stored in platform-specific secure locations
- Each session establishes new encryption keys
- Path translation assumes SSHFS mount on F: drive (Windows) or /Volumes (macOS)

## Dependencies

### Python Client/Server
- Python 3.6+ (core functionality)
- `cryptography` (optional, for enhanced encryption)
- `mcp[cli]` (for MCP server mode)

### Platform-Specific
- Windows: PowerShell 5.1+, .NET Framework
- macOS: Swift 5+, CommonCrypto
- Linux: Optional GTK3 for GUI, xclip/xsel for clipboard

## Virtual Environment

The project includes a venv in the root directory. Activate it before development:
```bash
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows
```

## MCP Server Integration

The Python client doubles as an MCP server providing these tools for Claude Code:
- `send_to_clipboard` - Send text to clipboard
- `send_file_to_clipboard` - Send file contents
- `open_explorer` - Open file explorer
- `open_file_with_default` - Open files
- `open_url_in_browser` - Open URLs
- `open_in_vscode` - VS Code integration
- `send_notification` - Desktop notifications
- `get_tmux_buffer_contents` - Read tmux buffer
- `restart_netpaste_server` - Restart server