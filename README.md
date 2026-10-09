# NetPaste - Seamless Remote Development Bridge

NetPaste is a network clipboard and system integration tool designed to enhance remote development workflows. It bridges the gap between remote development environments and local desktop systems, enabling seamless interaction across network boundaries.

## Overview

This tooling was created to ease the workflow of developers who primarily work on remote boxes through long-lived sessions. It integrates with [mosh](https://mosh.org/) (mobile shell) for persistent connections and provides a secure channel for clipboard sharing and desktop integration between remote development environments and local workstations.

## Key Features

- **Network Clipboard**: Send text from remote terminals to local clipboard
- **File System Integration**: Open files and folders from remote systems in local applications
- **VS Code Integration**: Open remote projects directly in VS Code on your local machine
- **Desktop Notifications**: Send notifications from remote systems to local desktop
- **URL Handling**: Open URLs from remote terminals in local browser
- **Secure Communication**: Diffie-Hellman key exchange with AES-256 encryption
- **Shared Secret Authentication**: Optional authentication layer for added security
- **Dual-Purpose Client**: Works as both CLI tool and MCP server
- **Claude Code Integration**: Full MCP server support for AI-assisted workflows (tested with Claude Code)
- **Tmux Integration**: Access tmux buffer contents via CLI and MCP

## Architecture

### Network Discovery
The system uses a custom mosh setup with syslog enabled (not default on Debian) to automatically detect the IP address of the Windows host. This allows seamless transitions between WiFi, Ethernet, and VPN connections without manual IP configuration. While IPs can be hard-coded, this dynamic approach provides flexibility for mobile development workflows.

### File System Access
NetPaste works in conjunction with SSHFS to mount the remote system's filesystem on the local machine. This enables:
- Opening remote files with local applications
- VS Code to access the full project structure
- File explorer to browse remote directories

All paths are automatically translated from Unix format to Windows paths (using F: drive as the mount point by default).

## Platform Support

> **Tested combination:** Python client on Linux/WSL → Windows PowerShell server.
> Everything else is implemented but untested. See [SECURITY.md](SECURITY.md#what-has-been-tested).

### Client (Python)
- ✅ **Linux / WSL** - Tested, in daily use (CLI and Claude Code MCP server), with auto IP detection via mosh/syslog
- ⚠️ **macOS** - Untested
- ⚠️ **Windows (native)** - Untested
- ⚠️ **PowerShell client** (`client/np-client.ps1`) - Untested

### Server
- ✅ **Windows** - PowerShell implementation (tested, in daily use)
- ⚠️ **macOS** - Swift implementation (untested; requires compilation)
- ⚠️ **Linux** - Python implementation with GTK support (untested)

## Installation

### Windows Server (PowerShell)
```powershell
# Run NetPaste server
.\server\NetPaste-Windows.ps1

# Optional: Run without system tray
.\server\NetPaste-Windows.ps1 -NoTray

# Optional: Specify custom port
.\server\NetPaste-Windows.ps1 -Port 8888
```

### Linux Server (Python)
```bash
# Minimal setup - works with just Python 3.6+
./server/NetPaste-Linux.py

# Optional: Install recommended packages for better experience
# For clipboard support (choose one):
sudo apt-get install xclip        # Most common
sudo apt-get install xsel         # Alternative
sudo apt-get install wl-clipboard  # For Wayland

# For GUI dialogs and system tray (optional):
sudo apt-get install python3-gi python3-gi-cairo gir1.2-gtk-3.0 gir1.2-appindicator3-0.1
# Or just zenity for simple dialogs:
sudo apt-get install zenity

# For encryption support (optional):
pip3 install cryptography

# Run with options:
./server/NetPaste-Linux.py --no-tray  # Run without system tray
./server/NetPaste-Linux.py --port 8888  # Custom port
```

### macOS Server (Swift)
```bash
# Compile the server
swiftc server/NetPaste-macOS.swift -o NetPaste

# Run NetPaste server
./NetPaste

# Optional: Specify custom port
./NetPaste -Port 8888
```

### Python Client (Dual-Purpose: CLI & MCP Server)

The Python client (`client/netpaste.py`) serves two purposes:
1. **Command-line tool** for sending data to NetPaste servers
2. **MCP server** for integration with Claude Desktop (Claude Code)

#### CLI Installation
```bash
# Linux/macOS
cp client/netpaste.py ~/bin/
chmod +x ~/bin/netpaste.py

# Windows (PowerShell)
# Copy client\netpaste.py to a location in your PATH

# Add shell aliases (Linux/macOS)
source client/.zshrc.np  # or add to your .zshrc/.bashrc

# For Windows, use directly with python:
# python netpaste.py [options]
```

#### MCP Server Installation (for Claude Code)
```bash
# Install with uv (recommended)
uv tool install --from /path/to/net-paste netpaste-mcp

# Add to Claude Code (tested and verified)
claude mcp add -s user netpaste -- uvx --from /path/to/net-paste netpaste-mcp

# Or install with pip
pip install 'mcp[cli]' cryptography
cd /path/to/net-paste
pip install -e .

# Then add to Claude Code
claude mcp add -s user netpaste -- python -m client.netpaste -m

# Note: Should also work with Claude Desktop but testing was done with Claude Code
```

## Usage Examples

### Shell Aliases (with .zshrc.np)
```bash
# Send piped text to clipboard
echo "Hello World" | np
cat file.txt | np

# Open current directory in VS Code
npcode .

# Open specific project in VS Code
npcode ~/projects/myapp

# Open file explorer
npd /home/user/documents

# Send notification
npnotify "Build completed"

# Open URL in browser
npurl https://example.com
```

### Direct Python Client Usage
```bash
# Send text to clipboard
echo "Hello" | python3 ~/bin/netpaste.py

# Open in VS Code
python3 ~/bin/netpaste.py --vscode ~/project

# Open file explorer
python3 ~/bin/netpaste.py -e /path/to/directory

# Send notification
python3 ~/bin/netpaste.py -n "Task completed"
```

### MCP Integration with Claude Code

NetPaste includes a Model Context Protocol (MCP) server that allows Claude Code to interact with your clipboard and system. While the MCP protocol should work with any MCP-compatible client (including Claude Desktop), all testing and examples here are specific to Claude Code.

#### Available MCP Tools
- `send_to_clipboard` - Send text to Windows/macOS/Linux clipboard
- `send_file_to_clipboard` - Send file contents to clipboard
- `open_explorer` - Open file explorer at specified path
- `open_file_with_default` - Open files with default application
- `open_url_in_browser` - Open URLs in default browser
- `open_in_vscode` - Open files/folders in VS Code
- `send_notification` - Send desktop notifications
- `send_ls_output` - Send directory listing to clipboard
- `send_git_output` - Send git command output to clipboard
- `send_current_path` - Send working directory to clipboard
- `get_tmux_buffer_contents` - Read tmux buffer contents
- `restart_netpaste_server` - Restart the NetPaste server

#### Testing MCP Server Manually
```bash
# Run as standalone MCP server (for testing)
python3 ~/bin/netpaste.py -m

# Or with the installed tool
netpaste-mcp
```

#### Environment Variables
The MCP server respects these environment variables:
- `NETPASTE_IP` - Target server IP (auto-detected from mosh if not set)
- `NETPASTE_PORT` - Target server port (default: 9999)

## Security

> ⚠️ **The custom protocol has not been audited.** Remaining weaknesses
> include AES-CBC without a MAC and no in-session replay protection. Run it
> only on trusted networks. Details: [SECURITY.md](SECURITY.md).

### Pairing (once per client and server)
```bash
nppair                         # or: python3 client/netpaste.py --pair
```
The client and a dialog on the Windows server both show a 6-digit code.
Approve on both ends only if the codes match. Each side then stores a secret
derived from that exchange; the secret is never sent over the network.
Until a client is paired, every command against that server fails with
"Not paired".

### Encryption and authentication
- Diffie-Hellman key exchange (RFC 3526 2048-bit MODP Group), fresh per connection
- Session key = HMAC of the paired secret over the handshake transcript, so a
  man-in-the-middle without the secret cannot derive it
- Messages are encrypted with AES-256-CBC (no MAC / integrity check)
- The server only runs commands from authenticated sessions (unless started with `-NoEncrypt`)

### Pairing storage
- Windows server: `%APPDATA%\NetPaste\pairings.json` (one secret per client)
- Linux client: `~/.config/netpaste/pairings.json` (one secret per server; `0600`)
- Clear pairings with `-c` on the client, or "Clear Client Pairings" in the server's tray menu

### Upgrading from the single shared secret
Protocol v2 replaced the old auto-provisioned `secret.key`. Update both
`client/netpaste.py` and `NetPaste-Windows.ps1`, restart the server, then run
`nppair` once from each client. The Linux and macOS servers have not been
updated to v2 yet.

## Dependencies

### Windows Server
- PowerShell 5.1 or PowerShell 7+
- .NET Framework (for encryption and Windows Forms)

### macOS Server
- macOS 10.14+ (for Swift 5 support)
- Xcode Command Line Tools or full Xcode
- CommonCrypto framework (included with macOS)

### Linux Server
- **Required**: Python 3.6+ (no external dependencies needed!)
- **Optional enhancements**:
  - Clipboard: `xclip`, `xsel`, or `wl-clipboard` (falls back to file if not available)
  - Dialogs: `zenity` or `kdialog` (falls back to console prompts)
  - System tray: GTK3 libraries (runs fine without)
  - Encryption: `pip3 install cryptography` (basic DH still works without)
  - Notifications: `notify-send` (falls back to console output)

### Python Client (All Platforms)
- Python 3.10+ when installed as a package (`pip`/`uv`), which is required by `mcp` 2.x
- No external dependencies for core CLI functionality
- Optional: netcat (nc) for auto IP detection from mosh (Linux only)
- Optional: MCP support requires `pip install 'mcp[cli]>=2.3,<3'`

## Remote Development Workflow

1. **Connect to remote box**: Use mosh for persistent sessions
2. **Mount filesystem**: Use SSHFS to mount remote filesystem on Windows (typically as F: drive)
3. **Start NetPaste**: Run PowerShell server on Windows
4. **Work remotely**: Use shell aliases to seamlessly interact with local desktop

This setup provides a fluid development experience where you can:
- Copy command output directly to local clipboard
- Open remote projects in local VS Code
- Browse remote files with local file explorer
- Receive desktop notifications from remote processes
- All while maintaining secure, encrypted communication

## Network Configuration

The system automatically detects the Windows host IP through mosh's syslog, but you can also:

```bash
# Set explicit IP
export NETPASTE_IP=192.168.1.100

# Use custom port
export NETPASTE_PORT=8888
```

## Contributing

This tool is designed to solve real remote development pain points. Contributions for additional platform support (macOS, Linux desktop servers) and workflow improvements are welcome.

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Author

Created to streamline remote development workflows, particularly for developers who spend most of their time in SSH/mosh sessions on remote servers but need seamless integration with their local desktop environment.