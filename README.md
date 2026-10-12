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
The system uses mosh's connection logging to automatically detect the IP address of the Windows host. This allows seamless transitions between WiFi, Ethernet, and VPN connections without manual IP configuration. While IPs can be hard-coded (`NETPASTE_IP`), this dynamic approach provides flexibility for mobile development workflows.

Syslog support is a standard mosh build option (`./configure --enable-syslog`, in upstream [`configure.ac`](https://github.com/mobile-shell/mosh/blob/master/configure.ac)), not a patch. It is off by default, and Debian's `mosh` package doesn't enable it, so on Debian rebuild mosh-server with the flag. With it, mosh-server logs `user <name> connected from host: <ip>` on each connection. The client finds the newest such line for `$USER` with `journalctl` and uses that IP.

```bash
sudo apt build-dep mosh
git clone https://github.com/mobile-shell/mosh && cd mosh
./autogen.sh && ./configure --enable-syslog && make && sudo make install
```
Only mosh-server on the remote box needs the flag; the mosh client on Windows is unchanged. To install without root, configure with `--prefix=$HOME/.local` and connect with `mosh --server=~/.local/bin/mosh-server …` (or make sure `~/.local/bin` is on the PATH for non-interactive SSH). Without any of this, set `NETPASTE_IP`.

**The journal must be persistent.** mosh-server runs as you, so its log lines go to your own per-user journal, which you can read without `sudo` or extra groups. journald keeps per-user journals only with persistent storage. With the volatile (`/run`) journal, everything lands in the system journal, which a normal user can't read, so detection silently finds nothing. Enable persistent storage once with a drop-in:

```bash
sudo mkdir -p /etc/systemd/journald.conf.d
printf '[Journal]\nStorage=persistent\n' | sudo tee /etc/systemd/journald.conf.d/50-persistent.conf
sudo systemctl restart systemd-journald
```

(Alternatively, `sudo usermod -aG systemd-journal $USER` lets you read the system journal.) `kernel.dmesg_restrict` doesn't matter here, since it only governs `dmesg`. To check, reconnect with mosh, then run:

```bash
journalctl --grep 'connected from host' -o cat -q | tail -1
```

### File System Access
NetPaste works in conjunction with SSHFS to mount the remote system's filesystem on the local machine. This enables:
- Opening remote files with local applications
- VS Code to access the full project structure
- File explorer to browse remote directories

All paths are automatically translated from Unix format to Windows paths (using F: drive as the mount point by default). See [Related Tools](#related-tools-windows-server) for setting up the mount with SSHFS-Win Manager.

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

One-time setup:

1. **Execution policy.** A downloaded script is blocked by default. Unblock this one file, or allow local scripts for your user:
   ```powershell
   Unblock-File .\server\NetPaste-Windows.ps1
   Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
   ```
2. **Firewall.** Allow inbound TCP 9999 (or your `-Port`). Restrict it to the network profile or remote addresses your remote box uses:
   ```powershell
   New-NetFirewallRule -DisplayName "NetPaste" -Direction Inbound -Protocol TCP -LocalPort 9999 -Action Allow -Profile Private
   ```
   Add `-RemoteAddress 10.0.0.0/8` (your range) to narrow it further. On a VPN that Windows classifies as Public, use `-Profile Public` with `-RemoteAddress`.
3. **Reachability.** The remote box connects *back* to Windows. mosh working doesn't prove this, because mosh connects from Windows to the remote box. Test from the remote box with `nc -zv <windows-ip> 9999` (or `echo test | np` after pairing). NAT, or a VPN without a return route, blocks it.

The server restarts itself (`npr`, tray menu) with the same PowerShell it was started with: `powershell.exe` 5.1 or `pwsh.exe` 7.

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

Install the client on the **remote box**, where you work in the shell and run
Claude Code. `uv`/`uvx`, the Claude Code CLI, the `mcp` package and the shell
aliases all go here, not on the Windows server. (Running the client on Windows
itself is untested.)

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

Split by machine. The **remote box** runs the client (CLI, aliases, MCP server
for Claude Code). The **Windows desktop** runs the server.

### Remote box (client side: Linux / WSL)

| Needed for | Software |
|---|---|
| Everything | Python 3 with `cryptography` (`apt install python3-cryptography` or `pip install cryptography`); every session is encrypted, so it isn't optional |
| Everything | A network route to the Windows server on TCP 9999 (see [Windows Server](#windows-server-powershell)) |
| Auto IP detection | mosh-server built with `--enable-syslog`, plus a persistent journald journal (`journalctl`); otherwise set `NETPASTE_IP` (see [Network Discovery](#network-discovery)) |
| `npd`, `npo`, `npcode` | An SSH server that Windows can reach, for the SSHFS mount (see [Related Tools](#related-tools-windows-server)) |
| `npt`, `nptget`, tmux MCP tools | `tmux` |
| `npgit`, `send_git_output` | `git` |
| Shell aliases | zsh or bash, sourcing `client/.zshrc.np` |
| MCP server | Python 3.10+, `mcp[cli]>=2.3,<3` (installed for you by `uv`/`uvx` or `pip install -e .`), the [Claude Code](https://claude.com/claude-code) CLI, and [`uv`](https://docs.astral.sh/uv/) for the recommended install |

### Windows desktop (server side)

| Needed for | Software |
|---|---|
| Everything | PowerShell 5.1 (built in) or PowerShell 7+, and .NET Framework (built in) |
| Everything | Execution policy that allows the script, and an inbound firewall rule (see [Windows Server](#windows-server-powershell)) |
| `npd`, `npo`, `npcode` on remote files | WinFsp, SSHFS-Win, SSHFS-Win Manager (see [Related Tools](#related-tools-windows-server)) |
| `npcode` | [VS Code](https://code.visualstudio.com/) with `code` on the PATH (the installer's "Add to PATH" option, on by default) |
| Connecting to the remote box | A mosh client, plus SSH for SSHFS |

### Other servers (untested, protocol v1 only)

**macOS server**
- macOS 10.14+ (for Swift 5 support)
- Xcode Command Line Tools or full Xcode
- CommonCrypto framework (included with macOS)

**Linux server**
- **Required**: Python 3.6+ (no external dependencies needed!)
- **Optional enhancements**:
  - Clipboard: `xclip`, `xsel`, or `wl-clipboard` (falls back to file if not available)
  - Dialogs: `zenity` or `kdialog` (falls back to console prompts)
  - System tray: GTK3 libraries (runs fine without)
  - Encryption: `pip3 install cryptography` (basic DH still works without)
  - Notifications: `notify-send` (falls back to console output)

## Remote Development Workflow

1. **Connect to remote box**: Use mosh for persistent sessions
2. **Mount filesystem**: Use SSHFS to mount the remote filesystem's root on Windows, typically as F: (see [Related Tools](#related-tools-windows-server))
3. **Start NetPaste**: Run PowerShell server on Windows
4. **Work remotely**: Use shell aliases to seamlessly interact with local desktop

This setup provides a fluid development experience where you can:
- Copy command output directly to local clipboard
- Open remote projects in local VS Code
- Browse remote files with local file explorer
- Receive desktop notifications from remote processes
- All while maintaining secure, encrypted communication

## Related Tools (Windows server)

NetPaste sends Unix paths (for example `/home/user/project`), and the Windows
server opens them through an SSHFS mount of the remote box. Without that
mount, `npd`, `npo`, `npcode` and the matching MCP tools can't find the
files. Clipboard, notifications, URLs, `npget` and `npgetfile` work without it.

The recommended setup is [SSHFS-Win Manager](https://github.com/evsar3/sshfs-win-manager),
a tray app for SSHFS-Win. It needs two other packages first, installed in this order.

### 1. Install the dependencies

| Order | Package | What it is | Install |
|---|---|---|---|
| 1 | [WinFsp](https://github.com/winfsp/winfsp) | FUSE for Windows (Windows 7–11, x86/x64/ARM64) | Installer from the [latest release](https://github.com/winfsp/winfsp/releases/latest), or `choco install winfsp`. The default components are enough; the "Developer" option is only needed to build file systems. |
| 2 | [SSHFS-Win](https://github.com/winfsp/sshfs-win) | Port of [SSHFS](https://github.com/libfuse/sshfs) to WinFsp/Cygwin | `winget install SSHFS-Win.SSHFS-Win`, or the x64/x86 MSI from the [releases page](https://github.com/winfsp/sshfs-win/releases) |
| 3 | [SSHFS-Win Manager](https://github.com/evsar3/sshfs-win-manager) | GUI that manages SSHFS-Win connections from the tray | Installer from the [latest release](https://github.com/evsar3/sshfs-win-manager/releases/latest) |

Or install the first two from PowerShell, then install SSHFS-Win Manager from its release page:
```powershell
choco install winfsp
winget install SSHFS-Win.SSHFS-Win
```

### 2. Configure a connection in SSHFS-Win Manager

The server matches a mount to a client by **exact IP address**, and it maps
`/some/path` to `<drive>:\some\path`. Configure the connection to fit both rules:

**Basic** tab:

| Field | Value | Why |
|---|---|---|
| IP/Host | The remote box's **IP address**, the same address NetPaste connections come from (not a hostname) | The server compares the mount's host with the client's source IP. If they differ, it falls back to `F:` |
| Port / User | Your SSH port and user on the remote box | |
| Authentication method | **Key file**, using a key without a passphrase | SSHFS-Win can't prompt for a key passphrase. Passwords are stored in plain JSON ([issue #28](https://github.com/evsar3/sshfs-win-manager/issues/28)) |
| Path | `/` (the root of the remote filesystem) | Paths are translated as `/home/user/x` → `F:\home\user\x`, so the drive must show the remote root, not your home directory |
| Drive letter | `F:` (or any free letter, or Auto) | Any letter works. The server reads it from the running `sshfs.exe` command line, and `F:` is the fallback |

**Advanced** tab: turn on **Connect on Startup** and **Try to Reconnect on
Connection Loss**. In the app settings, turn on starting with Windows. Use the
connection debug log if a mount fails.

> SSHFS-Win Manager runs `sshfs.exe` with `StrictHostKeyChecking=no` and
> `UserKnownHostsFile=/dev/null`, so it does not verify the remote host key.
> Use it only on networks you trust, the same as NetPaste itself.

### 3. Check that NetPaste sees the mount

From the remote box, run `npd ~`. The server console should print
`Found SSHFS mount for <ip> on drive <X:>`, and Explorer should open your home
directory. `No SSHFS mount found for <ip>, defaulting to F:` means the
connection's host doesn't match the client's IP. Detection is cached for
5 minutes, so restart the server (`npr`) after you change the mount.

### Without the manager

A plain SSHFS-Win mapping also works when it is a root-relative mapping
(`\\sshfs.r\` for passwords, `\\sshfs.kr\` for keys from `%USERPROFILE%\.ssh\id_rsa`):
```powershell
net use F: \\sshfs.kr\user@192.168.1.50
```
The server detects these mappings from `net use` on any drive letter. A
home-relative mapping (`\\sshfs\`, `\\sshfs.k\`) is detected too, but its paths
won't line up, because the drive shows your home directory instead of `/`.

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