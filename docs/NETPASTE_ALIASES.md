# NetPaste Bash Aliases Setup

## Prerequisites

1. **Copy netpaste.py to ~/bin/**
   ```bash
   cp netpaste.py ~/bin/
   chmod +x ~/bin/netpaste.py
   ```

2. **Ensure ~/bin is in your PATH**
   Add this to your `~/.bashrc` or `~/.bash_profile`:
   ```bash
   export PATH="$HOME/bin:$PATH"
   ```

## Bash Aliases

Add these aliases to your `~/.bashrc` file:

```bash
# NetPaste Aliases - Cross-platform clipboard and file operations

# np - Send piped input to NetPaste (most common use case)
# Usage: echo "text" | np
np() {
    if [ -t 0 ]; then
        echo "Error: np requires piped input"
        echo "Usage: echo 'text' | np"
        echo "       cat file.txt | np"
        echo "       ps aux | np"
        return 1
    fi
    python3 ~/bin/netpaste.py -s
}

# npf - Send file contents to NetPaste
# Usage: npf filename
npf() {
    if [ $# -eq 0 ]; then
        echo "Usage: npf <filename>"
        echo "Send file contents to NetPaste clipboard"
        return 1
    fi
    
    local file="$1"
    if [ ! -f "$file" ]; then
        echo "Error: File '$file' not found"
        return 1
    fi
    
    cat "$file" | python3 ~/bin/netpaste.py
}

# npd - Send current directory to NetPaste file explorer
# Usage: npd [directory]
npd() {
    local dir="${1:-.}"  # Use provided directory or current directory
    python3 ~/bin/netpaste.py -e "$dir"
}

# npt - Send text directly to NetPaste
# Usage: npt "some text"
npt() {
    if [ $# -eq 0 ]; then
        echo "Usage: npt <text>"
        echo "Send text directly to NetPaste clipboard"
        return 1
    fi
    python3 ~/bin/netpaste.py -t "$*"
}

# npr - Restart NetPaste server
# Usage: npr
npr() {
    python3 ~/bin/netpaste.py -r
}

# nppair - Pair this client with the NetPaste server (once per server)
# Usage: nppair
# Shows a 6-digit code; approve on both ends only if it matches the server's dialog
nppair() {
    python3 ~/bin/netpaste.py --pair "$@"
}

# npls - Send ls output to NetPaste
# Usage: npls [directory]
npls() {
    local dir="${1:-.}"
    ls -la "$dir" | python3 ~/bin/netpaste.py -s
}

# npgit - Send git status/diff to NetPaste
# Usage: npgit [status|diff|log]
npgit() {
    local cmd="${1:-status}"
    case "$cmd" in
        status|st)
            git status | python3 ~/bin/netpaste.py -s
            ;;
        diff|d)
            git diff | python3 ~/bin/netpaste.py -s
            ;;
        log|l)
            git log --oneline -10 | python3 ~/bin/netpaste.py -s
            ;;
        *)
            echo "Usage: npgit [status|diff|log]"
            return 1
            ;;
    esac
}

# nppath - Send current path to NetPaste
# Usage: nppath
nppath() {
    pwd | python3 ~/bin/netpaste.py -s
}

# npo - Open file with default Windows application
# Usage: npo filename
npo() {
    if [ $# -eq 0 ]; then
        echo "Usage: npo <filename>"
        echo "Open file with default Windows application"
        return 1
    fi
    
    local file="$1"
    if [ ! -f "$file" ]; then
        echo "Error: File '$file' not found"
        return 1
    fi
    
    python3 ~/bin/netpaste.py -o "$file"
}

# npurl - Open URL in default Windows browser
# Usage: npurl <url>
npurl() {
    if [ $# -eq 0 ]; then
        echo "Usage: npurl <url>"
        echo "Open URL in default Windows browser"
        return 1
    fi
    
    python3 ~/bin/netpaste.py -u "$1"
}

# npnotify - Send notification to Windows
# Usage: npnotify "message"
npnotify() {
    if [ $# -eq 0 ]; then
        echo "Usage: npnotify <message>"
        echo "Send notification message to Windows"
        return 1
    fi
    
    python3 ~/bin/netpaste.py -n "$*"
}
```

## Usage Examples

```bash
# Send piped input to clipboard
echo "Hello World" | np
ps aux | np
cat myfile.txt | np

# Send file contents to clipboard
npf README.md
npf script.py

# Open directories in Windows File Explorer
npd                      # Current directory
npd /home/user/documents # Specific directory

# Open files with default Windows applications
npo document.pdf
npo image.jpg
npo script.py

# Open URLs in Windows browser
npurl "https://github.com"
npurl "https://docs.python.org"

# Send Windows notifications
npnotify "Build completed successfully"
npnotify "Server restarted at $(date)"

# Send text directly
npt "Quick message to clipboard"

# Restart NetPaste server
npr

# Pair with the server (first use, or after clearing pairings)
nppair

# Send directory listings
npls                     # Current directory
npls /etc               # Specific directory

# Send git information
npgit status            # Git status
npgit diff              # Git diff
npgit log               # Recent commits

# Send current path
nppath
```

## Installation

1. Copy the aliases to your `~/.bashrc` file
2. Reload your shell: `source ~/.bashrc`
3. All `np*` commands will now be available!

---

## Copy-Paste Block for ~/.bashrc

Copy this entire block and paste it into your `~/.bashrc` file:

```bash
# NetPaste - Cross-platform clipboard and file operations
export PATH="$HOME/bin:$PATH"

# np - Send piped input to NetPaste (most common use case)
np() { if [ -t 0 ]; then echo "Error: np requires piped input"; echo "Usage: echo 'text' | np"; echo "       cat file.txt | np"; echo "       ps aux | np"; return 1; fi; python3 ~/bin/netpaste.py -s; }

# npf - Send file contents to NetPaste
npf() { if [ $# -eq 0 ]; then echo "Usage: npf <filename>"; echo "Send file contents to NetPaste clipboard"; return 1; fi; local file="$1"; if [ ! -f "$file" ]; then echo "Error: File '$file' not found"; return 1; fi; cat "$file" | python3 ~/bin/netpaste.py; }

# npd - Send current directory to NetPaste file explorer
npd() { local dir="${1:-.}"; python3 ~/bin/netpaste.py -e "$dir"; }

# npt - Send text directly to NetPaste
npt() { if [ $# -eq 0 ]; then echo "Usage: npt <text>"; echo "Send text directly to NetPaste clipboard"; return 1; fi; python3 ~/bin/netpaste.py -t "$*"; }

# npr - Restart NetPaste server
npr() { python3 ~/bin/netpaste.py -r; }

# npls - Send ls output to NetPaste
npls() { local dir="${1:-.}"; ls -la "$dir" | python3 ~/bin/netpaste.py -s; }

# npgit - Send git status/diff to NetPaste
npgit() { local cmd="${1:-status}"; case "$cmd" in status|st) git status | python3 ~/bin/netpaste.py -s ;; diff|d) git diff | python3 ~/bin/netpaste.py -s ;; log|l) git log --oneline -10 | python3 ~/bin/netpaste.py -s ;; *) echo "Usage: npgit [status|diff|log]"; return 1 ;; esac; }

# nppath - Send current path to NetPaste
nppath() { pwd | python3 ~/bin/netpaste.py -s; }

# npo - Open file with default Windows application
npo() { if [ $# -eq 0 ]; then echo "Usage: npo <filename>"; echo "Open file with default Windows application"; return 1; fi; local file="$1"; if [ ! -f "$file" ]; then echo "Error: File '$file' not found"; return 1; fi; python3 ~/bin/netpaste.py -o "$file"; }

# npurl - Open URL in default Windows browser
npurl() { if [ $# -eq 0 ]; then echo "Usage: npurl <url>"; echo "Open URL in default Windows browser"; return 1; fi; python3 ~/bin/netpaste.py -u "$1"; }

# npnotify - Send notification to Windows
npnotify() { if [ $# -eq 0 ]; then echo "Usage: npnotify <message>"; echo "Send notification message to Windows"; return 1; fi; python3 ~/bin/netpaste.py -n "$*"; }
```