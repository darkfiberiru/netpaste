#!/usr/bin/env python3
"""
NetPaste Python Utility

A Python client for communicating with NetPaste.ps1 running on Windows.
Supports clipboard paste and file explorer functionality.
"""

import argparse
import socket
import subprocess
import sys
import re
import time
import os
import base64
import hashlib
import secrets
import json
import asyncio
from pathlib import Path
from typing import Optional

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.backends import default_backend
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False

DEFAULT_PORT = 9999
SECRET_FILE_PATH = Path.home() / '.config' / 'netpaste' / 'secret.key'

# Diffie-Hellman parameters (RFC 3526 - 2048-bit MODP Group)
DH_P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
DH_G = 2

# Global verbose flag
VERBOSE = False

def log(message, force=False):
    """Print message only if verbose mode or force is True"""
    if VERBOSE or force:
        print(message)

def get_or_create_secret():
    """Get existing shared secret or create a new one"""
    # Create config directory if it doesn't exist
    SECRET_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    
    if SECRET_FILE_PATH.exists():
        # Read existing secret
        with open(SECRET_FILE_PATH, 'r') as f:
            secret = f.read().strip()
            if secret:
                log(f"Loaded shared secret from {SECRET_FILE_PATH}")
                return secret
    
    # Generate new secret (32 bytes hex encoded)
    secret = secrets.token_hex(32)
    
    # Save to file with restrictive permissions
    with open(SECRET_FILE_PATH, 'w') as f:
        f.write(secret)
    
    # Set restrictive permissions (owner read/write only)
    os.chmod(SECRET_FILE_PATH, 0o600)
    
    print(f"Generated new shared secret and saved to {SECRET_FILE_PATH}", file=sys.stderr)
    print(f"Share this secret with the Windows machine to establish trust", file=sys.stderr)
    
    return secret

def clear_secret():
    """Clear the stored shared secret"""
    if SECRET_FILE_PATH.exists():
        SECRET_FILE_PATH.unlink()
        print(f"Cleared shared secret from {SECRET_FILE_PATH}")
        return True
    else:
        print(f"No shared secret found at {SECRET_FILE_PATH}")
        return False

def derive_key(password):
    """Derive a 32-byte AES key from password using SHA-256"""
    return hashlib.sha256(password.encode('utf-8')).digest()

def encrypt_data(data, key):
    """Encrypt data using AES-256-CBC"""
    if not ENCRYPTION_AVAILABLE:
        raise ImportError("cryptography library not available. Install with: pip install cryptography")
    
    # Generate a random 16-byte IV
    iv = os.urandom(16)
    
    # Create cipher
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad data to AES block size
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode('utf-8'))
    padded_data += padder.finalize()
    
    # Encrypt
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # Return base64-encoded IV + ciphertext with prefix
    encrypted_payload = base64.b64encode(iv + ciphertext).decode('ascii')
    return f"NETPASTE_ENCRYPTED:{encrypted_payload}"

def decrypt_data(encrypted_data, key):
    """Decrypt data using AES-256-CBC"""
    if not ENCRYPTION_AVAILABLE:
        raise ImportError("cryptography library not available. Install with: pip install cryptography")
    
    # Remove prefix and decode base64
    if not encrypted_data.startswith("NETPASTE_ENCRYPTED:"):
        raise ValueError("Invalid encrypted data format")
    
    payload = encrypted_data[19:]  # Remove "NETPASTE_ENCRYPTED:" prefix
    data = base64.b64decode(payload)
    
    # Extract IV and ciphertext
    iv = data[:16]
    ciphertext = data[16:]
    
    # Create cipher
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Unpad
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    
    return plaintext.decode('utf-8')

def generate_dh_keypair():
    """Generate Diffie-Hellman key pair"""
    private_key = secrets.randbelow(DH_P - 1) + 1
    public_key = pow(DH_G, private_key, DH_P)
    
    # Verify key generation is correct
    if public_key <= 1 or public_key >= DH_P:
        raise ValueError("Invalid public key generated")
    
    log("Generated valid DH keypair")
    
    return private_key, public_key

def compute_dh_shared_secret(their_public_key, my_private_key):
    """Compute shared secret from DH exchange"""
    # Verify inputs are within valid range
    if their_public_key <= 1 or their_public_key >= DH_P:
        raise ValueError("Invalid public key received")
    
    shared_secret = pow(their_public_key, my_private_key, DH_P)
    
    # Verify shared secret is within expected range
    if shared_secret >= DH_P:
        raise ValueError("Invalid shared secret computed")
    
    # Convert BigInteger to bytes properly (big-endian, fixed-width)
    # Calculate the number of bytes needed for this prime size (2048 bits = 256 bytes)
    byte_length = (DH_P.bit_length() + 7) // 8
    secret_bytes = shared_secret.to_bytes(byte_length, byteorder='big')
    
    # Hash the raw bytes, not the string representation
    hash_bytes = hashlib.sha256(secret_bytes).digest()
    
    log(f"DH exchange completed successfully")
    
    return hash_bytes

def perform_dh_exchange(sock):
    """Perform Diffie-Hellman key exchange with server"""
    log("Starting Diffie-Hellman key exchange...")
    
    # Generate our key pair
    my_private, my_public = generate_dh_keypair()
    log(f"Generated DH keypair")
    
    log(f"Generated DH keypair - public key length: {len(str(my_public))}")
    
    # Send handshake initiation - use string to avoid JSON precision loss
    handshake_msg = {
        "type": "dh_handshake",
        "public_key_str": str(my_public)
    }
    
    json_data = json.dumps(handshake_msg) + "\n"
    sock.sendall(json_data.encode('utf-8'))
    log("Sent DH public key to server")
    
    # Receive server's public key
    response = sock.recv(4096).decode('utf-8').strip()
    server_msg = json.loads(response)
    
    if server_msg.get("type") != "dh_response":
        raise ValueError("Invalid DH handshake response")
    
    server_public_str = server_msg["public_key_str"]
    server_public = int(server_public_str)
    log(f"Received server public key - length: {len(server_public_str)}")
    
    # Verify JSON precision preserved
    if server_public_str != str(server_public):
        raise ValueError("JSON precision loss detected in public key")
    
    # Compute shared secret
    shared_secret = compute_dh_shared_secret(server_public, my_private)
    log("Computed shared secret")
    
    return shared_secret

def authenticate_with_secret(sock, dh_key, shared_secret):
    """Send shared secret encrypted with DH key for authentication"""
    log("Sending encrypted shared secret for authentication...")
    
    # Create authentication message
    auth_msg = {
        "type": "auth",
        "secret": shared_secret
    }
    
    # Encrypt the authentication message with DH key
    auth_json = json.dumps(auth_msg)
    encrypted_auth = encrypt_data(auth_json, dh_key)
    
    # Send encrypted authentication
    sock.sendall(encrypted_auth.encode('utf-8') + b'\n')
    
    # Wait for authentication response (encrypted)
    response = sock.recv(4096).decode('utf-8').strip()
    
    if response.startswith("NETPASTE_ENCRYPTED:"):
        # Decrypt the response
        decrypted_response = decrypt_data(response, dh_key)
        auth_response = json.loads(decrypted_response)
        
        if auth_response.get("type") == "auth_response":
            if auth_response.get("status") == "accepted":
                log("Authentication successful")
                return True
            elif auth_response.get("status") == "stored":
                print("Shared secret stored on Windows machine for future connections", file=sys.stderr)
                return True
            else:
                print(f"Authentication failed: {auth_response.get('message', 'Unknown error')}", file=sys.stderr)
                return False
    
    print("Invalid authentication response from server", file=sys.stderr)
    return False


def get_windows_ip():
    """Extract Windows IP from mosh connection logs in journalctl"""
    try:
        # Get current username
        username = os.environ.get('USER', 'unknown')
        
        # Search journalctl for mosh-server connections for this user
        result = subprocess.run([
            'journalctl', 
            '--grep', f'user {username} connected from host',
            '--output', 'cat',
            '--no-pager',
            '--quiet'
        ], capture_output=True, text=True, check=True)
        
        # Look for the most recent connection
        lines = result.stdout.strip().split('\n')
        for line in reversed(lines):
            if f'user {username} connected from host' in line:
                # Extract IP from pattern like "user username connected from host: 192.168.1.100"
                match = re.search(rf'user {username} connected from host:\s*(\d+\.\d+\.\d+\.\d+)', line)
                if match:
                    ip = match.group(1)
                    log(f"Found most recent mosh connection from: {ip}")
                    return ip
        
        log(f"No mosh connections found for user {username} in journalctl")
        return None
        
    except subprocess.CalledProcessError as e:
        log(f"Error running journalctl command: {e}")
        return None

def send_to_netpaste(data, ip=None, port=DEFAULT_PORT):
    """Send data to NetPaste.ps1 via TCP"""
    if ip is None:
        ip = get_windows_ip()
        if ip is None:
            print("Could not determine Windows IP. Please specify with -i/--ip")
            return False
    
    try:
        print(f"Connecting to {ip}:{port}...")
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(10)  # 10 second timeout
            sock.connect((ip, port))
            
            # Always use Diffie-Hellman key exchange if available
            if ENCRYPTION_AVAILABLE:
                print("Using Diffie-Hellman key exchange...")
                print(f"Original data to encrypt: '{data[:100]}{'...' if len(data) > 100 else ''}'")
                try:
                    # First establish DH key exchange
                    dh_key = perform_dh_exchange(sock)
                    
                    # Then authenticate with shared secret (encrypted)
                    shared_secret = get_or_create_secret()
                    if not authenticate_with_secret(sock, dh_key, shared_secret):
                        print("Authentication failed")
                        return False
                    
                    # Now send the actual data
                    encrypted_data = encrypt_data(data, dh_key)
                    print(f"Encrypted payload: '{encrypted_data[:100]}{'...' if len(encrypted_data) > 100 else ''}'")
                    data = encrypted_data
                    print("Data encrypted with DH-derived key")
                except Exception as e:
                    print(f"DH exchange failed: {e}")
                    return False
            else:
                print("Warning: cryptography library not available")
                print("Install with: pip install cryptography")
                return False
            
            # Send the data
            print(f"Sending payload: '{data[:100]}{'...' if len(data) > 100 else ''}'")
            sock.sendall(data.encode('utf-8'))
            
            # Give the server a moment to process
            time.sleep(0.5)
            
        print(f"Data sent successfully to {ip}:{port}")
        return True
        
    except socket.timeout:
        print(f"Connection to {ip}:{port} timed out")
        return False
    except ConnectionRefusedError:
        print(f"Connection refused by {ip}:{port}. Is NetPaste.ps1 running?")
        return False
    except Exception as e:
        print(f"Error sending data: {e}")
        return False

def paste_text(text, ip=None, port=DEFAULT_PORT):
    """Send text to be pasted to clipboard"""
    paste_message = json.dumps({"type": "paste", "text": text})
    return send_to_netpaste(paste_message, ip, port)

def open_explorer(path, ip=None, port=DEFAULT_PORT):
    """Send file explorer request"""
    # Resolve to absolute path
    abs_path = os.path.abspath(os.path.expanduser(path))
    explorer_message = json.dumps({"type": "explorer", "path": abs_path})
    print(f"Sending explorer message: {explorer_message}")
    return send_to_netpaste(explorer_message, ip, port)

def open_file(path, ip=None, port=DEFAULT_PORT):
    """Send file open request"""
    # Resolve to absolute path
    abs_path = os.path.abspath(os.path.expanduser(path))
    file_message = json.dumps({"type": "open_file", "path": abs_path})
    print(f"Sending file open message: {file_message}")
    return send_to_netpaste(file_message, ip, port)

def open_url(url, ip=None, port=DEFAULT_PORT):
    """Send URL open request"""
    url_message = json.dumps({"type": "open_url", "url": url})
    print(f"Sending URL open message: {url_message}")
    return send_to_netpaste(url_message, ip, port)

def send_notification(message, ip=None, port=DEFAULT_PORT):
    """Send notification request"""
    notify_message = json.dumps({"type": "notification", "message": message})
    print(f"Sending notification: {message}")
    return send_to_netpaste(notify_message, ip, port)

def get_tmux_buffer():
    """Get the current tmux paste buffer contents"""
    try:
        # Check if we're in a tmux session
        if 'TMUX' not in os.environ:
            print("Not in a tmux session", file=sys.stderr)
            return None

        # Get tmux buffer contents
        result = subprocess.run(
            ['tmux', 'show-buffer'],
            capture_output=True,
            text=True,
            check=True
        )

        return result.stdout
    except subprocess.CalledProcessError as e:
        if "no buffers" in e.stderr.lower():
            print("No tmux buffer available", file=sys.stderr)
        else:
            print(f"Error reading tmux buffer: {e.stderr}", file=sys.stderr)
        return None
    except FileNotFoundError:
        print("tmux command not found", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return None

def open_vscode(path, ip=None, port=DEFAULT_PORT):
    """Send VS Code open request"""
    # Resolve to absolute path
    abs_path = os.path.abspath(os.path.expanduser(path))
    vscode_message = json.dumps({"type": "vscode", "path": abs_path})
    print(f"Sending VS Code open request: {abs_path}")
    return send_to_netpaste(vscode_message, ip, port)

def restart_netpaste(ip=None, port=DEFAULT_PORT):
    """Send restart request to NetPaste"""
    restart_message = json.dumps({"type": "restart"})
    print("Sending restart request...")
    return send_to_netpaste(restart_message, ip, port)

def paste_from_stdin(ip=None, port=DEFAULT_PORT):
    """Read from stdin and paste"""
    try:
        data = sys.stdin.read()
        if not data.strip():
            print("No data received from stdin")
            return False
        return paste_text(data, ip, port)
    except KeyboardInterrupt:
        print("\nOperation cancelled")
        return False

def run_mcp_server():
    """Run netpaste as an MCP server"""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print("MCP server support requires 'mcp' package")
        print("Install with: pip install 'mcp[cli]'")
        exit(1)
    
    # Create FastMCP server instance
    mcp = FastMCP(
        "NetPaste",
        instructions="NetPaste MCP Server - Send data to Windows clipboard and control Windows applications from Linux/WSL"
    )
    
    # Get IP from environment or try to auto-detect
    default_ip = os.environ.get('NETPASTE_IP') or get_windows_ip()
    default_port = int(os.environ.get('NETPASTE_PORT', DEFAULT_PORT))
    
    @mcp.tool()
    def send_to_clipboard(text: str) -> str:
        """Send text to Windows clipboard via NetPaste"""
        target_ip = default_ip
        if not target_ip:
            return "Error: Could not determine Windows IP. Set NETPASTE_IP environment variable."
        
        if paste_text(text, target_ip, default_port):
            return f"Successfully sent {len(text)} characters to clipboard"
        return "Failed to send text to clipboard"
    
    @mcp.tool()
    def send_file_to_clipboard(file_path: str) -> str:
        """Send file contents to Windows clipboard"""
        target_ip = default_ip
        if not target_ip:
            return "Error: Could not determine Windows IP. Set NETPASTE_IP environment variable."
        
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            if paste_text(content, target_ip, default_port):
                return f"Successfully sent contents of {file_path} ({len(content)} characters) to clipboard"
            return f"Failed to send contents of {file_path} to clipboard"
        except FileNotFoundError:
            return f"Error: File '{file_path}' not found"
        except Exception as e:
            return f"Error reading file: {e}"
    
    @mcp.tool()
    def open_explorer(path: str = ".") -> str:
        """Open Windows File Explorer at specified path"""
        target_ip = default_ip
        if not target_ip:
            return "Error: Could not determine Windows IP. Set NETPASTE_IP environment variable."
        
        # Resolve path
        resolved_path = os.path.abspath(path) if path else os.getcwd()
        
        explorer_message = json.dumps({"type": "explorer", "path": resolved_path})
        if send_to_netpaste(explorer_message, target_ip, default_port):
            return f"Opened File Explorer at: {resolved_path}"
        return f"Failed to open File Explorer at: {resolved_path}"
    
    @mcp.tool()
    def open_file_with_default(file_path: str) -> str:
        """Open file with default Windows application"""
        target_ip = default_ip
        if not target_ip:
            return "Error: Could not determine Windows IP. Set NETPASTE_IP environment variable."
        
        if not os.path.exists(file_path):
            return f"Error: File '{file_path}' not found"
        
        abs_path = os.path.abspath(file_path)
        file_message = json.dumps({"type": "open_file", "path": abs_path})
        
        if send_to_netpaste(file_message, target_ip, default_port):
            return f"Opened file: {abs_path}"
        return f"Failed to open file: {abs_path}"
    
    @mcp.tool()
    def open_url_in_browser(url: str) -> str:
        """Open URL in default Windows browser"""
        target_ip = default_ip
        if not target_ip:
            return "Error: Could not determine Windows IP. Set NETPASTE_IP environment variable."
        
        url_message = json.dumps({"type": "open_url", "url": url})
        if send_to_netpaste(url_message, target_ip, default_port):
            return f"Opened URL: {url}"
        return f"Failed to open URL: {url}"
    
    @mcp.tool()
    def open_in_vscode(path: str) -> str:
        """Open file or folder in VS Code on Windows"""
        target_ip = default_ip
        if not target_ip:
            return "Error: Could not determine Windows IP. Set NETPASTE_IP environment variable."
        
        if open_vscode(path, target_ip, default_port):
            return f"Opened in VS Code: {path}"
        return f"Failed to open in VS Code: {path}"
    
    @mcp.tool()
    def send_notification(message: str) -> str:
        """Send notification to Windows desktop"""
        target_ip = default_ip
        if not target_ip:
            return "Error: Could not determine Windows IP. Set NETPASTE_IP environment variable."
        
        notify_message = json.dumps({"type": "notification", "message": message})
        if send_to_netpaste(notify_message, target_ip, default_port):
            return f"Sent notification: {message}"
        return "Failed to send notification"
    
    @mcp.tool()
    def send_ls_output(directory: str = ".") -> str:
        """Send ls -la output to Windows clipboard"""
        target_ip = default_ip
        if not target_ip:
            return "Error: Could not determine Windows IP. Set NETPASTE_IP environment variable."
        
        try:
            result = subprocess.run(
                ['ls', '-la', directory],
                capture_output=True,
                text=True,
                check=True
            )
            if paste_text(result.stdout, target_ip, default_port):
                return f"Sent ls output for {directory} to clipboard ({len(result.stdout)} characters)"
            return f"Failed to send ls output for {directory}"
        except subprocess.CalledProcessError as e:
            return f"Error running ls: {e.stderr}"
        except Exception as e:
            return f"Error: {e}"
    
    @mcp.tool() 
    def send_git_output(command: str = "status") -> str:
        """Send git command output to Windows clipboard (status, diff, or log)"""
        target_ip = default_ip
        if not target_ip:
            return "Error: Could not determine Windows IP. Set NETPASTE_IP environment variable."
        
        git_commands = {
            "status": ["git", "status"],
            "st": ["git", "status"],
            "diff": ["git", "diff"],
            "d": ["git", "diff"],
            "log": ["git", "log", "--oneline", "-10"],
            "l": ["git", "log", "--oneline", "-10"]
        }
        
        if command not in git_commands:
            return f"Error: Unknown git command '{command}'. Use: status, diff, or log"
        
        try:
            result = subprocess.run(
                git_commands[command],
                capture_output=True,
                text=True,
                check=True
            )
            if paste_text(result.stdout, target_ip, default_port):
                return f"Sent git {command} output to clipboard ({len(result.stdout)} characters)"
            return f"Failed to send git {command} output"
        except subprocess.CalledProcessError as e:
            return f"Error running git: {e.stderr}"
        except Exception as e:
            return f"Error: {e}"
    
    @mcp.tool()
    def send_current_path() -> str:
        """Send current working directory path to Windows clipboard"""
        target_ip = default_ip
        if not target_ip:
            return "Error: Could not determine Windows IP. Set NETPASTE_IP environment variable."

        cwd = os.getcwd()
        if paste_text(cwd, target_ip, default_port):
            return f"Sent current path to clipboard: {cwd}"
        return "Failed to send current path to clipboard"

    @mcp.tool()
    def get_tmux_buffer_contents() -> str:
        """Get the current tmux paste buffer contents and return as string"""
        buffer_contents = get_tmux_buffer()
        if buffer_contents is None:
            return ""
        return buffer_contents

    @mcp.tool()
    def send_tmux_buffer_to_clipboard() -> str:
        """Send tmux buffer contents to Windows clipboard (equivalent to npt command)"""
        target_ip = default_ip
        if not target_ip:
            return "Error: Could not determine Windows IP. Set NETPASTE_IP environment variable."

        buffer_contents = get_tmux_buffer()
        if buffer_contents is None:
            return "Error: Could not retrieve tmux buffer (not in tmux session or buffer empty)"

        if not buffer_contents:
            return "Tmux buffer is empty"

        if paste_text(buffer_contents, target_ip, default_port):
            return f"Sent tmux buffer to clipboard ({len(buffer_contents)} characters)"
        return "Failed to send tmux buffer to clipboard"

    @mcp.tool()
    def restart_netpaste_server() -> str:
        """Restart the NetPaste PowerShell server"""
        target_ip = default_ip
        if not target_ip:
            return "Error: Could not determine Windows IP. Set NETPASTE_IP environment variable."
        
        if restart_netpaste(target_ip, default_port):
            return "NetPaste server restart requested"
        return "Failed to restart NetPaste server"
    
    # Run the MCP server
    print(f"Starting NetPaste MCP Server...")
    if default_ip:
        print(f"Default Windows IP: {default_ip}")
    else:
        print("Warning: Could not auto-detect Windows IP")
        print("Set NETPASTE_IP environment variable")
    
    # Support running with stdio transport when called from MCP
    if 'stdio' in sys.argv:
        # Running via MCP with stdio transport
        mcp.run(transport='stdio')
    else:
        # Direct execution, use default transport
        mcp.run()

def main():
    parser = argparse.ArgumentParser(
        description="NetPaste Python client - Send clipboard data or open file explorer on Windows",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-detect Windows IP and paste text
  echo "Hello World" | netpaste.py
  
  # Paste specific text
  netpaste.py -t "Some text to paste"
  
  # Open file explorer at path
  netpaste.py -e /home/user/documents
  
  # Open file explorer at current directory
  netpaste.py -e
  
  # Restart the PowerShell script
  netpaste.py -r
  
  # Specify Windows IP manually
  netpaste.py -i 192.168.1.100 -t "Hello"
  
  # Use different port
  netpaste.py -p 8888 -t "Hello"
        """
    )
    
    parser.add_argument('-i', '--ip', 
                       help='Windows machine IP (auto-detected from mosh if not specified)')
    parser.add_argument('-p', '--port', type=int, default=DEFAULT_PORT,
                       help=f'Port number (default: {DEFAULT_PORT})')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('-m', '--mcp', action='store_true',
                       help='Run as MCP server for Claude Code')
    
    # Optional positional argument for MCP stdio transport
    parser.add_argument('transport', nargs='?', choices=['stdio'], 
                       help=argparse.SUPPRESS)  # Hidden argument for MCP stdio mode
    
    # Action group - only one action at a time
    action_group = parser.add_mutually_exclusive_group()
    action_group.add_argument('-t', '--text', 
                             help='Text to paste to clipboard')
    action_group.add_argument('-e', '--explorer', nargs='?', const='.',
                             help='Path to open in file explorer (Unix path will be converted to F: drive). Uses current directory if no path specified.')
    action_group.add_argument('-o', '--open', 
                             help='File path to open with default application (Unix path will be converted to F: drive)')
    action_group.add_argument('-u', '--url',
                             help='URL to open in default Windows browser')
    action_group.add_argument('-n', '--notify',
                             help='Send notification message to Windows')
    action_group.add_argument('--vscode',
                             help='File or folder path to open in VS Code (Unix path will be converted to F: drive)')
    action_group.add_argument('-r', '--restart', action='store_true',
                             help='Restart the NetPaste PowerShell script')
    action_group.add_argument('-s', '--stdin', action='store_true',
                             help='Read text from stdin (default if no other action specified)')
    action_group.add_argument('-c', '--clear-secret', action='store_true',
                             help='Clear the stored shared secret')
    action_group.add_argument('--tmux-buffer', action='store_true',
                             help='Output tmux buffer contents to stdout (for piping or inspection)')
    action_group.add_argument('--tmux-send', action='store_true',
                             help='Send tmux buffer contents to clipboard')
    
    args = parser.parse_args()
    
    # If MCP mode is requested, run MCP server instead
    if args.mcp or args.transport == 'stdio':
        run_mcp_server()
        return
    
    # Set global verbose flag
    global VERBOSE
    VERBOSE = args.verbose
    
    # Handle clear-secret action first
    if args.clear_secret:
        success = clear_secret()
        sys.exit(0 if success else 1)

    # Handle tmux-buffer action
    if args.tmux_buffer:
        buffer_contents = get_tmux_buffer()
        if buffer_contents:
            print(buffer_contents, end='')
            sys.exit(0)
        else:
            sys.exit(1)

    # Handle tmux-send action
    if args.tmux_send:
        buffer_contents = get_tmux_buffer()
        if buffer_contents:
            success = paste_text(buffer_contents, args.ip, args.port)
            sys.exit(0 if success else 1)
        else:
            print("Error: Could not retrieve tmux buffer", file=sys.stderr)
            sys.exit(1)

    # If no action specified and stdin is available, default to stdin
    if not args.text and not args.explorer and not args.open and not args.url and not args.notify and not args.vscode and not args.restart and not args.stdin and not args.tmux_send:
        if not sys.stdin.isatty():  # Data available on stdin
            args.stdin = True
        else:
            parser.print_help()
            sys.exit(1)
    
    success = False
    
    if args.text:
        success = paste_text(args.text, args.ip, args.port)
    elif args.explorer is not None:
        # Pass the path directly - function will resolve it
        success = open_explorer(args.explorer, args.ip, args.port)
    elif args.open:
        success = open_file(args.open, args.ip, args.port)
    elif args.url:
        success = open_url(args.url, args.ip, args.port)
    elif args.notify:
        success = send_notification(args.notify, args.ip, args.port)
    elif args.vscode:
        success = open_vscode(args.vscode, args.ip, args.port)
    elif args.restart:
        success = restart_netpaste(args.ip, args.port)
    elif args.stdin:
        success = paste_from_stdin(args.ip, args.port)
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()