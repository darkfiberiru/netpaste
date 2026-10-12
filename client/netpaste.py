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
import hmac
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
# Pairing storage: this client's id plus one secret per paired server, keyed by server_id.
# Format: {"client_id": "...", "servers": {"<server_id>": {"secret": hex, "paired": iso, "ip": "..."}}}
PAIRINGS_FILE_PATH = Path.home() / '.config' / 'netpaste' / 'pairings.json'
# Pre-v2 single shared secret; no longer used, removed by --clear-secret
LEGACY_SECRET_FILE_PATH = Path.home() / '.config' / 'netpaste' / 'secret.key'
PROTOCOL_VERSION = 2
ID_PATTERN = re.compile(r'^[A-Za-z0-9._-]{1,64}$')

# Diffie-Hellman parameters (RFC 3526 - 2048-bit MODP Group)
DH_P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
DH_G = 2

# Global verbose flag
VERBOSE = False

def log(message, force=False):
    """Print message only if verbose mode or force is True"""
    if VERBOSE or force:
        print(message)

class NetPasteError(Exception):
    """Handshake, pairing or authentication failure with a user-facing message"""

def new_client_id():
    """Readable, unique id for this client: sanitized hostname plus random suffix"""
    host = re.sub(r'[^A-Za-z0-9.-]', '-', socket.gethostname())[:40] or 'client'
    return f"{host}-{secrets.token_hex(3)}"

def save_pairings(pairings):
    """Write pairings with owner-only permissions (directory 0700, file 0600)"""
    config_dir = PAIRINGS_FILE_PATH.parent
    config_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(config_dir, 0o700)
    tmp_path = PAIRINGS_FILE_PATH.with_suffix('.tmp')
    if tmp_path.exists():
        tmp_path.unlink()
    # Create with 0600 up front so the secret is never readable by others, then swap in atomically
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(pairings, f, indent=2)
    os.replace(tmp_path, PAIRINGS_FILE_PATH)

def load_pairings():
    """Load pairings, creating a client id on first use"""
    try:
        pairings = json.loads(PAIRINGS_FILE_PATH.read_text())
    except FileNotFoundError:
        pairings = {}
    if not isinstance(pairings.get('servers'), dict):
        pairings['servers'] = {}
    if not ID_PATTERN.match(str(pairings.get('client_id', ''))):
        pairings['client_id'] = new_client_id()
        save_pairings(pairings)
    return pairings

def clear_secret():
    """Clear all stored server pairings (and the pre-v2 shared secret, if present)"""
    cleared = False
    for path in (PAIRINGS_FILE_PATH, LEGACY_SECRET_FILE_PATH):
        if path.exists():
            path.unlink()
            print(f"Removed {path}")
            cleared = True
    if not cleared:
        print(f"No pairings found at {PAIRINGS_FILE_PATH}")
    return cleared

# --- Handshake key derivation (protocol v2) ---
# Must match server/NetPaste-Windows.ps1 byte for byte.
#   transcript = UTF8("netpaste-v2\n" + client_id + "\n" + server_id + "\n"
#                     + client_public_str + "\n" + server_public_str + "\n") || dh_key
#   pairing code   = (first 4 bytes of SHA256(b"netpaste-sas" || transcript), big-endian) mod 10^6
#   pairing secret = HMAC-SHA256(key = dh_key, b"netpaste-pair" || transcript)
#   session key    = HMAC-SHA256(key = pairing secret, b"netpaste-session" || transcript)
# dh_key is SHA256 of the 256-byte big-endian DH shared value; public keys are the
# exact decimal strings sent on the wire.

def handshake_transcript(client_id, server_id, client_public_str, server_public_str, dh_key):
    header = f"netpaste-v2\n{client_id}\n{server_id}\n{client_public_str}\n{server_public_str}\n"
    return header.encode('utf-8') + dh_key

def pairing_code(transcript):
    digest = hashlib.sha256(b"netpaste-sas" + transcript).digest()
    return f"{int.from_bytes(digest[:4], 'big') % 1000000:06d}"

def pairing_secret(dh_key, transcript):
    return hmac.new(dh_key, b"netpaste-pair" + transcript, hashlib.sha256).digest()

def session_key(secret, transcript):
    return hmac.new(secret, b"netpaste-session" + transcript, hashlib.sha256).digest()

def recv_line(sock, limit=65536):
    """Read one newline-terminated message from the socket"""
    data = b''
    while b'\n' not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > limit:
            raise NetPasteError("Message from server too large")
    return data.split(b'\n', 1)[0].decode('utf-8').strip()

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
    if their_public_key <= 1 or their_public_key >= DH_P - 1:
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

def perform_dh_exchange(sock, client_id, pair=False):
    """Perform Diffie-Hellman key exchange with server; returns handshake state.

    When pairing, the client first sends only a hash of its public key and reveals the key
    in the pair_request after the server has sent its own. Neither side can then choose its
    key after seeing the other's, so a man-in-the-middle cannot search for keys that make
    the two pairing codes match.
    """
    log("Starting Diffie-Hellman key exchange...")
    
    # Generate our key pair
    my_private, my_public = generate_dh_keypair()
    my_public_str = str(my_public)
    
    # Send handshake initiation - use string to avoid JSON precision loss
    handshake_msg = {
        "type": "dh_handshake",
        "v": PROTOCOL_VERSION,
        "client_id": client_id,
    }
    if pair:
        handshake_msg["pair"] = True
        handshake_msg["commit"] = hashlib.sha256(my_public_str.encode('utf-8')).hexdigest()
    else:
        handshake_msg["public_key_str"] = my_public_str
    sock.sendall((json.dumps(handshake_msg) + "\n").encode('utf-8'))
    log("Sent DH handshake to server")
    
    # Receive server's public key
    server_msg = json.loads(recv_line(sock))
    if server_msg.get("type") == "error":
        raise NetPasteError(f"Server refused handshake: {server_msg.get('message')}")
    if server_msg.get("type") != "dh_response":
        raise NetPasteError("Invalid DH handshake response")
    if server_msg.get("v") != PROTOCOL_VERSION:
        raise NetPasteError("Server uses an older NetPaste protocol; update NetPaste-Windows.ps1")
    
    server_id = str(server_msg.get("server_id", ""))
    if not ID_PATTERN.match(server_id):
        raise NetPasteError("Invalid server_id in DH handshake response")
    
    server_public_str = server_msg["public_key_str"]
    server_public = int(server_public_str)
    if server_public_str != str(server_public):
        raise NetPasteError("Malformed server public key")
    
    if pair:
        reveal = {"type": "pair_request", "public_key_str": my_public_str}
        sock.sendall((json.dumps(reveal) + "\n").encode('utf-8'))
    
    dh_key = compute_dh_shared_secret(server_public, my_private)
    log(f"DH exchange with server {server_id} complete (server has pairing: {server_msg.get('paired')})")
    
    return {
        "server_id": server_id,
        "server_paired": server_msg.get("paired") is True,
        "dh_key": dh_key,
        "transcript": handshake_transcript(client_id, server_id, my_public_str, server_public_str, dh_key),
    }

def open_session(sock):
    """DH key exchange plus proof of the paired secret; returns the session key.

    The secret itself never crosses the wire: both ends mix it into the session key, so a
    man-in-the-middle without it cannot derive the key that either side uses.
    """
    pairings = load_pairings()
    handshake = perform_dh_exchange(sock, pairings['client_id'])
    server_id = handshake['server_id']
    
    entry = pairings['servers'].get(server_id)
    if not entry:
        raise NetPasteError(f"Not paired with server {server_id}. Pair once from a terminal: nppair (netpaste.py --pair)")
    if not handshake['server_paired']:
        raise NetPasteError(f"Server {server_id} has no pairing for this client (cleared on the server?). "
                            "Pair again from a terminal: nppair (netpaste.py --pair)")
    
    key = session_key(bytes.fromhex(entry['secret']), handshake['transcript'])
    sock.sendall(encrypt_data(json.dumps({"type": "auth"}), key).encode('utf-8') + b'\n')
    
    response = recv_line(sock)
    if response.startswith("NETPASTE_ENCRYPTED:"):
        try:
            auth_response = json.loads(decrypt_data(response, key))
        except Exception:
            auth_response = {}
        if auth_response.get("type") == "auth_response" and auth_response.get("status") == "accepted":
            log("Authentication successful")
            return key
        raise NetPasteError("Could not verify the server's response (secret mismatch or man-in-the-middle)")
    
    try:
        message = json.loads(response).get('message', 'no reason given')
    except Exception:
        message = 'no response'
    raise NetPasteError(f"Authentication rejected: {message}")

def pair_with_server(ip=None, port=DEFAULT_PORT):
    """Pair with a server after both ends confirm a short code derived from the DH exchange"""
    if ip is None:
        ip = get_windows_ip()
        if ip is None:
            print("Could not determine Windows IP. Please specify with -i/--ip", file=sys.stderr)
            return False
    if not ENCRYPTION_AVAILABLE:
        print("Error: cryptography library not available. Install with: pip install cryptography", file=sys.stderr)
        return False
    try:
        # Separate handles: /dev/tty is not seekable, so text mode 'r+' fails
        tty_in = open('/dev/tty', 'r')
        tty = open('/dev/tty', 'w')
    except OSError as e:
        print(f"Pairing needs an interactive terminal to confirm the pairing code ({e})", file=sys.stderr)
        return False
    
    pairings = load_pairings()
    try:
        with tty_in, tty, socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(10)
            print(f"Connecting to {ip}:{port}...", file=sys.stderr)
            sock.connect((ip, port))
            
            handshake = perform_dh_exchange(sock, pairings['client_id'], pair=True)
            code = pairing_code(handshake['transcript'])
            
            tty.write(f"\nPairing client '{pairings['client_id']}' with server {handshake['server_id']} at {ip}.\n"
                      f"A dialog on the server shows a pairing code. This terminal shows:\n\n"
                      f"        {code[:3]} {code[3:]}\n\n"
                      f"If the codes differ, someone may be intercepting the connection: answer n and\n"
                      f"reject it on the server too.\n"
                      f"Do the codes match? [y/N] ")
            tty.flush()
            if tty_in.readline().strip().lower() not in ('y', 'yes'):
                print("Pairing cancelled", file=sys.stderr)
                return False
            
            print("Waiting for approval on the server...", file=sys.stderr)
            sock.settimeout(180)
            response = recv_line(sock)
            
            secret = pairing_secret(handshake['dh_key'], handshake['transcript'])
            key = session_key(secret, handshake['transcript'])
            if response.startswith("NETPASTE_ENCRYPTED:"):
                try:
                    pair_response = json.loads(decrypt_data(response, key))
                except Exception:
                    pair_response = {}
                if pair_response.get("type") == "pair_response" and pair_response.get("status") == "approved":
                    pairings['servers'][handshake['server_id']] = {
                        "secret": secret.hex(),
                        "paired": time.strftime('%Y-%m-%dT%H:%M:%S%z'),
                        "ip": ip,
                    }
                    save_pairings(pairings)
                    print(f"Paired with server {handshake['server_id']}", file=sys.stderr)
                    return True
                print("Could not verify the server's approval; pairing not saved", file=sys.stderr)
                return False
            print("Pairing rejected on the server", file=sys.stderr)
            return False
    except socket.timeout:
        print(f"Timed out talking to {ip}:{port}", file=sys.stderr)
        return False
    except ConnectionRefusedError:
        print(f"Connection refused by {ip}:{port}. Is NetPaste.ps1 running?", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Pairing failed: {e}", file=sys.stderr)
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
            print("Could not determine Windows IP. Please specify with -i/--ip", file=sys.stderr)
            return False

    try:
        print(f"Connecting to {ip}:{port}...", file=sys.stderr)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(10)  # 10 second timeout
            sock.connect((ip, port))

            # Always use Diffie-Hellman key exchange if available
            if ENCRYPTION_AVAILABLE:
                print("Using Diffie-Hellman key exchange...", file=sys.stderr)
                print(f"Original data to encrypt: '{data[:100]}{'...' if len(data) > 100 else ''}'", file=sys.stderr)
                try:
                    key = open_session(sock)

                    # Now send the actual data
                    encrypted_data = encrypt_data(data, key)
                    print(f"Encrypted payload: '{encrypted_data[:100]}{'...' if len(encrypted_data) > 100 else ''}'", file=sys.stderr)
                    data = encrypted_data
                    print("Data encrypted with session key", file=sys.stderr)
                except Exception as e:
                    print(f"Secure session failed: {e}", file=sys.stderr)
                    return False
            else:
                print("Warning: cryptography library not available", file=sys.stderr)
                print("Install with: pip install cryptography", file=sys.stderr)
                return False

            # Send the data
            print(f"Sending payload: '{data[:100]}{'...' if len(data) > 100 else ''}'", file=sys.stderr)
            sock.sendall(data.encode('utf-8'))

            # Give the server a moment to process
            time.sleep(0.5)

        print(f"Data sent successfully to {ip}:{port}", file=sys.stderr)
        return True

    except socket.timeout:
        print(f"Connection to {ip}:{port} timed out", file=sys.stderr)
        return False
    except ConnectionRefusedError:
        print(f"Connection refused by {ip}:{port}. Is NetPaste.ps1 running?", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Error sending data: {e}", file=sys.stderr)
        return False

def send_to_netpaste_with_response(data, ip=None, port=DEFAULT_PORT, timeout=60):
    """Send data to NetPaste.ps1 and wait for a response"""
    if ip is None:
        ip = get_windows_ip()
        if ip is None:
            print("Could not determine Windows IP. Please specify with -i/--ip", file=sys.stderr)
            return None

    try:
        log(f"Connecting to {ip}:{port}...")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)  # Longer timeout for user interaction
        sock.connect((ip, port))

        # Always use Diffie-Hellman key exchange if available
        if not ENCRYPTION_AVAILABLE:
            print("Error: cryptography library not available", file=sys.stderr)
            print("Install with: pip install cryptography", file=sys.stderr)
            sock.close()
            return None

        log("Using Diffie-Hellman key exchange...")
        try:
            key = open_session(sock)

            # Now send the actual data
            encrypted_data = encrypt_data(data, key)
            log(f"Encrypted payload: '{encrypted_data[:100]}{'...' if len(encrypted_data) > 100 else ''}'")
            log("Data encrypted with session key")
        except Exception as e:
            print(f"Secure session failed: {e}", file=sys.stderr)
            sock.close()
            return None

        # Send the data
        log(f"Sending payload: '{encrypted_data[:100]}{'...' if len(encrypted_data) > 100 else ''}'")
        sock.sendall(encrypted_data.encode('utf-8') + b'\n')

        # Wait for response from server
        log("Waiting for response from server...")
        response_data = b''
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
                # Check if we have a complete response (ends with newline)
                if b'\n' in response_data:
                    break
            except socket.timeout:
                break

        sock.close()

        if not response_data:
            print("No response received from server", file=sys.stderr)
            return None

        # Decrypt the response
        response_str = response_data.decode('utf-8').strip()
        if response_str.startswith("NETPASTE_ENCRYPTED:"):
            decrypted_response = decrypt_data(response_str, key)
            response_json = json.loads(decrypted_response)
            log(f"Received response: {response_json.get('type', 'unknown')}")
            return response_json
        else:
            print("Invalid response format from server", file=sys.stderr)
            return None

    except socket.timeout:
        print(f"Connection to {ip}:{port} timed out", file=sys.stderr)
        return None
    except ConnectionRefusedError:
        print(f"Connection refused by {ip}:{port}. Is NetPaste.ps1 running?", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Error communicating with server: {e}", file=sys.stderr)
        return None

def running_in_wsl():
    """True when this client runs inside WSL on the Windows machine itself"""
    if os.environ.get('WSL_DISTRO_NAME'):
        return True
    try:
        with open('/proc/sys/kernel/osrelease') as f:
            return 'microsoft' in f.read().lower()
    except OSError:
        return False

def path_message(msg_type, path):
    """Build a path-carrying message (explorer / open_file / vscode).

    Normally the path is sent as a Unix path, and the server maps it onto the
    SSHFS drive that mounts this box. Inside WSL there is no SSHFS mount: the
    files are local to Windows, so convert with `wslpath -w` (giving C:\\...
    for /mnt/c paths, \\\\wsl.localhost\\<distro>\\... otherwise) and mark
    the path as already Windows-style. NETPASTE_PATH_MODE=unix forces the SSHFS
    behaviour, e.g. when a WSL client targets a different Windows machine.
    """
    abs_path = os.path.abspath(os.path.expanduser(path)) if path else os.getcwd()
    mode = os.environ.get('NETPASTE_PATH_MODE', 'auto').lower()
    if mode != 'unix' and (mode == 'wsl' or running_in_wsl()):
        try:
            result = subprocess.run(['wslpath', '-w', abs_path],
                                    capture_output=True, text=True, check=True)
            win_path = result.stdout.strip()
            if win_path:
                return json.dumps({"type": msg_type, "path": win_path, "path_style": "windows"})
        except (OSError, subprocess.CalledProcessError) as e:
            log(f"wslpath failed for {abs_path}, sending Unix path: {e}")
    return json.dumps({"type": msg_type, "path": abs_path})

def paste_text(text, ip=None, port=DEFAULT_PORT):
    """Send text to be pasted to clipboard"""
    paste_message = json.dumps({"type": "paste", "text": text})
    return send_to_netpaste(paste_message, ip, port)

def open_explorer(path, ip=None, port=DEFAULT_PORT):
    """Send file explorer request"""
    # Resolve to absolute path
    explorer_message = path_message("explorer", path)
    print(f"Sending explorer message: {explorer_message}", file=sys.stderr)
    return send_to_netpaste(explorer_message, ip, port)

def open_file(path, ip=None, port=DEFAULT_PORT):
    """Send file open request"""
    # Resolve to absolute path
    file_message = path_message("open_file", path)
    print(f"Sending file open message: {file_message}", file=sys.stderr)
    return send_to_netpaste(file_message, ip, port)

def open_url(url, ip=None, port=DEFAULT_PORT):
    """Send URL open request"""
    url_message = json.dumps({"type": "open_url", "url": url})
    print(f"Sending URL open message: {url_message}", file=sys.stderr)
    return send_to_netpaste(url_message, ip, port)

def send_notification(message, ip=None, port=DEFAULT_PORT):
    """Send notification request"""
    notify_message = json.dumps({"type": "notification", "message": message})
    print(f"Sending notification: {message}", file=sys.stderr)
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
    vscode_message = path_message("vscode", path)
    print(f"Sending VS Code open request: {vscode_message}", file=sys.stderr)
    return send_to_netpaste(vscode_message, ip, port)

def restart_netpaste(ip=None, port=DEFAULT_PORT):
    """Send restart request to NetPaste"""
    restart_message = json.dumps({"type": "restart"})
    print("Sending restart request...", file=sys.stderr)
    return send_to_netpaste(restart_message, ip, port)

def get_text_from_server(prompt="Enter text:", ip=None, port=DEFAULT_PORT):
    """Request text input from server and return the text"""
    get_text_message = json.dumps({
        "type": "get_text",
        "prompt": prompt
    })
    log(f"Requesting text input from server: {prompt}")
    response = send_to_netpaste_with_response(get_text_message, ip, port)

    if response and response.get("type") == "text_response":
        if response.get("status") == "success":
            return response.get("text", "")
        elif response.get("status") == "cancelled":
            log("User cancelled text input")
            return None
        else:
            print(f"Error: {response.get('message', 'Unknown error')}", file=sys.stderr)
            return None
    else:
        print("Invalid or no response from server", file=sys.stderr)
        return None

def get_file_from_server(destination_dir=".", ip=None, port=DEFAULT_PORT):
    """Request file from server via file selector and save to destination directory"""
    get_file_message = json.dumps({
        "type": "get_file",
        "destination": os.path.abspath(destination_dir)
    })
    log(f"Requesting file from server to save in: {destination_dir}")
    response = send_to_netpaste_with_response(get_file_message, ip, port, timeout=120)

    if response and response.get("type") == "file_response":
        if response.get("status") == "success":
            filename = response.get("filename")
            content_b64 = response.get("content")

            if not filename or not content_b64:
                print("Error: Invalid file response from server", file=sys.stderr)
                return None

            try:
                # Decode base64 content
                file_content = base64.b64decode(content_b64)

                # Save to destination
                dest_path = os.path.join(destination_dir, filename)
                with open(dest_path, 'wb') as f:
                    f.write(file_content)

                log(f"File saved successfully: {dest_path}")
                return dest_path
            except Exception as e:
                print(f"Error saving file: {e}", file=sys.stderr)
                return None
        elif response.get("status") == "cancelled":
            log("User cancelled file selection")
            return None
        else:
            print(f"Error: {response.get('message', 'Unknown error')}", file=sys.stderr)
            return None
    else:
        print("Invalid or no response from server", file=sys.stderr)
        return None

def paste_from_stdin(ip=None, port=DEFAULT_PORT):
    """Read from stdin and paste"""
    try:
        data = sys.stdin.read()
        if not data.strip():
            print("No data received from stdin", file=sys.stderr)
            return False
        return paste_text(data, ip, port)
    except KeyboardInterrupt:
        print("\nOperation cancelled")
        return False

def run_mcp_server():
    """Run netpaste as an MCP server"""
    try:
        from mcp.server.mcpserver import MCPServer
    except ImportError as e:
        print(f"MCP server support requires 'mcp>=2' package: {e}", file=sys.stderr)
        print("Install with: pip install 'mcp[cli]>=2'", file=sys.stderr)
        exit(1)
    
    # Create MCPServer instance
    mcp = MCPServer(
        "NetPaste",
        instructions=(
            "NetPaste MCP Server - Send data to Windows clipboard and control Windows applications from Linux/WSL. "
            "The user may refer to tools by their shell alias names:\n"
            "  np / npf       -> send_to_clipboard / send_file_to_clipboard\n"
            "  npd            -> open_explorer\n"
            "  npo            -> open_file_with_default\n"
            "  npcode         -> open_in_vscode\n"
            "  npurl          -> open_url_in_browser\n"
            "  npnotify       -> send_notification\n"
            "  npls           -> send_ls_output\n"
            "  npgit          -> send_git_output\n"
            "  nppath         -> send_current_path\n"
            "  npt            -> send_tmux_buffer_to_clipboard\n"
            "  nptget         -> get_tmux_buffer_contents\n"
            "  npr            -> restart_netpaste_server\n"
            "  npget          -> get_text_input_from_server\n"
            "  npgetfile      -> get_file_from_server_to_current_dir\n"
            "When the user says something like 'npd this directory' or 'np that output', "
            "use the corresponding MCP tool."
        )
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
        
        explorer_message = path_message("explorer", resolved_path)
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
        file_message = path_message("open_file", abs_path)
        
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

    @mcp.tool()
    def get_text_input_from_server(prompt: str = "Enter text:") -> str:
        """Show a text input dialog on the server and return the entered text"""
        target_ip = default_ip
        if not target_ip:
            return "Error: Could not determine Windows IP. Set NETPASTE_IP environment variable."

        text = get_text_from_server(prompt, target_ip, default_port)
        if text is None:
            return "Text input cancelled by user"
        if text == "":
            return "(empty text returned)"
        return text

    @mcp.tool()
    def get_file_from_server_to_current_dir(destination_dir: str = ".") -> str:
        """Show a file selector dialog on the server and transfer selected file to specified directory"""
        target_ip = default_ip
        if not target_ip:
            return "Error: Could not determine Windows IP. Set NETPASTE_IP environment variable."

        # Resolve destination directory
        dest_path = os.path.abspath(destination_dir)
        if not os.path.exists(dest_path):
            return f"Error: Destination directory '{dest_path}' does not exist"
        if not os.path.isdir(dest_path):
            return f"Error: '{dest_path}' is not a directory"

        result_path = get_file_from_server(dest_path, target_ip, default_port)
        if result_path is None:
            return "File selection cancelled by user or failed"
        return f"File saved to: {result_path}"

    # Run the MCP server
    # stdout carries the stdio JSON-RPC stream, so status output goes to stderr
    print(f"Starting NetPaste MCP Server...", file=sys.stderr)
    if default_ip:
        print(f"Default Windows IP: {default_ip}", file=sys.stderr)
    else:
        print("Warning: Could not auto-detect Windows IP", file=sys.stderr)
        print("Set NETPASTE_IP environment variable", file=sys.stderr)
    
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
                             help='Clear all stored server pairings')
    action_group.add_argument('--pair', action='store_true',
                             help='Pair with the server (confirm the code shown on both ends; needs a terminal)')
    action_group.add_argument('--tmux-buffer', action='store_true',
                             help='Output tmux buffer contents to stdout (for piping or inspection)')
    action_group.add_argument('--tmux-send', action='store_true',
                             help='Send tmux buffer contents to clipboard')
    action_group.add_argument('--get-text', nargs='?', const='Enter text:', metavar='PROMPT',
                             help='Show text input dialog on server and output entered text to stdout')
    action_group.add_argument('--get-file', nargs='?', const='.', metavar='DIR',
                             help='Show file selector on server and save selected file to directory (default: current directory)')

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

    if args.pair:
        sys.exit(0 if pair_with_server(args.ip, args.port) else 1)

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

    # Handle get-text action
    if args.get_text is not None:
        prompt = args.get_text
        text = get_text_from_server(prompt, args.ip, args.port)
        if text is not None:
            print(text, end='')  # Output to stdout without extra newline
            sys.exit(0)
        else:
            sys.exit(1)

    # Handle get-file action
    if args.get_file is not None:
        dest_dir = args.get_file
        result_path = get_file_from_server(dest_dir, args.ip, args.port)
        if result_path:
            print(result_path)  # Output saved file path
            sys.exit(0)
        else:
            sys.exit(1)

    # If no action specified and stdin is available, default to stdin
    if not args.text and not args.explorer and not args.open and not args.url and not args.notify and not args.vscode and not args.restart and not args.stdin and not args.tmux_send and args.get_text is None and args.get_file is None:
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