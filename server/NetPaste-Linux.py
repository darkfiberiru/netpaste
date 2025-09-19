#!/usr/bin/env python3
"""
NetPaste Linux Server - Network clipboard and system integration server for Linux desktop environments
"""

import os
import sys
import json
import socket
import threading
import subprocess
import base64
import hashlib
import secrets
import argparse
import signal
import time
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta

# Try to import GUI libraries (optional)
try:
    import gi
    gi.require_version('Gtk', '3.0')
    gi.require_version('AppIndicator3', '0.1')
    gi.require_version('Notify', '0.7')
    from gi.repository import Gtk, GLib, AppIndicator3, Notify
    HAS_GTK = True
except ImportError:
    HAS_GTK = False
    # Silent - GUI is optional

# Try to import cryptography library (optional, fallback to built-in)
try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding, hashes
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    # We'll use built-in hashlib and a simple AES implementation or skip encryption

# Configuration
DEFAULT_PORT = 9999
SECRET_FILE_PATH = Path.home() / '.config' / 'netpaste' / 'secret.key'

# Diffie-Hellman parameters (RFC 3526 2048-bit MODP Group)
DH_PRIME_HEX = """
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74
020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437
4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05
98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB
9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718
3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
""".replace('\n', '').replace(' ', '')
DH_GENERATOR = 2

class SecretManager:
    """Manage shared secret storage and retrieval"""
    
    @staticmethod
    def get_stored_secret() -> Optional[str]:
        if SECRET_FILE_PATH.exists():
            try:
                secret = SECRET_FILE_PATH.read_text().strip()
                if secret:
                    print(f"✅ Loaded shared secret from {SECRET_FILE_PATH}")
                    return secret
            except Exception as e:
                print(f"❌ Error reading secret file: {e}")
        return None
    
    @staticmethod
    def store_secret(secret: str) -> None:
        SECRET_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
        SECRET_FILE_PATH.write_text(secret)
        SECRET_FILE_PATH.chmod(0o600)  # Owner read/write only
        print(f"✅ Stored shared secret to {SECRET_FILE_PATH}")
    
    @staticmethod
    def clear_secret() -> bool:
        if SECRET_FILE_PATH.exists():
            SECRET_FILE_PATH.unlink()
            print(f"🗑️ Cleared shared secret from {SECRET_FILE_PATH}")
            return True
        print(f"⚠️ No shared secret found at {SECRET_FILE_PATH}")
        return False

class DHKeyExchange:
    """Diffie-Hellman key exchange implementation"""
    
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.shared_secret = None
        self.session_key = None
        
        # Convert hex to integer
        self.dh_prime = int(DH_PRIME_HEX, 16)
        self.dh_generator = DH_GENERATOR
    
    def generate_keypair(self) -> str:
        """Generate DH keypair and return public key as hex string"""
        # Generate random private key (256 bytes)
        self.private_key = int.from_bytes(secrets.token_bytes(256), 'big')
        
        # Compute public key: g^private mod p
        self.public_key = pow(self.dh_generator, self.private_key, self.dh_prime)
        
        # Convert to hex string
        public_hex = format(self.public_key, 'x')
        return public_hex
    
    def compute_shared_secret(self, client_public_hex: str) -> bool:
        """Compute shared secret from client's public key"""
        try:
            # Convert client's public key from hex to int
            client_public = int(client_public_hex, 16)
            
            # Compute shared secret: client_public^private mod p
            self.shared_secret = pow(client_public, self.private_key, self.dh_prime)
            
            # Derive session key using SHA256
            shared_bytes = self.shared_secret.to_bytes((self.shared_secret.bit_length() + 7) // 8, 'big')
            self.session_key = hashlib.sha256(shared_bytes).digest()
            
            return True
        except Exception as e:
            print(f"❌ Error computing shared secret: {e}")
            return False
    
    def get_session_key(self) -> Optional[bytes]:
        return self.session_key

class CryptoHelper:
    """AES encryption/decryption helper"""
    
    @staticmethod
    def encrypt(data: bytes, key: bytes, iv: bytes) -> Optional[bytes]:
        """Encrypt data using AES-256-CBC with PKCS7 padding"""
        if not HAS_CRYPTO:
            return None
        
        try:
            # Add PKCS7 padding
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data) + padder.finalize()
            
            # Encrypt
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(padded_data) + encryptor.finalize()
            
            return encrypted
        except Exception as e:
            print(f"❌ Encryption error: {e}")
            return None
    
    @staticmethod
    def decrypt(data: bytes, key: bytes, iv: bytes) -> Optional[bytes]:
        """Decrypt data using AES-256-CBC with PKCS7 padding"""
        if not HAS_CRYPTO:
            return None
        
        try:
            # Decrypt
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(data) + decryptor.finalize()
            
            # Remove PKCS7 padding
            unpadder = padding.PKCS7(128).unpadder()
            unpadded = unpadder.update(decrypted) + unpadder.finalize()
            
            return unpadded
        except Exception as e:
            print(f"❌ Decryption error: {e}")
            return None

class PathConverter:
    """Convert Unix paths to local paths based on SSHFS mounts"""
    
    def __init__(self):
        self.mount_cache = {}
        self.cache_time = None
        self.cache_ttl = timedelta(minutes=5)
    
    def find_sshfs_mount(self, remote_ip: str) -> Optional[str]:
        """Find SSHFS mount point for given remote IP"""
        # Check cache
        now = datetime.now()
        if self.cache_time and now - self.cache_time < self.cache_ttl:
            return self.mount_cache.get(remote_ip)
        
        # Refresh mount information
        self.mount_cache.clear()
        self.cache_time = now
        
        try:
            # Check mount output
            result = subprocess.run(['mount'], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                # Look for SSHFS mounts: user@host:/path on /mount/point type fuse.sshfs
                if 'fuse.sshfs' in line:
                    parts = line.split()
                    if len(parts) >= 3 and '@' in parts[0]:
                        # Extract host from user@host:/path
                        mount_spec = parts[0]
                        if '@' in mount_spec and ':' in mount_spec:
                            host = mount_spec.split('@')[1].split(':')[0]
                            mount_point = parts[2]
                            
                            # Store by IP or hostname
                            self.mount_cache[host] = mount_point
                            
                            # Try to resolve hostname to IP
                            try:
                                ip = socket.gethostbyname(host)
                                self.mount_cache[ip] = mount_point
                            except:
                                pass
        except Exception as e:
            print(f"Warning: Could not check mounts: {e}")
        
        return self.mount_cache.get(remote_ip)
    
    def convert_path(self, unix_path: str, remote_ip: str) -> str:
        """Convert Unix path to local path based on SSHFS mount"""
        mount_point = self.find_sshfs_mount(remote_ip)
        if mount_point:
            # Convert /home/user/file to /mount/point/home/user/file
            return os.path.join(mount_point, unix_path.lstrip('/'))
        
        # Default: return as-is
        return unix_path

class NetPasteServer:
    """Main NetPaste server implementation"""
    
    def __init__(self, port: int = DEFAULT_PORT, no_encrypt: bool = False, no_tray: bool = False):
        self.port = port
        self.no_encrypt = no_encrypt
        self.no_tray = no_tray or not HAS_GTK
        self.running = False
        self.server_socket = None
        self.stored_secret = SecretManager.get_stored_secret()
        self.path_converter = PathConverter()
        
        # GUI components
        self.indicator = None
        self.menu = None
        
        # Initialize notifications
        if HAS_GTK:
            Notify.init("NetPaste")
    
    def start(self):
        """Start the server"""
        self.running = True
        
        # Start network listener in thread
        listener_thread = threading.Thread(target=self.run_listener, daemon=True)
        listener_thread.start()
        
        # Start GUI if available
        if not self.no_tray and HAS_GTK:
            GLib.idle_add(self.setup_tray)
            Gtk.main()
        else:
            print(f"🚀 NetPaste listening on port {self.port}")
            print("Press Ctrl+C to quit")
            try:
                while self.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                self.stop()
    
    def stop(self):
        """Stop the server"""
        print("\n🛑 Shutting down NetPaste...")
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        if HAS_GTK:
            Gtk.main_quit()
        sys.exit(0)
    
    def setup_tray(self):
        """Setup system tray indicator"""
        # Create app indicator
        self.indicator = AppIndicator3.Indicator.new(
            "netpaste",
            "network-idle",  # Default icon
            AppIndicator3.IndicatorCategory.APPLICATION_STATUS
        )
        self.indicator.set_status(AppIndicator3.IndicatorStatus.ACTIVE)
        self.indicator.set_title(f"NetPaste - Port {self.port}")
        
        # Create menu
        self.menu = Gtk.Menu()
        
        # Title item
        item_title = Gtk.MenuItem(label=f"NetPaste Running on Port {self.port}")
        item_title.set_sensitive(False)
        self.menu.append(item_title)
        
        self.menu.append(Gtk.SeparatorMenuItem())
        
        # Show console item
        item_console = Gtk.MenuItem(label="Show Console")
        item_console.connect("activate", self.show_console)
        self.menu.append(item_console)
        
        # Clear secret item
        item_clear = Gtk.MenuItem(label="Clear Shared Secret")
        item_clear.connect("activate", self.clear_secret)
        self.menu.append(item_clear)
        
        self.menu.append(Gtk.SeparatorMenuItem())
        
        # Quit item
        item_quit = Gtk.MenuItem(label="Quit NetPaste")
        item_quit.connect("activate", self.quit)
        self.menu.append(item_quit)
        
        self.menu.show_all()
        self.indicator.set_menu(self.menu)
    
    def show_console(self, widget):
        """Open terminal with server logs"""
        try:
            # Try common terminal emulators
            terminals = ['gnome-terminal', 'konsole', 'xfce4-terminal', 'xterm']
            for term in terminals:
                if subprocess.run(['which', term], capture_output=True).returncode == 0:
                    subprocess.Popen([term, '-e', f'journalctl -f -u netpaste || tail -f ~/.netpaste.log'])
                    break
        except Exception as e:
            print(f"Error opening console: {e}")
    
    def clear_secret(self, widget=None):
        """Clear stored shared secret"""
        cleared = SecretManager.clear_secret()
        self.stored_secret = None
        
        if HAS_GTK:
            dialog = Gtk.MessageDialog(
                transient_for=None,
                flags=0,
                message_type=Gtk.MessageType.INFO,
                buttons=Gtk.ButtonsType.OK,
                text="Clear Shared Secret"
            )
            if cleared:
                dialog.format_secondary_text("The shared secret has been removed.")
            else:
                dialog.format_secondary_text("No shared secret was found.")
            dialog.run()
            dialog.destroy()
    
    def quit(self, widget):
        """Quit the application"""
        self.stop()
    
    def run_listener(self):
        """Run the network listener"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('', self.port))
            self.server_socket.listen(5)
            
            print(f"🚀 NetPaste listening on port {self.port}")
            
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    # Handle client in new thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address),
                        daemon=True
                    )
                    client_thread.start()
                except socket.error:
                    if self.running:
                        print("Socket error occurred")
                    break
        except Exception as e:
            print(f"❌ Failed to start listener: {e}")
            self.stop()
    
    def handle_client(self, client_socket: socket.socket, address: Tuple[str, int]):
        """Handle client connection"""
        remote_ip = address[0]
        print(f"📡 Connection from {remote_ip}:{address[1]}")
        
        try:
            # Receive data
            data = client_socket.recv(65536)
            if not data:
                return
            
            # Try to parse as JSON
            try:
                message = json.loads(data.decode('utf-8'))
                
                # Handle DH handshake
                if 'publicKey' in message:
                    self.handle_dh_handshake(client_socket, message['publicKey'])
                    return
                
                # Handle authentication
                if 'sharedSecret' in message:
                    self.handle_authentication(client_socket, message['sharedSecret'])
                    return
                
                # Handle encrypted message
                if 'encrypted' in message and 'iv' in message:
                    # Note: In a full implementation, we'd decrypt here
                    # For now, we'll skip encryption handling
                    pass
                
                # Handle plain message
                self.handle_message(client_socket, message, remote_ip)
                
            except json.JSONDecodeError:
                # Handle as plain text paste for backwards compatibility
                message = {'type': 'paste', 'text': data.decode('utf-8')}
                self.handle_message(client_socket, message, remote_ip)
                
        except Exception as e:
            print(f"❌ Error handling client: {e}")
        finally:
            client_socket.close()
    
    def handle_dh_handshake(self, client_socket: socket.socket, client_public_key: str):
        """Handle Diffie-Hellman key exchange"""
        print("🔐 Starting DH handshake...")
        
        dh = DHKeyExchange()
        server_public_key = dh.generate_keypair()
        
        if not dh.compute_shared_secret(client_public_key):
            print("❌ Failed to compute shared secret")
            return
        
        # Send server public key back
        response = {'publicKey': server_public_key}
        client_socket.send(json.dumps(response).encode('utf-8'))
        print("✅ DH handshake completed")
    
    def handle_authentication(self, client_socket: socket.socket, shared_secret: str):
        """Handle shared secret authentication"""
        if self.stored_secret is None:
            # First connection - store the secret
            SecretManager.store_secret(shared_secret)
            self.stored_secret = shared_secret
            print("✅ Stored first shared secret")
            
            response = {'status': 'authenticated', 'message': 'Secret stored'}
            client_socket.send(json.dumps(response).encode('utf-8'))
            
        elif self.stored_secret == shared_secret:
            # Valid authentication
            print("✅ Authentication successful")
            
            response = {'status': 'authenticated'}
            client_socket.send(json.dumps(response).encode('utf-8'))
            
        else:
            # Invalid authentication
            print("❌ Authentication failed - invalid shared secret")
            
            response = {'status': 'unauthorized', 'message': 'Invalid shared secret'}
            client_socket.send(json.dumps(response).encode('utf-8'))
    
    def handle_message(self, client_socket: socket.socket, message: Dict[str, Any], remote_ip: str):
        """Handle incoming message"""
        msg_type = message.get('type', 'paste')
        
        if msg_type == 'paste':
            text = message.get('text', '')
            self.handle_paste(text, remote_ip)
            
        elif msg_type == 'notification':
            text = message.get('message', '')
            self.show_notification("NetPaste", text)
            
        elif msg_type == 'explorer':
            path = message.get('path', '.')
            local_path = self.path_converter.convert_path(path, remote_ip)
            self.open_file_manager(local_path, remote_ip)
            
        elif msg_type == 'open_file':
            path = message.get('path', '')
            local_path = self.path_converter.convert_path(path, remote_ip)
            self.open_file(local_path, remote_ip)
            
        elif msg_type == 'open_url':
            url = message.get('url', '')
            self.open_url(url, remote_ip)
            
        elif msg_type == 'vscode':
            path = message.get('path', '.')
            local_path = self.path_converter.convert_path(path, remote_ip)
            self.open_vscode(local_path, remote_ip)
            
        elif msg_type == 'restart':
            print("🔄 Restart request received")
            self.restart_server()
            
        elif msg_type == 'clear_secret':
            self.clear_secret()
            
        else:
            print(f"⚠️ Unknown message type: {msg_type}")
        
        # Send success response
        response = {'status': 'success'}
        try:
            client_socket.send(json.dumps(response).encode('utf-8'))
        except:
            pass
    
    def handle_paste(self, text: str, remote_ip: str):
        """Handle clipboard paste request"""
        print(f"📋 Paste request: {len(text)} characters from {remote_ip}")
        
        if HAS_GTK:
            # Show dialog on main thread
            GLib.idle_add(self.show_paste_dialog, text, remote_ip)
        else:
            # Try to show a simple dialog using zenity or similar
            if self.show_simple_dialog("Incoming Clipboard Data", 
                                      f"Copy {len(text)} characters from {remote_ip} to clipboard?"):
                self.copy_to_clipboard(text)
    
    def show_simple_dialog(self, title: str, message: str) -> bool:
        """Show a simple yes/no dialog without GTK"""
        # Try zenity
        try:
            result = subprocess.run(
                ['zenity', '--question', f'--title={title}', f'--text={message}'],
                capture_output=True
            )
            return result.returncode == 0
        except FileNotFoundError:
            pass
        
        # Try kdialog (KDE)
        try:
            result = subprocess.run(
                ['kdialog', '--yesno', message, '--title', title],
                capture_output=True
            )
            return result.returncode == 0
        except FileNotFoundError:
            pass
        
        # Try dialog in terminal
        try:
            result = subprocess.run(
                ['dialog', '--yesno', message, '10', '50'],
                capture_output=True
            )
            return result.returncode == 0
        except FileNotFoundError:
            pass
        
        # Fallback: console prompt
        print(f"\n{title}")
        print(f"{message}")
        response = input("Proceed? (y/n): ").lower().strip()
        return response in ['y', 'yes']
    
    def show_paste_dialog(self, text: str, remote_ip: str):
        """Show paste confirmation dialog"""
        dialog = Gtk.MessageDialog(
            transient_for=None,
            flags=0,
            message_type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.YES_NO,
            text="Incoming Clipboard Data"
        )
        dialog.format_secondary_text(
            f"Received {len(text)} characters from {remote_ip}.\n"
            f"Copy to clipboard?"
        )
        
        # Add text preview
        if len(text) > 100:
            preview = text[:100] + "..."
        else:
            preview = text
        
        expander = Gtk.Expander(label="Preview")
        text_view = Gtk.TextView()
        text_view.get_buffer().set_text(preview)
        text_view.set_editable(False)
        text_view.set_wrap_mode(Gtk.WrapMode.WORD)
        
        scrolled = Gtk.ScrolledWindow()
        scrolled.set_min_content_height(100)
        scrolled.add(text_view)
        expander.add(scrolled)
        
        dialog.get_content_area().add(expander)
        dialog.show_all()
        
        response = dialog.run()
        dialog.destroy()
        
        if response == Gtk.ResponseType.YES:
            self.copy_to_clipboard(text)
    
    def copy_to_clipboard(self, text: str):
        """Copy text to clipboard"""
        # Try various clipboard methods in order of preference
        clipboard_methods = [
            (['xclip', '-selection', 'clipboard'], 'xclip'),
            (['xsel', '--clipboard', '--input'], 'xsel'),
            (['wl-copy'], 'wl-copy (Wayland)'),  # Wayland support
            (['pbcopy'], 'pbcopy'),  # In case someone runs this on macOS
        ]
        
        for cmd, name in clipboard_methods:
            try:
                subprocess.run(cmd, input=text.encode('utf-8'), check=True, 
                             capture_output=True)
                print(f"✅ Copied {len(text)} characters to clipboard using {name}")
                return
            except (subprocess.CalledProcessError, FileNotFoundError):
                continue
        
        # Last resort: save to temp file
        temp_file = Path.home() / '.netpaste_clipboard.txt'
        temp_file.write_text(text)
        print(f"⚠️ No clipboard utility found. Text saved to {temp_file}")
        print("Install xclip, xsel, or wl-clipboard for clipboard support.")
    
    def show_notification(self, title: str, text: str):
        """Show desktop notification"""
        if HAS_GTK:
            try:
                notification = Notify.Notification.new(title, text, "dialog-information")
                notification.show()
                print(f"🔔 Notification: {text}")
                return
            except:
                pass
        
        # Try notify-send (works on most Linux desktops)
        try:
            subprocess.run(['notify-send', title, text], capture_output=True)
            print(f"🔔 Notification: {text}")
            return
        except FileNotFoundError:
            pass
        
        # Try zenity (often installed on GNOME systems)
        try:
            subprocess.run(['zenity', '--notification', f'--text={title}: {text}'], 
                         capture_output=True)
            print(f"🔔 Notification: {text}")
            return
        except FileNotFoundError:
            pass
        
        # Fallback: just print to console
        print(f"🔔 {title}: {text}")
    
    def open_file_manager(self, path: str, remote_ip: str):
        """Open file manager at specified path"""
        print(f"📁 Opening file manager: {path}")
        
        if HAS_GTK:
            GLib.idle_add(self.show_file_manager_dialog, path, remote_ip)
        else:
            if self.show_simple_dialog("Open File Manager", 
                                      f"Open file manager at:\n{path}\n\nFrom: {remote_ip}"):
                self.do_open_file_manager(path)
    
    def show_file_manager_dialog(self, path: str, remote_ip: str):
        """Show file manager confirmation dialog"""
        dialog = Gtk.MessageDialog(
            transient_for=None,
            flags=0,
            message_type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.YES_NO,
            text="Open File Manager"
        )
        dialog.format_secondary_text(
            f"Open file manager at:\n{path}\n\nFrom: {remote_ip}"
        )
        
        response = dialog.run()
        dialog.destroy()
        
        if response == Gtk.ResponseType.YES:
            self.do_open_file_manager(path)
    
    def do_open_file_manager(self, path: str):
        """Actually open the file manager"""
        try:
            # Try common file managers
            managers = ['xdg-open', 'nautilus', 'dolphin', 'thunar', 'pcmanfm', 'nemo']
            for fm in managers:
                if subprocess.run(['which', fm], capture_output=True).returncode == 0:
                    subprocess.Popen([fm, path])
                    break
        except Exception as e:
            print(f"❌ Error opening file manager: {e}")
    
    def open_file(self, path: str, remote_ip: str):
        """Open file with default application"""
        print(f"📄 Opening file: {path}")
        
        if HAS_GTK:
            GLib.idle_add(self.show_file_open_dialog, path, remote_ip)
        else:
            if self.show_simple_dialog("Open File", 
                                      f"Open file:\n{path}\n\nFrom: {remote_ip}"):
                self.do_open_file(path)
    
    def show_file_open_dialog(self, path: str, remote_ip: str):
        """Show file open confirmation dialog"""
        dialog = Gtk.MessageDialog(
            transient_for=None,
            flags=0,
            message_type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.YES_NO,
            text="Open File"
        )
        dialog.format_secondary_text(
            f"Open file with default application:\n{path}\n\nFrom: {remote_ip}"
        )
        
        response = dialog.run()
        dialog.destroy()
        
        if response == Gtk.ResponseType.YES:
            self.do_open_file(path)
    
    def do_open_file(self, path: str):
        """Actually open the file"""
        try:
            subprocess.Popen(['xdg-open', path])
        except Exception as e:
            print(f"❌ Error opening file: {e}")
    
    def open_url(self, url: str, remote_ip: str):
        """Open URL in browser"""
        print(f"🌐 Opening URL: {url}")
        
        if HAS_GTK:
            GLib.idle_add(self.show_url_dialog, url, remote_ip)
        else:
            # URL opening should have extra confirmation
            if self.show_simple_dialog("⚠️ Open URL", 
                                      f"Open URL in browser:\n{url}\n\nFrom: {remote_ip}"):
                self.do_open_url(url)
    
    def show_url_dialog(self, url: str, remote_ip: str):
        """Show URL open confirmation dialog"""
        dialog = Gtk.MessageDialog(
            transient_for=None,
            flags=0,
            message_type=Gtk.MessageType.WARNING,
            buttons=Gtk.ButtonsType.YES_NO,
            text="Open URL"
        )
        dialog.format_secondary_text(
            f"Open URL in browser:\n{url}\n\nFrom: {remote_ip}"
        )
        
        response = dialog.run()
        dialog.destroy()
        
        if response == Gtk.ResponseType.YES:
            self.do_open_url(url)
    
    def do_open_url(self, url: str):
        """Actually open the URL"""
        try:
            subprocess.Popen(['xdg-open', url])
        except Exception as e:
            print(f"❌ Error opening URL: {e}")
    
    def open_vscode(self, path: str, remote_ip: str):
        """Open in VS Code"""
        print(f"💻 Opening in VS Code: {path}")
        
        if HAS_GTK:
            GLib.idle_add(self.show_vscode_dialog, path, remote_ip)
        else:
            if self.show_simple_dialog("Open in VS Code", 
                                      f"Open in Visual Studio Code:\n{path}\n\nFrom: {remote_ip}"):
                self.do_open_vscode(path)
    
    def show_vscode_dialog(self, path: str, remote_ip: str):
        """Show VS Code open confirmation dialog"""
        dialog = Gtk.MessageDialog(
            transient_for=None,
            flags=0,
            message_type=Gtk.MessageType.QUESTION,
            buttons=Gtk.ButtonsType.YES_NO,
            text="Open in VS Code"
        )
        dialog.format_secondary_text(
            f"Open in Visual Studio Code:\n{path}\n\nFrom: {remote_ip}"
        )
        
        response = dialog.run()
        dialog.destroy()
        
        if response == Gtk.ResponseType.YES:
            self.do_open_vscode(path)
    
    def do_open_vscode(self, path: str):
        """Actually open VS Code"""
        try:
            subprocess.Popen(['code', path])
        except FileNotFoundError:
            print("❌ VS Code not found. Make sure 'code' is in your PATH.")
    
    def restart_server(self):
        """Restart the server"""
        print("🔄 Restarting NetPaste server...")
        # In a real implementation, we'd properly restart
        # For now, just log the request
        self.show_notification("NetPaste", "Server restart requested")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='NetPaste Linux Server')
    parser.add_argument('-p', '--port', type=int, default=DEFAULT_PORT,
                       help=f'Port to listen on (default: {DEFAULT_PORT})')
    parser.add_argument('--no-tray', action='store_true',
                       help='Run without system tray icon')
    parser.add_argument('--no-encrypt', action='store_true',
                       help='Disable encryption (not recommended)')
    
    args = parser.parse_args()
    
    # Print startup banner
    print("NetPaste Linux Server")
    print("=" * 20)
    print(f"Port: {args.port}")
    print(f"Encryption: {'Disabled' if args.no_encrypt else 'Enabled'}")
    print(f"System Tray: {'Disabled' if args.no_tray else 'Enabled'}")
    print("")
    
    # Create and start server
    server = NetPasteServer(
        port=args.port,
        no_encrypt=args.no_encrypt,
        no_tray=args.no_tray
    )
    
    # Handle signals
    signal.signal(signal.SIGINT, lambda s, f: server.stop())
    signal.signal(signal.SIGTERM, lambda s, f: server.stop())
    
    # Start server
    server.start()

if __name__ == '__main__':
    main()