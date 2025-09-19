#Requires -Version 5.0

<#
.SYNOPSIS
    NetPaste - Network clipboard and file explorer utility
.DESCRIPTION
    Interactive console application for network clipboard operations and file explorer integration.
    Uses Write-Host for colored console output which is appropriate for this use case.
#>

[CmdletBinding()]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification='Interactive console application requires colored output for user experience')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidGlobalVars', '', Justification='Script-scoped variables used for cross-process communication')]
param(
    [int]$Port = 9999,
    [switch]$Child,
    [string]$Key,
    [switch]$NoTray,
    [switch]$NoEncrypt
)

# Capture start time immediately after param block
$script:StartTime = Get-Date
Write-Host "[$(Get-Date -Format 'HH:mm:ss.fff')] NetPaste starting up..." -ForegroundColor Green

# Shared secret file path (Windows AppData)
$script:SecretFilePath = Join-Path $env:APPDATA "NetPaste\secret.key"

function Get-StoredSecret {
    if (Test-Path $script:SecretFilePath) {
        $secret = Get-Content $script:SecretFilePath -Raw
        if ($secret) {
            Write-Host "Loaded shared secret from $($script:SecretFilePath)" -ForegroundColor Green
            return $secret.Trim()
        }
    }
    return $null
}

function Store-SharedSecret {
    param([string]$Secret)
    
    # Create directory if it doesn't exist
    $secretDir = Split-Path $script:SecretFilePath -Parent
    if (-not (Test-Path $secretDir)) {
        New-Item -ItemType Directory -Path $secretDir -Force | Out-Null
    }
    
    # Store the secret
    $Secret | Out-File -FilePath $script:SecretFilePath -Encoding UTF8 -NoNewline
    
    # Set restrictive permissions (owner only)
    $acl = Get-Acl $script:SecretFilePath
    $acl.SetAccessRuleProtection($true, $false)
    $permission = New-Object System.Security.AccessControl.FileSystemAccessRule(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
        "FullControl",
        "Allow"
    )
    $acl.SetAccessRule($permission)
    Set-Acl $script:SecretFilePath $acl
    
    Write-Host "Stored shared secret to $($script:SecretFilePath)" -ForegroundColor Green
}

function Clear-SharedSecret {
    if (Test-Path $script:SecretFilePath) {
        Remove-Item $script:SecretFilePath -Force
        Write-Host "Cleared shared secret from $($script:SecretFilePath)" -ForegroundColor Yellow
        return $true
    } else {
        Write-Host "No shared secret found at $($script:SecretFilePath)" -ForegroundColor Yellow
        return $false
    }
}

try {
    Add-Type -AssemblyName System.Windows.Forms
} catch {
    # Silently continue - forms may not be available
}

try {
    Add-Type -AssemblyName PresentationFramework  
} catch {
    # Silently continue - WPF may not be available
}

# Add .NET crypto types for AES encryption
Add-Type -AssemblyName System.Security

# Diffie-Hellman parameters (RFC 3526 - 2048-bit MODP Group)
# Use exact decimal value that matches Python's hex conversion
$script:DH_P = [System.Numerics.BigInteger]::Parse("32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235796078236248884246189477587641105928646099411723245426622522193230540919037680524235519125679715870117001058055877651038861847280257976054903569732561526167081339361799541336476559160368317896729073178384589680639671900977202194168647225871031411336429319536193471636533209717077448227988588565369208645296636077250268955505928362751121174096972998068410554359584866583291642136218231078990999448652468262416972035911852507045361090559")
$script:DH_G = [System.Numerics.BigInteger]::new(2)

# Load BigInteger support
Add-Type -AssemblyName System.Numerics

function Get-SHA256Hash {
    param([string]$InputString)
    
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputString)
    $hashBytes = $sha256.ComputeHash($bytes)
    $sha256.Dispose()
    return $hashBytes
}

function Generate-DHKeypair {
    [CmdletBinding()]
    param()
    
    # Generate random private key
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $privateKeyBytes = New-Object byte[] 32
    $rng.GetBytes($privateKeyBytes)
    $rng.Dispose()
    
    # Convert to BigInteger and ensure it's in valid range
    $privateKey = [System.Numerics.BigInteger]::new($privateKeyBytes + @(0))  # Add 0 byte to ensure positive
    $privateKey = $privateKey % ($script:DH_P - 1) + 1
    
    # Compute public key: g^private mod p
    $publicKey = [System.Numerics.BigInteger]::ModPow($script:DH_G, $privateKey, $script:DH_P)
    
    # Verify key generation
    $verify = [System.Numerics.BigInteger]::ModPow($script:DH_G, $privateKey, $script:DH_P)
    Write-Host "DH Debug - Key generation verify: $($script:DH_G)^$($privateKey.ToString().Substring(0, 30))... = $($publicKey.ToString().Substring(0, 30))... (verify: $($verify.ToString().Substring(0, 30))...)" -ForegroundColor Magenta
    
    return @{
        PrivateKey = $privateKey
        PublicKey = $publicKey
    }
}

function Compute-DHSharedSecret {
    [CmdletBinding()]
    param(
        [System.Numerics.BigInteger]$TheirPublicKey,
        [System.Numerics.BigInteger]$MyPrivateKey
    )
    
    # Compute shared secret: their_public^my_private mod p
    Write-Host "DH Debug - Computing: $($TheirPublicKey.ToString().Substring(0, 50))... ^ $($MyPrivateKey.ToString().Substring(0, 50))... mod P" -ForegroundColor Magenta
    Write-Host "DH Debug - DH_P: $($script:DH_P.ToString().Substring(0, 50))..." -ForegroundColor Magenta
    Write-Host "DH Debug - DH_G: $($script:DH_G)" -ForegroundColor Magenta
    
    # Test basic arithmetic
    $testResult = [System.Numerics.BigInteger]::ModPow(2, 3, 7)
    Write-Host "DH Debug - Test 2^3 mod 7 = $testResult (should be 1)" -ForegroundColor Magenta
    
    $sharedSecret = [System.Numerics.BigInteger]::ModPow($TheirPublicKey, $MyPrivateKey, $script:DH_P)
    
    # Debug: show actual shared secret value
    Write-Host "DH Debug - Shared secret decimal: $($sharedSecret.ToString().Substring(0, 50))...$($sharedSecret.ToString().Substring($sharedSecret.ToString().Length - 10))" -ForegroundColor Magenta
    Write-Host "DH Debug - Shared secret vs Prime comparison: secret < P = $($sharedSecret -lt $script:DH_P)" -ForegroundColor Magenta
    Write-Host "DH Debug - Prime length: $($script:DH_P.ToString().Length), Secret length: $($sharedSecret.ToString().Length)" -ForegroundColor Magenta
    
    # To create a big-endian byte array of fixed length (256 bytes) that matches Python's
    # `to_bytes()`, we perform the following steps:
    # 1. Get the little-endian byte array from .NET's ToByteArray(). This is variable length.
    # 2. Create a target 256-byte buffer, initialized to all zeros.
    # 3. Copy the little-endian bytes into the start of the buffer. This pads with zeros at the end.
    # 4. Reverse the entire buffer. This moves the number to the correct (right-aligned) position
    #    and effectively converts from padded little-endian to padded big-endian.
    
    $correctByteLength = 256 # 2048 bits
    $secretBytes = New-Object byte[] $correctByteLength
    
    # Get little-endian bytes from BigInteger
    $secretBytesRaw = $sharedSecret.ToByteArray()
    
    # --- THIS IS THE FIX ---
    # Determine the number of bytes to copy - the smaller of the source length or our fixed buffer size.
    # This handles the edge case where .NET adds an extra byte for signing, preventing a crash.
    $bytesToCopy = [System.Math]::Min($secretBytesRaw.Length, $correctByteLength)
    
    Write-Host "DH Debug - Raw bytes length: $($secretBytesRaw.Length), copying: $bytesToCopy" -ForegroundColor Magenta
    
    # Copy these bytes to the beginning of our fixed-size buffer
    [System.Array]::Copy($secretBytesRaw, 0, $secretBytes, 0, $bytesToCopy)
    
    # Reverse the entire buffer to get the final big-endian representation
    [System.Array]::Reverse($secretBytes)

    Write-Host "DH Debug - Shared secret bytes length: $($secretBytes.Length)" -ForegroundColor Magenta
    
    # Now hash the raw bytes with SHA-256
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $sha256.ComputeHash($secretBytes)
    $sha256.Dispose()
    
    $hashHex = [System.BitConverter]::ToString($hashBytes) -replace '-', ''
    Write-Host "DH Debug - SHA256 hash: $hashHex" -ForegroundColor Magenta
    
    return $hashBytes
}

function Test-DHHandshakeMessage {
    param([string]$Data)
    
    # Check for DH handshake with more flexible matching (updated for string format)
    return ($Data -match '^\s*\{\s*"type"\s*:\s*"dh_handshake"' -or $Data.Contains('"type": "dh_handshake"') -or $Data.Contains('"public_key_str"'))
}

function Handle-DHHandshake {
    [CmdletBinding()]
    param(
        [System.Net.Sockets.NetworkStream]$Stream,
        [string]$HandshakeData
    )
    
    try {
        # Parse client handshake
        $clientMsg = $HandshakeData | ConvertFrom-Json
        
        if ($clientMsg.type -ne "dh_handshake") {
            throw "Invalid handshake message type"
        }
        
        $clientPublicKey = [System.Numerics.BigInteger]::Parse($clientMsg.public_key_str)
        
        # Generate our key pair
        $ourKeys = Generate-DHKeypair
        
        # Send our public key - use string to avoid JSON precision loss
        $response = @{
            type = "dh_response"
            public_key_str = $ourKeys.PublicKey.ToString()
        } | ConvertTo-Json -Compress
        
        Write-Host "DH Debug - Sending full response JSON: $response" -ForegroundColor Magenta
        
        $responseBytes = [System.Text.Encoding]::UTF8.GetBytes($response + "`n")
        $Stream.Write($responseBytes, 0, $responseBytes.Length)
        $Stream.Flush()
        
        # Cross-verification: compute what client should get using our values  
        $clientShouldGet = [System.Numerics.BigInteger]::ModPow($ourKeys.PublicKey, 999, $script:DH_P)
        Write-Host "DH Debug - Cross-verify: our_public^999 = $($clientShouldGet.ToString().Substring(0, 30))..." -ForegroundColor Magenta
        
        # Compute shared secret
        $sharedSecret = Compute-DHSharedSecret -TheirPublicKey $clientPublicKey -MyPrivateKey $ourKeys.PrivateKey
        
        Write-Host "DH Debug - Client public key: $($clientPublicKey.ToString().Substring(0, 50))..." -ForegroundColor Magenta
        Write-Host "DH Debug - Our private key: $($ourKeys.PrivateKey.ToString().Substring(0, 50))..." -ForegroundColor Magenta
        Write-Host "DH Debug - Our public key: $($ourKeys.PublicKey.ToString().Substring(0, 50))..." -ForegroundColor Magenta
        
        return $sharedSecret
    }
    catch {
        Write-Host "DH handshake failed: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Handle-Authentication {
    [CmdletBinding()]
    param(
        [System.Net.Sockets.NetworkStream]$Stream,
        [byte[]]$DHKey
    )
    
    try {
        Write-Host "Waiting for encrypted authentication..." -ForegroundColor Yellow
        
        # Read encrypted authentication message
        $buffer = New-Object byte[] 4096
        $authData = ""
        $consecutiveTimeouts = 0
        
        do {
            try {
                $bytesRead = $Stream.Read($buffer, 0, $buffer.Length)
                if ($bytesRead -gt 0) {
                    $consecutiveTimeouts = 0
                    $authData += [System.Text.Encoding]::UTF8.GetString($buffer, 0, $bytesRead)
                    if ($authData.Contains("`n")) {
                        break
                    }
                } elseif ($bytesRead -eq 0) {
                    break
                }
            }
            catch [System.IO.IOException] {
                $consecutiveTimeouts++
                if ($consecutiveTimeouts -ge 2) {
                    throw "Timeout waiting for authentication"
                }
            }
        } while ($bytesRead -gt 0)
        
        $authData = $authData.Trim()
        
        if (-not (Test-EncryptedMessage -Data $authData)) {
            throw "Authentication message is not encrypted"
        }
        
        # Decrypt the authentication message
        $decryptedAuth = Decrypt-DHData -EncryptedData $authData -KeyBytes $DHKey
        if (-not $decryptedAuth) {
            throw "Failed to decrypt authentication message"
        }
        
        $authMsg = $decryptedAuth | ConvertFrom-Json
        
        if ($authMsg.type -ne "auth") {
            throw "Invalid authentication message type"
        }
        
        $clientSecret = $authMsg.secret
        
        # Get stored secret
        $storedSecret = Get-StoredSecret
        
        $authResponse = $null
        
        if ($storedSecret) {
            # We have a stored secret - validate it
            if ($clientSecret -eq $storedSecret) {
                Write-Host "Authentication successful - shared secret matches" -ForegroundColor Green
                $authResponse = @{
                    type = "auth_response"
                    status = "accepted"
                    message = "Authentication successful"
                }
            } else {
                Write-Host "Authentication failed - shared secret mismatch" -ForegroundColor Red
                $authResponse = @{
                    type = "auth_response"
                    status = "rejected"
                    message = "Invalid shared secret"
                }
            }
        } else {
            # No stored secret - store the one we received
            Store-SharedSecret -Secret $clientSecret
            Write-Host "First connection - stored shared secret for future use" -ForegroundColor Yellow
            $authResponse = @{
                type = "auth_response"
                status = "stored"
                message = "Shared secret stored for future connections"
            }
        }
        
        # Send encrypted response
        $responseJson = $authResponse | ConvertTo-Json -Compress
        $encryptedResponse = Encrypt-DHData -Data $responseJson -KeyBytes $DHKey
        $responseBytes = [System.Text.Encoding]::UTF8.GetBytes($encryptedResponse + "`n")
        $Stream.Write($responseBytes, 0, $responseBytes.Length)
        $Stream.Flush()
        
        return ($authResponse.status -eq "accepted" -or $authResponse.status -eq "stored")
    }
    catch {
        Write-Host "Authentication handling failed: $($_.Exception.Message)" -ForegroundColor Red
        
        # Send error response
        try {
            $errorResponse = @{
                type = "auth_response"
                status = "error"
                message = $_.Exception.Message
            } | ConvertTo-Json -Compress
            $encryptedError = Encrypt-DHData -Data $errorResponse -KeyBytes $DHKey
            $errorBytes = [System.Text.Encoding]::UTF8.GetBytes($encryptedError + "`n")
            $Stream.Write($errorBytes, 0, $errorBytes.Length)
            $Stream.Flush()
        } catch {
            # Ignore errors sending error response
        }
        
        return $false
    }
}

function Encrypt-DHData {
    [CmdletBinding()]
    param(
        [string]$Data,
        [byte[]]$KeyBytes
    )
    
    if (-not $KeyBytes -or $KeyBytes.Length -ne 32) {
        throw "32-byte key is required for DH encryption"
    }
    
    try {
        # Generate random IV
        $iv = New-Object byte[] 16
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $rng.GetBytes($iv)
        $rng.Dispose()
        
        # Create AES encryptor using raw key bytes
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $KeyBytes
        $aes.IV = $iv
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        
        $encryptor = $aes.CreateEncryptor()
        
        # Encrypt
        $dataBytes = [System.Text.Encoding]::UTF8.GetBytes($Data)
        $encryptedBytes = $encryptor.TransformFinalBlock($dataBytes, 0, $dataBytes.Length)
        
        # Combine IV and ciphertext
        $combined = $iv + $encryptedBytes
        $base64 = [System.Convert]::ToBase64String($combined)
        
        # Clean up
        $encryptor.Dispose()
        $aes.Dispose()
        
        return "NETPASTE_ENCRYPTED:$base64"
    }
    catch {
        Write-Host "DH Encrypt error: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Test-EncryptedMessage {
    param([string]$Data)
    
    return $Data.StartsWith("NETPASTE_ENCRYPTED:")
}

function Decrypt-Data {
    [CmdletBinding()]
    param(
        [string]$EncryptedData,
        [string]$Key
    )
    
    if (-not $Key) {
        throw "Decryption key is required"
    }
    
    try {
        # Remove prefix
        if (-not $EncryptedData.StartsWith("NETPASTE_ENCRYPTED:")) {
            throw "Invalid encrypted data format"
        }
        
        $payload = $EncryptedData.Substring(19)  # Remove "NETPASTE_ENCRYPTED:" prefix
        $encryptedBytes = [System.Convert]::FromBase64String($payload)
        
        # Extract IV and ciphertext
        $iv = $encryptedBytes[0..15]
        $ciphertext = $encryptedBytes[16..($encryptedBytes.Length - 1)]
        
        # Derive key from password
        $keyBytes = Get-SHA256Hash -InputString $Key
        
        # Create AES decryptor
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $keyBytes
        $aes.IV = $iv
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        
        $decryptor = $aes.CreateDecryptor()
        
        # Decrypt
        $decryptedBytes = $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
        $plaintext = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
        
        # Clean up
        $decryptor.Dispose()
        $aes.Dispose()
        
        return $plaintext
    }
    catch {
        return $null
    }
}

function Decrypt-DHData {
    [CmdletBinding()]
    param(
        [string]$EncryptedData,
        [byte[]]$KeyBytes
    )
    
    if (-not $KeyBytes -or $KeyBytes.Length -ne 32) {
        throw "32-byte key is required for DH decryption"
    }
    
    try {
        # Remove prefix
        if (-not $EncryptedData.StartsWith("NETPASTE_ENCRYPTED:")) {
            throw "Invalid encrypted data format"
        }
        
        $payload = $EncryptedData.Substring(19)  # Remove "NETPASTE_ENCRYPTED:" prefix
        $encryptedBytes = [System.Convert]::FromBase64String($payload)
        
        # Extract IV and ciphertext
        $iv = $encryptedBytes[0..15]
        $ciphertext = $encryptedBytes[16..($encryptedBytes.Length - 1)]
        
        # Create AES decryptor using raw key bytes
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $KeyBytes
        $aes.IV = $iv
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        
        $decryptor = $aes.CreateDecryptor()
        
        # Decrypt
        $decryptedBytes = $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
        $plaintext = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
        
        # Clean up
        $decryptor.Dispose()
        $aes.Dispose()
        
        return $plaintext
    }
    catch {
        Write-Host "DH Decrypt error: $($_.Exception.Message)" -ForegroundColor Red
        # Show console on decrypt errors
        if (-not $script:consoleVisible) {
            Show-ConsoleWindow
        }
        return $null
    }
}

function Initialize-SystemTray {
    [CmdletBinding()]
    param()
    
    # Create NotifyIcon
    $script:notifyIcon = New-Object System.Windows.Forms.NotifyIcon
    $script:notifyIcon.Visible = $true
    
    # Create icon from system resources (green circle for active)
    $script:notifyIcon.Icon = [System.Drawing.SystemIcons]::Information
    $script:notifyIcon.Text = "NetPaste v4.0 - Port $Port (Double-click to show/hide)"
    
    # Create context menu
    $contextMenu = New-Object System.Windows.Forms.ContextMenuStrip
    
    # Add menu items
    $showItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $showItem.Text = "Show Console"
    $showItem.add_Click({
        param($sender, $e)
        Show-ConsoleWindow
    }.GetNewClosure())
    
    $hideItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $hideItem.Text = "Hide Console"
    $hideItem.add_Click({
        param($sender, $e)
        Hide-ConsoleWindow
    }.GetNewClosure())
    
    $statusItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $statusItem.Text = "Status: Running on port $Port"
    $statusItem.Enabled = $false
    
    $restartItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $restartItem.Text = "Restart NetPaste"
    $restartItem.add_Click({
        param($sender, $e)
        Write-Host "Restart button clicked - setting flags" -ForegroundColor Yellow
        $script:shouldRestart = $true
        $script:shouldStop = $true
        Write-Host "Flags set: shouldRestart=$($script:shouldRestart), shouldStop=$($script:shouldStop)" -ForegroundColor Yellow
    }.GetNewClosure())
    
    $separatorItem = New-Object System.Windows.Forms.ToolStripSeparator
    
    $clearSecretItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $clearSecretItem.Text = "Clear Shared Secret"
    $clearSecretItem.add_Click({
        param($sender, $e)
        if (Clear-SharedSecret) {
            [System.Windows.Forms.MessageBox]::Show(
                "Shared secret has been cleared. The next connection will establish a new trust.",
                "NetPaste",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Information
            )
        }
    }.GetNewClosure())
    
    $exitItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $exitItem.Text = "Exit NetPaste"
    $exitItem.add_Click({
        param($sender, $e)
        $script:shouldStop = $true
        if ($script:notifyIcon) {
            $script:notifyIcon.Visible = $false
            $script:notifyIcon.Dispose()
        }
        exit 0
    }.GetNewClosure())
    
    # Add items to context menu
    $contextMenu.Items.Add($statusItem) | Out-Null
    $contextMenu.Items.Add($separatorItem) | Out-Null
    $contextMenu.Items.Add($showItem) | Out-Null
    $contextMenu.Items.Add($hideItem) | Out-Null
    $contextMenu.Items.Add($separatorItem) | Out-Null
    $contextMenu.Items.Add($clearSecretItem) | Out-Null
    $contextMenu.Items.Add($restartItem) | Out-Null
    $contextMenu.Items.Add($exitItem) | Out-Null
    
    $script:notifyIcon.ContextMenuStrip = $contextMenu
    
    # Add double-click to show/hide console
    $script:notifyIcon.add_DoubleClick({
        param($sender, $e)
        if ($script:consoleVisible) {
            Hide-ConsoleWindow
        } else {
            Show-ConsoleWindow
        }
    }.GetNewClosure())
    
}

# Add Win32 console API once
try {
    Add-Type -TypeDefinition @"
        using System;
        using System.Runtime.InteropServices;
        using System.Diagnostics;
        
        public static class Win32Console {
            [DllImport("kernel32.dll")]
            public static extern IntPtr GetConsoleWindow();
            
            [DllImport("user32.dll")]
            public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
            
            [DllImport("user32.dll")]
            public static extern IntPtr GetSystemMenu(IntPtr hWnd, bool bRevert);
            
            [DllImport("user32.dll")]
            public static extern bool DeleteMenu(IntPtr hMenu, uint uPosition, uint uFlags);
            
            [DllImport("user32.dll")]
            public static extern bool EnableMenuItem(IntPtr hMenu, uint uIDEnableItem, uint uEnable);
            
            [DllImport("kernel32.dll")]
            public static extern bool SetConsoleCtrlHandler(ConsoleCtrlDelegate HandlerRoutine, bool Add);
            
            public delegate bool ConsoleCtrlDelegate(uint CtrlType);
            
            public const int SW_HIDE = 0;
            public const int SW_SHOW = 5;
            public const int SW_RESTORE = 9;
            public const uint SC_CLOSE = 0xF060;
            public const uint MF_BYCOMMAND = 0x00000000;
            public const uint MF_GRAYED = 0x00000001;
            public const uint MF_ENABLED = 0x00000000;
            
            // Control signals
            public const uint CTRL_C_EVENT = 0;
            public const uint CTRL_BREAK_EVENT = 1;
            public const uint CTRL_CLOSE_EVENT = 2;
            public const uint CTRL_LOGOFF_EVENT = 5;
            public const uint CTRL_SHUTDOWN_EVENT = 6;
        }
"@ -ErrorAction SilentlyContinue
} catch {
    # Type already exists, ignore
}

function Show-ConsoleWindow {
    try {
        $consoleWindow = [Win32Console]::GetConsoleWindow()
        [Win32Console]::ShowWindow($consoleWindow, 9) # SW_RESTORE
        
        # Try to bring window to front
        Add-Type -TypeDefinition @"
            using System;
            using System.Runtime.InteropServices;
            public class Win32Focus {
                [DllImport("user32.dll")]
                public static extern bool SetForegroundWindow(IntPtr hWnd);
                [DllImport("user32.dll")]
                public static extern bool BringWindowToTop(IntPtr hWnd);
                [DllImport("user32.dll")]
                public static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);
                public static readonly IntPtr HWND_TOPMOST = new IntPtr(-1);
                public static readonly IntPtr HWND_NOTOPMOST = new IntPtr(-2);
                public const uint SWP_NOMOVE = 0x0002;
                public const uint SWP_NOSIZE = 0x0001;
            }
"@ -ErrorAction SilentlyContinue
        
        # Bring window to top
        [Win32Focus]::BringWindowToTop($consoleWindow) | Out-Null
        [Win32Focus]::SetForegroundWindow($consoleWindow) | Out-Null
        # Temporarily set as topmost then remove to force to front
        [Win32Focus]::SetWindowPos($consoleWindow, [Win32Focus]::HWND_TOPMOST, 0, 0, 0, 0, [Win32Focus]::SWP_NOMOVE -bor [Win32Focus]::SWP_NOSIZE) | Out-Null
        [Win32Focus]::SetWindowPos($consoleWindow, [Win32Focus]::HWND_NOTOPMOST, 0, 0, 0, 0, [Win32Focus]::SWP_NOMOVE -bor [Win32Focus]::SWP_NOSIZE) | Out-Null
        
        $script:consoleVisible = $true
    }
    catch {
        # Could not show console window
    }
}

function Hide-ConsoleWindow {
    try {
        $consoleWindow = [Win32Console]::GetConsoleWindow()
        [Win32Console]::ShowWindow($consoleWindow, 0) # SW_HIDE
        $script:consoleVisible = $false
    }
    catch {
        # Could not hide console window
    }
}

function Show-PasteDialog {
    param([string]$Data, [string]$RemoteEndpoint)

    try {
        # Create a Windows Forms dialog with editable textbox
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        
        # Create form
        $form = New-Object System.Windows.Forms.Form
        $form.Text = "NetPaste - Incoming Data from $RemoteEndpoint"
        $form.Size = New-Object System.Drawing.Size(700, 520)
        $form.StartPosition = "CenterScreen"
        $form.TopMost = $true
        $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::Sizable
        $form.MaximizeBox = $true
        
        # Create label
        $label = New-Object System.Windows.Forms.Label
        $label.Location = New-Object System.Drawing.Point(10, 10)
        $label.Size = New-Object System.Drawing.Size(660, 40)
        $label.Text = "Received $($Data.Length) characters from $RemoteEndpoint`nEdit the text below if needed, then click 'Copy to Clipboard' or 'Cancel':"
        
        # Create textbox
        $textBox = New-Object System.Windows.Forms.RichTextBox
        $textBox.Location = New-Object System.Drawing.Point(10, 55)
        $textBox.Size = New-Object System.Drawing.Size(660, 380)
        $textBox.Multiline = $true
        $textBox.AcceptsTab = $true
        $textBox.WordWrap = $false
        $textBox.ScrollBars = "Both"
        $textBox.Font = New-Object System.Drawing.Font("Cascadia Code", 11)
        # Fallback to Consolas if Cascadia Code is not available
        if (-not $textBox.Font.Name.Contains("Cascadia")) {
            $textBox.Font = New-Object System.Drawing.Font("Consolas", 11)
        }
        $textBox.Text = $Data
        $textBox.SelectionStart = 0
        $textBox.SelectionLength = 0
        $textBox.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor 
                         [System.Windows.Forms.AnchorStyles]::Bottom -bor 
                         [System.Windows.Forms.AnchorStyles]::Left -bor 
                         [System.Windows.Forms.AnchorStyles]::Right
        
        # Create Copy button
        $copyButton = New-Object System.Windows.Forms.Button
        $copyButton.Location = New-Object System.Drawing.Point(480, 445)
        $copyButton.Size = New-Object System.Drawing.Size(120, 30)
        $copyButton.Text = "Copy to Clipboard"
        $copyButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor 
                             [System.Windows.Forms.AnchorStyles]::Right
        $copyButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
        
        # Create Cancel button
        $cancelButton = New-Object System.Windows.Forms.Button
        $cancelButton.Location = New-Object System.Drawing.Point(605, 445)
        $cancelButton.Size = New-Object System.Drawing.Size(65, 30)
        $cancelButton.Text = "Cancel"
        $cancelButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor 
                               [System.Windows.Forms.AnchorStyles]::Right
        $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        
        # Add controls to form
        $form.Controls.Add($label)
        $form.Controls.Add($textBox)
        $form.Controls.Add($copyButton)
        $form.Controls.Add($cancelButton)
        $form.AcceptButton = $copyButton
        $form.CancelButton = $cancelButton
        
        # Show dialog and get result
        $result = $form.ShowDialog()
        
        if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
            # Return the edited text
            $script:editedText = $textBox.Text
            return $true
        }
        return $false
    }
    catch {
        # Fallback to simple Yes/No dialog if form creation fails
        Write-Host "`n=== PASTE REQUEST ===" -ForegroundColor Yellow
        Write-Host "From: $RemoteEndpoint" -ForegroundColor Cyan
        Write-Host "Length: $($Data.Length) characters" -ForegroundColor Cyan
        Write-Host "Content:" -ForegroundColor Cyan
        Write-Host $Data -ForegroundColor White
        Write-Host "===================" -ForegroundColor Yellow
        
        do {
            $response = Read-Host "Copy to clipboard? (y/n)"
        } while ($response -notmatch '^[yn]$')
        
        if ($response -eq 'y') {
            $script:editedText = $Data
            return $true
        }
        return $false
    }
}

function Show-FileExplorerDialog {
    param([string]$Path, [string]$RemoteEndpoint)

    $message = "File Explorer request received from $RemoteEndpoint`n`nPath: $Path`n`nDo you want to open this location in File Explorer?"

    try {
        # Try Windows Forms MessageBox first (more compatible)
        [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
        $result = [System.Windows.Forms.MessageBox]::Show(
            $message,
            "Net Paste - File Explorer Request",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question,
            [System.Windows.Forms.MessageBoxDefaultButton]::Button1,
            [System.Windows.Forms.MessageBoxOptions]::ServiceNotification
        )
        $success = ($result -eq [System.Windows.Forms.DialogResult]::Yes)
    }
    catch {
        Write-Host "DEBUG: Windows Forms failed, trying WPF MessageBox: $($_.Exception.Message)" -ForegroundColor Yellow
        try {
            # Fallback to WPF MessageBox
            $result = [System.Windows.MessageBox]::Show(
                $message,
                "Net Paste - File Explorer Request",
                [System.Windows.MessageBoxButton]::YesNo,
                [System.Windows.MessageBoxImage]::Question
            )
            $success = ($result -eq [System.Windows.MessageBoxResult]::Yes)
        }
        catch {
            Write-Host "`n=== FILE EXPLORER REQUEST ===" -ForegroundColor Yellow
            Write-Host "From: $RemoteEndpoint" -ForegroundColor Cyan
            Write-Host "Path: $Path" -ForegroundColor Cyan
            Write-Host "=============================" -ForegroundColor Yellow
            
            do {
                $response = Read-Host "Open in File Explorer? (y/n)"
            } while ($response -notmatch '^[yn]$')
            
            $success = ($response -eq 'y')
        }
    }

    return $success
}

function Show-FileOpenDialog {
    param([string]$Path, [string]$RemoteEndpoint)

    $message = "File open request received from $RemoteEndpoint`n`nFile: $Path`n`nDo you want to open this file with its default application?"

    try {
        # Try Windows Forms MessageBox first (more compatible)
        [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
        $result = [System.Windows.Forms.MessageBox]::Show(
            $message,
            "Net Paste - File Open Request",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question,
            [System.Windows.Forms.MessageBoxDefaultButton]::Button1,
            [System.Windows.Forms.MessageBoxOptions]::ServiceNotification
        )
        $success = ($result -eq [System.Windows.Forms.DialogResult]::Yes)
    }
    catch {
        Write-Host "DEBUG: Windows Forms failed, trying WPF MessageBox: $($_.Exception.Message)" -ForegroundColor Yellow
        try {
            # Fallback to WPF MessageBox
            $result = [System.Windows.MessageBox]::Show(
                $message,
                "Net Paste - File Open Request",
                [System.Windows.MessageBoxButton]::YesNo,
                [System.Windows.MessageBoxImage]::Question
            )
            $success = ($result -eq [System.Windows.MessageBoxResult]::Yes)
        }
        catch {
            Write-Host "`n=== FILE OPEN REQUEST ===" -ForegroundColor Yellow
            Write-Host "From: $RemoteEndpoint" -ForegroundColor Cyan
            Write-Host "File: $Path" -ForegroundColor Cyan
            Write-Host "=========================" -ForegroundColor Yellow
            
            do {
                $response = Read-Host "Open file with default application? (y/n)"
            } while ($response -notmatch '^[yn]$')
            
            $success = ($response -eq 'y')
        }
    }

    return $success
}

function Open-File {
    param([string]$WindowsPath)

    try {
        if (Test-Path $WindowsPath) {
            # Open file with default application
            Start-Process -FilePath $WindowsPath -WindowStyle Normal
            return $true
        } else {
            return $false
        }
    }
    catch {
        return $false
    }
}

function Show-UrlOpenDialog {
    param([string]$Url, [string]$RemoteEndpoint)

    $message = "URL open request received from $RemoteEndpoint`n`nURL: $Url`n`nDo you want to open this URL in your default browser?"

    try {
        # Try Windows Forms MessageBox first (more compatible)
        [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
        $result = [System.Windows.Forms.MessageBox]::Show(
            $message,
            "Net Paste - URL Open Request",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question,
            [System.Windows.Forms.MessageBoxDefaultButton]::Button1,
            [System.Windows.Forms.MessageBoxOptions]::ServiceNotification
        )
        $success = ($result -eq [System.Windows.Forms.DialogResult]::Yes)
    }
    catch {
        Write-Host "DEBUG: Windows Forms failed, trying WPF MessageBox: $($_.Exception.Message)" -ForegroundColor Yellow
        try {
            # Fallback to WPF MessageBox
            $result = [System.Windows.MessageBox]::Show(
                $message,
                "Net Paste - URL Open Request",
                [System.Windows.MessageBoxButton]::YesNo,
                [System.Windows.MessageBoxImage]::Question
            )
            $success = ($result -eq [System.Windows.MessageBoxResult]::Yes)
        }
        catch {
            Write-Host "`n=== URL OPEN REQUEST ===" -ForegroundColor Yellow
            Write-Host "From: $RemoteEndpoint" -ForegroundColor Cyan
            Write-Host "URL: $Url" -ForegroundColor Cyan
            Write-Host "=======================" -ForegroundColor Yellow
            
            do {
                $response = Read-Host "Open URL in default browser? (y/n)"
            } while ($response -notmatch '^[yn]$')
            
            $success = ($response -eq 'y')
        }
    }

    return $success
}

function Open-Url {
    param([string]$Url)

    try {
        # Open URL in default browser
        Start-Process $Url
        return $true
    }
    catch {
        return $false
    }
}

function Open-InVSCode {
    param([string]$Path)
    try {
        # Check if VS Code is available
        $codePath = Get-Command code -ErrorAction SilentlyContinue
        if (-not $codePath) {
            Write-Host "VS Code not found in PATH" -ForegroundColor Yellow
            return $false
        }
        
        # Open path in VS Code
        Start-Process "code" -ArgumentList "`"$Path`"" -NoNewWindow
        Write-Host "Opened in VS Code: $Path" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "Failed to open in VS Code: $_" -ForegroundColor Red
        return $false
    }
}

function Show-VSCodeDialog {
    param([string]$Path, [string]$RemoteEndpoint)
    
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "Open in VS Code - NetPaste"
    $form.Size = New-Object System.Drawing.Size(500, 200)
    $form.StartPosition = "CenterScreen"
    $form.TopMost = $true
    
    # Info label
    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(10, 20)
    $label.Size = New-Object System.Drawing.Size(460, 40)
    $label.Text = "Request from $RemoteEndpoint to open in VS Code:`n$Path"
    $form.Controls.Add($label)
    
    # Path textbox
    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Location = New-Object System.Drawing.Point(10, 70)
    $textBox.Size = New-Object System.Drawing.Size(460, 20)
    $textBox.Text = $Path
    $textBox.ReadOnly = $true
    $form.Controls.Add($textBox)
    
    # Open button
    $openButton = New-Object System.Windows.Forms.Button
    $openButton.Location = New-Object System.Drawing.Point(150, 110)
    $openButton.Size = New-Object System.Drawing.Size(100, 30)
    $openButton.Text = "Open"
    $openButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.Controls.Add($openButton)
    
    # Cancel button
    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Location = New-Object System.Drawing.Point(260, 110)
    $cancelButton.Size = New-Object System.Drawing.Size(100, 30)
    $cancelButton.Text = "Cancel"
    $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.Controls.Add($cancelButton)
    
    $form.AcceptButton = $openButton
    $form.CancelButton = $cancelButton
    
    $result = $form.ShowDialog()
    return ($result -eq [System.Windows.Forms.DialogResult]::OK)
}

function Show-NotificationDialog {
    param([string]$Message, [string]$RemoteEndpoint)
    
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    
    # Create form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "NetPaste Notification"
    $form.Size = New-Object System.Drawing.Size(500, 300)
    $form.StartPosition = "CenterScreen"
    $form.TopMost = $true
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::Sizable
    $form.Icon = [System.Drawing.SystemIcons]::Information
    
    # Create label for header
    $headerLabel = New-Object System.Windows.Forms.Label
    $headerLabel.Location = New-Object System.Drawing.Point(10, 10)
    $headerLabel.Size = New-Object System.Drawing.Size(460, 30)
    $headerLabel.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $headerLabel.Text = "Notification from $RemoteEndpoint"
    
    # Create RichTextBox for message
    $textBox = New-Object System.Windows.Forms.RichTextBox
    $textBox.Location = New-Object System.Drawing.Point(10, 45)
    $textBox.Size = New-Object System.Drawing.Size(460, 150)
    $textBox.Font = New-Object System.Drawing.Font("Cascadia Code", 10)
    if (-not $textBox.Font.Name.Contains("Cascadia")) {
        $textBox.Font = New-Object System.Drawing.Font("Consolas", 10)
    }
    $textBox.Text = $Message
    $textBox.ReadOnly = $true
    $textBox.BorderStyle = [System.Windows.Forms.BorderStyle]::Fixed3D
    $textBox.BackColor = [System.Drawing.Color]::White
    $textBox.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor 
                     [System.Windows.Forms.AnchorStyles]::Bottom -bor 
                     [System.Windows.Forms.AnchorStyles]::Left -bor 
                     [System.Windows.Forms.AnchorStyles]::Right
    
    # Create Copy button
    $copyButton = New-Object System.Windows.Forms.Button
    $copyButton.Location = New-Object System.Drawing.Point(250, 210)
    $copyButton.Size = New-Object System.Drawing.Size(110, 30)
    $copyButton.Text = "Copy to Clipboard"
    $copyButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor 
                         [System.Windows.Forms.AnchorStyles]::Right
    $copyButton.Add_Click({
        [System.Windows.Forms.Clipboard]::SetText($Message)
        $form.Close()
    })
    
    # Create OK button
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location = New-Object System.Drawing.Point(370, 210)
    $okButton.Size = New-Object System.Drawing.Size(100, 30)
    $okButton.Text = "OK"
    $okButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor 
                       [System.Windows.Forms.AnchorStyles]::Right
    $okButton.Add_Click({ $form.Close() })
    
    # Add controls to form
    $form.Controls.Add($headerLabel)
    $form.Controls.Add($textBox)
    $form.Controls.Add($copyButton)
    $form.Controls.Add($okButton)
    
    # Show the form
    $form.ShowDialog() | Out-Null
}

function Show-Notification {
    param([string]$Message, [string]$RemoteEndpoint)

    try {
        Write-Host "Show-Notification called with Message: '$Message', RemoteEndpoint: '$RemoteEndpoint'" -ForegroundColor Cyan
        
        # Use the existing tray icon if available for balloon tip
        if ($script:notifyIcon) {
            # Remove any existing balloon click handler
            $script:notifyIcon.remove_BalloonTipClicked($script:notificationClickHandler) 2>$null
            
            # Capture the values in local variables for the closure
            $capturedMessage = $Message
            $capturedEndpoint = $RemoteEndpoint
            
            # Create new balloon click handler that shows the dialog
            $script:notificationClickHandler = {
                Write-Host "Balloon clicked - Message: '$capturedMessage', Endpoint: '$capturedEndpoint'" -ForegroundColor Magenta
                Show-NotificationDialog -Message $capturedMessage -RemoteEndpoint $capturedEndpoint
            }.GetNewClosure()
            
            # Add the balloon click handler
            $script:notifyIcon.add_BalloonTipClicked($script:notificationClickHandler)
            
            # Show the balloon tip
            $script:notifyIcon.ShowBalloonTip(
                10000,  # Duration in milliseconds
                "NetPaste Notification", 
                "Click to view message from $RemoteEndpoint", 
                [System.Windows.Forms.ToolTipIcon]::Info
            )
            Write-Host "Notification shown - click balloon to view message" -ForegroundColor Green
            return $true
        }
        else {
            # If no tray icon, show dialog directly
            Show-NotificationDialog -Message $Message -RemoteEndpoint $RemoteEndpoint
            return $true
        }
    }
    catch {
        Write-Host "Error showing notification: $_" -ForegroundColor Red
        return $false
    }
}

function Find-SshfsMount {
    <#
    .SYNOPSIS
        Finds SSHFS mounts from both network mappings and running processes.
    .DESCRIPTION
        This function searches for SSHFS mounts in two places:
        1. The output of the 'net use' command, which lists standard network drive mappings.
        2. The command line of any running 'sshfs.exe' processes, for direct WinFsp mounts.
        It returns custom objects containing the drive letter, IP address/host, and the source of the information.
    .PARAMETER IPAddress
        An optional IP address or hostname to filter the results. Wildcards are supported.
    #>
    param (
        [string]$IPAddress
    )

    $mounts = @()

    # Method 1: Check 'net use' for standard network mappings
    try {
        $netUseOutput = net use
        foreach ($line in $netUseOutput) {
            # Regex to find a drive letter and a UNC path starting with \\sshfs\
            if ($line -match '([A-Z]:)\s+\\\\sshfs\\(?<user>[^@]+)@(?<host>[\d\.\w\-]+)') {
                $mounts += [PSCustomObject]@{
                    DriveLetter = $Matches[1]
                    IPAddress   = $Matches['host']
                    Source      = "net use"
                }
            }
        }
    }
    catch {
        Write-Warning "Could not query 'net use'. Skipping."
    }

    # Method 2: Check running sshfs.exe processes for direct mounts
    try {
        $sshfsProcesses = Get-CimInstance -ClassName Win32_Process -Filter "Name = 'sshfs.exe'" -ErrorAction SilentlyContinue

        foreach ($process in $sshfsProcesses) {
            # Regex to find user@ip:/... and a drive letter like F:
            if ($process.CommandLine -match '(?<user>[^@\s]+)@(?<host>[\d\.\w\-]+):\/.*?\s(?<drive>[A-Z]:)') {
                $mounts += [PSCustomObject]@{
                    DriveLetter = $Matches['drive']
                    IPAddress   = $Matches['host']
                    Source      = "Process"
                }
            }
        }
    }
    catch {
        Write-Warning "Could not query Win32_Process. Skipping."
    }

    # Filter results if an IPAddress was provided
    if ($PSBoundParameters.ContainsKey('IPAddress')) {
        $mounts | Where-Object { $_.IPAddress -like $IPAddress }
    }
    else {
        $mounts
    }
}

# Cache for SSHFS mount detection to avoid repeated lookups
$script:SshfsMountCache = $null
$script:SshfsCacheTime = $null

function Get-SshfsDriveLetter {
    param([string]$RemoteIP)
    
    # Use cache if it's less than 5 minutes old
    if ($script:SshfsMountCache -and $script:SshfsCacheTime -and 
        ((Get-Date) - $script:SshfsCacheTime).TotalMinutes -lt 5) {
        $mount = $script:SshfsMountCache | Where-Object { $_.IPAddress -eq $RemoteIP } | Select-Object -First 1
        if ($mount) {
            return $mount.DriveLetter
        }
    }
    
    # Refresh cache
    $script:SshfsMountCache = Find-SshfsMount
    $script:SshfsCacheTime = Get-Date
    
    # Extract IP from remote endpoint (remove port)
    if ($RemoteIP -match '^([^:]+):\d+$') {
        $RemoteIP = $Matches[1]
    }
    
    # Find mount for this IP
    $mount = $script:SshfsMountCache | Where-Object { $_.IPAddress -eq $RemoteIP } | Select-Object -First 1
    
    if ($mount) {
        Write-Host "Found SSHFS mount for $RemoteIP on drive $($mount.DriveLetter)" -ForegroundColor Green
        return $mount.DriveLetter
    }
    else {
        # Default to F: if no mount found (backward compatibility)
        Write-Host "No SSHFS mount found for $RemoteIP, defaulting to F:" -ForegroundColor Yellow
        return "F:"
    }
}

function Test-JsonMessage {
    param([string]$Data)
    
    try {
        $msg = $Data | ConvertFrom-Json
        return $msg.type -ne $null
    }
    catch {
        return $false
    }
}

function Get-MessageType {
    param([string]$Data)
    
    try {
        $msg = $Data | ConvertFrom-Json
        return $msg.type
    }
    catch {
        return "paste"  # Default to paste for non-JSON messages
    }
}

function Get-MessageData {
    param([string]$Data)
    
    try {
        return $Data | ConvertFrom-Json
    }
    catch {
        # Return as paste message for backwards compatibility
        return @{type = "paste"; text = $Data}
    }
}

function Convert-UnixToWindowsPath {
    param(
        [string]$UnixPath,
        [string]$RemoteEndpoint = $null
    )

    # Remove leading slash if present
    if ($UnixPath.StartsWith("/")) {
        $UnixPath = $UnixPath.Substring(1)
    }

    # Get the appropriate drive letter based on the remote IP
    $driveLetter = if ($RemoteEndpoint) {
        Get-SshfsDriveLetter -RemoteIP $RemoteEndpoint
    } else {
        "F:"  # Default fallback
    }

    # Convert to Windows path with detected drive
    $windowsPath = "$driveLetter\$($UnixPath -replace "/", "\")"

    return $windowsPath
}

function Convert-UnixToWindowsFilePath {
    param(
        [string]$UnixPath,
        [string]$RemoteEndpoint = $null
    )

    # Remove leading slash if present
    if ($UnixPath.StartsWith("/")) {
        $UnixPath = $UnixPath.Substring(1)
    }

    # Get the appropriate drive letter based on the remote IP
    $driveLetter = if ($RemoteEndpoint) {
        Get-SshfsDriveLetter -RemoteIP $RemoteEndpoint
    } else {
        "F:"  # Default fallback
    }

    # Convert to Windows path with detected drive
    $windowsPath = "$driveLetter\$($UnixPath -replace "/", "\")"

    return $windowsPath
}

function Open-FileExplorer {
    param([string]$WindowsPath)

    try {
        if (Test-Path $WindowsPath) {
            # Start explorer process
            $process = Start-Process -FilePath "explorer.exe" -ArgumentList "`"$WindowsPath`"" -PassThru
            
            # Give it a moment to start
            Start-Sleep -Milliseconds 1000
            
            # Try to bring to front using COM object (more reliable)
            try {
                $shell = New-Object -ComObject "Shell.Application"
                $windows = $shell.Windows()
                
                foreach ($window in $windows) {
                    if ($window.LocationURL -like "*$($WindowsPath.Replace('\','%5C'))*" -or 
                        $window.Document.Folder.Self.Path -eq $WindowsPath) {
                        $window.Visible = $true
                        $hwnd = $window.HWND
                        
                        # Use ShowWindow API to force to front
                        Add-Type -TypeDefinition @"
                            using System;
                            using System.Runtime.InteropServices;
                            public class User32 {
                                [DllImport("user32.dll")]
                                public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
                                [DllImport("user32.dll")]
                                public static extern bool SetForegroundWindow(IntPtr hWnd);
                                [DllImport("user32.dll")]
                                public static extern bool BringWindowToTop(IntPtr hWnd);
                            }
"@
                        [User32]::ShowWindow([IntPtr]$hwnd, 9)  # SW_RESTORE
                        [User32]::SetForegroundWindow([IntPtr]$hwnd)
                        [User32]::BringWindowToTop([IntPtr]$hwnd)
                        break
                    }
                }
            }
            catch {
                # Note: Using basic explorer launch (window may stay in background)
            }
            
            return $true
        } else {
            # Still try to open it in case it's a valid network path
            Start-Process -FilePath "explorer.exe" -ArgumentList "`"$WindowsPath`""
            return $true
        }
    }
    catch {
        return $false
    }
}

function Set-ClipboardText {
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Text)

    if ($PSCmdlet.ShouldProcess("Clipboard", "Set text content")) {
        [System.Windows.Forms.Clipboard]::SetText($Text)
    }
}

function Get-LocalIPAddress {
    $ips = @()
    $networkAdapters = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'}

    foreach ($adapter in $networkAdapters) {
        $ipConfig = Get-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        foreach ($ip in $ipConfig) {
            if ($ip.IPAddress -ne '127.0.0.1') {
                $ips += $ip.IPAddress
            }
        }
    }

    return $ips
}

# Check if this is the parent process (no -Child flag)
if (-not $Child) {
    # Parent process - continuously restart child processes

    # Handle Ctrl+C gracefully for parent using script scope
    $script:parentShouldStop = $false
    Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
        $script:parentShouldStop = $true
    } | Out-Null

    do {

        # Start child process with -Child flag, Key parameter, NoTray parameter, and NoEncrypt parameter
        $keyParam = if ($Key) { " -Key `"$Key`"" } else { "" }
        $noTrayParam = if ($NoTray) { " -NoTray" } else { "" }
        $noEncryptParam = if ($NoEncrypt) { " -NoEncrypt" } else { "" }
        $childProcess = Start-Process -FilePath "powershell.exe" -ArgumentList "-File `"$PSCommandPath`" -Port $Port -Child$keyParam$noTrayParam$noEncryptParam" -NoNewWindow -PassThru -Wait

        if ($childProcess.ExitCode -eq 42) {
            Start-Sleep -Seconds 1
        } else {
            break
        }

    } while (-not $script:parentShouldStop)

    exit 0
}

# Child process - main NetPaste functionality

# Initialize flags
$script:consoleVisible = $NoTray
$script:shouldRestart = $false

# Initialize system tray by default (unless NoTray specified)
if (-not $NoTray) {
    Initialize-SystemTray
    
    Write-Host @"

======================================
NetPaste is running in system tray mode
======================================
- Click the X button or press Alt+F4 to HIDE this window (not close)
- Double-click the system tray icon to show/hide console
- Right-click the system tray icon for menu options
- Use 'Exit NetPaste' in the tray menu to fully exit
======================================

"@ -ForegroundColor Cyan
    
    # Hide console window by default when using tray
    Start-Sleep -Milliseconds 1500  # Give time for user to see the message
    Hide-ConsoleWindow
}

# Main execution for child process
try {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $Port)
    $listener.Start()

    $localIPs = Get-LocalIPAddress

    $readyTime = Get-Date
    $startupDuration = ($readyTime - $script:StartTime).TotalSeconds
    Write-Host "[$(Get-Date -Format 'HH:mm:ss.fff')] NetPaste ready - listening on port $Port (startup took $($startupDuration.ToString('F2')) seconds)" -ForegroundColor Green

    # Handle Ctrl+C gracefully using script scope
    $script:shouldStop = $false

    # Register event handler for Ctrl+C
    Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
        $script:shouldStop = $true
    } | Out-Null

    while (-not $script:shouldStop) {
        try {
            # Process Windows messages for tray icon if enabled
            if ($script:notifyIcon) {
                [System.Windows.Forms.Application]::DoEvents()
                
                # Check if console window exists but should be hidden
                # This handles the case where user tries to close the console
                if ($script:consoleVisible) {
                    $consoleWindow = [Win32Console]::GetConsoleWindow()
                    if ($consoleWindow -ne [IntPtr]::Zero) {
                        # Window still exists, keep processing
                    } else {
                        # Window was closed, but we're still running in tray
                        $script:consoleVisible = $false
                    }
                }
            }
            
            # Check for restart flag
            if ($script:shouldRestart) {
                Write-Host "Restart flag detected in main loop - exiting..." -ForegroundColor Yellow
                break
            }
            
            # Check for pending connections without blocking
            if ($listener.Pending()) {
                $client = $listener.AcceptTcpClient()
                $remoteEndpoint = $client.Client.RemoteEndPoint.ToString()
                
                # Show tray notification if enabled
                if ($script:notifyIcon) {
                    # Remove any existing balloon click handler to avoid duplicates
                    $script:notifyIcon.remove_BalloonTipClicked($script:balloonClickHandler) 2>$null
                    
                    # Create new balloon click handler
                    $script:balloonClickHandler = {
                        # Show console window when balloon is clicked
                        Show-ConsoleWindow
                        # Close the balloon tip
                        $script:notifyIcon.Visible = $false
                        $script:notifyIcon.Visible = $true
                    }.GetNewClosure()
                    
                    # Add the balloon click handler
                    $script:notifyIcon.add_BalloonTipClicked($script:balloonClickHandler)
                    
                    # Show the balloon tip
                    $script:notifyIcon.ShowBalloonTip(3000, "NetPaste", "Connection from $remoteEndpoint", [System.Windows.Forms.ToolTipIcon]::Info)
                }

                # Process the connection directly (simplified approach)
                try {
                    $stream = $client.GetStream()
                    $stream.ReadTimeout = 2000  # 2 second timeout

                    # Read data in chunks to capture partial data on timeout
                    $buffer = New-Object byte[] 4096
                    $allData = New-Object System.Collections.Generic.List[byte]
                    $receivedText = ""
                    $consecutiveTimeouts = 0
                    $isDHHandshake = $false

                    Write-Host "[$(Get-Date -Format 'HH:mm:ss.fff')] Reading data from client $remoteEndpoint..." -ForegroundColor Cyan

                    do {
                        try {
                            $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
                            if ($bytesRead -gt 0) {
                                $consecutiveTimeouts = 0  # Reset timeout counter
                                # Add to raw byte collection
                                for ($i = 0; $i -lt $bytesRead; $i++) {
                                    $allData.Add($buffer[$i])
                                }
                                # Convert to text
                                $newText = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $bytesRead)
                                $receivedText += $newText
                                
                                Write-Host "Received $bytesRead bytes, total length: $($receivedText.Length)" -ForegroundColor Gray
                                
                                # Check for DH handshake as soon as we have enough data
                                if (-not $isDHHandshake -and $receivedText.Length -ge 20 -and (Test-DHHandshakeMessage -Data $receivedText)) {
                                    Write-Host "Detected DH handshake message" -ForegroundColor Yellow
                                    $isDHHandshake = $true
                                    # Continue reading until we have the complete JSON message
                                    if ($receivedText.EndsWith("`n") -or $receivedText.EndsWith("}")) {
                                        Write-Host "Complete DH handshake received, processing..." -ForegroundColor Green
                                        break
                                    }
                                }
                            } elseif ($bytesRead -eq 0) {
                                # Connection closed by client
                                Write-Host "Client closed connection" -ForegroundColor Gray
                                break
                            }
                        }
                        catch [System.IO.IOException] {
                            # Read timeout - increment counter and break after 2 consecutive timeouts
                            $consecutiveTimeouts++
                            Write-Host "Read timeout $consecutiveTimeouts/2" -ForegroundColor Gray
                            if ($consecutiveTimeouts -ge 2) {
                                break
                            }
                        }
                    } while ($bytesRead -gt 0)

                    if ($receivedText.Length -gt 0) {
                        Write-Host "Processing received data (length: $($receivedText.Length))" -ForegroundColor Cyan
                        Write-Host "Data preview: $($receivedText.Substring(0, [Math]::Min(100, $receivedText.Length)))" -ForegroundColor Gray
                        
                        # Check if this is a DH handshake request
                        $isHandshake = Test-DHHandshakeMessage -Data $receivedText
                        Write-Host "DH Handshake test result: $isHandshake" -ForegroundColor Gray
                        if ($isDHHandshake -or $isHandshake) {
                            Write-Host "Processing DH handshake..." -ForegroundColor Yellow
                            $dhKey = Handle-DHHandshake -Stream $stream -HandshakeData $receivedText
                            if ($dhKey) {
                                Write-Host "DH handshake successful" -ForegroundColor Green
                                
                                # Handle authentication with shared secret
                                if (-not (Handle-Authentication -Stream $stream -DHKey $dhKey)) {
                                    Write-Host "Authentication failed - closing connection" -ForegroundColor Red
                                    # Show console on authentication errors
                                    if (-not $script:consoleVisible) {
                                        Show-ConsoleWindow
                                    }
                                    continue
                                }
                                
                                Write-Host "Authentication successful, waiting for encrypted data..." -ForegroundColor Green
                                
                                # Read the actual encrypted data after handshake
                                $buffer = New-Object byte[] 4096
                                $allData = New-Object System.Collections.Generic.List[byte]
                                $receivedText = ""
                                $consecutiveTimeouts = 0

                                do {
                                    try {
                                        $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
                                        if ($bytesRead -gt 0) {
                                            $consecutiveTimeouts = 0
                                            for ($i = 0; $i -lt $bytesRead; $i++) {
                                                $allData.Add($buffer[$i])
                                            }
                                            $receivedText += [System.Text.Encoding]::UTF8.GetString($buffer, 0, $bytesRead)
                                            Write-Host "Received $bytesRead encrypted bytes" -ForegroundColor Gray
                                        } elseif ($bytesRead -eq 0) {
                                            Write-Host "No more encrypted data from client" -ForegroundColor Gray
                                            break
                                        }
                                    }
                                    catch [System.IO.IOException] {
                                        $consecutiveTimeouts++
                                        Write-Host "Timeout waiting for encrypted data $consecutiveTimeouts/2" -ForegroundColor Gray
                                        if ($consecutiveTimeouts -ge 2) {
                                            break
                                        }
                                    }
                                } while ($bytesRead -gt 0)
                                
                                # Decrypt with DH-derived key
                                if ($receivedText.Length -gt 0 -and (Test-EncryptedMessage -Data $receivedText)) {
                                    Write-Host "Received encrypted payload: '$($receivedText.Substring(0, [Math]::Min(100, $receivedText.Length)))$(if ($receivedText.Length -gt 100) { '...' } else { '' })'" -ForegroundColor Cyan
                                    Write-Host "Decrypting data with DH-derived key..." -ForegroundColor Yellow
                                    # Use the raw DH key bytes directly, not converted to string
                                    $decryptedText = Decrypt-DHData -EncryptedData $receivedText -KeyBytes $dhKey
                                    if ($decryptedText) {
                                        Write-Host "Successfully decrypted data: '$($decryptedText.Substring(0, [Math]::Min(100, $decryptedText.Length)))$(if ($decryptedText.Length -gt 100) { '...' } else { '' })'" -ForegroundColor Green
                                        $receivedText = $decryptedText
                                    } else {
                                        Write-Host "Failed to decrypt data" -ForegroundColor Red
                                        # Show console on decryption errors
                                        if (-not $script:consoleVisible) {
                                            Show-ConsoleWindow
                                        }
                                        continue
                                    }
                                } elseif ($receivedText.Length -gt 0) {
                                    Write-Host "Received unencrypted data after DH handshake" -ForegroundColor Yellow
                                } else {
                                    # No data after handshake, skip processing
                                    Write-Host "No data received after DH handshake" -ForegroundColor Yellow
                                    continue
                                }
                            } else {
                                Write-Host "DH handshake failed" -ForegroundColor Red
                                # Show console on DH handshake errors
                                if (-not $script:consoleVisible) {
                                    Show-ConsoleWindow
                                }
                                continue
                            }
                            
                            # Now process the decrypted data (fall through to checks below)
                        }
                        # Skip non-DH encrypted messages (no static keys supported)
                        elseif (Test-EncryptedMessage -Data $receivedText) {
                            Write-Host "Received encrypted data without DH handshake - ignoring" -ForegroundColor Yellow
                            continue
                        }
                        
                        # Process the actual message content (after any decryption)
                        # Parse message as JSON or treat as legacy paste
                        $messageData = Get-MessageData -Data $receivedText
                        $messageType = $messageData.type
                        
                        Write-Host "Processing message type: $messageType" -ForegroundColor Cyan
                        
                        switch ($messageType) {
                            "restart" {
                                Write-Host "Restart request received" -ForegroundColor Yellow
                                exit 42  # Special exit code to signal restart
                            }
                            "explorer" {
                                $windowsPath = Convert-UnixToWindowsPath -UnixPath $messageData.path -RemoteEndpoint $remoteEndpoint
                                if (Show-FileExplorerDialog -Path $windowsPath -RemoteEndpoint $remoteEndpoint) {
                                    Open-FileExplorer -WindowsPath $windowsPath | Out-Null
                                }
                            }
                            "open_file" {
                                $windowsPath = Convert-UnixToWindowsFilePath -UnixPath $messageData.path -RemoteEndpoint $remoteEndpoint
                                if (Show-FileOpenDialog -Path $windowsPath -RemoteEndpoint $remoteEndpoint) {
                                    Open-File -WindowsPath $windowsPath | Out-Null
                                }
                            }
                            "open_url" {
                                if (Show-UrlOpenDialog -Url $messageData.url -RemoteEndpoint $remoteEndpoint) {
                                    Open-Url -Url $messageData.url | Out-Null
                                }
                            }
                            "vscode" {
                                $windowsPath = Convert-UnixToWindowsPath -UnixPath $messageData.path -RemoteEndpoint $remoteEndpoint
                                if (Show-VSCodeDialog -Path $windowsPath -RemoteEndpoint $remoteEndpoint) {
                                    Open-InVSCode -Path $windowsPath | Out-Null
                                }
                            }
                            "notification" {
                                Write-Host "Notification received - Message: '$($messageData.message)'" -ForegroundColor Yellow
                                Write-Host "Full messageData: $($messageData | ConvertTo-Json -Compress)" -ForegroundColor Yellow
                                $notificationMessage = if ($messageData.message) { $messageData.message } else { "No message content" }
                                Show-Notification -Message $notificationMessage -RemoteEndpoint $remoteEndpoint | Out-Null
                            }
                            "paste" {
                                $textToClipboard = if ($messageData.text) { $messageData.text } else { $receivedText }
                                if (Show-PasteDialog -Data $textToClipboard -RemoteEndpoint $remoteEndpoint) {
                                    # Use the edited text from the dialog
                                    Set-ClipboardText -Text $script:editedText
                                }
                            }
                            default {
                                # Legacy format or unknown - treat as paste
                                if (Show-PasteDialog -Data $receivedText -RemoteEndpoint $remoteEndpoint) {
                                    # Use the edited text from the dialog
                                    Set-ClipboardText -Text $script:editedText
                                }
                            }
                        }
                    } else {
                    }
                    
                    $client.Close()
                }
                catch {
                    if ($client) { $client.Close() }
                }
            } else {
                # No pending connections - sleep briefly and continue
                Start-Sleep -Milliseconds 100
            }
        }
        catch [System.Net.Sockets.SocketException] {
            if ($_.Exception.SocketErrorCode -eq 'Interrupted') {
                break
            }
            # Continue the loop for socket errors (don't break)
            Start-Sleep -Milliseconds 500
        }
        catch {
            # Continue the loop for general errors (don't break)
            Start-Sleep -Milliseconds 500
        }
    }
}
catch {
    exit 1
}
finally {
    if ($listener) {
        $listener.Stop()
    }
    
    # Clean up system tray icon
    if ($script:notifyIcon) {
        $script:notifyIcon.Visible = $false
        $script:notifyIcon.Dispose()
    }

    # Clean up event registrations
    Get-EventSubscriber | Unregister-Event
    
    # Handle restart request
    if ($script:shouldRestart) {
        Write-Host "Restart requested - exiting with code 42" -ForegroundColor Yellow
        exit 42  # Special exit code to signal restart
    }
}

# End of child process execution