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
    [switch]$NoTray,
    [switch]$NoEncrypt
)

# Capture start time immediately after param block
$script:StartTime = Get-Date
Write-Host "[$(Get-Date -Format 'HH:mm:ss.fff')] NetPaste starting up..." -ForegroundColor Green

# Pairing storage (Windows AppData). One secret per paired client, keyed by client_id.
# Format: {"server_id": "...", "clients": [{"client_id", "secret" (hex), "paired", "ip"}]}
$script:PairingsFilePath = Join-Path $env:APPDATA "NetPaste\pairings.json"
# Pre-v2 single shared secret; no longer accepted, removed when pairings are cleared
$script:LegacySecretFilePath = Join-Path $env:APPDATA "NetPaste\secret.key"

function Protect-OwnerOnly {
    param([string]$Path)

    $acl = Get-Acl $Path
    $acl.SetAccessRuleProtection($true, $false)
    $permission = New-Object System.Security.AccessControl.FileSystemAccessRule(
        [System.Security.Principal.WindowsIdentity]::GetCurrent().Name,
        "FullControl",
        "Allow"
    )
    $acl.SetAccessRule($permission)
    Set-Acl $Path $acl
}

function ConvertTo-HexString {
    param([byte[]]$Bytes)
    return ([System.BitConverter]::ToString($Bytes) -replace '-', '').ToLowerInvariant()
}

function ConvertFrom-HexString {
    param([string]$Hex)
    $bytes = New-Object byte[] ($Hex.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $bytes[$i] = [System.Convert]::ToByte($Hex.Substring($i * 2, 2), 16)
    }
    return ,$bytes
}

function Get-RandomHex {
    param([int]$ByteCount)
    $bytes = New-Object byte[] $ByteCount
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()
    return ConvertTo-HexString -Bytes $bytes
}

function Write-Pairings {
    param([hashtable]$Pairings)

    $dir = Split-Path $script:PairingsFilePath -Parent
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    # Restrict the file before any secret is written to it
    if (-not (Test-Path $script:PairingsFilePath)) {
        New-Item -ItemType File -Path $script:PairingsFilePath -Force | Out-Null
        Protect-OwnerOnly -Path $script:PairingsFilePath
    }

    $json = ConvertTo-Json -InputObject @{
        server_id = $Pairings.server_id
        clients = @($Pairings.clients)
    } -Depth 4
    Set-Content -Path $script:PairingsFilePath -Value $json -Encoding UTF8
}

function Read-Pairings {
    $serverId = $null
    $clients = New-Object System.Collections.ArrayList

    # A read or parse error throws: regenerating here would silently drop every pairing
    if (Test-Path $script:PairingsFilePath) {
        $raw = Get-Content $script:PairingsFilePath -Raw
        if ($raw -and $raw.Trim()) {
            $data = $raw | ConvertFrom-Json
            $serverId = $data.server_id
            foreach ($c in @($data.clients)) {
                if ($c -and $c.client_id -and $c.secret) {
                    [void]$clients.Add(@{
                        client_id = [string]$c.client_id
                        secret = [string]$c.secret
                        paired = [string]$c.paired
                        ip = [string]$c.ip
                    })
                }
            }
        }
    }

    $pairings = @{ server_id = $serverId; clients = $clients }
    if (-not $serverId) {
        $pairings.server_id = "srv-" + (Get-RandomHex -ByteCount 6)
        Write-Pairings -Pairings $pairings
    }
    return $pairings
}

function Get-PairedSecret {
    param([hashtable]$Pairings, [string]$ClientId)

    foreach ($c in $Pairings.clients) {
        if ($c.client_id -eq $ClientId) {
            return ,(ConvertFrom-HexString -Hex $c.secret)
        }
    }
    return $null
}

function Set-PairedClient {
    param([hashtable]$Pairings, [string]$ClientId, [byte[]]$Secret, [string]$RemoteEndpoint)

    $remaining = New-Object System.Collections.ArrayList
    foreach ($c in $Pairings.clients) {
        if ($c.client_id -ne $ClientId) { [void]$remaining.Add($c) }
    }
    [void]$remaining.Add(@{
        client_id = $ClientId
        secret = ConvertTo-HexString -Bytes $Secret
        paired = (Get-Date).ToString("o")
        ip = $RemoteEndpoint
    })
    $Pairings.clients = $remaining
    Write-Pairings -Pairings $Pairings
    Write-Host "Stored pairing for client '$ClientId' in $($script:PairingsFilePath)" -ForegroundColor Green
}

function Clear-AllPairings {
    $pairings = Read-Pairings
    $count = $pairings.clients.Count
    $pairings.clients = New-Object System.Collections.ArrayList
    Write-Pairings -Pairings $pairings
    if (Test-Path $script:LegacySecretFilePath) {
        Remove-Item $script:LegacySecretFilePath -Force
    }
    Write-Host "Cleared $count client pairing(s)" -ForegroundColor Yellow
    return $true
}

function Test-ClientId {
    param([string]$ClientId)
    return ($ClientId -cmatch '^[A-Za-z0-9._-]{1,64}$')
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
    $sharedSecret = [System.Numerics.BigInteger]::ModPow($TheirPublicKey, $MyPrivateKey, $script:DH_P)
    
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
    
    # Copy these bytes to the beginning of our fixed-size buffer
    [System.Array]::Copy($secretBytesRaw, 0, $secretBytes, 0, $bytesToCopy)
    
    # Reverse the entire buffer to get the final big-endian representation
    [System.Array]::Reverse($secretBytes)
    
    # Now hash the raw bytes with SHA-256
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $sha256.ComputeHash($secretBytes)
    $sha256.Dispose()
    
    return $hashBytes
}

function Test-DHHandshakeMessage {
    param([string]$Data)

    # Check for DH handshake - require both type field and dh_handshake value
    return ($Data -match '^\s*\{\s*"type"\s*:\s*"dh_handshake"' -or $Data.Contains('"type": "dh_handshake"'))
}

function Send-JsonLine {
    param([System.Net.Sockets.NetworkStream]$Stream, [hashtable]$Object)
    $json = $Object | ConvertTo-Json -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json + "`n")
    $Stream.Write($bytes, 0, $bytes.Length)
    $Stream.Flush()
}

function Send-EncryptedJsonLine {
    param([System.Net.Sockets.NetworkStream]$Stream, [hashtable]$Object, [byte[]]$KeyBytes)
    $json = $Object | ConvertTo-Json -Compress
    $encrypted = Encrypt-DHData -Data $json -KeyBytes $KeyBytes
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($encrypted + "`n")
    $Stream.Write($bytes, 0, $bytes.Length)
    $Stream.Flush()
}

function Read-StreamLine {
    param([System.Net.Sockets.NetworkStream]$Stream)

    $buffer = New-Object byte[] 4096
    $data = ""
    $consecutiveTimeouts = 0
    do {
        try {
            $bytesRead = $Stream.Read($buffer, 0, $buffer.Length)
            if ($bytesRead -gt 0) {
                $consecutiveTimeouts = 0
                $data += [System.Text.Encoding]::UTF8.GetString($buffer, 0, $bytesRead)
                if ($data.Contains("`n")) { break }
            }
        }
        catch [System.IO.IOException] {
            $consecutiveTimeouts++
            if ($consecutiveTimeouts -ge 2) { break }
            $bytesRead = 1
        }
    } while ($bytesRead -gt 0)
    return $data.Trim()
}

# --- Handshake key derivation (protocol v2) ---
# Both sides must compute these byte-for-byte identically to client/netpaste.py.
#   transcript = UTF8("netpaste-v2\n" + client_id + "\n" + server_id + "\n"
#                     + client_public_str + "\n" + server_public_str + "\n") || dh_key
#   pairing code   = (first 4 bytes of SHA256(UTF8("netpaste-sas") || transcript), big-endian) mod 10^6
#   pairing secret = HMAC-SHA256(key = dh_key, UTF8("netpaste-pair") || transcript)
#   session key    = HMAC-SHA256(key = pairing secret, UTF8("netpaste-session") || transcript)
# dh_key is SHA256 of the 256-byte big-endian DH shared value; public keys are the
# exact decimal strings sent on the wire.

function Get-HmacSha256 {
    param([byte[]]$Key, [byte[]]$Message)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256 -ArgumentList (,$Key)
    $result = $hmac.ComputeHash($Message)
    $hmac.Dispose()
    return ,$result
}

function Join-Labeled {
    param([string]$Label, [byte[]]$Data)
    return ,([byte[]]([System.Text.Encoding]::UTF8.GetBytes($Label) + $Data))
}

function Get-HandshakeTranscript {
    param([string]$ClientId, [string]$ServerId, [string]$ClientPublicStr, [string]$ServerPublicStr, [byte[]]$DHKey)
    $header = "netpaste-v2`n$ClientId`n$ServerId`n$ClientPublicStr`n$ServerPublicStr`n"
    return ,(Join-Labeled -Label $header -Data $DHKey)
}

function Get-PairingCode {
    param([byte[]]$Transcript)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $hash = $sha256.ComputeHash((Join-Labeled -Label "netpaste-sas" -Data $Transcript))
    $sha256.Dispose()
    $n = ([uint64]$hash[0] -shl 24) -bor ([uint64]$hash[1] -shl 16) -bor ([uint64]$hash[2] -shl 8) -bor [uint64]$hash[3]
    return ($n % 1000000).ToString("D6")
}

function Get-PairingSecret {
    param([byte[]]$DHKey, [byte[]]$Transcript)
    return ,(Get-HmacSha256 -Key $DHKey -Message (Join-Labeled -Label "netpaste-pair" -Data $Transcript))
}

function Get-SessionKey {
    param([byte[]]$Secret, [byte[]]$Transcript)
    return ,(Get-HmacSha256 -Key $Secret -Message (Join-Labeled -Label "netpaste-session" -Data $Transcript))
}

function Complete-DHSession {
    param([hashtable]$Session, [string]$ClientPublicStr)

    # Keep the exact string the client sent; it is part of the key derivation transcript
    $clientPublicKey = [System.Numerics.BigInteger]::Parse($ClientPublicStr)
    if ($clientPublicKey -le 1 -or $clientPublicKey -ge ($script:DH_P - 1)) {
        throw "Invalid client public key"
    }
    $Session.DHKey = Compute-DHSharedSecret -TheirPublicKey $clientPublicKey -MyPrivateKey $Session.OurKeys.PrivateKey
    $Session.Transcript = Get-HandshakeTranscript -ClientId $Session.ClientId -ServerId $Session.ServerId `
        -ClientPublicStr $ClientPublicStr -ServerPublicStr $Session.ServerPublicStr -DHKey $Session.DHKey
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

        if ($clientMsg.v -ne 2 -or -not (Test-ClientId -ClientId $clientMsg.client_id)) {
            Send-JsonLine -Stream $Stream -Object @{
                type = "error"
                message = "Unsupported client protocol. Update netpaste.py, then pair with: nppair (netpaste.py --pair)"
            }
            throw "Client did not send a v2 handshake with a valid client_id"
        }

        $clientId = [string]$clientMsg.client_id
        $isPairing = ($clientMsg.pair -eq $true)
        if ($isPairing) {
            # Pairing: the client commits to its public key and reveals it only after seeing ours,
            # so a man-in-the-middle cannot search for keys that make the two pairing codes match
            if (-not ([string]$clientMsg.commit -cmatch '^[0-9a-f]{64}$')) {
                throw "Pairing handshake without a valid commitment"
            }
        }

        $pairings = Read-Pairings
        $secret = Get-PairedSecret -Pairings $pairings -ClientId $clientId
        
        # Generate our key pair
        $ourKeys = Generate-DHKeypair
        
        $session = @{
            ClientId = $clientId
            IsPairing = $isPairing
            Commit = [string]$clientMsg.commit
            ServerId = $pairings.server_id
            OurKeys = $ourKeys
            ServerPublicStr = $ourKeys.PublicKey.ToString()
            Secret = $secret
            Pairings = $pairings
            DHKey = $null
            Transcript = $null
        }
        
        # Send our public key - use string to avoid JSON precision loss
        Send-JsonLine -Stream $Stream -Object @{
            type = "dh_response"
            v = 2
            server_id = $pairings.server_id
            public_key_str = $session.ServerPublicStr
            paired = [bool]$secret
        }
        
        if (-not $isPairing) {
            Complete-DHSession -Session $session -ClientPublicStr ([string]$clientMsg.public_key_str)
        }
        
        Write-Host "DH handshake with client '$clientId' (paired: $([bool]$secret), pairing: $isPairing)" -ForegroundColor Gray
        return $session
    }
    catch {
        Write-Host "DH handshake failed: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Show-PairingDialog {
    param([string]$ClientId, [string]$RemoteEndpoint, [string]$Code)

    $spacedCode = $Code.Substring(0, 3) + " " + $Code.Substring(3)
    $message = "Pairing request from client '$ClientId' at $RemoteEndpoint.`n`n" +
        "Approve only if the terminal on that client shows this same code:`n`n" +
        "        $spacedCode`n`n" +
        "If the codes differ, someone may be intercepting the connection. Approve pairing?"

    try {
        [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
        $result = [System.Windows.Forms.MessageBox]::Show(
            $message,
            "Net Paste - Pair New Client",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning,
            [System.Windows.Forms.MessageBoxDefaultButton]::Button2,
            [System.Windows.Forms.MessageBoxOptions]::ServiceNotification
        )
        return ($result -eq [System.Windows.Forms.DialogResult]::Yes)
    }
    catch {
        Write-Host "Pairing dialog failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Handle-PairRequest {
    param([System.Net.Sockets.NetworkStream]$Stream, [hashtable]$Session, [string]$RemoteEndpoint)

    $code = Get-PairingCode -Transcript $Session.Transcript
    Write-Host "Pairing request from client '$($Session.ClientId)' at $RemoteEndpoint - code $code" -ForegroundColor Yellow

    if (-not (Show-PairingDialog -ClientId $Session.ClientId -RemoteEndpoint $RemoteEndpoint -Code $code)) {
        Write-Host "Pairing rejected" -ForegroundColor Red
        Send-JsonLine -Stream $Stream -Object @{ type = "pair_response"; status = "rejected" }
        return
    }

    # The secret is derived from this connection's DH exchange; it never crosses the wire
    $secret = Get-PairingSecret -DHKey $Session.DHKey -Transcript $Session.Transcript
    Set-PairedClient -Pairings $Session.Pairings -ClientId $Session.ClientId -Secret $secret -RemoteEndpoint $RemoteEndpoint

    # Encrypting the approval with the new session key proves to the client we derived the same secret
    $sessionKey = Get-SessionKey -Secret $secret -Transcript $Session.Transcript
    Send-EncryptedJsonLine -Stream $Stream -KeyBytes $sessionKey -Object @{ type = "pair_response"; status = "approved" }
}

function Handle-Authentication {
    [CmdletBinding()]
    param(
        [System.Net.Sockets.NetworkStream]$Stream,
        [hashtable]$Session,
        [string]$RemoteEndpoint
    )
    # Returns the session key for an authenticated connection, otherwise $null
    # (pairing requests also return $null: a pairing connection carries no command).
    
    try {
        $line = Read-StreamLine -Stream $Stream
        if (-not $line) {
            throw "No authentication message received"
        }

        if ($Session.IsPairing) {
            $msg = $line | ConvertFrom-Json
            if ($msg.type -ne "pair_request") {
                throw "Expected pair_request, got '$($msg.type)'"
            }
            $revealed = [string]$msg.public_key_str
            $sha256 = [System.Security.Cryptography.SHA256]::Create()
            $revealedHash = ConvertTo-HexString -Bytes $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($revealed))
            $sha256.Dispose()
            if ($revealedHash -cne $Session.Commit) {
                throw "Revealed public key does not match the commitment"
            }
            Complete-DHSession -Session $Session -ClientPublicStr $revealed
            Handle-PairRequest -Stream $Stream -Session $Session -RemoteEndpoint $RemoteEndpoint
            return $null
        }

        if (-not (Test-EncryptedMessage -Data $line)) {
            throw "Unencrypted message on an authentication connection"
        }

        if (-not $Session.Secret) {
            Send-JsonLine -Stream $Stream -Object @{ type = "auth_response"; status = "rejected"; message = "Client not paired. Run on the client: nppair (netpaste.py --pair)" }
            throw "Client '$($Session.ClientId)' is not paired"
        }

        # Only a client holding the paired secret can derive this key; a man-in-the-middle cannot
        $sessionKey = Get-SessionKey -Secret $Session.Secret -Transcript $Session.Transcript
        $decrypted = Decrypt-DHData -EncryptedData $line -KeyBytes $sessionKey
        $authMsg = $null
        if ($decrypted) {
            try { $authMsg = $decrypted | ConvertFrom-Json } catch { $authMsg = $null }
        }
        if (-not $authMsg -or $authMsg.type -ne "auth") {
            Send-JsonLine -Stream $Stream -Object @{ type = "auth_response"; status = "rejected"; message = "Session key mismatch. Re-pair on the client: nppair (netpaste.py --pair)" }
            throw "Session key mismatch for client '$($Session.ClientId)'"
        }

        Write-Host "Authenticated client '$($Session.ClientId)'" -ForegroundColor Green
        Send-EncryptedJsonLine -Stream $Stream -KeyBytes $sessionKey -Object @{ type = "auth_response"; status = "accepted" }
        return ,$sessionKey
    }
    catch {
        Write-Host "Authentication failed: $($_.Exception.Message)" -ForegroundColor Red
        return $null
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
    
    $separatorItem1 = New-Object System.Windows.Forms.ToolStripSeparator
    $separatorItem2 = New-Object System.Windows.Forms.ToolStripSeparator

    $clearSecretItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $clearSecretItem.Text = "Clear Client Pairings"
    $clearSecretItem.add_Click({
        param($sender, $e)
        if (Clear-AllPairings) {
            [System.Windows.Forms.MessageBox]::Show(
                "All client pairings have been cleared. Each client must pair again with: netpaste --pair",
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
    $contextMenu.Items.Add($separatorItem1) | Out-Null
    $contextMenu.Items.Add($showItem) | Out-Null
    $contextMenu.Items.Add($hideItem) | Out-Null
    $contextMenu.Items.Add($separatorItem2) | Out-Null
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

# Add Win32 focus/window management API once
try {
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
            [DllImport("user32.dll")]
            public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
            [DllImport("user32.dll")]
            public static extern bool AllowSetForegroundWindow(int dwProcessId);
            [DllImport("user32.dll")]
            public static extern IntPtr GetForegroundWindow();
            [DllImport("user32.dll")]
            public static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);
            [DllImport("kernel32.dll")]
            public static extern uint GetCurrentThreadId();
            public static readonly IntPtr HWND_TOPMOST = new IntPtr(-1);
            public static readonly IntPtr HWND_NOTOPMOST = new IntPtr(-2);
            public const uint SWP_NOMOVE = 0x0002;
            public const uint SWP_NOSIZE = 0x0001;
        }
"@ -ErrorAction SilentlyContinue
} catch {
    # Type already exists, ignore
}

function Set-WindowForeground {
    param([IntPtr]$Handle)
    try {
        # Attach to the foreground window's thread to bypass Windows focus restrictions
        $foregroundHwnd = [Win32Focus]::GetForegroundWindow()
        $dummy = [uint32]0
        $foregroundThread = [Win32Focus]::GetWindowThreadProcessId($foregroundHwnd, [ref]$dummy)
        $ourThread = [Win32Focus]::GetCurrentThreadId()
        $attached = $false
        if ($foregroundThread -ne $ourThread) {
            $attached = [Win32Focus]::AttachThreadInput($ourThread, $foregroundThread, $true)
        }

        [Win32Console]::ShowWindow($Handle, 9) | Out-Null  # SW_RESTORE
        [Win32Focus]::BringWindowToTop($Handle) | Out-Null
        [Win32Focus]::SetForegroundWindow($Handle) | Out-Null
        # Temporarily set as topmost then remove to force to front
        [Win32Focus]::SetWindowPos($Handle, [Win32Focus]::HWND_TOPMOST, 0, 0, 0, 0,
            [Win32Focus]::SWP_NOMOVE -bor [Win32Focus]::SWP_NOSIZE) | Out-Null
        [Win32Focus]::SetWindowPos($Handle, [Win32Focus]::HWND_NOTOPMOST, 0, 0, 0, 0,
            [Win32Focus]::SWP_NOMOVE -bor [Win32Focus]::SWP_NOSIZE) | Out-Null

        if ($attached) {
            [Win32Focus]::AttachThreadInput($ourThread, $foregroundThread, $false) | Out-Null
        }
    } catch {
        # Best-effort focus
    }
}

function Show-ConsoleWindow {
    try {
        $consoleWindow = [Win32Console]::GetConsoleWindow()
        Set-WindowForeground -Handle $consoleWindow
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

function Show-TextInputDialog {
    param([string]$Prompt, [string]$RemoteEndpoint)

    try {
        # Create a Windows Forms dialog for text input
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing

        # Create form
        $form = New-Object System.Windows.Forms.Form
        $form.Text = "NetPaste - Text Input from $RemoteEndpoint"
        $form.Size = New-Object System.Drawing.Size(600, 400)
        $form.StartPosition = "CenterScreen"
        $form.TopMost = $true
        $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::Sizable

        # Create label
        $label = New-Object System.Windows.Forms.Label
        $label.Location = New-Object System.Drawing.Point(10, 10)
        $label.Size = New-Object System.Drawing.Size(560, 30)
        $label.Text = $Prompt

        # Create textbox
        $textBox = New-Object System.Windows.Forms.RichTextBox
        $textBox.Location = New-Object System.Drawing.Point(10, 45)
        $textBox.Size = New-Object System.Drawing.Size(560, 270)
        $textBox.Multiline = $true
        $textBox.AcceptsTab = $true
        $textBox.ScrollBars = "Both"
        $textBox.Font = New-Object System.Drawing.Font("Consolas", 11)
        $textBox.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor
                         [System.Windows.Forms.AnchorStyles]::Bottom -bor
                         [System.Windows.Forms.AnchorStyles]::Left -bor
                         [System.Windows.Forms.AnchorStyles]::Right

        # Create OK button
        $okButton = New-Object System.Windows.Forms.Button
        $okButton.Location = New-Object System.Drawing.Point(400, 325)
        $okButton.Size = New-Object System.Drawing.Size(80, 30)
        $okButton.Text = "OK"
        $okButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor
                           [System.Windows.Forms.AnchorStyles]::Right
        $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK

        # Create Cancel button
        $cancelButton = New-Object System.Windows.Forms.Button
        $cancelButton.Location = New-Object System.Drawing.Point(490, 325)
        $cancelButton.Size = New-Object System.Drawing.Size(80, 30)
        $cancelButton.Text = "Cancel"
        $cancelButton.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor
                               [System.Windows.Forms.AnchorStyles]::Right
        $cancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

        # Add controls to form
        $form.Controls.Add($label)
        $form.Controls.Add($textBox)
        $form.Controls.Add($okButton)
        $form.Controls.Add($cancelButton)
        $form.AcceptButton = $okButton
        $form.CancelButton = $cancelButton

        # Show dialog and get result
        $result = $form.ShowDialog()

        if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
            return @{success = $true; text = $textBox.Text}
        }
        return @{success = $false; cancelled = $true}
    }
    catch {
        # Fallback to console input
        Write-Host "`n=== TEXT INPUT REQUEST ===" -ForegroundColor Yellow
        Write-Host "From: $RemoteEndpoint" -ForegroundColor Cyan
        Write-Host "Prompt: $Prompt" -ForegroundColor Cyan
        Write-Host "Enter text (end with Ctrl+Z on a new line):" -ForegroundColor Yellow

        $inputText = @()
        while ($true) {
            $line = Read-Host
            if ($line -eq $null) { break }
            $inputText += $line
        }

        return @{success = $true; text = ($inputText -join "`n")}
    }
}

function Show-FilePickerDialog {
    param([string]$RemoteEndpoint)

    try {
        # Create OpenFileDialog
        Add-Type -AssemblyName System.Windows.Forms

        $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $openFileDialog.Title = "NetPaste - Select File to Send to $RemoteEndpoint"
        $openFileDialog.Filter = "All Files (*.*)|*.*"
        $openFileDialog.InitialDirectory = [Environment]::GetFolderPath('MyDocuments')

        $result = $openFileDialog.ShowDialog()

        if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
            $filePath = $openFileDialog.FileName

            # Read file and encode as base64
            try {
                $fileBytes = [System.IO.File]::ReadAllBytes($filePath)
                $base64Content = [Convert]::ToBase64String($fileBytes)
                $fileName = [System.IO.Path]::GetFileName($filePath)

                return @{
                    success = $true
                    filename = $fileName
                    content = $base64Content
                    filepath = $filePath
                }
            }
            catch {
                Write-Host "Error reading file: $_" -ForegroundColor Red
                return @{success = $false; error = "Failed to read file: $_"}
            }
        }
        return @{success = $false; cancelled = $true}
    }
    catch {
        Write-Host "Error showing file picker: $_" -ForegroundColor Red
        return @{success = $false; error = "Failed to show file picker: $_"}
    }
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
            # Regex to find a drive letter and an SSHFS-Win UNC path: \\sshfs\ (home-relative),
            # \\sshfs.r\ (root-relative), and the key-auth variants \\sshfs.k\ and \\sshfs.kr\
            if ($line -match '([A-Z]:)\s+\\\\sshfs(?:\.(?:kr|k|r))?\\(?<user>[^@\\]+)@(?<host>[\d\.\w\-]+)') {
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

    # Extract IP from remote endpoint (remove port) before any lookups
    if ($RemoteIP -match '^([^:]+):\d+$') {
        $RemoteIP = $Matches[1]
    }

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

    # Remove trailing slash if present (causes explorer to fail)
    $UnixPath = $UnixPath.TrimEnd('/')

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

    # If path points to a file, use its parent directory (explorer needs a directory)
    if ((Test-Path $windowsPath -PathType Leaf)) {
        $windowsPath = Split-Path $windowsPath -Parent
    }

    return $windowsPath
}

function Convert-UnixToWindowsFilePath {
    param(
        [string]$UnixPath,
        [string]$RemoteEndpoint = $null
    )

    # Remove trailing slash if present (causes file open to fail)
    $UnixPath = $UnixPath.TrimEnd('/')

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
        # Snapshot existing explorer window handles before launch
        $shell = New-Object -ComObject "Shell.Application"
        $beforeHwnds = @($shell.Windows() | ForEach-Object { $_.HWND })

        # Launch explorer (works for both local and network paths)
        Start-Process -FilePath "explorer.exe" -ArgumentList "`"$WindowsPath`""

        # Poll for the new window (up to 3 seconds)
        $newHwnd = $null
        for ($i = 0; $i -lt 30; $i++) {
            Start-Sleep -Milliseconds 100
            $afterHwnds = @($shell.Windows() | ForEach-Object { $_.HWND })
            $newHwnds = $afterHwnds | Where-Object { $_ -notin $beforeHwnds }
            if ($newHwnds) {
                $newHwnd = $newHwnds | Select-Object -First 1
                break
            }
        }

        if ($newHwnd) {
            Set-WindowForeground -Handle ([IntPtr]$newHwnd)
        }

        return $true
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

    # Path of the PowerShell executable running this script, so restarts keep the same version
    $script:PowerShellExe = (Get-Process -Id $PID).Path
    if (-not $script:PowerShellExe) { $script:PowerShellExe = "powershell.exe" }
    Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
        $script:parentShouldStop = $true
    } | Out-Null

    do {

        # Start child process with -Child flag, NoTray parameter, and NoEncrypt parameter, using the
        # same PowerShell host as the parent (powershell.exe 5.1 or pwsh.exe 7+)
        $noTrayParam = if ($NoTray) { " -NoTray" } else { "" }
        $noEncryptParam = if ($NoEncrypt) { " -NoEncrypt" } else { "" }
        $childProcess = Start-Process -FilePath $script:PowerShellExe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Port $Port -Child$noTrayParam$noEncryptParam" -NoNewWindow -PassThru -Wait

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
                    $sessionKey = $null

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
                            $session = Handle-DHHandshake -Stream $stream -HandshakeData $receivedText
                            if ($session) {
                                Write-Host "DH handshake successful" -ForegroundColor Green
                                
                                # Authenticate with the paired secret (or handle a pairing request)
                                $sessionKey = Handle-Authentication -Stream $stream -Session $session -RemoteEndpoint $remoteEndpoint
                                if (-not $sessionKey) {
                                    Write-Host "No authenticated session - closing connection" -ForegroundColor Yellow
                                    $client.Close()
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
                                    Write-Host "Decrypting data with session key..." -ForegroundColor Yellow
                                    $decryptedText = Decrypt-DHData -EncryptedData $receivedText -KeyBytes $sessionKey
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
                                    Write-Host "Rejected unencrypted data after authentication" -ForegroundColor Red
                                    $client.Close()
                                    continue
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
                        # Without a handshake there is no authentication: only allowed with -NoEncrypt
                        elseif (-not $NoEncrypt -or (Test-EncryptedMessage -Data $receivedText)) {
                            Write-Host "Rejected message from $remoteEndpoint without DH handshake and authentication" -ForegroundColor Red
                            $client.Close()
                            continue
                        }
                        else {
                            Write-Host "Processing unauthenticated message (-NoEncrypt)" -ForegroundColor Yellow
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
                            "get_text" {
                                Write-Host "Text input request received" -ForegroundColor Yellow
                                $prompt = if ($messageData.prompt) { $messageData.prompt } else { "Enter text:" }
                                $result = Show-TextInputDialog -Prompt $prompt -RemoteEndpoint $remoteEndpoint

                                # Send response back to client
                                if ($result.success) {
                                    $response = @{
                                        type = "text_response"
                                        status = "success"
                                        text = $result.text
                                    } | ConvertTo-Json -Compress
                                } elseif ($result.cancelled) {
                                    $response = @{
                                        type = "text_response"
                                        status = "cancelled"
                                    } | ConvertTo-Json -Compress
                                } else {
                                    $response = @{
                                        type = "text_response"
                                        status = "error"
                                        message = if ($result.error) { $result.error } else { "Unknown error" }
                                    } | ConvertTo-Json -Compress
                                }

                                # Encrypt and send response
                                $encryptedResponse = Encrypt-DHData -Data $response -KeyBytes $sessionKey
                                $responseBytes = [System.Text.Encoding]::UTF8.GetBytes($encryptedResponse + "`n")
                                $stream.Write($responseBytes, 0, $responseBytes.Length)
                                $stream.Flush()
                                Write-Host "Sent text response to client" -ForegroundColor Green
                            }
                            "get_file" {
                                Write-Host "File request received" -ForegroundColor Yellow
                                $result = Show-FilePickerDialog -RemoteEndpoint $remoteEndpoint

                                # Send response back to client
                                if ($result.success) {
                                    Write-Host "Sending file: $($result.filename) ($([Math]::Round($result.content.Length / 1024, 2)) KB)" -ForegroundColor Green
                                    $response = @{
                                        type = "file_response"
                                        status = "success"
                                        filename = $result.filename
                                        content = $result.content
                                    } | ConvertTo-Json -Compress
                                } elseif ($result.cancelled) {
                                    $response = @{
                                        type = "file_response"
                                        status = "cancelled"
                                    } | ConvertTo-Json -Compress
                                } else {
                                    $response = @{
                                        type = "file_response"
                                        status = "error"
                                        message = if ($result.error) { $result.error } else { "Unknown error" }
                                    } | ConvertTo-Json -Compress
                                }

                                # Encrypt and send response
                                $encryptedResponse = Encrypt-DHData -Data $response -KeyBytes $sessionKey
                                $responseBytes = [System.Text.Encoding]::UTF8.GetBytes($encryptedResponse + "`n")
                                $stream.Write($responseBytes, 0, $responseBytes.Length)
                                $stream.Flush()
                                Write-Host "Sent file response to client" -ForegroundColor Green
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
                                $windowsPath = Convert-UnixToWindowsFilePath -UnixPath $messageData.path -RemoteEndpoint $remoteEndpoint
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