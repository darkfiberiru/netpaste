#!/usr/bin/env pwsh
#Requires -Version 5.0

<#
.SYNOPSIS
    NetPaste PowerShell Client
.DESCRIPTION
    A PowerShell client for communicating with NetPaste.ps1 running on Windows.
    Supports clipboard paste and file explorer functionality with identical DH implementation.
.PARAMETER IP
    Windows machine IP (auto-detected from mosh if not specified)
.PARAMETER Port
    Port number (default: 9999)
.PARAMETER Text
    Text to paste to clipboard
.PARAMETER Explorer
    Path to open in file explorer (Unix path will be converted to F: drive). Uses current directory if no path specified.
.PARAMETER Open
    File path to open with default application (Unix path will be converted to F: drive)
.PARAMETER Url
    URL to open in default Windows browser
.PARAMETER Notify
    Send notification message to Windows
.PARAMETER Restart
    Restart the NetPaste PowerShell script
.PARAMETER Stdin
    Read text from stdin (default if no other action specified)
.PARAMETER ShowDebug
    Enable debug output
.EXAMPLE
    # Auto-detect Windows IP and paste text
    echo "Hello World" | ./np-client.ps1
.EXAMPLE
    # Paste specific text
    ./np-client.ps1 -Text "Some text to paste"
.EXAMPLE
    # Open file explorer at path
    ./np-client.ps1 -Explorer /home/user/documents
.EXAMPLE
    # Restart the PowerShell script
    ./np-client.ps1 -Restart
#>

[CmdletBinding()]
param(
    [string]$IP,
    [int]$Port = 9999,
    [string]$Text,
    [string]$Explorer,
    [string]$Open,
    [string]$Url,
    [string]$Notify,
    [switch]$Restart,
    [switch]$Stdin,
    [switch]$ShowDebug
)

# Load required assemblies
Add-Type -AssemblyName System.Numerics
Add-Type -AssemblyName System.Security

# Global debug flag
$script:VerboseOutput = $ShowDebug

# Diffie-Hellman parameters (RFC 3526 - 2048-bit MODP Group)
# Use exact decimal value that matches Python's hex conversion
$script:DH_P = [System.Numerics.BigInteger]::Parse("32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235796078236248884246189477587641105928646099411723245426622522193230540919037680524235519125679715870117001058055877651038861847280257976054903569732561526167081339361799541336476559160368317896729073178384589680639671900977202194168647225871031411336429319536193471636533209717077448227988588565369208645296636077250268955505928362751121174096972998068410554359584866583291642136218231078990999448652468262416972035911852507045361090559")
$script:DH_G = [System.Numerics.BigInteger]::new(2)

function Write-Log {
    param([string]$Message, [switch]$Force)
    
    if ($script:VerboseOutput -or $Force) {
        Write-Host $Message
    }
}

function Get-SHA256Hash {
    param([byte[]]$InputBytes)
    
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $hashBytes = $sha256.ComputeHash($InputBytes)
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
    Write-Log "DH Debug - Key generation verify: $($script:DH_G)^$($privateKey.ToString().Substring(0, 30))... = $($publicKey.ToString().Substring(0, 30))... (verify: $($verify.ToString().Substring(0, 30))...)"
    
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
    Write-Log "DH Debug - Computing: $($TheirPublicKey.ToString().Substring(0, 50))... ^ $($MyPrivateKey.ToString().Substring(0, 50))... mod P"
    Write-Log "DH Debug - DH_P: $($script:DH_P.ToString().Substring(0, 50))..."
    Write-Log "DH Debug - DH_G: $($script:DH_G)"
    
    # Test basic arithmetic
    $testResult = [System.Numerics.BigInteger]::ModPow(2, 3, 7)
    Write-Log "DH Debug - Test 2^3 mod 7 = $testResult (should be 1)"
    
    $sharedSecret = [System.Numerics.BigInteger]::ModPow($TheirPublicKey, $MyPrivateKey, $script:DH_P)
    
    # Debug: show actual shared secret value
    Write-Log "DH Debug - Shared secret decimal: $($sharedSecret.ToString().Substring(0, 50))...$($sharedSecret.ToString().Substring($sharedSecret.ToString().Length - 10))"
    Write-Log "DH Debug - Shared secret vs Prime comparison: secret < P = $($sharedSecret -lt $script:DH_P)"
    Write-Log "DH Debug - Prime length: $($script:DH_P.ToString().Length), Secret length: $($sharedSecret.ToString().Length)"
    
    # Convert BigInteger to fixed-size big-endian byte array (matching Python's to_bytes)
    $correctByteLength = 256 # 2048 bits
    $secretBytes = New-Object byte[] $correctByteLength
    
    # Get little-endian bytes from BigInteger
    $secretBytesRaw = $sharedSecret.ToByteArray()
    
    # Handle .NET sign byte and copy to fixed buffer
    $bytesToCopy = [System.Math]::Min($secretBytesRaw.Length, $correctByteLength)
    Write-Log "DH Debug - Raw bytes length: $($secretBytesRaw.Length), copying: $bytesToCopy"
    [System.Array]::Copy($secretBytesRaw, 0, $secretBytes, 0, $bytesToCopy)
    
    # Reverse the entire buffer to get the final big-endian representation
    [System.Array]::Reverse($secretBytes)

    Write-Log "DH Debug - Shared secret bytes length: $($secretBytes.Length)"
    
    # Hash the raw bytes with SHA-256
    $hashBytes = Get-SHA256Hash -InputBytes $secretBytes
    $hashHex = [System.BitConverter]::ToString($hashBytes) -replace '-', ''
    Write-Log "DH Debug - SHA256 hash: $hashHex"
    
    return $hashBytes
}

function Perform-DHExchange {
    [CmdletBinding()]
    param([System.Net.Sockets.NetworkStream]$Stream)
    
    Write-Log "Starting Diffie-Hellman key exchange..."
    
    # Generate our key pair
    $ourKeys = Generate-DHKeypair
    Write-Log "Generated DH keypair"
    
    Write-Host "DH Debug - Our private key: $($ourKeys.PrivateKey.ToString().Substring(0, 50))..."
    Write-Host "DH Debug - Our public key: $($ourKeys.PublicKey.ToString().Substring(0, 50))..."
    
    # Send handshake initiation - use string to avoid JSON precision loss
    $handshakeMsg = @{
        type = "dh_handshake"
        public_key_str = $ourKeys.PublicKey.ToString()
    }
    
    $jsonData = ($handshakeMsg | ConvertTo-Json -Compress) + "`n"
    Write-Host "DH Debug - Sending full JSON: $($jsonData.Trim())"
    $jsonBytes = [System.Text.Encoding]::UTF8.GetBytes($jsonData)
    $Stream.Write($jsonBytes, 0, $jsonBytes.Length)
    $Stream.Flush()
    Write-Log "Sent DH public key to server"
    
    # Receive server's public key
    $buffer = New-Object byte[] 4096
    $bytesRead = $Stream.Read($buffer, 0, $buffer.Length)
    $response = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $bytesRead).Trim()
    Write-Host "DH Debug - Received full response JSON: $response"
    
    $serverMsg = $response | ConvertFrom-Json
    
    if ($serverMsg.type -ne "dh_response") {
        throw "Invalid DH handshake response"
    }
    
    $serverPublicStr = $serverMsg.public_key_str
    $serverPublic = [System.Numerics.BigInteger]::Parse($serverPublicStr)
    Write-Host "DH Debug - Server public key string length: $($serverPublicStr.Length)"
    Write-Host "DH Debug - Server public key: $($serverPublic.ToString().Substring(0, 50))..."
    Write-Host "DH Debug - String precision preserved: $($serverPublicStr -eq $serverPublic.ToString())"
    Write-Log "Received server DH public key"
    
    # Cross-verification: compute what server should get using our values
    $crossVerify = [System.Numerics.BigInteger]::ModPow($ourKeys.PublicKey, 999, $script:DH_P)
    Write-Host "DH Debug - Cross-verify: our_public^999 = $($crossVerify.ToString().Substring(0, 30))..."
    
    # Compute shared secret
    $sharedSecret = Compute-DHSharedSecret -TheirPublicKey $serverPublic -MyPrivateKey $ourKeys.PrivateKey
    Write-Log "Computed shared secret"
    
    return $sharedSecret
}

function Encrypt-Data {
    [CmdletBinding()]
    param(
        [string]$Data,
        [byte[]]$Key
    )
    
    # Generate a random 16-byte IV
    $iv = New-Object byte[] 16
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($iv)
    $rng.Dispose()
    
    # Create AES cipher
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $Key
    $aes.IV = $iv
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    
    $encryptor = $aes.CreateEncryptor()
    
    # Convert data to bytes and encrypt
    $dataBytes = [System.Text.Encoding]::UTF8.GetBytes($Data)
    $ciphertext = $encryptor.TransformFinalBlock($dataBytes, 0, $dataBytes.Length)
    
    # Clean up
    $encryptor.Dispose()
    $aes.Dispose()
    
    # Return base64-encoded IV + ciphertext with prefix
    $combined = $iv + $ciphertext
    $base64Payload = [System.Convert]::ToBase64String($combined)
    return "NETPASTE_ENCRYPTED:$base64Payload"
}

function Get-WindowsIP {
    # Extract Windows IP from mosh connection logs in journalctl
    try {
        # Get current username
        $username = $env:USER
        if (-not $username) { $username = "unknown" }
        
        # Search journalctl for mosh-server connections for this user
        $result = & journalctl --grep "user $username connected from host" --output cat --no-pager --quiet
        
        if ($LASTEXITCODE -ne 0) {
            Write-Log "Error running journalctl command"
            return $null
        }
        
        # Look for the most recent connection
        $lines = $result -split "`n"
        for ($i = $lines.Length - 1; $i -ge 0; $i--) {
            $line = $lines[$i]
            if ($line -match "user $username connected from host:\s*(\d+\.\d+\.\d+\.\d+)") {
                $ip = $matches[1]
                Write-Log "Found most recent mosh connection from: $ip"
                return $ip
            }
        }
        
        Write-Log "No mosh connections found for user $username in journalctl"
        return $null
    }
    catch {
        Write-Log "Error running journalctl command: $($_.Exception.Message)"
        return $null
    }
}

function Send-ToNetPaste {
    [CmdletBinding()]
    param(
        [string]$Data,
        [string]$IP = $null,
        [int]$Port = 9999
    )
    
    if (-not $IP) {
        $IP = Get-WindowsIP
        if (-not $IP) {
            Write-Host "Could not determine Windows IP. Please specify with -IP" -ForegroundColor Red
            return $false
        }
    }
    
    try {
        Write-Host "Connecting to ${IP}:${Port}..."
        
        $client = [System.Net.Sockets.TcpClient]::new()
        $client.ReceiveTimeout = 10000  # 10 second timeout
        $client.SendTimeout = 10000
        $client.Connect($IP, $Port)
        
        $stream = $client.GetStream()
        
        Write-Host "Using Diffie-Hellman key exchange..."
        Write-Host "Original data to encrypt: '$($Data.Substring(0, [Math]::Min(100, $Data.Length)))$(if ($Data.Length -gt 100) { '...' } else { '' })'"
        
        try {
            $dhKey = Perform-DHExchange -Stream $stream
            $encryptedData = Encrypt-Data -Data $Data -Key $dhKey
            Write-Host "Encrypted payload: '$($encryptedData.Substring(0, [Math]::Min(100, $encryptedData.Length)))$(if ($encryptedData.Length -gt 100) { '...' } else { '' })'"
            $Data = $encryptedData
            Write-Host "Data encrypted with DH-derived key"
        }
        catch {
            Write-Host "DH exchange failed: $($_.Exception.Message)" -ForegroundColor Red
            return $false
        }
        
        # Send the data
        Write-Host "Sending payload: '$($Data.Substring(0, [Math]::Min(100, $Data.Length)))$(if ($Data.Length -gt 100) { '...' } else { '' })'"
        $dataBytes = [System.Text.Encoding]::UTF8.GetBytes($Data)
        $stream.Write($dataBytes, 0, $dataBytes.Length)
        $stream.Flush()
        
        # Give the server a moment to process
        Start-Sleep -Milliseconds 500
        
        # Clean up
        $stream.Close()
        $client.Close()
        
        Write-Host "Data sent successfully to ${IP}:${Port}"
        return $true
    }
    catch [System.Net.Sockets.SocketException] {
        if ($_.Exception.SocketErrorCode -eq 'TimedOut') {
            Write-Host "Connection to ${IP}:${Port} timed out" -ForegroundColor Red
        } elseif ($_.Exception.SocketErrorCode -eq 'ConnectionRefused') {
            Write-Host "Connection refused by ${IP}:${Port}. Is NetPaste.ps1 running?" -ForegroundColor Red
        } else {
            Write-Host "Socket error: $($_.Exception.Message)" -ForegroundColor Red
        }
        return $false
    }
    catch {
        Write-Host "Error sending data: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Send-Text {
    param([string]$Text, [string]$IP, [int]$Port)
    $textMessage = @{type = "paste"; text = $Text} | ConvertTo-Json -Compress
    return Send-ToNetPaste -Data $textMessage -IP $IP -Port $Port
}

function Send-Explorer {
    param([string]$Path, [string]$IP, [int]$Port)
    $explorerMessage = @{type = "explorer"; path = $Path} | ConvertTo-Json -Compress
    Write-Host "Sending explorer message: $explorerMessage"
    return Send-ToNetPaste -Data $explorerMessage -IP $IP -Port $Port
}

function Send-FileOpen {
    param([string]$Path, [string]$IP, [int]$Port)
    $fileMessage = @{type = "open_file"; path = $Path} | ConvertTo-Json -Compress
    Write-Host "Sending file open message: $fileMessage"
    return Send-ToNetPaste -Data $fileMessage -IP $IP -Port $Port
}

function Send-Url {
    param([string]$Url, [string]$IP, [int]$Port)
    $urlMessage = @{type = "open_url"; url = $Url} | ConvertTo-Json -Compress
    Write-Host "Sending URL open message: $urlMessage"
    return Send-ToNetPaste -Data $urlMessage -IP $IP -Port $Port
}

function Send-Notification {
    param([string]$Message, [string]$IP, [int]$Port)
    $notifyMessage = @{type = "notification"; message = $Message} | ConvertTo-Json -Compress
    Write-Host "Sending notification: $Message"
    return Send-ToNetPaste -Data $notifyMessage -IP $IP -Port $Port
}

function Send-Restart {
    param([string]$IP, [int]$Port)
    $restartMessage = @{type = "restart"} | ConvertTo-Json -Compress
    Write-Host "Sending restart request..."
    return Send-ToNetPaste -Data $restartMessage -IP $IP -Port $Port
}

function Read-FromStdin {
    param([string]$IP, [int]$Port)
    try {
        $data = [System.Console]::In.ReadToEnd()
        if (-not $data.Trim()) {
            Write-Host "No data received from stdin" -ForegroundColor Yellow
            return $false
        }
        return Send-Text -Text $data -IP $IP -Port $Port
    }
    catch {
        Write-Host "`nOperation cancelled" -ForegroundColor Yellow
        return $false
    }
}

# Main execution
$success = $false

# If no action specified and stdin is available, default to stdin
$hasAction = $Text -or $Explorer -or $Open -or $Url -or $Notify -or $Restart -or $Stdin
if (-not $hasAction) {
    if (-not [System.Console]::IsInputRedirected) {
        Write-Host @"
NetPaste PowerShell Core client - Send clipboard data or open file explorer on Windows

Usage:
  ./np-client.ps1 [-IP <ip>] [-Port <port>] [-Verbose] <action>

Actions:
  -Text <text>        Text to paste to clipboard
  -Explorer [<path>]  Path to open in file explorer (current dir if not specified)
  -Open <path>        File path to open with default application
  -Url <url>          URL to open in default Windows browser
  -Notify <message>   Send notification message to Windows
  -Restart            Restart the NetPaste PowerShell script
  -Stdin              Read text from stdin (default if no other action specified)

Examples:
  # Auto-detect Windows IP and paste text
  echo "Hello World" | ./np-client.ps1

  # Paste specific text
  ./np-client.ps1 -Text "Some text to paste"

  # Open file explorer at path
  ./np-client.ps1 -Explorer /home/user/documents

  # Restart the PowerShell script
  ./np-client.ps1 -Restart
"@
        exit 1
    } else {
        $Stdin = $true
    }
}

if ($Text) {
    $success = Send-Text -Text $Text -IP $IP -Port $Port
} elseif ($Explorer -ne $null) {
    # If Explorer is empty string (just -Explorer flag), use current directory
    $path = if ($Explorer -eq "") { Get-Location } else { $Explorer }
    $success = Send-Explorer -Path $path -IP $IP -Port $Port
} elseif ($Open) {
    $success = Send-FileOpen -Path $Open -IP $IP -Port $Port
} elseif ($Url) {
    $success = Send-Url -Url $Url -IP $IP -Port $Port
} elseif ($Notify) {
    $success = Send-Notification -Message $Notify -IP $IP -Port $Port
} elseif ($Restart) {
    $success = Send-Restart -IP $IP -Port $Port
} elseif ($Stdin) {
    $success = Read-FromStdin -IP $IP -Port $Port
}

exit $(if ($success) { 0 } else { 1 })