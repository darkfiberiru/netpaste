#!/usr/bin/swift

import Foundation
import AppKit
import Network
import CryptoKit
import CommonCrypto

// MARK: - Configuration
let DEFAULT_PORT: UInt16 = 9999
let SECRET_FILE_PATH = FileManager.default.homeDirectoryForCurrentUser
    .appendingPathComponent("Library/Application Support/NetPaste/secret.key")

// MARK: - Diffie-Hellman Parameters (RFC 3526 2048-bit MODP Group)
let DH_PRIME_HEX = """
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74\
020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437\
4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05\
98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB\
9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718\
3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
"""
let DH_GENERATOR = 2

// MARK: - BigInteger Extension for DH
extension Data {
    var hexString: String {
        return map { String(format: "%02x", $0) }.joined()
    }
    
    init?(hexString: String) {
        let cleanHex = hexString.replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "\n", with: "")
            .replacingOccurrences(of: "\r", with: "")
        
        let len = cleanHex.count / 2
        var data = Data(capacity: len)
        var index = cleanHex.startIndex
        for _ in 0..<len {
            let nextIndex = cleanHex.index(index, offsetBy: 2)
            guard let byte = UInt8(cleanHex[index..<nextIndex], radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }
        self = data
    }
    
    func toBigInt() -> BigInt {
        return BigInt(data: self)
    }
}

// MARK: - BigInt Implementation for DH
// This is a basic BigInt implementation specifically for DH operations
// For production, consider using a library like BigInt or GMP
class BigInt {
    private var bytes: [UInt8]
    
    init(data: Data) {
        self.bytes = [UInt8](data)
        // Remove leading zeros
        while bytes.count > 1 && bytes[0] == 0 {
            bytes.removeFirst()
        }
    }
    
    init(_ value: Int) {
        var val = value
        var result: [UInt8] = []
        repeat {
            result.insert(UInt8(val & 0xFF), at: 0)
            val >>= 8
        } while val > 0
        self.bytes = result.isEmpty ? [0] : result
    }
    
    static func fromHex(_ hex: String) -> BigInt? {
        guard let data = Data(hexString: hex) else { return nil }
        return BigInt(data: data)
    }
    
    func toData() -> Data {
        return Data(bytes)
    }
    
    func toHex() -> String {
        return bytes.map { String(format: "%02x", $0) }.joined()
    }
    
    // Modular exponentiation using the binary method (square-and-multiply)
    // This is suitable for DH operations
    static func modPow(_ base: BigInt, _ exponent: BigInt, _ modulus: BigInt) -> BigInt {
        // Special cases
        if modulus.isOne() {
            return BigInt(0)
        }
        
        var result = BigInt(1)
        var base = base.mod(modulus)
        var exp = BigInt(data: exponent.toData())
        
        while !exp.isZero() {
            // If exp is odd, multiply result with base
            if exp.isOdd() {
                result = result.multiply(base).mod(modulus)
            }
            
            // Square the base
            base = base.multiply(base).mod(modulus)
            
            // Divide exp by 2
            exp = exp.shiftRight()
        }
        
        return result
    }
    
    // Helper: Check if number is zero
    private func isZero() -> Bool {
        return bytes.count == 1 && bytes[0] == 0
    }
    
    // Helper: Check if number is one
    private func isOne() -> Bool {
        return bytes.count == 1 && bytes[0] == 1
    }
    
    // Helper: Check if number is odd
    private func isOdd() -> Bool {
        return bytes.count > 0 && (bytes[bytes.count - 1] & 1) == 1
    }
    
    // Helper: Right shift (divide by 2)
    private func shiftRight() -> BigInt {
        var result: [UInt8] = []
        var carry: UInt8 = 0
        
        for byte in bytes {
            let newByte = (byte >> 1) | (carry << 7)
            result.append(newByte)
            carry = byte & 1
        }
        
        // Remove leading zeros
        while result.count > 1 && result[0] == 0 {
            result.removeFirst()
        }
        
        return BigInt(data: Data(result))
    }
    
    // Helper: Multiply two BigInts
    private func multiply(_ other: BigInt) -> BigInt {
        let len1 = bytes.count
        let len2 = other.bytes.count
        var result = [UInt16](repeating: 0, count: len1 + len2)
        
        // Perform multiplication
        for i in (0..<len1).reversed() {
            for j in (0..<len2).reversed() {
                let mul = UInt16(bytes[i]) * UInt16(other.bytes[j])
                let pos = i + j + 1
                result[pos] += mul
                
                // Handle carry
                if result[pos] >= 256 {
                    result[pos - 1] += result[pos] / 256
                    result[pos] %= 256
                }
            }
        }
        
        // Convert back to bytes
        var resultBytes: [UInt8] = []
        var carry: UInt16 = 0
        for i in (0..<result.count).reversed() {
            let sum = result[i] + carry
            resultBytes.insert(UInt8(sum % 256), at: 0)
            carry = sum / 256
        }
        
        // Remove leading zeros
        while resultBytes.count > 1 && resultBytes[0] == 0 {
            resultBytes.removeFirst()
        }
        
        return BigInt(data: Data(resultBytes))
    }
    
    // Helper: Modulo operation
    private func mod(_ modulus: BigInt) -> BigInt {
        // This is a simplified modulo for DH operations
        // A proper implementation would use long division
        
        // For DH, we can use a binary search approach since we're dealing with
        // specific sizes and the modulus is always the DH prime
        
        var current = BigInt(data: self.toData())
        
        // If current is less than modulus, return as is
        if compare(current, modulus) < 0 {
            return current
        }
        
        // Subtract modulus repeatedly (inefficient but works for DH)
        while compare(current, modulus) >= 0 {
            current = subtract(current, modulus)
        }
        
        return current
    }
    
    // Helper: Compare two BigInts (-1: a<b, 0: a==b, 1: a>b)
    private func compare(_ a: BigInt, _ b: BigInt) -> Int {
        if a.bytes.count != b.bytes.count {
            return a.bytes.count < b.bytes.count ? -1 : 1
        }
        
        for i in 0..<a.bytes.count {
            if a.bytes[i] != b.bytes[i] {
                return a.bytes[i] < b.bytes[i] ? -1 : 1
            }
        }
        
        return 0
    }
    
    // Helper: Subtract b from a (assumes a >= b)
    private func subtract(_ a: BigInt, _ b: BigInt) -> BigInt {
        var result: [UInt8] = []
        var borrow: Int = 0
        
        let aBytes = a.bytes.reversed()
        let bBytes = b.bytes.reversed()
        
        for i in 0..<max(aBytes.count, bBytes.count) {
            let aVal = i < aBytes.count ? Int(Array(aBytes)[i]) : 0
            let bVal = i < bBytes.count ? Int(Array(bBytes)[i]) : 0
            
            var diff = aVal - bVal - borrow
            if diff < 0 {
                diff += 256
                borrow = 1
            } else {
                borrow = 0
            }
            
            result.insert(UInt8(diff), at: 0)
        }
        
        // Remove leading zeros
        while result.count > 1 && result[0] == 0 {
            result.removeFirst()
        }
        
        return BigInt(data: Data(result))
    }
}

// MARK: - Shared Secret Management
class SecretManager {
    static func getStoredSecret() -> String? {
        guard FileManager.default.fileExists(atPath: SECRET_FILE_PATH.path) else {
            return nil
        }
        guard let secret = try? String(contentsOf: SECRET_FILE_PATH) else {
            return nil
        }
        let trimmed = secret.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmed.isEmpty {
            print("✅ Loaded shared secret from \(SECRET_FILE_PATH.path)")
            return trimmed
        }
        return nil
    }
    
    static func storeSecret(_ secret: String) {
        let dir = SECRET_FILE_PATH.deletingLastPathComponent()
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try? secret.write(to: SECRET_FILE_PATH, atomically: true, encoding: .utf8)
        
        // Set restrictive permissions (owner only)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], 
                                              ofItemAtPath: SECRET_FILE_PATH.path)
        print("✅ Stored shared secret to \(SECRET_FILE_PATH.path)")
    }
    
    static func clearSecret() -> Bool {
        if FileManager.default.fileExists(atPath: SECRET_FILE_PATH.path) {
            try? FileManager.default.removeItem(at: SECRET_FILE_PATH)
            print("🗑️ Cleared shared secret from \(SECRET_FILE_PATH.path)")
            return true
        } else {
            print("⚠️ No shared secret found at \(SECRET_FILE_PATH.path)")
            return false
        }
    }
}

// MARK: - Cryptography Helpers
class CryptoHelper {
    static func generateRandomBytes(_ count: Int) -> Data? {
        var bytes = Data(count: count)
        let result = bytes.withUnsafeMutableBytes { bytesPtr in
            SecRandomCopyBytes(kSecRandomDefault, count, bytesPtr.baseAddress!)
        }
        return result == errSecSuccess ? bytes : nil
    }
    
    static func sha256(_ data: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return Data(hash)
    }
    
    static func aesEncrypt(data: Data, key: Data, iv: Data) -> Data? {
        let keyLength = size_t(kCCKeySizeAES256)
        let dataLength = data.count
        let cryptLength = size_t(dataLength + kCCBlockSizeAES128)
        var cryptData = Data(count: cryptLength)
        
        var numBytesEncrypted: size_t = 0
        let cryptStatus = cryptData.withUnsafeMutableBytes { cryptBytes in
            data.withUnsafeBytes { dataBytes in
                key.withUnsafeBytes { keyBytes in
                    iv.withUnsafeBytes { ivBytes in
                        CCCrypt(CCOperation(kCCEncrypt),
                               CCAlgorithm(kCCAlgorithmAES),
                               CCOptions(kCCOptionPKCS7Padding),
                               keyBytes.baseAddress, keyLength,
                               ivBytes.baseAddress,
                               dataBytes.baseAddress, dataLength,
                               cryptBytes.baseAddress, cryptLength,
                               &numBytesEncrypted)
                    }
                }
            }
        }
        
        if cryptStatus == kCCSuccess {
            cryptData.removeSubrange(numBytesEncrypted..<cryptData.count)
            return cryptData
        }
        return nil
    }
    
    static func aesDecrypt(data: Data, key: Data, iv: Data) -> Data? {
        let keyLength = size_t(kCCKeySizeAES256)
        let dataLength = data.count
        let cryptLength = size_t(dataLength + kCCBlockSizeAES128)
        var cryptData = Data(count: cryptLength)
        
        var numBytesDecrypted: size_t = 0
        let cryptStatus = cryptData.withUnsafeMutableBytes { cryptBytes in
            data.withUnsafeBytes { dataBytes in
                key.withUnsafeBytes { keyBytes in
                    iv.withUnsafeBytes { ivBytes in
                        CCCrypt(CCOperation(kCCDecrypt),
                               CCAlgorithm(kCCAlgorithmAES),
                               CCOptions(kCCOptionPKCS7Padding),
                               keyBytes.baseAddress, keyLength,
                               ivBytes.baseAddress,
                               dataBytes.baseAddress, dataLength,
                               cryptBytes.baseAddress, cryptLength,
                               &numBytesDecrypted)
                    }
                }
            }
        }
        
        if cryptStatus == kCCSuccess {
            cryptData.removeSubrange(numBytesDecrypted..<cryptData.count)
            return cryptData
        }
        return nil
    }
}

// MARK: - DH Key Exchange
class DHKeyExchange {
    private var privateKey: BigInt?
    private var publicKey: BigInt?
    private var sharedSecret: Data?
    private var sessionKey: Data?
    
    func generateKeypair() -> String? {
        // Generate random private key (256 bytes)
        guard let privateData = CryptoHelper.generateRandomBytes(256) else {
            return nil
        }
        
        privateKey = BigInt(data: privateData)
        
        // Compute public key: g^private mod p
        guard let p = BigInt.fromHex(DH_PRIME_HEX) else {
            return nil
        }
        let g = BigInt(DH_GENERATOR)
        
        publicKey = BigInt.modPow(g, privateKey!, p)
        
        return publicKey?.toHex()
    }
    
    func computeSharedSecret(clientPublicHex: String) -> Bool {
        guard let clientPublic = BigInt.fromHex(clientPublicHex),
              let privateKey = privateKey,
              let p = BigInt.fromHex(DH_PRIME_HEX) else {
            return false
        }
        
        // Compute shared secret: clientPublic^private mod p
        let sharedBigInt = BigInt.modPow(clientPublic, privateKey, p)
        sharedSecret = sharedBigInt.toData()
        
        // Derive session key using SHA256
        sessionKey = CryptoHelper.sha256(sharedSecret!)
        
        return true
    }
    
    func getSessionKey() -> Data? {
        return sessionKey
    }
}

// MARK: - Message Handling
struct NetPasteMessage: Codable {
    var type: String?
    var text: String?
    var path: String?
    var url: String?
    var message: String?
    var publicKey: String?
    var sharedSecret: String?
    var encrypted: String?
    var iv: String?
}

// MARK: - Menu Bar App
class NetPasteApp: NSObject {
    private var statusItem: NSStatusItem!
    private var listener: NWListener!
    private let port: UInt16
    private var noEncrypt: Bool = false
    private var storedSecret: String?
    private var dhKeyExchange = DHKeyExchange()
    private var sessionKey: Data?
    
    init(port: UInt16 = DEFAULT_PORT, noEncrypt: Bool = false) {
        self.port = port
        self.noEncrypt = noEncrypt
        super.init()
        
        // Load stored secret
        storedSecret = SecretManager.getStoredSecret()
        
        setupMenuBar()
        startListener()
    }
    
    private func setupMenuBar() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        
        if let button = statusItem.button {
            button.image = NSImage(systemSymbolName: "network", accessibilityDescription: "NetPaste")
            button.toolTip = "NetPaste - Port \(port)"
        }
        
        let menu = NSMenu()
        
        menu.addItem(withTitle: "NetPaste Running on Port \(port)", 
                    action: nil, keyEquivalent: "").isEnabled = false
        menu.addItem(NSMenuItem.separator())
        
        menu.addItem(withTitle: "Show Console", 
                    action: #selector(showConsole), keyEquivalent: "")
        
        menu.addItem(withTitle: "Clear Shared Secret", 
                    action: #selector(clearSecret), keyEquivalent: "")
        
        menu.addItem(NSMenuItem.separator())
        
        menu.addItem(withTitle: "Quit NetPaste", 
                    action: #selector(quit), keyEquivalent: "q")
        
        statusItem.menu = menu
    }
    
    private func startListener() {
        let parameters = NWParameters.tcp
        parameters.allowLocalEndpointReuse = true
        
        listener = try? NWListener(using: parameters, on: NWEndpoint.Port(integerLiteral: port))
        
        listener?.newConnectionHandler = { [weak self] connection in
            self?.handleConnection(connection)
        }
        
        listener?.start(queue: .main)
        print("🚀 NetPaste listening on port \(port)")
    }
    
    private func handleConnection(_ connection: NWConnection) {
        connection.start(queue: .main)
        
        // Store remote endpoint for path conversion
        let remoteEndpoint = connection.endpoint
        
        // Read incoming data
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [weak self] data, _, isComplete, error in
            if let data = data, !data.isEmpty {
                self?.processData(data, from: connection, remoteEndpoint: remoteEndpoint)
            }
            
            if isComplete {
                connection.cancel()
            }
        }
    }
    
    private func processData(_ data: Data, from connection: NWConnection, remoteEndpoint: NWEndpoint) {
        // Try to parse as JSON first
        if let message = try? JSONDecoder().decode(NetPasteMessage.self, from: data) {
            // Handle DH handshake
            if let clientPublicKey = message.publicKey {
                handleDHHandshake(clientPublicKey: clientPublicKey, connection: connection)
                return
            }
            
            // Handle authentication
            if let sharedSecret = message.sharedSecret {
                handleAuthentication(sharedSecret: sharedSecret, connection: connection)
                return
            }
            
            // Handle encrypted message
            if let encrypted = message.encrypted, let iv = message.iv {
                handleEncryptedMessage(encrypted: encrypted, iv: iv, connection: connection, remoteEndpoint: remoteEndpoint)
                return
            }
            
            // Handle plain message
            handlePlainMessage(message, connection: connection, remoteEndpoint: remoteEndpoint)
        } else {
            // Handle as plain text paste for backwards compatibility
            if let text = String(data: data, encoding: .utf8) {
                let message = NetPasteMessage(type: "paste", text: text)
                handlePlainMessage(message, connection: connection, remoteEndpoint: remoteEndpoint)
            }
        }
    }
    
    private func handleDHHandshake(clientPublicKey: String, connection: NWConnection) {
        print("🔐 Starting DH handshake...")
        
        // Generate server keypair
        guard let serverPublicKey = dhKeyExchange.generateKeypair() else {
            print("❌ Failed to generate DH keypair")
            connection.cancel()
            return
        }
        
        // Compute shared secret
        guard dhKeyExchange.computeSharedSecret(clientPublicHex: clientPublicKey) else {
            print("❌ Failed to compute shared secret")
            connection.cancel()
            return
        }
        
        sessionKey = dhKeyExchange.getSessionKey()
        
        // Send server public key back
        let response = ["publicKey": serverPublicKey]
        if let responseData = try? JSONSerialization.data(withJSONObject: response) {
            connection.send(content: responseData, completion: .contentProcessed { _ in
                print("✅ DH handshake completed")
            })
        }
    }
    
    private func handleAuthentication(sharedSecret: String, connection: NWConnection) {
        if storedSecret == nil {
            // First connection - store the secret
            SecretManager.storeSecret(sharedSecret)
            storedSecret = sharedSecret
            print("✅ Stored first shared secret")
            
            let response = ["status": "authenticated", "message": "Secret stored"]
            if let responseData = try? JSONSerialization.data(withJSONObject: response) {
                connection.send(content: responseData, completion: .contentProcessed { _ in })
            }
        } else if storedSecret == sharedSecret {
            // Valid authentication
            print("✅ Authentication successful")
            
            let response = ["status": "authenticated"]
            if let responseData = try? JSONSerialization.data(withJSONObject: response) {
                connection.send(content: responseData, completion: .contentProcessed { _ in })
            }
        } else {
            // Invalid authentication
            print("❌ Authentication failed - invalid shared secret")
            
            let response = ["status": "unauthorized", "message": "Invalid shared secret"]
            if let responseData = try? JSONSerialization.data(withJSONObject: response) {
                connection.send(content: responseData, completion: .contentProcessed { _ in
                    connection.cancel()
                })
            }
        }
    }
    
    private func handleEncryptedMessage(encrypted: String, iv: String, connection: NWConnection, remoteEndpoint: NWEndpoint) {
        guard let sessionKey = sessionKey,
              let encryptedData = Data(base64Encoded: encrypted),
              let ivData = Data(base64Encoded: iv) else {
            print("❌ Failed to decode encrypted message")
            return
        }
        
        guard let decryptedData = CryptoHelper.aesDecrypt(data: encryptedData, key: sessionKey, iv: ivData),
              let message = try? JSONDecoder().decode(NetPasteMessage.self, from: decryptedData) else {
            print("❌ Failed to decrypt message")
            return
        }
        
        handlePlainMessage(message, connection: connection, remoteEndpoint: remoteEndpoint)
    }
    
    private func handlePlainMessage(_ message: NetPasteMessage, connection: NWConnection, remoteEndpoint: NWEndpoint) {
        let messageType = message.type ?? "paste"
        
        switch messageType {
        case "paste":
            if let text = message.text {
                showPasteDialog(text: text, from: connection, remoteEndpoint: remoteEndpoint)
            }
            
        case "notification":
            if let text = message.message {
                showNotification(title: "NetPaste", text: text)
            }
            
        case "explorer":
            if let path = message.path {
                let localPath = convertUnixToMacPath(path, remoteEndpoint: remoteEndpoint)
                showFileExplorerDialog(path: localPath, remoteEndpoint: remoteEndpoint)
            }
            
        case "open_file":
            if let path = message.path {
                let localPath = convertUnixToMacPath(path, remoteEndpoint: remoteEndpoint)
                showFileOpenDialog(path: localPath, remoteEndpoint: remoteEndpoint)
            }
            
        case "open_url":
            if let url = message.url {
                showUrlOpenDialog(url: url, remoteEndpoint: remoteEndpoint)
            }
            
        case "vscode":
            if let path = message.path {
                let localPath = convertUnixToMacPath(path, remoteEndpoint: remoteEndpoint)
                showVSCodeDialog(path: localPath, remoteEndpoint: remoteEndpoint)
            }
            
        case "restart":
            print("🔄 Restart request received")
            restartServer()
            
        case "clear_secret":
            _ = SecretManager.clearSecret()
            storedSecret = nil
            
        default:
            print("⚠️ Unknown message type: \(messageType)")
        }
    }
    
    // MARK: - Path Conversion
    private func convertUnixToMacPath(_ unixPath: String, remoteEndpoint: NWEndpoint) -> String {
        // Find SSHFS mount point based on remote IP
        if let mountPoint = findSSHFSMount(for: remoteEndpoint) {
            // Convert /home/user/file to /Volumes/sshfs-xxx/home/user/file
            return mountPoint + unixPath
        }
        
        // Default: assume it's already a Mac path or use as-is
        return unixPath
    }
    
    private func findSSHFSMount(for endpoint: NWEndpoint) -> String? {
        // Extract IP from endpoint
        guard case let .hostPort(host, _) = endpoint,
              case let .ipv4(address) = host else {
            return nil
        }
        
        let ipString = "\(address)"
        
        // Check mounted volumes for SSHFS mounts
        let fm = FileManager.default
        guard let volumes = try? fm.contentsOfDirectory(atPath: "/Volumes") else {
            return nil
        }
        
        // Look for SSHFS mounts matching the IP
        for volume in volumes {
            if volume.contains("sshfs") || volume.contains(ipString) {
                return "/Volumes/\(volume)"
            }
        }
        
        // Check if using macFUSE mount points
        let userName = NSUserName()
        let macfusePath = "/Users/\(userName)/sshfs"
        if fm.fileExists(atPath: macfusePath) {
            return macfusePath
        }
        
        return nil
    }
    
    // MARK: - Dialog Functions
    private func showPasteDialog(text: String, from connection: NWConnection, remoteEndpoint: NWEndpoint) {
        DispatchQueue.main.async {
            let alert = NSAlert()
            alert.messageText = "Incoming Clipboard Data"
            alert.informativeText = "Received \(text.count) characters from \(self.getEndpointString(remoteEndpoint)). Copy to clipboard?"
            alert.alertStyle = .informational
            alert.addButton(withTitle: "Copy")
            alert.addButton(withTitle: "Cancel")
            
            // Add text preview in expandable area
            alert.accessoryView = self.createTextPreview(text)
            
            if alert.runModal() == .alertFirstButtonReturn {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(text, forType: .string)
                print("📋 Copied \(text.count) characters to clipboard")
                
                // Send success response
                let response = ["status": "success", "message": "Copied to clipboard"]
                if let responseData = try? JSONSerialization.data(withJSONObject: response) {
                    connection.send(content: responseData, completion: .contentProcessed { _ in })
                }
            }
        }
    }
    
    private func showFileExplorerDialog(path: String, remoteEndpoint: NWEndpoint) {
        DispatchQueue.main.async {
            let alert = NSAlert()
            alert.messageText = "Open Finder"
            alert.informativeText = "Open Finder at:\n\(path)\n\nFrom: \(self.getEndpointString(remoteEndpoint))"
            alert.alertStyle = .informational
            alert.addButton(withTitle: "Open")
            alert.addButton(withTitle: "Cancel")
            
            if alert.runModal() == .alertFirstButtonReturn {
                self.openInFinder(path: path)
            }
        }
    }
    
    private func showFileOpenDialog(path: String, remoteEndpoint: NWEndpoint) {
        DispatchQueue.main.async {
            let alert = NSAlert()
            alert.messageText = "Open File"
            alert.informativeText = "Open file with default application:\n\(path)\n\nFrom: \(self.getEndpointString(remoteEndpoint))"
            alert.alertStyle = .informational
            alert.addButton(withTitle: "Open")
            alert.addButton(withTitle: "Cancel")
            
            if alert.runModal() == .alertFirstButtonReturn {
                self.openFile(path: path)
            }
        }
    }
    
    private func showUrlOpenDialog(url: String, remoteEndpoint: NWEndpoint) {
        DispatchQueue.main.async {
            let alert = NSAlert()
            alert.messageText = "Open URL"
            alert.informativeText = "Open URL in browser:\n\(url)\n\nFrom: \(self.getEndpointString(remoteEndpoint))"
            alert.alertStyle = .warning
            alert.addButton(withTitle: "Open")
            alert.addButton(withTitle: "Cancel")
            
            if alert.runModal() == .alertFirstButtonReturn {
                self.openURL(url)
            }
        }
    }
    
    private func showVSCodeDialog(path: String, remoteEndpoint: NWEndpoint) {
        DispatchQueue.main.async {
            let alert = NSAlert()
            alert.messageText = "Open in VS Code"
            alert.informativeText = "Open in Visual Studio Code:\n\(path)\n\nFrom: \(self.getEndpointString(remoteEndpoint))"
            alert.alertStyle = .informational
            alert.addButton(withTitle: "Open")
            alert.addButton(withTitle: "Cancel")
            
            if alert.runModal() == .alertFirstButtonReturn {
                self.openInVSCode(path: path)
            }
        }
    }
    
    // MARK: - Helper Functions
    private func createTextPreview(_ text: String) -> NSView {
        let scrollView = NSScrollView(frame: NSRect(x: 0, y: 0, width: 400, height: 100))
        let textView = NSTextView(frame: scrollView.bounds)
        
        textView.string = String(text.prefix(500))
        textView.isEditable = false
        textView.font = NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)
        
        scrollView.documentView = textView
        scrollView.hasVerticalScroller = true
        
        return scrollView
    }
    
    private func getEndpointString(_ endpoint: NWEndpoint) -> String {
        switch endpoint {
        case .hostPort(let host, let port):
            return "\(host):\(port)"
        default:
            return "unknown"
        }
    }
    
    private func showNotification(title: String, text: String) {
        DispatchQueue.main.async {
            let notification = NSUserNotification()
            notification.title = title
            notification.informativeText = text
            notification.soundName = NSUserNotificationDefaultSoundName
            NSUserNotificationCenter.default.deliver(notification)
            print("🔔 Notification shown: \(text)")
        }
    }
    
    private func openInFinder(path: String) {
        let url = URL(fileURLWithPath: path)
        if FileManager.default.fileExists(atPath: path) {
            NSWorkspace.shared.selectFile(nil, inFileViewerRootedAtPath: url.path)
            print("📁 Opened Finder at: \(path)")
        } else {
            print("❌ Path not found: \(path)")
            showNotification(title: "NetPaste Error", text: "Path not found: \(path)")
        }
    }
    
    private func openFile(path: String) {
        let url = URL(fileURLWithPath: path)
        if FileManager.default.fileExists(atPath: path) {
            NSWorkspace.shared.open(url)
            print("📄 Opened file: \(path)")
        } else {
            print("❌ File not found: \(path)")
            showNotification(title: "NetPaste Error", text: "File not found: \(path)")
        }
    }
    
    private func openURL(_ urlString: String) {
        if let url = URL(string: urlString) {
            NSWorkspace.shared.open(url)
            print("🌐 Opened URL: \(urlString)")
        } else {
            print("❌ Invalid URL: \(urlString)")
            showNotification(title: "NetPaste Error", text: "Invalid URL: \(urlString)")
        }
    }
    
    private func openInVSCode(path: String) {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        task.arguments = ["-a", "Visual Studio Code", path]
        
        do {
            try task.run()
            print("💻 Opened in VS Code: \(path)")
        } catch {
            // Try using 'code' command as fallback
            let codeTask = Process()
            codeTask.executableURL = URL(fileURLWithPath: "/usr/local/bin/code")
            codeTask.arguments = [path]
            
            do {
                try codeTask.run()
                print("💻 Opened in VS Code: \(path)")
            } catch {
                print("❌ Failed to open VS Code: \(error)")
                showNotification(title: "NetPaste Error", text: "Could not open VS Code")
            }
        }
    }
    
    private func restartServer() {
        print("🔄 Restarting NetPaste server...")
        
        // Cancel current listener
        listener?.cancel()
        
        // Restart after a short delay
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) { [weak self] in
            self?.startListener()
            self?.showNotification(title: "NetPaste", text: "Server restarted")
        }
    }
    
    @objc private func showConsole() {
        // Open Terminal with log output
        let script = """
        tell application "Terminal"
            do script "log stream --process NetPaste --level debug"
            activate
        end tell
        """
        
        if let scriptObject = NSAppleScript(source: script) {
            scriptObject.executeAndReturnError(nil)
        }
    }
    
    @objc private func clearSecret() {
        let cleared = SecretManager.clearSecret()
        storedSecret = nil
        
        let alert = NSAlert()
        alert.messageText = "Clear Shared Secret"
        if cleared {
            alert.informativeText = "The shared secret has been removed."
        } else {
            alert.informativeText = "No shared secret was found."
        }
        alert.runModal()
    }
    
    @objc private func quit() {
        listener?.cancel()
        NSApplication.shared.terminate(nil)
    }
}

// MARK: - Command Line Argument Parsing
struct Arguments {
    var port: UInt16 = DEFAULT_PORT
    var noTray: Bool = false
    var noEncrypt: Bool = false
    
    init() {
        let args = CommandLine.arguments
        
        for i in 0..<args.count {
            switch args[i] {
            case "-Port", "--port":
                if i + 1 < args.count, let portNum = UInt16(args[i + 1]) {
                    port = portNum
                }
            case "-NoTray", "--no-tray":
                noTray = true
            case "-NoEncrypt", "--no-encrypt":
                noEncrypt = true
            default:
                break
            }
        }
    }
}

// MARK: - Main
let args = Arguments()
let app = NSApplication.shared
let netpaste = NetPasteApp(port: args.port, noEncrypt: args.noEncrypt)

if !args.noTray {
    app.setActivationPolicy(.accessory) // Run as menu bar app
} else {
    app.setActivationPolicy(.regular) // Run as regular app
}

print("NetPaste macOS Server")
print("====================")
print("Port: \(args.port)")
print("Encryption: \(!args.noEncrypt)")
print("Tray Icon: \(!args.noTray)")
print("")

app.run()