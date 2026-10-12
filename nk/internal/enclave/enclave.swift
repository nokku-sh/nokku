import CryptoKit
import Foundation
import Security

// Prehashed is a SHA-256 digest computed by the caller. CryptoKit only signs
// Digest values and has no way to build one from raw bytes.
private struct Prehashed: Digest {
    static var byteCount: Int { 32 }

    let bytes: [UInt8]

    var description: String { "prehashed SHA-256 digest" }

    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        try bytes.withUnsafeBytes(body)
    }

    func makeIterator() -> IndexingIterator<[UInt8]> { bytes.makeIterator() }
}

private struct BridgeError: Error, CustomStringConvertible {
    let description: String
}

// Key hides whether the private half lives in the enclave or in memory, so
// both run through the same bridge code.
private struct Key {
    let blob: Data
    let publicKey: Data
    let sign: (Prehashed) throws -> Data
}

private func enclaveKey(_ key: SecureEnclave.P256.Signing.PrivateKey) -> Key {
    Key(
        blob: key.dataRepresentation,
        publicKey: key.publicKey.x963Representation,
        sign: { try key.signature(for: $0).derRepresentation }
    )
}

// softwareKey exists for tests. CI runners are VMs without an enclave.
private func softwareKey(_ key: P256.Signing.PrivateKey) -> Key {
    Key(
        blob: key.rawRepresentation,
        publicKey: key.publicKey.x963Representation,
        sign: { try key.signature(for: $0).derRepresentation }
    )
}

private func createKey(software: Bool) throws -> Key {
    if software {
        return softwareKey(P256.Signing.PrivateKey())
    }
    // No user presence flag, so signing never prompts. Usable while the
    // screen is locked, because ssh sessions rekey in the background.
    var failure: Unmanaged<CFError>?
    guard
        let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, .privateKeyUsage, &failure)
    else {
        let reason = failure.map { String(describing: $0.takeRetainedValue()) } ?? "unknown error"
        throw BridgeError(description: "create access control: \(reason)")
    }
    return enclaveKey(try SecureEnclave.P256.Signing.PrivateKey(accessControl: access))
}

private func openKey(_ blob: Data, software: Bool) throws -> Key {
    if software {
        return softwareKey(try P256.Signing.PrivateKey(rawRepresentation: blob))
    }
    return enclaveKey(try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: blob))
}

// finish hands the result of body to C. The caller frees out and err.
private func finish(
    _ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ outLen: UnsafeMutablePointer<Int>,
    _ err: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>,
    _ body: () throws -> Data
) -> Int32 {
    do {
        let data = try body()
        guard let buf = malloc(max(data.count, 1)) else {
            throw BridgeError(description: "out of memory")
        }
        let bytes = buf.assumingMemoryBound(to: UInt8.self)
        data.copyBytes(to: bytes, count: data.count)
        out.pointee = bytes
        outLen.pointee = data.count
        return 0
    } catch {
        err.pointee = strdup(String(describing: error))
        return 1
    }
}

private func data(_ ptr: UnsafePointer<UInt8>?, _ len: Int) -> Data {
    Data(UnsafeBufferPointer(start: ptr, count: len))
}

@_cdecl("nk_enclave_available")
public func nkEnclaveAvailable() -> Int32 {
    SecureEnclave.isAvailable ? 1 : 0
}

@_cdecl("nk_enclave_create")
public func nkEnclaveCreate(
    _ software: Int32,
    _ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ outLen: UnsafeMutablePointer<Int>,
    _ err: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Int32 {
    finish(out, outLen, err) { try createKey(software: software != 0).blob }
}

@_cdecl("nk_enclave_public")
public func nkEnclavePublic(
    _ software: Int32,
    _ blob: UnsafePointer<UInt8>?,
    _ blobLen: Int,
    _ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ outLen: UnsafeMutablePointer<Int>,
    _ err: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Int32 {
    finish(out, outLen, err) { try openKey(data(blob, blobLen), software: software != 0).publicKey }
}

@_cdecl("nk_enclave_sign")
public func nkEnclaveSign(
    _ software: Int32,
    _ blob: UnsafePointer<UInt8>?,
    _ blobLen: Int,
    _ digest: UnsafePointer<UInt8>?,
    _ digestLen: Int,
    _ out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ outLen: UnsafeMutablePointer<Int>,
    _ err: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Int32 {
    finish(out, outLen, err) {
        guard digestLen == Prehashed.byteCount else {
            throw BridgeError(description: "digest is \(digestLen) bytes, want \(Prehashed.byteCount)")
        }
        let key = try openKey(data(blob, blobLen), software: software != 0)
        return try key.sign(Prehashed(bytes: Array(UnsafeBufferPointer(start: digest, count: digestLen))))
    }
}
