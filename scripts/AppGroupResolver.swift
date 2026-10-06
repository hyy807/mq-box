import Foundation

// No SecTask/private API: inspect the signed executable, then let the OS validate access.
public enum AppGroupResolver {
    public static let signingDiagnosis = "Signing error: no shared App Group is accessible to the app and VPN extension. Re-sign the app and every extension with the same authorized App Group and packet-tunnel-provider entitlement. VPN is disabled; private storage is not used for tunnels."

    public static func groups(in data: Data) -> [String] {
        let bytes = [UInt8](data)
        func word(_ offset: Int, _ little: Bool = false) -> UInt32? {
            guard offset >= 0, offset <= bytes.count - 4 else { return nil }
            var value: UInt32 = 0
            for i in 0..<4 { value = (value << 8) | UInt32(bytes[offset + (little ? 3 - i : i)]) }
            return value
        }
        func wide(_ offset: Int) -> Int? {
            guard let hi = word(offset), let lo = word(offset + 4) else { return nil }
            let value = (UInt64(hi) << 32) | UInt64(lo)
            guard value <= UInt64(Int.max) else { return nil }
            return Int(value)
        }
        var base = 0
        var limit = bytes.count
        if let magic = word(0), magic == 0xcafebabe || magic == 0xcafebabf {
            guard let count = word(4), count <= 128 else { return [] }
            let stride = magic == 0xcafebabf ? 32 : 20
            var found = false
            for i in 0..<Int(count) {
                let entry = 8 + i * stride
                guard let cpu = word(entry) else { return [] }
                if cpu != 0x0100000c { continue }
                let offset = stride == 32 ? wide(entry + 8) : word(entry + 8).map { Int($0) }
                let size = stride == 32 ? wide(entry + 16) : word(entry + 12).map { Int($0) }
                guard let offset, let size, offset >= 0, size >= 32,
                      offset <= bytes.count, size <= bytes.count - offset else { return [] }
                base = offset
                limit = offset + size
                found = true
                break
            }
            if !found { return [] }
        }
        guard word(base, true) == 0xfeedfacf,
              let ncmds = word(base + 16, true), ncmds <= 65536,
              let commandBytes = word(base + 20, true),
              base + 32 <= limit, Int(commandBytes) <= limit - base - 32 else { return [] }
        let commandEnd = base + 32 + Int(commandBytes)
        var command = base + 32
        for _ in 0..<Int(ncmds) {
            guard command <= commandEnd - 8, let kind = word(command, true),
                  let size = word(command + 4, true), size >= 8,
                  Int(size) <= commandEnd - command else { return [] }
            if kind == 0x1d {
                guard size >= 16, let offset = word(command + 8, true),
                      let length = word(command + 12, true), Int(offset) <= limit - base,
                      Int(length) <= limit - base - Int(offset) else { return [] }
                let signature = base + Int(offset)
                let end = signature + Int(length)
                guard length >= 12, word(signature) == 0xfade0cc0,
                      let blobLength = word(signature + 4), blobLength >= 12,
                      Int(blobLength) <= end - signature,
                      let count = word(signature + 8), count <= 4096,
                      Int(count) <= (Int(blobLength) - 12) / 8 else { return [] }
                let blobEnd = signature + Int(blobLength)
                for i in 0..<Int(count) {
                    let entry = signature + 12 + i * 8
                    guard let slot = word(entry), let offset = word(entry + 4) else { return [] }
                    if slot != 5 { continue }
                    guard Int(offset) <= blobEnd - signature - 8 else { return [] }
                    let entitlement = signature + Int(offset)
                    guard word(entitlement) == 0xfade7171,
                          let length = word(entitlement + 4), length >= 8,
                          Int(length) <= blobEnd - entitlement else { return [] }
                    let xml = Data(bytes[(entitlement + 8)..<(entitlement + Int(length))])
                    guard let plist = try? PropertyListSerialization.propertyList(from: xml, format: nil) as? [String: Any] else { return [] }
                    return normalized(plist["com.apple.security.application-groups"] as? [String] ?? [])
                }
                return []
            }
            command += Int(size)
        }
        return []
    }

    private static func normalized(_ groups: [String]) -> [String] {
        Array(Set(groups.filter { $0.hasPrefix("group.") && $0.count > 6 && !$0.contains("*") })).sorted()
    }

    public static func candidates(in bundle: Bundle) -> [String] {
        if let executable = bundle.executableURL,
           let data = try? Data(contentsOf: executable, options: .mappedIfSafe) {
            let signed = groups(in: data)
            if !signed.isEmpty { return signed }
        }
        // A profile only supplies candidates, never proof of an entitlement grant.
        guard let url = bundle.url(forResource: "embedded", withExtension: "mobileprovision"),
              let data = try? Data(contentsOf: url), data.count <= 4 * 1024 * 1024,
              let start = data.range(of: Data("<?xml".utf8)),
              let end = data.range(of: Data("</plist>".utf8), in: start.lowerBound..<data.endIndex),
              let plist = try? PropertyListSerialization.propertyList(from: data.subdata(in: start.lowerBound..<end.upperBound), format: nil) as? [String: Any],
              let entitlements = plist["Entitlements"] as? [String: Any] else { return [] }
        return normalized(entitlements["com.apple.security.application-groups"] as? [String] ?? [])
    }

    public static func select(configured: String, candidates: [String], container: (String) -> URL?) -> (id: String, url: URL)? {
        for id in [configured] + normalized(candidates).filter({ $0 != configured }) {
            if !id.isEmpty, let url = container(id) { return (id, url) }
        }
        return nil
    }

    // All embedded processes use the app + packet tunnel pair, not their own differing list order.
    public static let resolved: (id: String, url: URL)? = {
        let current = Bundle.main
        let appURL = current.bundleURL.pathExtension == "appex"
            ? current.bundleURL.deletingLastPathComponent().deletingLastPathComponent() : current.bundleURL
        let app = Bundle(url: appURL) ?? current
        let tunnel = Bundle(url: appURL.appendingPathComponent("PlugIns/Extension.appex"))
        let appGroups = candidates(in: app)
        let tunnelGroups = tunnel.map { candidates(in: $0) } ?? []
        let common = appGroups.filter { tunnelGroups.contains($0) }
        let configured = app.object(forInfoDictionaryKey: "AppGroupIdentifier") as? String ?? ""
        // Preserve configured storage only when it is also granted to the tunnel.
        let preferred = (!appGroups.isEmpty || !tunnelGroups.isEmpty) && !common.contains(configured) ? "" : configured
        return select(configured: preferred, candidates: common) {
            FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: $0)
        }
    }()

    public static func requireSharedContainer() throws {
        guard resolved != nil else {
            throw NSError(domain: "AppGroupSigning", code: 1, userInfo: [NSLocalizedDescriptionKey: signingDiagnosis])
        }
    }

    // Used only to keep crash reporting / application diagnosis launchable, never for VPN operation.
    public static let diagnosticDirectory = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("SigningDiagnostics", isDirectory: true)
}
