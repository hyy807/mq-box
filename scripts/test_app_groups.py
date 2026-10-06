#!/usr/bin/env python3
"""Generate real Mach-O/signature fixtures and execute the shipped Swift parser on macOS."""
from pathlib import Path
import plistlib
import struct
import subprocess
import tempfile

here = Path(__file__).parent
xml = plistlib.dumps({'com.apple.security.application-groups': ['group.z', 'group.a', 'group.z']})
entitlement = struct.pack('>II', 0xfade7171, len(xml) + 8) + xml
signature = struct.pack('>IIIII', 0xfade0cc0, 20 + len(entitlement), 1, 5, 20) + entitlement
header = struct.pack('<IIIIIIII', 0xfeedfacf, 0x0100000c, 0, 2, 1, 16, 0, 0)
command = struct.pack('<IIII', 0x1d, 16, 48, len(signature))
thin = header + command + signature
fat = struct.pack('>IIIIIII', 0xcafebabe, 1, 0x0100000c, 0, 28, len(thin), 0) + thin
fat64 = struct.pack('>IIIIQQII', 0xcafebabf, 1, 0x0100000c, 0, 40, len(thin), 0, 0) + thin
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    for name, data in [('thin', thin), ('fat', fat), ('fat64', fat64)]:
        (root / name).write_bytes(data)
    tests = r'''
let directory = URL(fileURLWithPath: CommandLine.arguments[1])
for name in ["thin", "fat", "fat64"] {
    let data = try Data(contentsOf: directory.appendingPathComponent(name))
    precondition(AppGroupResolver.groups(in: data) == ["group.a", "group.z"])
    for length in 0..<data.count {
        precondition(AppGroupResolver.groups(in: Data(data.prefix(length))).isEmpty)
    }
}
let data = try Data(contentsOf: directory.appendingPathComponent("thin"))
for offset in [16, 20, 36, 40, 44, 52, 56, 64, 72] {
    var corrupt = data
    for index in offset..<(offset + 4) { corrupt[index] = 255 }
    precondition(AppGroupResolver.groups(in: corrupt).isEmpty)
}
let container: (String) -> URL? = { ["group.a", "group.z"].contains($0) ? URL(fileURLWithPath: "/" + $0) : nil }
precondition(AppGroupResolver.select(configured: "group.z", candidates: ["group.a"], container: container)?.id == "group.z")
precondition(AppGroupResolver.select(configured: "group.old", candidates: ["group.z", "group.a"], container: container)?.id == "group.a")
precondition(AppGroupResolver.select(configured: "group.old", candidates: ["group.a"], container: { _ in nil }) == nil)
precondition(AppGroupResolver.select(configured: "", candidates: ["group.*"], container: container) == nil)
print("PASS: thin/fat/fat64 signed entitlement parsing, all truncated prefixes, malformed bounds, configured preservation, sorted fallback, denied containers")
'''
    source = root / 'main.swift'
    source.write_text((here / 'AppGroupResolver.swift').read_text() + tests)
    subprocess.run(['swift', str(source), str(root)], check=True)
