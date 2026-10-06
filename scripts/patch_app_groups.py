#!/usr/bin/env python3
"""Inject one Foundation-only resolver into existing target files (no project changes)."""
from pathlib import Path
import sys

root = Path(sys.argv[1])
helper = Path(__file__).with_name('AppGroupResolver.swift').read_text()

def edit(name, old, new):
    path = root / name
    text = path.read_text()
    if text.count(old) != 1:
        raise RuntimeError(f'{name}: expected exactly one patch anchor: {old!r}')
    path.write_text(text.replace(old, new))

name = 'Library/Shared/AppConfiguration.swift'
edit(name, '        return value\n    }()\n\n    public static var teamID', '        #if os(iOS)\n            return AppGroupResolver.resolved?.id ?? value\n        #else\n            return value\n        #endif\n    }()\n\n    public static var teamID')
with (root / name).open('a') as f:
    f.write('\n' + helper)
edit('Library/Shared/FilePath.swift', 'public static let sharedDirectory = defaultSharedDirectory!', 'public static let sharedDirectory = AppGroupResolver.resolved?.url ?? AppGroupResolver.diagnosticDirectory')
edit('Library/Shared/ServiceSetup.swift', '        let options = LibboxSetupOptions()', '        #if os(iOS)\n            try AppGroupResolver.requireSharedContainer()\n        #endif\n        let options = LibboxSetupOptions()')
edit('Library/Network/ExtensionProvider.swift', '        let basePath: String', '        #if os(iOS)\n            try AppGroupResolver.requireSharedContainer()\n            if let requested = startOptions?["resolvedAppGroup"] as? String, requested != AppGroupResolver.resolved?.id {\n                throw ExtensionStartupError(AppGroupResolver.signingDiagnosis)\n            }\n        #endif\n        let basePath: String')
edit('Library/Network/ExtensionProfile.swift', '        guard let manager else { return }\n        try await fetchProfile()', '        #if os(iOS)\n            try AppGroupResolver.requireSharedContainer()\n        #endif\n        guard let manager else { return }\n        try await fetchProfile()')
edit('Library/Network/ExtensionProfile.swift', '        let profileID = await SharedPreferences.selectedProfileID.get()\n        guard let profile', '        #if os(iOS)\n            try AppGroupResolver.requireSharedContainer()\n            options["resolvedAppGroup"] = AppGroupResolver.resolved.map { NSString(string: $0.id) }\n        #endif\n        let profileID = await SharedPreferences.selectedProfileID.get()\n        guard let profile')
edit('SFI/ApplicationDelegate.swift', '        NSLog("Here I stand")', '        guard AppGroupResolver.resolved != nil else {\n            NSLog("%@", AppGroupResolver.signingDiagnosis)\n            return true\n        }\n        NSLog("Here I stand")')
edit('SFI/Application.swift', '        Task { @MainActor in', '        guard AppGroupResolver.resolved != nil else { return }\n        Task { @MainActor in')
edit('SFI/Application.swift', '            MainView()', '            if AppGroupResolver.resolved == nil {\n                VStack(spacing: 20) {\n                    Text("App Group signing required").font(.title2)\n                    Text(AppGroupResolver.signingDiagnosis).textSelection(.enabled)\n                }.padding()\n            } else {\n            MainView()')
edit('SFI/Application.swift', '                .environmentObject(taildropInbox)', '                .environmentObject(taildropInbox)\n            }')
for name in ['FileProviderExtension/FileProviderExtension.swift', 'WidgetExtension/WidgetTunnelControl.swift']:
    edit(name, '        return value\n    }()\n\n', '        return value\n    }()\n\n') if False else None
    text = (root / name).read_text()
    old = '''        guard let value = Bundle.main.object(forInfoDictionaryKey: "AppGroupIdentifier") as? String else {
            fatalError("Missing AppGroupIdentifier in Info.plist")
        }
        return value'''
    edit(name, old, '''        AppGroupResolver.resolved?.id ?? (Bundle.main.object(forInfoDictionaryKey: "AppGroupIdentifier") as? String ?? "")''')
    with (root / name).open('a') as f:
        f.write('\n' + helper)
edit('WidgetExtension/WidgetTunnelControl.swift', '        if started {', '        if started {\n            try AppGroupResolver.requireSharedContainer()')
edit('FileProviderExtension/FileProviderExtension.swift', 'let groupURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: Self.appGroupID)!', 'let groupURL = AppGroupResolver.resolved?.url ?? AppGroupResolver.diagnosticDirectory')
name = 'FileProviderExtension/FileProviderExtension.swift'
text = (root / name).read_text()
# Block every read/write/enumeration callback; the fallback only serves nonthrowing initialization.
anchors = [
    ('let progress = Progress(totalUnitCount: 1)', 'completionHandler(nil, NSError(domain: "AppGroupSigning", code: 1, userInfo: [NSLocalizedDescriptionKey: AppGroupResolver.signingDiagnosis]))'),
    ('let progress = Progress(totalUnitCount: 100)\n\n        let url = fileURL', 'completionHandler(nil, nil, NSError(domain: "AppGroupSigning", code: 1, userInfo: [NSLocalizedDescriptionKey: AppGroupResolver.signingDiagnosis]))'),
    ('let progress = Progress(totalUnitCount: 100)\n\n        let parentURL', 'completionHandler(nil, [], false, NSError(domain: "AppGroupSigning", code: 1, userInfo: [NSLocalizedDescriptionKey: AppGroupResolver.signingDiagnosis]))'),
    ('let progress = Progress(totalUnitCount: 100)\n\n        var currentURL', 'completionHandler(nil, [], false, NSError(domain: "AppGroupSigning", code: 1, userInfo: [NSLocalizedDescriptionKey: AppGroupResolver.signingDiagnosis]))'),
    ('let progress = Progress(totalUnitCount: 1)\n\n        let url = fileURL', 'completionHandler(NSError(domain: "AppGroupSigning", code: 1, userInfo: [NSLocalizedDescriptionKey: AppGroupResolver.signingDiagnosis]))'),
]
# The item anchor must be exact to avoid matching deletion too.
anchors[0] = ('let progress = Progress(totalUnitCount: 1)\n\n        if identifier', anchors[0][1])
for anchor, callback in anchors:
    first, *rest = anchor.split('\n\n')
    replacement = first + '\n        guard AppGroupResolver.resolved != nil else {\n            ' + callback + '\n            return progress\n        }'
    if rest:
        replacement += '\n\n' + rest[0]
    if text.count(anchor) != 1:
        raise RuntimeError(f'file provider anchor mismatch {anchor}')
    text = text.replace(anchor, replacement)
text = text.replace('        if containerItemIdentifier == .workingSet {', '        try AppGroupResolver.requireSharedContainer()\n        if containerItemIdentifier == .workingSet {')
(root / name).write_text(text)
print('AppGroup resolution, startup diagnosis, tunnel and file-provider guards injected')
