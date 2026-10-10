#!/usr/bin/env python3
"""Make SFI/MainView.swift compile for an iOS 15 deployment target.

`ToolbarContentBuilder.buildIf` (the `if` inside `.toolbar { }`) is only available
from iOS 16, so a 15.0 build fails with "'buildIf' is only available in iOS 16.0 or
newer". The condition has to move inside the ToolbarItem's own ViewBuilder, whose
`buildIf` is available from iOS 13.
"""
import sys
from pathlib import Path

OLD = """                .toolbar {
                    if remoteControlInToolbar, environments.remoteServer != nil || !remoteServers.isEmpty {
                        ToolbarItem(placement: .topBarLeading) {
                            remoteControlPicker
                        }
                        if #available(iOS 26.0, *) {
                            ToolbarSpacer(.fixed, placement: .topBarLeading)
                        }
                    }
                    ToolbarItem(placement: .topBarLeading) {
                        serviceToolbarItem
                    }
                }"""

NEW = """                .toolbar {
                    // iOS 15 target: ToolbarContentBuilder.buildIf needs iOS 16, so the
                    // condition lives in the item's ViewBuilder (buildIf is iOS 13+)
                    ToolbarItem(placement: .topBarLeading) {
                        if remoteControlInToolbar, environments.remoteServer != nil || !remoteServers.isEmpty {
                            remoteControlPicker
                        }
                    }
                    ToolbarItem(placement: .topBarLeading) {
                        serviceToolbarItem
                    }
                }"""


def patch(root: Path) -> bool:
    path = root / "SFI" / "MainView.swift"
    text = path.read_text()
    if NEW in text:
        print(f"{path}: already patched")
        return False
    if OLD not in text:
        raise SystemExit(f"{path}: expected toolbar block not found")
    path.write_text(text.replace(OLD, NEW, 1))
    print(f"{path}: patched")
    return True


if __name__ == "__main__":
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "sing-box-for-apple")
    patch(root)
