#!/bin/bash
set -e

WARDEN_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_PATH="/Applications/Warden.app"

echo "Building Warden v0.3.0..."
cd "$WARDEN_DIR"

cargo build --release 2>&1

echo "Creating .app bundle..."
mkdir -p target/release/bundle/macos/Warden.app/Contents/MacOS
mkdir -p target/release/bundle/macos/Warden.app/Contents/Resources

cp target/release/warden target/release/bundle/macos/Warden.app/Contents/MacOS/warden

cat > target/release/bundle/macos/Warden.app/Contents/Info.plist << PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key><string>warden</string>
    <key>CFBundleIdentifier</key><string>com.dbalchunas.warden</string>
    <key>CFBundleName</key><string>Warden</string>
    <key>CFBundleDisplayName</key><string>Warden - MCP Security Gateway</string>
    <key>CFBundleVersion</key><string>0.3.0</string>
    <key>CFBundleShortVersionString</key><string>0.3.0</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>LSMinimumSystemVersion</key><string>11.0</string>
    <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
PLISTEOF

if [ -d "$APP_PATH" ]; then
    echo "Removing old Warden.app..."
    rm -rf "$APP_PATH"
fi

codesign --force --deep --sign - target/release/bundle/macos/Warden.app 2>/dev/null || true
echo "Installing to /Applications..."
cp -R target/release/bundle/macos/Warden.app "$APP_PATH"

echo "Done! Warden is installed at $APP_PATH"
echo "Open it with: open /Applications/Warden.app"
