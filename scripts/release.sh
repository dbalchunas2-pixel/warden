#!/bin/bash
# One-command Warden release: bump version, build signed update artifacts, commit, push, upload to GitHub release + latest.json
# Usage: ./scripts/release.sh 0.3.2
set -e
VER=$1
if [ -z "$VER" ]; then echo "Usage: ./scripts/release.sh <version>"; exit 1; fi
cd "$(dirname "$0")/.."
export PATH=$HOME/.cargo/bin:$PATH
export TAURI_SIGNING_PRIVATE_KEY="$(cat $HOME/.tauri/warden-updater.key)"
export TAURI_SIGNING_PRIVATE_KEY_PASSWORD=''

python3 - << PY
import json, re
p='tauri.conf.json'; c=json.load(open(p)); c['version']='$VER'; json.dump(c,open(p,'w'),indent=2)
p='Cargo.toml'; s=open(p).read(); s=re.sub(r'version = "[0-9.]+"', 'version = "$VER"', s, count=1); open(p,'w').write(s)
print('Bumped to $VER')
PY

npx @tauri-apps/cli@2 build
# Bundler strips _CodeSignature: re-sign the app, then rebuild tar.gz from the SIGNED app and sign THAT.
codesign --force --deep --sign - target/release/bundle/macos/Warden.app
codesign -v --strict target/release/bundle/macos/Warden.app
(cd target/release/bundle/macos && rm -f Warden.app.tar.gz Warden.app.tar.gz.sig && tar -czf Warden.app.tar.gz Warden.app && npx --yes @tauri-apps/cli@2 signer sign -k "$TAURI_SIGNING_PRIVATE_KEY" --password "" Warden.app.tar.gz)

TARGZ=target/release/bundle/macos/Warden.app.tar.gz
SIG=target/release/bundle/macos/Warden.app.tar.gz.sig
DMG=$(ls "$(pwd)/target/release/bundle/dmg/"*.dmg | head -1)

git add -A && git commit -m "release v$VER" && git tag "v$VER" && git push origin main --tags

SIG_CONTENT=$(cat "$SIG")
TARGZ_NAME=$(basename "$TARGZ")
gh release create "v$VER" "$TARGZ" "$DMG" --title "Warden v$VER" --notes "Release $VER" --generate-notes

cat > /tmp/latest.json << JSON
{
  "version": "$VER",
  "pub_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "platforms": {
    "darwin-aarch64": {
      "signature": "$SIG_CONTENT",
      "url": "https://github.com/dbalchunas2-pixel/warden/releases/download/v$VER/$TARGZ_NAME"
    }
  }
}
JSON
gh release upload "v$VER" /tmp/latest.json --clobber
python3 -c "import json; json.load(open('/tmp/latest.json'))" && echo 'RELEASE COMPLETE: v$VER shipped with updater artifacts'
