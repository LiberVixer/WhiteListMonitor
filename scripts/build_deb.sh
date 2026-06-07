#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGE_NAME="white-list-monitor"
VERSION="${WLM_VERSION:-0.1.0~alpha1}"
ARCH="${WLM_ARCH:-all}"

BUILD_ROOT="$PROJECT_ROOT/build/deb"
PKG_ROOT="$BUILD_ROOT/${PACKAGE_NAME}_${VERSION}_${ARCH}"
DIST_DIR="$PROJECT_ROOT/dist"
DEBIAN_DIR="$PKG_ROOT/DEBIAN"
PYTHON_DIST="$PKG_ROOT/usr/lib/python3/dist-packages"
DOC_DIR="$PKG_ROOT/usr/share/doc/$PACKAGE_NAME"

rm -rf "$PKG_ROOT"
mkdir -p "$DEBIAN_DIR"
mkdir -p "$PYTHON_DIST"
mkdir -p "$PKG_ROOT/usr/bin"
mkdir -p "$PKG_ROOT/usr/share/applications"
mkdir -p "$PKG_ROOT/usr/share/icons/hicolor/scalable/apps"
mkdir -p "$PKG_ROOT/usr/share/$PACKAGE_NAME/scripts"
mkdir -p "$DOC_DIR"
mkdir -p "$DIST_DIR"

sed \
    -e "s/@VERSION@/$VERSION/g" \
    -e "s/@ARCH@/$ARCH/g" \
    "$PROJECT_ROOT/packaging/debian/control.in" > "$DEBIAN_DIR/control"

install -m 0755 "$PROJECT_ROOT/packaging/debian/postinst" "$DEBIAN_DIR/postinst"
install -m 0755 "$PROJECT_ROOT/packaging/debian/postrm" "$DEBIAN_DIR/postrm"

sed -e "s/@VERSION@/$VERSION/g" \
    "$PROJECT_ROOT/packaging/debian/changelog.in" \
    | gzip -9n > "$DOC_DIR/changelog.gz"

mkdir -p "$PYTHON_DIST/white_list_monitor"
find "$PROJECT_ROOT/white_list_monitor" -maxdepth 1 -type f -name "*.py" \
    -exec install -m 0644 {} "$PYTHON_DIST/white_list_monitor/" \;

install -m 0755 "$PROJECT_ROOT/packaging/linux/white-list-monitor" "$PKG_ROOT/usr/bin/white-list-monitor"
install -m 0644 "$PROJECT_ROOT/config/white-list-monitor.desktop" "$PKG_ROOT/usr/share/applications/white-list-monitor.desktop"
install -m 0644 "$PROJECT_ROOT/icons/white-list-monitor.svg" "$PKG_ROOT/usr/share/icons/hicolor/scalable/apps/white-list-monitor.svg"

install -m 0644 "$PROJECT_ROOT/README.md" "$DOC_DIR/README.md"
install -m 0644 "$PROJECT_ROOT/LICENSE" "$DOC_DIR/copyright"

install -m 0644 "$PROJECT_ROOT/scripts/compact_sni_whitelist.py" "$PKG_ROOT/usr/share/$PACKAGE_NAME/scripts/compact_sni_whitelist.py"
install -m 0644 "$PROJECT_ROOT/scripts/import_sni_domains_from_files.py" "$PKG_ROOT/usr/share/$PACKAGE_NAME/scripts/import_sni_domains_from_files.py"
install -m 0644 "$PROJECT_ROOT/scripts/sync_sni_domain_pool.py" "$PKG_ROOT/usr/share/$PACKAGE_NAME/scripts/sync_sni_domain_pool.py"

find "$PKG_ROOT" -type d -exec chmod 0755 {} +
find "$PKG_ROOT" -type f -exec chmod go-w {} +

OUTPUT="$DIST_DIR/${PACKAGE_NAME}_${VERSION}_${ARCH}.deb"
dpkg-deb --build --root-owner-group "$PKG_ROOT" "$OUTPUT"

echo "$OUTPUT"
