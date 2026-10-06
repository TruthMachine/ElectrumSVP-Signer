#!/bin/bash
set -e

# ============================================================
# ElectrumSVP Signer AppImage Build
#
# Built on Ubuntu 18.04 / GLIBC 2.27 for broad Linux
# compatibility, including TAILS and older distributions.
# ============================================================


# ===[ CONFIG ]===

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"

APPDIR="$PROJECT_DIR/appimage-build/ElectrumSVP-Signer.AppDir"

PYTHON_DIR="$HOME/AppImageBuild/python-3.9.13"
VENV_DIR="$HOME/AppImageBuild/py39-venv"

SRC_DIR="$PROJECT_DIR/electrumsv"
SIGNER_DIR="$PROJECT_DIR/signer"

APPIMAGE_TOOL="$PROJECT_DIR/appimagetool-x86_64.AppImage"
APPIMAGE_NAME="ElectrumSVP_Signer-x86_64.AppImage"

# Application icon.
# This is the 256x256 square ElectrumSVP Signer icon.
ICON="$SIGNER_DIR/electrumsvp-signer-icon.png"

QT5_DIR="$VENV_DIR/lib/python3.9/site-packages/PyQt5/Qt5"
SITE_PACKAGES="$VENV_DIR/lib/python3.9/site-packages"


# ===[ CHECK BUILD ENVIRONMENT ]===

echo
echo "========================================"
echo " ElectrumSVP Signer AppImage Builder"
echo "========================================"
echo

echo "=== Checking build environment ==="

for path in \
    "$PYTHON_DIR/bin/python3.9" \
    "$PYTHON_DIR/lib" \
    "$VENV_DIR/lib/python3.9/site-packages" \
    "$SRC_DIR" \
    "$SIGNER_DIR" \
    "$APPIMAGE_TOOL" \
    "$ICON"
do
    if [ ! -e "$path" ]; then
        echo
        echo "ERROR: Required path not found:"
        echo "  $path"
        exit 1
    fi
done

echo "✓ Python:"
"$PYTHON_DIR/bin/python3.9" --version

echo "✓ GLIBC:"
ldd --version | head -n1

echo "✓ Build environment OK"


# ===[ CLEAN APPDIR ]===

echo
echo "=== Cleaning AppDir ==="

rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr"

echo "✓ AppDir cleaned"


# ===[ REMOVE OLD BYTECODE ]===

echo
echo "=== Removing old Python bytecode ==="

find "$SIGNER_DIR" -name "*.pyc" -delete
find "$SIGNER_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

find "$SRC_DIR" -name "*.pyc" -delete
find "$SRC_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

echo "✓ Old bytecode removed"


# ===[ COPY PYTHON RUNTIME ]===

echo
echo "=== Copying Python runtime ==="

cp -a "$PYTHON_DIR/bin" "$APPDIR/usr/"
cp -a "$PYTHON_DIR/lib" "$APPDIR/usr/"
cp -a "$PYTHON_DIR/include" "$APPDIR/usr/"

echo "✓ Python runtime copied"


# ===[ PATCH PYTHON INTERPRETER ]===

echo
echo "=== Patching Python interpreter ==="

patchelf \
    --set-interpreter /lib64/ld-linux-x86-64.so.2 \
    "$APPDIR/usr/bin/python3.9" || true

echo "✓ Python interpreter patched"


# ===[ COPY PYTHON PACKAGES ]===

echo
echo "=== Copying Python packages ==="

mkdir -p "$APPDIR/usr/lib/python3.9/site-packages"

cp -a \
    "$SITE_PACKAGES/"* \
    "$APPDIR/usr/lib/python3.9/site-packages/"

echo "✓ Python packages copied"


# ===[ COPY SIGNER SOURCE ]===

echo
echo "=== Copying signer source ==="

cp -a \
    "$SIGNER_DIR" \
    "$APPDIR/"

echo "✓ Signer copied"


# ===[ COPY ELECTRUMSV SOURCE ]===

echo
echo "=== Copying ElectrumSV source ==="

cp -a \
    "$SRC_DIR" \
    "$APPDIR/"

echo "✓ ElectrumSV source copied"


# ===[ LIBRARY DIRECTORY ]===

mkdir -p "$APPDIR/usr/lib"


# ===[ CUSTOM SQLITE ]===

echo
echo "=== Copying SQLite ==="

if [ -d "$HOME/AppImageBuild/sqlite-install/lib" ]; then

    cp -av \
        "$HOME/AppImageBuild/sqlite-install/lib/libsqlite3.so"* \
        "$APPDIR/usr/lib/"

    echo "✓ Custom SQLite copied"

else

    echo "⚠ Custom SQLite directory not found."
    echo "  Continuing without custom SQLite."

fi


# ===[ MINIMAL CORE LIBRARIES ]===

echo
echo "=== Copying core libraries ==="

for lib in \
    libelf.so.1 \
    libz.so.1 \
    liblzma.so.5 \
    libbz2.so.1.0
do

    SRC_LIB=$(ldconfig -p 2>/dev/null |
        grep "$lib" |
        head -n1 |
        awk '{print $4}')

    if [ -n "$SRC_LIB" ] && [ -f "$SRC_LIB" ]; then

        cp -v \
            "$SRC_LIB" \
            "$APPDIR/usr/lib/"

    else

        echo "⚠ $lib not found"

    fi

done

echo "✓ Core libraries processed"


# ===[ GMP / SSL / LIBFFI ]===

echo
echo "=== Copying crypto/system libraries ==="

if [ -f /usr/lib/x86_64-linux-gnu/libgmp.so.10 ]; then

    cp \
        /usr/lib/x86_64-linux-gnu/libgmp.so.10 \
        "$APPDIR/usr/lib/"

fi

if [ -f /usr/lib/x86_64-linux-gnu/libssl.so.1.1 ]; then

    cp \
        /usr/lib/x86_64-linux-gnu/libssl.so.1.1 \
        "$APPDIR/usr/lib/"

fi

if [ -f /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1 ]; then

    cp \
        /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1 \
        "$APPDIR/usr/lib/"

fi

for lib in /usr/lib/x86_64-linux-gnu/libffi.so.*; do

    if [ -f "$lib" ]; then
        cp "$lib" "$APPDIR/usr/lib/"
    fi

done

echo "✓ Crypto/system libraries processed"


# ===[ QT5 + ICU ]===

echo
echo "=== Copying Qt5 and ICU libraries ==="

mkdir -p "$APPDIR/usr/lib/qt5/plugins"

if [ -d "$QT5_DIR/lib" ]; then

    cp -a \
        "$QT5_DIR"/lib/libQt5*.so* \
        "$APPDIR/usr/lib/"

    cp -a \
        "$QT5_DIR"/lib/libicu*.so* \
        "$APPDIR/usr/lib/" \
        2>/dev/null || true

    echo "✓ PyQt5 Qt libraries copied"

else

    echo "ERROR: PyQt5 Qt5 directory not found:"
    echo "  $QT5_DIR"
    exit 1

fi


# ===[ QT PLUGINS FROM PYQT5 ]===

echo
echo "=== Copying PyQt5 plugins ==="

if [ -d "$QT5_DIR/plugins" ]; then

    cp -a \
        "$QT5_DIR/plugins/"* \
        "$APPDIR/usr/lib/qt5/plugins/"

    echo "✓ PyQt5 plugins copied"

else

    echo "⚠ PyQt5 plugin directory not found"

fi


# ===[ SYSTEM QT PLUGINS ]===

echo
echo "=== Copying system Qt plugins ==="

SYSTEM_QT_PLUGINS="/usr/lib/x86_64-linux-gnu/qt5/plugins"

if [ -d "$SYSTEM_QT_PLUGINS/platforms" ]; then

    cp -a \
        "$SYSTEM_QT_PLUGINS/platforms" \
        "$APPDIR/usr/lib/qt5/plugins/"

fi

if [ -d "$SYSTEM_QT_PLUGINS/styles" ]; then

    cp -a \
        "$SYSTEM_QT_PLUGINS/styles" \
        "$APPDIR/usr/lib/qt5/plugins/"

fi

if [ -d "$SYSTEM_QT_PLUGINS/iconengines" ]; then

    cp -a \
        "$SYSTEM_QT_PLUGINS/iconengines" \
        "$APPDIR/usr/lib/qt5/plugins/"

fi

echo "✓ System Qt plugins processed"


# ===[ X11 / XCB LIBRARIES ]===

echo
echo "=== Copying X11/XCB libraries ==="

for pattern in \
    libxcb*.so* \
    libX11.so* \
    libX11-xcb.so* \
    libxkbcommon*.so* \
    libXrender.so* \
    libXrandr.so* \
    libXcursor.so* \
    libXfixes.so* \
    libXi.so* \
    libXext.so* \
    libXtst.so* \
    libSM.so* \
    libICE.so* \
    libGL.so*
do

    for lib in /usr/lib/x86_64-linux-gnu/$pattern; do

        if [ -f "$lib" ]; then
            cp -a "$lib" "$APPDIR/usr/lib/"
        fi

    done

done

echo "✓ X11/XCB libraries copied"


# ===[ QT PLATFORM PLUGIN ]===

echo
echo "=== Installing Qt platform plugin ==="

mkdir -p "$APPDIR/usr/plugins/platforms"

if [ -f "$QT5_DIR/plugins/platforms/libqxcb.so" ]; then

    cp \
        "$QT5_DIR/plugins/platforms/libqxcb.so" \
        "$APPDIR/usr/plugins/platforms/"

    echo "✓ PyQt5 libqxcb.so copied"

elif [ -f "$SYSTEM_QT_PLUGINS/platforms/libqxcb.so" ]; then

    cp \
        "$SYSTEM_QT_PLUGINS/platforms/libqxcb.so" \
        "$APPDIR/usr/plugins/platforms/"

    echo "✓ System libqxcb.so copied"

else

    echo "⚠ libqxcb.so not found"

fi


# ===[ DESKTOP FILE + ICON ]===

echo
echo "=== Installing desktop file and icon ==="

mkdir -p \
    "$APPDIR/usr/share/applications" \
    "$APPDIR/usr/share/icons/hicolor/256x256/apps"

# Copy the 256x256 Signer icon into the AppImage root.
cp \
    "$ICON" \
    "$APPDIR/electrumsvp-signer.png"

# Install the icon where desktop environments look for application icons.
cp \
    "$ICON" \
    "$APPDIR/usr/share/icons/hicolor/256x256/apps/electrumsvp-signer.png"

# Create the AppImage desktop entry.
cat > "$APPDIR/electrumsvp-signer.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=ElectrumSVP Signer
Comment=Offline Bitcoin SV transaction signer
Exec=AppRun
Icon=electrumsvp-signer
StartupWMClass=electrumsvp-signer
Categories=Finance;Security;
Terminal=false
EOF

# Also install the desktop entry in the standard location.
cp \
    "$APPDIR/electrumsvp-signer.desktop" \
    "$APPDIR/usr/share/applications/electrumsvp-signer.desktop"

echo "✓ Desktop file installed"
echo "✓ 256x256 icon installed"


# ===[ APPIMAGE LAUNCHER ]===

echo
echo "=== Creating AppRun ==="

cat > "$APPDIR/AppRun" <<'EOF'
#!/bin/bash

HERE="$(dirname "$(readlink -f "$0")")"

# ------------------------------------------------------------
# Bundled native libraries
# ------------------------------------------------------------

export LD_LIBRARY_PATH="$HERE/usr/lib:$HERE/usr/lib/python3.9:$HERE/usr/lib/python3.9/site-packages/pillow.libs:$LD_LIBRARY_PATH"


# ------------------------------------------------------------
# Bundled Python
# ------------------------------------------------------------

export PYTHONHOME="$HERE/usr"


# ------------------------------------------------------------
# Bundled Python packages
# ------------------------------------------------------------

export PYTHONPATH="$HERE/usr/lib/python3.9/site-packages:$HERE/electrumsv:$HERE"


# ------------------------------------------------------------
# Qt
# ------------------------------------------------------------

export QT_QPA_PLATFORM_PLUGIN_PATH="$HERE/usr/plugins/platforms"

export QT_PLUGIN_PATH="$HERE/usr/lib/qt5/plugins"


# ------------------------------------------------------------
# Launch signer
# ------------------------------------------------------------

exec "$HERE/usr/bin/python3.9" \
    -s \
    "$HERE/signer/signer_gui.py" \
    "$@"
EOF

chmod +x "$APPDIR/AppRun"

echo "✓ AppRun created"


# ===[ PATCH QT PLUGIN RPATHS ]===

echo
echo "=== Patching Qt plugin RPATHs ==="

find "$APPDIR/usr/plugins" \
    -type f \
    -name "*.so*" |
while read -r plugin
do

    patchelf \
        --remove-rpath \
        "$plugin" \
        2>/dev/null || true

    patchelf \
        --set-rpath '$ORIGIN/../../lib' \
        "$plugin" \
        2>/dev/null || true

done

find "$APPDIR/usr/lib/qt5/plugins" \
    -type f \
    -name "*.so*" |
while read -r plugin
do

    patchelf \
        --remove-rpath \
        "$plugin" \
        2>/dev/null || true

    patchelf \
        --set-rpath '$ORIGIN/../../..' \
        "$plugin" \
        2>/dev/null || true

done

echo "✓ Qt plugin RPATHs patched"


# ===[ PATCH PYTHON RUNTIME ]===

echo
echo "=== Patching Python runtime RPATHs ==="

find "$APPDIR/usr/bin" \
    -type f \
    -exec file {} \; |
    grep ELF |
    cut -d: -f1 |
while read -r elf_file
do

    patchelf \
        --remove-rpath \
        "$elf_file" \
        2>/dev/null || true

    patchelf \
        --set-rpath '$ORIGIN/../lib' \
        "$elf_file" \
        2>/dev/null || true

done

echo "✓ Python runtime RPATHs patched"


# ===[ PATCH NATIVE PYTHON EXTENSIONS ]===

echo
echo "=== Patching Python native extensions ==="

find "$APPDIR/usr/lib/python3.9/site-packages" \
    -type f \
    \( \
        -name "*.so" \
        -o -name "*.so.*" \
    \) |
while read -r elf_file
do

    if file "$elf_file" | grep -q ELF; then

        patchelf \
            --remove-rpath \
            "$elf_file" \
            2>/dev/null || true

        # site-packages is:
        #
        # usr/lib/python3.9/site-packages
        #
        # so ../../../ reaches usr/
        # and then /lib reaches bundled libraries.

        patchelf \
            --set-rpath '$ORIGIN/../../..' \
            "$elf_file" \
            2>/dev/null || true

    fi

done

echo "✓ Python extension RPATHs patched"


# ===[ VERIFY BUNDLED PYTHON ]===

echo
echo "========================================"
echo " Verifying bundled Python"
echo "========================================"

env \
    -u PYTHONPATH \
    PYTHONHOME="$APPDIR/usr" \
    LD_LIBRARY_PATH="$APPDIR/usr/lib:$APPDIR/usr/lib/python3.9" \
    "$APPDIR/usr/bin/python3.9" \
    -c "
import sys

print('Python:', sys.version)
print('Prefix:', sys.prefix)
print('Executable:', sys.executable)
"

echo "✓ Bundled Python works"


# ===[ VERIFY BUNDLED IMPORTS ]===

echo
echo "========================================"
echo " Verifying bundled dependencies"
echo "========================================"

env \
    -u PYTHONPATH \
    PYTHONHOME="$APPDIR/usr" \
    PYTHONPATH="$APPDIR/usr/lib/python3.9/site-packages:$APPDIR/electrumsv:$APPDIR" \
    LD_LIBRARY_PATH="$APPDIR/usr/lib:$APPDIR/usr/lib/python3.9" \
    "$APPDIR/usr/bin/python3.9" \
    -c "
import qrcode
import PyQt5
import zxingcpp
import dbus_next
import bitcoinx
import electrumsv

print('qrcode       OK')
print('PyQt5        OK')
print('zxingcpp     OK')
print('dbus_next    OK')
print('bitcoinx     OK')
print('electrumsv   OK')
"

echo "✓ Bundled imports OK"


# ===[ VERIFY SIGNER IMPORTS ]===

echo
echo "========================================"
echo " Verifying signer imports"
echo "========================================"

env \
    -u PYTHONPATH \
    PYTHONHOME="$APPDIR/usr" \
    PYTHONPATH="$APPDIR/usr/lib/python3.9/site-packages:$APPDIR/electrumsv:$APPDIR" \
    LD_LIBRARY_PATH="$APPDIR/usr/lib:$APPDIR/usr/lib/python3.9" \
    "$APPDIR/usr/bin/python3.9" \
    -c "
from signer.seed_generator import generate_recovery_phrase
from signer.transaction_signer import (
    parse_derivation_path,
    transaction_fingerprint,
    derive_private_key,
    review_transaction,
    sign_approved_transaction,
    offline_sign,
)
from signer.luks_manager import open_storage, close_storage
from signer.signer_protocol import (
    create_signing_request,
    apply_signing_response,
)

print('seed_generator          OK')
print('transaction_signer      OK')
print('luks_manager            OK')
print('signer_protocol         OK')
print('offline_sign            OK')
"

echo "✓ Signer imports OK"


# ===[ VERIFY ZXING NATIVE MODULE ]===

echo
echo "=== Checking bundled zxingcpp ==="

env \
    -u PYTHONPATH \
    PYTHONHOME="$APPDIR/usr" \
    PYTHONPATH="$APPDIR/usr/lib/python3.9/site-packages:$APPDIR/electrumsv:$APPDIR" \
    LD_LIBRARY_PATH="$APPDIR/usr/lib:$APPDIR/usr/lib/python3.9" \
    "$APPDIR/usr/bin/python3.9" \
    -c "
import zxingcpp
print(
    'zxingcpp:',
    getattr(zxingcpp, '__version__', 'installed successfully')
)
"

echo "✓ zxingcpp check passed"


# ===[ VERIFY APPRUN ENVIRONMENT ]===

echo
echo "========================================"
echo " Verifying AppRun environment"
echo "========================================"

(
    cd /tmp

    env \
        -u PYTHONPATH \
        PYTHONHOME="$APPDIR/usr" \
        PYTHONPATH="$APPDIR/usr/lib/python3.9/site-packages:$APPDIR/electrumsv:$APPDIR" \
        LD_LIBRARY_PATH="$APPDIR/usr/lib:$APPDIR/usr/lib/python3.9" \
        "$APPDIR/usr/bin/python3.9" \
        -c "
import sys
import signer
import signer.signer_gui
import signer.transaction_signer
import signer.signer_protocol
import signer.luks_manager
import electrumsv
import zxingcpp
import PyQt5

print('Python:', sys.version.split()[0])
print('Signer:', signer.transaction_signer.__file__)
print('ElectrumSV:', electrumsv.__file__)
print('zxingcpp:', zxingcpp.__file__)
print('PyQt5:', PyQt5.__file__)


assert signer.signer_gui.__file__.startswith('$APPDIR/')
assert signer.transaction_signer.__file__.startswith('$APPDIR/')
assert signer.signer_protocol.__file__.startswith('$APPDIR/')
assert signer.luks_manager.__file__.startswith('$APPDIR/')
assert electrumsv.__file__.startswith('$APPDIR/')

print('AppDir environment OK')
    "
)

echo "✓ AppRun environment works"


# ===[ BUILD APPIMAGE ]===

echo
echo "========================================"
echo " Building AppImage"
echo "========================================"

cd "$PROJECT_DIR"

rm -f "$APPIMAGE_NAME"
rm -f "ElectrumSVP-Signer-x86_64.AppImage"

"$APPIMAGE_TOOL" "$APPDIR"

DEFAULT_APPIMAGE="ElectrumSVP-Signer-x86_64.AppImage"

if [ -f "$DEFAULT_APPIMAGE" ]; then

    cp \
        "$DEFAULT_APPIMAGE" \
        "$APPIMAGE_NAME"

elif [ -f "$APPIMAGE_NAME" ]; then

    echo "AppImage already has requested name."

else

    echo
    echo "ERROR: AppImage was not created."
    exit 1

fi


# ===[ FINAL RESULT ]===

echo
echo "========================================"
echo " AppImage build successful"
echo "========================================"
echo
echo "Output:"
echo "  $PROJECT_DIR/$APPIMAGE_NAME"
echo

ls -lh "$PROJECT_DIR/$APPIMAGE_NAME"

echo
echo "Build environment:"
echo "  Python: $("$PYTHON_DIR/bin/python3.9" --version 2>&1)"
echo "  GLIBC:  $(ldd --version 2>&1 | head -n1)"
echo
echo "✓ Done"
