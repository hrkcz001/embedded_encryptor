#!/usr/bin/env bash

function cleanup {
    echo $2 >&2
    rm -rf "$TMP_DIR"
    exit $1
}

for cmd in wget gpg tar make gcc nproc realpath autoconf automake libtool; do
    command -v "$cmd" >/dev/null 2>&1 || {
        echo "$cmd is not installed."
        exit 1
    }
done

WOLFSSL_580="wolfssl-5.8.0-stable"
WOLFSSL_580_TAR_ASC="https://github.com/wolfSSL/wolfssl/releases/download/v5.8.0-stable/wolfssl-5.8.0-stable.tar.gz.asc"
WOLFSSL_580_TAR="https://github.com/wolfSSL/wolfssl/archive/refs/tags/v5.8.0-stable.tar.gz"

TMP_DIR="$(mktemp -d)"
WOLFSSL_TARGET="$(dirname $(realpath $0))/wolfssl-5.8.0"

#WARN: configure: error: unrecognized options: --enable-opensslcompat
CONF_FLAGS="--enable-opensslextra  \
            --enable-opensslall    \
            --enable-rsa           \
            --enable-keygen        \
            --enable-ecc           \
            --enable-asn           \
            --enable-certgen       "

cd $TMP_DIR

wget -q -O asc-key $WOLFSSL_580_TAR_ASC || cleanup 1 "Failed to download wolfssl asc key"

wget -q -O tarball $WOLFSSL_580_TAR || cleanup 1 "Failed to download wolfssl tarball"

#WARN: https://github.com/wolfSSL/wolfssl/issues/8771
#gpg --verify asc-key tarball || cleanup 1 "Failed to verify wolfssl tarball"

mkdir wolfssl && cd wolfssl || cleanup 1 "Failed to create wolfssl directory"
tar -xzf ../tarball || cleanup 1 "Failed to extract wolfssl tarball"

cd $WOLFSSL_580 || cleanup 1 "Failed to change directory to $WOLFSSL_580"

rm -rf $WOLFSSL_TARGET 2>/dev/null
mkdir -p $WOLFSSL_TARGET || cleanup 1 "Failed to create wolfssl target directory"

./autogen.sh || cleanup 1 "Failed to run autogen.sh"
./configure $CONF_FLAGS "--prefix=$WOLFSSL_TARGET" || cleanup 1 "Failed to configure wolfssl"
make -j$(nproc) || cleanup 1 "Failed to build wolfssl"
make install && cleanup 0 "Successfully installed wolfssl" || cleanup 1 "Failed to install wolfssl"
