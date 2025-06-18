#!/usr/bin/env bash

if [ -z "$1" ] || [[ ! "$1" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
  echo "Usage: $0 <[a-zA-Z_][a-zA-Z0-9_]*>"
  exit 1
fi

TMP_PRIV=$(mktemp)

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 > $TMP_PRIV

{
  echo "#ifndef PRIVATE_${1}_RSA_KEY_H"
  echo "#define PRIVATE_${1}_RSA_KEY_H"
  echo "#include <stdint.h>"
  openssl pkcs8 -topk8 -inform PEM -outform DER -nocrypt -in $TMP_PRIV | \
  xxd -i -n private_${1}_rsa_key    | \
  sed -e 's/unsigned char/uint8_t/'   \
      -e 's/unsigned int/uint32_t/'
  echo "#endif /* PRIVATE_${1}_RSA_KEY_H */"
} > private_${1}_rsa_key.h

{
  echo "#ifndef PUBLIC_${1}_RSA_KEY_H"
  echo "#define PUBLIC_${1}_RSA_KEY_H"
  echo "#include <stdint.h>"
  openssl rsa -in $TMP_PRIV -pubout -outform DER | \
  xxd -i -n public_${1}_rsa_key     | \
  sed -e 's/unsigned char/uint8_t/'   \
      -e 's/unsigned int/uint32_t/'
  echo "#endif /* PUBLIC_${1}_RSA_KEY_H */"
} > public_${1}_rsa_key.h

rm -f $TMP_PRIV