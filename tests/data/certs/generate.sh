#!/bin/sh
# Regenerates the test PKCS#12 keystores. Password for all of them: 1234
# These are throwaway test keys; never use them for anything else.
set -eu
cd "$(dirname "$0")"
DAYS=7300
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Test CA
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$TMP/ca.key" -out ca.pem -days $DAYS \
  -subj "/C=ES/O=autofirma-rs/CN=autofirma-rs Test CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"

leaf() { # name keyopts subject
  openssl req -utf8 -newkey "$2" -nodes -keyout "$TMP/$1.key" -out "$TMP/$1.csr" -subj "$3"
  openssl x509 -req -in "$TMP/$1.csr" -CA ca.pem -CAkey "$TMP/ca.key" -CAcreateserial \
    -out "$TMP/$1.pem" -days $DAYS -extfile /dev/stdin <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,nonRepudiation
extendedKeyUsage=emailProtection
EXT
}

leaf rsa rsa:2048 "/C=ES/O=autofirma-rs/serialNumber=IDCES-99999999R/GN=JUAN/SN=ESPAÑOL/CN=ESPAÑOL ESPAÑOL JUAN - 99999999R"
leaf ec ec:"$(openssl ecparam -name prime256v1 -out "$TMP/p256.param" && echo "$TMP/p256.param")" "/C=ES/O=autofirma-rs/CN=Prueba EC P-256"

openssl pkcs12 -export -inkey "$TMP/rsa.key" -in "$TMP/rsa.pem" -certfile ca.pem -name "rsa" -passout pass:1234 -out rsa.p12
openssl pkcs12 -export -inkey "$TMP/ec.key" -in "$TMP/ec.pem" -certfile ca.pem -name "ec" -passout pass:1234 -out ec.p12
# Legacy encryption (RC2-40 / 3DES), as exported by older browsers and Windows.
openssl pkcs12 -export -legacy -inkey "$TMP/rsa.key" -in "$TMP/rsa.pem" -certfile ca.pem -name "rsa" -passout pass:1234 -out rsa-legacy.p12
rm -f ca.srl
