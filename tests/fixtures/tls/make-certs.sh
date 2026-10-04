#!/bin/sh
# Generates the throwaway CA and localhost certificate that dog's TLS tests
# trust. They protect nothing real: they exist so the tests can run
# DNS-over-TLS and DNS-over-HTTPS servers on 127.0.0.1. They are valid for
# 100 years so the suite never starts failing on a calendar date, and the CA
# key is deleted so nothing else can ever be signed with it.
set -eu
cd "$(dirname "$0")"

openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -days 36500 -subj "/CN=dog test CA" -keyout ca.key -out ca.pem \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj "/CN=localhost" -keyout localhost.key -out localhost.csr

cat > localhost.ext <<'EOF'
subjectAltName=DNS:localhost,IP:127.0.0.1
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
EOF

openssl x509 -req -in localhost.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
    -days 36500 -extfile localhost.ext -out localhost.pem

rm -f ca.key ca.srl localhost.csr localhost.ext
