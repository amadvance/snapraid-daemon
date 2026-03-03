# Generate Key
openssl genrsa -out am_https.key 2048

# Generate CSR
openssl req -new -key am_https.key -out am_https.csr \
    -config am_openssl.cnf -subj "/C=IT/ST=Bergamo/L=Bergamo/O=Andrea Mazzoleni/CN=localhost"

# Sign with Root CA
openssl x509 -req -in am_https.csr -CA am_ca.crt -CAkey am_ca.key \
    -CAcreateserial -out am_https.crt -days 3650 -sha256 \
    -extfile am_openssl.cnf -extensions https_server_ext
