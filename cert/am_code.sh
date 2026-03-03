# Generate Key
openssl genrsa -out am_code.key 4096

# Generate CSR (Overriding ONLY the Common Name for this specific cert)
openssl req -new -key am_code.key -out am_code.csr \
    -config am_openssl.cnf -subj "/C=IT/ST=Bergamo/L=Bergamo/O=Andrea Mazzoleni/CN=Andrea Mazzoleni Code Signing"

# Sign with Root CA
openssl x509 -req -in am_code.csr -CA am_ca.crt -CAkey am_ca.key \
    -CAcreateserial -out am_code.crt -days 3650 -sha256 \
    -extfile am_openssl.cnf -extensions codesigning_ext

# Export to .p12 for Windows
openssl pkcs12 -export -out am_code.p12 -inkey am_code.key \
    -in am_code.crt -certfile am_ca.crt
    
