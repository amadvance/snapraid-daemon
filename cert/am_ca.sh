# Generate Key
openssl genrsa -out am_ca.key 4096

# Generate Root Cert (Uses 'commonName' from the .cnf)
openssl req -x509 -new -nodes -key am_ca.key -sha256 -days 3650 -config am_openssl.cnf -out am_ca.crt
