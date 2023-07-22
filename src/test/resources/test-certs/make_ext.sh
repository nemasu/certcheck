#!/usr/bin/bash
set -e
openssl req -newkey rsa:4096 -keyout ext_domain.tld.key -out ext_domain.tld.csr -config ext_cert.conf
openssl x509 -req -days 3650 -in ext_domain.tld.csr -extfile ext_cert.conf -CA domain.tld.crt -CAkey domain.tld.key -CAcreateserial -out ext_domain.tld.crt
openssl x509 -outform PEM -in ext_domain.tld.crt -out ext_domain.tld.pem
