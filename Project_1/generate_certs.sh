#!/bin/bash
# Generate self-signed SSL certificate for testing

openssl req -x509 -newkey rsa:4096 \
    -keyout server.key \
    -out server.crt \
    -days 365 \
    -nodes \
    -subj "/C=US/ST=California/L=Los Angeles/O=UCLA/OU=CS118/CN=localhost"

echo "✓ Generated server.crt and server.key"
echo "These files are valid for 365 days"