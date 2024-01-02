#!/bin/bash

# Generate a self-signed certificate using OpenSSL
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365 -subj "/C=PT/ST=Aveiro/L=Aveiro/O=UA/OU=UA/CN=localhost"

docker compose down
docker compose build
docker compose up -d

open https://localhost:8080