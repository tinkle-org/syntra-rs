#!/bin/sh
# Negative TLS fixture only. NEVER installs a trust anchor or disables validation.
# These outputs must be rejected by the browser. Do not use for positive evidence.
set -eu
umask 077
directory=${1:-target/syntra-browser-fixture}
test -d "$directory"
test ! -e "$directory/untrusted-cert.pem"
test ! -e "$directory/untrusted-key.pem"
openssl req -x509 -newkey rsa:2048 -noenc -days 1 \
  -subj /CN=localhost -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  -keyout "$directory/untrusted-key.pem" -out "$directory/untrusted-cert.pem"
