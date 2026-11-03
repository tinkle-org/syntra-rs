#!/bin/sh
# Negative browser TLS lane ONLY, not a successful Syntra or Upgrade server.
# Uses the self-signed outputs of make-untrusted-cert.sh. Do not install them in
# any root store. The browser must reject before WebSocket.send (including M1).
set -eu
directory=${1:-target/syntra-browser-fixture}
test -f "$directory/untrusted-cert.pem"
test -f "$directory/untrusted-key.pem"
exec openssl s_server -accept 127.0.0.1:9443 -tls1_3 -quiet -www \
  -cert "$directory/untrusted-cert.pem" -key "$directory/untrusted-key.pem"
