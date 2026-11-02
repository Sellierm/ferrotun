"""Fake PIA API for the e2e tests: token, getSignature, bindPort.

usage: python3 mock_pia.py <ip> <port> [cert.pem key.pem]
"""

import base64
import json
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

USERNAME, PASSWORD = "p1234567", "secret"
AUTH_TOKEN = "auth-token"
PF_TOKEN, PF_PORT, PF_EXPIRES = "pf-token", 40123, "2099-01-01T00:00:00Z"
# Compact JSON, like PIA.
PAYLOAD = base64.b64encode(
    json.dumps({"token": PF_TOKEN, "port": PF_PORT, "expires_at": PF_EXPIRES}, separators=(",", ":")).encode()
).decode()
SIGNATURE = "sig-ok"


class Handler(BaseHTTPRequestHandler):
    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if urlparse(self.path).path != "/api/client/v2/token":
            return self._json(404, {})
        length = int(self.headers.get("Content-Length", 0))
        form = parse_qs(self.rfile.read(length).decode())
        if form.get("username") == [USERNAME] and form.get("password") == [PASSWORD]:
            return self._json(200, {"token": AUTH_TOKEN})
        return self._json(401, {"message": "invalid credentials"})

    def do_GET(self):
        url = urlparse(self.path)
        q = parse_qs(url.query)
        if url.path == "/getSignature":
            if q.get("token") == [AUTH_TOKEN]:
                return self._json(200, {"status": "OK", "payload": PAYLOAD, "signature": SIGNATURE})
            return self._json(200, {"status": "ERROR", "message": "invalid token"})
        if url.path == "/bindPort":
            if q.get("payload") == [PAYLOAD] and q.get("signature") == [SIGNATURE]:
                return self._json(200, {"status": "OK", "message": "port scheduled for add"})
            return self._json(200, {"status": "ERROR", "message": "invalid payload or signature"})
        return self._json(404, {})

    def log_message(self, fmt, *args):
        sys.stderr.write("mock-pia: " + (fmt % args) + "\n")
        sys.stderr.flush()


server = ThreadingHTTPServer((sys.argv[1], int(sys.argv[2])), Handler)
if len(sys.argv) > 4:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(sys.argv[3], sys.argv[4])
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
server.serve_forever()
