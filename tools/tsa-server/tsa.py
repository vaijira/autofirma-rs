"""Test timestamping authority (RFC 3161) for development and the e2e tests.

Answers POSTed `application/timestamp-query` requests with `openssl ts -reply`,
allowing any origin (CORS), as a browser app needs. Never use it for anything
but tests: the TSA key is generated on start and thrown away.

Usage: python3 tools/tsa-server/tsa.py [PORT]   (default 8091)
"""

import http.server
import os
import subprocess
import sys
import tempfile

WORK = tempfile.mkdtemp(prefix="afirma-tsa-")
KEY, CERT, CONFIG = (os.path.join(WORK, name) for name in ("tsa.key", "tsa.pem", "tsa.cnf"))


def setup():
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
         "-subj", "/C=ES/O=autofirma-rs/CN=autofirma-rs Test TSA",
         "-addext", "extendedKeyUsage=critical,timeStamping",
         "-keyout", KEY, "-out", CERT],
        check=True, capture_output=True)
    with open(os.path.join(WORK, "serial"), "w") as serial:
        serial.write("01\n")
    with open(CONFIG, "w") as config:
        config.write(f"""[ tsa ]
default_tsa = tsa1
[ tsa1 ]
serial = {os.path.join(WORK, "serial")}
crypto_device = builtin
signer_digest = sha256
default_policy = 1.2.3.4.1
other_policies = 0.4.0.2023.1.1
digests = sha256, sha384, sha512
accuracy = secs:1
ordering = no
tsa_name = yes
ess_cert_id_chain = no
ess_cert_id_alg = sha256
""")


class Handler(http.server.BaseHTTPRequestHandler):
    def cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(204)
        self.cors()
        self.end_headers()

    def do_POST(self):
        query = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        reply = subprocess.run(
            ["openssl", "ts", "-reply", "-config", CONFIG, "-queryfile", "/dev/stdin",
             "-signer", CERT, "-inkey", KEY, "-out", "/dev/stdout"],
            input=query, capture_output=True)
        if reply.returncode != 0:
            self.send_response(400)
            self.cors()
            self.end_headers()
            self.wfile.write(reply.stderr)
            return
        self.send_response(200)
        self.cors()
        self.send_header("Content-Type", "application/timestamp-reply")
        self.send_header("Content-Length", str(len(reply.stdout)))
        self.end_headers()
        self.wfile.write(reply.stdout)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8091
    setup()
    print(f"Test TSA on http://127.0.0.1:{port}/", flush=True)
    http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
