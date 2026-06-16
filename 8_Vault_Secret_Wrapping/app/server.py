from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import ssl
import urllib.error
import urllib.request


class WrappingDemoHandler(SimpleHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/unwrap":
            self.send_error(404)
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            request_body = self.rfile.read(content_length)
            payload = json.loads(request_body or b"{}")

            vault_address = payload["vaultAddress"].rstrip("/")
            wrap_token = payload["wrapToken"]
            namespace = payload.get("namespace", "")

            vault_request = urllib.request.Request(
                f"{vault_address}/v1/sys/wrapping/unwrap",
                data=b"{}",
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "X-Vault-Token": wrap_token,
                },
            )

            if namespace:
                vault_request.add_header("X-Vault-Namespace", namespace)

            context = None
            if os.environ.get("VAULT_SKIP_VERIFY", "false").lower() == "true":
                context = ssl._create_unverified_context()

            with urllib.request.urlopen(vault_request, timeout=20, context=context) as response:
                self._send_json(response.status, response.read())
        except urllib.error.HTTPError as error:
            self._send_json(error.code, error.read())
        except Exception as error:
            self._send_json(500, json.dumps({"errors": [str(error)]}).encode("utf-8"))

    def _send_json(self, status_code, body):
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 8788), WrappingDemoHandler)
    print("Serving Vault wrapping demo at http://localhost:8788")
    server.serve_forever()