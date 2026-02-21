#!/usr/bin/env python3
#
# Copyrigth(c) 2026 Vladlen Popolitov vladlen@FreeBSD.org
#
# SPDX-License-Identifier: BSD-2-Clause
#
# Debug environment with imds_mock server
# # python3 imds_mock.py --config config.json --host 127.0.0.1 --port 8000
#

import argparse
import json
import time
import secrets
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from urllib.parse import urlparse

import traceback

TOKENS = {}
TOKENS_LOCK = threading.Lock()


def now():
    return time.time()


def generate_token():
    return secrets.token_hex(32)


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class IMDSHandler(BaseHTTPRequestHandler):

    server_version = "IMDSv2Mock/2.0"

    def log_message(self, format, *args):
        return

    def _log(self, status):
        print(f"{self.command} {self.path} -> {status}", flush=True)

    def _delay(self, path):
        cfg = self.server.config
        delay_ms = cfg.get("default_delay_ms", 0)
        per = cfg.get("endpoint_delay_ms", {})
        if path in per:
            delay_ms = per[path]
        if delay_ms > 0:
            time.sleep(delay_ms / 1000.0)

    def _force_status(self, path):
        return self.server.config.get("force_status", {}).get(path)

    def _send(self, status, body=None, content_type="text/plain"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        if body is not None:
            if isinstance(body, str):
                body = body.encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_header("Content-Length", "0")
            self.end_headers()
        self._log(status)

    def _validate_token(self):
        token = self.headers.get("X-aws-ec2-metadata-token")
        if not token:
            return False
        with TOKENS_LOCK:
            expiry = TOKENS.get(token)
        if not expiry:
            return False
        if now() > expiry:
            return False
        return True

    # ---------------- TOKEN ----------------

    def do_PUT(self):
        if self.path == "/latest/api/token":
            ttl_header = self.headers.get(
                "X-aws-ec2-metadata-token-ttl-seconds"
            )
            if not ttl_header:
                self._send(400)
                return
            try:
                ttl = int(ttl_header)
            except ValueError:
                self._send(400)
                return
            token = generate_token()
            with TOKENS_LOCK:
                TOKENS[token] = now() + ttl
            self._send(200, token)
            return
        self._send(404)

    # ---------------- GET ----------------

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        cfg = self.server.config

        self._delay(path)

        forced = self._force_status(path)
        if forced:
            self._send(forced)
            return

        if path.startswith("/latest/"):
            if not self._validate_token():
                self._send(401)
                return

        # -------- instance identity --------

        if path == "/latest/dynamic/instance-identity/document":
            doc = {
                "instanceId": cfg.get("instance_id"),
                "accountId": cfg.get("account_id"),
                "availabilityZone": cfg.get("availability_zone"),
                "region": cfg.get("region"),
                "architecture": cfg.get("architecture"),
                "instanceType": cfg.get("instance_type"),
            }
            self._send(200, json.dumps(doc), "application/json")
            return

        if path == "/latest/dynamic/instance-identity/signature":
            self._send(200, "FAKE_SIGNATURE")
            return

        # -------- meta-data listing --------

        if path == "/latest/meta-data/":
            entries = [
                "instance-id",
                "hostname",
                "local-hostname",
                "public-hostname",
                "local-ipv4",
                "public-ipv4",
                "mac",
                "placement/",
                "public-keys/",
                "network/",
            ]
            self._send(200, "\n".join(entries))
            return

        # -------- basic meta-data --------

        if path == "/latest/meta-data/instance-id":
            self._send(200, cfg.get("instance_id", ""))
            return

        if path == "/latest/meta-data/hostname":
            # meta_data.json -> hostname
            self._send(200, cfg.get("hostname", ""))
            return

        if path == "/latest/meta-data/public-hostname":
            # meta_data.json -> public_hostname
            self._send(200, cfg.get("public_hostname", ""))
            return

        if path == "/latest/meta-data/local-hostname":
            # meta_data.json -> local_hostname
            self._send(200, cfg.get("local_hostname", ""))
            return

        if path == "/latest/meta-data/local-ipv4":
            self._send(200, cfg.get("local_ipv4", ""))
            return

        if path == "/latest/meta-data/public-ipv4":
            self._send(200, cfg.get("public_ipv4", ""))
            return

        if path == "/latest/meta-data/mac":
            self._send(200, cfg.get("mac", ""))
            return

        if path == "/latest/meta-data/placement/":
            self._send(200, "availability-zone")
            return


        if path == "/latest/meta-data/placement/availability-zone":
            self._send(200, cfg.get("availability_zone", ""))
            return

        if path == "/latest/meta-data/public-keys/":
            keys = cfg.get("ssh_public_keys", [])
            if not keys:
                self._send(404)
                return
            indices = "\n".join(str(i)+'/' for i in range(len(keys)))
            self._send(200, indices)
            return

        if path.startswith("/latest/meta-data/public-keys/") \
                and not path.endswith("/openssh-key"):
            parts = path.split("/")
            try:
                idx = int(parts[4])
                key = cfg.get("ssh_public_keys", [])[idx]
                self._send(200, "openssh-key")
            except (ValueError, IndexError):
                traceback.print_exc()
                self._send(404)
            return


        if path.startswith("/latest/meta-data/public-keys/") \
                and path.endswith("/openssh-key"):
            parts = path.split("/")
            try:
                idx = int(parts[4])
                key = cfg.get("ssh_public_keys", [])[idx]
                self._send(200, key)
            except (ValueError, IndexError):
                traceback.print_exc()
                self._send(404)
            return

        # -------- network subtree --------

        mac = cfg.get("mac", "")

        if path == "/latest/meta-data/network/":
            self._send(200, "interfaces/")
            return

        if path == "/latest/meta-data/network/interfaces/":
            self._send(200, "macs/")
            return

        if path == "/latest/meta-data/network/interfaces/macs/":
            self._send(200, f"{mac}/")
            return

        if path == f"/latest/meta-data/network/interfaces/macs/{mac}/":
            self._send(200, "device-number\nlocal-ipv4s")
            return

        if path == f"/latest/meta-data/network/interfaces/macs/{mac}/device-number":
            self._send(200, "0")
            return

        if path == f"/latest/meta-data/network/interfaces/macs/{mac}/local-ipv4s":
            self._send(200, cfg.get("local_ipv4", ""))
            return

        # -------- user-data --------

        if path == "/latest/user-data":
            self._send(200, cfg.get("user_data", ""))
            return
        print(path)
        self._send(404)


def load_config(path):
    with open(path, "r") as f:
        return json.load(f)


def main():
    parser = argparse.ArgumentParser(description="IMDSv2 mock v2.0")
    parser.add_argument("--config", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    config = load_config(args.config)

    server = ThreadedHTTPServer((args.host, args.port), IMDSHandler)
    server.config = config

    print(f"IMDSv2 mock v2.0 running on http://{args.host}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
