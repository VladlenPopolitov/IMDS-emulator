import threading
import time
import requests
import pytest

from imds_mock import ThreadedHTTPServer, IMDSHandler

#
# Copyrigth(c) 2026 Vladlen Popolitov vladlen@FreeBSD.org
#
# SPDX-License-Identifier: BSD-2-Clause
#


# ----------------------------
# Test server fixture
# ----------------------------

@pytest.fixture
def start_server():
    servers = []

    def _start(config):
        server = ThreadedHTTPServer(("127.0.0.1", 0), IMDSHandler)
        server.config = config

        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()

        # wait for server
        time.sleep(0.05)

        port = server.server_address[1]
        servers.append(server)
        return f"http://127.0.0.1:{port}"

    yield _start

    for s in servers:
        s.shutdown()


# ----------------------------
# Helper
# ----------------------------

def get_token(base_url):
    r = requests.put(
        f"{base_url}/latest/api/token",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
    )
    assert r.status_code == 200
    return r.text


# ==========================================================
# 1 Basic metadata test
# ==========================================================

def test_basic_metadata(start_server):
    config = {
        "imdsv2_required": "true",
        "instance_id": "i-123456",
        "local_ipv4": "10.0.0.10",
    }

    base_url = start_server(config)
    token = get_token(base_url)

    r = requests.get(
        f"{base_url}/latest/meta-data/instance-id",
        headers={"X-aws-ec2-metadata-token": token},
    )

    assert r.status_code == 200
    assert r.text == "i-123456"


# ==========================================================
# 2 Public keys present
# ==========================================================

def test_public_keys_present(start_server):
    config = {
        "imdsv2_required": "true",
        "ssh_public_keys": ["ssh-rsa TESTKEY1", "ssh-ed25519 TESTKEY2"]
    }

    base_url = start_server(config)
    token = get_token(base_url)

    r = requests.get(
        f"{base_url}/latest/meta-data/public-keys/",
        headers={"X-aws-ec2-metadata-token": token},
    )

    assert r.status_code == 200
    assert "0" in r.text

    r = requests.get(
        f"{base_url}/latest/meta-data/public-keys/0/openssh-key",
        headers={"X-aws-ec2-metadata-token": token},
    )

    assert r.status_code == 200
    assert "ssh-rsa" in r.text


# ==========================================================
# 3 Public keys missing
# ==========================================================

def test_public_keys_missing(start_server):
    config = {"imdsv2_required": "true",}

    base_url = start_server(config)
    token = get_token(base_url)

    r = requests.get(
        f"{base_url}/latest/meta-data/public-keys/",
        headers={"X-aws-ec2-metadata-token": token},
    )

    assert r.status_code == 404


# ==========================================================
# 4 IMDSv2 token required
# ==========================================================

def test_token_required_yes(start_server):
    config = {
        "imdsv2_required": True,
        "instance_id": "i-123456",
        }

    base_url = start_server(config)

    r = requests.get(f"{base_url}/latest/meta-data/instance-id")

    assert r.status_code == 401

def test_token_required_no(start_server):
    config = {"imdsv2_required": False,
              "instance_id": "i-123456",}

    base_url = start_server(config)

    r = requests.get(f"{base_url}/latest/meta-data/instance-id")

    assert r.status_code == 200


# ==========================================================
# 5 Expired token
# ==========================================================

def test_token_expired(start_server):
    config = {}

    base_url = start_server(config)

    r = requests.put(
        f"{base_url}/latest/api/token",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "1"},
    )
    assert r.status_code == 200
    token = r.text

    time.sleep(1.2)

    r = requests.get(
        f"{base_url}/latest/meta-data/",
        headers={"X-aws-ec2-metadata-token": token},
    )

    assert r.status_code == 401


# ==========================================================
# 6 Network subtree with optional values
# ==========================================================

def test_network_with_optional_fields(start_server):
    config = {
        "mac": "aa:bb:cc:dd:ee:ff",
        "local_ipv4": "10.0.0.10",
        "local_hostname": "ip-10-0-0-10",
        "mac_public_ipv4": ["1.2.3.4"],
        "mac_subnet_ipv4_cidr_block": "10.0.0.0/24",
    }

    base_url = start_server(config)
    token = get_token(base_url)

    r = requests.get(
        f"{base_url}/latest/meta-data/network/interfaces/macs/aa:bb:cc:dd:ee:ff/",
        headers={"X-aws-ec2-metadata-token": token},
    )

    assert r.status_code == 200
    assert "public-ipv4s" in r.text
    assert "subnet-ipv4-cidr-block" in r.text


# ==========================================================
# 7 Forced status override
# ==========================================================

def test_forced_status(start_server):
    config = {
        "force_status": {
            "/latest/meta-data/instance-id": 503
        }
    }

    base_url = start_server(config)
    token = get_token(base_url)

    r = requests.get(
        f"{base_url}/latest/meta-data/instance-id",
        headers={"X-aws-ec2-metadata-token": token},
    )

    assert r.status_code == 503
