# Overview

This mock server implements a minimal subset of the Amazon EC2 Instance Metadata Service (IMDS). It is intended for local development and testing of software that expects to retrieve instance metadata (for example, SSH public keys) from the standard link-local address.

The server responds to HTTP GET requests and returns predefined metadata values from a configuration object.

# How to run

Run
```sh
python3 imds_mock.py --config config.json --host 127.0.0.1 --port 8000
```

Test in jail / VM:
```sh
python3 imds_mock.py --config config.json --host 169.254.169.254 --port 80
```


# Supported Endpoints

The following endpoints are currently supported:

/latest/meta-data/

Returns a basic listing of available metadata keys (depending on implementation).

/latest/meta-data/public-keys/

Returns a list of available SSH public key indexes.

/latest/meta-data/public-keys/<index>/openssh-key

Returns the OpenSSH public key corresponding to the given numeric index.

The index must be a zero-based integer. If the index is invalid or does not exist, the server returns HTTP 404.

# Supported Endpoints

IMDSv2:

PUT /latest/api/token

Metadata:

1. GET /latest/meta-data/
1. GET /latest/meta-data/hostname
1. GET /latest/meta-data/instance-id
1. GET /latest/meta-data/local-hostname
1. GET /latest/meta-data/local-ipv4
1. GET /latest/meta-data/mac
1. GET /latest/meta-data/network/
1. GET /latest/meta-data/placement/
1. GET /latest/meta-data/public-hostname
1. GET /latest/meta-data/public-ipv4
1. GET /latest/meta-data/public-keys/
1. GET /latest/meta-data/public-keys/<index>/
1. GET /latest/meta-data/public-keys/<index>/openssh-key

## IMDSv2 Token Flow

The server implements the IMDSv2 session-oriented flow:

```
PUT /latest/api/token
```
The client must send header:
```
X-aws-ec2-metadata-token-ttl-seconds: <seconds>
```
The server returns a token string in the response body.

Subsequent GET requests to metadata endpoints must include header:
```
X-aws-ec2-metadata-token: <token>
```
If the token is missing or invalid, the server returns `401 Unauthorized`.

# Configuration

The server reads parameters from the configuration structure:

Example:
```json
{
  "instance_id": "i-1234567890",
  "hostname": "test-vm",
  "public_hostname": "192.168.199.199",
  "local_hostname": "test-vm",
  "local_ipv4": "10.0.0.10",
  "public_ipv4": "192.168.199.199",
  "mac": "02:00:00:00:00:01",

  "account_id": "123456789012",
  "region": "antarctica-1",
  "availability_zone": "antarc-north-1z",
  "instance_type": "a1.pinguin",
  "architecture": "x86_64",

  "ssh_public_keys": [
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDkey1",
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIkey2"
  ],

  "user_data": "#cloud-config\nhostname: test-vm\nssh_pwauth: no\nusers:\n- name: connect\n  sudo: ALL=(ALL) NOPASSWD:ALL\n  shell: /bin/sh\n  ssh_authorized_keys:\n  - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII09srKGDwCQepHQnWk1tS8Zpublickey connect",

  "default_delay_ms": 0,
  "endpoint_delay_ms": {},
  "force_status": {}
}
```

Each list element of `ssh_public_keys` corresponds to its numeric index in the URL (starting from 0).

# Response Codes

## 200 OK

Returned when a valid metadata key or SSH public key is found.

## 404 Not Found

Returned when:
1. The requested path is not supported
1. The public key index is invalid
1. The key does not exist

## 401 Unauthorized

Returned when:

1. IMDSv2 token is missing
1. IMDSv2 token is invalid or expired

## 500 Internal Server Error

Returned if an unexpected exception occurs (optional, depending on implementation).

# Intended Use

This server is designed for:

1. Local development
1. Integration testing
1. CI environments
1. Testing cloud-init or other metadata consumers without real EC2

It is not intended for production use. The server implements IMDSv2 token flow but does not provide full EC2 metadata coverage or production-grade security.

# Limitations

1. Only a limited subset of metadata paths is supported.
1. No security hardening.
1. No concurrency guarantees unless explicitly implemented.

The implementation is intentionally simple to make behavior predictable and easy to debug.

# How to test

## Test using `curl`.

### Connect without token (answer must be 401)
```sh
curl -v http://127.0.0.1:8000/latest/meta-data/instance-id
```

### Get token
```sh
TOKEN=$(curl -X PUT \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 60" \
  http://127.0.0.1:8000/latest/api/token)
```

### Get instance-id
```sh
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://127.0.0.1:8000/latest/meta-data/instance-id
```

### Check SSH keys
```sh
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://127.0.0.1:8000/latest/meta-data/public-keys/
```

```sh
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://127.0.0.1:8000/latest/meta-data/public-keys/0/openssh-key
```

### Test TTL
```sh
TOKEN=$(curl -X PUT \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 1" \
  http://127.0.0.1:8000/latest/api/token)

sleep 2

curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://127.0.0.1:8000/latest/meta-data/instance-id
```

Code 401 must be returned.

## Testing by getimds

`getimds` utility provided with imds_mock.py server. It queries all IMDS resources in cycle and outputs them.

Run in test environment.
```sh
python3 imds_mock.py --config config.json --host 127.0.0.1 --port 8000
getimds 127.0.0.1:8000
```

Run in real environment (with server on 69.254.169.254available).
```sh
getimds
```


# Links
https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html
https://seifrajhi.github.io/blog/instance-security-imdsv1-vs-v2/

# Copyrigth

Copyrigth(c) 2026 Vladlen Popolitov vladlen@FreeBSD.org

SPDX-License-Identifier: BSD-2-Clause

