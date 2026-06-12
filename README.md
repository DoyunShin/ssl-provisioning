# sslpv

`sslpv` is an SSL certificate provisioning tool. A long-running FastAPI server holds
the paths to a `fullchain`/`privkey` pair and a set of API keys. A one-shot CLI client
authenticates with an API key and pulls the current certificate and private key over an
authenticated, end-to-end encrypted channel, writing them atomically to local paths.

---

## Installation

The distribution is published on PyPI as `ssl-provisioning`; the installed command
and import package are both named `sslpv`.

**From PyPI:**

```sh
pip install ssl-provisioning
# or, one-shot without a permanent install:
uvx --from ssl-provisioning sslpv --help
```

**From a local checkout:**

```sh
uv pip install .   # or: pip install .
```

---

## Server

### Starting the server

```sh
sslpv server --config /path/to/config.json
```

The server blocks until interrupted (Ctrl-C).

### config.json reference

```json
{
  "fullchain": "/etc/letsencrypt/live/example.com/fullchain.pem",
  "privkey": "/etc/letsencrypt/live/example.com/privkey.pem",
  "apikeys": ["replace-with-a-long-random-secret", "another-client-key"],
  "host": "0.0.0.0",
  "port": 1243,
  "server_certfile": null,
  "server_keyfile": null,
  "trusted_proxies": []
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `fullchain` | string | yes | Path to the PEM fullchain certificate to distribute to clients. |
| `privkey` | string | yes | Path to the PEM private key to distribute to clients. |
| `apikeys` | list of strings | yes | One or more API keys that clients may authenticate with. |
| `host` | string | no | Bind address. Defaults to `"0.0.0.0"`. |
| `port` | int | no | TCP port to listen on. Defaults to `1243`. |
| `server_certfile` | string or null | no | TLS certificate for the server itself. Falls back to `fullchain` when null. |
| `server_keyfile` | string or null | no | TLS private key for the server itself. Falls back to `privkey` when null. |
| `trusted_proxies` | list of strings | no | IP addresses of trusted reverse proxies whose `X-Forwarded-For` header is used to determine the real client IP for rate limiting. |

### File permissions

The server hard-errors on startup if the config file is readable by group or other.
Restrict permissions before starting:

```sh
chmod 600 /path/to/config.json
chmod 600 /path/to/privkey.pem
```

---

## Client

```sh
sslpv client \
  --server https://example.com:1243 \
  --key /path/to/apikey.txt \
  --cert /path/to/fullchain.pem \
  --privkey /path/to/privkey.pem
```

### Client flags

| Flag | Required | Description |
|---|---|---|
| `--server URL` | yes | Server base URL. Must use `https`. |
| `--key PATH` | yes | File containing the API key. |
| `--cert PATH` | yes | Destination path for the retrieved PEM certificate. |
| `--privkey PATH` | yes | Destination path for the retrieved PEM private key. |
| `--insecure` | no | Disable TLS certificate verification. Dangerous; see note below. |
| `--ca-cert PATH` | no | Path to a custom PEM CA bundle for TLS verification. |
| `--pin-sha256 HEX` | no | Expected SHA-256 hex fingerprint of the server leaf certificate. |
| `--timeout SECONDS` | no | Per-request timeout in seconds. Default: `30.0`. |
| `--post-hook COMMAND` | no | Shell command to run after a successful update. See "Post-update hook" below. |
| `--hook-on-change` | no | Only run `--post-hook` when the certificate or key content actually changed. |

### Post-update hook

`--post-hook COMMAND` runs the given shell command after the certificate and private key
have been written successfully.  This is intended for actions such as reloading a web
server that holds the certificate in memory.

The hook process receives the following environment variables:

| Variable | Value |
|---|---|
| `SSLPV_CERT_PATH` | Absolute path to the written certificate file. |
| `SSLPV_PRIVKEY_PATH` | Absolute path to the written private key file. |
| `SSLPV_SERVER` | Server base URL passed to the client. |
| `SSLPV_CHANGED` | `"1"` if the certificate or key content changed; `"0"` otherwise. |

Use `--hook-on-change` to skip the hook when the fetched certificate and key are
byte-for-byte identical to what is already on disk.  This avoids unnecessary service
reloads in scheduled runs where the certificate has not yet been renewed.

```sh
sslpv client \
  --server https://example.com:1243 \
  --key /path/to/apikey.txt \
  --cert /etc/ssl/fullchain.pem \
  --privkey /etc/ssl/privkey.pem \
  --post-hook 'systemctl reload nginx' \
  --hook-on-change
```

If the hook exits with a non-zero code, `sslpv client` exits with that same code so
that cron or monitoring systems can detect the failure.  The certificate files are
always written before the hook runs; a hook failure does not roll back the write.

**Security note:** The command is executed via the shell (`sh -c`), following the same
trust model as certbot's `--deploy-hook`.  Do not pass untrusted input as the command
value.  The operator is responsible for ensuring the command string is safe.

### TLS for self-signed or IP-addressed servers

For servers with self-signed certificates or no matching DNS name, use `--ca-cert` or
`--pin-sha256` instead of `--insecure`:

```sh
# Trust a custom CA bundle
sslpv client --server https://192.0.2.1:1243 --ca-cert /path/to/ca.pem ...

# Pin by SHA-256 fingerprint (colons optional, case-insensitive)
sslpv client --server https://192.0.2.1:1243 --pin-sha256 ab:cd:ef:... ...
```

`--insecure` disables all chain and hostname verification and leaves the connection
vulnerable to MITM attacks. The end-to-end encryption described below still protects
the payload content, but the identity of the server is not verified.

---

## How it works

### Stateless signed challenge-response authentication

1. The client fetches a signed one-time nonce from `/challenge`.
2. The client computes an HMAC proof that binds the API key, HTTP method, endpoint path,
   nonce, issue timestamp, and an ephemeral X25519 public key. The raw API key is never
   sent over the wire.
3. The server verifies the proof, checks the nonce has not been spent, and marks the
   nonce as spent immediately (one-time use).

### End-to-end AES-256-GCM payload encryption

Each response payload (certificate or private key) is encrypted with AES-256-GCM. The
symmetric key is derived from an X25519 ECDH exchange between a server-side ephemeral
key and the client's ephemeral key, with the API key mixed in as additional key
material. Even if the TLS layer is broken or bypassed (e.g. by an on-path attacker
under `--insecure`), the payload cannot be decrypted or forged without knowledge of the
API key.

### TLS transport

The server uses uvicorn with `ssl.PROTOCOL_TLS_SERVER` (TLS 1.2 or higher) and a
modern cipher suite (`ECDHE+AESGCM:ECDHE+CHACHA20`). Use `--ca-cert` or `--pin-sha256`
on the client when the server certificate is not trusted by the system CA store.

---

## Scheduled renewal (cron)

A typical cron entry that fetches the certificate nightly and reloads nginx only when
the content actually changes:

```cron
0 3 * * * sslpv client \
  --server https://example.com:1243 \
  --key /run/secrets/sslpv-apikey \
  --cert /etc/ssl/fullchain.pem \
  --privkey /etc/ssl/privkey.pem \
  --post-hook 'systemctl reload nginx' \
  --hook-on-change
```

Without `--hook-on-change`, the hook runs on every cron invocation regardless of
whether the certificate changed.  Using `--hook-on-change` avoids unnecessary nginx
reloads while still ensuring the service is reloaded whenever a new certificate is
written.

---

## Security model and limitations

- **Availability / DoS**: Protection against on-path denial-of-service is out of scope.
  Rate limiting is implemented per-IP but an on-path attacker can still disrupt
  availability.
- **Single-process requirement**: The server must run with `workers=1` (the default).
  Nonce deduplication and the rate limiter use in-memory state; multiple workers would
  allow nonce replay across process boundaries.
- **API key confidentiality**: Keep API key files restricted to `0600`. A key with group
  or other read permission will trigger a warning from the client.
- **Config file confidentiality**: The server rejects a config file with group or other
  read bits set. Always `chmod 600` the config.
