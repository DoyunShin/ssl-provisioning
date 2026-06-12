"""Server configuration model."""

from typing import Optional

from pydantic import BaseModel


class ServerConfig(BaseModel):
    """Server configuration loaded from a JSON config file.

    Args:
        fullchain(str): Path to the PEM fullchain certificate file served to clients.
        privkey(str): Path to the PEM private key file served to clients.
        apikeys(list[str]): List of authorized API keys.
        host(str): Host address to bind. Defaults to "0.0.0.0".
        port(int): Port to bind. Defaults to 1243.
        server_certfile(Optional[str]): Path to the TLS certificate for the server
            itself. Falls back to ``fullchain`` when not set.
        server_keyfile(Optional[str]): Path to the TLS private key for the server
            itself. Falls back to ``privkey`` when not set.
        trusted_proxies(list[str]): IP addresses of trusted reverse proxies whose
            X-Forwarded-For header is used to determine the real client IP.
    """

    fullchain: str
    privkey: str
    apikeys: list[str]
    host: str = "0.0.0.0"
    port: int = 1243
    server_certfile: Optional[str] = None
    server_keyfile: Optional[str] = None
    trusted_proxies: list[str] = []

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "fullchain": "/etc/ssl/certs/fullchain.pem",
                    "privkey": "/etc/ssl/private/privkey.pem",
                    "apikeys": ["changeme-replace-with-a-strong-random-key"],
                    "host": "0.0.0.0",
                    "port": 1243,
                    "server_certfile": None,
                    "server_keyfile": None,
                    "trusted_proxies": ["127.0.0.1"],
                }
            ]
        }
    }

    @property
    def tls_certfile(self) -> str:
        """Return the TLS certificate path for the server (server_certfile or fullchain).

        Return:
            path(str): Effective TLS certificate file path.
        """
        return self.server_certfile or self.fullchain

    @property
    def tls_keyfile(self) -> str:
        """Return the TLS key path for the server (server_keyfile or privkey).

        Return:
            path(str): Effective TLS key file path.
        """
        return self.server_keyfile or self.privkey
