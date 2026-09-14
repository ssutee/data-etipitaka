import os
from dataclasses import dataclass, field


@dataclass
class Config:
    base_url: str
    username: str | None
    password: str | None
    token: str | None
    default_edition: str | None
    transport: str = 'stdio'            # 'stdio' | 'http'
    issuer_url: str | None = None       # public OAuth issuer (http mode)
    resource_url: str | None = None     # public URL of this MCP endpoint (http mode)
    http_host: str = '0.0.0.0'
    http_port: int = 8001
    allowed_hosts: list[str] = field(default_factory=list)


def _csv(value):
    return [h.strip() for h in value.split(',') if h.strip()]


def load_config():
    return Config(
        base_url=os.environ.get('ETIPITAKA_BASE_URL', 'https://data.etipitaka.com'),
        username=os.environ.get('ETIPITAKA_USERNAME'),
        password=os.environ.get('ETIPITAKA_PASSWORD'),
        token=os.environ.get('ETIPITAKA_TOKEN'),
        default_edition=os.environ.get('ETIPITAKA_DEFAULT_EDITION'),
        transport=os.environ.get('ETIPITAKA_TRANSPORT', 'stdio'),
        issuer_url=os.environ.get('ETIPITAKA_ISSUER_URL'),
        resource_url=os.environ.get('ETIPITAKA_RESOURCE_URL'),
        http_host=os.environ.get('ETIPITAKA_HTTP_HOST', '0.0.0.0'),
        http_port=int(os.environ.get('ETIPITAKA_HTTP_PORT', '8001')),
        # Hosts the SDK's DNS-rebinding protection accepts; nginx forwards the
        # original Host header, so production adds its public hostname.
        allowed_hosts=_csv(os.environ.get('ETIPITAKA_ALLOWED_HOSTS',
                                          'localhost:*,127.0.0.1:*')),
    )
