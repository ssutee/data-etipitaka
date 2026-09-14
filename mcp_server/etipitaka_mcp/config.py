import os
from dataclasses import dataclass, field

TRANSPORTS = ('stdio', 'http')

# Hosts the SDK's DNS-rebinding protection accepts by default; nginx forwards
# the original Host header, so production adds its public hostname on top of
# this. Shared by the dataclass default and load_config so an unset variable
# and an explicit ETIPITAKA_ALLOWED_HOSTS= (empty) behave differently: only
# the latter yields [].
DEFAULT_ALLOWED_HOSTS = ['localhost:*', '127.0.0.1:*', '[::1]:*']


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
    allowed_hosts: list[str] = field(default_factory=lambda: list(DEFAULT_ALLOWED_HOSTS))


def _csv(value):
    return [h.strip() for h in value.split(',') if h.strip()]


def _strip_trailing_slash(url):
    return url.rstrip('/') if url is not None else None


def load_config():
    transport = os.environ.get('ETIPITAKA_TRANSPORT', 'stdio').strip().lower()
    if transport not in TRANSPORTS:
        raise ValueError(
            f'ETIPITAKA_TRANSPORT must be one of {TRANSPORTS}, got {transport!r}')

    raw_port = os.environ.get('ETIPITAKA_HTTP_PORT', '8001')
    try:
        http_port = int(raw_port)
    except ValueError:
        raise ValueError(f'ETIPITAKA_HTTP_PORT must be an integer, got {raw_port!r}')

    return Config(
        base_url=os.environ.get('ETIPITAKA_BASE_URL', 'https://data.etipitaka.com'),
        username=os.environ.get('ETIPITAKA_USERNAME'),
        password=os.environ.get('ETIPITAKA_PASSWORD'),
        token=os.environ.get('ETIPITAKA_TOKEN'),
        default_edition=os.environ.get('ETIPITAKA_DEFAULT_EDITION'),
        transport=transport,
        issuer_url=_strip_trailing_slash(os.environ.get('ETIPITAKA_ISSUER_URL')),
        resource_url=_strip_trailing_slash(os.environ.get('ETIPITAKA_RESOURCE_URL')),
        http_host=os.environ.get('ETIPITAKA_HTTP_HOST', '0.0.0.0'),
        http_port=http_port,
        allowed_hosts=_csv(os.environ.get('ETIPITAKA_ALLOWED_HOSTS',
                                          ','.join(DEFAULT_ALLOWED_HOSTS))),
    )
