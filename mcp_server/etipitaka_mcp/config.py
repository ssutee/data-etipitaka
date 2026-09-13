import os
from dataclasses import dataclass


@dataclass
class Config:
    base_url: str
    username: str | None
    password: str | None
    token: str | None
    default_edition: str | None


def load_config():
    return Config(
        base_url=os.environ.get('ETIPITAKA_BASE_URL', 'https://data.etipitaka.com'),
        username=os.environ.get('ETIPITAKA_USERNAME'),
        password=os.environ.get('ETIPITAKA_PASSWORD'),
        token=os.environ.get('ETIPITAKA_TOKEN'),
        default_edition=os.environ.get('ETIPITAKA_DEFAULT_EDITION'),
    )
