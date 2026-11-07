"""Fixed capture-page assets; no paths or HTML come from a request."""
from functools import lru_cache
import hashlib
from pathlib import Path
import re
from typing import NamedTuple


ROOT = Path(__file__).resolve().parents[2] / 'web'
PAGE = re.compile(r'/sentinel/captures/[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}\Z')
ROUTES = {'/sentinel/capture-assets/capture.css': ('capture.css', 'text/css; charset=utf-8'),
          '/sentinel/capture-assets/capture.js': ('capture.js', 'text/javascript; charset=utf-8')}
CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"


class PageAsset(NamedTuple):
    content: bytes
    content_type: str


@lru_cache(maxsize=1)
def assets():
    result = {}
    for name, content_type in [('capture.html', 'text/html; charset=utf-8'), *ROUTES.values()]:
        file = ROOT / name
        if file.is_symlink() or not file.is_file() or not 0 < file.stat().st_size <= 65536:
            raise ValueError('Capture page is unavailable')
        content = file.read_bytes()
        if not 0 < len(content) <= 65536:
            raise ValueError('Capture page is unavailable')
        result[name] = PageAsset(content, content_type)
    return result


def page_asset(route):
    if PAGE.fullmatch(route):
        return assets()['capture.html']
    entry = ROUTES.get(route)
    return assets()[entry[0]] if entry is not None else None


def capability():
    return {'schema': 'orbis-sentinel.capture-ui.v1', 'version': 1, 'progressVersion': 1,
            'page': '/sentinel/captures/{id}', 'mutations': False,
            'assets': {name: hashlib.sha256(asset.content).hexdigest() for name, asset in assets().items()}}
