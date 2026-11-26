"""Build self-contained Hiddify direct-route rule sets from public RU data.

The output is published only after every input was downloaded and parsed.
Both outputs embed the blocked lists, so they do not depend on separate
client downloads of exclusions. An absent output matches nothing.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.request import Request, urlopen

REPOSITORY = 'https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/'
COMMIT_API = 'https://api.github.com/repos/runetfreedom/russia-v2ray-rules-dat/commits/release'
INPUTS = {
    'blocked-sites': 'rule-set-geosite/geosite-ru-blocked.srs',
    'blocked-ips': 'rule-set-geoip/geoip-ru-blocked.srs',
    'russian-sites': 'rule-set-geosite/geosite-category-ru.srs',
    'inside-sites': 'rule-set-geosite/geosite-ru-available-only-inside.srs',
    'russian-ips': 'rule-set-geoip/geoip-ru.srs',
}
LIMIT = 4 * 1024 * 1024


def get(url: str, limit: int) -> bytes:
    headers = {'User-Agent': 'GameLife-routing-updater/1'}
    token = os.environ.get('GH_TOKEN')
    if token and url.startswith('https://api.github.com/'):
        headers['Authorization'] = 'Bearer ' + token
    request = Request(url, headers=headers)
    with urlopen(request, timeout=40) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError('upstream response too large')
    return data


def fetch(url: str) -> bytes:
    data = get(url, LIMIT)
    if not data.startswith(b'SRS\x01') or len(data) > LIMIT:
        raise ValueError('invalid upstream rule set')
    return data


def upstream_revision():
    data = json.loads(get(COMMIT_API, 256 * 1024))
    revision = data.get('sha')
    if not isinstance(revision, str) or not re.fullmatch('[0-9a-f]{40}', revision):
        raise ValueError('invalid upstream revision')
    return revision


def build(sing_box: str, destination: Path, fetcher=fetch, revision=None):
    revision = revision or upstream_revision()
    if not re.fullmatch('[0-9a-f]{40}', revision):
        raise ValueError('invalid upstream revision')
    root_url = REPOSITORY + revision + '/sing-box/'
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='gamelife-routing-') as temporary:
        root = Path(temporary)
        rules = {}
        for name, path in INPUTS.items():
            source = root / (name + '.srs')
            decoded = root / (name + '.json')
            source.write_bytes(fetcher(root_url + path))
            subprocess.run([sing_box, 'rule-set', 'decompile', '-o', str(decoded), str(source)],
                           check=True, timeout=60, stdout=subprocess.DEVNULL)
            data = json.loads(decoded.read_text(encoding='utf-8'))
            if not isinstance(data, dict) or not isinstance(data.get('rules'), list) or not data['rules']:
                raise ValueError('empty upstream rule set: ' + name)
            rules[name] = data['rules']

        blocked = {'type': 'logical', 'mode': 'or', 'invert': True,
                   'rules': rules['blocked-sites'] + rules['blocked-ips']}
        sources = {
            'geosite-gamelife-direct.srs': rules['russian-sites'] + rules['inside-sites'] + [
                {'domain_suffix': ['.ru', '2ip.io', 'sidzen.shop', '3dprinta.shop']}],
            'geoip-gamelife-direct.srs': rules['russian-ips'],
        }
        built = {}
        for name, included in sources.items():
            combined = {'version': 3, 'rules': [{
                'type': 'logical', 'mode': 'and', 'rules': [
                    {'type': 'logical', 'mode': 'or', 'rules': included}, blocked,
                ],
            }]}
            definition = root / (name + '.json')
            definition.write_text(json.dumps(combined, ensure_ascii=False, separators=(',', ':')),
                                  encoding='utf-8')
            output = root / name
            subprocess.run([sing_box, 'rule-set', 'compile', '-o', str(output), str(definition)],
                           check=True, timeout=60, stdout=subprocess.DEVNULL)
            data = output.read_bytes()
            if not data.startswith(b'SRS') or not 5 <= len(data) <= LIMIT:
                raise ValueError('invalid generated rule set: ' + name)
            built[name] = data

        # Both artifacts are prepared before either published path is touched.
        # A Git commit makes the pair available to clients as one revision.
        for name, data in built.items():
            target = destination / name
            fd, tmp = tempfile.mkstemp(prefix='.route-', dir=destination)
            try:
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(tmp, target)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)
    return {name: len(data) for name, data in built.items()}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sing-box', required=True)
    parser.add_argument('--destination', type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    for name, size in build(args.sing_box, args.destination).items():
        print(f'{name}: {size} bytes')
