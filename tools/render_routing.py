"""Render or verify the public page from the same payload used in tests."""
import argparse
import html
from pathlib import Path

from routing_import import import_link

ROOT = Path(__file__).resolve().parent.parent


def render():
    template = (ROOT / 'tools' / 'routing-template.html').read_text(encoding='utf-8')
    if template.count('__ROUTING_LINK__') != 1:
        raise ValueError('template must contain one routing link')
    return template.replace('__ROUTING_LINK__', html.escape(import_link(), quote=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    target = ROOT / 'routing.html'
    if args.check:
        if not target.is_file() or target.read_text(encoding='utf-8') != render():
            raise SystemExit('routing.html differs from the tested import link')
    else:
        target.write_text(render(), encoding='utf-8', newline='\n')
