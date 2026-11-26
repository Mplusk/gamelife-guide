"""Build a shareable Hiddify 5.9 route-rule import link.

Hiddify's deep link uses a base64-encoded JSON *string* containing protobuf
legacy JSON (numeric field tags), not proto3 JSON. This link contains only
public rule-set URLs; it is unrelated to any personal subscription.
"""
from __future__ import annotations

import base64
import json
from urllib.parse import quote


ROOT = 'https://raw.githubusercontent.com/Mplusk/gamelife-guide/main/assets/routing/'
DIRECT_SETS = (
    ROOT + 'geosite-gamelife-direct.srs',
    ROOT + 'geoip-gamelife-direct.srs',
)


def legacy_rules():
    """Return the numeric-tag encoding consumed by Dart's RouteRule.fromJson.

    Include each built-in explicitly: Hiddify otherwise inserts missing built-ins
    *before* imported rules. Region bypass is disabled so it cannot route a
    different region directly before blocked-site exceptions are checked.
    Hiddify replaces each built-in's content with its own implementation.
    """
    return {'1': [
        {'1': 0, '2': True, '3': 'builtin:bypassLan', '4': 1},
        {'1': 1, '2': True, '3': 'Российские сайты — напрямую', '4': 1,
         '5': list(DIRECT_SETS)},
        {'1': 2, '2': False, '3': 'builtin:bypassRegion', '4': 1},
        {'1': 3, '2': False, '3': 'builtin:systemDirect', '4': 1},
        {'1': 4, '2': False, '3': 'builtin:blockAds', '4': 3},
    ]}


def import_link():
    inner = json.dumps(legacy_rules(), ensure_ascii=False, separators=(',', ':'))
    outer = json.dumps(inner, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    data = base64.b64encode(outer).decode('ascii')
    return 'hiddify:///settings/routing-options?routeRule=' + quote(data, safe='')


if __name__ == '__main__':
    print(import_link())
