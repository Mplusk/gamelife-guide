import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import build


class BuilderTests(unittest.TestCase):
    def setUp(self):
        self.sing_box = os.environ.get('SING_BOX')
        if not self.sing_box:
            self.skipTest('set SING_BOX to the pinned sing-box binary')
        self.temporary = tempfile.TemporaryDirectory(prefix='gamelife-build-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.inputs = {}
        examples = {
            'blocked-sites': {'domain_suffix': ['blocked.ru']},
            'blocked-ips': {'ip_cidr': ['198.51.100.0/24']},
            'russian-sites': {'domain_suffix': ['normal.ru', 'blocked.ru']},
            'inside-sites': {'domain_suffix': ['inside.test']},
            'russian-ips': {'ip_cidr': ['203.0.113.0/24']},
        }
        for name, rule in examples.items():
            source = self.root / (name + '.json')
            target = self.root / (name + '.srs')
            source.write_text(json.dumps({'version': 3, 'rules': [rule]}), encoding='utf-8')
            subprocess.run([self.sing_box, 'rule-set', 'compile', '-o', str(target), str(source)],
                           check=True, capture_output=True)
            self.inputs[build.INPUTS[name]] = target.read_bytes()

    def fetch(self, url):
        suffix = url.split('/sing-box/', 1)[1]
        return self.inputs[suffix]

    def test_outputs_embed_the_exclusions(self):
        destination = self.root / 'output'
        built = build.build(self.sing_box, destination, self.fetch, 'a' * 40)
        self.assertEqual(set(built), {'geosite-gamelife-direct.srs', 'geoip-gamelife-direct.srs'})
        for name in built:
            decoded = self.root / (name + '.json')
            subprocess.run([self.sing_box, 'rule-set', 'decompile', '-o', str(decoded),
                            str(destination / name)], check=True, capture_output=True)
            rule = json.loads(decoded.read_text(encoding='utf-8'))['rules'][0]
            self.assertEqual((rule['type'], rule['mode']), ('logical', 'and'))
            exclusions = rule['rules'][1]
            self.assertEqual((exclusions['type'], exclusions['mode'], exclusions['invert']),
                             ('logical', 'or', True))
            self.assertEqual(len(exclusions['rules']), 2)

    def test_failed_download_preserves_previous_artifacts(self):
        destination = self.root / 'output'
        destination.mkdir()
        old = {name: b'previous-' + name.encode() for name in
               ('geosite-gamelife-direct.srs', 'geoip-gamelife-direct.srs')}
        for name, data in old.items():
            (destination / name).write_bytes(data)

        def broken(url):
            if url.endswith('geosite-category-ru.srs'):
                raise OSError('simulated upstream failure')
            return self.fetch(url)

        with self.assertRaises(OSError):
            build.build(self.sing_box, destination, broken, 'a' * 40)
        self.assertEqual({name: (destination / name).read_bytes() for name in old}, old)


if __name__ == '__main__':
    unittest.main()
