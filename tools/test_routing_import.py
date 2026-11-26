"""Check the deep-link payload and routing order with the real Hiddify core."""
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import unittest
from urllib.parse import parse_qs, urlsplit

import routing_import as routes


def receive(sock, length):
    data = b''
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise EOFError
        data += chunk
    return data


class MockNode(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, name, rules_port=None):
        self.name = name
        self.rules_port = rules_port
        super().__init__(('127.0.0.1', 0), MockNodeHandler)


class MockNodeHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(5)
            hello = receive(self.request, 2)
            receive(self.request, hello[1])
            self.request.sendall(b'\x05\x00')
            request = receive(self.request, 4)
            size = 4 if request[3] == 1 else 16 if request[3] == 4 else receive(self.request, 1)[0]
            address = receive(self.request, size)
            port = int.from_bytes(receive(self.request, 2), 'big')
            self.request.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            if (request[3] == 1 and address == b'\x7f\x00\x00\x01'
                    and port == self.server.rules_port):
                with socket.create_connection(('127.0.0.1', port), timeout=5) as upstream:
                    upstream.settimeout(5)
                    upstream.sendall(self.request.recv(8192))
                    while True:
                        chunk = upstream.recv(16384)
                        if not chunk:
                            break
                        self.request.sendall(chunk)
                return
            self.request.recv(8192)
            body = json.dumps({'node': self.server.name}).encode()
            self.request.sendall(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: '
                                 + str(len(body)).encode() + b'\r\n\r\n' + body)
        except (OSError, EOFError):
            pass


class RuleHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.server.requests += 1
        if self.server.fail:
            self.send_response(503)
            self.send_header('Connection', 'close')
            self.end_headers()
            return
        site = 'blocked.ru' if self.server.blocked else 'different.test'
        body = json.dumps({'version': 3, 'rules': [{
            'type': 'logical', 'mode': 'and', 'rules': [
                {'domain_suffix': ['blocked.ru', 'normal.ru']},
                {'type': 'logical', 'mode': 'or', 'invert': True,
                 'rules': [{'domain_suffix': [site]}, {'ip_cidr': ['198.51.100.0/24']}]},
            ]}]}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)


def start_http_rules():
    server = ThreadingHTTPServer(('127.0.0.1', 0), RuleHandler)
    server.requests = 0
    server.blocked = True
    server.fail = False
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class MockDNS(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, answer):
        self.answer = ipaddress.ip_address(answer).packed
        super().__init__(('127.0.0.1', 0), MockDNSHandler)


class MockDNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        packet, server = self.request
        if len(packet) < 17:
            return
        response = (packet[:2] + b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00'
                    + packet[12:] + b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x1e\x00\x04'
                    + self.server.answer)
        server.sendto(response, self.client_address)


def query_dns(port, name):
    question = b''.join(bytes([len(part)]) + part.encode('ascii') for part in name.split('.'))
    packet = b'\x19\x71\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + question + b'\x00\x00\x01\x00\x01'
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(3)
            sock.sendto(packet, ('127.0.0.1', port))
            data, _ = sock.recvfrom(4096)
            if len(data) < 4 or data[:2] != packet[:2] or data[3] & 15:
                return None
            return str(ipaddress.ip_address(data[-4:]))
    except (OSError, ValueError):
        return None


def core_environment(core):
    env = os.environ.copy()
    env['LD_LIBRARY_PATH'] = str(Path(core).resolve().parent) + os.pathsep + env.get('LD_LIBRARY_PATH', '')
    return env


def parse_link(link):
    parsed = urlsplit(link)
    if parsed.scheme != 'hiddify' or parsed.path != '/settings/routing-options':
        raise ValueError('unexpected Hiddify link')
    encoded = parse_qs(parsed.query, strict_parsing=True)['routeRule'][0]
    return json.loads(json.loads(base64.b64decode(encoded, validate=True).decode('utf-8')))


def proto3_rules(legacy):
    """Translate legacy Dart JSON to the proto3 JSON sent to the core."""
    fields = {'1': 'list_order', '2': 'enabled', '3': 'name', '4': 'outbound',
              '5': 'rule_set', '16': 'domain_suffix'}
    return {'rules': [{fields[key]: value for key, value in item.items()}
                      for item in legacy['1']]}


def query(port, target, host):
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=3) as sock:
            sock.settimeout(5)
            sock.sendall(b'\x05\x01\x00')
            if receive(sock, 2) != b'\x05\x00':
                return None
            try:
                address = ipaddress.ip_address(target)
                dest = bytes([1 if address.version == 4 else 4]) + address.packed
            except ValueError:
                data = target.encode('ascii')
                dest = b'\x03' + bytes([len(data)]) + data
            sock.sendall(b'\x05\x01\x00' + dest + (80).to_bytes(2, 'big'))
            reply = receive(sock, 4)
            if reply[1]:
                return None
            size = 4 if reply[3] == 1 else 16 if reply[3] == 4 else receive(sock, 1)[0]
            receive(sock, size + 2)
            sock.sendall(b'GET / HTTP/1.1\r\nHost: ' + host.encode('ascii') + b'\r\nConnection: close\r\n\r\n')
            output = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                output += chunk
            return json.loads(output.split(b'\r\n\r\n', 1)[1])['node']
    except (OSError, EOFError, ValueError, KeyError, IndexError):
        return None


class RouteImportTests(unittest.TestCase):
    def test_link_matches_hiddify_legacy_double_json(self):
        data = parse_link(routes.import_link())
        self.assertEqual(data, routes.legacy_rules())
        self.assertEqual([entry['3'] for entry in data['1']], [
            'builtin:bypassLan', 'Российские сайты — напрямую', 'builtin:bypassRegion',
            'builtin:systemDirect', 'builtin:blockAds'])
        self.assertEqual(data['1'][1]['4'], 1)
        self.assertFalse(data['1'][2]['2'])
        self.assertEqual(len(routes.DIRECT_SETS), 2)
        self.assertTrue(all(url.startswith(routes.ROOT) and url.endswith('.srs')
                            for url in routes.DIRECT_SETS))

    def test_real_core_applies_order_and_ip_rules(self):
        core = os.environ.get('HIDDIFY_CORE_V5')
        if not core:
            if os.environ.get('REQUIRE_HIDDIFY_CORE_TESTS'):
                self.fail('HIDDIFY_CORE_V5 is required in CI')
            self.skipTest('Hiddify 5 core binary not supplied')
        rule_server = start_http_rules()
        nodes = [MockNode('proxy', rule_server.server_port), MockNode('direct')]
        dns_servers = [MockDNS('192.0.2.11'), MockDNS('192.0.2.22')]
        for node in nodes + dns_servers:
            threading.Thread(target=node.serve_forever, daemon=True).start()
        proc = None
        try:
            with tempfile.TemporaryDirectory(prefix='hiddify-routing-import-') as folder:
                root = Path(folder)
                raw = root / 'raw.json'
                raw.write_text(json.dumps({'outbounds': [{'type': 'socks', 'tag': 'test',
                              'server': '127.0.0.1', 'server_port': nodes[0].server_address[1]}]}))
                parsed, built, settings = root / 'parsed.json', root / 'built.json', root / 'settings.json'
                # Built-ins are reconstructed by the Hiddify app. These two
                # custom rules are forwarded to the core as proto3 JSON.
                legacy = parse_link(routes.import_link())
                custom = {'1': legacy['1'][1:2]}
                settings.write_text(json.dumps({'mixed-port': 12334, 'region': 'other',
                    'direct-dns-address': '1.1.1.1', 'remote-dns-address': '1.1.1.1',
                    'connection-test-url': 'http://example.invalid/', 'url-test-interval': 600,
                    'balancer-strategy': 'round-robin', 'route-rule': proto3_rules(custom)}))
                env = core_environment(core)
                # `srun` installs a strict deprecation manager; the app uses
                # libbox.BaseContext without it. This only affects test runs.
                standalone_env = dict(env, ENABLE_DEPRECATED_LEGACY_RULE_SET_DOWNLOAD_DETOUR='true',
                                      ENABLE_DEPRECATED_IMPLICIT_DEFAULT_HTTP_CLIENT='true',
                                      ENABLE_DEPRECATED_LEGACY_DNS_ADDRESS_FILTER='true',
                                      ENABLE_DEPRECATED_LEGACY_DNS_RULE_STRATEGY='true')
                for args in (['parse', str(raw), '-o', str(parsed)],
                             ['build', '-c', str(parsed), '-d', str(settings), '-o', str(built)]):
                    subprocess.run([core, *args], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   cwd=folder, env=env, timeout=40, check=True)
                config = json.loads(built.read_text(encoding='utf-8-sig'))
                rules = config['route']['rules']
                direct = next(i for i, rule in enumerate(rules)
                              if 'geosite-gamelife-direct' in rule.get('rule_set', []))
                self.assertEqual(rules[direct].get('outbound'), 'direct §hide§')
                self.assertIn('geoip-gamelife-direct', rules[direct].get('rule_set', []))
                self.assertTrue(all(item.get('update_interval') == '120h0m0s'
                                    for item in config['route']['rule_set']))

                # Keep the generated route rules, but replace remote lists and
                # network outbounds with isolated local test doubles.
                blocked = {'type': 'logical', 'mode': 'or', 'invert': True, 'rules': [
                    {'domain_suffix': ['blocked.ru']}, {'ip_cidr': ['198.51.100.0/24']}]}
                fake_sets = {
                    'geosite-gamelife-direct': [{'type': 'logical', 'mode': 'and', 'rules': [
                        {'domain_suffix': ['blocked.ru', 'normal.ru', 'sidzen.shop', '2ip.io']}, blocked]}],
                    'geoip-gamelife-direct': [{'type': 'logical', 'mode': 'and', 'rules': [
                        {'ip_cidr': ['198.51.100.0/24', '203.0.113.0/24']}, blocked]}],
                }
                with socket.socket() as listener:
                    listener.bind(('127.0.0.1', 0))
                    port = listener.getsockname()[1]
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
                    listener.bind(('127.0.0.1', 0))
                    dns_port = listener.getsockname()[1]
                dns_rule = next(rule for rule in config['dns']['rules']
                                if rule.get('rule_set') == 'geosite-gamelife-direct')
                runtime = {'log': {'disabled': True},
                    'inbounds': [{'type': 'socks', 'tag': 'in', 'listen': '127.0.0.1', 'listen_port': port},
                                 {'type': 'direct', 'tag': 'dns-in', 'listen': '127.0.0.1',
                                  'listen_port': dns_port, 'network': 'udp'}],
                    'dns': {'servers': [{'type': 'udp', 'tag': tag, 'server': '127.0.0.1',
                                         'server_port': server.server_address[1]}
                                        for tag, server in zip(('dns-direct-group', 'dns-remote-group'), dns_servers)],
                            'rules': [dns_rule, {'server': 'dns-remote-group', 'strategy': 'ipv4_only'}],
                            'final': 'dns-remote-group'},
                    'outbounds': [{'type': 'socks', 'tag': tag, 'server': '127.0.0.1',
                                   'server_port': node.server_address[1], 'version': '5'}
                                  for tag, node in zip(('select', 'direct §hide§'), nodes)],
                    'route': {'final': 'select', 'rules': [{'inbound': 'dns-in', 'action': 'hijack-dns'}] + rules,
                              'rule_set': [{'type': 'inline', 'tag': tag, 'rules': items}
                                           for tag, items in fake_sets.items()]}}
                path = root / 'runtime.json'
                path.write_text(json.dumps(runtime, ensure_ascii=False), encoding='utf-8')
                proc = subprocess.Popen([core, '-D', folder, 'srun', '-c', str(path)], cwd=folder, env=standalone_env,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                deadline = time.monotonic() + 12
                while time.monotonic() < deadline:
                    if proc.poll() is not None:
                        detail = proc.stdout.read().decode('utf-8', 'replace')[-2000:]
                        self.fail('isolated Hiddify core exited: ' + detail)
                    if query(port, 'normal.ru', 'normal.ru'):
                        break
                    time.sleep(.2)
                else:
                    self.fail('isolated Hiddify core did not start')
                for target, host, expected in [
                    ('blocked.ru', 'blocked.ru', 'proxy'),
                    ('normal.ru', 'normal.ru', 'direct'),
                    ('sidzen.shop', 'sidzen.shop', 'direct'),
                    ('2ip.io', '2ip.io', 'direct'),
                    ('global.test', 'global.test', 'proxy'),
                    # A domain without a matching site entry can reach the
                    # default proxy before Hiddify resolves its destination IP.
                    ('unknown-ru.test', 'unknown-ru.test', 'proxy'),
                    ('203.0.113.9', 'unknown.test', 'direct'),
                    ('198.51.100.9', 'normal.ru', 'proxy'),
                ]:
                    with self.subTest(target=target, host=host):
                        self.assertEqual(query(port, target, host), expected)
                for domain, expected in [('blocked.ru', '192.0.2.22'), ('normal.ru', '192.0.2.11'),
                                         ('unknown.test', '192.0.2.22')]:
                    with self.subTest(dns=domain):
                        self.assertEqual(query_dns(dns_port, domain), expected)

                # Exercise the actual remote rule-set loader with a short test
                # interval. Production Hiddify 5.9 uses 120 hours, checked above.
                proc.terminate()
                proc.wait(timeout=5)
                proc.stdout.close()
                runtime['route']['rule_set'][0] = {
                    'type': 'remote', 'tag': 'geosite-gamelife-direct', 'format': 'source',
                    'url': f'http://127.0.0.1:{rule_server.server_port}/direct.json',
                    'download_detour': 'select', 'update_interval': '2s'}
                path.write_text(json.dumps(runtime, ensure_ascii=False), encoding='utf-8')
                rule_server.fail = True
                proc = subprocess.Popen([core, '-D', folder, 'srun', '-c', str(path)], cwd=folder,
                                        env=standalone_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline and (not rule_server.requests
                        or query(port, 'normal.ru', 'normal.ru') != 'proxy'):
                    if proc.poll() is not None:
                        detail = proc.stdout.read().decode('utf-8', 'replace')[-2000:]
                        self.fail('Hiddify failed to load a remote rule set: ' + detail)
                    time.sleep(.2)
                self.assertGreater(rule_server.requests, 0, 'initial fetch was not attempted')
                self.assertEqual(query(port, 'normal.ru', 'normal.ru'), 'proxy',
                                 'uncached rules must fail to the VPN')
                self.assertEqual(query(port, 'blocked.ru', 'blocked.ru'), 'proxy')
                rule_server.fail = False
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline and query(port, 'normal.ru', 'normal.ru') != 'direct':
                    if proc.poll() is not None:
                        self.fail('Hiddify exited after the failed initial download')
                    time.sleep(.2)
                self.assertEqual(query(port, 'normal.ru', 'normal.ru'), 'direct',
                                 'remote rule set was not fetched on retry')
                self.assertEqual(query(port, 'blocked.ru', 'blocked.ru'), 'proxy')
                rule_server.blocked = False
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline and query(port, 'blocked.ru', 'blocked.ru') != 'direct':
                    if proc.poll() is not None:
                        self.fail('Hiddify exited while updating a rule set')
                    time.sleep(.2)
                self.assertEqual(query(port, 'blocked.ru', 'blocked.ru'), 'direct',
                                 'updated rule set was not applied')
                before_failure = rule_server.requests
                rule_server.fail = True
                deadline = time.monotonic() + 12
                while time.monotonic() < deadline and rule_server.requests <= before_failure:
                    time.sleep(.2)
                self.assertGreater(rule_server.requests, before_failure, 'failed refresh was not attempted')
                self.assertIsNone(proc.poll(), 'core stopped after a failed refresh')
                self.assertEqual(query(port, 'blocked.ru', 'blocked.ru'), 'direct',
                                 'failed refresh did not preserve last good rules')

                real_dir = os.environ.get('HIDDIFY_TEST_REAL_SRS_DIR')
                if real_dir:
                    proc.terminate()
                    proc.wait(timeout=5)
                    proc.stdout.close()
                    runtime['route']['rule_set'] = [
                        {'type': 'local', 'tag': item['tag'], 'format': 'binary',
                         'path': str(Path(real_dir) / (item['tag'] + '.srs'))}
                        for item in runtime['route']['rule_set']]
                    path.write_text(json.dumps(runtime, ensure_ascii=False), encoding='utf-8')
                    proc = subprocess.Popen([core, '-D', folder, 'srun', '-c', str(path)], cwd=folder,
                                            env=standalone_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    deadline = time.monotonic() + 12
                    while time.monotonic() < deadline and not query(port, 'yandex.ru', 'yandex.ru'):
                        if proc.poll() is not None:
                            self.fail('Hiddify core could not load current SRS data')
                        time.sleep(.2)
                    real_examples = [
                        ('unknown-does-not-exist.invalid', 'unknown-does-not-exist.invalid', 'proxy'),
                    ]
                    if os.environ.get('HIDDIFY_VERIFY_EXAMPLES'):
                        real_examples.extend([
                        ('agentura.ru', 'agentura.ru', 'proxy'),
                        ('yandex.ru', 'yandex.ru', 'direct'),
                        ('sidzen.shop', 'sidzen.shop', 'direct'),
                        ('2ip.io', '2ip.io', 'direct'),
                        ('92.63.101.127', 'unknown.test', 'direct'),
                        ])
                    for target, host, expected in real_examples:
                        with self.subTest(real_data=True, target=target):
                            self.assertEqual(query(port, target, host), expected)
        finally:
            if proc and proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=5)
            if proc and proc.stdout:
                proc.stdout.close()
            for node in nodes + dns_servers:
                node.shutdown()
                node.server_close()
            rule_server.shutdown()
            rule_server.server_close()


if __name__ == '__main__':
    unittest.main()
