import contextlib
import io
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from http_inspect import analyze, fetch, main, validate_url


def checks(headers, url='https://example.test'):
    return {c['header']: c for c in analyze(url, 200, headers)['checks']}


class InspectTests(unittest.TestCase):
    def test_case_insensitive_headers(self):
        self.assertEqual(checks([('x-content-type-options', 'nosniff')])['X-Content-Type-Options']['status'], 'presente')

    def test_hsts_zero_and_http(self):
        self.assertEqual(checks([('Strict-Transport-Security', 'max-age=0')])['Strict-Transport-Security']['status'], 'atenção')
        self.assertEqual(checks([('Strict-Transport-Security', 'max-age=100')], 'http://example.test')['Strict-Transport-Security']['status'], 'atenção')

    def test_hsts_duplicates(self):
        self.assertEqual(checks([('Strict-Transport-Security', 'max-age=100'), ('Strict-Transport-Security', 'max-age=200')])['Strict-Transport-Security']['status'], 'atenção')

    def test_report_only_is_not_enforcement(self):
        c = checks([('Content-Security-Policy-Report-Only', "default-src 'self'")])
        self.assertEqual(c['Content-Security-Policy']['status'], 'ausente')

    def test_frame_ancestors(self):
        c = checks([('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'")])
        self.assertEqual(c['X-Frame-Options']['status'], 'informativo')

    def test_reject_bad_urls(self):
        for url in ('file:///etc/passwd', 'example.com', 'https://user:pass@example.com', 'https://example.com/#a', 'https://example.com:bad', 'https://example.com/\n'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_url(url)

    def test_demo_export_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'report.json'
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(['--demo', '--json', str(path)]), 0)
                self.assertEqual(main(['--demo', '--json', str(path)]), 2)
            self.assertTrue(json.loads(path.read_text(encoding='utf-8'))['demo'])

    def test_real_http_redirect_and_error_headers(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302 if self.path == '/' else 404)
                if self.path == '/':
                    self.send_header('Location', '/missing')
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.end_headers()
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            url, status, headers = fetch(f'http://127.0.0.1:{server.server_port}/')
            self.assertEqual(status, 404)
            self.assertTrue(url.endswith('/missing'))
            self.assertEqual(checks(headers, url)['X-Content-Type-Options']['status'], 'presente')
        finally:
            server.shutdown()
            server.server_close()
            worker.join()


if __name__ == '__main__':
    unittest.main()
