import contextlib
import io
import os
import shlex
import subprocess
import sys
import types
import unittest
from unittest.mock import Mock, patch
import fuzzhttpbypass as wrapper


class WrapperTests(unittest.TestCase):
    def test_urls(self):
        self.assertEqual(wrapper.getPartsFromUrl('https://example.test:8443/a?b=1'), ('https:', 'example.test:8443', '/a?b=1'))
        self.assertTrue(wrapper.isIP('127.0.0.1:8000'))
        self.assertTrue(wrapper.isIP('[::1]:8000'))
        self.assertFalse(wrapper.isIP('example.test'))
        for url in ('ftp://example.test', 'https://user:pass@example.test', 'http://example.test:bad', 'http://example.test/#fragment'):
            with self.assertRaises(ValueError):
                wrapper.validate_url(url)

    def test_filters(self):
        self.assertEqual(wrapper.build_filter('notcontains,403'), '--hc 403')
        self.assertEqual(shlex.split(wrapper.build_filter('contains,Invalid  Access')), ['--ss', 'Invalid  Access'])
        for value in ('bad,403', 'contains,', 'contains,999', 'missing'):
            with self.assertRaises(ValueError):
                wrapper.build_filter(value)

    def test_explicit_arguments(self):
        self.assertEqual(wrapper.parse_main_args(['-u', 'http://127.0.0.1:8000', '-f', 'contains,200']), ('http://127.0.0.1:8000', '', 'contains,200'))

    def test_import_and_help_without_network(self):
        result = subprocess.run([sys.executable, 'fuzzhttpbypass.py', '--help'], capture_output=True, text=True, check=True, timeout=10)
        self.assertIn('authorized', result.stdout)
        result = subprocess.run([sys.executable, '-c', "import fuzzhttpbypass, sys; assert 'requests' not in sys.modules; assert 'wfuzz' not in sys.modules"], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0)

    def test_cleanup_when_stage_fails(self):
        response = Mock(status_code=200, text='fixture', cookies=[], is_redirect=False, is_permanent_redirect=False)
        requests = types.ModuleType('requests')
        requests.get = Mock(return_value=response)
        observed = []
        original = wrapper.tempfile.NamedTemporaryFile
        def temporary(*args, **kwargs):
            file = original(*args, **kwargs)
            observed.append(file.name)
            return file
        with patch.dict(sys.modules, {'requests': requests}), patch.object(wrapper, 'parse_main_args', return_value=('http://127.0.0.1:8000', '', 'contains,200')), patch.object(wrapper.tempfile, 'NamedTemporaryFile', side_effect=temporary), patch.object(wrapper, 'fuzzPaths'), patch.object(wrapper, 'fuzzMethods', side_effect=RuntimeError('synthetic failure')), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(RuntimeError):
                wrapper.main()
        self.assertTrue(observed)
        self.assertTrue(all(not os.path.exists(path) for path in observed))
        self.assertEqual(requests.get.call_args.kwargs, {'timeout': 30, 'allow_redirects': False})

    def test_dns_is_mocked(self):
        with patch.object(wrapper.socket, 'getaddrinfo', return_value=[(2, 1, 6, '', ('127.0.0.1', 0))]), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(wrapper.getIPsFromDomain('example.test:8000'), ['127.0.0.1'])


if __name__ == '__main__':
    unittest.main()
