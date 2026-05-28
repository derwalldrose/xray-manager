#!/usr/bin/env python3
"""Lightweight static checks for xray-manager inbound test feature."""
from pathlib import Path

p = Path('/mnt/code/hermes/workspace/xray-manager/app.py')
s = p.read_text()
required = [
    'DEFAULT_TEST_URLS',
    '@app.route("/api/test-urls"',
    '@app.route("/api/inbounds/test", methods=["POST"])',
    'function testInbound',
    'function loadTestUrls',
    'id="test-url-select"',
]
missing = [x for x in required if x not in s]
if missing:
    raise SystemExit('missing: ' + ', '.join(missing))
print('feature markers present')
