"""Exercise the actual shell downloader without network or installation."""
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / 'distribution/macos/install.sh'


def run_download(tmp_path, body):
    source = SCRIPT.read_text()
    function = source[source.index('download() {'):source.index('verify_sha() {')]
    return subprocess.run(['sh', '-c', 'set -eu\n' + body + '\n' + function +
                           '\ndownload https://example.invalid/package output\n'],
                          cwd=tmp_path, text=True, capture_output=True)


def test_http2_failure_falls_back_and_publishes_complete_file(tmp_path):
    result = run_download(tmp_path, '''
sleep() { :; }
curl() {
  printf '%s\\n' "$*" >> calls
  case "$*" in
    *--http1.1*) printf complete > output.part; return 0 ;;
    *) printf partial > output.part; return 16 ;;
  esac
}
''')
    assert result.returncode == 0, result.stderr
    assert (tmp_path / 'output').read_text() == 'complete'
    assert len((tmp_path / 'calls').read_text().splitlines()) == 2
    assert not (tmp_path / 'output.part').exists()


def test_retry_exhaustion_never_publishes_partial_file(tmp_path):
    result = run_download(tmp_path, '''
sleep() { :; }
curl() { echo called >> calls; printf partial > output.part; return 28; }
''')
    assert result.returncode == 28
    assert len((tmp_path / 'calls').read_text().splitlines()) == 3
    assert not (tmp_path / 'output').exists()


def test_certificate_failure_not_retried(tmp_path):
    result = run_download(tmp_path, '''
curl() { echo called >> calls; return 60; }
''')
    assert result.returncode == 60
    assert (tmp_path / 'calls').read_text().splitlines() == ['called']


def test_cached_archive_requires_matching_checksum(tmp_path):
    import hashlib
    old = tmp_path / 'download-old'
    stage = tmp_path / 'download-new'
    old.mkdir()
    stage.mkdir()
    (old / 'package').write_bytes(b'verified payload')
    digest = hashlib.sha256(b'verified payload').hexdigest()
    source = SCRIPT.read_text()
    block = source[source.index('# Fetch the small checksum'):source.index('\nfi\n# Only the uniquely')]
    for expected, reuse in [(digest, True), ('0' * 64, False)]:
        (stage / 'package').unlink(missing_ok=True)
        setup = '''set -eu
root=$PWD
stage=$PWD/download-new
asset=package
base=https://example.invalid
check_path() { :; }
download() {
 case "$2" in
  *.sha256) printf '%s  package\\n' "$EXPECTED" > "$2" ;;
  *) printf downloaded > "$2" ;;
 esac
}
'''
        import os
        result = subprocess.run(['sh', '-c', setup + block], cwd=tmp_path,
                                env={**os.environ, 'EXPECTED': expected}, capture_output=True)
        assert result.returncode == 0, result.stderr
        assert (stage / 'package').read_bytes() == (b'verified payload' if reuse else b'downloaded')
