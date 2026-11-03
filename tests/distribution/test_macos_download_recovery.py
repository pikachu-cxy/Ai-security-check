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


def test_download_failure_stops_once_with_specific_diagnosis(tmp_path):
    for code, message in [(16, 'GitHub'), (28, 'GitHub'), (22, '404'), (60, '证书')]:
        (tmp_path / 'calls').unlink(missing_ok=True)
        result = run_download(tmp_path, 
            'curl() { echo called >> calls; printf partial > output.part; return %s; }' % code)
        assert result.returncode == code
        assert (tmp_path / 'calls').read_text().splitlines() == ['called']
        assert not (tmp_path / 'output').exists()
        assert message in result.stderr
        assert '不自动重试' in result.stderr


def test_success_publishes_complete_download(tmp_path):
    result = run_download(tmp_path, 'curl() { printf complete > output.part; }')
    assert result.returncode == 0, result.stderr
    assert (tmp_path / 'output').read_text() == 'complete'
    assert not (tmp_path / 'output.part').exists()


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
