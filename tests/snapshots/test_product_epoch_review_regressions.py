"""Independent regressions for immutable product-observation history."""
import shutil

import pytest
from security_runtime.product_epoch_capture import platform_supported

pytestmark = pytest.mark.skipif(not platform_supported(), reason="Historical product epochs require POSIX descriptor observations")

from security_runtime.hook_state import HookStateStore
from security_runtime.product_epoch_service import ProductEpochService
from security_runtime.product_epoch_store import ProductEpochError
from security_runtime.tasks.ownership import session_owner


@pytest.mark.parametrize('reopen', [False, True])
@pytest.mark.parametrize('sealed', [False, True])
def test_lost_entire_product_directory_never_rebuilds_an_epoch_from_current_source(tmp_path, reopen, sealed):
    root = tmp_path.resolve()/'source'
    root.mkdir()
    (root/'source.py').write_bytes(b'original product observation\n')
    hooks = HookStateStore(tmp_path.resolve()/'private')
    current = ProductEpochService(hooks, root)
    owner = session_owner('codex', 'missing-product-history')
    original = current.ensure(owner)
    if sealed:
        for _ in range(16):
            original = current.step(owner)
            if original['state'] == 'SEALED':
                break
        assert original['state'] == 'SEALED'
    current.close()
    shutil.rmtree(current.store.directory)
    (root/'source.py').write_bytes(b'current source must not become the old comparison anchor\n')
    if reopen:
        current = ProductEpochService(hooks, root)
    try:
        with pytest.raises(ProductEpochError, match='PRODUCT_EPOCH_HISTORY_UNAVAILABLE'):
            current.ensure(owner)
        assert not current.store.directory.exists()
    finally:
        current.close()
