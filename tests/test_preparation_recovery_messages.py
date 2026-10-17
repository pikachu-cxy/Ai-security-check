from security_runtime.background_preparation import preparation_message


def test_timeout_and_build_mismatch_explain_retry_without_reinstall():
    value = {'status': 'OTHER_BUILD', 'build_match': False,
        'receipt': {'message': '漏洞数据已过期。',
                    'preparation': {'error_code': 'NETWORK_TIMEOUT'}}}
    message = preparation_message(value)
    assert '下载超时' in message and '另一个安装构建' in message
    assert 'preparation retry' in message and '无需反复重装' in message


def test_current_ready_receipt_does_not_repeat_historical_failure():
    value = {'status': 'READY', 'current_readiness': {'ready': True, 'message': '已准备完成'},
        'background_receipt': {'preparation': {'error_code': 'NETWORK_TIMEOUT'}}}
    assert preparation_message(value) == '已准备完成'


def test_failure_details_are_closed_and_never_echo_raw_values():
    value = {'status': 'FAILED', 'receipt': {'preparation': {'error_code': 'PRIVATE_CANARY'}}}
    message = preparation_message(value)
    assert 'PRIVATE_CANARY' not in message and 'preparation retry' in message
