"""Opt-in transport projection; capability checks and full discovery stay intact."""


def runtime_info_view(info, view='full'):
    if view == 'full':
        return info
    if view != 'summary':
        raise ValueError('Runtime info view must be full or summary')
    result = {key: value for key, value in info.items()
              if key not in {'rule_inventory', 'delivery_manifest'}}
    inventory = info.get('rule_inventory') or {}
    result['rule_inventory'] = {key: inventory[key] for key in (
        'status', 'rule_pack_version', 'rule_pack_checksum', 'execution_proof') if key in inventory}
    manifest = info.get('delivery_manifest') or {}
    result['delivery_manifest'] = {key: manifest[key] for key in (
        'contract', 'manifest_sha256', 'runtime', 'protocols', 'compatibility', 'comparison', 'scope',
        'existing_tasks', 'vulnerability_data_freshness', 'security_proof',
        'repair_authorized', 'automatic_execution') if key in manifest}
    tools = manifest.get('tools') or {}
    result['delivery_manifest']['tools'] = {key: tools[key] for key in (
        'specification_contract', 'schema_sha256', 'names') if key in tools}
    result['view'] = 'summary'
    result['detail_request'] = {'tool': 'get_runtime_info', 'arguments': {'view': 'full'}}
    return result
