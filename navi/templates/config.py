from pathlib import Path

PACKS = Path(__file__).resolve().parent / 'packs'


def options(config):
    value = config.get('scanners', {})
    allowed = {'mode', 'semgrep_rules', 'nuclei_templates'}
    if not isinstance(value, dict) or value.keys() - allowed:
        raise ValueError('scanners accepts mode, semgrep_rules and nuclei_templates; no external scanner executable is used.')
    result = {'mode': 'native', 'semgrep_rules': [str(PACKS / 'php.yaml')],
              'nuclei_templates': [str(PACKS / 'http')], **value}
    if result['mode'] not in {'templates', 'native'}: raise ValueError('scanners.mode must be templates or native.')
    for key in ['semgrep_rules', 'nuclei_templates']:
        if not isinstance(result[key], list) or not all(isinstance(p, str) and p for p in result[key]):
            raise ValueError(f'scanners.{key} must be a list of local YAML paths.')
        if any('://' in p for p in result[key]): raise ValueError('Template paths must be local; scans never download rules.')
    return result
