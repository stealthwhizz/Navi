"""Bounded YAML loading with explicit omissions and content fingerprints."""
import hashlib
from pathlib import Path

from ..model import gap


class Unsupported(ValueError):
    pass


def documents(paths, component):
    import yaml
    from yaml.tokens import AliasToken, AnchorToken
    files, warnings, manifests, result = [], [], [], []
    for raw in paths:
        path = Path(raw).expanduser()
        if path.is_symlink():
            warnings.append(gap(component, 'Symbolic-link template paths are unsupported.', file=str(path))); continue
        if path.is_dir():
            for index, child in enumerate(path.rglob('*')):
                if index >= 5000:
                    warnings.append(gap(component, 'Template directory traversal limit reached (5000 entries).', file=str(path))); break
                if child.suffix.lower() in {'.yaml', '.yml'} and child.is_file() and not child.is_symlink(): files.append(child)
                if len(files) > 200: break
        elif path.is_file(): files.append(path)
        else: warnings.append(gap(component, 'Template path is unavailable.', file=str(path)))
    if len(files) > 200: warnings.append(gap(component, 'Template file limit reached (200); select a smaller pack.'))
    total = 0
    for path in sorted(dict.fromkeys(files[:200])):
        try:
            if path.stat().st_size > 262144: raise Unsupported('Template exceeds 256 KiB.')
            data = path.read_bytes(); total += len(data)
            if total > 4 * 1024 * 1024: raise Unsupported('Template pack exceeds 4 MiB.')
            text = data.decode('utf-8')
            if any(isinstance(t, (AliasToken, AnchorToken)) for t in yaml.scan(text)):
                raise Unsupported('YAML anchors/aliases are unsupported.')
            class UniqueLoader(yaml.SafeLoader):
                pass
            def mapping(loader, node):
                pairs = loader.construct_pairs(node)
                if any(not isinstance(k, (str, int)) for k, _ in pairs): raise Unsupported('Unsupported YAML mapping key.')
                value = dict(pairs)
                if len(value) != len(pairs): raise Unsupported('Duplicate YAML keys are unsupported.')
                return value
            UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
            value = yaml.load(text, Loader=UniqueLoader)
            if not isinstance(value, dict): raise Unsupported('Template document must be an object.')
            manifest = {'file': str(path), 'sha256': hashlib.sha256(data).hexdigest()}
            manifests.append(manifest); result.append((value, manifest))
        except (ValueError, OSError, yaml.YAMLError, RecursionError) as error:
            reason = str(error) if isinstance(error, Unsupported) else f'Cannot read/parse template ({type(error).__name__}).'
            warnings.append(gap(component, reason, file=str(path)))
    return result, warnings, manifests


def cwe(value):
    import re
    for candidate in value if isinstance(value, list) else [value]:
        found = re.match(r'^(?:CWE-)?([1-9]\d{0,4})(?:\b|$)', str(candidate))
        if found: return 'CWE-' + found[1]
    raise Unsupported('A CWE identifier is required in metadata/classification; IDs are not inferred from template names.')
