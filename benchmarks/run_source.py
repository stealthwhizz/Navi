"""Hash-pinned source benchmark; no target requests, answer keys stay outside scanners."""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile

from navi.engine import scan
from navi.evaluate import evaluate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, default=Path(__file__).with_name('dvwa-source.json'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    key = json.loads(args.manifest.read_text())
    root = args.source.resolve()
    with tempfile.TemporaryDirectory(prefix='navi-reviewed-source-') as temporary:
        selected = Path(temporary)
        for name, expected in key['files'].items():
            relative = Path(name)
            if relative.is_absolute() or '..' in relative.parts: raise ValueError('Invalid manifest path.')
            source = (root / relative).resolve()
            if not source.is_relative_to(root): raise ValueError('Source file leaves benchmark root.')
            content = source.read_bytes()
            if hashlib.sha256(content).hexdigest() != expected:
                raise ValueError(f'Reviewed file changed; update its truth anchors and hash before scoring: {name}')
            destination = selected / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
        report = scan(selected, None, {'ai': {'enabled': False}, 'scanners': {'mode': 'native'}}, args.output, browser=False)
    scoped = {**report, 'findings': [f for f in report['findings'] if f['cwe'] in key['scope_cwes']],
              'issues': [i for i in report['issues'] if i['cwe'] in key['scope_cwes']]}
    result = evaluate(scoped, key)
    result['benchmark_scope'] = {'files': key['files'], 'cwes': key['scope_cwes'], 'http_requests': report['http_requests'],
                                 'excluded_finding_ids': [f['id'] for f in report['findings'] if f['cwe'] not in key['scope_cwes']],
                                 'note': 'Selected independently authored source operations only. Runtime recall and link accuracy were not measured.'}
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / 'evaluation.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result['metrics'], indent=2))


if __name__ == '__main__': main()
