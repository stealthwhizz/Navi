"""Bounded abstract values and cancellation on ordinary branch-heavy PHP."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from navi.php import PHPAnalyzer, Value, join, merge, MAX_STRING_CONTEXT
from navi.model import Input


def test_branch_join_is_idempotent_and_retains_unsafe_alternative():
    name = Input('query', 'name')
    safe = Value({name: frozenset({'CWE-79'})}, '<p>', literal='<p>')
    for _ in range(100):
        safe = join([safe, safe])
    assert safe.prefix == '<p>' and safe.literal == '<p>'
    assert safe.inputs[name] == frozenset({'CWE-79'})
    unsafe = Value({name: frozenset()}, '<script>')
    forward, reverse = join([safe, unsafe]), join([unsafe, safe])
    assert forward == reverse
    assert not forward.context_known and not forward.inputs[name]
    assert forward.literal is None


def test_concatenation_is_bounded_without_losing_input_or_uncertainty():
    name = Input('query', 'name')
    value = Value(prefix='123456789')
    for _ in range(100):
        value = merge([value, value])
    assert len(value.prefix) == MAX_STRING_CONTEXT
    assert value.context_limited and not value.context_known
    value = merge([value, Value({name: frozenset({'CWE-79'})})])
    assert name in value.inputs and value.context_limited
    assert not value.protected('CWE-78').context_known


@pytest.mark.skipif(not shutil.which('php') or sys.platform != 'linux', reason='PHP and Linux memory limits required')
def test_branch_heavy_php_finishes_under_memory_limit(tmp_path):
    # Regression runs in a child so an accidental return of exponential growth
    # cannot kill pytest or the workstation. No application code is executed.
    source = "<?php $html='<p>';\n" + "if ($condition) { $unused=1; }\n" * 100
    source += "echo $html . $_GET['name'];\n"
    (tmp_path / 'index.php').write_text(source)
    script = '''import json, resource, sys
from pathlib import Path
resource.setrlimit(resource.RLIMIT_AS, (192*1024*1024,192*1024*1024))
from navi.static import analyze
result=analyze(sys.argv[1])
# ru_maxrss can include the pytest parent's pre-exec fork high-water mark.
# /proc reports the executed child's own memory high-water mark instead.
peak=int(next(line for line in Path('/proc/self/status').read_text().splitlines() if line.startswith('VmHWM:')).split()[1])
print(json.dumps({'findings':[(f.cwe, f.bindings[0].parameter) for f in result.findings], 'rss_kib':peak}))
'''
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1]), PYTHON_DOTENV_DISABLED='1')
    process = subprocess.run([sys.executable, '-c', script, str(tmp_path)], env=env,
                             capture_output=True, text=True, timeout=15)
    assert process.returncode == 0, process.stderr
    result = json.loads(process.stdout)
    assert result['findings'] == [['CWE-79', 'name']]
    assert result['rss_kib'] < 128 * 1024


@pytest.mark.skipif(not shutil.which('php'), reason='PHP tokenizer required')
def test_large_html_context_does_not_suppress_an_uncertain_candidate(tmp_path):
    prefix = '<p>' + 'a' * (MAX_STRING_CONTEXT + 100) + '</p><script>'
    (tmp_path / 'index.php').write_text("<?php echo '" + prefix + "' . htmlspecialchars($_GET['name'], ENT_QUOTES);")
    from navi.static import analyze
    result = analyze(tmp_path)
    assert any(f.cwe == 'CWE-79' for f in result.findings)
    assert any('string context limit' in g['reason'] for g in result.gaps)


def test_oversized_constant_never_resolves_to_a_truncated_include():
    from navi.php_paths import constant
    tokens = [('T_VARIABLE', '$a', 1), ('.', '.', 1), ('T_VARIABLE', '$a', 1)]
    value = constant(tokens, {'$a': Value(literal='a' * MAX_STRING_CONTEXT)}, Path('/app/index.php'))
    assert value is None


@pytest.mark.skipif(not shutil.which('php'), reason='PHP tokenizer required')
def test_php_cancellation_inside_a_file_preserves_completed_evidence(tmp_path, monkeypatch):
    from navi.control import ScanControl
    from navi.engine import scan
    root = tmp_path / 'app'; root.mkdir()
    (root / 'index.php').write_text("<?php echo $_GET['first']; echo $_GET['second'];")
    control = ScanControl()
    original = PHPAnalyzer.mark

    def mark(self, *args, **kwargs):
        original(self, *args, **kwargs)
        if self.findings: control.cancel()

    monkeypatch.setattr(PHPAnalyzer, 'mark', mark)
    report = scan(root, None, {'ai': {'enabled': False}}, tmp_path / 'report', browser=False, control=control)
    assert report['stop_reason'] == 'cancelled' and report['status'] == 'partial'
    assert len(report['issues']) == 1
    assert report['issues'][0]['bindings'][0]['parameter'] == 'first'
    assert (tmp_path / 'report/report.json').is_file()
