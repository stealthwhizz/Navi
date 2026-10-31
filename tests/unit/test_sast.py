from pathlib import Path

from app.analysis.routemap import build_route_map
from app.analysis.sast import scan_source

PHP = '''<?php
$db->query("SELECT * FROM users WHERE id=" . $_GET['id']);
echo $_GET['q'];
system($_GET['cmd']);
file_get_contents($_GET['file']);
header("Location: " . $_GET['next']);
$api_secret = "ABCD1234-very-long-test-secret-value";
'''


def test_detects_all_six_cwes_with_code_evidence(tmp_path: Path) -> None:
    root = tmp_path / "src"
    root.mkdir()
    (root / "index.php").write_text(PHP, encoding="utf-8")
    routes, _, _ = build_route_map(root)

    findings, suppressed, coverage = scan_source(root, routes)

    assert {finding.cwe for finding in findings} == {22, 78, 79, 89, 601, 798}
    assert all(finding.source == "sast" and finding.sast["path"] for finding in findings)
    assert all(finding.location["file"] == "index.php" for finding in findings)
    secret = next(finding for finding in findings if finding.cwe == 798)
    assert "ABCD1234" not in secret.sast["snippet"]["code"]
    assert suppressed == []
    assert coverage["files_parsed"] == 1


def test_does_not_flag_directly_sanitized_or_parameterized_examples(tmp_path: Path) -> None:
    root = tmp_path / "src"
    root.mkdir()
    (root / "safe.php").write_text(
        '''<?php
        $db->prepare("SELECT * FROM users WHERE id = ?")->execute([$_GET['id']]);
        echo htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');
        system(escapeshellarg($_GET['cmd']));
        file_get_contents(basename($_GET['file']));
        header("Location: /home.php");
        $api_secret = "replace-me-placeholder";
        ''',
        encoding="utf-8",
    )
    routes, _, _ = build_route_map(root)

    findings, _, _ = scan_source(root, routes)

    assert findings == []


def test_tracks_simple_assignment_alias_to_sink(tmp_path: Path) -> None:
    root = tmp_path / "src"
    root.mkdir()
    (root / "search.php").write_text(
        "<?php\n$term = $_GET['term'];\necho $term;",
        encoding="utf-8",
    )
    routes, _, _ = build_route_map(root)

    findings, _, _ = scan_source(root, routes)

    assert len(findings) == 1
    assert findings[0].cwe == 79
    assert findings[0].sast["source"]["expr"] == "$_GET['term']"
    assert findings[0].sast["sink"]["type"] == "html_output"
    assert findings[0].sast["source"]["location"] == "search.php:2"
    assert findings[0].sast["sink"]["location"] == "search.php:3"


def test_sanitized_alias_and_mixed_sinks_are_tracked_independently(tmp_path: Path) -> None:
    root = tmp_path / "src"
    root.mkdir()
    (root / "mixed.php").write_text(
        '''<?php
$safe = htmlspecialchars($_GET['safe']);
echo $safe;
echo htmlspecialchars($_GET['also_safe']) . $_GET['unsafe'];
''',
        encoding="utf-8",
    )
    routes, _, _ = build_route_map(root)

    findings, _, _ = scan_source(root, routes)

    assert len(findings) == 1
    assert findings[0].sast["source"]["expr"] == "$_GET['unsafe']"
    assert findings[0].location["line"] == 4


def test_overwriting_tainted_variable_removes_stale_source_flow(tmp_path: Path) -> None:
    root = tmp_path / "src"
    root.mkdir()
    (root / "reassigned.php").write_text(
        "<?php\n$x = $_GET['q'];\n$x = 'safe';\necho $x;",
        encoding="utf-8",
    )
    routes, _, _ = build_route_map(root)

    findings, _, _ = scan_source(root, routes)

    assert findings == []
