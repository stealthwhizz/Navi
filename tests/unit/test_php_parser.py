from pathlib import Path

import pytest

from app.analysis.php import PhpParseError, parse_php_file, php_files


def test_parser_reads_valid_php_with_tree_sitter(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    source_root.mkdir()
    path = source_root / "index.php"
    path.write_text("<?php echo $_GET['name'];", encoding="utf-8")

    parsed = parse_php_file(path, source_root)

    assert parsed.relative_path == "index.php"
    assert parsed.tree.root_node.has_error is False
    assert parsed.source == "<?php echo $_GET['name'];"


def test_parser_reports_syntax_error_and_oversized_file(tmp_path: Path) -> None:
    source_root = tmp_path / "src"
    source_root.mkdir()
    invalid = source_root / "invalid.php"
    invalid.write_text("<?php function broken( {", encoding="utf-8")

    with pytest.raises(PhpParseError, match="syntax"):
        parse_php_file(invalid, source_root)

    huge = source_root / "huge.php"
    huge.write_bytes(b"<?php " + b" " * 100)
    with pytest.raises(PhpParseError, match="size limit"):
        parse_php_file(huge, source_root, max_bytes=32)


def test_php_file_discovery_skips_virtual_environment(tmp_path: Path) -> None:
    (tmp_path / "index.php").write_text("<?php echo 'ok';", encoding="utf-8")
    venv = tmp_path / ".venv"
    venv.mkdir()
    (venv / "package.php").write_text("<?php echo 'vendor';", encoding="utf-8")

    files, skipped = php_files(tmp_path)

    assert [path.relative_to(tmp_path).as_posix() for path in files] == ["index.php"]
    assert skipped == []
