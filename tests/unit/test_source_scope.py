from pathlib import Path

import pytest

from app.analysis.php import validate_source_root


def test_source_root_must_stay_inside_configured_workspace(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    target = workspace / "dvwa"
    target.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()

    assert validate_source_root(target, workspace) == target.resolve()
    with pytest.raises(ValueError, match="outside"):
        validate_source_root(outside, workspace)


def test_source_root_rejects_symlink_escape(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = workspace / "app-link"
    link.symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="outside"):
        validate_source_root(link, workspace)
