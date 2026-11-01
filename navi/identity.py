"""Deployment identity from a clean, tracked source checkout."""
from pathlib import Path
import subprocess


def git_revision(source):
    source = Path(source).resolve()
    directory = source if source.is_dir() else source.parent
    def git(*args):
        result = subprocess.run(["git", "-C", str(directory), *args], capture_output=True, text=True, timeout=10)
        if result.returncode: raise ValueError("Git build identity requires an accessible checkout.")
        return result.stdout.strip()
    revision = git("rev-parse", "HEAD")
    if git("status", "--porcelain", "--untracked-files=all"):
        raise ValueError("Git build identity requires a clean checkout, including untracked files.")
    base = Path(git("rev-parse", "--show-toplevel"))
    tracked = set(git("ls-files", "--full-name").splitlines())
    from .static import project_files
    if any(p.relative_to(base).as_posix() not in tracked for p in project_files(source)):
        raise ValueError("Git build identity requires every analyzed source file to be tracked.")
    return revision
