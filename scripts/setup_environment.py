"""Install Navi into a project-local virtual environment without changing OS Python.

Default: fetch pinned Python dependencies (internet required). --reuse-installed is
an offline recovery option when this interpreter already has a complete bundled
Playwright installation and the other runtime dependencies are installed locally.
"""
import argparse
import importlib.metadata
from pathlib import Path
import shutil
import subprocess
import sys
import venv

ROOT = Path(__file__).resolve().parents[1]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reuse-installed', action='store_true', help='Reuse system packages and copy this interpreter\'s complete Playwright package into .venv (offline recovery)')
    args = parser.parse_args(argv)
    package = metadata = None
    try:
        if args.reuse_installed:
            import playwright
            package = Path(playwright.__file__).resolve().parent
            if not (package / 'driver/package/cli.js').is_file() or not (package / 'driver/node').is_file():
                raise ValueError('This Python lacks a complete bundled Playwright package. Run setup without --reuse-installed to install one.')
            distribution = importlib.metadata.distribution('playwright')
            metadata = Path(distribution._path)
        destination = ROOT / '.venv'
        venv.EnvBuilder(with_pip=True, system_site_packages=args.reuse_installed).create(destination)
        python = destination / 'bin/python'
        if args.reuse_installed:
            site = Path(subprocess.check_output([str(python), '-c', 'import sysconfig; print(sysconfig.get_path("purelib"))'], text=True).strip())
            if package != (site / 'playwright').resolve():
                shutil.copytree(package, site / 'playwright', dirs_exist_ok=True, ignore=shutil.ignore_patterns('__pycache__'))
            if metadata.resolve() != (site / metadata.name).resolve():
                shutil.copytree(metadata, site / metadata.name, dirs_exist_ok=True)
            command = [str(python), '-m', 'pip', 'install', '--no-cache-dir', '--no-deps', '--no-build-isolation', '--no-index', '-e', str(ROOT)]
        else:
            command = [str(python), '-m', 'pip', 'install', '--retries', '1', '--timeout', '15', '-e', str(ROOT) + '[browser]']
        subprocess.run(command, check=True)
        subprocess.run([str(python), '-c', 'from navi.browser import check_driver; check_driver(); print("Playwright driver installation: OK")'], cwd=ROOT, check=True)
        print(f'Environment ready. Use {python} -m navi scan')
        print('XSS also requires Chromium. A system Chromium is detected automatically; otherwise run .venv/bin/python -m playwright install chromium.')
        if args.reuse_installed:
            print('Offline recovery uses existing system runtime packages plus the copied Playwright package. The default setup performs an independent dependency installation.')
        return 0
    except (OSError, ValueError, ImportError, subprocess.CalledProcessError) as error:
        print(f'Setup incomplete ({type(error).__name__}): {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
