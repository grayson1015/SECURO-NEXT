import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PYTHON = Path(sys.executable)
PACKAGER_ROOT = Path(tempfile.gettempdir()) / "securo_pyinstaller_cache"
APP_NAME = "Securo"


def run(args):
    subprocess.run(args, cwd=ROOT, check=True)


def main():
    python = PYTHON if PYTHON.exists() else Path(sys.executable)
    python_root = python.parent
    cache_name = f"pyinstaller-{python_root.name.lower()}-{sys.version_info.major}{sys.version_info.minor}"
    packager = PACKAGER_ROOT / cache_name
    if not (packager / "PyInstaller" / "__main__.py").exists():
        packager.mkdir(parents=True, exist_ok=True)
        run([str(python), "-m", "pip", "install", "--target", str(packager), "pyinstaller"])

    env = os.environ.copy()
    env["PYTHONPATH"] = str(packager)
    env["TCL_LIBRARY"] = str(python_root / "tcl" / "tcl8.6")
    env["TK_LIBRARY"] = str(python_root / "tcl" / "tk8.6")
    subprocess.run(
        [
            str(python),
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            "--onedir",
            "--windowed",
            "--hidden-import",
            "tkinter",
            "--add-data",
            f"{python_root / 'tcl'};tcl",
            "--add-data",
            f"{python_root / 'Lib' / 'tkinter'};tkinter",
            "--add-binary",
            f"{python_root / 'DLLs' / 'tcl86t.dll'};.",
            "--add-binary",
            f"{python_root / 'DLLs' / 'tk86t.dll'};.",
            "--add-binary",
            f"{python_root / 'DLLs' / '_tkinter.pyd'};.",
            "--name",
            APP_NAME,
            "--add-data",
            "config.json;.",
            "--add-data",
            "securo_iocs.json;.",
            "roblox_pc_checker.py",
        ],
        cwd=ROOT,
        env=env,
        check=True,
    )
    portable_dir = ROOT / "dist" / APP_NAME
    tools_src = ROOT / "Tools"
    tools_dst = portable_dir / "Tools"
    if tools_src.exists():
        shutil.copytree(tools_src, tools_dst, dirs_exist_ok=True)
    for name in ("config.json", "securo_iocs.json"):
        src = ROOT / name
        if src.exists():
            shutil.copy2(src, portable_dir / name)
    downloads = ROOT / "public" / "downloads"
    downloads.mkdir(parents=True, exist_ok=True)
    zip_base = downloads / APP_NAME
    zip_path = shutil.make_archive(str(zip_base), "zip", ROOT / "dist", APP_NAME)
    print(portable_dir / f"{APP_NAME}.exe")
    print(zip_path)


if __name__ == "__main__":
    main()
