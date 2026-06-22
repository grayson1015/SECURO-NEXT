import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PYTHON = Path(sys.executable)
PACKAGER = ROOT / ".packager_securo_gui"


def run(args):
    subprocess.run(args, cwd=ROOT, check=True)


def main():
    python = PYTHON if PYTHON.exists() else Path(sys.executable)
    python_root = python.parent
    if (PACKAGER / "PyInstaller").exists() and not (PACKAGER / "PyInstaller" / "__main__.py").exists():
        shutil.rmtree(PACKAGER, ignore_errors=True)
    if not (PACKAGER / "PyInstaller" / "__main__.py").exists():
        run([str(python), "-m", "pip", "install", "--upgrade", "--target", str(PACKAGER), "pyinstaller"])

    env = os.environ.copy()
    env["PYTHONPATH"] = str(PACKAGER)
    env["TCL_LIBRARY"] = str(python_root / "tcl" / "tcl8.6")
    env["TK_LIBRARY"] = str(python_root / "tcl" / "tk8.6")
    subprocess.run(
        [
            str(python),
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            "--onefile",
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
            "SecuroChecker",
            "--add-data",
            "config.json;.",
            "roblox_pc_checker.py",
        ],
        cwd=ROOT,
        env=env,
        check=True,
    )
    print(ROOT / "dist" / "SecuroChecker.exe")


if __name__ == "__main__":
    main()
