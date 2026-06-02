import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PYTHON = Path(r"C:\Users\Grayson Gollotte\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe")
PACKAGER = ROOT / ".packager_gui_confirmed_rules"
PYTHON_ROOT = PYTHON.parent


def run(args):
    subprocess.run(args, cwd=ROOT, check=True)


def main():
    python = PYTHON if PYTHON.exists() else Path(sys.executable)
    if not (PACKAGER / "PyInstaller").exists():
        run([str(python), "-m", "pip", "install", "--upgrade", "--target", str(PACKAGER), "pyinstaller"])

    env = os.environ.copy()
    env["PYTHONPATH"] = str(PACKAGER)
    env["TCL_LIBRARY"] = str(PYTHON_ROOT / "tcl" / "tcl8.6")
    env["TK_LIBRARY"] = str(PYTHON_ROOT / "tcl" / "tk8.6")
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
            f"{PYTHON_ROOT / 'tcl'};tcl",
            "--add-data",
            f"{PYTHON_ROOT / 'Lib' / 'tkinter'};tkinter",
            "--add-binary",
            f"{PYTHON_ROOT / 'DLLs' / 'tcl86t.dll'};.",
            "--add-binary",
            f"{PYTHON_ROOT / 'DLLs' / 'tk86t.dll'};.",
            "--add-binary",
            f"{PYTHON_ROOT / 'DLLs' / '_tkinter.pyd'};.",
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
