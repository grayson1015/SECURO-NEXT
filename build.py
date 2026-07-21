import os
import shutil
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
PYTHON = Path(sys.executable)
PACKAGER_ROOT = ROOT / ".securo_build_tools"
APP_NAME = "Securo"
ICON_PATH = ROOT / "assets" / "securo.ico"

ROOT_TOOL_FILES = {
    "AmcacheParser.exe",
    "AppCompatCacheParser.exe",
    "JLECmd.exe",
    "MFTECmd.exe",
    "PECmd.exe",
    "SBECmd.exe",
    "SrumECmd.exe",
}

NET9_TOOL_FILE_STEMS = {
    "AmcacheParser",
    "AppCompatCacheParser",
    "bstrings",
    "JLECmd",
    "LECmd",
    "MFTECmd",
    "PECmd",
    "RBCmd",
    "RecentFileCacheParser",
    "rla",
    "SBECmd",
    "SrumECmd",
    "SumECmd",
    "VSCMount",
    "WxTCmd",
}

NET9_TOOL_DIRS = {
    "EvtxeCmd",
    "RECmd",
    "SQLECmd",
}


def run(args):
    subprocess.run(args, cwd=ROOT, check=True)


def copy_securo_tools(tools_src: Path, tools_dst: Path):
    tools_dst.mkdir(parents=True, exist_ok=True)
    for name in sorted(ROOT_TOOL_FILES):
        src = tools_src / name
        if src.exists():
            shutil.copy2(src, tools_dst / name)

    net9_src = tools_src / "net9"
    if not net9_src.exists():
        return
    net9_dst = tools_dst / "net9"
    net9_dst.mkdir(parents=True, exist_ok=True)
    for stem in sorted(NET9_TOOL_FILE_STEMS):
        for suffix in (".exe", ".dll", ".runtimeconfig.json"):
            src = net9_src / f"{stem}{suffix}"
            if src.exists():
                shutil.copy2(src, net9_dst / src.name)
    for name in sorted(NET9_TOOL_DIRS):
        src = net9_src / name
        if src.exists():
            shutil.copytree(src, net9_dst / name, dirs_exist_ok=True)


def main():
    build_started = time.time()
    build_id = time.strftime("%Y%m%d_%H%M%S")
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
    staging_root = ROOT / ".securo_staging" / build_id
    staging_dist = staging_root / "dist"
    staging_work = staging_root / "build"
    staging_spec = staging_root / "spec"
    staging_dist.mkdir(parents=True, exist_ok=True)
    staging_work.mkdir(parents=True, exist_ok=True)
    staging_spec.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            str(python),
            "-m",
            "PyInstaller",
            "--noconfirm",
            "--clean",
            "--distpath",
            str(staging_dist),
            "--workpath",
            str(staging_work),
            "--specpath",
            str(staging_spec),
            "--onedir",
            "--windowed",
            "--uac-admin",
            "--icon",
            str(ICON_PATH),
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
            f"{ROOT / 'config.json'};.",
            "--add-data",
            f"{ROOT / 'securo_iocs.json'};.",
            "--add-data",
            f"{ICON_PATH};assets",
            str(ROOT / "roblox_pc_checker.py"),
        ],
        cwd=ROOT,
        env=env,
        check=True,
    )
    portable_dir = staging_dist / APP_NAME
    tools_src = ROOT / "Tools"
    tools_dst = portable_dir / "Tools"
    if tools_src.exists():
        copy_securo_tools(tools_src, tools_dst)
    for name in ("config.json", "securo_iocs.json"):
        src = ROOT / name
        if src.exists():
            shutil.copy2(src, portable_dir / name)
    downloads = ROOT / "public" / "downloads"
    downloads.mkdir(parents=True, exist_ok=True)
    zip_base = downloads / APP_NAME
    zip_path = shutil.make_archive(str(zip_base), "zip", staging_dist, APP_NAME)
    zip_file = Path(zip_path)
    source_mtime = max((ROOT / "roblox_pc_checker.py").stat().st_mtime, (ROOT / "config.json").stat().st_mtime)
    if zip_file.stat().st_mtime < source_mtime or zip_file.stat().st_mtime < build_started:
        raise RuntimeError("Securo.zip is stale; the build did not package the current scanner source.")
    print(portable_dir / f"{APP_NAME}.exe")
    print(zip_file)


if __name__ == "__main__":
    main()
